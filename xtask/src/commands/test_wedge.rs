// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_wedge.rs

//! Interrupts-off wedge test (#33): one CPU of a running system is wedged in
//! the kernel with interrupts off, and the softlockup watchdog's heartbeat
//! cross-check must report it (core/kernel/docs/scheduling-internals.md
//! § Softlockup Watchdog).
//!
//! The wedge is made at the hardware boundary, so the kernel carries no test
//! code: the production image boots with QEMU's gdbstub on a unix socket, and
//! once the system is idle the host stops the VM over the GDB remote serial
//! protocol, finds the chosen CPU halted in the idle loop, moves its program
//! counter to the kernel's `halt_loop` (which masks interrupts and halts for
//! good), and resumes the VM. A CPU is moved only when its program counter is
//! the one after the idle loop's halt instruction, a point where the idle
//! thread holds no lock ([`is_idle_halt`]), so the wedge leaves no lock held
//! for the other CPUs to spin on.
//!
//! Two boots: one wedges the highest-numbered AP, which the BSP's
//! `ap_silence_check` reports; the other wedges the BSP, which an AP's
//! `bsp_stall_check` reports. Each boot passes on the watchdog's whole
//! report. On `x86_64` the report also holds the wedged CPU's own frame,
//! printed from the NMI the observer sends it, with its `rip` inside
//! `halt_loop`; on riscv64, which has no supervisor-mode NMI, it holds none.
//!
//! A pure runner like `test-terminal`: it neither builds nor stages, and boots
//! the default boot set (`terminal.svc` autostarted), idle once the terminal
//! prints its READY marker. A gdbstub that cannot be reached fails the test.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use gdb_rsp::PACKET_SIZE;
use gdb_rsp::frame::{Event, PacketReader, PacketWriter};
use object::{Object as _, ObjectSymbol as _, SymbolKind};

use crate::arch::Arch;
use crate::cli::TestWedgeArgs;
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::guest::Guest;
use crate::qemu::{
    GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, X86Paging, build_qemu_argv,
    prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::util::{require_tool, step};

/// Marker the guest `terminal` prints once the default boot is up. Kept in
/// sync with `programs/terminal`.
const READY_MARKER: &str = "terminal: READY for injection";

/// The kernel's serial-only layout line (`core/kernel/src/main.rs`).
const KASLR_MARKER: &str = "kaslr: slide=";

/// The Phase 8 lines naming each logical CPU's hardware id
/// (`core/kernel/src/main.rs`): `smp: starting N AP(s); BSP is CPU 0
/// (hardware id 0x..)` and `smp: AP K (hardware id 0x..) online`.
const BSP_LINE: &str = "smp: starting ";
const AP_LINE: &str = "smp: AP ";
const HW_ID_FIELD: &str = "hardware id ";

/// The last line of a watchdog report (`sched::watchdog_dump`).
const END_MARKER: &str = "=== END WATCHDOG ===";

/// The x86-64 NMI handler's frame line (`idt::ipi_nmi_backtrace_handler`).
const NMI_LINE: &str = "NMI BACKTRACE: cpu=";

/// Budget for the boot to reach [`READY_MARKER`].
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Time after [`READY_MARKER`] for the boot's last services to go idle.
const SETTLE: Duration = Duration::from_secs(2);

/// Budget from the wedge to the end of the report: the heartbeat checks wait
/// 8 s of guest time at up to 128 CPUs, and an emulated guest's time runs
/// slower than the host's on a loaded host.
const REPORT_TIMEOUT: Duration = Duration::from_mins(2);

/// Budget for one gdbstub reply.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);

/// How many times the host stops the VM looking for the CPU halted in the
/// idle loop, and the pause between tries, during which the VM runs.
const MOVE_ATTEMPTS: u32 = 100;
const MOVE_RETRY: Duration = Duration::from_millis(100);

/// Which CPU a boot wedges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Victim
{
    /// The highest-numbered AP, reported by the BSP.
    Ap,
    /// The BSP, reported by an AP.
    Bsp,
}

/// A half-open address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span
{
    start: u64,
    end: u64,
}

impl Span
{
    fn contains(self, addr: u64) -> bool
    {
        (self.start..self.end).contains(&addr)
    }

    fn slid(self, slide: u64) -> Self
    {
        Self {
            start: self.start.wrapping_add(slide),
            end: self.end.wrapping_add(slide),
        }
    }
}

/// The kernel functions the test needs, at their link addresses.
#[derive(Debug)]
struct Image
{
    /// `arch::<arch>::cpu::halt_loop`, where the victim is moved.
    halt_loop: Span,
    /// The idle loop (`sched::idle_thread_entry`) and the halt primitive it
    /// calls (`arch::<arch>::cpu::halt_until_interrupt`), when not inlined.
    idle: Vec<Span>,
}

/// What the boot printed before the system went idle.
#[derive(Debug, PartialEq, Eq)]
struct Boot
{
    slide: u64,
    /// `(logical index, hardware id)` of every CPU, the BSP first.
    cpus: Vec<(u32, u32)>,
}

pub fn run(ctx: &Context, args: &TestWedgeArgs) -> Result<()>
{
    if args.cpus < 2
    {
        bail!("test-wedge needs at least 2 CPUs: the wedged CPU is reported by another");
    }
    validate_sysroot_for_launch(ctx, args.arch)?;
    let kernel_path = ctx.sysroot_efi_seraph().join("kernel");
    let kernel = std::fs::read(&kernel_path)
        .with_context(|| format!("reading {}", kernel_path.display()))?;
    let image = image_spans(&kernel)
        .with_context(|| format!("finding the kernel functions in {}", kernel_path.display()))?;
    // Held until the command returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;

    for victim in [Victim::Ap, Victim::Bsp]
    {
        boot_once(ctx, args, &image, victim).with_context(|| format!("wedging the {victim:?}"))?;
    }
    step("interrupts-off wedge test: PASS (AP and BSP reported)");
    Ok(())
}

/// One boot: wait for the idle system, wedge `victim`, check the report.
fn boot_once(ctx: &Context, args: &TestWedgeArgs, image: &Image, victim: Victim) -> Result<()>
{
    let (firmware_code, firmware_vars) = match args.arch
    {
        Arch::X86_64 => (find_ovmf_code()?, None),
        Arch::Riscv64 =>
        {
            let (code, vars) = prepare_riscv_firmware(ctx)?;
            (code, Some(vars))
        }
    };
    let disk_path = ctx.disk_image();
    let sock_dir = ctx.target_dir.join("xtask");
    std::fs::create_dir_all(&sock_dir)
        .with_context(|| format!("creating {}", sock_dir.display()))?;
    let sock_path = sock_dir.join(format!("wedge-{}.gdb", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);

    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: None,
        firmware_code_path: &firmware_code,
        firmware_vars_path: firmware_vars.as_deref(),
        cpus: args.cpus,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Unix(&sock_path),
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        x86_paging: X86Paging::Four,
        iommu: Iommu::Attached,
        debug_port: None,
        test_devices: false,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    step(&format!(
        "Launching QEMU for the interrupts-off wedge test ({victim:?}, gdbstub on {})",
        sock_path.display()
    ));
    let child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let mut guest = Guest::from_child(child)?;

    let result = (|| {
        let lines = guest.collect_until(READY_MARKER, BOOT_TIMEOUT)?;
        let boot = parse_boot(&lines)?;
        let &(logical, hw_id) = match victim
        {
            Victim::Ap => boot.cpus.iter().max_by_key(|&&(cpu, _)| cpu),
            Victim::Bsp => boot.cpus.first(),
        }
        .context("the boot named no CPU")?;
        if victim == Victim::Ap && logical == 0
        {
            bail!("the boot brought no AP online");
        }
        thread::sleep(SETTLE);

        let pc = wedge(&sock_path, args.arch, hw_id, image, boot.slide)?;
        step(&format!(
            "Moved CPU {logical} (hardware id {hw_id:#x}) from the idle halt at {pc:#x} to \
             halt_loop; waiting for the watchdog"
        ));
        let report = guest.collect_until(END_MARKER, REPORT_TIMEOUT)?;
        check_report(
            args.arch,
            victim,
            logical,
            &report,
            image.halt_loop.slid(boot.slide),
        )
    })();
    guest.shutdown();
    let _ = std::fs::remove_file(&sock_path);
    result?;
    step(&format!("wedge test: {victim:?} reported"));
    Ok(())
}

/// Stop the VM until the CPU with hardware id `hw_id` is halted in the idle
/// loop, move it to `halt_loop`, and resume the VM. Returns the program
/// counter it was moved from.
///
/// QEMU numbers a CPU's GDB thread one past its CPU index, which under a
/// plain `-smp N` is its hardware id (the x86-64 APIC id, the riscv64 hart
/// id); [`check_report`] confirms the mapping, since the report names the
/// logical CPU that went silent.
fn wedge(sock: &Path, arch: Arch, hw_id: u32, image: &Image, slide: u64) -> Result<u64>
{
    let target = gdb_arch(arch);
    let pc_reg = target.pc_regnum();
    let thread_id = u64::from(hw_id) + 1;
    let halt = halt_instruction(arch);
    let halt_len = halt.len() as u64;
    for _ in 0..MOVE_ATTEMPTS
    {
        // Connecting stops the VM; detaching resumes it.
        let mut stub = Stub::connect(sock)?;
        stub.request(b"?")?;
        stub.expect_ok(format!("Hg{thread_id:x}").as_bytes())?;
        // Reading the whole register block has QEMU fetch the CPU's state from
        // the accelerator (KVM) and write it back on resume; the single
        // register and memory accesses below do not, and would otherwise read
        // a stale state and have the write lost.
        stub.request(b"g")?;
        let pc = stub.read_register(pc_reg)?;
        let before = stub.read_memory(pc.wrapping_sub(halt_len), halt.len())?;
        if is_idle_halt(image, slide, pc, &before, halt)
        {
            let to = image.halt_loop.start.wrapping_add(slide);
            stub.expect_ok(format!("P{pc_reg:x}={}", le_hex(to)).as_bytes())?;
            stub.expect_ok(b"D")?;
            return Ok(pc);
        }
        stub.expect_ok(b"D")?;
        drop(stub);
        thread::sleep(MOVE_RETRY);
    }
    bail!(
        "the CPU with hardware id {hw_id:#x} was not halted in the idle loop in any of \
         {MOVE_ATTEMPTS} stops"
    )
}

/// Whether a CPU stopped at `pc`, with `before` the bytes just below it, is
/// halted in the idle loop: `pc` lies in the idle loop or its halt primitive
/// and follows a halt instruction. At that point the idle loop has read its
/// flags and run queue lock-free and holds no lock
/// (`sched::idle_thread_entry`), and nothing else halts there.
fn is_idle_halt(image: &Image, slide: u64, pc: u64, before: &[u8], halt: &[u8]) -> bool
{
    let link = pc.wrapping_sub(slide);
    before == halt && image.idle.iter().any(|span| span.contains(link))
}

/// The architecture's halt instruction as it lies in memory: `hlt` on
/// x86-64, `wfi` on riscv64 (little-endian).
fn halt_instruction(arch: Arch) -> &'static [u8]
{
    match arch
    {
        Arch::X86_64 => &[0xF4],
        Arch::Riscv64 => &[0x73, 0x00, 0x50, 0x10],
    }
}

fn gdb_arch(arch: Arch) -> gdb_rsp::target::Arch
{
    match arch
    {
        Arch::X86_64 => gdb_rsp::target::Arch::X86_64,
        Arch::Riscv64 => gdb_rsp::target::Arch::Riscv64,
    }
}

/// Check the watchdog report the wedge produced: `lines` run from the wedge
/// to the report's last line. `halt_loop` is the function's runtime span.
fn check_report(
    arch: Arch,
    victim: Victim,
    logical: u32,
    lines: &[String],
    halt_loop: Span,
) -> Result<()>
{
    let (detector, header) = match victim
    {
        Victim::Ap => (
            format!("watchdog: cpu{logical} timer heartbeat stalled"),
            "=== WATCHDOG: AP timer heartbeat stalled",
        ),
        Victim::Bsp => (
            "observes BSP heartbeat stalled".to_owned(),
            "=== WATCHDOG: BSP timer heartbeat stalled",
        ),
    };
    let find = |needle: &str| lines.iter().position(|l| l.contains(needle));
    let Some(detector_at) = find(&detector)
    else
    {
        bail!("the report has no `{detector}` line");
    };
    if find(header).is_none()
    {
        bail!("the report has no `{header}` header");
    }
    let nmi_prefix = format!("{NMI_LINE}{logical} ");
    let frame = find(&nmi_prefix);
    match arch
    {
        Arch::X86_64 =>
        {
            let Some(frame_at) = frame
            else
            {
                bail!("the report has no `{nmi_prefix}` frame from the wedged CPU");
            };
            if frame_at > detector_at
            {
                bail!("the wedged CPU's frame follows the observer's report");
            }
            let rip = lines
                .get(frame_at)
                .and_then(|l| field_hex(l, "rip="))
                .context("the NMI frame line has no rip")?;
            if !halt_loop.contains(rip)
            {
                bail!(
                    "the NMI frame's rip {rip:#x} is outside halt_loop ({:#x}..{:#x})",
                    halt_loop.start,
                    halt_loop.end
                );
            }
            expect_own_frame(lines.get(detector_at), "true")
        }
        Arch::Riscv64 =>
        {
            if frame.is_some()
            {
                bail!("an NMI frame on riscv64, which has no supervisor-mode NMI");
            }
            expect_own_frame(lines.get(detector_at), "false")
        }
    }
}

fn expect_own_frame(line: Option<&String>, want: &str) -> Result<()>
{
    let field = format!("own_frame={want})");
    if line.is_some_and(|l| l.contains(&field))
    {
        Ok(())
    }
    else
    {
        bail!("the detector's line does not end with `{field}`: {line:?}")
    }
}

/// Read the KASLR slide and the CPU map from the boot's lines.
fn parse_boot(lines: &[String]) -> Result<Boot>
{
    let slide = lines
        .iter()
        .find_map(|l| field_hex(l, KASLR_MARKER))
        .context("no `kaslr: slide=` line before the READY marker")?;
    let bsp = lines
        .iter()
        .filter(|l| l.contains(BSP_LINE))
        .find_map(|l| field_hex(l, HW_ID_FIELD))
        .context("no `smp: starting` line naming the BSP's hardware id")?;
    let mut cpus = vec![(0, u32::try_from(bsp).context("the BSP's hardware id")?)];
    for line in lines
    {
        let Some((_, rest)) = line.split_once(AP_LINE)
        else
        {
            continue;
        };
        let (Some(logical), Some(hw)) = (
            rest.split_whitespace().next().and_then(|n| n.parse().ok()),
            field_hex(rest, HW_ID_FIELD),
        )
        else
        {
            continue;
        };
        cpus.push((logical, u32::try_from(hw).context("an AP's hardware id")?));
    }
    Ok(Boot { slide, cpus })
}

/// The hexadecimal number after `key` in `line` (`0x` prefix optional), up
/// to whitespace or a closing parenthesis.
fn field_hex(line: &str, key: &str) -> Option<u64>
{
    let (_, rest) = line.split_once(key)?;
    let digits = rest.split(|c: char| c.is_whitespace() || c == ')').next()?;
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    u64::from_str_radix(digits, 16).ok()
}

/// Find `halt_loop` and the idle loop in the kernel's symbol table.
fn image_spans(data: &[u8]) -> Result<Image>
{
    let file = object::File::parse(data).context("parsing the kernel ELF")?;
    let mut halt_loop = None;
    let mut idle = Vec::new();
    for sym in file.symbols()
    {
        if sym.kind() != SymbolKind::Text || !sym.is_definition() || sym.size() == 0
        {
            continue;
        }
        let Ok(raw) = sym.name()
        else
        {
            continue;
        };
        let name = addr2line::demangle_auto(std::borrow::Cow::Borrowed(raw), None);
        let span = Span {
            start: sym.address(),
            end: sym.address().saturating_add(sym.size()),
        };
        match function_path(&name)
        {
            p if p.ends_with("::cpu::halt_loop") =>
            {
                if halt_loop.replace(span).is_some_and(|s| s != span)
                {
                    bail!("two halt_loop symbols");
                }
            }
            p if p.ends_with("::sched::idle_thread_entry")
                || p.ends_with("::cpu::halt_until_interrupt") =>
            {
                idle.push(span);
            }
            _ =>
            {}
        }
    }
    let halt_loop = halt_loop.context("no halt_loop symbol (is it inlined?)")?;
    if idle.is_empty()
    {
        bail!("no idle_thread_entry symbol");
    }
    Ok(Image { halt_loop, idle })
}

/// A demangled symbol name without the legacy mangling's `::h<16 hex>` hash.
fn function_path(name: &str) -> &str
{
    match name.rsplit_once("::h")
    {
        Some((path, hash)) if hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            path
        }
        _ => name,
    }
}

/// `value` as GDB register bytes: little-endian, two hex digits a byte.
fn le_hex(value: u64) -> String
{
    let mut hex = String::with_capacity(16);
    for b in value.to_le_bytes()
    {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Bytes from GDB hex digits.
fn from_hex(hex: &[u8]) -> Result<Vec<u8>>
{
    if hex.len() % 2 != 0
    {
        bail!("odd hex length {}", hex.len());
    }
    hex.chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).context("non-ASCII hex")?;
            u8::from_str_radix(digits, 16).with_context(|| format!("bad hex `{digits}`"))
        })
        .collect()
}

/// A little-endian 64-bit value from a register reply.
fn le_u64(hex: &[u8]) -> Result<u64>
{
    let bytes = from_hex(hex)?;
    let array: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("a {}-byte register, not 8", bytes.len()))?;
    Ok(u64::from_le_bytes(array))
}

/// QEMU's gdbstub over its unix socket, in the protocol's acknowledged mode.
struct Stub
{
    stream: UnixStream,
    reader: PacketReader<PACKET_SIZE>,
}

impl Stub
{
    fn connect(path: &Path) -> Result<Self>
    {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connecting to the gdbstub at {}", path.display()))?;
        stream.set_read_timeout(Some(ANSWER_TIMEOUT))?;
        Ok(Self {
            stream,
            reader: PacketReader::new(),
        })
    }

    /// Send `body` and return the reply's body, acknowledging it.
    fn request(&mut self, body: &[u8]) -> Result<Vec<u8>>
    {
        let mut buf = vec![0u8; 2 * PACKET_SIZE];
        let mut w = PacketWriter::new(&mut buf);
        w.bytes(body);
        let len = w
            .finish()
            .map_err(|e| anyhow::anyhow!("packet past the buffer: {e:?}"))?;
        let packet = buf.get(..len).context("packet length past the buffer")?;
        let what = String::from_utf8_lossy(body).into_owned();
        self.stream
            .write_all(packet)
            .with_context(|| format!("sending `{what}`"))?;
        let mut byte = [0u8; 1];
        loop
        {
            let n = self
                .stream
                .read(&mut byte)
                .with_context(|| format!("reading the reply to `{what}`"))?;
            if n == 0
            {
                bail!("the gdbstub closed the connection before replying to `{what}`");
            }
            match self.reader.push(byte[0])
            {
                None | Some(Event::Ack) =>
                {}
                Some(Event::Nack) => self.stream.write_all(packet)?,
                Some(Event::Packet(reply)) =>
                {
                    let reply = reply.to_vec();
                    self.stream.write_all(b"+")?;
                    if reply.first() == Some(&b'E') && reply.len() == 3
                    {
                        bail!(
                            "the gdbstub refused `{what}`: {}",
                            String::from_utf8_lossy(&reply)
                        );
                    }
                    return Ok(reply);
                }
                Some(other) => bail!("unexpected {other:?} replying to `{what}`"),
            }
        }
    }

    fn expect_ok(&mut self, body: &[u8]) -> Result<()>
    {
        let reply = self.request(body)?;
        if reply != b"OK"
        {
            bail!(
                "`{}` answered {:?}, not OK",
                String::from_utf8_lossy(body),
                String::from_utf8_lossy(&reply)
            );
        }
        Ok(())
    }

    fn read_register(&mut self, regnum: usize) -> Result<u64>
    {
        let reply = self.request(format!("p{regnum:x}").as_bytes())?;
        le_u64(&reply).with_context(|| format!("register {regnum}"))
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>>
    {
        let reply = self.request(format!("m{addr:x},{len:x}").as_bytes())?;
        from_hex(&reply).with_context(|| format!("memory at {addr:#x}"))
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn lines(text: &str) -> Vec<String>
    {
        text.lines().map(str::to_owned).collect()
    }

    const BOOT_LOG: &str = "\
[--------] kernel: kaslr: slide=0x1f200000 image_base=0xffffffff9f200000 dm_base=0xff00000000000000
[0.010000] kernel: smp: starting 3 AP(s); BSP is CPU 0 (hardware id 0x2)
[0.020000] kernel: smp: AP 1 (hardware id 0x0) online
[0.030000] kernel: smp: AP 2 (hardware id 0x1) online
[0.040000] kernel: smp: AP 3 (hardware id 0x3) online
terminal: READY for injection";

    #[test]
    fn the_boot_lines_give_the_slide_and_the_cpu_map()
    {
        let boot = parse_boot(&lines(BOOT_LOG)).unwrap();
        assert_eq!(boot.slide, 0x1f20_0000);
        assert_eq!(boot.cpus, [(0, 2), (1, 0), (2, 1), (3, 3)]);
    }

    #[test]
    fn a_boot_without_the_layout_or_the_bsp_line_is_refused()
    {
        parse_boot(&lines(
            "smp: starting 1 AP(s); BSP is CPU 0 (hardware id 0x0)",
        ))
        .unwrap_err();
        parse_boot(&lines("kaslr: slide=0x0 image_base=0x0")).unwrap_err();
    }

    #[test]
    fn register_values_round_trip_little_endian()
    {
        let v = 0xffff_ffff_8012_3456;
        assert_eq!(le_hex(v), "56341280ffffffff");
        assert_eq!(le_u64(le_hex(v).as_bytes()).unwrap(), v);
        le_u64(b"5634").unwrap_err();
        le_u64(b"zz34128000000000").unwrap_err();
        assert_eq!(from_hex(b"f4").unwrap(), [0xF4]);
        from_hex(b"f").unwrap_err();
    }

    #[test]
    fn the_legacy_hash_is_stripped_from_a_symbol()
    {
        assert_eq!(
            function_path("kernel::arch::x86_64::cpu::halt_loop::h0123456789abcdef"),
            "kernel::arch::x86_64::cpu::halt_loop"
        );
        assert_eq!(
            function_path("kernel::sched::helper"),
            "kernel::sched::helper"
        );
        assert_eq!(function_path("a::hxyz"), "a::hxyz");
    }

    fn image() -> Image
    {
        Image {
            halt_loop: Span {
                start: 0x1000,
                end: 0x1010,
            },
            idle: vec![Span {
                start: 0x2000,
                end: 0x2100,
            }],
        }
    }

    #[test]
    fn only_a_cpu_just_past_the_idle_halt_is_moved()
    {
        let img = image();
        let slide = 0x10_0000;
        let hlt = halt_instruction(Arch::X86_64);
        assert!(is_idle_halt(&img, slide, 0x10_2042, &[0xF4], hlt));
        // Past a different instruction, or outside the idle loop.
        assert!(!is_idle_halt(&img, slide, 0x10_2042, &[0x90], hlt));
        assert!(!is_idle_halt(&img, slide, 0x10_1008, &[0xF4], hlt));
        // The slide is applied: the link address itself is not the idle loop.
        assert!(!is_idle_halt(&img, slide, 0x2042, &[0xF4], hlt));
        let wfi = halt_instruction(Arch::Riscv64);
        assert!(is_idle_halt(
            &img,
            0,
            0x2044,
            &[0x73, 0x00, 0x50, 0x10],
            wfi
        ));
        assert!(!is_idle_halt(
            &img,
            0,
            0x2044,
            &[0x73, 0x00, 0x00, 0x10],
            wfi
        ));
    }

    const HALT_LOOP: Span = Span {
        start: 0xffff_ffff_8010_0000,
        end: 0xffff_ffff_8010_0010,
    };

    #[test]
    fn an_x86_ap_report_needs_the_wedged_cpus_frame_first()
    {
        let report = lines(
            "kernel-nmi: NMI BACKTRACE: cpu=3 rip=0xffffffff80100004 rsp=0x0 rbp=0x0 cs=0x8 rflags=0x2
kernel: watchdog: cpu3 timer heartbeat stalled (last=1 now=9000 own_frame=true)
kernel: === WATCHDOG: AP timer heartbeat stalled ===
kernel: === END WATCHDOG ===",
        );
        check_report(Arch::X86_64, Victim::Ap, 3, &report, HALT_LOOP).unwrap();
        // Another CPU named, or the frame outside halt_loop.
        assert!(check_report(Arch::X86_64, Victim::Ap, 2, &report, HALT_LOOP).is_err());
        let elsewhere = Span {
            start: 0x1000,
            end: 0x2000,
        };
        assert!(check_report(Arch::X86_64, Victim::Ap, 3, &report, elsewhere).is_err());
        // The frame after the observer's line, or missing.
        let mut late = report.clone();
        late.swap(0, 1);
        assert!(check_report(Arch::X86_64, Victim::Ap, 3, &late, HALT_LOOP).is_err());
        assert!(check_report(Arch::X86_64, Victim::Ap, 3, &report[1..], HALT_LOOP).is_err());
    }

    #[test]
    fn a_riscv_bsp_report_is_the_observers_alone()
    {
        let report = lines(
            "kernel: watchdog: cpu2 observes BSP heartbeat stalled (bsp=5 now=9000 own_frame=false)
kernel: === WATCHDOG: BSP timer heartbeat stalled — sleep wakeups and BSP detectors dead ===
kernel: === END WATCHDOG ===",
        );
        check_report(Arch::Riscv64, Victim::Bsp, 0, &report, HALT_LOOP).unwrap();
        // The AP detector's report does not pass for the BSP's.
        assert!(check_report(Arch::Riscv64, Victim::Ap, 0, &report, HALT_LOOP).is_err());
        // An x86-64 report needs the frame this one lacks.
        assert!(check_report(Arch::X86_64, Victim::Bsp, 0, &report, HALT_LOOP).is_err());
    }
}
