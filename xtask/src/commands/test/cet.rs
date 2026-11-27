// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/cet.rs

//! CET supervisor shadow-stack test (#1083): the `x86_64` kernel runs on
//! shadow stacks when the CPU offers them and its transient-execution
//! selection rewrites no return, and a corrupted kernel return address raises
//! a control-protection fault instead of being followed
//! (core/kernel/docs/return-address-integrity.md).
//!
//! Neither the CI runners nor TCG emulate CET, so only a host whose CPU has
//! CET shadow stacks (`CET_SS`) and enhanced or Automatic IBRS, under KVM,
//! can run the enabled path: without either IBRS the kernel takes the
//! retpoline sequence and keeps shadow stacks off, and the case fails,
//! naming that cause. The
//! guest CPU is `-cpu host,cet-ss=on,enforce`: QEMU refuses to start when KVM
//! cannot give the guest the feature, and the case then fails, naming
//! it. It never passes on a host that did not run the shadow stacks. Every
//! other launch pins the feature off, or runs a QEMU that cannot offer it
//! ([`X86ShadowStack`]), so this case is where shadow stacks are
//! booted: the cet cell (docs/testing.md "Coverage tiers").
//!
//! Two boots of the current sysroot, which must hold the composed ktest
//! bundle (`cargo xtask mkdisk --harness ktest`):
//!
//! 1. ktest runs to its pass marker, and the kernel reports
//!    `shadow stacks: on` before it.
//! 2. With QEMU's gdbstub on a unix socket, the host sets a hardware
//!    breakpoint at `syscall::dispatch`, and at the first hit overwrites the
//!    return address at the stopped CPU's stack pointer, which the shadow
//!    stack also holds, then resumes. The `ret` of that `dispatch` must raise
//!    `#CP` (vector 21) with error code 1 (`NEAR-RET`) at an address inside
//!    `dispatch`. A call that does not return (a thread that exits or stays
//!    blocked) leaves no fault, so the host tries again, up to
//!    [`CORRUPT_ATTEMPTS`] times.
//!
//! The kernel carries no test code for either boot: the fault is made at the
//! hardware boundary, as the `wedge` case makes its wedge.
//!
//! A boot whose kernel faults with `CR4.CET` set, `SH_STK_EN` clear and a
//! zero interrupt SSP table address in its exception report, a state the
//! kernel never leaves, ran on a host that lost the guest's CET state. On a
//! host that is itself a guest of another hypervisor (the CPUID hypervisor
//! bit), where that state can be lost at run time, such a run is
//! inconclusive: the boot runs again, up to [`CET_ATTEMPTS`] times, and
//! passes only on a run without it. On any other host it fails
//! (core/kernel/docs/return-address-integrity.md § Verification Record).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::error::{Context as _, Result, bail};
use object::{Object as _, ObjectSymbol as _, SymbolKind};

use crate::accel::{self, Accel};
use crate::arch::Arch;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::guest::Guest;
use crate::qemu::{
    Firmware, GdbMode, InterruptRemapping, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr,
    X86Paging, X86ShadowStack, build_qemu_argv, validate_sysroot_for_launch,
};
use crate::qemu_gdb::{Span, Stub, field_hex, function_path, stop_thread};
use crate::socket_dir::SocketDir;
use crate::util::{require_tool, step};

/// The kernel's line once shadow stacks are on (`kernel_entry_post_rebase`).
const ON_MARKER: &str = "shadow stacks: on";
/// The kernel's line when the CPU reports `CET_SS` but the
/// transient-execution selection keeps shadow stacks off
/// (`shadow_stack::decide`).
const OFF_MARKER: &str = "shadow stacks: off";

/// The kernel's serial-only layout line.
const KASLR_MARKER: &str = "kaslr: slide=";

/// ktest's first line, by which the system is making system calls.
const KTEST_STARTED: &str = "ktest: starting";

/// ktest's terminal pass marker, and the lines that end a boot as a failure.
const PASS_MARKER: &str = "[ktest] ALL TESTS PASSED";
const FAIL_MARKERS: [&str; 4] = ["SOME TESTS FAILED", "KERNEL EXCEPTION", "FATAL:", "PANIC"];

/// The kernel's exception report line and the fault the test expects.
const EXCEPTION_MARKER: &str = "KERNEL EXCEPTION";
const CP_NEAR_RET: &str = "(vec=21 err=0x1)";

/// The line that ends the kernel's exception report (`crate::fatal`).
const FATAL_MARKER: &str = "FATAL:";

/// The exception report's CET line, which the kernel prints while `CR4.CET`
/// is set (`shadow_stack::report_registers`), and its two fields read here.
const CET_LINE: &str = "cet: s_cet=";
const S_CET_FIELD: &str = "s_cet=";
const SSP_TABLE_FIELD: &str = "int_ssp_table=";

/// `IA32_S_CET.SH_STK_EN` (bit 0): supervisor shadow stacks on.
const S_CET_SH_STK_EN: u64 = 1;

/// How many times each boot runs while every run ends with the host having
/// lost the guest's CET state ([`Attempt::HostLostCetState`]).
const CET_ATTEMPTS: u32 = 4;

/// Budget for boot 1's ktest run, and for boot 2 to reach ktest.
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget for one gdbstub reply, the breakpoint's hit included.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// How many corrupted returns the host makes, and how long it waits after
/// each for the fault.
const CORRUPT_ATTEMPTS: u32 = 5;
const FAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The `x86_64` GDB register numbers of the stack and program counters.
const RSP: usize = 7;
const RIP: usize = 16;

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    let accel = accel::detect_for_arch(Arch::X86_64);
    if accel != Accel::Kvm
    {
        bail!(
            "the cet case needs KVM: CET shadow stacks reach a guest only from the host CPU, and this \
             host's accelerator is {}",
            accel.name()
        );
    }
    validate_sysroot_for_launch(ctx, Arch::X86_64)?;
    let kernel_path = ctx.sysroot_efi_seraph().join("kernel");
    let kernel = std::fs::read(&kernel_path)
        .with_context(|| format!("reading {}", kernel_path.display()))?;
    let dispatch = dispatch_span(&kernel)
        .with_context(|| format!("finding syscall::dispatch in {}", kernel_path.display()))?;
    // Held until the case returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;

    let host = this_host();
    retry(host, || ktest_boot(ctx, args)).context("boot 1, ktest on shadow stacks")?;
    step("CET boot 1: ktest passed with shadow stacks on");
    retry(host, || corrupt_boot(ctx, args, dispatch))
        .context("boot 2, a corrupted return address")?;
    step("CET shadow-stack test: PASS (ktest on shadow stacks; #CP on a corrupted return)");
    Ok(())
}

/// How a boot that did not fail ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attempt
{
    /// Every check of the boot passed.
    Passed,
    /// The kernel faulted after the host lost the guest's CET state
    /// ([`lost_cet_state`]): the run says nothing about the kernel.
    HostLostCetState,
}

/// Whether the machine this case runs on is itself a guest of another
/// hypervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Host
{
    /// The CPUID hypervisor bit is set.
    Guest,
    /// It is clear.
    NotGuest,
}

/// Run `boot` until it passes, up to [`CET_ATTEMPTS`] times while each run
/// ends in [`Attempt::HostLostCetState`] on a [`Host::Guest`], where a
/// guest's CET state can be lost at run time
/// (core/kernel/docs/return-address-integrity.md § Verification Record). It
/// passes only on a run with no such end. On a [`Host::NotGuest`] the same
/// end is a failure.
fn retry(host: Host, mut boot: impl FnMut() -> Result<Attempt>) -> Result<()>
{
    for attempt in 1..=CET_ATTEMPTS
    {
        match boot()?
        {
            Attempt::Passed => return Ok(()),
            Attempt::HostLostCetState if host == Host::NotGuest => bail!(
                "the kernel faulted with CR4.CET set and IA32_S_CET and the interrupt SSP table \
                 address 0, which the kernel never leaves, on a host that is not itself a guest \
                 (no CPUID hypervisor bit)"
            ),
            Attempt::HostLostCetState => step(&format!(
                "Inconclusive run {attempt} of {CET_ATTEMPTS}: this nested host lost the guest's \
                 CET state (IA32_S_CET and the interrupt SSP table address 0); booting again"
            )),
        }
    }
    bail!(
        "inconclusive: this nested host lost the guest's CET state in all {CET_ATTEMPTS} runs, \
         and the test passes only on a run in which it does not"
    )
}

/// Whether the kernel exception reports in `lines` show CET state lost
/// outside the kernel: at least one CET line, and every CET line with
/// `SH_STK_EN` clear and a zero interrupt SSP table address. The kernel
/// writes a non-zero table address before it sets `CR4.CET` and writes
/// `IA32_S_CET` only with `SH_STK_EN` set, so it never leaves that state
/// itself (core/kernel/docs/return-address-integrity.md § x86-64 Mechanism);
/// a report with any other CET state is the kernel's fault.
fn lost_cet_state(lines: &[String]) -> bool
{
    let mut seen = false;
    for line in lines.iter().filter(|l| l.contains(CET_LINE))
    {
        let (Some(s_cet), Some(table)) = (
            field_hex(line, S_CET_FIELD),
            field_hex(line, SSP_TABLE_FIELD),
        )
        else
        {
            return false;
        };
        if s_cet & S_CET_SH_STK_EN != 0 || table != 0
        {
            return false;
        }
        seen = true;
    }
    seen
}

/// The machine this case runs on, by the CPUID hypervisor bit
/// (`CPUID.1:ECX[31]`).
#[cfg(target_arch = "x86_64")]
fn this_host() -> Host
{
    if std::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0
    {
        Host::Guest
    }
    else
    {
        Host::NotGuest
    }
}

/// A host that is not `x86_64` runs no KVM `x86_64` guest, so `run` stops
/// before this matters.
#[cfg(not(target_arch = "x86_64"))]
fn this_host() -> Host
{
    Host::NotGuest
}

/// `lines`, which end in a kernel exception report's first line, with the
/// rest of that report: the lines up to its `FATAL:` line, or none when it
/// does not come within [`FAULT_TIMEOUT`].
fn with_report(guest: &mut Guest, mut lines: Vec<String>) -> Vec<String>
{
    if lines.last().is_some_and(|l| l.contains(EXCEPTION_MARKER))
    {
        lines.extend(
            guest
                .collect_until(FATAL_MARKER, FAULT_TIMEOUT)
                .unwrap_or_default(),
        );
    }
    lines
}

/// A QEMU on the current sysroot with shadow stacks on, its stderr kept in a
/// file so a refused feature can be named.
struct Launch
{
    guest: Guest,
    stderr: PathBuf,
}

impl Launch
{
    /// The failure for `err`: QEMU's refusal of the feature when it printed
    /// one, otherwise `err` with the stderr QEMU wrote.
    fn explain(&self, err: crate::error::Error) -> crate::error::Error
    {
        let qemu = std::fs::read_to_string(&self.stderr).unwrap_or_default();
        match refusal(&qemu)
        {
            Some(line) => crate::error::err!(
                "the host cannot give the guest CET shadow stacks (QEMU: {line}); the cet case \
                 needs a CPU with CET_SS and a KVM that passes it through"
            ),
            None if qemu.trim().is_empty() => err,
            None => err.context(format!("QEMU stderr:\n{}", qemu.trim_end())),
        }
    }
}

fn launch(ctx: &Context, args: &CaseArgs, gdb: GdbMode<'_>, name: &str) -> Result<Launch>
{
    let firmware = Firmware::prepare(ctx, Arch::X86_64)?;
    let vars = firmware.launch_vars()?;
    let disk_path = ctx.disk_image();
    let dir = ctx.target_dir.join("xtask");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let stderr = dir.join(format!("cet-{name}-{}.stderr", std::process::id()));
    let block_size = crate::disk::logical_block_size(&disk_path)?;
    let qemu_args = build_qemu_argv(&cet_spec(
        &disk_path,
        block_size,
        &firmware.code,
        vars.path(),
        args,
        gdb,
        InterruptRemapping::for_sysroot(ctx),
    ))?;
    let qemu_binary = require_tool(Arch::X86_64.qemu_binary())?;
    let stderr_file =
        std::fs::File::create(&stderr).with_context(|| format!("creating {}", stderr.display()))?;
    let child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .with_context(|| format!("spawning {}", Arch::X86_64.qemu_binary()))?;
    Ok(Launch {
        guest: Guest::from_child(child)?.holding(vars),
        stderr,
    })
}

/// The launch of both boots: the composed system on a guest CPU with shadow
/// stacks on.
fn cet_spec<'a>(
    disk_path: &'a Path,
    disk_block_size: u32,
    firmware_code: &'a Path,
    firmware_vars: &'a Path,
    args: &CaseArgs,
    gdb: GdbMode<'a>,
    interrupt_remapping: InterruptRemapping,
) -> QemuLaunchSpec<'a>
{
    QemuLaunchSpec {
        arch: Arch::X86_64,
        disk_path,
        disk_block_size,
        second_disk: None,
        firmware_code_path: firmware_code,
        firmware_vars_path: firmware_vars,
        smm: false,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb,
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        idle_wait: crate::qemu::IdleWait::Off,
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::On,
        iommu: Iommu::Attached,
        interrupt_remapping,
        debug_port: None,
        test_devices: false,
        hotplug_port: None,
    }
}

/// Boot 1: ktest to its pass marker, on shadow stacks.
fn ktest_boot(ctx: &Context, args: &CaseArgs) -> Result<Attempt>
{
    step("Launching QEMU for the CET ktest boot");
    let mut run = launch(ctx, args, GdbMode::Off, "ktest")?;
    let mut ends = vec![PASS_MARKER];
    ends.extend(FAIL_MARKERS);
    let result = match run.guest.collect_until_any(&ends, BOOT_TIMEOUT)
    {
        Err(e) => Err(run.explain(e)),
        Ok(lines) =>
        {
            let lines = with_report(&mut run.guest, lines);
            if lost_cet_state(&lines)
            {
                Ok(Attempt::HostLostCetState)
            }
            else
            {
                check_ktest(&lines).map(|()| Attempt::Passed)
            }
        }
    };
    let stderr = run.stderr.clone();
    run.guest.shutdown();
    let _ = std::fs::remove_file(stderr);
    result
}

/// Boot 2: corrupt a `dispatch` return address and expect the `#CP`.
fn corrupt_boot(ctx: &Context, args: &CaseArgs, dispatch: Span) -> Result<Attempt>
{
    // Declared before the launch, so it is removed after QEMU is reaped.
    let sockets = SocketDir::create()?;
    let sock = sockets.socket("cet.gdb")?;
    step(&format!(
        "Launching QEMU for the CET corruption boot (gdbstub on {})",
        sock.display()
    ));
    let mut run = launch(ctx, args, GdbMode::Unix(&sock), "corrupt")?;
    let result = (|| {
        let lines = run
            .guest
            .collect_until_any(&[KTEST_STARTED, EXCEPTION_MARKER], BOOT_TIMEOUT)
            .map_err(|e| run.explain(e))?;
        let lines = with_report(&mut run.guest, lines);
        if lost_cet_state(&lines)
        {
            return Ok(Attempt::HostLostCetState);
        }
        let slide = check_started(&lines)?;
        let span = dispatch.slid(slide);
        for attempt in 1..=CORRUPT_ATTEMPTS
        {
            let (cpu, from) = corrupt_one_return(&sock, span.start)?;
            step(&format!(
                "Corrupted the return address {from:#x} of syscall::dispatch on gdb thread \
                 {cpu} (attempt {attempt}); waiting for #CP"
            ));
            let Ok(report) = run
                .guest
                .collect_until_any(&[EXCEPTION_MARKER], FAULT_TIMEOUT)
            else
            {
                continue;
            };
            let rest = run.guest.collect_until(FATAL_MARKER, FAULT_TIMEOUT)?;
            if lost_cet_state(&rest)
            {
                return Ok(Attempt::HostLostCetState);
            }
            let rip = rest.iter().find(|l| l.contains("rip="));
            return check_fault(report.last().map(String::as_str), rip, span)
                .map(|()| Attempt::Passed);
        }
        bail!("no #CP in {CORRUPT_ATTEMPTS} corrupted returns of syscall::dispatch")
    })();
    let stderr = run.stderr.clone();
    run.guest.shutdown();
    let _ = std::fs::remove_file(stderr);
    result
}

/// Stop the VM at the next `dispatch` entry (`at`), overwrite the return
/// address at that CPU's stack pointer, and resume. Returns the GDB thread
/// that stopped and the address overwritten.
fn corrupt_one_return(sock: &Path, at: u64) -> Result<(u64, u64)>
{
    // Connecting stops the VM; detaching resumes it.
    let mut stub = Stub::connect(sock, ANSWER_TIMEOUT)?;
    stub.request(b"?")?;
    stub.expect_ok(format!("Z1,{at:x},1").as_bytes())?;
    let stop = stub.request(b"c")?;
    let thread = stop_thread(&stop).with_context(|| {
        format!(
            "the stop reply `{}` names no thread",
            String::from_utf8_lossy(&stop)
        )
    })?;
    stub.expect_ok(format!("Hg{thread:x}").as_bytes())?;
    // Reading the whole register block has QEMU fetch the CPU's state from
    // KVM; the single-register reads below would otherwise be stale.
    stub.request(b"g")?;
    let pc = stub.read_register(RIP)?;
    if pc != at
    {
        bail!("the VM stopped at {pc:#x}, not at syscall::dispatch ({at:#x})");
    }
    let rsp = stub.read_register(RSP)?;
    let from = stub.read_u64(rsp)?;
    stub.write_u64(rsp, corrupted(from))?;
    stub.expect_ok(format!("z1,{at:x},1").as_bytes())?;
    stub.expect_ok(b"D")?;
    Ok((thread, from))
}

/// The value written over a return address: one 16 bytes off, still in the
/// caller's code, which the ordinary stack alone would follow.
fn corrupted(ret: u64) -> u64
{
    ret ^ 0x10
}

/// The line of QEMU's stderr that refuses the shadow-stack feature, if any.
fn refusal(stderr: &str) -> Option<&str>
{
    stderr.lines().find(|l| l.contains("cet-ss")).map(str::trim)
}

/// Why the kernel did not turn shadow stacks on, from its lines: its own
/// `shadow stacks: off` line, which names the transient-execution selection
/// that keeps them off on a CPU reporting `CET_SS`, or else a guest CPU that
/// does not report `CET_SS`.
fn not_on(lines: &[String]) -> String
{
    match lines.iter().find(|l| l.contains(OFF_MARKER))
    {
        Some(off) => format!(
            "the kernel kept shadow stacks off: {}; the host needs enhanced or Automatic IBRS \
             as well as CET_SS",
            off.trim()
        ),
        None => format!(
            "the kernel did not turn shadow stacks on (no `{ON_MARKER}` line): the guest CPU \
             does not report CET_SS"
        ),
    }
}

/// Boot 1's verdict on its lines, the last of them the end marker.
fn check_ktest(lines: &[String]) -> Result<()>
{
    let on = lines.iter().position(|l| l.contains(ON_MARKER));
    let last = lines.last().map_or("", String::as_str);
    if on.is_none()
    {
        bail!("{}", not_on(lines));
    }
    if !last.contains(PASS_MARKER)
    {
        bail!("ktest did not pass on shadow stacks: {last}");
    }
    Ok(())
}

/// Boot 2's lines up to ktest's start: shadow stacks on, no fault yet, and
/// the KASLR slide.
fn check_started(lines: &[String]) -> Result<u64>
{
    if !lines.iter().any(|l| l.contains(ON_MARKER))
    {
        bail!("{}", not_on(lines));
    }
    if let Some(fault) = lines.iter().find(|l| l.contains(EXCEPTION_MARKER))
    {
        bail!("the kernel faulted before ktest started: {fault}");
    }
    lines
        .iter()
        .find_map(|l| field_hex(l, KASLR_MARKER))
        .context("no `kaslr: slide=` line before ktest started")
}

/// Boot 2's verdict: a `#CP` with the near-return error code, at a `rip`
/// inside `dispatch` (its runtime span).
fn check_fault(exception: Option<&str>, rip_line: Option<&String>, dispatch: Span) -> Result<()>
{
    let exception = exception.unwrap_or("");
    if !exception.contains(CP_NEAR_RET)
    {
        bail!("the fault is not a near-return #CP `{CP_NEAR_RET}`: {exception}");
    }
    let rip = rip_line
        .and_then(|l| field_hex(l, "rip="))
        .context("the exception report has no rip")?;
    if !dispatch.contains(rip)
    {
        bail!(
            "the #CP rip {rip:#x} is outside syscall::dispatch ({:#x}..{:#x})",
            dispatch.start,
            dispatch.end
        );
    }
    Ok(())
}

/// `syscall::dispatch` in the kernel's symbol table.
fn dispatch_span(data: &[u8]) -> Result<Span>
{
    let file = object::File::parse(data).context("parsing the kernel ELF")?;
    let mut found = None;
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
        let name = crate::symbolize::demangle(raw);
        if function_path(&name) == "kernel::syscall::dispatch"
        {
            let span = Span {
                start: sym.address(),
                end: sym.address().saturating_add(sym.size()),
            };
            if found.replace(span).is_some_and(|s| s != span)
            {
                bail!("two syscall::dispatch symbols");
            }
        }
    }
    found.context("no syscall::dispatch symbol (is it inlined?)")
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn lines(text: &str) -> Vec<String>
    {
        text.lines().map(str::to_owned).collect()
    }

    // The defect caught: a launch that leaves shadow stacks at the launchers'
    // default (off), so the guest boots without them and the test checks
    // nothing.
    #[test]
    fn both_boots_ask_for_shadow_stacks()
    {
        let args = CaseArgs::default();
        let spec = cet_spec(
            Path::new("disk.img"),
            512,
            Path::new("code.fd"),
            Path::new("vars.fd"),
            &args,
            GdbMode::Off,
            InterruptRemapping::Withheld,
        );
        assert_eq!(spec.x86_shadow_stack, X86ShadowStack::On);
        assert_eq!(spec.arch, Arch::X86_64);
    }

    // The defect caught: a host that cannot enforce the feature passing, or
    // failing without naming what it lacks.
    #[test]
    fn a_host_without_the_feature_fails_naming_it()
    {
        let qemu = "qemu-system-x86_64: warning: host doesn't support requested feature: \
                    CPUID[eax=07h,ecx=00h].ECX.cet-ss [bit 7]\n\
                    qemu-system-x86_64: Host doesn't support requested features\n";
        assert!(refusal(qemu).unwrap().contains("cet-ss"));
        assert_eq!(refusal("qemu-system-x86_64: some other warning"), None);
        let off = lines(
            "kernel: tagged-tlb ok\nkernel: syscall ok\n[0.1] ktest: starting\n[ktest] ALL TESTS \
             PASSED",
        );
        let err = check_ktest(&off).unwrap_err().to_string();
        assert!(err.contains("CET_SS"), "{err}");
    }

    // The defect caught: a CET host whose kernel kept shadow stacks off for the
    // retpoline sequence (no enhanced or Automatic IBRS) reported as a host
    // without CET_SS, which the kernel's own line contradicts.
    #[test]
    fn a_retpoline_selection_is_named_as_the_cause()
    {
        let off = lines(
            "kernel: shadow stacks: off, CET_SS reported but the retpoline sequence is selected
             [0.1] ktest: starting
[ktest] ALL TESTS PASSED",
        );
        for err in [
            check_ktest(&off).unwrap_err().to_string(),
            check_started(&off).unwrap_err().to_string(),
        ]
        {
            assert!(err.contains("retpoline"), "{err}");
            assert!(err.contains("enhanced or Automatic IBRS"), "{err}");
            assert!(!err.contains("does not report CET_SS"), "{err}");
        }
    }

    #[test]
    fn ktest_passes_only_on_shadow_stacks_and_its_pass_marker()
    {
        let on = lines("kernel: shadow stacks: on\n[1.0] [ktest] ALL TESTS PASSED");
        check_ktest(&on).unwrap();
        let failed = lines("kernel: shadow stacks: on\n[1.0] [ktest] SOME TESTS FAILED");
        check_ktest(&failed).unwrap_err();
        let fault = lines(
            "kernel: shadow stacks: on\nkernel: KERNEL EXCEPTION: cpu=2 cause=#CP control \
             protection (vec=21 err=0x4)",
        );
        check_ktest(&fault).unwrap_err();
    }

    const DISPATCH: Span = Span {
        start: 0xffff_ffff_c763_0d50,
        end: 0xffff_ffff_c763_1462,
    };

    // The defect caught: a fault of another kind, or at another place, taken
    // for the shadow stack's refusal of the corrupted return.
    #[test]
    fn only_a_near_return_cp_inside_dispatch_passes()
    {
        let cp = "kernel: KERNEL EXCEPTION: cpu=1 cause=#CP control protection (vec=21 err=0x1)";
        let inside = "kernel:   rip=0xffffffffc7631460  cr2=0x0000000000000000".to_owned();
        let outside = "kernel:   rip=0xffffffffc7631462  cr2=0x0000000000000000".to_owned();
        check_fault(Some(cp), Some(&inside), DISPATCH).unwrap();
        check_fault(Some(cp), Some(&outside), DISPATCH).unwrap_err();
        let gp = "kernel: KERNEL EXCEPTION: cpu=1 cause=#GP general protection (vec=13 err=0x0)";
        check_fault(Some(gp), Some(&inside), DISPATCH).unwrap_err();
        let rstorssp =
            "kernel: KERNEL EXCEPTION: cpu=1 cause=#CP control protection (vec=21 err=0x4)";
        check_fault(Some(rstorssp), Some(&inside), DISPATCH).unwrap_err();
        check_fault(Some(cp), None, DISPATCH).unwrap_err();
    }

    #[test]
    fn the_started_boot_gives_the_slide_once_shadow_stacks_are_on()
    {
        let started = lines(
            "kernel: kaslr: slide=0x47600000 image_base=0xffffffffc7600000\nkernel: shadow \
             stacks: on\n[0.17] ktest: starting",
        );
        assert_eq!(check_started(&started).unwrap(), 0x4760_0000);
        let off = lines("kernel: kaslr: slide=0x47600000 image\n[0.17] ktest: starting");
        check_started(&off).unwrap_err();
        let faulted = lines(
            "kernel: kaslr: slide=0x0 i\nkernel: shadow stacks: on\nkernel: KERNEL EXCEPTION: x",
        );
        check_started(&faulted).unwrap_err();
    }

    const LOST: &str = "kernel:   cet: s_cet=0x0  int_ssp_table=0x0000000000000000  \
                        pl0_ssp=0x0000000000000000";
    const HEALTHY: &str = "kernel:   cet: s_cet=0x1  int_ssp_table=0xffffffffc7a41000  \
                           pl0_ssp=0x0000000000000000";
    const KERNEL_LEFT_OFF: &str = "kernel:   cet: s_cet=0x0  int_ssp_table=0xffffffffc7a41000  \
                                   pl0_ssp=0x0000000000000000";
    const UD: &str = "kernel: KERNEL EXCEPTION: cpu=3 cause=#UD invalid opcode (vec=6 err=0x0)";

    // The defect caught: a kernel fault taken for the host's loss of the
    // guest's CET state, so a kernel bug counts as inconclusive. Only the
    // state the kernel never leaves (SH_STK_EN clear and a zero table
    // address, in every report) is the host's.
    #[test]
    fn only_cleared_s_cet_and_table_is_the_hosts_loss()
    {
        let report = |cet: &str| lines(&format!("{UD}\nkernel:   rip=0x1  cr2=0x0\n{cet}"));
        assert!(lost_cet_state(&report(LOST)));
        assert!(!lost_cet_state(&report(HEALTHY)));
        assert!(!lost_cet_state(&report(KERNEL_LEFT_OFF)));
        let table_only = "kernel:   cet: s_cet=0x1  int_ssp_table=0x0000000000000000  pl0_ssp=0x0";
        assert!(!lost_cet_state(&report(table_only)));
        // No CET line: CR4.CET was clear, or the report did not arrive.
        assert!(!lost_cet_state(&lines(UD)));
        // Two CPUs' reports, one of them a kernel fault.
        assert!(!lost_cet_state(&lines(&format!(
            "{UD}\n{LOST}\n{UD}\n{HEALTHY}"
        ))));
        assert!(lost_cet_state(&lines(&format!(
            "{UD}\n{LOST}\n{UD}\n{LOST}"
        ))));
        let unreadable = "kernel:   cet: s_cet=zz  int_ssp_table=0x0  pl0_ssp=0x0";
        assert!(!lost_cet_state(&report(unreadable)));
    }

    /// Run `retry` over `ends`, returning its verdict and how many boots it
    /// made.
    fn retried(host: Host, ends: &[Result<Attempt, &str>]) -> (Result<()>, usize)
    {
        let mut boots = 0;
        let verdict = retry(host, || {
            let end = ends[boots];
            boots += 1;
            end.map_err(|e| crate::error::err!("{e}"))
        });
        (verdict, boots)
    }

    // The defect caught: an inconclusive run counted as a pass, retries
    // without bound, the host's loss forgiven on a host that is not a guest,
    // or a real failure retried away.
    #[test]
    fn a_lost_state_run_is_retried_only_on_a_guest_host_and_never_passes()
    {
        use Attempt::{HostLostCetState as Lost, Passed};

        let (verdict, boots) = retried(Host::Guest, &[Ok(Lost), Ok(Lost), Ok(Passed)]);
        verdict.unwrap();
        assert_eq!(boots, 3);

        let (verdict, boots) = retried(Host::Guest, &[Ok(Lost); CET_ATTEMPTS as usize]);
        assert!(verdict.unwrap_err().to_string().contains("inconclusive"));
        assert_eq!(boots, CET_ATTEMPTS as usize);

        let (verdict, boots) = retried(Host::NotGuest, &[Ok(Lost), Ok(Passed)]);
        assert!(
            verdict
                .unwrap_err()
                .to_string()
                .contains("not itself a guest")
        );
        assert_eq!(boots, 1);

        let (verdict, boots) = retried(Host::Guest, &[Ok(Lost), Err("ktest failed"), Ok(Passed)]);
        assert_eq!(verdict.unwrap_err().to_string(), "ktest failed");
        assert_eq!(boots, 2);
    }

    #[test]
    fn the_corrupted_return_differs_and_stays_near()
    {
        let ret = 0xffff_ffff_8005_63d2;
        assert_ne!(corrupted(ret), ret);
        assert_eq!(corrupted(ret) & !0xff, ret & !0xff);
    }
}
