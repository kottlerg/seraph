// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_cet.rs

//! CET supervisor shadow-stack test (#1083): the `x86_64` kernel runs on
//! shadow stacks when the CPU offers them, and a corrupted kernel return
//! address raises a control-protection fault instead of being followed
//! (core/kernel/docs/return-address-integrity.md).
//!
//! Neither the CI runners nor TCG emulate CET, so only a host whose CPU has
//! CET shadow stacks (`CET_SS`), under KVM, can run the enabled path. The
//! guest CPU is `-cpu host,cet-ss=on,enforce`: QEMU refuses to start when KVM
//! cannot give the guest the feature, and the command then fails, naming
//! it. It never passes on a host that did not run the shadow stacks.
//!
//! Two boots of the current sysroot, which must hold the composed ktest
//! bundle (`cargo xtask compose-bundle --harness ktest`):
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
//! hardware boundary, as `test-wedge` makes its wedge.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use object::{Object as _, ObjectSymbol as _, SymbolKind};

use crate::accel::{self, Accel};
use crate::arch::Arch;
use crate::cli::TestCetArgs;
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::guest::Guest;
use crate::qemu::{
    GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, X86Paging, build_qemu_argv,
    validate_sysroot_for_launch,
};
use crate::qemu_gdb::{Span, Stub, field_hex, function_path, stop_thread};
use crate::util::{require_tool, step};

/// The QEMU CPU properties that give the guest shadow stacks, or stop QEMU
/// from starting when the host cannot.
const CET_PROPERTIES: &str = ",cet-ss=on,enforce";

/// The kernel's line once shadow stacks are on (`kernel_entry_post_rebase`).
const ON_MARKER: &str = "shadow stacks: on";

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

pub fn run(ctx: &Context, args: &TestCetArgs) -> Result<()>
{
    let accel = accel::detect_for_arch(Arch::X86_64);
    if accel != Accel::Kvm
    {
        bail!(
            "test-cet needs KVM: CET shadow stacks reach a guest only from the host CPU, and this \
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
    // Held until the command returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;

    ktest_boot(ctx, args).context("boot 1, ktest on shadow stacks")?;
    step("CET boot 1: ktest passed with shadow stacks on");
    corrupt_boot(ctx, args, dispatch).context("boot 2, a corrupted return address")?;
    step("CET shadow-stack test: PASS (ktest on shadow stacks; #CP on a corrupted return)");
    Ok(())
}

/// A QEMU on the current sysroot with the CET properties, its stderr kept in
/// a file so a refused feature can be named.
struct Launch
{
    guest: Guest,
    stderr: PathBuf,
}

impl Launch
{
    /// The failure for `err`: QEMU's refusal of the feature when it printed
    /// one, otherwise `err` with the stderr QEMU wrote.
    fn explain(&self, err: anyhow::Error) -> anyhow::Error
    {
        let qemu = std::fs::read_to_string(&self.stderr).unwrap_or_default();
        match refusal(&qemu)
        {
            Some(line) => anyhow::anyhow!(
                "the host cannot give the guest CET shadow stacks (QEMU: {line}); test-cet needs \
                 a CPU with CET_SS and a KVM that passes it through"
            ),
            None if qemu.trim().is_empty() => err,
            None => err.context(format!("QEMU stderr:\n{}", qemu.trim_end())),
        }
    }
}

fn launch(ctx: &Context, args: &TestCetArgs, gdb: GdbMode<'_>, name: &str) -> Result<Launch>
{
    let firmware_code = find_ovmf_code()?;
    let disk_path = ctx.disk_image();
    let dir = ctx.target_dir.join("xtask");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let stderr = dir.join(format!("cet-{name}-{}.stderr", std::process::id()));
    let spec = QemuLaunchSpec {
        arch: Arch::X86_64,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: None,
        firmware_code_path: &firmware_code,
        firmware_vars_path: None,
        cpus: args.cpus,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb,
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
    let mut qemu_args = build_qemu_argv(&spec)?;
    with_cet(&mut qemu_args)?;
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
        guest: Guest::from_child(child)?,
        stderr,
    })
}

/// Boot 1: ktest to its pass marker, on shadow stacks.
fn ktest_boot(ctx: &Context, args: &TestCetArgs) -> Result<()>
{
    step("Launching QEMU for the CET ktest boot");
    let mut run = launch(ctx, args, GdbMode::Off, "ktest")?;
    let mut ends = vec![PASS_MARKER];
    ends.extend(FAIL_MARKERS);
    let result = run
        .guest
        .collect_until_any(&ends, BOOT_TIMEOUT)
        .map_err(|e| run.explain(e))
        .and_then(|lines| check_ktest(&lines));
    let stderr = run.stderr.clone();
    run.guest.shutdown();
    let _ = std::fs::remove_file(stderr);
    result
}

/// Boot 2: corrupt a `dispatch` return address and expect the `#CP`.
fn corrupt_boot(ctx: &Context, args: &TestCetArgs, dispatch: Span) -> Result<()>
{
    let sock = ctx
        .target_dir
        .join("xtask")
        .join(format!("cet-{}.gdb", std::process::id()));
    let _ = std::fs::remove_file(&sock);
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
            let rip = run.guest.collect_until("rip=", FAULT_TIMEOUT)?;
            return check_fault(report.last().map(String::as_str), rip.last(), span);
        }
        bail!("no #CP in {CORRUPT_ATTEMPTS} corrupted returns of syscall::dispatch")
    })();
    let stderr = run.stderr.clone();
    run.guest.shutdown();
    let _ = std::fs::remove_file(&sock);
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

/// `args` with the CET properties appended to its `-cpu` model.
fn with_cet(args: &mut [String]) -> Result<()>
{
    let model = args
        .iter_mut()
        .skip_while(|a| *a != "-cpu")
        .nth(1)
        .context("the QEMU command line has no -cpu model")?;
    model.push_str(CET_PROPERTIES);
    Ok(())
}

/// The line of QEMU's stderr that refuses the shadow-stack feature, if any.
fn refusal(stderr: &str) -> Option<&str>
{
    stderr.lines().find(|l| l.contains("cet-ss")).map(str::trim)
}

/// Boot 1's verdict on its lines, the last of them the end marker.
fn check_ktest(lines: &[String]) -> Result<()>
{
    let on = lines.iter().position(|l| l.contains(ON_MARKER));
    let last = lines.last().map_or("", String::as_str);
    if on.is_none()
    {
        bail!(
            "the kernel did not turn shadow stacks on (no `{ON_MARKER}` line): the guest CPU does \
             not report CET_SS"
        );
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
        bail!("the kernel did not turn shadow stacks on (no `{ON_MARKER}` line)");
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
        let name = addr2line::demangle_auto(std::borrow::Cow::Borrowed(raw), None);
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

    // The defect caught: a command line whose CPU model lacks the CET
    // properties, so the guest boots without shadow stacks and the test
    // checks nothing, or one that names them on the wrong option.
    #[test]
    fn the_cet_properties_go_on_the_cpu_model()
    {
        let mut args: Vec<String> = ["-enable-kvm", "-cpu", "host,la57=off", "-m", "512"]
            .map(String::from)
            .to_vec();
        with_cet(&mut args).unwrap();
        assert_eq!(args[2], "host,la57=off,cet-ss=on,enforce");
        assert_eq!(args[4], "512");
        let mut none: Vec<String> = vec!["-m".into(), "512".into()];
        with_cet(&mut none).unwrap_err();
        let mut cut: Vec<String> = vec!["-cpu".into()];
        with_cet(&mut cut).unwrap_err();
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

    #[test]
    fn the_corrupted_return_differs_and_stays_near()
    {
        let ret = 0xffff_ffff_8005_63d2;
        assert_ne!(corrupted(ret), ret);
        assert_eq!(corrupted(ret) & !0xff, ret & !0xff);
    }
}
