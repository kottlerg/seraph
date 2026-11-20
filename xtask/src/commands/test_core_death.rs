// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_core_death.rs

//! Core-death power-off test (#262): the death of a core service (memmgr,
//! procmgr, svcmgr), or the permanent death of a critical one (devmgr, vfsd,
//! logd), powers the system off (docs/supervision.md § Core Set and System
//! Death).
//!
//! Each target is killed by a terminal fault made from outside the guest, so
//! no service carries a test hook: the host moves one of the target's
//! threads to program counter 0, an address no process maps, and resumes it.
//! The thread's instruction fetch faults, and the fault is terminal. Two
//! routes reach the thread:
//!
//! - **The GDB stub service** (svcmgr, devmgr, vfsd, logd, which procmgr
//!   creates): the stub is staged naming the target, as `run --debug-target`
//!   stages it (`crate::debug_stub`), and attaches to it during the boot; the
//!   host connects over the debug port, moves the main thread, and detaches,
//!   which gives the target its crash bindings back. logd is killed at the
//!   stub's first attach, which can fall before logd asks svcmgr for its
//!   bootstrap round, and as it restarts, it is killed again, through the
//!   stub's attach to each new instance, until svcmgr's restart budget is
//!   spent. A first kill before logd's release of init-logd leaves init-logd
//!   serving the log endpoint, so the first restart must take the handover:
//!   the test waits for init-logd's last line before the second kill.
//! - **QEMU's own gdbstub** (memmgr and procmgr, which init creates with raw
//!   syscalls, so no debugger can attach to them): once the default boot is
//!   up, the host sets a hardware breakpoint on a function of the target's
//!   binary, at the image bias init logs for it plus the function's address
//!   in the symbol table, and has the terminal's shell run `/programs/hello`
//!   over the serial line, whose spawn and reap run the function. On the stop
//!   it checks that the code at the stopped program counter is the
//!   function's, since another process can map the same address, moves that
//!   CPU's program counter, removes the breakpoint, and resumes the VM.
//!
//! A boot passes when, after the kill, QEMU's `SHUTDOWN` event gives reason
//! `guest-shutdown` and QEMU exits on its own. One boot per target; the
//! stub's recipe is always removed again and the disk images repacked in the
//! layout they had.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build` with
//! the default boot set (terminal and shell) and a packed `disk.img`.

use std::io::Write as _;
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::arch::Arch;
use crate::breakpoint_kill;
use crate::cli::{CoreDeathTarget, TestCoreDeathArgs};
use crate::context::Context;
use crate::debug_stub;
use crate::disk::DiskLayout;
use crate::error::{Context as _, Result, bail};
use crate::firmware::find_ovmf_code;
use crate::guest::Guest;
use crate::qemu::{
    GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, SecondDisk, X86Paging,
    X86ShadowStack, build_qemu_argv, prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::qemu_gdb::{Stub, field_hex};
use crate::qmp;
use crate::util::{require_tool, step};

/// The terminal's line once the default boot is up. Kept in sync with
/// `programs/terminal`.
const READY_MARKER: &str = "terminal: READY for injection";

/// What the host types at the shell: a program whose spawn runs procmgr's
/// create and memmgr's allocation, and whose exit runs procmgr's reap.
const SERIAL_INPUT: &[u8] = b"hello\r";

/// The `SHUTDOWN` event's reason for a guest power-off.
const POWER_OFF_REASON: &str = "guest-shutdown";

/// Budget for the boot to reach the point of the kill.
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget from the kill to QEMU's exit.
const POWER_OFF_TIMEOUT: Duration = Duration::from_mins(2);

/// How long the guest's serial lines are still shown after a stub request
/// failed, for the stub's own lines on its refusal.
const STUB_FAILURE_ECHO: Duration = Duration::from_secs(8);

/// Budget for QEMU's exit once its serial stream has ended.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for one reply of the GDB stub service.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);

/// How the host reaches a target's thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route
{
    /// The GDB stub service, attached to the process of this name; the main
    /// thread is moved at the point the second field names, the host first
    /// asking for it once the boot shows the line the third names.
    Stub(&'static str, KillPoint, Contact),
    /// QEMU's gdbstub, with a hardware breakpoint on a function of the
    /// target's binary; the thread that runs it is moved.
    Hardware(Breakpoint),
}

/// When a target the stub holds is killed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KillPoint
{
    /// Once the stub has attached. svcmgr's: the stub stops every thread of
    /// its target, and the boot waits on svcmgr's launches to come up.
    Attach,
    /// Once the boot is up and svcmgr has reconciled its recipes: the death
    /// of a supervised service, after the window in which svcmgr still
    /// calls devmgr and vfsd during its launches, where a call to a server
    /// that died after svcmgr's check of it waits for good (#1185).
    SystemUp,
    /// As [`KillPoint::Attach`], then again after each restart svcmgr makes,
    /// until its restart budget is spent and the death is permanent. The
    /// first kill can fall before the target asks svcmgr for its bootstrap
    /// round, a death svcmgr routes as any other
    /// (`services/svcmgr/docs/restart-protocol.md` § Death detection).
    RestartsSpent,
}

/// The line the boot shows before the host first asks the stub for its
/// target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Contact
{
    /// The stub's attach marker, naming the target.
    Attached,
    /// svcmgr's line launching the target. The log sink's: the stub's lines
    /// reach the serial line through it, so a stub that attaches once the
    /// sink has taken the log over from init holds the process that would
    /// carry its marker, and the marker is lost.
    Launched,
}

/// The start of svcmgr's line as it launches a service. Kept in sync with
/// `services/svcmgr/src/definitions/reconcile.rs`.
const LAUNCHING_MARKER: &str = "svcmgr: launching: ";

/// Budget for the stub's answer to the host's first request: the stub
/// answers once its look for the target at its start has ended, which takes
/// up to 60 s with no such process yet (`services/gdbstub/src/main.rs`).
const FIRST_ANSWER_TIMEOUT: Duration = Duration::from_mins(2);

/// The start of svcmgr's line once it has restarted a service. Kept in sync
/// with `services/svcmgr/src/restart.rs`.
const RESTARTED_MARKER: &str = "service restarted: ";

/// The end of svcmgr's line when a service it launched from its recipe dies
/// before its bootstrap request, after `svcmgr: <name>`. Kept in sync with
/// `services/svcmgr/src/definitions/reconcile.rs`.
const BOOT_DEATH_MARKER: &str = " died during its bootstrap";

/// init-logd's last line, written once real-logd has pulled its history and
/// released it. Kept in sync with `services/init/src/logging.rs`.
const HANDOVER_MARKER: &str = "handover complete; init-logd thread exiting";

/// The pause after a kill before the stub is asked to attach again, so its
/// walk does not find the dying instance.
const REAP_PAUSE: Duration = Duration::from_secs(2);

/// pwrmgr's line once its power-off on a core death is armed: it observes the
/// core-death queue, holds the architecture's immediate power-off, and is
/// pinned, so the power-off after the kill runs with its allocation guard
/// armed and takes no page fault on memmgr. Kept in sync with
/// `services/pwrmgr/src/main.rs`.
const ARMED_MARKER: &str = "pwrmgr] core-death power-off armed";

/// svcmgr's line once its reconciliation has recorded every service. Kept in
/// sync with `services/svcmgr/src/main.rs`.
const RECONCILED_MARKER: &str = "service(s) after reconciliation";

/// A function of an init-created service, by which a hardware breakpoint
/// stops one of its threads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Breakpoint
{
    /// The binary, relative to the sysroot.
    binary: &'static str,
    /// The start of init's line naming the binary's image bias. Kept in sync
    /// with `services/init/src/bootstrap.rs`.
    bias_line: &'static str,
    /// The function's demangled path, without its hash.
    function: &'static str,
}

/// The route to `target`'s thread.
fn route(target: CoreDeathTarget) -> Route
{
    const MEMMGR_BIAS: &str = "init: memmgr image bias=";
    const PROCMGR_BIAS: &str = "init: procmgr image bias=";
    match target
    {
        // memmgr's receive loop, in the admission of an allocation the spawn
        // charges. A function the release build keeps out of line, as it
        // does not `memmgr::select`.
        CoreDeathTarget::Memmgr => Route::Hardware(Breakpoint {
            binary: "services/memmgr",
            bias_line: MEMMGR_BIAS,
            function: "memmgr::admit",
        }),
        // A request worker (the main thread is one), in the spawn's create.
        CoreDeathTarget::Procmgr => Route::Hardware(Breakpoint {
            binary: "services/procmgr",
            bias_line: PROCMGR_BIAS,
            function: "procmgr::handle_create",
        }),
        // The reaper thread, never the main thread, in the program's reap.
        CoreDeathTarget::ProcmgrReaper => Route::Hardware(Breakpoint {
            binary: "services/procmgr",
            bias_line: PROCMGR_BIAS,
            function: "procmgr::process::reap_dead",
        }),
        CoreDeathTarget::Svcmgr => Route::Stub("svcmgr", KillPoint::Attach, Contact::Attached),
        CoreDeathTarget::Devmgr => Route::Stub("devmgr", KillPoint::SystemUp, Contact::Attached),
        CoreDeathTarget::Vfsd => Route::Stub("vfsd", KillPoint::SystemUp, Contact::Attached),
        CoreDeathTarget::Logd => Route::Stub("logd", KillPoint::RestartsSpent, Contact::Launched),
    }
}

pub fn run(ctx: &Context, args: &TestCoreDeathArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    let targets = if args.target.is_empty()
    {
        CoreDeathTarget::ALL.to_vec()
    }
    else
    {
        args.target.clone()
    };
    // Held until the command returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let mut failed = Vec::new();
    for target in &targets
    {
        step(&format!("core-death test: killing {target:?}"));
        match boot_once(ctx, args, *target)
        {
            Ok(()) => step(&format!(
                "core-death test: {target:?}: the system powered off"
            )),
            Err(e) =>
            {
                eprintln!("core-death test: {target:?}: FAIL: {e:#}");
                failed.push(*target);
            }
        }
    }
    if !failed.is_empty()
    {
        bail!("core-death test: FAIL for {failed:?}");
    }
    step(&format!(
        "core-death test: PASS ({targets:?} each powered the system off)"
    ));
    Ok(())
}

/// One boot: kill `target` and judge the power-off.
fn boot_once(ctx: &Context, args: &TestCoreDeathArgs, target: CoreDeathTarget) -> Result<()>
{
    match route(target)
    {
        route @ Route::Stub(name, ..) =>
        {
            let layout = debug_stub::stage(ctx, args.arch, name)?;
            let result = boot(ctx, args, layout, route);
            let unstaged = debug_stub::unstage(ctx, args.arch, layout)
                .context("restoring the disk images without the stub");
            result.and(unstaged)
        }
        route @ Route::Hardware(_) => boot(ctx, args, crate::disk::current_layout(ctx)?, route),
    }
}

fn boot(ctx: &Context, args: &TestCoreDeathArgs, layout: DiskLayout, route: Route) -> Result<()>
{
    let function = match route
    {
        Route::Hardware(bp) => Some(breakpoint_kill::resolve_installed(
            ctx,
            bp.binary,
            bp.function,
        )?),
        Route::Stub(..) => None,
    };
    let sock_dir = ctx.target_dir.join("xtask");
    std::fs::create_dir_all(&sock_dir)
        .with_context(|| format!("creating {}", sock_dir.display()))?;
    let pid = std::process::id();
    let qmp_sock = sock_dir.join(format!("core-death-{pid}.qmp"));
    let gdb_sock = sock_dir.join(format!("core-death-{pid}.gdb"));
    let _ = std::fs::remove_file(&qmp_sock);
    let _ = std::fs::remove_file(&gdb_sock);
    let debug_port = match route
    {
        Route::Stub(..) => Some(crate::util::debug_port_or_free(None)?),
        Route::Hardware(_) => None,
    };
    let (mut guest, stdin) = launch(
        ctx,
        args,
        layout,
        &qmp_sock,
        match route
        {
            Route::Hardware(_) => GdbMode::Unix(&gdb_sock),
            Route::Stub(..) => GdbMode::Off,
        },
        debug_port,
    )?;

    // Connected before the guest can shut down: an event QEMU emits with no
    // client connected is lost.
    let (tx, rx) = mpsc::channel();
    let qmp_thread = {
        let sock = qmp_sock.clone();
        thread::spawn(move || {
            let reason = qmp::wait_shutdown(&sock, BOOT_TIMEOUT.saturating_add(POWER_OFF_TIMEOUT));
            let _ = tx.send((reason, Instant::now()));
        })
    };

    let killed = match (route, function, debug_port, stdin)
    {
        (Route::Stub(name, point, contact), _, Some(port), stdin) =>
        {
            let _stdin = stdin;
            let killed = kill_through_stub(&mut guest, args.arch, port, name, point, contact);
            if killed.is_err()
            {
                // Show the stub's lines on a refusal, which reach the serial
                // line when its log sink is not the target it holds. With
                // logd held its lines are dropped, and the answer's `E`
                // number carries the cause.
                let _ = guest.echo_until_end(STUB_FAILURE_ECHO);
            }
            killed
        }
        (Route::Hardware(bp), Some(function), _, Some(stdin)) => guest
            .collect_until(READY_MARKER, BOOT_TIMEOUT)
            .context("the boot")
            .and_then(|lines| {
                // memmgr and procmgr are core members: their death is
                // pwrmgr's alone, and the kill waits until pwrmgr has armed
                // the power-off that needs neither.
                if !lines.iter().any(|l| l.contains(ARMED_MARKER))
                {
                    guest
                        .collect_until(ARMED_MARKER, BOOT_TIMEOUT)
                        .context("pwrmgr's core-death power-off armed")?;
                }
                let bias = lines
                    .iter()
                    .find_map(|l| field_hex(l, bp.bias_line))
                    .with_context(|| {
                        format!("no `{}` line before the READY marker", bp.bias_line)
                    })?;
                let killed = breakpoint_kill::kill_at_breakpoint(
                    args.arch,
                    &gdb_sock,
                    bias,
                    &function,
                    move || type_input(stdin),
                )?;
                step(&format!(
                    "core-death test: moved the CPU at {:#x} to 0",
                    killed.pc
                ));
                // QEMU's stdin closes here, ending the serial line's input:
                // the typed bytes are already in the pipe, and nothing is
                // typed after the kill.
                drop(killed.triggered);
                Ok(killed.resumed)
            }),
        _ => Err(crate::error::err!("the route's launch is incomplete")),
    };
    let verdict = killed.and_then(|killed_at| {
        let ended_at = guest.echo_until_end(POWER_OFF_TIMEOUT).then(Instant::now);
        let (reason, shutdown_at) = rx
            .recv_timeout(EXIT_TIMEOUT)
            .context("QMP gave no SHUTDOWN event")?;
        judge(&reason?, shutdown_at, killed_at, ended_at)
    });
    let exited = verdict.and_then(|()| guest.wait_exit(EXIT_TIMEOUT));
    let _ = qmp_thread.join();
    let _ = std::fs::remove_file(&qmp_sock);
    let _ = std::fs::remove_file(&gdb_sock);
    exited
}

/// Launch QEMU on the images of `layout`, with its QMP socket at `qmp_sock`,
/// its gdbstub as `gdb` says, and the debug port on `debug_port` when one is
/// given. Returns the guest and QEMU's stdin, the guest's serial receive line
/// (`-serial stdio`).
fn launch(
    ctx: &Context,
    args: &TestCoreDeathArgs,
    layout: DiskLayout,
    qmp_sock: &Path,
    gdb: GdbMode<'_>,
    debug_port: Option<u16>,
) -> Result<(Guest, Option<ChildStdin>)>
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
    let data_image = layout.second_image(ctx);
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: data_image
            .as_deref()
            .map(SecondDisk::of_image)
            .transpose()?,
        firmware_code_path: &firmware_code,
        firmware_vars_path: firmware_vars.as_deref(),
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb,
        qmp_socket: Some(qmp_sock),
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu: Iommu::Attached,
        debug_port,
        test_devices: false,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let stdin = child.stdin.take();
    Ok((Guest::from_child(child)?, stdin))
}

/// The verdict on a boot whose `SHUTDOWN` event gave `reason` at
/// `shutdown_at`, whose kill resumed the target at `killed_at`, and whose
/// serial stream ended at `ended_at` (`None`: not within the power-off
/// budget): a power-off after the kill passes.
fn judge(
    reason: &str,
    shutdown_at: Instant,
    killed_at: Instant,
    ended_at: Option<Instant>,
) -> Result<()>
{
    if shutdown_at < killed_at
    {
        bail!("QEMU shut down before the kill");
    }
    if reason != POWER_OFF_REASON
    {
        bail!("QEMU's SHUTDOWN event gave reason {reason:?}, not {POWER_OFF_REASON:?}");
    }
    if ended_at.is_none()
    {
        bail!(
            "QEMU did not exit within {}s of the kill",
            POWER_OFF_TIMEOUT.as_secs()
        );
    }
    Ok(())
}

/// Once the GDB stub service has attached to `name`, connect to it over the
/// debug port on `port`, move the target's main thread to program counter 0
/// at `point`, and detach. Returns the moment of the last detach, which
/// resumes the thread.
fn kill_through_stub(
    guest: &mut Guest,
    arch: Arch,
    port: u16,
    name: &str,
    point: KillPoint,
    contact: Contact,
) -> Result<Instant>
{
    let seen = match contact
    {
        Contact::Attached => guest
            .collect_until(
                &format!("{} ({name})", debug_stub::ATTACHED_MARKER),
                BOOT_TIMEOUT,
            )
            .context("the stub's attach")?,
        Contact::Launched => guest
            .collect_until(&format!("{LAUNCHING_MARKER}{name}"), BOOT_TIMEOUT)
            .with_context(|| format!("{name}'s launch"))?,
    };
    let mut stub = Stub::connect_tcp(&format!("127.0.0.1:{port}"), FIRST_ANSWER_TIMEOUT)?;
    // The bytes wait in the port until the stub reads them, after its look
    // for the target at its start; a stub that found none looks again here.
    stub.request(b"qSupported")?;
    stub.set_answer_timeout(ANSWER_TIMEOUT)?;
    if point == KillPoint::SystemUp
    {
        // The attach holds every thread of the target, and the boot waits on
        // devmgr and vfsd: released until the system is up, the target is
        // held again by the next `qSupported`, which finds the stub detached.
        stub.expect_ok(b"D")?;
        let awaited: Vec<&str> = [READY_MARKER, RECONCILED_MARKER]
            .into_iter()
            .filter(|m| !seen.iter().any(|l| l.contains(m)))
            .collect();
        guest
            .wait_for_markers(&awaited, BOOT_TIMEOUT)
            .context("the boot")?;
        stub.request(b"qSupported")?;
    }
    let kills = match point
    {
        KillPoint::RestartsSpent => restart_budget::RESTART_BURST.saturating_add(1),
        KillPoint::Attach | KillPoint::SystemUp => 1,
    };
    for kill in 1..=kills
    {
        if kill > 1
        {
            // The restart's line is written by the new logd once it runs.
            let lines = guest
                .collect_until(&format!("{RESTARTED_MARKER}{name}"), BOOT_TIMEOUT)
                .with_context(|| {
                    format!("{name}'s restart after kill {}", kill.saturating_sub(1))
                })?;
            // logd, the only target killed more than once, is the log sink:
            // until an instance's release reaches init-logd, init-logd serves
            // the log endpoint and writes the UART directly, whether the first
            // kill fell before that instance's bootstrap request or after it.
            // The restarted instance must take the handover from it, as the
            // first launch would have, or both write the UART and their lines
            // interleave byte by byte.
            let died_early = format!("svcmgr: {name}{BOOT_DEATH_MARKER}");
            if kill == 2
                && !seen
                    .iter()
                    .chain(&lines)
                    .any(|l| l.contains(HANDOVER_MARKER))
            {
                guest
                    .collect_until(HANDOVER_MARKER, BOOT_TIMEOUT)
                    .with_context(|| {
                        format!("the handover to {name}'s restart after its first instance died")
                    })?;
                let when = if lines.iter().any(|l| l.contains(&died_early))
                {
                    "before"
                }
                else
                {
                    "after"
                };
                step(&format!(
                    "core-death test: {name}'s first instance died {when} its bootstrap request, \
                     before its release; its restart took the handover"
                ));
            }
            stub.request(b"qSupported")?;
        }
        let pc = debug_stub::kill_held(&mut stub, arch, name)
            .with_context(|| format!("kill {kill} of {kills}"))?;
        step(&format!(
            "core-death test: kill {kill} of {kills}: moved {name}'s main thread from {pc:#x} to 0"
        ));
        if kill < kills
        {
            thread::sleep(REAP_PAUSE);
        }
    }
    Ok(Instant::now())
}

/// Type [`SERIAL_INPUT`] once the VM has had time to resume; returns the
/// handle, kept open. Another request can reach the function first, and the
/// kill's power-off can end QEMU before the input is typed, closing its
/// stdin: the input is then not needed, and the failure is only noted.
fn type_input(mut stdin: ChildStdin) -> Option<ChildStdin>
{
    thread::sleep(Duration::from_secs(1));
    match stdin.write_all(SERIAL_INPUT).and_then(|()| stdin.flush())
    {
        Ok(()) => Some(stdin),
        Err(e) =>
        {
            step(&format!("core-death test: the input was not typed ({e})"));
            None
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a reset, a power-off before the kill, or a guest that
    // never stopped, judged a pass.
    #[test]
    fn only_a_power_off_after_the_kill_passes()
    {
        let killed = Instant::now();
        let later = killed.checked_add(Duration::from_secs(1)).unwrap();
        judge(POWER_OFF_REASON, later, killed, Some(later)).unwrap();
        judge("guest-reset", later, killed, Some(later)).unwrap_err();
        judge(POWER_OFF_REASON, killed, later, Some(later)).unwrap_err();
        judge(POWER_OFF_REASON, later, killed, None).unwrap_err();
    }

    // Defect caught: a target reached by a route that cannot attach to it
    // (init creates memmgr and procmgr with raw syscalls, so no process list
    // names them), or the reaper's kill landing on the main thread.
    #[test]
    fn init_created_services_are_reached_through_qemu()
    {
        for target in [
            CoreDeathTarget::Memmgr,
            CoreDeathTarget::Procmgr,
            CoreDeathTarget::ProcmgrReaper,
        ]
        {
            assert!(matches!(route(target), Route::Hardware(_)), "{target:?}");
        }
        // svcmgr is killed held, since the boot waits on it; devmgr and vfsd
        // once svcmgr no longer calls them unchecked, and logd once it has
        // taken its bootstrap round. Defect caught too: the stub's attach to
        // logd, the log sink, awaited by its marker, which logd itself
        // carries, so a stub holding logd never shows it.
        for (target, name, point, contact) in [
            (
                CoreDeathTarget::Svcmgr,
                "svcmgr",
                KillPoint::Attach,
                Contact::Attached,
            ),
            (
                CoreDeathTarget::Devmgr,
                "devmgr",
                KillPoint::SystemUp,
                Contact::Attached,
            ),
            (
                CoreDeathTarget::Vfsd,
                "vfsd",
                KillPoint::SystemUp,
                Contact::Attached,
            ),
            (
                CoreDeathTarget::Logd,
                "logd",
                KillPoint::RestartsSpent,
                Contact::Launched,
            ),
        ]
        {
            assert_eq!(route(target), Route::Stub(name, point, contact));
        }
        let Route::Hardware(reaper) = route(CoreDeathTarget::ProcmgrReaper)
        else
        {
            unreachable!()
        };
        assert_eq!(reaper.function, "procmgr::process::reap_dead");
    }
}
