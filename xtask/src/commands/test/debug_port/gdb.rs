// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/debug_port/gdb.rs

//! GDB stub batch test: the host's GDB debugs a guest process through the
//! stub over the debug port.
//!
//! Stages the `gdb-target` recipe (`programs/debugger --gdb-target`) and the
//! GDB stub naming it, repacks `disk.img`, and boots the current sysroot once
//! with the debug port attached. Once the stub logs [`READY_MARKER`], the host
//! runs `gdb -batch` against the port with the image's symbols ([`SCRIPT`]):
//! it lists the threads, breaks on `gdb_target_tick`, continues to it,
//! rewrites a variable and a register and reads each back, single-steps,
//! selects the second thread and reads its registers, and detaches. The
//! output is checked against [`expect`], and the stub's own detach line
//! against [`expect_restored`]: procmgr gave the target its crash bindings
//! back. A restart round follows ([`restart_round`]): the host connects to
//! the stub again, which attaches to the target anew, kills the debug port's
//! driver through QEMU's gdbstub at a hardware breakpoint in its code
//! (`breakpoint_kill`), and once the stub logs [`FOLLOWED_MARKER`], holding
//! the driver devmgr restarted at the class's next ordinal, requires the
//! session to go on through it on the same connection. The recipes are always removed and the disk images repacked in the
//! layout they had afterwards; the host kills QEMU.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build` and a
//! host GDB that debugs the architecture (`gdb` built with all targets, or
//! `gdb-multiarch`).

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::breakpoint_kill;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::debug_stub;
use crate::disk::DiskLayout;
use crate::guest::{QemuStderr, explain_exit};
use crate::qemu::{
    Firmware, GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, SecondDisk,
    X86Paging, X86ShadowStack, build_qemu_argv, validate_sysroot_for_launch,
};
use crate::qemu_gdb::Stub;
use crate::socket_dir::SocketDir;
use crate::symbolize::store::Store;
use crate::util::{require_tool, step};

/// The target's recipe and process name.
const TARGET_RECIPE: &str = "gdb-target.svc";
const TARGET_NAME: &str = "gdb-target";

/// The stub's line once it is attached. Kept in sync with
/// `services/gdbstub/src/main.rs`.
const READY_MARKER: &str = "[gdbstub] attached; serving the debug port";

/// The start of the stub's line once it has detached, which ends with
/// whether procmgr restored the target's crash bindings. Kept in sync with
/// `services/gdbstub/src/main.rs`.
const DETACHED_MARKER: &str = "[gdbstub] detached from gdb-target (crash bindings restored: ";

/// The stub's line once it holds the driver devmgr restarted at the class's
/// next ordinal. Kept in sync with `shared/device-tracker`.
const FOLLOWED_MARKER: &str = "[gdbstub] debug port driver at ordinal 1";

/// The debug port's driver: its process name, its binary under the sysroot,
/// and the function the kill breaks on, which the driver runs on every
/// `SERIAL_READ_BYTES`, so the stub's reads reach it. Kept in sync with
/// `services/drivers/virtio/console/src/main.rs`.
const PORT_DRIVER_NAME: &str = "/services/drivers/virtio-console";
const PORT_DRIVER_BINARY: &str = "services/drivers/virtio-console";
const PORT_DRIVER_FUNCTION: &str = "<virtio_console::Console>::drain_rx";

/// Budget for each of the stub's answers in the restart round.
const RESTART_ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for the restart, from the kill to [`FOLLOWED_MARKER`].
const RESTART_TIMEOUT: Duration = Duration::from_mins(1);

/// Budget for the boot to reach [`READY_MARKER`].
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget, from GDB's exit, for the stub's [`DETACHED_MARKER`] line.
const DETACH_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for GDB's whole session.
const GDB_TIMEOUT: Duration = Duration::from_mins(3);

/// The batch session, after `file` and `target remote`. Each `echo` marks a
/// point [`expect`] finds the output after. `$scratch` stands for a
/// caller-saved register of the architecture ([`scratch_register`]), which
/// the session rewrites, reads back from the stub past GDB's register cache,
/// and restores before it steps.
const SCRIPT: &[&str] = &[
    "info threads",
    "echo @@attach-step\\n",
    "stepi",
    "print/x $pc",
    "echo @@break\\n",
    "break gdb_target_tick",
    "continue",
    "echo @@pc\\n",
    "print/x $pc",
    "echo @@counter\\n",
    "set var *(unsigned long *)&GDB_TARGET_COUNTER = 0x5eed",
    "x/gx &GDB_TARGET_COUNTER",
    "echo @@register\\n",
    "set $seraph_saved = $scratch",
    "set $scratch = 0x5eed5eed",
    "maint flush register-cache",
    "print/x $scratch",
    "set $scratch = $seraph_saved",
    "echo @@step\\n",
    "stepi",
    "print/x $pc",
    "delete",
    "echo @@thread\\n",
    "thread 2",
    "print/x $pc",
    "print/x $sp",
    "echo @@detach\\n",
    "detach",
];

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the case returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let gdb = require_tool(&args.gdb)?;
    let target_staged = ctx
        .sysroot
        .join("config/svcmgr/services")
        .join(TARGET_RECIPE);
    let target_source = ctx.sysroot.join("config/svcmgr/tests").join(TARGET_RECIPE);
    std::fs::copy(&target_source, &target_staged)
        .with_context(|| format!("staging {}", target_source.display()))?;
    let staged = debug_stub::stage(ctx, args.arch, TARGET_NAME);
    let booted = staged
        .as_ref()
        .ok()
        .map(|&layout| boot(ctx, args, &gdb, layout));
    // Restore first, every step of it whatever another's outcome, and
    // surface its first failure ahead of the staging's and the boot's.
    let removed = std::fs::remove_file(&target_staged)
        .with_context(|| format!("removing {}", target_staged.display()));
    let unstaged = staged.as_ref().ok().map(|&layout| {
        debug_stub::unstage(ctx, args.arch, layout)
            .context("restoring the disk images without the stub and its target")
    });
    removed?;
    unstaged.transpose()?;
    staged?;
    let session = booted.context("the boot did not run")??;
    expect(&session.gdb)?;
    expect_restored(session.detached.as_deref())?;
    session.restarted.context("the restart round")?;
    step(
        "gdb stub test: PASS (step from the attach stop, break, memory and register write, step, \
         second thread, detach, the session across a restart of the port's driver)",
    );
    Ok(())
}

/// What one session left to check.
struct Session
{
    /// GDB's output.
    gdb: String,
    /// The stub's [`DETACHED_MARKER`] line, when it appeared within
    /// [`DETACH_TIMEOUT`] of GDB's exit.
    detached: Option<String>,
    /// The restart round's outcome.
    restarted: Result<()>,
}

/// A line of the guest's serial output the test waits on.
enum Serial
{
    Ready,
    Detached(String),
    /// procmgr's bias line for the debug port's driver: the bias.
    DriverBias(u64),
    Followed,
}

/// Boot the images of `layout` with the debug port, wait for the stub, run
/// GDB, wait for the stub's detach line, kill QEMU.
fn boot(ctx: &Context, args: &CaseArgs, gdb: &Path, layout: DiskLayout) -> Result<Session>
{
    // Picked here, right before QEMU binds it, to keep the window in which
    // another process could take it short.
    let port = crate::util::debug_port_or_free(args.port)?;
    let driver = breakpoint_kill::resolve_installed(ctx, PORT_DRIVER_BINARY, PORT_DRIVER_FUNCTION)?;
    // Removed on every return, after QEMU is reaped below.
    let sockets = SocketDir::create()?;
    let gdb_sock = sockets.socket("gdb.gdb")?;
    // GDB reads the symbols of the stripped installed image from the symbols
    // store's file of its build id.
    let binary =
        Store::at(ctx.symbols_dir()).symbols_path(&ctx.sysroot.join("programs/debugger"))?;
    let firmware = Firmware::prepare(ctx, args.arch)?;
    let vars = firmware.launch_vars()?;
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
        firmware_code_path: &firmware.code,
        firmware_vars_path: vars.path(),
        smm: firmware.smm,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Unix(&gdb_sock),
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu: Iommu::Attached,
        debug_port: Some(port),
        test_devices: false,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;
    step(&format!(
        "gdb stub test: booting with the debug port on 127.0.0.1:{port}"
    ));
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let mut stderr = QemuStderr::take(&mut child);
    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;
    let (tx, rx) = mpsc::channel::<Serial>();
    let reader = thread::spawn(move || forward_serial(stdout, &tx));
    let mut bias = None;
    let ready = loop
    {
        match rx.recv_timeout(BOOT_TIMEOUT)
        {
            Ok(Serial::Ready) => break Ok(()),
            Ok(Serial::DriverBias(b)) => bias = bias.or(Some(b)),
            Ok(Serial::Detached(_) | Serial::Followed) =>
            {}
            Err(mpsc::RecvTimeoutError::Timeout) =>
            {
                break Err(crate::error::err!(
                    "the stub's {READY_MARKER:?} line did not appear within {}s",
                    BOOT_TIMEOUT.as_secs()
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) =>
            {
                let err = crate::error::err!(
                    "the serial stream ended before the stub's {READY_MARKER:?} line"
                );
                break Err(explain_exit(err, &mut child, stderr.as_mut()));
            }
        }
    };
    let result = ready
        .and_then(|()| run_gdb(gdb, args.arch, port, &binary))
        .map(|output| after_gdb(output, args.arch, port, &gdb_sock, bias, &driver, &rx));
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    result
}

/// Echo the guest's serial output, and send `tx` each line the test waits
/// on.
fn forward_serial(stdout: std::process::ChildStdout, tx: &mpsc::Sender<Serial>)
{
    for line in BufReader::new(stdout).lines()
    {
        let Ok(l) = line
        else
        {
            break;
        };
        println!("{l}");
        let event = if l.contains(READY_MARKER)
        {
            Serial::Ready
        }
        else if let Some(bias) = breakpoint_kill::spawn_bias(&[l.as_str()], PORT_DRIVER_NAME)
        {
            Serial::DriverBias(bias)
        }
        else if l.contains(FOLLOWED_MARKER)
        {
            Serial::Followed
        }
        else if l.contains(DETACHED_MARKER)
        {
            Serial::Detached(l)
        }
        else
        {
            continue;
        };
        let _ = tx.send(event);
    }
}

/// What is left once GDB has run, given its `output`: the stub's detach
/// line, and the restart round, given the driver's `bias` when procmgr's line
/// named it.
fn after_gdb(
    output: String,
    arch: Arch,
    port: u16,
    gdb_sock: &Path,
    bias: Option<u64>,
    driver: &breakpoint_kill::Function,
    rx: &mpsc::Receiver<Serial>,
) -> Session
{
    let detached = loop
    {
        match rx.recv_timeout(DETACH_TIMEOUT)
        {
            Ok(Serial::Detached(line)) => break Some(line),
            Ok(Serial::Ready | Serial::DriverBias(_) | Serial::Followed) =>
            {}
            Err(_) => break None,
        }
    };
    let restarted = bias
        .with_context(|| {
            format!("no procmgr bias line for {PORT_DRIVER_NAME} before the stub's READY")
        })
        .and_then(|bias| restart_round(arch, port, gdb_sock, bias, driver, rx));
    Session {
        gdb: output,
        detached,
        restarted,
    }
}

/// The restart round: connect to the stub, which attaches to the target
/// again at `qSupported` and holds its threads; kill the debug port's driver
/// at [`PORT_DRIVER_FUNCTION`], which the stub's reads reach, so no trigger is
/// needed; wait for the stub to hold the driver devmgr restarted; and on the
/// same connection select the target's first thread, read its pointer, and
/// detach, each answered through the restarted driver.
fn restart_round(
    arch: Arch,
    port: u16,
    gdb_sock: &Path,
    bias: u64,
    driver: &breakpoint_kill::Function,
    rx: &mpsc::Receiver<Serial>,
) -> Result<()>
{
    let mut stub = Stub::connect_tcp(&format!("127.0.0.1:{port}"), RESTART_ANSWER_TIMEOUT)?;
    stub.request(b"qSupported")?;
    let killed = breakpoint_kill::kill_at_breakpoint(arch, gdb_sock, bias, driver, || ())?;
    step(&format!(
        "gdb stub test: moved the port's driver at {:#x} to 0",
        killed.pc
    ));
    let deadline = Instant::now()
        .checked_add(RESTART_TIMEOUT)
        .context("the restart's deadline")?;
    loop
    {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(Serial::Followed) => break,
            Ok(Serial::Ready | Serial::Detached(_) | Serial::DriverBias(_)) =>
            {}
            Err(_) => bail!(
                "the stub's {FOLLOWED_MARKER:?} did not appear within {}s of the kill",
                RESTART_TIMEOUT.as_secs()
            ),
        }
    }
    let halt = stub.request(b"?")?;
    if !halt.starts_with(b"T")
    {
        bail!(
            "? after the restart answered {:?}, not a stop",
            String::from_utf8_lossy(&halt)
        );
    }
    stub.expect_ok(b"Hg1")?;
    stub.read_register(debug_stub::rsp_arch(arch).pc_regnum())?;
    stub.expect_ok(b"D")?;
    Ok(())
}

/// Run the batch session, bounded by [`GDB_TIMEOUT`]; returns its output.
fn run_gdb(gdb: &Path, arch: Arch, port: u16, binary: &Path) -> Result<String>
{
    let mut cmd = Command::new(gdb);
    cmd.args(["-nx", "-batch"])
        .args(["-ex", "set pagination off", "-ex", "set confirm off"])
        .args(["-ex", "set remotetimeout 30"])
        .args([
            "-ex".to_string(),
            format!("set architecture {}", debug_stub::gdb_architecture(arch)),
        ])
        .args(["-ex".to_string(), format!("file {}", binary.display())])
        .args(["-ex".to_string(), format!("target remote 127.0.0.1:{port}")]);
    for line in SCRIPT
    {
        cmd.args([
            "-ex".to_string(),
            line.replace("$scratch", scratch_register(arch)),
        ]);
    }
    step("gdb stub test: running gdb -batch");
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", gdb.display()))?;
    let (tx, rx) = mpsc::channel();
    let mut out = child.stdout.take().context("gdb stdout unavailable")?;
    let mut err = child.stderr.take().context("gdb stderr unavailable")?;
    thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut out, &mut text);
        let mut errs = String::new();
        let _ = std::io::Read::read_to_string(&mut err, &mut errs);
        let _ = tx.send(text + &errs);
    });
    let output = rx.recv_timeout(GDB_TIMEOUT);
    let _ = child.kill();
    let _ = child.wait();
    let output = output
        .map_err(|_| crate::error::err!("gdb did not finish within {}s", GDB_TIMEOUT.as_secs()))?;
    println!("{output}");
    Ok(output)
}

/// The register the session rewrites: one the stopped function's caller
/// does not expect preserved, so a write the session undoes before it steps
/// changes nothing the target relies on.
fn scratch_register(arch: Arch) -> &'static str
{
    match arch
    {
        Arch::X86_64 => "$rax",
        Arch::Riscv64 => "$t0",
    }
}

/// The part of `output` after `mark` up to the next `@@` mark.
fn section<'a>(output: &'a str, mark: &str) -> &'a str
{
    let Some((_, rest)) = output.split_once(mark)
    else
    {
        return "";
    };
    rest.split_once("@@").map_or(rest, |(section, _)| section)
}

/// The `$N = 0x...` values a section printed, in order.
fn printed_values(text: &str) -> Vec<u64>
{
    text.lines()
        .filter_map(|l| l.split_once("= 0x"))
        .filter_map(|(_, v)| u64::from_str_radix(v.trim(), 16).ok())
        .collect()
}

/// Whether the `info threads` output `text` has the row of thread `id`
/// (`[*] <id>  Thread <id> ...`).
fn lists_thread(text: &str, id: u32) -> bool
{
    let label = format!("Thread {id} ");
    text.lines().any(|line| {
        let row = line.trim_start().trim_start_matches('*').trim_start();
        row.split_whitespace().next() == Some(id.to_string().as_str()) && row.contains(&label)
    })
}

/// Check the batch session's output.
fn expect(output: &str) -> Result<()>
{
    let threads = section(output, "@@break");
    let before = output
        .split_once("@@attach-step")
        .map_or("", |(before, _)| before);
    if !lists_thread(before, 1) || !lists_thread(before, 2)
    {
        bail!("info threads did not list two threads");
    }
    // The first step runs from where the attach stopped the main thread, on
    // text the target shares with no breakpoint planted on its page yet.
    if printed_values(section(output, "@@attach-step")).is_empty()
    {
        bail!("stepi from the attach stop printed no pc");
    }
    if !threads.contains("Breakpoint 1, ") || !threads.contains("gdb_target_tick")
    {
        bail!("the breakpoint on gdb_target_tick was not reported");
    }
    let pc = printed_values(section(output, "@@pc"));
    let Some(&bp_pc) = pc.first()
    else
    {
        bail!("no pc printed at the breakpoint");
    };
    if !section(output, "@@counter").contains("0x0000000000005eed")
    {
        bail!("the rewritten GDB_TARGET_COUNTER did not read back");
    }
    if printed_values(section(output, "@@register")).first() != Some(&0x5eed_5eed)
    {
        bail!("the rewritten register did not read back from the stub");
    }
    let stepped = printed_values(section(output, "@@step"));
    if stepped.first().is_none_or(|&p| p == bp_pc)
    {
        bail!("stepi did not move the pc from {bp_pc:#x}");
    }
    let second = section(output, "@@thread");
    if !second.contains("Switching to thread 2") || printed_values(second).len() < 2
    {
        bail!("thread 2 was not selected, or its registers not read");
    }
    if !section(output, "@@detach").contains("[Inferior 1 (Remote target) detached]")
    {
        bail!("the session did not detach");
    }
    Ok(())
}

/// Check the stub's detach line: procmgr took the target's crash bindings
/// back.
fn expect_restored(line: Option<&str>) -> Result<()>
{
    match line
    {
        Some(l) if l.contains(&format!("{DETACHED_MARKER}true)")) => Ok(()),
        Some(l) => bail!("the stub detached without restoring the crash bindings: {l}"),
        None => bail!(
            "the stub's detach line did not appear within {}s",
            DETACH_TIMEOUT.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a check that passes a session missing one of its
    // results (either step, the rewritten variable or register, the second
    // thread's row).
    #[test]
    fn a_session_missing_a_result_fails_the_check()
    {
        let good = "[New Thread 2]\n  Id   Target Id   Frame\n* 1    Thread 1   0x8 in f ()\n  \
                    2    Thread 2   0x9 in f ()\n@@attach-step\n0x0c in f ()\n$0 = 0xc\n\
                    @@break\nBreakpoint 1, 0x10 in \
                    gdb_target_tick ()\n@@pc\n$1 = 0x10\n@@counter\n0x20:\t0x0000000000005eed\n\
                    @@register\nRegister cache flushed.\n$2 = 0x5eed5eed\n\
                    @@step\n$3 = 0x14\n@@thread\n[Switching to thread 2 (Thread 2)]\n$4 = 0x30\n\
                    $5 = 0x40\n@@detach\n[Inferior 1 (Remote target) detached]\n";
        expect(good).unwrap();
        assert!(
            expect(&good.replace(
                "[Inferior 1 (Remote target) detached]",
                "Can't detach Thread 1"
            ))
            .is_err()
        );
        assert!(expect(&good.replace("$3 = 0x14", "$3 = 0x10")).is_err());
        assert!(expect(&good.replace("$0 = 0xc\n", "")).is_err());
        assert!(expect(&good.replace("0x0000000000005eed", "0x0000000000000000")).is_err());
        assert!(expect(&good.replace("$2 = 0x5eed5eed", "$2 = 0x7")).is_err());
        assert!(expect(&good.replace("2    Thread 2   0x9 in f ()", "")).is_err());
    }

    // Defect caught: a detach that left the target's crash bindings with the
    // stub, or no detach line at all, passing the test.
    #[test]
    fn a_detach_without_the_restored_bindings_fails_the_check()
    {
        let line = "$ [1.7] [gdbstub] detached from gdb-target (crash bindings restored: true)";
        expect_restored(Some(line)).unwrap();
        assert!(expect_restored(Some(&line.replace("true", "false"))).is_err());
        assert!(expect_restored(None).is_err());
    }
}
