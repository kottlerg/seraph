// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_gdb.rs

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
//! back. The recipes are always removed and the disk images repacked in the
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
use std::time::Duration;

use anyhow::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::cli::TestGdbArgs;
use crate::context::Context;
use crate::debug_stub;
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, X86Paging, build_qemu_argv,
    prepare_riscv_firmware, validate_sysroot_for_launch,
};
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

pub fn run(ctx: &Context, args: &TestGdbArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the command returns, after its last QEMU has exited.
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
    let booted = staged.as_ref().ok().map(|_| boot(ctx, args, &gdb));
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
    step("gdb stub test: PASS (break, memory and register write, step, second thread, detach)");
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
}

/// A line of the guest's serial output the test waits on.
enum Serial
{
    Ready,
    Detached(String),
}

/// Boot with the debug port, wait for the stub, run GDB, wait for the stub's
/// detach line, kill QEMU.
fn boot(ctx: &Context, args: &TestGdbArgs, gdb: &Path) -> Result<Session>
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
        gdb: GdbMode::Off,
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        x86_paging: X86Paging::Four,
        iommu: Iommu::Attached,
        debug_port: Some(args.port),
        test_devices: false,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;
    step(&format!(
        "gdb stub test: booting with the debug port on 127.0.0.1:{}",
        args.port
    ));
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;
    let (tx, rx) = mpsc::channel::<Serial>();
    let reader = thread::spawn(move || forward_serial(stdout, &tx));
    let binary = ctx.sysroot.join("programs/debugger");
    let ready = loop
    {
        match rx.recv_timeout(BOOT_TIMEOUT)
        {
            Ok(Serial::Ready) => break Ok(()),
            Ok(Serial::Detached(_)) =>
            {}
            Err(_) =>
            {
                break Err(anyhow::anyhow!(
                    "the stub's {READY_MARKER:?} line did not appear within {}s",
                    BOOT_TIMEOUT.as_secs()
                ));
            }
        }
    };
    let result = ready
        .and_then(|()| run_gdb(gdb, args.arch, args.port, &binary))
        .map(|output| Session {
            gdb: output,
            detached: loop
            {
                match rx.recv_timeout(DETACH_TIMEOUT)
                {
                    Ok(Serial::Detached(line)) => break Some(line),
                    Ok(Serial::Ready) =>
                    {}
                    Err(_) => break None,
                }
            },
        });
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
        .args(["-ex".to_string(), format!("target remote localhost:{port}")]);
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
        .map_err(|_| anyhow::anyhow!("gdb did not finish within {}s", GDB_TIMEOUT.as_secs()))?;
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
    let Some(start) = output.find(mark)
    else
    {
        return "";
    };
    let rest = &output[start + mark.len()..];
    rest.find("@@").map_or(rest, |end| &rest[..end])
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
    let before = &output[..output.find("@@break").unwrap_or(0)];
    if !lists_thread(before, 1) || !lists_thread(before, 2)
    {
        bail!("info threads did not list two threads");
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
    // results (the step, the rewritten variable or register, the second
    // thread's row).
    #[test]
    fn a_session_missing_a_result_fails_the_check()
    {
        let good = "[New Thread 2]\n  Id   Target Id   Frame\n* 1    Thread 1   0x8 in f ()\n  \
                    2    Thread 2   0x9 in f ()\n@@break\nBreakpoint 1, 0x10 in \
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
