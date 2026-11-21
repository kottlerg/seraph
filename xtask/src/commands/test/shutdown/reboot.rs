// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/shutdown/reboot.rs

//! Reboot test: pwrmgr's `REBOOT` resets the machine.
//!
//! Stages the `reboot` fixture's recipe (`svctest`'s `reboot` role, seeded
//! with `pwrmgr.shutdown`) into the boot set, repacks the disk images in the
//! layout they have, and boots the current sysroot once with a QMP socket.
//! The fixture sends `REBOOT`; on `x86_64` pwrmgr has acpid write the FADT's
//! `RESET_VALUE` to its `RESET_REG`, on riscv64 it makes the SBI system
//! reset call. QEMU runs with `-no-reboot`, so a guest reset ends it, and
//! QMP's `SHUTDOWN` event names the cause: `guest-reset` for a reset,
//! `guest-shutdown` for a power-off. The test passes on the fixture's
//! [`FIXTURE_MARKER`], on `x86_64` acpid's [`ACPID_RESET_MARKER`], a
//! `SHUTDOWN` event with reason `guest-reset`, and QEMU exiting on its own.
//! The fixture's recipe is always removed and the images repacked in that
//! layout afterwards.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::disk::DiskLayout;
use crate::qemu::{
    Firmware, GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, SecondDisk,
    X86Paging, X86ShadowStack, build_qemu_argv,
};
use crate::qmp;
use crate::util::{require_tool, step};

/// The fixture's recipe, as `cargo xtask build` installs it under
/// `config/svcmgr/tests/`, staged into `config/svcmgr/services/` for the boot.
const RECIPE: &str = "reboot.svc";

/// The fixture's line before it sends `REBOOT`. Kept in sync with
/// `services/svctest/src/phases/pwrmgr.rs`.
const FIXTURE_MARKER: &str = "reboot fixture: requesting REBOOT";

/// acpid's line before its `RESET_REG` write on `x86_64`. Kept in sync with
/// `services/acpid/src/arch/x86_64/mod.rs`.
const ACPID_RESET_MARKER: &str = "RESET: RESET_REG";

/// The `SHUTDOWN` event's reason for a guest reset under `-no-reboot`.
const RESET_REASON: &str = "guest-reset";

/// Budget for the boot to reach the fixture and reset.
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget for QEMU to exit after its `SHUTDOWN` event.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// The reboot cause's boot. The caller has checked the sysroot and admitted
/// the boot.
pub(super) fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    let services = ctx.sysroot.join("config").join("svcmgr");
    let staged = services.join("services").join(RECIPE);
    let source = services.join("tests").join(RECIPE);
    // Read before staging, so a failed staging repack cannot change the
    // layout the restore writes.
    let layout = crate::disk::current_layout(ctx)?;
    std::fs::copy(&source, &staged)
        .with_context(|| format!("staging {} as {}", source.display(), staged.display()))?;
    let booted = crate::disk::create_disk_image(ctx, args.arch, layout)
        .and_then(|()| boot(ctx, args, layout));
    // Restore first, and surface its failure ahead of the boot's: a recipe
    // left staged would reset every later boot.
    std::fs::remove_file(&staged)
        .with_context(|| format!("removing {}", staged.display()))
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, layout))
        .context("restoring the disk images without the fixture")?;
    booted?;
    step("reboot test: PASS (the fixture's REBOOT reset the machine)");
    Ok(())
}

/// What the serial stream showed.
#[derive(Default)]
struct Seen
{
    fixture: bool,
    acpid_reset: bool,
}

/// Boot the images of `layout` with a QMP socket, wait for the `SHUTDOWN`
/// event and QEMU's exit, and judge them and the serial stream.
fn boot(ctx: &Context, args: &CaseArgs, layout: DiskLayout) -> Result<()>
{
    let firmware = Firmware::prepare(ctx, args.arch)?;
    let vars = firmware.launch_vars()?;
    let sock_dir = ctx.target_dir.join("xtask");
    std::fs::create_dir_all(&sock_dir)
        .with_context(|| format!("creating {}", sock_dir.display()))?;
    // Per architecture, so the two architectures' runs side by side never
    // reach each other's QEMU.
    let sock = sock_dir.join(format!("reboot-test-{}.sock", args.arch));
    let _ = std::fs::remove_file(&sock);
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
        smm: false,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: Some(&sock),
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu: Iommu::Attached,
        debug_port: None,
        test_devices: false,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    step("reboot test: booting with the reboot fixture staged");
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;

    let seen = Arc::new(Mutex::new(Seen::default()));
    let reader = {
        let seen = Arc::clone(&seen);
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines()
            {
                let Ok(l) = line
                else
                {
                    break;
                };
                println!("{l}");
                let mut seen = seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                seen.fixture |= l.contains(FIXTURE_MARKER);
                seen.acpid_reset |= l.contains(ACPID_RESET_MARKER);
            }
        })
    };

    // Connected right after the spawn, long before the guest can reset.
    let reason = qmp::wait_shutdown(&sock, BOOT_TIMEOUT);
    let exited = wait_exit(&mut child, EXIT_TIMEOUT);
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let _ = std::fs::remove_file(&sock);
    let seen = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    judge(args.arch, &reason?, exited?, &seen)
}

/// Wait up to `timeout` for `child` to exit; whether it did, and with
/// success.
fn wait_exit(child: &mut std::process::Child, timeout: Duration) -> Result<Option<bool>>
{
    let start = Instant::now();
    while start.elapsed() < timeout
    {
        if let Some(status) = child.try_wait().context("waiting for QEMU")?
        {
            return Ok(Some(status.success()));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(None)
}

/// The verdict on a boot of `arch` whose `SHUTDOWN` event gave `reason`,
/// whose QEMU exited as `exited` says (`None`: not within the budget), and
/// whose serial stream showed `seen`.
fn judge(arch: Arch, reason: &str, exited: Option<bool>, seen: &Seen) -> Result<()>
{
    if !seen.fixture
    {
        bail!("the fixture's {FIXTURE_MARKER:?} line did not appear");
    }
    if reason != RESET_REASON
    {
        bail!("QEMU's SHUTDOWN event gave reason {reason:?}, not {RESET_REASON:?}");
    }
    if arch == Arch::X86_64 && !seen.acpid_reset
    {
        bail!("acpid's {ACPID_RESET_MARKER:?} line did not appear");
    }
    match exited
    {
        Some(true) => Ok(()),
        Some(false) => bail!("QEMU exited with a failure status after the reset"),
        None => bail!(
            "QEMU did not exit within {}s of the reset",
            EXIT_TIMEOUT.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const BOTH: Seen = Seen {
        fixture: true,
        acpid_reset: true,
    };

    #[test]
    fn a_reset_with_both_lines_and_a_clean_exit_passes()
    {
        judge(Arch::X86_64, RESET_REASON, Some(true), &BOTH).unwrap();
        let fixture_only = Seen {
            fixture: true,
            acpid_reset: false,
        };
        judge(Arch::Riscv64, RESET_REASON, Some(true), &fixture_only).unwrap();
    }

    #[test]
    fn a_power_off_a_missing_line_or_no_exit_fails()
    {
        judge(Arch::X86_64, "guest-shutdown", Some(true), &BOTH).unwrap_err();
        judge(Arch::X86_64, RESET_REASON, None, &BOTH).unwrap_err();
        judge(Arch::X86_64, RESET_REASON, Some(false), &BOTH).unwrap_err();
        let no_acpid = Seen {
            fixture: true,
            acpid_reset: false,
        };
        judge(Arch::X86_64, RESET_REASON, Some(true), &no_acpid).unwrap_err();
        judge(Arch::X86_64, RESET_REASON, Some(true), &Seen::default()).unwrap_err();
    }
}
