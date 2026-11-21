// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/shutdown/power_button.rs

//! Power-button test (`x86_64` only): a press of the ACPI fixed power button
//! powers the machine off.
//!
//! Boots the current sysroot once with a QMP socket and waits for acpid's
//! [`ARMED_MARKER`], which it logs once the SCI is taken and the fixed
//! power-button event enabled, and the terminal's [`READY_MARKER`]. It then
//! sends QMP `system_powerdown`, which on q35 sets `PWRBTN_STS` in the PM1
//! event block and raises the SCI. acpid's event thread finds the press
//! ([`PRESS_MARKER`]) and hands it to pwrmgr's `WAIT_EVENT`, and pwrmgr
//! powers off through acpid's `SLEEP(5)` ([`PWRMGR_MARKER`], then acpid's
//! [`SLEEP_MARKER`]). The test passes on the three lines, QMP's `SHUTDOWN` event with reason `guest-shutdown`, and
//! QEMU exiting on its own. QEMU's `riscv64` `virt` machine has a
//! hardware-reduced ACPI with no fixed power button, so the test has no
//! `riscv64` form.
//!
//! A pure runner like the `terminal` case: requires a populated `x86_64` sysroot
//! with the default boot set (terminal + shell) and a repacked `disk.img`.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::guest::Guest;
use crate::qemu::{
    Firmware, GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, X86Paging,
    X86ShadowStack, build_qemu_argv,
};
use crate::qmp;
use crate::socket_dir::SocketDir;
use crate::util::{require_tool, step};

/// acpid's line once the events are armed. Kept in sync with
/// `services/acpid/src/server.rs`.
const ARMED_MARKER: &str = "events armed";

/// The terminal's line once the system is up. Kept in sync with
/// `programs/terminal`.
const READY_MARKER: &str = "terminal: READY for injection";

/// acpid's line when its event thread finds the press. Kept in sync with
/// `services/acpid/src/server.rs`.
const PRESS_MARKER: &str = "power button pressed";

/// pwrmgr's line before it powers off on the press. Kept in sync with
/// `services/pwrmgr/src/arch/x86_64/mod.rs`.
const PWRMGR_MARKER: &str = "power button: shutting down";

/// acpid's line before its `PM1a_CNT` writes. Kept in sync with
/// `services/acpid/src/arch/x86_64/mod.rs`.
const SLEEP_MARKER: &str = "SLEEP(5): PM1a_CNT";

/// The `SHUTDOWN` event's reason for a guest power-off.
const POWER_OFF_REASON: &str = "guest-shutdown";

/// Budget for the boot to reach both start markers.
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget from the press to QEMU's `SHUTDOWN` event, and for the lines of
/// the press.
const PRESS_TIMEOUT: Duration = Duration::from_mins(1);

/// Budget for QEMU to exit after its `SHUTDOWN` event.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// The power-button cause's boot (`x86_64` only). The caller has checked the
/// sysroot and admitted the boot.
pub(super) fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    let qemu_binary = require_tool(Arch::X86_64.qemu_binary())?;
    // Declared before the guest, so it is removed after QEMU is reaped.
    let sockets = SocketDir::create()?;
    let sock = sockets.socket("power-button.qmp")?;

    step("power-button test: booting, waiting for the events to be armed");
    // Every `?` below drops the live `Guest`, which kills and reaps its QEMU
    // (see `Guest`).
    let mut guest = launch(&qemu_binary, ctx, args, &sock)?;
    guest
        .wait_for_markers(&[ARMED_MARKER, READY_MARKER], BOOT_TIMEOUT)
        .context("boot")?;

    step("power-button test: pressing the power button (QMP system_powerdown)");
    let reason = {
        let sock = sock.clone();
        std::thread::spawn(move || qmp::powerdown(&sock, PRESS_TIMEOUT))
    };
    let lines = guest.wait_for_markers(&[PRESS_MARKER, PWRMGR_MARKER, SLEEP_MARKER], PRESS_TIMEOUT);
    let reason = reason
        .join()
        .map_err(|_| crate::error::Error::msg("the QMP thread panicked"))?;
    let verdict = lines
        .context("the press")
        .and_then(|()| judge(&reason?))
        .and_then(|()| guest.wait_exit(EXIT_TIMEOUT));
    verdict?;
    step("power-button test: PASS (the press powered the machine off)");
    Ok(())
}

/// Launch QEMU for the boot, with its QMP socket at `sock`.
fn launch(qemu_binary: &Path, ctx: &Context, args: &CaseArgs, sock: &Path) -> Result<Guest>
{
    let disk_path = ctx.disk_image();
    let firmware = Firmware::prepare(ctx, Arch::X86_64)?;
    let vars = firmware.launch_vars()?;
    let spec = QemuLaunchSpec {
        arch: Arch::X86_64,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: None,
        firmware_code_path: &firmware.code,
        firmware_vars_path: vars.path(),
        smm: firmware.smm,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: Some(sock),
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
    let child = Command::new(qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning qemu-system-x86_64")?;
    Ok(Guest::from_child(child)?.holding(vars))
}

/// The verdict on the `SHUTDOWN` event's `reason`: a power-off passes, a
/// reset or any other cause fails.
fn judge(reason: &str) -> Result<()>
{
    if reason != POWER_OFF_REASON
    {
        bail!("QEMU's SHUTDOWN event gave reason {reason:?}, not {POWER_OFF_REASON:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a press that reset the machine, or a shutdown QEMU
    // made for another cause, judged a pass.
    #[test]
    fn only_a_guest_power_off_passes()
    {
        judge(POWER_OFF_REASON).unwrap();
        judge("guest-reset").unwrap_err();
        judge("host-qmp-quit").unwrap_err();
        judge("unknown").unwrap_err();
    }
}
