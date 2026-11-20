// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/arch/riscv64/mod.rs

//! RISC-V platform shutdown and reboot via the SBI SRST extension.
//!
//! pwrmgr owns the actuation; devmgr owns the `SbiControl` authority. At
//! startup pwrmgr asks devmgr for a Reset-only derivation of it via
//! [`devmgr_labels::QUERY_SHUTDOWN_DEVICE`], then forwards an SBI
//! `system_reset` call through the kernel to M-mode firmware. The
//! `SbiControl` cap gates kernel-side acceptance; pwrmgr's cap-gating
//! gates the userspace IPC. acpid serves no power request on RISC-V and
//! the platform has no ACPI power button, so the `acpid.power` seed is
//! deleted.

use crate::caps::{Bootstrap, drop_unused};
use ipc::{IpcMessage, devmgr_errors, devmgr_labels};

const SBI_EXT_SRST: u64 = 0x5352_5354; // "SRST" in ASCII.
const SBI_SRST_RESET: u64 = 0; // function 0: system_reset
const SRST_TYPE_SHUTDOWN: u64 = 0;
const SRST_TYPE_COLD_REBOOT: u64 = 1;
const SRST_REASON_NONE: u64 = 0;

/// Resolved shutdown actuation state: a Reset-only derivation of devmgr's
/// `SbiControl` cap, acquired once at startup and held for pwrmgr's
/// lifetime.
#[derive(Clone, Copy)]
pub struct Actuator
{
    sbi_control_cap: u64,
}

/// Resolve the SBI SRST authority from devmgr through the
/// `devmgr.shutdown` seed, which is then deleted. Returns `None` if the seed
/// is absent, the query fails, or devmgr served no cap.
pub fn resolve(bootstrap: &Bootstrap, ipc_buf: *mut u64) -> Option<Actuator>
{
    drop_unused(bootstrap.acpid_power);
    let registry = bootstrap.devmgr_shutdown;
    if registry == 0
    {
        return None;
    }
    let msg = IpcMessage::builder(devmgr_labels::QUERY_SHUTDOWN_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: `ipc_buf` is the kernel-registered per-thread IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry, &msg, ipc_buf) };
    let _ = syscall::cap_delete(registry);
    let reply = reply.ok()?;
    if reply.label != devmgr_errors::SUCCESS
    {
        return None;
    }
    let sbi_control_cap = *reply.caps().first()?;
    Some(Actuator { sbi_control_cap })
}

/// A no-op: QEMU `virt`'s ACPI is hardware-reduced, with no fixed power
/// button for acpid to report.
pub const fn watch_events(_act: Actuator) {}

/// The core-death power-off: the same `SbiControl` derivation, which the
/// SRST call needs alone.
pub struct PowerOff
{
    sbi_control_cap: u64,
}

/// The core-death power-off from `actuator`, the SRST authority resolved at
/// startup; `None` without one.
pub fn resolve_power_off(actuator: Option<&Actuator>, _ipc_buf: *mut u64) -> Option<PowerOff>
{
    actuator.map(|act| PowerOff {
        sbi_control_cap: act.sbi_control_cap,
    })
}

/// Power off at once: SBI SRST shutdown through the kernel. Allocates,
/// logs and calls nothing; returns only when the kernel or the firmware
/// refuses the call, and the caller then takes the ordinary shutdown.
pub fn power_off_now(power_off: &PowerOff)
{
    let _ = syscall::sbi_call(
        power_off.sbi_control_cap,
        SBI_EXT_SRST,
        SBI_SRST_RESET,
        SRST_TYPE_SHUTDOWN,
        SRST_REASON_NONE,
        0,
    );
}

/// Attempt SBI SRST shutdown. Logs and returns on failure.
pub fn shutdown(act: &Actuator, _ipc_buf: *mut u64)
{
    sbi_reset(*act, SRST_TYPE_SHUTDOWN, "shutdown");
}

/// Attempt SBI SRST cold reboot. Logs and returns on failure.
pub fn reboot(act: &Actuator, _ipc_buf: *mut u64)
{
    sbi_reset(*act, SRST_TYPE_COLD_REBOOT, "reboot");
}

/// Issue SBI `system_reset` of `reset_type` through the kernel. Does not
/// return when the platform resets. Logs and returns when the kernel or
/// firmware rejects the call, and, after [`crate::await_reset`]'s grace,
/// when the call returned success but the platform kept running (SRST does
/// not return on success, so that is a firmware failure too).
fn sbi_reset(act: Actuator, reset_type: u64, op: &str)
{
    let result = syscall::sbi_call(
        act.sbi_control_cap,
        SBI_EXT_SRST,
        SBI_SRST_RESET,
        reset_type,
        SRST_REASON_NONE,
        0,
    );
    match result
    {
        Ok(_) => crate::await_reset(op),
        Err(e) => std::os::seraph::log!(error: "{op} failed (sbi_call err={e})"),
    }
}
