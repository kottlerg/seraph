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
//! gates the userspace IPC.

use crate::caps::devmgr_call;
use ipc::devmgr_labels;

const SBI_EXT_SRST: u64 = 0x5352_5354; // "SRST" in ASCII.
const SBI_SRST_RESET: u64 = 0; // function 0: system_reset
const SRST_TYPE_SHUTDOWN: u64 = 0;
const SRST_TYPE_COLD_REBOOT: u64 = 1;
const SRST_REASON_NONE: u64 = 0;

/// Resolved shutdown actuation state: a Reset-only derivation of devmgr's
/// `SbiControl` cap, acquired once at startup and held for pwrmgr's
/// lifetime.
pub struct Actuator
{
    sbi_control_cap: u32,
}

/// Resolve the SBI SRST authority from devmgr. Returns `None` if the query
/// fails or devmgr served no cap.
pub fn resolve(devmgr_registry: u32, _self_aspace: u32, ipc_buf: *mut u64) -> Option<Actuator>
{
    let reply = devmgr_call(
        devmgr_registry,
        devmgr_labels::QUERY_SHUTDOWN_DEVICE,
        0,
        0,
        ipc_buf,
    )?;
    let sbi_control_cap = *reply.caps().first()?;
    Some(Actuator { sbi_control_cap })
}

/// Attempt SBI SRST shutdown. Logs and returns on failure.
pub fn shutdown(_self_thread: u32, act: &Actuator)
{
    sbi_reset(act, SRST_TYPE_SHUTDOWN, "shutdown");
}

/// Attempt SBI SRST cold reboot. Logs and returns on failure.
pub fn reboot(_self_thread: u32, act: &Actuator)
{
    sbi_reset(act, SRST_TYPE_COLD_REBOOT, "reboot");
}

/// Issue SBI `system_reset` of `reset_type` through the kernel. Does not
/// return when the platform resets. Logs and returns when the kernel or
/// firmware rejects the call, and, after [`crate::await_reset`]'s grace,
/// when the call returned success but the platform kept running (SRST does
/// not return on success, so that is a firmware failure too).
fn sbi_reset(act: &Actuator, reset_type: u64, op: &str)
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
        Err(e) => std::os::seraph::log!("{op} failed (sbi_call err={e})"),
    }
}
