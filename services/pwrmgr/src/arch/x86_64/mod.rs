// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/arch/x86_64/mod.rs

//! x86-64 platform shutdown and reboot, through acpid.
//!
//! The ACPI sleep and reset sequences run in acpid, which holds the FADT's
//! fixed register blocks and runs the AML (`services/acpid/README.md`
//! § Power requests): pwrmgr calls [`acpid_labels::SLEEP`] with
//! [`acpid_labels::STATE_S5`] to power off and [`acpid_labels::RESET`] to
//! reboot, through the `acpid.power` seed. It holds no port of its own and
//! reads no table.
//!
//! On any failure, including a request acpid carried out without the
//! platform acting within [`crate::await_reset`]'s grace, a routine logs
//! and returns, and the caller (`main`) replies
//! `pwrmgr_errors::INVALID_REQUEST`.

use crate::caps::{Bootstrap, drop_unused};
use ipc::{IpcMessage, acpid_errors, acpid_labels};

/// Resolved actuation state: the `acpid.power` SEND.
pub struct Actuator
{
    acpid: u64,
}

/// Keep the `acpid.power` seed and delete the `devmgr.shutdown` one, which
/// serves nothing on x86-64. `None`, logged, when the seed is absent.
pub fn resolve(bootstrap: &Bootstrap, _ipc_buf: *mut u64) -> Option<Actuator>
{
    drop_unused(bootstrap.devmgr_shutdown);
    if bootstrap.acpid_power == 0
    {
        // Loud: a boot whose final shutdown cannot run still passes on its
        // harness marker, so this line is what shows the missing seed.
        std::os::seraph::log!(error: "no acpid.power seed: SHUTDOWN and REBOOT cannot run");
        return None;
    }
    Some(Actuator {
        acpid: bootstrap.acpid_power,
    })
}

/// Power off: acpid's `SLEEP(5)`. Does not return when the platform powers
/// off; logs and returns otherwise.
pub fn shutdown(act: &Actuator, ipc_buf: *mut u64)
{
    call(
        act,
        acpid_labels::SLEEP,
        acpid_labels::STATE_S5,
        "shutdown",
        ipc_buf,
    );
}

/// Reboot: acpid's `RESET`, the FADT reset register. Does not return when
/// the platform resets; logs and returns otherwise.
pub fn reboot(act: &Actuator, ipc_buf: *mut u64)
{
    call(act, acpid_labels::RESET, 0, "reboot", ipc_buf);
}

/// Call acpid's `label` with `arg` in `data[1]`. A `SUCCESS` reply means
/// acpid wrote the register and the platform still runs, so pwrmgr waits out
/// [`crate::await_reset`]'s grace; any other reply or a failed call is
/// logged.
fn call(act: &Actuator, label: u64, arg: u64, op: &str, ipc_buf: *mut u64)
{
    let msg = IpcMessage::builder(label)
        .word(0, u64::from(ipc::ACPID_LABELS_VERSION))
        .word(1, arg)
        .build();
    // SAFETY: `ipc_buf` is the kernel-registered per-thread IPC buffer.
    match unsafe { ipc::ipc_call(act.acpid, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == acpid_errors::SUCCESS => crate::await_reset(op),
        Ok(reply) =>
        {
            std::os::seraph::log!(error: "{op} failed (acpid replied {:#x})", reply.label);
        }
        Err(e) => std::os::seraph::log!(error: "{op} failed (acpid call err={e})"),
    }
}
