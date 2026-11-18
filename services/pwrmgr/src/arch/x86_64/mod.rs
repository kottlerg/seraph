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
//! Each call is bounded by [`ACPID_CALL_TIMEOUT_MS`], so an acpid that is
//! down, or blocked, fails the request instead of holding pwrmgr and its
//! caller, svcmgr's graceful shutdown among them. On any failure, including
//! a request acpid carried out without the platform acting within
//! [`crate::await_reset`]'s grace, a routine logs and returns, and the
//! caller (`main`) replies `pwrmgr_errors::INVALID_REQUEST`. acpid
//! answers a `SLEEP` only 10 s after its writes (its `SLEEP_GRACE`), so a
//! power-off the platform does not act on fails about 11 s after it was
//! issued, a reboot about one second after.
//!
//! The power button reaches pwrmgr through acpid too: a thread of its own
//! ([`watch_events`]) waits in [`acpid_labels::WAIT_EVENT`] and powers
//! off on a press, as `SHUTDOWN` does.

use std::time::Duration;

use crate::caps::{Bootstrap, drop_unused};
use ipc::{IpcMessage, acpid_errors, acpid_labels};

/// The bound on one acpid call, from the send to the reply, in
/// milliseconds. A time bound that bounds no capacity: far above acpid's
/// start-up, which a request sent during it waits behind, and its `\_PTS`
/// evaluation, so a live acpid answers within it; an acpid that is down or
/// blocked (on a dead devmgr, say) fails the request after it.
const ACPID_CALL_TIMEOUT_MS: u32 = 30_000;

/// How long the event thread waits before it calls `WAIT_EVENT` again
/// after a call that failed in transit: acpid died holding it, and svcmgr
/// restarts acpid on the same endpoint.
const WAIT_EVENT_RETRY: Duration = Duration::from_secs(1);

/// Resolved actuation state: the `acpid.power` SEND.
#[derive(Clone, Copy)]
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

/// Watch the power button: spawn the event thread, which waits in acpid's
/// `WAIT_EVENT` for pwrmgr's lifetime and powers off on a press. A thread
/// that cannot be spawned is logged, and pwrmgr serves without it.
pub fn watch_events(act: Actuator)
{
    let spawned = std::thread::Builder::new()
        .name("pwrmgr-events".into())
        .spawn(move || events(&act));
    if let Err(e) = spawned
    {
        std::os::seraph::log!(error: "power-button thread not spawned: {e}");
    }
}

/// The event thread: call `WAIT_EVENT` with no bound, and on the power
/// button power off as `SHUTDOWN` does. A call that fails in transit is
/// made again after [`WAIT_EVENT_RETRY`], and a superseded one at once; any
/// other reply (acpid has no event to wait for, or refuses the call) ends
/// the thread, logged.
fn events(act: &Actuator)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    std::os::seraph::log!("watching the power button");
    let msg = IpcMessage::builder(acpid_labels::WAIT_EVENT)
        .word(0, u64::from(ipc::ACPID_LABELS_VERSION))
        .build();
    loop
    {
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
        match unsafe { ipc::ipc_call(act.acpid, &msg, ipc_buf) }
        {
            Ok(reply) if reply.label == acpid_errors::SUCCESS =>
            {
                if reply.word(0) & acpid_labels::EVENT_POWER_BUTTON != 0
                {
                    std::os::seraph::log!("power button: shutting down");
                    shutdown(act, ipc_buf);
                }
            }
            Ok(reply) if reply.label == acpid_errors::SUPERSEDED =>
            {}
            Ok(reply) =>
            {
                std::os::seraph::log!(
                    "not watching the power button (acpid replied {:#x})",
                    reply.label
                );
                return;
            }
            Err(e) =>
            {
                std::os::seraph::log!(warn: "WAIT_EVENT failed (err={e}); calling again");
                std::thread::sleep(WAIT_EVENT_RETRY);
            }
        }
    }
}

/// Call acpid's `label` with `arg` in `data[1]`, bounded by
/// [`ACPID_CALL_TIMEOUT_MS`]. A `SUCCESS` reply means acpid wrote the
/// register and the platform still runs, so pwrmgr waits out
/// [`crate::await_reset`]'s grace; any other reply, a failed call, or no
/// answer within the bound is logged.
fn call(act: &Actuator, label: u64, arg: u64, op: &str, ipc_buf: *mut u64)
{
    let msg = IpcMessage::builder(label)
        .word(0, u64::from(ipc::ACPID_LABELS_VERSION))
        .word(1, arg)
        .build();
    // SAFETY: `ipc_buf` is the kernel-registered per-thread IPC buffer.
    match unsafe { ipc::ipc_call_timeout(act.acpid, &msg, ipc_buf, ACPID_CALL_TIMEOUT_MS) }
    {
        Ok(reply) if reply.label == acpid_errors::SUCCESS => crate::await_reset(op),
        Ok(reply) =>
        {
            std::os::seraph::log!(error: "{op} failed (acpid replied {:#x})", reply.label);
        }
        Err(e) if e == syscall_abi::SyscallError::WouldBlock as i64 =>
        {
            std::os::seraph::log!(
                error: "{op} failed (acpid did not answer within {ACPID_CALL_TIMEOUT_MS} ms)"
            );
        }
        Err(e) => std::os::seraph::log!(error: "{op} failed (acpid call err={e})"),
    }
}
