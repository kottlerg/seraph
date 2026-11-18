// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/main.rs

//! Seraph power manager — userspace authority for platform shutdown and
//! reboot.
//!
//! pwrmgr is a svcmgr-launched provider. It owns the shutdown policy and
//! holds no hardware caps of its own: on x86-64 it reaches the ACPI sleep
//! and reset registers through acpid, which runs the AML and holds the
//! FADT's register blocks, and on RISC-V it drives SBI SRST through a
//! `SbiControl` derivation it acquires from devmgr at startup. svcmgr
//! publishes a `SHUTDOWN_AUTHORITY`-badged SEND (`pwrmgr.shutdown`) and its
//! no-auth twin (`pwrmgr.deny`) on pwrmgr's service endpoint; the recipes
//! that seed `pwrmgr.shutdown` hold the authority, and svcmgr calls it as
//! the shutdown actuator. On x86-64 a second thread waits on acpid for the
//! power button and powers the platform off when it is pressed.
//!
//! As the shutdown actuator pwrmgr also observes svcmgr: svcmgr serves it a
//! receive-only derivation of the event queue svcmgr's own main thread and
//! address space post their death to, and pwrmgr waits on that queue beside
//! its service endpoint. An entry is svcmgr's death, and pwrmgr powers the
//! platform off (docs/supervision.md § Observing svcmgr).
//!
//! See `services/pwrmgr/README.md` for the design and future-scope
//! sketch.

mod arch;
mod caps;

use ipc::{IpcMessage, pwrmgr_errors, pwrmgr_labels};
use std::os::seraph::startup_info;
use std::time::Duration;

/// How long pwrmgr waits after a power-off or reset request returns before
/// treating it as failed. A platform that acts on the request stops
/// executing well within this (QEMU at once); the wait keeps the error
/// reply from racing a reset that lands shortly after the request returns.
const RESET_GRACE: Duration = Duration::from_secs(1);

fn main() -> !
{
    std::os::seraph::log::register_name(b"pwrmgr");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is page-aligned (4 KiB) by the boot protocol, satisfying u64 alignment"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(bootstrap) = caps::request_bootstrap(info, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "bootstrap failed, exiting");
        syscall::thread_exit();
    };

    if bootstrap.service_ep == 0
    {
        std::os::seraph::log!(error: "no service endpoint, exiting");
        syscall::thread_exit();
    }

    // Resolve the actuation state. `None` means the platform authority
    // could not be resolved; pwrmgr still serves so callers get a clean
    // error rather than a hung ipc_call.
    let actuator = arch::current::resolve(&bootstrap, ipc_buf);
    if let Some(act) = &actuator
    {
        arch::current::watch_events(*act);
        std::os::seraph::log!("ready");
    }
    else
    {
        std::os::seraph::log!(warn: "ready (degraded: no shutdown actuator)");
    }

    let wait_set = observe_svcmgr(bootstrap.service_ep, bootstrap.svcmgr_death);

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        if wait_set != 0
        {
            match syscall::wait_set_wait(wait_set)
            {
                Ok(WAKE_SVCMGR_DEATH) =>
                {
                    svcmgr_died(bootstrap.svcmgr_death, actuator.as_ref(), ipc_buf);
                    continue;
                }
                Ok(_) =>
                {}
                Err(e) =>
                {
                    guard.on_failure(e);
                    continue;
                }
            }
        }
        // A wake on the endpoint is readiness that can lapse before the
        // receive (its caller stopped or destroyed in between). With the wait
        // set the receive does not block, so the wait, where svcmgr's death
        // is seen, stays pwrmgr's one blocking point.
        let received = if wait_set == 0
        {
            // SAFETY: ipc_buf is the registered IPC buffer.
            unsafe { ipc::ipc_recv(bootstrap.service_ep, ipc_buf) }
        }
        else
        {
            // SAFETY: ipc_buf is the registered IPC buffer.
            unsafe { ipc::ipc_try_recv(bootstrap.service_ep, ipc_buf) }
        };
        let msg = match received
        {
            Ok(msg) => msg,
            Err(e) if wait_set != 0 && e == syscall_abi::SyscallError::WouldBlock as i64 =>
            {
                continue;
            }
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        let authorized = msg.badge & pwrmgr_labels::SHUTDOWN_AUTHORITY != 0;
        match msg.label
        {
            pwrmgr_labels::SHUTDOWN =>
            {
                if !authorized
                {
                    reject(pwrmgr_errors::UNAUTHORIZED, ipc_buf);
                    continue;
                }
                std::os::seraph::log!("SHUTDOWN requested");
                if let Some(act) = &actuator
                {
                    arch::current::shutdown(act, ipc_buf);
                }
                // Reached here → no actuator or shutdown failed. Reply so
                // the caller does not hang on its ipc_call.
                reject(pwrmgr_errors::INVALID_REQUEST, ipc_buf);
            }
            pwrmgr_labels::REBOOT =>
            {
                if !authorized
                {
                    reject(pwrmgr_errors::UNAUTHORIZED, ipc_buf);
                    continue;
                }
                std::os::seraph::log!("REBOOT requested");
                if let Some(act) = &actuator
                {
                    arch::current::reboot(act, ipc_buf);
                }
                reject(pwrmgr_errors::INVALID_REQUEST, ipc_buf);
            }
            _ => reject(pwrmgr_errors::UNKNOWN_OPCODE, ipc_buf),
        }
    }
}

/// Wait-set badge of pwrmgr's service endpoint.
const WAKE_REQUEST: u64 = 0;
/// Wait-set badge of the queue svcmgr's death posts to.
const WAKE_SVCMGR_DEATH: u64 = 1;
/// Members of the wait set: the service endpoint and svcmgr's death queue.
const WAIT_SET_MEMBERS: u32 = 2;

/// Make the wait set over pwrmgr's service endpoint and `svcmgr_death`, the
/// receive-only derivation of svcmgr's own death queue. `0`, logged, when the
/// queue is absent or the set cannot be made: pwrmgr then receives on its
/// endpoint alone, and svcmgr's death goes unobserved.
fn observe_svcmgr(service_ep: u64, svcmgr_death: u64) -> u64
{
    if svcmgr_death == 0
    {
        std::os::seraph::log!(error: "no svcmgr death queue; svcmgr's death is unobserved");
        return 0;
    }
    let wait_set = std::os::seraph::object_slab_retype(
        std::os::seraph::wait_set_retype_bytes(u64::from(WAIT_SET_MEMBERS)),
        |slab| syscall::wait_set_create(slab, WAIT_SET_MEMBERS).ok(),
    )
    .unwrap_or(0);
    let joined = wait_set != 0
        && syscall::wait_set_add(wait_set, service_ep, WAKE_REQUEST).is_ok()
        && syscall::wait_set_add(wait_set, svcmgr_death, WAKE_SVCMGR_DEATH).is_ok();
    if !joined
    {
        if wait_set != 0
        {
            // Deleting the set removes the members it took.
            let _ = syscall::cap_delete(wait_set);
        }
        std::os::seraph::log!(error: "svcmgr death wait set not made; svcmgr's death is unobserved");
        return 0;
    }
    wait_set
}

/// svcmgr has died: drain the entries its observers posted to
/// `svcmgr_death` and power the platform off through `actuator`, the path a
/// `SHUTDOWN` request takes. With no actuator, or a power-off that does not
/// take effect, pwrmgr logs it and serves on.
fn svcmgr_died(svcmgr_death: u64, actuator: Option<&arch::current::Actuator>, ipc_buf: *mut u64)
{
    // svcmgr's main thread and its address space each post one entry; the
    // first names the exit reason, and the rest are the same death.
    let mut reason = None;
    while let Ok(death) = syscall::event_try_recv_death(svcmgr_death)
    {
        reason.get_or_insert(death.exit_reason);
    }
    match reason
    {
        Some(r) => std::os::seraph::log!(error: "svcmgr died (exit reason {r:#x}); powering off"),
        None => std::os::seraph::log!(error: "svcmgr died; powering off"),
    }
    match actuator
    {
        Some(act) => arch::current::shutdown(act, ipc_buf),
        None => std::os::seraph::log!(error: "svcmgr died; no shutdown actuator to power off"),
    }
}

/// Wait out [`RESET_GRACE`] after a power-off or reset request (`op`) that
/// returned, then log that it did not take effect. The arch routine then
/// returns, and `main` replies `pwrmgr_errors::INVALID_REQUEST`, so the
/// caller is answered whenever the platform keeps running. Blocks in
/// `thread_sleep`, which is legal in user mode on every architecture.
pub(crate) fn await_reset(op: &str)
{
    std::thread::sleep(RESET_GRACE);
    std::os::seraph::log!(error: "{op} did not take effect");
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

fn reject(code: u64, ipc_buf: *mut u64)
{
    let reply = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}
