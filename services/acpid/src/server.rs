// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/server.rs

//! acpid's service loop: the power requests of `ipc::acpid_labels`, served
//! on the evaluation thread once start-up is done, so that one thread owns
//! the namespace and every evaluation runs in turn. A request sent during
//! start-up waits in the endpoint's queue.

use acpid::power::{self, Request};
use aml::{Evaluator, Namespace};
use ipc::{IpcMessage, acpid_errors};

use crate::arch::current::Power;
use crate::platform::Platform;

/// Serve the requests received on `service` for acpid's lifetime: `ns`
/// is the namespace start-up loaded, `None` when the DSDT could not be;
/// `platform` the evaluator's host; `power` the sleep and reset registers.
/// A receive that keeps failing exits acpid (`ipc::recv_guard`), and
/// svcmgr restarts it.
pub fn serve(
    service: u64,
    mut ns: Option<&mut Namespace>,
    platform: &mut Platform<'_>,
    power: &Power,
) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
        let msg = match unsafe { ipc::ipc_recv(service, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        let status = match power::decode(msg.label, msg.badge, msg.word(0), msg.word(1))
        {
            Ok(Request::Sleep(state)) => sleep(state, ns.as_deref_mut(), platform, power),
            Ok(Request::Reset) => reset(power),
            Err(code) => code,
        };
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(status), ipc_buf) };
    }
}

/// Enter sleep state `state`: its `SLP_TYPa`, then `\_PTS`, then the
/// `PM1a_CNT` writes. The reply status when the platform keeps running.
fn sleep(state: u8, ns: Option<&mut Namespace>, platform: &mut Platform<'_>, power: &Power) -> u64
{
    if !power.can_sleep()
    {
        std::os::seraph::log!(warn: "SLEEP({state}) refused: no PM1a control block");
        return acpid_errors::NO_DEVICE;
    }
    let Some(ns) = ns
    else
    {
        std::os::seraph::log!(warn: "SLEEP({state}) refused: no AML loaded");
        return acpid_errors::NO_DEVICE;
    };
    let mut ev = Evaluator::new(ns, platform);
    let slp_typ = match power::sleep_type(&mut ev, state)
    {
        Ok(Some(slp_typ)) => slp_typ,
        Ok(None) =>
        {
            std::os::seraph::log!(warn: "SLEEP({state}) refused: no \\_S{state}_ package");
            return acpid_errors::NO_DEVICE;
        }
        Err(why) =>
        {
            std::os::seraph::log!(warn: "SLEEP({state}) refused: \\_S{state}_ failed: {why:?}");
            return acpid_errors::NO_DEVICE;
        }
    };
    if let Some(fault) = power::prepare(&mut ev, state)
    {
        std::os::seraph::log!(warn: "\\_PTS({state}) faulted: {fault:?}; sleeping anyway");
    }
    if power.sleep(state, slp_typ)
    {
        acpid_errors::SUCCESS
    }
    else
    {
        acpid_errors::NO_DEVICE
    }
}

/// Reset through `RESET_REG`. The reply status when the platform keeps
/// running.
fn reset(power: &Power) -> u64
{
    if power.reset()
    {
        acpid_errors::SUCCESS
    }
    else
    {
        std::os::seraph::log!(warn: "RESET refused: no RESET_REG");
        acpid_errors::NO_DEVICE
    }
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
