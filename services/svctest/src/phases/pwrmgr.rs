// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/pwrmgr.rs

//! pwrmgr service surface: cap-deny enforcement, terminal shutdown, and the
//! `reboot` re-entry role the `shutdown` case's reboot boot stages.

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// Only the deny-cap phase is registry-resident. The shutdown phase is
/// terminal and invoked from `main` explicitly after the runner
/// completes and `ALL TESTS PASSED` has been logged.
pub fn deny_only() -> &'static [Phase]
{
    &[Phase {
        name: "pwrmgr_cap_deny",
        run: pwrmgr_cap_deny_phase,
    }]
}

pub fn pwrmgr_cap_deny_phase(caps: &Caps)
{
    let pwrmgr_noauth_cap = caps.pwrmgr_noauth;
    if pwrmgr_noauth_cap == 0
    {
        std::os::seraph::log!("pwrmgr cap-deny phase skipped: no no-authority cap");
        return;
    }

    let ipc_buf = std::os::seraph::current_ipc_buf();

    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(pwrmgr_noauth_cap, &msg, ipc_buf) }
        .expect("pwrmgr SHUTDOWN ipc_call (no-auth) must return a reply");
    assert_eq!(
        reply.label,
        ipc::pwrmgr_errors::UNAUTHORIZED,
        "pwrmgr SHUTDOWN through no-authority cap must reply UNAUTHORIZED (got {:#x})",
        reply.label
    );
    std::os::seraph::log!("pwrmgr cap-deny phase passed (UNAUTHORIZED reply)");
}

/// The `reboot` role, run by the `reboot` test recipe
/// (`rootfs/config/svcmgr/tests/reboot.svc`, which the
/// `shutdown` case's reboot boot stages): drain the one-seed bootstrap round
/// (`pwrmgr.shutdown`) and send `REBOOT` through it. On the success path
/// the machine resets, which ends QEMU under `-no-reboot`; a reply, or no
/// cap, is logged and the role exits 1. Returns on any other role.
pub fn reentry_main(role: &str)
{
    if role != "reboot"
    {
        return;
    }
    let info = std::os::seraph::startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let cap = if info.creator_endpoint == 0
    {
        0
    }
    else
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer.
        unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) }
            .map_or(0, |[cap]| cap)
    };
    if cap == 0
    {
        std::os::seraph::log!("reboot fixture: no pwrmgr.shutdown seed");
        std::process::exit(1);
    }
    std::os::seraph::log!("reboot fixture: requesting REBOOT");
    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::REBOOT);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer.
    match unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
    {
        Ok(r) => std::os::seraph::log!(
            "reboot fixture: pwrmgr REBOOT returned (label={:#x})",
            r.label
        ),
        Err(e) => std::os::seraph::log!("reboot fixture: pwrmgr REBOOT ipc_call failed ({e})"),
    }
    std::process::exit(1);
}

/// Terminal-only. On the success path the platform powers off and
/// QEMU exits; no return. A reply arrives only on failure (pwrmgr
/// could not power off the platform, or the cap is missing the
/// authority badge); in that case svctest logs and falls through to
/// its normal `thread_exit`, leaving the system idle.
pub fn pwrmgr_shutdown_phase(caps: &Caps)
{
    request_shutdown(caps.pwrmgr_auth);
}

/// Send `SHUTDOWN` on `pwrmgr_auth_cap`, the authority-badged pwrmgr cap.
/// When the cap is zero, pwrmgr replies, or the call fails, it logs the
/// outcome and returns. It never panics or allocates, because the failure
/// hooks call it too.
pub fn request_shutdown(pwrmgr_auth_cap: u64)
{
    if pwrmgr_auth_cap == 0
    {
        std::os::seraph::log!("pwrmgr SHUTDOWN skipped: no authority cap");
        return;
    }

    let ipc_buf = std::os::seraph::current_ipc_buf();

    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(pwrmgr_auth_cap, &msg, ipc_buf) };
    match reply
    {
        Ok(r) => std::os::seraph::log!(
            "pwrmgr SHUTDOWN returned unexpectedly (label={:#x})",
            r.label
        ),
        Err(_) => std::os::seraph::log!("pwrmgr SHUTDOWN ipc_call failed"),
    }
}
