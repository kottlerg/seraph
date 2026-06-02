// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! pwrmgr service surface: cap-deny enforcement + terminal shutdown.

use std::os::seraph::startup_info;

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

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

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

/// Terminal-only. On the success path the platform powers off and
/// QEMU exits; no return. A reply arrives only on failure (pwrmgr
/// could not power off the platform, or the cap is missing the
/// authority badge); in that case svctest logs and falls through to
/// its normal `thread_exit`, leaving the system idle.
pub fn pwrmgr_shutdown_phase(caps: &Caps)
{
    let pwrmgr_auth_cap = caps.pwrmgr_auth;
    if pwrmgr_auth_cap == 0
    {
        std::os::seraph::log!("pwrmgr shutdown phase skipped: no authority cap");
        return;
    }

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

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
