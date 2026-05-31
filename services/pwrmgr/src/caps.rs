// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// pwrmgr/src/caps.rs

//! Bootstrap and devmgr-query acquisition for pwrmgr.
//!
//! pwrmgr is a svcmgr-launched provider. Its bootstrap round (served by
//! svcmgr's provider path) delivers:
//!
//! * `caps[0]` = pwrmgr's own service endpoint (RECV; the SHUTDOWN/REBOOT
//!   receive end). svcmgr holds the persistent source and publishes
//!   `pwrmgr.shutdown` / `pwrmgr.deny` SENDs against it.
//! * `caps[1]` = `REGISTRY_QUERY_AUTHORITY`-tokened SEND on devmgr's
//!   registry endpoint (from `pwrmgr.svc` `seed = devmgr.registry`).
//!
//! pwrmgr owns no hardware caps directly. It acquires its shutdown
//! actuator caps from devmgr "as if it were a device driver": the ACPI
//! tables it interprets come from [`devmgr_labels::QUERY_ACPI_TABLE`]
//! (devmgr is the sole ACPI owner) and the carved I/O-port / `SbiControl`
//! caps from [`devmgr_labels::QUERY_SHUTDOWN_DEVICE`]. The arch module
//! ([`crate::arch`]) drives those queries and parses what it needs; devmgr
//! runs no shutdown logic.

use ipc::{IpcMessage, devmgr_errors};
use std::os::seraph::StartupInfo;

/// Caps delivered to pwrmgr by svcmgr's provider bootstrap round.
pub struct Bootstrap
{
    /// pwrmgr's service endpoint (RECV). Zero if the round was empty.
    pub service_ep: u32,
    /// `REGISTRY_QUERY_AUTHORITY`-tokened SEND on devmgr's registry
    /// endpoint. Zero if absent — the arch module then degrades to its
    /// no-actuator path.
    pub devmgr_registry: u32,
}

/// Drain the single provider bootstrap round from `creator_endpoint`.
pub fn request_bootstrap(info: &StartupInfo, ipc_buf: *mut u64) -> Option<Bootstrap>
{
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }
    // SAFETY: `ipc_buf` is the kernel-registered per-thread IPC buffer.
    let round = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    let service_ep = if round.cap_count >= 1
    {
        round.caps[0]
    }
    else
    {
        0
    };
    let devmgr_registry = if round.cap_count >= 2
    {
        round.caps[1]
    }
    else
    {
        0
    };
    Some(Bootstrap {
        service_ep,
        devmgr_registry,
    })
}

/// Issue a devmgr registry query and return the reply on a
/// [`devmgr_errors::SUCCESS`] status. `word1` / `word2` are the
/// label-specific request words (`data[1]` / `data[2]`); `data[0]` is
/// always the compiled `DEVMGR_LABELS_VERSION` so devmgr can version-gate.
/// Returns `None` on a transport error or any non-success reply.
pub(crate) fn devmgr_call(
    registry: u32,
    label: u64,
    word1: u64,
    word2: u64,
    ipc_buf: *mut u64,
) -> Option<IpcMessage>
{
    if registry == 0
    {
        return None;
    }
    let msg = IpcMessage::builder(label)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .word(1, word1)
        .word(2, word2)
        .build();
    // SAFETY: `ipc_buf` is the kernel-registered per-thread IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry, &msg, ipc_buf) }.ok()?;
    if reply.label != devmgr_errors::SUCCESS
    {
        return None;
    }
    Some(reply)
}
