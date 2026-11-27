// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/caps.rs

//! acpid's bootstrap round.
//!
//! svcmgr delivers three capabilities: `caps[0]`, the RECV on acpid's own
//! service endpoint (`provides`), on which svcmgr publishes `acpid.power`
//! and `acpid.deny`; `caps[1]`, the `devmgr.acpi` seed, a SEND on
//! devmgr's registry endpoint badged `REGISTRY_QUERY_AUTHORITY |
//! ACPI_AUTHORITY`; and `caps[2]`, the `logd.flush` seed, a SEND on the
//! master log endpoint badged `LOG_FLUSH_AUTHORITY`, through which acpid
//! waits for logd to write its line before a write that ends the machine.

use std::os::seraph::StartupInfo;

/// The capabilities of acpid's bootstrap round.
pub struct Caps
{
    /// acpid's service endpoint (RECV), `0` when not delivered.
    pub service: u64,
    /// The `devmgr.acpi` SEND, `0` when not delivered.
    pub registry: u64,
    /// The `logd.flush` SEND, `0` when not delivered.
    pub log_flush: u64,
}

/// Drain the bootstrap rounds from the creator; `None` when the round
/// fails. A capability the round did not deliver is `0`.
pub fn request_bootstrap(info: &StartupInfo, ipc_buf: *mut u64) -> Option<Caps>
{
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }
    // SAFETY: `ipc_buf` is the kernel-registered IPC buffer of this thread.
    // Only the present caps ride, named by each round's presence word; an
    // absent slot decodes as `0`.
    let [service, registry, log_flush] =
        unsafe { ipc::bootstrap::request_slots::<3>(creator, ipc_buf) }.ok()?;
    Some(Caps {
        service,
        registry,
        log_flush,
    })
}
