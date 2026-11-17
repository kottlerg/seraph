// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/caps.rs

//! acpid's bootstrap round.
//!
//! svcmgr delivers two capabilities: `caps[0]`, the RECV on acpid's own
//! service endpoint (`provides`), on which svcmgr publishes `acpid.power`
//! and `acpid.deny`; and `caps[1]`, the `devmgr.acpi` seed, a SEND on
//! devmgr's registry endpoint badged `REGISTRY_QUERY_AUTHORITY |
//! ACPI_AUTHORITY`.

use std::os::seraph::StartupInfo;

/// The capabilities of acpid's bootstrap round.
pub struct Caps
{
    /// acpid's service endpoint (RECV).
    pub service: u64,
    /// The `devmgr.acpi` SEND.
    pub registry: u64,
}

/// Drain the bootstrap rounds from the creator; `None` when the round
/// fails or lacks either capability.
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
    let [service, registry] =
        unsafe { ipc::bootstrap::request_slots::<2>(creator, ipc_buf) }.ok()?;
    (service != 0 && registry != 0).then_some(Caps { service, registry })
}
