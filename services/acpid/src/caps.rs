// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/caps.rs

//! acpid's bootstrap round.
//!
//! svcmgr delivers one capability: the `devmgr.acpi` seed, a SEND on
//! devmgr's registry endpoint badged `REGISTRY_QUERY_AUTHORITY |
//! ACPI_AUTHORITY`. acpid provides no service endpoint.

use std::os::seraph::StartupInfo;

/// Drain the bootstrap rounds from the creator and return the
/// `devmgr.acpi` SEND; `None` when the round fails or delivers none.
pub fn request_bootstrap(info: &StartupInfo, ipc_buf: *mut u64) -> Option<u64>
{
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }
    // SAFETY: `ipc_buf` is the kernel-registered IPC buffer of this thread.
    // Only the present caps ride, named by each round's presence word; an
    // absent slot decodes as `0`.
    let [registry] = unsafe { ipc::bootstrap::request_slots::<1>(creator, ipc_buf) }.ok()?;
    (registry != 0).then_some(registry)
}
