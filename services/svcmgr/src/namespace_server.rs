// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/namespace_server.rs

//! vfsd, the server of svcmgr's namespace root, watched until reconciliation
//! records it.
//!
//! init builds svcmgr's namespace root from vfsd's system-root endpoint, so
//! vfsd serves every `std::fs` and namespace call svcmgr makes: the device
//! class files and the drivers directory before the handover, and the recipe
//! directory at it. A call on an endpoint none of whose receivers is left
//! waits for good, since svcmgr's own SEND keeps the endpoint alive, and a
//! vfsd death before reconciliation has recorded vfsd would then leave svcmgr
//! blocked with the death unrouted. So svcmgr reads vfsd's liveness ([`death`])
//! before each of those steps and after every vfsd access that fails, and a
//! dead vfsd ends the step; at the handover its death is routed as system
//! death (`route_namespace_server_death` in `main.rs`). A vfsd that dies
//! after a check, while svcmgr's next call to it waits unreceived, still
//! leaves svcmgr blocked (#1185). The specification is
//! `services/svcmgr/docs/restart-protocol.md` § Death detection.

use svcmgr_endowment::SubstrateObserver;

use crate::definitions::reconcile::PendingRegistration;
use crate::restart;

/// The name init's `SUBSTRATE` round gives the namespace server's registration.
pub const NAME: &str = "vfsd";

/// The exit reason of vfsd when it is dead, else `None`, read from its
/// substrate registration in `pending` while reconciliation has not consumed
/// it: its main thread's state through the endowed thread cap
/// ([`restart::caps_death`]), then, while memmgr and procmgr show alive, its
/// process through procmgr (`procmgr_labels::QUERY_PROCESS` on the endowed
/// process handle, [`restart::queried_death`]), which reports a terminal fault
/// of a worker thread procmgr has not yet torn down. `None` with no such
/// registration.
pub fn death(pending: &[PendingRegistration], ipc_buf: *mut u64) -> Option<u64>
{
    let server = pending.iter().find(|p| !p.consumed && p.matches(NAME))?;
    if let Some(reason) = registration_death(server)
    {
        return Some(reason);
    }
    let SubstrateObserver::ProcessHandle(handle) = server.observer
    else
    {
        return None;
    };
    // The query blocks until procmgr answers, so it is made only while every
    // registration whose address space svcmgr holds (memmgr and procmgr)
    // shows alive.
    let core_alive = pending
        .iter()
        .filter(|p| !p.consumed && matches!(p.observer, SubstrateObserver::AddressSpace(_)))
        .all(|p| registration_death(p).is_none());
    if !core_alive
    {
        return None;
    }
    restart::queried_death(handle, ipc_buf)
}

/// The exit reason of the service a substrate registration names when its
/// caps show it dead ([`restart::caps_death`]), else `None`.
fn registration_death(registration: &PendingRegistration) -> Option<u64>
{
    let aspace = match registration.observer
    {
        SubstrateObserver::AddressSpace(cap) => cap,
        SubstrateObserver::ProcessHandle(_) | SubstrateObserver::None => 0,
    };
    restart::caps_death(registration.thread_cap, aspace)
}
