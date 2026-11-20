// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/endowed_servers.rs

//! The servers svcmgr calls before reconciliation records them, watched until
//! it does: vfsd and devmgr.
//!
//! init builds svcmgr's namespace root from vfsd's system-root endpoint, so
//! vfsd serves every `std::fs` and namespace call svcmgr makes: the device
//! class files and the drivers directory before the handover, and the recipe
//! directory at it. devmgr serves the class mints and `SET_DRIVERS_DIR`
//! before the handover, through the endowed devmgr-registry source. Neither
//! svcmgr nor init holds a capability with the Receive right on either
//! server's endpoints, so once a dead server's process is torn down the
//! kernel fails a call to it, queued or new, with `NoReceiver`. A failed call
//! does not itself say that the server died, so svcmgr reads a server's
//! liveness ([`death`]) before each step that calls it and after every call
//! to it that fails, and a dead server ends the step. At the handover a dead
//! vfsd's death is routed as system death (`route_namespace_server_death` in
//! `main.rs`); a dead devmgr is recorded by reconciliation with the caps init
//! endowed, and the resync after it routes the death. The specification is
//! `services/svcmgr/docs/restart-protocol.md` § Death detection.

use svcmgr_endowment::SubstrateObserver;

use crate::definitions::reconcile::PendingRegistration;
use crate::restart;

/// The name init's `SUBSTRATE` round gives vfsd's registration.
pub const VFSD: &str = "vfsd";

/// The name init's `SUBSTRATE` round gives devmgr's registration.
pub const DEVMGR: &str = "devmgr";

/// The exit reason of the server whose substrate registration in `pending`
/// is named `name` when it is dead, else `None`, read while reconciliation
/// has not consumed the registration: its main thread's state through the
/// endowed thread cap ([`restart::caps_death`]), then, while memmgr and
/// procmgr show alive, its process through procmgr
/// (`procmgr_labels::QUERY_PROCESS` on the endowed process handle,
/// [`restart::queried_death`]), which reports a terminal fault of a worker
/// thread procmgr has not yet torn down. `None` with no such registration.
pub fn death(pending: &[PendingRegistration], name: &str, ipc_buf: *mut u64) -> Option<u64>
{
    let server = pending.iter().find(|p| !p.consumed && p.matches(name))?;
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
