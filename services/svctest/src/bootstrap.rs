// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/bootstrap.rs

//! Decode the creator-endpoint bootstrap round into a typed [`Caps`].
//!
//! Slot layout (set by whichever launcher minted the round):
//!   * `caps[0]`: badged SEND on the unified **root-filesystem**
//!     namespace at its root directory (`rootfs.root`; zero when the
//!     launcher could not mint one). This is vfsd's synthetic system
//!     root — `NS_LOOKUP` walks it, and vfsd transparently delegates
//!     to the underlying fs driver (fatfs today), which stays opaque
//!     to svctest.
//!   * `caps[1]`: `SHUTDOWN_AUTHORITY`-badged SEND on pwrmgr's
//!     service endpoint (zero when pwrmgr is absent)
//!   * `caps[2]`: `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's
//!     registry endpoint (`devmgr.registry`; zero when devmgr is absent).
//!     Lacking `SHUTDOWN_DEVICE_AUTHORITY` and `ORPHAN_TEST_AUTHORITY`, it
//!     drives the devmgr deny phases.
//!   * `caps[3]`: `REGISTRY_QUERY_AUTHORITY | ORPHAN_TEST_AUTHORITY`-badged
//!     SEND on devmgr's registry endpoint (`devmgr.test`; zero when devmgr
//!     is absent). Drives the `TEST_SPAWN_ORPHAN` fault-injection shim in
//!     the devmgr orphan-teardown phase. TODO(#165): retire with that shim.
//!
//! The no-authority pwrmgr SEND (`pwrmgr.deny`) is public, so svctest
//! resolves it itself through `QUERY_ENDPOINT` rather than spending a seed
//! slot on it (zero when pwrmgr is absent).
//!
//! The launcher requests the round from `info.creator_endpoint`; if no
//! creator endpoint is present (`== 0`), every slot stays zero and
//! dependent phases self-skip.

use std::os::seraph::startup_info;

/// Bootstrap caps delivered to svctest by its launcher.
#[derive(Default)]
pub struct Caps
{
    /// Badged SEND on the unified root-filesystem namespace at its
    /// root directory (vfsd's synthetic root). The fs driver behind
    /// vfsd's delegation is opaque.
    pub root_fs: u32,
    pub pwrmgr_auth: u32,
    /// `pwrmgr.deny`, resolved through `QUERY_ENDPOINT`.
    pub pwrmgr_noauth: u32,
    /// `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's registry
    /// endpoint (`devmgr.registry`).
    pub devmgr_registry: u32,
    /// `REGISTRY_QUERY_AUTHORITY | ORPHAN_TEST_AUTHORITY`-badged SEND on
    /// devmgr's registry endpoint (`devmgr.test`). TODO(#165): retire with
    /// the `TEST_SPAWN_ORPHAN` shim.
    pub devmgr_test: u32,
}

/// Drain the bootstrap round from `creator_endpoint` and pull caps out.
pub fn request() -> Caps
{
    let mut caps = Caps {
        pwrmgr_noauth: std::os::seraph::registry::lookup(ipc::published_names::PWRMGR_DENY)
            .unwrap_or(0),
        ..Caps::default()
    };

    let info = startup_info();
    if info.creator_endpoint == 0
    {
        return caps;
    }

    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB), satisfying u64 alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by
    // the boot protocol.
    let Ok(round) = (unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) })
    else
    {
        return caps;
    };

    if round.cap_count >= 1
    {
        caps.root_fs = round.caps[0];
    }
    if round.cap_count >= 2
    {
        caps.pwrmgr_auth = round.caps[1];
    }
    if round.cap_count >= 3
    {
        caps.devmgr_registry = round.caps[2];
    }
    if round.cap_count >= 4
    {
        caps.devmgr_test = round.caps[3];
    }

    caps
}
