// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/bootstrap.rs

//! Decode the creator-endpoint bootstrap round into a typed [`Caps`].
//!
//! Slot layout (set by whichever launcher minted the round, which carries
//! only the present caps and names the slot each fills in its presence word;
//! see `ipc::bootstrap::unpack_slots`):
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
//!     Lacking `SHUTDOWN_DEVICE_AUTHORITY` and `TEST_LABEL_AUTHORITY`, it
//!     drives the devmgr deny phases.
//!   * `caps[3]`: `REGISTRY_QUERY_AUTHORITY | TEST_LABEL_AUTHORITY`-badged
//!     SEND on devmgr's registry endpoint (`devmgr.test`; zero when devmgr
//!     is absent). Drives devmgr's test labels: the `TEST_SPAWN_ORPHAN`
//!     fault-injection shim in the devmgr orphan-teardown phase, and
//!     `TEST_QUERY_DENY_DEVICE` in the drivers deny phase. TODO(#165):
//!     retire with those labels.
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
    /// `REGISTRY_QUERY_AUTHORITY | TEST_LABEL_AUTHORITY`-badged SEND on
    /// devmgr's registry endpoint (`devmgr.test`), for the
    /// `TEST_SPAWN_ORPHAN` shim and `TEST_QUERY_DENY_DEVICE`. TODO(#165):
    /// retire with those labels.
    pub devmgr_test: u32,
}

/// Drain the bootstrap round from `creator_endpoint` and pull caps out,
/// then resolve `pwrmgr.deny`. The lookup follows the round: svcmgr serves
/// no `QUERY_ENDPOINT` until it has served the round.
pub fn request() -> Caps
{
    let mut caps = request_round();
    caps.pwrmgr_noauth =
        std::os::seraph::registry::lookup(ipc::published_names::PWRMGR_DENY).unwrap_or(0);
    caps
}

/// The seeded slots of the bootstrap round from `creator_endpoint`.
fn request_round() -> Caps
{
    let mut caps = Caps::default();

    let info = startup_info();
    if info.creator_endpoint == 0
    {
        return caps;
    }

    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by
    // the boot protocol.
    let Ok(round) = (unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) })
    else
    {
        return caps;
    };

    // Only the present caps ride, named by the round's presence word; an
    // absent slot decodes as `0`, and a malformed word leaves every slot `0`.
    let [root_fs, pwrmgr_auth, devmgr_registry, devmgr_test] =
        ipc::bootstrap::unpack_slots(&round).unwrap_or_default();
    caps.root_fs = root_fs;
    caps.pwrmgr_auth = pwrmgr_auth;
    caps.devmgr_registry = devmgr_registry;
    caps.devmgr_test = devmgr_test;

    caps
}
