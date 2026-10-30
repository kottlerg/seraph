// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/bootstrap.rs

//! Decode the creator-endpoint bootstrap round into a typed [`Caps`].
//!
//! Slot layout (set by whichever launcher minted the rounds, each of which
//! carries only its window's present caps and names the slot each fills in
//! its presence word; see `ipc::bootstrap::request_slots`):
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
//!   * `caps[4]`: the no-authority pwrmgr SEND (`pwrmgr.deny`). It is the
//!     fifth seed, so svcmgr delivers it in a second round: every svctest
//!     boot exercises a seed list longer than one round, and the
//!     `svcmgr_second_seed_round` phase fails the run when slot 4 is empty.
//!
//! `pwrmgr.deny` is also public, and the pwrmgr cap-deny phase uses the
//! copy svctest resolves through `QUERY_ENDPOINT` (zero when pwrmgr is
//! absent).
//!
//! svctest requests the rounds from `info.creator_endpoint`; if no
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
    /// `pwrmgr.deny`, seeded in slot 4: the second-round seed whose
    /// arrival the `svcmgr_second_seed_round` phase checks.
    pub pwrmgr_deny_seed: u32,
}

/// Drain the bootstrap rounds from `creator_endpoint` and pull caps out,
/// then resolve `pwrmgr.deny`. The lookup follows the rounds: svcmgr serves
/// no `QUERY_ENDPOINT` until it has served them.
pub fn request() -> Caps
{
    let mut caps = request_round();
    caps.pwrmgr_noauth =
        std::os::seraph::registry::lookup(ipc::published_names::PWRMGR_DENY).unwrap_or(0);
    caps
}

/// The seeded slots of the bootstrap rounds from `creator_endpoint`.
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
    // Five seeds take two rounds; an absent slot decodes as `0`, and a
    // round that does not decode leaves every slot `0`.
    let Ok(
        [
            root_fs,
            pwrmgr_auth,
            devmgr_registry,
            devmgr_test,
            pwrmgr_deny_seed,
        ],
    ) = (unsafe { ipc::bootstrap::request_slots::<5>(info.creator_endpoint, ipc_buf) })
    else
    {
        return caps;
    };
    caps.root_fs = root_fs;
    caps.pwrmgr_auth = pwrmgr_auth;
    caps.devmgr_registry = devmgr_registry;
    caps.devmgr_test = devmgr_test;
    caps.pwrmgr_deny_seed = pwrmgr_deny_seed;

    caps
}
