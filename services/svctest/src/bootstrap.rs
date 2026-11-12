// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/bootstrap.rs

//! Decode the creator-endpoint bootstrap rounds into a typed [`Caps`].
//!
//! The seed each slot carries, and what svctest uses it for, are specified in
//! `services/svctest/README.md` § Capabilities; each seed's cap shape in
//! `services/svcmgr/docs/service-definitions.md` § `seed`; and which phases
//! skip or fail on a zero slot in the README's § Run Sequence. The rounds are
//! drained with `ipc::bootstrap::request_slots`, which leaves an absent slot
//! `0`. The public `pwrmgr.deny` is resolved here too, through
//! `QUERY_ENDPOINT`, after the rounds.

use std::os::seraph::startup_info;

/// Bootstrap caps delivered to svctest by its launcher.
#[derive(Default)]
pub struct Caps
{
    /// Badged SEND on the unified root-filesystem namespace at its
    /// root directory (vfsd's synthetic root). The fs driver behind
    /// vfsd's delegation is opaque.
    pub root_fs: u64,
    pub pwrmgr_auth: u64,
    /// `pwrmgr.deny`, resolved through `QUERY_ENDPOINT`.
    pub pwrmgr_noauth: u64,
    /// `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's registry
    /// endpoint (`devmgr.registry`).
    pub devmgr_registry: u64,
    /// `REGISTRY_QUERY_AUTHORITY | BIND_AUTHORITY`-badged `SEND|GRANT` on
    /// devmgr's registry endpoint (`devmgr.bind`), for `BIND_DRIVERS`.
    pub devmgr_bind: u64,
    /// `MOUNT_AUTHORITY`-badged SEND on vfsd's service endpoint
    /// (`vfsd.mount`), in slot 4.
    pub vfsd_mount: u64,
    /// `DENY_BADGE`-badged SEND on vfsd's service endpoint (`vfsd.deny`),
    /// in slot 5.
    pub vfsd_deny: u64,
    /// `LOG_QUERY_AUTHORITY`-badged SEND on the master log endpoint
    /// (`logd.query`), in slot 6.
    pub logd_query: u64,
    /// The `serial` class SEND on devmgr's registry endpoint
    /// (`devmgr.class.serial`), in slot 7.
    pub serial_class: u64,
    /// The `input` class SEND on devmgr's registry endpoint
    /// (`devmgr.class.input`), in slot 8.
    pub input_class: u64,
    /// The `test-dma` class SEND (`devmgr.class.test-dma`), in slot 9, from
    /// a test class file the svctest recipe stages.
    pub test_dma_class: u64,
    /// The `test-fault` class SEND (`devmgr.class.test-fault`), in slot 10,
    /// from a test class file the svctest recipe stages.
    pub test_fault_class: u64,
    /// SENDs on the `serial`, `input`, and `framebuffer` classes whose verb
    /// mask holds only bit 58, which none of those drivers checks
    /// (`devmgr.class.serial-deny`, `input-deny`, `framebuffer-deny`), in
    /// slots 11 to 13, from test class files the svctest recipe stages.
    pub serial_deny_class: u64,
    pub input_deny_class: u64,
    pub framebuffer_deny_class: u64,
    /// `DEBUG_AUTHORITY`-badged `SEND|GRANT` on procmgr, which the recipe's
    /// `debug_authority = yes` delivers in slot 14, after the seeds.
    pub debug_authority: u64,
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
    // Fourteen seeds and the debug-authority slot take four rounds; an absent slot decodes as
    // `0`, and a round that does not decode leaves every slot `0`.
    let Ok(
        [
            root_fs,
            pwrmgr_auth,
            devmgr_registry,
            devmgr_bind,
            vfsd_mount,
            vfsd_deny,
            logd_query,
            serial_class,
            input_class,
            test_dma_class,
            test_fault_class,
            serial_deny_class,
            input_deny_class,
            framebuffer_deny_class,
            debug_authority,
        ],
    ) = (unsafe { ipc::bootstrap::request_slots::<15>(info.creator_endpoint, ipc_buf) })
    else
    {
        return caps;
    };
    caps.root_fs = root_fs;
    caps.pwrmgr_auth = pwrmgr_auth;
    caps.devmgr_registry = devmgr_registry;
    caps.devmgr_bind = devmgr_bind;
    caps.vfsd_mount = vfsd_mount;
    caps.vfsd_deny = vfsd_deny;
    caps.logd_query = logd_query;
    caps.serial_class = serial_class;
    caps.input_class = input_class;
    caps.test_dma_class = test_dma_class;
    caps.test_fault_class = test_fault_class;
    caps.serial_deny_class = serial_deny_class;
    caps.input_deny_class = input_deny_class;
    caps.framebuffer_deny_class = framebuffer_deny_class;
    caps.debug_authority = debug_authority;

    caps
}
