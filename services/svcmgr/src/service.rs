// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/service.rs

//! Service table and bootstrap cap acquisition for svcmgr.
//!
//! Defines the `ServiceEntry` struct used to track monitored services and the
//! `SvcmgrCaps` struct for well-known capabilities acquired via the bootstrap
//! protocol at startup.

use std::os::seraph::StartupInfo;

/// Maximum number of monitored services.
pub const MAX_SERVICES: usize = 16;

/// Maximum number of extra named caps stored per service for restart.
///
/// Constrained by the 4-cap IPC message limit: a single `REGISTER_SERVICE`
/// delivers `thread + module + log + 1 extra`. Larger bundles would need
/// multi-round registration; defer until a concrete consumer appears.
pub const MAX_BUNDLE_CAPS: usize = 1;

/// Maximum restart attempts before marking degraded.
pub const MAX_RESTARTS: u32 = 1;

/// Restart policy: restart unconditionally on any exit.
pub const POLICY_ALWAYS: u8 = 0;

/// Restart policy: restart only on fault (nonzero exit reason).
pub const POLICY_ON_FAILURE: u8 = 1;

/// Criticality: crash of this service is fatal — halt the system.
pub const CRITICALITY_FATAL: u8 = 0;

/// Criticality: crash can be handled by restart policy.
pub const CRITICALITY_NORMAL: u8 = 1;

// ── Service table ───────────────────────────────────────────────────────────

/// A monitored service entry in svcmgr's service table.
pub struct ServiceEntry
{
    /// Service name, packed into a fixed-size buffer.
    pub name: [u8; 32],
    /// Length of the service name in bytes.
    pub name_len: u8,
    /// Capability slot for the service's thread.
    pub thread_cap: u32,
    /// Capability slot for the service's boot module. Zero for VFS-loaded
    /// services (`vfs_path_len > 0`); the restart path then uses
    /// `CREATE_FROM_VFS` instead of `CREATE_PROCESS`.
    pub module_cap: u32,
    /// VFS path used to respawn this service via `CREATE_FROM_VFS`. Mutually
    /// exclusive with `module_cap` at registration time.
    pub vfs_path: [u8; ipc::MAX_PATH_LEN],
    /// Length of `vfs_path` in bytes (0 = module-loaded).
    pub vfs_path_len: u8,
    /// Extra named restart-bundle caps beyond `thread/module`. Each
    /// entry is re-derived and re-delivered over the bootstrap protocol
    /// after a restart so the child comes back with its full cap set.
    pub bundle: [registry::Entry; MAX_BUNDLE_CAPS],
    /// Number of valid entries at the front of `bundle`.
    pub bundle_count: u8,
    /// Restart policy (`POLICY_ALWAYS`, `POLICY_ON_FAILURE`, etc.).
    pub restart_policy: u8,
    /// Criticality level (`CRITICALITY_FATAL`, `CRITICALITY_NORMAL`).
    pub criticality: u8,
    /// Number of restart attempts so far.
    pub restart_count: u32,
    /// Whether this service is currently active.
    pub active: bool,
    /// Per-child token used on the svcmgr bootstrap endpoint for restart
    /// bootstrap (`cap_derive_token(svcmgr_bootstrap_ep, SEND, token)`).
    pub bootstrap_token: u64,
    /// Tokened SEND cap on procmgr's service endpoint identifying the
    /// current process instance. Populated by the restart path after the
    /// first successful `CREATE_PROCESS` reply; used to call
    /// `DESTROY_PROCESS` before spawning the next restart so procmgr can
    /// reclaim kernel objects and free frames back to the buddy allocator.
    /// Zero for the initial instance (which svcmgr never created — init
    /// did), so the first death cannot destroy; subsequent deaths can.
    pub process_handle: u32,
}

impl ServiceEntry
{
    /// Create an empty (inactive) service entry.
    pub const fn empty() -> Self
    {
        Self {
            name: [0; 32],
            name_len: 0,
            thread_cap: 0,
            module_cap: 0,
            vfs_path: [0; ipc::MAX_PATH_LEN],
            vfs_path_len: 0,
            bundle: [registry::Entry {
                name: [0; registry::NAME_MAX],
                name_len: 0,
                cap: 0,
            }; MAX_BUNDLE_CAPS],
            bundle_count: 0,
            restart_policy: 0,
            criticality: 0,
            restart_count: 0,
            active: false,
            bootstrap_token: 0,
            process_handle: 0,
        }
    }

    /// Return the service name as a UTF-8 string slice.
    pub fn name_str(&self) -> &str
    {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("???")
    }
}

// ── Bootstrap ───────────────────────────────────────────────────────────────
//
// init → svcmgr bootstrap plan (one round, 2 caps):
//   caps[0]: service endpoint (svcmgr receives on this for registrations)
//   caps[1]: svcmgr's own bootstrap endpoint (svcmgr receives on this when
//            serving bootstrap requests from restarted children)
//
// log and procmgr endpoints arrive via `ProcessInfo` / `StartupInfo` and are
// not part of this round.

/// Well-known capability slots acquired from the bootstrap protocol.
#[allow(clippy::struct_field_names)]
pub struct SvcmgrCaps
{
    /// Service protocol endpoint capability slot.
    pub service_ep: u32,
    /// svcmgr's own bootstrap endpoint (receives bootstrap requests from
    /// restarted children).
    pub bootstrap_ep: u32,
}

/// Acquire svcmgr's initial cap set from its creator (init) via bootstrap IPC.
pub fn bootstrap_caps(info: &StartupInfo, ipc_buf: *mut u64) -> Option<SvcmgrCaps>
{
    if info.creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
    if round.cap_count < 2 || !round.done
    {
        return None;
    }
    Some(SvcmgrCaps {
        service_ep: round.caps[0],
        bootstrap_ep: round.caps[1],
    })
}
