// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/service.rs

//! Service table and bootstrap cap acquisition for svcmgr.
//!
//! Defines the `ServiceEntry` struct used to track monitored services and the
//! `SvcmgrCaps` struct for well-known capabilities acquired via the bootstrap
//! protocol at startup.

use std::os::seraph::StartupInfo;

use svcmgr_endowment::{DecodeError, kind as endow_kind};

use crate::definitions::reconcile::PendingRegistration;

/// Maximum number of monitored services.
pub const MAX_SERVICES: usize = 16;

/// Maximum restarts over a service's lifetime; a death after the budget is
/// spent leaves the service permanently down (see
/// `services/svcmgr/docs/restart-protocol.md` § Decision tree).
/// `restart_count` is never reset, so the budget has no window.
pub const MAX_RESTARTS: u32 = 1;

/// Restart policy: restart unconditionally on any exit.
pub const POLICY_ALWAYS: u8 = 0;

/// Restart policy: restart only on a fault exit (`exit_reason >= EXIT_FAULT_BASE`).
pub const POLICY_ON_FAILURE: u8 = 1;

/// Restart policy: never restart, even on fault. Used for one-shot
/// integration-test fixtures whose exit is the success notification.
pub const POLICY_NEVER: u8 = 2;

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
    /// Persistent service endpoint svcmgr created for a `provides = ...`
    /// service: the source half (the child holds a RECV derivation,
    /// consumers a published SEND). Zero for pure-consumer services. The
    /// endpoint outlives any single instance — on restart svcmgr derives a
    /// fresh RECV from this slot and re-serves it, so the published SEND
    /// stays valid across the crash and cached client caps keep resolving.
    pub provided_endpoint: u32,
    /// VFS path used to respawn this service via svcmgr-side walk +
    /// `CREATE_FROM_FILE`. The sole restart source: every restartable
    /// service is reloaded from the filesystem.
    pub vfs_path: [u8; ipc::MAX_PATH_LEN],
    /// Length of `vfs_path` in bytes. Zero only for an empty slot: every
    /// reconciled entry carries its recipe's `binary` path.
    pub vfs_path_len: u8,
    /// Restart policy (`POLICY_ALWAYS`, `POLICY_ON_FAILURE`, etc.).
    pub restart_policy: u8,
    /// Whether the system is viable without this service once it is
    /// permanently down. `true` → svcmgr initiates graceful shutdown on
    /// unrecoverable death; `false` → the system continues degraded.
    /// Orthogonal to `restart_policy`, which alone decides respawn.
    pub system_critical: bool,
    /// Number of successful restarts over the service's lifetime; never
    /// reset.
    pub restart_count: u32,
    /// Whether this service is currently active.
    pub active: bool,
    /// Per-child badge used on the svcmgr bootstrap endpoint for restart
    /// bootstrap (`cap_derive_badge(svcmgr_bootstrap_ep, SEND, badge)`).
    pub bootstrap_badge: u64,
    /// Badged SEND cap on procmgr's service endpoint identifying the
    /// current process instance. Set at first launch for svcmgr-launched
    /// services (reconciliation records the launch's handle) and refreshed
    /// after each successful `CREATE_FROM_FILE` reply on restart; used to
    /// call `DESTROY_PROCESS` before spawning the next restart so procmgr
    /// can reclaim kernel objects and return its memory caps to memmgr's
    /// pool. Zero only for init-endowed services (which svcmgr never
    /// created — init did), so their first death cannot destroy; the
    /// restart then populates it and subsequent deaths can.
    pub process_handle: u32,
    /// Namespace-policy kind reconciliation recorded from the `.svc`
    /// `namespace = ...` line; one of `ipc::svcmgr_labels::NS_POLICY_*`.
    /// svcmgr re-applies this shape on every restart so attenuation
    /// survives a crash cycle.
    pub ns_policy_kind: u8,
    /// Length of `ns_subtree_path` in bytes (0 for non-`Subtree`).
    pub ns_subtree_path_len: u8,
    /// Subtree path svcmgr walks against its own root for
    /// `NS_POLICY_SUBTREE`.
    pub ns_subtree_path: [u8; ipc::MAX_PATH_LEN],
    /// Rights mask svcmgr requests per hop when walking
    /// `ns_subtree_path`. Only the low 24 bits are meaningful per
    /// `namespace-protocol`.
    pub ns_subtree_rights: u32,
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
            provided_endpoint: 0,
            vfs_path: [0; ipc::MAX_PATH_LEN],
            vfs_path_len: 0,
            restart_policy: 0,
            system_critical: false,
            restart_count: 0,
            active: false,
            bootstrap_badge: 0,
            process_handle: 0,
            // Fail-safe default: an empty slot has no installed
            // policy yet, so `None` (no namespace cap delivered) is
            // the correct shape if any code path were to inspect it
            // before reconciliation's `build_entry` overwrites every
            // field. Universal would silently grant the most permissive
            // cap on a programmer error.
            ns_policy_kind: ipc::svcmgr_labels::NS_POLICY_NONE,
            ns_subtree_path_len: 0,
            ns_subtree_path: [0; ipc::MAX_PATH_LEN],
            ns_subtree_rights: 0,
        }
    }

    /// Return the service name as a UTF-8 string slice.
    pub fn name_str(&self) -> &str
    {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("???")
    }
}

/// Heap-backed launch surfaces that don't fit the fixed-size
/// [`ServiceEntry`] record but must be replayed on every restart so a
/// respawned child comes back with the same argv/env/cwd/seed, log-sink
/// flag, and scheduling fields it got on first launch. Held in a table on
/// `SvcmgrState` index-aligned with `services[]` via the death correlator
/// (which is the table index).
pub struct RestartRecipe
{
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: Option<String>,
    pub seed: Vec<String>,
    /// The log-sink service: its restart bootstrap round is minted from the
    /// reserved log-sink sources (with no `HANDOVER_PULL` SEND), not from
    /// `seed`/provider caps. See `definitions::launch::mint_logd_boot_caps`.
    pub log_sink: bool,
    /// Recipe `priority = ...` value; `0` = unspecified (procmgr default).
    /// Replayed on every restart so a respawned child lands at the same
    /// level it got on first launch.
    pub priority: u8,
    /// Recipe `sched_max = ...` value; `0` = unspecified (child inherits a
    /// copy of svcmgr's band). Replayed like [`Self::priority`].
    pub sched_max: u8,
}

// ── Bootstrap (init → svcmgr handover endowment) ────────────────────────────
//
// init hands svcmgr its entire startup state over the bootstrap-round
// protocol — there is no separate post-bootstrap registration label. The
// round kinds and the encoding of the `CAPS` and `LOGD_SOURCES` rounds
// (only present caps ride, a presence bitmap names the slot each fills) are
// the `svcmgr_endowment` crate, which init encodes with; the wire layout is
// specified in services/svcmgr/docs/ipc-interface.md § Handover endowment.
// Each `SUBSTRATE` round parks one `(name, thread_cap)` pair in `pending`;
// `HANDOVER_COMPLETE` later reconciles them against
// `/config/svcmgr/services/`. log and procmgr endpoints arrive via
// `ProcessInfo` / `StartupInfo`, not these rounds.

/// Well-known capability slots acquired from the handover endowment.
#[allow(clippy::struct_field_names)]
pub struct SvcmgrCaps
{
    /// Service protocol endpoint capability slot.
    pub service_ep: u32,
    /// svcmgr's own bootstrap endpoint (receives bootstrap requests from
    /// restarted children).
    pub bootstrap_ep: u32,
    /// SEND on the root filesystem's namespace endpoint, published as
    /// `rootfs.root`. Zero if init could not derive it.
    pub rootfs_root: u32,
    /// `SEND|GRANT`, badge-0 source on devmgr's registry endpoint. svcmgr
    /// mints the seed-only `devmgr.registry`, `devmgr.shutdown`, and
    /// `devmgr.test` publish caps and the `SET_DRIVERS_DIR` cap
    /// (`DRIVERS_DIR_AUTHORITY`) from it. Zero if absent.
    pub devmgr_registry: u32,
    /// Reserved master-log endpoint source (`RIGHTS_ALL`). svcmgr mints
    /// real-logd's master-log RECV from it on every (re)launch, and the
    /// one-shot `HANDOVER_PULL` SEND on the first launch. Holding it keeps the
    /// log endpoint object alive across a logd crash. Zero if absent.
    pub master_log_source: u32,
    /// Badge-0 `SEND|GRANT` source on procmgr's service endpoint. svcmgr mints
    /// real-logd's `DEATH_EQ_AUTHORITY` `SEND|GRANT` cap from it per launch. Zero if absent.
    pub procmgr_death_auth_source: u32,
}

/// Acquire svcmgr's initial cap set and substrate registrations from its
/// creator (init) by draining the handover endowment rounds. Substrate
/// `(name, thread_cap)` pairs are parked in `pending`; the returned
/// `SvcmgrCaps` carries the endpoint + publish-source caps. Returns `None`
/// on a missing creator endpoint, a failed round, a version mismatch, or a
/// malformed CAPS round.
pub fn bootstrap_caps(
    info: &StartupInfo,
    ipc_buf: *mut u64,
    pending: &mut [PendingRegistration],
    pending_count: &mut usize,
) -> Option<SvcmgrCaps>
{
    if info.creator_endpoint == 0
    {
        return None;
    }
    let mut caps: Option<SvcmgrCaps> = None;
    let mut caps_decoder = svcmgr_endowment::CapsDecoder::new();
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let round =
            unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
        match round.data[0]
        {
            endow_kind::CAPS =>
            {
                match caps_decoder.push(
                    &round.caps[..round.cap_count],
                    &round.data[..round.data_words],
                )
                {
                    // More CAPS rounds are owed; their caps are recorded.
                    Ok(None) =>
                    {}
                    Ok(Some(c)) =>
                    {
                        caps = Some(SvcmgrCaps {
                            service_ep: c.service_ep,
                            bootstrap_ep: c.bootstrap_ep,
                            rootfs_root: c.rootfs_root,
                            devmgr_registry: c.devmgr_registry,
                            master_log_source: 0,
                            procmgr_death_auth_source: 0,
                        });
                    }
                    Err(DecodeError::VersionMismatch) =>
                    {
                        std::os::seraph::log!("bootstrap: endowment version mismatch");
                        return None;
                    }
                    Err(DecodeError::Malformed) =>
                    {
                        std::os::seraph::log!("bootstrap: malformed endowment CAPS round");
                        return None;
                    }
                }
            }
            endow_kind::SUBSTRATE => ingest_substrate(&round, pending, pending_count),
            endow_kind::LOGD_SOURCES =>
            {
                // Terminal round (arrives after CAPS). Record the reserved
                // log-sink sources on the already-built cap set; a round
                // with no cap set to land on, or one that does not decode,
                // is released rather than leaked.
                let delivered = &round.caps[..round.cap_count];
                match (
                    caps.as_mut(),
                    svcmgr_endowment::decode_logd_sources(
                        delivered,
                        &round.data[..round.data_words],
                    ),
                )
                {
                    (Some(c), Ok(sources)) =>
                    {
                        c.master_log_source = sources.master_log_source;
                        c.procmgr_death_auth_source = sources.procmgr_death_auth_source;
                    }
                    (_, decoded) =>
                    {
                        if decoded.is_err()
                        {
                            std::os::seraph::log!(
                                "bootstrap: malformed endowment LOGD_SOURCES round"
                            );
                        }
                        for &cap in delivered
                        {
                            let _ = syscall::cap_delete(cap);
                        }
                    }
                }
            }
            other => std::os::seraph::log!("bootstrap: unknown endowment kind {other}"),
        }
        if round.done
        {
            break;
        }
    }
    caps
}

/// Park one substrate `(name, thread_cap)` round in `pending`. Releases the
/// delivered thread cap on any reject (invalid name, full table) so a
/// malformed round cannot leak a cap.
fn ingest_substrate(
    round: &ipc::bootstrap::BootstrapRound,
    pending: &mut [PendingRegistration],
    pending_count: &mut usize,
)
{
    if round.cap_count < 1
    {
        return;
    }
    let thread_cap = round.caps[0];
    if thread_cap == 0
    {
        return;
    }
    let reject = |cap: u32| {
        let _ = syscall::cap_delete(cap);
    };
    let name_len = round.data[1] as usize;
    if name_len == 0 || name_len > 32
    {
        std::os::seraph::log!("bootstrap: substrate name_len invalid");
        reject(thread_cap);
        return;
    }
    if *pending_count >= pending.len()
    {
        std::os::seraph::log!("bootstrap: pending table full; dropping substrate");
        reject(thread_cap);
        return;
    }
    let mut name = [0u8; 32];
    let words = name_len.div_ceil(8);
    for w in 0..words
    {
        let word = round.data[2 + w];
        for b in 0..8
        {
            let idx = w * 8 + b;
            if idx < name_len && idx < name.len()
            {
                name[idx] = (word >> (b * 8)) as u8;
            }
        }
    }
    let idx = *pending_count;
    pending[idx] = PendingRegistration {
        name,
        name_len: name_len as u8,
        thread_cap,
        consumed: false,
    };
    *pending_count += 1;
    std::os::seraph::log!("endowed: {}", pending[idx].name_str());
}
