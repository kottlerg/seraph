// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/service.rs

//! Service table and bootstrap cap acquisition for svcmgr.
//!
//! Defines the `ServiceEntry` struct used to track monitored services and the
//! `SvcmgrCaps` struct for well-known capabilities acquired via the bootstrap
//! protocol at startup.

use std::os::seraph::StartupInfo;

use restart_budget::RestartBudget;
use svcmgr_endowment::{DecodeError, kind as endow_kind};

use crate::definitions::reconcile::PendingRegistration;

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
    /// Service name: its `.svc` file's stem, at most
    /// `ipc::svcmgr_labels::NAME_MAX` bytes.
    pub name: String,
    /// Capability slot for the service's main thread.
    pub thread_cap: u64,
    /// The instance of the service [`Self::thread_cap`] belongs to: `0` for
    /// the first, one more for each restart (wrapping). Both death observers
    /// of an instance carry it in their [`svcmgr_defs::DeathTag`], so a post
    /// is routed only for the instance that runs now.
    pub instance: u32,
    /// A `Control`-only cap on the address space of a service init created by
    /// raw syscalls (memmgr, procmgr), from its endowment round: svcmgr bound
    /// the service's address-space observer on the core-death queue with it,
    /// and reads the space's retained terminal fault back through it in a
    /// resync. Zero
    /// for every other service, whose address space procmgr observes for
    /// svcmgr through [`Self::process_handle`].
    pub aspace_cap: u64,
    /// Persistent service endpoint svcmgr created for a `provides = ...`
    /// service: the source half (the child holds a RECV derivation,
    /// consumers a published SEND). Zero for pure-consumer services. The
    /// endpoint outlives any single instance — on restart svcmgr derives a
    /// fresh RECV from this slot and re-serves it, so the published SEND
    /// stays valid across the crash and cached client caps keep resolving.
    pub provided_endpoint: u64,
    /// VFS path used to respawn this service via svcmgr-side walk +
    /// `CREATE_FROM_FILE`. The sole restart source: every restartable
    /// service is reloaded from the filesystem.
    /// At most `ipc::procmgr_labels::CREATE_NAME_MAX` bytes, in the canonical
    /// form procmgr verifies it under. Empty only for an empty slot:
    /// every reconciled entry carries its recipe's `binary` path.
    pub vfs_path: String,
    /// Restart policy (`POLICY_ALWAYS`, `POLICY_ON_FAILURE`, etc.).
    pub restart_policy: u8,
    /// Whether the system is viable without this service once it is
    /// permanently down. `true` → svcmgr initiates graceful shutdown on
    /// unrecoverable death; `false` → the system continues degraded.
    /// Orthogonal to `restart_policy`, which alone decides respawn.
    pub system_critical: bool,
    /// Number of successful restarts over the service's lifetime, for the
    /// restart log line; the budget is [`Self::restart_budget`].
    pub restart_count: u32,
    /// Windowed restart budget: whether a death may restart the service
    /// (`services/svcmgr/docs/restart-protocol.md` § Decision tree).
    pub restart_budget: RestartBudget,
    /// Whether this service is currently active.
    pub active: bool,
    /// The restart's memory wait, when procmgr refused its create for want of
    /// memory (`svcmgr_defs::memory_wait`;
    /// `services/svcmgr/docs/restart-protocol.md` § Decision tree). The entry
    /// is inactive and holds no instance meanwhile. `None` otherwise.
    pub memory_wait: Option<svcmgr_defs::memory_wait::MemoryWait>,
    /// Whether svcmgr launched the service from its recipe, as against
    /// binding one init started (memmgr, procmgr, devmgr, vfsd). Only a
    /// service svcmgr launched may be stopped
    /// (`svcmgr_defs::stop::StopFacts::launched`).
    pub launched: bool,
    /// The node handle of the current instance's memmgr budget node, which
    /// svcmgr asks procmgr for when the recipe sets `oom_stop = yes`
    /// (`procmgr_labels::CREATE_NODE_HANDLE`) and reads the instance's usage
    /// through for `stop_labels::LIST_CANDIDATES`; memmgr refuses it once the
    /// instance is gone. Released with the instance on restart. Zero for every
    /// other service.
    pub node_handle: u64,
    /// Per-child badge used on the svcmgr bootstrap endpoint for restart
    /// bootstrap (`cap_derive_badge(svcmgr_bootstrap_ep, SEND, badge)`).
    pub bootstrap_badge: u64,
    /// Badged SEND cap on procmgr's service endpoint identifying the
    /// current process instance. Set at first launch for svcmgr-launched
    /// services (reconciliation records the launch's handle) and refreshed
    /// after each successful `CREATE_FROM_FILE` reply on restart; used to
    /// call `DESTROY_PROCESS` before spawning the next restart so procmgr
    /// can reclaim kernel objects and return its memory caps to memmgr's
    /// pool; svcmgr also binds the death observer of the service's address
    /// space through it (`procmgr_labels::BIND_DEATH_OBSERVER`) and asks
    /// procmgr for the instance's state through it in a resync
    /// (`procmgr_labels::QUERY_PROCESS`). For a
    /// substrate service init created through procmgr (devmgr, vfsd) it is
    /// the handle init endowed; zero for memmgr and procmgr, which procmgr
    /// did not create.
    pub process_handle: u64,
    /// Namespace-policy kind reconciliation recorded from the `.svc`
    /// `namespace = ...` line; one of `ipc::svcmgr_labels::NS_POLICY_*`.
    /// svcmgr re-applies this shape on every restart so attenuation
    /// survives a crash cycle.
    pub ns_policy_kind: u8,
    /// Subtree path svcmgr walks against its own root for
    /// `NS_POLICY_SUBTREE`, at most `ipc::MAX_PATH_LEN` bytes; empty for
    /// the other policies.
    pub ns_subtree_path: String,
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
            name: String::new(),
            thread_cap: 0,
            instance: 0,
            aspace_cap: 0,
            provided_endpoint: 0,
            vfs_path: String::new(),
            restart_policy: 0,
            system_critical: false,
            restart_count: 0,
            restart_budget: RestartBudget::new(),
            active: false,
            memory_wait: None,
            launched: false,
            node_handle: 0,
            bootstrap_badge: 0,
            process_handle: 0,
            // Fail-safe default: an empty slot has no installed
            // policy yet, so `None` (no namespace cap delivered) is
            // the correct shape if any code path were to inspect it
            // before reconciliation's `build_entry` overwrites every
            // field. Universal would silently grant the most permissive
            // cap on a programmer error.
            ns_policy_kind: ipc::svcmgr_labels::NS_POLICY_NONE,
            ns_subtree_path: String::new(),
            ns_subtree_rights: 0,
        }
    }

    /// Return the service name.
    pub fn name_str(&self) -> &str
    {
        &self.name
    }
}

/// Heap-backed launch surfaces kept beside the [`ServiceEntry`] record that
/// must be replayed on every restart so a
/// respawned child comes back with the same argv/env/cwd/seed, log-sink
/// flag, and scheduling fields it got on first launch. Held in a table on
/// `SvcmgrState` index-aligned with `services[]` via the death correlator
/// (which is the table index).
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is one independent `yes | no` recipe key: `log_sink`, \
              `debug_authority`, `oom_stop`, `stop_authority`, `entropy_authority` \
              and `reserve`"
)]
pub struct RestartRecipe
{
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: Option<String>,
    pub seed: Vec<String>,
    /// The log-sink service: its restart bootstrap round is minted from the
    /// reserved log-sink sources, not from `seed`/provider caps, and carries
    /// the `HANDOVER_PULL` SEND while `svcmgr_defs::log_sink_handover_owed`
    /// holds (until procmgr reports init reaped) and none after. See `definitions::launch::mint_logd_boot_caps`.
    pub log_sink: bool,
    /// The `debug_authority = yes` service: a freshly minted
    /// `DEBUG_AUTHORITY` cap rides the slot after its seeds on every launch.
    /// See `restart::mint_debug_authority`.
    pub debug_authority: bool,
    /// The `oom_stop = yes` service: each instance is created with a node
    /// handle (`svcmgr_defs::create_flags`), and a stop-authority holder may
    /// stop it (`svcmgr_defs::stop`).
    pub oom_stop: bool,
    /// The `stop_authority = yes` service: a freshly minted
    /// `STOP_AUTHORITY` SEND on svcmgr's service endpoint rides the slot after
    /// its seeds and debug-authority cap on every launch. See
    /// `restart::mint_stop_authority`.
    pub stop_authority: bool,
    /// The `entropy_authority = yes` service, the one launch order names
    /// (`svcmgr_defs::entropy_holder`): a freshly derived `EntropyControl`
    /// copy rides the slot after its seeds, debug- and stop-authority caps on
    /// every launch. See `restart::mint_entropy_authority`.
    pub entropy_authority: bool,
    /// The `reserve = yes` service: each instance is created in the system
    /// reserve (`svcmgr_defs::create_flags`).
    pub reserve: bool,
    /// The `private_image = yes` service: each instance is created with a
    /// private image (`svcmgr_defs::create_flags`).
    pub private_image: bool,
    /// The `stop_source = <class>` service's class: each instance is created
    /// contained (`svcmgr_defs::create_flags`), and while it runs, a
    /// stop-authority holder finds it, with a stop-badged SEND on its service
    /// endpoint, through `svcmgr_labels::LIST_STOP_SOURCES` (`crate::stop`).
    pub stop_source: Option<svcmgr_defs::stop::StopClass>,
    /// The recognised shutdown actuator: each instance is created pinned
    /// (`svcmgr_defs::create_flags`), and a receive-only derivation of the
    /// core-death queue rides the slot after its seeds and authority caps on
    /// every launch, so each instance observes the core set. See
    /// `restart::mint_core_death_recv`.
    pub shutdown_actuator: bool,
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
// Each `SUBSTRATE` round parks one service's name, main thread cap and
// address-space observer cap in `pending`;
// `HANDOVER_COMPLETE` later reconciles them against
// `/config/svcmgr/services/`. log and procmgr endpoints arrive via
// `ProcessInfo` / `StartupInfo`, not these rounds.

/// Well-known capability slots acquired from the handover endowment.
pub struct SvcmgrCaps
{
    /// Service protocol endpoint capability slot.
    pub service_ep: u64,
    /// svcmgr's own bootstrap endpoint (receives bootstrap requests from
    /// restarted children).
    pub bootstrap_ep: u64,
    /// SEND on vfsd's synthetic root, derived by init from its system-root
    /// cap, published as `rootfs.root`. Zero if init could not derive it.
    pub rootfs_root: u64,
    /// `SEND|GRANT`, badge-0 source on devmgr's registry endpoint. svcmgr
    /// mints the seed-only `devmgr.registry`, `devmgr.shutdown`, and
    /// `devmgr.bind` publish caps, the `CLASS_AUTHORITY` SEND it requests the
    /// `devmgr.class.*` class SENDs with, and the `SET_DRIVERS_DIR` cap
    /// (`DRIVERS_DIR_AUTHORITY`) from it. Zero if absent.
    pub devmgr_registry: u64,
    /// `MOUNT_AUTHORITY`-badged SEND on vfsd's service endpoint, published
    /// seed-only as `vfsd.mount`. Zero if absent.
    pub vfsd_mount: u64,
    /// `DENY_BADGE`-badged SEND on vfsd's service endpoint, published
    /// seed-only as `vfsd.deny`. Zero if absent.
    pub vfsd_deny: u64,
    /// `SWAP_AUTHORITY`-badged SEND on vfsd's service endpoint, published
    /// seed-only as `vfsd.swap`. Zero if absent.
    pub vfsd_swap: u64,
    /// `EntropyControl` source carrying `Contribute`. svcmgr derives a copy
    /// from it per launch for the one `entropy_authority = yes` service, and
    /// never publishes it. Zero if absent.
    pub entropy_source: u64,
    /// `SWAP_AUTHORITY`-badged `SEND|GRANT` on memmgr's endpoint, published
    /// seed-only, with `GRANT`, as `memmgr.swap`. Zero if absent.
    pub memmgr_swap: u64,
    /// Reserved master-log endpoint source (`RIGHTS_ALL`). svcmgr mints
    /// real-logd's master-log RECV from it on every (re)launch, and the
    /// one-shot `HANDOVER_PULL` SEND on the first launch and on a restart
    /// until procmgr reports init reaped, and publishes the
    /// `LOG_QUERY_AUTHORITY` SEND minted from it as `logd.query`. Holding it
    /// keeps the log endpoint object alive across a logd crash. Zero if
    /// absent.
    pub master_log_source: u64,
    /// Badge-0 `SEND|GRANT` source on procmgr's service endpoint. svcmgr mints
    /// real-logd's `DEATH_EQ_AUTHORITY` `SEND|GRANT` cap from it per launch,
    /// and a `debug_authority = yes` service's `DEBUG_AUTHORITY` `SEND|GRANT`
    /// cap per launch. Zero if absent.
    pub procmgr_death_auth_source: u64,
}

/// Acquire svcmgr's initial cap set and substrate registrations from its
/// creator (init) by draining the handover endowment rounds. Each substrate
/// service's registration (name, main thread cap, address-space observer
/// cap) is parked in `pending`; the returned
/// `SvcmgrCaps` carries the endpoint + publish-source caps. Returns `None`
/// on a missing creator endpoint, a failed round, a version mismatch, or a
/// malformed CAPS round.
pub fn bootstrap_caps(
    info: &StartupInfo,
    ipc_buf: *mut u64,
    pending: &mut Vec<PendingRegistration>,
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
        // The valid prefixes of the round's caps and data words.
        let round_caps = round.caps.get(..round.cap_count).unwrap_or_default();
        let round_words = round.data.get(..round.data_words).unwrap_or_default();
        match round.data[0]
        {
            endow_kind::CAPS =>
            {
                match caps_decoder.push(round_caps, round_words)
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
                            vfsd_mount: c.vfsd_mount,
                            vfsd_deny: c.vfsd_deny,
                            vfsd_swap: c.vfsd_swap,
                            entropy_source: c.entropy_source,
                            memmgr_swap: c.memmgr_swap,
                            master_log_source: 0,
                            procmgr_death_auth_source: 0,
                        });
                    }
                    Err(DecodeError::VersionMismatch) =>
                    {
                        std::os::seraph::log!(error: "bootstrap: endowment version mismatch");
                        return None;
                    }
                    Err(DecodeError::Malformed) =>
                    {
                        std::os::seraph::log!(error: "bootstrap: malformed endowment CAPS round");
                        return None;
                    }
                }
            }
            endow_kind::SUBSTRATE => ingest_substrate(&round, pending),
            endow_kind::LOGD_SOURCES =>
            {
                // Terminal round (arrives after CAPS). Record the reserved
                // log-sink sources on the already-built cap set; a round
                // with no cap set to land on, or one that does not decode,
                // is released rather than leaked.
                let delivered = round_caps;
                match (
                    caps.as_mut(),
                    svcmgr_endowment::decode_logd_sources(delivered, round_words),
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
                                warn: "bootstrap: malformed endowment LOGD_SOURCES round"
                            );
                        }
                        for &cap in delivered
                        {
                            let _ = syscall::cap_delete(cap);
                        }
                    }
                }
            }
            other =>
            {
                // A round of a kind svcmgr does not know: its caps have no
                // role here, so release them rather than hold them.
                std::os::seraph::log!(warn: "bootstrap: unknown endowment kind {other}");
                for &cap in round_caps
                {
                    let _ = syscall::cap_delete(cap);
                }
            }
        }
        if round.done
        {
            break;
        }
    }
    caps
}

/// Copy `s` into a new `String`, or `None` when the heap cannot hold it:
/// the fallible copy every name and path svcmgr stores goes through.
pub fn try_string(s: &str) -> Option<String>
{
    let mut out = String::new();
    out.try_reserve_exact(s.len()).ok()?;
    out.push_str(s);
    Some(out)
}

/// Park one decoded `SUBSTRATE` round (the service's name, its main thread
/// cap, and the cap svcmgr observes its address space through) in
/// `pending`. Releases every delivered cap on any reject (a round that does
/// not decode, a name that is not UTF-8, heap exhausted), so a malformed round
/// cannot leak a cap.
fn ingest_substrate(round: &ipc::bootstrap::BootstrapRound, pending: &mut Vec<PendingRegistration>)
{
    let caps = round.caps.get(..round.cap_count).unwrap_or_default();
    let words = round.data.get(..round.data_words).unwrap_or_default();
    let reject = |why: &str| {
        std::os::seraph::log!(warn: "bootstrap: substrate round dropped: {why}");
        for &cap in caps
        {
            let _ = syscall::cap_delete(cap);
        }
    };
    let Ok(substrate) = svcmgr_endowment::decode_substrate(caps, words)
    else
    {
        reject("malformed");
        return;
    };
    let Some(name) = core::str::from_utf8(substrate.name()).ok()
    else
    {
        reject("name invalid");
        return;
    };
    let Some(name) = try_string(name).filter(|_| pending.try_reserve(1).is_ok())
    else
    {
        reject("no memory for a pending registration");
        return;
    };
    std::os::seraph::log!("endowed: {name}");
    pending.push(PendingRegistration {
        name,
        thread_cap: substrate.thread,
        observer: substrate.observer,
        consumed: false,
    });
}
