// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/definitions/mod.rs

//! On-disk service definitions.
//!
//! Every userspace service supervised by svcmgr has a `.svc` file at
//! `/config/svcmgr/services/<name>.svc`. The file is the **single
//! source of truth** for the service's recipe: binary path, argv,
//! env, restart policy, criticality, namespace shape, optional cwd,
//! and the named seed caps to inject into its bootstrap round. The
//! same definition drives both first-launch (when init didn't
//! bootstrap the service) and restart (when init did).
//!
//! At [`crate::svcmgr_labels::HANDOVER_COMPLETE`] svcmgr calls
//! [`reconcile_and_launch`]:
//!
//! 1. Scan [`SERVICES_DIR`] and parse every `.svc` into a [`Definition`].
//! 2. Reconcile against the pending-registration table
//!    [`crate::service::bootstrap_caps`] populated from init's handover
//!    endowment (one substrate `(name, thread_cap)` round each):
//!    - **Defined AND parked**: bind death-notification on the endowed
//!      thread cap and store the parsed `Definition` on the
//!      `ServiceEntry` for restart use.
//!    - **Defined only**: launch the service via [`launch::launch`].
//!    - **Parked without definition**: log a hard error and refuse to
//!      bind — svcmgr has no recipe to restart it.
//!
//! After reconciliation the supervision loop proceeds as today.

pub mod launch;
pub mod parse;
pub mod reconcile;

/// Restart-policy values parsed from the `restart = ...` line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RestartPolicy
{
    /// Service is one-shot; never restart, even on fault. Used for
    /// integration-test fixtures whose exit is the success signal
    /// (e.g. `svctest`).
    Never,
    /// Restart only on a fault exit (`exit_reason >= EXIT_FAULT_BASE`).
    /// Clean exits are treated as intentional.
    OnFailure,
    /// Restart on every exit, clean or faulty. Default for daemons
    /// that should never terminate during normal operation.
    Always,
}

/// Namespace shape parsed from the `namespace = ...` line.
///
/// One of:
///   * `namespace = none` → no namespace cap at all.
///   * `namespace = universal` → `cap_copy` of svcmgr's universal
///     `system_root_cap`.
///   * `namespace = subtree:<path>:<rights>` → walk `path` from
///     svcmgr's root requesting `<rights>` per hop.
#[derive(Clone, Debug)]
pub enum NamespaceShape
{
    None,
    Universal,
    Subtree
    {
        path: String,
        rights: u32,
    },
}

/// One parsed `.svc` definition.
///
/// Storage uses heap-allocated `String` / `Vec` because svcmgr is
/// std-built and parsing happens once at handover. Reconciliation
/// either consumes the definition into a fixed-size `ServiceEntry`
/// (for supervision) or hands it straight to [`launch::launch`] for
/// one-shot spawn.
pub struct Definition
{
    pub name: String,
    pub binary: String,
    /// Each element is one argv token. The wire blob is built at
    /// launch time as NUL-separated, NUL-terminated bytes.
    pub argv: Vec<String>,
    /// Each element is one `KEY=VAL` entry. The wire blob is built at
    /// launch time as NUL-separated, NUL-terminated bytes.
    pub env: Vec<String>,
    pub restart: RestartPolicy,
    /// Whether the system is viable without this service once it is
    /// permanently down (restart not attempted, or budget exhausted).
    /// `true` (`critical = yes`) → svcmgr issues `pwrmgr_labels::SHUTDOWN`
    /// on unrecoverable death; `false` (`critical = no`) → the system
    /// continues degraded. Orthogonal to [`Definition::restart`], which
    /// alone decides whether/when to respawn.
    pub system_critical: bool,
    pub namespace: NamespaceShape,
    /// Optional cwd path. Interpreted relative to the namespace root
    /// installed via [`NamespaceShape`], or absolute against svcmgr's
    /// universal root when `namespace = universal`. Forbidden when
    /// `namespace = none` (parser rejects).
    pub cwd: Option<String>,
    /// Published-registry names svcmgr resolves at launch time and
    /// injects positionally into the child's bootstrap round.
    pub seed: Vec<String>,
    /// Registry names this service's own service endpoint is published
    /// under. When non-empty, svcmgr's launch path creates a service
    /// endpoint, serves its RECV half as bootstrap cap[0] (ahead of the
    /// `seed` caps), and publishes one SEND half per entry — each stamped
    /// with that entry's [`ProvidedName::token`] — into the discovery
    /// registry. The endpoint persists across restarts (svcmgr holds the
    /// source), so cached client caps survive a crash-restart cycle and no
    /// re-publish is needed. Empty for pure-consumer services that only
    /// receive `seed` caps. A provider also launches ahead of pure
    /// consumers during reconciliation so its names resolve before any
    /// consumer queries them.
    pub provides: Vec<ProvidedName>,
    /// `log_sink = yes` marks the service as the system log sink (real-logd).
    /// svcmgr mints its bootstrap round — master-log RECV, the first-launch
    /// `HANDOVER_PULL` SEND, a `DEATH_EQ_AUTHORITY` SEND, and a
    /// `devmgr.registry` query cap — from the reserved log-sink sources and
    /// the `devmgr.registry` source it holds, rather than from `seed` /
    /// `provides` (which the parser rejects in combination). Exactly one
    /// recipe carries this; supervision/restart otherwise follow the normal
    /// `restart`/`critical` fields.
    pub log_sink: bool,
}

/// One published name in a service's `provides = ...` list, with the
/// token svcmgr stamps on the SEND it publishes.
///
/// The token rides through publish → registry → `QUERY_ENDPOINT` lookup
/// unchanged (`cap_derive` inherits a source cap's token), so a consumer
/// that resolves the name receives a SEND already carrying it. The verb
/// the server gates on is `token & (1 << 63)`, the universal
/// verb-authority bit shared by every `*_AUTHORITY` constant.
#[derive(Clone, Debug)]
pub struct ProvidedName
{
    pub name: String,
    /// `1 << 63` for an `:auth` entry (carries the verb-authority bit),
    /// `1` for a `:deny` entry (present but gate-failing), `0` for a bare
    /// entry (untokened — published via `cap_derive`, not
    /// `cap_derive_token`).
    pub token: u64,
}

/// Directory svcmgr scans for service definitions. Absolute path
/// against svcmgr's `system_root_cap`; post-#21 handover that cap is
/// universal, so absolute lookups via `std::fs` resolve normally.
pub const SERVICES_DIR: &str = "/config/svcmgr/services";
