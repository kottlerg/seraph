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
//! 2. Reconcile against the pending-registration table init populated
//!    via [`crate::svcmgr_labels::REGISTER_SERVICE`]:
//!    - **Defined AND registered**: bind death-notification on the
//!      registered thread cap and store the parsed `Definition` on
//!      the `ServiceEntry` for restart use.
//!    - **Defined only**: launch the service via [`launch::launch`].
//!    - **Registered without definition**: log a hard error and
//!      refuse to bind — svcmgr has no recipe to restart it.
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
}

/// Directory svcmgr scans for service definitions. Absolute path
/// against svcmgr's `system_root_cap`; post-#21 handover that cap is
/// universal, so absolute lookups via `std::fs` resolve normally.
pub const SERVICES_DIR: &str = "/config/svcmgr/services";
