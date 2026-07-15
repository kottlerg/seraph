// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/definitions/mod.rs

//! On-disk service definitions.
//!
//! Every userspace service supervised by svcmgr has a `.svc` file at
//! `/config/svcmgr/services/<name>.svc`. The file is the **single
//! source of truth** for the service's recipe: binary path, argv,
//! env, restart policy, criticality, namespace shape, optional cwd,
//! scheduling placement (`priority` / `sched_max`), and the named seed
//! caps to inject into its bootstrap round. A `log_sink = yes` recipe
//! (the master log sink, real-logd) instead takes a svcmgr-minted
//! bootstrap round from the reserved log-sink sources and declares
//! neither `seed` nor `provides`. The same definition drives both
//! first-launch (when init didn't bootstrap the service) and restart
//! (when init did).
//!
//! The plain-data recipe types and the `.svc` parser live in the
//! host-tested `svcmgr-defs` crate (re-exported here); this module keeps
//! the impure halves:
//!
//! At [`crate::svcmgr_labels::HANDOVER_COMPLETE`] svcmgr calls
//! [`reconcile::reconcile_and_launch`]:
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
pub mod reconcile;

pub use svcmgr_defs::{
    Definition, NamespaceShape, ProvidedName, RestartPolicy, SERVICES_DIR, parse,
};
