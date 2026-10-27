// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/definitions/mod.rs

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
//! neither `seed` nor `provides`. The same definition drives both first
//! launch (for services init did not bootstrap) and every restart.
//!
//! The plain-data recipe types, the `.svc` parser, and the argv/env
//! wire-blob encoder `build_blob` live in the host-tested `svcmgr-defs`
//! crate (re-exported here); this module keeps the impure halves:
//!
//! At [`crate::svcmgr_labels::HANDOVER_COMPLETE`] svcmgr calls
//! [`reconcile::reconcile_and_launch`]:
//!
//! 1. Scan [`SERVICES_DIR`] and parse every `.svc` into a [`Definition`].
//! 2. Reconcile against the pending-registration table
//!    [`crate::service::bootstrap_caps`] populated from init's handover
//!    endowment (one substrate `(name, thread_cap)` round each):
//!    - **Defined AND parked**: bind death-notification on the endowed
//!      thread cap, record the recipe's fixed fields on the
//!      `ServiceEntry` and its argv/env/cwd/seed, log-sink flag, and
//!      scheduling fields in the parallel `RestartRecipe` table for
//!      restart use.
//!    - **Defined only**: launch the service via [`launch::launch`].
//!    - **Parked without definition**: log a hard error and refuse to
//!      bind — svcmgr has no recipe to restart it.
//!
//! After reconciliation the supervision loop proceeds as today.

pub mod launch;
pub mod reconcile;

pub use svcmgr_defs::{
    Definition, NamespaceShape, ProvidedName, RestartPolicy, SERVICES_DIR, build_blob, cwd_rights,
    handover_permitted, parse,
};
