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
//! The plain-data recipe types, the `.svc` parser, the argv/env wire-blob
//! encoder `build_blob`, and the cwd-cap rights (`cwd_rights`) and
//! `HANDOVER_COMPLETE` gate (`handover_permitted`) decisions live in the
//! host-tested `svcmgr-defs` crate (re-exported here); this module keeps the
//! impure halves:
//!
//! At [`crate::svcmgr_labels::HANDOVER_COMPLETE`] svcmgr calls
//! [`reconcile::reconcile_and_launch`], which scans [`SERVICES_DIR`], parses
//! every `.svc` into a [`Definition`], and pairs each with the
//! pending-registration table [`crate::service::bootstrap_caps`] populated
//! from init's endowment; a defined-only service is launched through
//! [`launch::launch`]. The three reconcile outcomes are specified in
//! `services/svcmgr/docs/service-definitions.md` § Reconciliation.

pub mod launch;
pub mod reconcile;

pub use svcmgr_defs::{
    Definition, NamespaceShape, ProvidedName, RestartPolicy, SERVICES_DIR, build_blob, cwd_rights,
    handover_permitted, parse,
};
