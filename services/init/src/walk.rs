// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/walk.rs

//! Init's namespace walk surface, re-exporting [`ns_client`].
//!
//! The implementation moved into the workspace-shared `shared/ns-client`
//! crate so devmgr can use the same walker against the attenuated
//! `/services/drivers/` subtree cap init delivers via
//! `devmgr_labels::SET_DRIVERS_DIR`. Init's call sites continue to import
//! through this module to avoid churn.

pub use ns_client::{walk_to_dir, walk_to_file};
