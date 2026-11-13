// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/lib.rs

//! Host-testable logic of the VT-d IOMMU driver (`iommu-vtd`).
//!
//! The driver binary owns the remapping units' registers and the IPC loop
//! devmgr drives. This library holds the pure encodings those paths write:
//! the register offsets and fields ([`regs`]), the root, context, and
//! second-level translation structures ([`tables`]), with the page-table walk
//! running over a caller-supplied page store so the host tests exercise it,
//! the queued-invalidation descriptors ([`queue`]), and the interrupt
//! remapping table's entries ([`remap`]).
//! See `docs/device-management.md` § IOMMU Discovery and Programming.

#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
// Staged roll-out of these lints: docs/coding-standards.md § Clippy. The
// test configuration is exempt from the second set, as from `unwrap_used`.
#![warn(
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

extern crate alloc;

pub mod queue;
pub mod regs;
pub mod remap;
pub mod tables;
