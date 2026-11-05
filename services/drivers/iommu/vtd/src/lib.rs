// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/lib.rs

//! Host-testable logic of the VT-d IOMMU driver (`iommu-vtd`).
//!
//! The driver binary owns the remapping units' registers and the IPC loop
//! devmgr drives. This library holds the pure encodings those paths write:
//! the register offsets and fields ([`regs`]) and the root, context, and
//! second-level translation structures ([`tables`]), with the page-table walk
//! running over a caller-supplied page store so the host tests exercise it.
//! See `docs/device-management.md` § IOMMU Discovery and Programming.

extern crate alloc;

pub mod regs;
pub mod tables;
