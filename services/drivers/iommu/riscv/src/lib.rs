// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/riscv/src/lib.rs

//! Host-testable logic of the RISC-V IOMMU driver (`iommu-riscv`).
//!
//! The driver binary owns the IOMMUs' registers and the IPC loop devmgr
//! drives. This library holds the pure encodings those paths write: the
//! register offsets and fields, the commands, and the fault record
//! ([`regs`]), and the device directory, the device context, and the
//! first-stage page tables ([`tables`]), the walks running over a
//! caller-supplied page store so the host tests exercise them. See
//! `docs/device-management.md` § IOMMU Discovery and Programming.

#![cfg_attr(not(test), no_std)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(clippy::large_stack_frames)]
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

pub mod regs;
pub mod tables;
