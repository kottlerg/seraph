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

pub mod regs;
pub mod tables;
