// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! Arch-neutral code reaches arch-specific behaviour through the
//! `arch::current` re-export, per `docs/coding-standards.md`
//! § C. Architecture Invariants. VT-d exists only on x86-64, and xtask builds
//! the driver for that architecture alone; the riscv64 side is a documented
//! no-op that keeps the surface defined on every supported architecture.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
