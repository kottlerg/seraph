// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! Arch-neutral code reaches arch-specific behaviour through the
//! `arch::current` re-export, per `docs/coding-standards.md`
//! § C. Architecture Invariants. VT-d exists only on x86-64, and xtask builds
//! the driver for that architecture alone, so x86-64 is the one
//! implementation.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;
