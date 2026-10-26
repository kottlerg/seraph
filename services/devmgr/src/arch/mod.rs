// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! Arch-neutral code reaches arch-specific behaviour through the
//! `arch::current` re-export, per `docs/coding-standards.md`
//! § C. Architecture Invariants.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
