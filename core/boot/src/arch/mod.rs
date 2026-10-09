// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/mod.rs

//! Architecture dispatch module: the bootloader's arch-module declaration
//! site (per `docs/coding-standards.md` § C. Architecture Invariants). All other
//! modules reach architecture-specific functionality through the
//! `arch::current` re-export.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
