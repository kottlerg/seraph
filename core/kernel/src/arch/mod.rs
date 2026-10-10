// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/mod.rs

//! Architecture dispatch module: selects the active architecture's module as
//! `current` (see `docs/coding-standards.md` § C. Architecture Invariants and
//! `core/kernel/docs/arch-interface.md`).

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
