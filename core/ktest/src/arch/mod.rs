// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/mod.rs

//! ktest's architecture-dispatch surface.
//!
//! One module per architecture, selected here by `target_arch` (the arch-module
//! declaration site, per docs/coding-standards.md § C). Each exposes the same
//! entry points; architecture-specific ktest code belongs behind them. Some
//! older arch-gated items elsewhere in ktest have not moved yet (#460).

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
mod current;

pub use current::run_integration;
