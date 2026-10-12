// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/mod.rs

//! ktest's architecture-dispatch surface.
//!
//! One module per architecture, selected here by `target_arch` (the arch-module
//! declaration site, per docs/coding-standards.md § C). Each exposes the same
//! entry points; architecture-specific ktest code belongs behind them.
//!
//! TODO: move every `#[cfg(target_arch)]` item outside `src/arch/` behind this
//! surface. Deferred because the move is ktest-wide restructuring, separate from
//! the kernel fixes the code here validates; #460 lists the remaining sites.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
mod current;

pub use current::{run_integration, run_unit};
