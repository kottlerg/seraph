// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/arch/mod.rs

//! Architecture-specific Tier 2 scenarios.
//!
//! One module per architecture, selected here (the only `target_arch` gate);
//! each exposes `run_all`, which registers that architecture's scenarios with
//! `run_integration_test!`. An architecture with none provides an empty
//! `run_all`.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
mod current;

pub use current::run_all;
