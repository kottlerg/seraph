// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/debugger/src/arch/mod.rs

//! The debugger fixture's architecture-dispatch surface.
//!
//! One module per architecture, selected here by `target_arch` (the
//! arch-module declaration site, per docs/coding-standards.md § C). Each
//! exposes the same items:
//!
//! - `IP`, `RESUME_ADVANCE`, `BREAKPOINT`, `reported`, `breakpoint`: the
//!   register-file pointer offset and the software breakpoint;
//! - `arm_step`, `single_step`: the single-step of step 2, by the trap flag
//!   on x86-64 and by a `c.ebreak` planted at each successor on riscv64;
//!   `arm_step` returns the armed step (each module's `Step`), which
//!   `single_step` takes.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64.rs"]
mod current;

pub use current::{BREAKPOINT, IP, RESUME_ADVANCE, arm_step, breakpoint, reported, single_step};
