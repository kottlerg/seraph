// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/arch/mod.rs

//! Architecture dispatch: the target description and the single-step
//! route of each architecture (docs/fault-handling.md § Debugging).
//!
//! One module per architecture, selected here by `target_arch` (the
//! arch-module declaration site, per docs/coding-standards.md § C). Each
//! exposes the same items: `ARCH`, `BREAKPOINT_PC_ADVANCE`, `StepUndo`,
//! `prepare_step`, and the undo of a step in its two parts:
//! `finish_step_text`, through any thread of the target, and
//! `finish_step_regs`, on the held stepped thread's register file.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
mod current;

pub use current::{
    ARCH, BREAKPOINT_PC_ADVANCE, StepUndo, finish_step_regs, finish_step_text, prepare_step,
};
