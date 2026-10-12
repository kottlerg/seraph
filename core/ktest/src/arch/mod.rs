// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/mod.rs

//! ktest's architecture-dispatch surface.
//!
//! One module per architecture, selected here by `target_arch` (the arch-module
//! declaration site, per docs/coding-standards.md § C). Each exposes the same
//! entry points; architecture-specific ktest code belongs behind them.
//!
//! TODO: move the arch-gated items still outside this surface behind it: the
//! `acpi_shutdown`, `ioport` and `sbi_shutdown` modules and their calls in `main.rs`,
//! `integration/sbi_gating.rs`, the arch-gated scenarios in
//! `integration/death_notification_late_bind.rs`, `integration/fault_exception_*.rs` and
//! `integration/thread_lifecycle.rs`, and the `TrapFrame` layout constants
//! (`TRAP_FRAME_BYTES`, `IP_OFFSET`) in `unit/thread.rs`. Deferred because the move is
//! ktest-wide restructuring, separate from the kernel fixes the scenarios here
//! validate; tracked on #460.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
mod current;

pub use current::run_integration;
