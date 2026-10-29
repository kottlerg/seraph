// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/mod.rs

//! ktest's architecture-dispatch surface.
//!
//! One module per architecture, selected here by `target_arch` (the arch-module
//! declaration site, per docs/coding-standards.md § C). Each exposes the same
//! entry points, constants, and modules; all architecture-specific ktest code
//! lives behind them, and no `#[cfg(target_arch)]` appears elsewhere in ktest.
//!
//! - `fpu`, `callee_saved`, `code_stub`: the per-architecture halves of
//!   arch-neutral tests (register-file probes, machine-code stubs).
//! - `serial`: the UART behind `crate::serial`.
//! - `init_io_ports`, `shutdown`, `cycles_now`: harness services.
//! - `run_unit`, `run_integration`: architecture-only Tier 1 and Tier 2 tests.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
mod current;

pub use current::{
    ARG1_OFFSET, ILLEGAL_INSTRUCTION_VECTOR, IP_OFFSET, MMIO_PROBE_OFFSET, MMIO_PROBE_PHYS,
    PAGE_FAULT_LOAD_VECTOR, PAGE_FAULT_STORE_VECTOR, SYSCALL_NR_OFFSET, TRAP_FRAME_BYTES,
    callee_saved, code_stub, cycles_now, fpu, illegal_instruction, init_io_ports, run_integration,
    run_unit, serial, shutdown,
};
