// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/arch/mod.rs

//! Architecture dispatch: the target description and the single-step
//! route of each architecture (docs/fault-handling.md § Debugging).

#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "riscv64")]
pub use riscv64 as current;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as current;
