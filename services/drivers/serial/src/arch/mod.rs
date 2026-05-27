// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/serial/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! The only file in the serial driver permitted to contain
//! `#[cfg(target_arch)]` guards. All other modules reach arch-specific
//! UART access through `arch::current::*`.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
