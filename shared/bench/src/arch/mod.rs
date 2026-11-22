// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! This is the only file in this crate permitted to contain
//! `#[cfg(target_arch)]` guards. All other modules reach the
//! architecture-specific items through the `arch::current` re-export: the
//! architecture's name in the result line and the cycle counter read.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
