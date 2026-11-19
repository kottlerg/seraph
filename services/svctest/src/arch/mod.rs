// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! This is the only file in svctest permitted to contain `#[cfg(target_arch)]`
//! guards. A phase reaches the register-file layout and the RTC driver's name
//! through the `arch::current` re-export.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
