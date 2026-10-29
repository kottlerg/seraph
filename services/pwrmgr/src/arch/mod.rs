// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! This is the only file in pwrmgr permitted to contain `#[cfg(target_arch)]`
//! guards. All other modules reach the platform actuator through the
//! `arch::current` re-export, whose dispatch surface every architecture
//! defines: `Actuator`, `resolve`, `shutdown`, and `reboot`.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
