// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! This is the only file in pwrmgr permitted to contain `#[cfg(target_arch)]`
//! guards. All other modules reach the platform actuator through the
//! `arch::current` re-export, whose dispatch surface every architecture
//! defines: `Actuator`, `resolve`, `watch_events`, `shutdown`, `reboot`,
//! and the core-death power-off's `PowerOff`, `resolve_power_off` and
//! `power_off_now`.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
