// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! This is the only file in acpid permitted to contain `#[cfg(target_arch)]`
//! guards. The rest of acpid reaches the platform through the
//! `arch::current` re-export, whose dispatch surface every architecture
//! defines: `APIC_MODEL`, `enable_acpi`, `bind_ports`, `port_read`,
//! `port_write`, `Power`, and `Events` with its `Ports`.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
