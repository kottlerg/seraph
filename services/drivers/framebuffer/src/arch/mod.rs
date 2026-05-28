// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/framebuffer/src/arch/mod.rs

//! Architecture dispatch module.
//!
//! The only file in the framebuffer driver permitted to contain
//! `#[cfg(target_arch)]` guards. All other modules reach arch-specific
//! framebuffer MMIO mapping through `arch::current::*`.
//!
//! Both arches use the same MMIO mapping mechanism today; the
//! per-arch leaves remain symmetric with the serial driver template
//! and reserve a place for future cache-attribute divergence (e.g.
//! write-combining on x86-64) without disturbing the main flow.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
