// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/syscall/src/arch/mod.rs

//! Architecture dispatch module: selects the active architecture's raw syscall
//! wrappers as `current`.
//!
//! This is the only file in this crate permitted to contain
//! `#[cfg(target_arch)]` guards (`docs/coding-standards.md` § C. Architecture
//! Invariants). Every architecture defines the same wrappers: `syscall2` to
//! `syscall6` (primary return only), `syscall5_ret2`, `syscall1_ret4`, and
//! `syscall6_ret3`.
//!
//! # Safety
//!
//! Every wrapper is an `unsafe fn` with one contract: `nr` must be a syscall
//! number the kernel defines, and the remaining arguments must be that call's
//! arguments, in the order `core/kernel/docs/syscalls.md` gives; a pointer argument must be
//! valid for the access the call's contract specifies. The kernel ABI's
//! register clobbers are declared in each wrapper's asm.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub(crate) mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub(crate) mod current;
