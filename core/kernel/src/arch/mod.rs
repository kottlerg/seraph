// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/mod.rs

//! Architecture dispatch module: selects the active architecture's module as
//! `current` (see `docs/coding-standards.md` § C. Architecture Invariants and
//! `core/kernel/docs/arch-interface.md`), defines [`ThreadKind`], the one
//! type both architectures' `context::new_state` share, and holds [`nospec`],
//! the arch-neutral speculation-safe bounds built on `current::speculation`. Host test builds of
//! other architectures also compile riscv64's `encoding` module, which
//! depends on nothing else in its arch module, so its tests run on the host.

// Staged roll-out of docs/coding-standards.md § Clippy: this subsystem's sites are fixed.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;

pub mod nospec;

// The riscv64 module's pure register-map and encoding arithmetic, compiled
// alone into the host test builds of the other architectures so that
// `cargo xtask test`, which runs on an x86_64 host, runs its tests.
#[cfg(all(test, not(target_arch = "riscv64")))]
#[path = "riscv64/encoding.rs"]
mod riscv64_encoding;

// The riscv64 AIA register-map arithmetic, compiled alone into the host test
// builds of the other architectures for the same reason.
#[cfg(all(test, not(target_arch = "riscv64")))]
#[path = "riscv64/aia_encoding.rs"]
mod riscv64_aia_encoding;

/// Which privilege level a new thread runs at, selecting its first-dispatch
/// interrupt state in `context::new_state` (the first-dispatch trampoline rule of
/// core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadKind
{
    /// A user thread: its first dispatch runs the kernel-side trampoline to
    /// `return_to_user` with interrupts masked.
    User,
    /// A kernel thread (idle): its first dispatch runs kernel code that may
    /// wait for interrupts.
    Kernel,
}
