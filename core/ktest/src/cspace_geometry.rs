// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/cspace_geometry.rs

//! Mirrors of the kernel's `CSpace` directory geometry, for the cases that
//! probe the boundaries of its slot regions (`unit::cap::lookup_bounds`) and
//! the pages a `CSpace` spends on them (`unit::retype`).
//!
//! The kernel keeps these private (`L1_DIRECT`, `L1_INDIRECT` and `DIR_FANOUT`
//! in core/kernel/src/cap/cspace.rs; core/kernel/docs/capability-internals.md
//! § Storage: Hybrid Two-Level Radix), so ktest holds this one copy, listed
//! under docs/limits.md § Cross-Cutting Findings, Unpinned couplings. Each leaf
//! holds `syscall_abi::CSPACE_SLOTS_PER_PAGE` slots, the ABI's asserted copy of
//! the kernel's `L2_SIZE`.

/// Leaf pages the `CSpace` root addresses directly: the kernel's `L1_DIRECT`.
pub const DIRECT_LEAVES: u64 = 128;

/// Directory pages the `CSpace` root addresses past the direct leaves: the
/// kernel's `L1_INDIRECT`.
pub const INDIRECT_DIRS: u64 = 128;

/// Leaves per directory page, one page of leaf pointers: the kernel's
/// `DIR_FANOUT`.
pub const DIR_FANOUT: u64 = syscall_abi::PAGE_SIZE / core::mem::size_of::<*const ()>() as u64;
