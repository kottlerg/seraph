// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/cspace_geometry.rs

//! Mirrors of the kernel's `CSpace` directory geometry, for the cases that
//! probe the boundaries of its slot regions (`unit::cap::lookup_bounds`) and
//! the pages a `CSpace` spends on them (`unit::retype`).
//!
//! The kernel keeps these private (`L1_DIRECT`, `L1_INDIRECT`, `L1_DOUBLE` and
//! `DIR_FANOUT` in core/kernel/src/cap/cspace.rs;
//! core/kernel/docs/capability-internals.md § Storage: Hybrid Radix
//! Directory), so ktest holds this one copy, listed under docs/limits.md
//! § Cross-Cutting Findings, Unpinned couplings. Each leaf holds
//! `syscall_abi::CSPACE_SLOTS_PER_PAGE` slots, the ABI's asserted copy of the
//! kernel's `L2_SIZE`; the slot ceiling derives from the ABI alone.

use syscall_abi::{CAP_INDEX_BITS, CSPACE_SLOTS_PER_PAGE};

/// Leaf pages the `CSpace` root addresses directly: the kernel's `L1_DIRECT`.
pub const DIRECT_LEAVES: u64 = 128;

/// Level-1 directory pages the `CSpace` root addresses past the direct
/// leaves: the kernel's `L1_INDIRECT`.
pub const INDIRECT_DIRS: u64 = 64;

/// Level-2 directory pages the `CSpace` root addresses past the indirect
/// region: the kernel's `L1_DOUBLE`.
pub const DOUBLE_DIRS: u64 = 63;

/// Entries per directory page, one page of pointers: the kernel's
/// `DIR_FANOUT`.
pub const DIR_FANOUT: u64 = syscall_abi::PAGE_SIZE / core::mem::size_of::<*const ()>() as u64;

/// First leaf of the double-indirect region.
pub const DOUBLE_BASE: u64 = DIRECT_LEAVES + INDIRECT_DIRS * DIR_FANOUT;

/// First leaf of the triple-indirect region.
pub const TRIPLE_BASE: u64 = DOUBLE_BASE + DOUBLE_DIRS * DIR_FANOUT * DIR_FANOUT;

/// The structural slot ceiling: the whole leaves the handle's index field
/// addresses, which the kernel's directory reaches.
pub const SLOT_CEILING: u64 = (1 << CAP_INDEX_BITS) / CSPACE_SLOTS_PER_PAGE * CSPACE_SLOTS_PER_PAGE;

/// Pool pages a `CSpace` with no grown leaf spends to cover slot `index` below
/// the triple region: every leaf through the covering one, plus the directory
/// pages above the leaves past the direct region at each level. Mirrors the
/// kernel's `CSpace::pages_to_cover` from leaf 0.
pub const fn pages_to_cover(index: u64) -> u64
{
    // Every count here is a page count below `SLOT_CEILING`'s, far from the
    // `u64` range, so no saturating step clamps.
    let leaf = index / CSPACE_SLOTS_PER_PAGE;
    let mut pages = leaf.saturating_add(1);
    if leaf >= DIRECT_LEAVES
    {
        let last = if leaf < DOUBLE_BASE
        {
            leaf
        }
        else
        {
            DOUBLE_BASE - 1
        };
        let dirs = last.saturating_sub(DIRECT_LEAVES) / DIR_FANOUT;
        pages = pages.saturating_add(dirs).saturating_add(1);
    }
    if leaf >= DOUBLE_BASE
    {
        let rel = leaf.saturating_sub(DOUBLE_BASE);
        pages = pages
            .saturating_add(rel / DIR_FANOUT)
            .saturating_add(1)
            .saturating_add(rel / (DIR_FANOUT * DIR_FANOUT))
            .saturating_add(1);
    }
    pages
}
