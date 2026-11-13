// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/lib.rs

//! Pure bookkeeping logic for memmgr: the metadata arena, the free pool, the
//! deferred list of reclaimed frames not yet pooled, the process index, and
//! the demand-region interval arithmetic and protection check.
//!
//! The crate performs no IPC and issues no syscalls. Storage arrives through
//! the [`SlotStore`] and [`WordStore`] traits (mapped pool pages in memmgr, a
//! vector in host tests), and the two kernel operations the pool needs —
//! merging two adjacent Memory caps (`memory_merge`) and splitting one
//! (`memory_split`) — are injected as closures, so memmgr keeps the syscall
//! surface and this logic stays host-testable. The quiescence check that
//! decides whether a reclaimed frame may join the pool is injected the same
//! way. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]

pub mod arena;
pub mod deferred;
pub mod index;
pub mod ledger;
pub mod pool;

pub use arena::{
    Arena, ArenaLayout, FrameDesc, NO_REGION_ID, NODE_NULL, Node, NodeIdx, ProcessRecord,
    SLOTS_PER_PAGE, SlotStore,
};
pub use deferred::{DeferredList, RecheckBudget};
pub use index::{BUCKETS_PER_PAGE, ProcessIndex, WordStore};
pub use ledger::{Ledger, RegionError};
pub use pool::{Fit, FreePool, Grant, GrantEntry, MAX_GRANT_RUNS, SelectError};

use syscall_abi::{FAULT_ACCESS_EXEC, FAULT_ACCESS_WRITE, MAP_EXECUTABLE, MAP_WRITABLE, PAGE_SIZE};

/// Pages backed per demand fault: memmgr maps a contiguous chunk of up to this
/// many pages (clamped to the region) on each fault rather than a single page.
/// A fault-around tuning value that bounds no capacity: a page outside the
/// chunk faults again and is backed by the next chunk.
pub const DEMAND_CHUNK_PAGES: u32 = 16;

/// One free run: a Memory cap memmgr owns, covering `page_count` pages
/// starting at physical address `phys_base`. The page count is `u64`, so a
/// run of any size the kernel can mint is held whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreeRun
{
    pub cap_slot: u64,
    pub page_count: u64,
    pub phys_base: u64,
}

/// One demand-paged anonymous region a process registered via
/// `REGISTER_REGION`. A page fault inside `[va_base, va_base + len)` is backed
/// on demand with `prot`; a fault outside every region is declined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DemandRegion
{
    pub va_base: u64,
    pub len: u64,
    pub prot: u64,
}

/// Whether `region`'s protection grants a fault's `access`, the
/// `FAULT_ACCESS_*` flags of a `FAULT_KIND_VM` message
/// (docs/fault-handling.md § Fault Message): a write needs `MAP_WRITABLE`
/// and an instruction fetch `MAP_EXECUTABLE`, while a read needs nothing, the
/// kernel granting read at every map. A fault the region does not grant is
/// never satisfiable by backing the page, since memmgr maps every chunk with
/// the region's protection.
#[must_use]
pub fn region_grants(region: &DemandRegion, access: u64) -> bool
{
    let write_refused = access & FAULT_ACCESS_WRITE != 0 && region.prot & MAP_WRITABLE == 0;
    let fetch_refused = access & FAULT_ACCESS_EXEC != 0 && region.prot & MAP_EXECUTABLE == 0;
    !write_refused && !fetch_refused
}

/// Whether `[base, base + len)` contains `va` (half-open, saturating at the
/// top of the address space).
#[must_use]
pub fn region_contains(base: u64, len: u64, va: u64) -> bool
{
    va >= base && va < base.saturating_add(len)
}

/// Whether `[a_base, a_base + a_len)` and `[b_base, b_base + b_len)` overlap.
/// Adjacent (touching) ranges are disjoint. Ends saturate at the top of the
/// address space.
#[must_use]
pub fn regions_overlap(a_base: u64, a_len: u64, b_base: u64, b_len: u64) -> bool
{
    a_base < b_base.saturating_add(b_len) && b_base < a_base.saturating_add(a_len)
}

/// The contiguous chunk of `region` that backs a fault at `page_base`: the
/// `DEMAND_CHUNK_PAGES`-aligned window within the region containing the page,
/// clamped to the region end (the last chunk may be shorter). Chunks are
/// fixed and non-overlapping, so each region page belongs to exactly one.
/// Returns `(chunk_base, chunk_pages)` with `chunk_pages ∈ [1, DEMAND_CHUNK_PAGES]`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "chunk_pages is bounded by DEMAND_CHUNK_PAGES (16), so the u64 -> u32 narrowing \
              cannot truncate"
)]
#[must_use]
pub fn chunk_for(region: &DemandRegion, page_base: u64) -> (u64, u32)
{
    const CHUNK_BYTES: u64 = DEMAND_CHUNK_PAGES as u64 * PAGE_SIZE;
    // page_base >= region.va_base: region_for matched `va`, and va_base is
    // page-aligned, so the page containing `va` cannot precede it.
    let chunk_idx = page_base.saturating_sub(region.va_base) / CHUNK_BYTES;
    // The region lies within the address space, so its end and the chunk sums stay below
    // `u64::MAX`.
    let chunk_base = region
        .va_base
        .saturating_add(chunk_idx.saturating_mul(CHUNK_BYTES));
    let region_end = region.va_base.saturating_add(region.len);
    let chunk_end = chunk_base.saturating_add(CHUNK_BYTES).min(region_end);
    let chunk_pages = (chunk_end.saturating_sub(chunk_base) / PAGE_SIZE) as u32;
    (chunk_base, chunk_pages)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn region_grants_refuses_only_an_access_the_protection_lacks()
    {
        use syscall_abi::{FAULT_ACCESS_PRESENT, FAULT_ACCESS_READ, MAP_READ};
        let region = |prot| DemandRegion {
            va_base: 0x1000,
            len: 0x1000,
            prot,
        };
        let ro = region(MAP_READ);
        let rw = region(MAP_READ | MAP_WRITABLE);
        let rx = region(MAP_READ | MAP_EXECUTABLE);
        let write = FAULT_ACCESS_WRITE | FAULT_ACCESS_PRESENT;

        assert!(region_grants(&ro, FAULT_ACCESS_READ));
        assert!(!region_grants(&ro, write));
        assert!(!region_grants(&ro, FAULT_ACCESS_EXEC));
        assert!(region_grants(&rw, write));
        assert!(!region_grants(&rw, FAULT_ACCESS_EXEC));
        assert!(region_grants(&rx, FAULT_ACCESS_EXEC));
        assert!(!region_grants(&rx, FAULT_ACCESS_WRITE));
    }

    #[test]
    fn region_contains_is_half_open_at_both_bounds()
    {
        // [0x1000, 0x3000): base included, base+len excluded.
        assert!(region_contains(0x1000, 0x2000, 0x1000));
        assert!(region_contains(0x1000, 0x2000, 0x2FFF));
        assert!(!region_contains(0x1000, 0x2000, 0x3000));
        assert!(!region_contains(0x1000, 0x2000, 0x0FFF));
    }

    #[test]
    fn region_contains_saturates_at_address_space_top()
    {
        // base + len overflows u64; saturating_add pins the end at u64::MAX so a
        // high-address fault inside the region is still claimed.
        assert!(region_contains(u64::MAX - 0x1000, 0x8000, u64::MAX - 1));
    }

    #[test]
    fn regions_overlap_treats_adjacent_ranges_as_disjoint()
    {
        // Back-to-back ranges touch but do not overlap.
        assert!(!regions_overlap(0, 0x1000, 0x1000, 0x1000));
        // One byte of overlap is an overlap.
        assert!(regions_overlap(0, 0x1001, 0x1000, 0x1000));
    }

    #[test]
    fn chunk_for_returns_aligned_window_for_first_chunk()
    {
        let region = DemandRegion {
            va_base: 0x10000,
            len: 0x10_0000,
            prot: 0,
        };
        let chunk_bytes = u64::from(DEMAND_CHUNK_PAGES) * PAGE_SIZE;
        // A fault at the region base maps to the first full chunk.
        assert_eq!(chunk_for(&region, 0x10000), (0x10000, DEMAND_CHUNK_PAGES));
        // A page inside the second chunk maps to the second chunk's base, not
        // a window misaligned by dividing by PAGE_SIZE instead of chunk_bytes.
        let (base, _) = chunk_for(&region, 0x10000 + chunk_bytes + PAGE_SIZE);
        assert_eq!(base, 0x10000 + chunk_bytes);
    }

    #[test]
    fn chunk_for_clamps_final_chunk_to_region_end()
    {
        // Region shorter than one chunk: the only chunk is clamped to its length.
        let region = DemandRegion {
            va_base: 0x10000,
            len: 5 * PAGE_SIZE,
            prot: 0,
        };
        assert_eq!(chunk_for(&region, 0x10000), (0x10000, 5));
    }
}
