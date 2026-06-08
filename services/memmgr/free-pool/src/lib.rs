// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// memmgr/free-pool/src/lib.rs

//! Pure free-pool allocator and region-interval logic.
//!
//! The free pool is a fixed array of physically-described memory runs; this
//! crate owns the run bookkeeping (best/largest fit, coalescing, splitting) and
//! the demand-region interval arithmetic. It performs no IPC and issues no
//! syscalls: the two operations that need the kernel — merging two adjacent
//! Memory caps (`memory_merge`) and splitting one (`memory_split`) — are
//! injected by the caller as closures, so `memmgr` keeps the syscall surface
//! and this logic stays host-testable. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

use syscall_abi::PAGE_SIZE;

/// Maximum free runs in the pool. Each run is one Memory cap covering one
/// or more contiguous pages.
pub const MAX_FREE_RUNS: usize = 512;

/// Pages backed per demand fault: memmgr maps a contiguous chunk of up to this
/// many pages (clamped to the region) on each fault rather than a single page.
pub const DEMAND_CHUNK_PAGES: u32 = 16;

/// One free run: a Memory cap memmgr owns, covering `page_count` pages
/// starting at physical address `phys_base`.
#[derive(Clone, Copy)]
pub struct FreeRun
{
    pub cap_slot: u32,
    pub page_count: u32,
    pub phys_base: u64,
}

/// One demand-paged anonymous region a process registered via
/// `REGISTER_REGION`. A page fault inside `[va_base, va_base + len)` is backed
/// on demand with `prot`; a fault outside every region is declined.
#[derive(Clone, Copy)]
pub struct DemandRegion
{
    pub va_base: u64,
    pub len: u64,
    pub prot: u64,
}

/// Free pool: array of runs. Order is irrelevant; allocation scans linearly.
pub struct FreePool
{
    pub runs: [Option<FreeRun>; MAX_FREE_RUNS],
}

impl Default for FreePool
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl FreePool
{
    // large_stack_arrays: FreePool lives in a `static mut` so this
    // initializer never lands on a runtime stack frame.
    #[allow(clippy::large_stack_arrays)]
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            runs: [None; MAX_FREE_RUNS],
        }
    }

    /// Pages currently parked in free runs — owned by memmgr but lent to no
    /// process. Unlike `pool_total` (monotonic owned-RAM), this falls as pages
    /// are allocated and rises as they are reclaimed (`PROCESS_DIED`,
    /// `RELEASE_MEMORY_CAPS`, `UNREGISTER_REGION`), so it is the observable a
    /// caller polls to confirm a dead process's pages came back.
    #[must_use]
    pub fn free_pages(&self) -> u64
    {
        let mut total: u64 = 0;
        for run in self.runs.iter().flatten()
        {
            total = total.saturating_add(u64::from(run.page_count));
        }
        total
    }

    /// Push a run into the first empty slot.
    ///
    /// # Errors
    /// Returns `Err(())` when all `MAX_FREE_RUNS` slots are occupied. The error
    /// is unit because the only failure mode is "array full"; callers branch on
    /// success alone.
    #[allow(clippy::result_unit_err)]
    pub fn push(&mut self, run: FreeRun) -> Result<(), ()>
    {
        for slot in &mut self.runs
        {
            if slot.is_none()
            {
                *slot = Some(run);
                return Ok(());
            }
        }
        Err(())
    }

    /// Push a run, coalescing once and retrying if the array is full.
    ///
    /// `push` fails only when all `MAX_FREE_RUNS` slots are occupied.
    /// Occupancy is dominated by fragmentation — many small runs `merge`
    /// can fold into fewer, larger ones — so on a full array we coalesce
    /// (freeing a slot per successful merge) and retry the push once. `Err`
    /// means the array is still full afterward (every run physically
    /// disjoint). `merge(parent, tail)` returns `true` iff the kernel joined
    /// the two caps.
    ///
    /// # Errors
    /// Returns `Err(())` when the array is still full after coalescing.
    #[allow(clippy::result_unit_err)]
    pub fn push_or_coalesce_with(
        &mut self,
        run: FreeRun,
        merge: impl Fn(u32, u32) -> bool,
    ) -> Result<(), ()>
    {
        if self.push(run).is_ok()
        {
            return Ok(());
        }
        self.coalesce_with(merge);
        self.push(run)
    }

    /// Find the smallest run covering at least `want` pages. Returns the
    /// array index, or `None` if no run is large enough.
    #[must_use]
    pub fn smallest_fit(&self, want: u32) -> Option<usize>
    {
        let mut best: Option<usize> = None;
        let mut best_size: u32 = u32::MAX;
        for (i, slot) in self.runs.iter().enumerate()
        {
            if let Some(run) = slot
                && run.page_count >= want
                && run.page_count < best_size
            {
                best = Some(i);
                best_size = run.page_count;
            }
        }
        best
    }

    /// Find the largest run regardless of size. Used by best-effort
    /// allocation to greedily pick the biggest available chunk.
    #[must_use]
    pub fn largest(&self) -> Option<usize>
    {
        let mut best: Option<usize> = None;
        let mut best_size: u32 = 0;
        for (i, slot) in self.runs.iter().enumerate()
        {
            if let Some(run) = slot
                && run.page_count > best_size
            {
                best = Some(i);
                best_size = run.page_count;
            }
        }
        best
    }

    /// Coalesce free runs into larger physically-contiguous chunks.
    ///
    /// `merge` (the kernel's `memory_merge`) only joins runs adjacent in
    /// physical memory, so sorting the populated runs by `phys_base` places
    /// every mergeable pair consecutively. A single linear pass then folds each
    /// run into its lower-addressed neighbour with one `merge` per pair: O(P)
    /// over P populated runs, versus the O(P²) of blind all-pairs probing. The
    /// distinction is load-bearing once the pool spans the whole machine and
    /// every process death coalesces — a syscall per ordered pair dominates
    /// teardown latency. `merge(parent, tail)` returns `true` iff the kernel
    /// joined the two caps.
    // cast_possible_truncation: slot indices are bounded by MAX_FREE_RUNS
    // (512), so `i as u16` cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    pub fn coalesce_with(&mut self, merge: impl Fn(u32, u32) -> bool)
    {
        // Collect populated slot indices (slot < MAX_FREE_RUNS fits u16).
        let mut order = [0u16; MAX_FREE_RUNS];
        let mut n = 0usize;
        for (i, slot) in self.runs.iter().enumerate()
        {
            if slot.is_some()
            {
                order[n] = i as u16;
                n += 1;
            }
        }
        // Insertion sort by phys_base: P is small in practice and this needs
        // no allocator. None never appears in `order`, so map_or's default is
        // unreachable.
        for a in 1..n
        {
            let key = order[a];
            let key_phys = self.runs[key as usize].map_or(0, |r| r.phys_base);
            let mut b = a;
            while b > 0 && self.runs[order[b - 1] as usize].map_or(0, |r| r.phys_base) > key_phys
            {
                order[b] = order[b - 1];
                b -= 1;
            }
            order[b] = key;
        }
        // Fold each run into the current survivor while `merge` accepts the
        // pair. The survivor is the lower-addressed run, so it is always the
        // merge parent; a rejection (non-adjacent or foreign parent) ends this
        // survivor's run and promotes the rejecting run to survivor.
        let mut s = 0usize;
        while s < n
        {
            let surv = order[s] as usize;
            let mut t = s + 1;
            while t < n
            {
                let (Some(parent), Some(tail)) = (self.runs[surv], self.runs[order[t] as usize])
                else
                {
                    break;
                };
                if !merge(parent.cap_slot, tail.cap_slot)
                {
                    break;
                }
                self.runs[surv] = Some(FreeRun {
                    cap_slot: parent.cap_slot,
                    page_count: parent.page_count + tail.page_count,
                    phys_base: parent.phys_base,
                });
                self.runs[order[t] as usize] = None;
                t += 1;
            }
            s = t;
        }
    }

    /// Peel exactly `want` pages off the run at index `idx`.
    ///
    /// If the run is larger, `split(cap_slot, offset)` (the kernel's
    /// `memory_split`) shrinks the run's cap in place to the first `offset`
    /// bytes and returns the new tail cap covering the remainder, which is
    /// reinserted into the pool. Returns the cap slot covering exactly `want`
    /// pages plus its physical base, or `None` if the run is too small or the
    /// split fails.
    #[must_use]
    pub fn take_exactly(
        &mut self,
        idx: usize,
        want: u32,
        split: impl FnOnce(u32, u64) -> Option<u32>,
    ) -> Option<(u32, u64)>
    {
        let run = self.runs[idx]?;
        if run.page_count == want
        {
            self.runs[idx] = None;
            return Some((run.cap_slot, run.phys_base));
        }
        if run.page_count < want
        {
            return None;
        }
        let split_offset = u64::from(want) * PAGE_SIZE;
        // Option-D split: `run.cap_slot` shrinks in place to cover the first
        // `split_offset` bytes; the returned slot is the new tail covering the
        // remainder at `phys_base + split_offset`.
        let tail = split(run.cap_slot, split_offset)?;
        self.runs[idx] = Some(FreeRun {
            cap_slot: tail,
            page_count: run.page_count - want,
            phys_base: run.phys_base + split_offset,
        });
        Some((run.cap_slot, run.phys_base))
    }
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
// cast_possible_truncation: chunk_pages is bounded by DEMAND_CHUNK_PAGES (16),
// so the u64 -> u32 narrowing cannot truncate.
#[allow(clippy::cast_possible_truncation)]
#[must_use]
pub fn chunk_for(region: &DemandRegion, page_base: u64) -> (u64, u32)
{
    let chunk_bytes = u64::from(DEMAND_CHUNK_PAGES) * PAGE_SIZE;
    // page_base >= region.va_base: region_for matched `va`, and va_base is
    // page-aligned, so the page containing `va` cannot precede it.
    let chunk_idx = (page_base - region.va_base) / chunk_bytes;
    let chunk_base = region.va_base + chunk_idx * chunk_bytes;
    let region_end = region.va_base + region.len;
    let chunk_end = (chunk_base + chunk_bytes).min(region_end);
    let chunk_pages = ((chunk_end - chunk_base) / PAGE_SIZE) as u32;
    (chunk_base, chunk_pages)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn run(cap_slot: u32, page_count: u32, phys_base: u64) -> FreeRun
    {
        FreeRun {
            cap_slot,
            page_count,
            phys_base,
        }
    }

    #[test]
    fn smallest_fit_picks_smallest_run_that_covers_want()
    {
        let mut pool = FreePool::new();
        pool.push(run(1, 8, 0)).unwrap();
        pool.push(run(2, 4, 0)).unwrap();
        pool.push(run(3, 16, 0)).unwrap();
        // want=4 fits the 4-page run exactly (smallest covering run), not the 8.
        let idx = pool.smallest_fit(4).expect("a run covers 4 pages");
        assert_eq!(pool.runs[idx].unwrap().cap_slot, 2);
        // want=5 cannot use the 4-page run; smallest covering is the 8.
        let idx = pool.smallest_fit(5).expect("a run covers 5 pages");
        assert_eq!(pool.runs[idx].unwrap().cap_slot, 1);
    }

    #[test]
    fn smallest_fit_returns_none_when_no_run_is_large_enough()
    {
        let mut pool = FreePool::new();
        pool.push(run(1, 2, 0)).unwrap();
        pool.push(run(2, 3, 0)).unwrap();
        assert!(pool.smallest_fit(4).is_none());
    }

    #[test]
    fn largest_returns_none_on_empty_pool()
    {
        let pool = FreePool::new();
        assert!(pool.largest().is_none());
    }

    #[test]
    fn push_fills_first_empty_slot_and_errs_when_full()
    {
        let mut pool = FreePool::new();
        assert_eq!(pool.free_pages(), 0);
        pool.push(run(1, 3, 0)).unwrap();
        pool.push(run(2, 5, 0x10000)).unwrap();
        // free_pages sums the populated runs.
        assert_eq!(pool.free_pages(), 8);
        // Fill every remaining slot; the next push then fails.
        for i in 0..(MAX_FREE_RUNS - 2)
        {
            pool.push(run(100 + i as u32, 1, 0)).unwrap();
        }
        assert!(pool.push(run(9999, 1, 0)).is_err());
    }

    #[test]
    fn take_exactly_consumes_whole_run_when_size_matches()
    {
        let mut pool = FreePool::new();
        pool.push(run(7, 4, 0x2000)).unwrap();
        // Exact match: the run leaves the pool and split is never called.
        let got = pool.take_exactly(0, 4, |_, _| panic!("split must not run on exact match"));
        assert_eq!(got, Some((7, 0x2000)));
        assert!(pool.runs[0].is_none());
    }

    #[test]
    fn take_exactly_returns_none_when_run_smaller_than_want()
    {
        let mut pool = FreePool::new();
        pool.push(run(7, 3, 0x2000)).unwrap();
        let got = pool.take_exactly(0, 4, |_, _| panic!("split must not run when too small"));
        assert!(got.is_none());
        // The run stays in the pool untouched.
        assert_eq!(pool.runs[0].unwrap().page_count, 3);
    }

    #[test]
    fn take_exactly_splits_larger_run_and_reinserts_residue()
    {
        let mut pool = FreePool::new();
        pool.push(run(5, 8, 0x1000)).unwrap();
        // Larger run: split off 3 pages; the 5-page residue tail (cap 99) is
        // reinserted at phys_base + 3*PAGE_SIZE.
        let got = pool.take_exactly(0, 3, |cap, off| {
            assert_eq!(cap, 5);
            assert_eq!(off, 3 * PAGE_SIZE);
            Some(99)
        });
        assert_eq!(got, Some((5, 0x1000)));
        let residue = pool.runs[0].unwrap();
        assert_eq!(residue.cap_slot, 99);
        assert_eq!(residue.page_count, 5);
        assert_eq!(residue.phys_base, 0x1000 + 3 * PAGE_SIZE);
    }

    #[test]
    fn coalesce_merges_contiguous_runs_into_lower_addressed_survivor()
    {
        let mut pool = FreePool::new();
        // Pushed out of physical order; coalesce must sort by phys_base.
        pool.push(run(30, 1, 0x3000)).unwrap();
        pool.push(run(10, 1, 0x1000)).unwrap();
        pool.push(run(20, 1, 0x2000)).unwrap();
        // Kernel accepts every merge: all three fold into the lowest-addressed
        // run (cap 10 @ 0x1000), summing pages.
        pool.coalesce_with(|_, _| true);

        let survivors: Vec<FreeRun> = pool.runs.iter().flatten().copied().collect();
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].cap_slot, 10);
        assert_eq!(survivors[0].phys_base, 0x1000);
        assert_eq!(survivors[0].page_count, 3);
        assert_eq!(pool.free_pages(), 3);
    }

    #[test]
    fn coalesce_stops_and_promotes_survivor_on_non_adjacent_run()
    {
        let mut pool = FreePool::new();
        pool.push(run(10, 1, 0x1000)).unwrap();
        pool.push(run(20, 1, 0x2000)).unwrap();
        pool.push(run(30, 1, 0x5000)).unwrap(); // physically detached
        // Kernel rejects any merge whose tail is cap 30 (the detached run);
        // 10+20 fold, then the rejection ends that survivor and promotes 30.
        pool.coalesce_with(|_, tail| tail != 30);

        let mut survivors: Vec<FreeRun> = pool.runs.iter().flatten().copied().collect();
        survivors.sort_by_key(|r| r.phys_base);
        assert_eq!(survivors.len(), 2);
        assert_eq!((survivors[0].cap_slot, survivors[0].page_count), (10, 2));
        assert_eq!((survivors[1].cap_slot, survivors[1].page_count), (30, 1));
        assert_eq!(pool.free_pages(), 3);
    }

    #[test]
    fn push_or_coalesce_retries_after_freeing_a_slot()
    {
        let mut pool = FreePool::new();
        // Fill every slot with physically-contiguous runs (mergeable).
        for i in 0..MAX_FREE_RUNS
        {
            pool.push(run(i as u32, 1, (i as u64) * PAGE_SIZE)).unwrap();
        }
        // A bare push has no room.
        assert!(pool.push(run(9999, 1, 0)).is_err());
        // push_or_coalesce folds the contiguous runs (freeing slots) and retries.
        assert!(
            pool.push_or_coalesce_with(run(9999, 1, 0x9_0000_0000), |_, _| true)
                .is_ok()
        );
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
            len: 0x100000,
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
