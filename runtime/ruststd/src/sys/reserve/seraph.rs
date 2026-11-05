// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/reserve/seraph.rs

//! Page-granular reservation allocator. Owns one arena per process, carved
//! out on first use at a per-process randomised base in the arena zone
//! `process_layout::growth_zones` sizes to the address space (see
//! `Arena::ensure_init`). Hands out unmapped contiguous VA ranges; the caller
//! is responsible for `mem_map` / `mem_unmap` against owned Memory caps. The
//! arena holds no Memory caps; under its lock it issues only the one
//! `getrandom` base draw, and it grows its run table from the byte heap with
//! the lock released, so it never holds its lock across an allocation or IPC
//! and takes no other lock while holding it.
//!
//! Used for foreign Memory mappings: MMIO from devmgr, DMA buffers from
//! drivers, shmem backings, zero-copy file pages from fs drivers, ELF-load
//! scratch in procmgr, and demand-paged thread stacks. The byte heap
//! (`#[global_allocator]`) is a disjoint surface owned by `sys::alloc::seraph`.
//!
//! Free runs: a table sorted by address, kept maximal by coalescing on every
//! release, so it never holds more runs than there are live reservations plus
//! one (each run lies below a reservation or at the arena's top). A
//! reservation first makes room for that bound, growing the table into the
//! byte heap when it is full (allocated outside the lock, then installed
//! under it), and fails with `OutOfSpace` when it cannot; a release therefore
//! always has a slot, and freed VA is never dropped.
//!
//! Concurrency: a single spin-lock guards the arena.

use crate::alloc::{Layout, alloc, dealloc};
use crate::ptr;
use crate::sys::alloc::seraph::SpinMutex;

use syscall_abi::PAGE_SIZE;

/// Runs the arena tracks in its static table before it first grows the table
/// into the byte heap. A process without a heap (no memmgr endpoint) keeps
/// this table: past `INLINE_RUNS - 1` live reservations its next reservation
/// fails with `OutOfSpace` rather than leaking VA on a later release.
const INLINE_RUNS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub enum ReserveError {
    /// `n == 0`.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    InvalidArgument,
    /// No contiguous run of the requested size remains.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    OutOfSpace,
}

/// A reserved contiguous VA range. Held by value; the caller releases it
/// by passing it back to [`unreserve_pages`]. Dropping a `ReservedRange`
/// without calling `unreserve_pages` leaks the address-space slice — no
/// `Drop` impl, since the caller must `mem_unmap` first and the
/// allocator cannot prove that has happened.
#[must_use = "ReservedRange leaks VA on drop; pass to unreserve_pages"]
#[derive(Debug)]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub struct ReservedRange {
    va_start: u64,
    page_count: u64,
}

impl ReservedRange {
    /// Inclusive lower VA of the reservation, page-aligned.
    #[must_use]
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn va_start(&self) -> u64 {
        self.va_start
    }

    /// Length of the reservation in 4 KiB pages.
    #[must_use]
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn page_count(&self) -> u64 {
        self.page_count
    }
}

#[derive(Clone, Copy)]
struct Run {
    va_start: u64,
    page_count: u64,
}

const EMPTY_RUN: Run = Run { va_start: 0, page_count: 0 };

struct Arena {
    /// The run table: `capacity` slots, the first `len` holding the free
    /// runs in ascending address order. Points at `inline` until the first
    /// grow, then at a byte-heap allocation of `capacity` runs.
    runs: *mut Run,
    len: usize,
    capacity: usize,
    /// Reservations handed out and not yet released.
    live: usize,
    inline: [Run; INLINE_RUNS],
    initialized: bool,
}

impl Arena {
    const fn new() -> Self {
        Self {
            runs: ptr::null_mut(),
            len: 0,
            capacity: INLINE_RUNS,
            live: 0,
            inline: [EMPTY_RUN; INLINE_RUNS],
            initialized: false,
        }
    }

    fn ensure_init(&mut self) {
        if self.initialized {
            return;
        }
        // ASLR (#39): draw the arena base on first use. The draw is one
        // bounded, non-allocating, non-reentrant getrandom syscall taken
        // under the arena spin-lock — it cannot IPC, allocate, or re-enter
        // the arena, so holding the lock across it is safe. A failed draw
        // degrades to the deterministic window base.
        let zone = crate::os::seraph::growth_zones().arena;
        let mut entropy = [0u8; 8];
        let drawn = match syscall::getrandom(&mut entropy) {
            Ok(n) if n == entropy.len() as u64 => Some(u64::from_le_bytes(entropy)),
            _ => None,
        };
        // The arena lives in a static, so the table pointer is taken only
        // once the arena sits at its final address.
        self.runs = self.inline.as_mut_ptr();
        self.inline[0] = Run { va_start: zone.base(drawn), page_count: zone.span / PAGE_SIZE };
        self.len = 1;
        self.initialized = true;
    }

    fn runs(&mut self) -> &mut [Run] {
        // SAFETY: `runs` points at `capacity >= len` slots whose first `len`
        // are initialised (the inline table or a heap table `install_table`
        // filled), owned by this arena and reached only under its lock.
        unsafe { crate::slice::from_raw_parts_mut(self.runs, self.len) }
    }

    /// Remove run `i` (`i < len`), shifting the runs above it down.
    fn remove_run(&mut self, i: usize) {
        self.runs().copy_within(i + 1.., i);
        self.len -= 1;
    }

    /// Insert `run` at index `i` (`i <= len < capacity`), shifting the runs
    /// at and above it up.
    fn insert_run(&mut self, i: usize, run: Run) {
        assert!(self.len < self.capacity);
        // SAFETY: `len < capacity`, so slot `len` exists; slots `i..len`
        // move up by one within the table, and slot `i` is then written.
        unsafe {
            ptr::copy(self.runs.add(i), self.runs.add(i + 1), self.len - i);
            self.runs.add(i).write(run);
        }
        self.len += 1;
    }

    /// The capacity the table must grow to before one more reservation, so
    /// that a release after it always has a slot (`live + 2` runs), or
    /// `None` when the table already holds that many.
    fn capacity_needed(&self) -> Option<usize> {
        if self.live + 2 <= self.capacity {
            None
        } else {
            Some(self.capacity.saturating_mul(2))
        }
    }

    /// Install `fresh`, a byte-heap table of `capacity` runs, unless another
    /// thread already grew the table that far. Returns the table the caller
    /// frees after releasing the lock: the replaced heap table, or `fresh`
    /// itself when it was not needed. `None` when nothing is to be freed (the
    /// replaced table was the inline one).
    ///
    /// # Safety
    /// `fresh` came from `alloc` with `Layout::array::<Run>(capacity)` and
    /// nothing else refers to it.
    unsafe fn install_table(
        &mut self,
        fresh: *mut Run,
        capacity: usize,
    ) -> Option<(*mut Run, usize)> {
        if capacity <= self.capacity {
            return Some((fresh, capacity));
        }
        // SAFETY: `fresh` holds `capacity > len` runs and is disjoint from
        // the current table, whose first `len` slots are initialised.
        unsafe { ptr::copy_nonoverlapping(self.runs, fresh, self.len) };
        let old = (self.runs, self.capacity);
        self.runs = fresh;
        self.capacity = capacity;
        (old.1 != INLINE_RUNS).then_some(old)
    }

    /// Take `n` pages, lowest-address first fit. The caller has grown the
    /// table to [`Self::capacity_needed`].
    fn alloc(&mut self, n: u64) -> Option<ReservedRange> {
        debug_assert!(self.capacity_needed().is_none());
        // Lowest-address first fit.
        let i = self.runs().iter().position(|r| r.page_count >= n)?;
        let run = self.runs()[i];
        if run.page_count == n {
            self.remove_run(i);
        } else {
            self.runs()[i] = Run {
                va_start: run.va_start + n * PAGE_SIZE,
                page_count: run.page_count - n,
            };
        }
        self.live += 1;
        Some(ReservedRange { va_start: run.va_start, page_count: n })
    }

    fn free(&mut self, va: u64, pages: u64) {
        self.ensure_init();
        self.live = self.live.saturating_sub(1);
        let end = va + pages * PAGE_SIZE;
        let runs = self.runs();
        // First run above the released range; no run overlaps it.
        let i = runs.partition_point(|r| r.va_start < va);
        let joins_left = i > 0 && runs[i - 1].va_start + runs[i - 1].page_count * PAGE_SIZE == va;
        let joins_right = i < runs.len() && runs[i].va_start == end;
        match (joins_left, joins_right) {
            (true, true) => {
                runs[i - 1].page_count += pages + runs[i].page_count;
                self.remove_run(i);
            }
            (true, false) => runs[i - 1].page_count += pages,
            (false, true) => {
                runs[i].va_start = va;
                runs[i].page_count += pages;
            }
            // `reserve_pages` kept `capacity >= live + 2` when this range was
            // reserved, and maximal runs number at most `live + 1` after
            // this release, so the insert has a slot.
            (false, false) => self.insert_run(i, Run { va_start: va, page_count: pages }),
        }
    }
}

// ── Global arena ───────────────────────────────────────────────────────────

// SAFETY: `runs` points at the arena's own `inline` table or at a byte-heap
// table the arena owns, which no thread owns apart from it, and the arena is
// reached only through `ARENA`'s lock, so any thread holding that lock may
// follow it.
unsafe impl Send for Arena {}

/// The process's arena, under the byte heap's spin mutex type. Nothing
/// under it blocks or allocates: the table grows with the lock released.
static ARENA: SpinMutex<Arena> = SpinMutex::new(Arena::new());

/// Reserve `n` contiguous pages of unmapped VA from the per-process
/// arena. The returned range is exclusively owned until passed back to
/// [`unreserve_pages`].
///
/// Returns [`ReserveError::InvalidArgument`] when `n == 0` and
/// [`ReserveError::OutOfSpace`] when no contiguous run of `n` pages
/// remains (either the arena is full or fragmented).
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn reserve_pages(n: u64) -> Result<ReservedRange, ReserveError> {
    if n == 0 {
        return Err(ReserveError::InvalidArgument);
    }
    loop {
        let mut arena = ARENA.lock();
        arena.ensure_init();
        let Some(capacity) = arena.capacity_needed() else {
            return arena.alloc(n).ok_or(ReserveError::OutOfSpace);
        };
        drop(arena);
        // Grow the table with the lock released: the byte heap takes its own
        // lock and may IPC to memmgr, neither of which may nest inside this
        // spinlock.
        let Ok(layout) = Layout::array::<Run>(capacity) else {
            return Err(ReserveError::OutOfSpace);
        };
        // SAFETY: `layout` has a non-zero size (`capacity > INLINE_RUNS`).
        let fresh = unsafe { alloc(layout) }.cast::<Run>();
        if fresh.is_null() {
            return Err(ReserveError::OutOfSpace);
        }
        let mut arena = ARENA.lock();
        // SAFETY: `fresh` is the allocation of `layout` above.
        let spare = unsafe { arena.install_table(fresh, capacity) };
        drop(arena);
        if let Some((table, table_capacity)) = spare {
            if let Ok(old) = Layout::array::<Run>(table_capacity) {
                // SAFETY: `table` is a heap table of `table_capacity` runs
                // that the arena no longer refers to.
                unsafe { dealloc(table.cast::<u8>(), old) };
            }
        }
    }
}

/// Release a reservation back to the arena. The caller must have
/// `mem_unmap`'d every Memory cap it mapped into the range before calling;
/// the arena does not inspect mappings.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn unreserve_pages(range: ReservedRange) {
    let va = range.va_start;
    let pages = range.page_count;
    ARENA.lock().free(va, pages);
}
