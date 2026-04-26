// seraph-overlay: std::sys::reserve (seraph-only)
//
// Page-granular reservation allocator. Owns one fixed-size arena per
// process, carved out at process start. Hands out unmapped contiguous VA
// ranges; the caller is responsible for `mem_map` / `mem_unmap` against
// owned Frame caps. The arena holds no Frame caps and issues no syscalls
// — it is pure VA bookkeeping.
//
// Used for foreign Frame mappings: MMIO from devmgr, DMA buffers from
// drivers, shmem backings, zero-copy file pages from fs drivers, ELF-load
// scratch in procmgr. The byte heap (`#[global_allocator]`) is a
// disjoint surface owned by `sys::alloc::seraph`.
//
// Concurrency: a single spin-lock guards the arena. The free-list is a
// bounded sorted array; coalescing runs on every release.

use crate::cell::UnsafeCell;
use crate::sync::atomic::{AtomicBool, Ordering};

use syscall_abi::PAGE_SIZE;

/// Base of the per-process page-reservation arena. Deterministic for the
/// first cut; structured so a one-line change switches to an RNG draw
/// once the kernel RNG lands. Sits above the heap zone (`HEAP_MAX =
/// 0x8000_0000`) and below the bootstrap-cross-boundary VAs at the top
/// of the lower-canonical half.
const RESERVE_ARENA_BASE: u64 = 0x0000_0001_0000_0000;

/// Arena length in 4 KiB pages. 256 MiB total — sized to cover the
/// worst-case sum of MMIO + DMA + zero-copy-VFS + ELF-load reservations
/// at the workload sizes the boot tests exercise.
const RESERVE_ARENA_PAGES: u64 = 256 * 1024 * 1024 / PAGE_SIZE;

/// Maximum distinct free runs the arena can track. A conservative bound
/// on plausible userspace fragmentation: drivers, fs zero-copy windows,
/// and procmgr's ELF scratch each occupy O(1) reservations and free in
/// LIFO order, so the steady-state run count stays well below this.
/// Exhausting this cap leaks the freed range — coalescing on insert
/// keeps the worst case at the count of disjoint live reservations.
const MAX_FREE_RUNS: usize = 64;

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

struct Arena {
    runs: [Option<Run>; MAX_FREE_RUNS],
    initialized: bool,
}

impl Arena {
    const fn new() -> Self {
        Self {
            runs: [None; MAX_FREE_RUNS],
            initialized: false,
        }
    }

    fn ensure_init(&mut self) {
        if self.initialized {
            return;
        }
        self.runs[0] = Some(Run {
            va_start: RESERVE_ARENA_BASE,
            page_count: RESERVE_ARENA_PAGES,
        });
        self.initialized = true;
    }

    fn alloc(&mut self, n: u64) -> Option<ReservedRange> {
        self.ensure_init();
        for slot in &mut self.runs {
            let Some(run) = slot else { continue };
            if run.page_count < n {
                continue;
            }
            let result = ReservedRange {
                va_start: run.va_start,
                page_count: n,
            };
            if run.page_count == n {
                *slot = None;
            } else {
                run.va_start += n * PAGE_SIZE;
                run.page_count -= n;
            }
            return Some(result);
        }
        None
    }

    fn free(&mut self, mut va: u64, mut pages: u64) {
        self.ensure_init();
        // Coalesce with any abutting runs. A single freed range can absorb
        // at most one left and one right neighbour, but a single pass over
        // the table is sufficient because coalesced slots are cleared and
        // the surviving range carries the merged extents.
        let mut absorbed_left = false;
        let mut absorbed_right = false;
        for slot in &mut self.runs {
            let Some(run) = slot else { continue };
            if !absorbed_left && run.va_start + run.page_count * PAGE_SIZE == va {
                va = run.va_start;
                pages += run.page_count;
                *slot = None;
                absorbed_left = true;
            } else if !absorbed_right && va + pages * PAGE_SIZE == run.va_start {
                pages += run.page_count;
                *slot = None;
                absorbed_right = true;
            }
            if absorbed_left && absorbed_right {
                break;
            }
        }

        for slot in &mut self.runs {
            if slot.is_none() {
                *slot = Some(Run {
                    va_start: va,
                    page_count: pages,
                });
                return;
            }
        }
        // Run-table full: leak the range. Coalescing above keeps this
        // unreachable unless the live reservations have produced more
        // than `MAX_FREE_RUNS` disjoint holes simultaneously.
    }
}

// ── Spinlock ───────────────────────────────────────────────────────────────

struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    fn lock(&self) {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

struct GlobalArena {
    inner: UnsafeCell<Arena>,
    lock: SpinLock,
}

// SAFETY: all access to `inner` is serialised by `lock`.
unsafe impl Sync for GlobalArena {}

static ARENA: GlobalArena = GlobalArena {
    inner: UnsafeCell::new(Arena::new()),
    lock: SpinLock::new(),
};

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
    ARENA.lock.lock();
    // SAFETY: lock held; single mutator.
    let result = unsafe { (*ARENA.inner.get()).alloc(n) };
    ARENA.lock.unlock();
    result.ok_or(ReserveError::OutOfSpace)
}

/// Release a reservation back to the arena. The caller must have
/// `mem_unmap`'d every Frame it mapped into the range before calling;
/// the arena does not inspect mappings.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn unreserve_pages(range: ReservedRange) {
    let va = range.va_start;
    let pages = range.page_count;
    ARENA.lock.lock();
    // SAFETY: lock held; single mutator.
    unsafe {
        (*ARENA.inner.get()).free(va, pages);
    }
    ARENA.lock.unlock();
}
