// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/frame_pool.rs

//! Memory capability pool for test memory management.
//!
//! Manages a fixed pool of single-page memory caps that are allocated to tests
//! and reclaimed after use. Prevents resource exhaustion by reusing caps.
//!
//! ## Design
//!
//! ktest receives a set of buddy-backed RAM Memory caps from the kernel
//! alongside its three segment caps (TEXT, RODATA, BSS/DATA). Before any
//! tests run, `init()` carves a tail of up to `POOL_SIZE` pages off the
//! first RAM cap (leaving at least one page in its head), splits that tail
//! into single-page frames, and stores the capability slots in `POOL_SLOTS`.
//! Each slot is marked available in `POOL_AVAILABLE` (one bit per slot).
//! Segment caps are intentionally left intact: the pool never draws from
//! the binary's own image, so non-zero initialised statics in ktest cannot
//! be corrupted by test mappings.
//!
//! Tests call `alloc()` to reserve a memory cap from the pool. When done, they
//! call `free()` to return it. The cap is never deleted, only marked available
//! for reuse. With proper cleanup, the pool's caps (at most `POOL_SIZE`) can
//! service any number of tests.
//!
//! ## Usage
//!
//! ```ignore
//! // In main(), before running tests:
//! unsafe { frame_pool::init(info) };
//!
//! // In a test:
//! let frame = frame_pool::alloc().ok_or("frame pool exhausted")?;
//! // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs).
//! unsafe { mem_map(frame, aspace_cap, va, 0, 1, syscall::MAP_WRITABLE)? };
//! // ... test logic ...
//! // SAFETY: no Rust reference into the page is live any more.
//! unsafe { mem_unmap(aspace_cap, va, 1)? };
//! unsafe { frame_pool::free(frame) };
//! ```
//!
//! For automatic cleanup, use `FrameGuard`:
//!
//! ```ignore
//! let mut frame = FrameGuard::new(ctx.aspace_cap)
//!     .ok_or("frame pool exhausted")?;
//! frame.map(TEST_VA)?;
//! // ... test logic ...
//! // Drop automatically unmaps and returns to pool
//! ```

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use init_protocol::{CapType, InitInfo};

/// Maximum frames in the pool.
///
/// Sixty-four is the width of the `u64` availability bitmap
/// (`POOL_AVAILABLE`), one bit per frame.
pub(crate) const POOL_SIZE: usize = 64;

/// Size of one page.
const PAGE_SIZE: u64 = 0x1000;

/// Bytes the pool carves off the first RAM cap when it is large enough.
const POOL_BYTES: u64 = POOL_SIZE as u64 * PAGE_SIZE;

/// Return the byte size of the Memory cap occupying `slot`, or `None` if no
/// Memory descriptor matches.
fn find_frame_size(info: &InitInfo, slot: u64) -> Option<u64>
{
    for d in crate::init_info::descriptors(info)
    {
        if d.slot == slot && d.cap_type == CapType::Memory
        {
            return Some(d.aux1);
        }
    }
    None
}

/// Pool of available memory capability slots.
///
/// Bit N set = slot N is available. Cleared = slot N is allocated to a test.
static POOL_AVAILABLE: AtomicU64 = AtomicU64::new(0);

/// Memory capability slots (indices into init's `CSpace`).
///
/// Initialized once at startup by splitting the tail carved off the first RAM
/// Memory cap into single-page caps. Atomics so that every access is a safe,
/// bounds-checked one; `init` writes the entries before any test runs, and
/// each is read by value.
static POOL_SLOTS: [AtomicU64; POOL_SIZE] = [const { AtomicU64::new(0) }; POOL_SIZE];

/// Number of frames in the pool (set during init).
static POOL_COUNT: AtomicU32 = AtomicU32::new(0);

/// `POOL_SLOTS` as `init` left it, or as the last [`check_slots`] that found
/// a change re-baselined it: the reference a stray write into `POOL_SLOTS`
/// is detected against.
static POOL_SHADOW: [AtomicU64; POOL_SIZE] = [const { AtomicU64::new(0) }; POOL_SIZE];

/// The pool's entries in use: the first `POOL_COUNT` of `POOL_SLOTS`.
fn live_slots() -> impl Iterator<Item = &'static AtomicU64>
{
    POOL_SLOTS
        .iter()
        .take(POOL_COUNT.load(Ordering::Acquire) as usize)
}

/// Log every pool entry that differs from its shadow, with its index, value
/// and expected value, then re-baseline the shadow. The pool's entries never
/// change after `init`, so a difference is a stray write into ktest's memory;
/// the harness calls this after each cell, so the cell logged just before it
/// is the first suspect.
pub fn check_slots()
{
    for (i, (slot, shadow)) in live_slots().zip(POOL_SHADOW.iter()).enumerate()
    {
        let now = slot.load(Ordering::Relaxed);
        let then = shadow.load(Ordering::Relaxed);
        if now != then
        {
            crate::log_u64("ktest: BUG frame pool entry changed, index=", i as u64);
            crate::log_u64("ktest: BUG frame pool entry value=", now);
            crate::log_u64("ktest: BUG frame pool entry expected=", then);
            shadow.store(now, Ordering::Relaxed);
        }
    }
}

/// Whether `cap` is one of the pool's entries.
pub fn is_pool_frame(cap: u64) -> bool
{
    live_slots().any(|slot| slot.load(Ordering::Relaxed) == cap)
}

/// Recursively split a frame into single-page frames and add them to the pool.
///
/// Splits `memory_cap` at `PAGE_SIZE`, stores the single-page first half (A)
/// in the pool, then recursively splits the remaining larger half (B) until
/// all pages have been extracted or the pool is full.
///
/// # Safety
///
/// Must be called only during `init()`, before any concurrent access.
unsafe fn split_frame_recursive(memory_cap: u64, count: &mut usize)
{
    let Some(entry) = POOL_SLOTS.get(*count)
    else
    {
        return;
    };

    // memory_split: `memory_cap` shrinks in place to one page; the
    // returned slot is the new tail covering the remainder. The
    // (now-single-page) original goes in the pool either way: a frame too
    // small to split (single page), or one whose split failed, as it is.
    let split = syscall::memory_split(memory_cap, PAGE_SIZE);
    entry.store(memory_cap, Ordering::Relaxed);
    *count = count.saturating_add(1);

    if let Ok(tail) = split
    {
        // Recursively split the tail to extract more pages.
        // SAFETY: same preconditions as the outer unsafe fn (init phase only).
        unsafe { split_frame_recursive(tail, count) };
    }
}

/// Initialize the frame pool by carving a tail off the first RAM cap.
///
/// Called once from `main()` before any tests run. Reads the size of the
/// first RAM Memory cap from the `CapDescriptor` array, splits a tail of up
/// to `POOL_SIZE * PAGE_SIZE` off the end, leaving at least one page in the
/// head (no pool when the cap is two pages or smaller), then recursively
/// splits that tail into single-page frames. The head of the RAM cap stays in
/// `info.memory_base` with full retype rights so tests can continue
/// to create kernel objects from it.
///
/// # Safety
///
/// Must be called exactly once before any tests run, while no other threads exist.
pub unsafe fn init(info: &init_protocol::InitInfo)
{
    if info.memory_count == 0
    {
        crate::log("frame pool: no RAM caps available; pool is empty");
        POOL_AVAILABLE.store(0, Ordering::Release);
        POOL_COUNT.store(0, Ordering::Release);
        return;
    }
    let ram_frame = info.memory_base;

    // Locate the descriptor for the first RAM cap to learn its size.
    let Some(ram_size) = find_frame_size(info, ram_frame)
    else
    {
        crate::log("frame pool: RAM cap descriptor not found; pool is empty");
        POOL_AVAILABLE.store(0, Ordering::Release);
        POOL_COUNT.store(0, Ordering::Release);
        return;
    };

    // Leave at least one page in the head so retype callers keep a usable
    // cap. If the cap is small, take whatever fits.
    let pool_chunk = if ram_size > POOL_BYTES + PAGE_SIZE
    {
        POOL_BYTES
    }
    else if ram_size > 2 * PAGE_SIZE
    {
        ram_size.saturating_sub(PAGE_SIZE)
    }
    else
    {
        crate::log("frame pool: RAM cap too small to carve pool; pool is empty");
        POOL_AVAILABLE.store(0, Ordering::Release);
        POOL_COUNT.store(0, Ordering::Release);
        return;
    };
    // `pool_chunk` is below `ram_size` on both branches above.
    let split_at = ram_size.saturating_sub(pool_chunk);

    // ram_frame validated above; single-threaded boot.
    let Ok(pool_tail) = syscall::memory_split(ram_frame, split_at)
    else
    {
        crate::log("frame pool: memory_split on RAM cap failed; pool is empty");
        POOL_AVAILABLE.store(0, Ordering::Release);
        POOL_COUNT.store(0, Ordering::Release);
        return;
    };

    let mut count = 0usize;

    // Recursively split the carved-out tail into individual pages.
    // The original RAM cap's head remains at `info.memory_base` for
    // retype-based tests; only the pool's tail is consumed here.
    // SAFETY: called from init() which is documented as single-threaded boot-time only.
    unsafe { split_frame_recursive(pool_tail, &mut count) };

    // count is bounded by POOL_SIZE (64), so cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    let count_u32 = count as u32;
    // Mark all slots as available: the low `count` bits, none for a count of
    // zero (a shift by the full width).
    let mask = u64::MAX
        .checked_shr(u64::BITS.saturating_sub(count_u32))
        .unwrap_or(0);
    POOL_AVAILABLE.store(mask, Ordering::Release);
    POOL_COUNT.store(count_u32, Ordering::Release);
    for (slot, shadow) in POOL_SLOTS.iter().zip(POOL_SHADOW.iter())
    {
        shadow.store(slot.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    crate::log_args(format_args!("frame pool: initialized with {count} frames"));
}

/// Allocate a frame from the pool.
///
/// Returns the memory capability slot, or `None` if the pool is exhausted.
/// Caller must call `free()` when done to return the frame to the pool.
#[must_use]
pub fn alloc() -> Option<u64>
{
    loop
    {
        let available = POOL_AVAILABLE.load(Ordering::Acquire);
        if available == 0
        {
            return None; // Pool exhausted
        }

        // Find first set bit (lowest available slot)
        let slot_idx = available.trailing_zeros();
        let mask = 1u64.checked_shl(slot_idx).unwrap_or(0);

        // Try to claim it atomically
        let prev = POOL_AVAILABLE.fetch_and(!mask, Ordering::AcqRel);
        if prev & mask != 0
        {
            // Successfully claimed: a set bit is below POOL_SIZE.
            return POOL_SLOTS
                .get(slot_idx as usize)
                .map(|slot| slot.load(Ordering::Relaxed));
        }
        // Race lost, retry
    }
}

/// Return a frame to the pool.
///
/// The frame is NOT automatically unmapped — caller must unmap it first.
/// This function just marks the cap slot as available for reuse.
///
/// # Safety
///
/// - `memory_cap` must be a cap previously returned by `alloc()`
/// - Caller must have unmapped all pages using this frame
pub unsafe fn free(memory_cap: u64)
{
    // Find the slot index
    if let Some(i) = live_slots().position(|slot| slot.load(Ordering::Relaxed) == memory_cap)
    {
        let mask = u32::try_from(i)
            .ok()
            .and_then(|i| 1u64.checked_shl(i))
            .unwrap_or(0);
        POOL_AVAILABLE.fetch_or(mask, Ordering::Release);
        return;
    }

    // Frame not in pool - this is a bug
    crate::log("BUG: frame_pool::free() called with unknown memory cap");
}

// ── RAII wrapper ──────────────────────────────────────────────────────────────

/// RAII wrapper for allocated frames.
///
/// Automatically unmaps and frees the frame when dropped; a frame whose unmap
/// fails is logged and not returned to the pool.
pub struct FrameGuard
{
    memory_cap: u64,
    aspace_cap: u64,
    mapped_va: Option<u64>,
}

impl FrameGuard
{
    /// Allocate a frame from the pool.
    #[must_use]
    pub fn new(aspace_cap: u64) -> Option<Self>
    {
        alloc().map(|memory_cap| FrameGuard {
            memory_cap,
            aspace_cap,
            mapped_va: None,
        })
    }

    /// Get the memory capability slot.
    #[must_use]
    pub fn cap(&self) -> u64
    {
        self.memory_cap
    }

    /// Map the frame at the given virtual address. The guard's drop unmaps it.
    ///
    /// # Safety
    ///
    /// When the guard's address space is ktest's own, `va` must be a scratch
    /// VA (crate docs § Scratch VAs): the page there must hold no live Rust
    /// object or registered IPC page from this call until the guard drops,
    /// and every Rust reference a test forms into the page must end before
    /// the drop (the contracts of `syscall::mem_map` and `syscall::mem_unmap`).
    ///
    /// # Errors
    ///
    /// Returns `InvalidState` when the guard is already mapped (a second
    /// mapping would escape the drop's unmap), else the syscall error code if
    /// `mem_map` fails.
    pub unsafe fn map(&mut self, va: u64) -> Result<(), i64>
    {
        if self.mapped_va.is_some()
        {
            return Err(syscall_abi::SyscallError::InvalidState as i64);
        }
        // SAFETY: the caller's contract keeps `va` off live Rust objects and
        // IPC pages.
        unsafe {
            syscall::mem_map(
                self.memory_cap,
                self.aspace_cap,
                va,
                0,
                1,
                syscall::MAP_WRITABLE,
            )
        }?;
        self.mapped_va = Some(va);
        Ok(())
    }
}

impl Drop for FrameGuard
{
    fn drop(&mut self)
    {
        // Unmap if mapped. A frame whose unmap fails stays out of the pool
        // rather than alias the next test's mapping.
        // SAFETY: `map`'s contract keeps the page the guard's own until now,
        // with every Rust reference into it ended.
        let unmap_failed = self
            .mapped_va
            .is_some_and(|va| unsafe { syscall::mem_unmap(self.aspace_cap, va, 1) }.is_err());
        if unmap_failed
        {
            crate::log("ktest: frame_pool: FrameGuard unmap failed; frame not returned");
            return;
        }

        // Return to pool
        // SAFETY: memory_cap was allocated from the pool by new(), and it is
        // mapped nowhere: never mapped, or its mapping was just removed.
        unsafe { free(self.memory_cap) };
    }
}
