// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/frame_pool.rs

//! Frame capability pool for test memory management.
//!
//! Manages a fixed pool of single-page frame caps that are allocated to tests
//! and reclaimed after use. Prevents resource exhaustion by reusing caps.
//!
//! ## Design
//!
//! ktest starts with three large segment frame caps (TEXT, RODATA, BSS/DATA).
//! Before any tests run, `init()` splits the BSS segment into single-page
//! frames (up to `POOL_SIZE`) and stores the capability slots in `POOL_SLOTS`.
//! Each slot is marked available in `POOL_AVAILABLE` (one bit per slot).
//! TEXT and RODATA frames are intentionally left intact for direct use by tests.
//!
//! Tests call `alloc()` to reserve a frame cap from the pool. When done, they
//! call `free()` to return it. The cap is never deleted, only marked available
//! for reuse. With proper cleanup, 64 frame caps can service unlimited tests.
//!
//! ## Usage
//!
//! ```ignore
//! // In main(), before running tests:
//! unsafe { frame_pool::init(aspace_cap) };
//!
//! // In a test:
//! let frame = frame_pool::alloc().ok_or("frame pool exhausted")?;
//! mem_map(frame, aspace_cap, va, 0, 1)?;
//! // ... test logic ...
//! mem_unmap(aspace_cap, va, 1)?;
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

/// Maximum frames in the pool.
const POOL_SIZE: usize = 64;

/// Size of one page.
const PAGE_SIZE: u64 = 0x1000;

/// Pool of available frame capability slots.
///
/// Bit N set = slot N is available. Cleared = slot N is allocated to a test.
static POOL_AVAILABLE: AtomicU64 = AtomicU64::new(0);

/// Frame capability slots (indices into init's `CSpace`).
///
/// Initialized once at startup by splitting segment frames.
static mut POOL_SLOTS: [u32; POOL_SIZE] = [0; POOL_SIZE];

/// Number of frames in the pool (set during init).
static POOL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Recursively split a frame into single-page frames and add them to the pool.
///
/// Splits `frame_cap` at `PAGE_SIZE`, stores the single-page first half (A)
/// in the pool, then recursively splits the remaining larger half (B) until
/// all pages have been extracted or the pool is full.
///
/// # Safety
///
/// Must be called only during `init()`, before any concurrent access.
unsafe fn split_frame_recursive(frame_cap: u32, count: &mut usize)
{
    if *count >= POOL_SIZE
    {
        return;
    }

    // Option-D frame_split: `frame_cap` shrinks in place to one page; the
    // returned slot is the new tail covering the remainder. Store the
    // (now-single-page) original in the pool, then recurse on the tail.
    match syscall::frame_split(frame_cap, PAGE_SIZE)
    {
        Ok(tail) =>
        {
            // SAFETY: count < POOL_SIZE, checked above.
            unsafe {
                POOL_SLOTS[*count] = frame_cap;
            }
            *count += 1;

            // Recursively split the tail to extract more pages.
            // SAFETY: same preconditions as the outer unsafe fn (init phase only).
            unsafe { split_frame_recursive(tail, count) };
        }
        Err(_) =>
        {
            // Frame is too small to split (single page) or split failed.
            // Store it as-is in the pool.
            if *count < POOL_SIZE
            {
                // SAFETY: count < POOL_SIZE, checked above.
                unsafe {
                    POOL_SLOTS[*count] = frame_cap;
                }
                *count += 1;
            }
        }
    }
}

/// Initialize the frame pool by splitting segment frames.
///
/// Called once from `main()` before any tests run. Recursively splits the
/// BSS frame (largest segment) into single-page frames until the pool is full.
///
/// # Safety
///
/// Must be called exactly once before any tests run, while no other threads exist.
pub unsafe fn init(info: &init_protocol::InitInfo)
{
    // BSS is the third segment (index 2) after TEXT and RODATA.
    let bss_frame = info.segment_frame_base + 2;

    let mut count = 0usize;

    // Recursively split the BSS frame into individual pages.
    // Each split produces two child frames; we store both and continue splitting
    // the larger child until we've filled the pool or run out of splittable frames.
    // SAFETY: called from init() which is documented as single-threaded boot-time only.
    unsafe { split_frame_recursive(bss_frame, &mut count) };

    // Mark all slots as available
    let mask = if count >= 64
    {
        u64::MAX
    }
    else
    {
        (1u64 << count) - 1
    };
    POOL_AVAILABLE.store(mask, Ordering::Release);
    // count is bounded by POOL_SIZE (64), so cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    let count_u32 = count as u32;
    POOL_COUNT.store(count_u32, Ordering::Release);

    let mut msg = [0u8; 64];
    let prefix = b"frame pool: initialized with ";
    let plen = prefix.len().min(msg.len());
    msg[..plen].copy_from_slice(&prefix[..plen]);

    // Write count as decimal
    let mut n = count;
    let mut digits = [0u8; 10];
    let mut dlen = 0usize;
    if n == 0
    {
        digits[0] = b'0';
        dlen = 1;
    }
    else
    {
        while n > 0
        {
            // n % 10 is always 0..=9, so cast to u8 is safe.
            #[allow(clippy::cast_possible_truncation)]
            let digit = (n % 10) as u8;
            digits[dlen] = b'0' + digit;
            n /= 10;
            dlen += 1;
        }
        digits[..dlen].reverse();
    }

    let nlen = dlen.min(msg.len() - plen);
    msg[plen..plen + nlen].copy_from_slice(&digits[..nlen]);
    let mut pos = plen + nlen;

    let suffix = b" frames";
    let slen = suffix.len().min(msg.len() - pos);
    msg[pos..pos + slen].copy_from_slice(&suffix[..slen]);
    pos += slen;

    if let Ok(s) = core::str::from_utf8(&msg[..pos])
    {
        crate::log(s);
    }
}

/// Allocate a frame from the pool.
///
/// Returns the frame capability slot, or `None` if the pool is exhausted.
/// Caller must call `free()` when done to return the frame to the pool.
#[must_use]
pub fn alloc() -> Option<u32>
{
    loop
    {
        let available = POOL_AVAILABLE.load(Ordering::Acquire);
        if available == 0
        {
            return None; // Pool exhausted
        }

        // Find first set bit (lowest available slot)
        let slot_idx = available.trailing_zeros() as usize;
        let mask = 1u64 << slot_idx;

        // Try to claim it atomically
        let prev = POOL_AVAILABLE.fetch_and(!mask, Ordering::AcqRel);
        if prev & mask != 0
        {
            // Successfully claimed
            // SAFETY: slot_idx is within bounds (< trailing_zeros result < 64).
            unsafe { return Some(POOL_SLOTS[slot_idx]) }
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
/// - `frame_cap` must be a cap previously returned by `alloc()`
/// - Caller must have unmapped all pages using this frame
pub unsafe fn free(frame_cap: u32)
{
    // Find the slot index
    let count = POOL_COUNT.load(Ordering::Acquire) as usize;
    // needless_range_loop: must index directly to avoid creating shared ref to mutable static.
    #[allow(clippy::needless_range_loop)]
    for i in 0..count
    {
        // SAFETY: i < count, and count <= POOL_SIZE.
        let slot = unsafe { POOL_SLOTS[i] };
        if slot == frame_cap
        {
            let mask = 1u64 << i;
            POOL_AVAILABLE.fetch_or(mask, Ordering::Release);
            return;
        }
    }

    // Frame not in pool - this is a bug
    crate::log("BUG: frame_pool::free() called with unknown frame cap");
}

// ── RAII wrapper ──────────────────────────────────────────────────────────────

/// RAII wrapper for allocated frames.
///
/// Automatically unmaps and frees the frame when dropped.
pub struct FrameGuard
{
    frame_cap: u32,
    aspace_cap: u32,
    mapped_va: Option<u64>,
}

impl FrameGuard
{
    /// Allocate a frame from the pool.
    #[must_use]
    pub fn new(aspace_cap: u32) -> Option<Self>
    {
        alloc().map(|frame_cap| FrameGuard {
            frame_cap,
            aspace_cap,
            mapped_va: None,
        })
    }

    /// Get the frame capability slot.
    #[must_use]
    pub fn cap(&self) -> u32
    {
        self.frame_cap
    }

    /// Map the frame at the given virtual address.
    ///
    /// # Errors
    ///
    /// Returns the syscall error code if `mem_map` fails.
    pub fn map(&mut self, va: u64) -> Result<(), i64>
    {
        syscall::mem_map(
            self.frame_cap,
            self.aspace_cap,
            va,
            0,
            1,
            syscall::MAP_WRITABLE,
        )?;
        self.mapped_va = Some(va);
        Ok(())
    }
}

impl Drop for FrameGuard
{
    fn drop(&mut self)
    {
        // Unmap if mapped
        if let Some(va) = self.mapped_va
        {
            let _ = syscall::mem_unmap(self.aspace_cap, va, 1);
        }

        // Return to pool
        // SAFETY: frame_cap was allocated from the pool by new().
        unsafe { free(self.frame_cap) };
    }
}
