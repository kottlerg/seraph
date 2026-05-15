// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/retype.rs

//! Retype primitive — turn Frame-cap-backed memory into kernel-object backings.
//!
//! The seven `SYS_CAP_CREATE_*` handlers consume a Frame cap with
//! `Rights::RETYPE` and call [`retype_allocate`] to carve out a sub-region
//! of the cap's backing memory; the kernel object is constructed in place
//! at the returned offset. On `dec_ref → 0`, the dealloc path looks at
//! `KernelObjectHeader.ancestor` and calls [`retype_free`] to return the
//! bytes to the source `FrameObject`.
//!
//! ## Authority
//!
//! The caller MUST validate `tag == Frame && rights.contains(RETYPE)` on the
//! source slot before invoking [`retype_allocate`]. This module trusts the
//! caller; the syscall handler enforces the gate.
//!
//! ## Allocator semantics
//!
//! Each retypable Frame cap carries an inline [`RetypeAllocator`] in its
//! [`FrameObject`] (kernel-owned memory). The allocator manages two pools:
//!
//! - **Sub-page bins** (`BIN_128`, `BIN_512`) — fixed-size free lists. Each
//!   freed slot's first 8 bytes hold the next-offset pointer for the bin's
//!   linked list. New allocations pop from the list, or bump-allocate.
//! - **Page-aligned blocks** — first-fit free list with split-on-allocate.
//!   Each freed block's first 16 bytes hold `(size_pages: u64,
//!   next_offset: u64)`. Allocations walk the list looking for a block
//!   `>= requested pages`; on a larger fit, the block is split and the
//!   remainder kept on the list. No coalesce on free.
//!
//! Free-list nodes are still stored inline in the cap's region (the freed
//! offsets that the lists thread together), but the *head pointers and
//! bump cursor* live in kernel memory. Userspace `sys_mem_map` writes
//! against the cap's region therefore cannot corrupt allocator metadata;
//! they can at worst overwrite a freed offset's `(next, size)` cell —
//! detected by the bounded-walk corruption check in `try_alloc_page_block`.
//!
//! ## Concurrency
//!
//! Each [`RetypeAllocator`] carries its own spinlock. The lock guards every
//! state mutation — bump pointer, both free lists. `available_bytes`
//! mutations use atomic `fetch_*` and don't require the lock (callers
//! reading `available` without the lock get a snapshot, which is exactly
//! what they want for budget queries).

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::object::{FrameObject, KernelObjectHeader, ObjectType};
use crate::mm::PAGE_SIZE;
use syscall::SyscallError;

/// Sub-page size classes. Each retype request is rounded up to one of these
/// or to a page multiple. Tunable as the object catalogue evolves.
const BIN_128: u64 = 128;
const BIN_512: u64 = 512;

/// Number of sub-page free-list bins.
const NUM_SUBPAGE_BINS: usize = 2;

/// Sentinel value for an empty free list. Real offsets are bounded by
/// `frame.size` (well below `u64::MAX`).
const FREE_LIST_END: u64 = u64::MAX;

/// Per-Frame-cap retype allocator. Lives inline in [`FrameObject`] (kernel-
/// owned memory). Manages bump-allocation plus per-class free lists over
/// the cap's backing region.
#[repr(C)]
pub struct RetypeAllocator
{
    /// Spinlock guarding the bump pointer and free lists.
    /// `0` = unlocked, `1` = locked. Acquired with CAS.
    lock: AtomicU64,
    /// Next free byte (high water mark) within the Frame cap region.
    bump_offset: AtomicU64,
    /// Sub-page free-list heads, one per size class. `FREE_LIST_END` = empty.
    /// At each non-empty offset, the first 8 bytes of the freed slot hold
    /// the next-offset pointer for this bin's linked list.
    subpage_free_lists: [AtomicU64; NUM_SUBPAGE_BINS],
    /// Page-aligned free-list head. `FREE_LIST_END` = empty. Each freed block
    /// stores `(size_pages: u64, next_offset: u64)` at offset 0..16 within
    /// the freed region.
    page_free_head: AtomicU64,
}

impl RetypeAllocator
{
    /// Construct a fresh allocator: empty free lists, bump cursor at 0.
    pub const fn new_inline() -> Self
    {
        Self {
            lock: AtomicU64::new(0),
            bump_offset: AtomicU64::new(0),
            subpage_free_lists: [AtomicU64::new(FREE_LIST_END), AtomicU64::new(FREE_LIST_END)],
            page_free_head: AtomicU64::new(FREE_LIST_END),
        }
    }

    fn lock(&self)
    {
        while self
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self)
    {
        self.lock.store(0, Ordering::Release);
    }
}

/// Round `bytes` up to the smallest size class that fits.
///
/// Sub-page sizes round to `BIN_128` or `BIN_512`. Larger sizes round up to
/// `PAGE_SIZE`. The returned value is the actual bytes consumed from the
/// cap's `available_bytes`.
pub fn round_to_class(bytes: u64) -> u64
{
    if bytes == 0
    {
        return 0;
    }
    if bytes <= BIN_128
    {
        BIN_128
    }
    else if bytes <= BIN_512
    {
        BIN_512
    }
    else
    {
        // Page-aligned. PAGE_SIZE is a constant power of two; align upward.
        let p = PAGE_SIZE as u64;
        (bytes + p - 1) & !(p - 1)
    }
}

/// Map a sub-page rounded size to its bin index.
fn subpage_bin_for(rounded: u64) -> Option<usize>
{
    if rounded == BIN_128
    {
        Some(0)
    }
    else if rounded == BIN_512
    {
        Some(1)
    }
    else
    {
        None
    }
}

/// Page-aligned allocations require the bump offset to be page-aligned too.
///
/// Returns the smallest offset `>= bump` that's `align`-aligned.
fn align_up(value: u64, align: u64) -> u64
{
    (value + align - 1) & !(align - 1)
}

/// Read a u64 from `phys + offset` via the kernel direct map.
///
/// # Safety
///
/// `phys + offset` must be inside a live Frame cap region; the bytes at that
/// location must be safe to read (not concurrently written by anyone other
/// than the holder of the allocator lock).
#[cfg(not(test))]
unsafe fn read_u64_at(phys: u64, offset: u64) -> u64
{
    let virt = crate::mm::paging::phys_to_virt(phys + offset);
    // SAFETY: caller guarantees the address is in the kernel direct map and
    // that the slot is not concurrently written.
    unsafe { core::ptr::read_volatile(virt as *const u64) }
}

/// Write a u64 to `phys + offset` via the kernel direct map.
///
/// # Safety
///
/// `phys + offset` must be inside a live Frame cap region; the bytes at that
/// location must be safe to write (the slot is freed and not aliased).
#[cfg(not(test))]
unsafe fn write_u64_at(phys: u64, offset: u64, value: u64)
{
    let virt = crate::mm::paging::phys_to_virt(phys + offset);
    // SAFETY: caller guarantees the address is in the kernel direct map and
    // not aliased.
    unsafe { core::ptr::write_volatile(virt as *mut u64, value) };
}

/// Try to pop a slot from the bin's free list. Returns the offset if a slot
/// was reused, or `None` if the list is empty.
///
/// Caller holds the allocator lock.
///
/// # Safety
///
/// `frame.base + head_offset` must be a valid kernel direct-map address.
#[cfg(not(test))]
unsafe fn try_pop_subpage(alloc: &RetypeAllocator, frame: &FrameObject, bin: usize) -> Option<u64>
{
    let head = alloc.subpage_free_lists[bin].load(Ordering::Acquire);
    if head == FREE_LIST_END
    {
        return None;
    }
    // Read next-offset stored at offset `head` within the cap region.
    // SAFETY: head was previously placed on the free list, meaning it's a
    // valid offset within the cap region.
    let next = unsafe { read_u64_at(frame.base, head) };
    alloc.subpage_free_lists[bin].store(next, Ordering::Release);
    Some(head)
}

/// Push `offset` onto the bin's free list.
///
/// Caller holds the allocator lock and has dropped any kernel-object state
/// that previously occupied the slot.
///
/// # Safety
///
/// `frame.base + offset` must be a valid kernel direct-map address; the
/// slot must not be concurrently aliased.
#[cfg(not(test))]
unsafe fn push_subpage(alloc: &RetypeAllocator, frame: &FrameObject, bin: usize, offset: u64)
{
    let prev_head = alloc.subpage_free_lists[bin].load(Ordering::Acquire);
    // Write next-offset at the start of the freed slot.
    // SAFETY: caller guarantees the slot is no longer in use.
    unsafe { write_u64_at(frame.base, offset, prev_head) };
    alloc.subpage_free_lists[bin].store(offset, Ordering::Release);
}

/// Predecessor pointer for the page-aligned free-list walk.
///
/// The list head lives in the `RetypeAllocator` (which itself sits at
/// offset 0 of the cap region); mid-list next-pointers live inline at
/// `frame.base + offset + 8`. The two storage shapes need different
/// update paths, captured here.
enum PagePrev
{
    /// Predecessor is the allocator's `page_free_head` field.
    Head,
    /// Predecessor is an inline next-pointer slot at the given cap offset.
    /// The next-pointer is at `frame.base + offset + 8`.
    InCap(u64),
}

/// Try to satisfy a page-aligned allocation from the page free list.
///
/// First-fit search; on a larger-than-needed block, splits and keeps the
/// remainder on the list. Returns the offset of the allocated block, or
/// `None` if no fit.
///
/// Caller holds the allocator lock.
///
/// # Safety
///
/// `frame.base` must be a valid kernel direct-map address.
#[cfg(not(test))]
unsafe fn try_alloc_page_block(
    alloc: &RetypeAllocator,
    frame: &FrameObject,
    pages: u64,
) -> Option<u64>
{
    let p = PAGE_SIZE as u64;
    let mut prev = PagePrev::Head;
    let mut cur = alloc.page_free_head.load(Ordering::Acquire);
    let mut iter: u64 = 0;

    while cur != FREE_LIST_END
    {
        iter += 1;
        if iter > 1024
        {
            crate::kprintln!(
                "RETYPE PAGE FREE-LIST CYCLE: frame.base=0x{:x} size=0x{:x} head=0x{:x} cur=0x{:x} iter={}",
                frame.base,
                frame.size,
                alloc.page_free_head.load(Ordering::Acquire),
                cur,
                iter
            );
            return None;
        }
        if cur >= frame.size
        {
            crate::kprintln!(
                "RETYPE PAGE FREE-LIST CORRUPT: frame.base=0x{:x} size=0x{:x} cur=0x{:x} (out of range)",
                frame.base,
                frame.size,
                cur
            );
            return None;
        }
        // SAFETY: cur is a valid offset placed by a previous push.
        let block_pages = unsafe { read_u64_at(frame.base, cur) };
        // SAFETY: same as above; next is at offset cur+8.
        let block_next = unsafe { read_u64_at(frame.base, cur + 8) };

        if block_pages >= pages
        {
            // Unlink the current node from the list. Where the predecessor
            // lives determines which write path we use.
            match prev
            {
                PagePrev::Head =>
                {
                    alloc.page_free_head.store(block_next, Ordering::Release);
                }
                PagePrev::InCap(prev_off) =>
                {
                    // SAFETY: prev_off was produced by a prior iteration's
                    // observation of a valid free-list node.
                    unsafe { write_u64_at(frame.base, prev_off + 8, block_next) };
                }
            }

            if block_pages == pages
            {
                return Some(cur);
            }

            // Split: front `pages` go to the caller; remainder forms a new
            // free block at offset `cur + pages * p` with size
            // `(block_pages - pages)` pushed onto the list head.
            let remainder_offset = cur + pages * p;
            let remainder_pages = block_pages - pages;
            let cur_head = alloc.page_free_head.load(Ordering::Acquire);
            // SAFETY: remainder_offset is page-aligned and within the cap.
            unsafe { write_u64_at(frame.base, remainder_offset, remainder_pages) };
            // SAFETY: same.
            unsafe { write_u64_at(frame.base, remainder_offset + 8, cur_head) };
            alloc
                .page_free_head
                .store(remainder_offset, Ordering::Release);
            return Some(cur);
        }

        // Advance: this node's next-pointer becomes the new predecessor.
        prev = PagePrev::InCap(cur);
        cur = block_next;
    }

    None
}

/// Push a page-aligned freed block onto the page free list.
///
/// Caller holds the allocator lock.
///
/// # Safety
///
/// `offset` must be page-aligned and within the cap; the bytes at
/// `frame.base + offset` must not be concurrently aliased.
#[cfg(not(test))]
unsafe fn push_page_block(alloc: &RetypeAllocator, frame: &FrameObject, offset: u64, pages: u64)
{
    let prev_head = alloc.page_free_head.load(Ordering::Acquire);
    // SAFETY: caller guarantees offset is page-aligned within the cap and
    // no longer aliased.
    unsafe { write_u64_at(frame.base, offset, pages) };
    // SAFETY: same.
    unsafe { write_u64_at(frame.base, offset + 8, prev_head) };
    alloc.page_free_head.store(offset, Ordering::Release);
}

/// Reserve `bytes` from `frame`'s region. Returns the offset within the cap
/// where the new kernel object should be placed.
///
/// `bytes` is the *raw* requested size; it is rounded up to the next size
/// class internally. The actual bytes debited from `available_bytes` is the
/// rounded value. Sub-page allocations are size-class-aligned but not
/// page-aligned; page-aligned allocations are always page-aligned within
/// the cap.
///
/// Returns `Err(SyscallError::OutOfMemory)` if the cap doesn't have enough
/// room. Caller must validate `tag == Frame && rights.contains(RETYPE)`
/// before invoking.
///
/// # Safety
///
/// `frame` must be a valid, live `FrameObject` reference. Returned offset
/// is valid only while `frame` is live; use `frame.base + offset` and
/// `phys_to_virt` to access the memory.
#[cfg(not(test))]
pub fn retype_allocate(frame: &FrameObject, bytes: u64) -> Result<u64, SyscallError>
{
    let need = round_to_class(bytes);
    if need == 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Read-lock the cap for the duration: a concurrent `sys_frame_split`
    // would otherwise mutate `frame.size` between the bump validation
    // (`new_bump > frame.size`) and the commit. Lock order: cap-rwlock
    // outer, allocator spinlock inner.
    let _frame_guard = crate::cap::object::FrameReadGuard::acquire(frame);

    if frame.available_bytes.load(Ordering::Acquire) < need
    {
        return Err(SyscallError::OutOfMemory);
    }

    let alloc = &frame.allocator;
    alloc.lock();

    // Try the appropriate free list first.
    if let Some(bin) = subpage_bin_for(need)
    {
        // SAFETY: alloc lock held; bin is a valid index.
        if let Some(off) = unsafe { try_pop_subpage(alloc, frame, bin) }
        {
            // Free-list reuse — debit available_bytes.
            frame.available_bytes.fetch_sub(need, Ordering::AcqRel);
            alloc.unlock();
            return Ok(off);
        }
    }
    else
    {
        // Page-aligned: walk the page free list.
        let pages = need / PAGE_SIZE as u64;
        // SAFETY: alloc lock held.
        if let Some(off) = unsafe { try_alloc_page_block(alloc, frame, pages) }
        {
            frame.available_bytes.fetch_sub(need, Ordering::AcqRel);
            alloc.unlock();
            return Ok(off);
        }
    }

    // Fall through to bump.
    let bump = alloc.bump_offset.load(Ordering::Relaxed);
    let aligned_bump = if need >= PAGE_SIZE as u64
    {
        align_up(bump, PAGE_SIZE as u64)
    }
    else
    {
        bump
    };
    let alignment_pad = aligned_bump - bump;
    let new_bump = aligned_bump + need;

    if new_bump > frame.size
    {
        alloc.unlock();
        return Err(SyscallError::OutOfMemory);
    }

    // Debit only the bytes the caller is consuming. The alignment pad is
    // retained as future-reusable sub-page slots, NOT charged to the cap
    // ledger. This matters when a sub-page bump is followed by a page-aligned
    // request: the gap (up to one page) is recovered into the free lists
    // rather than lost to the bump.
    let prev_avail = frame.available_bytes.fetch_sub(need, Ordering::AcqRel);
    if prev_avail < need
    {
        frame.available_bytes.fetch_add(need, Ordering::Release);
        alloc.unlock();
        return Err(SyscallError::OutOfMemory);
    }

    // Chop the alignment pad into the largest sub-page bins that fit. Each
    // pushed slot is reusable by future sub-page retypes.
    if alignment_pad > 0
    {
        let mut cursor = bump;
        let mut remaining = alignment_pad;
        while remaining >= BIN_512
        {
            // SAFETY: alloc lock held; cursor is within the cap region.
            unsafe { push_subpage(alloc, frame, 1, cursor) };
            cursor += BIN_512;
            remaining -= BIN_512;
        }
        while remaining >= BIN_128
        {
            // SAFETY: alloc lock held.
            unsafe { push_subpage(alloc, frame, 0, cursor) };
            cursor += BIN_128;
            remaining -= BIN_128;
        }
        // Any tail < BIN_128 is unreachable from the free lists. Bounded by
        // 127 bytes per first-page-aligned bump event per cap.
    }

    alloc.bump_offset.store(new_bump, Ordering::Release);
    alloc.unlock();

    Ok(aligned_bump)
}

/// Read the current bump offset against `frame`.
///
/// Used by `sys_frame_split` to enforce the Option D invariant that a
/// split offset cannot land below the highest live retype.
///
/// # Safety
///
/// Caller must hold either `frame.read_lock()` or `frame.write_lock()` so
/// the cap's `size` cannot change under the reader.
#[cfg(not(test))]
pub fn current_bump(frame: &FrameObject) -> u64
{
    frame.allocator.bump_offset.load(Ordering::Acquire)
}

/// Return `bytes` to `frame`'s region. Pushes the freed slot onto the
/// matching free list and credits `available_bytes`.
///
/// # Safety
///
/// `frame` must be a valid `FrameObject` reference; `offset` and `bytes`
/// must match a previous successful [`retype_allocate`] return. The slot
/// at `offset` must not contain a live kernel object — caller has dropped
/// any state, drained wait queues, etc., before calling.
#[cfg(not(test))]
pub fn retype_free(frame: &FrameObject, offset: u64, bytes: u64)
{
    let need = round_to_class(bytes);
    let alloc = &frame.allocator;

    alloc.lock();

    // Bump rollback when the freed block sits at the top of the allocator's
    // bump frontier: the freed range is contiguous with `bump_offset`, no
    // live retype lives above it, so we can shrink the bump back to `offset`.
    // This keeps `sys_frame_split` usable on caps that have been retyped and
    // then freed — without it, a Frame that was once the source for a
    // `cap_create_aspace` slab can never again be split into smaller pieces,
    // even after the AS is dealloc'd. (The allocator's free list still
    // services future retypes either way; this rollback only affects what
    // the *split* primitive sees.)
    let bump = alloc.bump_offset.load(Ordering::Relaxed);
    if offset + need == bump
    {
        alloc.bump_offset.store(offset, Ordering::Release);
    }
    else if let Some(bin) = subpage_bin_for(need)
    {
        // SAFETY: lock held; offset is from a prior successful allocation.
        unsafe { push_subpage(alloc, frame, bin, offset) };
    }
    else
    {
        let pages = need / PAGE_SIZE as u64;
        // SAFETY: lock held; offset is page-aligned (was returned by
        // retype_allocate's page-aligned path).
        unsafe { push_page_block(alloc, frame, offset, pages) };
    }

    frame.available_bytes.fetch_add(need, Ordering::Release);
    alloc.unlock();
}

/// Phase-7 boot-time mint: allocate `size_of::<T>()` bytes from `seed`,
/// write `body` in place, bump the seed's refcount once for the descendant's
/// retype lease, and return a `NonNull<KernelObjectHeader>` to the body.
///
/// `body` must already carry an ancestor pointer matching `seed.header` set
/// via [`KernelObjectHeader::with_ancestor`]; the helper does not synthesise
/// it because the caller chooses the per-type fields and is the natural
/// owner of the construction expression.
///
/// `T` must be `#[repr(C)]` with [`KernelObjectHeader`] as its first field at
/// offset 0 — the standard layout shared by every concrete object type — so
/// the returned pointer can be cast back to `*mut T` by the dealloc path via
/// `header.obj_type` dispatch.
///
/// Used by `cap::populate_cspace` and `mint_module_frame_caps` (Phase 7) and
/// by `core/kernel/src/main.rs` (Phase 9, init segment Frame caps).
///
/// Calls [`crate::fatal`] on `OutOfMemory` — Phase 7 boot-time mints cannot
/// recover from a too-small seed.
#[cfg(not(test))]
pub fn boot_retype_body<T>(seed: &FrameObject, body: T) -> NonNull<KernelObjectHeader>
{
    let bytes = core::mem::size_of::<T>() as u64;
    let Ok(offset) = retype_allocate(seed, bytes)
    else
    {
        crate::fatal("Phase 7: seed Frame too small for boot mint");
    };
    let virt = crate::mm::paging::phys_to_virt(seed.base + offset) as *mut T;
    // SAFETY: `virt` is in the kernel direct map, freshly carved out by
    // `retype_allocate`, and not aliased.
    unsafe { core::ptr::write(virt, body) };
    seed.header.inc_ref();
    // SAFETY: T is repr(C) with KernelObjectHeader at offset 0; the cast
    // preserves the pointer validity established by the write above.
    unsafe { NonNull::new_unchecked(virt.cast::<KernelObjectHeader>()) }
}

/// Runtime mint: allocate `size_of::<T>()` bytes from the kernel SEED Frame
/// cap, write `body` in place, bump SEED's refcount, and return a pointer
/// suitable for `CSpace::insert_cap`.
///
/// SEED is the only kernel-internal Frame cap; it backs the wrapper bodies
/// of split-derived caps (`sys_mmio_split`, `sys_irq_split`, the tail of
/// `sys_frame_split`) and lazy per-thread state (`sys_iopb_set`'s IOPB).
/// All callers debit `SEED.available_bytes`; runtime exhaustion returns
/// `OutOfMemory` to the syscall surface (unlike [`boot_retype_body`] which
/// fatals).
///
/// `body.header.ancestor` MUST be stamped by the caller via
/// [`KernelObjectHeader::with_ancestor`] using
/// [`crate::cap::seed_header_nn`] so the dealloc cascade returns the body
/// to SEED.
///
/// `T` must be `#[repr(C)]` with [`KernelObjectHeader`] at offset 0.
#[cfg(not(test))]
pub fn alloc_in_seed<T>(body: T) -> Result<NonNull<KernelObjectHeader>, SyscallError>
{
    let seed = crate::cap::seed_frame_ref();
    let bytes = core::mem::size_of::<T>() as u64;
    let offset = retype_allocate(seed, bytes)?;
    let virt = crate::mm::paging::phys_to_virt(seed.base + offset) as *mut T;
    // SAFETY: `virt` is in the kernel direct map, freshly carved by
    // `retype_allocate`, and not aliased.
    unsafe { core::ptr::write(virt, body) };
    seed.header.inc_ref();
    // SAFETY: T is repr(C) with KernelObjectHeader at offset 0.
    Ok(unsafe { NonNull::new_unchecked(virt.cast::<KernelObjectHeader>()) })
}

/// Reserve `bytes` of opaque scratch from SEED for non-cap kernel state
/// (currently x86_64-only: per-thread IOPB pages). Returns a kernel-
/// direct-map pointer to the freshly-carved region; bumps SEED's
/// refcount once so the bytes outlive any holder.
///
/// Caller frees via [`free_seed_scratch`] giving back the matching
/// `(ptr, bytes)` pair.
///
/// Unlike [`alloc_in_seed`], no `KernelObjectHeader` is written and the
/// region does not enter any `CSpace`; the returned pointer is opaque.
///
/// Consumers: the IOPB allocation in `sys_iopb_set` (x86-64 only) and the
/// per-thread XSAVE / FP save area allocated by `arch::current::fpu::alloc_area`
/// (both arches).
#[cfg(not(test))]
pub fn alloc_seed_scratch(bytes: u64) -> Result<*mut u8, SyscallError>
{
    let seed = crate::cap::seed_frame_ref();
    let offset = retype_allocate(seed, bytes)?;
    seed.header.inc_ref();
    Ok(crate::mm::paging::phys_to_virt(seed.base + offset) as *mut u8)
}

/// Return a [`alloc_seed_scratch`] reservation to SEED. `ptr` and `bytes`
/// must match the values returned/passed at allocation time. Decrements
/// SEED's refcount once.
///
/// SEED is statically pinned (initial refcount 1 + Phase-7 `inc_ref` pin),
/// so its refcount can never drop to zero in normal operation; the
/// `dec_ref` here is bookkeeping for the scratch lease.
#[cfg(not(test))]
pub fn free_seed_scratch(ptr: *mut u8, bytes: u64)
{
    let seed = crate::cap::seed_frame_ref();
    let phys = crate::mm::paging::virt_to_phys(ptr as u64);
    let offset = phys - seed.base;
    retype_free(seed, offset, bytes);
    seed.header.dec_ref();
}

/// Per-`ObjectType` retype dispatch entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchEntry
{
    /// Bytes consumed for this object type, before size-class rounding.
    pub raw_bytes: u64,
    /// `true` if the object's region must be page-aligned (split mode).
    pub split: bool,
}

/// `EventQueueObject` wrapper bytes, used by the `EventQueue` layout helpers.
const EVENT_QUEUE_WRAPPER_BYTES: u64 = 24;

/// `EventQueueState` body bytes, kept in sync with the struct in
/// `core/kernel/src/ipc/event_queue.rs` (anchored by the const assertion
/// in that module). Update both sides together.
pub const EVENT_QUEUE_STATE_BYTES: u64 = 56;

/// Compute the inline byte cost of an `EventQueue` retype slot for a
/// user-visible `capacity`: wrapper + state + (capacity + 1) ring slots,
/// padded so the ring starts at a `u64` boundary.
pub const fn event_queue_raw_bytes(capacity: u64) -> u64
{
    let header = EVENT_QUEUE_WRAPPER_BYTES + EVENT_QUEUE_STATE_BYTES;
    // Both 24 and 56 are 8-byte multiples, so no extra alignment padding.
    let ring_bytes = (capacity + 1) * 8;
    header + ring_bytes
}

/// Offset of the inline ring buffer from the start of an `EventQueue`
/// retype slot. Used by `sys_cap_create_event_queue` and the reclaim
/// path; must match the layout assumed by `event_queue_raw_bytes`.
pub const EVENT_QUEUE_RING_OFFSET: u64 = EVENT_QUEUE_WRAPPER_BYTES + EVENT_QUEUE_STATE_BYTES;

/// Look up the byte cost and allocation mode for a given `ObjectType`.
///
/// `size_arg` is the variable-size argument (capacity for `EventQueue`,
/// page count for `Frame`, initial growth-budget pages for `AddressSpace`
/// / `CSpace`). Pass `0` for fixed-size types.
///
/// Returns `None` for object types that cannot be retyped (`Frame` is
/// retypable; `MmioRegion`/`Interrupt`/`IoPortRange`/`SchedControl`/
/// `SbiControl` are boot-minted only).
pub fn dispatch_for(object_type: ObjectType, size_arg: u64) -> Option<DispatchEntry>
{
    match object_type
    {
        // Sub-page wrappers + state. Header (16) + state (variable).
        // Endpoint: 24 wrapper + 64 EndpointState = 88 → BIN_128.
        ObjectType::Endpoint => Some(DispatchEntry {
            raw_bytes: 88,
            split: false,
        }),
        // Signal: 24 wrapper + 96 SignalState = 120 → BIN_128.
        ObjectType::Signal => Some(DispatchEntry {
            raw_bytes: 120,
            split: false,
        }),
        // WaitSet: 24 wrapper + ~440 WaitSetState (16 × 24 B niche-packed
        // members + ready ring + bookkeeping). Rounds to BIN_512.
        ObjectType::WaitSet => Some(DispatchEntry {
            raw_bytes: 24 + 440,
            split: false,
        }),
        // EventQueue: 24 wrapper + EventQueueState (≈ 56 B) + (size_arg + 1)
        // u64 ring slots, all inline in the retype slot. Sub-page in-place
        // for small rings; page-aligned split when the total exceeds the
        // 512 B sub-page bin. The exact byte count here must match the
        // construction layout in `sys_cap_create_event_queue` and the
        // reclaim arithmetic in `dealloc_object`'s EventQueue arm.
        ObjectType::EventQueue =>
        {
            let raw_bytes = event_queue_raw_bytes(size_arg);
            Some(DispatchEntry {
                raw_bytes,
                split: raw_bytes > BIN_512,
            })
        }
        // Thread: KERNEL_STACK_PAGES kstack pages + 1 page holding the
        // ThreadObject wrapper and the TCB. Layout: pages 0..N are kstack
        // (kstack_top = base + N*PAGE_SIZE); page N holds wrapper + TCB.
        // The construction site `sys_cap_create_thread` asserts equality
        // against this dispatch entry.
        ObjectType::Thread => Some(DispatchEntry {
            raw_bytes: (crate::sched::KERNEL_STACK_PAGES as u64 + 1) * PAGE_SIZE as u64,
            split: true,
        }),
        // AddressSpace and CSpace are both kernel-half growable objects.
        // The wrapper struct (`AddressSpaceObject` / `CSpaceKernelObject`)
        // and the inner `AddressSpace` / `CSpace` struct live in the
        // kernel heap; the cap consumes pure budget pages: `size_arg`
        // pages, all going onto the wrapper's growth pool.
        //
        // For AddressSpace, page 0 is consumed immediately as the root PT;
        // pages 1..size_arg form the initial PT growth pool. Caller must
        // pass `size_arg >= 1` (verified by sys_cap_create_aspace).
        //
        // For CSpace, all `size_arg` pages enter the slot-page pool;
        // CSpace::grow consumes them on demand.
        //
        // `size_arg.checked_mul` rejects pathological sizes (caller-supplied
        // u64) that would otherwise wrap into a small `raw_bytes`.
        ObjectType::AddressSpace | ObjectType::CSpaceObj => Some(DispatchEntry {
            raw_bytes: size_arg.checked_mul(PAGE_SIZE as u64)?,
            split: true,
        }),
        // Frame retype: subsumes today's frame_split. size_arg is page count.
        ObjectType::Frame => Some(DispatchEntry {
            raw_bytes: size_arg.saturating_mul(PAGE_SIZE as u64),
            split: true,
        }),
        // Boot-minted only.
        ObjectType::MmioRegion
        | ObjectType::Interrupt
        | ObjectType::IoPortRange
        | ObjectType::SchedControl
        | ObjectType::SbiControl => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn round_to_class_zero()
    {
        assert_eq!(round_to_class(0), 0);
    }

    #[test]
    fn round_to_class_sub_page()
    {
        assert_eq!(round_to_class(1), BIN_128);
        assert_eq!(round_to_class(64), BIN_128);
        assert_eq!(round_to_class(BIN_128), BIN_128);
        assert_eq!(round_to_class(BIN_128 + 1), BIN_512);
        assert_eq!(round_to_class(BIN_512), BIN_512);
    }

    #[test]
    fn round_to_class_page_aligned()
    {
        let p = PAGE_SIZE as u64;
        assert_eq!(round_to_class(BIN_512 + 1), p);
        assert_eq!(round_to_class(p), p);
        assert_eq!(round_to_class(p + 1), 2 * p);
        assert_eq!(round_to_class(5 * p), 5 * p);
    }

    #[test]
    fn align_up_basic()
    {
        assert_eq!(align_up(0, 8), 0);
        assert_eq!(align_up(1, 8), 8);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(9, 8), 16);
        assert_eq!(align_up(0x1234, 0x1000), 0x2000);
    }

    #[test]
    fn subpage_bin_lookup()
    {
        assert_eq!(subpage_bin_for(BIN_128), Some(0));
        assert_eq!(subpage_bin_for(BIN_512), Some(1));
        assert_eq!(subpage_bin_for(PAGE_SIZE as u64), None);
        assert_eq!(subpage_bin_for(0), None);
    }

    #[test]
    fn dispatch_subpage_objects()
    {
        let e = dispatch_for(ObjectType::Endpoint, 0).unwrap();
        assert!(!e.split);
        assert_eq!(round_to_class(e.raw_bytes), BIN_128);

        let s = dispatch_for(ObjectType::Signal, 0).unwrap();
        assert!(!s.split);
        assert_eq!(round_to_class(s.raw_bytes), BIN_128);

        // WaitSetState is niche-packed to fit, with the wrapper, inside
        // the 512 B sub-page bin.
        let w = dispatch_for(ObjectType::WaitSet, 0).unwrap();
        assert!(!w.split);
        assert_eq!(round_to_class(w.raw_bytes), BIN_512);
    }

    #[test]
    fn dispatch_event_queue()
    {
        // Inline ring: 24 wrapper + 56 state + (capacity+1)*8.
        // capacity=4 → 80 + 40 = 120 → BIN_128, in-place.
        let small = dispatch_for(ObjectType::EventQueue, 4).unwrap();
        assert!(!small.split);
        assert_eq!(small.raw_bytes, 120);
        assert_eq!(round_to_class(small.raw_bytes), BIN_128);
        // capacity=32 → 80 + 33*8 = 344 → BIN_512, in-place.
        let medium = dispatch_for(ObjectType::EventQueue, 32).unwrap();
        assert!(!medium.split);
        assert_eq!(medium.raw_bytes, 344);
        assert_eq!(round_to_class(medium.raw_bytes), BIN_512);
        // capacity=64 → 80 + 65*8 = 600 → exceeds BIN_512 → split.
        let large = dispatch_for(ObjectType::EventQueue, 64).unwrap();
        assert!(large.split);
        assert_eq!(large.raw_bytes, 600);
    }

    #[test]
    fn dispatch_thread_split()
    {
        let t = dispatch_for(ObjectType::Thread, 0).unwrap();
        assert!(t.split);
        assert_eq!(t.raw_bytes, 5 * PAGE_SIZE as u64);
    }

    #[test]
    fn dispatch_aspace_initial_budget()
    {
        let p = PAGE_SIZE as u64;
        let one = dispatch_for(ObjectType::AddressSpace, 1).unwrap();
        assert_eq!(one.raw_bytes, p);
        let with_budget = dispatch_for(ObjectType::AddressSpace, 8).unwrap();
        assert_eq!(with_budget.raw_bytes, 8 * p);
        assert!(with_budget.split);
    }

    #[test]
    fn dispatch_cspace_initial_budget()
    {
        let p = PAGE_SIZE as u64;
        let one = dispatch_for(ObjectType::CSpaceObj, 1).unwrap();
        assert_eq!(one.raw_bytes, p);
        let with_budget = dispatch_for(ObjectType::CSpaceObj, 4).unwrap();
        assert_eq!(with_budget.raw_bytes, 4 * p);
    }

    #[test]
    fn dispatch_frame_retype_pages()
    {
        let p = PAGE_SIZE as u64;
        let f = dispatch_for(ObjectType::Frame, 4).unwrap();
        assert!(f.split);
        assert_eq!(f.raw_bytes, 4 * p);
    }

    #[test]
    fn dispatch_boot_minted_types_refused()
    {
        assert!(dispatch_for(ObjectType::MmioRegion, 0).is_none());
        assert!(dispatch_for(ObjectType::Interrupt, 0).is_none());
        assert!(dispatch_for(ObjectType::IoPortRange, 0).is_none());
        assert!(dispatch_for(ObjectType::SchedControl, 0).is_none());
        assert!(dispatch_for(ObjectType::SbiControl, 0).is_none());
    }
}
