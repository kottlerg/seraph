// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/retype.rs

//! Retype primitive — turn Memory-cap-backed memory into kernel-object backings.
//!
//! The seven `SYS_CAP_CREATE_*` handlers consume a Memory cap with
//! `MemRights::RETYPE` and call [`retype_allocate`] to carve out a sub-region
//! of the cap's backing memory; the kernel object is constructed in place
//! at the returned offset. On `dec_ref → 0`, the dealloc path looks at
//! `KernelObjectHeader.ancestor` and calls [`retype_free`] to return the
//! bytes to the source `MemoryObject`.
//!
//! ## Authority
//!
//! The caller MUST validate `tag == Memory && rights.contains(RETYPE)` on the
//! source slot before invoking [`retype_allocate`]. This module trusts the
//! caller; the syscall handler enforces the gate.
//!
//! ## Allocator semantics
//!
//! Each retypable Memory cap carries an inline [`RetypeAllocator`] in its
//! [`MemoryObject`] (kernel-owned memory). The allocator manages two pools:
//!
//! - **Sub-page bins** (`BIN_128`, `BIN_512`) — fixed-size free lists. Each
//!   freed slot's first 8 bytes hold the next-offset pointer for the bin's
//!   linked list. New allocations pop from the list, or bump-allocate; once
//!   the bump frontier is spent, one free page block is carved into the
//!   bin's slots.
//! - **Page-aligned blocks** — an address-ordered first-fit free list with
//!   split-on-allocate and coalesce-on-free. Each freed block's first 16
//!   bytes hold `(size_pages: u64, next_offset: u64)`. A free merges the
//!   block with the free blocks on either side; an allocation walks the list
//!   for a block `>= requested pages` and, on a larger fit, leaves the
//!   remainder in the block's place.
//!
//! Free-list nodes are still stored inline in the cap's region (the freed
//! offsets that the lists thread together), but the *head pointers and
//! bump cursor* live in kernel memory. Userspace `sys_mem_map` writes
//! against the cap's region therefore cannot corrupt allocator metadata;
//! they can at worst overwrite a freed offset's link cell. Every walk
//! validates each inline link before dereferencing it. The page walks use
//! `page_node_ok`: a node must lie in the region, be page-aligned and
//! non-empty, and start at or above its predecessor's end, so a walk is
//! bounded by `size / PAGE_SIZE` nodes and a cycle cannot be followed; a
//! malformed node stops the allocation walk (the request falls through to
//! bump allocation), sends a free to the list head, and is reported once per
//! boot. The sub-page path uses `subpage_link_ok` in `try_pop_subpage`, which
//! truncates the bin's list to `FREE_LIST_END` at a corrupt link. No corrupt
//! link is dereferenced.
//!
//! ## Concurrency
//!
//! Each [`RetypeAllocator`] carries its own spinlock. The lock guards every
//! state mutation — bump pointer, both free lists. `available_bytes`
//! mutations use atomic `fetch_*` and don't require the lock (callers
//! reading `available` without the lock get a snapshot, which is exactly
//! what they want for budget queries).
//!
//! [`retype_allocate`] and [`retype_free`] additionally take the cap's read
//! lock ([`MemoryReadGuard`](crate::cap::object::MemoryReadGuard)) for their
//! whole body, because both compare allocator state against `memory.size`
//! (`retype_allocate`'s bump bound; `retype_free`'s drain-reset) and
//! `sys_memory_split`/`sys_memory_merge` mutate `memory.size` under the cap
//! write lock. Lock order: cap-rwlock outer, allocator spinlock inner.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cap::object::{KernelObjectHeader, MemoryObject, ObjectType};
use crate::mm::PAGE_SIZE;
use syscall::SyscallError;

/// Sub-page size classes. Each retype request is rounded up to one of these
/// or to a page multiple. Tunable as the object catalogue evolves. They set
/// rounding, not capacity: a request above `BIN_512` takes whole pages.
const BIN_128: u64 = 128;
const BIN_512: u64 = 512;

/// Number of sub-page free-list bins.
const NUM_SUBPAGE_BINS: usize = 2;

/// `PAGE_SIZE` as a region offset.
const PAGE_BYTES: u64 = PAGE_SIZE as u64;

/// The bits of a region offset below its page.
const PAGE_OFFSET_MASK: u64 = PAGE_BYTES - 1;

/// Sentinel value for an empty free list. Real offsets are bounded by
/// `memory.size` (well below `u64::MAX`).
const FREE_LIST_END: u64 = u64::MAX;

/// Per-Memory-cap retype allocator. Lives inline in [`MemoryObject`] (kernel-
/// owned memory). Manages bump-allocation plus per-class free lists over
/// the cap's backing region.
#[repr(C)]
pub struct RetypeAllocator
{
    /// Spinlock guarding the bump pointer and free lists.
    /// `0` = unlocked, `1` = locked. Acquired with CAS.
    lock: AtomicU64,
    /// Next free byte (high water mark) within the Memory cap region.
    bump_offset: AtomicU64,
    /// Sub-page free-list heads, one per size class. `FREE_LIST_END` = empty.
    /// At each non-empty offset, the first 8 bytes of the freed slot hold
    /// the next-offset pointer for this bin's linked list.
    subpage_free_lists: [AtomicU64; NUM_SUBPAGE_BINS],
    /// Page-aligned free-list head. `FREE_LIST_END` = empty. Each freed block
    /// stores `(size_pages: u64, next_offset: u64)` at offset 0..16 within
    /// the freed region. The list is kept in ascending address order with
    /// adjacent blocks merged ([`PageCursor::insert`]), so it holds at most one
    /// node per free run and a walk visits at most `size / PAGE_SIZE` nodes.
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

    /// Acquire the allocator lock. A contended wait is recorded in the
    /// calling CPU's lock-wait breadcrumb for the softlockup watchdog; the
    /// uncontended path records nothing.
    #[track_caller]
    fn lock(&self)
    {
        crate::sched::check_lock_hold_preemptible(
            crate::sched::LockKind::RetypeAlloc,
            core::panic::Location::caller(),
        );
        if self
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::sched::lock_wait_enter(
                crate::sched::LockKind::RetypeAlloc,
                core::ptr::from_ref(&self.lock).expose_provenance(),
            );
            while self
                .lock
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            crate::sched::lock_wait_exit();
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
/// cap's `available_bytes`. A size within a page of `u64::MAX`, which no page
/// multiple holds, gives `u64::MAX`: more than any region holds, so its
/// retype fails as too large.
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
        bytes
            .checked_next_multiple_of(PAGE_SIZE as u64)
            .unwrap_or(u64::MAX)
    }
}

/// A sub-page size class, naming the free list of
/// [`RetypeAllocator::subpage_free_lists`] that holds its freed slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubpageBin
{
    /// `BIN_128` slots.
    Bin128,
    /// `BIN_512` slots.
    Bin512,
}

impl SubpageBin
{
    /// The bin's free-list head in `alloc`.
    fn head(self, alloc: &RetypeAllocator) -> &AtomicU64
    {
        let [bin_128, bin_512] = &alloc.subpage_free_lists;
        match self
        {
            Self::Bin128 => bin_128,
            Self::Bin512 => bin_512,
        }
    }
}

/// Map a sub-page rounded size to its bin.
fn subpage_bin_for(rounded: u64) -> Option<SubpageBin>
{
    if rounded == BIN_128
    {
        Some(SubpageBin::Bin128)
    }
    else if rounded == BIN_512
    {
        Some(SubpageBin::Bin512)
    }
    else
    {
        None
    }
}

/// Where a bump allocation of `need` bytes goes when the bump cursor is at
/// `bump`: its start, page-aligned for a page-class request, and the cursor
/// after it. `None` when either passes the end of the address space, which
/// places nothing, as a cursor past the region's end does.
fn bump_placement(bump: u64, need: u64) -> Option<(u64, u64)>
{
    let start = if need >= PAGE_SIZE as u64
    {
        bump.checked_next_multiple_of(PAGE_SIZE as u64)?
    }
    else
    {
        bump
    };
    Some((start, start.checked_add(need)?))
}

/// Read a u64 from `phys + offset` via the kernel direct map.
///
/// # Safety
///
/// `phys + offset` must be inside a live Memory cap region; the bytes at that
/// location must be safe to read (not concurrently written by anyone other
/// than the holder of the allocator lock).
#[cfg(not(test))]
unsafe fn read_u64_at(phys: u64, offset: u64) -> u64
{
    // An offset inside the region keeps the sum inside RAM, far below the
    // wrap; it wraps as `phys_to_virt` does.
    let virt = crate::mm::paging::phys_to_virt(phys.wrapping_add(offset));
    // SAFETY: caller guarantees the address is in the kernel direct map and
    // that the slot is not concurrently written.
    unsafe { core::ptr::read_volatile(virt as *const u64) }
}

/// Write a u64 to `phys + offset` via the kernel direct map.
///
/// # Safety
///
/// `phys + offset` must be inside a live Memory cap region; the bytes at that
/// location must be safe to write (the slot is freed and not aliased).
#[cfg(not(test))]
unsafe fn write_u64_at(phys: u64, offset: u64, value: u64)
{
    // As in `read_u64_at`.
    let virt = crate::mm::paging::phys_to_virt(phys.wrapping_add(offset));
    // SAFETY: caller guarantees the address is in the kernel direct map and
    // not aliased.
    unsafe { core::ptr::write_volatile(virt as *mut u64, value) };
}

/// Host-test form of `read_u64_at`: a test region's `memory.base` is the
/// host address of an 8-byte-aligned buffer, so `phys + offset` is read
/// directly instead of through the direct map, which a host process lacks.
///
/// # Safety
///
/// `phys + offset` must lie inside the test's live buffer, 8-byte aligned.
#[cfg(test)]
unsafe fn read_u64_at(phys: u64, offset: u64) -> u64
{
    // SAFETY: caller guarantees the address lies in the live, aligned test buffer.
    unsafe { core::ptr::read_volatile((phys + offset) as *const u64) }
}

/// Host-test form of `write_u64_at`; see the host-test `read_u64_at`.
///
/// # Safety
///
/// `phys + offset` must lie inside the test's live buffer, 8-byte aligned,
/// and not be aliased by a live reference.
#[cfg(test)]
unsafe fn write_u64_at(phys: u64, offset: u64, value: u64)
{
    // SAFETY: caller guarantees the address lies in the live, aligned,
    // unaliased test buffer.
    unsafe { core::ptr::write_volatile((phys + offset) as *mut u64, value) };
}

/// True if `link` is a structurally valid sub-page free-list pointer for a
/// region of `memory_size` bytes: either the empty sentinel, or an in-range
/// offset aligned to the smallest sub-page class. Mirrors the bounds guard in
/// [`try_alloc_page_block`].
fn subpage_link_ok(link: u64, memory_size: u64) -> bool
{
    link == FREE_LIST_END || (link < memory_size && link.is_multiple_of(BIN_128))
}

/// Try to pop a slot from the bin's free list. Returns the offset if a slot
/// was reused, or `None` if the list is empty.
///
/// Caller holds the allocator lock.
///
/// # Safety
///
/// `memory.base + head_offset` must be a valid kernel direct-map address.
unsafe fn try_pop_subpage(
    alloc: &RetypeAllocator,
    memory: &MemoryObject,
    bin: SubpageBin,
) -> Option<u64>
{
    let list = bin.head(alloc);
    let head = list.load(Ordering::Acquire);
    if head == FREE_LIST_END
    {
        return None;
    }
    // Validate the head offset before dereferencing it. A freed slot's link
    // cell lives inline in the cap's backing region; a stray writer there
    // (the hazard the module docs note) could leave a bogus value. Reject an
    // out-of-range or misaligned head: drop the corrupted list and fall back
    // to bump allocation — mirroring the bounded-walk guard in
    // `try_alloc_page_block`, never dereferencing the bad pointer.
    if !subpage_link_ok(head, memory.size)
    {
        crate::kprintln!(
            "RETYPE SUBPAGE FREE-LIST CORRUPT: memory.base=0x{:x} size=0x{:x} bin={:?} head=0x{:x}",
            memory.base,
            memory.size,
            bin,
            head
        );
        list.store(FREE_LIST_END, Ordering::Release);
        return None;
    }
    // Read next-offset stored at offset `head` within the cap region.
    // SAFETY: head validated in-range above; memory.base + head is direct-map.
    let next = unsafe { read_u64_at(memory.base, head) };
    // Validate the successor before promoting it to the new head, so a bad
    // link cannot be dereferenced by the next pop.
    if !subpage_link_ok(next, memory.size)
    {
        crate::kprintln!(
            "RETYPE SUBPAGE FREE-LIST CORRUPT: memory.base=0x{:x} size=0x{:x} bin={:?} next=0x{:x}",
            memory.base,
            memory.size,
            bin,
            next
        );
        // `head` itself is valid and returned; truncate the list at the bad
        // successor.
        list.store(FREE_LIST_END, Ordering::Release);
        return Some(head);
    }
    list.store(next, Ordering::Release);
    Some(head)
}

/// Push `offset` onto the bin's free list.
///
/// Caller holds the allocator lock and has dropped any kernel-object state
/// that previously occupied the slot.
///
/// # Safety
///
/// `memory.base + offset` must be a valid kernel direct-map address; the
/// slot must not be concurrently aliased.
unsafe fn push_subpage(alloc: &RetypeAllocator, memory: &MemoryObject, bin: SubpageBin, offset: u64)
{
    let list = bin.head(alloc);
    let prev_head = list.load(Ordering::Acquire);
    // Write next-offset at the start of the freed slot.
    // SAFETY: caller guarantees the slot is no longer in use.
    unsafe { write_u64_at(memory.base, offset, prev_head) };
    list.store(offset, Ordering::Release);
}

/// Predecessor pointer for the page-aligned free-list walk.
///
/// The list head lives in the `RetypeAllocator` (inline in the
/// `MemoryObject`, in kernel-owned memory); mid-list next-pointers live
/// inline at `memory.base + offset + 8`. The two storage shapes need
/// different update paths, captured here.
#[derive(Clone, Copy)]
enum PagePrev
{
    /// Predecessor is the allocator's `page_free_head` field.
    Head,
    /// Predecessor is an inline next-pointer slot at the given cap offset.
    /// The next-pointer is at `memory.base + offset + 8`.
    InCap(u64),
}

/// Set by the first malformed page free-list node a walk meets, so a corrupt
/// list costs one console line per boot rather than one per retype.
static PAGE_LIST_CORRUPT_REPORTED: AtomicBool = AtomicBool::new(false);

/// Report a malformed page free-list node, once per boot. A well-formed list
/// never reaches this, however long it is: an ordinary miss prints nothing.
fn report_page_list_corrupt(memory: &MemoryObject, cur: u64, prev_end: u64)
{
    if !PAGE_LIST_CORRUPT_REPORTED.swap(true, Ordering::Relaxed)
    {
        crate::kprintln!(
            "RETYPE PAGE FREE-LIST CORRUPT: memory.base=0x{:x} size=0x{:x} cur=0x{:x} prev_end=0x{:x}",
            memory.base,
            memory.size,
            cur,
            prev_end
        );
    }
}

/// The end offset of a page free-list node at `cur` holding `block_pages`
/// pages, if the node is well formed for a region of `memory_size` bytes,
/// reached from a predecessor that ends at `prev_end` (0 for the list head):
/// page-aligned, non-empty, inside the region, and at or above the
/// predecessor's end. `None` for a malformed node. The list is kept
/// address-ordered and coalesced, so every node starts strictly above the
/// previous one; a walk that follows only well-formed nodes therefore visits at
/// most `memory_size / PAGE_SIZE` of them, and a cycle shows up as a node that
/// is not above its predecessor.
fn page_node_ok(cur: u64, block_pages: u64, prev_end: u64, memory_size: u64) -> Option<u64>
{
    let p = PAGE_SIZE as u64;
    let end = cur.checked_add(block_pages.checked_mul(p)?)?;
    (cur.is_multiple_of(p) && cur >= prev_end && block_pages != 0 && end <= memory_size)
        .then_some(end)
}

/// Offset of the next-pointer word of the page free-list node at `node`, the
/// node's second `u64`. A node lies page-aligned inside the region, so the
/// word lies in its first page and the sum cannot wrap.
const fn node_next_word(node: u64) -> u64
{
    node.wrapping_add(8)
}

/// Point `prev` (the list head, or a node's next-pointer) at `value`.
///
/// Caller holds the allocator lock.
///
/// # Safety
///
/// `memory.base` must be a valid kernel direct-map address and an
/// [`PagePrev::InCap`] offset a node the caller's walk validated.
unsafe fn set_page_link(alloc: &RetypeAllocator, memory: &MemoryObject, prev: &PagePrev, value: u64)
{
    match *prev
    {
        PagePrev::Head => alloc.page_free_head.store(value, Ordering::Release),
        PagePrev::InCap(prev_off) =>
        {
            // SAFETY: caller contract; the next-pointer is at offset + 8.
            unsafe { write_u64_at(memory.base, node_next_word(prev_off), value) };
        }
    }
}

/// Try to satisfy a page-aligned allocation from the page free list.
///
/// First-fit search over the address-ordered list; on a larger-than-needed
/// block, the front `pages` go to the caller and the remainder takes the
/// block's place in the list, which keeps the order. Returns the offset of the
/// allocated block, or `None` if no block fits or the walk meets a malformed
/// node ([`page_node_ok`], reported once per boot).
///
/// Caller holds the allocator lock.
///
/// # Safety
///
/// `memory.base` must be a valid kernel direct-map address.
unsafe fn try_alloc_page_block(
    alloc: &RetypeAllocator,
    memory: &MemoryObject,
    pages: u64,
) -> Option<u64>
{
    let p = PAGE_SIZE as u64;
    let mut prev = PagePrev::Head;
    let mut prev_end = 0;
    let mut cur = alloc.page_free_head.load(Ordering::Acquire);

    while cur != FREE_LIST_END
    {
        if cur >= memory.size
        {
            report_page_list_corrupt(memory, cur, prev_end);
            return None;
        }
        // SAFETY: cur lies inside the cap (checked above) and was placed by a
        // push; the size word is at offset 0.
        let block_pages = unsafe { read_u64_at(memory.base, cur) };
        let Some(block_end) = page_node_ok(cur, block_pages, prev_end, memory.size)
        else
        {
            report_page_list_corrupt(memory, cur, prev_end);
            return None;
        };
        // SAFETY: same node; next is at offset cur+8.
        let block_next = unsafe { read_u64_at(memory.base, node_next_word(cur)) };

        if let Some(rest_pages) = block_pages.checked_sub(pages)
        {
            let replacement = if rest_pages == 0
            {
                block_next
            }
            else
            {
                // The rest of the block is its last `rest_pages` pages, inside
                // the block `page_node_ok` validated, so neither product nor
                // difference can wrap.
                let remainder = block_end.wrapping_sub(rest_pages.wrapping_mul(p));
                // SAFETY: remainder is page-aligned and inside the block being
                // unlinked, which no object occupies.
                unsafe {
                    write_u64_at(memory.base, remainder, rest_pages);
                    write_u64_at(memory.base, node_next_word(remainder), block_next);
                }
                remainder
            };
            // SAFETY: lock held; prev is the head or a node validated by this
            // walk.
            unsafe { set_page_link(alloc, memory, &prev, replacement) };
            return Some(cur);
        }

        prev = PagePrev::InCap(cur);
        prev_end = block_end;
        cur = block_next;
    }

    None
}

/// A position in a walk of the address-ordered page free list, from which
/// freed page blocks are inserted: `prev` is the node below the next block
/// (with its size and end) and `cur` the first node not yet passed. Each
/// insertion leaves the cursor just past the block it placed, so blocks freed
/// in ascending order through one cursor cost one walk of the list in all.
///
/// Used under the allocator lock, for the whole life of the cursor.
struct PageCursor
{
    prev: PagePrev,
    prev_pages: u64,
    prev_end: u64,
    cur: u64,
    /// Set once the walk meets a malformed node: the list is no longer
    /// trustworthy, and every later block goes to the head.
    corrupt: bool,
}

impl PageCursor
{
    /// A cursor at the head of `alloc`'s page free list.
    fn new(alloc: &RetypeAllocator) -> Self
    {
        Self {
            prev: PagePrev::Head,
            prev_pages: 0,
            prev_end: 0,
            cur: alloc.page_free_head.load(Ordering::Acquire),
            corrupt: false,
        }
    }

    /// Insert the freed block of `pages` pages at `offset` into the list,
    /// merging it with the free block that ends where it starts and with the
    /// one that starts where it ends, so adjacent free pages are always one
    /// node.
    ///
    /// If the walk meets a malformed node ([`page_node_ok`], reported once per
    /// boot), the block is pushed at the head instead: the list is no longer
    /// trustworthy, and the next walk stops at that node.
    ///
    /// # Safety
    ///
    /// The caller holds the allocator lock, as for every earlier insertion
    /// through this cursor; `offset` is page-aligned, within the cap, and at
    /// or above the end of every block this cursor inserted before; the bytes
    /// at `memory.base + offset` are not concurrently aliased.
    unsafe fn insert(
        &mut self,
        alloc: &RetypeAllocator,
        memory: &MemoryObject,
        offset: u64,
        pages: u64,
    )
    {
        // The caller's block lies inside the region, so its end does not
        // saturate; a saturated end would only match no node above it.
        let end = offset.saturating_add(pages.saturating_mul(PAGE_SIZE as u64));
        let mut cur_pages = 0;
        let mut cur_end = 0;
        let mut cur_next = FREE_LIST_END;

        // Advance to the first node above `offset`; `prev` is the node below it.
        while !self.corrupt && self.cur != FREE_LIST_END
        {
            let cur = self.cur;
            let node_end = if cur < memory.size
            {
                // SAFETY: cur lies inside the cap; the size word is at offset 0.
                cur_pages = unsafe { read_u64_at(memory.base, cur) };
                page_node_ok(cur, cur_pages, self.prev_end, memory.size)
            }
            else
            {
                None
            };
            let Some(node_end) = node_end
            else
            {
                report_page_list_corrupt(memory, cur, self.prev_end);
                self.corrupt = true;
                break;
            };
            cur_end = node_end;
            // SAFETY: the node was validated above; next is at offset cur+8.
            cur_next = unsafe { read_u64_at(memory.base, node_next_word(cur)) };
            if cur > offset
            {
                break;
            }
            self.prev = PagePrev::InCap(cur);
            self.prev_pages = cur_pages;
            self.prev_end = node_end;
            self.cur = cur_next;
        }
        if self.corrupt
        {
            let head = alloc.page_free_head.load(Ordering::Acquire);
            // SAFETY: caller contract: offset is ours and page-aligned.
            unsafe {
                write_u64_at(memory.base, offset, pages);
                write_u64_at(memory.base, node_next_word(offset), head);
            }
            alloc.page_free_head.store(offset, Ordering::Release);
            return;
        }
        debug_assert!(
            self.prev_end <= offset && (self.cur == FREE_LIST_END || end <= self.cur),
            "PageCursor::insert: freed block 0x{offset:x}+{pages} overlaps a free block"
        );

        let merge_next = self.cur != FREE_LIST_END && self.cur == end;
        let (after_pages, after_end, after_next) = if merge_next
        {
            (cur_pages, cur_end, cur_next)
        }
        else
        {
            (0, end, self.cur)
        };
        // The merged blocks are disjoint and inside the region, so their page
        // count is at most the region's and the sums cannot saturate.
        match self.prev
        {
            PagePrev::InCap(prev_off) if self.prev_end == offset =>
            {
                // Grow the block below over the freed pages (and the block above).
                let total = self
                    .prev_pages
                    .saturating_add(pages)
                    .saturating_add(after_pages);
                // SAFETY: prev_off is a node this walk validated; lock held.
                unsafe {
                    write_u64_at(memory.base, prev_off, total);
                    write_u64_at(memory.base, node_next_word(prev_off), after_next);
                }
                self.prev_pages = total;
            }
            _ =>
            {
                let total = pages.saturating_add(after_pages);
                // SAFETY: caller contract: offset is ours and page-aligned.
                unsafe {
                    write_u64_at(memory.base, offset, total);
                    write_u64_at(memory.base, node_next_word(offset), after_next);
                }
                // SAFETY: lock held; prev is the head or a validated node.
                unsafe { set_page_link(alloc, memory, &self.prev, offset) };
                self.prev = PagePrev::InCap(offset);
                self.prev_pages = total;
            }
        }
        // Either way the block now ends where the freed block, or the free
        // block above it that the freed block joined, ends.
        self.prev_end = after_end;
        self.cur = after_next;
    }
}

/// Take one page from the page free list and cut it into `class`-byte slots
/// of sub-page bin `bin`: the first slot is returned to the caller, the rest
/// are pushed onto the bin's free list. Returns `None` when the page free list
/// holds no block. `available_bytes` is unchanged: the page's bytes move from
/// one free list to another, and the caller debits the slot it takes.
///
/// A carved page stays sub-page slots until the cap drains (the drain reset
/// in [`retype_free`] returns the allocator to virgin): its slots return to
/// the sub-page bin, never to the page free list, so the page free list's
/// coalescing never reassembles it.
///
/// Caller holds the allocator lock.
///
/// # Safety
///
/// `memory.base` must be a valid kernel direct-map address.
unsafe fn carve_page_into_bin(
    alloc: &RetypeAllocator,
    memory: &MemoryObject,
    bin: SubpageBin,
    class: u64,
) -> Option<u64>
{
    // SAFETY: caller holds the allocator lock; memory.base is direct-map.
    let page = unsafe { try_alloc_page_block(alloc, memory, 1) }?;
    // Push from the top down so later pops hand the slots out in ascending order.
    // The page lies inside the region, so its end cannot wrap.
    let mut slot = page.wrapping_add(PAGE_SIZE as u64);
    while let Some(below) = slot.checked_sub(class).filter(|&below| below > page)
    {
        slot = below;
        // SAFETY: lock held; `slot` lies in the page just unlinked from the
        // page free list, which no object occupies.
        unsafe { push_subpage(alloc, memory, bin, slot) };
    }
    Some(page)
}

/// Reserve `bytes` from `memory`'s region. Returns the offset within the cap
/// where the new kernel object should be placed.
///
/// `bytes` is the *raw* requested size; it is rounded up to the next size
/// class internally. The actual bytes debited from `available_bytes` is the
/// rounded value. Sub-page allocations are `BIN_128`-aligned (a `BIN_512`
/// slot is not necessarily 512-aligned) and not page-aligned; page-aligned
/// allocations are always page-aligned within the cap.
///
/// A sub-page request is served from its bin's free list, else the bump
/// frontier, else one page carved from the page free list into that bin
/// ([`carve_page_into_bin`]). A page-aligned request is served from the page
/// free list, else the bump frontier.
///
/// Returns `Err(SyscallError::OutOfMemory)` if the cap doesn't have enough
/// room: `available_bytes` is below the rounded size, or no path above can
/// place it (free bytes held only in the other sub-page bin, or only in
/// sub-page slots for a page-aligned request, stay unusable), or when the
/// bump frontier would advance over a page some address space maps
/// (`crate::mm::frame_map`), in which case nothing changes. A carve is
/// permanent while the cap holds a live object (the drain reset alone undoes
/// it, and SEED never drains), so carving trades page blocks for sub-page
/// capacity. A carve happens only once the bump frontier cannot
/// serve the class, so the bump frontier is by then spent and the class's
/// free list empty: without the carve, the sub-page request fails instead.
/// Returns `Err(SyscallError::QuotaExceeded)`, changing nothing, when
/// `memory`'s reference count is at
/// [`REF_COUNT_LIMIT`](crate::cap::object::REF_COUNT_LIMIT): the object placed
/// would take one more lease on `memory`.
/// Caller must validate `tag == Memory && rights.contains(RETYPE)` before
/// invoking.
///
/// # Safety
///
/// `memory` must be a valid, live `MemoryObject` reference. Returned offset
/// is valid only while `memory` is live; use `memory.base + offset` and
/// `phys_to_virt` to access the memory.
#[track_caller]
pub fn retype_allocate(memory: &MemoryObject, bytes: u64) -> Result<u64, SyscallError>
{
    let need = round_to_class(bytes);
    if need == 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Read-lock the cap for the duration: a concurrent `sys_memory_split`
    // would otherwise mutate `memory.size` between the bump validation
    // (`new_bump > memory.size`) and the commit. Lock order: cap-rwlock
    // outer, allocator spinlock inner.
    let _memory_guard = crate::cap::object::MemoryReadGuard::acquire(memory);

    if memory.available_bytes.load(Ordering::Acquire) < need
    {
        return Err(SyscallError::OutOfMemory);
    }
    // Every object placed here takes a lease on `memory`, a reference whose
    // number userspace can grow, so the retype is refused once the count is
    // at the ceiling (`REF_COUNT_LIMIT`). The lease itself is taken unchecked
    // after this call; at most one per thread mid-retype can pass this check
    // before another reaches the ceiling, which the ceiling's headroom covers.
    if memory.header.at_ref_limit()
    {
        return Err(SyscallError::QuotaExceeded);
    }

    let alloc = &memory.allocator;
    alloc.lock();

    // Try the appropriate free list first.
    if let Some(bin) = subpage_bin_for(need)
    {
        // SAFETY: alloc lock held; bin is a valid index.
        if let Some(off) = unsafe { try_pop_subpage(alloc, memory, bin) }
        {
            // Free-list reuse — debit available_bytes.
            memory.available_bytes.fetch_sub(need, Ordering::AcqRel);
            alloc.unlock();
            return Ok(off);
        }
    }
    else
    {
        // Page-aligned: walk the page free list.
        let pages = need / PAGE_BYTES;
        // SAFETY: alloc lock held.
        if let Some(off) = unsafe { try_alloc_page_block(alloc, memory, pages) }
        {
            memory.available_bytes.fetch_sub(need, Ordering::AcqRel);
            alloc.unlock();
            return Ok(off);
        }
    }

    // Fall through to bump.
    let bump = alloc.bump_offset.load(Ordering::Relaxed);
    let placement = bump_placement(bump, need).filter(|&(_, new_bump)| new_bump <= memory.size);
    let Some((aligned_bump, new_bump)) = placement
    else
    {
        // The bump frontier cannot fit the request. A sub-page request can
        // still be served from a freed page block, whose bytes
        // `available_bytes` counts: carve one page into the request's bin
        // rather than fail while those bytes are free. A cap reaches this state
        // once page-sized children it held are freed and sub-page ones follow
        // (SEED does at init's reap, when init's bootstrap slabs return to it
        // as page blocks).
        // SAFETY: alloc lock held.
        let carved = subpage_bin_for(need)
            .and_then(|bin| unsafe { carve_page_into_bin(alloc, memory, bin, need) });
        if carved.is_some()
        {
            memory.available_bytes.fetch_sub(need, Ordering::AcqRel);
        }
        alloc.unlock();
        return carved.ok_or(SyscallError::OutOfMemory);
    };

    // Retype/map boundary (docs/capability-model.md § Typed Memory): publish
    // the new cursor, then refuse if any frame the advance covers is mapped.
    // A concurrent `sys_mem_map` pins its frames before it reads the cursor,
    // so with the fences on both sides one of the two sees the other
    // (core/kernel/docs/memory-internals.md § Frame Map Table). The free-list
    // paths above need no check: their bytes lie below the cursor, which no
    // mapping can reach once the cursor has passed them. A refusal restores
    // the cursor before anything else changes, leaving the ledger, the free
    // lists, and the cap's bytes as they were.
    alloc.bump_offset.store(new_bump, Ordering::SeqCst);
    core::sync::atomic::fence(Ordering::SeqCst);
    // `advance_start <= bump <= new_bump <= memory.size`, so the length cannot
    // wrap, and the start is a physical address inside the region.
    let advance_start = bump & !PAGE_OFFSET_MASK;
    if crate::mm::frame_map::any_mapped(
        memory.base.wrapping_add(advance_start),
        new_bump.wrapping_sub(advance_start),
    )
    {
        alloc.bump_offset.store(bump, Ordering::Release);
        alloc.unlock();
        return Err(SyscallError::OutOfMemory);
    }

    // Debit only the bytes the caller is consuming. The alignment pad is
    // retained as future-reusable sub-page slots, NOT charged to the cap
    // ledger. This matters when a sub-page bump is followed by a page-aligned
    // request: the gap (up to one page) is recovered into the free lists
    // rather than lost to the bump.
    let prev_avail = memory.available_bytes.fetch_sub(need, Ordering::AcqRel);
    if prev_avail < need
    {
        memory.available_bytes.fetch_add(need, Ordering::Release);
        alloc.bump_offset.store(bump, Ordering::Release);
        alloc.unlock();
        return Err(SyscallError::OutOfMemory);
    }

    // Chop the alignment pad `[bump, aligned_bump)` into the largest sub-page
    // bins that fit. Each pushed slot is reusable by future sub-page retypes.
    // The bump cursor is always a `BIN_128` multiple (every class size and
    // every rollback target is), so the pad divides exactly into bins.
    let mut cursor = bump;
    while let Some(remaining) = aligned_bump
        .checked_sub(cursor)
        .filter(|&remaining| remaining >= BIN_128)
    {
        let (bin, class) = if remaining >= BIN_512
        {
            (SubpageBin::Bin512, BIN_512)
        }
        else
        {
            (SubpageBin::Bin128, BIN_128)
        };
        // SAFETY: alloc lock held; cursor is within the cap region.
        unsafe { push_subpage(alloc, memory, bin, cursor) };
        // The slot ends at or below `aligned_bump`, so the sum cannot wrap.
        cursor = cursor.wrapping_add(class);
    }

    alloc.unlock();

    Ok(aligned_bump)
}

/// Read the current bump offset against `memory`.
///
/// Used by `sys_memory_split` to reject a split offset below the page-rounded
/// bump (live retypes occupy `[0, bump)`), by `sys_mem_map` to reject a mapping
/// that starts below it, and by `sys_memory_merge` to require a virgin tail; see
/// `core/kernel/docs/syscalls.md` § `SYS_MEMORY_SPLIT` (33) and § `SYS_MEM_MAP` (16).
///
/// # Locking
///
/// Caller must hold either `memory.read_lock()` or `memory.write_lock()` so
/// the cap's `size` cannot change under the reader.
#[cfg(not(test))]
pub fn current_bump(memory: &MemoryObject) -> u64
{
    memory.allocator.bump_offset.load(Ordering::Acquire)
}

/// Return `bytes` to `memory`'s region. Pushes the freed slot onto the
/// matching free list and credits `available_bytes`.
///
/// # Safety
///
/// `memory` must be a valid `MemoryObject` reference; `offset` and `bytes`
/// must match a previous successful [`retype_allocate`] return, or, for a
/// page-class allocation, name a page-aligned run of whole pages within one,
/// each page of it freed exactly once (a dead `CSpace` returns a donation's
/// span in runs around the arena pages it keeps, and each kept page alone;
/// the page free list is address-ordered and coalescing, so the runs merge as
/// one free of the whole would). The slot at `offset` must not contain a live
/// kernel object — caller has dropped any state, drained wait queues, etc.,
/// before calling.
#[track_caller]
pub unsafe fn retype_free(memory: &MemoryObject, offset: u64, bytes: u64)
{
    let need = round_to_class(bytes);

    // Defense-in-depth: every caller is a trusted internal dealloc path passing a
    // kernel-computed offset, so an out-of-region (offset, bytes) is a kernel
    // logic regression — caught here in debug/test at no release cost.
    debug_assert!(
        offset.saturating_add(need) <= memory.size,
        "retype_free out of range: offset=0x{:x} need=0x{:x} size=0x{:x}",
        offset,
        need,
        memory.size
    );

    // Read-lock the cap for the duration: the drain-reset below compares
    // `prev_avail + need` against `memory.size`, and a concurrent
    // `sys_memory_split`/`sys_memory_merge` mutates `memory.size` under the cap
    // write lock. Lock order matches `retype_allocate`: cap-rwlock outer,
    // allocator spinlock inner. Deadlock-free — no `retype_free` caller holds
    // the ancestor cap rwlock (the dealloc cascade releases `DERIVATION_LOCK`
    // before invoking this, and reads the immutable `memory.base` without it).
    let _memory_guard = crate::cap::object::MemoryReadGuard::acquire(memory);

    let alloc = &memory.allocator;

    alloc.lock();

    // Bump rollback when the freed block sits at the top of the allocator's
    // bump frontier: no live retype lives above it, so the bump shrinks back to
    // `offset`. This lets `sys_memory_split` carve the freed top while lower
    // retypes stay live (the drain-reset below covers the fully-drained case).
    // The rollback does not cascade past freed slots below the new frontier;
    // those stay on the free lists.
    let bump = alloc.bump_offset.load(Ordering::Relaxed);
    if offset.checked_add(need) == Some(bump)
    {
        alloc.bump_offset.store(offset, Ordering::Release);
    }
    else if let Some(bin) = subpage_bin_for(need)
    {
        // SAFETY: lock held; offset is from a prior successful allocation.
        unsafe { push_subpage(alloc, memory, bin, offset) };
    }
    else
    {
        let pages = need / PAGE_BYTES;
        // SAFETY: lock held; offset is page-aligned (was returned by
        // retype_allocate's page-aligned path).
        unsafe { PageCursor::new(alloc).insert(alloc, memory, offset, pages) };
    }

    credit_freed(memory, need);
    alloc.unlock();
}

/// Return the parts of page-class allocations a caller frees to `memory` as
/// ascending runs of whole pages: `produce` hands each run to the callback it
/// receives as `(offset, bytes)`, lowest first, and the runs go back through
/// one walk of the page free list for them all. A dead pool returns each
/// group of its donations that share a Memory object this way, a `CSpace`'s
/// cut around the arena pages it keeps (`cap::object::free_donation_group`),
/// so `k` runs cost one pass over the Memory object's page free list and `k`
/// insertions, not `k` walks from the list's head.
///
/// The runs end as [`retype_free`] of each, from the highest down, would leave
/// them: the contiguous runs that end at the bump frontier roll it back to
/// the lowest of them, and every other run goes onto the free list. As in
/// [`retype_free`], the rollback stops at the first page the runs do not
/// cover, so a block freed before the call stays on the free list.
///
/// `produce` runs under `memory`'s allocator lock and read guard: it takes no
/// lock and calls no retype function.
///
/// # Safety
///
/// Each run meets [`retype_free`]'s contract: a page-aligned run of whole
/// pages within one page-class allocation of `memory`, each page freed
/// exactly once and holding no live kernel object. The runs ascend and do not
/// overlap.
#[track_caller]
pub unsafe fn retype_free_runs(
    memory: &MemoryObject,
    produce: impl FnOnce(&mut dyn FnMut(u64, u64)),
)
{
    let p = PAGE_BYTES;
    // Read-locked as in retype_free, for the drain reset's size comparison.
    let _memory_guard = crate::cap::object::MemoryReadGuard::acquire(memory);
    let alloc = &memory.allocator;
    alloc.lock();
    let mut cursor = PageCursor::new(alloc);
    let mut freed: u64 = 0;
    let mut last_end = 0;
    // The span `[start, end)` of the contiguous runs since the last gap, held
    // off the list until a run past a gap shows it does not end at the bump
    // frontier: only the span the last run closes can.
    let mut held: Option<(u64, u64)> = None;
    produce(&mut |offset, bytes| {
        // The contract keeps every run inside the region, so neither its end
        // nor the sum of the runs, at most the region's size, saturates.
        let run_end = offset.saturating_add(bytes);
        debug_assert!(
            offset.is_multiple_of(p)
                && bytes.is_multiple_of(p)
                && bytes != 0
                && offset >= last_end
                && run_end <= memory.size,
            "retype_free_runs: run 0x{offset:x}+0x{bytes:x} is not an ascending page run in range"
        );
        last_end = run_end;
        freed = freed.saturating_add(bytes);
        match held
        {
            Some((start, end)) if end == offset => held = Some((start, run_end)),
            _ =>
            {
                if let Some((start, end)) = held.replace((offset, run_end))
                {
                    // SAFETY: lock held for the cursor's life; the span is
                    // page-aligned, ours (the contract above), and above every
                    // span inserted before.
                    unsafe { cursor.insert(alloc, memory, start, span_pages(start, end)) };
                }
            }
        }
    });
    if let Some((start, end)) = held
    {
        // As in retype_free: a span that ends at the bump frontier rolls it
        // back.
        if end == alloc.bump_offset.load(Ordering::Relaxed)
        {
            alloc.bump_offset.store(start, Ordering::Release);
        }
        else
        {
            // SAFETY: as for the spans inserted above.
            unsafe { cursor.insert(alloc, memory, start, span_pages(start, end)) };
        }
    }
    credit_freed(memory, freed);
    alloc.unlock();
}

/// Pages in the held span `[start, end)` of [`retype_free_runs`], whose end is
/// never below its start.
fn span_pages(start: u64, end: u64) -> u64
{
    end.saturating_sub(start) / PAGE_BYTES
}

/// Credit `need` freed bytes to `memory`, resetting its allocator to virgin
/// when that leaves no live retype.
///
/// Caller holds the allocator lock and `memory`'s read guard.
fn credit_freed(memory: &MemoryObject, need: u64)
{
    let alloc = &memory.allocator;
    let prev_avail = memory.available_bytes.fetch_add(need, Ordering::Release);
    if prev_avail.checked_add(need) == Some(memory.size)
    {
        // Memory cap fully drained — no live retyped object remains. Reset the
        // allocator to virgin so a recycled Memory cap carries no bump/free-list
        // residual into its next consumer, and so a virgin tail lets
        // `sys_memory_merge` coalesce it back into the free pool. Without this,
        // a former object-slab keeps its `bump` cursor and freed-slot links for
        // the `MemoryObject`'s whole life (forever for pooled caps): that
        // residual blocks coalescing the recycled Memory cap — leaving it grantable
        // as a standalone run that can be handed out a second time — and leaves
        // a stale free-list link an aliasing writer can clobber.
        alloc.bump_offset.store(0, Ordering::Release);
        for head in &alloc.subpage_free_lists
        {
            head.store(FREE_LIST_END, Ordering::Release);
        }
        alloc.page_free_head.store(FREE_LIST_END, Ordering::Release);
    }
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
/// Called only through `cap::mint_phase7_body`, which serves
/// `cap::populate_cspace`, `mint_module_memory_caps`, and the reclaim mints
/// (`mint_reclaim_memory_caps` at Phase 7, `mint_late_reclaim_memory_caps` at
/// the end of Phase 8), and `kernel_entry_post_rebase` in
/// `core/kernel/src/main.rs` (Phase 9, init segment Memory caps).
///
/// Calls [`crate::fatal`] on any `retype_allocate` error — a boot-time mint
/// cannot recover from a too-small seed.
#[cfg(not(test))]
#[track_caller]
pub fn boot_retype_body<T>(seed: &MemoryObject, body: T) -> NonNull<KernelObjectHeader>
{
    let bytes = core::mem::size_of::<T>() as u64;
    let Ok(offset) = retype_allocate(seed, bytes)
    else
    {
        crate::fatal("Phase 7: seed Memory cap too small for boot mint");
    };
    // An offset `retype_allocate` returned lies inside the seed's RAM region,
    // so the sum cannot wrap.
    let virt = crate::mm::paging::phys_to_virt(seed.base.wrapping_add(offset)) as *mut T;
    // SAFETY: `virt` is in the kernel direct map, freshly carved out by
    // `retype_allocate`, and not aliased.
    unsafe { core::ptr::write(virt, body) };
    seed.header.inc_ref();
    // SAFETY: T is repr(C) with KernelObjectHeader at offset 0; the cast
    // preserves the pointer validity established by the write above.
    unsafe { NonNull::new_unchecked(virt.cast::<KernelObjectHeader>()) }
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

// The sub-page wrappers are header (16) + one pointer, and `dispatch_for`
// budgets them as the literal 24 (this constant, and the Endpoint /
// Notification / WaitSet entries). Their construction sites write the state
// at `size_of::<Wrapper>()`, so a field added to a wrapper would silently
// drift the budget away from the layout; pin both sides here.
const _: () = assert!(core::mem::size_of::<KernelObjectHeader>() == 16);
const _: () = assert!(core::mem::size_of::<crate::cap::object::EndpointObject>() == 24);
const _: () = assert!(core::mem::size_of::<crate::cap::object::NotificationObject>() == 24);
const _: () = assert!(core::mem::size_of::<crate::cap::object::WaitSetObject>() == 24);
const _: () = assert!(
    core::mem::size_of::<crate::cap::object::EventQueueObject>()
        == EVENT_QUEUE_WRAPPER_BYTES as usize
);

/// Raw bytes of a Notification retype slot: the 24 B `NotificationObject`
/// wrapper plus `NotificationState` (a bin overflow is caught by the const
/// assertion in core/kernel/src/ipc/notification.rs).
pub const NOTIFICATION_RAW_BYTES: u64 =
    24 + core::mem::size_of::<crate::ipc::notification::NotificationState>() as u64;

/// `EventQueueState` body bytes, kept in sync with the struct in
/// `core/kernel/src/ipc/event_queue.rs` (anchored by the const assertion
/// in that module). Update both sides together.
pub const EVENT_QUEUE_STATE_BYTES: u64 = 64;

/// `WaitSetState` body bytes, kept in sync with the struct in
/// `core/kernel/src/ipc/wait_set.rs` (anchored by the const assertion in that
/// module).
pub const WAIT_SET_STATE_BYTES: u64 = 40;

/// Offset of a `WaitSet`'s inline member array from the start of its retype
/// slot: directly after the wrapper and the state, both 8-byte multiples.
pub const WAIT_SET_MEMBERS_OFFSET: u64 = 24 + WAIT_SET_STATE_BYTES;

/// Offset of a `WaitSet`'s inline ready ring from the start of its retype
/// slot: directly after the `capacity` member slots.
///
/// The `WaitSet` layout functions saturate: a capacity is at most
/// `WAIT_SET_MAX_MEMBERS` (the const assertions below evaluate them there), so
/// a saturated size names no slot any capacity takes.
pub const fn wait_set_ring_offset(capacity: u64) -> u64
{
    WAIT_SET_MEMBERS_OFFSET.saturating_add(
        capacity.saturating_mul(core::mem::size_of::<crate::ipc::wait_set::WaitSetMember>() as u64),
    )
}

/// Inline byte cost of a `WaitSet` retype slot of `capacity` members: wrapper
/// + state + members + the `capacity + 1` `u16` ready ring, padded to 8 bytes.
pub const fn wait_set_raw_bytes(capacity: u64) -> u64
{
    let ring_bytes = capacity.saturating_add(1).saturating_mul(2);
    wait_set_ring_offset(capacity).saturating_add(ring_bytes.div_ceil(8).saturating_mul(8))
}

/// Byte cost and allocation mode of a `WaitSet` of `capacity` members:
/// sub-page in place while it fits the 512 B bin, page-aligned split beyond.
/// The construction in `sys_cap_create_wait_set` and the reclaim in
/// `dealloc_object_one`'s `WaitSet` arm use the same formula, the ABI's
/// `wait_set_retype_bytes` (pinned below).
pub const fn wait_set_dispatch(capacity: u64) -> DispatchEntry
{
    let raw_bytes = syscall::wait_set_retype_bytes(capacity);
    DispatchEntry {
        raw_bytes,
        split: raw_bytes > BIN_512,
    }
}

/// Bytes of one death-observer node in an `EventQueue`'s inline pool.
const EVENT_QUEUE_OBSERVER_BYTES: u64 =
    core::mem::size_of::<crate::sched::thread::DeathObserver>() as u64;

/// Compute the inline byte cost of an `EventQueue` retype slot for a
/// user-visible `capacity` and `observers` death-observer nodes: wrapper +
/// state + (capacity + 1) two-word ring slots + the node pool. Every part is
/// an 8-byte multiple, so the ring and the pool start at `u64` boundaries.
///
/// The `EventQueue` layout functions saturate: a capacity and an observer
/// count are at most `EVENT_QUEUE_MAX_CAPACITY` (the const assertions below
/// evaluate them there), so a saturated size names no slot any queue takes.
pub const fn event_queue_raw_bytes(capacity: u64, observers: u64) -> u64
{
    event_queue_observer_offset(capacity)
        .saturating_add(observers.saturating_mul(EVENT_QUEUE_OBSERVER_BYTES))
}

/// Offset of the inline ring buffer from the start of an `EventQueue`
/// retype slot. Used by `sys_cap_create_event_queue` and the reclaim
/// path; must match the layout assumed by `event_queue_raw_bytes`.
pub const EVENT_QUEUE_RING_OFFSET: u64 = EVENT_QUEUE_WRAPPER_BYTES + EVENT_QUEUE_STATE_BYTES;

/// Offset of the death-observer node pool from the start of an `EventQueue`
/// retype slot of `capacity`: directly after the ring.
pub const fn event_queue_observer_offset(capacity: u64) -> u64
{
    EVENT_QUEUE_RING_OFFSET.saturating_add(
        capacity
            .saturating_add(1)
            .saturating_mul(core::mem::size_of::<crate::ipc::event_queue::EventEntry>() as u64),
    )
}

/// Byte cost and allocation mode of an `EventQueue` of `capacity` entries and
/// `observers` death-observer nodes: sub-page in place while it fits the
/// 512 B bin, page-aligned split beyond. The construction layout in
/// `sys_cap_create_event_queue` and the reclaim arithmetic in
/// `dealloc_object_one`'s `EventQueue` arm use the same formula, the ABI's
/// `event_queue_retype_bytes` (pinned below).
pub const fn event_queue_dispatch(capacity: u64, observers: u64) -> DispatchEntry
{
    let raw_bytes = syscall::event_queue_retype_bytes(capacity, observers);
    DispatchEntry {
        raw_bytes,
        split: raw_bytes > BIN_512,
    }
}

/// Look up the byte cost and allocation mode for a given `ObjectType`.
///
/// `size_arg` is the variable-size argument (page count for `Memory`, total
/// pages carved — the syscall's `init_pages` — for `AddressSpace` / `CSpace`).
/// Pass `0` for fixed-size types. An `EventQueue` takes two sizes and is
/// looked up through [`event_queue_dispatch`] instead; this returns `None`
/// for it.
///
/// Returns `None` for object types that cannot be retyped (`Memory` is
/// retypable; `Mmio`/`Interrupt`/`IoPort`/`SchedControl`/
/// `SbiControl` are boot-minted only).
pub fn dispatch_for(object_type: ObjectType, size_arg: u64) -> Option<DispatchEntry>
{
    match object_type
    {
        // Sub-page wrappers + state. The Endpoint and Notification debits are
        // the ABI's retype-cost constants, which userspace sizes its slab
        // requests from; the const assertions after this function pin them to
        // the real `24 + size_of::<State>()`, so a field change breaks the
        // build instead of drifting (a bin overflow is caught by the
        // const-asserts in endpoint.rs and notification.rs).
        // Endpoint: 24 wrapper + EndpointState → BIN_128.
        ObjectType::Endpoint => Some(DispatchEntry {
            raw_bytes: syscall::ENDPOINT_RETYPE_BYTES,
            split: false,
        }),
        // Notification: 24 wrapper + NotificationState → BIN_128.
        ObjectType::Notification => Some(DispatchEntry {
            raw_bytes: syscall::NOTIFICATION_RETYPE_BYTES,
            split: false,
        }),
        // Thread: 1 guard page + KERNEL_STACK_PAGES kstack pages + 1 page
        // holding the ThreadObject wrapper and the TCB + the per-thread
        // extended-state save area's pages, sized at boot from the boot CPU
        // (`sched::thread_slot`). Layout: page 0 is the guard, unmapped from
        // the direct map while the thread exists; pages 1..=N are kstack
        // (kstack_top = base + (N+1)*PAGE_SIZE); page N+1 holds wrapper +
        // TCB; pages N+2.. are the save area (XSAVE on x86-64; F/D and V on
        // RISC-V). `sys_cap_create_thread` and the reclaim arm in
        // `dealloc_object_one` read the same size.
        ObjectType::Thread => Some(DispatchEntry {
            raw_bytes: crate::sched::thread_slot::thread_slot_bytes(),
            split: true,
        }),
        // AddressSpace and CSpace: `size_arg` pages, page-aligned. The slab layout
        // in create-mode and augment-mode is specified in
        // core/kernel/docs/syscalls.md § `SYS_CAP_CREATE_ASPACE` (11) and
        // § `SYS_CAP_CREATE_CSPACE` (12); the syscalls construct it.
        //
        // `size_arg.checked_mul` rejects pathological sizes (caller-supplied
        // u64) that would otherwise wrap into a small `raw_bytes`.
        ObjectType::AddressSpace | ObjectType::CSpaceObj => Some(DispatchEntry {
            raw_bytes: size_arg.checked_mul(PAGE_SIZE as u64)?,
            split: true,
        }),
        // Memory: `size_arg` pages, page-aligned. No syscall currently retypes a
        // Memory cap through this entry; `sys_memory_split` carves Memory caps on
        // its own path.
        ObjectType::Memory => Some(DispatchEntry {
            raw_bytes: size_arg.saturating_mul(PAGE_SIZE as u64),
            split: true,
        }),
        // Boot-minted only; and the caller-sized EventQueue and WaitSet,
        // looked up through `event_queue_dispatch` and `wait_set_dispatch`.
        ObjectType::EventQueue
        | ObjectType::WaitSet
        | ObjectType::Mmio
        | ObjectType::Interrupt
        | ObjectType::IoPort
        | ObjectType::SchedControl
        | ObjectType::SbiControl
        | ObjectType::ArenaPage => None,
    }
}

// Pins the ABI retype-cost constants `dispatch_for` debits (and the reclaim
// path in cap/object.rs credits back) to the kernel's real object sizes. The
// ABI EventQueue formula is checked against the kernel's layout formula at
// capacities 0, 1 and `EVENT_QUEUE_MAX_CAPACITY`, with and without observer
// nodes (both bodies are affine in each size, so two points per axis and the
// largest pin them).
const _: () = {
    assert!(
        24 + core::mem::size_of::<crate::ipc::endpoint::EndpointState>() as u64
            == syscall::ENDPOINT_RETYPE_BYTES
    );
    assert!(NOTIFICATION_RAW_BYTES == syscall::NOTIFICATION_RETYPE_BYTES);
    // The WaitSet formula, at one member, four (where the ring's 8-byte
    // padding steps), and the largest.
    assert!(wait_set_raw_bytes(1) == syscall::wait_set_retype_bytes(1));
    assert!(wait_set_raw_bytes(4) == syscall::wait_set_retype_bytes(4));
    assert!(
        wait_set_raw_bytes(syscall::WAIT_SET_MAX_MEMBERS as u64)
            == syscall::wait_set_retype_bytes(syscall::WAIT_SET_MAX_MEMBERS as u64)
    );
    assert!(event_queue_raw_bytes(0, 0) == syscall::event_queue_retype_bytes(0, 0));
    assert!(event_queue_raw_bytes(1, 0) == syscall::event_queue_retype_bytes(1, 0));
    assert!(event_queue_raw_bytes(0, 1) == syscall::event_queue_retype_bytes(0, 1));
    assert!(event_queue_raw_bytes(1, 1) == syscall::event_queue_retype_bytes(1, 1));
    assert!(
        event_queue_raw_bytes(
            syscall::EVENT_QUEUE_MAX_CAPACITY as u64,
            syscall::EVENT_QUEUE_MAX_CAPACITY as u64
        ) == syscall::event_queue_retype_bytes(
            syscall::EVENT_QUEUE_MAX_CAPACITY as u64,
            syscall::EVENT_QUEUE_MAX_CAPACITY as u64
        )
    );
};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    /// [`retype_free`] of an allocation a test made from its own region.
    fn free(memory: &MemoryObject, offset: u64, bytes: u64)
    {
        // SAFETY: every test frees only what it allocated from its own host
        // region, once, and places no object in it.
        unsafe { retype_free(memory, offset, bytes) };
    }

    /// [`retype_free_runs`] of runs of an allocation a test made.
    fn free_runs(memory: &MemoryObject, produce: impl FnOnce(&mut dyn FnMut(u64, u64)))
    {
        // SAFETY: as for `free`; the tests hand ascending, disjoint runs.
        unsafe { retype_free_runs(memory, produce) };
    }

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

    // Defect guarded: a size within a page of `u64::MAX` wraps to 0 when
    // rounded up to a page, which reads as no size at all.
    #[test]
    fn round_to_class_saturates_a_size_no_page_multiple_holds()
    {
        let p = PAGE_SIZE as u64;
        assert_eq!(round_to_class(u64::MAX - p + 1), u64::MAX - p + 1);
        assert_eq!(round_to_class(u64::MAX - p + 2), u64::MAX);
        assert_eq!(round_to_class(u64::MAX), u64::MAX);
        let (_buf, memory) = host_region(1);
        assert_eq!(
            retype_allocate(&memory, u64::MAX),
            Err(SyscallError::OutOfMemory)
        );
    }

    #[test]
    fn bump_placement_aligns_page_requests_only()
    {
        let p = PAGE_SIZE as u64;
        assert_eq!(bump_placement(0, BIN_128), Some((0, BIN_128)));
        assert_eq!(
            bump_placement(BIN_128, BIN_512),
            Some((BIN_128, BIN_128 + BIN_512))
        );
        assert_eq!(bump_placement(BIN_128, p), Some((p, 2 * p)));
        assert_eq!(bump_placement(p, 2 * p), Some((p, 3 * p)));
    }

    // Defect guarded: a bump cursor or request near the end of the address
    // space wraps the placement to a small offset that passes the region
    // check.
    #[test]
    fn bump_placement_past_the_end_of_the_address_space_places_nothing()
    {
        let p = PAGE_SIZE as u64;
        let last_slot = u64::MAX - BIN_128;
        assert_eq!(
            bump_placement(last_slot, BIN_128),
            Some((last_slot, u64::MAX))
        );
        assert_eq!(bump_placement(last_slot + 1, BIN_128), None);
        // The page alignment itself passes the end.
        assert_eq!(bump_placement(u64::MAX - p + 2, p), None);
        assert_eq!(
            bump_placement(0, u64::MAX - p + 1),
            Some((0, u64::MAX - p + 1))
        );
        assert_eq!(bump_placement(p, u64::MAX - p + 1), None);
    }

    #[test]
    fn subpage_link_ok_accepts_sentinel_and_valid_offsets()
    {
        let size = 0x2000; // 2-page Memory cap region
        // Empty-list sentinel is always valid regardless of size.
        assert!(subpage_link_ok(FREE_LIST_END, size));
        // In-range, BIN_128-aligned offsets are valid.
        assert!(subpage_link_ok(0, size));
        assert!(subpage_link_ok(BIN_128, size));
        assert!(subpage_link_ok(size - BIN_128, size));
    }

    #[test]
    fn subpage_link_ok_rejects_corrupt_links()
    {
        let size = 0x2000;
        // Out of range (>= size) — e.g. a clobbered user pointer.
        assert!(!subpage_link_ok(size, size));
        assert!(!subpage_link_ok(0x7FFF_FFFF_D048, size));
        // In range but misaligned (not a multiple of BIN_128).
        assert!(!subpage_link_ok(BIN_128 - 8, size));
        assert!(!subpage_link_ok(0x40, size));
    }

    #[test]
    fn subpage_bin_lookup()
    {
        assert_eq!(subpage_bin_for(BIN_128), Some(SubpageBin::Bin128));
        assert_eq!(subpage_bin_for(BIN_512), Some(SubpageBin::Bin512));
        assert_eq!(subpage_bin_for(PAGE_SIZE as u64), None);
        assert_eq!(subpage_bin_for(0), None);
    }

    #[test]
    fn dispatch_subpage_objects()
    {
        let e = dispatch_for(ObjectType::Endpoint, 0).unwrap();
        assert!(!e.split);
        assert_eq!(round_to_class(e.raw_bytes), BIN_128);

        let s = dispatch_for(ObjectType::Notification, 0).unwrap();
        assert!(!s.split);
        assert_eq!(round_to_class(s.raw_bytes), BIN_128);

        // WaitSetState is niche-packed to fit, with the wrapper, inside
        // the 512 B sub-page bin.
        // WaitSet: 64 header + 24 per member + the u16 ring padded to 8.
        // 16 members → 64 + 384 + 40 = 488 → BIN_512, in place.
        let w = wait_set_dispatch(16);
        assert!(!w.split);
        assert_eq!(w.raw_bytes, 488);
        assert_eq!(round_to_class(w.raw_bytes), BIN_512);
        // 17 members → 64 + 408 + 40 = 512, still in place; 18 → split.
        assert!(!wait_set_dispatch(17).split);
        assert!(wait_set_dispatch(18).split);
        assert!(dispatch_for(ObjectType::WaitSet, 0).is_none());
    }

    #[test]
    fn dispatch_event_queue()
    {
        // Inline: 24 wrapper + 64 state + (capacity+1)*16 ring + observers*24.
        // capacity=1, no observers → 88 + 32 = 120 → BIN_128, in-place.
        let small = event_queue_dispatch(1, 0);
        assert!(!small.split);
        assert_eq!(small.raw_bytes, 120);
        assert_eq!(round_to_class(small.raw_bytes), BIN_128);
        // capacity=16, 2 observers → 88 + 17*16 + 48 = 408 → BIN_512, in-place.
        let medium = event_queue_dispatch(16, 2);
        assert!(!medium.split);
        assert_eq!(medium.raw_bytes, 408);
        assert_eq!(round_to_class(medium.raw_bytes), BIN_512);
        // capacity=1, 18 observers → 88 + 32 + 432 = 552 → exceeds BIN_512 → split.
        let large = event_queue_dispatch(1, 18);
        assert!(large.split);
        assert_eq!(large.raw_bytes, 552);
        // The two-size type has no single-size entry.
        assert!(dispatch_for(ObjectType::EventQueue, 4).is_none());
    }

    #[test]
    fn dispatch_thread_split()
    {
        let t = dispatch_for(ObjectType::Thread, 0).unwrap();
        assert!(t.split);
        assert_eq!(t.raw_bytes, crate::sched::thread_slot::thread_slot_bytes());
        // No boot CPU reports a save area in a host test: the guard page +
        // KERNEL_STACK_PAGES (4) + 1 wrapper/TCB page + the one-page minimum
        // save area.
        assert_eq!(t.raw_bytes, 7 * PAGE_SIZE as u64);
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
    fn dispatch_memory_retype_pages()
    {
        let p = PAGE_SIZE as u64;
        let f = dispatch_for(ObjectType::Memory, 4).unwrap();
        assert!(f.split);
        assert_eq!(f.raw_bytes, 4 * p);
    }

    #[test]
    fn dispatch_boot_minted_types_refused()
    {
        assert!(dispatch_for(ObjectType::Mmio, 0).is_none());
        assert!(dispatch_for(ObjectType::Interrupt, 0).is_none());
        assert!(dispatch_for(ObjectType::IoPort, 0).is_none());
        assert!(dispatch_for(ObjectType::SchedControl, 0).is_none());
        assert!(dispatch_for(ObjectType::SbiControl, 0).is_none());
    }

    /// A Memory object over a zeroed host buffer of `pages` pages, every byte
    /// available: the host-test `read_u64_at`/`write_u64_at` reach the
    /// buffer through `base`. The buffer is returned to outlive the object.
    fn host_region(pages: usize) -> (Vec<u64>, MemoryObject)
    {
        let bytes = pages * PAGE_SIZE;
        let mut buf = vec![0u64; bytes / 8];
        let memory = MemoryObject {
            header: KernelObjectHeader::new(ObjectType::Memory),
            base: buf.as_mut_ptr() as u64,
            size: bytes as u64,
            available_bytes: AtomicU64::new(bytes as u64),
            owns_memory: core::sync::atomic::AtomicBool::new(false),
            allocator: RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
            slot_count: core::sync::atomic::AtomicU32::new(0),
        };
        (buf, memory)
    }

    #[test]
    fn a_clobbered_sub_page_successor_link_is_dropped_not_followed()
    {
        // A freed slot's link cell lives in the cap's bytes. No mapping can
        // reach them (the retype/map boundary), so the guard is defence in
        // depth: a corrupt successor truncates the list, and the valid head is
        // still served, without the poison ever being dereferenced.
        let (_buf, memory) = host_region(1);
        let a = retype_allocate(&memory, 96).unwrap();
        let b = retype_allocate(&memory, 96).unwrap();
        assert_eq!((a, b), (0, BIN_128));
        free(&memory, a, 96);
        // SAFETY: offset 0 is the freed slot's link cell in the live buffer.
        unsafe { write_u64_at(memory.base, 0, 0x3F_FFFF_D048) };
        assert_eq!(retype_allocate(&memory, 96), Ok(0));
        assert_eq!(
            retype_allocate(&memory, 96),
            Ok(2 * BIN_128),
            "the truncated list falls through to the bump frontier"
        );
    }

    #[test]
    fn sub_page_allocation_carves_a_freed_page_once_the_bump_is_spent()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(2);
        // Spend the bump frontier on two pages, then free the lower one: its
        // bytes are available again but only as a page block, the state SEED
        // reaches after init's reap.
        let low = retype_allocate(&memory, p).unwrap();
        let high = retype_allocate(&memory, p).unwrap();
        assert_eq!((low, high), (0, p));
        free(&memory, low, p);
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), p);

        // Every 128-byte slot of the freed page is allocatable, each once.
        let slots = p / BIN_128;
        let mut seen = Vec::new();
        for _ in 0..slots
        {
            let off = retype_allocate(&memory, 96).unwrap();
            assert!(off < p && off.is_multiple_of(BIN_128));
            assert!(!seen.contains(&off));
            seen.push(off);
        }
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), 0);
        // With no page block left either, the next request fails.
        assert_eq!(retype_allocate(&memory, 96), Err(SyscallError::OutOfMemory));
    }

    #[test]
    fn a_512_byte_request_carves_once_the_bump_cannot_fit_it()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(2);
        // Leave 384 bytes of bump room: enough for no 512-byte slot. The page
        // freed below is then the only place a 512-byte request fits.
        let low = retype_allocate(&memory, p).unwrap();
        for _ in 0..29
        {
            retype_allocate(&memory, 96).unwrap();
        }
        free(&memory, low, p);

        let slots = p / BIN_512;
        for _ in 0..slots
        {
            let off = retype_allocate(&memory, BIN_512).unwrap();
            assert!(off < p && off.is_multiple_of(BIN_512));
        }
        // Only 384 bytes are counted as available now, so the next request
        // fails at retype_allocate's `available_bytes < need` check (384 <
        // 512), before any placement is tried.
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), 384);
        assert_eq!(
            retype_allocate(&memory, BIN_512),
            Err(SyscallError::OutOfMemory)
        );
    }

    #[test]
    fn a_page_request_is_not_served_from_carved_sub_page_slots()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(3);
        let a = retype_allocate(&memory, p).unwrap();
        let b = retype_allocate(&memory, p).unwrap();
        let _c = retype_allocate(&memory, p).unwrap();
        free(&memory, a, p);
        free(&memory, b, p);
        // Carve both freed pages into 128-byte slots, then free every slot:
        // two pages of bytes are available again, but only as sub-page slots.
        let carved: Vec<u64> = (0..=p / BIN_128)
            .map(|_| retype_allocate(&memory, 96).unwrap())
            .collect();
        for off in carved
        {
            free(&memory, off, 96);
        }
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), 2 * p);
        assert_eq!(retype_allocate(&memory, p), Err(SyscallError::OutOfMemory));
    }

    // Defect guarded: a retype admitted from a Memory object whose reference
    // count is at the ceiling takes a lease past it, the step toward a wrap
    // that frees the Memory object while its children live.
    #[test]
    fn a_retype_is_refused_once_the_memory_reference_count_is_at_the_ceiling()
    {
        use crate::cap::object::REF_COUNT_LIMIT;
        let (_buf, memory) = host_region(1);
        memory
            .header
            .ref_count
            .store(REF_COUNT_LIMIT, Ordering::Relaxed);
        assert_eq!(
            retype_allocate(&memory, 96),
            Err(SyscallError::QuotaExceeded)
        );
        assert_eq!(
            memory.available_bytes.load(Ordering::Acquire),
            PAGE_SIZE as u64,
            "a refused retype debits nothing"
        );
        memory
            .header
            .ref_count
            .store(REF_COUNT_LIMIT - 1, Ordering::Relaxed);
        assert_eq!(retype_allocate(&memory, 96), Ok(0));
    }

    // Defect guarded: a walk bound below the list's real length (the former
    // 1024-node cap) fails a page retype that a free block past the bound
    // could serve.
    #[test]
    fn a_page_request_finds_a_fitting_block_past_a_thousand_free_holes()
    {
        const HOLES: u64 = 1030;
        let p = PAGE_SIZE as u64;
        // HOLES pairs of single pages, a 4-page block, and a 1-page guard that
        // keeps the block off the bump frontier; nothing is left for the bump.
        let (_buf, memory) = host_region((2 * HOLES + 5) as usize);
        let singles: Vec<u64> = (0..2 * HOLES)
            .map(|_| retype_allocate(&memory, p).unwrap())
            .collect();
        let block = retype_allocate(&memory, 4 * p).unwrap();
        let _guard = retype_allocate(&memory, p).unwrap();
        // The block is freed first, the holes after it (the order that buried
        // the block 1030 nodes deep under the former head-pushed list).
        free(&memory, block, 4 * p);
        for &off in singles.iter().step_by(2)
        {
            free(&memory, off, p);
        }
        assert_eq!(
            retype_allocate(&memory, 4 * p),
            Ok(block),
            "the block after {HOLES} non-adjacent one-page holes is found"
        );
    }

    // Defect guarded: freed neighbours kept as separate nodes leave a run of
    // free pages unable to serve a request for the whole run.
    #[test]
    fn adjacent_freed_page_blocks_coalesce_into_one()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(4);
        let a = retype_allocate(&memory, p).unwrap();
        let b = retype_allocate(&memory, p).unwrap();
        let c = retype_allocate(&memory, p).unwrap();
        let _d = retype_allocate(&memory, p).unwrap();
        // Free the outer two first, then the middle one: the middle free joins
        // both neighbours.
        free(&memory, a, p);
        free(&memory, c, p);
        free(&memory, b, p);
        assert_eq!(retype_allocate(&memory, 3 * p), Ok(a));
    }

    // Defect guarded: a free that meets a malformed node follows it, or drops
    // the freed block, instead of keeping the block allocatable.
    #[test]
    fn a_free_past_a_malformed_page_node_keeps_the_freed_block_allocatable()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(4);
        let a = retype_allocate(&memory, p).unwrap();
        let _b = retype_allocate(&memory, p).unwrap();
        let c = retype_allocate(&memory, p).unwrap();
        let _d = retype_allocate(&memory, p).unwrap();
        free(&memory, a, p);
        // Zero a's size word: a node no well-formed list holds.
        // SAFETY: a's size cell lies in the live buffer.
        unsafe { write_u64_at(memory.base, a, 0) };
        free(&memory, c, p);
        assert_eq!(
            retype_allocate(&memory, p),
            Ok(c),
            "the freed block went to the head"
        );
        assert_eq!(
            retype_allocate(&memory, p),
            Err(SyscallError::OutOfMemory),
            "the walk stops at the malformed node"
        );
    }

    // Defect guarded: a list that loops back (a corrupt link) is walked
    // forever, or its cycle is reported on every retype.
    #[test]
    fn a_page_list_that_loops_back_is_not_followed()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(4);
        let a = retype_allocate(&memory, p).unwrap();
        let _b = retype_allocate(&memory, p).unwrap();
        let c = retype_allocate(&memory, p).unwrap();
        let _d = retype_allocate(&memory, p).unwrap();
        free(&memory, a, p);
        free(&memory, c, p);
        // Point c's next link back at a: a cycle the order check rejects.
        // SAFETY: c's next cell lies in the live buffer.
        unsafe { write_u64_at(memory.base, c + 8, a) };
        assert_eq!(
            retype_allocate(&memory, 2 * p),
            Err(SyscallError::OutOfMemory)
        );
        assert_eq!(retype_allocate(&memory, p), Ok(a));
    }

    /// Pages 0, 1..11, 11 and 12 of a 16-page region retyped as one page, a
    /// 10-page span, and two more single pages, with page 0 freed again: the
    /// span is then cut around the pages at `KEPT` and returned in runs.
    const KEPT: [u64; 3] = [3, 6, 7];

    fn free_span_around_kept() -> (Vec<u64>, MemoryObject, u64)
    {
        let p = PAGE_SIZE as u64;
        let (buf, memory) = host_region(16);
        let lo = retype_allocate(&memory, p).unwrap();
        let span = retype_allocate(&memory, 10 * p).unwrap();
        let hi = retype_allocate(&memory, p).unwrap();
        let _guard = retype_allocate(&memory, p).unwrap();
        assert_eq!((lo, span, hi), (0, p, 11 * p));
        free(&memory, lo, p);
        free_runs(&memory, |run| {
            let mut from = span;
            for &k in &KEPT
            {
                if k * p > from
                {
                    run(from, k * p - from);
                }
                from = (k + 1) * p;
            }
            run(from, span + 10 * p - from);
        });
        (buf, memory, hi)
    }

    // Defect guarded: runs freed through one cursor leave the list unordered,
    // unmerged with the free block below them, or debit the wrong byte count,
    // so the pages a dead CSpace returns around its kept arena pages are not
    // placeable as one free of each run would leave them.
    #[test]
    fn freed_runs_merge_and_place_as_single_frees_would()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory, _hi) = free_span_around_kept();
        // Free: [0, 3) (page 0 merged with the first run), [4, 6), [8, 11),
        // and the 3 virgin pages above the guard.
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), 11 * p);
        assert_eq!(retype_allocate(&memory, 3 * p), Ok(0));
        assert_eq!(
            retype_allocate(&memory, 3 * p),
            Ok(8 * p),
            "first fit passes [4, 6)"
        );
        assert_eq!(retype_allocate(&memory, 2 * p), Ok(4 * p));
    }

    // Defect guarded: a kept page freed after its donation's runs fails to
    // join them, so the span never coalesces back into one block.
    #[test]
    fn kept_pages_freed_after_their_runs_coalesce_the_whole_span()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory, hi) = free_span_around_kept();
        for &k in KEPT.iter().rev()
        {
            free(&memory, k * p, p);
        }
        free(&memory, hi, p);
        assert_eq!(retype_allocate(&memory, 12 * p), Ok(0));
    }

    // Defect guarded: a last run ending at the bump frontier is pushed as a
    // node instead of rolling the frontier back, so the drain reset that
    // follows the last page's free starts from a stale list.
    #[test]
    fn a_last_run_at_the_bump_frontier_rolls_it_back()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(4);
        let span = retype_allocate(&memory, 4 * p).unwrap();
        free_runs(&memory, |run| {
            run(span, p);
            run(span + 2 * p, 2 * p);
        });
        assert_eq!(memory.allocator.bump_offset.load(Ordering::Acquire), 2 * p);
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), 3 * p);
        free(&memory, span + p, p);
        assert_eq!(retype_allocate(&memory, 4 * p), Ok(0), "the region drained");
    }

    // Defect guarded: contiguous allocations returned in one call (a dead
    // pool's donations from one Memory object) roll the bump frontier back
    // over the top run only, leaving the runs below it a free block that ends
    // at the frontier, where freeing each from the highest down rolls the
    // frontier back over them all.
    #[test]
    fn contiguous_runs_at_the_bump_frontier_roll_it_back_over_them_all()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(8);
        let lo = retype_allocate(&memory, p).unwrap();
        let a = retype_allocate(&memory, p).unwrap();
        let b = retype_allocate(&memory, p).unwrap();
        let c = retype_allocate(&memory, 2 * p).unwrap();
        assert_eq!((lo, a, b, c), (0, p, 2 * p, 3 * p));
        free_runs(&memory, |run| {
            run(a, p);
            run(b, p);
            run(c, 2 * p);
        });
        assert_eq!(memory.allocator.bump_offset.load(Ordering::Acquire), p);
        assert_eq!(
            memory.allocator.page_free_head.load(Ordering::Acquire),
            FREE_LIST_END,
            "no run went onto the free list"
        );
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), 7 * p);
    }

    // Defect guarded: the rollback over a call's contiguous runs passes the
    // runs and swallows a block freed before the call, which the frontier
    // never covered (rollback does not cascade past the free lists), or a gap
    // between two runs lets the span below it roll back too.
    #[test]
    fn the_rollback_stops_at_the_first_page_the_runs_do_not_cover()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(8);
        let lo = retype_allocate(&memory, p).unwrap();
        let early = retype_allocate(&memory, p).unwrap();
        let a = retype_allocate(&memory, p).unwrap();
        let held = retype_allocate(&memory, p).unwrap();
        let b = retype_allocate(&memory, p).unwrap();
        let c = retype_allocate(&memory, p).unwrap();
        assert_eq!(
            (lo, early, a, held, b, c),
            (0, p, 2 * p, 3 * p, 4 * p, 5 * p)
        );
        free(&memory, early, p);
        free_runs(&memory, |run| {
            run(a, p);
            run(b, p);
            run(c, p);
        });
        assert_eq!(
            memory.allocator.bump_offset.load(Ordering::Acquire),
            b,
            "the frontier stops at the held page"
        );
        assert_eq!(
            retype_allocate(&memory, 2 * p),
            Ok(early),
            "the early block and the first run merged on the free list"
        );
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), 4 * p);
    }

    // Defect guarded: runs freed through a cursor that meets a malformed node
    // follow it, drop a run, or place a later run past the node, instead of
    // pushing every run from that node on at the head.
    #[test]
    fn runs_freed_past_a_malformed_page_node_all_stay_allocatable()
    {
        let p = PAGE_SIZE as u64;
        let (_buf, memory) = host_region(8);
        let a = retype_allocate(&memory, p).unwrap();
        let span = retype_allocate(&memory, 6 * p).unwrap();
        let _guard = retype_allocate(&memory, p).unwrap();
        free(&memory, a, p);
        // Zero a's size word: a node no well-formed list holds.
        // SAFETY: a's size cell lies in the live buffer.
        unsafe { write_u64_at(memory.base, a, 0) };
        free_runs(&memory, |run| {
            run(span, p);
            run(span + 2 * p, p);
            run(span + 4 * p, 2 * p);
        });
        assert_eq!(memory.available_bytes.load(Ordering::Acquire), 5 * p);
        // Every run went to the head, the last one first.
        assert_eq!(retype_allocate(&memory, 2 * p), Ok(span + 4 * p));
        assert_eq!(retype_allocate(&memory, p), Ok(span + 2 * p));
        assert_eq!(retype_allocate(&memory, p), Ok(span));
        assert_eq!(
            retype_allocate(&memory, p),
            Err(SyscallError::OutOfMemory),
            "the walk stops at the malformed node"
        );
    }
}
