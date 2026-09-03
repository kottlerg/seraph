// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/cspace.rs

//! Capability space implementation.
//!
//! A [`CSpace`] is a hybrid two-level radix of [`CapabilitySlot`]s. The
//! inline root holds `L1_DIRECT` pointers to leaf [`CSpacePage`]s (the
//! direct region, the first `L1_DIRECT × L2_SIZE` slots) plus
//! `L1_INDIRECT` pointers to pool-allocated [`CSpaceDirPage`]s of
//! `DIR_FANOUT` leaf pointers each (the indirect region). Lookup is O(1):
//! two dereferences in the direct region, three in the indirect. Capacity
//! is bounded only by the pool pages the owner has donated (see Growth
//! below) and the structural ceiling, [`MAX_SLOTS_STRUCTURAL`].
//!
//! ## Free list
//!
//! Freed slots are tracked via an intrusive doubly-linked list encoded in
//! each slot's `deriv_parent` (successor) and `deriv_first_child`
//! (predecessor) fields (see `slot.rs`). Slot 0 is permanently null and is
//! never placed on the free list.
//!
//! ## Growth
//!
//! Leaves are allocated on demand by [`CSpace::grow`], strictly in index
//! order behind the `next_leaf` cursor — allocated leaves are always the
//! contiguous range `0..next_leaf`, so grow is O(1). The first leaf skips
//! slot 0 (always null); every other leaf contributes all [`L2_SIZE`] slots
//! to the free list. A grow into the indirect region first materialises the
//! covering directory page from the same pool; a directory page that
//! outlives a failed leaf allocation stays published — already paid for, it
//! serves the next grow.

// cast_possible_truncation: usize→u32 slot index bounded by MAX_SLOTS_STRUCTURAL.
#![allow(clippy::cast_possible_truncation)]

// `alloc` is needed by the host-test stubs (CSpace::grow heap fallback,
// CSpace::Drop heap reclaim, dummy-object factory). Production CSpace is
// retype-pool-backed end-to-end and does not allocate from the kernel heap.
#[cfg(test)]
extern crate alloc;

#[cfg(test)]
use alloc::boxed::Box;
use core::num::NonZeroU32;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

use super::object::{CSpaceKernelObject, KernelObjectHeader};
use super::slot::{CSpaceId, CapTag, CapabilitySlot, Rights};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Slots per `CSpace` page (56 × 72 B = 4032 B, fits in a 4096-byte slab bin
/// with 64 B of tail slack).
pub const L2_SIZE: usize = 56;

/// Inline root pointers to leaf pages (the direct region).
const L1_DIRECT: usize = 128;

/// Inline root pointers to directory pages (the indirect region).
const L1_INDIRECT: usize = 128;

/// Leaf pointers per pool-allocated directory page (one 4 KiB page of
/// 8-byte pointers).
const DIR_FANOUT: usize = crate::mm::PAGE_SIZE / core::mem::size_of::<*mut CSpacePage>();

/// Maximum leaf pages a `CSpace` can ever hold.
const MAX_LEAVES: usize = L1_DIRECT + L1_INDIRECT * DIR_FANOUT;

/// The directory's structural slot ceiling; see
/// core/kernel/docs/capability-internals.md § Storage: Hybrid Two-Level
/// Radix for the bound's role.
pub const MAX_SLOTS_STRUCTURAL: usize = MAX_LEAVES * L2_SIZE;

// Every slot index must fit in the cap handle's index field; the rest of the
// handle carries the per-slot generation. If the maximum CSpace capacity ever
// exceeds the index field, the encoding would truncate indices — trip at
// compile time instead.
const _: () = assert!(MAX_SLOTS_STRUCTURAL <= (1usize << syscall::CAP_INDEX_BITS));

// The leaf cursor is a u32; the ceiling must fit it.
const _: () = assert!(MAX_LEAVES <= u32::MAX as usize);

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by `CSpace` operations.
#[derive(Debug, PartialEq, Eq)]
pub enum CapError
{
    /// The directory is full: every leaf up to `MAX_LEAVES` is populated
    /// and no free slot remains. A structural ceiling derived from the
    /// directory shape and the cap-handle index width; donating memory
    /// cannot lift it.
    OutOfSlots,
    /// The slot-page pool was exhausted while growing. Refillable: donate
    /// pages via augment-mode `cap_create_cspace`. (Host-test heap path:
    /// heap allocation failed.)
    PoolExhausted,
    /// The provided slot index is out of range or unmapped.
    InvalidIndex,
    /// Mapping request violates the W^X constraint (both writable and executable).
    WxViolation,
}

/// The one canonical `CapError` → `SyscallError` mapping. Every syscall-path
/// consumer routes through this so the pool-exhausted (refillable,
/// `OutOfMemory`) vs structural-ceiling (hard, `QuotaExceeded`) distinction
/// reaches userspace uniformly (#366).
impl From<CapError> for syscall::SyscallError
{
    fn from(e: CapError) -> Self
    {
        match e
        {
            CapError::OutOfSlots => Self::QuotaExceeded,
            CapError::PoolExhausted => Self::OutOfMemory,
            CapError::InvalidIndex => Self::InvalidArgument,
            CapError::WxViolation => Self::WxViolation,
        }
    }
}

// ── CSpacePage ────────────────────────────────────────────────────────────────

/// One page of capability slots.
///
/// Popped from the owning `CSpaceKernelObject`'s growth pool (host tests
/// box one). All-zeros is a valid initial state (every slot is null).
#[repr(C)]
struct CSpacePage
{
    slots: [CapabilitySlot; L2_SIZE],
}

// CSpacePage MUST fit in a single 4 KiB page — `alloc_slot_page` returns
// `PAGE_SIZE`-aligned bytes and the kernel casts that to `*mut CSpacePage`
// expecting one struct per allocation. A regression that grows
// `CapabilitySlot` beyond the headroom would overflow the slab silently;
// the assertion makes that a build error.
const _: () = assert!(
    core::mem::size_of::<CSpacePage>() <= crate::mm::PAGE_SIZE,
    "CSpacePage exceeds PAGE_SIZE — reduce L2_SIZE or shrink CapabilitySlot"
);

// ── CSpaceDirPage ─────────────────────────────────────────────────────────────

/// One pool-allocated directory page of the indirect region: `DIR_FANOUT`
/// leaf-page pointers. All-zeros (every entry null) is the valid initial
/// state. Entries are write-once while the `CSpace` is live: published with
/// Release by [`CSpace::grow`], read with Acquire by the lock-free lookup
/// path.
#[repr(C)]
struct CSpaceDirPage
{
    entries: [AtomicPtr<CSpacePage>; DIR_FANOUT],
}

// A CSpaceDirPage occupies exactly one page — `grow` pops one pool page per
// directory page and casts it wholesale.
const _: () = assert!(core::mem::size_of::<CSpaceDirPage>() == crate::mm::PAGE_SIZE);

// ── CSpace ────────────────────────────────────────────────────────────────────

/// A capability space: a growable indexed collection of capability slots.
///
/// Slots are identified by a `u32` index. Slot 0 is permanently null. Indices
/// are stable for the lifetime of the capability they hold.
///
/// To add a capability: call [`insert_cap`][CSpace::insert_cap].
/// To look up a slot: call [`slot`][CSpace::slot] or [`slot_mut`][CSpace::slot_mut].
///
/// ## Concurrency and memory ordering
///
/// Two lock domains guard disjoint field families:
///
/// - **`CSpace` spinlock** — slot occupancy (tag, rights, badge, object,
///   the `pad` markers), the free list (including the `deriv_*` fields'
///   free-list reuse on Null slots), the directory pointers, and the
///   counters. Syscall paths mutate these through a lock holder's
///   `&mut self`.
/// - **`DERIVATION_LOCK`** — the derivation linkage (`deriv_*`) of
///   *occupied* slots, reached from the derivation code via registry
///   lookup without taking this spinlock (see
///   `derivation::resolve_slot_mut`). Paths that move a slot between the
///   families (free, revoke-collect, teardown) hold `DERIVATION_LOCK`
///   outermost, then this spinlock.
///
/// Both domains reach slots through raw `CSpace` pointers with short,
/// per-slot borrows never held across a foreign-slot access.
///
/// Directory and leaf pointers are **write-once while the `CSpace` is
/// live**: [`grow`][Self::grow] publishes each fully-initialised page with
/// a Release store, and no page is freed, moved, or replaced before
/// refcount-0 teardown. [`slot`][Self::slot] therefore supports lock-free
/// readers (`lookup_cap`, `cap_info`): its Acquire loads at each level
/// pair with grow's Release publication, so a reader that observes a
/// pointer observes the initialised page behind it. Races on slot
/// *content* against such unlocked readers are narrowed — not closed — by
/// the tag and per-slot generation checks at the resolution sites; the
/// residual is confined to threads of the owning process racing each
/// other (see `lookup_cap`'s SAFETY discussion).
pub struct CSpace
{
    id: CSpaceId,
    /// Direct region: inline pointers to the first `L1_DIRECT` leaf
    /// pages. Null = unallocated. Pages come from the retype pool (or the
    /// host heap in the test stub — the `kobj` field discriminates: null =
    /// heap, Drop Box-frees each page; non-null = retype pool,
    /// `dealloc_object(CSpaceObj)` reclaims chunks wholesale).
    direct: [AtomicPtr<CSpacePage>; L1_DIRECT],
    /// Indirect region: inline pointers to pool-allocated directory pages,
    /// each fanning out to `DIR_FANOUT` further leaves. Null =
    /// unallocated.
    indirect: [AtomicPtr<CSpaceDirPage>; L1_INDIRECT],
    /// Grow cursor: leaves `0..next_leaf` are allocated (contiguously);
    /// `next_leaf` is the next leaf `grow` will materialise.
    next_leaf: u32,
    /// Total usable slots allocated across all pages (excludes slot 0).
    allocated_slots: usize,
    /// Head of the intrusive free list; None if no free slots.
    ///
    /// Slot 0 is permanently null and never placed on the free list, so the
    /// head index is always non-zero when present — encoded in the type.
    free_head: Option<NonZeroU32>,
    /// Number of slots currently on the free list (for O(1) `pre_allocate`).
    free_count: usize,
    /// Protects concurrent access to all `CSpace` state.
    pub(crate) lock: crate::sync::Spinlock,
    /// Pool source for new slot and directory pages (pop from
    /// `CSpaceKernelObject::alloc_slot_page`); null only in the host-test
    /// stub, which boxes pages instead. Set once via [`Self::set_kobj`]
    /// right after construction.
    kobj: AtomicPtr<CSpaceKernelObject>,
}

// SAFETY: page pointers are write-once, Release-published after full
// initialisation, and never freed while the CSpace is live; all other state
// is mutated only under `self.lock` (or single-threaded refcount-0
// teardown). Lock-free readers use Acquire loads.
unsafe impl Send for CSpace {}
// SAFETY: see Send impl above.
unsafe impl Sync for CSpace {}

impl CSpace
{
    /// Create an empty `CSpace`. No pages are allocated until the first slot
    /// is requested. The pool source defaults to null (heap path); call
    /// [`Self::set_kobj`] to switch to a retype pool.
    pub fn new(id: CSpaceId) -> Self
    {
        Self {
            id,
            direct: core::array::from_fn(|_| AtomicPtr::new(core::ptr::null_mut())),
            indirect: core::array::from_fn(|_| AtomicPtr::new(core::ptr::null_mut())),
            next_leaf: 0,
            allocated_slots: 0,
            free_head: None,
            free_count: 0,
            lock: crate::sync::Spinlock::new(),
            kobj: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Wire this `CSpace` to a `CSpaceKernelObject`'s slot-page pool.
    ///
    /// MUST be called before any `grow()` if the `CSpace` is retype-backed.
    /// Calling on a `CSpace` that has already grown via the heap path
    /// produces a mixed-allocation directory and is a kernel bug.
    pub fn set_kobj(&self, kobj: *mut CSpaceKernelObject)
    {
        self.kobj.store(kobj, Ordering::Release);
    }

    /// Read the wrapping [`CSpaceKernelObject`] pointer wired by
    /// [`set_kobj`]. Returns `None` for the host-test stub `CSpace`s that
    /// never wire a wrapper. Phase 9 uses this to insert init's `CSpace` cap
    /// without re-allocating a fresh wrapper.
    pub fn kobj_ptr(&self) -> Option<*mut CSpaceKernelObject>
    {
        let p = self.kobj.load(Ordering::Acquire);
        if p.is_null() { None } else { Some(p) }
    }

    /// Return this `CSpace`'s unique identifier.
    pub fn id(&self) -> CSpaceId
    {
        self.id
    }

    /// Allocate a free slot index, growing the `CSpace` if needed.
    ///
    /// Returns [`CapError::OutOfSlots`] if the directory is structurally
    /// full, or [`CapError::PoolExhausted`] if the slot-page pool has no
    /// page left. The returned slot is cleared to null; callers must
    /// populate it.
    ///
    /// The returned index is always non-zero (slot 0 is reserved).
    pub fn allocate_slot(&mut self) -> Result<NonZeroU32, CapError>
    {
        if self.free_head.is_none()
        {
            self.grow()?;
        }

        let idx = self.free_head.ok_or(CapError::OutOfSlots)?;

        // Read next_free through a shared borrow, then drop it before the
        // mutable borrow so the borrow checker is satisfied.
        let next = {
            let slot = self.slot(idx.get()).ok_or(CapError::InvalidIndex)?;
            // The free-time guard prevents an occupied slot from ever entering
            // the list; this catches any other corruption source before we hand
            // the slot out, so `allocate_slot` never returns an occupied slot.
            debug_assert!(
                slot.is_on_free_list(),
                "allocate_slot popped a slot not on the free list"
            );
            slot.next_free()
        };

        self.free_head = next;
        if let Some(new_head) = next
            && let Some(head_slot) = self.slot_mut(new_head.get())
        {
            head_slot.set_prev_free_link(None);
        }
        // Clear the slot (removes free-list encoding) but keep the per-slot
        // generation that `free_slot` left, so the minted cap handle's
        // generation matches the slot the recipient will resolve (#349).
        let slot = self.slot_mut(idx.get()).ok_or(CapError::InvalidIndex)?;
        slot.clear_keep_generation();
        self.free_count -= 1;
        Ok(idx)
    }

    /// Allocate one zeroed backing page for a leaf or directory page.
    ///
    /// Production `CSpace`s are always retype-backed (root via
    /// `boot_retype_cspace`, userspace via `sys_cap_create_cspace`) and pop
    /// from the wrapper's pool; the host-test stub allocates from the heap.
    /// `T` must be a page-sized-or-smaller type whose all-zeros bit pattern
    /// is a valid value (both `CSpacePage` and `CSpaceDirPage` are).
    fn alloc_zeroed_page<T>(&self) -> Result<NonNull<T>, CapError>
    {
        const {
            assert!(
                core::mem::size_of::<T>() <= crate::mm::PAGE_SIZE,
                "alloc_zeroed_page: T exceeds one pool page"
            );
        }
        let kobj_ptr = self.kobj.load(Ordering::Acquire);
        #[cfg(not(test))]
        {
            debug_assert!(
                !kobj_ptr.is_null(),
                "CSpace::alloc_zeroed_page: production CSpace must be retype-backed"
            );
            // SAFETY: kobj_ptr is the wrapper that owns this CSpace; its
            // pool was seeded at retype time.
            let Some(phys) = (unsafe { (*kobj_ptr).alloc_slot_page() })
            else
            {
                crate::kprintln!(
                    "cspace {}: slot-page pool exhausted (allocated={})",
                    self.id,
                    self.allocated_slots
                );
                return Err(CapError::PoolExhausted);
            };
            let virt = crate::mm::paging::phys_to_virt(phys);
            // SAFETY: pool returns page-aligned, freshly-zeroed pages mapped
            // in the kernel direct map; T fits one page and is zero-valid.
            Ok(unsafe { NonNull::new_unchecked(virt as *mut T) })
        }
        #[cfg(test)]
        {
            if kobj_ptr.is_null()
            {
                // Test stub: no retype machinery, allocate via the host
                // heap.
                // SAFETY: the caller's T is zero-valid per the contract.
                let boxed = Box::new(unsafe { core::mem::zeroed::<T>() });
                // SAFETY: Box::into_raw is non-null.
                Ok(unsafe { NonNull::new_unchecked(Box::into_raw(boxed)) })
            }
            else
            {
                Err(CapError::PoolExhausted)
            }
        }
    }

    /// Grow the `CSpace` by one leaf page.
    ///
    /// Materialises leaf `next_leaf`, threads all its slots onto the free
    /// list, publishes it, and advances the cursor. Slot 0 in the first
    /// leaf is skipped. A grow into the indirect region first materialises
    /// the covering directory page from the same pool; if the subsequent
    /// leaf allocation fails, the directory page stays published — already
    /// paid for, it serves the next grow.
    fn grow(&mut self) -> Result<(), CapError>
    {
        let leaf_idx = self.next_leaf as usize;
        if leaf_idx >= MAX_LEAVES
        {
            return Err(CapError::OutOfSlots);
        }

        // Indirect region: ensure the covering directory page exists.
        if leaf_idx >= L1_DIRECT
        {
            let dir_idx = (leaf_idx - L1_DIRECT) / DIR_FANOUT;
            if self.indirect[dir_idx].load(Ordering::Relaxed).is_null()
            {
                let dir_nn: NonNull<CSpaceDirPage> = self.alloc_zeroed_page()?;
                // All-null entries are the valid empty state; the Release
                // publication pairs with the lookup path's Acquire so a
                // lock-free reader never observes uninitialised entries.
                self.indirect[dir_idx].store(dir_nn.as_ptr(), Ordering::Release);
            }
        }

        let mut page_nn: NonNull<CSpacePage> = self.alloc_zeroed_page()?;
        // SAFETY: page_nn points at an exclusively-owned, zeroed CSpacePage
        // not yet published to any reader.
        let page = unsafe { page_nn.as_mut() };

        // Thread the leaf's slots onto the free list BEFORE publication so
        // the Release store below orders the initialised slot bytes ahead
        // of pointer visibility.
        let base = leaf_idx * L2_SIZE;
        let start_slot = usize::from(leaf_idx == 0);
        let mut new_free = 0usize;
        let old_head = self.free_head;
        let mut next = old_head;
        for i in (start_slot..L2_SIZE).rev()
        {
            // `base + i >= 1`: `start_slot` skips slot 0 of the first leaf. A
            // zero index (unreachable) is left off the list — fail closed —
            // rather than threaded as some other slot.
            debug_assert!(base + i >= 1, "grow: slot 0 must not be threaded");
            let Some(idx) = NonZeroU32::new((base + i) as u32)
            else
            {
                continue;
            };
            page.slots[i].set_next_free(next);
            next = Some(idx);
            new_free += 1;
        }
        // Back-fill the predecessor links (the doubly-linked list makes
        // `remove_from_free_list` O(1)): each new slot's successor is the
        // next slot in this page, except the last, whose successor is the
        // old head in a possibly different page — patched below.
        let mut prev: Option<NonZeroU32> = None;
        for i in start_slot..L2_SIZE
        {
            page.slots[i].set_prev_free_link(prev);
            prev = NonZeroU32::new((base + i) as u32);
        }
        self.free_head = next;
        if let Some(old_head_idx) = old_head
        {
            // The old head's predecessor is this page's last slot; it lives
            // in an already-published page, reached via slot_mut.
            let last = prev;
            if let Some(old_head_slot) = self.slot_mut(old_head_idx.get())
            {
                old_head_slot.set_prev_free_link(last);
            }
        }

        // Publish.
        if leaf_idx < L1_DIRECT
        {
            self.direct[leaf_idx].store(page_nn.as_ptr(), Ordering::Release);
        }
        else
        {
            let rel = leaf_idx - L1_DIRECT;
            let dir = self.indirect[rel / DIR_FANOUT].load(Ordering::Relaxed);
            // SAFETY: ensured non-null above under the same lock; directory
            // pages are write-once and never freed while the CSpace lives.
            unsafe {
                (*dir).entries[rel % DIR_FANOUT].store(page_nn.as_ptr(), Ordering::Release);
            }
        }

        self.next_leaf += 1;
        self.allocated_slots += new_free;
        self.free_count += new_free;
        Ok(())
    }

    /// Resolve a leaf index to its page pointer, or `None` if the leaf is
    /// unallocated or out of range.
    ///
    /// Acquire loads at each level pair with [`grow`][Self::grow]'s Release
    /// publications, so a non-null result points at a fully-initialised
    /// page (see the struct's memory-ordering contract).
    fn leaf_ptr(&self, leaf_idx: usize) -> Option<NonNull<CSpacePage>>
    {
        if leaf_idx < L1_DIRECT
        {
            NonNull::new(self.direct[leaf_idx].load(Ordering::Acquire))
        }
        else if leaf_idx < MAX_LEAVES
        {
            let rel = leaf_idx - L1_DIRECT;
            let dir = NonNull::new(self.indirect[rel / DIR_FANOUT].load(Ordering::Acquire))?;
            // SAFETY: directory pages are write-once, Release-published
            // after zero-init, and never freed while the CSpace is live.
            let dir_ref = unsafe { dir.as_ref() };
            NonNull::new(dir_ref.entries[rel % DIR_FANOUT].load(Ordering::Acquire))
        }
        else
        {
            None
        }
    }

    /// Look up a slot by index. Returns `None` if the index is out of range
    /// or the backing page has not been allocated.
    pub fn slot(&self, index: u32) -> Option<&CapabilitySlot>
    {
        let idx = index as usize;
        let page_nn = self.leaf_ptr(idx / L2_SIZE)?;
        // SAFETY: leaf pages are never freed or moved while the CSpace is
        // live; CapabilitySlot is repr(C) and the page bytes belong to this
        // CSpace. Content races are defended by tag/generation checks at
        // every resolution site.
        let page = unsafe { page_nn.as_ref() };
        Some(&page.slots[idx % L2_SIZE])
    }

    /// Mutable variant of [`slot`][Self::slot].
    pub fn slot_mut(&mut self, index: u32) -> Option<&mut CapabilitySlot>
    {
        let idx = index as usize;
        let mut page_nn = self.leaf_ptr(idx / L2_SIZE)?;
        // SAFETY: same as `slot`; `&mut self` comes from the holder of
        // whichever lock domain guards the fields being written (see the
        // struct's concurrency contract).
        let page = unsafe { page_nn.as_mut() };
        Some(&mut page.slots[idx % L2_SIZE])
    }

    /// Number of allocated leaf pages; leaves `0..leaf_count()` are exactly
    /// the allocated ones (the grow cursor keeps them contiguous).
    ///
    /// Used by the pre-unregister derivation drain in
    /// `dealloc_object(CSpaceObj)` to bound its walk of the dying `CSpace`.
    pub(crate) fn leaf_count(&self) -> usize
    {
        self.next_leaf as usize
    }

    /// Pool pages a grow to cover `index`'s leaf would consume: the
    /// missing leaves plus the missing directory pages over that span.
    /// Zero when the covering leaf already exists; also zero for an
    /// out-of-range index (the placement path rejects it instead).
    ///
    /// Callers use this to fail a doomed explicit placement fast, before
    /// any pool page is consumed.
    pub(crate) fn pages_to_cover(&self, index: u32) -> u64
    {
        let target_leaf = index as usize / L2_SIZE;
        let next = self.next_leaf as usize;
        if target_leaf < next || target_leaf >= MAX_LEAVES
        {
            return 0;
        }
        let leaves = (target_leaf + 1 - next) as u64;
        let mut dirs = 0u64;
        if target_leaf >= L1_DIRECT
        {
            let first = (next.max(L1_DIRECT) - L1_DIRECT) / DIR_FANOUT;
            let last = (target_leaf - L1_DIRECT) / DIR_FANOUT;
            for d in first..=last
            {
                if self.indirect[d].load(Ordering::Relaxed).is_null()
                {
                    dirs += 1;
                }
            }
        }
        leaves + dirs
    }

    /// Grow toward covering `index`'s leaf, materialising at most
    /// `max_leaves` leaves in this call. Returns `Ok(true)` once the
    /// covering leaf exists. Lets the explicit-placement syscall path
    /// pre-grow in bounded batches under only this `CSpace`'s lock,
    /// keeping each interrupts-off hold constant-sized. An `index` beyond
    /// the structural ceiling is clamped to the last leaf: the caller
    /// rejects such an index up front (`pages_to_cover`), so the clamp
    /// only keeps this function total.
    pub(crate) fn grow_toward(&mut self, index: u32, max_leaves: usize) -> Result<bool, CapError>
    {
        let target_leaf = (index as usize / L2_SIZE).min(MAX_LEAVES - 1);
        let mut grown = 0usize;
        while (self.next_leaf as usize) <= target_leaf
        {
            if grown >= max_leaves
            {
                return Ok(false);
            }
            self.grow()?;
            grown += 1;
        }
        Ok(true)
    }

    /// Return a slot to the free list and clear its contents.
    ///
    /// Silently ignores an out-of-range, unmapped, or zero index.
    ///
    /// Callers freeing an occupied slot MUST hold `DERIVATION_LOCK` around
    /// the free (in addition to this `CSpace`'s spinlock): the derivation
    /// code's occupancy gate (`resolve_slot_mut`) relies on
    /// occupied-to-free transitions being excluded while it holds that
    /// lock.
    ///
    /// Rejects a double-free of any slot: [`CapabilitySlot::is_on_free_list`]
    /// is true for every slot currently linked on the list (head, interior, or
    /// tail), so re-freeing one is detected and dropped. Pushing an already-on-
    /// list slot would splice it in a second time, creating a cycle the next
    /// `allocate_slot` would walk into — handing out an occupied slot. A Null
    /// tag alone is not enough to detect this (`allocate_slot` clears the slot
    /// on pop, so a freshly-allocated, not-yet-populated slot is also Null);
    /// the free-list marker is the discriminator.
    pub fn free_slot(&mut self, index: u32)
    {
        let Some(nz_index) = NonZeroU32::new(index)
        else
        {
            return;
        };
        let old_head = self.free_head;
        let Some(slot) = self.slot_mut(index)
        else
        {
            return;
        };
        if slot.is_on_free_list()
        {
            #[cfg(not(test))]
            crate::kprintln!(
                "free_slot: double-free index={} ignored (already on free list)",
                index
            );
            return;
        }
        // Bump the per-slot generation before returning the slot to the free
        // list (the legitimate-free path only — the double-free guard above
        // returns without bumping). Every outstanding handle to the prior
        // occupant now carries a stale generation and fails lookup_cap (#349).
        slot.bump_generation();
        slot.set_next_free(old_head);
        self.free_head = Some(nz_index);
        if let Some(old_head_idx) = old_head
            && let Some(old_head_slot) = self.slot_mut(old_head_idx.get())
        {
            old_head_slot.set_prev_free_link(Some(nz_index));
        }
        self.free_count += 1;
    }

    /// Allocate a slot, populate it with the given capability, and return the
    /// slot index.
    ///
    /// The returned index is always non-zero (inherited from `allocate_slot`).
    pub fn insert_cap(
        &mut self,
        tag: CapTag,
        rights: Rights,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<NonZeroU32, CapError>
    {
        let index = self.allocate_slot()?;

        // SAFETY: allocate_slot returned a valid index into an allocated page.
        let slot = self.slot_mut(index.get()).ok_or(CapError::InvalidIndex)?;
        slot.tag = tag;
        slot.rights = rights;
        slot.badge = 0;
        slot.object = Some(object);
        slot.deriv_parent = None;
        slot.deriv_first_child = None;
        slot.deriv_next_sibling = None;
        slot.deriv_prev_sibling = None;

        Ok(index)
    }

    /// Encode the cap handle (per-slot generation + slot index) for `index`.
    ///
    /// Call right after inserting a cap at `index`, under the `CSpace` lock, to
    /// build the handle returned to userspace. Reads the slot's current
    /// generation and packs it with the index per [`syscall::cap_handle_encode`];
    /// a never-recycled slot has generation 0, so the handle equals the bare
    /// index. Returns the bare index if the slot is somehow absent.
    pub fn cap_handle(&self, index: NonZeroU32) -> u32
    {
        let generation = self
            .slot(index.get())
            .map_or(0, super::slot::CapabilitySlot::generation);
        syscall::cap_handle_encode(index.get(), generation)
    }

    /// Allocate a slot, populate it, and return the encoded cap handle.
    ///
    /// Convenience over [`insert_cap`](Self::insert_cap) +
    /// [`cap_handle`](Self::cap_handle) for the common mint path: the
    /// generation read happens under the same `&mut self` the caller already
    /// holds the `CSpace` lock for, so no separate locked read is needed.
    pub fn insert_cap_handle(
        &mut self,
        tag: CapTag,
        rights: Rights,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<u32, CapError>
    {
        let index = self.insert_cap(tag, rights, object)?;
        Ok(self.cap_handle(index))
    }

    /// [`insert_cap`](Self::insert_cap) with the tag derived from the typed
    /// rights argument, so a mint site cannot pair a tag with another type's
    /// rights. Use for static mints; dynamic restamp paths (copy/move/derive)
    /// keep the untyped API.
    pub fn insert_cap_typed<K: super::slot::CapKind>(
        &mut self,
        rights: super::slot::TypedRights<K>,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<NonZeroU32, CapError>
    {
        self.insert_cap(K::TAG, rights.erase(), object)
    }

    /// [`insert_cap_handle`](Self::insert_cap_handle) with the tag derived
    /// from the typed rights argument; see
    /// [`insert_cap_typed`](Self::insert_cap_typed).
    pub fn insert_cap_handle_typed<K: super::slot::CapKind>(
        &mut self,
        rights: super::slot::TypedRights<K>,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<u32, CapError>
    {
        self.insert_cap_handle(K::TAG, rights.erase(), object)
    }

    /// Grow the `CSpace` until at least `min_free` slots are available without
    /// a further grow. Used to pre-warm the free list before bulk insertions.
    pub fn pre_allocate(&mut self, min_free: usize) -> Result<(), CapError>
    {
        while self.free_count < min_free
        {
            self.grow()?;
        }
        Ok(())
    }

    /// Remove a specific slot index from the free list.
    ///
    /// Returns `true` if the index was found and removed, `false` if not on the list.
    ///
    /// O(1): the free list is doubly linked (successor in `deriv_parent`,
    /// predecessor in `deriv_first_child`), so the splice reads the target's
    /// two neighbours directly. Callers (`insert_cap_at` explicit
    /// placement) run under the `CSpace` spinlock with interrupts disabled,
    /// which is why a list walk is not acceptable here.
    pub fn remove_from_free_list(&mut self, target: u32) -> bool
    {
        let Some(target_nz) = NonZeroU32::new(target)
        else
        {
            return false;
        };
        let (prev, next) = match self.slot(target)
        {
            Some(slot) if slot.is_on_free_list() => (slot.prev_free(), slot.next_free()),
            _ => return false,
        };
        debug_assert_eq!(
            prev.is_none(),
            self.free_head == Some(target_nz),
            "free-list head/prev disagreement"
        );
        match prev
        {
            None => self.free_head = next,
            Some(p) =>
            {
                if let Some(prev_slot) = self.slot_mut(p.get())
                {
                    prev_slot.set_next_free_link(next);
                }
            }
        }
        if let Some(n) = next
            && let Some(next_slot) = self.slot_mut(n.get())
        {
            next_slot.set_prev_free_link(prev);
        }
        self.free_count -= 1;
        // Drop the free-list marker so the unlinked slot is canonical
        // off-list (same state as an `allocate_slot` pop). Keep the
        // generation so a cap later placed here via insert_cap_at carries
        // the recycled slot's generation (#349).
        if let Some(slot) = self.slot_mut(target)
        {
            slot.clear_keep_generation();
        }
        true
    }

    /// Insert a capability at a caller-chosen slot index.
    ///
    /// Used by `SYS_CAP_COPY`'s explicit-slot path (non-zero destination slot)
    /// to place a cap at a well-known index (e.g., init populating a child's
    /// `CSpace`). The target slot must currently be Null.
    ///
    /// # Errors
    ///
    /// - [`CapError::InvalidIndex`] — index is 0, out of range, or occupied.
    /// - [`CapError::PoolExhausted`] — slot-page pool empty during grow.
    pub fn insert_cap_at(
        &mut self,
        index: u32,
        tag: CapTag,
        rights: Rights,
        object: core::ptr::NonNull<KernelObjectHeader>,
    ) -> Result<(), CapError>
    {
        if index == 0
        {
            return Err(CapError::InvalidIndex); // slot 0 is permanently null
        }

        // Reject indices beyond the directory's structural ceiling.
        //
        // Below the ceiling, the grow loop that follows allocates every
        // intermediate page up to the chosen index — bounded by the
        // destination CSpace's donated pool, which is the intended bound:
        // whoever funded that pool pays for the intervening pages.
        if index as usize >= MAX_SLOTS_STRUCTURAL
        {
            return Err(CapError::InvalidIndex);
        }

        // Ensure the leaf covering this index is allocated. Leaves are
        // contiguous behind the grow cursor, so every intermediate leaf up
        // to the target is materialised on the way. Syscall paths pre-grow
        // in bounded batches (`pre_grow_for_explicit_slot`) before taking
        // the heavyweight locks, so this loop is a zero-iteration backstop
        // for them (`sys_cap_copy` and `sys_cap_move` are the only callers).
        let leaf_idx = index as usize / L2_SIZE;
        while (self.next_leaf as usize) <= leaf_idx
        {
            self.grow()?;
        }

        // Verify slot is currently Null (free).
        {
            let slot = self.slot(index).ok_or(CapError::InvalidIndex)?;
            if !slot.is_null()
            {
                return Err(CapError::InvalidIndex);
            }
        }

        // Remove from free list (may or may not be on it if page was just grown).
        self.remove_from_free_list(index);

        // Populate the slot.
        let slot = self.slot_mut(index).ok_or(CapError::InvalidIndex)?;
        slot.tag = tag;
        slot.rights = rights;
        slot.badge = 0;
        slot.object = Some(object);
        slot.deriv_parent = None;
        slot.deriv_first_child = None;
        slot.deriv_next_sibling = None;
        slot.deriv_prev_sibling = None;

        Ok(())
    }

    /// Count the number of non-null (occupied) slots.
    ///
    /// O(1): derived from `allocated_slots - free_count`.
    pub fn populated_count(&self) -> usize
    {
        self.allocated_slots - self.free_count
    }

    /// Total usable slots allocated across all pages (excludes slot 0).
    ///
    /// Used by `SYS_CAP_INFO`'s `CAP_INFO_CSPACE_CAPACITY` handler, which
    /// reports the currently-backed capacity: this count plus what the
    /// remaining growth-budget pages would add.
    pub fn allocated_slots(&self) -> usize
    {
        self.allocated_slots
    }

    /// Call `f` for each non-null slot's kernel object pointer.
    ///
    /// Used by `dealloc_object(CSpaceObj)` to dec-ref all objects before
    /// the `CSpace` pages are freed. Skips slot 0 (permanently null) and
    /// unallocated pages.
    pub fn for_each_object<F>(&self, mut f: F)
    where
        F: FnMut(NonNull<KernelObjectHeader>),
    {
        for leaf_idx in 0..self.next_leaf as usize
        {
            if let Some(page_nn) = self.leaf_ptr(leaf_idx)
            {
                // SAFETY: page_nn is owned by this CSpace and not aliased
                // outside the lock.
                let page = unsafe { page_nn.as_ref() };
                let start = usize::from(leaf_idx == 0);
                for slot_idx in start..L2_SIZE
                {
                    let slot = &page.slots[slot_idx];
                    if slot.tag != CapTag::Null
                        && let Some(obj) = slot.object
                    {
                        f(obj);
                    }
                }
            }
        }
    }
}

impl Drop for CSpace
{
    /// Production `CSpace` is always retype-backed: pages live inside chunks
    /// tracked by [`CSpaceKernelObject`] which `dealloc_object(CSpaceObj)`
    /// reclaims wholesale via `retype_free`. Drop is a no-op so we don't
    /// double-free pool pages through the global allocator.
    ///
    /// The host-test stubs allocate `CSpace` directly without wiring a
    /// `kobj`; in that build, Drop reconstructs each leaked `Box` to return
    /// pages to the host heap so unit tests do not leak.
    fn drop(&mut self)
    {
        #[cfg(test)]
        {
            if self.kobj.load(Ordering::Acquire).is_null()
            {
                for entry in &self.direct
                {
                    let p = entry.swap(core::ptr::null_mut(), Ordering::AcqRel);
                    if !p.is_null()
                    {
                        // SAFETY: test stub: p came from Box::into_raw via
                        // alloc_zeroed_page's heap branch.
                        unsafe { drop(Box::from_raw(p)) };
                    }
                }
                for entry in &self.indirect
                {
                    let dir = entry.swap(core::ptr::null_mut(), Ordering::AcqRel);
                    if dir.is_null()
                    {
                        continue;
                    }
                    // SAFETY: dir came from Box::into_raw; its entries hold
                    // leaf pages from the same heap branch.
                    unsafe {
                        for leaf in &(*dir).entries
                        {
                            let p = leaf.swap(core::ptr::null_mut(), Ordering::AcqRel);
                            if !p.is_null()
                            {
                                drop(Box::from_raw(p));
                            }
                        }
                        drop(Box::from_raw(dir));
                    }
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cap::object::{KernelObjectHeader, MemoryObject, ObjectType};
    use crate::cap::slot::MemRights;
    use core::ptr::NonNull;

    /// Construct a dummy NonNull<KernelObjectHeader> backed by a leaked Box
    /// so tests don't need unsafe pointer arithmetic.
    fn dummy_object() -> NonNull<KernelObjectHeader>
    {
        let obj = Box::new(MemoryObject {
            header: KernelObjectHeader::new(ObjectType::Memory),
            base: 0,
            size: 0x1000,
            available_bytes: core::sync::atomic::AtomicU64::new(0),
            owns_memory: core::sync::atomic::AtomicBool::new(false),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        let raw = Box::into_raw(obj) as *mut KernelObjectHeader;
        // SAFETY: Box::into_raw never returns null.
        unsafe { NonNull::new_unchecked(raw) }
    }

    #[test]
    fn new_cspace_is_empty()
    {
        let cs = CSpace::new(0);
        assert_eq!(cs.populated_count(), 0);
        assert_eq!(cs.allocated_slots, 0);
    }

    #[test]
    fn slot_zero_is_null()
    {
        let mut cs = CSpace::new(0);
        // Force page 0 to be allocated by requesting slot 1.
        let _idx = cs.allocate_slot().unwrap();
        // Slot 0 must exist and be null.
        let s = cs.slot(0).expect("slot 0 should exist after grow");
        assert!(s.is_null());
    }

    #[test]
    fn allocate_returns_nonzero_index()
    {
        let mut cs = CSpace::new(0);
        let _idx = cs.allocate_slot().unwrap();
    }

    #[test]
    fn allocate_and_lookup_round_trip()
    {
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        let idx = cs
            .insert_cap_typed(MemRights::MAP | MemRights::WRITE, obj)
            .unwrap();
        let slot = cs.slot(idx.get()).unwrap();
        assert_eq!(slot.tag, CapTag::Memory);
        assert!(slot.rights.contains(MemRights::MAP.erase()));
        assert!(slot.rights.contains(MemRights::WRITE.erase()));
        assert_eq!(slot.object, Some(obj));
    }

    #[test]
    fn growth_across_l2_boundary()
    {
        // Allocate L2_SIZE - 1 slots (page 0 has 55 usable slots after skipping 0).
        let mut cs = CSpace::new(0);
        let mut indices = Vec::new();
        for _ in 0..(L2_SIZE - 1)
        {
            indices.push(cs.allocate_slot().unwrap());
        }
        // Next allocation must cross into page 1.
        let idx = cs.allocate_slot().unwrap();
        assert!(
            idx.get() as usize >= L2_SIZE,
            "expected index in page 1 or beyond"
        );
        assert!(!indices.contains(&idx));
    }

    #[test]
    fn free_and_reallocate()
    {
        let mut cs = CSpace::new(0);
        let idx1 = cs.allocate_slot().unwrap();
        cs.free_slot(idx1.get());
        // After freeing, the next allocate should return the same index.
        let idx2 = cs.allocate_slot().unwrap();
        assert_eq!(idx1, idx2, "freed slot should be reused");
    }

    #[test]
    fn pool_exhaustion_is_distinct()
    {
        // A retype-backed CSpace (non-null kobj) with no pool page left
        // fails grow with PoolExhausted, not the structural OutOfSlots.
        // The test-mode grow path returns before dereferencing the kobj
        // pointer, so a dangling marker stands in for a real wrapper.
        let mut cs = CSpace::new(0);
        cs.set_kobj(NonNull::dangling().as_ptr());
        let err = cs.allocate_slot().unwrap_err();
        assert_eq!(err, CapError::PoolExhausted);
    }

    #[test]
    fn write_execute_cap_allowed()
    {
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        let slot = cs
            .insert_cap_typed(MemRights::WRITE | MemRights::EXECUTE, obj)
            .expect("WRITE|EXECUTE cap should be allowed at cap level");
        let s = cs.slot(slot.get()).unwrap();
        assert!(
            s.rights
                .contains((MemRights::WRITE | MemRights::EXECUTE).erase())
        );
    }

    #[test]
    fn pre_allocate_succeeds()
    {
        let mut cs = CSpace::new(0);
        cs.pre_allocate(10).unwrap();
        assert!(cs.free_count >= 10);
    }

    #[test]
    fn populated_count_tracks_inserts()
    {
        let mut cs = CSpace::new(0);
        assert_eq!(cs.populated_count(), 0);
        let obj = dummy_object();
        cs.insert_cap_typed(MemRights::MAP, obj).unwrap();
        assert_eq!(cs.populated_count(), 1);
    }

    #[test]
    fn free_list_prioritized_over_new_slots()
    {
        // Allocate 3 slots; free the first; verify next alloc reuses it rather
        // than consuming a brand-new slot beyond the current high-water mark.
        let mut cs = CSpace::new(0);
        let s1 = cs.allocate_slot().unwrap();
        let s2 = cs.allocate_slot().unwrap();
        let s3 = cs.allocate_slot().unwrap();

        cs.free_slot(s1.get());

        // Must return s1 (from free list), not a fresh slot past s3.
        let s4 = cs.allocate_slot().unwrap();
        assert_eq!(
            s4, s1,
            "free list entry must be reused before consuming new slot space"
        );
        assert_ne!(
            s4.get(),
            s3.get() + 1,
            "should not allocate a brand-new slot when free list is non-empty"
        );
        let _ = (s2, s3);
    }

    #[test]
    fn populated_count_accurate_after_repeated_inserts()
    {
        // populated_count must increment by exactly 1 for each successful insert.
        let mut cs = CSpace::new(0);
        let obj = dummy_object();

        for expected in 1..=5usize
        {
            cs.insert_cap_typed(MemRights::MAP, obj).unwrap();
            assert_eq!(
                cs.populated_count(),
                expected,
                "populated_count should be {} after {} inserts",
                expected,
                expected
            );
        }
    }

    #[test]
    fn insert_cap_at_grows_to_high_index()
    {
        // Placing a cap at index 200 (page 3) on a fresh CSpace must grow
        // every intermediate page and land the cap at exactly that slot.
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        cs.insert_cap_at(200, CapTag::Memory, MemRights::MAP.erase(), obj)
            .expect("insert_cap_at(200) on a fresh CSpace failed");
        let slot = cs.slot(200).expect("slot 200 unmapped after insert");
        assert_eq!(slot.tag, CapTag::Memory);
        assert_eq!(slot.object, Some(obj));
        // Pages 0..=3 allocated: 55 + 3 * 56 usable slots.
        assert_eq!(cs.allocated_slots, (L2_SIZE - 1) + 3 * L2_SIZE);
        assert_eq!(cs.populated_count(), 1);
    }

    #[test]
    fn insert_cap_at_rejects_out_of_range_indices()
    {
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        let err = cs
            .insert_cap_at(
                MAX_SLOTS_STRUCTURAL as u32,
                CapTag::Memory,
                MemRights::MAP.erase(),
                obj,
            )
            .unwrap_err();
        assert_eq!(err, CapError::InvalidIndex);
        let err = cs
            .insert_cap_at(0, CapTag::Memory, MemRights::MAP.erase(), obj)
            .unwrap_err();
        assert_eq!(err, CapError::InvalidIndex);
        assert_eq!(cs.allocated_slots, 0, "rejected inserts must not grow");
    }

    #[test]
    fn insert_cap_at_rejects_occupied_slot()
    {
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        cs.insert_cap_at(5, CapTag::Memory, MemRights::MAP.erase(), obj)
            .expect("first insert at slot 5 failed");
        let err = cs
            .insert_cap_at(5, CapTag::Memory, MemRights::MAP.erase(), obj)
            .unwrap_err();
        assert_eq!(err, CapError::InvalidIndex, "occupied slot must reject");
        assert_eq!(cs.populated_count(), 1, "the live cap must be untouched");
    }

    #[test]
    fn structural_ceiling_returns_out_of_slots()
    {
        // Filling all 3.6M slots is not host-viable (~270 MiB of pages);
        // force the grow cursor to the ceiling instead — with an empty free
        // list, the next allocation's grow must fail with the structural
        // OutOfSlots, not PoolExhausted.
        let mut cs = CSpace::new(0);
        cs.next_leaf = MAX_LEAVES as u32;
        let err = cs.allocate_slot().unwrap_err();
        assert_eq!(err, CapError::OutOfSlots);
    }

    #[test]
    fn growth_crosses_direct_indirect_boundary()
    {
        // Exhaust the direct region (128 leaves x 56 slots, minus reserved
        // slot 0), then verify the next allocation materialises the first
        // indirect leaf — directory page included — and that slots on both
        // sides of the boundary round-trip.
        let mut cs = CSpace::new(0);
        let direct_slots = L1_DIRECT * L2_SIZE - 1;
        let mut last_direct = 0u32;
        for i in 0..direct_slots
        {
            let idx = cs
                .allocate_slot()
                .unwrap_or_else(|e| panic!("direct-region allocation {i} failed: {e:?}"));
            last_direct = idx.get();
        }
        assert!(
            (last_direct as usize) < L1_DIRECT * L2_SIZE,
            "direct region overflowed early"
        );
        assert_eq!(cs.next_leaf as usize, L1_DIRECT);

        // Crossing allocation: leaf 128, the first indirect leaf.
        let obj = dummy_object();
        let idx = cs
            .insert_cap_typed(MemRights::MAP, obj)
            .expect("first indirect-region insert failed");
        assert!(
            idx.get() as usize >= L1_DIRECT * L2_SIZE,
            "expected an index in the indirect region"
        );
        let slot = cs.slot(idx.get()).expect("indirect slot unmapped");
        assert_eq!(slot.tag, CapTag::Memory);
        assert_eq!(slot.object, Some(obj));

        // A direct-region slot still resolves after the boundary crossing.
        assert!(cs.slot(1).is_some(), "direct-region slot lost");

        // Deep explicit placement drives the cursor further into the
        // indirect region through the same contiguous-grow path.
        cs.insert_cap_at(8000, CapTag::Memory, MemRights::MAP.erase(), obj)
            .expect("insert_cap_at(8000) failed");
        let deep = cs.slot(8000).expect("slot 8000 unmapped");
        assert_eq!(deep.object, Some(obj));
        assert_eq!(cs.next_leaf as usize, 8000 / L2_SIZE + 1);
        assert_eq!(cs.populated_count(), direct_slots + 2);
    }

    #[test]
    fn pages_to_cover_counts_leaves_and_dir_pages()
    {
        let mut cs = CSpace::new(0);
        // Fresh CSpace, direct-region target: leaves only.
        assert_eq!(cs.pages_to_cover(0), 1, "slot 0 needs leaf 0");
        assert_eq!(cs.pages_to_cover((L2_SIZE - 1) as u32), 1);
        assert_eq!(cs.pages_to_cover((3 * L2_SIZE) as u32), 4, "leaves 0..=3");
        // First indirect target: all 129 leaves plus one directory page.
        assert_eq!(
            cs.pages_to_cover((L1_DIRECT * L2_SIZE) as u32),
            (L1_DIRECT + 1) as u64 + 1
        );
        // Out of range: zero (the placement path rejects instead).
        assert_eq!(cs.pages_to_cover(MAX_SLOTS_STRUCTURAL as u32), 0);
        // Already covered after an allocation.
        cs.allocate_slot().unwrap();
        assert_eq!(cs.pages_to_cover(1), 0);
        // Second target under an already-materialised directory page costs
        // only the missing leaves.
        cs.insert_cap_at(
            (L1_DIRECT * L2_SIZE) as u32,
            CapTag::Memory,
            MemRights::MAP.erase(),
            dummy_object(),
        )
        .expect("indirect placement failed");
        assert_eq!(
            cs.pages_to_cover(((L1_DIRECT + 2) * L2_SIZE) as u32),
            2,
            "existing dir page must not be re-counted"
        );
    }

    #[test]
    fn grow_toward_batches_and_completes()
    {
        let mut cs = CSpace::new(0);
        // Target leaf 9 with a 4-leaf batch: two partial calls, then done.
        let target = (9 * L2_SIZE) as u32;
        assert_eq!(cs.grow_toward(target, 4).unwrap(), false);
        assert_eq!(cs.leaf_count(), 4);
        assert_eq!(cs.grow_toward(target, 4).unwrap(), false);
        assert_eq!(cs.leaf_count(), 8);
        assert_eq!(cs.grow_toward(target, 4).unwrap(), true);
        assert_eq!(cs.leaf_count(), 10);
        // Covered target: immediate true, no growth.
        assert_eq!(cs.grow_toward(target, 0).unwrap(), true);
        assert_eq!(cs.leaf_count(), 10);
    }

    #[test]
    fn remove_from_free_list_all_positions()
    {
        let mut cs = CSpace::new(0);
        // Materialise the first page; free list = slots 1..=55 in order.
        cs.allocate_slot().unwrap();
        cs.free_slot(1);
        let initial_free = cs.free_count;

        // Not on the list: slot 0 (permanently null, never linked) and an
        // out-of-range index.
        assert!(!cs.remove_from_free_list(0));
        assert!(!cs.remove_from_free_list(999_999));

        // Head removal (slot 1 was pushed last, so it is the head).
        assert!(cs.remove_from_free_list(1));
        assert_ne!(cs.free_head, NonZeroU32::new(1));

        // Interior removal.
        assert!(cs.remove_from_free_list(30));
        // Tail removal (slot 55 is the deepest of the original threading).
        assert!(cs.remove_from_free_list(55));
        // Double removal: no longer on the list.
        assert!(!cs.remove_from_free_list(30));
        assert_eq!(cs.free_count, initial_free - 3);

        // Drain exactly the remaining free entries; every pop must be
        // unique and none may be a removed index — proving the doubly-
        // linked splices left a consistent list.
        let mut seen = Vec::new();
        for _ in 0..cs.free_count
        {
            let idx = cs.allocate_slot().expect("free list drained early");
            assert!(!seen.contains(&idx), "duplicate index from free list");
            assert!(
                ![1u32, 30, 55].contains(&idx.get()),
                "removed index resurfaced on the free list"
            );
            seen.push(idx);
        }
        assert!(cs.free_head.is_none());
    }

    #[test]
    fn double_free_non_head_does_not_corrupt_freelist()
    {
        let mut cs = CSpace::new(0);
        let a = cs.allocate_slot().unwrap();
        let b = cs.allocate_slot().unwrap();
        let c = cs.allocate_slot().unwrap();

        // Build a multi-entry free list: head = a -> b -> c -> (rest).
        cs.free_slot(c.get());
        cs.free_slot(b.get());
        cs.free_slot(a.get());
        assert_eq!(cs.free_head, Some(a), "a should be the free-list head");

        let free_before = cs.free_count;
        // Double-free a NON-head slot (b; the head is a). The old head-only
        // guard missed this and spliced b in a second time, cycling the list.
        cs.free_slot(b.get());
        assert_eq!(
            cs.free_count, free_before,
            "non-head double-free must be rejected, not re-pushed"
        );

        // Drain exactly the free list (stopping before allocate_slot would
        // grow a fresh page). A cycle would hand out a duplicate index
        // within these pops; every popped index must be unique.
        let mut seen = Vec::new();
        for _ in 0..free_before
        {
            let idx = cs.allocate_slot().expect("free list drained early");
            assert!(
                !seen.contains(&idx),
                "allocate_slot returned duplicate index {} — free list corrupted",
                idx.get()
            );
            seen.push(idx);
        }
        assert!(
            cs.free_head.is_none(),
            "free list must be empty after draining free_count entries"
        );
    }
}
