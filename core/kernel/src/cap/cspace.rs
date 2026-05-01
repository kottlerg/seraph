// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/cspace.rs

//! Capability space implementation.
//!
//! A [`CSpace`] is a two-level directory of [`CapabilitySlot`]s. The directory
//! has [`L1_SIZE`] entries; each points to a [`CSpacePage`] containing
//! [`L2_SIZE`] slots. Maximum capacity: `L1_SIZE * L2_SIZE = 16384` slots.
//!
//! ## Free list
//!
//! Freed slots are tracked via an intrusive singly-linked list encoded in each
//! slot's `deriv_parent` field (see `slot.rs`). Slot 0 is permanently null and
//! is never placed on the free list.
//!
//! ## Growth
//!
//! `CSpace` pages are allocated on demand by [`CSpace::grow`]. The first page
//! skips slot 0 (always null); subsequent pages contribute all 64 slots to the
//! free list.

// cast_possible_truncation: usize→u32 slot index bounded by L1_SIZE * L2_SIZE (16384).
#![allow(clippy::cast_possible_truncation)]

// In no_std builds alloc must be declared explicitly; std builds include it implicitly.
extern crate alloc;

use alloc::boxed::Box;
use core::num::NonZeroU32;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

use super::object::{CSpaceKernelObject, KernelObjectHeader};
use super::slot::{CSpaceId, CapTag, CapabilitySlot, Rights};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Slots per `CSpace` page (64 × 56 B = 3584 B, fits in a 4096-byte slab bin).
pub const L2_SIZE: usize = 64;

/// Directory entries per `CSpace` (max 256 × 64 = 16384 slots).
pub const L1_SIZE: usize = 256;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by `CSpace` operations.
#[derive(Debug, PartialEq, Eq)]
pub enum CapError
{
    /// No free slots remain and the `CSpace` is at `max_slots`.
    OutOfSlots,
    /// Heap allocation failed while growing the `CSpace`.
    OutOfMemory,
    /// The provided slot index is out of range or unmapped.
    InvalidIndex,
    /// Mapping request violates the W^X constraint (both writable and executable).
    WxViolation,
}

// ── CSpacePage ────────────────────────────────────────────────────────────────

/// One page of capability slots.
///
/// Allocated either from the kernel heap (legacy bootstrap path) or popped
/// from the parent `CSpaceKernelObject`'s growth pool (typed-memory path).
/// All-zeros is a valid initial state (every slot is null).
#[repr(C)]
struct CSpacePage
{
    slots: [CapabilitySlot; L2_SIZE],
}

// ── CSpace ────────────────────────────────────────────────────────────────────

/// A capability space: a growable indexed collection of capability slots.
///
/// Slots are identified by a `u32` index. Slot 0 is permanently null. Indices
/// are stable for the lifetime of the capability they hold.
///
/// To add a capability: call [`insert_cap`][CSpace::insert_cap].
/// To look up a slot: call [`slot`][CSpace::slot] or [`slot_mut`][CSpace::slot_mut].
///
/// ## Concurrency
///
/// All operations are protected by an internal spinlock to allow safe
/// concurrent access from multiple CPUs (e.g., parent inserting caps into
/// child's `CSpace` while child accesses it). External callers of `slot()` and
/// `slot_mut()` automatically acquire the lock. Internal helpers use unlocked
/// accessors when the lock is already held.
pub struct CSpace
{
    id: CSpaceId,
    /// Two-level directory; each Some entry is a 64-slot page.
    /// Pages are stored as raw `NonNull` pointers so the heap-backed and
    /// retype-pool-backed paths can coexist with different reclamation
    /// semantics. The `kobj` field discriminates: null = heap (Drop walks
    /// the directory and Box-frees each page); non-null = retype pool
    /// (`dealloc_object(CSpaceObj)` reclaims chunks wholesale).
    directory: [Option<NonNull<CSpacePage>>; L1_SIZE],
    /// Total usable slots allocated across all pages (excludes slot 0).
    allocated_slots: usize,
    /// Maximum number of usable slots this `CSpace` may hold.
    max_slots: usize,
    /// Head of the intrusive free list; None if no free slots.
    ///
    /// Slot 0 is permanently null and never placed on the free list, so the
    /// head index is always non-zero when present — encoded in the type.
    free_head: Option<NonZeroU32>,
    /// Number of slots currently on the free list (for O(1) `pre_allocate`).
    free_count: usize,
    /// Protects concurrent access to all `CSpace` state.
    pub(crate) lock: crate::sync::Spinlock,
    /// Pool source for new slot pages. Null = legacy heap path
    /// (`Box::leak` from kernel heap); non-null = retype-pool path
    /// (pop from `CSpaceKernelObject::alloc_slot_page`). Set once via
    /// [`Self::set_kobj`] right after construction.
    kobj: AtomicPtr<CSpaceKernelObject>,
}

// SAFETY: NonNull<CSpacePage> entries are accessed only under `self.lock`
// or after the CSpace has reached refcount 0 (single-threaded teardown).
unsafe impl Send for CSpace {}
// SAFETY: see Send impl above.
unsafe impl Sync for CSpace {}

impl CSpace
{
    /// Create an empty `CSpace`. No pages are allocated until the first slot
    /// is requested. The pool source defaults to null (heap path); call
    /// [`Self::set_kobj`] to switch to a retype pool.
    pub fn new(id: CSpaceId, max_slots: usize) -> Self
    {
        Self {
            id,
            directory: core::array::from_fn(|_| None),
            allocated_slots: 0,
            max_slots,
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

    /// Return this `CSpace`'s unique identifier.
    pub fn id(&self) -> CSpaceId
    {
        self.id
    }

    /// Allocate a free slot index, growing the `CSpace` if needed.
    ///
    /// Returns an error if `max_slots` is reached or heap allocation fails.
    /// The returned slot is cleared to null; callers must populate it.
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
            slot.next_free()
        };

        self.free_head = next;
        // Clear the slot (removes free-list encoding).
        let slot = self.slot_mut(idx.get()).ok_or(CapError::InvalidIndex)?;
        slot.clear();
        self.free_count -= 1;
        Ok(idx)
    }

    /// Grow the `CSpace` by one page.
    ///
    /// Allocates the next unoccupied directory entry, threads all its slots
    /// onto the free list, then returns. Slot 0 in the first page is skipped.
    /// The page comes from the retype-pool pool when [`Self::set_kobj`] has
    /// installed a parent `CSpaceKernelObject`; otherwise from the kernel
    /// heap (legacy bootstrap path).
    fn grow(&mut self) -> Result<(), CapError>
    {
        let page_idx = self
            .directory
            .iter()
            .position(|p: &Option<NonNull<CSpacePage>>| p.is_none())
            .ok_or(CapError::OutOfSlots)?;

        let base = page_idx * L2_SIZE;
        let start_slot = usize::from(page_idx == 0);

        let available = L2_SIZE - start_slot;
        let remaining_quota = self.max_slots.saturating_sub(self.allocated_slots);
        let new_free = available.min(remaining_quota);

        if new_free == 0
        {
            return Err(CapError::OutOfSlots);
        }

        // Source the page from the retype-pool when wired, else from heap.
        let kobj_ptr = self.kobj.load(Ordering::Acquire);
        let page_nn: NonNull<CSpacePage> = if kobj_ptr.is_null()
        {
            // SAFETY: all-zeros is a valid CSpacePage (every slot null).
            let boxed = Box::new(unsafe { core::mem::zeroed::<CSpacePage>() });
            // SAFETY: Box::into_raw is non-null.
            unsafe { NonNull::new_unchecked(Box::into_raw(boxed)) }
        }
        else
        {
            #[cfg(not(test))]
            {
                // SAFETY: kobj_ptr is the wrapper that owns this CSpace; its
                // pool was seeded at retype time.
                let phys = unsafe { (*kobj_ptr).alloc_slot_page() }.ok_or(CapError::OutOfMemory)?;
                let virt = crate::mm::paging::phys_to_virt(phys);
                // SAFETY: pool returns page-aligned, freshly-zeroed pages
                // mapped in the kernel direct map.
                unsafe { NonNull::new_unchecked(virt as *mut CSpacePage) }
            }
            #[cfg(test)]
            {
                // Tests never wire a kobj; this branch is unreachable.
                return Err(CapError::OutOfMemory);
            }
        };

        // SAFETY: page_nn points at an exclusively-owned, zeroed CSpacePage.
        let page = unsafe { page_nn.as_ptr().as_mut().unwrap_unchecked() };

        let end_slot = start_slot + new_free;
        let old_head = self.free_head;
        let mut next = old_head;
        for i in (start_slot..end_slot).rev()
        {
            let idx = NonZeroU32::new((base + i) as u32).ok_or(CapError::InvalidIndex)?;
            page.slots[i].set_next_free(next);
            next = Some(idx);
        }
        self.free_head = next;

        self.allocated_slots += new_free;
        self.free_count += new_free;
        self.directory[page_idx] = Some(page_nn);
        Ok(())
    }

    /// Look up a slot by index. Returns `None` if the index is out of range
    /// or the backing page has not been allocated.
    pub fn slot(&self, index: u32) -> Option<&CapabilitySlot>
    {
        let idx = index as usize;
        let page_idx = idx / L2_SIZE;
        let slot_idx = idx % L2_SIZE;
        let page_nn = self.directory[page_idx]?;
        // SAFETY: directory entries are never aliased while the CSpace lock
        // is held; CapabilitySlot is repr(C) and the page bytes are exclusively
        // owned by this CSpace.
        let page = unsafe { page_nn.as_ref() };
        Some(&page.slots[slot_idx])
    }

    /// Mutable variant of [`slot`][Self::slot].
    pub fn slot_mut(&mut self, index: u32) -> Option<&mut CapabilitySlot>
    {
        let idx = index as usize;
        let page_idx = idx / L2_SIZE;
        let slot_idx = idx % L2_SIZE;
        let mut page_nn = self.directory[page_idx]?;
        // SAFETY: same as `slot`; `&mut self` excludes other readers.
        let page = unsafe { page_nn.as_mut() };
        Some(&mut page.slots[slot_idx])
    }

    /// Return a slot to the free list and clear its contents.
    ///
    /// Silently ignores an out-of-range, unmapped, or zero index.
    pub fn free_slot(&mut self, index: u32)
    {
        let Some(nz_index) = NonZeroU32::new(index)
        else
        {
            return;
        };
        let old_head = self.free_head;
        if let Some(slot) = self.slot_mut(index)
        {
            slot.set_next_free(old_head);
            self.free_head = Some(nz_index);
            self.free_count += 1;
        }
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
        slot.token = 0;
        slot.object = Some(object);
        slot.deriv_parent = None;
        slot.deriv_first_child = None;
        slot.deriv_next_sibling = None;
        slot.deriv_prev_sibling = None;

        Ok(index)
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
    /// O(n) walk of the singly-linked free list. Acceptable because callers
    /// (`insert_cap_at`) are infrequent (only init populating child `CSpaces`).
    pub fn remove_from_free_list(&mut self, target: u32) -> bool
    {
        let Some(target_nz) = NonZeroU32::new(target)
        else
        {
            return false;
        };
        if self.free_head == Some(target_nz)
        {
            // Target is the head: pop it.
            let next = self
                .slot(target)
                .and_then(super::slot::CapabilitySlot::next_free);
            self.free_head = next;
            self.free_count -= 1;
            return true;
        }
        // Walk the list looking for the predecessor.
        let Some(mut cur_idx) = self.free_head
        else
        {
            return false;
        };
        loop
        {
            let Some(next_idx) = self
                .slot(cur_idx.get())
                .and_then(super::slot::CapabilitySlot::next_free)
            else
            {
                return false;
            };
            if next_idx == target_nz
            {
                // Splice out: cur.next = target.next
                let after = self
                    .slot(target)
                    .and_then(super::slot::CapabilitySlot::next_free);
                let Some(cur_slot) = self.slot_mut(cur_idx.get())
                else
                {
                    return false;
                };
                cur_slot.set_next_free(after);
                self.free_count -= 1;
                return true;
            }
            cur_idx = next_idx;
        }
    }

    /// Insert a capability at a caller-chosen slot index.
    ///
    /// Used by `SYS_CAP_INSERT` to place a cap at a well-known index (e.g.,
    /// init populating a child's `CSpace`). The target slot must currently be Null.
    ///
    /// # Errors
    ///
    /// - [`CapError::InvalidIndex`] — index is 0, out of range, or occupied.
    /// - [`CapError::OutOfMemory`] — backing page allocation failed during grow.
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

        // Reject indices beyond the CSpace's maximum capacity.
        if index as usize >= self.max_slots
        {
            return Err(CapError::InvalidIndex);
        }

        // Ensure the page covering this index is allocated.
        let page_idx = index as usize / L2_SIZE;
        while self.directory[page_idx].is_none()
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
        slot.token = 0;
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

    /// Return the configured maximum number of usable slots.
    ///
    /// Set at construction via [`Self::new`]; immutable thereafter.
    /// Used by `SYS_CAP_INFO`'s `CAP_INFO_CSPACE_CAPACITY` field to expose
    /// the slot capacity to userspace inspection without granting any
    /// mutation authority.
    pub fn max_slots(&self) -> usize
    {
        self.max_slots
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
        for page_idx in 0..L1_SIZE
        {
            if let Some(page_nn) = self.directory[page_idx]
            {
                // SAFETY: page_nn is owned by this CSpace and not aliased
                // outside the lock.
                let page = unsafe { page_nn.as_ref() };
                let start = usize::from(page_idx == 0);
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
    /// Reclaim heap-backed pages on `CSpace` destruction.
    ///
    /// Heap path (`kobj == null`): every `Some(NonNull<CSpacePage>)` was
    /// `Box::leak`ed in [`Self::grow`]; reconstruct each `Box` and let it
    /// drop, returning the page to the kernel heap.
    ///
    /// Retype-pool path (`kobj != null`): pages live inside chunks tracked
    /// by [`CSpaceKernelObject`] which `dealloc_object(CSpaceObj)` reclaims
    /// wholesale via `retype_free`. Drop here is a no-op so we don't
    /// double-free pool pages through the global allocator.
    fn drop(&mut self)
    {
        if !self.kobj.load(Ordering::Acquire).is_null()
        {
            return;
        }
        for entry in &mut self.directory
        {
            if let Some(page_nn) = entry.take()
            {
                // SAFETY: heap path: page_nn came from Box::into_raw via
                // grow's heap branch.
                unsafe {
                    drop(Box::from_raw(page_nn.as_ptr()));
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
    use crate::cap::object::{FrameObject, KernelObjectHeader, ObjectType};
    use core::ptr::NonNull;

    /// Construct a dummy NonNull<KernelObjectHeader> backed by a leaked Box
    /// so tests don't need unsafe pointer arithmetic.
    fn dummy_object() -> NonNull<KernelObjectHeader>
    {
        let obj = Box::new(FrameObject {
            header: KernelObjectHeader::new(ObjectType::Frame),
            base: 0,
            size: 0x1000,
            available_bytes: core::sync::atomic::AtomicU64::new(0),
            owns_memory: core::sync::atomic::AtomicBool::new(false),
            allocator: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        let raw = Box::into_raw(obj) as *mut KernelObjectHeader;
        // SAFETY: Box::into_raw never returns null.
        unsafe { NonNull::new_unchecked(raw) }
    }

    #[test]
    fn new_cspace_is_empty()
    {
        let cs = CSpace::new(0, 16384);
        assert_eq!(cs.populated_count(), 0);
        assert_eq!(cs.allocated_slots, 0);
    }

    #[test]
    fn slot_zero_is_null()
    {
        let mut cs = CSpace::new(0, 16384);
        // Force page 0 to be allocated by requesting slot 1.
        let _idx = cs.allocate_slot().unwrap();
        // Slot 0 must exist and be null.
        let s = cs.slot(0).expect("slot 0 should exist after grow");
        assert!(s.is_null());
    }

    #[test]
    fn allocate_returns_nonzero_index()
    {
        let mut cs = CSpace::new(0, 16384);
        let _idx = cs.allocate_slot().unwrap();
    }

    #[test]
    fn allocate_and_lookup_round_trip()
    {
        let mut cs = CSpace::new(0, 16384);
        let obj = dummy_object();
        let idx = cs
            .insert_cap(CapTag::Frame, Rights::MAP | Rights::WRITE, obj)
            .unwrap();
        let slot = cs.slot(idx.get()).unwrap();
        assert_eq!(slot.tag, CapTag::Frame);
        assert!(slot.rights.contains(Rights::MAP));
        assert!(slot.rights.contains(Rights::WRITE));
        assert_eq!(slot.object, Some(obj));
    }

    #[test]
    fn growth_across_l2_boundary()
    {
        // Allocate L2_SIZE - 1 slots (page 0 has 63 usable slots after skipping 0).
        let mut cs = CSpace::new(0, 16384);
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
        let mut cs = CSpace::new(0, 16384);
        let idx1 = cs.allocate_slot().unwrap();
        cs.free_slot(idx1.get());
        // After freeing, the next allocate should return the same index.
        let idx2 = cs.allocate_slot().unwrap();
        assert_eq!(idx1, idx2, "freed slot should be reused");
    }

    #[test]
    fn max_slots_enforced()
    {
        // max_slots = 63: exactly one page minus slot 0.
        let mut cs = CSpace::new(0, 63);
        for _ in 0..63
        {
            cs.allocate_slot().unwrap();
        }
        let err = cs.allocate_slot().unwrap_err();
        assert_eq!(err, CapError::OutOfSlots);
    }

    #[test]
    fn write_execute_cap_allowed()
    {
        let mut cs = CSpace::new(0, 16384);
        let obj = dummy_object();
        let slot = cs
            .insert_cap(CapTag::Frame, Rights::WRITE | Rights::EXECUTE, obj)
            .expect("WRITE|EXECUTE cap should be allowed at cap level");
        let s = cs.slot(slot.get()).unwrap();
        assert!(s.rights.contains(Rights::WRITE | Rights::EXECUTE));
    }

    #[test]
    fn pre_allocate_succeeds()
    {
        let mut cs = CSpace::new(0, 16384);
        cs.pre_allocate(10).unwrap();
        assert!(cs.free_count >= 10);
    }

    #[test]
    fn populated_count_tracks_inserts()
    {
        let mut cs = CSpace::new(0, 16384);
        assert_eq!(cs.populated_count(), 0);
        let obj = dummy_object();
        cs.insert_cap(CapTag::Frame, Rights::MAP, obj).unwrap();
        assert_eq!(cs.populated_count(), 1);
    }

    #[test]
    fn free_list_prioritized_over_new_slots()
    {
        // Allocate 3 slots; free the first; verify next alloc reuses it rather
        // than consuming a brand-new slot beyond the current high-water mark.
        let mut cs = CSpace::new(0, 16384);
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
        let mut cs = CSpace::new(0, 16384);
        let obj = dummy_object();

        for expected in 1..=5usize
        {
            cs.insert_cap(CapTag::Frame, Rights::MAP, obj).unwrap();
            assert_eq!(
                cs.populated_count(),
                expected,
                "populated_count should be {} after {} inserts",
                expected,
                expected
            );
        }
    }
}
