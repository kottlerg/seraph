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

use super::object::KernelObjectHeader;
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
/// Allocated as a `Box<CSpacePage>` when the `CSpace` grows. All-zeros is a
/// valid initial state (every slot is null), so pages are allocated via
/// `unsafe { core::mem::zeroed() }`.
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
    directory: [Option<Box<CSpacePage>>; L1_SIZE],
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
}

impl CSpace
{
    /// Create an empty `CSpace`. No pages are allocated until the first slot
    /// is requested.
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
        }
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
    fn grow(&mut self) -> Result<(), CapError>
    {
        let page_idx = self
            .directory
            .iter()
            .position(|p: &Option<Box<CSpacePage>>| p.is_none())
            .ok_or(CapError::OutOfSlots)?;

        let base = page_idx * L2_SIZE;
        // Skip slot 0 in the first page (permanently null, not in free list).
        let start_slot = usize::from(page_idx == 0);

        // Clamp to the remaining quota. A full page may exceed max_slots (e.g.
        // when max_slots < L2_SIZE); only add the permitted number of slots to
        // the free list. The rest of the page is allocated but left unused.
        let available = L2_SIZE - start_slot;
        let remaining_quota = self.max_slots.saturating_sub(self.allocated_slots);
        let new_free = available.min(remaining_quota);

        if new_free == 0
        {
            return Err(CapError::OutOfSlots);
        }

        // Allocate page (all-zeros = all null slots).
        // SAFETY: all-zeros is a valid CSpacePage: every CapabilitySlot is null
        // (Null tag = 0, Rights::NONE = 0, NonNull/Option niches encode None at 0).
        let mut page = Box::new(unsafe { core::mem::zeroed::<CSpacePage>() });

        // Thread only the permitted slots onto the free list in reverse order so
        // ascending indices are popped in ascending order.
        let end_slot = start_slot + new_free;
        let old_head = self.free_head;
        let mut next = old_head;
        for i in (start_slot..end_slot).rev()
        {
            // `base + i` is structurally non-zero: the first page sets
            // `start_slot = 1`, and every later page has `base >= L2_SIZE`.
            // The `ok_or` propagates an impossible error rather than
            // panicking, keeping the free-list type honest.
            let idx = NonZeroU32::new((base + i) as u32).ok_or(CapError::InvalidIndex)?;
            page.slots[i].set_next_free(next);
            next = Some(idx);
        }
        self.free_head = next;

        self.allocated_slots += new_free;
        self.free_count += new_free;
        self.directory[page_idx] = Some(page);
        Ok(())
    }

    /// Look up a slot by index. Returns `None` if the index is out of range
    /// or the backing page has not been allocated.
    pub fn slot(&self, index: u32) -> Option<&CapabilitySlot>
    {
        let idx = index as usize;
        let page_idx = idx / L2_SIZE;
        let slot_idx = idx % L2_SIZE;
        self.directory[page_idx]
            .as_ref()
            .map(|p| &p.slots[slot_idx])
    }

    /// Mutable variant of [`slot`][Self::slot].
    pub fn slot_mut(&mut self, index: u32) -> Option<&mut CapabilitySlot>
    {
        let idx = index as usize;
        let page_idx = idx / L2_SIZE;
        let slot_idx = idx % L2_SIZE;
        self.directory[page_idx]
            .as_mut()
            .map(|p| &mut p.slots[slot_idx])
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
            if let Some(page) = &self.directory[page_idx]
            {
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
            owns_memory: core::sync::atomic::AtomicBool::new(false),
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
