// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/derivation.rs

//! Global derivation tree lock and tree manipulation.
//!
//! The derivation tree tracks parent/child relationships between capability
//! slots across all `CSpaces.` All mutations require the write lock; traversals
//! require the read lock.
//!
//! The lock is spin-based: sufficient for single-threaded boot and
//! forward-compatible with SMP — no changes to call sites when SMP is added.
//!
//! ## State encoding
//!
//! - `state == 0`: unlocked
//! - `0 < state < u32::MAX`: that many concurrent readers hold the lock
//! - `state == u32::MAX`: one writer holds the lock
//!
//! ## Tree structure
//!
//! Each slot has four derivation pointers:
//! - `deriv_parent`: the slot this was derived from
//! - `deriv_first_child`: head of this slot's children (doubly-linked via next/prev)
//! - `deriv_next_sibling` / `deriv_prev_sibling`: intrusive doubly-linked list
//!   of slots derived from the same parent
//!
//! When `tag == Null`, `deriv_parent` is repurposed for the free list; do not
//! read derivation fields on Null slots.
//!
//! ## Adding new operations
//!
//! All functions here assume `DERIVATION_LOCK` write lock is held by the caller.
//! Resolve `SlotIds` via [`crate::cap::lookup_cspace`].

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use super::object::KernelObjectHeader;
use super::slot::SlotId;

const WRITE_LOCKED: u32 = u32::MAX;

/// Shared derivation tree lock.
///
/// Acquire before reading or modifying any slot's `deriv_*` fields across
/// `CSpace` boundaries. Within a single `CSpace`, the `CSpace`'s own lock (future
/// phases) is sufficient.
pub static DERIVATION_LOCK: DerivationLock = DerivationLock::new();

/// Spin-based reader/writer lock protecting the capability derivation tree.
pub struct DerivationLock
{
    state: AtomicU32,
}

impl DerivationLock
{
    /// Construct an unlocked `DerivationLock`. Const for static initialisation.
    pub const fn new() -> Self
    {
        Self {
            state: AtomicU32::new(0),
        }
    }

    /// Acquire a shared read lock. Spins while a writer holds the lock.
    ///
    /// Multiple readers may hold the lock simultaneously. Blocks writers.
    ///
    /// Currently unused: all derivation operations take an exclusive write
    /// lock. Read-locking is reserved for SMP — concurrent cap-lookup
    /// traversals (read-only) will share this lock instead of serialising.
    #[allow(dead_code)]
    pub fn read_lock(&self)
    {
        loop
        {
            let cur = self.state.load(Ordering::Relaxed);
            // Refuse to increment if a writer holds the lock.
            if cur != WRITE_LOCKED
                && self
                    .state
                    .compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }
    }

    /// Release a shared read lock previously acquired with [`read_lock`].
    #[allow(dead_code)]
    pub fn read_unlock(&self)
    {
        self.state.fetch_sub(1, Ordering::Release);
    }

    /// Acquire the write lock. Spins until no readers or writers hold it.
    pub fn write_lock(&self)
    {
        loop
        {
            if self
                .state
                .compare_exchange_weak(0, WRITE_LOCKED, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }
    }

    /// Release the write lock previously acquired with [`write_lock`].
    pub fn write_unlock(&self)
    {
        self.state.store(0, Ordering::Release);
    }
}

// ── Tree manipulation ─────────────────────────────────────────────────────────

/// Resolve a [`SlotId`] to a mutable slot reference.
///
/// Returns `None` if the `CSpace` is not registered or the index is invalid.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` (write lock). The returned reference
/// is valid only while the lock is held and the `CSpace` is live.
unsafe fn resolve_slot_mut(id: SlotId) -> Option<&'static mut super::slot::CapabilitySlot>
{
    let cs_ptr = crate::cap::lookup_cspace(id.cspace_id)?;
    // SAFETY: cspace registry lookup validated; CSpace pointer lives as long as the registry entry.
    let cs = unsafe { &mut *cs_ptr };
    cs.slot_mut(id.index.get())
}

/// Link `child` as a new child of `parent` in the derivation tree.
///
/// Prepends `child` to `parent`'s child list (child becomes `first_child`).
/// Updates `child.deriv_parent` and the prev/next sibling chain.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock. `parent` and `child` must
/// be valid, live capability slots (not Null).
#[cfg(not(test))]
pub unsafe fn link_child(parent: SlotId, child: SlotId)
{
    // Update child's parent pointer.
    // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
    if let Some(child_slot) = unsafe { resolve_slot_mut(child) }
    {
        child_slot.deriv_parent = Some(parent);
        child_slot.deriv_prev_sibling = None;

        // child.next = old first_child
        // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
        let old_first = if let Some(parent_slot) = unsafe { resolve_slot_mut(parent) }
        {
            let old = parent_slot.deriv_first_child;
            parent_slot.deriv_first_child = Some(child);
            old
        }
        else
        {
            None
        };

        // Wire the former first_child's prev pointer to the new child.
        if let Some(old_first_id) = old_first
        {
            // SAFETY: DERIVATION_LOCK held; old_first_id retrieved from parent's child list.
            if let Some(old_first_slot) = unsafe { resolve_slot_mut(old_first_id) }
            {
                old_first_slot.deriv_prev_sibling = Some(child);
            }
        }

        // Wire child's next sibling to the former first child.
        // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
        if let Some(child_slot2) = unsafe { resolve_slot_mut(child) }
        {
            child_slot2.deriv_next_sibling = old_first;
        }
    }
}

/// Remove `node` from the derivation tree without affecting its children.
///
/// Updates the parent's `first_child` pointer and the sibling chain around
/// `node`. Clears `node`'s `deriv_parent` and sibling pointers.
///
/// Children of `node` are left dangling (caller should call
/// [`reparent_children`] first if needed).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock.
#[cfg(not(test))]
pub unsafe fn unlink_node(node: SlotId)
{
    // Read node's current pointers.
    // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
    let (parent, prev, next) = if let Some(slot) = unsafe { resolve_slot_mut(node) }
    {
        let p = slot.deriv_parent;
        let pr = slot.deriv_prev_sibling;
        let nx = slot.deriv_next_sibling;
        // Clear node's own pointers.
        slot.deriv_parent = None;
        slot.deriv_prev_sibling = None;
        slot.deriv_next_sibling = None;
        (p, pr, nx)
    }
    else
    {
        return;
    };

    // Splice node out of the sibling chain.
    if let Some(prev_id) = prev
    {
        // SAFETY: DERIVATION_LOCK held; prev_id retrieved from node's sibling pointer.
        if let Some(prev_slot) = unsafe { resolve_slot_mut(prev_id) }
        {
            prev_slot.deriv_next_sibling = next;
        }
    }
    else if let Some(parent_id) = parent
    {
        // node was the first child; update parent's first_child.
        // SAFETY: DERIVATION_LOCK held; parent_id retrieved from node's parent pointer.
        if let Some(parent_slot) = unsafe { resolve_slot_mut(parent_id) }
        {
            parent_slot.deriv_first_child = next;
        }
    }

    if let Some(next_id) = next
    {
        // SAFETY: DERIVATION_LOCK held; next_id retrieved from node's sibling pointer.
        if let Some(next_slot) = unsafe { resolve_slot_mut(next_id) }
        {
            next_slot.deriv_prev_sibling = prev;
        }
    }
}

/// Move all children of `node` to a new parent (or make them tree roots).
///
/// Used by [`SYS_CAP_DELETE`] so grandchildren remain revocable by the
/// grandparent after the intermediate slot is deleted.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock.
#[cfg(not(test))]
pub unsafe fn reparent_children(node: SlotId, new_parent: Option<SlotId>)
{
    // Collect node's first_child.
    // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
    let first_child = if let Some(slot) = unsafe { resolve_slot_mut(node) }
    {
        let fc = slot.deriv_first_child;
        slot.deriv_first_child = None;
        fc
    }
    else
    {
        return;
    };

    // Walk the child list and re-link each child under new_parent.
    let mut cur = first_child;
    while let Some(child_id) = cur
    {
        // SAFETY: DERIVATION_LOCK held; child_id retrieved from node's child list.
        let next = if let Some(slot) = unsafe { resolve_slot_mut(child_id) }
        {
            slot.deriv_parent = new_parent;
            slot.deriv_next_sibling
        }
        else
        {
            None
        };

        if let Some(np) = new_parent
        {
            // Prepend child to new_parent's child list.
            // SAFETY: DERIVATION_LOCK held; parent/child/sibling pointers maintained by link/unlink operations.
            unsafe { link_child(np, child_id) };

            // link_child sets deriv_parent again (idempotent) and wires the
            // sibling chain. Clear the deriv_parent we set above to avoid
            // double-set (link_child will set it properly).
            // Actually link_child handles everything; the interim parent set
            // above is harmless since link_child overwrites it.
        }
        else
        {
            // Make child a root (no parent).
            // SAFETY: DERIVATION_LOCK held; child_id retrieved from node's child list.
            if let Some(slot) = unsafe { resolve_slot_mut(child_id) }
            {
                slot.deriv_parent = None;
                // prev_sibling already set to None by the prior walk? No —
                // the siblings are still chained. For roots, detach from siblings.
                slot.deriv_prev_sibling = None;
                slot.deriv_next_sibling = None;
            }
        }

        cur = next;
    }
}

/// Iteratively revoke all descendants of `root`, collecting their object
/// pointers for the caller to `dec_ref`/deallocate outside the lock.
///
/// The root slot itself is NOT touched. After this call, the root has no
/// children (the subtree is fully cleared).
///
/// Returns a [`Vec`] of object pointers for deallocation. For each pointer,
/// the caller must call `header.dec_ref()` and, if it returns 0, call
/// `dealloc_object()`.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock. All `SlotIds` in the subtree
/// must be valid (registered in the `CSpace` registry).
#[cfg(not(test))]
pub unsafe fn revoke_subtree(root: SlotId) -> Vec<NonNull<KernelObjectHeader>>
{
    let mut to_dealloc: Vec<NonNull<KernelObjectHeader>> = Vec::new();

    // Iterative depth-first traversal using the child/sibling pointers.
    // Visit all descendants of root (not root itself).
    // We use the child lists as an implicit stack: always descend to first_child
    // first, then move to next_sibling when no child remains.
    //
    // To avoid following stale pointers after clearing, we collect children
    // of the root into a work stack first, then process each subtree.
    // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
    let root_first_child = if let Some(slot) = unsafe { resolve_slot_mut(root) }
    {
        let fc = slot.deriv_first_child;
        slot.deriv_first_child = None;
        fc
    }
    else
    {
        return to_dealloc;
    };

    // Work stack: nodes to process (each will have all its descendants revoked).
    let mut stack: Vec<SlotId> = Vec::new();

    // Collect root's immediate children into the stack.
    let mut cur = root_first_child;
    while let Some(id) = cur
    {
        // SAFETY: DERIVATION_LOCK held; id retrieved from root's child list.
        let next = unsafe { resolve_slot_mut(id) }.and_then(|s| s.deriv_next_sibling);
        stack.push(id);
        cur = next;
    }

    // Process the stack: for each node, collect its object, clear the slot,
    // and push its children onto the stack.
    while let Some(node_id) = stack.pop()
    {
        let Some(cs_ptr) = crate::cap::lookup_cspace(node_id.cspace_id)
        else
        {
            continue;
        };
        // SAFETY: cspace registry lookup validated; CSpace pointer lives as long as the registry entry.
        let cs = unsafe { &mut *cs_ptr };

        // Snapshot derivation fields and object pointer, then clear.
        let (obj_ptr, first_child) = {
            let Some(slot) = cs.slot_mut(node_id.index.get())
            else
            {
                continue;
            };
            let obj = slot.object;
            let fc = slot.deriv_first_child;
            // Release the borrow on cs so free_slot can be called below.
            let _ = slot;
            (obj, fc)
        };

        // Return the slot to the CSpace free list.
        cs.free_slot(node_id.index.get());

        // Collect the object for the caller to dec_ref.
        if let Some(ptr) = obj_ptr
        {
            to_dealloc.push(ptr);
        }

        // Push children onto the work stack.
        let mut child = first_child;
        while let Some(child_id) = child
        {
            // SAFETY: DERIVATION_LOCK held; child_id retrieved from node's child list.
            let next = unsafe { resolve_slot_mut(child_id) }.and_then(|s| s.deriv_next_sibling);
            stack.push(child_id);
            child = next;
        }
    }

    to_dealloc
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn read_lock_unlock()
    {
        let lock = DerivationLock::new();
        lock.read_lock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 1);
        lock.read_unlock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn multiple_readers()
    {
        let lock = DerivationLock::new();
        lock.read_lock();
        lock.read_lock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 2);
        lock.read_unlock();
        lock.read_unlock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn write_lock_unlock()
    {
        let lock = DerivationLock::new();
        lock.write_lock();
        assert_eq!(lock.state.load(Ordering::Relaxed), WRITE_LOCKED);
        lock.write_unlock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 0);
    }
}
