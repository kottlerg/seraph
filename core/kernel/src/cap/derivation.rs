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
    let cs_ptr = crate::cap::lookup_cspace(id.cspace_id, id.epoch)?;
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

/// Maximum number of nodes a single [`revoke_subtree_batch`] call frees —
/// the revoke batch size.
///
/// Bounds the BSS dealloc-output buffer (`MAX_REVOKE_NODES` entries ×
/// 8 bytes = 2 KiB). The caller copies the output buffer to a stack-local
/// array of the same bound (so the DERIVATION write lock can be released
/// before the dealloc loop), so keeping `MAX_REVOKE_NODES` small enough to
/// fit on a 16 KiB kernel stack with breathing room is the binding
/// constraint. Subtrees larger than one batch are handled by calling
/// [`revoke_subtree_batch`] repeatedly until it reports no more work; the
/// batch size bounds lock hold time and stack cost per call, not the
/// revocable subtree size.
pub const MAX_REVOKE_NODES: usize = 256;

/// Output buffer for [`revoke_subtree_batch`]. `static mut` because the
/// surrounding `DERIVATION_LOCK` write lock guarantees a single in-flight
/// caller across all CPUs.
#[cfg(not(test))]
static mut REVOKE_OBJECTS: [Option<NonNull<KernelObjectHeader>>; MAX_REVOKE_NODES] =
    [None; MAX_REVOKE_NODES];

/// Revoke up to [`MAX_REVOKE_NODES`] descendants of `root`, returning a
/// slice of object pointers for the caller to `dec_ref`/deallocate outside
/// the lock, and whether the subtree may still hold unprocessed nodes.
///
/// The root slot itself is NOT touched. When the returned flag is `false`,
/// the root has no children (the subtree is fully cleared). When it is
/// `true`, the caller must call again (re-acquiring the lock and
/// revalidating the root in between); each call frees at least one node,
/// so repeated calls terminate against any fixed subtree. Nodes derived
/// concurrently between batches are picked up by the next batch's
/// re-descent from the root.
///
/// The traversal is a stackless post-order walk over the tree's own links:
/// descend `deriv_first_child` to a leaf, free it (its sibling becomes the
/// new list head via [`unlink_node`]), then continue with that sibling or,
/// when the list is exhausted, with the now-childless parent. No work
/// stack, so no subtree size can overflow one.
///
/// The returned slice borrows from [`REVOKE_OBJECTS`]; the caller must
/// finish consuming it before any other call. The `DERIVATION_LOCK` held
/// across this call enforces that exclusivity.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock. All `SlotIds` in the
/// subtree must be valid (registered in the `CSpace` registry); the
/// pre-unregister drain scrubs cross-`CSpace` links under this same lock,
/// so an unresolvable link cannot appear mid-walk. If one does anyway, the
/// walk severs the branch it hangs from (logging the anomaly) rather than
/// spinning on it.
#[cfg(not(test))]
pub unsafe fn revoke_subtree_batch(
    root: SlotId,
) -> (&'static [Option<NonNull<KernelObjectHeader>>], bool)
{
    // SAFETY: DERIVATION_LOCK held → single-threaded access to the static
    // output buffer.
    let out = unsafe { &mut *core::ptr::addr_of_mut!(REVOKE_OBJECTS) };

    // Reset the output buffer to None so a stale entry doesn't leak across
    // calls if the fill count somehow under-reports.
    for slot in out.iter_mut()
    {
        *slot = None;
    }
    let mut out_count: usize = 0;
    // Nodes freed this batch. Distinct from `out_count`: objectless slots
    // are freed but produce no dealloc entry, and the batch bound must cap
    // lock hold time by nodes walked, not objects collected.
    let mut processed: usize = 0;

    'outer: loop
    {
        // (Re)enter the walk at the head of root's child list.
        // SAFETY: DERIVATION_LOCK held; ensures exclusive access to the tree.
        let Some(root_slot) = (unsafe { resolve_slot_mut(root) })
        else
        {
            return (&out[..out_count], false);
        };
        let Some(mut cur) = root_slot.deriv_first_child
        else
        {
            return (&out[..out_count], false);
        };

        // The node whose `deriv_first_child` currently points at `cur`.
        // None = unknown (only after ascending); used solely by the
        // sever-on-anomaly containment below, which falls back to cutting
        // root's child list when unknown.
        let mut parent_of_cur: Option<SlotId> = Some(root);

        loop
        {
            // Descend along `deriv_first_child` to a leaf. Every step visits
            // the head of a child list, so `parent_of_cur.first_child == cur`
            // holds at each descent point.
            loop
            {
                // SAFETY: DERIVATION_LOCK held.
                let Some(slot) = (unsafe { resolve_slot_mut(cur) })
                else
                {
                    // Invariant violation (see Safety): a live tree link
                    // failed to resolve. Sever the branch so the walk
                    // cannot spin on it, and restart from the root.
                    crate::kprintln!(
                        "cap: revoke: unresolvable derivation link (cspace {} slot {}); severing",
                        cur.cspace_id,
                        cur.index.get()
                    );
                    let sever_from = parent_of_cur.unwrap_or(root);
                    // SAFETY: DERIVATION_LOCK held.
                    if let Some(sever_slot) = unsafe { resolve_slot_mut(sever_from) }
                    {
                        sever_slot.deriv_first_child = None;
                    }
                    continue 'outer;
                };
                match slot.deriv_first_child
                {
                    Some(child) =>
                    {
                        parent_of_cur = Some(cur);
                        cur = child;
                    }
                    None => break,
                }
            }

            // `cur` is a leaf. Capture its links before unlinking clears them.
            // SAFETY: DERIVATION_LOCK held; `cur` resolved in the loop above.
            let Some((parent, next)) = (unsafe { resolve_slot_mut(cur) })
                .map(|slot| (slot.deriv_parent, slot.deriv_next_sibling))
            else
            {
                continue 'outer;
            };

            // SAFETY: DERIVATION_LOCK held; `cur` is a valid, live SlotId.
            unsafe { unlink_node(cur) };

            if let Some(cs_ptr) = crate::cap::lookup_cspace(cur.cspace_id, cur.epoch)
            {
                // Take cspace.lock around the slot read + free_slot so the
                // freelist mutation cannot tear against a concurrent
                // SYS_CAP_CREATE_* on the same cspace. Lock order:
                // DERIVATION_LOCK → cspace.lock.
                // SAFETY: cspace registry lookup validated; CSpace pointer
                // lives as long as the registry entry; lock_raw/unlock_raw
                // paired.
                let saved = unsafe { (*cs_ptr).lock.lock_raw() };
                // SAFETY: lock held; aliasing prevented.
                let cs = unsafe { &mut *cs_ptr };
                let obj_ptr = cs.slot_mut(cur.index.get()).and_then(|slot| slot.object);
                cs.free_slot(cur.index.get());
                // SAFETY: paired with lock_raw above.
                unsafe { (*cs_ptr).lock.unlock_raw(saved) };

                if let Some(ptr) = obj_ptr
                {
                    out[out_count] = Some(ptr);
                    out_count += 1;
                }
            }

            processed += 1;
            if processed >= MAX_REVOKE_NODES
            {
                return (&out[..out_count], true);
            }

            // Advance: the freed leaf's next sibling is now the head of the
            // same child list; when the list is exhausted, its parent has no
            // children left and is processed next — unless the parent is the
            // root, in which case re-enter from the top (root may be
            // childless now). Root identity compares cspace + index only, so
            // an epoch-0 legacy stamp in a parent link cannot break the
            // stop condition.
            match next
            {
                Some(sibling) => cur = sibling,
                None => match parent
                {
                    Some(p) if !(p.cspace_id == root.cspace_id && p.index == root.index) =>
                    {
                        parent_of_cur = None;
                        cur = p;
                    }
                    _ => continue 'outer,
                },
            }
        }
    }
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
