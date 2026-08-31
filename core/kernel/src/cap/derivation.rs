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

/// Maximum number of O(1) tree edits (hoists + frees) a single
/// [`revoke_subtree_batch`] call performs — the revoke batch size.
///
/// Frees never exceed edits, so this also bounds the BSS dealloc-output
/// buffer (`MAX_REVOKE_EDITS` entries × 8 bytes = 2 KiB). The caller copies
/// the output buffer to a stack-local array of the same bound (so the
/// DERIVATION write lock can be released before the dealloc loop), so
/// keeping `MAX_REVOKE_EDITS` small enough to fit on a 16 KiB kernel stack
/// with breathing room is the binding constraint. Subtrees larger than one
/// batch are handled by calling [`revoke_subtree_batch`] repeatedly until
/// it reports no more work; the batch size bounds lock hold time and stack
/// cost per call, not the revocable subtree size.
pub const MAX_REVOKE_EDITS: usize = 256;

/// Output buffer for [`revoke_subtree_batch`]. `static mut` because the
/// surrounding `DERIVATION_LOCK` write lock guarantees a single in-flight
/// caller across all CPUs.
static mut REVOKE_OBJECTS: [Option<NonNull<KernelObjectHeader>>; MAX_REVOKE_EDITS] =
    [None; MAX_REVOKE_EDITS];

/// How a [`revoke_subtree_batch`] call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchStatus
{
    /// The root has no children left; the subtree is fully cleared.
    Cleared,
    /// The edit budget ran out with work remaining; call again after
    /// releasing the lock, deallocating the collected objects, and
    /// revalidating the root.
    MoreWork,
    /// A derivation link failed to resolve — an invariant violation (the
    /// pre-unregister drain guarantees no live slot references a dead
    /// `CSpace`). The dangling chain was truncated for containment; the
    /// caller must surface an error rather than report a clean revoke.
    DeadLink,
}

/// Revoke descendants of `root` with at most [`MAX_REVOKE_EDITS`] O(1) tree
/// edits, returning a slice of object pointers for the caller to
/// `dec_ref`/deallocate outside the lock, and how the batch ended.
///
/// The root slot itself is NOT touched. On [`BatchStatus::MoreWork`] the
/// caller must call again (re-acquiring the lock and revalidating the root
/// in between); such a call performed exactly [`MAX_REVOKE_EDITS`] edits,
/// and clearing a subtree of N nodes needs at most 2N edits in total (each
/// node is hoisted at most once and freed exactly once), so repeated calls
/// terminate against any fixed subtree in O(N) total work. Nodes derived
/// concurrently between batches are still cleared, because the walk only
/// ever operates on root's current child list.
///
/// Each edit acts on the head `H` of root's child list in O(1):
///
/// - `H` has a child: unlink that child and re-link it directly under root
///   (a *hoist* — it becomes the new list head, ahead of `H`).
/// - `H` is childless: unlink it, free its slot, collect its object.
///
/// Hoisting flattens the subtree in place: while a multi-batch revoke is in
/// flight, surviving descendants may temporarily appear as direct children
/// of root. They remain descendants of root and of every ancestor above it,
/// so ancestor revocation reach is preserved; intermediate parent→child
/// edges inside the subtree are destroyed as the flattening proceeds, which
/// is why the syscall pins the root against delete/move for the whole
/// multi-batch operation (see `CapabilitySlot::revoke_in_progress`) — an
/// abandoned half-flattened subtree would otherwise permanently outlive the
/// intermediate holders' revocation authority.
///
/// The returned slice borrows from [`REVOKE_OBJECTS`]; the caller must
/// finish consuming it before any other call. The `DERIVATION_LOCK` held
/// across this call enforces that exclusivity.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock. Every derivation link
/// reachable from a live slot resolves — `drain_dying_cspace` splices all
/// foreign-facing links to surviving neighbours before a `CSpace`
/// unregisters. A link that fails to resolve anyway is corruption: the walk
/// truncates the chain hanging from it (containment), logs it, and reports
/// [`BatchStatus::DeadLink`].
pub unsafe fn revoke_subtree_batch(
    root: SlotId,
) -> (&'static [Option<NonNull<KernelObjectHeader>>], BatchStatus)
{
    // SAFETY: DERIVATION_LOCK held → single-threaded access to the static
    // output buffer. Entries are written before `out_count` advances and
    // callers read only `..out_count`, so stale entries beyond the returned
    // length are never observed.
    let out = unsafe { &mut *core::ptr::addr_of_mut!(REVOKE_OBJECTS) };
    let mut out_count: usize = 0;
    // Tree edits this batch (hoists + frees). Distinct from `out_count`:
    // hoists and objectless slots produce no dealloc entry, and the batch
    // bound caps lock hold time by edits performed, not objects collected.
    let mut steps: usize = 0;

    loop
    {
        // SAFETY: DERIVATION_LOCK held; ensures exclusive access to the tree.
        let Some(head) = (unsafe { resolve_slot_mut(root) }).and_then(|s| s.deriv_first_child)
        else
        {
            // Childless root: subtree cleared. (An unresolvable root lands
            // here too; the caller's per-batch revalidation is what tells a
            // vanished root apart from a cleared subtree.)
            return (&out[..out_count], BatchStatus::Cleared);
        };

        if !slot_exists(head)
        {
            // SAFETY: DERIVATION_LOCK held (see Safety: corruption path).
            unsafe { truncate_dead_link(root, head, "root child list") };
            return (&out[..out_count], BatchStatus::DeadLink);
        }
        // SAFETY: DERIVATION_LOCK held; existence checked above.
        let grandchild =
            (unsafe { resolve_slot_mut(head) }).and_then(|slot| slot.deriv_first_child);

        if let Some(g) = grandchild
        {
            if !slot_exists(g)
            {
                // SAFETY: DERIVATION_LOCK held (see Safety: corruption path).
                unsafe { truncate_dead_link(head, g, "child chain") };
                return (&out[..out_count], BatchStatus::DeadLink);
            }
            // Hoist: g leaves head's child list and becomes root's first
            // child (head keeps its own list position).
            // SAFETY: DERIVATION_LOCK held; g and root are live.
            unsafe {
                unlink_node(g);
                link_child(root, g);
            }
        }
        else
        {
            // Head is childless: unlink, free its slot, collect its object.
            // SAFETY: DERIVATION_LOCK held; head is a valid, live SlotId.
            if let Some(ptr) = unsafe { unlink_free_collect(head) }
            {
                out[out_count] = Some(ptr);
                out_count += 1;
            }
        }

        steps += 1;
        if steps >= MAX_REVOKE_EDITS
        {
            return (&out[..out_count], BatchStatus::MoreWork);
        }
    }
}

/// Return `true` if `id` resolves to a slot (its `CSpace` is registered
/// with a matching epoch and the index is in range).
fn slot_exists(id: SlotId) -> bool
{
    crate::cap::lookup_cspace(id.cspace_id, id.epoch)
        // SAFETY: registry pointer valid while the entry resolves; brief
        // immutable read under DERIVATION_LOCK.
        .and_then(|cs| unsafe { (*cs).slot(id.index.get()) })
        .is_some()
}

/// Containment for a dead derivation link: log it and cut `owner`'s
/// `deriv_first_child`, abandoning the unreachable chain behind `dead`.
///
/// Cutting the whole chain is the tightest containment available: the dead
/// node's sibling links lived in storage reclaimed with its `CSpace`, so
/// the rest of the chain cannot be located to splice past it. Any live
/// nodes chained behind the dead link are abandoned — which is why the
/// caller reports [`BatchStatus::DeadLink`] and the syscall surfaces an
/// error instead of claiming a clean revoke.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock.
unsafe fn truncate_dead_link(owner: SlotId, dead: SlotId, context: &str)
{
    #[cfg(not(test))]
    crate::kprintln!(
        "cap: revoke: dead derivation link (cspace {} slot {}) in {}; truncating",
        dead.cspace_id,
        dead.index.get(),
        context
    );
    #[cfg(test)]
    let _ = (dead, context);
    // SAFETY: DERIVATION_LOCK held (caller contract).
    if let Some(owner_slot) = unsafe { resolve_slot_mut(owner) }
    {
        owner_slot.deriv_first_child = None;
    }
}

/// Unlink `id` from the derivation tree, free its slot in its owning
/// `CSpace`, and return its object pointer for the caller to queue for
/// deallocation (`None` if the slot held no object or its `CSpace` is gone).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock. `id` must be childless —
/// its subtree already cleared or hoisted away.
unsafe fn unlink_free_collect(id: SlotId) -> Option<NonNull<KernelObjectHeader>>
{
    // SAFETY: DERIVATION_LOCK held (caller contract).
    unsafe { unlink_node(id) };

    let cs_ptr = crate::cap::lookup_cspace(id.cspace_id, id.epoch)?;

    // Take cspace.lock around the slot read + free_slot so the freelist
    // mutation cannot tear against a concurrent SYS_CAP_CREATE_* on the
    // same cspace. Lock order: DERIVATION_LOCK → cspace.lock.
    // SAFETY: cspace registry lookup validated; CSpace pointer lives as
    // long as the registry entry; lock_raw/unlock_raw paired.
    let saved = unsafe { (*cs_ptr).lock.lock_raw() };
    // SAFETY: lock held; aliasing prevented.
    let cs = unsafe { &mut *cs_ptr };
    let obj_ptr = cs.slot_mut(id.index.get()).and_then(|slot| slot.object);
    cs.free_slot(id.index.get());
    // SAFETY: paired with lock_raw above.
    unsafe { (*cs_ptr).lock.unlock_raw(saved) };

    obj_ptr
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

    // ── revoke_subtree_batch (host harness) ──────────────────────────────
    //
    // Each test registers heap-backed CSpaces in the shared test registry
    // under hard-coded ids unique to that test (the registry is a
    // process-wide static and `cargo test` runs tests concurrently). The
    // ids sit far above anything the test-stub `alloc_cspace_id` counter
    // reaches in this suite and below the recycle test's reserved top id;
    // nothing enforces that — a new direct-registration test must pick an
    // unused id. Leaked Boxes are acceptable — the process exits after the
    // run. The global DERIVATION_LOCK is taken for fidelity with the
    // production contract; assertions run only after `write_unlock`, so a
    // failing test unwinds without wedging the other tests on the lock.

    use crate::cap::cspace::CSpace;
    use crate::cap::slot::CapTag;
    use core::num::NonZeroU32;

    fn mk_registered_cspace(id: crate::cap::slot::CSpaceId, max_slots: usize) -> *mut CSpace
    {
        let cs = Box::leak(Box::new(CSpace::new(id, max_slots)));
        crate::cap::register_cspace(id, cs).expect("register test cspace");
        core::ptr::from_mut(cs)
    }

    /// Populate one slot (Endpoint tag, dangling object pointer — the batch
    /// only collects object pointers, never dereferences them) and return
    /// its stamped `SlotId`.
    fn occupy(cs: *mut CSpace, id: crate::cap::slot::CSpaceId) -> SlotId
    {
        // SAFETY: single-threaded test ownership of the leaked CSpace.
        let idx = unsafe { (*cs).allocate_slot() }.expect("allocate slot");
        // SAFETY: as above.
        let slot = unsafe { (*cs).slot_mut(idx.get()) }.expect("slot_mut");
        slot.tag = CapTag::Endpoint;
        slot.object = Some(NonNull::dangling());
        SlotId::current(id, idx)
    }

    fn count_populated(cs: *mut CSpace) -> usize
    {
        // SAFETY: single-threaded test ownership.
        unsafe { (*cs).populated_count() }
    }

    /// Link pre-occupied `nodes` as a derive chain under `root` (each node
    /// the sole child of the previous). Nodes are allocated by the caller
    /// before locking so no fallible call runs while `DERIVATION_LOCK` is
    /// held; the caller holds the lock across this call.
    fn link_chain(root: SlotId, nodes: &[SlotId])
    {
        let mut parent = root;
        for &child in nodes
        {
            // SAFETY: DERIVATION_LOCK held by caller; both slots live.
            unsafe { link_child(parent, child) };
            parent = child;
        }
    }

    /// [`occupy`] `len` slots up front, before the caller takes
    /// `DERIVATION_LOCK` — no fallible allocation may run under the global
    /// lock (a panic there would wedge the whole suite).
    fn occupy_many(
        cs: *mut CSpace,
        id: crate::cap::slot::CSpaceId,
        len: usize,
    ) -> std::vec::Vec<SlotId>
    {
        (0..len).map(|_| occupy(cs, id)).collect()
    }

    #[test]
    fn revoke_batch_clears_mixed_tree_and_preserves_root()
    {
        const ID: crate::cap::slot::CSpaceId = 3101;
        let cs = mk_registered_cspace(ID, 512);
        let root = occupy(cs, ID);
        // Allocate before locking — no fallible call under the global lock.
        let children = occupy_many(cs, ID, 3);
        let grandchildren = occupy_many(cs, ID, 12);
        DERIVATION_LOCK.write_lock();
        for (c, child) in children.iter().enumerate()
        {
            // SAFETY: DERIVATION_LOCK held; both slots live.
            unsafe { link_child(root, *child) };
            for grandchild in &grandchildren[c * 4..(c + 1) * 4]
            {
                // SAFETY: as above.
                unsafe { link_child(*child, *grandchild) };
            }
        }
        // SAFETY: DERIVATION_LOCK held.
        let (objects, status) = unsafe { revoke_subtree_batch(root) };
        let collected = objects.len();
        DERIVATION_LOCK.write_unlock();

        assert_eq!(status, BatchStatus::Cleared);
        assert_eq!(collected, 15, "3 children + 12 grandchildren collected");
        assert_eq!(count_populated(cs), 1, "only the root survives");
        // SAFETY: test ownership.
        let root_slot = unsafe { (*cs).slot_mut(root.index.get()) }.expect("root slot");
        assert_eq!(root_slot.tag, CapTag::Endpoint, "root untouched");
        assert_eq!(root_slot.deriv_first_child, None, "root childless");
        crate::cap::unregister_cspace(ID);
    }

    // A chain of N nodes needs 2N-1 edits (N-1 hoists + N frees), so
    // N = 150 forces exactly one MoreWork boundary at 256 edits.
    const BUDGET_CHAIN: usize = 150;

    #[test]
    fn revoke_batch_stops_at_edit_budget_then_clears()
    {
        const ID: crate::cap::slot::CSpaceId = 3102;
        let cs = mk_registered_cspace(ID, 512);
        let root = occupy(cs, ID);
        let nodes = occupy_many(cs, ID, BUDGET_CHAIN);
        DERIVATION_LOCK.write_lock();
        link_chain(root, &nodes);

        // SAFETY: DERIVATION_LOCK held.
        let (first_objects, first_status) = unsafe { revoke_subtree_batch(root) };
        let first_freed = first_objects.len();
        // SAFETY: DERIVATION_LOCK held.
        let (second_objects, second_status) = unsafe { revoke_subtree_batch(root) };
        let second_freed = second_objects.len();
        DERIVATION_LOCK.write_unlock();

        assert_eq!(first_status, BatchStatus::MoreWork);
        assert!(
            first_freed < BUDGET_CHAIN,
            "budgeted batch must leave survivors ({first_freed} freed)"
        );
        assert_eq!(second_status, BatchStatus::Cleared);
        assert_eq!(first_freed + second_freed, BUDGET_CHAIN);
        assert_eq!(count_populated(cs), 1, "only the root survives");
        crate::cap::unregister_cspace(ID);
    }

    #[test]
    fn revoke_batch_hoists_survivors_under_root_between_batches()
    {
        const ID: crate::cap::slot::CSpaceId = 3105;
        let cs = mk_registered_cspace(ID, 512);
        let root = occupy(cs, ID);
        let nodes = occupy_many(cs, ID, BUDGET_CHAIN);
        DERIVATION_LOCK.write_lock();
        link_chain(root, &nodes);

        // SAFETY: DERIVATION_LOCK held.
        let (first_objects, first_status) = unsafe { revoke_subtree_batch(root) };
        let first_freed = first_objects.len();

        // Between batches, every survivor must be a direct child of root.
        // No panics while the global lock is held — capture, unlock, assert.
        let mut survivors = 0;
        let mut all_hoisted = true;
        // SAFETY: DERIVATION_LOCK held.
        let mut cur = unsafe { resolve_slot_mut(root) }.and_then(|s| s.deriv_first_child);
        let mut all_resolved = true;
        while let Some(node) = cur
        {
            // SAFETY: DERIVATION_LOCK held.
            let Some(slot) = (unsafe { resolve_slot_mut(node) })
            else
            {
                all_resolved = false;
                break;
            };
            all_hoisted &= slot.deriv_parent == Some(root);
            survivors += 1;
            cur = slot.deriv_next_sibling;
        }
        DERIVATION_LOCK.write_unlock();

        assert_eq!(first_status, BatchStatus::MoreWork);
        assert!(all_resolved, "every survivor must resolve");
        assert!(all_hoisted, "every survivor hoisted under root");
        assert_eq!(survivors, BUDGET_CHAIN - first_freed);
        crate::cap::unregister_cspace(ID);
    }

    #[test]
    fn revoke_batch_dead_link_truncates_and_reports()
    {
        const ID_A: crate::cap::slot::CSpaceId = 3103;
        const ID_B: crate::cap::slot::CSpaceId = 3104;
        let cs_a = mk_registered_cspace(ID_A, 64);
        let cs_b = mk_registered_cspace(ID_B, 64);
        let root = occupy(cs_a, ID_A);
        let foreign_child = occupy(cs_b, ID_B);
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; both slots live.
        unsafe { link_child(root, foreign_child) };

        // Simulate the corruption the drain invariant forbids: the child's
        // CSpace vanishes without its foreign back-links being spliced.
        crate::cap::unregister_cspace(ID_B);

        // SAFETY: DERIVATION_LOCK held.
        let (objects, status) = unsafe { revoke_subtree_batch(root) };
        let collected = objects.len();
        // No panics while the global lock is held — capture, unlock, assert.
        // SAFETY: DERIVATION_LOCK held.
        let root_state = unsafe { resolve_slot_mut(root) }.map(|s| s.deriv_first_child);
        DERIVATION_LOCK.write_unlock();

        assert_eq!(status, BatchStatus::DeadLink);
        assert_eq!(collected, 0, "nothing collectable behind a dead link");
        // Containment: the dangling chain is cut so a retry cannot spin
        // (root still resolves; its child list is empty).
        assert_eq!(root_state, Some(None));
        crate::cap::unregister_cspace(ID_A);
    }
}
