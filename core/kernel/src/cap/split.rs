// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/split.rs

//! Shared tail of the range-authority split syscalls.
//!
//! `SYS_IRQ_SPLIT`, `SYS_MMIO_SPLIT`, `SYS_IOPORT_SPLIT`, and `SYS_SCHED_SPLIT`
//! all narrow a `[..]`-range capability into two disjoint children. The
//! per-cap handlers differ only in how they validate the split point and
//! construct the two child object bodies; everything after that — installing
//! both children into the caller's `CSpace`, rewiring the derivation tree, and
//! consuming the original — is identical. That common tail lives here.

use core::num::NonZeroU32;
use core::ptr::NonNull;

use crate::cap::cspace::CSpace;
#[cfg(not(test))]
use crate::cap::derivation::{DERIVATION_LOCK, MAX_REPARENT_BATCHES, link_child};
use crate::cap::derivation::{MAX_REPARENT_EDITS, reparent_children, unlink_node};
use crate::cap::object::KernelObjectHeader;
#[cfg(not(test))]
use crate::cap::object::dealloc_object;
use crate::cap::slot::{CSpaceId, CapTag, CapabilitySlot, Rights, SlotId};
use syscall::SyscallError;

/// Install the two children of a range-cap split and consume the original.
///
/// The caller must have already validated the split point and allocated the
/// two child object bodies. This:
///   1. under `DERIVATION_LOCK`, revalidates the original, inserts both
///      children into the caller's `CSpace` (`cspace.lock` nested) and links
///      each under the original's derivation parent — in the same hold, so
///      no child is ever reachable but unlinked (see
///      `core/kernel/docs/capability-internals.md` § Revocation Algorithm);
///      either insert failing rolls back (a body is deallocated only once
///      nothing references it);
///   2. reparents the original's children to that parent in
///      `MAX_REPARENT_EDITS` batches ([`split_batch`]), the lock released
///      between batches with this CPU's pending interrupts taken there and
///      both children pinned meanwhile, so no sibling derives from, copies,
///      moves, deletes, or transfers one before the split ends; a batch that
///      finds the original gone rolls both children back (no handle is
///      returned);
///   3. in the final batch's hold, unlinks the original, unpins both
///      children, and frees the original slot; then drops the slot's object
///      reference.
///
/// The original was looked up without the derivation lock, so it is
/// revalidated under the lock (`Original::revalidate`) before every batch and
/// before it is consumed. The failure semantics (`InvalidState`,
/// `Interrupted`, and the children earlier batches already moved) are defined
/// in `core/kernel/docs/syscalls.md` § `SYS_MMIO_SPLIT` and
/// `core/kernel/docs/capability-internals.md` § Revocation Algorithm.
///
/// Returns the two encoded child handles `(handle1, handle2)` (generation +
/// index each), minted under the insert's own `cspace.lock` hold (see
/// `core/kernel/docs/capability-internals.md` § Revocation Algorithm).
/// The caller delivers `handle1` in the primary return register and
/// `handle2` in the secondary — never packed into one word, so a high
/// generation cannot set the sign bit of an `i64` return (#349).
///
/// # Safety
/// `caller_cspace` must be a valid non-null `CSpace` pointer for the calling
/// thread, and `cspace_id` must equal `(*caller_cspace).id()`. `orig_handle`
/// must be the capability handle (index + generation) that resolved the
/// original cap (tag `tag`) in that `CSpace` via `lookup_cap`, and
/// `orig_obj_ptr` must be the object it resolved to (refcount > 0).
/// `child1_ptr` and `child2_ptr` must be freshly-allocated arena-backed bodies
/// of tag `tag`, each with refcount 1, not yet inserted into any `CSpace`.
/// Syscall context with interrupts disabled and no lock held: the batches
/// take `DERIVATION_LOCK` and open an interrupt window between them.
#[cfg(not(test))]
#[expect(
    clippy::too_many_arguments,
    reason = "the split tail genuinely needs the original cap's coordinates (cspace, id, slot, \
              tag, rights, object) plus both children; bundling them into a struct would only move \
              the argument list, not shrink it"
)]
pub(crate) unsafe fn install_split_children(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    orig_handle: u64,
    tag: CapTag,
    rights: Rights,
    orig_obj_ptr: NonNull<KernelObjectHeader>,
    child1_ptr: NonNull<KernelObjectHeader>,
    child2_ptr: NonNull<KernelObjectHeader>,
) -> Result<(u64, u64), SyscallError>
{
    let orig_idx = syscall::cap_handle_index(orig_handle);
    let orig_gen = syscall::cap_handle_gen(orig_handle);
    let Some(orig_idx_nz) = NonZeroU32::new(orig_idx)
    else
    {
        // Unreachable for the in-tree callers (each resolves orig_handle with
        // lookup_cap, which rejects slot 0), but fail as the other arms do:
        // return both uninserted children to their arena.
        // SAFETY: both bodies are fresh (refcount 1) and were never inserted
        // anywhere (caller contract).
        unsafe { dealloc_object(child1_ptr) };
        // SAFETY: as above.
        unsafe { dealloc_object(child2_ptr) };
        return Err(SyscallError::InvalidCapability);
    };
    let original = Original {
        idx: orig_idx,
        generation: orig_gen,
        tag,
        object: orig_obj_ptr,
    };

    // First hold: revalidate the original, insert and link both children
    // (see the function doc), then run the first batch.
    DERIVATION_LOCK.write_lock();
    // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
    let Revalidated::Live { parent } = (unsafe { original.revalidate(caller_cspace) })
    else
    {
        DERIVATION_LOCK.write_unlock();
        // SAFETY: both bodies are fresh (refcount 1) and were never inserted
        // anywhere.
        unsafe { dealloc_object(child1_ptr) };
        // SAFETY: as above.
        unsafe { dealloc_object(child2_ptr) };
        return Err(SyscallError::InvalidState);
    };
    // SAFETY: caller contract (children fresh, refcount 1, uninserted);
    // DERIVATION_LOCK held, released by the helper on failure.
    let (child1, child2) = unsafe {
        insert_and_link_children(
            caller_cspace,
            cspace_id,
            tag,
            rights,
            parent,
            child1_ptr,
            child2_ptr,
        )
    }?;
    let split = SplitInFlight {
        cspace: caller_cspace,
        cspace_id,
        orig_node: SlotId::current(cspace_id, orig_idx_nz),
        original,
        child1,
        child2,
    };

    let mut batches: u32 = 0;
    loop
    {
        // SAFETY: DERIVATION_LOCK held; split as built above for this split.
        match unsafe { split_batch(&split, &mut batches, MAX_REPARENT_BATCHES) }
        {
            SplitStep::Pending =>
            {
                // Take this CPU's pending interrupts between the batches (no
                // lock is held, per the contract); the next hold revalidates
                // the original.
                DERIVATION_LOCK.write_unlock_between_batches();
                DERIVATION_LOCK.write_lock();
            }
            SplitStep::Done =>
            {
                DERIVATION_LOCK.write_unlock();
                // Release the reference the consumed slot held, freeing the
                // original if it was the last (a caller's syscall pin,
                // released after this call, usually is).
                // SAFETY: orig_obj_ptr is the object the freed slot
                // referenced, live until this release (contract: refcount >
                // 0), and the slot's reference is released exactly once,
                // here; syscall context with no lock held.
                unsafe { crate::cap::object::release_ref(orig_obj_ptr) };
                // Return the handles minted under the insert's lock hold
                // (#349), never a re-read of the slot
                // (core/kernel/docs/capability-internals.md § Revocation
                // Algorithm).
                return Ok((child1.handle, child2.handle));
            }
            SplitStep::Failed(e, released) =>
            {
                DERIVATION_LOCK.write_unlock();
                // SAFETY: each flagged pointer reached refcount zero in
                // rollback_child and is referenced by no slot.
                unsafe { dealloc_rolled_back(released, child1.object, child2.object) };
                return Err(e);
            }
        }
    }
}

/// A split between its `DERIVATION_LOCK` holds: the caller's `CSpace`, the
/// original, and the two children inserted in the first hold.
#[derive(Clone, Copy)]
struct SplitInFlight
{
    cspace: *mut CSpace,
    cspace_id: CSpaceId,
    orig_node: SlotId,
    original: Original,
    child1: InsertedChild,
    child2: InsertedChild,
}

/// Outcome of one [`split_batch`] hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SplitStep
{
    /// Children of the original remain to be moved; both split children are
    /// pinned, and the caller releases the lock before the next batch.
    Pending,
    /// The original was unlinked and its slot freed in this hold, and both
    /// children unpinned; the slot's object reference is the caller's to
    /// release once the lock is released.
    Done,
    /// The split failed in this hold and both children were rolled back;
    /// the flags name, in `(child1, child2)` order, the bodies to deallocate
    /// once the lock is released (see [`rollback_child`]).
    Failed(SyscallError, (bool, bool)),
}

/// One split hold: revalidate the original, move one `MAX_REPARENT_EDITS`
/// batch of its children under its derivation parent, then end the split in
/// this hold or leave it pending. `backstop` is the batch count at which a
/// split still pending fails with `Interrupted` (`MAX_REPARENT_BATCHES`; the
/// host tests lower it to reach that arm).
///
/// Every exit leaves no pin of the split's behind: `Done` unpins both
/// children, and `Failed` frees their slots, which clears a slot's pin
/// (`CapabilitySlot::set_next_free`). Only `Pending` leaves them pinned, for
/// the caller's next hold. A child an ancestor's revoke freed meanwhile is
/// not touched, nor any refill of its slot (`InsertedChild::still_held`).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; `split.cspace` must be
/// valid, its children as returned by [`insert_children`] for this split
/// and linked in its first hold, and `batches` the count earlier holds of
/// this split left.
unsafe fn split_batch(split: &SplitInFlight, batches: &mut u32, backstop: u32) -> SplitStep
{
    // The parent is re-read with every revalidation: a delete of the parent
    // between batches moves the original (and the children already moved)
    // under the grandparent.
    // SAFETY: caller contract.
    let parent = match unsafe { split.original.revalidate(split.cspace) }
    {
        Revalidated::Live { parent } => parent,
        Revalidated::Gone =>
        {
            // Deleted or recycled meanwhile (consuming the slot would free an
            // unrelated cap and release the original's object twice), or
            // pinned by a revoke, move, IPC capability transfer, or range split
            // in flight (see `CapabilitySlot::pinned`).
            // SAFETY: caller contract.
            let released = unsafe { rollback_children(split) };
            return SplitStep::Failed(SyscallError::InvalidState, released);
        }
    };
    // SAFETY: DERIVATION_LOCK held; the original revalidated in this hold.
    let done = unsafe { reparent_children(split.orig_node, parent, MAX_REPARENT_EDITS) };
    // The backstop below ends the split once the count reaches it.
    *batches = batches.saturating_add(1);
    if done
    {
        // SAFETY: DERIVATION_LOCK held; orig_node revalidated in this hold.
        unsafe { unlink_node(split.orig_node) };
        // SAFETY: caller contract.
        if let Some(slot) = unsafe { split.child1.held_slot(split.cspace) }
        {
            slot.unpin();
        }
        // SAFETY: caller contract.
        if let Some(slot) = unsafe { split.child2.held_slot(split.cspace) }
        {
            slot.unpin();
        }
        // Freed inside the SAME derivation-lock hold as the unlink above: a
        // gap would let a concurrent derive re-link a child under the
        // still-handle-valid original, stranding it as a dangling parent
        // link.
        // SAFETY: split.cspace validated; the original's index is within its
        // bounds (revalidated above); cspace.lock nests inside
        // DERIVATION_LOCK (core/kernel/docs/scheduling-internals.md § Lock
        // Hierarchy).
        let lock = unsafe { &(*split.cspace).lock };
        // SAFETY: as above; lock_raw/unlock_raw paired.
        let saved = unsafe { lock.lock_raw() };
        // SAFETY: as above; cspace.lock held.
        unsafe { (*split.cspace).free_slot(split.original.idx) };
        // SAFETY: as above.
        let lock = unsafe { &(*split.cspace).lock };
        // SAFETY: paired with lock_raw above.
        unsafe { lock.unlock_raw(saved) };
        return SplitStep::Done;
    }
    if *batches >= backstop
    {
        // A concurrent deriver is extending the list faster than it is
        // moved: fail closed rather than loop in-kernel forever.
        // SAFETY: caller contract.
        let released = unsafe { rollback_children(split) };
        return SplitStep::Failed(SyscallError::Interrupted, released);
    }
    // The lock is released before the next batch. Pin both children
    // (`CapabilitySlot::pin`, idempotent across holds) so that no sibling
    // derives from, copies, moves, deletes, or transfers one until this split
    // ends: each stays childless and where the first hold put it, which keeps
    // [`rollback_child`] one constant-time step.
    // SAFETY: caller contract.
    if let Some(slot) = unsafe { split.child1.held_slot(split.cspace) }
    {
        slot.pin();
    }
    // SAFETY: caller contract.
    if let Some(slot) = unsafe { split.child2.held_slot(split.cspace) }
    {
        slot.pin();
    }
    SplitStep::Pending
}

/// The original cap as looked up before `DERIVATION_LOCK` was taken.
#[derive(Clone, Copy)]
struct Original
{
    idx: u32,
    generation: u32,
    tag: CapTag,
    object: NonNull<KernelObjectHeader>,
}

/// Outcome of revalidating the original under `DERIVATION_LOCK`.
#[derive(Clone, Copy)]
enum Revalidated
{
    /// Deleted, recycled, or pinned by a revoke, move, IPC capability
    /// transfer, or range split in flight since the lookup
    /// (`CapabilitySlot::pinned`).
    Gone,
    /// Still the cap that was looked up; its derivation parent (`None` for
    /// a root).
    Live
    {
        parent: Option<SlotId>
    },
}

impl Original
{
    /// Whether `cspace`'s slot still holds this cap under the looked-up
    /// generation and is not pinned by a revoke, move, IPC capability
    /// transfer, or range split in flight (`CapabilitySlot::pinned`).
    ///
    /// # Safety
    ///
    /// `cspace` must be valid; caller must hold `DERIVATION_LOCK`, so a free
    /// of the slot is observed stably (every free holds the lock).
    unsafe fn revalidate(self, cspace: *mut CSpace) -> Revalidated
    {
        // SAFETY: caller contract.
        match unsafe { (*cspace).slot(self.idx) }
        {
            Some(slot)
                if slot.tag == self.tag
                    && slot.generation() == self.generation
                    && slot.object == Some(self.object)
                    && !slot.pinned() =>
            {
                Revalidated::Live {
                    parent: slot.deriv_parent,
                }
            }
            _ => Revalidated::Gone,
        }
    }
}

/// Roll both split children back under `DERIVATION_LOCK`; returns, in
/// `(child1, child2)` order, which bodies the caller must deallocate once it
/// has released the lock (see [`rollback_child`]).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; `split` as for
/// [`split_batch`].
unsafe fn rollback_children(split: &SplitInFlight) -> (bool, bool)
{
    // SAFETY: caller contract.
    let released1 = unsafe { rollback_child(split.cspace, split.cspace_id, split.child1) };
    // SAFETY: caller contract.
    let released2 = unsafe { rollback_child(split.cspace, split.cspace_id, split.child2) };
    (released1, released2)
}

/// First-hold step of a split: insert both children into the caller's
/// `CSpace` and link each under `parent` — the revalidated original's
/// derivation parent (`None` for a root) — all inside the caller's
/// `DERIVATION_LOCK` hold. On error the lock has been released and both
/// bodies disposed of (deallocated, or left to their new owners).
///
/// # Safety
///
/// As for [`insert_children`], plus: the caller holds `DERIVATION_LOCK`
/// write lock and, when this returns `Err`, no longer does.
#[cfg(not(test))]
unsafe fn insert_and_link_children(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    tag: CapTag,
    rights: Rights,
    parent: Option<SlotId>,
    child1_ptr: NonNull<KernelObjectHeader>,
    child2_ptr: NonNull<KernelObjectHeader>,
) -> Result<(InsertedChild, InsertedChild), SyscallError>
{
    // SAFETY: caller contract; DERIVATION_LOCK held.
    let inserted = unsafe {
        insert_children(
            caller_cspace,
            cspace_id,
            tag,
            rights,
            child1_ptr,
            child2_ptr,
        )
    };
    let (child1, child2) = match inserted
    {
        Ok(pair) => pair,
        Err((e, released)) =>
        {
            DERIVATION_LOCK.write_unlock();
            // SAFETY: each flagged pointer is an unreferenced refcount-0
            // body (see insert_children).
            unsafe { dealloc_rolled_back(released, child1_ptr, child2_ptr) };
            return Err(e);
        }
    };
    if let Some(parent_id) = parent
    {
        // SAFETY: DERIVATION_LOCK held; parent_id is the revalidated
        // original's parent and both child slots are occupied by the
        // inserts above. A parent whose CSpace has since unregistered is a
        // dead link (see `truncate_dead_link`); the children then stay
        // clean roots, as `reparent_children` leaves them.
        let _ = unsafe { link_child(parent_id, SlotId::current(cspace_id, child1.slot)) };
        // SAFETY: as above.
        let _ = unsafe { link_child(parent_id, SlotId::current(cspace_id, child2.slot)) };
    }
    Ok((child1, child2))
}

/// One split child as installed by [`insert_children`]: its slot, the
/// handle minted under the same `cspace.lock` hold as the insert, and the
/// object body it references.
#[derive(Clone, Copy)]
struct InsertedChild
{
    slot: NonZeroU32,
    handle: u64,
    object: NonNull<KernelObjectHeader>,
}

impl InsertedChild
{
    /// Whether the slot still holds this child: same object under the
    /// insert-time generation. The generation is what makes the check
    /// ABA-safe — a sibling can delete the child, have the slab reuse the
    /// body address, and refill the slot with that new object, but the
    /// slot's free bumped the generation.
    ///
    /// # Safety
    ///
    /// `cspace` must be valid; caller must hold `DERIVATION_LOCK` so the
    /// answer stays stable for the caller's subsequent use.
    unsafe fn still_held(self, cspace: *mut CSpace) -> bool
    {
        // SAFETY: caller contract.
        unsafe { (*cspace).slot(self.slot.get()) }.is_some_and(|s| {
            s.generation() == syscall::cap_handle_gen(self.handle) && s.object == Some(self.object)
        })
    }

    /// The child's slot when it still holds this child
    /// ([`still_held`](Self::still_held)); `None` for a slot an ancestor's
    /// revoke freed, and for any refill of it, which the split leaves as it
    /// is.
    ///
    /// # Safety
    ///
    /// `cspace` must be valid, and the caller must hold `DERIVATION_LOCK`
    /// while it uses the slot (the in-flight pin is written only under it).
    unsafe fn held_slot<'a>(self, cspace: *mut CSpace) -> Option<&'a mut CapabilitySlot>
    {
        // SAFETY: caller contract.
        if !unsafe { self.still_held(cspace) }
        {
            return None;
        }
        // SAFETY: caller contract.
        unsafe { (*cspace).slot_mut(self.slot.get()) }
    }
}

/// Insert both split children into the caller's `CSpace`, returning each
/// with the handle minted under its insert's lock hold. On either insert
/// failure the error carries, in `(child1, child2)` order, which bodies the
/// caller must deallocate once it has released `DERIVATION_LOCK` (a slot1
/// already taken is released through [`rollback_child`] first).
///
/// # Safety
///
/// `caller_cspace` must be valid and non-null with id `cspace_id`;
/// `child1_ptr`/`child2_ptr` must be freshly-allocated refcount-1 bodies of
/// tag `tag` not yet inserted anywhere. Caller must hold `DERIVATION_LOCK`
/// write lock: the slot1 rollback runs under it, and `cspace.lock` nests
/// inside it (`core/kernel/docs/scheduling-internals.md` § Lock Hierarchy).
#[cfg(not(test))]
unsafe fn insert_children(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    tag: CapTag,
    rights: Rights,
    child1_ptr: NonNull<KernelObjectHeader>,
    child2_ptr: NonNull<KernelObjectHeader>,
) -> Result<(InsertedChild, InsertedChild), (SyscallError, (bool, bool))>
{
    // Insert both children into the caller's CSpace under cspace.lock so the
    // freelist mutation cannot tear against a concurrent SYS_CAP_CREATE_*;
    // `insert_cap_slot_and_handle` mints each handle in the same hold.
    let child1 = {
        // SAFETY: caller_cspace validated by the caller.
        let lock = unsafe { &(*caller_cspace).lock };
        // SAFETY: as above; lock_raw/unlock_raw paired.
        let saved = unsafe { lock.lock_raw() };
        // SAFETY: as above; cspace.lock held.
        let r = unsafe { (*caller_cspace).insert_cap_slot_and_handle(tag, rights, child1_ptr) }
            .map(|(slot, handle)| InsertedChild {
                slot,
                handle,
                object: child1_ptr,
            });
        // SAFETY: as above.
        let lock = unsafe { &(*caller_cspace).lock };
        // SAFETY: paired with lock_raw above.
        unsafe { lock.unlock_raw(saved) };
        r
    }
    // Neither body has been stored: the caller frees both.
    .map_err(|e| (SyscallError::from(e), (true, true)))?;
    let child2 = {
        // SAFETY: caller_cspace validated by the caller.
        let lock = unsafe { &(*caller_cspace).lock };
        // SAFETY: as above; lock_raw/unlock_raw paired.
        let saved = unsafe { lock.lock_raw() };
        // SAFETY: as above; cspace.lock held.
        let r = unsafe { (*caller_cspace).insert_cap_slot_and_handle(tag, rights, child2_ptr) }
            .map(|(slot, handle)| InsertedChild {
                slot,
                handle,
                object: child2_ptr,
            });
        // SAFETY: as above.
        let lock = unsafe { &(*caller_cspace).lock };
        // SAFETY: paired with lock_raw above.
        unsafe { lock.unlock_raw(saved) };
        r
    }
    .map_err(|e| {
        // Undo slot1: child1_ptr was inserted (reachable only via slot1);
        // child2_ptr was passed to the failing insert_cap_slot_and_handle and
        // never stored.
        // SAFETY: caller_cspace validated; DERIVATION_LOCK held by the
        // caller, so the occupied-to-free transition stays atomic against
        // derivation-side occupancy gates (see `resolve_slot_mut`).
        let release1 = unsafe { rollback_child(caller_cspace, cspace_id, child1) };
        // child1_ptr is freed only if rollback_child dropped its last
        // reference; child2_ptr was never stored.
        (SyscallError::from(e), (release1, true))
    })?;
    Ok((child1, child2))
}

/// Release one split child during rollback.
///
/// If the slot still holds the child under its insert-time generation, the
/// child is unlinked, its slot freed (which clears its in-flight pin), and
/// the object's reference dropped; returns `true` only when that drop
/// reached zero, in which case the caller must
/// `dealloc_object(child.object)` after releasing the lock. Returns `false`
/// if the slot no longer holds the child (an ancestor's revoke freed it; a
/// refill of the slot since is left as it is), or other references to the
/// object remain (a sibling's syscall invoking the child holds one until it
/// returns).
///
/// The child is childless, so the rollback is one constant-time step: no
/// child list is walked under the lock. Nothing derives from it before the
/// first hold releases the lock, and from then until the split ends it is
/// pinned ([`split_batch`]): a copy, derive, move or IPC transfer refuses a
/// pinned source and a revoke a pinned root, so no path links a slot under
/// it (core/kernel/docs/capability-internals.md § Revocation Algorithm).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; `caller_cspace` must be
/// valid with id `cspace_id`, and `child` as returned by [`insert_children`]
/// for this split.
unsafe fn rollback_child(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    child: InsertedChild,
) -> bool
{
    // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
    if !unsafe { child.still_held(caller_cspace) }
    {
        return false;
    }
    let slot = child.slot;
    let child_ptr = child.object;
    let child_id = SlotId::current(cspace_id, slot);
    // The child has no child (see above); were one ever linked under it, it
    // would go under the child's own parent (the original's parent, or roots
    // if the original was a root), never out of an ancestor's revoke reach.
    // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
    let child_parent = unsafe { (*caller_cspace).slot(slot.get()) }.and_then(|s| s.deriv_parent);
    // SAFETY: DERIVATION_LOCK held; child_id occupied (checked above).
    let childless = unsafe { reparent_children(child_id, child_parent, MAX_REPARENT_EDITS) };
    debug_assert!(childless, "a pinned split child gained children");
    // SAFETY: DERIVATION_LOCK held.
    unsafe { unlink_node(child_id) };
    // SAFETY: caller_cspace validated; cspace.lock nests inside
    // DERIVATION_LOCK (core/kernel/docs/scheduling-internals.md
    // § Lock Hierarchy).
    let lock = unsafe { &(*caller_cspace).lock };
    // SAFETY: as above; lock_raw/unlock_raw paired.
    let saved = unsafe { lock.lock_raw() };
    // SAFETY: as above; cspace.lock held.
    unsafe { (*caller_cspace).free_slot(slot.get()) };
    // SAFETY: as above.
    let lock = unsafe { &(*caller_cspace).lock };
    // SAFETY: paired with lock_raw above.
    unsafe { lock.unlock_raw(saved) };
    // SAFETY: child_ptr is a live object header (the slot referenced it
    // until the free above); the slot's reference is dropped exactly once.
    unsafe { (*child_ptr.as_ptr()).dec_ref() == 0 }
}

/// Deallocate the split children flagged (`(child1, child2)` order) as
/// having reached refcount zero in [`rollback_child`], or never stored.
///
/// # Safety
///
/// Must run with `DERIVATION_LOCK` released (dealloc may take inner locks);
/// each flagged pointer must be an unreferenced refcount-0 body.
#[cfg(not(test))]
unsafe fn dealloc_rolled_back(
    released: (bool, bool),
    child1_ptr: NonNull<KernelObjectHeader>,
    child2_ptr: NonNull<KernelObjectHeader>,
)
{
    if released.0
    {
        // SAFETY: caller contract.
        unsafe { dealloc_object(child1_ptr) };
    }
    if released.1
    {
        // SAFETY: caller contract.
        unsafe { dealloc_object(child2_ptr) };
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cap::derivation::harness::*;
    use crate::cap::derivation::{DERIVATION_LOCK, MAX_REPARENT_BATCHES, link_child};
    use crate::cap::object::ObjectType;
    use core::sync::atomic::Ordering;

    /// A real header for a child or the original: the rollback drops a
    /// child's reference, which the harness's dangling object pointers
    /// cannot carry. Refcount starts at 1, standing in for the slot.
    fn mk_object() -> NonNull<KernelObjectHeader>
    {
        NonNull::from(Box::leak(Box::new(KernelObjectHeader::new(
            ObjectType::Notification,
        ))))
    }

    fn refcount(obj: NonNull<KernelObjectHeader>) -> u32
    {
        // SAFETY: leaked header, valid for the process lifetime.
        unsafe { obj.as_ref() }.ref_count.load(Ordering::Relaxed)
    }

    /// Give the occupied slot `id` the object `obj`.
    fn hold(cs: *mut CSpace, id: SlotId, obj: NonNull<KernelObjectHeader>)
    {
        // SAFETY: single-threaded test ownership of the leaked CSpace.
        unsafe {
            (*cs)
                .slot_mut(id.index.get())
                .expect("occupied slot")
                .object = Some(obj);
        };
    }

    /// The state a split has after its first hold: an original under `root`
    /// with `kids` children, and both split children inserted and linked
    /// under `root`, each holding a fresh object.
    struct Fixture
    {
        cs: *mut CSpace,
        split: SplitInFlight,
        root: SlotId,
        kids: Vec<SlotId>,
    }

    fn mk_split(id: CSpaceId, kids: usize) -> Fixture
    {
        let cs = mk_registered_cspace(id);
        let root = occupy(cs, id);
        let orig = occupy(cs, id);
        let c1 = occupy(cs, id);
        let c2 = occupy(cs, id);
        let kids = occupy_many(cs, id, kids);
        let orig_obj = mk_object();
        hold(cs, orig, orig_obj);
        let child = |slot: SlotId| {
            let object = mk_object();
            hold(cs, slot, object);
            InsertedChild {
                slot: slot.index,
                // SAFETY: single-threaded test ownership of the leaked CSpace.
                handle: unsafe { (*cs).cap_handle(slot.index) },
                object,
            }
        };
        let (child1, child2) = (child(c1), child(c2));
        // SAFETY: single-threaded test ownership of the leaked CSpace.
        let orig_handle = unsafe { (*cs).cap_handle(orig.index) };
        let split = SplitInFlight {
            cspace: cs,
            cspace_id: id,
            orig_node: orig,
            original: Original {
                idx: orig.index.get(),
                generation: syscall::cap_handle_gen(orig_handle),
                tag: CapTag::Endpoint,
                object: orig_obj,
            },
            child1,
            child2,
        };
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; all slots live.
        let mut linked = unsafe { link_child(root, orig) };
        for k in &kids
        {
            // SAFETY: DERIVATION_LOCK held; all slots live.
            linked &= unsafe { link_child(orig, *k) };
        }
        // SAFETY: DERIVATION_LOCK held; all slots live.
        linked &= unsafe { link_child(root, c1) };
        // SAFETY: DERIVATION_LOCK held; all slots live.
        linked &= unsafe { link_child(root, c2) };
        DERIVATION_LOCK.write_unlock();
        assert!(linked, "setup links must land");
        Fixture {
            cs,
            split,
            root,
            kids,
        }
    }

    /// One split hold, as `install_split_children` runs it.
    fn step(f: &Fixture, batches: &mut u32, backstop: u32) -> SplitStep
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; the fixture is this split's state.
        let s = unsafe { split_batch(&f.split, batches, backstop) };
        DERIVATION_LOCK.write_unlock();
        s
    }

    /// `(occupied, pinned)` of slot `idx`, read under the lock.
    fn state(cs: *mut CSpace, idx: u32) -> (bool, bool)
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; single-threaded test ownership.
        let s = unsafe { (*cs).slot(idx) }
            .map_or((false, false), |s| (s.tag != CapTag::Null, s.pinned()));
        DERIVATION_LOCK.write_unlock();
        s
    }

    fn children(f: &Fixture) -> [(bool, bool); 2]
    {
        [
            state(f.cs, f.split.child1.slot.get()),
            state(f.cs, f.split.child2.slot.get()),
        ]
    }

    fn parent_of(cs: *mut CSpace, idx: u32) -> Option<SlotId>
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; single-threaded test ownership.
        let p = unsafe { (*cs).slot(idx) }.and_then(|s| s.deriv_parent);
        DERIVATION_LOCK.write_unlock();
        p
    }

    /// Free `id` as an ancestor's revoke does once it reaches it: unlinked,
    /// its slot freed under the lock.
    fn free_as_revoked(cs: *mut CSpace, id: SlotId)
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; id occupied.
        unsafe { unlink_node(id) };
        // SAFETY: DERIVATION_LOCK held; single-threaded test ownership.
        unsafe { (*cs).free_slot(id.index.get()) };
        DERIVATION_LOCK.write_unlock();
    }

    /// Set the in-flight pin on `idx` as a revoke, move, or transfer does.
    fn pin(cs: *mut CSpace, idx: u32)
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; single-threaded test ownership.
        let s = unsafe { (*cs).slot_mut(idx) };
        let found = s.map(CapabilitySlot::pin).is_some();
        DERIVATION_LOCK.write_unlock();
        assert!(found, "slot {idx} resolves");
    }

    const UNPINNED: (bool, bool) = (true, false);
    const PINNED: (bool, bool) = (true, true);
    const FREED: (bool, bool) = (false, false);

    // Defect guarded: a split that pins its children for a batch it never
    // releases the lock after makes the common one-hold split pay a pin.
    #[test]
    fn one_hold_split_never_pins()
    {
        let f = mk_split(3401, 3);
        let mut batches = 0;
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Done
        );
        assert_eq!(children(&f), [UNPINNED; 2]);
        assert_eq!(state(f.cs, f.split.original.idx), FREED);
        assert!(
            f.kids
                .iter()
                .all(|k| parent_of(f.cs, k.index.get()) == Some(f.root))
        );
    }

    // Defect guarded: a child left unpinned between batches can gain a
    // child, which the rollback would then walk under the lock; a child left
    // pinned after the split ends refuses its holder's copy, delete, and move
    // for good.
    #[test]
    fn multi_batch_split_pins_children_until_its_final_hold()
    {
        let f = mk_split(3402, 2 * MAX_REPARENT_EDITS + 1);
        let mut batches = 0;
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Pending
        );
        assert_eq!(children(&f), [PINNED; 2]);
        assert_eq!(state(f.cs, f.split.original.idx), UNPINNED);
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Pending
        );
        assert_eq!(children(&f), [PINNED; 2]);
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Done
        );
        assert_eq!(batches, 3);
        assert_eq!(children(&f), [UNPINNED; 2]);
        assert_eq!(state(f.cs, f.split.original.idx), FREED);
        assert!(
            f.kids
                .iter()
                .all(|k| parent_of(f.cs, k.index.get()) == Some(f.root))
        );
    }

    // Defect guarded: an `InvalidState` exit that rolls the children back
    // without freeing their slots leaves them pinned.
    #[test]
    fn original_gone_between_batches_frees_both_children()
    {
        let f = mk_split(3403, MAX_REPARENT_EDITS + 1);
        let mut batches = 0;
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Pending
        );
        // A revoke starting on the original pins it: the next hold finds it
        // gone.
        pin(f.cs, f.split.original.idx);
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Failed(SyscallError::InvalidState, (true, true))
        );
        assert_eq!(children(&f), [FREED; 2]);
        assert_eq!(refcount(f.split.child1.object), 0);
        assert_eq!(refcount(f.split.child2.object), 0);
        // The revoke's pin is the revoke's to clear.
        assert_eq!(state(f.cs, f.split.original.idx), PINNED);
    }

    // Defect guarded: the `Interrupted` backstop exit leaves the children
    // pinned.
    #[test]
    fn backstop_frees_both_children()
    {
        let f = mk_split(3404, 2 * MAX_REPARENT_EDITS + 1);
        let mut batches = 0;
        assert_eq!(step(&f, &mut batches, 2), SplitStep::Pending);
        assert_eq!(
            step(&f, &mut batches, 2),
            SplitStep::Failed(SyscallError::Interrupted, (true, true))
        );
        assert_eq!(children(&f), [FREED; 2]);
        assert_eq!(state(f.cs, f.split.original.idx), UNPINNED);
    }

    /// Free child 1 as an ancestor's revoke does, refill its slot, and pin
    /// the refill as an operation of its own would.
    fn revoke_and_refill_child1(f: &Fixture, id: CSpaceId)
    {
        let c1 = SlotId::current(id, f.split.child1.slot);
        free_as_revoked(f.cs, c1);
        let refill = occupy(f.cs, id);
        assert_eq!(
            refill.index, f.split.child1.slot,
            "the freed slot is reused"
        );
        pin(f.cs, refill.index.get());
    }

    // Defect guarded: the final hold unpinning a slot that no longer holds
    // its child clears the pin of an unrelated operation on the refill.
    #[test]
    fn done_leaves_a_revoked_childs_refill_alone()
    {
        const ID: CSpaceId = 3405;
        let f = mk_split(ID, MAX_REPARENT_EDITS + 1);
        let mut batches = 0;
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Pending
        );
        revoke_and_refill_child1(&f, ID);
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Done
        );
        assert_eq!(children(&f), [PINNED, UNPINNED]);
    }

    // Defect guarded: a rollback freeing a slot that no longer holds its
    // child frees an unrelated capability.
    #[test]
    fn rollback_leaves_a_revoked_childs_refill_alone()
    {
        const ID: CSpaceId = 3406;
        let f = mk_split(ID, MAX_REPARENT_EDITS + 1);
        let mut batches = 0;
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Pending
        );
        revoke_and_refill_child1(&f, ID);
        pin(f.cs, f.split.original.idx);
        assert_eq!(
            step(&f, &mut batches, MAX_REPARENT_BATCHES),
            SplitStep::Failed(SyscallError::InvalidState, (false, true))
        );
        assert_eq!(children(&f), [PINNED, FREED]);
    }
}
