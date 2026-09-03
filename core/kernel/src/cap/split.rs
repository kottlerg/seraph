// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/split.rs

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
use crate::cap::derivation::{
    DERIVATION_LOCK, MAX_REPARENT_BATCHES, MAX_REPARENT_EDITS, link_child, reparent_children,
    unlink_node,
};
use crate::cap::object::{KernelObjectHeader, dealloc_object};
use crate::cap::slot::{CSpaceId, CapTag, Rights, SlotId};
use syscall::SyscallError;

/// Install the two children of a range-cap split and consume the original.
///
/// The caller must have already validated the split point and allocated the
/// two child object bodies. This:
///   1. under `DERIVATION_LOCK`, revalidates the original, inserts both
///      children into the caller's `CSpace` (`cspace.lock` nested) and links
///      each under the original's derivation parent — in the same hold, so
///      no child is ever reachable but unlinked (a sibling's `SYS_CAP_MOVE`
///      would carry an unlinked child out of the grantor's revoke reach);
///      either insert failing rolls back (a body is deallocated only once
///      nothing references it);
///   2. reparents the original's children to that parent in
///      `MAX_REPARENT_EDITS` batches (lock released between batches) and
///      unlinks the original; a batch that finds the original gone rolls
///      both children back (a child a sibling deleted or moved meanwhile is
///      left as the sibling left it; no handle is returned);
///   3. frees the original slot and drops its object reference.
///
/// The original was looked up without the derivation lock, so it is
/// revalidated under the lock before every batch and before it is consumed:
/// the slot must still hold `orig_obj_ptr` under `tag` with the handle's
/// generation and no revoke in flight. Otherwise a sibling thread deleted
/// (or deleted and recycled) it meanwhile; consuming the slot would then free
/// an unrelated cap and release the original's object twice, so the split
/// rolls both children back and fails with `InvalidState`. A concurrent
/// deriver extending the original's child list faster than one batch per
/// hold trips the `MAX_REPARENT_BATCHES` backstop (`Interrupted`, children
/// rolled back). On either failure the original's children that earlier
/// batches already moved stay under its parent, so the surviving original
/// no longer holds revoke authority over them (`syscalls.md`,
/// `SYS_MMIO_SPLIT`).
///
/// Returns the two encoded child handles `(handle1, handle2)` (generation +
/// index each), captured under the insert's own `cspace.lock` hold so a
/// child deleted and its slot refilled by a sibling before the split returns
/// yields a handle that no longer resolves, never a handle to the refill.
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
/// `child1_ptr` and `child2_ptr` must be freshly-allocated SEED-backed bodies
/// of tag `tag`, each with refcount 1, not yet inserted into any `CSpace`.
// too_many_arguments: the split tail genuinely needs the original cap's
// coordinates (cspace, id, slot, tag, rights, object) plus both children;
// bundling them into a struct would only move the argument list, not shrink it.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn install_split_children(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    orig_handle: u32,
    tag: CapTag,
    rights: Rights,
    orig_obj_ptr: NonNull<KernelObjectHeader>,
    child1_ptr: NonNull<KernelObjectHeader>,
    child2_ptr: NonNull<KernelObjectHeader>,
) -> Result<(u32, u32), SyscallError>
{
    let orig_idx = syscall::cap_handle_index(orig_handle);
    let orig_gen = syscall::cap_handle_gen(orig_handle);
    let orig_idx_nz = NonZeroU32::new(orig_idx).ok_or(SyscallError::InvalidCapability)?;
    let orig_node = SlotId::current(cspace_id, orig_idx_nz);
    let original = Original {
        idx: orig_idx,
        generation: orig_gen,
        tag,
        object: orig_obj_ptr,
    };

    // First hold: revalidate the original, insert and link both children
    // (see the function doc), then start moving the original's children.
    DERIVATION_LOCK.write_lock();
    // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
    let Revalidated::Live { mut parent } = (unsafe { original.revalidate(caller_cspace) })
    else
    {
        DERIVATION_LOCK.write_unlock();
        // SAFETY: both bodies are fresh (refcount 1) and were never inserted
        // anywhere.
        unsafe {
            dealloc_object(child1_ptr);
            dealloc_object(child2_ptr);
        }
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

    // Move the original's children under its parent in batches; the final
    // batch's hold continues below with the unlink and the consume. The
    // parent is re-read with every revalidation: a delete of the parent
    // between batches moves the original (and the children already moved)
    // under the grandparent.
    let mut batches: u32 = 0;
    loop
    {
        // SAFETY: DERIVATION_LOCK held; the original revalidated in this hold.
        let done = unsafe { reparent_children(orig_node, parent, MAX_REPARENT_EDITS) };
        batches += 1;
        if done
        {
            break;
        }
        if batches >= MAX_REPARENT_BATCHES
        {
            // A concurrent deriver is extending the list faster than it is
            // moved: fail closed rather than loop in-kernel forever.
            // SAFETY: DERIVATION_LOCK held; children inserted in the first hold.
            unsafe { rollback_children(caller_cspace, cspace_id, child1, child2) };
            return Err(SyscallError::Interrupted);
        }
        DERIVATION_LOCK.write_unlock();
        DERIVATION_LOCK.write_lock();
        // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
        match unsafe { original.revalidate(caller_cspace) }
        {
            Revalidated::Live { parent: p } => parent = p,
            Revalidated::Gone =>
            {
                // Deleted, recycled, or under revoke meanwhile: consuming
                // the slot would free an unrelated cap and release the
                // original's object twice.
                // SAFETY: as above.
                unsafe { rollback_children(caller_cspace, cspace_id, child1, child2) };
                return Err(SyscallError::InvalidState);
            }
        }
    }

    // SAFETY: DERIVATION_LOCK held (final batch); orig_node revalidated.
    unsafe { unlink_node(orig_node) };

    // ── Consume the original cap ──────────────────────────────────────────────
    // Freed inside the SAME derivation-lock hold as the unlink above: a gap
    // would let a concurrent derive re-link a child under the
    // still-handle-valid original, stranding it as a dangling parent link.
    // SAFETY: caller_cspace validated; orig_idx within CSpace bounds;
    // cspace.lock nests inside DERIVATION_LOCK per the documented order.
    unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        (*caller_cspace).free_slot(orig_idx);
        (*caller_cspace).lock.unlock_raw(saved);
    }

    DERIVATION_LOCK.write_unlock();

    // SAFETY: orig_obj_ptr from the caller's lookup; object still valid.
    let remaining = unsafe { (*orig_obj_ptr.as_ptr()).dec_ref() };
    if remaining == 0
    {
        // SAFETY: ref count reached zero; no other references exist.
        unsafe { dealloc_object(orig_obj_ptr) };
    }

    // Both handles were minted under the insert's lock hold (#349), so a
    // child a sibling deleted meanwhile yields a handle that no longer
    // resolves, exactly as if it had been deleted after the split returned;
    // re-reading the slot here could instead hand back a live handle to
    // whatever cap now occupies the recycled slot.
    Ok((child1.handle, child2.handle))
}

/// The original cap as looked up before `DERIVATION_LOCK` was taken.
#[derive(Clone, Copy)]
struct Original
{
    idx: u32,
    generation: u8,
    tag: CapTag,
    object: NonNull<KernelObjectHeader>,
}

/// Outcome of revalidating the original under `DERIVATION_LOCK`.
#[derive(Clone, Copy)]
enum Revalidated
{
    /// Deleted, recycled, or under revoke since the lookup.
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
    /// generation with no revoke in flight.
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
                    && !slot.revoke_in_progress() =>
            {
                Revalidated::Live {
                    parent: slot.deriv_parent,
                }
            }
            _ => Revalidated::Gone,
        }
    }
}

/// Roll both split children back, release `DERIVATION_LOCK`, and free the
/// bodies whose last reference went.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock (released here);
/// `caller_cspace` must be valid, and the children as returned by
/// [`insert_and_link_children`] for this split.
unsafe fn rollback_children(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    child1: InsertedChild,
    child2: InsertedChild,
)
{
    // SAFETY: caller contract.
    let released = unsafe {
        (
            rollback_child(caller_cspace, cspace_id, child1),
            rollback_child(caller_cspace, cspace_id, child2),
        )
    };
    DERIVATION_LOCK.write_unlock();
    // SAFETY: each flagged pointer reached refcount zero in rollback_child
    // and is referenced by no slot.
    unsafe { dealloc_rolled_back(released, child1.object, child2.object) };
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
        // inserts above.
        unsafe {
            link_child(parent_id, SlotId::current(cspace_id, child1.slot));
            link_child(parent_id, SlotId::current(cspace_id, child2.slot));
        }
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
    handle: u32,
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
/// inside it per the documented order.
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
    // freelist mutation cannot tear against a concurrent SYS_CAP_CREATE_*.
    // The handle is read under the same hold: a later read could see the
    // generation of a sibling's refill of the slot.
    // SAFETY: caller_cspace validated by the caller; lock_raw/unlock_raw paired.
    let child1 = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace)
            .insert_cap(tag, rights, child1_ptr)
            .map(|slot| InsertedChild {
                slot,
                handle: (*caller_cspace).cap_handle(slot),
                object: child1_ptr,
            });
        (*caller_cspace).lock.unlock_raw(saved);
        r
    }
    // Neither body has been stored: the caller frees both.
    .map_err(|e| (SyscallError::from(e), (true, true)))?;
    // SAFETY: caller_cspace validated by the caller; lock_raw/unlock_raw paired.
    let child2 = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace)
            .insert_cap(tag, rights, child2_ptr)
            .map(|slot| InsertedChild {
                slot,
                handle: (*caller_cspace).cap_handle(slot),
                object: child2_ptr,
            });
        (*caller_cspace).lock.unlock_raw(saved);
        r
    }
    .map_err(|e| {
        // Undo slot1: child1_ptr was inserted (reachable only via slot1);
        // child2_ptr was passed to the failing insert_cap and never stored.
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

/// Release one inserted-but-not-yet-wired split child during rollback.
///
/// If the slot still holds the child under its insert-time generation, the
/// slot is freed and the object's reference dropped; returns `true` only
/// when that drop reached zero, in which case the caller must
/// `dealloc_object(child.object)` after releasing the lock. Returns `false`
/// if a sibling thread already deleted the child (its delete released the
/// object), the slot was recycled since, or other slots still reference the
/// object — a sibling may have derived, copied, or moved the child between
/// its insert and this rollback, and those caps stay valid (a moved child
/// survives the failed split in its new `CSpace`). Anything derived from
/// the child is moved under the child's own parent first (the original's
/// parent; roots if the original was a root), so the free never strands a
/// child with a dangling parent link nor lets a descendant escape an
/// ancestor's revoke reach. That walk runs to completion under the lock:
/// its length is however many derivations a sibling landed in the window,
/// not a constant, but nothing can extend the list while the lock is held,
/// so it terminates.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; `caller_cspace` must be
/// valid, and `child` as returned by [`insert_children`] for this split.
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
    // Anything a sibling derived from the child meanwhile goes under the
    // child's own parent — the original's parent, or roots if the original
    // was a root — never out of an ancestor's revoke reach.
    // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
    let child_parent = unsafe { (*caller_cspace).slot(slot.get()) }.and_then(|s| s.deriv_parent);
    // SAFETY: DERIVATION_LOCK held; child_id occupied (checked above).
    while !unsafe { reparent_children(child_id, child_parent, MAX_REPARENT_EDITS) }
    {}
    // SAFETY: DERIVATION_LOCK held.
    unsafe { unlink_node(child_id) };
    // SAFETY: caller_cspace validated; cspace.lock nests inside
    // DERIVATION_LOCK per the documented order; lock_raw/unlock_raw paired.
    unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        (*caller_cspace).free_slot(slot.get());
        (*caller_cspace).lock.unlock_raw(saved);
    }
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
