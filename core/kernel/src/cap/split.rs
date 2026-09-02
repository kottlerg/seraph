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
///   1. inserts both children into the caller's `CSpace` under `cspace.lock`,
///      rolling back on either insert failure (a body is deallocated only
///      once nothing references it);
///   2. rewires the derivation tree under `DERIVATION_LOCK` — reparents the
///      original's children to its parent in `MAX_REPARENT_EDITS` batches
///      (lock released between batches), unlinks the original, then links
///      to that parent each new cap whose slot still holds it (a sibling may
///      have deleted a child meanwhile; its returned handle is then stale);
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
/// rolled back).
///
/// Returns the two encoded child handles `(handle1, handle2)` (generation +
/// index each). The caller delivers `handle1` in the primary return register
/// and `handle2` in the secondary — never packed into one word, so a high
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

    // SAFETY: caller contract (children fresh, refcount 1, uninserted).
    let (slot1_nz, slot2_nz) = unsafe {
        insert_children(
            caller_cspace,
            cspace_id,
            tag,
            rights,
            child1_ptr,
            child2_ptr,
        )
    }?;

    // ── Wire derivation tree ──────────────────────────────────────────────────

    let orig_node = SlotId::current(cspace_id, orig_idx_nz);
    let child1_id = SlotId::current(cspace_id, slot1_nz);
    let child2_id = SlotId::current(cspace_id, slot2_nz);

    // Move the original's children under its parent in batches; the final
    // batch's hold continues below with the unlink and the consume.
    let mut batches: u32 = 0;
    let orig_parent = loop
    {
        DERIVATION_LOCK.write_lock();

        // Revalidate the original (see the function doc): it must still be
        // the cap that was looked up, with no revoke in flight on it.
        // SAFETY: caller_cspace validated; DERIVATION_LOCK held, so a free
        // of this slot is observed stably (every free holds the lock).
        let orig_parent = unsafe { (*caller_cspace).slot(orig_idx) }.and_then(|slot| {
            (slot.tag == tag
                && slot.generation() == orig_gen
                && slot.object == Some(orig_obj_ptr)
                && !slot.revoke_in_progress())
            .then_some(slot.deriv_parent)
        });
        // SAFETY: DERIVATION_LOCK held; orig_node revalidated when Some.
        let done = orig_parent
            .map(|parent| unsafe { reparent_children(orig_node, parent, MAX_REPARENT_EDITS) });
        batches += 1;
        match (orig_parent, done)
        {
            (Some(parent), Some(true)) => break parent,
            (Some(_), Some(false)) if batches < MAX_REPARENT_BATCHES =>
            {
                DERIVATION_LOCK.write_unlock();
            }
            _ =>
            {
                // Original gone (or revoke in flight), or the deriver
                // backstop tripped: roll both children back, fail closed.
                // SAFETY: DERIVATION_LOCK held; both child slots were
                // inserted above and are released only here.
                let released = unsafe {
                    (
                        rollback_child(caller_cspace, cspace_id, slot1_nz, child1_ptr),
                        rollback_child(caller_cspace, cspace_id, slot2_nz, child2_ptr),
                    )
                };
                DERIVATION_LOCK.write_unlock();
                // SAFETY: each flagged pointer reached refcount zero in
                // rollback_child and is referenced by no slot.
                unsafe { dealloc_rolled_back(released, child1_ptr, child2_ptr) };
                return Err(
                    if orig_parent.is_some()
                    {
                        SyscallError::Interrupted
                    }
                    else
                    {
                        SyscallError::InvalidState
                    },
                );
            }
        }
    };

    // SAFETY: DERIVATION_LOCK held (final batch); orig_node revalidated.
    unsafe { unlink_node(orig_node) };

    if let Some(parent_id) = orig_parent
    {
        // A sibling thread may have deleted a child (and refilled its slot)
        // since the insert: link only a slot that still holds our child, so
        // an unrelated cap is never wired under the original's parent.
        for (slot_nz, child_ptr, child_id) in [
            (slot1_nz, child1_ptr, child1_id),
            (slot2_nz, child2_ptr, child2_id),
        ]
        {
            // SAFETY: caller_cspace validated; DERIVATION_LOCK held, so the
            // slot's occupancy is stable from this check through the link.
            let still_ours = unsafe { (*caller_cspace).slot(slot_nz.get()) }
                .is_some_and(|s| s.object == Some(child_ptr));
            if still_ours
            {
                // SAFETY: DERIVATION_LOCK held; parent_id and child_id occupied.
                unsafe { link_child(parent_id, child_id) };
            }
        }
    }

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

    // Encode both child handles (generation + index, #349). Returned separately
    // so the caller can deliver them in two registers. A child a sibling
    // deleted meanwhile yields a handle that no longer resolves, exactly as
    // if it had been deleted after the split returned.
    // SAFETY: caller_cspace validated; the generation reads run under its lock.
    let handles = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let h = (
            (*caller_cspace).cap_handle(slot1_nz),
            (*caller_cspace).cap_handle(slot2_nz),
        );
        (*caller_cspace).lock.unlock_raw(saved);
        h
    };
    Ok(handles)
}

/// Insert both split children into the caller's `CSpace`, returning their
/// slots. On either insert failure both bodies are deallocated (and a
/// slot1 already taken is released through [`rollback_child`]).
///
/// # Safety
///
/// `caller_cspace` must be valid and non-null with id `cspace_id`;
/// `child1_ptr`/`child2_ptr` must be freshly-allocated refcount-1 bodies of
/// tag `tag` not yet inserted anywhere.
unsafe fn insert_children(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    tag: CapTag,
    rights: Rights,
    child1_ptr: NonNull<KernelObjectHeader>,
    child2_ptr: NonNull<KernelObjectHeader>,
) -> Result<(NonZeroU32, NonZeroU32), SyscallError>
{
    // Insert both children into the caller's CSpace under cspace.lock so the
    // freelist mutation cannot tear against a concurrent SYS_CAP_CREATE_*.
    // SAFETY: caller_cspace validated by the caller; lock_raw/unlock_raw paired.
    let slot1_nz = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace).insert_cap(tag, rights, child1_ptr);
        (*caller_cspace).lock.unlock_raw(saved);
        r
    }
    .map_err(|e| {
        // SAFETY: child1_ptr and child2_ptr were freshly allocated with
        // refcount 1; neither has been inserted into any CSpace.
        unsafe {
            dealloc_object(child1_ptr);
            dealloc_object(child2_ptr);
        }
        SyscallError::from(e)
    })?;
    // SAFETY: caller_cspace validated by the caller; lock_raw/unlock_raw paired.
    let slot2_nz = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace).insert_cap(tag, rights, child2_ptr);
        (*caller_cspace).lock.unlock_raw(saved);
        r
    }
    .map_err(|e| {
        // Undo slot1: child1_ptr was inserted (reachable only via slot1);
        // child2_ptr was passed to the failing insert_cap and never stored.
        // SAFETY: caller_cspace validated; DERIVATION_LOCK brackets the free
        // so the occupied-to-free transition stays atomic against
        // derivation-side occupancy gates (see `resolve_slot_mut`).
        let release1 = unsafe {
            DERIVATION_LOCK.write_lock();
            let r = rollback_child(caller_cspace, cspace_id, slot1_nz, child1_ptr);
            DERIVATION_LOCK.write_unlock();
            r
        };
        // SAFETY: child2_ptr was freshly allocated with refcount 1 and never
        // stored; child1_ptr is freed only if rollback_child dropped its
        // last reference.
        unsafe { dealloc_rolled_back((release1, true), child1_ptr, child2_ptr) };
        SyscallError::from(e)
    })?;
    Ok((slot1_nz, slot2_nz))
}

/// Release one inserted-but-not-yet-wired split child during rollback.
///
/// If the slot still holds `child_ptr`, the slot is freed and the object's
/// reference dropped; returns `true` only when that drop reached zero, in
/// which case the caller must `dealloc_object(child_ptr)` after releasing
/// the lock. Returns `false` if a sibling thread already deleted the child
/// (its delete released the object), the slot was recycled since, or other
/// slots still reference the object — a sibling may have derived or copied
/// the child between its insert and this rollback, and those caps stay
/// valid. Anything derived from the child is detached into derivation
/// roots first, so the free never strands a child with a dangling parent
/// link. That walk runs to completion under the lock: its length is
/// however many derivations a sibling landed in the window, not a
/// constant, but nothing can extend the list while the lock is held, so it
/// terminates.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; `caller_cspace` must be
/// valid, and `child_ptr` the object inserted at `slot` by this split.
unsafe fn rollback_child(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    slot: NonZeroU32,
    child_ptr: NonNull<KernelObjectHeader>,
) -> bool
{
    // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
    let still_ours =
        unsafe { (*caller_cspace).slot(slot.get()) }.is_some_and(|s| s.object == Some(child_ptr));
    if !still_ours
    {
        return false;
    }
    let child_id = SlotId::current(cspace_id, slot);
    // SAFETY: DERIVATION_LOCK held; child_id occupied (checked above).
    while !unsafe { reparent_children(child_id, None, MAX_REPARENT_EDITS) }
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
