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
use crate::cap::derivation::{DERIVATION_LOCK, link_child, reparent_children, unlink_node};
use crate::cap::object::{KernelObjectHeader, dealloc_object};
use crate::cap::slot::{CSpaceId, CapTag, Rights, SlotId};
use syscall::SyscallError;

/// Install the two children of a range-cap split and consume the original.
///
/// The caller must have already validated the split point and allocated the
/// two child object bodies. This:
///   1. inserts both children into the caller's `CSpace` under `cspace.lock`,
///      rolling back (and deallocating both bodies) on either insert failure;
///   2. rewires the derivation tree under `DERIVATION_LOCK` — reparents the
///      original's children to its parent, unlinks the original, then links
///      both new caps to that parent;
///   3. frees the original slot and drops its object reference.
///
/// Returns the two encoded child handles `(handle1, handle2)` (generation +
/// index each). The caller delivers `handle1` in the primary return register
/// and `handle2` in the secondary — never packed into one word, so a high
/// generation cannot set the sign bit of an `i64` return (#349).
///
/// # Safety
/// `caller_cspace` must be a valid non-null `CSpace` pointer for the calling
/// thread, and `cspace_id` must equal `(*caller_cspace).id()`. `orig_idx` must
/// index the original cap (tag `tag`) in that `CSpace`, and `orig_obj_ptr` must
/// be its live object (refcount > 0). `child1_ptr` and `child2_ptr` must be
/// freshly-allocated SEED-backed bodies of tag `tag`, each with refcount 1, not
/// yet inserted into any `CSpace`.
// too_many_arguments: the split tail genuinely needs the original cap's
// coordinates (cspace, id, slot, tag, rights, object) plus both children;
// bundling them into a struct would only move the argument list, not shrink it.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn install_split_children(
    caller_cspace: *mut CSpace,
    cspace_id: CSpaceId,
    orig_idx: u32,
    tag: CapTag,
    rights: Rights,
    orig_obj_ptr: NonNull<KernelObjectHeader>,
    child1_ptr: NonNull<KernelObjectHeader>,
    child2_ptr: NonNull<KernelObjectHeader>,
) -> Result<(u32, u32), SyscallError>
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
    let slot1 = slot1_nz.get();

    // SAFETY: caller_cspace validated by the caller; lock_raw/unlock_raw paired.
    let slot2_nz = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace).insert_cap(tag, rights, child2_ptr);
        (*caller_cspace).lock.unlock_raw(saved);
        r
    }
    .map_err(|e| {
        // Undo slot1: child1_ptr was inserted (reachable only via slot1, which
        // we free here); child2_ptr was passed to the failing insert_cap and
        // never stored.
        // SAFETY: caller_cspace validated; lock_raw/unlock_raw paired.
        unsafe {
            let saved = (*caller_cspace).lock.lock_raw();
            (*caller_cspace).free_slot(slot1);
            (*caller_cspace).lock.unlock_raw(saved);
        }
        // SAFETY: both child pointers were freshly allocated with refcount 1.
        unsafe {
            dealloc_object(child1_ptr);
            dealloc_object(child2_ptr);
        }
        SyscallError::from(e)
    })?;
    // ── Wire derivation tree ──────────────────────────────────────────────────

    let orig_idx_nz = NonZeroU32::new(orig_idx).ok_or(SyscallError::InvalidCapability)?;

    DERIVATION_LOCK.write_lock();

    let orig_node = SlotId::current(cspace_id, orig_idx_nz);
    let child1_id = SlotId::current(cspace_id, slot1_nz);
    let child2_id = SlotId::current(cspace_id, slot2_nz);

    // SAFETY: caller_cspace validated; orig_idx within CSpace bounds.
    let orig_parent = unsafe { (*caller_cspace).slot(orig_idx).and_then(|s| s.deriv_parent) };

    // SAFETY: DERIVATION_LOCK held; orig_node/orig_parent valid.
    unsafe { reparent_children(orig_node, orig_parent) };
    // SAFETY: DERIVATION_LOCK held; orig_node valid.
    unsafe { unlink_node(orig_node) };

    if let Some(parent_id) = orig_parent
    {
        // SAFETY: DERIVATION_LOCK held; parent_id/child1_id/child2_id valid.
        unsafe { link_child(parent_id, child1_id) };
        // SAFETY: DERIVATION_LOCK held; parent_id/child2_id valid.
        unsafe { link_child(parent_id, child2_id) };
    }

    DERIVATION_LOCK.write_unlock();

    // ── Consume the original cap ──────────────────────────────────────────────

    // SAFETY: caller_cspace validated; orig_idx within CSpace bounds.
    unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        (*caller_cspace).free_slot(orig_idx);
        (*caller_cspace).lock.unlock_raw(saved);
    }

    // SAFETY: orig_obj_ptr from the caller's lookup; object still valid.
    let remaining = unsafe { (*orig_obj_ptr.as_ptr()).dec_ref() };
    if remaining == 0
    {
        // SAFETY: ref count reached zero; no other references exist.
        unsafe { dealloc_object(orig_obj_ptr) };
    }

    // Encode both child handles (generation + index, #349). Returned separately
    // so the caller can deliver them in two registers.
    // SAFETY: caller_cspace validated; both slots occupied so the reads are stable.
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
