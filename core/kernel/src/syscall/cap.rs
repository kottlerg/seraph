// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/cap.rs

//! Capability creation and manipulation syscall handlers.
//!
//! Allocates kernel objects and inserts them into a `CSpace`.
//! Returns a slot index on success.
//!
//! # Adding a new capability creation syscall
//! 1. Look the source Memory cap up with `RETYPE` and carve the object's
//!    bytes with `retype_allocate` (`dispatch_for` gives the size).
//! 2. Construct the wrapper, and any inline state, in place at the carved
//!    offset with `KernelObjectHeader::with_ancestor`.
//! 3. Insert with `insert_cap_handle_typed` under the `CSpace` lock, rolling
//!    the carve back (`retype_free`) on failure.
//! 4. Return the handle as `u64`.

// cast_possible_truncation: all u64→u32 casts in this file extract cap slot indices
// from 64-bit trap frame registers. Seraph runs on 64-bit only; slot indices are
// defined as u32 and always fit. No truncation occurs in practice.
#![allow(clippy::cast_possible_truncation)]

use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

#[cfg(not(test))]
use super::current_tcb;

/// Resolve a user-supplied source-cap handle for `cap_copy` / `cap_derive` /
/// `cap_derive_badge` / `cap_move`: verify the slot is non-null and that the
/// handle's generation matches the slot's, rejecting a stale handle to a
/// recycled slot (#349). The index is decoded from the handle. Returns the
/// `(tag, rights, object, badge)` a copy/derive/move needs.
///
/// # Safety
/// `cspace` must be a valid `CSpace` pointer.
#[cfg(not(test))]
unsafe fn resolve_src_cap(
    cspace: *mut crate::cap::cspace::CSpace,
    handle: u32,
) -> Result<
    (
        crate::cap::slot::CapTag,
        crate::cap::slot::Rights,
        core::ptr::NonNull<crate::cap::object::KernelObjectHeader>,
        u64,
    ),
    SyscallError,
>
{
    // SAFETY: cspace is a valid CSpace pointer (caller contract).
    let cs = unsafe { &*cspace };
    let slot = cs
        .slot(syscall::cap_handle_index(handle))
        .ok_or(SyscallError::InvalidCapability)?;
    if slot.tag == crate::cap::slot::CapTag::Null
    {
        return Err(SyscallError::InvalidCapability);
    }
    if slot.generation() != syscall::cap_handle_gen(handle)
    {
        return Err(SyscallError::InvalidCapability);
    }
    Ok((
        slot.tag,
        slot.rights,
        slot.object.ok_or(SyscallError::InvalidCapability)?,
        slot.badge,
    ))
}

/// Revalidate `handle`'s slot under `DERIVATION_LOCK` before its object is
/// touched or the tree is edited around it — the source of a copy or
/// derive, the parent of a memory split, both caps of a memory merge: same
/// tag-bearing occupancy, same generation, same `object`, no revoke in
/// flight. The unlocked resolution that produced `object` may have raced a
/// delete, move, or revoke batch that freed the slot (and possibly the
/// object): `link_child` drops a link under a freed parent, so a copy or
/// derive would publish a derivation root outside every ancestor's revoke
/// reach; the memory syscalls would dereference a freed wrapper, and the
/// merge would free a recycled tail index holding an unrelated live cap.
/// Every occupied→free transition holds the lock, so a slot that matches
/// here stays live — and stays the link's parent — for the rest of the
/// hold.
///
/// # Errors
///
/// `InvalidCapability` when the slot no longer holds the resolved cap;
/// `InvalidState` when a revoke is in flight on it (transient — retry after
/// the revoke completes).
///
/// # Safety
///
/// `cspace` must be a valid `CSpace` pointer; the caller must hold
/// `DERIVATION_LOCK` (write).
#[cfg(not(test))]
pub(super) unsafe fn revalidate_src_under_lock(
    cspace: *mut crate::cap::cspace::CSpace,
    handle: u32,
    object: core::ptr::NonNull<crate::cap::object::KernelObjectHeader>,
) -> Result<(), SyscallError>
{
    // SAFETY: caller contract.
    let slot = unsafe { (*cspace).slot(syscall::cap_handle_index(handle)) }
        .ok_or(SyscallError::InvalidCapability)?;
    if slot.tag == crate::cap::slot::CapTag::Null
        || slot.generation() != syscall::cap_handle_gen(handle)
        || slot.object != Some(object)
    {
        return Err(SyscallError::InvalidCapability);
    }
    if slot.revoke_in_progress()
    {
        return Err(SyscallError::InvalidState);
    }
    Ok(())
}

/// Give up the reference a copy or derive took on its source object when the
/// new slot did not materialise; frees the object if that was the last
/// reference (a sibling may have deleted the source meanwhile).
///
/// # Safety
///
/// The caller must hold one reference on `object` that it is giving up; no
/// lock may be held (`dealloc_object` takes its own).
#[cfg(not(test))]
unsafe fn release_src_ref(object: core::ptr::NonNull<crate::cap::object::KernelObjectHeader>)
{
    // SAFETY: caller contract.
    if unsafe { (*object.as_ptr()).dec_ref() } == 0
    {
        // SAFETY: refcount reached 0; no other references exist.
        unsafe { crate::cap::object::dealloc_object(object) };
    }
}

/// `SYS_CAP_CREATE_ENDPOINT` (7): retype a Memory cap into a new Endpoint.
///
/// arg0 = Memory-cap slot index in the caller's `CSpace`. The Memory cap
/// MUST carry `MemRights::RETYPE` and have at least
/// `dispatch_for(Endpoint, 0).raw_bytes` (80 B = 24 wrapper + 56
/// `EndpointState`) of `available_bytes`.
///
/// On success, the wrapper + `EndpointState` are constructed in place inside
/// the source Memory cap's region; a cap with `SEND | RECEIVE | GRANT` rights
/// is inserted into the caller's `CSpace`; returns the slot index.
///
/// On `dec_ref → 0`, auto-reclaim returns the bytes to the source Memory cap
/// via [`crate::cap::object::dealloc_object`] consulting `header.ancestor`.
#[cfg(not(test))]
pub fn sys_cap_create_endpoint(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{EndpointObject, KernelObjectHeader, MemoryObject, ObjectType};
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{EpRights, MemRights};
    use crate::ipc::endpoint::EndpointState;
    use core::ptr::NonNull;

    let memory_slot = tf.arg(0) as u32;

    // SAFETY: syscall entry ensures current_tcb() returns the active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace field is immutable after thread creation.
    let cspace = unsafe { (*tcb).cspace };
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Resolve the source Memory cap. Requires MemRights::RETYPE.
    // SAFETY: cspace validated non-null above.
    let memory_slot_ref = unsafe { super::lookup_cap(cspace, memory_slot, MemRights::RETYPE)? };
    let memory_obj_nn = memory_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Memory slot whose object pointer is
    // valid for the lifetime of the slot.
    let memory = unsafe { &*memory_obj_nn.as_ptr().cast::<MemoryObject>() };

    let entry = dispatch_for(ObjectType::Endpoint, 0).ok_or(SyscallError::InvalidArgument)?;

    // Reserve bytes in the Memory cap region.
    let offset = retype_allocate(memory, entry.raw_bytes)?;

    // Compute the kernel direct-map virtual address of the new object.
    let block_phys = memory.base + offset;
    let block_virt = crate::mm::paging::phys_to_virt(block_phys);

    // Layout: EndpointObject at offset 0; EndpointState at offset
    // size_of::<EndpointObject>() (24). Total 24 + 56 = 80 B, rounds to 128 B.
    let ep_obj_ptr = block_virt as *mut EndpointObject;
    let state_offset = core::mem::size_of::<EndpointObject>() as u64;
    let ep_state_ptr = (block_virt + state_offset) as *mut EndpointState;

    let ancestor = memory_obj_nn;

    // SAFETY: ep_state_ptr / ep_obj_ptr point into the just-allocated region;
    // alignment: the region is page-aligned (memory.base is page-aligned, and
    // BIN_128 sub-page slots inherit 8-byte alignment from `bump_offset`'s
    // initialisation at zero plus 128 B granularity, which exceeds the
    // 8-byte alignment requirement of both structs).
    unsafe {
        core::ptr::write(ep_state_ptr, EndpointState::new());
        core::ptr::write(
            ep_obj_ptr,
            EndpointObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::Endpoint, ancestor),
                state: ep_state_ptr,
            },
        );
    }

    // Bump the ancestor's refcount: each retyped descendant holds a lease.
    // SAFETY: ancestor is the MemoryObject's header (offset 0 of MemoryObject);
    // dereferencing through the header is safe.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: ep_obj_ptr is a freshly-constructed EndpointObject; header at
    // offset 0 makes the cast safe.
    let nonnull = unsafe { NonNull::new_unchecked(ep_obj_ptr.cast::<KernelObjectHeader>()) };

    // Insert into the caller's CSpace under the cspace lock so the freelist
    // and tag invariant cannot tear against a concurrent mutator on another
    // CPU (parent inserting caps via SYS_CAP_COPY, sibling thread also
    // creating caps, etc.).
    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap_handle_typed(
            EpRights::SEND | EpRights::RECEIVE | EpRights::GRANT,
            nonnull,
        );
        (*cspace).lock.unlock_raw(saved);
        r
    };

    match idx_res
    {
        Ok(idx) => Ok(u64::from(idx)),
        Err(e) =>
        {
            // CSpace slot allocation failed; roll back. Drop in place,
            // return the bytes, drop the lease.
            // SAFETY: we just constructed both objects in place above;
            // nothing else has observed them yet.
            unsafe {
                core::ptr::drop_in_place(ep_obj_ptr);
                core::ptr::drop_in_place(ep_state_ptr);
            }
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches the inc_ref above.
            unsafe { ancestor.as_ref().dec_ref() };
            Err(e.into())
        }
    }
}

/// `SYS_CAP_CREATE_NOTIFICATION` (8): retype a Memory cap into a new Notification.
///
/// arg0 = Memory-cap slot index in the caller's `CSpace`. The Memory cap MUST
/// carry `MemRights::RETYPE` and have at least `dispatch_for(Notification, 0).raw_bytes`
/// of `available_bytes`.
///
/// On success, the wrapper + `NotificationState` are constructed in place inside
/// the source Memory cap's region; a cap with `NOTIFY | WAIT` rights is
/// inserted into the caller's `CSpace`; returns the slot index.
///
/// Auto-reclaim (`dec_ref → 0`) consults `header.ancestor` and credits bytes
/// back to the source Memory cap.
#[cfg(not(test))]
pub fn sys_cap_create_notification(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{KernelObjectHeader, MemoryObject, NotificationObject, ObjectType};
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{MemRights, NtfRights};
    use crate::ipc::notification::NotificationState;
    use core::ptr::NonNull;

    let memory_slot = tf.arg(0) as u32;

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace = unsafe { (*tcb).cspace };
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: cspace validated; lookup_cap checks tag and rights.
    let memory_slot_ref = unsafe { super::lookup_cap(cspace, memory_slot, MemRights::RETYPE)? };
    let memory_obj_nn = memory_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Memory slot.
    let memory = unsafe { &*memory_obj_nn.as_ptr().cast::<MemoryObject>() };

    let entry = dispatch_for(ObjectType::Notification, 0).ok_or(SyscallError::InvalidArgument)?;

    let offset = retype_allocate(memory, entry.raw_bytes)?;

    let block_phys = memory.base + offset;
    let block_virt = crate::mm::paging::phys_to_virt(block_phys);

    // Layout: NotificationObject at offset 0; NotificationState at offset
    // size_of::<NotificationObject>() (24).
    let sig_obj_ptr = block_virt as *mut NotificationObject;
    let state_offset = core::mem::size_of::<NotificationObject>() as u64;
    let sig_state_ptr = (block_virt + state_offset) as *mut NotificationState;

    let ancestor = memory_obj_nn;

    // SAFETY: pointers are inside the freshly-allocated retype slot;
    // size-class alignment (BIN_128 = 128 B granular) exceeds the 8-byte
    // alignment requirement of both structs.
    unsafe {
        core::ptr::write(sig_state_ptr, NotificationState::new());
        core::ptr::write(
            sig_obj_ptr,
            NotificationObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::Notification, ancestor),
                state: sig_state_ptr,
            },
        );
    }

    // SAFETY: ancestor is the MemoryObject's header at offset 0.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: header at offset 0 of NotificationObject.
    let nonnull = unsafe { NonNull::new_unchecked(sig_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap_handle_typed(NtfRights::NOTIFY | NtfRights::WAIT, nonnull);
        (*cspace).lock.unlock_raw(saved);
        r
    };

    match idx_res
    {
        Ok(idx) => Ok(u64::from(idx)),
        Err(e) =>
        {
            // CSpace slot allocation failed: roll back the in-place
            // construction.
            // SAFETY: nothing else has observed these constructed objects.
            unsafe {
                core::ptr::drop_in_place(sig_obj_ptr);
                core::ptr::drop_in_place(sig_state_ptr);
            }
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches the inc_ref above.
            unsafe { ancestor.as_ref().dec_ref() };
            Err(e.into())
        }
    }
}

/// `SYS_CAP_CREATE_ASPACE` (11): create a new `AddressSpace` object, or
/// augment an existing one's PT growth budget.
///
/// arg0 = source Memory-cap slot (must carry `MemRights::RETYPE`, with at least
///        `init_pages * PAGE_SIZE` available bytes).
/// arg1 = augment-target `AddressSpace` cap slot, or `0` to create new.
/// arg2 = `init_pages`: number of PT pages to carve from the Memory cap.
///        Create-mode requires `init_pages >= 2` (one wrapper page + one
///        root PT page; the remainder seed the PT growth pool).
///        Augment-mode accepts `init_pages >= 1`.
///
/// Create-mode slab layout:
/// - page 0 — wrapper page: [`AddressSpaceObject`] at offset 0, immediately
///   followed by the wrapped [`AddressSpace`]. Both are constructed in place
///   via `core::ptr::write`; the wrapper's `address_space` pointer indexes
///   into this same page.
/// - page 1 — root page table (PML4 / RISC-V root), zeroed, kernel-half PT
///   entries copied from the active root.
/// - pages `2..init_pages` — PT growth pool. Drawn on demand by
///   [`AddressSpace::map_page`](crate::mm::address_space::AddressSpace::map_page)
///   for intermediate PT levels.
///
/// Inserts a cap with `MAP | READ | CONTROL` rights into the caller's
/// `CSpace`. `CONTROL` lets the creator register terminal-fault death
/// observers on the address space via `SYS_ASPACE_BIND_NOTIFICATION`;
/// derived copies handed to other components (e.g. memmgr) drop it via
/// the `cap_derive` rights mask. Returns the new slot index.
///
/// Augment-mode: pushes all carved pages onto the target AS's PT growth pool
/// and increases its `pt_growth_budget_bytes`. Returns `0` on success.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub fn sys_cap_create_aspace(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{
        AddressSpaceObject, KernelObjectHeader, MemoryObject, ObjectType, vacant_chunk_slots,
    };
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{AsRights, MemRights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::address_space::AddressSpace;
    use crate::mm::paging::phys_to_virt;
    use core::ptr::NonNull;
    use core::sync::atomic::AtomicU64;

    let memory_idx = tf.arg(0) as u32;
    let augment_idx = tf.arg(1) as u32;
    let init_pages = tf.arg(2);

    if init_pages == 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    // Reject `init_pages` that would overflow `init_pages * PAGE_SIZE` when
    // `dispatch_for` computes the byte cost. Caller-controlled value; an
    // attacker passing `u64::MAX` must not wrap into a small target size.
    let init_bytes = init_pages
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(SyscallError::InvalidArgument)?;

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace = unsafe { (*tcb).cspace };
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Resolve the source Memory cap (RETYPE-rights gated).
    // SAFETY: cspace validated non-null above.
    let memory_slot_ref = unsafe { super::lookup_cap(cspace, memory_idx, MemRights::RETYPE)? };
    let memory_obj_nn = memory_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Memory slot.
    let memory = unsafe { &*memory_obj_nn.as_ptr().cast::<MemoryObject>() };

    // Validate dispatch math against the user-provided init_pages.
    let entry =
        dispatch_for(ObjectType::AddressSpace, init_pages).ok_or(SyscallError::InvalidArgument)?;
    debug_assert!(entry.split);
    debug_assert_eq!(entry.raw_bytes, init_bytes);

    // Reserve the contiguous slab from the Memory cap. The slab will be split
    // page-by-page onto the target AS's pool.
    let offset = retype_allocate(memory, entry.raw_bytes)?;
    let memory_base = memory.base;

    // Augment-mode: push all carved pages onto the target AS's pool.
    if augment_idx != 0
    {
        // SAFETY: cspace validated non-null above.
        let target_slot = match unsafe { super::lookup_cap(cspace, augment_idx, AsRights::MAP) }
        {
            Ok(slot) => slot,
            Err(e) =>
            {
                retype_free(memory, offset, entry.raw_bytes);
                return Err(e);
            }
        };
        let Some(target_aso_nn) = target_slot.object
        else
        {
            retype_free(memory, offset, entry.raw_bytes);
            return Err(SyscallError::InvalidCapability);
        };
        // SAFETY: tag confirmed AddressSpace.
        #[allow(clippy::cast_ptr_alignment)]
        let target_aso = unsafe { &*target_aso_nn.as_ptr().cast::<AddressSpaceObject>() };

        // SAFETY: ref is held until AS-dealloc (released per chunk slot).
        unsafe { memory_obj_nn.as_ref().inc_ref() };

        // SAFETY: target_aso wraps a live AS; offset/init_pages are from a
        // successful retype against `memory`.
        let res = unsafe {
            target_aso.add_chunk(memory_obj_nn, memory_base, offset, init_pages, init_pages)
        };
        if res.is_err()
        {
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches the inc_ref above.
            unsafe { memory_obj_nn.as_ref().dec_ref() };
            return Err(SyscallError::OutOfMemory);
        }
        return Ok(0);
    }

    // Create-mode: slab layout is [wrapper page, root PT, pool pages...].
    // Requires `init_pages >= 2`.
    if init_pages < 2
    {
        retype_free(memory, offset, entry.raw_bytes);
        return Err(SyscallError::InvalidArgument);
    }

    let wrapper_phys = memory_base + offset;
    let root_pt_phys = wrapper_phys + PAGE_SIZE as u64;
    let wrapper_virt = phys_to_virt(wrapper_phys) as *mut u8;

    // Wrapper page layout: AddressSpaceObject at offset 0 (header at 0),
    // wrapped AddressSpace at offset size_of::<AddressSpaceObject>()
    // (8-byte aligned because both structs have alignment 8).
    // cast_ptr_alignment: wrapper_virt is page-aligned (4096), the wrapper
    // struct's alignment is at most 8.
    #[allow(clippy::cast_ptr_alignment)]
    let aso_ptr = wrapper_virt.cast::<AddressSpaceObject>();
    let as_offset = core::mem::size_of::<AddressSpaceObject>();
    debug_assert_eq!(as_offset % core::mem::align_of::<AddressSpace>(), 0);
    debug_assert!(as_offset + core::mem::size_of::<AddressSpace>() <= PAGE_SIZE);
    // cast_ptr_alignment: as_offset is a multiple of align_of::<AddressSpace>()
    // (asserted above) and wrapper_virt is page-aligned.
    // similar_names: aso_ptr / aspace_ptr both name pointers in the same
    // wrapper page; the disambiguating prefixes are intentional.
    #[allow(clippy::cast_ptr_alignment, clippy::similar_names)]
    // SAFETY: wrapper_virt is page-aligned; as_offset stays inside page 0.
    let aspace_ptr = unsafe { wrapper_virt.add(as_offset) }.cast::<AddressSpace>();

    // Construct AS in place at offset `as_offset`. The root PT sits in
    // page 1 of the slab.
    // SAFETY: root_pt_phys is a freshly-retyped page exclusively owned by
    // this slab; phys_to_virt gives a valid kernel-direct-map VA.
    let aspace = unsafe { AddressSpace::new_user_with_root(root_pt_phys) };
    // SAFETY: aspace_ptr lives in the wrapper page, exclusively owned.
    unsafe { core::ptr::write(aspace_ptr, aspace) };

    // Construct the wrapper in place at offset 0; the back-pointer indexes
    // into the same page.
    // SAFETY: aso_ptr lives in the wrapper page, exclusively owned.
    unsafe {
        core::ptr::write(
            aso_ptr,
            AddressSpaceObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::AddressSpace, memory_obj_nn),
                address_space: aspace_ptr,
                pt_growth_budget_bytes: AtomicU64::new(0),
                pt_pool_lock: AtomicU64::new(0),
                pt_pool_head_phys: AtomicU64::new(0),
                pt_chunks: vacant_chunk_slots(),
                deferred_next: core::ptr::null_mut(),
            },
        );
    }

    // Hold a reference on the source Memory cap for the AS's lifetime; the
    // matching dec_ref happens in `dealloc_object(AddressSpace)` after the
    // chunk is reclaimed.
    // SAFETY: memory_obj_nn is a live MemoryObject.
    unsafe { memory_obj_nn.as_ref().inc_ref() };

    // Record the chunk covering all `init_pages`; the lower 2 pages
    // (wrapper + root PT) are reserved, the remainder seeds the pool.
    let pool_pages = init_pages - 2;
    // SAFETY: aso just constructed; offset/init_pages from a successful
    // retype against `memory`.
    let res =
        unsafe { (*aso_ptr).add_chunk(memory_obj_nn, memory_base, offset, init_pages, pool_pages) };
    if res.is_err()
    {
        // Roll back: drop the in-place objects, free the slab, dec_ref the
        // ancestor. AS has no Drop logic; the explicit drop_in_place is for
        // future-proofing.
        // SAFETY: aso/aspace not observed externally yet.
        unsafe {
            core::ptr::drop_in_place(aso_ptr);
            core::ptr::drop_in_place(aspace_ptr);
        }
        retype_free(memory, offset, entry.raw_bytes);
        // SAFETY: matches inc_ref above.
        unsafe { memory_obj_nn.as_ref().dec_ref() };
        return Err(SyscallError::OutOfMemory);
    }

    // SAFETY: aso_ptr is in-place at offset 0; header at offset 0 of ASObject.
    let nonnull = unsafe { NonNull::new_unchecked(aso_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace)
            .insert_cap_handle_typed(AsRights::MAP | AsRights::READ | AsRights::CONTROL, nonnull);
        (*cspace).lock.unlock_raw(saved);
        r
    };
    let idx = match idx_res
    {
        Ok(idx) => idx,
        Err(e) =>
        {
            // The cap never reached visibility; mirror the add_chunk
            // rollback above (the chunk record lives inside the wrapper
            // page being freed, so no external bookkeeping survives).
            // SAFETY: aso/aspace not observed externally yet.
            unsafe {
                core::ptr::drop_in_place(aso_ptr);
                core::ptr::drop_in_place(aspace_ptr);
            }
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches inc_ref above.
            unsafe { memory_obj_nn.as_ref().dec_ref() };
            return Err(e.into());
        }
    };

    Ok(u64::from(idx))
}

/// `SYS_CAP_CREATE_CSPACE` (12): retype a Memory cap into a new `CSpace`,
/// or augment an existing one's slot-page growth budget.
///
/// arg0 = source Memory-cap slot (must carry `MemRights::RETYPE`).
/// arg1 = augment-target `CSpace` cap slot, or `0` to create new.
/// arg2 = `init_pages`: number of pages to carve from the Memory cap.
///        Create-mode requires `init_pages >= 1` (one wrapper page; the
///        remainder seed the slot-page pool — `init_pages == 1` yields an
///        empty pool that requires immediate augment-mode refill before any
///        cap can be inserted). Augment-mode accepts `init_pages >= 1`.
/// arg3 = reserved; MUST be `0` (was the removed `max_slots` quota — a
///        `CSpace`'s capacity is whatever its paid slot-page pool backs).
///        Non-zero → `InvalidArgument`.
///
/// Create-mode slab layout:
/// - page 0 — wrapper page: [`CSpaceKernelObject`] at offset 0, immediately
///   followed by the wrapped [`CSpace`] directory. The wrapper's `cspace`
///   pointer indexes into this same page.
/// - pages `1..init_pages` — slot-page pool, drawn on demand by
///   [`CSpace::grow`](crate::cap::cspace::CSpace::grow) when the directory
///   needs another 56-slot leaf.
///
/// Create-mode returns the new `CSpace` slot index. Augment-mode returns 0.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub fn sys_cap_create_cspace(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::alloc_cspace_id;
    use crate::cap::cspace::CSpace;
    use crate::cap::object::{
        CSpaceKernelObject, KernelObjectHeader, MemoryObject, ObjectType, vacant_chunk_slots,
    };
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{CsRights, MemRights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;
    use core::ptr::NonNull;
    use core::sync::atomic::AtomicU64;

    let memory_idx = tf.arg(0) as u32;
    let augment_idx = tf.arg(1) as u32;
    let init_pages = tf.arg(2);

    if init_pages == 0 || tf.arg(3) != 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    // Reject overflow on `init_pages * PAGE_SIZE` — caller-controlled, must
    // not wrap into a small target size.
    let init_bytes = init_pages
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(SyscallError::InvalidArgument)?;

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace = unsafe { (*tcb).cspace };
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Resolve the source Memory cap.
    // SAFETY: cspace validated non-null above.
    let memory_slot_ref = unsafe { super::lookup_cap(cspace, memory_idx, MemRights::RETYPE)? };
    let memory_obj_nn = memory_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Memory slot.
    let memory = unsafe { &*memory_obj_nn.as_ptr().cast::<MemoryObject>() };

    let entry =
        dispatch_for(ObjectType::CSpaceObj, init_pages).ok_or(SyscallError::InvalidArgument)?;
    debug_assert!(entry.split);
    debug_assert_eq!(entry.raw_bytes, init_bytes);

    let offset = retype_allocate(memory, entry.raw_bytes)?;
    let memory_base = memory.base;

    // Augment-mode.
    if augment_idx != 0
    {
        // SAFETY: cspace validated non-null above.
        let target_slot = match unsafe { super::lookup_cap(cspace, augment_idx, CsRights::INSERT) }
        {
            Ok(slot) => slot,
            Err(e) =>
            {
                retype_free(memory, offset, entry.raw_bytes);
                return Err(e);
            }
        };
        let Some(target_kobj_nn) = target_slot.object
        else
        {
            retype_free(memory, offset, entry.raw_bytes);
            return Err(SyscallError::InvalidCapability);
        };
        // SAFETY: tag confirmed CSpace.
        #[allow(clippy::cast_ptr_alignment)]
        let target_kobj = unsafe { &*target_kobj_nn.as_ptr().cast::<CSpaceKernelObject>() };

        // SAFETY: ref kept until CS-dealloc.
        unsafe { memory_obj_nn.as_ref().inc_ref() };

        // SAFETY: target_kobj is live.
        let res = unsafe {
            target_kobj.add_chunk(memory_obj_nn, memory_base, offset, init_pages, init_pages)
        };
        if res.is_err()
        {
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches inc_ref above.
            unsafe { memory_obj_nn.as_ref().dec_ref() };
            return Err(SyscallError::OutOfMemory);
        }
        return Ok(0);
    }

    // Create-mode: slab layout is [wrapper page, slot pool pages...].
    // Page 0 holds CSpaceKernelObject at offset 0 followed by CSpace at
    // offset size_of::<CSpaceKernelObject>(). Pages 1..init_pages seed the
    // slot-page pool; CSpace::grow pops one when the directory needs a leaf.
    let wrapper_phys = memory_base + offset;
    let wrapper_virt = phys_to_virt(wrapper_phys) as *mut u8;

    // cast_ptr_alignment: wrapper_virt is page-aligned (4096), the wrapper
    // struct's alignment is at most 8.
    #[allow(clippy::cast_ptr_alignment)]
    let cs_kobj_ptr = wrapper_virt.cast::<CSpaceKernelObject>();
    let cs_offset = core::mem::size_of::<CSpaceKernelObject>();
    debug_assert_eq!(cs_offset % core::mem::align_of::<CSpace>(), 0);
    debug_assert!(cs_offset + core::mem::size_of::<CSpace>() <= PAGE_SIZE);
    // cast_ptr_alignment: cs_offset is a multiple of align_of::<CSpace>()
    // (asserted above) and wrapper_virt is page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: wrapper_virt is page-aligned; cs_offset stays inside page 0.
    let cs_ptr = unsafe { wrapper_virt.add(cs_offset) }.cast::<CSpace>();

    let Some(id) = alloc_cspace_id()
    else
    {
        // Free list empty and high-water at MAX_CSPACES — namespace
        // exhausted. Surface to userspace; the retype carve is undone below
        // by `retype_free` after the error return.
        retype_free(memory, offset, entry.raw_bytes);
        return Err(SyscallError::OutOfMemory);
    };

    // Construct CSpace in place.
    // SAFETY: cs_ptr lives inside the wrapper page, exclusively owned.
    unsafe { core::ptr::write(cs_ptr, CSpace::new(id)) };

    // Construct the wrapper in place; the back-pointer indexes into the
    // same page.
    // SAFETY: cs_kobj_ptr is page-aligned and exclusively owned.
    unsafe {
        core::ptr::write(
            cs_kobj_ptr,
            CSpaceKernelObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::CSpaceObj, memory_obj_nn),
                cspace: cs_ptr,
                cspace_growth_budget_bytes: AtomicU64::new(0),
                cs_pool_lock: AtomicU64::new(0),
                cs_pool_head_phys: AtomicU64::new(0),
                cs_chunks: vacant_chunk_slots(),
                deferred_next: core::ptr::null_mut(),
            },
        );
    }

    // Wire the back-pointer so the first CSpace::grow uses the pool.
    // SAFETY: cs_ptr just constructed.
    unsafe { (*cs_ptr).set_kobj(cs_kobj_ptr) };

    // Register in the global registry so derivation lookups resolve.
    // Overflow → `SyscallError::OutOfMemory` with full rollback below.
    // The returned epoch is the current registry value — `SlotId`s minted
    // for this CSpace's slots during its lifetime stamp with it via
    // `SlotId::current`.
    if crate::cap::register_cspace(id, cs_ptr).is_err()
    {
        // SAFETY: wrapper/cs not observed externally yet (registry
        // rejected the entry; no slot in any CSpace points at `cs_ptr`).
        unsafe {
            core::ptr::drop_in_place(cs_kobj_ptr);
            core::ptr::drop_in_place(cs_ptr);
        }
        // The id was drawn but never registered; return it or the 4096-id
        // namespace drains one entry per failed create.
        crate::cap::free_cspace_id(id);
        retype_free(memory, offset, entry.raw_bytes);
        return Err(SyscallError::OutOfMemory);
    }

    // Hold a reference on the source Memory cap.
    // SAFETY: memory_obj_nn is live.
    unsafe { memory_obj_nn.as_ref().inc_ref() };

    // Record the chunk covering all init_pages; reserve page 0 (wrapper),
    // pool seeds pages 1..init_pages.
    let pool_pages = init_pages - 1;
    // SAFETY: wrapper just constructed; offset/init_pages from a successful
    // retype against `memory`.
    let res = unsafe {
        (*cs_kobj_ptr).add_chunk(memory_obj_nn, memory_base, offset, init_pages, pool_pages)
    };
    if res.is_err()
    {
        // SAFETY: wrapper/cs not observed externally yet.
        unsafe {
            core::ptr::drop_in_place(cs_kobj_ptr);
            core::ptr::drop_in_place(cs_ptr);
        }
        crate::cap::unregister_cspace(id);
        crate::cap::free_cspace_id(id);
        retype_free(memory, offset, entry.raw_bytes);
        // SAFETY: matches inc_ref above.
        unsafe { memory_obj_nn.as_ref().dec_ref() };
        return Err(SyscallError::OutOfMemory);
    }

    // SAFETY: cs_kobj_ptr is in-place at offset 0; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(cs_kobj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let insert_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap_handle_typed(
            CsRights::INSERT | CsRights::DELETE | CsRights::DERIVE,
            nonnull,
        );
        (*cspace).lock.unlock_raw(saved);
        r
    };
    let idx = match insert_res
    {
        Ok(idx) => idx,
        Err(e) =>
        {
            // Roll back the registry slot and its id, the memory inc_ref,
            // the in-place wrapper/CSpace constructions, and the retype
            // carve. Without this rollback, a failed `insert_cap` would leak
            // a live CSpace registry entry and its id (one of 4096 — a
            // caller with a full slot pool could drain the namespace), leave
            // `memory_obj_nn`'s refcount permanently incremented, and
            // surrender the carved offset back to the retype allocator only
            // when the source memory itself was dec_ref'd to zero.
            crate::cap::unregister_cspace(id);
            crate::cap::free_cspace_id(id);
            // SAFETY: wrapper/cs not observed externally (no slot in any
            // CSpace points at `nonnull`, and we just removed the registry
            // entry).
            unsafe {
                core::ptr::drop_in_place(cs_kobj_ptr);
                core::ptr::drop_in_place(cs_ptr);
            }
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches the `memory_obj_nn.as_ref().inc_ref()` above.
            unsafe { memory_obj_nn.as_ref().dec_ref() };
            return Err(e.into());
        }
    };

    Ok(u64::from(idx))
}

/// `SYS_CAP_CREATE_THREAD` (10): create a new Thread object.
///
/// arg0 = Memory cap index (must have RETYPE); supplies the 6-page Thread slot.
/// arg1 = `AddressSpace` cap index (must have MAP).
/// arg2 = `CSpace` cap index (must have INSERT).
/// arg3 = `SchedControl` cap index, or 0.
/// arg4 = initial priority, or 0.
///
/// Creation priority: with arg3 = 0, arg4 must also be 0 and the thread is
/// created at `PRIORITY_MIN` — floor-only creation needs no scheduling
/// authority. With a `SchedControl` cap, arg4 = 0 selects the cap's band
/// floor (`min`); a nonzero arg4 must lie within the cap's `[min, max]`
/// band. There is no ambient priority authority above the floor.
///
/// Allocates a kernel stack and a TCB in `Created` state, bound to the
/// provided address space and `CSpace`. Inserts a cap with `CONTROL | OBSERVE`
/// rights into the caller's `CSpace`. Returns the Thread cap slot index.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub fn sys_cap_create_thread(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTF;
    use crate::cap::object::{
        KernelObjectHeader, MemoryObject, ObjectType, SchedControlObject, ThreadObject,
    };
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{AsRights, CsRights, MemRights, SchedRights, ThreadRights};
    use crate::ipc::message::Message;
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;
    use crate::sched::alloc_thread_id;
    use crate::sched::thread::{IpcThreadState, ThreadControlBlock, ThreadState};
    use crate::sched::{AFFINITY_ANY, KERNEL_STACK_PAGES, TIME_SLICE_TICKS};
    use core::ptr::NonNull;
    use syscall::{PRIORITY_MAX, PRIORITY_MIN};

    // TRAMPOLINE_FRAME_SIZE: reserved gap between trampoline's starting RSP and the
    // TrapFrame base. 512 bytes is sufficient for the minimal C frame.
    const TRAMPOLINE_FRAME_SIZE: u64 = 512;

    let memory_idx = tf.arg(0) as u32;
    let as_idx = tf.arg(1) as u32;
    let cs_idx = tf.arg(2) as u32;
    let sched_idx = tf.arg(3) as u32;
    // Kept as u64 until range-checked: an `as u8` here would wrap 256 to 0
    // and silently select the band floor.
    let priority_arg = tf.arg(4);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Resolve the source Memory cap; consumes 6 retype-pages (4 kstack +
    // 1 wrapper/TCB + 1 FPU/SIMD save area).
    // SAFETY: caller_cspace validated non-null above.
    let memory_slot_ref =
        unsafe { super::lookup_cap(caller_cspace, memory_idx, MemRights::RETYPE)? };
    let memory_obj_nn = memory_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Memory slot.
    let memory = unsafe { &*memory_obj_nn.as_ptr().cast::<MemoryObject>() };

    // Resolve AddressSpace cap.
    // SAFETY: caller_cspace validated non-null above.
    let as_slot = unsafe { super::lookup_cap(caller_cspace, as_idx, AsRights::MAP) }?;
    // One read of the slot's object pointer: it is what the TCB binds below
    // and what the post-registration revalidation compares against
    // (`as_slot` is a live reference into the leaf page, not a copy).
    let as_object = as_slot.object;
    let as_ptr = {
        use crate::cap::object::AddressSpaceObject;
        let obj = as_object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: cap tag confirmed AddressSpace; object pointer is valid.
        #[allow(clippy::cast_ptr_alignment)]
        let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
        as_obj.address_space
    };

    // Resolve CSpace cap.
    // SAFETY: caller_cspace validated non-null above.
    let cs_slot = unsafe { super::lookup_cap(caller_cspace, cs_idx, CsRights::INSERT) }?;
    let cs_object = cs_slot.object;
    let new_cs_ptr = {
        use crate::cap::object::CSpaceKernelObject;
        let obj = cs_object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: cap tag confirmed CSpace; object pointer is valid.
        #[allow(clippy::cast_ptr_alignment)]
        let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
        cs_obj.cspace
    };

    // Resolve the creation priority (validated before any allocation).
    let creation_priority = if sched_idx == 0
    {
        if priority_arg != 0
        {
            return Err(SyscallError::InvalidArgument);
        }
        PRIORITY_MIN
    }
    else
    {
        // Presence-only cap — no rights bit to check.
        // SAFETY: caller_cspace validated non-null above.
        let sched_slot = unsafe { super::lookup_cap(caller_cspace, sched_idx, SchedRights::NONE) }?;
        let sched_obj = sched_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of SchedControlObject; allocator
        // guarantees alignment.
        // SAFETY: tag confirmed SchedControl; pointer is a valid SchedControlObject.
        #[allow(clippy::cast_ptr_alignment)]
        let sched = unsafe { &*(sched_obj.as_ptr().cast::<SchedControlObject>()) };
        if priority_arg == 0
        {
            sched.min
        }
        else
        {
            if priority_arg > u64::from(PRIORITY_MAX)
            {
                return Err(SyscallError::InvalidArgument);
            }
            #[allow(clippy::cast_possible_truncation)]
            // cast_possible_truncation: bounded by PRIORITY_MAX above.
            let priority = priority_arg as u8;
            if priority < sched.min || priority > sched.max
            {
                return Err(SyscallError::InsufficientRights);
            }
            priority
        }
    };

    // Reserve the 6-page slot from the source Memory cap. Layout:
    //   pages 0..3 (16 KiB) — kstack
    //   page 4              — ThreadObject (24 B) followed by TCB
    //   page 5              — per-thread FPU/SIMD/V save area
    let entry = dispatch_for(ObjectType::Thread, 0).ok_or(SyscallError::InvalidArgument)?;
    debug_assert_eq!(
        entry.raw_bytes,
        (KERNEL_STACK_PAGES as u64 + 2) * PAGE_SIZE as u64
    );
    let offset = retype_allocate(memory, entry.raw_bytes)?;
    let block_phys = memory.base + offset;
    let block_virt = phys_to_virt(block_phys);

    let kstack_virt = block_virt;
    let kstack_top = block_virt + (KERNEL_STACK_PAGES * PAGE_SIZE) as u64;
    let thread_obj_ptr = kstack_top as *mut ThreadObject;
    let tcb_offset = core::mem::size_of::<ThreadObject>() as u64;
    let tcb_ptr = (kstack_top + tcb_offset) as *mut ThreadControlBlock;
    // Per-thread FPU/SIMD/V save area: one page directly after the wrapper
    // page. Zero-initialised so the first XRSTOR / F-D restore sees the
    // architected initial state. The area's lifecycle is the Thread retype
    // slot's; `retype_free` reclaims it wholesale, so no separate free
    // path is needed.
    let extended_area = (kstack_top + PAGE_SIZE as u64) as *mut u8;
    // SAFETY: extended_area points at a freshly-retyped page exclusively
    // owned by this TCB construction.
    unsafe {
        core::ptr::write_bytes(extended_area, 0u8, PAGE_SIZE);
    }

    // Build the initial SavedState. The "entry point" is the user_thread_trampoline
    // so that when schedule() first switches to this thread, switch() jumps to
    // the trampoline instead of address 0. The trampoline calls return_to_user
    // with the TrapFrame set up by SYS_THREAD_CONFIGURE.
    //
    // The TrapFrame will be placed at kstack_top - sizeof(TrapFrame) by
    // SYS_THREAD_CONFIGURE. Set the trampoline's initial RSP BELOW the TrapFrame
    // so the trampoline's C stack frame cannot overwrite TrapFrame fields.
    let tf_size = core::mem::size_of::<ArchTF>() as u64;
    let trampoline_rsp = kstack_top - tf_size - TRAMPOLINE_FRAME_SIZE;
    let saved = crate::arch::current::context::new_state(
        crate::sched::user_thread_trampoline as *const () as u64,
        trampoline_rsp,
        0,
        true,
    );

    let ancestor = memory_obj_nn;

    // SAFETY: pointers are inside the freshly-allocated retype slot.
    // Both the wrapper and the TCB land on page 4 of the slot, so they
    // are 8-byte aligned (page-aligned, in fact). The kstack pages are
    // intentionally left uninitialised — they are written from the top
    // down by the first context switch, and `kstack_top` excludes the
    // wrapper page.
    unsafe {
        core::ptr::write(
            tcb_ptr,
            ThreadControlBlock {
                state: ThreadState::Created,
                priority: creation_priority,
                slice_remaining: TIME_SLICE_TICKS,
                cpu_affinity: AFFINITY_ANY,
                preferred_cpu: 0,
                run_queue_next: None,
                queued_on: core::sync::atomic::AtomicI16::new(-1),
                #[cfg(debug_assertions)]
                last_enqueue: None,
                sched_lock: crate::sync::Spinlock::new(),
                wake_pending: false,
                park_started_tick: 0,
                ipc_state: IpcThreadState::None,
                ipc_msg: Message::default(),
                reply_tcb: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                park_disposition: core::sync::atomic::AtomicU8::new(
                    crate::sched::thread::PARK_DISPOSITION_NONE,
                ),
                #[cfg(debug_assertions)]
                park_episode: core::sync::atomic::AtomicU32::new(0),
                #[cfg(debug_assertions)]
                deposit_episode: core::sync::atomic::AtomicU32::new(0),
                ipc_wait_next: None,
                fault_handler: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                fault_badge: core::sync::atomic::AtomicU64::new(0),
                fault_outcome: core::sync::atomic::AtomicU8::new(0),
                in_fault_delivery: false,
                is_user: true,
                saved_state: saved,
                kernel_stack_top: kstack_top,
                trap_frame: core::ptr::null_mut(),
                syscall_nr: core::sync::atomic::AtomicU64::new(u64::MAX),
                address_space: as_ptr,
                cspace: new_cs_ptr,
                ipc_buffer: 0,
                wakeup_value: 0,
                timed_out: false,
                iopb: core::ptr::null_mut(),
                blocked_on_object: core::ptr::null_mut(),
                thread_id: alloc_thread_id(),
                context_saved: core::sync::atomic::AtomicU32::new(1),
                wake_in_flight: core::sync::atomic::AtomicU32::new(0),
                death_observers: [crate::sched::thread::DeathObserver::empty();
                    crate::sched::thread::MAX_DEATH_OBSERVERS],
                death_observer_count: 0,
                exit_reason: 0,
                sleep_deadline: 0,
                extended: crate::sched::thread::ExtendedState::from_raw(extended_area),
                registry_next: core::ptr::null_mut(),
                registry_prev: core::ptr::null_mut(),
                magic: crate::sched::thread::TCB_MAGIC,
            },
        );
        core::ptr::write(
            thread_obj_ptr,
            ThreadObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::Thread, ancestor),
                tcb: tcb_ptr,
                deferred_next: core::ptr::null_mut(),
            },
        );
        // Register before the cap becomes visible: the TCB already names its
        // CSpace and AddressSpace, and the teardown of either must find it
        // (`sched::stop_threads_bound_to`). The rollback arm unregisters.
        crate::sched::thread_registry::register(tcb_ptr);
    }

    // SAFETY: ancestor is the MemoryObject's header at offset 0; this lease
    // bump is undone on rollback below or when the Thread cap is dealloc'd.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: thread_obj_ptr is in-place; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(thread_obj_ptr.cast::<KernelObjectHeader>()) };

    // Revalidate both bindings now that the registry can find this TCB. A
    // teardown of either object that ran between the lookups above and
    // `register` walked a registry without this thread and may already have
    // reclaimed the storage the TCB names. The last capability to the object
    // is gone in that case, so a lookup that still resolves to the object
    // snapshotted above (the pointer bound into the TCB, not the slot, which
    // could have been recycled through a full generation cycle) proves it
    // outlived the registration — and any teardown starting now finds this
    // thread in the walk (docs/capability-model.md, process termination).
    // SAFETY: caller_cspace validated non-null above.
    let bound = unsafe {
        super::lookup_cap(caller_cspace, as_idx, AsRights::MAP).is_ok_and(|s| s.object == as_object)
            && super::lookup_cap(caller_cspace, cs_idx, CsRights::INSERT)
                .is_ok_and(|s| s.object == cs_object)
    };
    let idx_res: Result<u32, SyscallError> = if bound
    {
        // SAFETY: caller_cspace validated non-null above; lock_raw/unlock_raw paired.
        unsafe {
            let saved = (*caller_cspace).lock.lock_raw();
            let r = (*caller_cspace)
                .insert_cap_handle_typed(ThreadRights::CONTROL | ThreadRights::OBSERVE, nonnull);
            (*caller_cspace).lock.unlock_raw(saved);
            r
        }
        .map_err(SyscallError::from)
    }
    else
    {
        Err(SyscallError::InvalidCapability)
    };

    match idx_res
    {
        Ok(idx) =>
        {
            let _ = kstack_virt;
            Ok(u64::from(idx))
        }
        Err(e) =>
        {
            // The cap never reached visibility, so no scheduler queue can hold
            // this TCB and no IPC object has a back-pointer to it. Unlink it
            // from the registry (an object teardown walking it meanwhile saw
            // a `Created` thread and marked it `Exited`, which is harmless
            // here), drop both in-place objects, return the slot bytes (all
            // 5 pages) to the ancestor cap, and undo the lease bump.
            // SAFETY: tcb and wrapper were just constructed in place above;
            // the registry is the only structure that has observed the TCB.
            unsafe {
                crate::sched::thread_registry::unregister(tcb_ptr);
                core::ptr::drop_in_place(tcb_ptr);
                core::ptr::drop_in_place(thread_obj_ptr);
            }
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches the inc_ref above.
            unsafe { ancestor.as_ref().dec_ref() };
            Err(e)
        }
    }
}

/// Pre-grow `dest_cs_ptr` for `dest_idx` while holding a reference on the
/// destination's wrapper (`dest_obj`): the pre-grow's holds are preemptible
/// and the caller's destination lookup takes no reference, so without one a
/// concurrent delete of the last capability to the destination could
/// reclaim the wrapper under the walk. If that delete happens meanwhile, the
/// reference dropped here is the last: the destination's teardown runs here
/// and the caller gets `InvalidCapability`.
///
/// Residual: from the `dec_ref` here to the caller's next touch of the
/// destination under `DERIVATION_LOCK`, the same race stays open — the
/// `lookup_cap` residual, confined to a sibling thread of the caller's own
/// process (the caller holds a destination capability in its own `CSpace`,
/// so nobody else can drop the last one).
///
/// # Safety
/// `dest_obj` must be the header of the live `CSpaceKernelObject` wrapping
/// `dest_cs_ptr`; no scheduler, IPC-source, registry, or derivation lock
/// may be held (the teardown takes them).
#[cfg(not(test))]
unsafe fn pre_grow_holding_dest(
    dest_obj: core::ptr::NonNull<crate::cap::object::KernelObjectHeader>,
    dest_cs_ptr: *mut crate::cap::cspace::CSpace,
    dest_idx: u32,
) -> Result<(), SyscallError>
{
    // SAFETY: dest_obj is a live header per the caller contract.
    unsafe { dest_obj.as_ref().inc_ref() };
    let grown = pre_grow_for_explicit_slot(dest_cs_ptr, dest_idx);
    // SAFETY: matches the inc_ref above.
    let remaining = unsafe { dest_obj.as_ref().dec_ref() };
    if remaining == 0
    {
        // SAFETY: refcount reached zero here; no slot references the object
        // and no conflicting lock is held (caller contract).
        unsafe { crate::cap::object::dealloc_object(dest_obj) };
        return Err(SyscallError::InvalidCapability);
    }
    grown
}

/// Leaves materialised per `CSpace`-lock hold while pre-growing for an
/// explicit destination slot (each leaf costs one page zeroing plus
/// free-list threading; 64 keeps the interrupts-off hold small).
#[cfg(not(test))]
const MAX_GROW_LEAVES_PER_HOLD: usize = 64;

/// Pre-grow `cs_ptr` to cover explicit destination `index`, in bounded
/// batches under only that `CSpace`'s lock, before the placement path
/// takes `DERIVATION_LOCK` and the `CSpace` lock pair. Keeps the
/// unbounded-donation growth out of the heavyweight critical sections:
/// `insert_cap_at`'s own grow loop then runs zero iterations (leaves never
/// un-grow).
///
/// Fails fast with `OutOfMemory` — before consuming a single pool page —
/// when the pool budget cannot cover the remaining growth, so a doomed
/// placement does not burn the destination's budget. The budget is
/// re-checked each batch; leaves grown before a concurrent consumer
/// drains the pool remain as ordinary free capacity (donor-funded, not
/// leaked). An out-of-range index is left for `insert_cap_at` to reject.
#[cfg(not(test))]
fn pre_grow_for_explicit_slot(
    cs_ptr: *mut crate::cap::cspace::CSpace,
    index: u32,
) -> Result<(), SyscallError>
{
    use core::sync::atomic::Ordering;
    loop
    {
        // SAFETY: cs_ptr validated by the caller; lock_raw/unlock_raw paired.
        let step = unsafe {
            let saved = (*cs_ptr).lock.lock_raw();
            let needed = (*cs_ptr).pages_to_cover(index);
            let r = if needed == 0
            {
                Ok(true)
            }
            else
            {
                let budget_pages = (*cs_ptr).kobj_ptr().map_or(0, |k| {
                    (*k).cspace_growth_budget_bytes.load(Ordering::Acquire)
                        / crate::mm::PAGE_SIZE as u64
                });
                if budget_pages < needed
                {
                    // Route through the canonical CapError mapping: the
                    // shortfall is refillable pool exhaustion.
                    Err(crate::cap::cspace::CapError::PoolExhausted.into())
                }
                else
                {
                    (*cs_ptr)
                        .grow_toward(index, MAX_GROW_LEAVES_PER_HOLD)
                        .map_err(SyscallError::from)
                }
            };
            (*cs_ptr).lock.unlock_raw(saved);
            r
        };
        match step
        {
            Ok(true) => return Ok(()),
            // Leaf batch for this hold spent with leaves still missing: the
            // next iteration takes a fresh hold.
            Ok(false) =>
            {}
            Err(e) => return Err(e),
        }
    }
}

/// `SYS_CAP_COPY` (24): copy a capability into another `CSpace.`
///
/// arg0 = source slot index (in caller's `CSpace`).
/// arg1 = destination `CSpace` cap index (in caller's `CSpace`; must have INSERT).
/// arg2 = destination slot index in the target `CSpace`, or `0` to let the
///        kernel allocate a free slot. Slot 0 is permanently null, so it is a
///        safe "kernel picks" sentinel.
/// arg3 = rights mask for the new slot (must be a subset of source rights).
///
/// Copies the source capability's kernel object into the destination `CSpace`
/// with the requested (attenuated) rights, increments the object's reference
/// count, propagates the source badge, and wires the new slot as a child of the
/// source in the derivation tree. When `arg2 == 0` a free slot is allocated;
/// otherwise the cap is placed at the caller-chosen index — init populates
/// well-known slots in child `CSpaces` this way.
///
/// Returns the destination slot index.
#[cfg(not(test))]
pub fn sys_cap_copy(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::CSpaceKernelObject;
    use crate::cap::slot::Rights;

    let src_handle = tf.arg(0) as u32;
    let src_idx = syscall::cap_handle_index(src_handle);
    let dest_cs_idx = tf.arg(1) as u32;
    // Destination is a placement index (slot may be empty), not a live handle:
    // decode the index, but do not generation-check it.
    let dest_slot_idx = syscall::cap_handle_index(tf.arg(2) as u32);
    let rights_mask = Rights(tf.arg(3) as u32);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_cspace validated non-null above.
    let caller_cspace_id = unsafe { (*caller_cspace).id() };

    // Resolve destination CSpace cap.
    // SAFETY: caller_cspace validated non-null above.
    let dest_cs_slot = unsafe {
        super::lookup_cap(
            caller_cspace,
            dest_cs_idx,
            crate::cap::slot::CsRights::INSERT,
        )
    }?;
    let dest_obj = dest_cs_slot.object.ok_or(SyscallError::InvalidCapability)?;
    let dest_cs_ptr = {
        // cast_ptr_alignment: header is at offset 0 of CSpaceKernelObject; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: cap tag confirmed CSpace; object pointer is valid.
        let cs_obj = unsafe { &*(dest_obj.as_ptr().cast::<CSpaceKernelObject>()) };
        cs_obj.cspace
    };
    // SAFETY: dest_cs_ptr extracted from validated CSpace object above.
    let dest_cs_id = unsafe { (*dest_cs_ptr).id() };

    // Fail fast on an invalid or stale source before the pre-grow spends
    // pool pages that stay spent (`syscalls.md`, SYS_CAP_COPY); the source
    // is resolved again below, right before its reference is taken.
    // SAFETY: caller_cspace validated non-null above.
    unsafe { resolve_src_cap(caller_cspace, src_handle)? };

    // Pre-grow for an explicit destination before the inc_ref and the
    // destination lock: bounded holds, budget fast-fail, nothing to roll
    // back on failure. The destination wrapper is held across it.
    if dest_slot_idx != 0
    {
        // May run the destination's teardown if its last capability went
        // meanwhile (see pre_grow_holding_dest).
        // SAFETY: dest_obj is the live wrapper resolved above; no lock held.
        unsafe { pre_grow_holding_dest(dest_obj, dest_cs_ptr, dest_slot_idx)? };
    }

    // Resolve the source only now, after the pre-grow's preemptible lock
    // releases: the object reference is taken immediately below, and a
    // sibling's delete of the source during a long pre-grow would otherwise
    // free the body between the resolution and the inc_ref (the residual
    // window is the lookup itself, as everywhere else).
    // SAFETY: caller_cspace validated non-null above. Decodes + generation-
    // checks the source handle, rejecting a stale handle to a recycled slot.
    let (src_tag, src_rights, src_object, src_badge) =
        unsafe { resolve_src_cap(caller_cspace, src_handle)? };

    // Convert src_idx to NonZeroU32 before the reference is taken. The
    // non-null tag check above excludes slot 0 (which is permanently Null),
    // so this only fires on a malformed request.
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;

    // Compute the effective rights for the copy: intersection of the requested
    // mask and what the source actually grants. Bits not in the source are
    // silently dropped — callers cannot escalate.
    let effective_rights = rights_mask & src_rights;

    // Increment reference count on the shared kernel object.
    // SAFETY: src_object is a valid NonNull from a live capability slot.
    unsafe {
        (*src_object.as_ptr()).inc_ref();
    }

    // Revalidate the source, then insert and link, under one DERIVATION_LOCK
    // hold (the destination's cspace.lock nested per the documented order).
    // The source was resolved unlocked: a delete, move, or revoke batch may
    // have freed its slot meanwhile, and a link under a freed parent is
    // dropped — the new cap would be a derivation root outside every
    // ancestor's revoke reach. A cap reachable through the destination
    // CSpace but not yet linked could be moved out by a sibling, and a move
    // carries whatever derivation position it finds — the cap would leave
    // the source's revoke reach for good. Every occupied→free transition
    // holds the lock, so neither can interleave once the source
    // revalidates. dest_slot_idx == 0 allocates a free slot; otherwise the
    // cap is placed at the caller-chosen index. The badge write and the
    // handle read share the insert's critical section.
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: caller_cspace validated non-null above; DERIVATION_LOCK held.
    if let Err(e) = unsafe { revalidate_src_under_lock(caller_cspace, src_handle, src_object) }
    {
        crate::cap::DERIVATION_LOCK.write_unlock();
        // SAFETY: the reference taken above is given up; no lock held.
        unsafe { release_src_ref(src_object) };
        return Err(e);
    }
    // SAFETY: dest_cs_ptr validated above; lock_raw/unlock_raw paired.
    let insert_res = unsafe {
        let saved = (*dest_cs_ptr).lock.lock_raw();
        let r: Result<u32, crate::cap::cspace::CapError> = if dest_slot_idx == 0
        {
            (*dest_cs_ptr)
                .insert_cap(src_tag, effective_rights, src_object)
                .map(core::num::NonZeroU32::get)
        }
        else
        {
            // insert_cap_at returns () on success; the destination index is the
            // caller-supplied (non-zero) dest_slot_idx.
            (*dest_cs_ptr)
                .insert_cap_at(dest_slot_idx, src_tag, effective_rights, src_object)
                .map(|()| dest_slot_idx)
        };
        if let Ok(idx) = r
            && src_badge != 0
            && let Some(new_slot) = (*dest_cs_ptr).slot_mut(idx)
        {
            new_slot.badge = src_badge;
        }
        // The index is non-zero: auto-allocation returns a non-zero slot and
        // the explicit path used a non-zero dest_slot_idx.
        let r = r
            .and_then(|idx| {
                core::num::NonZeroU32::new(idx).ok_or(crate::cap::cspace::CapError::InvalidIndex)
            })
            .map(|nz| (nz, (*dest_cs_ptr).cap_handle(nz)));
        (*dest_cs_ptr).lock.unlock_raw(saved);
        r
    };
    let (new_idx_nz, new_handle) = match insert_res
    {
        Ok(v) => v,
        Err(e) =>
        {
            crate::cap::DERIVATION_LOCK.write_unlock();
            // SAFETY: the reference taken above is given up; no lock held.
            unsafe { release_src_ref(src_object) };
            return Err(SyscallError::from(e));
        }
    };
    // Wire derivation tree: new slot is a child of the source slot.
    let parent = crate::cap::slot::SlotId::current(caller_cspace_id, src_idx_nz);
    let child = crate::cap::slot::SlotId::current(dest_cs_id, new_idx_nz);
    // SAFETY: DERIVATION_LOCK held; the parent revalidated and the child was
    // inserted under this hold, so both ends resolve.
    let linked = unsafe { crate::cap::derivation::link_child(parent, child) };
    debug_assert!(linked, "derivation link dropped under DERIVATION_LOCK");
    crate::cap::DERIVATION_LOCK.write_unlock();
    Ok(u64::from(new_handle))
}

/// `SYS_CAP_DERIVE` (14): attenuate a capability within the caller's own `CSpace.`
///
/// arg0 = source slot index (caller's `CSpace`).
/// arg1 = rights mask (must be a subset of source rights).
///
/// Creates a new slot in the caller's `CSpace` with the attenuated rights, wired
/// as a child of the source in the derivation tree. Unlike `SYS_CAP_COPY`, the
/// destination is always the caller's own `CSpace`, and no `CSpace` cap is required.
///
/// Returns the new slot index.
#[cfg(not(test))]
pub fn sys_cap_derive(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::Rights;

    let src_handle = tf.arg(0) as u32;
    let src_idx = syscall::cap_handle_index(src_handle);
    let rights_mask = Rights(tf.arg(1) as u32);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_cspace validated non-null above.
    let cspace_id = unsafe { (*caller_cspace).id() };

    // Resolve source slot.
    // SAFETY: caller_cspace validated non-null above. Decodes + generation-
    // checks the source handle, rejecting a stale handle to a recycled slot.
    let (src_tag, src_rights, src_object, src_badge) =
        unsafe { resolve_src_cap(caller_cspace, src_handle)? };

    let effective_rights = rights_mask & src_rights;

    // Convert src_idx to NonZeroU32 before the reference is taken; the
    // non-null tag check above excludes slot 0, so this only fires on a
    // malformed request.
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;

    // Increment refcount, then insert into caller's CSpace.
    // SAFETY: src_object validated above as valid NonNull from live slot.
    unsafe {
        (*src_object.as_ptr()).inc_ref();
    }

    // Revalidate the source, then insert and link, under one DERIVATION_LOCK
    // hold (cspace.lock nested per the documented order). The source was
    // resolved unlocked: a delete, move, or revoke batch may have freed its
    // slot meanwhile, and a link under a freed parent is dropped — the new
    // cap would be a derivation root outside every ancestor's revoke reach.
    // A cap reachable through the CSpace but not yet linked could be moved
    // out by a sibling, and a move carries whatever derivation position it
    // finds — the cap would leave the source's revoke reach for good. Every
    // occupied→free transition holds the lock, so neither can interleave
    // once the source revalidates. The badge write and the handle read share
    // the insert's critical section.
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: caller_cspace validated non-null above; DERIVATION_LOCK held.
    if let Err(e) = unsafe { revalidate_src_under_lock(caller_cspace, src_handle, src_object) }
    {
        crate::cap::DERIVATION_LOCK.write_unlock();
        // SAFETY: the reference taken above is given up; no lock held.
        unsafe { release_src_ref(src_object) };
        return Err(e);
    }
    // SAFETY: caller_cspace validated non-null above; lock_raw/unlock_raw paired.
    let insert_res = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace).insert_cap(src_tag, effective_rights, src_object);
        if let Ok(idx) = r
            && src_badge != 0
            && let Some(new_slot) = (*caller_cspace).slot_mut(idx.get())
        {
            new_slot.badge = src_badge;
        }
        let r = r.map(|idx| (idx, (*caller_cspace).cap_handle(idx)));
        (*caller_cspace).lock.unlock_raw(saved);
        r
    };
    let (new_idx_nz, new_handle) = match insert_res
    {
        Ok(v) => v,
        Err(e) =>
        {
            crate::cap::DERIVATION_LOCK.write_unlock();
            // SAFETY: the reference taken above is given up; no lock held.
            unsafe { release_src_ref(src_object) };
            return Err(SyscallError::from(e));
        }
    };
    let parent = crate::cap::slot::SlotId::current(cspace_id, src_idx_nz);
    let child = crate::cap::slot::SlotId::current(cspace_id, new_idx_nz);
    // SAFETY: DERIVATION_LOCK held; the parent revalidated and the child was
    // inserted under this hold, so both ends resolve.
    let linked = unsafe { crate::cap::derivation::link_child(parent, child) };
    debug_assert!(linked, "derivation link dropped under DERIVATION_LOCK");
    crate::cap::DERIVATION_LOCK.write_unlock();
    Ok(u64::from(new_handle))
}

/// `SYS_CAP_DERIVE_BADGE` (48): derive a capability with a badge attached.
///
/// arg0 = source slot index (caller's `CSpace`).
/// arg1 = rights mask (must be a subset of source rights).
/// arg2 = badge value (must be non-zero; source must have badge == 0).
///
/// Creates a new slot with the attenuated rights and the specified badge.
/// The badge is immutable once set — deriving from a badged cap inherits
/// the badge (via `SYS_CAP_DERIVE`), but setting a new badge on an already-
/// badged cap returns `InvalidArgument`.
///
/// Returns the new slot index.
#[cfg(not(test))]
pub fn sys_cap_derive_badge(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::Rights;

    let src_handle = tf.arg(0) as u32;
    let src_idx = syscall::cap_handle_index(src_handle);
    let rights_mask = Rights(tf.arg(1) as u32);
    let badge_value = tf.arg(2);

    if badge_value == 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_cspace validated non-null above.
    let cspace_id = unsafe { (*caller_cspace).id() };

    // Resolve source slot.
    // SAFETY: caller_cspace validated non-null above. Decodes + generation-
    // checks the source handle, rejecting a stale handle to a recycled slot.
    let (src_tag, src_rights, src_object, src_badge) =
        unsafe { resolve_src_cap(caller_cspace, src_handle)? };

    // Cannot re-badge a capability that already has a badge.
    if src_badge != 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    let effective_rights = rights_mask & src_rights;

    // Convert src_idx to NonZeroU32 before the reference is taken; the
    // non-null tag check above excludes slot 0, so this only fires on a
    // malformed request.
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;

    // Increment refcount, then insert into caller's CSpace.
    // SAFETY: src_object validated above as valid NonNull from live slot.
    unsafe {
        (*src_object.as_ptr()).inc_ref();
    }

    // Revalidate the source, then insert and link, under one DERIVATION_LOCK
    // hold (cspace.lock nested per the documented order). The source was
    // resolved unlocked: a delete, move, or revoke batch may have freed its
    // slot meanwhile, and a link under a freed parent is dropped — the new
    // cap would be a derivation root outside every ancestor's revoke reach.
    // A cap reachable through the CSpace but not yet linked could be moved
    // out by a sibling, and a move carries whatever derivation position it
    // finds — the cap would leave the source's revoke reach for good. Every
    // occupied→free transition holds the lock, so neither can interleave
    // once the source revalidates. The badge write and the handle read share
    // the insert's critical section.
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: caller_cspace validated non-null above; DERIVATION_LOCK held.
    if let Err(e) = unsafe { revalidate_src_under_lock(caller_cspace, src_handle, src_object) }
    {
        crate::cap::DERIVATION_LOCK.write_unlock();
        // SAFETY: the reference taken above is given up; no lock held.
        unsafe { release_src_ref(src_object) };
        return Err(e);
    }
    // SAFETY: caller_cspace validated non-null above; lock_raw/unlock_raw paired.
    let insert_res = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace).insert_cap(src_tag, effective_rights, src_object);
        if let Ok(idx) = r
            && let Some(new_slot) = (*caller_cspace).slot_mut(idx.get())
        {
            new_slot.badge = badge_value;
        }
        let r = r.map(|idx| (idx, (*caller_cspace).cap_handle(idx)));
        (*caller_cspace).lock.unlock_raw(saved);
        r
    };
    let (new_idx_nz, new_handle) = match insert_res
    {
        Ok(v) => v,
        Err(e) =>
        {
            crate::cap::DERIVATION_LOCK.write_unlock();
            // SAFETY: the reference taken above is given up; no lock held.
            unsafe { release_src_ref(src_object) };
            return Err(SyscallError::from(e));
        }
    };
    let parent = crate::cap::slot::SlotId::current(cspace_id, src_idx_nz);
    let child = crate::cap::slot::SlotId::current(cspace_id, new_idx_nz);
    // SAFETY: DERIVATION_LOCK held; the parent revalidated and the child was
    // inserted under this hold, so both ends resolve.
    let linked = unsafe { crate::cap::derivation::link_child(parent, child) };
    debug_assert!(linked, "derivation link dropped under DERIVATION_LOCK");
    crate::cap::DERIVATION_LOCK.write_unlock();
    Ok(u64::from(new_handle))
}

/// One-shot guard for [`log_self_cap_delete_refused`].
#[cfg(not(test))]
static SELF_CAP_DELETE_REFUSED_LOGGED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// One-shot diagnostic (#341): the first time a thread is refused deletion of
/// its own running Thread cap, log its tid, the cap slot, and the userspace rip
/// so the triggering call site can be symbolised from a burn-in log.
#[cfg(not(test))]
fn log_self_cap_delete_refused(tcb: *mut crate::sched::thread::ThreadControlBlock, slot: u32)
{
    use core::sync::atomic::Ordering;
    if SELF_CAP_DELETE_REFUSED_LOGGED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    // SAFETY: tcb is the live caller; trap_frame is its in-flight syscall frame.
    let (tid, tf) = unsafe { ((*tcb).thread_id, (*tcb).trap_frame) };
    if tf.is_null()
    {
        crate::kprintln!(
            "cap: refused self thread-cap delete: tid={tid} slot={slot} (no trap frame)"
        );
        return;
    }
    // SAFETY: tf non-null; it is the caller's saved userspace frame.
    let rip = unsafe { (*tf).instruction_pointer() };
    crate::kprintln!(
        "cap: refused self thread-cap delete: tid={tid} slot={slot} user_rip=0x{rip:x}"
    );
}

/// Resolve `SYS_CAP_DELETE`'s target under `DERIVATION_LOCK`: the slot's
/// object and derivation parent, or the syscall's early result — `Ok(0)` for
/// an idempotent Null slot (or, after the first batch, a slot a concurrent
/// delete finished), else the rejecting error. `expected` is the object the
/// first batch resolved (`None` on the first batch): a later batch that finds
/// the generation current but a different object is looking at a recycled
/// slot whose generation wrapped while the lock was released, and reports
/// success like the finished-delete case.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; `caller_cspace` must be
/// valid and non-null.
#[cfg(not(test))]
// type_complexity: the outer `Err` carries the delete's early result — its
// success (`Ok(0)`) or its rejecting error — so the loop returns it verbatim;
// a named alias would restate the syscall's return type for one call site.
#[allow(clippy::type_complexity)]
unsafe fn resolve_delete_target(
    caller_cspace: *mut crate::cap::cspace::CSpace,
    slot_idx: u32,
    slot_handle: u32,
    expected: Option<core::ptr::NonNull<crate::cap::object::KernelObjectHeader>>,
) -> Result<
    (
        core::ptr::NonNull<crate::cap::object::KernelObjectHeader>,
        Option<crate::cap::slot::SlotId>,
    ),
    Result<u64, SyscallError>,
>
{
    // SAFETY: caller contract.
    match unsafe { (*caller_cspace).slot(slot_idx) }
    {
        Some(slot) if slot.tag != crate::cap::slot::CapTag::Null =>
        {
            // Reject a stale handle to a recycled slot (#349). Must not fall to
            // the idempotent Null arm below — that would silently succeed
            // against the unrelated live cap now occupying the index. After
            // the first batch a recycled index means a concurrent delete
            // finished this slot: report success like the Null arm. The
            // object comparison catches a generation that wrapped across the
            // released-lock windows.
            if slot.generation() != syscall::cap_handle_gen(slot_handle)
            {
                return Err(
                    if expected.is_none()
                    {
                        Err(SyscallError::InvalidCapability)
                    }
                    else
                    {
                        Ok(0)
                    },
                );
            }
            if let Some(expected) = expected
                && slot.object != Some(expected)
            {
                return Err(Ok(0));
            }
            // A revoke is mid-flight on this slot (see
            // `CapabilitySlot::revoke_in_progress`): deleting the root
            // between revoke batches would promote its temporarily hoisted
            // survivors and sever intermediate revocation edges.
            // Transient — retry after the revoke completes.
            if slot.revoke_in_progress()
            {
                return Err(Err(SyscallError::InvalidState));
            }
            let Some(obj) = slot.object
            else
            {
                return Err(Err(SyscallError::InvalidCapability));
            };
            Ok((obj, slot.deriv_parent))
        }
        // Slot was Null on entry, or was cleared by a concurrent
        // revoke_subtree_batch / delete before we acquired the lock. Idempotent.
        Some(_) => Err(Ok(0)),
        None => Err(Err(SyscallError::InvalidCapability)),
    }
}

/// `SYS_CAP_DELETE` (31): delete a capability slot.
///
/// arg0 = slot index in the caller's `CSpace.`
///
/// Reparents any children to the deleted slot's parent (preserving revocability
/// from the grandparent), unlinks the slot from the derivation tree, clears it,
/// and `dec_refs` the kernel object. If refcount reaches 0, frees the object.
///
/// The reparenting runs in `MAX_REPARENT_EDITS` batches with the derivation
/// lock released in between (a slot can have arbitrarily many children); the
/// slot is revalidated (generation and object) before every batch. Between
/// batches it stays live with its remaining children still under it, so a
/// concurrent revoke starting on it stops this delete with `InvalidState`
/// (children already moved stay under the parent — still inside every
/// ancestor's subtree) and a concurrent delete — or move — that frees the
/// slot first makes this call return success (the generation, or the object
/// behind a wrapped generation, no longer matches; nothing is released here).
/// `MAX_REPARENT_BATCHES` bounds a concurrent-deriver livelock with
/// `Interrupted`.
///
/// Idempotent: deleting a Null slot returns success.
#[cfg(not(test))]
pub fn sys_cap_delete(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    let slot_handle = tf.arg(0) as u32;
    let slot_idx = syscall::cap_handle_index(slot_handle);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_cspace validated non-null above.
    let cspace_id = unsafe { (*caller_cspace).id() };

    let slot_idx_nz =
        core::num::NonZeroU32::new(slot_idx).ok_or(SyscallError::InvalidCapability)?;
    let node = crate::cap::slot::SlotId::current(cspace_id, slot_idx_nz);

    // Resolve the slot, unlink, and clear under DERIVATION_LOCK so a concurrent
    // revoke_subtree_batch on a parent cap cannot race-clear this slot between the
    // tag-check and the dec_ref. Both paths must dec_ref the object exactly
    // once between them. The loop re-enters once per reparent batch; the
    // final batch's hold performs the unlink and the free.
    let mut batches: u32 = 0;
    let mut expected = None;
    let obj_ptr = loop
    {
        crate::cap::DERIVATION_LOCK.write_lock();

        // SAFETY: caller_cspace validated non-null above; DERIVATION_LOCK held.
        let (obj_ptr, parent) =
            match unsafe { resolve_delete_target(caller_cspace, slot_idx, slot_handle, expected) }
            {
                Ok(target) => target,
                Err(early) =>
                {
                    crate::cap::DERIVATION_LOCK.write_unlock();
                    return early;
                }
            };
        expected = Some(obj_ptr);

        // #341: refuse to delete the last capability to the RUNNING thread's own
        // Thread object. This is always an aliased/stale-cap bug — std's
        // `Process::drop` deletes a child's `thread_cap` whose slot was reused for
        // the running (waiter) thread after the child was reaped. Completing the
        // delete tears the running thread down mid-syscall and orphans whatever it
        // was driving (the shell hangs). Refuse here, before the dec-ref/dealloc:
        // the cap stays and is reclaimed normally when a DIFFERENT thread later
        // joins/reaps this one. Logged once so the userspace site is symbolisable.
        // SAFETY: obj_ptr is a live KernelObjectHeader (slot confirmed live above);
        // tcb is the validated caller.
        if unsafe {
            (*obj_ptr.as_ptr()).obj_type == crate::cap::object::ObjectType::Thread
                && core::ptr::eq(
                    (*obj_ptr.as_ptr().cast::<crate::cap::object::ThreadObject>()).tcb,
                    tcb,
                )
        }
        {
            log_self_cap_delete_refused(tcb, slot_idx);
            crate::cap::DERIVATION_LOCK.write_unlock();
            return Err(SyscallError::InvalidState);
        }

        // SAFETY: DERIVATION_LOCK held; node and parent are valid SlotIds.
        let done = unsafe {
            crate::cap::derivation::reparent_children(
                node,
                parent,
                crate::cap::derivation::MAX_REPARENT_EDITS,
            )
        };
        batches += 1;
        if !done
        {
            crate::cap::DERIVATION_LOCK.write_unlock();
            if batches >= crate::cap::derivation::MAX_REPARENT_BATCHES
            {
                return Err(SyscallError::Interrupted);
            }
            continue;
        }

        // SAFETY: DERIVATION_LOCK held; node is a valid SlotId.
        unsafe { crate::cap::derivation::unlink_node(node) };

        // SAFETY: caller_cspace validated; slot confirmed live above. Take the
        // cspace lock strictly inside DERIVATION_LOCK so the freelist mutation
        // cannot tear against a concurrent SYS_CAP_CREATE_* on the same cspace.
        // Lock order: DERIVATION_LOCK → cspace.lock (matches transfer_caps).
        unsafe {
            let saved = (*caller_cspace).lock.lock_raw();
            (*caller_cspace).free_slot(slot_idx);
            (*caller_cspace).lock.unlock_raw(saved);
        }

        crate::cap::DERIVATION_LOCK.write_unlock();
        break obj_ptr;
    };

    // Dec-ref outside the lock — dealloc_object may take other locks.
    // SAFETY: obj_ptr captured under DERIVATION_LOCK while the slot was live;
    // unlink_node + free_slot above ensure no other CSpace path can re-dec_ref
    // this slot's object.
    let remaining = unsafe { (*obj_ptr.as_ptr()).dec_ref() };
    if remaining == 0
    {
        // SAFETY: refcount reached 0; no other references exist.
        unsafe {
            crate::cap::object::dealloc_object(obj_ptr);
        }
    }

    Ok(0)
}

/// `SYS_CAP_REVOKE` (15): revoke all capabilities derived from a slot.
///
/// arg0 = slot index in the caller's `CSpace.`
///
/// Walks and clears the entire descendant subtree of the target slot. The
/// target slot itself is preserved. For each revoked capability, the kernel
/// object's refcount is decremented; objects with zero refcount are freed.
///
/// # Errors
///
/// - `InvalidCapability` — the handle names no live slot, or its generation
///   is stale.
/// - `InvalidState` — another revoke is already in flight on this slot; or a
///   corrupted derivation link was found (the dangling chain was truncated
///   and the revoke is incomplete).
/// - `Interrupted` — the liveness backstop tripped: sustained concurrent
///   derivation kept extending the subtree past `MAX_REVOKE_BATCHES`
///   batches. Everything revoked so far stays revoked; retry to continue.
#[cfg(not(test))]
pub fn sys_cap_revoke(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    let slot_handle = tf.arg(0) as u32;
    let slot_idx = syscall::cap_handle_index(slot_handle);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_cspace validated non-null above.
    let cspace_id = unsafe { (*caller_cspace).id() };

    let slot_idx_nz =
        core::num::NonZeroU32::new(slot_idx).ok_or(SyscallError::InvalidCapability)?;
    let root = crate::cap::slot::SlotId::current(cspace_id, slot_idx_nz);

    // Revoke the subtree in batches of up to MAX_REVOKE_EDITS constant-time
    // tree edits (see the revocation algorithm in capability-internals.md).
    // Per batch: revalidate the root and run one batch under the lock, then
    // snapshot the dealloc list to a stack-local array so the lock is
    // released before calling `dealloc_object` (which may acquire the frame
    // allocator and other inner locks — see the safety doc on
    // `dealloc_object`).
    //
    // The root carries the revoke-in-progress marker for the whole
    // multi-batch operation so SYS_CAP_DELETE / SYS_CAP_MOVE / IPC transfer
    // cannot act on it between batches — that would promote the temporarily
    // hoisted survivors and permanently sever intermediate revocation
    // edges. The marker is cleared under the lock on every exit path —
    // completion, dead-link error, and the Interrupted backstop alike — so
    // it cannot leak. A root freed mid-revoke sheds the marker on the free
    // path (`set_next_free` zeroes it).
    let mut snapshot: [Option<core::ptr::NonNull<crate::cap::object::KernelObjectHeader>>;
        crate::cap::derivation::MAX_REVOKE_EDITS] =
        [None; crate::cap::derivation::MAX_REVOKE_EDITS];
    let mut first_batch = true;
    let mut batches: u32 = 0;
    loop
    {
        crate::cap::DERIVATION_LOCK.write_lock();

        // Validate the root slot is non-null and the handle's generation is
        // current — on entry (stale handles to recycled slots, #349), and
        // again before every later batch: the root may be deleted or its
        // slot recycled while the lock is dropped between batches, in which
        // case the remaining subtree now belongs to whatever reparenting the
        // concurrent operation performed, and this revoke must stop.
        let root_live = {
            // SAFETY: caller_cspace validated non-null above. Free paths
            // (delete/revoke) run under DERIVATION_LOCK, so a freed root is
            // observed stably here; re-population of a recycled index runs
            // under cspace.lock only and can race this read, but the
            // generation bump on free makes a raced read fail closed (the
            // handle's generation no longer matches).
            let cs = unsafe { &*caller_cspace };
            cs.slot(slot_idx).is_some_and(|slot| {
                slot.tag != crate::cap::slot::CapTag::Null
                    && slot.generation() == syscall::cap_handle_gen(slot_handle)
            })
        };
        if !root_live
        {
            crate::cap::DERIVATION_LOCK.write_unlock();
            return if first_batch
            {
                Err(SyscallError::InvalidCapability)
            }
            else
            {
                Ok(0)
            };
        }

        if first_batch
        {
            // A marker already set means another thread's revoke is in
            // flight on this slot; refuse rather than interleave two
            // marker lifetimes on one root.
            // SAFETY: caller_cspace validated; marker accessed only under
            // DERIVATION_LOCK.
            let already = unsafe {
                (*caller_cspace)
                    .slot_mut(slot_idx)
                    .is_none_or(|slot| slot.revoke_in_progress())
            };
            if already
            {
                crate::cap::DERIVATION_LOCK.write_unlock();
                return Err(SyscallError::InvalidState);
            }
            // SAFETY: as above.
            unsafe { pin_revoke_root(caller_cspace, slot_idx) };
        }

        // SAFETY: DERIVATION_LOCK held; root is a valid SlotId.
        let (objects, status) = unsafe { crate::cap::derivation::revoke_subtree_batch(root) };
        let snapshot_count = objects.len();
        debug_assert!(snapshot_count <= crate::cap::derivation::MAX_REVOKE_EDITS);
        snapshot[..snapshot_count].copy_from_slice(objects);

        // Liveness backstop: MoreWork batches beyond this bound mean a
        // concurrent deriver is extending the subtree at least as fast as
        // revocation reclaims it. Give the CPU back instead of looping
        // in-kernel forever; everything revoked so far stays revoked and a
        // retry continues from the surviving subtree.
        batches += 1;
        let backstop = batches >= MAX_REVOKE_BATCHES
            && status == crate::cap::derivation::BatchStatus::MoreWork;

        if status != crate::cap::derivation::BatchStatus::MoreWork || backstop
        {
            // Final batch (or backstop): release the root before dropping
            // the lock.
            // SAFETY: caller_cspace validated; marker accessed only under
            // DERIVATION_LOCK.
            unsafe { unpin_revoke_root(caller_cspace, slot_idx) };
        }
        crate::cap::DERIVATION_LOCK.write_unlock();

        dealloc_revoked(&snapshot[..snapshot_count]);

        if backstop
        {
            return Err(SyscallError::Interrupted);
        }
        match status
        {
            crate::cap::derivation::BatchStatus::Cleared => return Ok(0),
            crate::cap::derivation::BatchStatus::DeadLink =>
            {
                return Err(SyscallError::InvalidState);
            }
            crate::cap::derivation::BatchStatus::MoreWork =>
            {}
        }
        first_batch = false;
    }
}

/// Liveness backstop for `sys_cap_revoke`: the maximum number of batches one
/// syscall runs before returning `Interrupted`. At `MAX_REVOKE_EDITS` edits
/// per batch this covers ~2.7 × 10^8 edits (~1.3 × 10^8 revoked nodes) —
/// beyond any derivation subtree plausibly-sized hardware can hold, since
/// every node costs its creator a 72-byte slot plus a kernel object.
/// Reaching it therefore indicates sustained concurrent re-derivation, not a
/// large fixed subtree.
#[cfg(not(test))]
const MAX_REVOKE_BATCHES: u32 = 1 << 20;

/// Set the revoke-in-progress marker on `slot_idx` of `cspace`, pinning it
/// against delete/move/IPC-transfer for the duration of a multi-batch
/// revoke.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` (the marker's synchronisation domain)
/// and `cspace` must be a valid `CSpace` pointer.
#[cfg(not(test))]
unsafe fn pin_revoke_root(cspace: *mut crate::cap::cspace::CSpace, slot_idx: u32)
{
    // SAFETY: caller contract.
    if let Some(slot) = unsafe { (*cspace).slot_mut(slot_idx) }
    {
        slot.mark_revoke_in_progress();
    }
}

/// Clear the revoke-in-progress marker set by [`pin_revoke_root`].
///
/// # Safety
///
/// As for [`pin_revoke_root`].
#[cfg(not(test))]
unsafe fn unpin_revoke_root(cspace: *mut crate::cap::cspace::CSpace, slot_idx: u32)
{
    // SAFETY: caller contract.
    if let Some(slot) = unsafe { (*cspace).slot_mut(slot_idx) }
    {
        slot.clear_revoke_in_progress();
    }
}

/// Dec-ref each collected object and deallocate those that reach refcount
/// zero. Must run outside `DERIVATION_LOCK` — `dealloc_object` may acquire
/// the frame allocator and other inner locks.
#[cfg(not(test))]
fn dealloc_revoked(snapshot: &[Option<core::ptr::NonNull<crate::cap::object::KernelObjectHeader>>])
{
    for entry in snapshot
    {
        let Some(obj_ptr) = *entry
        else
        {
            continue;
        };
        // SAFETY: obj_ptr from revoke_subtree_batch; was a live capability object.
        let remaining = unsafe { (*obj_ptr.as_ptr()).dec_ref() };
        if remaining == 0
        {
            // SAFETY: refcount reached 0; no other references exist.
            unsafe {
                crate::cap::object::dealloc_object(obj_ptr);
            }
        }
    }
}

/// `SYS_CAP_MOVE` (25): atomically move a capability to another `CSpace.`
///
/// arg0 = source slot index (caller's `CSpace`).
/// arg1 = destination `CSpace` cap index (must have INSERT right).
/// arg2 = destination slot index in the target `CSpace`, or 0 to auto-allocate.
///
/// The source slot is cleared and the capability (with its full derivation tree
/// links) is relocated to the destination. The object refcount is unchanged.
///
/// Returns the destination slot index.
// too_many_lines: cap-move logic requires atomically resolving two CSpaces, handling
// both auto-allocate and fixed-index paths, and updating the derivation tree.
// Splitting would not improve clarity.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_cap_move(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::CSpaceKernelObject;
    use crate::cap::slot::SlotId;

    let src_handle = tf.arg(0) as u32;
    let src_idx = syscall::cap_handle_index(src_handle);
    let dest_cs_idx = tf.arg(1) as u32;
    // Destination is a placement index (slot may be empty), not a live handle:
    // decode the index, but do not generation-check it. 0 = auto-allocate.
    let dest_idx = syscall::cap_handle_index(tf.arg(2) as u32);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Resolve destination CSpace.
    // SAFETY: caller_cspace validated non-null above.
    let dest_cs_slot = unsafe {
        super::lookup_cap(
            caller_cspace,
            dest_cs_idx,
            crate::cap::slot::CsRights::INSERT,
        )
    }?;
    let dest_obj = dest_cs_slot.object.ok_or(SyscallError::InvalidCapability)?;
    let dest_cs_ptr = {
        // cast_ptr_alignment: header is at offset 0 of CSpaceKernelObject; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: cap tag confirmed CSpace; object pointer is valid.
        let cs_obj = unsafe { &*(dest_obj.as_ptr().cast::<CSpaceKernelObject>()) };
        cs_obj.cspace
    };

    // Generation-check the source handle before the move. `move_cap_between_cspaces`
    // takes a pre-decoded, pre-validated bare index — every caller checks its
    // own source handle first (the IPC transfer path in
    // `prevalidate_transfer_slots`, this path here) (#349).
    {
        // SAFETY: caller_cspace validated non-null above.
        let cs = unsafe { &*caller_cspace };
        let slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == crate::cap::slot::CapTag::Null
            || slot.generation() != syscall::cap_handle_gen(src_handle)
        {
            return Err(SyscallError::InvalidCapability);
        }
    }

    if dest_idx == 0
    {
        // Auto-allocate: delegate to the shared helper. Hold both cspace
        // locks (in pointer address order to prevent ABBA deadlock) so the
        // freelist mutations inside `move_cap_between_cspaces` cannot tear
        // against a concurrent SYS_CAP_CREATE_*. Lock order:
        // DERIVATION_LOCK → cspace.lock(s) (matches transfer_caps).
        crate::cap::DERIVATION_LOCK.write_lock();
        // SAFETY: both CSpace pointers validated above; released via
        // unlock_cspace_pair with the same argument order.
        let (saved1, saved2) = unsafe { crate::cap::lock_cspace_pair(caller_cspace, dest_cs_ptr) };
        // SAFETY: both CSpace pointers valid; DERIVATION_LOCK and both cspace locks held.
        let result =
            unsafe { crate::cap::move_cap_between_cspaces(caller_cspace, src_idx, dest_cs_ptr) };
        // SAFETY: saved1 and saved2 came from the lock_cspace_pair call above.
        unsafe {
            crate::cap::unlock_cspace_pair(caller_cspace, dest_cs_ptr, saved1, saved2);
        }
        crate::cap::DERIVATION_LOCK.write_unlock();
        return Ok(u64::from(result?));
    }

    // Explicit destination index — keep inline so we can use insert_cap_at.
    // SAFETY: caller_cspace validated non-null above.
    let src_cspace_id = unsafe { (*caller_cspace).id() };
    // SAFETY: dest_cs_ptr extracted from validated CSpace object above.
    let dest_cspace_id = unsafe { (*dest_cs_ptr).id() };

    // Read source slot contents.
    // SAFETY: caller_cspace validated non-null above. Decodes + generation-
    // checks the source handle, rejecting a stale handle to a recycled slot.
    let (src_tag, src_rights, src_object, src_badge) =
        unsafe { resolve_src_cap(caller_cspace, src_handle)? };

    // Pre-convert indices before locking so failure cannot leak locks.
    // src_idx cleared the non-null tag check (slot 0 is permanently Null);
    // dest_idx is != 0 (the `dest_idx == 0` path returned above).
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;
    let dest_idx_nz =
        core::num::NonZeroU32::new(dest_idx).ok_or(SyscallError::InvalidCapability)?;

    // Pre-grow for the explicit destination before the heavyweight locks:
    // bounded holds, budget fast-fail (see pre_grow_for_explicit_slot), the
    // destination wrapper held across it.
    // May run the destination's teardown if its last capability went
    // meanwhile (see pre_grow_holding_dest).
    // SAFETY: dest_obj is the live wrapper resolved above; no lock held.
    unsafe { pre_grow_holding_dest(dest_obj, dest_cs_ptr, dest_idx)? };

    crate::cap::DERIVATION_LOCK.write_lock();

    // Lock both CSpaces in pointer address order to prevent deadlock.
    // SAFETY: both CSpace pointers validated above; released via
    // unlock_cspace_pair with the same argument order.
    let (saved1, saved2) = unsafe { crate::cap::lock_cspace_pair(caller_cspace, dest_cs_ptr) };

    // Re-validate the source under the locks: it may have been freed,
    // recycled, or gained a revoke-in-progress marker since the unlocked
    // checks above (moving a mid-revoke root would abandon its temporarily
    // hoisted survivors — see `CapabilitySlot::revoke_in_progress`).
    {
        // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
        let cs = unsafe { &*caller_cspace };
        let err = match cs.slot(src_idx)
        {
            None => Some(SyscallError::InvalidCapability),
            Some(slot)
                if slot.tag == crate::cap::slot::CapTag::Null
                    || slot.generation() != syscall::cap_handle_gen(src_handle)
                    || slot.object != Some(src_object) =>
            {
                Some(SyscallError::InvalidCapability)
            }
            Some(slot) if slot.revoke_in_progress() => Some(SyscallError::InvalidState),
            Some(_) => None,
        };
        if let Some(e) = err
        {
            // SAFETY: saved1 and saved2 came from the lock_cspace_pair call above.
            unsafe {
                crate::cap::unlock_cspace_pair(caller_cspace, dest_cs_ptr, saved1, saved2);
            }
            crate::cap::DERIVATION_LOCK.write_unlock();
            return Err(e);
        }
    }

    // SAFETY: dest_cs_ptr validated above; DERIVATION_LOCK and both CSpace locks held.
    let insert_result =
        unsafe { (*dest_cs_ptr).insert_cap_at(dest_idx, src_tag, src_rights, src_object) };
    if let Err(e) = insert_result
    {
        // Unlock before returning error.
        // SAFETY: saved1 and saved2 came from the lock_cspace_pair call above.
        unsafe {
            crate::cap::unlock_cspace_pair(caller_cspace, dest_cs_ptr, saved1, saved2);
        }
        crate::cap::DERIVATION_LOCK.write_unlock();
        return Err(e.into());
    }

    let src_slot_id = SlotId::current(src_cspace_id, src_idx_nz);
    let dst_slot_id = SlotId::current(dest_cspace_id, dest_idx_nz);

    // Copy derivation links to destination.
    let (src_parent, src_first_child, src_prev, src_next) = {
        // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
        let cs = unsafe { &*caller_cspace };
        // SAFETY: src_idx was validated to index a live slot by the
        // cs.slot(src_idx).ok_or(...) check in the source-slot read above.
        #[allow(clippy::unwrap_used)]
        let slot = cs.slot(src_idx).unwrap();
        (
            slot.deriv_parent,
            slot.deriv_first_child,
            slot.deriv_prev_sibling,
            slot.deriv_next_sibling,
        )
    };
    // SAFETY: dest_cs_ptr validated; DERIVATION_LOCK held.
    if let Some(dst_slot) = unsafe { (*dest_cs_ptr).slot_mut(dest_idx) }
    {
        dst_slot.badge = src_badge;
        dst_slot.deriv_parent = src_parent;
        dst_slot.deriv_first_child = src_first_child;
        dst_slot.deriv_prev_sibling = src_prev;
        dst_slot.deriv_next_sibling = src_next;
    }

    // Update parent's child pointer.
    if let Some(parent_id) = src_parent
        && let Some(parent_cs) = crate::cap::lookup_cspace(parent_id.cspace_id, parent_id.epoch)
    {
        // SAFETY: parent_cs from registry; DERIVATION_LOCK held.
        if let Some(parent_slot) = unsafe { (*parent_cs).slot_mut(parent_id.index.get()) }
            && parent_slot.deriv_first_child == Some(src_slot_id)
        {
            parent_slot.deriv_first_child = Some(dst_slot_id);
        }
    }

    // Update siblings' pointers.
    if let Some(prev_id) = src_prev
        && let Some(prev_cs) = crate::cap::lookup_cspace(prev_id.cspace_id, prev_id.epoch)
    {
        // SAFETY: prev_cs from registry; DERIVATION_LOCK held.
        if let Some(prev_slot) = unsafe { (*prev_cs).slot_mut(prev_id.index.get()) }
            && prev_slot.deriv_next_sibling == Some(src_slot_id)
        {
            prev_slot.deriv_next_sibling = Some(dst_slot_id);
        }
    }
    if let Some(next_id) = src_next
        && let Some(next_cs) = crate::cap::lookup_cspace(next_id.cspace_id, next_id.epoch)
    {
        // SAFETY: next_cs from registry; DERIVATION_LOCK held.
        if let Some(next_slot) = unsafe { (*next_cs).slot_mut(next_id.index.get()) }
            && next_slot.deriv_prev_sibling == Some(src_slot_id)
        {
            next_slot.deriv_prev_sibling = Some(dst_slot_id);
        }
    }

    // Update children's parent pointer.
    let mut child_cur = src_first_child;
    while let Some(child_id) = child_cur
    {
        child_cur = if let Some(child_cs) =
            crate::cap::lookup_cspace(child_id.cspace_id, child_id.epoch)
        {
            // SAFETY: child_cs from registry; DERIVATION_LOCK held.
            if let Some(child_slot) = unsafe { (*child_cs).slot_mut(child_id.index.get()) }
            {
                child_slot.deriv_parent = Some(dst_slot_id);
                child_slot.deriv_next_sibling
            }
            else
            {
                None
            }
        }
        else
        {
            None
        };
    }

    // Clear the source slot. No inc_ref/dec_ref needed (it's a move).
    // SAFETY: caller_cspace validated; DERIVATION_LOCK and CSpace locks held.
    unsafe {
        (*caller_cspace).free_slot(src_idx);
    }

    // Encode the destination slot's generation into the returned handle
    // (#349) while the destination lock is still held: read after the
    // release, a sibling's delete-and-refill of the slot could hand back a
    // live handle to the refill instead.
    // SAFETY: dest_cs_ptr validated above; its lock is held by the pair.
    let dest_handle = unsafe { (*dest_cs_ptr).cap_handle(dest_idx_nz) };

    // Unlock CSpaces in reverse order of acquisition.
    // SAFETY: saved1 and saved2 came from the lock_cspace_pair call above.
    unsafe {
        crate::cap::unlock_cspace_pair(caller_cspace, dest_cs_ptr, saved1, saved2);
    }

    crate::cap::DERIVATION_LOCK.write_unlock();
    Ok(u64::from(dest_handle))
}

/// `SYS_CAP_CREATE_EVENT_Q` (9): create a new `EventQueue` object.
///
/// arg0 = capacity (`1..=EVENT_QUEUE_MAX_CAPACITY`).
///
/// Allocates `EventQueueState` (with its ring buffer) and `EventQueueObject`,
/// inserts a cap with `POST | RECV` rights into the caller's `CSpace.`
/// Returns the slot index in rax/a0.
#[cfg(not(test))]
pub fn sys_cap_create_event_queue(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{EventQueueObject, KernelObjectHeader, MemoryObject, ObjectType};
    use crate::cap::retype::{EVENT_QUEUE_RING_OFFSET, dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{EqRights, MemRights};
    use crate::ipc::event_queue::EventQueueState;
    use core::ptr::NonNull;
    use syscall::EVENT_QUEUE_MAX_CAPACITY;

    let memory_slot = tf.arg(0) as u32;
    let capacity = tf.arg(1) as u32;
    if capacity == 0 || capacity > EVENT_QUEUE_MAX_CAPACITY
    {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace = unsafe { (*tcb).cspace };
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: cspace validated; lookup_cap checks tag and rights.
    let memory_slot_ref = unsafe { super::lookup_cap(cspace, memory_slot, MemRights::RETYPE)? };
    let memory_obj_nn = memory_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Memory slot.
    let memory = unsafe { &*memory_obj_nn.as_ptr().cast::<MemoryObject>() };

    let entry = dispatch_for(ObjectType::EventQueue, u64::from(capacity))
        .ok_or(SyscallError::InvalidArgument)?;

    let offset = retype_allocate(memory, entry.raw_bytes)?;

    let block_phys = memory.base + offset;
    let block_virt = crate::mm::paging::phys_to_virt(block_phys);

    // Layout (matches `cap::retype::event_queue_raw_bytes`):
    //   offset  0: EventQueueObject (24 B)
    //   offset 24: EventQueueState  (56 B)
    //   offset 80: ring buffer ((capacity + 1) * 8 B)
    let eq_obj_ptr = block_virt as *mut EventQueueObject;
    let state_offset = core::mem::size_of::<EventQueueObject>() as u64;
    let eq_state_ptr = (block_virt + state_offset) as *mut EventQueueState;
    let ring_ptr = (block_virt + EVENT_QUEUE_RING_OFFSET) as *mut u64;
    let ring_len = (capacity as usize) + 1;

    let ancestor = memory_obj_nn;

    // SAFETY: pointers are inside the freshly-allocated retype slot.
    // The ring lives inline; zero it first since retype memory is not
    // guaranteed clean (bump path returns uninitialised bytes; free-list
    // reuse may also return stale contents).
    unsafe {
        core::ptr::write_bytes(ring_ptr, 0, ring_len);
        core::ptr::write(eq_state_ptr, EventQueueState::new(capacity, ring_ptr));
        core::ptr::write(
            eq_obj_ptr,
            EventQueueObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::EventQueue, ancestor),
                state: eq_state_ptr,
            },
        );
    }

    // SAFETY: ancestor is the MemoryObject's header at offset 0.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: header at offset 0 of EventQueueObject.
    let nonnull = unsafe { NonNull::new_unchecked(eq_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap_handle_typed(EqRights::POST | EqRights::RECV, nonnull);
        (*cspace).lock.unlock_raw(saved);
        r
    };

    match idx_res
    {
        Ok(idx) => Ok(u64::from(idx)),
        Err(e) =>
        {
            // The cap never reached visibility, so no waiter or `wait_set`
            // back-pointer can exist. Drop the in-place state and wrapper,
            // return the slot bytes (which include the inline ring) to the
            // ancestor cap, and undo the lease bump.
            // SAFETY: state and wrapper were just constructed in place above
            // and have not been observed by any other thread.
            unsafe {
                core::ptr::drop_in_place(eq_state_ptr);
                core::ptr::drop_in_place(eq_obj_ptr);
            }
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches the inc_ref above.
            unsafe { ancestor.as_ref().dec_ref() };
            Err(e.into())
        }
    }
}

/// `SYS_CAP_CREATE_WAIT_SET` (13): retype a Memory cap into a new `WaitSet`.
///
/// arg0 = Memory-cap slot. The Memory cap MUST carry `MemRights::RETYPE` and have
/// at least `dispatch_for(WaitSet, 0).raw_bytes` (504) of `available_bytes`.
#[cfg(not(test))]
pub fn sys_cap_create_wait_set(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{KernelObjectHeader, MemoryObject, ObjectType, WaitSetObject};
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{MemRights, WsRights};
    use crate::ipc::wait_set::WaitSetState;
    use core::ptr::NonNull;

    let memory_slot = tf.arg(0) as u32;

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace = unsafe { (*tcb).cspace };
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: cspace validated; lookup_cap checks tag and rights.
    let memory_slot_ref = unsafe { super::lookup_cap(cspace, memory_slot, MemRights::RETYPE)? };
    let memory_obj_nn = memory_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Memory slot.
    let memory = unsafe { &*memory_obj_nn.as_ptr().cast::<MemoryObject>() };

    let entry = dispatch_for(ObjectType::WaitSet, 0).ok_or(SyscallError::InvalidArgument)?;

    let offset = retype_allocate(memory, entry.raw_bytes)?;

    let block_phys = memory.base + offset;
    let block_virt = crate::mm::paging::phys_to_virt(block_phys);

    // Layout: WaitSetObject at offset 0; WaitSetState at offset 24.
    let ws_obj_ptr = block_virt as *mut WaitSetObject;
    let state_offset = core::mem::size_of::<WaitSetObject>() as u64;
    let ws_state_ptr = (block_virt + state_offset) as *mut WaitSetState;

    let ancestor = memory_obj_nn;

    // SAFETY: pointers are inside the freshly-allocated retype slot.
    unsafe {
        core::ptr::write(ws_state_ptr, WaitSetState::new());
        core::ptr::write(
            ws_obj_ptr,
            WaitSetObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::WaitSet, ancestor),
                state: ws_state_ptr,
            },
        );
    }

    // SAFETY: ancestor is the MemoryObject's header at offset 0.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: header at offset 0 of WaitSetObject.
    let nonnull = unsafe { NonNull::new_unchecked(ws_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap_handle_typed(WsRights::MODIFY | WsRights::WAIT, nonnull);
        (*cspace).lock.unlock_raw(saved);
        r
    };

    match idx_res
    {
        Ok(idx) => Ok(u64::from(idx)),
        Err(e) =>
        {
            // Roll back: nothing else has observed these constructed objects.
            // SAFETY: pointers are unique-ownership for this caller.
            unsafe {
                core::ptr::drop_in_place(ws_obj_ptr);
                core::ptr::drop_in_place(ws_state_ptr);
            }
            retype_free(memory, offset, entry.raw_bytes);
            // SAFETY: matches the inc_ref above.
            unsafe { ancestor.as_ref().dec_ref() };
            Err(e.into())
        }
    }
}

/// `SYS_CAP_INFO` (36): read-only inspection of a capability slot's runtime state.
///
/// arg0 = slot index in the caller's `CSpace`.
/// arg1 = field selector (one of `syscall::CAP_INFO_*`).
///
/// Returns a single `u64`. Userspace assembles the full picture of a cap
/// by issuing repeated calls with different selectors. The shape mirrors
/// `SYS_SYSTEM_INFO`.
///
/// # Field selectors
/// - [`syscall::CAP_INFO_TAG_RIGHTS`] — universal; returns
///   `((tag as u8 as u64) << 32) | (rights.0 as u64)`.
/// - [`syscall::CAP_INFO_MEMORY_SIZE`] / `_AVAILABLE` / `_HAS_RETYPE` —
///   require `CapTag::Memory`.
/// - [`syscall::CAP_INFO_ASPACE_PT_BUDGET`] — requires `CapTag::AddressSpace`.
/// - [`syscall::CAP_INFO_CSPACE_CAPACITY`] / `_USED` / `_BUDGET` —
///   require `CapTag::CSpace`.
///
/// # Errors
/// - [`SyscallError::InvalidCapability`] if the slot is null or out of range.
/// - [`SyscallError::InvalidArgument`] if the selector is unknown or
///   tag-specific and the slot's tag does not match.
///
/// This handler does not gate on rights — holding the slot is sufficient to
/// inspect its state. No mutation occurs.
// too_many_lines: a single flat dispatch on the field selector is the clearest
// shape for this read-only inquiry handler. Splitting it adds only indirection.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_cap_info(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use core::sync::atomic::Ordering;

    use syscall::{
        CAP_INFO_ASPACE_PT_BUDGET, CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_CAPACITY,
        CAP_INFO_CSPACE_USED, CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_HAS_RETYPE,
        CAP_INFO_MEMORY_PHYS_BASE, CAP_INFO_MEMORY_SIZE, CAP_INFO_TAG_RIGHTS,
        CAP_INFO_THREAD_STATE, CAP_INFO_TLB_ELIDED, CAP_INFO_TLB_PERFORMED, THREAD_STATE_ALIVE,
        THREAD_STATE_CREATED, THREAD_STATE_EXITED,
    };

    use crate::cap::object::{AddressSpaceObject, CSpaceKernelObject, MemoryObject, ThreadObject};
    use crate::cap::slot::{CapTag, MemRights};
    use crate::sched::thread::ThreadState;

    let slot_handle = tf.arg(0) as u32;
    let slot_idx = syscall::cap_handle_index(slot_handle);
    let field = tf.arg(1);

    // Resolve the caller's CSpace via its TCB.
    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above; cspace field set at thread creation.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Snapshot the slot's tag, rights, and object pointer. cap_info is a
    // read-only inquiry: holding the slot is sufficient — no per-field rights
    // check is required.
    // SAFETY: caller_cspace validated non-null above.
    let cs = unsafe { &*caller_cspace };
    let slot = cs.slot(slot_idx).ok_or(SyscallError::InvalidCapability)?;
    if slot.tag == CapTag::Null
    {
        return Err(SyscallError::InvalidCapability);
    }
    // Reject a stale handle to a recycled slot (#349).
    if slot.generation() != syscall::cap_handle_gen(slot_handle)
    {
        return Err(SyscallError::InvalidCapability);
    }
    let tag = slot.tag;
    let rights = slot.rights;
    let obj = slot.object.ok_or(SyscallError::InvalidCapability)?;

    match field
    {
        CAP_INFO_TAG_RIGHTS =>
        {
            // Pack the discriminant and bitmask. CapTag is repr(u8), so the
            // u8 cast is total; widening to u64 then shifting left 32 keeps
            // the rights bitmask in the low 32 bits with no overlap.
            let packed = (u64::from(tag as u8) << 32) | u64::from(rights.0);
            Ok(packed)
        }
        CAP_INFO_TLB_ELIDED =>
        {
            // System-wide tagged-TLB diagnostic; independent of the slot.
            Ok(crate::percpu::ctxsw_flush_totals().0)
        }
        CAP_INFO_TLB_PERFORMED => Ok(crate::percpu::ctxsw_flush_totals().1),
        CAP_INFO_MEMORY_SIZE =>
        {
            if tag != CapTag::Memory
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed Memory; header is at offset 0 of MemoryObject.
            // cast_ptr_alignment: MemoryObject (8-byte aligned via Box) holds the header at offset 0.
            #[allow(clippy::cast_ptr_alignment)]
            let memory = unsafe { &*(obj.as_ptr().cast::<MemoryObject>()) };
            Ok(memory.size)
        }
        CAP_INFO_MEMORY_AVAILABLE =>
        {
            if tag != CapTag::Memory
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed Memory.
            #[allow(clippy::cast_ptr_alignment)]
            let memory = unsafe { &*(obj.as_ptr().cast::<MemoryObject>()) };
            Ok(memory.available_bytes.load(Ordering::Acquire))
        }
        CAP_INFO_MEMORY_HAS_RETYPE =>
        {
            if tag != CapTag::Memory
            {
                return Err(SyscallError::InvalidArgument);
            }
            Ok(u64::from(rights.contains(MemRights::RETYPE.erase())))
        }
        CAP_INFO_MEMORY_PHYS_BASE =>
        {
            if tag != CapTag::Memory
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed Memory.
            #[allow(clippy::cast_ptr_alignment)]
            let memory = unsafe { &*(obj.as_ptr().cast::<MemoryObject>()) };
            Ok(memory.base)
        }
        CAP_INFO_THREAD_STATE =>
        {
            if tag != CapTag::Thread
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed Thread; header at offset 0 of ThreadObject.
            #[allow(clippy::cast_ptr_alignment)]
            let thr_obj = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
            let target_tcb = thr_obj.tcb;
            if target_tcb.is_null()
            {
                return Err(SyscallError::InvalidCapability);
            }
            // Acquire the local CPU's scheduler lock to synchronise with the
            // matching `set_state_under_all_locks(Exited)` on whichever CPU
            // ran the dying thread. That writer held every CPU's scheduler
            // lock; releasing this CPU's lock provides Release ordering, and
            // our acquire here provides the matching Acquire — so the
            // (`exit_reason`, `state`) pair written before the all-CPU
            // release is visible coherently.
            let cpu = crate::arch::current::cpu::current_cpu() as usize;
            // SAFETY: cpu is the running CPU; scheduler slab is initialised.
            let sched = unsafe { crate::sched::scheduler_for(cpu) };
            // SAFETY: lock_raw / unlock_raw paired below.
            let saved = unsafe { sched.lock.lock_raw() };
            // SAFETY: target_tcb came from a Thread cap; lifetime extends to
            // cap_revoke / cap_delete which we do not race here.
            let (state, exit_reason) = unsafe { ((*target_tcb).state, (*target_tcb).exit_reason) };
            // SAFETY: paired with lock_raw above.
            unsafe { sched.lock.unlock_raw(saved) };
            let state_code = match state
            {
                ThreadState::Created => THREAD_STATE_CREATED,
                ThreadState::Exited => THREAD_STATE_EXITED,
                ThreadState::Ready
                | ThreadState::Running
                | ThreadState::Blocked
                | ThreadState::Stopped => THREAD_STATE_ALIVE,
            };
            let reason_low = exit_reason & 0xFFFF_FFFF;
            Ok((u64::from(state_code) << 32) | reason_low)
        }
        CAP_INFO_ASPACE_PT_BUDGET =>
        {
            if tag != CapTag::AddressSpace
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed AddressSpace.
            #[allow(clippy::cast_ptr_alignment)]
            let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
            Ok(as_obj.pt_growth_budget_bytes.load(Ordering::Acquire))
        }
        CAP_INFO_CSPACE_CAPACITY =>
        {
            if tag != CapTag::CSpace
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed CSpace; header at offset 0 of CSpaceKernelObject.
            #[allow(clippy::cast_ptr_alignment)]
            let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
            let target = cs_obj.cspace;
            if target.is_null()
            {
                return Err(SyscallError::InvalidCapability);
            }
            // Currently-backed capacity: slots already threaded onto pages
            // plus what the remaining growth-budget pages would add, clamped
            // to the highest reachable count (the structural ceiling minus
            // the permanently-reserved slot 0). A mild over-estimate: page 0
            // is counted before it exists (reserved slot 0), and past the
            // direct region roughly one budget page per DIR_FANOUT leaves
            // is spent on a directory page that backs no slots. Headroom
            // triggers tolerate both. The budget read is outside the CSpace
            // lock, so grows landing between the two reads skew the sum;
            // the value is advisory and the same triggers tolerate the
            // skew.
            // SAFETY: cs_obj.cspace validated non-null; allocated_slots is
            // mutated only under the CSpace lock, taken here; lock_raw /
            // unlock_raw paired.
            let allocated = unsafe {
                let saved = (*target).lock.lock_raw();
                let a = (*target).allocated_slots();
                (*target).lock.unlock_raw(saved);
                a
            } as u64;
            let budget = cs_obj.cspace_growth_budget_bytes.load(Ordering::Acquire);
            let backed = allocated
                + (budget / crate::mm::PAGE_SIZE as u64) * crate::cap::cspace::L2_SIZE as u64;
            Ok(backed.min(crate::cap::cspace::MAX_SLOTS_STRUCTURAL as u64 - 1))
        }
        CAP_INFO_CSPACE_USED =>
        {
            if tag != CapTag::CSpace
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed CSpace.
            #[allow(clippy::cast_ptr_alignment)]
            let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
            let target = cs_obj.cspace;
            if target.is_null()
            {
                return Err(SyscallError::InvalidCapability);
            }
            // SAFETY: cs_obj.cspace validated non-null; the two usize fields
            // populated_count derives from are mutated only under the CSpace
            // lock, taken here; lock_raw / unlock_raw paired.
            let used = unsafe {
                let saved = (*target).lock.lock_raw();
                let u = (*target).populated_count();
                (*target).lock.unlock_raw(saved);
                u
            };
            Ok(used as u64)
        }
        CAP_INFO_CSPACE_BUDGET =>
        {
            if tag != CapTag::CSpace
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed CSpace.
            #[allow(clippy::cast_ptr_alignment)]
            let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
            Ok(cs_obj.cspace_growth_budget_bytes.load(Ordering::Acquire))
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

// ── Test stubs ─────────────────────────────────────────────────────────────────
// These stubs satisfy the type checker for host test builds. Syscall handlers
// are never called in host tests; the stubs exist only so the module compiles.

#[cfg(test)]
pub fn sys_cap_create_endpoint(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_create_notification(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_create_aspace(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_create_cspace(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_create_thread(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_copy(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_derive(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_delete(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_revoke(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_move(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_create_event_queue(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_cap_create_wait_set(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}
