// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/cap.rs

//! Capability creation and manipulation syscall handlers.
//!
//! Allocates kernel objects and inserts them into a `CSpace`.
//! Returns a slot index on success.
//!
//! # Adding a new capability creation syscall
//! 1. Allocate any secondary state (e.g. `EndpointState`).
//! 2. Allocate the kernel object (`Box::new(FooObject { ... })`).
//! 3. Call `nonnull_from_box` to get a `NonNull<KernelObjectHeader>`.
//! 4. Call `(*cspace).insert_cap(tag, rights, nonnull)`.
//! 5. Return the slot index as `u64`.

// cast_possible_truncation: all u64→u32 casts in this file extract cap slot indices
// from 64-bit trap frame registers. Seraph runs on 64-bit only; slot indices are
// defined as u32 and always fit. No truncation occurs in practice.
#![allow(clippy::cast_possible_truncation)]

use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

#[cfg(not(test))]
use super::current_tcb;

/// `SYS_CAP_CREATE_ENDPOINT` (7): retype a Frame cap into a new Endpoint.
///
/// arg0 = Frame-cap slot index in the caller's `CSpace`. The Frame cap
/// MUST carry `Rights::RETYPE` and have at least
/// `dispatch_for(Endpoint, 0).raw_bytes` (88 B) of `available_bytes`.
///
/// On success, the wrapper + `EndpointState` are constructed in place inside
/// the source Frame cap's region; a cap with `SEND | RECEIVE | GRANT` rights
/// is inserted into the caller's `CSpace`; returns the slot index.
///
/// On `dec_ref → 0`, auto-reclaim returns the bytes to the source Frame cap
/// via [`crate::cap::object::dealloc_object`] consulting `header.ancestor`.
#[cfg(not(test))]
pub fn sys_cap_create_endpoint(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{EndpointObject, FrameObject, KernelObjectHeader, ObjectType};
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::endpoint::EndpointState;
    use core::ptr::NonNull;

    let frame_slot = tf.arg(0) as u32;

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

    // Resolve the source Frame cap. Requires Rights::RETYPE.
    // SAFETY: cspace validated non-null above.
    let frame_slot_ref =
        unsafe { super::lookup_cap(cspace, frame_slot, CapTag::Frame, Rights::RETYPE)? };
    let frame_obj_nn = frame_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Frame slot whose object pointer is
    // valid for the lifetime of the slot.
    let frame = unsafe { &*frame_obj_nn.as_ptr().cast::<FrameObject>() };

    let entry = dispatch_for(ObjectType::Endpoint, 0).ok_or(SyscallError::InvalidArgument)?;

    // Reserve bytes in the Frame cap region.
    let offset = retype_allocate(frame, entry.raw_bytes)?;

    // Compute the kernel direct-map virtual address of the new object.
    let block_phys = frame.base + offset;
    let block_virt = crate::mm::paging::phys_to_virt(block_phys);

    // Layout: EndpointObject at offset 0; EndpointState at offset
    // size_of::<EndpointObject>() (24). Total 24 + 56 = 80 B, rounds to 128 B.
    let ep_obj_ptr = block_virt as *mut EndpointObject;
    let state_offset = core::mem::size_of::<EndpointObject>() as u64;
    let ep_state_ptr = (block_virt + state_offset) as *mut EndpointState;

    let ancestor = frame_obj_nn;

    // SAFETY: ep_state_ptr / ep_obj_ptr point into the just-allocated region;
    // alignment: the region is page-aligned (frame.base is page-aligned, and
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
    // SAFETY: ancestor is the FrameObject's header (offset 0 of FrameObject);
    // dereferencing through the header is safe.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: ep_obj_ptr is a freshly-constructed EndpointObject; header at
    // offset 0 makes the cast safe.
    let nonnull = unsafe { NonNull::new_unchecked(ep_obj_ptr.cast::<KernelObjectHeader>()) };

    // Insert into the caller's CSpace under the cspace lock so the freelist
    // and tag invariant cannot tear against a concurrent mutator on another
    // CPU (parent inserting caps via SYS_CAP_INSERT, sibling thread also
    // creating caps, etc.).
    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap(
            CapTag::Endpoint,
            Rights::SEND | Rights::RECEIVE | Rights::GRANT,
            nonnull,
        );
        (*cspace).lock.unlock_raw(saved);
        r
    };

    if let Ok(idx) = idx_res
    {
        Ok(u64::from(idx.get()))
    }
    else
    {
        // CSpace is full; roll back the allocation. Drop in place, return
        // the bytes, drop the lease.
        // SAFETY: we just constructed both objects in place above; nothing
        // else has observed them yet.
        unsafe {
            core::ptr::drop_in_place(ep_obj_ptr);
            core::ptr::drop_in_place(ep_state_ptr);
        }
        retype_free(frame, offset, entry.raw_bytes);
        // SAFETY: matches the inc_ref above.
        unsafe { ancestor.as_ref().dec_ref() };
        Err(SyscallError::OutOfMemory)
    }
}

/// `SYS_CAP_CREATE_SIGNAL` (8): retype a Frame cap into a new Signal.
///
/// arg0 = Frame-cap slot index in the caller's `CSpace`. The Frame cap MUST
/// carry `Rights::RETYPE` and have at least `dispatch_for(Signal, 0).raw_bytes`
/// of `available_bytes`.
///
/// On success, the wrapper + `SignalState` are constructed in place inside
/// the source Frame cap's region; a cap with `SIGNAL | WAIT` rights is
/// inserted into the caller's `CSpace`; returns the slot index.
///
/// Auto-reclaim (`dec_ref → 0`) consults `header.ancestor` and credits bytes
/// back to the source Frame cap.
#[cfg(not(test))]
pub fn sys_cap_create_signal(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{FrameObject, KernelObjectHeader, ObjectType, SignalObject};
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::signal::SignalState;
    use core::ptr::NonNull;

    let frame_slot = tf.arg(0) as u32;

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
    let frame_slot_ref =
        unsafe { super::lookup_cap(cspace, frame_slot, CapTag::Frame, Rights::RETYPE)? };
    let frame_obj_nn = frame_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Frame slot.
    let frame = unsafe { &*frame_obj_nn.as_ptr().cast::<FrameObject>() };

    let entry = dispatch_for(ObjectType::Signal, 0).ok_or(SyscallError::InvalidArgument)?;

    let offset = retype_allocate(frame, entry.raw_bytes)?;

    let block_phys = frame.base + offset;
    let block_virt = crate::mm::paging::phys_to_virt(block_phys);

    // Layout: SignalObject at offset 0; SignalState at offset
    // size_of::<SignalObject>() (24).
    let sig_obj_ptr = block_virt as *mut SignalObject;
    let state_offset = core::mem::size_of::<SignalObject>() as u64;
    let sig_state_ptr = (block_virt + state_offset) as *mut SignalState;

    let ancestor = frame_obj_nn;

    // SAFETY: pointers are inside the freshly-allocated retype slot;
    // size-class alignment (BIN_128 = 128 B granular) exceeds the 8-byte
    // alignment requirement of both structs.
    unsafe {
        core::ptr::write(sig_state_ptr, SignalState::new());
        core::ptr::write(
            sig_obj_ptr,
            SignalObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::Signal, ancestor),
                state: sig_state_ptr,
            },
        );
    }

    // SAFETY: ancestor is the FrameObject's header at offset 0.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: header at offset 0 of SignalObject.
    let nonnull = unsafe { NonNull::new_unchecked(sig_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap(CapTag::Signal, Rights::SIGNAL | Rights::WAIT, nonnull);
        (*cspace).lock.unlock_raw(saved);
        r
    };

    if let Ok(idx) = idx_res
    {
        Ok(u64::from(idx.get()))
    }
    else
    {
        // CSpace full: roll back the in-place construction.
        // SAFETY: nothing else has observed these constructed objects.
        unsafe {
            core::ptr::drop_in_place(sig_obj_ptr);
            core::ptr::drop_in_place(sig_state_ptr);
        }
        retype_free(frame, offset, entry.raw_bytes);
        // SAFETY: matches the inc_ref above.
        unsafe { ancestor.as_ref().dec_ref() };
        Err(SyscallError::OutOfMemory)
    }
}

/// `SYS_CAP_CREATE_ASPACE` (11): create a new `AddressSpace` object, or
/// augment an existing one's PT growth budget.
///
/// arg0 = source Frame-cap slot (must carry `Rights::RETYPE`, with at least
///        `init_pages * PAGE_SIZE` available bytes).
/// arg1 = augment-target `AddressSpace` cap slot, or `0` to create new.
/// arg2 = `init_pages`: number of PT pages to carve from the Frame cap.
///        Create-mode requires `init_pages >= 2` (one wrapper page + one
///        root PT page; the remainder seed the PT growth pool).
///        Augment-mode accepts `init_pages >= 1`.
///
/// Create-mode slab layout:
/// - page 0 — wrapper page: [`AddressSpaceObject`] at offset 0, immediately
///   followed by the wrapped [`AddressSpace`]. Both are constructed in place
///   via `core::ptr::write`; the wrapper's `address_space` pointer indexes
///   into this same page.
/// - page 1 — root page table (PML4 / Sv48 root), zeroed, kernel-half PT
///   entries copied from the active root.
/// - pages `2..init_pages` — PT growth pool. Drawn on demand by
///   [`AddressSpace::map_page`](crate::mm::address_space::AddressSpace::map_page)
///   for intermediate PT levels.
///
/// Inserts a cap with `MAP | READ` rights into the caller's `CSpace`.
/// Returns the new slot index.
///
/// Augment-mode: pushes all carved pages onto the target AS's PT growth pool
/// and increases its `pt_growth_budget_bytes`. Returns `0` on success.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub fn sys_cap_create_aspace(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{
        AddressSpaceObject, FrameObject, KernelObjectHeader, ObjectType, vacant_chunk_slots,
    };
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{CapTag, Rights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::address_space::AddressSpace;
    use crate::mm::paging::phys_to_virt;
    use core::ptr::NonNull;
    use core::sync::atomic::AtomicU64;

    let frame_idx = tf.arg(0) as u32;
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

    // Resolve the source Frame cap (RETYPE-rights gated).
    // SAFETY: cspace validated non-null above.
    let frame_slot_ref =
        unsafe { super::lookup_cap(cspace, frame_idx, CapTag::Frame, Rights::RETYPE)? };
    let frame_obj_nn = frame_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Frame slot.
    let frame = unsafe { &*frame_obj_nn.as_ptr().cast::<FrameObject>() };

    // Validate dispatch math against the user-provided init_pages.
    let entry =
        dispatch_for(ObjectType::AddressSpace, init_pages).ok_or(SyscallError::InvalidArgument)?;
    debug_assert!(entry.split);
    debug_assert_eq!(entry.raw_bytes, init_bytes);

    // Reserve the contiguous slab from the Frame cap. The slab will be split
    // page-by-page onto the target AS's pool.
    let offset = retype_allocate(frame, entry.raw_bytes)?;
    let frame_base = frame.base;

    // Augment-mode: push all carved pages onto the target AS's pool.
    if augment_idx != 0
    {
        // SAFETY: cspace validated non-null above.
        let target_slot =
            unsafe { super::lookup_cap(cspace, augment_idx, CapTag::AddressSpace, Rights::MAP) }?;
        let target_aso_nn = target_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed AddressSpace.
        #[allow(clippy::cast_ptr_alignment)]
        let target_aso = unsafe { &*target_aso_nn.as_ptr().cast::<AddressSpaceObject>() };

        // SAFETY: ref is held until AS-dealloc (released per chunk slot).
        unsafe { frame_obj_nn.as_ref().inc_ref() };

        // SAFETY: target_aso wraps a live AS; offset/init_pages are from a
        // successful retype against `frame`.
        let res = unsafe {
            target_aso.add_chunk(frame_obj_nn, frame_base, offset, init_pages, init_pages)
        };
        if res.is_err()
        {
            retype_free(frame, offset, entry.raw_bytes);
            // SAFETY: matches the inc_ref above.
            unsafe { frame_obj_nn.as_ref().dec_ref() };
            return Err(SyscallError::OutOfMemory);
        }
        return Ok(0);
    }

    // Create-mode: slab layout is [wrapper page, root PT, pool pages...].
    // Requires `init_pages >= 2`.
    if init_pages < 2
    {
        retype_free(frame, offset, entry.raw_bytes);
        return Err(SyscallError::InvalidArgument);
    }

    let wrapper_phys = frame_base + offset;
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
                header: KernelObjectHeader::with_ancestor(ObjectType::AddressSpace, frame_obj_nn),
                address_space: aspace_ptr,
                pt_growth_budget_bytes: AtomicU64::new(0),
                pt_pool_lock: AtomicU64::new(0),
                pt_pool_head_phys: AtomicU64::new(0),
                pt_chunks: vacant_chunk_slots(),
            },
        );
    }

    // Hold a reference on the source Frame cap for the AS's lifetime; the
    // matching dec_ref happens in `dealloc_object(AddressSpace)` after the
    // chunk is reclaimed.
    // SAFETY: frame_obj_nn is a live FrameObject.
    unsafe { frame_obj_nn.as_ref().inc_ref() };

    // Record the chunk covering all `init_pages`; the lower 2 pages
    // (wrapper + root PT) are reserved, the remainder seeds the pool.
    let pool_pages = init_pages - 2;
    // SAFETY: aso just constructed; offset/init_pages from a successful
    // retype against `frame`.
    let res =
        unsafe { (*aso_ptr).add_chunk(frame_obj_nn, frame_base, offset, init_pages, pool_pages) };
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
        retype_free(frame, offset, entry.raw_bytes);
        // SAFETY: matches inc_ref above.
        unsafe { frame_obj_nn.as_ref().dec_ref() };
        return Err(SyscallError::OutOfMemory);
    }

    // SAFETY: aso_ptr is in-place at offset 0; header at offset 0 of ASObject.
    let nonnull = unsafe { NonNull::new_unchecked(aso_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap(CapTag::AddressSpace, Rights::MAP | Rights::READ, nonnull);
        (*cspace).lock.unlock_raw(saved);
        r
    }
    .map_err(|_| SyscallError::OutOfMemory)?;

    Ok(u64::from(idx.get()))
}

/// `SYS_CAP_CREATE_CSPACE` (12): retype a Frame cap into a new `CSpace`,
/// or augment an existing one's slot-page growth budget.
///
/// arg0 = source Frame-cap slot (must carry `Rights::RETYPE`).
/// arg1 = augment-target `CSpace` cap slot, or `0` to create new.
/// arg2 = `init_pages`: number of pages to carve from the Frame cap.
///        Create-mode requires `init_pages >= 1` (one wrapper page; the
///        remainder seed the slot-page pool — `init_pages == 1` yields an
///        empty pool that requires immediate augment-mode refill before any
///        cap can be inserted). Augment-mode accepts `init_pages >= 1`.
/// arg3 = `max_slots` (create-mode only): hard cap on usable slots
///        (clamped to `[1, 16384]`). Ignored in augment mode.
///
/// Create-mode slab layout:
/// - page 0 — wrapper page: [`CSpaceKernelObject`] at offset 0, immediately
///   followed by the wrapped [`CSpace`] directory. The wrapper's `cspace`
///   pointer indexes into this same page.
/// - pages `1..init_pages` — slot-page pool, drawn on demand by
///   [`CSpace::grow`](crate::cap::cspace::CSpace::grow) when the directory
///   needs another 64-slot leaf.
///
/// Create-mode returns the new `CSpace` slot index. Augment-mode returns 0.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub fn sys_cap_create_cspace(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::alloc_cspace_id;
    use crate::cap::cspace::CSpace;
    use crate::cap::object::{
        CSpaceKernelObject, FrameObject, KernelObjectHeader, ObjectType, vacant_chunk_slots,
    };
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{CapTag, Rights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;
    use core::ptr::NonNull;
    use core::sync::atomic::AtomicU64;

    const MAX_SLOTS: usize = 16384;

    let frame_idx = tf.arg(0) as u32;
    let augment_idx = tf.arg(1) as u32;
    let init_pages = tf.arg(2);
    let requested_max_slots = tf.arg(3);

    if init_pages == 0
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

    // Resolve the source Frame cap.
    // SAFETY: cspace validated non-null above.
    let frame_slot_ref =
        unsafe { super::lookup_cap(cspace, frame_idx, CapTag::Frame, Rights::RETYPE)? };
    let frame_obj_nn = frame_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Frame slot.
    let frame = unsafe { &*frame_obj_nn.as_ptr().cast::<FrameObject>() };

    let entry =
        dispatch_for(ObjectType::CSpaceObj, init_pages).ok_or(SyscallError::InvalidArgument)?;
    debug_assert!(entry.split);
    debug_assert_eq!(entry.raw_bytes, init_bytes);

    let offset = retype_allocate(frame, entry.raw_bytes)?;
    let frame_base = frame.base;

    // Augment-mode.
    if augment_idx != 0
    {
        // SAFETY: cspace validated non-null above.
        let target_slot =
            unsafe { super::lookup_cap(cspace, augment_idx, CapTag::CSpace, Rights::INSERT) }?;
        let target_kobj_nn = target_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed CSpace.
        #[allow(clippy::cast_ptr_alignment)]
        let target_kobj = unsafe { &*target_kobj_nn.as_ptr().cast::<CSpaceKernelObject>() };

        // SAFETY: ref kept until CS-dealloc.
        unsafe { frame_obj_nn.as_ref().inc_ref() };

        // SAFETY: target_kobj is live.
        let res = unsafe {
            target_kobj.add_chunk(frame_obj_nn, frame_base, offset, init_pages, init_pages)
        };
        if res.is_err()
        {
            retype_free(frame, offset, entry.raw_bytes);
            // SAFETY: matches inc_ref above.
            unsafe { frame_obj_nn.as_ref().dec_ref() };
            return Err(SyscallError::OutOfMemory);
        }
        return Ok(0);
    }

    // Create-mode: slab layout is [wrapper page, slot pool pages...].
    // Page 0 holds CSpaceKernelObject at offset 0 followed by CSpace at
    // offset size_of::<CSpaceKernelObject>(). Pages 1..init_pages seed the
    // slot-page pool; CSpace::grow pops one when the directory needs a leaf.
    let max_slots = if requested_max_slots == 0
    {
        MAX_SLOTS
    }
    else
    {
        (requested_max_slots as usize).clamp(1, MAX_SLOTS)
    };

    let wrapper_phys = frame_base + offset;
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

    let id = alloc_cspace_id();

    // Construct CSpace in place.
    // SAFETY: cs_ptr lives inside the wrapper page, exclusively owned.
    unsafe { core::ptr::write(cs_ptr, CSpace::new(id, max_slots)) };

    // Construct the wrapper in place; the back-pointer indexes into the
    // same page.
    // SAFETY: cs_kobj_ptr is page-aligned and exclusively owned.
    unsafe {
        core::ptr::write(
            cs_kobj_ptr,
            CSpaceKernelObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::CSpaceObj, frame_obj_nn),
                cspace: cs_ptr,
                cspace_growth_budget_bytes: AtomicU64::new(0),
                cs_pool_lock: AtomicU64::new(0),
                cs_pool_head_phys: AtomicU64::new(0),
                cs_chunks: vacant_chunk_slots(),
            },
        );
    }

    // Wire the back-pointer so the first CSpace::grow uses the pool.
    // SAFETY: cs_ptr just constructed.
    unsafe { (*cs_ptr).set_kobj(cs_kobj_ptr) };

    // Register in the global registry so derivation lookups resolve.
    crate::cap::register_cspace(id, cs_ptr);

    // Hold a reference on the source Frame cap.
    // SAFETY: frame_obj_nn is live.
    unsafe { frame_obj_nn.as_ref().inc_ref() };

    // Record the chunk covering all init_pages; reserve page 0 (wrapper),
    // pool seeds pages 1..init_pages.
    let pool_pages = init_pages - 1;
    // SAFETY: wrapper just constructed; offset/init_pages from a successful
    // retype against `frame`.
    let res = unsafe {
        (*cs_kobj_ptr).add_chunk(frame_obj_nn, frame_base, offset, init_pages, pool_pages)
    };
    if res.is_err()
    {
        // SAFETY: wrapper/cs not observed externally yet.
        unsafe {
            core::ptr::drop_in_place(cs_kobj_ptr);
            core::ptr::drop_in_place(cs_ptr);
        }
        crate::cap::unregister_cspace(id);
        retype_free(frame, offset, entry.raw_bytes);
        // SAFETY: matches inc_ref above.
        unsafe { frame_obj_nn.as_ref().dec_ref() };
        return Err(SyscallError::OutOfMemory);
    }

    // SAFETY: cs_kobj_ptr is in-place at offset 0; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(cs_kobj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap(
            CapTag::CSpace,
            Rights::INSERT | Rights::DELETE | Rights::DERIVE,
            nonnull,
        );
        (*cspace).lock.unlock_raw(saved);
        r
    }
    .map_err(|_| SyscallError::OutOfMemory)?;

    Ok(u64::from(idx.get()))
}

/// `SYS_CAP_CREATE_THREAD` (10): create a new Thread object.
///
/// arg0 = `AddressSpace` cap index (must have MAP).
/// arg1 = `CSpace` cap index (must have INSERT).
///
/// Allocates a kernel stack and a TCB in `Created` state, bound to the
/// provided address space and `CSpace`. Inserts a cap with `CONTROL | OBSERVE`
/// rights into the caller's `CSpace`. Returns the Thread cap slot index.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub fn sys_cap_create_thread(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTF;
    use crate::cap::object::{FrameObject, KernelObjectHeader, ObjectType, ThreadObject};
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::message::Message;
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;
    use crate::sched::alloc_thread_id;
    use crate::sched::thread::{IpcThreadState, ThreadControlBlock, ThreadState};
    use crate::sched::{AFFINITY_ANY, INIT_PRIORITY, KERNEL_STACK_PAGES, TIME_SLICE_TICKS};
    use core::ptr::NonNull;

    // TRAMPOLINE_FRAME_SIZE: reserved gap between trampoline's starting RSP and the
    // TrapFrame base. 512 bytes is sufficient for the minimal C frame.
    const TRAMPOLINE_FRAME_SIZE: u64 = 512;

    #[allow(clippy::cast_possible_truncation)]
    // cast_possible_truncation: Seraph targets 64-bit only; cap slot indices fit in u32.
    let frame_idx = tf.arg(0) as u32;
    #[allow(clippy::cast_possible_truncation)]
    // cast_possible_truncation: Seraph targets 64-bit only; cap slot indices fit in u32.
    let as_idx = tf.arg(1) as u32;
    #[allow(clippy::cast_possible_truncation)]
    // cast_possible_truncation: Seraph targets 64-bit only; cap slot indices fit in u32.
    let cs_idx = tf.arg(2) as u32;

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

    // Resolve the source Frame cap; consumes 5 retype-pages (4 kstack +
    // 1 wrapper/TCB).
    // SAFETY: caller_cspace validated non-null above.
    let frame_slot_ref =
        unsafe { super::lookup_cap(caller_cspace, frame_idx, CapTag::Frame, Rights::RETYPE)? };
    let frame_obj_nn = frame_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Frame slot.
    let frame = unsafe { &*frame_obj_nn.as_ptr().cast::<FrameObject>() };

    // Resolve AddressSpace cap.
    // SAFETY: caller_cspace validated non-null above.
    let as_slot =
        unsafe { super::lookup_cap(caller_cspace, as_idx, CapTag::AddressSpace, Rights::MAP) }?;
    let as_ptr = {
        use crate::cap::object::AddressSpaceObject;
        let obj = as_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: cap tag confirmed AddressSpace; object pointer is valid.
        #[allow(clippy::cast_ptr_alignment)]
        let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
        as_obj.address_space
    };

    // Resolve CSpace cap.
    // SAFETY: caller_cspace validated non-null above.
    let cs_slot =
        unsafe { super::lookup_cap(caller_cspace, cs_idx, CapTag::CSpace, Rights::INSERT) }?;
    let new_cs_ptr = {
        use crate::cap::object::CSpaceKernelObject;
        let obj = cs_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: cap tag confirmed CSpace; object pointer is valid.
        #[allow(clippy::cast_ptr_alignment)]
        let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
        cs_obj.cspace
    };

    // Reserve the 5-page slot from the source Frame cap. Layout (a):
    //   pages 0..4 (16 KiB) — kstack
    //   page 4              — ThreadObject (24 B) followed by TCB
    let entry = dispatch_for(ObjectType::Thread, 0).ok_or(SyscallError::InvalidArgument)?;
    debug_assert_eq!(
        entry.raw_bytes,
        (KERNEL_STACK_PAGES as u64 + 1) * PAGE_SIZE as u64
    );
    let offset = retype_allocate(frame, entry.raw_bytes)?;
    let block_phys = frame.base + offset;
    let block_virt = phys_to_virt(block_phys);

    let kstack_virt = block_virt;
    let kstack_top = block_virt + (KERNEL_STACK_PAGES * PAGE_SIZE) as u64;
    let thread_obj_ptr = kstack_top as *mut ThreadObject;
    let tcb_offset = core::mem::size_of::<ThreadObject>() as u64;
    let tcb_ptr = (kstack_top + tcb_offset) as *mut ThreadControlBlock;

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

    let ancestor = frame_obj_nn;

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
                priority: INIT_PRIORITY,
                slice_remaining: TIME_SLICE_TICKS,
                cpu_affinity: AFFINITY_ANY,
                preferred_cpu: 0,
                run_queue_next: None,
                ipc_state: IpcThreadState::None,
                ipc_msg: Message::default(),
                reply_tcb: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                ipc_wait_next: None,
                is_user: true,
                saved_state: saved,
                kernel_stack_top: kstack_top,
                trap_frame: core::ptr::null_mut(),
                address_space: as_ptr,
                cspace: new_cs_ptr,
                ipc_buffer: 0,
                wakeup_value: 0,
                timed_out: false,
                iopb: core::ptr::null_mut(),
                blocked_on_object: core::ptr::null_mut(),
                thread_id: alloc_thread_id(),
                context_saved: core::sync::atomic::AtomicU32::new(1),
                death_observers: [crate::sched::thread::DeathObserver::empty();
                    crate::sched::thread::MAX_DEATH_OBSERVERS],
                death_observer_count: 0,
                exit_reason: 0,
                sleep_deadline: 0,
                magic: crate::sched::thread::TCB_MAGIC,
            },
        );
        core::ptr::write(
            thread_obj_ptr,
            ThreadObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::Thread, ancestor),
                tcb: tcb_ptr,
            },
        );
    }

    // SAFETY: ancestor is the FrameObject's header at offset 0; this lease
    // bump is undone on rollback below or when the Thread cap is dealloc'd.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: thread_obj_ptr is in-place; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(thread_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: caller_cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r =
            (*caller_cspace).insert_cap(CapTag::Thread, Rights::CONTROL | Rights::OBSERVE, nonnull);
        (*caller_cspace).lock.unlock_raw(saved);
        r
    };

    if let Ok(idx) = idx_res
    {
        let _ = kstack_virt;
        Ok(u64::from(idx.get()))
    }
    else
    {
        // The cap never reached visibility, so no scheduler queue can hold
        // this TCB and no IPC object has a back-pointer to it. Drop both
        // in-place objects, return the slot bytes (all 5 pages) to the
        // ancestor cap, and undo the lease bump.
        // SAFETY: tcb and wrapper were just constructed in place above and
        // have not been observed by any other thread.
        unsafe {
            core::ptr::drop_in_place(tcb_ptr);
            core::ptr::drop_in_place(thread_obj_ptr);
        }
        retype_free(frame, offset, entry.raw_bytes);
        // SAFETY: matches the inc_ref above.
        unsafe { ancestor.as_ref().dec_ref() };
        Err(SyscallError::OutOfMemory)
    }
}

/// `SYS_CAP_COPY` (24): copy a capability into another `CSpace.`
///
/// arg0 = source slot index (in caller's `CSpace`).
/// arg1 = destination `CSpace` cap index (in caller's `CSpace`; must have INSERT).
/// arg2 = rights mask for the new slot (must be a subset of source rights).
///
/// Allocates a new slot in the destination `CSpace`, populates it with the same
/// kernel object and the requested (attenuated) rights, increments the object's
/// reference count, and wires the new slot as a child of the source in the
/// derivation tree.
///
/// Returns the destination slot index.
#[cfg(not(test))]
pub fn sys_cap_copy(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::Rights;

    let src_idx = tf.arg(0) as u32;
    let dest_cs_idx = tf.arg(1) as u32;
    let rights_mask = Rights(tf.arg(2) as u32);

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

    // Resolve source slot (any non-null tag, any rights — just non-null).
    let (src_tag, src_rights, src_object, src_token) = {
        // SAFETY: caller_cspace validated non-null above.
        let cs = unsafe { &*caller_cspace };
        let slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == crate::cap::slot::CapTag::Null
        {
            return Err(SyscallError::InvalidCapability);
        }
        (
            slot.tag,
            slot.rights,
            slot.object.ok_or(SyscallError::InvalidCapability)?,
            slot.token,
        )
    };

    // Convert src_idx to NonZeroU32 before any state mutation. The non-null
    // tag check above excludes slot 0 (which is permanently Null), so this
    // only fires on a malformed request.
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;

    // Compute the effective rights for the copy: intersection of the requested
    // mask and what the source actually grants. Bits not in the source are
    // silently dropped — callers cannot escalate.
    let effective_rights = rights_mask & src_rights;

    // Resolve destination CSpace cap.
    // SAFETY: caller_cspace validated non-null above.
    let dest_cs_slot = unsafe {
        super::lookup_cap(
            caller_cspace,
            dest_cs_idx,
            crate::cap::slot::CapTag::CSpace,
            Rights::INSERT,
        )
    }?;
    let dest_cs_ptr = {
        use crate::cap::object::CSpaceKernelObject;
        let obj = dest_cs_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header is at offset 0 of CSpaceKernelObject; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: cap tag confirmed CSpace; object pointer is valid.
        let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
        cs_obj.cspace
    };
    // SAFETY: dest_cs_ptr extracted from validated CSpace object above.
    let dest_cs_id = unsafe { (*dest_cs_ptr).id() };

    // Increment reference count on the shared kernel object.
    // SAFETY: src_object is a valid NonNull from a live capability slot.
    unsafe {
        (*src_object.as_ptr()).inc_ref();
    }

    // Insert into destination CSpace with the effective (attenuated) rights,
    // and copy the token if any, all under cspace.lock so the freelist/tag
    // invariant cannot tear against a concurrent SYS_CAP_CREATE_*.
    // SAFETY: dest_cs_ptr validated above; lock_raw/unlock_raw paired.
    let insert_res = unsafe {
        let saved = (*dest_cs_ptr).lock.lock_raw();
        let r = (*dest_cs_ptr).insert_cap(src_tag, effective_rights, src_object);
        if let Ok(idx) = r
            && src_token != 0
            && let Some(new_slot) = (*dest_cs_ptr).slot_mut(idx.get())
        {
            new_slot.token = src_token;
        }
        (*dest_cs_ptr).lock.unlock_raw(saved);
        r
    };
    let new_idx_nz = insert_res.map_err(|e| {
        // Roll back the inc_ref if insertion fails.
        // SAFETY: src_object validated above; we just incremented refcount.
        unsafe {
            (*src_object.as_ptr()).dec_ref();
        }
        match e
        {
            crate::cap::cspace::CapError::WxViolation => SyscallError::WxViolation,
            _ => SyscallError::OutOfMemory,
        }
    })?;
    let new_idx = new_idx_nz.get();

    // Wire derivation tree: new slot is a child of the source slot.
    let parent = crate::cap::slot::SlotId::new(caller_cspace_id, src_idx_nz);
    let child = crate::cap::slot::SlotId::new(dest_cs_id, new_idx_nz);
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: DERIVATION_LOCK held; parent/child are valid SlotIds just created.
    unsafe {
        crate::cap::derivation::link_child(parent, child);
    }
    crate::cap::DERIVATION_LOCK.write_unlock();

    Ok(u64::from(new_idx))
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

    let src_idx = tf.arg(0) as u32;
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
    let (src_tag, src_rights, src_object, src_token) = {
        // SAFETY: caller_cspace validated non-null above.
        let cs = unsafe { &*caller_cspace };
        let slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == crate::cap::slot::CapTag::Null
        {
            return Err(SyscallError::InvalidCapability);
        }
        (
            slot.tag,
            slot.rights,
            slot.object.ok_or(SyscallError::InvalidCapability)?,
            slot.token,
        )
    };

    let effective_rights = rights_mask & src_rights;

    // Increment refcount, then insert into caller's CSpace.
    // SAFETY: src_object validated above as valid NonNull from live slot.
    unsafe {
        (*src_object.as_ptr()).inc_ref();
    }

    // Insert under cspace.lock so the freelist/tag invariant cannot tear
    // against a concurrent SYS_CAP_CREATE_*. Token write happens in the same
    // critical section so the new slot's fields are atomic w.r.t. other
    // observers.
    // SAFETY: caller_cspace validated non-null above; lock_raw/unlock_raw paired.
    let insert_res = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace).insert_cap(src_tag, effective_rights, src_object);
        if let Ok(idx) = r
            && src_token != 0
            && let Some(new_slot) = (*caller_cspace).slot_mut(idx.get())
        {
            new_slot.token = src_token;
        }
        (*caller_cspace).lock.unlock_raw(saved);
        r
    };
    let new_idx_nz = insert_res.map_err(|e| {
        // SAFETY: src_object validated above; we just incremented refcount.
        unsafe {
            (*src_object.as_ptr()).dec_ref();
        }
        match e
        {
            crate::cap::cspace::CapError::WxViolation => SyscallError::WxViolation,
            _ => SyscallError::OutOfMemory,
        }
    })?;
    let new_idx = new_idx_nz.get();

    // Wire derivation link.
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;
    let parent = crate::cap::slot::SlotId::new(cspace_id, src_idx_nz);
    let child = crate::cap::slot::SlotId::new(cspace_id, new_idx_nz);
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: DERIVATION_LOCK held; parent/child are valid SlotIds.
    unsafe {
        crate::cap::derivation::link_child(parent, child);
    }
    crate::cap::DERIVATION_LOCK.write_unlock();

    Ok(u64::from(new_idx))
}

/// `SYS_CAP_DERIVE_TOKEN` (48): derive a capability with a token attached.
///
/// arg0 = source slot index (caller's `CSpace`).
/// arg1 = rights mask (must be a subset of source rights).
/// arg2 = token value (must be non-zero; source must have token == 0).
///
/// Creates a new slot with the attenuated rights and the specified token.
/// The token is immutable once set — deriving from a tokened cap inherits
/// the token (via `SYS_CAP_DERIVE`), but setting a new token on an already-
/// tokened cap returns `InvalidArgument`.
///
/// Returns the new slot index.
#[cfg(not(test))]
pub fn sys_cap_derive_token(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::Rights;

    let src_idx = tf.arg(0) as u32;
    let rights_mask = Rights(tf.arg(1) as u32);
    let token_value = tf.arg(2);

    if token_value == 0
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
    let (src_tag, src_rights, src_object, src_token) = {
        // SAFETY: caller_cspace validated non-null above.
        let cs = unsafe { &*caller_cspace };
        let slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == crate::cap::slot::CapTag::Null
        {
            return Err(SyscallError::InvalidCapability);
        }
        (
            slot.tag,
            slot.rights,
            slot.object.ok_or(SyscallError::InvalidCapability)?,
            slot.token,
        )
    };

    // Cannot re-token a capability that already has a token.
    if src_token != 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    let effective_rights = rights_mask & src_rights;

    // Increment refcount, then insert into caller's CSpace.
    // SAFETY: src_object validated above as valid NonNull from live slot.
    unsafe {
        (*src_object.as_ptr()).inc_ref();
    }

    // Insert under cspace.lock so the freelist/tag invariant cannot tear
    // against a concurrent SYS_CAP_CREATE_*. Token write happens in the same
    // critical section.
    // SAFETY: caller_cspace validated non-null above; lock_raw/unlock_raw paired.
    let insert_res = unsafe {
        let saved = (*caller_cspace).lock.lock_raw();
        let r = (*caller_cspace).insert_cap(src_tag, effective_rights, src_object);
        if let Ok(idx) = r
            && let Some(new_slot) = (*caller_cspace).slot_mut(idx.get())
        {
            new_slot.token = token_value;
        }
        (*caller_cspace).lock.unlock_raw(saved);
        r
    };
    let new_idx_nz = insert_res.map_err(|e| {
        // SAFETY: src_object validated above; we just incremented refcount.
        unsafe {
            (*src_object.as_ptr()).dec_ref();
        }
        match e
        {
            crate::cap::cspace::CapError::WxViolation => SyscallError::WxViolation,
            _ => SyscallError::OutOfMemory,
        }
    })?;
    let new_idx = new_idx_nz.get();

    // Wire derivation link.
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;
    let parent = crate::cap::slot::SlotId::new(cspace_id, src_idx_nz);
    let child = crate::cap::slot::SlotId::new(cspace_id, new_idx_nz);
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: DERIVATION_LOCK held; parent/child are valid SlotIds.
    unsafe {
        crate::cap::derivation::link_child(parent, child);
    }
    crate::cap::DERIVATION_LOCK.write_unlock();

    Ok(u64::from(new_idx))
}

/// `SYS_CAP_DELETE` (31): delete a capability slot.
///
/// arg0 = slot index in the caller's `CSpace.`
///
/// Reparents any children to the deleted slot's parent (preserving revocability
/// from the grandparent), unlinks the slot from the derivation tree, clears it,
/// and `dec_refs` the kernel object. If refcount reaches 0, frees the object.
///
/// Idempotent: deleting a Null slot returns success.
#[cfg(not(test))]
pub fn sys_cap_delete(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    let slot_idx = tf.arg(0) as u32;

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
    let node = crate::cap::slot::SlotId::new(cspace_id, slot_idx_nz);

    // Resolve the slot, unlink, and clear under DERIVATION_LOCK so a concurrent
    // revoke_subtree on a parent cap cannot race-clear this slot between the
    // tag-check and the dec_ref. Both paths must dec_ref the object exactly
    // once between them.
    crate::cap::DERIVATION_LOCK.write_lock();

    // SAFETY: caller_cspace validated non-null above; DERIVATION_LOCK held.
    let (obj_ptr, parent) = match unsafe { (*caller_cspace).slot(slot_idx) }
    {
        Some(slot) if slot.tag != crate::cap::slot::CapTag::Null =>
        {
            let Some(obj) = slot.object
            else
            {
                crate::cap::DERIVATION_LOCK.write_unlock();
                return Err(SyscallError::InvalidCapability);
            };
            (obj, slot.deriv_parent)
        }
        Some(_) =>
        {
            // Slot was Null on entry, or was cleared by a concurrent
            // revoke_subtree before we acquired the lock. Idempotent.
            crate::cap::DERIVATION_LOCK.write_unlock();
            return Ok(0);
        }
        None =>
        {
            crate::cap::DERIVATION_LOCK.write_unlock();
            return Err(SyscallError::InvalidCapability);
        }
    };

    // SAFETY: DERIVATION_LOCK held; node and parent are valid SlotIds.
    unsafe {
        crate::cap::derivation::reparent_children(node, parent);
        crate::cap::derivation::unlink_node(node);
    }

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
#[cfg(not(test))]
pub fn sys_cap_revoke(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    let slot_idx = tf.arg(0) as u32;

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

    // Validate slot is non-null.
    {
        // SAFETY: caller_cspace validated non-null above.
        let cs = unsafe { &*caller_cspace };
        let slot = cs.slot(slot_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == crate::cap::slot::CapTag::Null
        {
            return Err(SyscallError::InvalidCapability);
        }
    }

    let slot_idx_nz =
        core::num::NonZeroU32::new(slot_idx).ok_or(SyscallError::InvalidCapability)?;
    let root = crate::cap::slot::SlotId::new(cspace_id, slot_idx_nz);

    // Revoke the subtree under the lock; snapshot the dealloc list to a
    // stack-local array so we can release the lock before calling
    // `dealloc_object` (which may acquire the frame allocator and other
    // inner locks — see the safety doc on `dealloc_object`).
    let mut snapshot: [Option<core::ptr::NonNull<crate::cap::object::KernelObjectHeader>>;
        crate::cap::derivation::MAX_REVOKE_NODES] =
        [None; crate::cap::derivation::MAX_REVOKE_NODES];
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: DERIVATION_LOCK held; root is valid SlotId.
    let objects = unsafe { crate::cap::derivation::revoke_subtree(root) };
    let snapshot_count = objects.len();
    debug_assert!(snapshot_count <= crate::cap::derivation::MAX_REVOKE_NODES);
    snapshot[..snapshot_count].copy_from_slice(objects);
    crate::cap::DERIVATION_LOCK.write_unlock();

    // Dec-ref and free objects outside the lock.
    for entry in &snapshot[..snapshot_count]
    {
        let Some(obj_ptr) = *entry
        else
        {
            continue;
        };
        // SAFETY: obj_ptr from revoke_subtree; was a live capability object.
        let remaining = unsafe { (*obj_ptr.as_ptr()).dec_ref() };
        if remaining == 0
        {
            // SAFETY: refcount reached 0; no other references exist.
            unsafe {
                crate::cap::object::dealloc_object(obj_ptr);
            }
        }
    }

    Ok(0)
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
    use crate::cap::slot::{Rights, SlotId};

    let src_idx = tf.arg(0) as u32;
    let dest_cs_idx = tf.arg(1) as u32;
    let dest_idx = tf.arg(2) as u32; // 0 = auto-allocate

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
            crate::cap::slot::CapTag::CSpace,
            Rights::INSERT,
        )
    }?;
    let dest_cs_ptr = {
        let obj = dest_cs_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header is at offset 0 of CSpaceKernelObject; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: cap tag confirmed CSpace; object pointer is valid.
        let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
        cs_obj.cspace
    };

    if dest_idx == 0
    {
        // Auto-allocate: delegate to the shared helper. Hold both cspace
        // locks (in pointer address order to prevent ABBA deadlock) so the
        // freelist mutations inside `move_cap_between_cspaces` cannot tear
        // against a concurrent SYS_CAP_CREATE_*. Lock order:
        // DERIVATION_LOCK → cspace.lock(s) (matches transfer_caps).
        crate::cap::DERIVATION_LOCK.write_lock();
        // SAFETY: both CSpace pointers valid; address-ordered acquisition.
        let (saved1, saved2) = unsafe {
            use core::cmp::Ordering;
            match caller_cspace.cmp(&dest_cs_ptr)
            {
                Ordering::Less =>
                {
                    let s1 = (*caller_cspace).lock.lock_raw();
                    let s2 = (*dest_cs_ptr).lock.lock_raw();
                    (s1, s2)
                }
                Ordering::Greater =>
                {
                    let s2 = (*dest_cs_ptr).lock.lock_raw();
                    let s1 = (*caller_cspace).lock.lock_raw();
                    (s1, s2)
                }
                Ordering::Equal =>
                {
                    let s = (*caller_cspace).lock.lock_raw();
                    (s, 0)
                }
            }
        };
        // SAFETY: both CSpace pointers valid; DERIVATION_LOCK and both cspace locks held.
        let result =
            unsafe { crate::cap::move_cap_between_cspaces(caller_cspace, src_idx, dest_cs_ptr) };
        // SAFETY: saved1/saved2 from lock_raw above; release in reverse order.
        unsafe {
            use core::cmp::Ordering;
            match caller_cspace.cmp(&dest_cs_ptr)
            {
                Ordering::Equal =>
                {
                    (*caller_cspace).lock.unlock_raw(saved1);
                }
                Ordering::Less =>
                {
                    (*dest_cs_ptr).lock.unlock_raw(saved2);
                    (*caller_cspace).lock.unlock_raw(saved1);
                }
                Ordering::Greater =>
                {
                    (*caller_cspace).lock.unlock_raw(saved1);
                    (*dest_cs_ptr).lock.unlock_raw(saved2);
                }
            }
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
    let (src_tag, src_rights, src_object, src_token) = {
        // SAFETY: caller_cspace validated non-null above.
        let cs = unsafe { &*caller_cspace };
        let slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == crate::cap::slot::CapTag::Null
        {
            return Err(SyscallError::InvalidCapability);
        }
        (
            slot.tag,
            slot.rights,
            slot.object.ok_or(SyscallError::InvalidCapability)?,
            slot.token,
        )
    };

    // Pre-convert indices before locking so failure cannot leak locks.
    // src_idx cleared the non-null tag check (slot 0 is permanently Null);
    // dest_idx is != 0 (the `dest_idx == 0` path returned above).
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;
    let dest_idx_nz =
        core::num::NonZeroU32::new(dest_idx).ok_or(SyscallError::InvalidCapability)?;

    crate::cap::DERIVATION_LOCK.write_lock();

    // Lock both CSpaces in pointer address order to prevent deadlock.
    // SAFETY: Locking in deterministic order (lower address first) prevents
    // ABBA deadlock. CSpace pointers validated above.
    let (saved1, saved2) = unsafe {
        use core::cmp::Ordering;
        match caller_cspace.cmp(&dest_cs_ptr)
        {
            Ordering::Less =>
            {
                let s1 = (*caller_cspace).lock.lock_raw();
                let s2 = (*dest_cs_ptr).lock.lock_raw();
                (s1, s2)
            }
            Ordering::Greater =>
            {
                let s2 = (*dest_cs_ptr).lock.lock_raw();
                let s1 = (*caller_cspace).lock.lock_raw();
                (s1, s2)
            }
            Ordering::Equal =>
            {
                // caller_cspace == dest_cs_ptr: same CSpace, lock once.
                let s = (*caller_cspace).lock.lock_raw();
                (s, 0)
            }
        }
    };

    // SAFETY: dest_cs_ptr validated above; DERIVATION_LOCK and both CSpace locks held.
    let insert_result =
        unsafe { (*dest_cs_ptr).insert_cap_at(dest_idx, src_tag, src_rights, src_object) };
    if insert_result.is_err()
    {
        // Unlock before returning error.
        // SAFETY: saved1 and saved2 came from lock_raw calls above.
        unsafe {
            use core::cmp::Ordering;
            match caller_cspace.cmp(&dest_cs_ptr)
            {
                Ordering::Equal =>
                {
                    (*caller_cspace).lock.unlock_raw(saved1);
                }
                Ordering::Less =>
                {
                    (*dest_cs_ptr).lock.unlock_raw(saved2);
                    (*caller_cspace).lock.unlock_raw(saved1);
                }
                Ordering::Greater =>
                {
                    (*caller_cspace).lock.unlock_raw(saved1);
                    (*dest_cs_ptr).lock.unlock_raw(saved2);
                }
            }
        }
        crate::cap::DERIVATION_LOCK.write_unlock();
        return Err(SyscallError::InvalidArgument);
    }

    let src_slot_id = SlotId::new(src_cspace_id, src_idx_nz);
    let dst_slot_id = SlotId::new(dest_cspace_id, dest_idx_nz);

    // Copy derivation links to destination.
    let (src_parent, src_first_child, src_prev, src_next) = {
        // SAFETY: caller_cspace validated; DERIVATION_LOCK held.
        let cs = unsafe { &*caller_cspace };
        // SAFETY: We validated src_idx exists at line 752
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
        dst_slot.token = src_token;
        dst_slot.deriv_parent = src_parent;
        dst_slot.deriv_first_child = src_first_child;
        dst_slot.deriv_prev_sibling = src_prev;
        dst_slot.deriv_next_sibling = src_next;
    }

    // Update parent's child pointer.
    if let Some(parent_id) = src_parent
        && let Some(parent_cs) = crate::cap::lookup_cspace(parent_id.cspace_id)
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
        && let Some(prev_cs) = crate::cap::lookup_cspace(prev_id.cspace_id)
    {
        // SAFETY: prev_cs from registry; DERIVATION_LOCK held.
        if let Some(prev_slot) = unsafe { (*prev_cs).slot_mut(prev_id.index.get()) }
            && prev_slot.deriv_next_sibling == Some(src_slot_id)
        {
            prev_slot.deriv_next_sibling = Some(dst_slot_id);
        }
    }
    if let Some(next_id) = src_next
        && let Some(next_cs) = crate::cap::lookup_cspace(next_id.cspace_id)
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
        child_cur = if let Some(child_cs) = crate::cap::lookup_cspace(child_id.cspace_id)
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

    // Unlock CSpaces in reverse order of acquisition.
    // SAFETY: saved1 and saved2 came from lock_raw calls above.
    unsafe {
        use core::cmp::Ordering;
        match caller_cspace.cmp(&dest_cs_ptr)
        {
            Ordering::Equal =>
            {
                (*caller_cspace).lock.unlock_raw(saved1);
            }
            Ordering::Less =>
            {
                (*dest_cs_ptr).lock.unlock_raw(saved2);
                (*caller_cspace).lock.unlock_raw(saved1);
            }
            Ordering::Greater =>
            {
                (*caller_cspace).lock.unlock_raw(saved1);
                (*dest_cs_ptr).lock.unlock_raw(saved2);
            }
        }
    }

    crate::cap::DERIVATION_LOCK.write_unlock();

    Ok(u64::from(dest_idx))
}

/// `SYS_CAP_INSERT` (32): copy a capability to a caller-chosen slot index.
///
/// arg0 = source slot index (caller's `CSpace`).
/// arg1 = destination `CSpace` cap index (must have INSERT right).
/// arg2 = destination slot index in the target `CSpace.`
/// arg3 = rights mask (subset of source rights).
///
/// Like `SYS_CAP_COPY` but the destination slot index is caller-chosen. Used
/// by init to populate well-known slot indices in child process `CSpaces.`
///
/// Returns 0 on success (destination index is already known from arg2).
#[cfg(not(test))]
pub fn sys_cap_insert(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::CSpaceKernelObject;
    use crate::cap::slot::Rights;

    let src_idx = tf.arg(0) as u32;
    let dest_cs_idx = tf.arg(1) as u32;
    let dest_slot_idx = tf.arg(2) as u32;
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
    let src_cspace_id = unsafe { (*caller_cspace).id() };

    // Read source slot.
    let (src_tag, src_rights, src_object, src_token) = {
        // SAFETY: caller_cspace validated non-null above.
        let cs = unsafe { &*caller_cspace };
        let slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == crate::cap::slot::CapTag::Null
        {
            return Err(SyscallError::InvalidCapability);
        }
        (
            slot.tag,
            slot.rights,
            slot.object.ok_or(SyscallError::InvalidCapability)?,
            slot.token,
        )
    };

    let effective_rights = rights_mask & src_rights;

    // Resolve destination CSpace.
    // SAFETY: caller_cspace validated non-null above.
    let dest_cs_slot = unsafe {
        super::lookup_cap(
            caller_cspace,
            dest_cs_idx,
            crate::cap::slot::CapTag::CSpace,
            Rights::INSERT,
        )
    }?;
    let dest_cs_ptr = {
        let obj = dest_cs_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header is at offset 0 of CSpaceKernelObject; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: cap tag confirmed CSpace; object pointer is valid.
        let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
        cs_obj.cspace
    };
    // SAFETY: dest_cs_ptr extracted from validated CSpace object above.
    let dest_cspace_id = unsafe { (*dest_cs_ptr).id() };

    // Pre-convert indices before any state mutation (inc_ref / insert_cap_at
    // / lock acquisition) so a zero index fails cleanly. src_idx cleared the
    // non-null tag check above; dest_slot_idx is further validated inside
    // `insert_cap_at` (which rejects zero).
    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;
    let dest_slot_idx_nz =
        core::num::NonZeroU32::new(dest_slot_idx).ok_or(SyscallError::InvalidCapability)?;

    // Increment refcount before inserting.
    // SAFETY: src_object validated above as live NonNull from slot.
    unsafe {
        (*src_object.as_ptr()).inc_ref();
    }

    // Insert at the specific index under cspace.lock so the freelist/tag
    // invariant cannot tear against a concurrent SYS_CAP_CREATE_*. Token
    // write happens in the same critical section.
    // SAFETY: dest_cs_ptr validated above; lock_raw/unlock_raw paired.
    let insert_res = unsafe {
        let saved = (*dest_cs_ptr).lock.lock_raw();
        let r = (*dest_cs_ptr).insert_cap_at(dest_slot_idx, src_tag, effective_rights, src_object);
        if r.is_ok()
            && src_token != 0
            && let Some(new_slot) = (*dest_cs_ptr).slot_mut(dest_slot_idx)
        {
            new_slot.token = src_token;
        }
        (*dest_cs_ptr).lock.unlock_raw(saved);
        r
    };
    insert_res.map_err(|e| {
        // SAFETY: src_object validated above; we just incremented refcount.
        unsafe {
            (*src_object.as_ptr()).dec_ref();
        }
        match e
        {
            crate::cap::cspace::CapError::WxViolation => SyscallError::WxViolation,
            crate::cap::cspace::CapError::InvalidIndex => SyscallError::InvalidArgument,
            _ => SyscallError::OutOfMemory,
        }
    })?;

    // Wire derivation link.
    let parent = crate::cap::slot::SlotId::new(src_cspace_id, src_idx_nz);
    let child = crate::cap::slot::SlotId::new(dest_cspace_id, dest_slot_idx_nz);
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: DERIVATION_LOCK held; parent/child are valid SlotIds.
    unsafe {
        crate::cap::derivation::link_child(parent, child);
    }
    crate::cap::DERIVATION_LOCK.write_unlock();

    Ok(0)
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
    use crate::cap::object::{EventQueueObject, FrameObject, KernelObjectHeader, ObjectType};
    use crate::cap::retype::{EVENT_QUEUE_RING_OFFSET, dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::event_queue::EventQueueState;
    use core::ptr::NonNull;
    use syscall::EVENT_QUEUE_MAX_CAPACITY;

    let frame_slot = tf.arg(0) as u32;
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
    let frame_slot_ref =
        unsafe { super::lookup_cap(cspace, frame_slot, CapTag::Frame, Rights::RETYPE)? };
    let frame_obj_nn = frame_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Frame slot.
    let frame = unsafe { &*frame_obj_nn.as_ptr().cast::<FrameObject>() };

    let entry = dispatch_for(ObjectType::EventQueue, u64::from(capacity))
        .ok_or(SyscallError::InvalidArgument)?;

    let offset = retype_allocate(frame, entry.raw_bytes)?;

    let block_phys = frame.base + offset;
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

    let ancestor = frame_obj_nn;

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

    // SAFETY: ancestor is the FrameObject's header at offset 0.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: header at offset 0 of EventQueueObject.
    let nonnull = unsafe { NonNull::new_unchecked(eq_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap(CapTag::EventQueue, Rights::POST | Rights::RECV, nonnull);
        (*cspace).lock.unlock_raw(saved);
        r
    };

    if let Ok(idx) = idx_res
    {
        Ok(u64::from(idx.get()))
    }
    else
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
        retype_free(frame, offset, entry.raw_bytes);
        // SAFETY: matches the inc_ref above.
        unsafe { ancestor.as_ref().dec_ref() };
        Err(SyscallError::OutOfMemory)
    }
}

/// `SYS_CAP_CREATE_WAIT_SET` (13): retype a Frame cap into a new `WaitSet`.
///
/// arg0 = Frame-cap slot. The Frame cap MUST carry `Rights::RETYPE` and have
/// at least `dispatch_for(WaitSet, 0).raw_bytes` (504) of `available_bytes`.
#[cfg(not(test))]
pub fn sys_cap_create_wait_set(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{FrameObject, KernelObjectHeader, ObjectType, WaitSetObject};
    use crate::cap::retype::{dispatch_for, retype_allocate, retype_free};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::wait_set::WaitSetState;
    use core::ptr::NonNull;

    let frame_slot = tf.arg(0) as u32;

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
    let frame_slot_ref =
        unsafe { super::lookup_cap(cspace, frame_slot, CapTag::Frame, Rights::RETYPE)? };
    let frame_obj_nn = frame_slot_ref
        .object
        .ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: lookup_cap returned a live Frame slot.
    let frame = unsafe { &*frame_obj_nn.as_ptr().cast::<FrameObject>() };

    let entry = dispatch_for(ObjectType::WaitSet, 0).ok_or(SyscallError::InvalidArgument)?;

    let offset = retype_allocate(frame, entry.raw_bytes)?;

    let block_phys = frame.base + offset;
    let block_virt = crate::mm::paging::phys_to_virt(block_phys);

    // Layout: WaitSetObject at offset 0; WaitSetState at offset 24.
    let ws_obj_ptr = block_virt as *mut WaitSetObject;
    let state_offset = core::mem::size_of::<WaitSetObject>() as u64;
    let ws_state_ptr = (block_virt + state_offset) as *mut WaitSetState;

    let ancestor = frame_obj_nn;

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

    // SAFETY: ancestor is the FrameObject's header at offset 0.
    unsafe { ancestor.as_ref().inc_ref() };

    // SAFETY: header at offset 0 of WaitSetObject.
    let nonnull = unsafe { NonNull::new_unchecked(ws_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above; lock_raw/unlock_raw paired.
    let idx_res = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let r = (*cspace).insert_cap(CapTag::WaitSet, Rights::MODIFY | Rights::WAIT, nonnull);
        (*cspace).lock.unlock_raw(saved);
        r
    };

    if let Ok(idx) = idx_res
    {
        Ok(u64::from(idx.get()))
    }
    else
    {
        // Roll back: nothing else has observed these constructed objects.
        // SAFETY: pointers are unique-ownership for this caller.
        unsafe {
            core::ptr::drop_in_place(ws_obj_ptr);
            core::ptr::drop_in_place(ws_state_ptr);
        }
        retype_free(frame, offset, entry.raw_bytes);
        // SAFETY: matches the inc_ref above.
        unsafe { ancestor.as_ref().dec_ref() };
        Err(SyscallError::OutOfMemory)
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
/// - [`syscall::CAP_INFO_FRAME_SIZE`] / `_AVAILABLE` / `_HAS_RETYPE` —
///   require `CapTag::Frame`.
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
        CAP_INFO_CSPACE_USED, CAP_INFO_FRAME_AVAILABLE, CAP_INFO_FRAME_HAS_RETYPE,
        CAP_INFO_FRAME_PHYS_BASE, CAP_INFO_FRAME_SIZE, CAP_INFO_TAG_RIGHTS, CAP_INFO_THREAD_STATE,
        THREAD_STATE_ALIVE, THREAD_STATE_CREATED, THREAD_STATE_EXITED,
    };

    use crate::cap::object::{AddressSpaceObject, CSpaceKernelObject, FrameObject, ThreadObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::sched::thread::ThreadState;

    let slot_idx = tf.arg(0) as u32;
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
        CAP_INFO_FRAME_SIZE =>
        {
            if tag != CapTag::Frame
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed Frame; header is at offset 0 of FrameObject.
            // cast_ptr_alignment: FrameObject (8-byte aligned via Box) holds the header at offset 0.
            #[allow(clippy::cast_ptr_alignment)]
            let frame = unsafe { &*(obj.as_ptr().cast::<FrameObject>()) };
            Ok(frame.size)
        }
        CAP_INFO_FRAME_AVAILABLE =>
        {
            if tag != CapTag::Frame
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed Frame.
            #[allow(clippy::cast_ptr_alignment)]
            let frame = unsafe { &*(obj.as_ptr().cast::<FrameObject>()) };
            Ok(frame.available_bytes.load(Ordering::Acquire))
        }
        CAP_INFO_FRAME_HAS_RETYPE =>
        {
            if tag != CapTag::Frame
            {
                return Err(SyscallError::InvalidArgument);
            }
            Ok(u64::from(rights.contains(Rights::RETYPE)))
        }
        CAP_INFO_FRAME_PHYS_BASE =>
        {
            if tag != CapTag::Frame
            {
                return Err(SyscallError::InvalidArgument);
            }
            // SAFETY: tag confirmed Frame.
            #[allow(clippy::cast_ptr_alignment)]
            let frame = unsafe { &*(obj.as_ptr().cast::<FrameObject>()) };
            Ok(frame.base)
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
            // SAFETY: cs_obj.cspace validated non-null; max_slots is immutable after construction.
            let cap = unsafe { (*target).max_slots() };
            Ok(cap as u64)
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
            // SAFETY: cs_obj.cspace validated non-null; populated_count is O(1) read of two usize fields.
            // The kernel runs with the scheduler lock effectively held during a syscall, so
            // concurrent mutation of these fields by another CPU is not possible at this point.
            let used = unsafe { (*target).populated_count() };
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
pub fn sys_cap_create_signal(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
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
pub fn sys_cap_insert(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
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
