// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/mem.rs

//! Memory management syscall handlers.
//!
//! # Adding new memory syscalls
//! 1. Add a new `pub fn sys_mem_*` in this file.
//! 2. Add the syscall constant import to `syscall/mod.rs`.
//! 3. Add a dispatch arm to `syscall/mod.rs`.
//! 4. Add a userspace wrapper to `shared/syscall/src/lib.rs`.

// cast_possible_truncation: u64→u32/usize casts extract cap indices and sizes
// from 64-bit trap frame args. Seraph is 64-bit only; all values fit in the target type.
#![allow(clippy::cast_possible_truncation)]

use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

/// `SYS_MEM_MAP` (16): map a physical Frame into a user address space.
///
/// arg0 = Frame cap index (must have MAP right; WRITE/EXECUTE determine page perms).
/// arg1 = `AddressSpace` cap index (must have MAP right).
/// arg2 = virtual address of the first page to map (must be page-aligned, user range).
/// arg3 = offset into the frame in pages (0 = start of frame).
/// arg4 = number of pages to map.
/// arg5 = protection bits (bit 1 = WRITE, bit 2 = EXECUTE). If zero, permissions
///         are derived from the Frame cap's rights. If nonzero, must be a subset
///         of the cap's rights. W^X is enforced: WRITE and EXECUTE may not both
///         be set.
///
/// Returns 0 on success.
#[cfg(not(test))]
// too_many_lines: single validation pass over cap rights, prot bits, and address
// range; splitting would require threading shared state through helpers.
#[allow(clippy::too_many_lines)]
pub fn sys_mem_map(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{AddressSpaceObject, FrameObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::PageFlags;
    use crate::syscall::current_tcb;

    const USER_HALF_TOP: u64 = 0x0000_8000_0000_0000;

    let frame_idx = tf.arg(0) as u32;
    let aspace_idx = tf.arg(1) as u32;
    let virt_base = tf.arg(2);
    let offset_pages = tf.arg(3) as usize;
    let page_count = tf.arg(4) as usize;
    let prot_bits = tf.arg(5);

    // ── Validation ────────────────────────────────────────────────────────────

    // Virtual address must be page-aligned.
    if virt_base & 0xFFF != 0
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Virtual address must be in the user half (< canonical kernel boundary).
    if virt_base >= USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Reject zero-length mappings.
    if page_count == 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Guard against overflow in the virtual range.
    let mapping_size = page_count
        .checked_mul(PAGE_SIZE)
        .ok_or(SyscallError::InvalidArgument)?;
    let virt_end = virt_base
        .checked_add(mapping_size as u64)
        .ok_or(SyscallError::InvalidArgument)?;
    if virt_end > USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }

    // ── Capability lookup ─────────────────────────────────────────────────────

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Resolve Frame cap.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let frame_slot =
        unsafe { super::lookup_cap(caller_cspace, frame_idx, CapTag::Frame, Rights::MAP) }?;
    let (frame_phys, frame_size) = {
        let obj = frame_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Frame; pointer is valid.
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let fo = unsafe { &*(obj.as_ptr().cast::<FrameObject>()) };
        (fo.base, fo.size)
    };
    let frame_rights = frame_slot.rights;

    // Validate that offset + page_count stays within the frame.
    let byte_offset = offset_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(SyscallError::InvalidArgument)? as u64;
    let byte_end = byte_offset
        .checked_add(mapping_size as u64)
        .ok_or(SyscallError::InvalidArgument)?;
    if byte_end > frame_size
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Determine page permissions. If prot_bits is nonzero, use explicit
    // permissions (must be a subset of the Frame cap's rights). If zero,
    // derive from the cap's rights directly (backward compatibility).
    let (writable, executable) = if prot_bits != 0
    {
        let w = (prot_bits & 0x2) != 0;
        let x = (prot_bits & 0x4) != 0;
        if w && !frame_rights.contains(Rights::WRITE)
        {
            return Err(SyscallError::InsufficientRights);
        }
        if x && !frame_rights.contains(Rights::EXECUTE)
        {
            return Err(SyscallError::InsufficientRights);
        }
        (w, x)
    }
    else
    {
        (
            frame_rights.contains(Rights::WRITE),
            frame_rights.contains(Rights::EXECUTE),
        )
    };
    // W^X is enforced at mapping time: no page may be both writable and executable.
    if writable && executable
    {
        return Err(SyscallError::WxViolation);
    }
    let page_flags = PageFlags {
        readable: true,
        writable,
        executable,
        uncacheable: false,
    };

    // Resolve AddressSpace cap.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let aspace_slot =
        unsafe { super::lookup_cap(caller_cspace, aspace_idx, CapTag::AddressSpace, Rights::MAP) }?;
    let as_ptr = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed AddressSpace; pointer is valid.
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
        as_obj.address_space
    };

    // ── Mapping loop ──────────────────────────────────────────────────────────

    for i in 0..page_count
    {
        let virt = virt_base + (i * PAGE_SIZE) as u64;
        let phys = frame_phys + byte_offset + (i * PAGE_SIZE) as u64;

        // SAFETY: virt is in user range (validated above); phys is from a
        // Frame cap confirmed by the kernel at capability creation.
        // as_ptr validated non-null. map_page acquires pt_lock and
        // FRAME_ALLOC_LOCK internally.
        unsafe { (*as_ptr).map_page(virt, phys, page_flags) }
            .map_err(|()| SyscallError::OutOfMemory)?;
    }

    Ok(0)
}

// Test stub.
#[cfg(test)]
pub fn sys_mem_map(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_MEM_UNMAP ─────────────────────────────────────────────────────────────

/// `SYS_MEM_UNMAP` (17): remove page mappings from a user address space.
///
/// arg0 = `AddressSpace` cap index (must have MAP right).
/// arg1 = virtual address of the first page to unmap (page-aligned, user range).
/// arg2 = number of pages to unmap (non-zero).
///
/// Unmapping a page that is not mapped is a no-op (not an error).
/// Returns 0 on success.
///
/// Note: intermediate page table frames are not reclaimed; full teardown
/// happens when the address space object is destroyed.
#[cfg(not(test))]
pub fn sys_mem_unmap(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::AddressSpaceObject;
    use crate::cap::slot::{CapTag, Rights};
    const USER_HALF_TOP: u64 = 0x0000_8000_0000_0000;
    use crate::mm::PAGE_SIZE;
    use crate::syscall::current_tcb;

    let aspace_idx = tf.arg(0) as u32;
    let virt_base = tf.arg(1);
    let page_count = tf.arg(2) as usize;

    // ── Validation ────────────────────────────────────────────────────────────

    if virt_base & 0xFFF != 0
    {
        return Err(SyscallError::InvalidAddress);
    }
    if virt_base >= USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }
    if page_count == 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    let mapping_size = page_count
        .checked_mul(PAGE_SIZE)
        .ok_or(SyscallError::InvalidArgument)?;
    let virt_end = virt_base
        .checked_add(mapping_size as u64)
        .ok_or(SyscallError::InvalidArgument)?;
    if virt_end > USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }

    // ── Capability lookup ─────────────────────────────────────────────────────

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let aspace_slot =
        unsafe { super::lookup_cap(caller_cspace, aspace_idx, CapTag::AddressSpace, Rights::MAP) }?;
    let as_ptr = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed AddressSpace.
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
        as_obj.address_space
    };

    // ── Unmap loop ────────────────────────────────────────────────────────────

    for i in 0..page_count
    {
        let virt = virt_base + (i * PAGE_SIZE) as u64;
        // SAFETY: virt is in user range (validated above); as_ptr is valid.
        unsafe { (*as_ptr).unmap_page(virt) };
    }

    Ok(0)
}

// Test stub.
#[cfg(test)]
pub fn sys_mem_unmap(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_MEM_PROTECT ───────────────────────────────────────────────────────────

/// `SYS_MEM_PROTECT` (18): change permission flags on existing page mappings.
///
/// arg0 = Frame cap index (must have MAP right; authorises the new permissions).
/// arg1 = `AddressSpace` cap index (must have MAP right).
/// arg2 = virtual address of the first page (page-aligned, user range).
/// arg3 = number of pages (non-zero).
/// arg4 = new protection bits: bit 1 = WRITE, bit 2 = EXECUTE (matches Rights layout).
///
/// The new permissions must be a subset of the Frame cap's rights. W^X is
/// enforced: WRITE and EXECUTE may not both be set. Protecting a page that
/// is not mapped returns `InvalidAddress`.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_mem_protect(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::AddressSpaceObject;
    use crate::cap::slot::{CapTag, Rights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::{PageFlags, PagingError};
    use crate::syscall::current_tcb;
    const USER_HALF_TOP: u64 = 0x0000_8000_0000_0000;

    let frame_idx = tf.arg(0) as u32;
    let aspace_idx = tf.arg(1) as u32;
    let virt_base = tf.arg(2);
    let page_count = tf.arg(3) as usize;
    let prot_bits = tf.arg(4);

    // ── Validation ────────────────────────────────────────────────────────────

    if virt_base & 0xFFF != 0
    {
        return Err(SyscallError::InvalidAddress);
    }
    if virt_base >= USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }
    if page_count == 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    let mapping_size = page_count
        .checked_mul(PAGE_SIZE)
        .ok_or(SyscallError::InvalidArgument)?;
    let virt_end = virt_base
        .checked_add(mapping_size as u64)
        .ok_or(SyscallError::InvalidArgument)?;
    if virt_end > USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Parse new protection bits (bit 1 = WRITE, bit 2 = EXECUTE per Rights layout).
    let writable = (prot_bits & 0x2) != 0;
    let executable = (prot_bits & 0x4) != 0;

    // W^X check.
    if writable && executable
    {
        return Err(SyscallError::WxViolation);
    }

    // ── Capability lookup ─────────────────────────────────────────────────────

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Frame cap authorises the permission level.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let frame_slot =
        unsafe { super::lookup_cap(caller_cspace, frame_idx, CapTag::Frame, Rights::MAP) }?;
    // Verify object pointer is valid; rights are read from the slot directly.
    let _ = frame_slot.object.ok_or(SyscallError::InvalidCapability)?;
    let frame_rights = frame_slot.rights;

    // Requested permissions must be a subset of what the Frame cap allows.
    if writable && !frame_rights.contains(Rights::WRITE)
    {
        return Err(SyscallError::InsufficientRights);
    }
    if executable && !frame_rights.contains(Rights::EXECUTE)
    {
        return Err(SyscallError::InsufficientRights);
    }

    let page_flags = PageFlags {
        readable: true,
        writable,
        executable,
        uncacheable: false,
    };

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let aspace_slot =
        unsafe { super::lookup_cap(caller_cspace, aspace_idx, CapTag::AddressSpace, Rights::MAP) }?;
    let as_ptr = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed AddressSpace.
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
        as_obj.address_space
    };

    // ── Protect loop ──────────────────────────────────────────────────────────

    for i in 0..page_count
    {
        let virt = virt_base + (i * PAGE_SIZE) as u64;
        // SAFETY: virt is in user range (validated above); as_ptr is valid.
        unsafe { (*as_ptr).protect_page(virt, page_flags) }.map_err(|e| match e
        {
            PagingError::NotMapped => SyscallError::InvalidAddress,
            PagingError::OutOfFrames => SyscallError::InvalidArgument,
        })?;
    }

    Ok(0)
}

// Test stub.
#[cfg(test)]
pub fn sys_mem_protect(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_FRAME_SPLIT ───────────────────────────────────────────────────────────

/// `SYS_FRAME_SPLIT` (33): split a Frame cap into two non-overlapping children.
///
/// arg0 = Frame cap index (must have MAP right).
/// arg1 = split offset in bytes (page-aligned; must be > 0 and < frame size).
/// arg2 = reserved (must be 0).
///
/// Consumes the original cap and creates two new Frame caps with the same
/// rights, covering `[base, base+split_offset)` and `[base+split_offset, end)`.
/// Both children are reparented to the original cap's derivation parent (same
/// revocability semantics as the sibling caps).
///
/// Returns `slot1 | (slot2 << 32)` on success.
// too_many_lines: `sys_frame_split` is one transactional operation — validate
// the source cap, create two child `FrameObject`s, wire them into the
// derivation tree, and consume the original. Splitting further would thread
// half-constructed children and derivation locks through helpers without
// reducing complexity.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_frame_split(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    extern crate alloc;
    use alloc::boxed::Box;
    use core::ptr::NonNull;

    use crate::cap::derivation::{DERIVATION_LOCK, link_child, reparent_children, unlink_node};
    use crate::cap::object::{FrameObject, KernelObjectHeader, ObjectType, dealloc_object};
    use crate::cap::slot::{CapTag, Rights, SlotId};
    use crate::mm::PAGE_SIZE;
    use crate::syscall::current_tcb;

    let frame_idx = tf.arg(0) as u32;
    let split_offset = tf.arg(1);
    // arg2 is reserved; ignore.

    // ── Validation ────────────────────────────────────────────────────────────

    if split_offset & 0xFFF != 0
    {
        return Err(SyscallError::InvalidArgument); // must be page-aligned
    }
    if split_offset == 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // ── Capability lookup ─────────────────────────────────────────────────────

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    let (frame_phys, frame_size, frame_rights, cspace_id, orig_obj_ptr, orig_owns_memory) = {
        // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
        let slot =
            unsafe { super::lookup_cap(caller_cspace, frame_idx, CapTag::Frame, Rights::MAP) }?;
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: FrameObject (8-byte) behind KernelObjectHeader (4-byte header);
        // Box<FrameObject> allocation guarantees 8-byte alignment.
        // SAFETY: tag confirmed Frame; pointer is valid FrameObject.
        #[allow(clippy::cast_ptr_alignment)]
        let fo = unsafe { &*(obj_ptr.as_ptr().cast::<FrameObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (
            fo.base,
            fo.size,
            slot.rights,
            cspace_id,
            obj_ptr,
            fo.owns_memory.load(core::sync::atomic::Ordering::Acquire),
        )
    };

    // split_offset must be strictly within [1, frame_size).
    if split_offset >= frame_size
    {
        return Err(SyscallError::InvalidArgument);
    }
    // At least one page must remain on each side.
    if frame_size - split_offset < PAGE_SIZE as u64
    {
        return Err(SyscallError::InvalidArgument);
    }

    // ── Create two child FrameObjects ─────────────────────────────────────────

    // Allocate child1: [base, base + split_offset).
    //
    // Inherit the original's memory-ownership state: if the original was
    // buddy-backed (owns_memory = true), ownership transfers to the two
    // children; if it was an MMIO / firmware / boot-module frame, neither
    // child owns its sub-region either.
    let child1_obj = Box::new(FrameObject {
        header: crate::cap::object::KernelObjectHeader::new(ObjectType::Frame),
        base: frame_phys,
        size: split_offset,
        owns_memory: core::sync::atomic::AtomicBool::new(orig_owns_memory),
    });
    let child1_ptr: NonNull<KernelObjectHeader> = {
        let raw = Box::into_raw(child1_obj).cast::<KernelObjectHeader>();
        // SAFETY: Box::into_raw returns non-null; FrameObject.header is at offset 0;
        // cast preserves alignment and validity.
        unsafe { NonNull::new_unchecked(raw) }
    };

    // Allocate child2: [base + split_offset, end).
    let child2_obj = Box::new(FrameObject {
        header: crate::cap::object::KernelObjectHeader::new(ObjectType::Frame),
        base: frame_phys + split_offset,
        size: frame_size - split_offset,
        owns_memory: core::sync::atomic::AtomicBool::new(orig_owns_memory),
    });
    let child2_ptr: NonNull<KernelObjectHeader> = {
        let raw = Box::into_raw(child2_obj).cast::<KernelObjectHeader>();
        // SAFETY: Box::into_raw is non-null; header at offset 0.
        unsafe { NonNull::new_unchecked(raw) }
    };

    // Insert both children into the caller's CSpace (auto-allocate slots).
    // SAFETY: caller_cspace validated non-null; CSpace methods handle slot allocation.
    let cs = unsafe { &mut *caller_cspace };
    let slot1_nz = cs
        .insert_cap(CapTag::Frame, frame_rights, child1_ptr)
        .map_err(|_| SyscallError::OutOfMemory)?;
    let slot1 = slot1_nz.get();
    let slot2_nz = cs
        .insert_cap(CapTag::Frame, frame_rights, child2_ptr)
        .map_err(|_| {
            // Undo slot1 insertion on failure.
            cs.free_slot(slot1);
            // SAFETY: child1_ptr just allocated above; ref count is 1.
            unsafe { crate::cap::object::dealloc_object(child1_ptr) };
            SyscallError::OutOfMemory
        })?;
    let slot2 = slot2_nz.get();

    // ── Wire derivation tree ──────────────────────────────────────────────────
    //
    // Pattern mirrors sys_cap_delete: reparent original's children to its
    // parent, unlink original, then link both new caps to that same parent.

    let frame_idx_nz =
        core::num::NonZeroU32::new(frame_idx).ok_or(SyscallError::InvalidCapability)?;

    DERIVATION_LOCK.write_lock();

    let orig_node = SlotId::new(cspace_id, frame_idx_nz);
    let child1_id = SlotId::new(cspace_id, slot1_nz);
    let child2_id = SlotId::new(cspace_id, slot2_nz);

    // Read the original's parent before we modify anything.
    // SAFETY: caller_cspace validated; frame_idx within CSpace bounds.
    let orig_parent = unsafe {
        (*caller_cspace)
            .slot(frame_idx)
            .and_then(|s| s.deriv_parent)
    };

    // Reparent original's existing children (if any) to its parent.
    // SAFETY: DERIVATION_LOCK held; orig_node/orig_parent valid.
    unsafe { reparent_children(orig_node, orig_parent) };
    // Unlink the original node from the tree.
    // SAFETY: DERIVATION_LOCK held; orig_node valid.
    unsafe { unlink_node(orig_node) };

    // Link both new caps to the original's parent (if any).
    if let Some(parent_id) = orig_parent
    {
        // SAFETY: DERIVATION_LOCK held; parent_id/child1_id/child2_id valid.
        unsafe { link_child(parent_id, child1_id) };
        // SAFETY: DERIVATION_LOCK held; parent_id/child2_id valid.
        unsafe { link_child(parent_id, child2_id) };
    }

    DERIVATION_LOCK.write_unlock();

    // ── Consume the original cap ──────────────────────────────────────────────

    // Transfer memory ownership to the children before the original's
    // refcount drops: both halves of the physical region now belong to
    // child1/child2. Clearing `owns_memory` here ensures that, if the
    // original's refcount hits zero below, `dealloc_object` does not free
    // the backing memory that is still in use by the children.
    //
    // SAFETY: orig_obj_ptr is live (ref > 0 at lookup); FrameObject is
    // #[repr(C)] with header at offset 0; AtomicBool store is well-defined
    // through a shared reference.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        (*orig_obj_ptr.as_ptr().cast::<FrameObject>())
            .owns_memory
            .store(false, core::sync::atomic::Ordering::Release);
    }

    // Return original slot to free list (tag becomes Null).
    // SAFETY: caller_cspace validated; frame_idx within CSpace bounds.
    unsafe { (*caller_cspace).free_slot(frame_idx) };

    // Dec-ref original object; free if no references remain.
    // SAFETY: orig_obj_ptr from lookup_cap; object still valid (ref > 0 at lookup).
    let remaining = unsafe { (*orig_obj_ptr.as_ptr()).dec_ref() };
    if remaining == 0
    {
        // SAFETY: ref count reached zero; no other references exist.
        unsafe { dealloc_object(orig_obj_ptr) };
    }

    Ok(u64::from(slot1) | (u64::from(slot2) << 32))
}

// Test stub.
#[cfg(test)]
pub fn sys_frame_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}
