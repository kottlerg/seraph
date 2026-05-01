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
    let frame_obj_nn = frame_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
    // SAFETY: tag confirmed Frame; pointer remains valid for the whole syscall
    // (cap held by caller's CSpace; refcount > 0).
    #[allow(clippy::cast_ptr_alignment)]
    let frame_ref = unsafe { &*(frame_obj_nn.as_ptr().cast::<FrameObject>()) };

    // Read-lock the cap across the validate-and-commit sequence: shrinks of
    // `frame.size` by a concurrent `sys_frame_split` would otherwise race
    // with the bound check below or the mapping loop. RAII guard releases on
    // every return path.
    let _frame_guard = crate::cap::object::FrameReadGuard::acquire(frame_ref);

    let frame_phys = frame_ref.base;
    let frame_size = frame_ref.size;
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
    let (as_ptr, aso_raw) = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let aso = obj.as_ptr().cast::<AddressSpaceObject>();
        // SAFETY: aso is a valid pointer to an AddressSpaceObject.
        let as_inner = unsafe { (*aso).address_space };
        (as_inner, aso)
    };

    // Choose the PT-page source. Retype-backed AS (any chunk slot occupied)
    // pulls intermediate PT pages from its own growth pool; the legacy
    // heap-backed bootstrap AS falls back to the kernel buddy.
    // SAFETY: aso_raw is non-null and valid for the lifetime of the cap.
    let pooled = !unsafe {
        (*aso_raw).pt_chunks[0]
            .ancestor
            .load(core::sync::atomic::Ordering::Acquire)
            .is_null()
    };

    // ── Mapping loop ──────────────────────────────────────────────────────────

    for i in 0..page_count
    {
        let virt = virt_base + (i * PAGE_SIZE) as u64;
        let phys = frame_phys + byte_offset + (i * PAGE_SIZE) as u64;

        // SAFETY: virt is in user range (validated above); phys is from a
        // Frame cap confirmed by the kernel at capability creation.
        // as_ptr validated non-null. Pooled vs heap-backed dispatch is
        // chosen once above based on the AS's typed-memory state.
        let result = if pooled
        {
            // SAFETY: aso_raw is valid; it wraps as_ptr.
            unsafe { (*as_ptr).map_page_pooled(virt, phys, page_flags, &*aso_raw) }
        }
        else
        {
            // SAFETY: legacy heap-backed AS; map_page acquires pt_lock and
            // FRAME_ALLOC_LOCK internally.
            unsafe { (*as_ptr).map_page(virt, phys, page_flags) }
        };
        result.map_err(|()| SyscallError::OutOfMemory)?;
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

/// `SYS_FRAME_SPLIT` (33): carve a virgin tail off a Frame cap.
///
/// arg0 = Frame cap index (must have MAP right).
/// arg1 = split offset in bytes (page-aligned; > 0 and < cap size; must be
///        at or above the cap's highest live retype offset, page-aligned).
/// arg2 = reserved (must be 0).
///
/// The parent cap stays in its slot; its `size` shrinks to `split_offset`
/// and its `available_bytes` debits by `(orig_size - split_offset)` (when
/// the cap carries `Rights::RETYPE`). A new child cap covering
/// `[base + split_offset, base + orig_size)` is inserted in the caller's
/// `CSpace` and linked as a derivation child of the parent's existing
/// derivation parent — making it a co-equal sibling of the (now shrunken)
/// parent in the derivation tree.
///
/// Live retypes against the parent always sit below `bump_offset`; any
/// `split_offset >= round_up(bump_offset, PAGE_SIZE)` is therefore safe —
/// the new tail is virgin (no live descendants). Smaller offsets are
/// refused.
///
/// Returns the new tail-cap slot on success.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_frame_split(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    extern crate alloc;
    use alloc::boxed::Box;
    use core::ptr::NonNull;

    use crate::cap::derivation::{DERIVATION_LOCK, link_child};
    use crate::cap::object::{FrameObject, KernelObjectHeader, ObjectType};
    use crate::cap::retype;
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

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let parent_slot =
        unsafe { super::lookup_cap(caller_cspace, frame_idx, CapTag::Frame, Rights::MAP) }?;
    let parent_obj_nn = parent_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: FrameObject (8-byte) behind KernelObjectHeader header.
    // SAFETY: tag confirmed Frame; pointer is valid FrameObject.
    #[allow(clippy::cast_ptr_alignment)]
    let parent_ref = unsafe { &*(parent_obj_nn.as_ptr().cast::<FrameObject>()) };
    let parent_rights = parent_slot.rights;
    let parent_retypable = parent_rights.contains(Rights::RETYPE);
    // SAFETY: caller_cspace validated non-null; id() reads discriminator.
    let cspace_id = unsafe { (*caller_cspace).id() };

    let frame_idx_nz =
        core::num::NonZeroU32::new(frame_idx).ok_or(SyscallError::InvalidCapability)?;
    let parent_id = SlotId::new(cspace_id, frame_idx_nz);

    // ── Acquire locks (DERIVATION outer, frame-write inner) ──────────────────
    DERIVATION_LOCK.write_lock();
    parent_ref.write_lock();

    // Snapshot parent state under the write lock. From here until unlock,
    // no concurrent mem_map / retype_allocate can observe a torn `size`.
    let orig_size = parent_ref.size;
    let parent_phys = parent_ref.base;
    let parent_owns = parent_ref
        .owns_memory
        .load(core::sync::atomic::Ordering::Acquire);

    // Refuse split when the parent has cap-derivation children. Their
    // FrameObject pointer would still alias the (shrunken) parent and could
    // observe a region the parent no longer owns. memmgr / init / ktest's
    // split callers never derive before splitting.
    // SAFETY: caller_cspace validated; frame_idx within CSpace bounds;
    // DERIVATION_LOCK held.
    let parent_first_child = unsafe {
        (*caller_cspace)
            .slot(frame_idx)
            .and_then(|s| s.deriv_first_child)
    };
    if parent_first_child.is_some()
    {
        parent_ref.write_unlock();
        DERIVATION_LOCK.write_unlock();
        return Err(SyscallError::InvalidArgument);
    }

    // split_offset must be strictly within (0, orig_size) with at least
    // one page on each side.
    if split_offset >= orig_size || orig_size - split_offset < PAGE_SIZE as u64
    {
        parent_ref.write_unlock();
        DERIVATION_LOCK.write_unlock();
        return Err(SyscallError::InvalidArgument);
    }

    // Live retypes against the parent occupy `[0, bump_offset)`. The split
    // point must sit at or above the next page boundary so the carved tail
    // is virgin.
    let bump = retype::current_bump(parent_ref);
    let page_size = PAGE_SIZE as u64;
    let bump_aligned = bump.div_ceil(page_size).saturating_mul(page_size);
    if split_offset < bump_aligned
    {
        parent_ref.write_unlock();
        DERIVATION_LOCK.write_unlock();
        return Err(SyscallError::InvalidArgument);
    }

    let tail_size = orig_size - split_offset;
    let tail_avail = if parent_retypable { tail_size } else { 0 };

    // ── Mint tail FrameObject ─────────────────────────────────────────────────
    let tail_obj = Box::new(FrameObject {
        header: KernelObjectHeader::new(ObjectType::Frame),
        base: parent_phys + split_offset,
        size: tail_size,
        available_bytes: core::sync::atomic::AtomicU64::new(tail_avail),
        // Tail inherits the parent's ownership flag. On dealloc each half
        // buddy-frees its own (now disjoint) range; together they cover the
        // original allocation.
        owns_memory: core::sync::atomic::AtomicBool::new(parent_owns),
        allocator: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        lock: core::sync::atomic::AtomicU32::new(0),
    });
    let tail_ptr: NonNull<KernelObjectHeader> = {
        let raw = Box::into_raw(tail_obj).cast::<KernelObjectHeader>();
        // SAFETY: Box::into_raw returns non-null; header at offset 0.
        unsafe { NonNull::new_unchecked(raw) }
    };

    // SAFETY: caller_cspace validated non-null.
    let cs = unsafe { &mut *caller_cspace };
    let Ok(tail_slot_nz) = cs.insert_cap(CapTag::Frame, parent_rights, tail_ptr)
    else
    {
        // SAFETY: tail_ptr just allocated; refcount is 1 with no other holders.
        unsafe { crate::cap::object::dealloc_object(tail_ptr) };
        parent_ref.write_unlock();
        DERIVATION_LOCK.write_unlock();
        return Err(SyscallError::OutOfMemory);
    };
    let tail_slot = tail_slot_nz.get();
    let tail_id = SlotId::new(cspace_id, tail_slot_nz);

    // ── Wire derivation: tail becomes a sibling of parent under parent's parent ──

    // SAFETY: DERIVATION_LOCK held; frame_idx within CSpace bounds.
    let parent_deriv_parent = unsafe {
        (*caller_cspace)
            .slot(frame_idx)
            .and_then(|s| s.deriv_parent)
    };
    if let Some(grandparent) = parent_deriv_parent
    {
        // SAFETY: DERIVATION_LOCK held; ids valid.
        unsafe { link_child(grandparent, tail_id) };
    }
    // If the parent was a derivation root, the tail is also a root: no
    // parent edge needed.
    let _ = parent_id; // silence unused if no grandparent

    // ── Mutate parent in place ────────────────────────────────────────────────
    //
    // Shrink size; debit the carved bytes from `available_bytes` (only when
    // the cap is retypable — non-RETYPE caps already have available = 0).
    // The parent's allocator state, derivation children (none — refused
    // above), and slot identity all stay intact. Live retypes against the
    // parent (`ancestor` pointers) continue to refer to the same
    // `KernelObjectHeader` — no re-ancestoring required.
    //
    // SAFETY: write_lock held; this is the only mutator of `parent_ref.size`.
    // No reference is created from the raw pointer; the write goes directly
    // through `parent_obj_nn` (a NonNull obtained from the cap slot).
    unsafe {
        let parent_mut = parent_obj_nn.as_ptr().cast::<FrameObject>();
        (*parent_mut).size = split_offset;
    }
    if parent_retypable
    {
        parent_ref
            .available_bytes
            .fetch_sub(tail_size, core::sync::atomic::Ordering::AcqRel);
    }

    parent_ref.write_unlock();
    DERIVATION_LOCK.write_unlock();

    Ok(u64::from(tail_slot))
}

// Test stub.
#[cfg(test)]
pub fn sys_frame_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_FRAME_MERGE ───────────────────────────────────────────────────────────

/// `SYS_FRAME_MERGE` (50): absorb a virgin tail Frame cap back into its parent.
///
/// arg0 = parent Frame cap index (must have MAP right; physically-lower half).
///        Stays valid; its `size` grows to cover the absorbed tail's region.
/// arg1 = tail Frame cap index (must have MAP right; physically-upper half).
///        Consumed; its slot is freed.
/// arg2 = reserved (must be 0).
///
/// Inverse of [`sys_frame_split`] under Option D. Both caps must:
/// - Be physically contiguous (`parent.base + parent.size == tail.base`).
/// - Carry identical rights.
/// - Agree on `owns_memory`.
/// - Be siblings under the same derivation parent.
/// - Have no derivation children of their own.
/// - The tail must be virgin (no live retypes — `allocator == null` and
///   `available_bytes == size` for retypable caps; non-retypable caps
///   trivially satisfy this).
///
/// Returns 0 on success. The parent's slot index is unchanged; the tail's
/// slot is returned to the caller's `CSpace` free list.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_frame_merge(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::derivation::{DERIVATION_LOCK, unlink_node};
    use crate::cap::object::{FrameObject, dealloc_object};
    use crate::cap::slot::{CapTag, Rights, SlotId};
    use crate::syscall::current_tcb;

    let parent_idx = tf.arg(0) as u32;
    let tail_idx = tf.arg(1) as u32;
    // arg2 reserved.

    if parent_idx == tail_idx
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

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let parent_slot =
        unsafe { super::lookup_cap(caller_cspace, parent_idx, CapTag::Frame, Rights::MAP) }?;
    let parent_obj_nn = parent_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let tail_slot =
        unsafe { super::lookup_cap(caller_cspace, tail_idx, CapTag::Frame, Rights::MAP) }?;
    let tail_obj_nn = tail_slot.object.ok_or(SyscallError::InvalidCapability)?;

    if parent_obj_nn == tail_obj_nn
    {
        return Err(SyscallError::InvalidArgument);
    }
    if parent_slot.rights != tail_slot.rights
    {
        return Err(SyscallError::InvalidArgument);
    }
    let merged_rights = parent_slot.rights;
    let merged_retypable = merged_rights.contains(Rights::RETYPE);

    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: tag confirmed Frame; cap held by caller's CSpace, ref count > 0.
    let parent_ref = unsafe { &*(parent_obj_nn.as_ptr().cast::<FrameObject>()) };
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: tag confirmed Frame; cap held by caller's CSpace, ref count > 0.
    let tail_ref = unsafe { &*(tail_obj_nn.as_ptr().cast::<FrameObject>()) };

    // ── Acquire locks (DERIVATION outer; per-cap write locks inner, ordered
    // by FrameObject pointer to avoid deadlocks against concurrent merges) ──
    DERIVATION_LOCK.write_lock();

    let (lock_first, lock_second) = if core::ptr::from_ref(parent_ref)
        < core::ptr::from_ref(tail_ref)
    {
        (parent_ref, tail_ref)
    }
    else
    {
        (tail_ref, parent_ref)
    };
    lock_first.write_lock();
    lock_second.write_lock();

    let release_locks = || {
        lock_second.write_unlock();
        lock_first.write_unlock();
        DERIVATION_LOCK.write_unlock();
    };

    // Snapshot under locks.
    let parent_base = parent_ref.base;
    let parent_size = parent_ref.size;
    let parent_owns = parent_ref
        .owns_memory
        .load(core::sync::atomic::Ordering::Acquire);
    let tail_base = tail_ref.base;
    let tail_size = tail_ref.size;
    let tail_owns = tail_ref
        .owns_memory
        .load(core::sync::atomic::Ordering::Acquire);
    let tail_avail = tail_ref
        .available_bytes
        .load(core::sync::atomic::Ordering::Acquire);
    let tail_alloc = tail_ref
        .allocator
        .load(core::sync::atomic::Ordering::Acquire);

    // Physical contiguity.
    if parent_base.checked_add(parent_size) != Some(tail_base)
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }
    // Memory-ownership state must match.
    if parent_owns != tail_owns
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }
    // Tail must be virgin: no retype allocator installed, and
    // available_bytes matches the rights state.
    if !tail_alloc.is_null()
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }
    let expected_tail_avail = if merged_retypable { tail_size } else { 0 };
    if tail_avail != expected_tail_avail
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }

    // ── Derivation-tree validation: parent and tail must be siblings, and
    //    neither may have derivation children. ────────────────────────────────
    let parent_idx_nz = core::num::NonZeroU32::new(parent_idx);
    let tail_idx_nz = core::num::NonZeroU32::new(tail_idx);
    let (Some(parent_idx_nz), Some(tail_idx_nz)) = (parent_idx_nz, tail_idx_nz)
    else
    {
        release_locks();
        return Err(SyscallError::InvalidCapability);
    };
    // SAFETY: caller_cspace validated non-null.
    let cspace_id = unsafe { (*caller_cspace).id() };
    let tail_id = SlotId::new(cspace_id, tail_idx_nz);
    let _ = parent_idx_nz; // parent slot not unlinked (it stays alive)

    // SAFETY: DERIVATION_LOCK held; indices within CSpace bounds.
    let parent_deriv = unsafe {
        (*caller_cspace)
            .slot(parent_idx)
            .ok_or(SyscallError::InvalidCapability)
    };
    // SAFETY: DERIVATION_LOCK held; indices within CSpace bounds.
    let tail_deriv = unsafe {
        (*caller_cspace)
            .slot(tail_idx)
            .ok_or(SyscallError::InvalidCapability)
    };
    let (parent_dp, parent_fc) = match parent_deriv
    {
        Ok(s) => (s.deriv_parent, s.deriv_first_child),
        Err(e) =>
        {
            release_locks();
            return Err(e);
        }
    };
    let (tail_dp, tail_fc) = match tail_deriv
    {
        Ok(s) => (s.deriv_parent, s.deriv_first_child),
        Err(e) =>
        {
            release_locks();
            return Err(e);
        }
    };

    if parent_dp != tail_dp
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }
    if parent_fc.is_some() || tail_fc.is_some()
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }

    // ── Detach the tail from the derivation tree ─────────────────────────────
    // SAFETY: DERIVATION_LOCK held; tail_id is a valid live slot.
    unsafe { unlink_node(tail_id) };

    // ── Mutate parent in place: grow size, credit available ──────────────────
    let merged_size = parent_size + tail_size; // contiguity already verified
    // SAFETY: parent's write_lock held; this is the only mutator of size.
    unsafe {
        let parent_mut = parent_obj_nn.as_ptr().cast::<FrameObject>();
        (*parent_mut).size = merged_size;
    }
    if merged_retypable
    {
        parent_ref
            .available_bytes
            .fetch_add(tail_size, core::sync::atomic::Ordering::AcqRel);
    }

    // ── Consume tail: clear owns_memory (parent now owns the merged range)
    //    and release the tail's slot. ──────────────────────────────────────────
    // SAFETY: tail's write_lock held; this is the only mutator.
    tail_ref
        .owns_memory
        .store(false, core::sync::atomic::Ordering::Release);

    // SAFETY: caller_cspace validated; tail_idx within CSpace bounds.
    unsafe { (*caller_cspace).free_slot(tail_idx) };

    // Drop both write locks before dec_ref'ing the tail (dec_ref can take
    // dealloc_object, which may itself acquire other locks).
    lock_second.write_unlock();
    lock_first.write_unlock();
    DERIVATION_LOCK.write_unlock();

    // SAFETY: tail_obj_nn from lookup_cap; object valid (ref > 0 at lookup).
    let remaining = unsafe { (*tail_obj_nn.as_ptr()).dec_ref() };
    if remaining == 0
    {
        // SAFETY: refcount reached zero; owns_memory cleared above so the
        // dealloc path will not double-free the buddy region (parent now
        // covers it).
        unsafe { dealloc_object(tail_obj_nn) };
    }

    Ok(0)
}

// Test stub.
#[cfg(test)]
pub fn sys_frame_merge(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}
