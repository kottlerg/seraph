// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/mem.rs

//! Memory management syscall handlers.
//!
//! # Adding new memory syscalls
//! Follow `core/kernel/src/syscall/mod.rs` (module docs, "Adding new syscalls"), placing
//! the handler here as a `pub fn sys_mem_*` / `sys_memory_*`, then add a userspace wrapper
//! to `shared/syscall/src/lib.rs`.

#![cfg_attr(
    not(test),
    expect(
        clippy::cast_possible_truncation,
        reason = "u64→usize casts extract page counts and offsets from 64-bit trap frame args. \
                  Seraph is 64-bit only; all values fit in the target type; the casts are in the \
                  cfg(not(test)) handlers, so the lint fires outside the host test build alone"
    )
)]

#[cfg(not(test))]
use super::UserFrame;
// The host-test stubs keep the arch frame type in their signatures.
#[cfg(test)]
use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

/// `SYS_MEM_MAP` (16): map a Memory cap's pages into a user address space.
///
/// Arguments, return, and errors: `core/kernel/docs/syscalls.md` § `SYS_MEM_MAP` (16).
#[cfg(not(test))]
pub fn sys_mem_map(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{AddressSpaceObject, MemoryObject};
    use crate::cap::slot::{AsRights, MemRights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::{LeafGrant, PageFlags};
    use crate::syscall::current_tcb;

    let memory_idx = tf.arg(0);
    let aspace_idx = tf.arg(1);
    let virt_base = tf.arg(2);
    let offset_pages = tf.arg(3) as usize;
    let page_count = tf.arg(4) as usize;
    let prot_bits = tf.arg(5);

    // ── Validation ────────────────────────────────────────────────────────────

    // The range lies wholly in the user range, above `USER_VA_FLOOR`.
    let virt_end = crate::mm::user_range_end(virt_base, page_count)?;
    // Bytes the range spans; `virt_end` lies above `virt_base`, so the
    // difference does not wrap.
    let mapping_size = virt_end.wrapping_sub(virt_base);

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

    // Resolve Memory cap.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let memory_slot = unsafe { super::lookup_cap(caller_cspace, memory_idx, MemRights::MAP) }?;
    let memory_obj_nn = memory_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: tag confirmed Memory; pointer remains valid for the whole syscall
    // (cap held by caller's CSpace; refcount > 0).
    let memory_ref = unsafe { &*(memory_obj_nn.as_ptr().cast::<MemoryObject>()) };

    // The page permissions, decided now so that an executable mapping
    // synchronises instruction fetch before the Memory object's read lock is
    // taken (the sync is a firmware call that waits for every hart, made with
    // no kernel lock held; mm::icache). The bytes it exposes were stored
    // before this call. A refusal is reported where the checks stood, after
    // the range checks below.
    let permissions = map_permissions(prot_bits, memory_slot.rights);
    if matches!(permissions, Ok((_, true)))
    {
        crate::mm::icache::sync_user_code();
    }

    // Read-lock the cap across the validate-and-commit sequence: shrinks of
    // `memory.size` by a concurrent `sys_memory_split` would otherwise race
    // with the bound check below or the mapping loop. RAII guard releases on
    // every return path.
    let _frame_guard = crate::cap::object::MemoryReadGuard::acquire(memory_ref);

    let memory_phys = memory_ref.base;
    let memory_size = memory_ref.size;

    // Validate that offset + page_count stays within the Memory cap region.
    let byte_offset = offset_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(SyscallError::InvalidArgument)? as u64;
    let byte_end = byte_offset
        .checked_add(mapping_size)
        .ok_or(SyscallError::InvalidArgument)?;
    if byte_end > memory_size
    {
        return Err(SyscallError::InvalidArgument);
    }
    // The physical span of the mapped pages. It lies inside the Memory
    // object's range, which cannot pass the end of the address space; the
    // checks refuse a span that would rather than wrap it.
    let phys_base = memory_phys
        .checked_add(byte_offset)
        .ok_or(SyscallError::InvalidArgument)?;
    let phys_end = phys_base
        .checked_add(mapping_size)
        .ok_or(SyscallError::InvalidArgument)?;

    // Retype/map boundary (docs/capability-model.md § Typed Memory). Pin the
    // range's frames in the frame map first, then read the bump cursor: a
    // retype publishes its cursor before it reads the frame map, so with the
    // fences on both sides either this map sees the retype's cursor or the
    // retype sees the pin (core/kernel/docs/memory-internals.md § Frame Map
    // Table). Every live retype lies below the cursor, so a range at or above
    // the page-rounded cursor holds none, and none can be carved under the
    // pinned frames while this call maps them. The pins drop when the call
    // returns; each installed leaf holds its own count.
    let pins = FramePins::pin(phys_base, phys_end)?;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    let retyped_end = crate::cap::retype::current_bump(memory_ref)
        .div_ceil(PAGE_SIZE as u64)
        .saturating_mul(PAGE_SIZE as u64);
    if byte_offset < retyped_end
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Revocation/map boundary (core/kernel/docs/memory-internals.md § Frame
    // Map Table). Resolve the handle again now that the frames are pinned: a
    // revoke clears the slot before its issuer reads the mapping count, so
    // either this lookup sees the cleared slot and the map is refused, or the
    // issuer's count sees the pins and every leaf this call installs.
    // SAFETY: caller_cspace validated above; lookup_cap checks tag and rights.
    let still_held = unsafe { super::lookup_cap(caller_cspace, memory_idx, MemRights::MAP) }?;
    if still_held.object != memory_slot.object
    {
        return Err(SyscallError::InvalidCapability);
    }

    let (writable, executable) = permissions?;
    let page_flags = PageFlags {
        readable: true,
        writable,
        executable,
        uncacheable: false,
    };
    // Each leaf records the cap's Write and Execute, whatever `prot_bits`
    // asked for: the most a later SYS_MEM_PROTECT may make of it, and what a
    // text write of SYS_THREAD_WRITE_MEM needs of a read-only page.
    let grant = LeafGrant {
        writable: memory_slot.rights.contains(MemRights::WRITE.erase()),
        executable: memory_slot.rights.contains(MemRights::EXECUTE.erase()),
    };

    // Resolve AddressSpace cap.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let aspace_slot = unsafe { super::lookup_cap(caller_cspace, aspace_idx, AsRights::MAP) }?;
    let (as_ptr, aso_raw) = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        let aso = obj.as_ptr().cast::<AddressSpaceObject>();
        // SAFETY: aso is a valid pointer to an AddressSpaceObject.
        let as_inner = unsafe { (*aso).address_space };
        (as_inner, aso)
    };

    // Page-table pages come from the address space's own pool, which its
    // create-time donation seeds: every address space records that donation
    // before it is published, so the kernel page-table pool is never drawn on
    // here (`core/kernel/docs/memory-internals.md` § Page Table Node Ownership).
    // SAFETY: aso_raw is non-null and valid for the lifetime of the cap.
    unsafe { (*aso_raw).require_create_donation() }?;

    // ── Mapping loop ──────────────────────────────────────────────────────────

    let virts = (virt_base..virt_end).step_by(PAGE_SIZE);
    let frames = (phys_base..phys_end).step_by(PAGE_SIZE);
    for (virt, phys) in virts.zip(frames)
    {
        // SAFETY: as_ptr is the AddressSpace of the AddressSpaceObject
        // `aspace_slot` pins for the call.
        let aspace = unsafe { &*as_ptr };
        // SAFETY: aso_raw is the AddressSpaceObject `aspace_slot` pins for the
        // call.
        let aso = unsafe { &*aso_raw };
        // SAFETY: virt is in user range (validated above); phys is a 4 KiB-aligned
        // frame of a Memory cap confirmed by the kernel at capability creation;
        // aso wraps aspace, both resolved from the same capability.
        unsafe { aspace.map_page_pooled(virt, phys, page_flags, grant, aso) }
            .map_err(|()| SyscallError::OutOfMemory)?;
    }

    drop(pins);
    Ok(0)
}

/// The `(writable, executable)` permissions of a `SYS_MEM_MAP` leaf, per
/// `core/kernel/docs/syscalls.md` § `SYS_MEM_MAP` (16): `prot_bits` when
/// non-zero, else the Memory cap's own `rights`.
///
/// # Errors
/// - `InsufficientRights`: `prot_bits` asks for write or execute that
///   `rights` lacks.
/// - `WxViolation`: the result is both writable and executable
///   (docs/capability-model.md § Memory).
#[cfg(not(test))]
fn map_permissions(
    prot_bits: u64,
    rights: crate::cap::slot::Rights,
) -> Result<(bool, bool), SyscallError>
{
    use crate::cap::slot::MemRights;

    let (writable, executable) = if prot_bits != 0
    {
        let w = (prot_bits & syscall::MAP_WRITABLE) != 0;
        let x = (prot_bits & syscall::MAP_EXECUTABLE) != 0;
        if w && !rights.contains(MemRights::WRITE.erase())
        {
            return Err(SyscallError::InsufficientRights);
        }
        if x && !rights.contains(MemRights::EXECUTE.erase())
        {
            return Err(SyscallError::InsufficientRights);
        }
        (w, x)
    }
    else
    {
        (
            rights.contains(MemRights::WRITE.erase()),
            rights.contains(MemRights::EXECUTE.erase()),
        )
    };
    if writable && executable
    {
        return Err(SyscallError::WxViolation);
    }
    Ok((writable, executable))
}

/// Frame-map pins over a span of frames, held by `sys_mem_map` from before its
/// retype-cursor check until it returns, and dropped (each count lowered) when
/// the guard drops.
#[cfg(not(test))]
struct FramePins
{
    /// First frame of the span.
    phys: u64,
    /// End of the span, exclusive.
    end: u64,
    /// Frames from `phys` whose count this guard raised.
    pages: usize,
}

#[cfg(not(test))]
impl FramePins
{
    /// Raise the count of each frame in `[phys, end)`.
    ///
    /// # Errors
    /// `OutOfMemory` when a frame's count is saturated; nothing stays pinned.
    fn pin(phys: u64, end: u64) -> Result<Self, SyscallError>
    {
        let mut pins = Self {
            phys,
            end,
            pages: 0,
        };
        for frame in (phys..end).step_by(crate::mm::PAGE_SIZE)
        {
            crate::mm::frame_map::raise(frame).map_err(|()| SyscallError::OutOfMemory)?;
            // Bounded by the span's frame count, a `usize`: cannot saturate.
            pins.pages = pins.pages.saturating_add(1);
        }
        Ok(pins)
    }
}

#[cfg(not(test))]
impl Drop for FramePins
{
    fn drop(&mut self)
    {
        for frame in (self.phys..self.end)
            .step_by(crate::mm::PAGE_SIZE)
            .take(self.pages)
        {
            crate::mm::frame_map::lower(frame);
        }
    }
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
/// Arguments, flags, return, and errors: `core/kernel/docs/syscalls.md` § `SYS_MEM_UNMAP` (17);
/// page-table reclaim: `core/kernel/docs/memory-internals.md` § Page Table Node Ownership.
/// Unmapping a page that is not mapped is a no-op.
#[cfg(not(test))]
pub fn sys_mem_unmap(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::AddressSpaceObject;
    use crate::cap::slot::AsRights;
    use crate::mm::PAGE_SIZE;
    use crate::syscall::current_tcb;
    use syscall::MEM_UNMAP_RECLAIM_PTS;

    let aspace_idx = tf.arg(0);
    let virt_base = tf.arg(1);
    let page_count = tf.arg(2) as usize;
    let flags = tf.arg(3);

    // ── Validation ────────────────────────────────────────────────────────────

    // The range lies wholly in the user range, above `USER_VA_FLOOR`.
    let virt_end = crate::mm::user_range_end(virt_base, page_count)?;

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
    let aspace_slot = unsafe { super::lookup_cap(caller_cspace, aspace_idx, AsRights::MAP) }?;
    let (as_ptr, aso_raw) = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        let aso = obj.as_ptr().cast::<AddressSpaceObject>();
        // SAFETY: tag confirmed AddressSpace; aso is a valid AddressSpaceObject.
        let as_inner = unsafe { (*aso).address_space };
        (as_inner, aso)
    };

    // ── Unmap ───────────────────────────────────────────────────────────────

    if flags & MEM_UNMAP_RECLAIM_PTS != 0
    {
        // Region teardown: clear the whole span and reclaim each now-empty
        // intermediate page table to the AS's pool, with one coarse shootdown
        // (plus the span invalidations of the frame-map release batch).
        // SAFETY: as_ptr is the AddressSpace of the AddressSpaceObject
        // `aspace_slot` pins for the call.
        let aspace = unsafe { &*as_ptr };
        // SAFETY: aso_raw is the AddressSpaceObject `aspace_slot` pins for the
        // call.
        let aso = unsafe { &*aso_raw };
        // SAFETY: aso wraps aspace, both resolved from the same capability;
        // virt_base is page-aligned and the span is user-range (validated
        // above).
        unsafe { aspace.unmap_region_pooled(virt_base, page_count, aso) };
    }
    else
    {
        for virt in (virt_base..virt_end).step_by(PAGE_SIZE)
        {
            // SAFETY: as_ptr is the AddressSpace of the AddressSpaceObject
            // `aspace_slot` pins for the call.
            let aspace = unsafe { &*as_ptr };
            // SAFETY: virt is in user range (validated above).
            unsafe { aspace.unmap_page(virt) };
        }
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
/// Arguments, return, and errors: `core/kernel/docs/syscalls.md` § `SYS_MEM_PROTECT` (18).
#[cfg(not(test))]
pub fn sys_mem_protect(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::AddressSpaceObject;
    use crate::cap::slot::{AsRights, MemRights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::{PageFlags, PagingError};
    use crate::syscall::current_tcb;

    let memory_idx = tf.arg(0);
    let aspace_idx = tf.arg(1);
    let virt_base = tf.arg(2);
    let page_count = tf.arg(3) as usize;
    let prot_bits = tf.arg(4);

    // ── Validation ────────────────────────────────────────────────────────────

    // The range lies wholly in the user range, above `USER_VA_FLOOR`.
    let virt_end = crate::mm::user_range_end(virt_base, page_count)?;

    // Parse new protection bits (MAP_WRITABLE / MAP_EXECUTABLE share the Memory
    // rights bit positions; asserted in abi/syscall).
    let writable = (prot_bits & syscall::MAP_WRITABLE) != 0;
    let executable = (prot_bits & syscall::MAP_EXECUTABLE) != 0;

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

    // Memory cap authorises the permission level.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let memory_slot = unsafe { super::lookup_cap(caller_cspace, memory_idx, MemRights::MAP) }?;
    // Verify object pointer is valid; rights are read from the slot directly.
    let _ = memory_slot.object.ok_or(SyscallError::InvalidCapability)?;
    let memory_rights = memory_slot.rights;

    // Requested permissions must be a subset of what the Memory cap allows.
    if writable && !memory_rights.contains(MemRights::WRITE.erase())
    {
        return Err(SyscallError::InsufficientRights);
    }
    if executable && !memory_rights.contains(MemRights::EXECUTE.erase())
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
    let aspace_slot = unsafe { super::lookup_cap(caller_cspace, aspace_idx, AsRights::MAP) }?;
    let as_ptr = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed AddressSpace.
        let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
        as_obj.address_space
    };

    // Making a page executable may expose bytes stored through its earlier
    // writable mapping; instruction fetch must see them before the first leaf
    // below turns executable. A protect to executable synchronises even when
    // the pages are executable already: it is the route by which a process
    // that wrote code through a writable alias of an executable frame makes
    // the code visible (mm::icache). No lock is held here.
    if executable
    {
        crate::mm::icache::sync_user_code();
    }

    // ── Protect loop ──────────────────────────────────────────────────────────

    // Each page is also bounded by its own leaf's grant, the Write and Execute
    // of the capability that mapped it: the Memory cap named here authorises
    // the call, not the frames under the range. A page that refuses stops the
    // loop with the pages before it already changed.
    for virt in (virt_base..virt_end).step_by(PAGE_SIZE)
    {
        // SAFETY: as_ptr is the AddressSpace of the AddressSpaceObject
        // `aspace_slot` pins for the call.
        let aspace = unsafe { &*as_ptr };
        // SAFETY: virt is in user range (validated above). Whether it is
        // mapped is checked by protect_page itself under pt_lock, which
        // refuses an unmapped page with NotMapped.
        unsafe { aspace.protect_page(virt, page_flags) }.map_err(|e| match e
        {
            PagingError::NotMapped => SyscallError::InvalidAddress,
            PagingError::NotGranted => SyscallError::InsufficientRights,
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

// ── SYS_MEMORY_SPLIT ───────────────────────────────────────────────────────────

/// `SYS_MEMORY_SPLIT` (33): carve a virgin tail off a Memory cap.
///
/// Arguments, semantics, return, and errors: `core/kernel/docs/syscalls.md`
/// § `SYS_MEMORY_SPLIT` (33). The bump bound is read with `retype::current_bump`.
#[expect(
    clippy::too_many_lines,
    reason = "one locked pass — pin, snapshot, validate, mint, insert, link, mutate in place — \
              that would otherwise thread the held locks through helpers"
)]
#[cfg(not(test))]
pub fn sys_memory_split(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::derivation::{DERIVATION_LOCK, link_child};
    use crate::cap::object::{KernelObjectHeader, MemoryObject, ObjectType};
    use crate::cap::retype;
    use crate::cap::slot::{CapTag, MemRights, SlotId};
    use crate::mm::PAGE_SIZE;
    use crate::syscall::current_tcb;

    let memory_handle = tf.arg(0);
    let memory_idx = syscall::cap_handle_index(memory_handle);
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
    let parent_slot = unsafe { super::lookup_cap(caller_cspace, memory_handle, MemRights::MAP) }?;
    let parent_obj_nn = parent_slot.object.ok_or(SyscallError::InvalidCapability)?;
    let parent_rights = parent_slot.rights;
    let parent_retypable = parent_rights.contains(MemRights::RETYPE.erase());
    // SAFETY: caller_cspace validated non-null; id() reads discriminator.
    let cspace_id = unsafe { (*caller_cspace).id() };

    // ── Acquire locks (DERIVATION outer, frame-write inner) ──────────────────
    DERIVATION_LOCK.write_lock();
    // Pin the unlocked-resolved parent under the lock
    // (`core/kernel/docs/capability-internals.md` § Global Derivation Lock).
    // SAFETY: caller_cspace validated non-null; DERIVATION_LOCK held.
    if let Err(e) = unsafe {
        super::cap::revalidate_src_under_lock(caller_cspace, memory_handle, parent_obj_nn)
    }
    {
        DERIVATION_LOCK.write_unlock();
        return Err(e);
    }
    // SAFETY: tag confirmed Memory; the slot is pinned under DERIVATION_LOCK,
    // so the object is live for the rest of the hold.
    let parent_ref = unsafe { &*(parent_obj_nn.as_ptr().cast::<MemoryObject>()) };
    parent_ref.write_lock();

    // Snapshot parent state under the write lock. From here until unlock,
    // no concurrent mem_map / retype_allocate can observe a torn `size`.
    let orig_size = parent_ref.size;
    let parent_phys = parent_ref.base;
    let parent_owns = parent_ref
        .owns_memory
        .load(core::sync::atomic::Ordering::Acquire);

    // Refuse a split of an object another capability slot names (a
    // derivation, a copy, or a slot that shares it unlinked): shrinking it
    // in place would shrink what that slot names too. The count is exact
    // under DERIVATION_LOCK, and the caller's slot was revalidated above.
    if !parent_ref.named_by_one_slot()
    {
        parent_ref.write_unlock();
        DERIVATION_LOCK.write_unlock();
        return Err(SyscallError::InvalidArgument);
    }

    // split_offset must be strictly within (0, orig_size) with at least
    // one page on each side. The tail's base lies inside the parent's range,
    // which cannot pass the end of the address space; the check refuses a
    // base that would rather than wrap it.
    let Some((tail_size, tail_base)) = orig_size
        .checked_sub(split_offset)
        .filter(|&rest| rest >= PAGE_SIZE as u64)
        .zip(parent_phys.checked_add(split_offset))
    else
    {
        parent_ref.write_unlock();
        DERIVATION_LOCK.write_unlock();
        return Err(SyscallError::InvalidArgument);
    };

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

    let tail_avail = if parent_retypable { tail_size } else { 0 };

    // ── Mint tail MemoryObject ─────────────────────────────────────────────────
    //
    // The caller's CSpace, which receives the tail's slot, funds its body from
    // its arena (core/kernel/docs/capability-internals.md § Body Arena); the
    // dealloc returns the chunk there. The tail inherits `owns_memory` once it
    // is inserted; the insert-failure path below clears the flag before
    // destroying it, since the parent still covers the range and, after
    // handoff, the buddy is sealed (`core/kernel/src/mm/buddy.rs` § Post-handoff
    // sealing).
    // SAFETY: caller_cspace is the running thread's own CSpace, live while the
    // thread runs.
    let funder = unsafe { crate::cap::object::arena_of(caller_cspace) }.inspect_err(|_| {
        parent_ref.write_unlock();
        DERIVATION_LOCK.write_unlock();
    })?;
    let tail_ptr = funder
        .alloc_body(MemoryObject {
            header: KernelObjectHeader::new(ObjectType::Memory),
            base: tail_base,
            size: tail_size,
            available_bytes: core::sync::atomic::AtomicU64::new(tail_avail),
            // Tail inherits the parent's ownership flag so the two halves together
            // carry the original range's `owns_memory` accounting (the buddy is
            // sealed after handoff; see `core/kernel/src/mm/buddy.rs`).
            owns_memory: core::sync::atomic::AtomicBool::new(parent_owns),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
            slot_count: core::sync::atomic::AtomicU32::new(0),
        })
        .inspect_err(|_| {
            parent_ref.write_unlock();
            DERIVATION_LOCK.write_unlock();
        })?;

    // Insert under cspace.lock to keep the freelist/tag invariant against a
    // concurrent SYS_CAP_CREATE_* on the same cspace (lock order:
    // `core/kernel/docs/scheduling-internals.md` § Lock Hierarchy).
    // `insert_cap_slot_and_handle` mints the returned handle in the same hold.
    // SAFETY: caller_cspace validated non-null; it is the running thread's own
    // CSpace, live while the thread runs.
    let lock = unsafe { &(*caller_cspace).lock };
    // SAFETY: lock_raw pairs with the unlock_raw below.
    let saved = unsafe { lock.lock_raw() };
    // SAFETY: caller_cspace is live (as above), and its held lock serialises
    // the slot freelist and tags.
    let insert_res = unsafe {
        (*caller_cspace).insert_cap_slot_and_handle(CapTag::Memory, parent_rights, tail_ptr)
    };
    // SAFETY: caller_cspace is live (as above).
    let lock = unsafe { &(*caller_cspace).lock };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(saved) };
    let (tail_slot_nz, tail_handle) = match insert_res
    {
        Ok(inserted) => inserted,
        Err(e) =>
        {
            // The parent still covers the tail's range, so the tail owns none of
            // it: clear the inherited flag so the dealloc returns only the
            // body's chunk to the arena and frees nothing into the buddy.
            // SAFETY: tail_ptr is the MemoryObject minted above (header at offset
            // 0), uninserted and reachable from no other thread.
            unsafe {
                (*tail_ptr.as_ptr().cast::<MemoryObject>())
                    .owns_memory
                    .store(false, core::sync::atomic::Ordering::Release);
            }
            parent_ref.write_unlock();
            DERIVATION_LOCK.write_unlock();
            // Freed after both locks go, as `dealloc_object` requires.
            // SAFETY: tail_ptr just allocated; refcount is 1 with no other
            // holders, and no lock is held.
            unsafe { crate::cap::object::dealloc_object(tail_ptr) };
            return Err(e.into());
        }
    };
    let tail_id = SlotId::current(cspace_id, tail_slot_nz);

    // ── Wire derivation: tail becomes a sibling of parent under parent's parent ──

    // SAFETY: DERIVATION_LOCK held; memory_idx within CSpace bounds.
    let parent_deriv_parent = unsafe {
        (*caller_cspace)
            .slot(memory_idx)
            .and_then(|s| s.deriv_parent)
    };
    if let Some(grandparent) = parent_deriv_parent
    {
        // SAFETY: DERIVATION_LOCK held; the grandparent link was read from
        // the pinned parent and the tail was inserted under this hold. A
        // grandparent whose CSpace has since unregistered is a dead link
        // (see `truncate_dead_link`); the tail then stays a root.
        let _ = unsafe { link_child(grandparent, tail_id) };
    }
    // If the parent was a derivation root, the tail is also a root: no
    // parent edge needed.

    // ── Mutate parent in place ────────────────────────────────────────────────
    //
    // Shrink size; debit the carved bytes from `available_bytes` (only when
    // the cap is retypable — non-RETYPE caps already have available = 0).
    // The parent's allocator state and slot identity stay intact, and no
    // other slot names it (refused above). Live retypes against the
    // parent (`ancestor` pointers) continue to refer to the same
    // `KernelObjectHeader` — no re-ancestoring required.
    //
    // SAFETY: write_lock held; this is the only mutator of `parent_ref.size`.
    // No reference is created from the raw pointer; the write goes directly
    // through `parent_obj_nn` (a NonNull obtained from the cap slot).
    unsafe {
        let parent_mut = parent_obj_nn.as_ptr().cast::<MemoryObject>();
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

    Ok(tail_handle)
}

// Test stub.
#[cfg(test)]
pub fn sys_memory_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_MEMORY_MERGE ───────────────────────────────────────────────────────────

/// `SYS_MEMORY_MERGE` (50): absorb a virgin tail Memory cap back into its parent.
///
/// Inverse of [`sys_memory_split`]. Arguments, return, preconditions, and errors:
/// `core/kernel/docs/syscalls.md` § `SYS_MEMORY_MERGE` (50).
#[expect(
    clippy::too_many_lines,
    reason = "one locked pass — pin, snapshot, validate, unlink, mutate, free — over two objects \
              under three locks that would otherwise be threaded through helpers"
)]
#[cfg(not(test))]
pub fn sys_memory_merge(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::derivation::{DERIVATION_LOCK, unlink_node};
    use crate::cap::object::MemoryObject;
    use crate::cap::slot::{MemRights, SlotId};
    use crate::syscall::current_tcb;

    let parent_handle = tf.arg(0);
    let tail_handle = tf.arg(1);
    let parent_idx = syscall::cap_handle_index(parent_handle);
    let tail_idx = syscall::cap_handle_index(tail_handle);
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
    let parent_slot = unsafe { super::lookup_cap(caller_cspace, parent_handle, MemRights::MAP) }?;
    let parent_obj_nn = parent_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let tail_slot = unsafe { super::lookup_cap(caller_cspace, tail_handle, MemRights::MAP) }?;
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
    let merged_retypable = merged_rights.contains(MemRights::RETYPE.erase());

    // ── Acquire locks (order: `core/kernel/docs/scheduling-internals.md`
    // § Lock Hierarchy; DERIVATION_LOCK already excludes a concurrent merge,
    // so the pointer order is defence, not deadlock avoidance) ──
    DERIVATION_LOCK.write_lock();

    // Pin both unlocked-resolved caps under the lock
    // (`core/kernel/docs/capability-internals.md` § Global Derivation Lock).
    // SAFETY: caller_cspace validated non-null; DERIVATION_LOCK held.
    let pinned = unsafe {
        super::cap::revalidate_src_under_lock(caller_cspace, parent_handle, parent_obj_nn)
    }
    .and_then(|()| {
        // SAFETY: caller_cspace validated non-null; DERIVATION_LOCK held.
        unsafe { super::cap::revalidate_src_under_lock(caller_cspace, tail_handle, tail_obj_nn) }
    });
    if let Err(e) = pinned
    {
        DERIVATION_LOCK.write_unlock();
        return Err(e);
    }
    // SAFETY: tag confirmed Memory; the slot is pinned under DERIVATION_LOCK,
    // so the object is live for the rest of the hold.
    let parent_ref = unsafe { &*(parent_obj_nn.as_ptr().cast::<MemoryObject>()) };
    // SAFETY: as for parent_ref.
    let tail_ref = unsafe { &*(tail_obj_nn.as_ptr().cast::<MemoryObject>()) };

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
    let tail_bump = crate::cap::retype::current_bump(tail_ref);

    // Physical contiguity. The merged size cannot overflow once the two are
    // contiguous, since the tail's range ends inside the address space; the
    // check refuses a size that would rather than wrap it.
    if parent_base.checked_add(parent_size) != Some(tail_base)
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }
    let Some(merged_size) = parent_size.checked_add(tail_size)
    else
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    };
    // Memory-ownership state must match.
    if parent_owns != tail_owns
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }
    // Tail must be virgin: no retype allocations performed, and
    // available_bytes matches the rights state.
    if tail_bump != 0
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

    // ── Each object must be named by its slot alone: growing the parent would
    //    grow what another slot naming it reaches, and consuming the tail
    //    would leave another slot naming it on a range the parent now owns. ─
    if !parent_ref.named_by_one_slot() || !tail_ref.named_by_one_slot()
    {
        release_locks();
        return Err(SyscallError::InvalidArgument);
    }

    // ── Derivation-tree validation: parent and tail must be siblings. ───────
    let Some(tail_idx_nz) = core::num::NonZeroU32::new(tail_idx)
    else
    {
        release_locks();
        return Err(SyscallError::InvalidCapability);
    };
    // SAFETY: caller_cspace validated non-null.
    let cspace_id = unsafe { (*caller_cspace).id() };
    let tail_id = SlotId::current(cspace_id, tail_idx_nz);

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
    let parent_dp = match parent_deriv
    {
        Ok(s) => s.deriv_parent,
        Err(e) =>
        {
            release_locks();
            return Err(e);
        }
    };
    let tail_dp = match tail_deriv
    {
        Ok(s) => s.deriv_parent,
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

    // ── Detach the tail from the derivation tree ─────────────────────────────
    // SAFETY: DERIVATION_LOCK held; tail_id is a valid live slot.
    unsafe { unlink_node(tail_id) };

    // ── Mutate parent in place: grow size, credit available ──────────────────
    // SAFETY: parent's write_lock held; this is the only mutator of size.
    unsafe {
        let parent_mut = parent_obj_nn.as_ptr().cast::<MemoryObject>();
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
    // tail's write_lock held; this is the only mutator.
    tail_ref
        .owns_memory
        .store(false, core::sync::atomic::Ordering::Release);

    // Free the tail slot under cspace.lock so the freelist mutation cannot
    // tear against a concurrent SYS_CAP_CREATE_* on the same cspace (lock
    // order: `core/kernel/docs/scheduling-internals.md` § Lock Hierarchy).
    // SAFETY: caller_cspace validated non-null; it is the running thread's own
    // CSpace, live while the thread runs.
    let lock = unsafe { &(*caller_cspace).lock };
    // SAFETY: lock_raw pairs with the unlock_raw below.
    let saved = unsafe { lock.lock_raw() };
    // SAFETY: caller_cspace is live (as above), and its held lock serialises
    // the freelist; tail_idx is within CSpace bounds.
    unsafe { (*caller_cspace).free_slot(tail_idx) };
    // SAFETY: caller_cspace is live (as above).
    let lock = unsafe { &(*caller_cspace).lock };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(saved) };

    // Drop both write locks before releasing the tail's reference (the
    // release can free the tail, which takes other locks).
    release_locks();

    // Release the reference the freed tail slot held. `tail_slot` still pins
    // the tail, so the free happens when that pin drops; owns_memory was
    // cleared above, so the free does not return the merged range to the
    // buddy allocator (the parent now covers it).
    // SAFETY: tail_obj_nn is the object the freed slot referenced, live
    // until this release; that reference is released exactly once, here;
    // syscall context with no lock held.
    unsafe { crate::cap::object::release_ref(tail_obj_nn) };

    Ok(0)
}

// Test stub.
#[cfg(test)]
pub fn sys_memory_merge(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}
