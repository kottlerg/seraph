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

#[cfg(not(test))]
extern crate alloc;

#[cfg(not(test))]
use alloc::boxed::Box;

use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

#[cfg(not(test))]
use super::current_tcb;

/// `SYS_CAP_CREATE_ENDPOINT` (7): create a new Endpoint object.
///
/// Allocates `EndpointState` and `EndpointObject`, inserts a cap with
/// `SEND | RECEIVE | GRANT` rights into the current thread's `CSpace`.
/// Returns the slot index in rax/a0.
#[cfg(not(test))]
pub fn sys_cap_create_endpoint(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{EndpointObject, KernelObjectHeader, ObjectType};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::endpoint::EndpointState;
    use core::ptr::NonNull;

    // SAFETY: syscall entry ensures current_tcb() returns the active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above; cspace field is immutable after thread creation.
    let cspace = unsafe { (*tcb).cspace };
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Allocate EndpointState.
    let ep_state_ptr = Box::into_raw(Box::new(EndpointState::new()));

    // Allocate EndpointObject (header at offset 0 for safe *-to-header cast).
    let ep_obj_ptr = Box::into_raw(Box::new(EndpointObject {
        header: KernelObjectHeader::new(ObjectType::Endpoint),
        state: ep_state_ptr,
    }));

    // Build NonNull<KernelObjectHeader> by casting (header is at offset 0).
    // SAFETY: ep_obj_ptr is valid Box allocation; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(ep_obj_ptr.cast::<KernelObjectHeader>()) };

    // Insert into CSpace.
    // SAFETY: cspace validated non-null above.
    let idx = unsafe {
        (*cspace).insert_cap(
            CapTag::Endpoint,
            Rights::SEND | Rights::RECEIVE | Rights::GRANT,
            nonnull,
        )
    }
    .map_err(|_| SyscallError::OutOfMemory)?;

    Ok(u64::from(idx.get()))
}

/// `SYS_CAP_CREATE_SIGNAL` (8): create a new Signal object.
///
/// Allocates `SignalState` and `SignalObject`, inserts a cap with
/// `SIGNAL | WAIT` rights into the current thread's `CSpace`.
/// Returns the slot index in rax/a0.
#[cfg(not(test))]
pub fn sys_cap_create_signal(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{KernelObjectHeader, ObjectType, SignalObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::signal::SignalState;
    use core::ptr::NonNull;

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

    let sig_state_ptr = Box::into_raw(Box::new(SignalState::new()));
    let sig_obj_ptr = Box::into_raw(Box::new(SignalObject {
        header: KernelObjectHeader::new(ObjectType::Signal),
        state: sig_state_ptr,
    }));
    // SAFETY: sig_obj_ptr is valid Box allocation; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(sig_obj_ptr.cast::<KernelObjectHeader>()) };
    // SAFETY: cspace validated non-null above.
    let idx =
        unsafe { (*cspace).insert_cap(CapTag::Signal, Rights::SIGNAL | Rights::WAIT, nonnull) }
            .map_err(|_| SyscallError::OutOfMemory)?;
    Ok(u64::from(idx.get()))
}

/// `SYS_CAP_CREATE_ASPACE` (11): create a new `AddressSpace` object.
///
/// Allocates a fresh user address space (root page table + kernel-half copy)
/// and inserts a cap with `MAP | READ` rights into the caller's `CSpace`.
/// Returns the slot index in rax/a0.
#[cfg(not(test))]
pub fn sys_cap_create_aspace(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{AddressSpaceObject, KernelObjectHeader, ObjectType};
    use crate::cap::slot::{CapTag, Rights};
    use crate::mm::address_space::AddressSpace;
    use crate::mm::with_frame_allocator;
    use core::ptr::NonNull;

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

    // Allocate the root page table frame and initialise the address space.
    // SAFETY: Phase 3 (page tables) and Phase 4 (heap) are active.
    let as_obj = with_frame_allocator(|alloc| unsafe { AddressSpace::new_user(alloc) });

    // Allocate the AddressSpaceObject kernel wrapper (heap allocation, outside
    // the frame allocator lock — see with_frame_allocator docs).
    let as_obj_ptr = Box::into_raw(Box::new(AddressSpaceObject {
        header: KernelObjectHeader::new(ObjectType::AddressSpace),
        address_space: Box::into_raw(Box::new(as_obj)),
    }));

    // SAFETY: as_obj_ptr is valid Box allocation; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(as_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above.
    let idx =
        unsafe { (*cspace).insert_cap(CapTag::AddressSpace, Rights::MAP | Rights::READ, nonnull) }
            .map_err(|_| SyscallError::OutOfMemory)?;

    Ok(u64::from(idx.get()))
}

/// `SYS_CAP_CREATE_CSPACE` (12): create a new `CSpace` object.
///
/// arg0 = `max_slots` (clamped to 16384; 0 → default 256).
///
/// Inserts a cap with `INSERT | DELETE | DERIVE` rights into the caller's
/// `CSpace`. Returns the new `CSpace` slot index.
#[cfg(not(test))]
pub fn sys_cap_create_cspace(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::alloc_cspace_id;
    use crate::cap::cspace::CSpace;
    use crate::cap::object::{CSpaceKernelObject, KernelObjectHeader, ObjectType};
    use crate::cap::slot::{CapTag, Rights};
    use core::ptr::NonNull;

    // Clamp: 0 → 256 (small default), anything above 16384 → 16384.
    const DEFAULT_SLOTS: usize = 256;
    const MAX_SLOTS: usize = 16384;

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

    #[allow(clippy::cast_possible_truncation)]
    // cast_possible_truncation: Seraph targets 64-bit only; usize == u64.
    let requested = tf.arg(0) as usize;
    let max_slots = if requested == 0
    {
        DEFAULT_SLOTS
    }
    else
    {
        requested.min(MAX_SLOTS)
    };

    let id = alloc_cspace_id();
    let new_cs_raw = Box::into_raw(Box::new(CSpace::new(id, max_slots)));

    // Register in global registry before wiring into the capability system,
    // so cross-CSpace derivation tree operations can resolve it immediately.
    crate::cap::register_cspace(id, new_cs_raw);

    let cs_obj_ptr = Box::into_raw(Box::new(CSpaceKernelObject {
        header: KernelObjectHeader::new(ObjectType::CSpaceObj),
        cspace: new_cs_raw,
    }));

    // SAFETY: cs_obj_ptr is valid Box allocation; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(cs_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above.
    let idx = unsafe {
        (*cspace).insert_cap(
            CapTag::CSpace,
            Rights::INSERT | Rights::DELETE | Rights::DERIVE,
            nonnull,
        )
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
    use crate::cap::object::{KernelObjectHeader, ObjectType, ThreadObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::message::Message;
    use crate::mm::paging::phys_to_virt;
    use crate::mm::{PAGE_SIZE, with_frame_allocator};
    use crate::sched::alloc_thread_id;
    use crate::sched::thread::{IpcThreadState, ThreadControlBlock, ThreadState};
    use crate::sched::{AFFINITY_ANY, INIT_PRIORITY, KERNEL_STACK_PAGES, TIME_SLICE_TICKS};
    use core::ptr::NonNull;

    // TRAMPOLINE_FRAME_SIZE: reserved gap between trampoline's starting RSP and the
    // TrapFrame base. 512 bytes is sufficient for the minimal C frame.
    const TRAMPOLINE_FRAME_SIZE: u64 = 512;

    #[allow(clippy::cast_possible_truncation)]
    // cast_possible_truncation: Seraph targets 64-bit only; cap slot indices fit in u32.
    let as_idx = tf.arg(0) as u32;
    #[allow(clippy::cast_possible_truncation)]
    // cast_possible_truncation: Seraph targets 64-bit only; cap slot indices fit in u32.
    let cs_idx = tf.arg(1) as u32;

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

    // Resolve AddressSpace cap.
    // SAFETY: caller_cspace validated non-null above.
    let as_slot =
        unsafe { super::lookup_cap(caller_cspace, as_idx, CapTag::AddressSpace, Rights::MAP) }?;
    let as_ptr = {
        use crate::cap::object::AddressSpaceObject;
        let obj = as_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: cap tag confirmed AddressSpace; object pointer is valid.
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the slab allocation.
        #[allow(clippy::cast_ptr_alignment)]
        // cast_ptr_alignment: header is at offset 0 of AddressSpaceObject; allocator guarantees alignment.
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
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the slab allocation.
        #[allow(clippy::cast_ptr_alignment)]
        // cast_ptr_alignment: header is at offset 0 of CSpaceKernelObject; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let cs_obj = unsafe { &*(obj.as_ptr().cast::<CSpaceKernelObject>()) };
        cs_obj.cspace
    };

    // Allocate a kernel stack (4 pages = order 2) from the frame allocator.
    let stack_order = {
        let mut o = 0u32;
        while (1usize << o) < KERNEL_STACK_PAGES
        {
            o += 1;
        }
        o as usize
    };
    let kstack_phys =
        with_frame_allocator(|alloc| alloc.alloc(stack_order)).ok_or(SyscallError::OutOfMemory)?;
    let kstack_virt = phys_to_virt(kstack_phys);
    let kstack_top = kstack_virt + (KERNEL_STACK_PAGES * PAGE_SIZE) as u64;

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

    let new_tcb = Box::into_raw(Box::new(ThreadControlBlock {
        state: ThreadState::Created,
        priority: INIT_PRIORITY,
        slice_remaining: TIME_SLICE_TICKS,
        cpu_affinity: AFFINITY_ANY,
        preferred_cpu: 0,
        run_queue_next: None,
        ipc_state: IpcThreadState::None,
        ipc_msg: Message::default(),
        reply_tcb: core::ptr::null_mut(),
        ipc_wait_next: None,
        is_user: true,
        saved_state: saved,
        kernel_stack_top: kstack_top,
        trap_frame: core::ptr::null_mut(), // set by SYS_THREAD_CONFIGURE
        address_space: as_ptr,
        cspace: new_cs_ptr,
        ipc_buffer: 0,
        wakeup_value: 0,
        iopb: core::ptr::null_mut(),
        blocked_on_object: core::ptr::null_mut(),
        thread_id: alloc_thread_id(),
        context_saved: core::sync::atomic::AtomicU32::new(1),
        death_observers: [crate::sched::thread::DeathObserver::empty();
            crate::sched::thread::MAX_DEATH_OBSERVERS],
        death_observer_count: 0,
        sleep_deadline: 0,
        magic: crate::sched::thread::TCB_MAGIC,
    }));

    // Wrap in a ThreadObject and insert into the caller's CSpace.
    let thread_obj_ptr = Box::into_raw(Box::new(ThreadObject {
        header: KernelObjectHeader::new(ObjectType::Thread),
        tcb: new_tcb,
    }));

    // SAFETY: thread_obj_ptr is valid Box allocation; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(thread_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: caller_cspace validated non-null above.
    let idx = unsafe {
        (*caller_cspace).insert_cap(CapTag::Thread, Rights::CONTROL | Rights::OBSERVE, nonnull)
    }
    .map_err(|_| SyscallError::OutOfMemory)?;

    Ok(u64::from(idx.get()))
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

    // Insert into destination CSpace with the effective (attenuated) rights.
    // SAFETY: dest_cs_ptr validated above.
    let new_idx_nz = unsafe { (*dest_cs_ptr).insert_cap(src_tag, effective_rights, src_object) }
        .map_err(|e| {
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

    // Inherit token from source.
    if src_token != 0
    {
        // SAFETY: dest_cs_ptr validated; new_idx just allocated.
        if let Some(new_slot) = unsafe { (*dest_cs_ptr).slot_mut(new_idx) }
        {
            new_slot.token = src_token;
        }
    }

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

    // SAFETY: caller_cspace validated non-null above.
    let new_idx_nz = unsafe { (*caller_cspace).insert_cap(src_tag, effective_rights, src_object) }
        .map_err(|e| {
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

    // Inherit token from source.
    if src_token != 0
    {
        // SAFETY: caller_cspace validated; new_idx just allocated.
        if let Some(new_slot) = unsafe { (*caller_cspace).slot_mut(new_idx) }
        {
            new_slot.token = src_token;
        }
    }

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

    // SAFETY: caller_cspace validated non-null above.
    let new_idx_nz = unsafe { (*caller_cspace).insert_cap(src_tag, effective_rights, src_object) }
        .map_err(|e| {
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

    // Set the token on the new slot.
    // SAFETY: caller_cspace validated; new_idx just allocated.
    if let Some(new_slot) = unsafe { (*caller_cspace).slot_mut(new_idx) }
    {
        new_slot.token = token_value;
    }

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

    // Read object pointer; if slot is Null, return success.
    let obj_ptr = {
        // SAFETY: caller_cspace validated non-null above.
        let cs = unsafe { &*caller_cspace };
        let slot = cs.slot(slot_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == crate::cap::slot::CapTag::Null
        {
            return Ok(0);
        }
        slot.object.ok_or(SyscallError::InvalidCapability)?
    };

    let slot_idx_nz =
        core::num::NonZeroU32::new(slot_idx).ok_or(SyscallError::InvalidCapability)?;
    let node = crate::cap::slot::SlotId::new(cspace_id, slot_idx_nz);

    // Reparent children to this slot's parent, then unlink the slot itself.
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: caller_cspace validated non-null above; DERIVATION_LOCK held.
    let parent = unsafe { (*caller_cspace).slot(slot_idx).and_then(|s| s.deriv_parent) };
    // SAFETY: DERIVATION_LOCK held; node and parent are valid SlotIds.
    unsafe {
        crate::cap::derivation::reparent_children(node, parent);
    }
    // SAFETY: DERIVATION_LOCK held; node is valid SlotId.
    unsafe {
        crate::cap::derivation::unlink_node(node);
    }
    crate::cap::DERIVATION_LOCK.write_unlock();

    // Clear the slot and return it to the free list.
    // SAFETY: caller_cspace validated; slot_idx confirmed valid above.
    unsafe {
        (*caller_cspace).free_slot(slot_idx);
    }

    // Dec-ref the object; free if no references remain.
    // SAFETY: obj_ptr validated as live NonNull above.
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

    // Revoke the subtree under the lock; collect objects for deallocation.
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: DERIVATION_LOCK held; root is valid SlotId.
    let objects = unsafe { crate::cap::derivation::revoke_subtree(root) };
    crate::cap::DERIVATION_LOCK.write_unlock();

    // Dec-ref and free objects outside the lock (may acquire other locks).
    for obj_ptr in objects
    {
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
        // Auto-allocate: delegate to the shared helper.
        crate::cap::DERIVATION_LOCK.write_lock();
        // SAFETY: both CSpace pointers valid; DERIVATION_LOCK held write.
        let result =
            unsafe { crate::cap::move_cap_between_cspaces(caller_cspace, src_idx, dest_cs_ptr) };
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

    // Insert at the specific index.
    // SAFETY: dest_cs_ptr validated above.
    unsafe { (*dest_cs_ptr).insert_cap_at(dest_slot_idx, src_tag, effective_rights, src_object) }
        .map_err(|e| {
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

    // Inherit token from source.
    if src_token != 0
    {
        // SAFETY: dest_cs_ptr validated; dest_slot_idx just inserted.
        if let Some(new_slot) = unsafe { (*dest_cs_ptr).slot_mut(dest_slot_idx) }
        {
            new_slot.token = src_token;
        }
    }

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
    use crate::cap::object::{EventQueueObject, KernelObjectHeader, ObjectType};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::event_queue::EventQueueState;
    use core::ptr::NonNull;
    use syscall::EVENT_QUEUE_MAX_CAPACITY;

    let capacity = tf.arg(0) as u32;
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

    // Allocate EventQueueState (also allocates the ring buffer internally).
    let eq_state_ptr = Box::into_raw(Box::new(EventQueueState::new(capacity)));

    // Allocate EventQueueObject.
    let eq_obj_ptr = Box::into_raw(Box::new(EventQueueObject {
        header: KernelObjectHeader::new(ObjectType::EventQueue),
        state: eq_state_ptr,
    }));

    // SAFETY: eq_obj_ptr is valid Box allocation; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(eq_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above.
    let idx =
        unsafe { (*cspace).insert_cap(CapTag::EventQueue, Rights::POST | Rights::RECV, nonnull) }
            .map_err(|_| SyscallError::OutOfMemory)?;

    Ok(u64::from(idx.get()))
}

/// `SYS_CAP_CREATE_WAIT_SET` (13): create a new `WaitSet` object.
///
/// No arguments.
///
/// Allocates `WaitSetState` and `WaitSetObject`, inserts a cap with
/// `MODIFY | WAIT` rights into the caller's `CSpace.`
/// Returns the slot index in rax/a0.
#[cfg(not(test))]
pub fn sys_cap_create_wait_set(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{KernelObjectHeader, ObjectType, WaitSetObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::ipc::wait_set::WaitSetState;
    use core::ptr::NonNull;

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

    // Allocate WaitSetState (~480 bytes, heap-allocated).
    let ws_state_ptr = Box::into_raw(Box::new(WaitSetState::new()));

    // Allocate WaitSetObject (header + pointer, 16 bytes).
    let ws_obj_ptr = Box::into_raw(Box::new(WaitSetObject {
        header: KernelObjectHeader::new(ObjectType::WaitSet),
        state: ws_state_ptr,
    }));

    // SAFETY: ws_obj_ptr is valid Box allocation; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(ws_obj_ptr.cast::<KernelObjectHeader>()) };

    // SAFETY: cspace validated non-null above.
    let idx =
        unsafe { (*cspace).insert_cap(CapTag::WaitSet, Rights::MODIFY | Rights::WAIT, nonnull) }
            .map_err(|_| SyscallError::OutOfMemory)?;

    Ok(u64::from(idx.get()))
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
