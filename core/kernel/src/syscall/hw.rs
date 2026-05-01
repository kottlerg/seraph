// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/hw.rs

//! Hardware access syscall handlers.
//!
//! Implements:
//! - `SYS_IRQ_ACK` (29): re-enable a masked interrupt line.
//! - `SYS_IRQ_REGISTER` (30): bind a Signal to an interrupt line.
//! - `SYS_MMIO_MAP` (34): map an MMIO region into an address space.
//! - `SYS_IOPORT_BIND` (35): bind an I/O port range to a thread (`x86_64` only).
//! - `SYS_MMIO_SPLIT` (45): split an `MmioRegion` cap into two sub-regions.
//! - `SYS_IRQ_SPLIT` (49): split an `Interrupt` range cap into two sub-ranges.
//!
//! # Adding new hardware syscalls
//! 1. Add a new `pub fn sys_hw_*` in this file.
//! 2. Import the constant in `syscall/mod.rs`.
//! 3. Add a dispatch arm in `syscall/mod.rs`.
//! 4. Add a userspace wrapper in `shared/syscall/src/lib.rs`.

// cast_possible_truncation: capability slot indices extracted from 64-bit trap frame
// registers are always u32-range values. Seraph runs on 64-bit only; no truncation occurs.
#![allow(clippy::cast_possible_truncation)]

use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

// ── SYS_IRQ_ACK ───────────────────────────────────────────────────────────────

/// `SYS_IRQ_ACK` (29): re-enable an interrupt line after the driver has handled
/// the interrupt.
///
/// arg0 = Interrupt cap index (must have SIGNAL right).
///
/// Unmasks the IRQ line at the interrupt controller, allowing the next
/// interrupt delivery. The driver must call this after clearing the interrupt
/// source in the device to avoid an interrupt storm.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_irq_ack(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::InterruptObject;
    use crate::cap::slot::{CapTag, Rights};
    use crate::syscall::current_tcb;

    let irq_cap_idx = tf.arg(0) as u32;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let cspace = unsafe { (*tcb).cspace };

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let irq_slot =
        unsafe { super::lookup_cap(cspace, irq_cap_idx, CapTag::Interrupt, Rights::SIGNAL) }?;
    let irq_id = {
        let obj = irq_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Interrupt; object was allocated as Box<InterruptObject>.
        #[allow(clippy::cast_ptr_alignment)]
        let io = unsafe { &*obj.as_ptr().cast::<InterruptObject>() };
        if io.count != 1
        {
            return Err(SyscallError::InvalidArgument);
        }
        io.start
    };

    // Unmask at the interrupt controller to re-enable delivery.
    crate::arch::current::interrupts::unmask(irq_id);

    Ok(0)
}

#[cfg(test)]
pub fn sys_irq_ack(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IRQ_REGISTER ─────────────────────────────────────────────────────────

/// `SYS_IRQ_REGISTER` (30): bind a Signal to an interrupt line.
///
/// arg0 = Interrupt cap index (must have SIGNAL right).
/// arg1 = Signal cap index (must have SIGNAL right).
///
/// When the interrupt fires:
/// 1. The IRQ is masked at the controller.
/// 2. Bit 0 is `ORed` into the Signal.
/// 3. Any thread blocked on `SYS_SIGNAL_WAIT` for this signal is woken.
/// 4. The driver must call `SYS_IRQ_ACK` to re-enable delivery.
///
/// On `x86_64`: programs the IOAPIC redirection entry (masked until first ACK).
/// On RISC-V: enables the PLIC source (masked at controller until first ACK).
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_irq_register(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{InterruptObject, SignalObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::syscall::current_tcb;

    let irq_cap_idx = tf.arg(0) as u32;
    let sig_cap_idx = tf.arg(1) as u32;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let cspace = unsafe { (*tcb).cspace };

    // Resolve Interrupt cap.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let irq_slot =
        unsafe { super::lookup_cap(cspace, irq_cap_idx, CapTag::Interrupt, Rights::SIGNAL) }?;
    let irq_id = {
        let obj = irq_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Interrupt; object was allocated as Box<InterruptObject>.
        #[allow(clippy::cast_ptr_alignment)]
        let io = unsafe { &*obj.as_ptr().cast::<InterruptObject>() };
        if io.count != 1
        {
            // Range caps must be narrowed via SYS_IRQ_SPLIT before register.
            return Err(SyscallError::InvalidArgument);
        }
        io.start
    };

    // Resolve Signal cap.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let sig_slot =
        unsafe { super::lookup_cap(cspace, sig_cap_idx, CapTag::Signal, Rights::SIGNAL) }?;
    let sig_state = {
        let obj = sig_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Signal; object was allocated as Box<SignalObject>.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            (*obj.as_ptr().cast::<SignalObject>()).state
        }
    };

    // Register the signal in the IRQ routing table.
    // Disable interrupts to serialise with dispatch_device_irq, which reads
    // the table from interrupt context.
    // SAFETY: save_and_disable_interrupts/restore_interrupts are paired;
    //         irq::register requires interrupts disabled.
    unsafe {
        let saved = crate::arch::current::cpu::save_and_disable_interrupts();
        crate::irq::register(irq_id, sig_state);
        crate::arch::current::cpu::restore_interrupts(saved);
    }

    // Program arch-specific interrupt routing.
    // x86_64: write IOAPIC redirection entry (entry starts masked; driver ACKs
    //         to unmask after registering).
    // RISC-V: enable the PLIC source (starts masked at controller; ACK unmasks).
    #[cfg(target_arch = "x86_64")]
    // SAFETY: irq_id validated from capability; route() requires valid IRQ number.
    unsafe {
        crate::arch::current::ioapic::route(
            irq_id,
            crate::arch::current::ioapic::DEVICE_VECTOR_BASE + irq_id as u8,
        );
        // Entry is left masked by route(); driver unmasks via SYS_IRQ_ACK.
    }

    #[cfg(target_arch = "riscv64")]
    {
        // Enable at PLIC, then immediately mask until the driver ACKs.
        crate::arch::current::interrupts::plic_enable(irq_id);
        crate::arch::current::interrupts::mask(irq_id);
    }

    Ok(0)
}

#[cfg(test)]
pub fn sys_irq_register(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_MMIO_MAP ─────────────────────────────────────────────────────────────

/// `SYS_MMIO_MAP` (34): map an MMIO region into a user address space.
///
/// arg0 = `AddressSpace` cap index (must have MAP right).
/// arg1 = `MmioRegion` cap index (must have MAP right).
/// arg2 = virtual base address (page-aligned, user half).
/// arg3 = flags (bit 1 = WRITE; executable mappings are always rejected).
///
/// All pages are mapped with `uncacheable = true` (PCD|PWT on `x86_64`,
/// no-op on RISC-V under the current MMU mode — see [`PageFlags`] comment).
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_mmio_map(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{AddressSpaceObject, MmioRegionObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::PageFlags;
    use crate::syscall::current_tcb;

    // Virtual address must be page-aligned and in user half.
    const USER_HALF_TOP: u64 = 0x0000_8000_0000_0000;
    let aspace_idx = tf.arg(0) as u32;
    let mmio_idx = tf.arg(1) as u32;

    let virt_base = tf.arg(2);
    let flags = tf.arg(3);
    if virt_base & 0xFFF != 0 || virt_base >= USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let cspace = unsafe { (*tcb).cspace };

    // Resolve MmioRegion cap.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let mmio_slot =
        unsafe { super::lookup_cap(cspace, mmio_idx, CapTag::MmioRegion, Rights::MAP) }?;
    let (mmio_phys, mmio_size) = {
        let obj = mmio_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed MmioRegion; object was allocated as Box<MmioRegionObject>.
        #[allow(clippy::cast_ptr_alignment)]
        let mo = unsafe { &*obj.as_ptr().cast::<MmioRegionObject>() };
        (mo.base, mo.size)
    };

    // Size must be at least one page and page-aligned.
    if mmio_size == 0 || mmio_size & 0xFFF != 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    let page_count = (mmio_size / PAGE_SIZE as u64) as usize;

    // Guard against virtual range overflow.
    let virt_end = virt_base
        .checked_add(mmio_size)
        .ok_or(SyscallError::InvalidArgument)?;
    if virt_end > USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Resolve AddressSpace cap.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let as_slot =
        unsafe { super::lookup_cap(cspace, aspace_idx, CapTag::AddressSpace, Rights::MAP) }?;
    let as_ptr = {
        let obj = as_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed AddressSpace; object was allocated as Box<AddressSpaceObject>.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            (*obj.as_ptr().cast::<AddressSpaceObject>()).address_space
        }
    };

    // MMIO mappings are never executable.
    // Writability is derived from the cap's WRITE right, not the flags arg.
    // The flags arg is reserved for future use (cache mode overrides, etc.).
    let writable = mmio_slot.rights.contains(Rights::WRITE);
    let _ = flags; // reserved
    let page_flags = PageFlags {
        readable: true,
        writable,
        executable: false,
        uncacheable: true,
    };

    // Map each page.
    for i in 0..page_count
    {
        let virt = virt_base + (i * PAGE_SIZE) as u64;
        let phys = mmio_phys + (i * PAGE_SIZE) as u64;

        // SAFETY: virt in user range (validated above); phys from a
        // kernel-provisioned MmioRegion boot object. map_page acquires
        // pt_lock and FRAME_ALLOC_LOCK internally.
        unsafe { (*as_ptr).map_page(virt, phys, page_flags) }
            .map_err(|()| SyscallError::OutOfMemory)?;
    }

    Ok(0)
}

#[cfg(test)]
pub fn sys_mmio_map(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IOPORT_BIND ──────────────────────────────────────────────────────────

/// `SYS_IOPORT_BIND` (35): grant a thread access to an I/O port range.
///
/// arg0 = Thread cap index (must have CONTROL right).
/// arg1 = `IoPortRange` cap index (must have USE right).
///
/// On first bind, a 8 KiB per-thread IOPB bitmap is heap-allocated and all
/// ports are denied (0xFF). The requested range bits are then cleared (0 =
/// allowed). On context switch the bitmap is copied into the TSS IOPB region.
///
/// On RISC-V: always returns `NotSupported` (no I/O port concept).
///
/// Returns 0 on success.
// needless_return: the cfg-gated early return is required to terminate the
// riscv64 path; the x86_64 path follows in the same function body.
#[cfg(not(test))]
#[allow(clippy::needless_return)]
pub fn sys_ioport_bind(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // RISC-V has no I/O port space.
    #[cfg(target_arch = "riscv64")]
    {
        let _ = tf;
        // unnecessary_wraps suppressed: sys_ioport_bind must match the dispatch
        // table signature Result<u64, SyscallError> on all targets.
        return Err(SyscallError::NotSupported);
    }

    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::current::gdt;
        use crate::cap::object::{IoPortRangeObject, ThreadObject};
        use crate::cap::slot::{CapTag, Rights};
        use crate::syscall::current_tcb;

        let thread_idx = tf.arg(0) as u32;
        let ioport_idx = tf.arg(1) as u32;

        // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
        let caller_tcb = unsafe { current_tcb() };
        if caller_tcb.is_null()
        {
            return Err(SyscallError::InvalidCapability);
        }
        // SAFETY: tcb validated non-null; cspace set at thread creation.
        let cspace = unsafe { (*caller_tcb).cspace };

        // Resolve Thread cap.
        // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
        let th_slot =
            unsafe { super::lookup_cap(cspace, thread_idx, CapTag::Thread, Rights::CONTROL) }?;
        let target_tcb = {
            let obj = th_slot.object.ok_or(SyscallError::InvalidCapability)?;
            // SAFETY: tag confirmed Thread; object was allocated as Box<ThreadObject>.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                (*obj.as_ptr().cast::<ThreadObject>()).tcb
            }
        };
        if target_tcb.is_null()
        {
            return Err(SyscallError::InvalidCapability);
        }

        // Resolve IoPortRange cap.
        // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
        let port_slot =
            unsafe { super::lookup_cap(cspace, ioport_idx, CapTag::IoPortRange, Rights::USE) }?;
        let (port_base, port_size) = {
            let obj = port_slot.object.ok_or(SyscallError::InvalidCapability)?;
            // SAFETY: tag confirmed IoPortRange; object was allocated as Box<IoPortRangeObject>.
            #[allow(clippy::cast_ptr_alignment)]
            let po = unsafe { &*obj.as_ptr().cast::<IoPortRangeObject>() };
            (po.base, po.size)
        };

        // Allocate per-thread IOPB on first bind. Sourced from the kernel
        // SEED Frame cap (no heap alloc); freed back to SEED on thread
        // dealloc via the Thread arm of `dealloc_object`.
        // SAFETY: target_tcb validated non-null; iopb field always valid.
        if unsafe { (*target_tcb).iopb.is_null() }
        {
            let raw = crate::cap::retype::alloc_seed_scratch(gdt::IOPB_SIZE as u64)?;
            // SAFETY: raw points at a freshly-carved IOPB-sized block in
            // SEED's region; not aliased; we own it for the IOPB's lifetime.
            unsafe {
                core::ptr::write_bytes(raw, 0xFFu8, gdt::IOPB_SIZE);
                #[allow(clippy::cast_ptr_alignment)]
                {
                    (*target_tcb).iopb = raw.cast::<[u8; gdt::IOPB_SIZE]>();
                }
            }
        }

        // Clear the bits for the requested port range (0 = allow).
        // size == 0 encodes the full 64K range (u16 cannot hold 65536).
        let effective_size = if port_size == 0
        {
            65536u32
        }
        else
        {
            u32::from(port_size)
        };
        // SAFETY: iopb is non-null after the allocation above; target_tcb validated.
        unsafe {
            gdt::permit_port_range_u32(
                &mut *(*target_tcb).iopb,
                u32::from(port_base),
                effective_size,
            );
        }

        // If binding to the currently running thread, reload the TSS IOPB
        // immediately so in/out instructions work without a context switch.
        if target_tcb == caller_tcb
        {
            // SAFETY: iopb non-null after allocation; target_tcb validated.
            unsafe {
                gdt::load_iopb(Some(&*(*target_tcb).iopb));
            }
        }

        Ok(0)
    }
}

#[cfg(test)]
pub fn sys_ioport_bind(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_MMIO_SPLIT ──────────────────────────────────────────────────────────

/// `SYS_MMIO_SPLIT` (45): split an `MmioRegion` cap into two non-overlapping children.
///
/// arg0 = `MmioRegion` cap index (must have MAP right).
/// arg1 = split offset in bytes (page-aligned; must be > 0 and < region size).
/// arg2 = reserved (must be 0).
///
/// Consumes the original cap and creates two new `MmioRegion` caps with the same
/// rights and flags, covering `[base, base+split_offset)` and
/// `[base+split_offset, end)`. Both children are reparented to the original
/// cap's derivation parent (same revocability semantics as sibling caps).
///
/// Returns `slot1 | (slot2 << 32)` on success.
// too_many_lines: splitting an MMIO cap requires validating the original,
// building two child objects, wiring both into the derivation tree, and
// freeing the original — each step has its own bookkeeping and no meaningful
// split-point between them.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_mmio_split(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::derivation::{DERIVATION_LOCK, link_child, reparent_children, unlink_node};
    use crate::cap::object::{KernelObjectHeader, MmioRegionObject, ObjectType, dealloc_object};
    use crate::cap::retype::alloc_in_seed;
    use crate::cap::seed_header_nn;
    use crate::cap::slot::{CapTag, Rights, SlotId};
    use crate::mm::PAGE_SIZE;
    use crate::syscall::current_tcb;

    let mmio_idx = tf.arg(0) as u32;
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

    let (mmio_phys, mmio_size, mmio_flags, mmio_rights, cspace_id, orig_obj_ptr) = {
        // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
        let slot =
            unsafe { super::lookup_cap(caller_cspace, mmio_idx, CapTag::MmioRegion, Rights::MAP) }?;
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed MmioRegion; pointer is valid MmioRegionObject.
        #[allow(clippy::cast_ptr_alignment)]
        let mo = unsafe { &*(obj_ptr.as_ptr().cast::<MmioRegionObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (mo.base, mo.size, mo.flags, slot.rights, cspace_id, obj_ptr)
    };

    // split_offset must be strictly within [1, mmio_size).
    if split_offset >= mmio_size
    {
        return Err(SyscallError::InvalidArgument);
    }
    // At least one page must remain on each side.
    if mmio_size - split_offset < PAGE_SIZE as u64
    {
        return Err(SyscallError::InvalidArgument);
    }

    // ── Create two child MmioRegionObjects ────────────────────────────────────
    //
    // Both wrapper bodies live in the kernel SEED Frame cap; their
    // `header.ancestor` points at SEED so dealloc returns the bytes via
    // `retype_free`.

    // child1: [base, base + split_offset).
    let child1_ptr = alloc_in_seed(MmioRegionObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::MmioRegion, seed_header_nn()),
        base: mmio_phys,
        size: split_offset,
        flags: mmio_flags,
        _pad: 0,
    })?;

    // child2: [base + split_offset, end).
    let child2_ptr = match alloc_in_seed(MmioRegionObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::MmioRegion, seed_header_nn()),
        base: mmio_phys + split_offset,
        size: mmio_size - split_offset,
        flags: mmio_flags,
        _pad: 0,
    })
    {
        Ok(p) => p,
        Err(e) =>
        {
            // SAFETY: child1_ptr is a freshly-allocated SEED-backed body
            // with refcount 1 and not yet inserted into any CSpace.
            unsafe { dealloc_object(child1_ptr) };
            return Err(e);
        }
    };

    // Insert both children into the caller's CSpace (auto-allocate slots).
    // SAFETY: caller_cspace validated non-null; CSpace methods handle slot allocation.
    let cs = unsafe { &mut *caller_cspace };
    let slot1_nz = cs
        .insert_cap(CapTag::MmioRegion, mmio_rights, child1_ptr)
        .map_err(|_| SyscallError::OutOfMemory)?;
    let slot1 = slot1_nz.get();
    let slot2_nz = cs
        .insert_cap(CapTag::MmioRegion, mmio_rights, child2_ptr)
        .map_err(|_| {
            // Undo slot1 insertion on failure.
            cs.free_slot(slot1);
            // SAFETY: child1_ptr just allocated above; ref count is 1.
            unsafe { dealloc_object(child1_ptr) };
            SyscallError::OutOfMemory
        })?;
    let slot2 = slot2_nz.get();

    // ── Wire derivation tree ──────────────────────────────────────────────────
    //
    // Pattern mirrors sys_frame_split: reparent original's children to its
    // parent, unlink original, then link both new caps to that same parent.

    let mmio_idx_nz =
        core::num::NonZeroU32::new(mmio_idx).ok_or(SyscallError::InvalidCapability)?;

    DERIVATION_LOCK.write_lock();

    let orig_node = SlotId::new(cspace_id, mmio_idx_nz);
    let child1_id = SlotId::new(cspace_id, slot1_nz);
    let child2_id = SlotId::new(cspace_id, slot2_nz);

    // Read the original's parent before we modify anything.
    // SAFETY: caller_cspace validated; mmio_idx within CSpace bounds.
    let orig_parent = unsafe { (*caller_cspace).slot(mmio_idx).and_then(|s| s.deriv_parent) };

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

    // Return original slot to free list (tag becomes Null).
    // SAFETY: caller_cspace validated; mmio_idx within CSpace bounds.
    unsafe { (*caller_cspace).free_slot(mmio_idx) };

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

#[cfg(test)]
pub fn sys_mmio_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IRQ_SPLIT ───────────────────────────────────────────────────────────

/// `SYS_IRQ_SPLIT` (49): split an `Interrupt` range cap into two non-overlapping children.
///
/// arg0 = `Interrupt` cap index (must have SIGNAL right).
/// arg1 = `split_at` IRQ id. Must satisfy `start < split_at < start + count`.
///        The lower child covers `[start, split_at)`; the upper child covers
///        `[split_at, start + count)`.
///
/// Consumes the original cap and creates two new `Interrupt` caps with the
/// same rights, covering the two halves. Both children are reparented to the
/// original's derivation parent.
///
/// Returns `slot1 | (slot2 << 32)` on success.
// too_many_lines: mirrors sys_mmio_split exactly; the shape is unavoidable.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_irq_split(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::derivation::{DERIVATION_LOCK, link_child, reparent_children, unlink_node};
    use crate::cap::object::{InterruptObject, KernelObjectHeader, ObjectType, dealloc_object};
    use crate::cap::retype::alloc_in_seed;
    use crate::cap::seed_header_nn;
    use crate::cap::slot::{CapTag, Rights, SlotId};
    use crate::syscall::current_tcb;

    let irq_idx = tf.arg(0) as u32;
    let split_at = tf.arg(1) as u32;
    // arg2 reserved.

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

    let (start, count, rights, cspace_id, orig_obj_ptr) = {
        // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
        let slot = unsafe {
            super::lookup_cap(caller_cspace, irq_idx, CapTag::Interrupt, Rights::SIGNAL)
        }?;
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Interrupt; pointer is valid InterruptObject.
        #[allow(clippy::cast_ptr_alignment)]
        let io = unsafe { &*(obj_ptr.as_ptr().cast::<InterruptObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (io.start, io.count, slot.rights, cspace_id, obj_ptr)
    };

    // ── Validation ────────────────────────────────────────────────────────────

    // split_at must lie strictly inside the cap's range.
    if split_at <= start || split_at >= start.saturating_add(count)
    {
        return Err(SyscallError::InvalidArgument);
    }

    // ── Create two child InterruptObjects ─────────────────────────────────────

    let lower_count = split_at - start;
    let upper_count = count - lower_count;

    // Both wrapper bodies live in the kernel SEED Frame cap; their
    // `header.ancestor` points at SEED so dealloc returns the bytes via
    // `retype_free`.

    let child1_ptr = alloc_in_seed(InterruptObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::Interrupt, seed_header_nn()),
        start,
        count: lower_count,
    })?;

    let child2_ptr = match alloc_in_seed(InterruptObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::Interrupt, seed_header_nn()),
        start: split_at,
        count: upper_count,
    })
    {
        Ok(p) => p,
        Err(e) =>
        {
            // SAFETY: child1_ptr is a freshly-allocated SEED-backed body
            // with refcount 1 and not yet inserted into any CSpace.
            unsafe { dealloc_object(child1_ptr) };
            return Err(e);
        }
    };

    // Insert both children into the caller's CSpace.
    // SAFETY: caller_cspace validated non-null; CSpace methods handle slot allocation.
    let cs = unsafe { &mut *caller_cspace };
    let slot1_nz = cs
        .insert_cap(CapTag::Interrupt, rights, child1_ptr)
        .map_err(|_| SyscallError::OutOfMemory)?;
    let slot1 = slot1_nz.get();
    let slot2_nz = cs
        .insert_cap(CapTag::Interrupt, rights, child2_ptr)
        .map_err(|_| {
            cs.free_slot(slot1);
            // SAFETY: child1_ptr just allocated above; ref count is 1.
            unsafe { dealloc_object(child1_ptr) };
            SyscallError::OutOfMemory
        })?;
    let slot2 = slot2_nz.get();

    // ── Wire derivation tree ──────────────────────────────────────────────────

    let irq_idx_nz = core::num::NonZeroU32::new(irq_idx).ok_or(SyscallError::InvalidCapability)?;

    DERIVATION_LOCK.write_lock();

    let orig_node = SlotId::new(cspace_id, irq_idx_nz);
    let child1_id = SlotId::new(cspace_id, slot1_nz);
    let child2_id = SlotId::new(cspace_id, slot2_nz);

    // SAFETY: caller_cspace validated; irq_idx within CSpace bounds.
    let orig_parent = unsafe { (*caller_cspace).slot(irq_idx).and_then(|s| s.deriv_parent) };

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

    // SAFETY: caller_cspace validated; irq_idx within CSpace bounds.
    unsafe { (*caller_cspace).free_slot(irq_idx) };

    // SAFETY: orig_obj_ptr from lookup_cap; object still valid (ref > 0 at lookup).
    let remaining = unsafe { (*orig_obj_ptr.as_ptr()).dec_ref() };
    if remaining == 0
    {
        // SAFETY: ref count reached zero; no other references exist.
        unsafe { dealloc_object(orig_obj_ptr) };
    }

    Ok(u64::from(slot1) | (u64::from(slot2) << 32))
}

#[cfg(test)]
pub fn sys_irq_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}
