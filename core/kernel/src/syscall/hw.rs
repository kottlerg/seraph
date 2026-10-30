// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/hw.rs

//! Hardware access syscall handlers.
//!
//! Implements:
//! - `SYS_IRQ_ACK` (29): re-enable a masked interrupt line.
//! - `SYS_IRQ_REGISTER` (30): bind a Notification to an interrupt line.
//! - `SYS_MMIO_MAP` (34): map an MMIO region into an address space.
//! - `SYS_IOPORT_BIND` (35): bind an I/O port range to a thread (`x86_64` only).
//! - `SYS_MMIO_SPLIT` (45): split an `Mmio` cap into two sub-regions.
//! - `SYS_IRQ_SPLIT` (49): split an `Interrupt` range cap into two sub-ranges.
//! - `SYS_IOPORT_SPLIT` (51): split an `IoPort` cap into two sub-ranges
//!   (`x86_64` only).
//!
//! # Adding new hardware syscalls
//! 1. Define the `SYS_*` number in `abi/syscall/src/lib.rs`.
//! 2. Add a new `pub fn sys_*` handler in this file.
//! 3. Import the constant in `core/kernel/src/syscall/mod.rs`.
//! 4. Add a dispatch arm in `core/kernel/src/syscall/mod.rs`.
//! 5. Add a userspace wrapper in `shared/syscall/src/lib.rs`.

// cast_possible_truncation: user-supplied u64 trap-frame args are narrowed to the
// ABI's u32 capability handles and IRQ ids, keeping the low 32 bits (upper bits
// are discarded). The remaining narrowings (u64->usize on 64-bit targets, the
// IoPort u32->u16 halves) are lossless or range-checked beside the cast.
#![allow(clippy::cast_possible_truncation)]

#[cfg(not(test))]
use super::UserFrame;
// The host-test stubs keep the arch frame type in their signatures.
#[cfg(test)]
use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

// ── SYS_IRQ_ACK ───────────────────────────────────────────────────────────────

/// `SYS_IRQ_ACK` (29): re-enable an interrupt line after the driver has handled
/// the interrupt.
///
/// arg0 = Interrupt cap index (must have NOTIFY right).
///
/// Unmasks the IRQ line at the interrupt controller, allowing the next
/// interrupt delivery, when a notification is registered on it; a line with
/// no registration stays masked. The driver must call this after clearing the
/// interrupt source in the device to avoid an interrupt storm.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_irq_ack(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::InterruptObject;
    use crate::cap::slot::IrqRights;
    use crate::syscall::current_tcb;

    let irq_cap_idx = tf.arg(0) as u32;

    // SAFETY: syscall (kernel) context after sched::init; current_tcb() returns this
    // CPU's current thread.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let cspace = unsafe { (*tcb).cspace };

    // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
    // rejects a null cspace and checks tag and rights.
    let irq_slot = unsafe { super::lookup_cap(cspace, irq_cap_idx, IrqRights::NOTIFY) }?;
    let irq_id = {
        let obj = irq_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Interrupt; the object is an InterruptObject
        // constructed in place at a size-class-aligned retype offset.
        #[allow(clippy::cast_ptr_alignment)]
        let io = unsafe { &*obj.as_ptr().cast::<InterruptObject>() };
        if io.count != 1
        {
            return Err(SyscallError::InvalidArgument);
        }
        io.start
    };

    // Unmask at the interrupt controller to re-enable delivery, if the line is
    // routed (`irq::ack` checks and unmasks under the routing lock).
    // SAFETY: syscall context, not interrupt context, with no IPC source,
    // scheduler, or sleep-list lock held.
    unsafe { crate::irq::ack(irq_id) };

    Ok(0)
}

#[cfg(test)]
pub fn sys_irq_ack(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IRQ_REGISTER ─────────────────────────────────────────────────────────

/// `SYS_IRQ_REGISTER` (30): bind a Notification to an interrupt line.
///
/// arg0 = Interrupt cap index (must have NOTIFY right).
/// arg1 = Notification cap index (must have NOTIFY right).
///
/// When the interrupt fires:
/// 1. The IRQ is masked at the controller.
/// 2. Bit 0 is `ORed` into the Notification.
/// 3. Any thread blocked on `SYS_NOTIFICATION_WAIT` for this notification is woken.
/// 4. The driver must call `SYS_IRQ_ACK` to re-enable delivery.
///
/// On `x86_64`: assigns the GSI a device IDT vector and programs its IOAPIC
/// redirection entry (masked until first ACK). On RISC-V: assigns the PLIC
/// source a target hart (masked at the controller until first ACK).
///
/// Returns 0 on success; `InvalidArgument` for an id no discovered controller
/// implements, `QuotaExceeded` when the controller has no delivery resource left
/// (x86-64: every device vector assigned).
#[cfg(not(test))]
pub fn sys_irq_register(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{InterruptObject, NotificationObject};
    use crate::cap::slot::{IrqRights, NtfRights};
    use crate::syscall::current_tcb;

    let irq_cap_idx = tf.arg(0) as u32;
    let sig_cap_idx = tf.arg(1) as u32;

    // SAFETY: syscall (kernel) context after sched::init; current_tcb() returns this
    // CPU's current thread.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let cspace = unsafe { (*tcb).cspace };

    // Resolve Interrupt cap.
    // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
    // rejects a null cspace and checks tag and rights.
    let irq_slot = unsafe { super::lookup_cap(cspace, irq_cap_idx, IrqRights::NOTIFY) }?;
    let irq_id = {
        let obj = irq_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Interrupt; the object is an InterruptObject
        // constructed in place at a size-class-aligned retype offset.
        #[allow(clippy::cast_ptr_alignment)]
        let io = unsafe { &*obj.as_ptr().cast::<InterruptObject>() };
        if io.count != 1
        {
            // Range caps must be narrowed via SYS_IRQ_SPLIT before register.
            return Err(SyscallError::InvalidArgument);
        }
        io.start
    };
    // The root Interrupt cap spans the controller's whole id space
    // (`ROOT_IRQ_COUNT`); refuse an id outside the routable range here, and
    // `irq::register` refuses a line no discovered controller implements.
    if !(crate::arch::current::MIN_IRQ_ID..=crate::arch::current::MAX_IRQ_ID).contains(&irq_id)
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Resolve Notification cap.
    // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
    // rejects a null cspace and checks tag and rights.
    let sig_slot = unsafe { super::lookup_cap(cspace, sig_cap_idx, NtfRights::NOTIFY) }?;
    let sig_state = {
        let obj = sig_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Notification; the object is a NotificationObject
        // constructed in place at a size-class-aligned retype offset.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            (*obj.as_ptr().cast::<NotificationObject>()).state
        }
    };

    // Route the line at its controller (left masked: the x86_64 IOAPIC
    // redirection entry, the RISC-V PLIC source; the driver unmasks via
    // SYS_IRQ_ACK after registering) and record the notification in the IRQ
    // routing table, both under the table's routing lock.
    // SAFETY: syscall context, no IPC source, scheduler, or sleep-list lock held;
    // sig_state is the live state of the Notification cap resolved above.
    unsafe { crate::irq::register(irq_id, sig_state) }.map_err(|e| match e
    {
        crate::irq::RouteError::NoSuchLine => SyscallError::InvalidArgument,
        crate::irq::RouteError::Exhausted => SyscallError::QuotaExceeded,
    })?;

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
/// arg1 = `Mmio` cap index (must have MAP right).
/// arg2 = virtual base address (page-aligned, user half).
/// arg3 = flags (reserved; ignored). Writability comes from the `Mmio` cap's
/// WRITE right; mappings are never executable.
///
/// All pages are mapped with `uncacheable = true` (PCD|PWT on `x86_64`,
/// Svpbmt PBMT=IO on RISC-V — see [`PageFlags`]).
///
/// The `Mmio` object records the mapping, holding a reference on the address
/// space, before any page is mapped; freeing the object (its capability
/// deleted, consumed by a split, or revoked through an ancestor) unmaps it,
/// with TLB shootdown (docs/capability-model.md § Mmio). Returns
/// `QuotaExceeded` when the object already records `MMIO_MAX_MAPPINGS` other
/// mappings.
///
/// Intermediate page-table pages come from the target AS's PT growth pool;
/// the map fails with `OutOfMemory` when that pool is exhausted, so a caller
/// mapping a large region augments it first via `SYS_CAP_CREATE_ASPACE`
/// augment-mode (see `core/kernel/docs/memory-internals.md` § Page Table
/// Node Ownership).
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_mmio_map(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{AddressSpaceObject, MmioObject};
    use crate::cap::slot::{AsRights, MmioRights};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::PageFlags;
    use crate::syscall::current_tcb;

    // Virtual address must be page-aligned and in user half.
    let user_va_top = crate::mm::user_va_top();
    let aspace_idx = tf.arg(0) as u32;
    let mmio_idx = tf.arg(1) as u32;

    let virt_base = tf.arg(2);
    let flags = tf.arg(3);
    if virt_base & 0xFFF != 0 || virt_base >= user_va_top
    {
        return Err(SyscallError::InvalidAddress);
    }

    // SAFETY: syscall (kernel) context after sched::init; current_tcb() returns this
    // CPU's current thread.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let cspace = unsafe { (*tcb).cspace };

    // Resolve Mmio cap.
    // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
    // rejects a null cspace and checks tag and rights.
    let mmio_slot = unsafe { super::lookup_cap(cspace, mmio_idx, MmioRights::MAP) }?;
    // cast_ptr_alignment: tag confirmed Mmio; the MmioObject is constructed in
    // place at a size-class-aligned retype offset, header at offset 0.
    #[allow(clippy::cast_ptr_alignment)]
    let mmio_obj = mmio_slot
        .object
        .ok_or(SyscallError::InvalidCapability)?
        .as_ptr()
        .cast::<MmioObject>();
    // SAFETY: `mmio_slot` pins the MmioObject for the whole call.
    let (mmio_phys, mmio_size) = unsafe { ((*mmio_obj).base, (*mmio_obj).size) };

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
    if virt_end > user_va_top
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Resolve AddressSpace cap.
    // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
    // rejects a null cspace and checks tag and rights.
    let as_slot = unsafe { super::lookup_cap(cspace, aspace_idx, AsRights::MAP) }?;
    let (as_ptr, aso_raw) = {
        let obj = as_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let aso = obj.as_ptr().cast::<AddressSpaceObject>();
        // SAFETY: tag confirmed AddressSpace; aso is a valid AddressSpaceObject.
        let as_inner = unsafe { (*aso).address_space };
        (as_inner, aso)
    };

    // MMIO mappings are never executable.
    // Writability is derived from the cap's WRITE right, not the flags arg.
    // The flags arg is reserved for future use (cache mode overrides, etc.).
    let writable = mmio_slot.rights.contains(MmioRights::WRITE.erase());
    let _ = flags; // reserved
    let page_flags = PageFlags {
        readable: true,
        writable,
        executable: false,
        uncacheable: true,
    };

    // Choose the PT-page source, mirroring sys_mem_map. An AS that recorded
    // its create-time donation pulls intermediate PT pages from its own
    // caller-funded growth pool; one without falls back to the kernel PT
    // pool.
    // SAFETY: aso_raw is non-null and valid for the lifetime of the cap.
    let pooled = unsafe { (*aso_raw).pt_pool.has_create_donation() };

    // Record the mapping before mapping a page, so the object's teardown
    // finds every page this call maps, including after a partial failure.
    // SAFETY: `mmio_slot` pins the Mmio object and `as_slot` the address
    // space for the whole call.
    unsafe { (*mmio_obj).record_mapping(aso_raw, virt_base) }?;

    // Map each page.
    for i in 0..page_count
    {
        let virt = virt_base + (i * PAGE_SIZE) as u64;
        let phys = mmio_phys + (i * PAGE_SIZE) as u64;

        // SAFETY: virt in user range (validated above); phys from a
        // kernel-provisioned Mmio boot object. Pooled vs kernel-direct
        // dispatch is chosen once above from whether the AS records a
        // donation.
        let result = if pooled
        {
            // SAFETY: aso_raw is valid; it wraps as_ptr.
            unsafe { (*as_ptr).map_page_pooled(virt, phys, page_flags, &*aso_raw) }
        }
        else
        {
            // SAFETY: AS without a recorded donation; map_page acquires
            // pt_lock and the kernel page-table pool lock internally.
            unsafe { (*as_ptr).map_page(virt, phys, page_flags) }
        };
        result.map_err(|()| SyscallError::OutOfMemory)?;
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
/// arg1 = `IoPort` cap index (must have USE right).
///
/// On first bind, a per-thread port-binding table (`cap::ioport_bindings`: the
/// 8 KiB IOPB bitmap, all ports denied, and the record of each binding) is
/// carved from the SEED Memory cap. The bind records the `IoPort` object it is
/// made through and clears the range's bits (0 = allowed); freeing that object
/// withdraws the binding (docs/capability-model.md § `IoPort`). On context
/// switch the bitmap is copied into the TSS IOPB region. The install and the
/// edit run under the target's `sched_lock`, which the context-switch load
/// also holds, so concurrent binds on one thread accumulate their permits and
/// leak no table.
///
/// On RISC-V: always returns `NotSupported` (no I/O port concept).
///
/// Returns 0 on success; `QuotaExceeded` when the thread already records
/// `MAX_IOPORT_BINDINGS` bindings through other objects.
#[cfg(not(test))]
pub fn sys_ioport_bind(tf: UserFrame) -> Result<u64, SyscallError>
{
    // RISC-V has no I/O port space; the IOPB machinery below is x86-64-only.
    if !crate::arch::current::HAS_IO_PORTS
    {
        return Err(SyscallError::NotSupported);
    }

    {
        use crate::arch::current::gdt;
        use crate::cap::ioport_bindings::{IoPortBindings, TABLE_BYTES};
        use crate::cap::object::{IoPortObject, ThreadObject};
        use crate::cap::slot::{IoPortRights, ThreadRights};
        use crate::syscall::current_tcb;

        let thread_idx = tf.arg(0) as u32;
        let ioport_idx = tf.arg(1) as u32;

        // SAFETY: syscall (kernel) context after sched::init; current_tcb() returns this
        // CPU's current thread.
        let caller_tcb = unsafe { current_tcb() };
        if caller_tcb.is_null()
        {
            return Err(SyscallError::InvalidCapability);
        }
        // SAFETY: tcb validated non-null; cspace set at thread creation.
        let cspace = unsafe { (*caller_tcb).cspace };

        // Resolve Thread cap.
        // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
        // rejects a null cspace and checks tag and rights.
        let th_slot = unsafe { super::lookup_cap(cspace, thread_idx, ThreadRights::CONTROL) }?;
        let target_tcb = {
            let obj = th_slot.object.ok_or(SyscallError::InvalidCapability)?;
            // SAFETY: tag confirmed Thread; the object is a ThreadObject
            // constructed in place at a size-class-aligned retype offset.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                (*obj.as_ptr().cast::<ThreadObject>()).tcb
            }
        };
        if target_tcb.is_null()
        {
            return Err(SyscallError::InvalidCapability);
        }

        // Resolve IoPort cap.
        // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
        // rejects a null cspace and checks tag and rights.
        // `port_slot` pins the IoPort object for the rest of the call, so its
        // teardown, which withdraws the bindings recorded against it, cannot
        // run before the record below is in place.
        let port_slot = unsafe { super::lookup_cap(cspace, ioport_idx, IoPortRights::USE) }?;
        let (port_object, port_base, port_count) = {
            let obj = port_slot.object.ok_or(SyscallError::InvalidCapability)?;
            // SAFETY: tag confirmed IoPort; the object is an IoPortObject retyped in
            // place from the SEED reserve (at boot, by a split, or by a copy).
            #[allow(clippy::cast_ptr_alignment)]
            let po = unsafe { &*obj.as_ptr().cast::<IoPortObject>() };
            (obj.as_ptr() as usize, u32::from(po.base), po.port_count())
        };

        // The per-thread binding table is allocated on first bind from the
        // kernel SEED Memory cap and freed back to SEED on thread dealloc via
        // the Thread arm of `dealloc_object`. The pointer and the table's bytes
        // are owned by the target's `sched_lock`
        // (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership,
        // Address-space / capability row), which `schedule()` also holds when
        // it loads the bitmap into a CPU's TSS. The SEED allocation is not made
        // under that lock: a first bind peeks under it, allocates outside it,
        // and installs under it only if the slot is still empty; a concurrent
        // bind that installed first wins, and the loser's block goes back to
        // SEED.
        // SAFETY: target_tcb validated non-null; lock_raw/unlock_raw paired.
        let needs_iopb = unsafe {
            let saved = (*target_tcb).sched_lock.lock_raw();
            let empty = (*target_tcb).iopb.is_null();
            (*target_tcb).sched_lock.unlock_raw(saved);
            empty
        };
        let mut fresh: *mut IoPortBindings = core::ptr::null_mut();
        if needs_iopb
        {
            let raw = crate::cap::retype::alloc_seed_scratch(TABLE_BYTES)?;
            // cast_ptr_alignment: a page-class SEED scratch block is page-aligned,
            // which satisfies the table's alignment.
            #[allow(clippy::cast_ptr_alignment)]
            {
                fresh = raw.cast::<IoPortBindings>();
            }
            // SAFETY: fresh points at a freshly-carved TABLE_BYTES block in
            // SEED's region, page-aligned and not aliased.
            unsafe { IoPortBindings::init_in_place(fresh) };
        }

        // SAFETY: target_tcb validated non-null; under its sched_lock, iopb is
        // null or the bitmap of a live table installed by a bind, and `fresh`
        // (when non-null) is ours alone; lock_raw/unlock_raw paired, interrupts
        // disabled between.
        let bound = unsafe {
            let saved = (*target_tcb).sched_lock.lock_raw();
            if (*target_tcb).iopb.is_null() && !fresh.is_null()
            {
                (*target_tcb).iopb = fresh.cast::<[u8; gdt::IOPB_SIZE]>();
                fresh = core::ptr::null_mut();
            }
            // cast_ptr_alignment: a non-null `iopb` heads a page-aligned
            // IoPortBindings block (the allocation above or an earlier bind's).
            #[allow(clippy::cast_ptr_alignment)]
            let table = (*target_tcb).iopb.cast::<IoPortBindings>();
            let bound = if table.is_null()
            {
                Ok(())
            }
            else
            {
                let r = (*table).bind(port_object, port_base, port_count);
                // Binding the running thread: reload this CPU's TSS IOPB so in/out
                // instructions work without a context switch.
                if r.is_ok() && target_tcb == caller_tcb
                {
                    gdt::load_iopb(Some(&(*table).bitmap));
                }
                r
            };
            (*target_tcb).sched_lock.unlock_raw(saved);
            bound
        };

        // A concurrent bind installed its table first: return ours to SEED.
        if !fresh.is_null()
        {
            crate::cap::retype::free_seed_scratch(fresh.cast::<u8>(), TABLE_BYTES);
        }

        bound.map_err(|_| SyscallError::QuotaExceeded)?;
        // A target running on another CPU loaded its bitmap before this bind:
        // invalidate every TSS so its next port access reloads the grown
        // bitmap (the lazy reload of `gdt::reload_invalidated_iopb`) instead
        // of faulting on the stale copy.
        if target_tcb != caller_tcb
        {
            gdt::invalidate_all_iopbs();
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

/// `SYS_MMIO_SPLIT` (45): split an `Mmio` cap into two non-overlapping children.
///
/// arg0 = `Mmio` cap index (must have MAP right).
/// arg1 = split offset in bytes (page-aligned; must be > 0 and < region size).
/// arg2 = reserved (ignored).
///
/// Consumes the original cap and creates two new `Mmio` caps with the same
/// rights and flags, covering `[base, base+split_offset)` and
/// `[base+split_offset, end)`. Both children are reparented to the original
/// cap's derivation parent (same revocability semantics as sibling caps).
///
/// Returns the two child handles in the primary and secondary return
/// registers.
// too_many_lines: splitting an MMIO cap requires validating the original,
// building two child objects, wiring both into the derivation tree, and
// freeing the original — each step has its own bookkeeping and no meaningful
// split-point between them.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_mmio_split(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{MmioObject, dealloc_object};
    use crate::cap::retype::alloc_in_seed;
    use crate::cap::slot::{CapTag, MmioRights};
    use crate::cap::split::install_split_children;
    use crate::mm::PAGE_SIZE;
    use crate::syscall::current_tcb;

    let mmio_handle = tf.arg(0) as u32;
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

    // SAFETY: syscall (kernel) context after sched::init; current_tcb() returns this
    // CPU's current thread.
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

    // `_orig_pin` keeps the original pinned until the split has consumed it,
    // so the object the split revalidates under the derivation lock is live.
    let (mmio_phys, mmio_size, mmio_flags, mmio_rights, cspace_id, orig_obj_ptr, _orig_pin) = {
        // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
        let slot = unsafe { super::lookup_cap(caller_cspace, mmio_handle, MmioRights::MAP) }?;
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Mmio; pointer is valid MmioObject.
        // cast_ptr_alignment: the MmioObject is constructed in place at a
        // size-class-aligned retype offset.
        #[allow(clippy::cast_ptr_alignment)]
        let mo = unsafe { &*(obj_ptr.as_ptr().cast::<MmioObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (
            mo.base,
            mo.size,
            mo.flags,
            slot.rights,
            cspace_id,
            obj_ptr,
            slot,
        )
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

    // ── Create two child MmioObjects ────────────────────────────────────
    //
    // Both wrapper bodies live in the kernel SEED Memory cap; their
    // `header.ancestor` points at SEED so dealloc returns the bytes via
    // `retype_free`.

    // child1: [base, base + split_offset).
    let child1_ptr = alloc_in_seed(MmioObject::new_root(mmio_phys, split_offset, mmio_flags))?;

    // child2: [base + split_offset, end).
    let child2_ptr = match alloc_in_seed(MmioObject::new_root(
        mmio_phys + split_offset,
        mmio_size - split_offset,
        mmio_flags,
    ))
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

    // Install both children, rewire the derivation tree, and consume the
    // original — shared with the other range splits.
    // SAFETY: caller_cspace validated non-null; cspace_id is its id; both
    // children are freshly-allocated SEED-backed MmioObjects (refcount 1);
    // orig_obj_ptr is the live original from lookup_cap.
    let (handle1, handle2) = unsafe {
        install_split_children(
            caller_cspace,
            cspace_id,
            mmio_handle,
            CapTag::Mmio,
            mmio_rights,
            orig_obj_ptr,
            child1_ptr,
            child2_ptr,
        )
    }?;
    // Deliver both child handles: first in the primary return register, second
    // in the secondary (rdx / a1). Never packed into one word, so a high
    // generation cannot set the sign bit of the i64 return (#349).
    tf.set_ipc_return(u64::from(handle1), u64::from(handle2));
    Ok(u64::from(handle1))
}

#[cfg(test)]
pub fn sys_mmio_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IRQ_SPLIT ───────────────────────────────────────────────────────────

/// `SYS_IRQ_SPLIT` (49): split an `Interrupt` range cap into two non-overlapping children.
///
/// arg0 = `Interrupt` cap index (must have NOTIFY right).
/// arg1 = `split_at` IRQ id. Must satisfy `start < split_at < start + count`.
///        The lower child covers `[start, split_at)`; the upper child covers
///        `[split_at, start + count)`.
///
/// Consumes the original cap and creates two new `Interrupt` caps with the
/// same rights, covering the two halves. Both children are reparented to the
/// original's derivation parent.
///
/// Returns the two child handles in the primary and secondary return
/// registers.
// too_many_lines: mirrors sys_mmio_split exactly; the shape is unavoidable.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_irq_split(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{InterruptObject, KernelObjectHeader, ObjectType, dealloc_object};
    use crate::cap::retype::alloc_in_seed;
    use crate::cap::seed_header_nn;
    use crate::cap::slot::{CapTag, IrqRights};
    use crate::cap::split::install_split_children;
    use crate::syscall::current_tcb;

    let irq_handle = tf.arg(0) as u32;
    let split_at = tf.arg(1) as u32;
    // arg2 reserved.

    // ── Capability lookup ─────────────────────────────────────────────────────

    // SAFETY: syscall (kernel) context after sched::init; current_tcb() returns this
    // CPU's current thread.
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

    // `_orig_pin` keeps the original pinned until the split has consumed it,
    // so the object the split revalidates under the derivation lock is live.
    let (start, count, rights, cspace_id, orig_obj_ptr, _orig_pin) = {
        // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
        let slot = unsafe { super::lookup_cap(caller_cspace, irq_handle, IrqRights::NOTIFY) }?;
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Interrupt; pointer is valid InterruptObject.
        // cast_ptr_alignment: the InterruptObject is constructed in place at a
        // size-class-aligned retype offset.
        #[allow(clippy::cast_ptr_alignment)]
        let io = unsafe { &*(obj_ptr.as_ptr().cast::<InterruptObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (io.start, io.count, slot.rights, cspace_id, obj_ptr, slot)
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

    // Both wrapper bodies live in the kernel SEED Memory cap; their
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

    // Install both children, rewire the derivation tree, and consume the
    // original — shared with the other range splits.
    // SAFETY: caller_cspace validated non-null; cspace_id is its id; both
    // children are freshly-allocated SEED-backed InterruptObjects (refcount 1);
    // orig_obj_ptr is the live original from lookup_cap.
    let (handle1, handle2) = unsafe {
        install_split_children(
            caller_cspace,
            cspace_id,
            irq_handle,
            CapTag::Interrupt,
            rights,
            orig_obj_ptr,
            child1_ptr,
            child2_ptr,
        )
    }?;
    // Deliver both child handles: first in the primary return register, second
    // in the secondary (rdx / a1). Never packed into one word (#349).
    tf.set_ipc_return(u64::from(handle1), u64::from(handle2));
    Ok(u64::from(handle1))
}

#[cfg(test)]
pub fn sys_irq_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IOPORT_SPLIT ─────────────────────────────────────────────────────────

/// `SYS_IOPORT_SPLIT` (51): split an `IoPort` cap into two non-overlapping children.
///
/// arg0 = `IoPort` cap index (must have USE right).
/// arg1 = `split_at` port number. Must satisfy `base < split_at < base + size`
///        (with `size == 0` interpreted as full 64K range). The lower child
///        covers `[base, split_at)`; the upper child covers
///        `[split_at, base + size)`.
///
/// Consumes the original cap and creates two new `IoPort` caps with the
/// same rights, covering the two halves. Both children are reparented to the
/// original's derivation parent.
///
/// On RISC-V: always returns `NotSupported` (no I/O port concept).
///
/// Returns the two child handles in the primary and secondary return
/// registers.
// too_many_lines: mirrors sys_irq_split exactly; the shape is unavoidable.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sys_ioport_split(tf: UserFrame) -> Result<u64, SyscallError>
{
    // RISC-V has no I/O port space; the IoPort cap-split logic below is
    // x86-64-only (no IoPort capability is ever minted on RISC-V).
    if !crate::arch::current::HAS_IO_PORTS
    {
        return Err(SyscallError::NotSupported);
    }

    {
        use crate::cap::object::{IoPortObject, dealloc_object};
        use crate::cap::retype::alloc_in_seed;
        use crate::cap::slot::{CapTag, IoPortRights};
        use crate::cap::split::install_split_children;
        use crate::syscall::current_tcb;

        let port_handle = tf.arg(0) as u32;
        let split_at_raw = tf.arg(1);
        // arg2 reserved.

        // split_at must be a representable port number in [1, 65535].
        // 0 cannot be a valid split point (would yield an empty lower half).
        // 65536+ is out of range entirely.
        if split_at_raw == 0 || split_at_raw > 0xFFFF
        {
            return Err(SyscallError::InvalidArgument);
        }
        let split_at = split_at_raw as u32;

        // ── Capability lookup ────────────────────────────────────────────────

        // SAFETY: syscall (kernel) context after sched::init; current_tcb() returns this
        // CPU's current thread.
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

        // `_orig_pin` keeps the original pinned until the split has consumed
        // it, so the object the split revalidates under the derivation lock is
        // live.
        let (base, size_u16, rights, cspace_id, orig_obj_ptr, _orig_pin) = {
            // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
            let slot = unsafe { super::lookup_cap(caller_cspace, port_handle, IoPortRights::USE) }?;
            let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?;
            // SAFETY: tag confirmed IoPort; pointer is valid IoPortObject.
            // cast_ptr_alignment: the IoPortObject is constructed in place at a
            // size-class-aligned retype offset.
            #[allow(clippy::cast_ptr_alignment)]
            let po = unsafe { &*(obj_ptr.as_ptr().cast::<IoPortObject>()) };
            // SAFETY: caller_cspace validated non-null; id() reads discriminator.
            let cspace_id = unsafe { (*caller_cspace).id() };
            (po.base, po.size, slot.rights, cspace_id, obj_ptr, slot)
        };

        // ── Validation ───────────────────────────────────────────────────────

        // size == 0 encodes the full 64K range; matches sys_ioport_bind's
        // effective_size handling.
        let effective_size: u32 = if size_u16 == 0
        {
            65536
        }
        else
        {
            u32::from(size_u16)
        };
        let base_u32 = u32::from(base);
        let end = base_u32 + effective_size;

        // split_at must lie strictly inside the cap's range.
        if split_at <= base_u32 || split_at >= end
        {
            return Err(SyscallError::InvalidArgument);
        }

        // ── Create two child IoPortObjects ─────────────────────────────
        //
        // Both halves are guaranteed u16-representable because:
        //   lower_count = split_at - base_u32, where 1 <= split_at - base_u32 < 65536
        //   upper_count = end - split_at,     where 1 <= end - split_at      <= 65535
        // (Neither half can be the full 65536; the split is strict.)

        let lower_count: u16 = (split_at - base_u32) as u16;
        let upper_count: u16 = (end - split_at) as u16;
        let split_at_u16: u16 = split_at as u16;

        let child1_ptr = alloc_in_seed(IoPortObject::new_root(base, lower_count))?;

        let child2_ptr = match alloc_in_seed(IoPortObject::new_root(split_at_u16, upper_count))
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

        // Install both children, rewire the derivation tree, and consume the
        // original — shared with the other range splits.
        // SAFETY: caller_cspace validated non-null; cspace_id is its id; both
        // children are freshly-allocated SEED-backed IoPortObjects (refcount 1);
        // orig_obj_ptr is the live original from lookup_cap.
        let (handle1, handle2) = unsafe {
            install_split_children(
                caller_cspace,
                cspace_id,
                port_handle,
                CapTag::IoPort,
                rights,
                orig_obj_ptr,
                child1_ptr,
                child2_ptr,
            )
        }?;
        // Deliver both child handles: first in the primary return register,
        // second in the secondary (rdx / a1). Never packed into one word (#349).
        tf.set_ipc_return(u64::from(handle1), u64::from(handle2));
        Ok(u64::from(handle1))
    }
}

#[cfg(test)]
pub fn sys_ioport_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}
