// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/hw.rs

//! Hardware access syscall handlers.
//!
//! Implements:
//! - `SYS_IRQ_ACK` (29): acknowledge an interrupt line through its binding.
//! - `SYS_IRQ_REGISTER` (30): bind a Notification to an interrupt line.
//! - `SYS_MMIO_MAP` (34): map an MMIO region into an address space.
//! - `SYS_IOPORT_BIND` (35): bind an I/O port range to a thread (`x86_64` only).
//! - `SYS_MMIO_SPLIT` (45): split an `Mmio` cap into two sub-regions.
//! - `SYS_IRQ_SPLIT` (49): split an `Interrupt` range cap into two sub-ranges.
//! - `SYS_IOPORT_SPLIT` (51): split an `IoPort` cap into two sub-ranges
//!   (`x86_64` only).
//! - `SYS_IRQ_MSG_ALLOC` (62): mint a message-signaled `Interrupt` cap.
//! - `SYS_IRQ_ROUTE` (63): route a wired line at its controller.
//! - `SYS_IRQ_REMAP` (64): switch the kernel's interrupt formats to an
//!   IOMMU's interrupt remapping.
//!
//! # Adding new hardware syscalls
//! 1. Define the `SYS_*` number in `abi/syscall/src/lib.rs`.
//! 2. Add a new `pub fn sys_*` handler in this file.
//! 3. Import the constant in `core/kernel/src/syscall/mod.rs`.
//! 4. Add a dispatch arm in `core/kernel/src/syscall/mod.rs`.
//! 5. Add a userspace wrapper in `shared/syscall/src/lib.rs`.

#![cfg_attr(
    not(test),
    expect(
        clippy::cast_possible_truncation,
        reason = "user-supplied u64 trap-frame args are narrowed to the ABI's u32 IRQ ids, keeping \
                  the low 32 bits (upper bits are discarded). The remaining narrowings (u64->usize \
                  on 64-bit targets, the IoPort u32->u16 halves) are lossless or range-checked \
                  beside the cast; the casts are in the cfg(not(test)) handlers, so the lint fires \
                  outside the host test build alone"
    )
)]

#[cfg(not(test))]
use super::UserFrame;
// The host-test stubs keep the arch frame type in their signatures.
#[cfg(test)]
use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

// ── SYS_IRQ_ACK ───────────────────────────────────────────────────────────────

/// `SYS_IRQ_ACK` (29): acknowledge an interrupt line after the driver has
/// handled the interrupt.
///
/// arg0 = Interrupt cap index (must have NOTIFY right).
///
/// Clears the acknowledgement the cap's own binding owes and unmasks the line
/// at the interrupt controller, allowing the next delivery, once no binding on
/// the line owes one (`irq::ack`). Repeating it, or acknowledging with no
/// delivery since the last acknowledgement, clears nothing; through a cap whose
/// object is not bound it changes nothing. The driver must call this after
/// clearing the interrupt source in the device to avoid an interrupt storm.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_irq_ack(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::InterruptObject;
    use crate::cap::slot::IrqRights;
    use crate::syscall::current_tcb;

    let irq_cap_idx = tf.arg(0);

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
    let obj = irq_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: tag confirmed Interrupt; the object is an InterruptObject
    // constructed in place at a size-class-aligned retype offset, and
    // `irq_slot`'s pin keeps it live for this call.
    let io = unsafe { &*obj.as_ptr().cast::<InterruptObject>() };
    if io.count != 1
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Clear this binding's debt, and unmask the line once none owes
    // (`irq::ack` does both under the routing lock).
    // SAFETY: syscall context, not interrupt context, with no IPC source,
    // scheduler, or sleep-list lock held; `io` is live and its line is
    // `io.start`.
    unsafe { crate::irq::ack(io.start, &io.binding) };

    Ok(0)
}

#[cfg(test)]
pub fn sys_irq_ack(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IRQ_REGISTER ─────────────────────────────────────────────────────────

/// `SYS_IRQ_REGISTER` (30): bind a Notification to an interrupt line or a
/// message-signaled target.
///
/// arg0 = Interrupt cap index (must have NOTIFY right).
/// arg1 = Notification cap index (must have NOTIFY right).
/// arg2 = the line's mode (`IRQ_MODE_LEVEL`, `IRQ_MODE_ACTIVE_LOW`; 0 is
///        edge-triggered, active-high): the mode the line is routed in
///        (`SYS_IRQ_ROUTE`; `irq` module doc § Mode). A message-signaled
///        target takes mode 0 only.
///
/// Binds the cap's own object (each copy of an Interrupt cap is an object of
/// its own) to the Notification; a line holds one binding per bound object, up
/// to `irq::MAX_IRQ_BINDINGS`. Through an object already bound, rebinds it to
/// the new Notification (`irq::register`).
///
/// When the interrupt fires:
/// 1. The IRQ is masked at the controller.
/// 2. Every binding on the line owes an acknowledgement.
/// 3. Bit 0 is `ORed` into each bound Notification, and any thread blocked on
///    `SYS_NOTIFICATION_WAIT` for it is woken.
/// 4. Each driver calls `SYS_IRQ_ACK`; the line is unmasked once none owes.
///
/// A wired line is bound only once routed (`SYS_IRQ_ROUTE`), which gave it its
/// target and left it masked; a binding masks the line, which stays masked
/// until that binding's first ACK. The route lasts while a holder object or a
/// binding remains, so the line's target does not move while a driver
/// rebinds it.
///
/// A message-signaled target (`SYS_IRQ_MSG_ALLOC`) was given its CPU and slot
/// at its mint and is never masked: it takes one binding, which receives every
/// message the device sends, and `SYS_IRQ_ACK` on it changes nothing.
///
/// Returns 0 on success; `InvalidArgument` for an id outside
/// `MIN_IRQ_ID..=MAX_IRQ_ID` or past every line the discovered controllers
/// implement (past the routing table), a mode with a bit outside
/// `IRQ_MODE_MASK`, a mode other than the one the line is routed in, or a mode
/// other than 0 for a message-signaled target; `InvalidState` for a line not
/// routed, which an id within those bounds that no controller implements (an
/// x86-64 GSI between two I/O APICs' ranges) never is;
/// `QuotaExceeded` when the line already holds `MAX_IRQ_BINDINGS` bindings,
/// the message-signaled target is already bound, or the Notification holds as
/// many references as it may.
///
/// A bound binding holds a reference on its Notification, so the Notification
/// lives as long as a binding names it: deleting its capabilities does not
/// unbind it. A binding lasts until its Interrupt capability rebinds or is
/// deleted.
#[cfg(not(test))]
pub fn sys_irq_register(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{InterruptObject, NotificationObject};
    use crate::cap::slot::{IrqRights, NtfRights};
    use crate::syscall::current_tcb;

    let irq_cap_idx = tf.arg(0);
    let sig_cap_idx = tf.arg(1);
    let mode = tf.arg(2);
    if mode & !syscall::IRQ_MODE_MASK != 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "IRQ_MODE_MASK is two bits, so a mode that passed the check fits a u32"
    )]
    let mode = mode as u32;

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
    let irq_obj = irq_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: tag confirmed Interrupt; the object is an InterruptObject
    // constructed in place at a size-class-aligned retype offset, and
    // `irq_slot`'s pin keeps it live for this call.
    let io = unsafe { &*irq_obj.as_ptr().cast::<InterruptObject>() };
    if io.count != 1
    {
        // Range caps must be narrowed via SYS_IRQ_SPLIT before register.
        return Err(SyscallError::InvalidArgument);
    }
    let irq_id = io.start;
    // The root Interrupt cap spans the controller's whole id space
    // (`ROOT_IRQ_COUNT`); refuse an id outside the routable range here, and
    // `irq::register` refuses a line no discovered controller implements. A
    // message-signaled target's id lies past that space (`irq::MESSAGE_ID_BASE`)
    // and only `SYS_IRQ_MSG_ALLOC` makes a cap naming one.
    if !crate::irq::is_message(irq_id)
        && !(crate::arch::current::MIN_IRQ_ID..=crate::arch::current::MAX_IRQ_ID).contains(&irq_id)
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Resolve Notification cap.
    // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
    // rejects a null cspace and checks tag and rights.
    let sig_slot = unsafe { super::lookup_cap(cspace, sig_cap_idx, NtfRights::NOTIFY) }?;
    let sig_obj = sig_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: tag confirmed Notification; the object is a NotificationObject
    // constructed in place at a size-class-aligned retype offset.
    let sig_state = unsafe { (*sig_obj.as_ptr().cast::<NotificationObject>()).state };

    // Bind the cap's object to the notification, on a line routed by
    // SYS_IRQ_ROUTE, under the table's routing lock; the line is masked until
    // the driver acknowledges (SYS_IRQ_ACK) after registering. The binding
    // takes a reference on the Notification object.
    // SAFETY: syscall context, no IPC source, scheduler, or sleep-list lock held;
    // sig_state is the live state of `sig_obj`, which `sig_slot`'s pin keeps
    // live for the call; `io` is live, its line is `irq_id`, and its dealloc
    // arm unbinds it (`irq::unregister`) before it is freed.
    let replaced = unsafe { crate::irq::register(irq_id, &io.binding, sig_state, sig_obj, mode) }
        .map_err(|e| match e
    {
        crate::irq::RouteError::NoSuchLine | crate::irq::RouteError::ModeMismatch =>
        {
            SyscallError::InvalidArgument
        }
        crate::irq::RouteError::Exhausted
        | crate::irq::RouteError::TooManyBindings
        | crate::irq::RouteError::ReferenceLimit => SyscallError::QuotaExceeded,
        crate::irq::RouteError::NotRouted => SyscallError::InvalidState,
    })?;

    // A rebind gave up the reference its binding held on the Notification it
    // replaced; no delivery can reach that Notification any more.
    if let Some(old) = replaced
    {
        // SAFETY: the binding's reference, handed over by `register`; syscall
        // context with no lock held.
        unsafe { crate::cap::object::release_ref(old) };
    }

    Ok(0)
}

#[cfg(test)]
pub fn sys_irq_register(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IRQ_MSG_ALLOC ────────────────────────────────────────────────────────

/// `SYS_IRQ_MSG_ALLOC` (62): mint one message-signaled `Interrupt` capability.
///
/// arg0 = `Interrupt` cap handle carrying `RIGHTS_IRQ_MINT` (the authority).
///
/// Takes a free slot (an x86-64 device vector, a RISC-V IMSIC identity) of the
/// next CPU in turn with one (`irq::alloc_message`), whose entry anchors the new
/// target, and whose CPU and slot give the target's id, past every wired line.
/// The target's state is the lineage root of the new capability's `Interrupt`
/// object, which the caller's `CSpace` funds; the kernel keeps nothing else per
/// target. Inserts into the caller's `CSpace` an `Interrupt` capability over
/// that one id, unbound, carrying `RIGHTS_IRQ_NOTIFY` only, as a derivation
/// child of the authority, so a revoke of the authority reaches it. The holder
/// reads the message its device writes through `SYS_CAP_INFO`
/// (`CAP_INFO_IRQ_MSG_ADDRESS`, `CAP_INFO_IRQ_MSG_DATA`), programs it into the
/// device, and binds the capability with `SYS_IRQ_REGISTER` (mode 0). The
/// target's slot is freed, and its object's bytes returned, once neither the
/// capability nor any copy of it remains.
///
/// One target per call; a caller needing K targets calls K times.
///
/// Returns the new cap handle; `InvalidCapability` for a handle that names no
/// `Interrupt` cap; `InsufficientRights` when it lacks `RIGHTS_IRQ_MINT`;
/// `QuotaExceeded` when no CPU a message can reach has a free slot;
/// `OutOfMemory` when the caller's arena cannot fund the object, which a
/// refill of its pool cures; `InvalidState` when the authority's slot is
/// pinned by an in-flight revoke, move, or transfer; and the error of a full
/// `CSpace`.
#[cfg(not(test))]
pub fn sys_irq_msg_alloc(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{InterruptObject, arena_of, release_ref};
    use crate::cap::slot::{CapTag, IrqRights, SlotId};
    use crate::syscall::current_tcb;

    let authority_handle = tf.arg(0);

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
    // SAFETY: caller_cspace validated non-null above.
    let cspace_id = unsafe { (*caller_cspace).id() };

    // `authority` pins the authority's object for the call, so the object the
    // revalidation below compares against stays live.
    // SAFETY: caller_cspace is the running thread's bound CSpace; lookup_cap
    // checks tag and rights; no lock held.
    let authority = unsafe { super::lookup_cap(caller_cspace, authority_handle, IrqRights::MINT) }?;
    let authority_object = authority.object.ok_or(SyscallError::InvalidCapability)?;
    let authority_idx = core::num::NonZeroU32::new(syscall::cap_handle_index(authority_handle))
        .ok_or(SyscallError::InvalidCapability)?;

    // The caller's CSpace funds the object from its arena
    // (core/kernel/docs/capability-internals.md § Body Arena).
    // SAFETY: caller_cspace is the running thread's own CSpace, live while the
    // thread runs.
    let funder = unsafe { arena_of(caller_cspace) }?;
    let id = crate::irq::alloc_message().map_err(|_| SyscallError::QuotaExceeded)?;
    let object = match funder.alloc_body(InterruptObject::new_root(id, 1))
    {
        Ok(object) => object,
        Err(e) =>
        {
            // SAFETY: syscall context with no lock held; no object names `id`.
            unsafe { crate::irq::free_message(id) };
            return Err(e);
        }
    };
    // From here the object owns the target: its release frees it (the
    // Interrupt arm of `dealloc_object`).

    // Revalidate the authority, then insert and link, under one
    // DERIVATION_LOCK hold, as `SYS_CAP_DERIVE` does: a link under a parent a
    // concurrent delete, move, or revoke freed would leave the new cap outside
    // every ancestor's revoke reach.
    crate::cap::DERIVATION_LOCK.write_lock();
    // SAFETY: caller_cspace validated non-null above; DERIVATION_LOCK held.
    if let Err(e) = unsafe {
        super::cap::revalidate_src_under_lock(caller_cspace, authority_handle, authority_object)
    }
    {
        crate::cap::DERIVATION_LOCK.write_unlock();
        // SAFETY: the object's only reference, published nowhere; syscall
        // context with no lock held.
        unsafe { release_ref(object) };
        return Err(e);
    }
    // SAFETY: caller_cspace validated non-null above; it is the running
    // thread's own CSpace, live while the thread runs.
    let lock = unsafe { &(*caller_cspace).lock };
    // SAFETY: lock_raw pairs with the unlock_raw below.
    let saved = unsafe { lock.lock_raw() };
    // SAFETY: caller_cspace is live (as above), and its held lock serialises
    // the slot freelist and tags.
    let insert_res = unsafe {
        (*caller_cspace).insert_cap_slot_and_handle(
            CapTag::Interrupt,
            IrqRights::NOTIFY.erase(),
            object,
        )
    };
    // SAFETY: caller_cspace is live (as above).
    let lock = unsafe { &(*caller_cspace).lock };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(saved) };
    let (new_idx, new_handle) = match insert_res
    {
        Ok(v) => v,
        Err(e) =>
        {
            crate::cap::DERIVATION_LOCK.write_unlock();
            // SAFETY: as above.
            unsafe { release_ref(object) };
            return Err(SyscallError::from(e));
        }
    };
    let parent = SlotId::current(cspace_id, authority_idx);
    let child = SlotId::current(cspace_id, new_idx);
    // SAFETY: DERIVATION_LOCK held; the parent revalidated and the child was
    // inserted under this hold, so both ends resolve.
    let linked = unsafe { crate::cap::derivation::link_child(parent, child) };
    debug_assert!(linked, "derivation link dropped under DERIVATION_LOCK");
    crate::cap::DERIVATION_LOCK.write_unlock();
    drop(authority);
    Ok(new_handle)
}

#[cfg(test)]
pub fn sys_irq_msg_alloc(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IRQ_ROUTE ────────────────────────────────────────────────────────────

/// `SYS_IRQ_ROUTE` (63): route a wired interrupt line at its controller.
///
/// arg0 = single-line `Interrupt` cap handle carrying `RIGHTS_IRQ_MINT`.
/// arg1 = the line's mode (`IRQ_MODE_LEVEL`, `IRQ_MODE_ACTIVE_LOW`; 0 is
///        edge-triggered, active-high).
///
/// A line not routed is routed in the mode, masked, to the next CPU in turn
/// with a free delivery slot: on `x86_64` the GSI is given a device IDT vector
/// and its I/O APIC redirection entry is programmed, in the compatibility
/// format or, with interrupt remapping on (`SYS_IRQ_REMAP`), the remappable
/// one naming the vector's handle; on RISC-V the APLIC source is given a
/// target hart and an identity in that hart's IMSIC file. The cap's object
/// becomes the route's holder. A line routed in the same mode gains the
/// object as a holder too; through an object that holds the route already
/// the call changes nothing (`irq::route`).
///
/// The route, and so the line's target, lasts until neither a holder object
/// nor a binding (`SYS_IRQ_REGISTER`) remains: a holder object holds it until
/// it is deleted or revoked. devmgr routes each line it hands out, so the
/// IOMMU driver can write the line's remapping entry
/// (`CAP_INFO_IRQ_REMAP_ENTRY`) before a driver binds and unmasks it, and
/// the line's target does not move while a driver rebinds it.
///
/// Returns 0 on success; `InvalidCapability` for a handle that names no
/// `Interrupt` cap; `InsufficientRights` when it lacks `RIGHTS_IRQ_MINT`;
/// `InvalidArgument` for a range cap, a message-signaled target, an id no
/// discovered controller implements, a mode with a bit outside
/// `IRQ_MODE_MASK`, or a mode other than the one the line is routed in;
/// `QuotaExceeded` when no eligible CPU has a free delivery slot, or the line
/// holds as many holders as it may.
#[cfg(not(test))]
pub fn sys_irq_route(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::InterruptObject;
    use crate::cap::slot::IrqRights;
    use crate::syscall::current_tcb;

    let irq_cap_idx = tf.arg(0);
    let mode = tf.arg(1);
    if mode & !syscall::IRQ_MODE_MASK != 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "IRQ_MODE_MASK is two bits, so a mode that passed the check fits a u32"
    )]
    let mode = mode as u32;

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
    let irq_slot = unsafe { super::lookup_cap(cspace, irq_cap_idx, IrqRights::MINT) }?;
    let irq_obj = irq_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: tag confirmed Interrupt; the object is an InterruptObject
    // constructed in place at a size-class-aligned retype offset, and
    // `irq_slot`'s pin keeps it live for this call.
    let io = unsafe { &*irq_obj.as_ptr().cast::<InterruptObject>() };
    if io.count != 1
        || crate::irq::is_message(io.start)
        || !(crate::arch::current::MIN_IRQ_ID..=crate::arch::current::MAX_IRQ_ID)
            .contains(&io.start)
    {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: syscall context, no IPC source, scheduler, or sleep-list lock
    // held; `io` is live, its line is `io.start`, and its dealloc arm calls
    // `irq::drop_route_holder` when the flag is set.
    unsafe { crate::irq::route(io.start, &io.route_held, mode) }.map_err(|e| match e
    {
        crate::irq::RouteError::NoSuchLine | crate::irq::RouteError::ModeMismatch =>
        {
            SyscallError::InvalidArgument
        }
        crate::irq::RouteError::Exhausted
        | crate::irq::RouteError::TooManyBindings
        | crate::irq::RouteError::ReferenceLimit => SyscallError::QuotaExceeded,
        // `route` does not return it; a line it refuses is no line.
        crate::irq::RouteError::NotRouted => SyscallError::InvalidState,
    })?;
    Ok(0)
}

#[cfg(test)]
pub fn sys_irq_route(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── SYS_IRQ_REMAP ────────────────────────────────────────────────────────────

/// `SYS_IRQ_REMAP` (64): switch the formats the kernel hands out to an IOMMU's
/// interrupt remapping.
///
/// arg0 = `Interrupt` cap handle carrying `RIGHTS_IRQ_MINT`.
/// arg1 = `IRQ_REMAP_OFF`, `IRQ_REMAP_ON`, or `IRQ_REMAP_ON_EXTENDED`.
///
/// With remapping off, an I/O APIC entry and a message name their CPU and
/// vector in the compatibility formats. With it on, each names the handle of
/// the remapping entry its vector's CPU and vector own (`CAP_INFO_IRQ_REMAP_ENTRY`),
/// whose entry the IOMMU driver writes; `IRQ_REMAP_ON` places sources only on
/// CPUs whose APIC id fits 8 bits, `IRQ_REMAP_ON_EXTENDED` on any CPU with
/// handles. devmgr turns remapping on once the IOMMU driver has enabled the
/// remapping table, before it routes a line or mints a target.
///
/// Returns 0 on success; `InvalidCapability` for a handle that names no
/// `Interrupt` cap; `InsufficientRights` when it lacks `RIGHTS_IRQ_MINT`;
/// `InvalidArgument` for another setting; `InvalidState` while a line is
/// routed or a message-signaled target is minted (`irq::set_remap`);
/// `NotSupported` on an architecture with no interrupt remapping the kernel
/// programs (riscv64).
#[cfg(not(test))]
pub fn sys_irq_remap(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::IrqRights;
    use crate::irq::Remap;
    use crate::syscall::current_tcb;

    let remap = match tf.arg(1)
    {
        syscall::IRQ_REMAP_OFF => Remap::Off,
        syscall::IRQ_REMAP_ON => Remap::On { extended: false },
        syscall::IRQ_REMAP_ON_EXTENDED => Remap::On { extended: true },
        _ => return Err(SyscallError::InvalidArgument),
    };

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
    let authority = unsafe { super::lookup_cap(cspace, tf.arg(0), IrqRights::MINT) }?;

    crate::irq::set_remap(remap).map_err(|e| match e
    {
        crate::irq::RemapError::State => SyscallError::InvalidState,
        crate::irq::RemapError::NotSupported => SyscallError::NotSupported,
    })?;
    drop(authority);
    Ok(0)
}

#[cfg(test)]
pub fn sys_irq_remap(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
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
/// with TLB shootdown (docs/capability-model.md § Mmio). A record past the
/// object's `MMIO_INLINE_MAPPINGS` inline ones is a spill chunk from the
/// caller's `CSpace` arena; the map returns `OutOfMemory` when that arena
/// cannot fund one.
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
    use crate::mm::paging::{LeafGrant, PageFlags};
    use crate::syscall::current_tcb;

    const PAGE_BYTES: u64 = PAGE_SIZE as u64;

    let aspace_idx = tf.arg(0);
    let mmio_idx = tf.arg(1);

    let virt_base = tf.arg(2);
    let flags = tf.arg(3);
    // The base is page-aligned and in the user range, above `USER_VA_FLOOR`;
    // the whole range is checked once the region's size is known.
    crate::mm::check_user_base(virt_base)?;

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
    let mmio_obj = mmio_slot
        .object
        .ok_or(SyscallError::InvalidCapability)?
        .as_ptr()
        .cast::<MmioObject>();
    // SAFETY: `mmio_slot` pins the MmioObject for the whole call.
    let mmio_phys = unsafe { (*mmio_obj).base };
    // SAFETY: `mmio_slot` pins the MmioObject for the whole call.
    let mmio_size = unsafe { (*mmio_obj).size };

    // Size must be at least one page and page-aligned.
    if mmio_size == 0 || mmio_size & 0xFFF != 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // The range lies wholly in the user range, checked before the mapping is
    // recorded, so a refusal changes nothing.
    let page_count = (mmio_size / PAGE_BYTES) as usize;
    let virt_end = crate::mm::user_range_end(virt_base, page_count)?;
    // The region's physical end. A device region the kernel provisioned
    // cannot pass the end of the address space; the check refuses one that
    // would rather than wrap it.
    let mmio_end = mmio_phys
        .checked_add(mmio_size)
        .ok_or(SyscallError::InvalidArgument)?;

    // Resolve AddressSpace cap.
    // SAFETY: cspace is the current thread's CSpace pointer from its TCB; lookup_cap
    // rejects a null cspace and checks tag and rights.
    let as_slot = unsafe { super::lookup_cap(cspace, aspace_idx, AsRights::MAP) }?;
    let (as_ptr, aso_raw) = {
        let obj = as_slot.object.ok_or(SyscallError::InvalidCapability)?;
        let aso = obj.as_ptr().cast::<AddressSpaceObject>();
        // SAFETY: tag confirmed AddressSpace; aso is a valid AddressSpaceObject.
        let as_inner = unsafe { (*aso).address_space };
        (as_inner, aso)
    };

    // MMIO mappings are never executable.
    // Writability is derived from the cap's WRITE right, not the flags arg.
    // The flags arg is reserved for future use (cache mode overrides, etc.).
    // The leaf's grant is the same rights, so no SYS_MEM_PROTECT makes a
    // device page writable without WRITE, or executable at all.
    let writable = mmio_slot.rights.contains(MmioRights::WRITE.erase());
    let _ = flags; // reserved
    let page_flags = PageFlags {
        readable: true,
        writable,
        executable: false,
        uncacheable: true,
    };
    let grant = LeafGrant::of(page_flags);

    // Intermediate PT pages come from the address space's own caller-funded
    // pool, as in sys_mem_map; the kernel page-table pool is never drawn on
    // (`core/kernel/docs/memory-internals.md` § Page Table Node Ownership).
    // SAFETY: aso_raw is non-null and valid for the lifetime of the cap.
    unsafe { (*aso_raw).require_create_donation() }?;

    // Record the mapping before mapping a page, so the object's teardown
    // finds every page this call maps, including after a partial failure.
    // SAFETY: `mmio_slot` pins the Mmio object for the whole call.
    let mmio = unsafe { &*mmio_obj };
    // A record past the object's inline ones is funded by the caller's CSpace
    // (core/kernel/docs/capability-internals.md § Mmio Mappings).
    let new_spill = || {
        // SAFETY: cspace is the caller's own CSpace, live while it runs.
        unsafe { crate::cap::object::arena_of(cspace) }?.alloc_mmio_spill()
    };
    // SAFETY: `as_slot` pins the address space object aso_raw for the whole
    // call, and `mmio_slot` pins this object; a spill chunk is a fresh one
    // from the caller's arena.
    unsafe { mmio.record_mapping(aso_raw, virt_base, new_spill) }?;

    // Map each page.
    let virts = (virt_base..virt_end).step_by(PAGE_SIZE);
    let frames = (mmio_phys..mmio_end).step_by(PAGE_SIZE);
    for (virt, phys) in virts.zip(frames)
    {
        // SAFETY: as_ptr is the AddressSpace of the AddressSpaceObject
        // `as_slot` pins for the call.
        let aspace = unsafe { &*as_ptr };
        // SAFETY: aso_raw is the AddressSpaceObject `as_slot` pins for the
        // call.
        let aso = unsafe { &*aso_raw };
        // SAFETY: virt in user range (validated above); phys is a 4 KiB-aligned
        // frame of a kernel-provisioned Mmio boot object; aso wraps aspace,
        // both resolved from the same capability.
        unsafe { aspace.map_page_pooled(virt, phys, page_flags, grant, aso) }
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
/// arg1 = `IoPort` cap index (must have USE right).
///
/// On first bind, a per-thread port-binding table (`cap::ioport_bindings`: the
/// 8 KiB IOPB bitmap in page-sized parts, all ports denied, and the record of
/// each binding) is taken from the pool of the target thread's own `CSpace`,
/// three pages in all. The bind records the `IoPort` object it is
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
        use crate::cap::ioport_bindings::IoPortBindings;
        use crate::cap::object::{IoPortObject, ThreadObject};
        use crate::cap::slot::{IoPortRights, ThreadRights};
        use crate::syscall::current_tcb;

        let thread_idx = tf.arg(0);
        let ioport_idx = tf.arg(1);

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
            unsafe { (*obj.as_ptr().cast::<ThreadObject>()).tcb }
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
            // SAFETY: tag confirmed IoPort; the object is an IoPortObject built in
            // place (from SEED at boot, or from an arena by a split or a copy).
            let po = unsafe { &*obj.as_ptr().cast::<IoPortObject>() };
            (obj.as_ptr() as usize, u32::from(po.base), po.port_count())
        };

        // The per-thread binding table is allocated on the first bind from
        // the pool of the target thread's own CSpace
        // (core/kernel/docs/capability-internals.md § IoPort Bindings) and
        // returned there on thread dealloc via the Thread arm of
        // `dealloc_object`, or by that CSpace's teardown, whichever comes
        // first. The pointer and the table's bytes are owned by the target's
        // `sched_lock` (core/kernel/docs/scheduling-internals.md § Cross-CPU
        // TCB Ownership, Address-space / capability row), which `schedule()`
        // also holds when it loads the bitmap into a CPU's TSS. The table is
        // allocated and installed inside that lock, with the thread not yet
        // `Exited`: the CSpace's teardown marks its threads `Exited` and then
        // frees their tables, each under the same lock, so a table installed
        // here is one that teardown frees, and its pool is live while it is
        // taken.
        // SAFETY: target_tcb validated non-null, and `th_slot` pins its
        // Thread object for the call.
        let lock = unsafe { &(*target_tcb).sched_lock };
        // SAFETY: lock_raw pairs with the unlock_raw on each path below;
        // interrupts stay disabled between.
        let saved = unsafe { lock.lock_raw() };
        // SAFETY: target_tcb is live (as above), and its held sched_lock owns
        // `state`.
        let exited = unsafe { (*target_tcb).state } == crate::sched::thread::ThreadState::Exited;
        let bound = if exited || {
            // SAFETY: target_tcb is live (as above); `cspace` is set at
            // creation and read-only after it.
            unsafe { (*target_tcb).cspace }.is_null()
        }
        {
            Err(SyscallError::InvalidCapability)
        }
        else
        {
            // SAFETY: target_tcb is live (as above), and its held sched_lock
            // owns `iopb`, which is null or the bitmap of a live table
            // installed by a bind.
            let mut table = unsafe { (*target_tcb).iopb }.cast::<IoPortBindings>();
            if table.is_null()
            {
                // SAFETY: target_tcb is live (as above); `cspace` is set at
                // creation and read-only after it.
                let target_cspace = unsafe { (*target_tcb).cspace };
                // SAFETY: target_cspace is the bound CSpace of a thread that
                // is not Exited (checked above) and whose sched_lock is held,
                // so it stays live while the reference is used.
                match unsafe { crate::cap::object::arena_of(target_cspace) }
                    .and_then(crate::cap::object::alloc_port_binding_table)
                {
                    Ok(fresh) =>
                    {
                        // SAFETY: target_tcb is live (as above), and its held
                        // sched_lock owns `iopb`.
                        unsafe {
                            (*target_tcb).iopb = fresh.cast::<crate::arch::current::ThreadIopb>();
                        }
                        table = fresh;
                    }
                    Err(e) =>
                    {
                        // SAFETY: target_tcb is live (as above).
                        let lock = unsafe { &(*target_tcb).sched_lock };
                        // SAFETY: paired with the lock_raw above.
                        unsafe { lock.unlock_raw(saved) };
                        return Err(e);
                    }
                }
            }
            // SAFETY: table is the live binding table installed in `iopb`,
            // whose bytes the held sched_lock owns.
            let r = unsafe { (*table).bind(port_object, port_base, port_count) }
                .map_err(|_| SyscallError::QuotaExceeded);
            // Binding the running thread: reload this CPU's TSS IOPB so in/out
            // instructions work without a context switch.
            if r.is_ok() && target_tcb == caller_tcb
            {
                // SAFETY: table is live, its bytes owned by the held sched_lock.
                let bitmap = unsafe { &(*table).bitmap };
                // SAFETY: interrupts are disabled by the held sched_lock;
                // syscall context, so GS-base names this CPU's PerCpuData with
                // its TSS; the bitmap's parts are live and no other CPU writes
                // them while the thread's sched_lock is held.
                unsafe { gdt::load_iopb(Some(bitmap)) };
            }
            r
        };
        // SAFETY: target_tcb is live (as above).
        let lock = unsafe { &(*target_tcb).sched_lock };
        // SAFETY: paired with the lock_raw above.
        unsafe { lock.unlock_raw(saved) };

        bound?;
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
#[cfg(not(test))]
pub fn sys_mmio_split(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{MmioObject, dealloc_object};
    use crate::cap::slot::{CapTag, MmioRights};
    use crate::cap::split::install_split_children;
    use crate::mm::PAGE_SIZE;
    use crate::syscall::current_tcb;

    let mmio_handle = tf.arg(0);
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

    // split_offset must be strictly within [1, mmio_size), with at least one
    // page on each side. The upper child's base lies inside the region, which
    // cannot pass the end of the address space; the check refuses a base that
    // would rather than wrap it.
    let (upper_base, upper_size) = mmio_size
        .checked_sub(split_offset)
        .filter(|&rest| rest >= PAGE_SIZE as u64)
        .zip(mmio_phys.checked_add(split_offset))
        .map(|(rest, base)| (base, rest))
        .ok_or(SyscallError::InvalidArgument)?;

    // ── Create two child MmioObjects ────────────────────────────────────
    //
    // child1: [base, base + split_offset).
    // The caller's CSpace, which receives both children, funds their
    // bodies from its arena (core/kernel/docs/capability-internals.md
    // § Body Arena); dealloc returns each chunk there.
    // SAFETY: caller_cspace is the running thread's own CSpace, live
    // while the thread runs.
    let funder = unsafe { crate::cap::object::arena_of(caller_cspace) }?;
    let child1_ptr =
        funder.alloc_body(MmioObject::new_root(mmio_phys, split_offset, mmio_flags))?;

    // child2: [base + split_offset, end).
    let child2_ptr = match funder
        .alloc_body(MmioObject::new_root(upper_base, upper_size, mmio_flags))
    {
        Ok(p) => p,
        Err(e) =>
        {
            // SAFETY: child1_ptr is a freshly-allocated arena-backed body
            // with refcount 1 and not yet inserted into any CSpace.
            unsafe { dealloc_object(child1_ptr) };
            return Err(e);
        }
    };

    // Install both children, rewire the derivation tree, and consume the
    // original — shared with the other range splits.
    // SAFETY: caller_cspace validated non-null; cspace_id is its id; both
    // children are freshly-allocated arena-backed MmioObjects (refcount 1);
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
    tf.set_ipc_return(handle1, handle2);
    Ok(handle1)
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
#[cfg(not(test))]
pub fn sys_irq_split(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{InterruptObject, dealloc_object};
    use crate::cap::slot::{CapTag, IrqRights};
    use crate::cap::split::install_split_children;
    use crate::syscall::current_tcb;

    let irq_handle = tf.arg(0);
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
        let io = unsafe { &*(obj_ptr.as_ptr().cast::<InterruptObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (io.start, io.count, slot.rights, cspace_id, obj_ptr, slot)
    };

    // ── Validation ────────────────────────────────────────────────────────────

    // split_at must lie strictly inside the cap's range.
    let (lower_count, upper_count) =
        split_counts(start, count, split_at).ok_or(SyscallError::InvalidArgument)?;

    // ── Create two child InterruptObjects ─────────────────────────────────────

    // The caller's CSpace, which receives both children, funds their
    // bodies from its arena (core/kernel/docs/capability-internals.md
    // § Body Arena); dealloc returns each chunk there.
    // SAFETY: caller_cspace is the running thread's own CSpace, live
    // while the thread runs.
    let funder = unsafe { crate::cap::object::arena_of(caller_cspace) }?;
    let child1_ptr = funder.alloc_body(InterruptObject::new_root(start, lower_count))?;

    let child2_ptr = match funder.alloc_body(InterruptObject::new_root(split_at, upper_count))
    {
        Ok(p) => p,
        Err(e) =>
        {
            // SAFETY: child1_ptr is a freshly-allocated arena-backed body
            // with refcount 1 and not yet inserted into any CSpace.
            unsafe { dealloc_object(child1_ptr) };
            return Err(e);
        }
    };

    // Install both children, rewire the derivation tree, and consume the
    // original — shared with the other range splits.
    // SAFETY: caller_cspace validated non-null; cspace_id is its id; both
    // children are freshly-allocated arena-backed InterruptObjects (refcount 1);
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
    tf.set_ipc_return(handle1, handle2);
    Ok(handle1)
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
        use crate::cap::slot::{CapTag, IoPortRights};
        use crate::cap::split::install_split_children;
        use crate::syscall::current_tcb;

        let port_handle = tf.arg(0);
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
        // split_at must lie strictly inside the cap's range.
        let (lower_count, upper_count) = split_counts(u32::from(base), effective_size, split_at)
            .ok_or(SyscallError::InvalidArgument)?;

        // ── Create two child IoPortObjects ─────────────────────────────
        //
        // Both halves are guaranteed u16-representable because each holds at
        // least one port and the range at most 65536: neither half can be the
        // full 65536, since the split is strict.

        let lower_count: u16 = lower_count as u16;
        let upper_count: u16 = upper_count as u16;
        let split_at_u16: u16 = split_at as u16;

        // The caller's CSpace, which receives both children, funds their
        // bodies from its arena (core/kernel/docs/capability-internals.md
        // § Body Arena); dealloc returns each chunk there.
        // SAFETY: caller_cspace is the running thread's own CSpace, live
        // while the thread runs.
        let funder = unsafe { crate::cap::object::arena_of(caller_cspace) }?;
        let child1_ptr = funder.alloc_body(IoPortObject::new_root(base, lower_count))?;

        let child2_ptr = match funder.alloc_body(IoPortObject::new_root(split_at_u16, upper_count))
        {
            Ok(p) => p,
            Err(e) =>
            {
                // SAFETY: child1_ptr is a freshly-allocated arena-backed body
                // with refcount 1 and not yet inserted into any CSpace.
                unsafe { dealloc_object(child1_ptr) };
                return Err(e);
            }
        };

        // Install both children, rewire the derivation tree, and consume the
        // original — shared with the other range splits.
        // SAFETY: caller_cspace validated non-null; cspace_id is its id; both
        // children are freshly-allocated arena-backed IoPortObjects (refcount 1);
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
        tf.set_ipc_return(handle1, handle2);
        Ok(handle1)
    }
}

#[cfg(test)]
pub fn sys_ioport_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

// ── Range splits ─────────────────────────────────────────────────────────────

/// The counts of the two halves of the id range `[start, start + count)` split
/// at `split_at`, lower half first, or `None` unless `split_at` lies strictly
/// inside the range, so that each half holds at least one id. Shared by
/// `SYS_IRQ_SPLIT` and `SYS_IOPORT_SPLIT`.
const fn split_counts(start: u32, count: u32, split_at: u32) -> Option<(u32, u32)>
{
    let Some(lower) = split_at.checked_sub(start)
    else
    {
        return None;
    };
    match count.checked_sub(lower)
    {
        Some(upper) if lower > 0 && upper > 0 => Some((lower, upper)),
        _ => None,
    }
}

#[cfg(test)]
mod tests
{
    use super::split_counts;

    // Defect guarded: halves computed from the wrong end, or a full-port-space
    // range whose end passes the u16 ports, would mint children that do not
    // cover the parent exactly.
    #[test]
    fn split_counts_divides_a_range_at_an_inner_id()
    {
        assert_eq!(split_counts(32, 16, 33), Some((1, 15)));
        assert_eq!(split_counts(32, 16, 47), Some((15, 1)));
        // The full I/O port space, as `SYS_IOPORT_SPLIT` passes it.
        assert_eq!(split_counts(0, 65536, 0xFFFF), Some((0xFFFF, 1)));
    }

    // Defect guarded: a split point on or outside the range accepted, which
    // would mint an empty child or one whose count wrapped.
    #[test]
    fn split_counts_refuses_a_split_on_or_outside_the_range()
    {
        // At the start or the end: one half would be empty.
        assert_eq!(split_counts(32, 16, 32), None);
        assert_eq!(split_counts(32, 16, 48), None);
        // Below the start, where the lower count would underflow.
        assert_eq!(split_counts(32, 16, 0), None);
        // Past the end, where the upper count would underflow.
        assert_eq!(split_counts(32, 16, u32::MAX), None);
        // A single id has no inner split point.
        assert_eq!(split_counts(7, 1, 7), None);
        assert_eq!(split_counts(7, 1, 8), None);
    }
}
