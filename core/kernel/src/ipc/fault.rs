// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/fault.rs

//! Fault redirection — deliver a kernel-unresolvable userspace thread fault to
//! the thread's bound fault-handler endpoint and block until it is resolved.
//!
//! This is the shared, architecture-independent core of the fault-handler
//! protocol (`docs/fault-handling.md`). Two callers build a [`FaultInfo`] and
//! call [`fault_dispatch`] with the canonical [`TrapFrame`] the handler will
//! read/edit published: the architecture trap handlers (x86-64 `#PF` and the
//! other user exception vectors; RISC-V page-fault and other U-mode exception
//! causes), for `FAULT_KIND_VM` or `FAULT_KIND_EXCEPTION`, and the syscall
//! dispatcher (`syscall::deliver_copy_fault`), for the `FAULT_KIND_VM` of a
//! restartable syscall's user copy. The disposition it returns tells the
//! caller whether to resume (re-execute the faulting instruction, or the
//! syscall) or to take the unhandled outcome: a kill for a trap, the
//! syscall's `InvalidAddress` for a copy.
//!
//! A change of the binding of an in-flight delivery's class
//! ([`publish_bindings`], then [`redeliver_in_flight`], run by
//! `SYS_THREAD_SET_FAULT_HANDLER` and `SYS_THREAD_INHERIT_FAULT_HANDLER`)
//! cancels that delivery, and [`fault_dispatch`] makes it again under the
//! binding current when the faulting thread next runs; with none bound then,
//! the fault takes the unhandled outcome.
//!
//! Delivery reuses the synchronous-IPC machinery: the faulting thread takes the
//! caller role (parked in [`IpcThreadState::BlockedOnFault`] rather than
//! `BlockedOnReply`) and the handler services it with the ordinary receive /
//! reply cycle. Delivery is iterative (block + reschedule), never kernel-stack
//! recursion, so a fault chain cannot exhaust the kernel stack.
//!
//! [`TrapFrame`]: crate::arch::current::trap_frame::TrapFrame

use core::sync::atomic::Ordering;

use crate::cap::object::{EndpointObject, KernelObjectHeader};
use crate::sched::thread::{IpcThreadState, ThreadControlBlock, ThreadState};

/// [`ThreadControlBlock::fault_outcome`] value: no disposition committed yet.
pub const FAULT_OUTCOME_PENDING: u8 = 0;
/// [`ThreadControlBlock::fault_outcome`] value: resume (re-execute / continue).
pub const FAULT_OUTCOME_RESUME: u8 = 1;
/// [`ThreadControlBlock::fault_outcome`] value: unhandled with no reply
/// (handler thread destroyed, binding severed, or thread cancelled): the
/// faulting thread is killed, or its restartable syscall fails.
pub const FAULT_OUTCOME_KILL: u8 = 2;
/// [`ThreadControlBlock::fault_outcome`] value: the binding changed while the
/// delivery was in flight; [`fault_dispatch`] delivers the fault again under
/// the binding current then (docs/fault-handling.md § Delivery, Resume, and
/// Kill).
pub const FAULT_OUTCOME_REDELIVER: u8 = 3;
/// [`ThreadControlBlock::fault_outcome`] value: unhandled because the handler
/// replied [`syscall::FAULT_REPLY_KILL`]. Taken as [`FAULT_OUTCOME_KILL`] is;
/// the reply deposited its label and decline-reason word in the faulting
/// thread's `ipc_msg`, which [`fault_dispatch`] reads for [`KillCause::Declined`].
pub const FAULT_OUTCOME_DECLINED: u8 = 4;

/// [`deliver_once`]'s result when no binding was found: never a
/// `fault_outcome` value, it reports [`KillCause::BindingCleared`].
const DELIVERY_UNBOUND: u8 = u8::MAX;

/// Number of fault classes a thread binds separately
/// (docs/fault-handling.md § Fault-Handler Binding), and the length of the
/// per-class binding arrays of [`ThreadControlBlock`].
pub const FAULT_CLASSES: usize = 2;

/// Class index of virtual-memory faults ([`syscall::FAULT_CLASS_VM`]).
pub const CLASS_VM: usize = 0;

/// Class index of every other user exception
/// ([`syscall::FAULT_CLASS_EXCEPTION`]).
pub const CLASS_EXCEPTION: usize = 1;

/// The ABI class bit of each class index.
const CLASS_BITS: [u64; FAULT_CLASSES] = [syscall::FAULT_CLASS_VM, syscall::FAULT_CLASS_EXCEPTION];

/// The class index a fault of `kind` is delivered through: `FAULT_KIND_VM`
/// through [`CLASS_VM`], every other kind through [`CLASS_EXCEPTION`].
#[must_use]
pub fn class_of_kind(kind: u64) -> usize
{
    if kind == syscall::FAULT_KIND_VM
    {
        CLASS_VM
    }
    else
    {
        CLASS_EXCEPTION
    }
}

/// The classes a `fault_class_mask` selects, by class index: every class for
/// [`syscall::FAULT_CLASS_ALL`], else each class whose bit the mask sets.
/// `None` for a mask the ABI refuses: zero, or one with a bit no class
/// defines.
#[must_use]
pub fn classes_of_mask(mask: u64) -> Option<[bool; FAULT_CLASSES]>
{
    if mask == syscall::FAULT_CLASS_ALL
    {
        return Some([true; FAULT_CLASSES]);
    }
    let defined = CLASS_BITS.iter().fold(0, |acc, bit| acc | bit);
    if mask == 0 || mask & !defined != 0
    {
        return None;
    }
    Some(CLASS_BITS.map(|bit| mask & bit != 0))
}

/// The class index a mask of exactly one class bit names; `None` for any
/// other mask (zero, several bits, an undefined bit, or `FAULT_CLASS_ALL`).
#[must_use]
pub fn class_of_bit(mask: u64) -> Option<usize>
{
    CLASS_BITS.iter().position(|&bit| bit == mask)
}

/// One class's binding as published: the endpoint (null for none) and the
/// badge bound with it.
pub type Binding = (*mut EndpointObject, u64);

/// Architecture-neutral description of a fault, marshalled into the fault
/// message's data words `[kind, d1, d2, ip]`.
#[derive(Clone, Copy)]
pub struct FaultInfo
{
    /// Fault kind: [`syscall::FAULT_KIND_VM`] or [`syscall::FAULT_KIND_EXCEPTION`].
    pub kind: u64,
    /// Kind-specific word 1 (VM: faulting virtual address; exception: code).
    pub d1: u64,
    /// Kind-specific word 2 (VM: access flags; exception: arch aux code).
    pub d2: u64,
    /// Faulting instruction pointer.
    pub ip: u64,
}

/// Disposition returned by [`fault_dispatch`] to its caller, the architecture
/// fault handler or the syscall dispatcher.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FaultOutcome
{
    /// Resume the faulting thread (re-execute the faulting instruction or
    /// syscall, or continue from a handler-modified instruction pointer).
    Resume,
    /// The fault is unhandled: the architecture handler kills the faulting
    /// thread, and the syscall dispatcher fails the restartable syscall with
    /// `InvalidAddress` (docs/fault-handling.md § Reply).
    Kill(KillCause),
}

/// Why a delivered fault took the unhandled outcome, for the kill diagnostic
/// [`report_user_kill`] prints.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KillCause
{
    /// The binding was found cleared when the delivery read it.
    BindingCleared,
    /// The delivery was cancelled before any reply claimed it (handler thread
    /// destroyed, handler endpoint destroyed, a later receive on the handler
    /// thread, or a stop of the faulting thread).
    Cancelled,
    /// The handler replied [`syscall::FAULT_REPLY_KILL`], with the reason its
    /// reply's data word 0 carried, if it sent one.
    Declined(Option<u64>),
}

/// Print, on the kernel serial console, why the user-mode fault of the thread
/// whose id is `tid` went unhandled; the architecture kill path's
/// `USERSPACE FAULT` diagnostic follows it. The decline reason is the
/// handler's own value, printed verbatim; it is not interpreted here.
#[cfg(not(test))]
pub fn report_user_kill(tid: u32, cause: KillCause)
{
    match cause
    {
        KillCause::BindingCleared =>
        {
            crate::kprintln_serial!("fault unhandled: tid={tid} binding cleared before delivery");
        }
        KillCause::Cancelled =>
        {
            crate::kprintln_serial!("fault unhandled: tid={tid} delivery cancelled before a reply");
        }
        KillCause::Declined(None) =>
        {
            crate::kprintln_serial!("fault unhandled: tid={tid} handler declined");
        }
        KillCause::Declined(Some(reason)) =>
        {
            crate::kprintln_serial!(
                "fault unhandled: tid={tid} handler declined, reason={reason:#x}"
            );
        }
    }
}

/// True iff `tcb` has a fault handler bound for the class of a fault of
/// `kind` at the moment of the load.
///
/// A lock-free pre-check for the architecture handlers and the syscall
/// dispatcher: a concurrent unbind may clear the binding before
/// [`fault_dispatch`] runs, so its own load under `sched_lock` decides, and a
/// binding found cleared there takes the unhandled outcome.
///
/// # Safety
/// `tcb` must be a valid TCB pointer.
#[cfg(not(test))]
pub unsafe fn has_handler(tcb: *mut ThreadControlBlock, kind: u64) -> bool
{
    // SAFETY: tcb validated by caller; the binding fields are atomics.
    !unsafe { (*tcb).fault_handlers[class_of_kind(kind)].load(Ordering::Acquire) }.is_null()
}

/// Read `tcb`'s fault-handler binding for `class` once, pin its endpoint, and
/// open a delivery through it.
///
/// Returns the bound `EndpointObject`, with a reference the caller owns and
/// MUST release, and the badge bound with it; `None` when no handler is bound.
/// The pair is read under `tcb`'s `sched_lock`, the lock [`publish_bindings`]
/// publishes it under for both binders, so the badge is the one
/// bound with this endpoint, and the reference is taken while the binding's
/// own reference still holds the object: the binder releases the old binding's
/// reference only after it unlocks.
///
/// With a binding found, the same hold arms the in-flight markers:
/// `fault_outcome = Pending`, so a stale prior disposition cannot be mistaken
/// for this fault's (the single wake-claim winner overwrites it), and
/// `in_fault_delivery`, so a dequeuing `endpoint_recv` parks the thread
/// `BlockedOnFault` (not `BlockedOnReply`), with `fault_delivery_class`
/// naming the class. All are written under the lock the binding is, so a
/// binder finds in its own hold whether a delivery through the binding it
/// replaces is in flight ([`delivery_in_flight`]).
///
/// # Safety
/// `tcb` must be the current CPU's running thread, with no lock held;
/// `class < FAULT_CLASSES`.
#[cfg(not(test))]
unsafe fn pin_binding(
    tcb: *mut ThreadControlBlock,
    class: usize,
) -> Option<(core::ptr::NonNull<EndpointObject>, u64)>
{
    // SAFETY: tcb is the running thread (contract); lock_raw is paired with
    // the unlock_raw below. A non-null fault_handlers entry read under
    // sched_lock names an endpoint the binding references, so it is live for
    // inc_ref.
    // The markers are this thread's own until its delivery makes it
    // wakeable.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let ep = core::ptr::NonNull::new((*tcb).fault_handlers[class].load(Ordering::Acquire));
        let badge = (*tcb).fault_badges[class].load(Ordering::Relaxed);
        if let Some(ep) = ep
        {
            ep.as_ref().header.inc_ref();
            (*tcb)
                .fault_outcome
                .store(FAULT_OUTCOME_PENDING, Ordering::Release);
            (*tcb).in_fault_delivery = true;
            // cast_possible_truncation: class < FAULT_CLASSES (2).
            #[allow(clippy::cast_possible_truncation)]
            {
                (*tcb).fault_delivery_class = class as u8;
            }
        }
        (*tcb).sched_lock.unlock_raw(saved);
        ep.map(|ep| (ep, badge))
    }
}

/// Whether a fault delivery through `tcb`'s binding for `class` is in
/// flight: opened by [`pin_binding`] and given no disposition yet by a wake
/// claim.
///
/// # Safety
/// `tcb` must be a valid TCB whose `sched_lock` the caller holds.
#[cfg(not(test))]
pub unsafe fn delivery_in_flight(tcb: *mut ThreadControlBlock, class: usize) -> bool
{
    // SAFETY: the caller holds tcb.sched_lock, under which in_fault_delivery
    // and fault_delivery_class are written; fault_outcome is atomic.
    unsafe {
        (*tcb).in_fault_delivery
            && usize::from((*tcb).fault_delivery_class) == class
            && (*tcb).fault_outcome.load(Ordering::Acquire) == FAULT_OUTCOME_PENDING
    }
}

/// Read `tcb`'s bindings for the `selected` classes once, under its
/// `sched_lock`, each endpoint with a reference the caller owns and MUST
/// release (or hand to [`publish_bindings`]); an unselected or unbound
/// class reads `(null, 0)`. The reference is taken while the binding's own
/// still holds the object, as [`pin_binding`] takes its own.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins; the caller holds no lock.
#[cfg(not(test))]
pub unsafe fn pin_bindings(
    tcb: *mut ThreadControlBlock,
    selected: [bool; FAULT_CLASSES],
) -> [Binding; FAULT_CLASSES]
{
    let mut out: [Binding; FAULT_CLASSES] = [(core::ptr::null_mut(), 0); FAULT_CLASSES];
    // SAFETY: tcb valid per contract; lock_raw paired with unlock_raw. A
    // non-null endpoint read under sched_lock is held by the binding's
    // reference, so it is live for inc_ref.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        for (class, slot) in out.iter_mut().enumerate()
        {
            if !selected[class]
            {
                continue;
            }
            let ep = (*tcb).fault_handlers[class].load(Ordering::Acquire);
            if !ep.is_null()
            {
                (*ep).header.inc_ref();
                *slot = (ep, (*tcb).fault_badges[class].load(Ordering::Relaxed));
            }
        }
        (*tcb).sched_lock.unlock_raw(saved);
    }
    out
}

/// Publish `new[class]` as `tcb`'s binding for each `selected` class, in one
/// hold of its `sched_lock`, the lock [`pin_binding`] reads a binding under.
/// Each published endpoint's reference passes from the caller to the
/// binding. Returns the replaced endpoints, whose references pass to the
/// caller to release outside every lock (null for an unselected or unbound
/// class), and the class of a delivery in flight under a replaced binding
/// that changed (another endpoint or badge), for which the caller then runs
/// [`redeliver_in_flight`]. A thread has at most one delivery in flight, so
/// at most one class is returned.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins; the caller holds no lock.
#[cfg(not(test))]
pub unsafe fn publish_bindings(
    tcb: *mut ThreadControlBlock,
    selected: [bool; FAULT_CLASSES],
    new: [Binding; FAULT_CLASSES],
) -> ([*mut EndpointObject; FAULT_CLASSES], Option<usize>)
{
    let mut old = [core::ptr::null_mut(); FAULT_CLASSES];
    let mut redeliver = None;
    // SAFETY: tcb valid per contract; lock_raw paired with unlock_raw; the
    // binding pairs are written under this lock.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        for (class, &(ep, badge)) in new.iter().enumerate()
        {
            if !selected[class]
            {
                continue;
            }
            let old_badge = (*tcb).fault_badges[class].swap(badge, Ordering::Relaxed);
            old[class] = (*tcb).fault_handlers[class].swap(ep, Ordering::AcqRel);
            let changed = !core::ptr::eq(old[class], ep) || old_badge != badge;
            if changed && delivery_in_flight(tcb, class)
            {
                redeliver = Some(class);
            }
        }
        (*tcb).sched_lock.unlock_raw(saved);
    }
    (old, redeliver)
}

/// Release the endpoint references `eps` holds (null entries skipped),
/// freeing an endpoint whose last reference this is.
///
/// # Safety
/// Each non-null entry is a live `EndpointObject` whose reference the caller
/// owns; syscall context with interrupts disabled and no lock held
/// (`release_ref`'s precondition).
#[cfg(not(test))]
pub unsafe fn release_endpoints(eps: [*mut EndpointObject; FAULT_CLASSES])
{
    for ep in eps
    {
        if let Some(ep) = core::ptr::NonNull::new(ep)
        {
            // SAFETY: caller contract; the header is at offset 0.
            unsafe { crate::cap::object::release_ref(ep.cast::<KernelObjectHeader>()) };
        }
    }
}

/// Deliver `info` to `tcb`'s bound fault-handler endpoint and block until the
/// handler replies or the delivery is cancelled. Returns the disposition.
///
/// Each delivery reads the binding once ([`deliver_once`]). A delivery that a
/// binding change cancelled ([`FAULT_OUTCOME_REDELIVER`]) is made again under
/// the binding current then, in this loop rather than by a return to user
/// mode, so a trap-type exception whose saved instruction pointer is already
/// past the trapping instruction is not lost; a binding found cleared returns
/// [`FaultOutcome::Kill`], the unhandled-fault path. Every pass parks, and
/// only a binding change re-runs one, so the loop is iterative and bounded by
/// the binder's changes.
///
/// # Preconditions
/// - `tcb.trap_frame` already points at the canonical register frame the handler
///   reads/edits via `SYS_THREAD_READ_REGS`/`SYS_THREAD_WRITE_REGS` while the
///   thread is `BlockedOnFault`.
/// - No scheduler or IPC lock is held (fault entry, IF=0 / SIE=0).
///
/// # Safety
/// `tcb` must be the current CPU's running thread.
#[cfg(not(test))]
pub unsafe fn fault_dispatch(tcb: *mut ThreadControlBlock, info: &FaultInfo) -> FaultOutcome
{
    loop
    {
        // SAFETY: this fn's contract and preconditions are deliver_once's.
        match unsafe { deliver_once(tcb, info) }
        {
            FAULT_OUTCOME_RESUME => return FaultOutcome::Resume,
            FAULT_OUTCOME_REDELIVER =>
            {}
            FAULT_OUTCOME_DECLINED =>
            {
                // SAFETY: tcb still valid; the declining reply wrote ipc_msg as
                // the winner of this episode's reply claim, before the wake
                // that resumed this thread, and nothing writes it after that
                // claim.
                let reply = unsafe { &(*tcb).ipc_msg };
                return FaultOutcome::Kill(KillCause::Declined(
                    (reply.data_count > 0).then(|| reply.data[0]),
                ));
            }
            DELIVERY_UNBOUND => return FaultOutcome::Kill(KillCause::BindingCleared),
            // KILL, or a PENDING a spurious wake left: a cancelled delivery.
            _ => return FaultOutcome::Kill(KillCause::Cancelled),
        }
    }
}

/// Make one delivery of `info` through `tcb`'s binding and block until it is
/// given a disposition, which is returned as its `fault_outcome` value, or
/// return [`DELIVERY_UNBOUND`] when no binding was found.
///
/// Mirrors [`crate::syscall::ipc::sys_ipc_call`] but commits the
/// [`IpcThreadState::BlockedOnFault`] state and reads the disposition from
/// `tcb.fault_outcome` on resume rather than writing a syscall return value.
///
/// The binding is read once, under `tcb`'s `sched_lock`, and its endpoint is
/// pinned for the delivery ([`pin_binding`]); with none bound the result is
/// [`DELIVERY_UNBOUND`] and nothing is delivered. The pin is released after
/// the delivery and before the park's `schedule()` (the pin-before-park rule,
/// core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 10): a
/// release that drops the endpoint's last reference runs its teardown, whose
/// send-queue drain claims this thread with a kill outcome when it is still
/// queued there.
///
/// # Safety
/// As for [`fault_dispatch`].
#[cfg(not(test))]
unsafe fn deliver_once(tcb: *mut ThreadControlBlock, info: &FaultInfo) -> u8
{
    // SAFETY: tcb is the current CPU's running thread; no lock is held; the
    // class index is below FAULT_CLASSES.
    let Some((ep_obj, badge)) = (unsafe { pin_binding(tcb, class_of_kind(info.kind)) })
    else
    {
        return DELIVERY_UNBOUND;
    };
    // SAFETY: ep_obj is pinned by the reference pin_binding took.
    let ep_state = unsafe { ep_obj.as_ref().state };

    // Open the park episode (the fault protocol's disposition stays in
    // fault_outcome, which pin_binding armed; the episode counter is the
    // shared debug spurious-resume tripwire; see
    // core/kernel/docs/ipc-internals.md § Park Dispositions and Episodes).
    #[cfg(debug_assertions)]
    // SAFETY: tcb is the running thread; the counter is its own until the
    // delivery below makes it wakeable.
    unsafe {
        (*tcb).park_episode.fetch_add(1, Ordering::Relaxed);
    }

    let mut msg = crate::ipc::message::Message::new(syscall::FAULT_LABEL);
    msg.badge = badge;
    msg.data[0] = info.kind;
    msg.data[1] = info.d1;
    msg.data[2] = info.d2;
    msg.data[3] = info.ip;
    msg.data_count = 4;

    // SAFETY: ep_state is a valid EndpointState (this delivery's pin keeps it
    // live); tcb is the current CPU's running thread (this fn's contract); no
    // scheduler or IPC lock is held (# Preconditions). The BlockedOnFault
    // parked-state diverges from a normal call only in the committed
    // IpcThreadState; the reply linkage is identical.
    let result = unsafe {
        crate::ipc::endpoint::endpoint_call(ep_state, tcb, &msg, IpcThreadState::BlockedOnFault)
    };

    if let Ok(woken_handler) = result
    {
        // A handler was waiting; enqueue it so it can service the fault.
        // SAFETY: woken_handler returned by endpoint_call; valid TCB.
        unsafe {
            debug_assert!((*woken_handler).magic == crate::sched::thread::TCB_MAGIC);
            let target_cpu = crate::sched::select_target_cpu(woken_handler);
            crate::sched::enqueue_and_wake(woken_handler, target_cpu);
        }
    }
    // else: no handler waiting; we are queued on the endpoint's send queue as
    // BlockedOnSend + in_fault_delivery, to be picked up by a later recv.

    // Drop the delivery's pin before parking (rule 10): the park's binding now
    // keeps this thread reachable, and a release that frees the endpoint runs
    // its teardown here, which claims this thread if it is still queued.
    // SAFETY: the reference pin_binding took is owned here; fault delivery on
    // the faulting thread with interrupts disabled, before its park, is the
    // stable-CPU context release_ref's # Safety lists; no lock is held.
    unsafe { crate::cap::object::release_ref(ep_obj.cast::<KernelObjectHeader>()) };

    // Yield the CPU — the current thread is now blocked (or, on the rare
    // concurrent-stop rollback, already Stopped/Exited and not re-enqueued).
    // SAFETY: scheduler initialised; fault context.
    unsafe {
        crate::sched::schedule(crate::sched::Requeue::IfRunnable);
    }

    // Resumed. Read the disposition the wake-claim winner committed. A value
    // other than an explicit Resume or Redeliver is treated as Kill by the
    // caller — this defensively covers a spurious wake leaving the outcome at
    // `Pending`.
    // SAFETY: tcb still valid after resume.
    let outcome = unsafe { (*tcb).fault_outcome.load(Ordering::Acquire) };
    // Spurious-resume tripwire: every legitimate fault wake stamps the
    // episode at its claim site; a mismatch means this resume was produced by
    // nothing that owed it (the #352-class leaked wake). The Kill fallback
    // keeps release behavior fail-closed.
    #[cfg(debug_assertions)]
    // SAFETY: tcb still valid after resume.
    unsafe {
        let park = (*tcb).park_episode.load(Ordering::Relaxed);
        let deposit = (*tcb).deposit_episode.load(Ordering::Relaxed);
        debug_assert!(
            deposit == park,
            "fault_dispatch: spurious resume tid={} park_episode={park} \
             deposit_episode={deposit} outcome={outcome}",
            (*tcb).thread_id,
        );
    }
    // Close the delivery under the lock pin_binding opened it under, so a
    // binder's in-flight check never reads a torn marker.
    // SAFETY: tcb still valid; lock_raw paired with the unlock_raw.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        (*tcb).in_fault_delivery = false;
        (*tcb).sched_lock.unlock_raw(saved);
    }
    outcome
}

/// Cancel the fault delivery of `class` in flight on `tcb` for a change of
/// that class's binding, so the faulting thread delivers it again under the
/// binding current when it next runs ([`FAULT_OUTCOME_REDELIVER`]). Both
/// binders (`SYS_THREAD_SET_FAULT_HANDLER` and
/// `SYS_THREAD_INHERIT_FAULT_HANDLER`, through `apply_bindings`) call it after
/// a change whose own [`publish_bindings`] hold found a delivery of that class
/// in flight ([`delivery_in_flight`]).
///
/// Each pass re-reads the delivery under `tcb`'s `sched_lock` and ends when
/// none is in flight: a wake claim gave it a disposition first (a handler's
/// reply, a stop, a teardown, or a cancel), which stands. A delivery whose
/// park has committed is claimed with the claim every other canceller takes
/// ([`claim_fault_park`]); a won claim stamps the redelivery and wakes the
/// thread. A faulting thread that has opened its delivery but not yet
/// committed its park is running on another CPU with interrupts disabled,
/// inside a delivery that blocks on nothing, so the pass waits for that
/// commit (interrupts enabled, preemption disabled; spin site
/// `fault:rebind`).
///
/// A delivery opened under the new binding after the change's hold can be
/// the one cancelled here, when the old delivery's disposition and a second
/// fault land between that hold and the claim; it is then made again under
/// the same binding, a duplicate message and no change of outcome.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins, other than the calling
/// thread's; the caller holds no lock; `class < FAULT_CLASSES`.
#[cfg(not(test))]
pub unsafe fn redeliver_in_flight(tcb: *mut ThreadControlBlock, class: usize)
{
    let mut spinning: Option<u64> = None;
    loop
    {
        // SAFETY: tcb valid per contract; no lock held.
        let done = match unsafe { in_flight_park(tcb, class) }
        {
            Some((ThreadState::Blocked, ipc_state, blocked_on, park_seq)) =>
            {
                // SAFETY: tcb valid; no lock held.
                unsafe { claim_fault_park(tcb, ipc_state, blocked_on, park_seq) }
            }
            // Opened but not yet parked: wait for the park's commit.
            Some((ThreadState::Running, ..)) => false,
            // None in flight, or a stop or teardown gave it its disposition.
            _ => true,
        };
        if done
        {
            break;
        }
        if spinning.is_none()
        {
            crate::percpu::preempt_disable();
            // SAFETY: ring 0; restored below.
            spinning = Some(unsafe { crate::arch::current::cpu::save_and_disable_interrupts() });
            // SAFETY: ring 0; IDT loaded; preempt disabled.
            unsafe { crate::arch::current::interrupts::enable() };
            crate::sched::spin_site_enter(crate::sched::SPIN_SITE_FAULT_REBIND);
        }
        core::hint::spin_loop();
    }
    if let Some(saved_int) = spinning
    {
        crate::sched::spin_site_exit();
        // SAFETY: saved_int from save_and_disable_interrupts above.
        unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
        crate::percpu::preempt_enable();
    }
}

/// Snapshot `tcb`'s `(state, ipc_state, blocked_on_object, park_seq)` under
/// its `sched_lock` while a fault delivery of `class` is in flight on it
/// ([`delivery_in_flight`]); `None` when none is.
///
/// # Safety
/// `tcb` must be a valid TCB; the caller holds no lock.
#[cfg(not(test))]
unsafe fn in_flight_park(
    tcb: *mut ThreadControlBlock,
    class: usize,
) -> Option<(ThreadState, IpcThreadState, *mut u8, u32)>
{
    // SAFETY: tcb valid per contract; lock_raw paired with unlock_raw; the
    // Scheduling fields are read under sched_lock, their owner.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let snap = delivery_in_flight(tcb, class).then(|| {
            (
                (*tcb).state,
                (*tcb).ipc_state,
                (*tcb).blocked_on_object,
                (*tcb).park_seq.load(Ordering::Relaxed),
            )
        });
        (*tcb).sched_lock.unlock_raw(saved);
        snap
    }
}

/// Claim `tcb`'s fault park, snapshotted as `(ipc_state, blocked_on,
/// park_seq)`, for a redelivery, and wake the thread on a win. Returns `true`
/// when the claim was won, or when the park is not one this claim can take
/// (nothing to cancel); `false` when the park changed or the claim was lost,
/// for the caller's next pass to re-read.
///
/// A queued delivery is claimed by [`claim_queued_fault`], a received one by
/// [`claim_received_fault`]: the claims `cancel_ipc_block` takes, so this
/// claim and every other claimant of the park exclude one another. A won
/// claim stamps [`FAULT_OUTCOME_REDELIVER`] and the episode, clears the park
/// binding inside the same hold (rule 7 of
/// core/kernel/docs/scheduling-internals.md § Lock Hierarchy: no later reader
/// of the binding may reach the endpoint or the handler once neither holds
/// the thread), and wakes the thread through its `wake_in_flight` pin: the
/// one the reply binding set, or, for a queued delivery, one taken inside the
/// claim.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins; the caller holds no lock.
#[cfg(not(test))]
unsafe fn claim_fault_park(
    tcb: *mut ThreadControlBlock,
    ipc_state: IpcThreadState,
    blocked_on: *mut u8,
    park_seq: u32,
) -> bool
{
    let won = match ipc_state
    {
        IpcThreadState::BlockedOnSend =>
        {
            // SAFETY: tcb valid; no lock held (contract).
            unsafe { claim_queued_fault(tcb, blocked_on, park_seq) }
        }
        IpcThreadState::BlockedOnFault if !blocked_on.is_null() =>
        {
            // SAFETY: tcb valid; no lock held (contract); blocked_on non-null.
            unsafe { claim_received_fault(tcb, blocked_on) }
        }
        // Not a fault park: nothing to cancel.
        _ => return true,
    };
    if won
    {
        // SAFETY: the claim is won and the wake_in_flight pin keeps tcb
        // allocated until enqueue_and_wake clears it; no lock is held.
        unsafe {
            let target_cpu = crate::sched::select_target_cpu(tcb);
            crate::sched::enqueue_and_wake(tcb, target_cpu);
        }
    }
    won
}

/// Claim a queued fault delivery (`BlockedOnSend` on the endpoint
/// `blocked_on`) by its send-queue unlink under the endpoint's lock, reached
/// through [`crate::ipc::lock_bound_source`] gated on `park_seq`. On a win,
/// stamp the redelivery and take the `wake_in_flight` pin for the caller's
/// wake. Returns whether the claim was won.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins; the caller holds no lock.
#[cfg(not(test))]
unsafe fn claim_queued_fault(
    tcb: *mut ThreadControlBlock,
    blocked_on: *mut u8,
    park_seq: u32,
) -> bool
{
    // SAFETY: tcb valid; no lock held (contract).
    let held = unsafe {
        crate::ipc::lock_bound_source(
            tcb,
            IpcThreadState::BlockedOnSend,
            blocked_on,
            Some(park_seq),
        )
    };
    let Some(held) = held
    else
    {
        return false;
    };
    // cast_ptr_alignment: blocked_on_object stores a type-erased pointer; the
    // original allocation guarantees alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let ep = blocked_on.cast::<crate::ipc::endpoint::EndpointState>();
    // SAFETY: `held` holds ep.lock on the live endpoint the binding names, and
    // tcb's sched_lock.
    unsafe {
        let unlinked = crate::ipc::endpoint::unlink_from_wait_queue(
            tcb,
            &mut (*ep).send_head,
            &mut (*ep).send_tail,
        );
        if unlinked
        {
            (*ep).refresh_send_ready();
            stamp_redeliver(tcb);
            (*tcb).wake_in_flight.store(1, Ordering::Release);
        }
        held.unlock();
        unlinked
    }
}

/// Claim a received fault delivery (`BlockedOnFault` on the handler TCB
/// `blocked_on`) by the CAS of the handler's `reply_tcb`, under `tcb`'s
/// `sched_lock` with a `blocked_on_object` re-read (the CLOSURE LEMMA of
/// core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership). On a
/// win, stamp the redelivery; the `wake_in_flight` pin the reply binding set
/// stands for the caller's wake. Returns whether the claim was won.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins; the caller holds no lock;
/// `blocked_on` is non-null.
#[cfg(not(test))]
unsafe fn claim_received_fault(tcb: *mut ThreadControlBlock, blocked_on: *mut u8) -> bool
{
    // cast_ptr_alignment: blocked_on_object stores a type-erased pointer; the
    // original allocation guarantees alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let server = blocked_on.cast::<ThreadControlBlock>();
    // SAFETY: tcb valid; lock_raw paired with unlock_raw. The server is live
    // for the CAS by the CLOSURE LEMMA, behind the re-read of the binding under
    // this client's sched_lock.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let won = (*tcb).state == ThreadState::Blocked
            && (*tcb).ipc_state == IpcThreadState::BlockedOnFault
            && core::ptr::eq((*tcb).blocked_on_object, blocked_on)
            && (*server)
                .reply_tcb
                .compare_exchange(
                    tcb,
                    core::ptr::null_mut(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok();
        if won
        {
            stamp_redeliver(tcb);
        }
        (*tcb).sched_lock.unlock_raw(saved);
        won
    }
}

/// Stamp a won fault-park claim for redelivery and retire the park binding.
///
/// # Safety
/// The caller holds `tcb`'s `sched_lock` and the park's exclusive claim.
#[cfg(not(test))]
unsafe fn stamp_redeliver(tcb: *mut ThreadControlBlock)
{
    // SAFETY: caller contract; the binding pair is written under sched_lock.
    unsafe {
        (*tcb)
            .fault_outcome
            .store(FAULT_OUTCOME_REDELIVER, Ordering::Release);
        crate::sched::thread::stamp_deposit_episode(tcb);
        (*tcb).ipc_state = IpcThreadState::None;
        (*tcb).blocked_on_object = core::ptr::null_mut();
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn all_classes_mask_selects_every_class()
    {
        assert_eq!(
            classes_of_mask(syscall::FAULT_CLASS_ALL),
            Some([true; FAULT_CLASSES])
        );
    }

    #[test]
    fn class_bits_select_their_classes_alone_or_together()
    {
        assert_eq!(
            classes_of_mask(syscall::FAULT_CLASS_VM),
            Some([true, false])
        );
        assert_eq!(
            classes_of_mask(syscall::FAULT_CLASS_EXCEPTION),
            Some([false, true])
        );
        assert_eq!(
            classes_of_mask(syscall::FAULT_CLASS_VM | syscall::FAULT_CLASS_EXCEPTION),
            Some([true, true])
        );
    }

    #[test]
    fn empty_and_undefined_masks_are_refused()
    {
        assert_eq!(classes_of_mask(0), None);
        assert_eq!(classes_of_mask(1 << 2), None);
        assert_eq!(classes_of_mask(syscall::FAULT_CLASS_VM | (1 << 63)), None);
    }

    #[test]
    fn a_single_class_bit_names_its_class_and_nothing_else_does()
    {
        assert_eq!(class_of_bit(syscall::FAULT_CLASS_VM), Some(CLASS_VM));
        assert_eq!(
            class_of_bit(syscall::FAULT_CLASS_EXCEPTION),
            Some(CLASS_EXCEPTION)
        );
        assert_eq!(class_of_bit(0), None);
        assert_eq!(
            class_of_bit(syscall::FAULT_CLASS_VM | syscall::FAULT_CLASS_EXCEPTION),
            None
        );
        assert_eq!(class_of_bit(syscall::FAULT_CLASS_ALL), None);
    }

    #[test]
    fn vm_faults_use_the_vm_class_and_other_kinds_the_exception_class()
    {
        assert_eq!(class_of_kind(syscall::FAULT_KIND_VM), CLASS_VM);
        assert_eq!(
            class_of_kind(syscall::FAULT_KIND_EXCEPTION),
            CLASS_EXCEPTION
        );
    }
}
