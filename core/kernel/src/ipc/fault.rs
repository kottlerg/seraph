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
//! A handler's [`syscall::FAULT_REPLY_REDIRECT`] reply names an endpoint, which
//! the reply leaves in the faulting thread's
//! [`ThreadControlBlock::fault_redirect`]; [`fault_dispatch`] delivers the
//! fault there next, in flight under the class of the delivery redirected.
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
/// [`ThreadControlBlock::fault_outcome`] value: the handler of a
/// [`CLASS_VM`] delivery replied [`syscall::FAULT_REPLY_FORWARD`];
/// [`fault_dispatch`] delivers the fault again through the
/// [`CLASS_EXCEPTION`] binding, with the reason word the reply deposited in
/// the faulting thread's `ipc_msg` (docs/fault-handling.md § Reply).
pub const FAULT_OUTCOME_FORWARDED: u8 = 5;
/// [`ThreadControlBlock::fault_outcome`] value: the handler replied
/// [`syscall::FAULT_REPLY_REDIRECT`] naming an endpoint, which the reply left
/// in [`ThreadControlBlock::fault_redirect`] with the badge of the cap it
/// named and its word in the faulting thread's `ipc_msg`; [`fault_dispatch`]
/// delivers the fault there next (docs/fault-handling.md § Reply).
pub const FAULT_OUTCOME_REDIRECTED: u8 = 6;
/// [`ThreadControlBlock::fault_outcome`] value: the handler replied
/// [`syscall::FAULT_REPLY_REDIRECT`] naming no endpoint it holds, so the
/// fault is unhandled ([`KillCause::RedirectRefused`]).
pub const FAULT_OUTCOME_REDIRECT_REFUSED: u8 = 7;
/// [`ThreadControlBlock::fault_outcome`] value: the delivery's endpoint has
/// no capability with the Receive right left, so no handler can receive the
/// fault, and it is unhandled ([`KillCause::NoReceiver`]). Committed by the
/// endpoint's drain for a delivery queued on it, and returned by
/// [`deliver_once`] for one the endpoint refused at once.
pub const FAULT_OUTCOME_NO_RECEIVER: u8 = 8;

/// [`deliver_once`]'s result when no binding was found: never a
/// `fault_outcome` value, it reports [`KillCause::BindingCleared`].
const DELIVERY_UNBOUND: u8 = u8::MAX;

// A forward's reason and a redirect's word share data word 4, the word after
// the four every fault message carries, so a delivery carries at most one.
const _: () = assert!(syscall::FAULT_FORWARD_REASON_WORD == syscall::FAULT_REDIRECT_WORD);
// `deliver_once` sends the fifth word as the one after the four fault words.
const _: () = assert!(syscall::FAULT_REDIRECT_WORD == 4);

/// Number of fault classes a thread binds separately
/// (docs/fault-handling.md § Fault-Handler Binding), and the length of the
/// per-class binding arrays of [`ThreadControlBlock`].
pub const FAULT_CLASSES: usize = 3;

/// Class index of virtual-memory faults ([`syscall::FAULT_CLASS_VM`]).
pub const CLASS_VM: usize = 0;

/// Class index of every other user exception
/// ([`syscall::FAULT_CLASS_EXCEPTION`]).
pub const CLASS_EXCEPTION: usize = 1;

/// Class index of asynchronous upcalls ([`syscall::FAULT_CLASS_UPCALL`]),
/// delivered through the fault machinery by [`crate::ipc::upcall`].
pub const CLASS_UPCALL: usize = 2;

/// The ABI class bit of each class index.
const CLASS_BITS: [u64; FAULT_CLASSES] = [
    syscall::FAULT_CLASS_VM,
    syscall::FAULT_CLASS_EXCEPTION,
    syscall::FAULT_CLASS_UPCALL,
];

/// The class index a message of `kind` is delivered through: `FAULT_KIND_VM`
/// through [`CLASS_VM`], `FAULT_KIND_UPCALL` through [`CLASS_UPCALL`], every
/// other kind through [`CLASS_EXCEPTION`].
#[must_use]
pub fn class_of_kind(kind: u64) -> usize
{
    match kind
    {
        syscall::FAULT_KIND_VM => CLASS_VM,
        syscall::FAULT_KIND_UPCALL => CLASS_UPCALL,
        _ => CLASS_EXCEPTION,
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
    /// The binding of the fault's class was found cleared when the delivery
    /// read it.
    BindingCleared,
    /// The delivery was cancelled before any reply claimed it (handler thread
    /// destroyed, a later receive on the handler thread, or a stop of the
    /// faulting thread).
    Cancelled,
    /// The handler replied [`syscall::FAULT_REPLY_KILL`], with the reason its
    /// reply's data word 0 carried, if it sent one; or a VM-class handler
    /// replied [`syscall::FAULT_REPLY_FORWARD`] with that reason while no
    /// exception-class handler was bound.
    Declined(Option<u64>),
    /// No handler was bound for the fault's class when the architecture
    /// handler checked; nothing was delivered.
    NoHandler,
    /// A handler replied [`syscall::FAULT_REPLY_REDIRECT`] without naming an
    /// endpoint it holds.
    RedirectRefused,
    /// The endpoint the fault was delivered to has no capability with the
    /// Receive right left, so no handler could receive it.
    NoReceiver,
}

/// Print, on the kernel serial console, why the user-mode fault of the thread
/// whose id is `tid` went unhandled; the architecture kill path's
/// `USERSPACE FAULT` diagnostic, which names the fault's kind, address, and
/// instruction pointer, follows it. The decline reason is the
/// handler's own value, printed verbatim; it is not interpreted here.
#[cfg(not(test))]
pub fn report_user_kill(tid: u32, cause: KillCause)
{
    match cause
    {
        KillCause::BindingCleared =>
        {
            crate::kprintln_fault!(
                "fault unhandled: tid={tid} class binding cleared before delivery"
            );
        }
        KillCause::Cancelled =>
        {
            crate::kprintln_fault!("fault unhandled: tid={tid} delivery cancelled before a reply");
        }
        KillCause::Declined(None) =>
        {
            crate::kprintln_fault!("fault unhandled: tid={tid} handler declined");
        }
        KillCause::Declined(Some(reason)) =>
        {
            crate::kprintln_fault!(
                "fault unhandled: tid={tid} handler declined, reason={reason:#x}"
            );
        }
        KillCause::NoHandler =>
        {
            crate::kprintln_fault!("fault unhandled: tid={tid} no handler bound");
        }
        KillCause::RedirectRefused =>
        {
            crate::kprintln_fault!("fault unhandled: tid={tid} handler redirect refused");
        }
        KillCause::NoReceiver =>
        {
            crate::kprintln_fault!("fault unhandled: tid={tid} handler endpoint has no receiver");
        }
    }
}

/// Print the [`KillCause::NoHandler`] line for the user-mode fault of `tcb`,
/// which the architecture handler found no handler bound for and is about to
/// kill (thread id 0 for a null `tcb`, as the kill path's own diagnostic
/// prints it).
///
/// # Safety
/// `tcb` is the running user thread's TCB, or null.
#[cfg(not(test))]
pub unsafe fn report_unbound_kill(tcb: *mut ThreadControlBlock)
{
    let tid = if tcb.is_null()
    {
        0
    }
    else
    {
        // SAFETY: tcb non-null and valid (contract); thread_id is fixed at
        // creation.
        unsafe { (*tcb).thread_id }
    };
    report_user_kill(tid, KillCause::NoHandler);
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
    let handlers = unsafe { &(*tcb).fault_handlers };
    handlers
        .get(class_of_kind(kind))
        .is_some_and(|h| !h.load(Ordering::Acquire).is_null())
}

/// Read `tcb`'s fault-handler binding for `class` once, pin its endpoint, and
/// open a delivery through it.
///
/// Returns the bound `EndpointObject`, with a reference the caller owns and
/// MUST release, and the badge bound with it; `None` when no handler is bound
/// or `class` names no class.
/// The pair is read under `tcb`'s `sched_lock`, the lock [`publish_bindings`]
/// publishes it under for both binders, so the badge is the one
/// bound with this endpoint, and the reference is taken while the binding's
/// own reference still holds the object: the binder releases the old binding's
/// reference only after it unlocks.
///
/// With a binding found, the same hold arms the in-flight markers
/// ([`arm_delivery`]). They are written under the lock the binding is, so a
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
    // SAFETY: tcb is the running thread (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw is paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reads a binding array of tcb, which the held sched_lock serialises"
    )]
    // SAFETY: tcb is the running thread, and its binding pair is read under
    // the held sched_lock it is published under.
    let binding = unsafe {
        (*tcb)
            .fault_handlers
            .get(class)
            .zip((*tcb).fault_badges.get(class))
    };
    let ep = binding.and_then(|(h, _)| core::ptr::NonNull::new(h.load(Ordering::Acquire)));
    let badge = binding.map_or(0, |(_, b)| b.load(Ordering::Relaxed));
    if let Some(ep) = ep
    {
        // SAFETY: a non-null fault_handlers entry read under sched_lock names
        // an endpoint the binding references, so it is live for inc_ref.
        unsafe { ep.as_ref() }.header.inc_ref();
        // SAFETY: tcb is the running thread, whose sched_lock is held;
        // class < FAULT_CLASSES (contract).
        unsafe { arm_delivery(tcb, class) };
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    ep.map(|ep| (ep, badge))
}

/// Open a redirected delivery of `class` on `tcb`: arm its in-flight markers
/// under `tcb`'s `sched_lock`, as [`pin_binding`] arms them for a delivery
/// through a binding, so a change of `class`'s binding cancels this delivery
/// as it cancels one made through that binding.
///
/// # Safety
/// `tcb` must be the current CPU's running thread, with no lock held;
/// `class < FAULT_CLASSES`.
#[cfg(not(test))]
unsafe fn open_redirect(tcb: *mut ThreadControlBlock, class: usize)
{
    // SAFETY: tcb is the running thread (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw is paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    // SAFETY: tcb is the running thread, whose sched_lock is held;
    // class < FAULT_CLASSES (contract).
    unsafe { arm_delivery(tcb, class) };
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
}

/// Arm `tcb`'s in-flight markers for a delivery of `class`:
/// `fault_outcome = Pending`, so a stale prior disposition cannot be mistaken
/// for this delivery's (the single wake-claim winner overwrites it), and
/// `in_fault_delivery`, so a dequeuing `endpoint_recv` parks the thread
/// `BlockedOnFault` (not `BlockedOnReply`), with `fault_delivery_class`
/// naming the class, and `fault_rebound` clear, so only a change of the
/// binding while this delivery is in flight sets it.
///
/// # Safety
/// `tcb` must be the current CPU's running thread, whose `sched_lock` the
/// caller holds; `class < FAULT_CLASSES`.
#[cfg(not(test))]
unsafe fn arm_delivery(tcb: *mut ThreadControlBlock, class: usize)
{
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access writes a fault-delivery marker of tcb, which the held sched_lock \
                  serialises"
    )]
    // SAFETY: tcb is the running thread; the markers are its own until its
    // delivery makes it wakeable, and are written under the held sched_lock.
    unsafe {
        (*tcb)
            .fault_outcome
            .store(FAULT_OUTCOME_PENDING, Ordering::Release);
        (*tcb).in_fault_delivery = true;
        (*tcb).fault_rebound = false;
        #[expect(clippy::cast_possible_truncation, reason = "class < FAULT_CLASSES (3)")]
        {
            (*tcb).fault_delivery_class = class as u8;
        }
    }
}

/// Whether a fault delivery through `tcb`'s binding for `class` is in
/// flight: opened by [`pin_binding`], or by [`open_redirect`] for a redirect
/// of a delivery of `class`, and given no disposition yet by a wake claim.
///
/// # Safety
/// `tcb` must be a valid TCB whose `sched_lock` the caller holds.
#[cfg(not(test))]
pub unsafe fn delivery_in_flight(tcb: *mut ThreadControlBlock, class: usize) -> bool
{
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reads a fault-delivery marker of tcb, which the held sched_lock \
                  serialises"
    )]
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
    // SAFETY: tcb valid per contract.
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reads a binding array of tcb, which the held sched_lock serialises"
    )]
    // SAFETY: tcb valid per contract; the binding pairs are read under the
    // held sched_lock they are published under.
    let bound = unsafe { (*tcb).fault_handlers.iter().zip(&(*tcb).fault_badges) };
    for ((slot, selected), (handler, badge)) in out.iter_mut().zip(selected).zip(bound)
    {
        if !selected
        {
            continue;
        }
        let ep = handler.load(Ordering::Acquire);
        if !ep.is_null()
        {
            // SAFETY: a non-null endpoint read under sched_lock is held by the
            // binding's reference, so it is live for inc_ref.
            unsafe { (*ep).header.inc_ref() };
            *slot = (ep, badge.load(Ordering::Relaxed));
        }
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
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
/// at most one class is returned. The same hold marks that delivery
/// (`fault_rebound`), so one that ends without a park, its endpoint having no
/// receiver, is delivered again by the faulting thread itself.
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
    // SAFETY: tcb valid per contract.
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reaches a binding array of tcb, which the held sched_lock \
                  serialises"
    )]
    // SAFETY: tcb valid per contract; the binding pairs are written under the
    // held sched_lock.
    let bound = unsafe { (*tcb).fault_handlers.iter().zip(&(*tcb).fault_badges) };
    let classes = new.iter().zip(selected).zip(old.iter_mut()).zip(bound);
    for (class, (((&(ep, badge), selected), old_ep), (handler, badge_cell))) in classes.enumerate()
    {
        if !selected
        {
            continue;
        }
        let old_badge = badge_cell.swap(badge, Ordering::Relaxed);
        *old_ep = handler.swap(ep, Ordering::AcqRel);
        let changed = !core::ptr::eq(*old_ep, ep) || old_badge != badge;
        // SAFETY: tcb is valid and its sched_lock is held.
        if changed && unsafe { delivery_in_flight(tcb, class) }
        {
            // SAFETY: tcb is valid; fault_rebound is written under the held
            // sched_lock.
            unsafe { (*tcb).fault_rebound = true };
            redeliver = Some(class);
        }
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
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
/// past the trapping instruction is not lost, as is one whose endpoint had no
/// receiver left when a binding change had already cancelled it; a binding
/// found cleared, or an endpoint with no receiver left
/// ([`FAULT_OUTCOME_NO_RECEIVER`], at once or while the delivery was
/// queued), returns [`FaultOutcome::Kill`], the unhandled-fault path. A [`CLASS_VM`] delivery
/// its handler forwarded ([`FAULT_OUTCOME_FORWARDED`]) is made again through
/// the [`CLASS_EXCEPTION`] binding, which every later pass of the fault uses,
/// with the forwarder's reason as data word 4; with that binding cleared, or
/// its endpoint without a receiver, the fault takes the outcome of the
/// forwarder's own decline. A delivery its
/// handler redirected ([`FAULT_OUTCOME_REDIRECTED`]) is made again to the
/// endpoint the reply named ([`take_redirect`]), in flight under the class of
/// the delivery redirected, so a change of that class's binding cancels it
/// and the next pass goes back to that binding. Every pass parks, unless its
/// endpoint has no receiver, which ends the loop, and only a
/// binding change, the one forward, or a handler's redirecting reply re-runs
/// one, so the loop is iterative and bounded by the binder's changes and the
/// handlers' replies.
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
    // SAFETY: this fn's contract is dispatch's.
    unsafe { dispatch(tcb, info, Forwarding::Followed) }
}

/// [`fault_dispatch`] for the fault of a restartable syscall's user copy
/// (docs/fault-handling.md § Kernel Copies): a forward of it is a decline,
/// so the syscall fails with `InvalidAddress` and no exception handler sees a
/// fault the thread survives (docs/fault-handling.md § Reply). A redirect of
/// it is delivered, and a resume from the endpoint it names restarts the
/// syscall.
///
/// # Safety
/// As for [`fault_dispatch`].
#[cfg(not(test))]
pub unsafe fn copy_fault_dispatch(tcb: *mut ThreadControlBlock, info: &FaultInfo) -> FaultOutcome
{
    // SAFETY: this fn's contract is dispatch's.
    unsafe { dispatch(tcb, info, Forwarding::Declined) }
}

/// Whether [`dispatch`] delivers a forwarded fault through the exception
/// class or takes the forward as a decline.
#[cfg(not(test))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Forwarding
{
    /// A forward is delivered through the exception class.
    Followed,
    /// A forward is a decline: the fault of a kernel copy.
    Declined,
}

/// The loop [`fault_dispatch`] describes, with a forward taken as
/// `forwarding` says.
///
/// # Safety
/// As for [`fault_dispatch`].
#[cfg(not(test))]
unsafe fn dispatch(
    tcb: *mut ThreadControlBlock,
    info: &FaultInfo,
    forwarding: Forwarding,
) -> FaultOutcome
{
    let mut class = class_of_kind(info.kind);
    let mut forwarded = Forward::None;
    let mut route = Route::Binding;
    loop
    {
        // SAFETY: this fn's contract and preconditions are deliver_once's;
        // class < FAULT_CLASSES; a Redirect route's reference was taken from
        // fault_redirect by take_redirect and is handed over here.
        match unsafe { deliver_once(tcb, info, class, forwarded, route) }
        {
            FAULT_OUTCOME_RESUME => return FaultOutcome::Resume,
            FAULT_OUTCOME_REDELIVER => route = Route::Binding,
            FAULT_OUTCOME_FORWARDED if forwarding == Forwarding::Declined =>
            {
                // SAFETY: tcb resumed by the wake of the forwarding reply.
                return FaultOutcome::Kill(KillCause::Declined(unsafe { reply_reason(tcb) }));
            }
            FAULT_OUTCOME_FORWARDED =>
            {
                // SAFETY: tcb resumed by the wake of the forwarding reply.
                forwarded = Forward::Reason(unsafe { reply_reason(tcb) });
                class = CLASS_EXCEPTION;
                route = Route::Binding;
            }
            FAULT_OUTCOME_REDIRECTED =>
            {
                // SAFETY: tcb resumed by the wake of the redirecting reply.
                let Some(redirect) = (unsafe { take_redirect(tcb) })
                else
                {
                    return FaultOutcome::Kill(KillCause::Cancelled);
                };
                route = redirect;
            }
            FAULT_OUTCOME_REDIRECT_REFUSED =>
            {
                return FaultOutcome::Kill(KillCause::RedirectRefused);
            }
            // No handler can receive on the endpoint: unhandled, as an unbound
            // class is, a forwarded fault keeping its decline's reason.
            FAULT_OUTCOME_NO_RECEIVER =>
            {
                return FaultOutcome::Kill(match forwarded
                {
                    Forward::Reason(reason) => KillCause::Declined(reason),
                    Forward::None => KillCause::NoReceiver,
                });
            }
            FAULT_OUTCOME_DECLINED =>
            {
                // SAFETY: tcb resumed by the wake of the declining reply.
                return FaultOutcome::Kill(KillCause::Declined(unsafe { reply_reason(tcb) }));
            }
            DELIVERY_UNBOUND =>
            {
                return FaultOutcome::Kill(match forwarded
                {
                    Forward::Reason(reason) => KillCause::Declined(reason),
                    Forward::None => KillCause::BindingCleared,
                });
            }
            // KILL, or a PENDING a spurious wake left: a cancelled delivery.
            _ => return FaultOutcome::Kill(KillCause::Cancelled),
        }
    }
}

/// Whether a fault in [`fault_dispatch`] has been forwarded from the VM class
/// to the exception class, and with which reason word.
#[cfg(not(test))]
#[derive(Clone, Copy)]
enum Forward
{
    /// Not forwarded.
    None,
    /// Forwarded, with the forwarder's reason word if its reply carried one.
    Reason(Option<u64>),
}

/// Where [`deliver_once`] makes its delivery.
#[cfg(not(test))]
#[derive(Clone, Copy)]
enum Route
{
    /// Through the binding of the pass's class.
    Binding,
    /// To the endpoint a redirecting reply named, with the badge of the cap
    /// it named and the redirector's word.
    Redirect
    {
        /// The endpoint, with a reference the pass owns and releases before
        /// its park.
        ep: core::ptr::NonNull<EndpointObject>,
        /// The derivation badge of the cap the reply named.
        badge: u64,
        /// The redirector's data word 0, `0` when its reply carried none.
        word: u64,
    },
}

/// Take the redirect the reply that resumed `tcb` left: the endpoint from
/// [`ThreadControlBlock::fault_redirect`], whose reference passes to the
/// returned route, and the badge and word from `tcb`'s `ipc_msg`. `None`
/// when no endpoint is left, which no reply that committed
/// [`FAULT_OUTCOME_REDIRECTED`] produces.
///
/// # Safety
/// `tcb` is the current CPU's running thread, resumed by the wake of a reply
/// that committed [`FAULT_OUTCOME_REDIRECTED`], which wrote `fault_redirect`
/// and `ipc_msg` as the winner of the episode's reply claim before the wake.
#[cfg(not(test))]
unsafe fn take_redirect(tcb: *mut ThreadControlBlock) -> Option<Route>
{
    // SAFETY: tcb is the running thread (contract); the field is atomic.
    let ep = unsafe { &(*tcb).fault_redirect }.swap(core::ptr::null_mut(), Ordering::Acquire);
    let ep = core::ptr::NonNull::new(ep);
    debug_assert!(
        ep.is_some(),
        "fault_dispatch: redirect outcome with no endpoint"
    );
    // SAFETY: the contract above; nothing writes ipc_msg after the claim.
    let badge = unsafe { (*tcb).ipc_msg.badge };
    // SAFETY: as above.
    let word = unsafe { reply_reason(tcb) }.unwrap_or(0);
    ep.map(|ep| Route::Redirect { ep, badge, word })
}

/// The reason word the declining, forwarding or redirecting fault reply
/// deposited in `tcb`'s `ipc_msg`, if the reply carried one.
///
/// # Safety
/// `tcb` is the current CPU's running thread, resumed by the wake of that
/// reply, which wrote `ipc_msg` as the winner of the episode's reply claim
/// before the wake; nothing writes it after that claim.
#[cfg(not(test))]
unsafe fn reply_reason(tcb: *mut ThreadControlBlock) -> Option<u64>
{
    // SAFETY: the contract above.
    unsafe { &(*tcb).ipc_msg }.data().first().copied()
}

/// Make one delivery of `info` by `route`, through `tcb`'s binding for
/// `class` or to a redirect's endpoint in flight under `class`, and block
/// until it is given a disposition, which is returned as its `fault_outcome`
/// value, or return [`DELIVERY_UNBOUND`] when no binding was found, or,
/// without parking, when the endpoint has no receiver left:
/// [`FAULT_OUTCOME_REDELIVER`] when a binding change cancelled the delivery
/// before that ([`close_unparked_delivery`]), and
/// [`FAULT_OUTCOME_NO_RECEIVER`] otherwise. A
/// redirected delivery carries the redirector's word as data word
/// [`syscall::FAULT_REDIRECT_WORD`]; a `forwarded` delivery through a binding
/// carries the forwarder's reason (`0` for none) as data word
/// [`syscall::FAULT_FORWARD_REASON_WORD`].
///
/// Mirrors [`crate::syscall::ipc::sys_ipc_call`] but commits the
/// [`IpcThreadState::BlockedOnFault`] state and reads the disposition from
/// `tcb.fault_outcome` on resume rather than writing a syscall return value.
///
/// The binding is read once, under `tcb`'s `sched_lock`, and its endpoint is
/// pinned for the delivery ([`pin_binding`]); with none bound the result is
/// [`DELIVERY_UNBOUND`] and nothing is delivered. A redirect's endpoint is
/// pinned by the reference its route carries. The pin is released after
/// the delivery and before the park's `schedule()` (the pin-before-park rule,
/// core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 10): a
/// release that drops the endpoint's last reference runs its teardown, whose
/// send-queue drain claims this thread with a kill outcome when it is still
/// queued there.
///
/// # Safety
/// As for [`fault_dispatch`]; `class < FAULT_CLASSES`; a
/// [`Route::Redirect`]'s endpoint reference is the caller's, handed over.
#[cfg(not(test))]
unsafe fn deliver_once(
    tcb: *mut ThreadControlBlock,
    info: &FaultInfo,
    class: usize,
    forwarded: Forward,
    route: Route,
) -> u8
{
    let (ep_obj, badge, fifth) = match route
    {
        Route::Binding =>
        {
            // SAFETY: tcb is the current CPU's running thread; no lock is
            // held; the class index is below FAULT_CLASSES (this fn's
            // contract).
            let Some((ep, badge)) = (unsafe { pin_binding(tcb, class) })
            else
            {
                return DELIVERY_UNBOUND;
            };
            let reason = match forwarded
            {
                Forward::Reason(reason) => Some(reason.unwrap_or(0)),
                Forward::None => None,
            };
            (ep, badge, reason)
        }
        Route::Redirect { ep, badge, word } =>
        {
            // SAFETY: as for pin_binding above.
            unsafe { open_redirect(tcb, class) };
            (ep, badge, Some(word))
        }
    };
    // SAFETY: ep_obj is pinned by the delivery's reference.
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

    // Build the fault message in place, in the thread's own ipc_msg, which
    // endpoint_call sends: words 0..=3 are the fault, and word 4
    // (FAULT_REDIRECT_WORD, FAULT_FORWARD_REASON_WORD) the redirect word or
    // forward reason, read into `fifth` above before this overwrites the
    // reply that carried it.
    let words = [info.kind, info.d1, info.d2, info.ip, fifth.unwrap_or(0)];
    let sent = match fifth
    {
        Some(_) => words.as_slice(),
        None => words.get(..syscall::FAULT_REDIRECT_WORD).unwrap_or(&words),
    };
    // SAFETY: tcb is the current CPU's running thread outside any park, so it
    // owns its ipc_msg until endpoint_call publishes the delivery.
    let msg = unsafe { &mut (*tcb).ipc_msg };
    msg.begin(syscall::FAULT_LABEL, badge);
    msg.set_data(sent);

    // SAFETY: ep_state is a valid EndpointState (this delivery's pin keeps it
    // live); tcb is the current CPU's running thread (this fn's contract); no
    // scheduler or IPC lock is held (# Preconditions). The BlockedOnFault
    // parked-state diverges from a normal call only in the committed
    // IpcThreadState; the reply linkage is identical. A fault delivery is
    // never timed (deadline 0).
    let result = unsafe {
        crate::ipc::endpoint::endpoint_call(ep_state, tcb, IpcThreadState::BlockedOnFault, 0)
    };

    if let crate::ipc::endpoint::CallRendezvous::NoReceiver = result
    {
        // No thread can receive on the endpoint again, and the thread did not
        // park: the fault is unhandled, unless a binding change cancelled the
        // delivery first. The pin goes as below.
        // SAFETY: as for the release below; the thread has not parked.
        unsafe { crate::cap::object::release_ref(ep_obj.cast::<KernelObjectHeader>()) };
        // SAFETY: tcb is the running thread, with no lock held.
        return if unsafe { close_unparked_delivery(tcb) }
        {
            FAULT_OUTCOME_REDELIVER
        }
        else
        {
            FAULT_OUTCOME_NO_RECEIVER
        };
    }
    if let crate::ipc::endpoint::CallRendezvous::Bound {
        server: woken_handler,
        hint,
    } = result
    {
        // A handler was waiting; enqueue it so it can service the fault.
        // SAFETY: woken_handler returned by endpoint_call; valid TCB.
        let magic = unsafe { (*woken_handler).magic };
        debug_assert_eq!(magic, crate::sched::thread::TCB_MAGIC);
        // A committed park makes the hint Sync: this thread's schedule() below
        // follows before any return to user mode, so the handler may run here.
        // SAFETY: woken_handler is a valid TCB, pinned by the wake_in_flight
        // claim endpoint_call took; a Sync hint's caller is this running
        // thread, its park committed.
        let target = unsafe { crate::sched::select_wake_target(woken_handler, None, hint) };
        // SAFETY: woken_handler is valid and claimed, target came from
        // select_wake_target, and no scheduler lock is held.
        unsafe { crate::sched::enqueue_and_wake_at(woken_handler, target) };
    }
    // else: no handler waiting; we are queued on the endpoint's send queue as
    // BlockedOnSend + in_fault_delivery, to be picked up by a later recv.

    // Drop the delivery's pin before parking (rule 10): the park's binding now
    // keeps this thread reachable, and a release that frees the endpoint runs
    // its teardown here, which claims this thread if it is still queued.
    // SAFETY: the delivery's reference (pin_binding's, or the one the redirect
    // route handed over) is owned here; fault delivery on
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
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reads a field of tcb, the running thread's own TCB"
    )]
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
    // SAFETY: tcb is the running thread, with no lock held.
    unsafe { close_delivery(tcb) };
    outcome
}

/// Close `tcb`'s fault delivery under the lock [`pin_binding`] or
/// [`open_redirect`] opened it under, so a binder's in-flight check
/// ([`delivery_in_flight`]) never reads a torn marker.
///
/// # Safety
/// `tcb` must be the current CPU's running thread, with no lock held.
#[cfg(not(test))]
unsafe fn close_delivery(tcb: *mut ThreadControlBlock)
{
    // SAFETY: tcb is the running thread (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    // SAFETY: tcb is valid; in_fault_delivery is written under the held
    // sched_lock.
    unsafe { (*tcb).in_fault_delivery = false };
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
}

/// Close `tcb`'s fault delivery that ended without a park, as
/// [`close_delivery`] does, and return whether a binding change cancelled it
/// while it was in flight (`fault_rebound`, which [`publish_bindings`] sets
/// under the same lock). No wake claim can take an unparked delivery, so the
/// binder's [`redeliver_in_flight`] stamps nothing for it: the faulting
/// thread itself delivers the fault again under the binding current then.
///
/// # Safety
/// `tcb` must be the current CPU's running thread, with no lock held.
#[cfg(not(test))]
unsafe fn close_unparked_delivery(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: tcb is the running thread (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a fault-delivery marker of tcb, which the held sched_lock \
                  serialises"
    )]
    // SAFETY: tcb is valid; both markers are written under the held
    // sched_lock.
    let rebound = unsafe {
        (*tcb).in_fault_delivery = false;
        (*tcb).fault_rebound
    };
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    rebound
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
/// `fault:rebind`), or for the delivery's end without a park, when its
/// endpoint has no receiver: the faulting thread then reads the change
/// [`publish_bindings`] marked and delivers the fault again itself
/// ([`close_unparked_delivery`]), and the pass finds none in flight.
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
    // SAFETY: tcb valid per contract.
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    // SAFETY: tcb is valid and its sched_lock is held.
    let in_flight = unsafe { delivery_in_flight(tcb, class) };
    let snap = if in_flight
    {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access reads a Scheduling field of tcb, which the held sched_lock \
                      serialises"
        )]
        // SAFETY: tcb valid per contract; the Scheduling fields are read under
        // sched_lock, their owner.
        let fields = unsafe {
            (
                (*tcb).state,
                (*tcb).ipc_state,
                (*tcb).blocked_on_object,
                (*tcb).park_seq.load(Ordering::Relaxed),
            )
        };
        Some(fields)
    }
    else
    {
        None
    };
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    snap
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
        // Not a fault park this claim can take (a fault binding with no
        // endpoint among them): nothing to cancel.
        IpcThreadState::BlockedOnFault
        | IpcThreadState::None
        | IpcThreadState::BlockedOnRecv
        | IpcThreadState::BlockedOnReply
        | IpcThreadState::BlockedOnNotification
        | IpcThreadState::BlockedOnEventQueue
        | IpcThreadState::BlockedOnWaitSet => return true,
    };
    if won
    {
        // SAFETY: the claim is won and the wake_in_flight pin keeps tcb
        // allocated until enqueue_and_wake clears it.
        let target_cpu = unsafe { crate::sched::select_target_cpu(tcb) };
        // SAFETY: tcb is valid and claimed, target_cpu came from
        // select_target_cpu, and no lock is held.
        unsafe { crate::sched::enqueue_and_wake(tcb, target_cpu) };
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
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "blocked_on_object stores a type-erased pointer; the original allocation \
                  guarantees alignment"
    )]
    let ep = blocked_on.cast::<crate::ipc::endpoint::EndpointState>();
    // SAFETY: `held` holds ep.lock on the live endpoint the binding names.
    let send = unsafe { &mut (*ep).send };
    // SAFETY: ep.lock is held, and tcb is a valid TCB.
    let unlinked = unsafe { send.remove(tcb) };
    if unlinked
    {
        // SAFETY: `held` holds ep.lock on the live endpoint.
        let ep = unsafe { &*ep };
        // SAFETY: ep.lock is held.
        unsafe { ep.refresh_send_ready() };
        // SAFETY: `held` holds tcb's sched_lock, and the unlink under ep.lock
        // is the park's exclusive claim.
        unsafe { stamp_redeliver(tcb) };
        // SAFETY: tcb is a valid TCB the caller pins.
        unsafe { (*tcb).wake_in_flight.store(1, Ordering::Release) };
    }
    // SAFETY: `held` came from lock_bound_source and both its locks are held.
    unsafe { held.unlock() };
    unlinked
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
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "blocked_on_object stores a type-erased pointer; the original allocation \
                  guarantees alignment"
    )]
    let server = blocked_on.cast::<ThreadControlBlock>();
    // SAFETY: tcb valid per contract.
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reads a Scheduling field of tcb, which the held sched_lock \
                  serialises"
    )]
    // SAFETY: tcb valid; the binding is re-read under this client's
    // sched_lock, its owner.
    let bound = unsafe {
        (*tcb).state == ThreadState::Blocked
            && (*tcb).ipc_state == IpcThreadState::BlockedOnFault
            && core::ptr::eq((*tcb).blocked_on_object, blocked_on)
    };
    // SAFETY: the server is live for the CAS by the CLOSURE LEMMA, behind the
    // re-read of the binding above under this client's sched_lock.
    let won = bound
        && unsafe {
            (*server)
                .reply_tcb
                .compare_exchange(
                    tcb,
                    core::ptr::null_mut(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        };
    if won
    {
        // The redelivered faulter gets its turn back.
        // SAFETY: the won CAS claimed tcb's binding to server.
        unsafe { crate::sched::turn::reclaim_turn(server, tcb) };
        // SAFETY: tcb's sched_lock is held, and the CAS win is the park's
        // exclusive claim.
        unsafe { stamp_redeliver(tcb) };
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    won
}

/// Stamp a won fault-park claim for redelivery and retire the park binding.
///
/// # Safety
/// The caller holds `tcb`'s `sched_lock` and the park's exclusive claim.
#[cfg(not(test))]
unsafe fn stamp_redeliver(tcb: *mut ThreadControlBlock)
{
    // SAFETY: tcb is a valid TCB whose park claim the caller holds
    // (contract).
    unsafe {
        (*tcb)
            .fault_outcome
            .store(FAULT_OUTCOME_REDELIVER, Ordering::Release);
    }
    // SAFETY: the caller holds the park's exclusive claim (contract).
    unsafe { crate::sched::thread::stamp_deposit_episode(tcb) };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access writes the park binding of tcb, which the held sched_lock \
                  serialises"
    )]
    // SAFETY: caller contract; the binding pair is written under sched_lock.
    unsafe {
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
            Some([true, false, false])
        );
        assert_eq!(
            classes_of_mask(syscall::FAULT_CLASS_EXCEPTION),
            Some([false, true, false])
        );
        assert_eq!(
            classes_of_mask(syscall::FAULT_CLASS_UPCALL),
            Some([false, false, true])
        );
        assert_eq!(
            classes_of_mask(syscall::FAULT_CLASS_VM | syscall::FAULT_CLASS_EXCEPTION),
            Some([true, true, false])
        );
        assert_eq!(
            classes_of_mask(
                syscall::FAULT_CLASS_VM
                    | syscall::FAULT_CLASS_EXCEPTION
                    | syscall::FAULT_CLASS_UPCALL
            ),
            Some([true; FAULT_CLASSES])
        );
    }

    #[test]
    fn empty_and_undefined_masks_are_refused()
    {
        assert_eq!(classes_of_mask(0), None);
        assert_eq!(classes_of_mask(1 << 3), None);
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
        assert_eq!(
            class_of_bit(syscall::FAULT_CLASS_UPCALL),
            Some(CLASS_UPCALL)
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
        assert_eq!(class_of_kind(u64::MAX), CLASS_EXCEPTION);
    }

    #[test]
    fn upcalls_use_the_upcall_class()
    {
        assert_eq!(class_of_kind(syscall::FAULT_KIND_UPCALL), CLASS_UPCALL);
    }
}
