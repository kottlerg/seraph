// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/hold.rs

//! Address-space hold: the per-space hold state, the per-thread hold mark,
//! and the decisions the scheduler applies to them under its locks.
//!
//! `SYS_ASPACE_HOLD` stops every thread of an address space without
//! cancelling any park, and `SYS_ASPACE_RELEASE` starts again exactly the
//! threads the hold stopped. A `Ready` thread is stopped at once. A thread
//! that is `Running` or `Blocked` is marked [`HoldMark::Pending`] and keeps
//! running or stays parked; its next passage toward `Ready` (the wake that
//! ends its park, or the requeue of `schedule()` when it leaves its CPU)
//! commits `Stopped` instead, the wake's outcome already deposited in its
//! TCB. A start of a thread of the held space is deferred to the release.
//! The rules and their invariants are stated in
//! core/kernel/docs/thread-lifecycle-and-sleep.md § Address-Space Hold.
//!
//! The decisions are pure functions of the states, so the host tests below
//! can drive them through every reachable state of a space. The hold and the
//! release that apply them to the threads of a space under `sched_lock` and
//! the CPU locks are [`hold_space`] and [`release_space`] below; the
//! diverts and the start commit that apply them to one thread are in
//! `sched/mod.rs` (`enqueue_and_wake`, `schedule()`'s requeue,
//! `commit_state_under_all_locks`).

use super::thread::ThreadState;

/// The hold state of one address space (`AddressSpace::hold`).
///
/// A hold moves `Free` to `Holding` (refused in any other state), walks
/// the space's threads, waits until none is current on any CPU, and stores
/// `Held`. A release moves `Held` to `Releasing` (refused in any other
/// state), walks again, and stores `Free`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HoldState
{
    /// No hold: threads start and run as usual.
    Free = 0,
    /// A hold's walk or wait is in progress.
    Holding = 1,
    /// Every thread of the space is stopped or parked.
    Held = 2,
    /// A release's walk is in progress.
    Releasing = 3,
}

impl HoldState
{
    /// Decode the byte `AddressSpace::hold` stores; an unknown value, which
    /// no store writes, reads as `Free`.
    #[must_use]
    pub const fn from_u8(raw: u8) -> Self
    {
        match raw
        {
            1 => Self::Holding,
            2 => Self::Held,
            3 => Self::Releasing,
            _ => Self::Free,
        }
    }

    /// Whether a start of a thread of the space is deferred to the release.
    /// A start made while a release walks is not: the walk may already have
    /// passed the thread, and the release starts nothing it does not mark.
    #[must_use]
    pub const fn defers_start(self) -> bool
    {
        matches!(self, Self::Holding | Self::Held)
    }
}

/// What a hold or release has done to one thread (`ThreadControlBlock::hold`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldMark
{
    /// No hold applies to the thread.
    None,
    /// The hold found the thread `Running` or `Blocked`: its next passage
    /// toward `Ready` commits `Stopped` and moves the mark to
    /// [`HoldMark::Stopped`].
    Pending,
    /// The hold stopped the thread, diverted its passage toward `Ready`, or
    /// deferred its start; the release starts it.
    Stopped,
}

/// What a hold's walk does to one thread of the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldVisit
{
    /// `Ready`: commit `Stopped` under every CPU lock, draining its run-queue
    /// link, and mark it [`HoldMark::Stopped`].
    Stop,
    /// `Running` or `Blocked`: mark it [`HoldMark::Pending`]. A running
    /// thread is diverted when it next leaves its CPU runnable (its slice
    /// expiry, a yield, a refused park), a parked one by the wake that ends its
    /// park.
    Mark,
    /// `Created`, `Stopped` or `Exited`: nothing. A `Created` thread's start
    /// is deferred, and a thread a debugger stopped stays stopped.
    Leave,
}

/// The hold walk's decision for a thread in `state`.
#[must_use]
pub const fn hold_visit(state: ThreadState) -> HoldVisit
{
    match state
    {
        ThreadState::Ready => HoldVisit::Stop,
        ThreadState::Running | ThreadState::Blocked => HoldVisit::Mark,
        ThreadState::Created | ThreadState::Stopped | ThreadState::Exited => HoldVisit::Leave,
    }
}

/// Whether a thread carrying `mark` commits `Stopped` at its passage toward
/// `Ready` instead: the wake of its park (`enqueue_and_wake`'s `Blocked`
/// arm) or the requeue of a runnable outgoing thread (`schedule()`).
#[must_use]
pub const fn diverts(mark: HoldMark) -> bool
{
    matches!(mark, HoldMark::Pending)
}

/// What a `SYS_THREAD_START` commit does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartDecision
{
    /// Commit `Ready`; the start links the thread.
    Commit,
    /// The space is held: commit `Stopped` (from `Created` as from
    /// `Stopped`) and mark it [`HoldMark::Stopped`], linking nothing; the
    /// release starts it.
    Defer,
    /// Refused: the thread is neither `Created` nor `Stopped`, or it is
    /// stopped only by the hold, so that to its starter it is running.
    Refuse,
}

/// The start commit's decision for a thread in `state` carrying `mark`, of
/// a space in hold state `space`.
#[must_use]
pub const fn start_decision(space: HoldState, state: ThreadState, mark: HoldMark) -> StartDecision
{
    if !matches!(state, ThreadState::Created | ThreadState::Stopped)
        || matches!(mark, HoldMark::Stopped)
    {
        StartDecision::Refuse
    }
    else if space.defers_start()
    {
        StartDecision::Defer
    }
    else
    {
        StartDecision::Commit
    }
}

/// What a release's walk does to one thread of the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseVisit
{
    /// `Stopped` and marked [`HoldMark::Stopped`]: start it (commit `Ready`
    /// and link it), clearing the mark, once it is settled; an unsettled one
    /// waits for the walk's next pass.
    Start,
    /// Marked [`HoldMark::Pending`]: clear the mark, so the wake of its park
    /// links it as usual. Also a mark found on a thread that is no longer
    /// `Stopped`: an `Exited` thread a teardown has not yet unregistered is
    /// never started, since `Exited` is terminal.
    Clear,
    /// Unmarked: nothing.
    Leave,
}

/// The release walk's decision for a thread in `state` carrying `mark`.
#[must_use]
pub const fn release_visit(state: ThreadState, mark: HoldMark) -> ReleaseVisit
{
    match (mark, state)
    {
        (HoldMark::Stopped, ThreadState::Stopped) => ReleaseVisit::Start,
        (HoldMark::Stopped | HoldMark::Pending, _) => ReleaseVisit::Clear,
        (HoldMark::None, _) => ReleaseVisit::Leave,
    }
}

/// Whether `SYS_THREAD_STOP` refuses a thread in `state` carrying `mark`
/// (`InvalidState`). A thread stopped only by a hold is running to its
/// stopper: the stop succeeds and clears the mark, so the release leaves it
/// stopped.
#[must_use]
pub const fn stop_refused(state: ThreadState, mark: HoldMark) -> bool
{
    match state
    {
        ThreadState::Created | ThreadState::Exited => true,
        ThreadState::Stopped => !matches!(mark, HoldMark::Stopped),
        ThreadState::Ready | ThreadState::Running | ThreadState::Blocked => false,
    }
}

// ── Applying the decisions ────────────────────────────────────────────────────

#[cfg(not(test))]
use super::thread::ThreadControlBlock;
#[cfg(not(test))]
use crate::mm::address_space::AddressSpace;

/// Outcome of [`hold_space`].
#[cfg(not(test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldOutcome
{
    /// The space is held: none of its threads is current on any CPU, each
    /// one's register save has published, and none runs before the release.
    Held,
    /// The space was not `Free`: it is held, or a hold or a release of it is
    /// in progress. Nothing was done.
    Busy,
    /// The calling thread was itself stopped, killed, or marked by a hold of
    /// its own space while it waited. The hold was undone, as a release undoes
    /// it, and the caller must leave its CPU.
    Cancelled,
}

/// Hold the address space `aspace`: stop every thread of it without
/// cancelling any park, and defer every start of one, until
/// [`release_space`] (core/kernel/docs/thread-lifecycle-and-sleep.md
/// § Address-Space Hold).
///
/// The hold moves the space `Free` to `Holding`, then walks the thread
/// registry under its lock and, under each thread's `sched_lock`, applies
/// [`hold_visit`]: a `Ready` thread is committed `Stopped` under every CPU
/// lock, its run-queue link drained, and a `Running` or `Blocked` one is
/// marked [`HoldMark::Pending`]. It then waits, preempt-disabled with
/// interrupts enabled, until no CPU runs a thread of the space and each one's
/// register save has published (spin site `hold:settle`), and stores `Held`.
/// A marked running thread leaves its CPU at its next reschedule (its slice
/// expiry, at most one quantum, or its own park or yield), which diverts it.
///
/// A pass that must wait first reads the caller, under its `sched_lock`: a
/// caller stopped, `Exited`, or marked by a hold of its own space is waited
/// for by others, so its hold is undone (the release walk) and
/// [`HoldOutcome::Cancelled`] returned; two threads holding each other's
/// space would otherwise wait for each other forever.
///
/// The walk takes every CPU lock once per `Ready` thread of the space, as the
/// object-teardown walk does, and like it holds the registry lock, with
/// interrupts disabled on this CPU, for one batch at a time
/// ([`super::thread_registry::for_each`]), opening an interrupt window between
/// batches. A thread created into the space after the walk began, which the
/// walk may miss, has its start deferred, since the space is `Holding` first.
///
/// # Safety
/// `aspace` must be a valid address space that the caller keeps live for the
/// call (its capability pinned), other than the caller's own; `caller` must
/// be the running thread's TCB; no lock may be held.
#[cfg(not(test))]
pub unsafe fn hold_space(
    aspace: *const AddressSpace,
    caller: *mut ThreadControlBlock,
) -> HoldOutcome
{
    // SAFETY: aspace is valid and live for the call (contract).
    let space = unsafe { &*aspace };
    if !space.swap_hold_state(HoldState::Free, HoldState::Holding)
    {
        return HoldOutcome::Busy;
    }
    let visit = |tcb| {
        // SAFETY: the registry walk passes a registered TCB and holds only
        // its own lock.
        unsafe { hold_visit_thread(tcb, aspace) }
    };
    // SAFETY: no lock is held (contract); the visit registers no thread, takes
    // only a sched_lock and the run-queue locks, and waits on no CPU.
    unsafe { super::thread_registry::for_each(visit) };
    // SAFETY: aspace is valid (contract), and settle_spin calls this with no
    // lock held.
    let done = || unsafe { held_settled(aspace) };
    // SAFETY: caller is the running thread (contract), and settle_spin calls
    // this with no lock held.
    let abandon = || unsafe { caller_must_leave(caller) };
    // SAFETY: no lock is held; the closures take only a sched_lock, a CPU lock
    // or the registry lock, one at a time, and wait on nothing.
    let settled = unsafe { settle_spin(super::SPIN_SITE_HOLD_SETTLE, "hold_space", done, abandon) };
    if settled
    {
        space.set_hold_state(HoldState::Held);
        return HoldOutcome::Held;
    }
    // Undo the hold. This hold owns the space's state until it stores `Free`,
    // so no other hold or release runs meanwhile.
    space.set_hold_state(HoldState::Releasing);
    // SAFETY: aspace valid (contract); no lock is held.
    unsafe { release_walk(aspace) };
    space.set_hold_state(HoldState::Free);
    HoldOutcome::Cancelled
}

/// Release the held address space `aspace`: start exactly the threads the
/// hold stopped, diverted, or whose start it deferred, and clear the mark of
/// each thread still parked; `false`, doing nothing, when the space is not
/// `Held`.
///
/// The release moves the space `Held` to `Releasing`, walks the thread
/// registry applying [`release_visit`] under each thread's `sched_lock`,
/// and stores `Free`. A thread to start is committed `Ready` under every
/// CPU lock, with its start generation advanced, only once it is settled
/// (`start_ready_to_link`), then linked as a `SYS_THREAD_START` links it.
/// One that is not yet (a thread diverted by a wake while still switching
/// out, or a waker still releasing its pin) is left for another pass, made
/// with interrupts enabled after a spin (spin site `release:settle`); each
/// such wait is the tail of a switch or of a wake already under way, which no
/// other thread's progress gates.
///
/// # Safety
/// As for [`hold_space`], without the `caller`.
#[cfg(not(test))]
pub unsafe fn release_space(aspace: *const AddressSpace) -> bool
{
    // SAFETY: aspace is valid and live for the call (contract).
    let space = unsafe { &*aspace };
    if !space.swap_hold_state(HoldState::Held, HoldState::Releasing)
    {
        return false;
    }
    // SAFETY: aspace valid (contract); no lock is held.
    unsafe { release_walk(aspace) };
    space.set_hold_state(HoldState::Free);
    true
}

/// Walk the registry applying [`release_visit`] to every thread of
/// `aspace` until no thread to start is left unsettled.
///
/// # Safety
/// `aspace` must be valid; no lock may be held.
#[cfg(not(test))]
unsafe fn release_walk(aspace: *const AddressSpace)
{
    let pass = || {
        let mut unsettled = false;
        let visit = |tcb: *mut ThreadControlBlock| {
            // SAFETY: the registry walk passes a registered TCB; address_space
            // is read-only after creation.
            let in_space = core::ptr::eq(unsafe { (*tcb).address_space }, aspace);
            // SAFETY: the registry walk passes a registered TCB and holds
            // only its own lock.
            unsettled |= unsafe { release_visit_thread(tcb, aspace) };
            if in_space
            {
                super::thread_registry::Visit::Acted
            }
            else
            {
                super::thread_registry::Visit::Passed
            }
        };
        // SAFETY: no lock is held (contract); the visit registers no thread,
        // takes only a sched_lock and the run-queue locks, and waits on no
        // CPU (the link sends at most an IPI).
        unsafe { super::thread_registry::for_each(visit) };
        !unsettled
    };
    if pass()
    {
        return;
    }
    // SAFETY: no lock is held.
    unsafe {
        settle_spin(
            super::SPIN_SITE_RELEASE_SETTLE,
            "release_space",
            pass,
            || false,
        )
    };
}

/// Apply [`hold_visit`] to `tcb` when it executes in `aspace`; returns what
/// the visit cost the walk.
///
/// # Safety
/// `tcb` must be a registered TCB (the registry walk's argument); the
/// caller holds the registry lock and no other.
#[cfg(not(test))]
unsafe fn hold_visit_thread(
    tcb: *mut ThreadControlBlock,
    aspace: *const AddressSpace,
) -> super::thread_registry::Visit
{
    // SAFETY: tcb is registered, so valid; address_space is read-only after
    // creation.
    if !core::ptr::eq(unsafe { (*tcb).address_space }, aspace)
    {
        return super::thread_registry::Visit::Passed;
    }
    // SAFETY: tcb valid, as above.
    let lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: only the registry lock is held, which orders before sched_lock;
    // paired with the unlock_raw below.
    let f = unsafe { lock.lock_raw() };
    // SAFETY: tcb valid; state is written under its sched_lock, held here.
    match hold_visit(unsafe { (*tcb).state })
    {
        HoldVisit::Stop =>
        {
            // SAFETY: tcb valid and `Ready` under its held sched_lock; no CPU
            // lock is held.
            unsafe { stop_ready_under_cpu_locks(tcb) };
        }
        HoldVisit::Mark =>
        {
            // SAFETY: tcb valid; the mark is written under its sched_lock, held.
            unsafe { (*tcb).hold = HoldMark::Pending };
        }
        HoldVisit::Leave =>
        {}
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(f) };
    super::thread_registry::Visit::Acted
}

/// Commit the `Ready` thread `tcb` `Stopped` and marked
/// [`HoldMark::Stopped`] under every CPU lock, draining its run-queue link,
/// as a `SYS_THREAD_STOP` commit does. A CPU whose dispatch has already
/// dequeued it finds it `Stopped` at its dispatch flip and runs its idle
/// thread instead.
///
/// # Safety
/// `tcb` must be valid, and the caller must hold its `sched_lock` and no
/// CPU lock.
#[cfg(not(test))]
unsafe fn stop_ready_under_cpu_locks(tcb: *mut ThreadControlBlock)
{
    let cpu_count = super::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; the scheduler slab is initialised.
        let sched = unsafe { super::scheduler_for(cpu) };
        // SAFETY: taken in ascending order after the sched_lock; paired with
        // unlock_saved_flags below.
        unsafe { sched.lock_saving_flags() };
    }
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "fields of one valid TCB under its held sched_lock and every CPU lock"
    )]
    // SAFETY: tcb valid; state, hold and priority are written under its
    // sched_lock, held.
    let priority = unsafe {
        (*tcb).state = ThreadState::Stopped;
        (*tcb).hold = HoldMark::Stopped;
        (*tcb).priority
    };
    // SAFETY: every CPU's lock is held; tcb valid.
    unsafe { super::drain_from_every_queue(tcb, priority, cpu_count) };
    for cpu in (0..cpu_count).rev()
    {
        // SAFETY: cpu < cpu_count; the scheduler slab is initialised.
        let sched = unsafe { super::scheduler_for(cpu) };
        // SAFETY: paired with lock_saving_flags above.
        unsafe { sched.unlock_saved_flags() };
    }
}

/// Apply [`release_visit`] to `tcb` when it executes in `aspace`; `true`
/// when it is to be started but is not yet settled.
///
/// # Safety
/// As for [`hold_visit_thread`].
#[cfg(not(test))]
unsafe fn release_visit_thread(tcb: *mut ThreadControlBlock, aspace: *const AddressSpace) -> bool
{
    // SAFETY: tcb is registered, so valid; address_space is read-only after
    // creation.
    if !core::ptr::eq(unsafe { (*tcb).address_space }, aspace)
    {
        return false;
    }
    // SAFETY: tcb valid, as above.
    let lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: only the registry lock is held; paired with the unlock_raw below.
    let f = unsafe { lock.lock_raw() };
    let mut started = None;
    let mut unsettled = false;
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "both reads are of tcb fields its held sched_lock serialises"
    )]
    // SAFETY: tcb valid; its state and mark are written under its sched_lock,
    // held here.
    let (state, mark) = unsafe { ((*tcb).state, (*tcb).hold) };
    match release_visit(state, mark)
    {
        ReleaseVisit::Start =>
        {
            // SAFETY: tcb valid; its sched_lock is held and no CPU lock.
            started = unsafe { start_under_cpu_locks(tcb) };
            unsettled = started.is_none();
        }
        ReleaseVisit::Clear =>
        {
            // SAFETY: tcb valid; the mark is written under its sched_lock, held.
            unsafe { (*tcb).hold = HoldMark::None };
        }
        ReleaseVisit::Leave =>
        {}
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(f) };
    if let Some(seq) = started
    {
        // SAFETY: tcb valid, registered for the walk.
        let cpu = unsafe { super::select_target_cpu(tcb) };
        // A stop or an exit landing since the commit supersedes the link, and
        // takes effect over the release's start, as over a SYS_THREAD_START.
        // SAFETY: tcb valid; `Ready` at `seq` it is unlinked and current
        // nowhere (the commit's checks); cpu is a started CPU; no run-queue
        // lock is held.
        let _ = unsafe { super::enqueue_ready_thread(tcb, cpu, seq) };
    }
    unsettled
}

/// Commit the hold-stopped `tcb` `Ready` under every CPU lock when it is
/// settled (`start_ready_to_link`), advancing its start generation and
/// clearing its mark; the new generation, or `None`, writing nothing, when it
/// is not yet settled.
///
/// # Safety
/// `tcb` must be valid, and the caller must hold its `sched_lock` and no
/// CPU lock.
#[cfg(not(test))]
unsafe fn start_under_cpu_locks(tcb: *mut ThreadControlBlock) -> Option<u32>
{
    let cpu_count = super::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; the scheduler slab is initialised.
        let sched = unsafe { super::scheduler_for(cpu) };
        // SAFETY: taken in ascending order after the sched_lock; paired with
        // unlock_saved_flags below.
        unsafe { sched.lock_saving_flags() };
    }
    // SAFETY: tcb valid; its sched_lock and every CPU lock are held.
    let seq = unsafe { super::start_ready_to_link(tcb, cpu_count) }.then(|| {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "fields of one valid TCB under its held sched_lock and every CPU lock"
        )]
        // SAFETY: tcb valid; start_seq, state and hold are written under its
        // sched_lock, held.
        unsafe {
            (*tcb).start_seq = (*tcb).start_seq.wrapping_add(1);
            (*tcb).state = ThreadState::Ready;
            (*tcb).hold = HoldMark::None;
            (*tcb).start_seq
        }
    });
    for cpu in (0..cpu_count).rev()
    {
        // SAFETY: cpu < cpu_count; the scheduler slab is initialised.
        let sched = unsafe { super::scheduler_for(cpu) };
        // SAFETY: paired with lock_saving_flags above.
        unsafe { sched.unlock_saved_flags() };
    }
    seq
}

/// Whether the hold of `aspace` may return: no CPU's `current` executes in
/// it, and every thread of it has published its register save.
///
/// No thread of a space being held becomes `current` once the hold's walk
/// has passed: it found none `Ready` that it did not stop, the starts it
/// missed are deferred, and the diverts link none. So a check that finds both
/// stays true until the release.
///
/// # Safety
/// `aspace` must be valid; no lock may be held.
#[cfg(not(test))]
unsafe fn held_settled(aspace: *const AddressSpace) -> bool
{
    let cpu_count = super::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; the scheduler slab is initialised.
        let sched = unsafe { super::scheduler_for(cpu) };
        // SAFETY: no lock is held; paired with the unlock_raw below.
        let f = unsafe { sched.lock.lock_raw() };
        let cur = sched.current();
        let bound = !cur.is_null()
            // SAFETY: `current` is stable under its CPU's lock, held here, and
            // a current thread is valid; address_space is read-only.
            && core::ptr::eq(unsafe { (*cur).address_space }, aspace);
        // SAFETY: paired with the lock_raw above.
        unsafe { sched.lock.unlock_raw(f) };
        if bound
        {
            return false;
        }
    }
    let mut saved = true;
    let check = |tcb: *mut ThreadControlBlock| {
        // SAFETY: tcb is registered for the call, so valid; address_space is
        // read-only after creation.
        let bound = core::ptr::eq(unsafe { (*tcb).address_space }, aspace);
        // SAFETY: as above; context_saved is atomic.
        let flag = unsafe { &(*tcb).context_saved };
        saved &= !bound || flag.load(core::sync::atomic::Ordering::Acquire) != 0;
        super::thread_registry::Visit::Passed
    };
    // SAFETY: no lock is held; the closure only reads two fields of each
    // registered TCB.
    unsafe { super::thread_registry::for_each(check) };
    saved
}

/// Whether the holding thread `caller` must leave its CPU instead of
/// waiting: it is `Stopped` or `Exited`, or a hold of its own space marked
/// it. Read under its `sched_lock`, which each of those writes holds.
///
/// # Safety
/// `caller` must be the running thread's TCB; no lock may be held.
#[cfg(not(test))]
unsafe fn caller_must_leave(caller: *mut ThreadControlBlock) -> bool
{
    // SAFETY: caller is the running thread's valid TCB.
    let lock = unsafe { &(*caller).sched_lock };
    // SAFETY: no lock is held; paired with the unlock_raw below.
    let f = unsafe { lock.lock_raw() };
    // SAFETY: caller valid; state is written under its sched_lock, held.
    let state = unsafe { (*caller).state };
    // SAFETY: as for state.
    let mark = unsafe { (*caller).hold };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(f) };
    matches!(state, ThreadState::Stopped | ThreadState::Exited) || mark == HoldMark::Pending
}

/// Spin, preempt-disabled with interrupts enabled (the #207 envelope, so
/// this CPU still takes the IPIs other CPUs wait on), until `done` holds,
/// returning `true`, or a pass where it does not finds `abandon` true,
/// returning `false`. Records `site` for the watchdog and warns once after
/// 100 ms.
///
/// # Safety
/// No lock may be held; `done` and `abandon` must not wait.
#[cfg(not(test))]
unsafe fn settle_spin(
    site: u32,
    what: &str,
    mut done: impl FnMut() -> bool,
    mut abandon: impl FnMut() -> bool,
) -> bool
{
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    super::spin_site_enter(site);
    let mut warn = super::SpinWarnOnce::new();
    let finished = loop
    {
        if done()
        {
            break true;
        }
        if abandon()
        {
            break false;
        }
        if warn.due()
        {
            let cpu = crate::arch::current::cpu::current_cpu();
            crate::kprintln!("kernel: {what} spin >100ms on cpu {cpu}");
        }
        core::hint::spin_loop();
    };
    super::spin_site_exit();
    // SAFETY: saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
    crate::percpu::preempt_enable();
    finished
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::collections::{HashSet, VecDeque};

    /// Threads in the modelled space.
    const N: usize = 3;

    /// One modelled thread: the scheduler's state and hold mark, whether a
    /// debugger stop (not the hold) is what holds it `Stopped`, and whether
    /// the hold or release walk in progress has visited it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Thread
    {
        state: ThreadState,
        mark: HoldMark,
        debug_stopped: bool,
        visited: bool,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Space
    {
        hold: HoldState,
        threads: [Thread; N],
    }

    impl Space
    {
        fn key(&self) -> u64
        {
            let mut key = self.hold as u64;
            for t in &self.threads
            {
                key = key * 64
                    + (t.state as u64) * 8
                    + (t.mark as u64) * 2
                    + u64::from(t.debug_stopped);
                key = key * 2 + u64::from(t.visited);
            }
            key
        }
    }

    /// Every event the kernel can apply to the space or to thread `i`, as the
    /// scheduler applies the decisions of this module. `None` when the event
    /// does not apply in this state.
    fn step(s: &Space, event: usize) -> Option<Space>
    {
        let (kind, i) = (event / N, event % N);
        if kind < 6
        {
            space_step(s, kind, i)
        }
        else
        {
            let mut n = *s;
            n.threads[i] = thread_step(s.hold, n.threads[i], kind)?;
            Some(n)
        }
    }

    /// The hold's and the release's own steps: begin (a compare-exchange of
    /// the space's state), the walk's visit of thread `i`, and the return.
    fn space_step(s: &Space, kind: usize, i: usize) -> Option<Space>
    {
        let mut n = *s;
        let all_visited = s.threads.iter().all(|t| t.visited);
        match kind
        {
            // SYS_ASPACE_HOLD's compare-exchange from Free.
            0 if i == 0 && s.hold == HoldState::Free =>
            {
                n.hold = HoldState::Holding;
                n.threads.iter_mut().for_each(|t| t.visited = false);
            }
            // The hold walk visits thread i.
            1 if s.hold == HoldState::Holding && !s.threads[i].visited =>
            {
                let t = &mut n.threads[i];
                t.visited = true;
                match hold_visit(t.state)
                {
                    HoldVisit::Stop =>
                    {
                        (t.state, t.mark) = (ThreadState::Stopped, HoldMark::Stopped);
                    }
                    HoldVisit::Mark => t.mark = HoldMark::Pending,
                    HoldVisit::Leave =>
                    {}
                }
            }
            // The hold returns: walked, and no thread of the space current.
            2 if i == 0
                && s.hold == HoldState::Holding
                && all_visited
                && s.threads.iter().all(|t| t.state != ThreadState::Running) =>
            {
                n.hold = HoldState::Held;
            }
            // SYS_ASPACE_RELEASE's compare-exchange from Held.
            3 if i == 0 && s.hold == HoldState::Held =>
            {
                n.hold = HoldState::Releasing;
                n.threads.iter_mut().for_each(|t| t.visited = false);
            }
            // The release walk visits thread i.
            4 if s.hold == HoldState::Releasing && !s.threads[i].visited =>
            {
                let t = &mut n.threads[i];
                t.visited = true;
                match release_visit(t.state, t.mark)
                {
                    ReleaseVisit::Start =>
                    {
                        assert!(
                            !t.debug_stopped,
                            "the release started a debugger-stopped thread"
                        );
                        (t.state, t.mark) = (ThreadState::Ready, HoldMark::None);
                    }
                    ReleaseVisit::Clear => t.mark = HoldMark::None,
                    ReleaseVisit::Leave =>
                    {}
                }
            }
            // The release returns.
            5 if i == 0 && s.hold == HoldState::Releasing && all_visited =>
            {
                n.hold = HoldState::Free;
            }
            _ => return None,
        }
        Some(n)
    }

    /// The steps of one thread `t` of a space in hold state `hold`.
    fn thread_step(hold: HoldState, mut t: Thread, kind: usize) -> Option<Thread>
    {
        match kind
        {
            // The wake that ends a park (a reply, a send, a timer, a cancel),
            // or a running thread leaving its CPU runnable (preemption, a
            // yield, a refused park: schedule()'s requeue).
            6 | 7
                if (kind == 6 && t.state == ThreadState::Blocked)
                    || (kind == 7 && t.state == ThreadState::Running) =>
            {
                if diverts(t.mark)
                {
                    (t.state, t.mark) = (ThreadState::Stopped, HoldMark::Stopped);
                }
                else
                {
                    t.state = ThreadState::Ready;
                }
            }
            // A running thread commits a park.
            8 if t.state == ThreadState::Running => t.state = ThreadState::Blocked,
            // A CPU dispatches a ready thread.
            9 if t.state == ThreadState::Ready => t.state = ThreadState::Running,
            // SYS_THREAD_START.
            10 => match start_decision(hold, t.state, t.mark)
            {
                StartDecision::Commit => (t.state, t.debug_stopped) = (ThreadState::Ready, false),
                StartDecision::Defer =>
                {
                    (t.state, t.mark, t.debug_stopped) =
                        (ThreadState::Stopped, HoldMark::Stopped, false);
                }
                StartDecision::Refuse => return None,
            },
            // SYS_THREAD_STOP (a debugger), which cancels any park.
            11 if !stop_refused(t.state, t.mark) =>
            {
                (t.state, t.mark, t.debug_stopped) = (ThreadState::Stopped, HoldMark::None, true);
            }
            // An exit, or the teardown of the space: Exited clears the mark.
            12 if t.state != ThreadState::Exited =>
            {
                (t.state, t.mark, t.debug_stopped) = (ThreadState::Exited, HoldMark::None, false);
            }
            _ => return None,
        }
        Some(t)
    }

    /// The hold's invariants (core/kernel/docs/thread-lifecycle-and-sleep.md
    /// § Address-Space Hold), checked on one reachable state.
    fn check(s: &Space)
    {
        for t in &s.threads
        {
            match t.mark
            {
                HoldMark::Stopped =>
                {
                    assert_eq!(t.state, ThreadState::Stopped, "a hold-stopped thread runs");
                }
                HoldMark::Pending => assert!(
                    matches!(t.state, ThreadState::Running | ThreadState::Blocked),
                    "a pending mark outlived the thread's run or park"
                ),
                HoldMark::None =>
                {}
            }
            if t.debug_stopped
            {
                assert_eq!(t.state, ThreadState::Stopped, "a debugger stop was undone");
                assert_eq!(
                    t.mark,
                    HoldMark::None,
                    "the release would start a debugger-stopped thread"
                );
            }
            // Containment: a thread the hold has reached is never made runnable
            // while the space is held, and only one already running at the
            // hold may still run until it leaves its CPU.
            let reached = match s.hold
            {
                HoldState::Holding => t.visited,
                HoldState::Held => true,
                HoldState::Free | HoldState::Releasing => false,
            };
            if reached
            {
                assert_ne!(
                    t.state,
                    ThreadState::Ready,
                    "a held thread was made runnable"
                );
                if t.state == ThreadState::Running
                {
                    assert_eq!(t.mark, HoldMark::Pending, "a held thread runs unmarked");
                }
            }
        }
        if s.hold == HoldState::Free
        {
            assert!(
                s.threads.iter().all(|t| t.mark == HoldMark::None),
                "a mark survived the release"
            );
        }
    }

    #[test]
    fn the_release_starts_only_a_stopped_thread_and_clears_every_other_mark()
    {
        // A teardown commits Exited before it unregisters the thread, so a
        // release walk can meet an Exited thread; Exited is terminal.
        for state in [
            ThreadState::Created,
            ThreadState::Ready,
            ThreadState::Running,
            ThreadState::Blocked,
            ThreadState::Stopped,
            ThreadState::Exited,
        ]
        {
            let stopped = release_visit(state, HoldMark::Stopped);
            if state == ThreadState::Stopped
            {
                assert_eq!(stopped, ReleaseVisit::Start);
            }
            else
            {
                assert_eq!(stopped, ReleaseVisit::Clear, "{state:?}");
            }
            assert_eq!(release_visit(state, HoldMark::Pending), ReleaseVisit::Clear);
            assert_eq!(release_visit(state, HoldMark::None), ReleaseVisit::Leave);
        }
    }

    #[test]
    fn every_reachable_state_of_a_held_and_released_space_keeps_the_hold_invariants()
    {
        let starts = [
            (ThreadState::Created, false),
            (ThreadState::Ready, false),
            (ThreadState::Running, false),
            (ThreadState::Blocked, false),
            (ThreadState::Stopped, true),
            (ThreadState::Exited, false),
        ];
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        for a in starts
        {
            for b in starts
            {
                for c in starts
                {
                    let thread = |(state, debug_stopped): (ThreadState, bool)| Thread {
                        state,
                        mark: HoldMark::None,
                        debug_stopped,
                        visited: false,
                    };
                    let s = Space {
                        hold: HoldState::Free,
                        threads: [thread(a), thread(b), thread(c)],
                    };
                    if seen.insert(s.key())
                    {
                        queue.push_back(s);
                    }
                }
            }
        }
        let mut released = 0usize;
        while let Some(s) = queue.pop_front()
        {
            check(&s);
            for event in 0..13 * N
            {
                if let Some(next) = step(&s, event)
                {
                    if s.hold == HoldState::Releasing && next.hold == HoldState::Free
                    {
                        released += 1;
                    }
                    if seen.insert(next.key())
                    {
                        queue.push_back(next);
                    }
                }
            }
        }
        // The exploration reached complete holds and releases, not only the
        // initial states.
        assert!(released > 0);
        assert!(seen.iter().any(|&k| k >> (7 * N) == HoldState::Held as u64));
    }

    #[test]
    fn a_wake_during_the_hold_stops_its_thread_and_the_release_starts_it()
    {
        let blocked = Thread {
            state: ThreadState::Blocked,
            mark: HoldMark::None,
            debug_stopped: false,
            visited: false,
        };
        let mut s = Space {
            hold: HoldState::Free,
            threads: [blocked; N],
        };
        // Hold, walk, return.
        s = step(&s, 0).unwrap();
        for i in 0..N
        {
            s = step(&s, N + i).unwrap();
        }
        s = step(&s, 2 * N).unwrap();
        assert_eq!(s.hold, HoldState::Held);
        // The park of thread 0 ends during the hold: its outcome is deposited
        // but it is stopped, not made runnable.
        s = step(&s, 6 * N).unwrap();
        assert_eq!(s.threads[0].state, ThreadState::Stopped);
        // Release: thread 0 runs again; threads 1 and 2 stay parked, unmarked.
        s = step(&s, 3 * N).unwrap();
        for i in 0..N
        {
            s = step(&s, 4 * N + i).unwrap();
        }
        s = step(&s, 5 * N).unwrap();
        assert_eq!(s.threads[0].state, ThreadState::Ready);
        assert_eq!(s.threads[1].state, ThreadState::Blocked);
        assert_eq!(s.threads[1].mark, HoldMark::None);
    }
}
