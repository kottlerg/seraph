// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/thread_registry.rs

//! Global live-thread registry — an intrusive doubly-linked list of every
//! live TCB.
//!
//! Threads are spliced in at construction ([`register`]) and removed at dealloc
//! ([`unregister`]), both under [`THREAD_REGISTRY_LOCK`]. The softlockup
//! watchdog walks it ([`try_for_each`]) to enumerate `Blocked` waiters that the
//! per-CPU `current` dump cannot reach: the lost-wakeup victim in #351 is a
//! `Blocked` thread referenced only by the IPC object it parked on, invisible
//! to a `current`-only dump. Object teardown walks it ([`for_each`]) to find
//! and stop every thread bound to a dying `CSpace` or `AddressSpace`
//! (`sched::stop_threads_bound_to`), and to withdraw a dying `IoPort`'s
//! bindings and free a dying `CSpace`'s port-binding tables
//! (`cap::ioport_bindings`). The address-space hold and release walk it
//! ([`for_each`]) to find every thread of the held space.
//!
//! [`THREAD_REGISTRY_LOCK`] sits above every IPC-source, `SLEEP_LIST_LOCK`,
//! `sched_lock`, and run-queue lock; its ordering and the rule that it is never
//! held while waiting on another CPU's progress are specified in
//! core/kernel/docs/scheduling-internals.md § Lock Hierarchy, rule 3.
//!
//! A registry holds as many threads as memory backs, so no walk holds the lock
//! for more than one batch ([`REGISTRY_BATCH_COST`]): between batches it
//! releases the lock, and a walk made by a syscall opens an
//! `interrupt_window`. The walk keeps its place in a cursor that
//! [`unregister`] moves past the thread it unlinks
//! ([`super::registry_list`]), so a walk visits every thread registered for
//! its whole span once, and none after its unregister, whatever registers and
//! unregisters run between its batches; it may miss only a thread registered
//! after it began. A walk that takes more steps than the registry held when it
//! began has met a list corrupted into a cycle: the watchdog walk stops there
//! (it is already inside a fatal stall dump), the teardown walk halts the
//! kernel, since a thread it cannot enumerate could still be running on the
//! object being freed. See core/kernel/docs/scheduling-internals.md § Thread
//! Registry.

#![cfg(not(test))]

use super::registry_list::{Cursor, RegistryLinks, RegistryList, RegistryNode, Step};
use super::thread::ThreadControlBlock;
use crate::sync::Spinlock;

/// Serialises every access to the registry list and to the cursors of the
/// walks in progress. Ordered above every IPC-source, sleep-list,
/// `sched_lock`, and run-queue lock (see module docs).
static THREAD_REGISTRY_LOCK: Spinlock = Spinlock::new();

/// The registry. Guarded by [`THREAD_REGISTRY_LOCK`].
static mut THREAD_REGISTRY: RegistryList<ThreadControlBlock> = RegistryList::new();

impl RegistryNode for ThreadControlBlock
{
    unsafe fn links(node: *mut Self) -> *mut RegistryLinks<Self>
    {
        // SAFETY: node is a valid TCB (contract).
        unsafe { &raw mut (*node).registry }
    }
}

/// What a walk's visit of one thread cost, which decides when the walk's
/// batch is full ([`REGISTRY_BATCH_COST`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Visit
{
    /// The visit read the thread, at most under its `sched_lock`, and acted
    /// on nothing: one unit.
    Passed,
    /// The visit acted on the thread: a park's cancel and a commit under every
    /// CPU's lock, a hold's stop or start, or the rebuild or free of its
    /// port-binding table; [`VISIT_ACTED_COST`] units.
    Acted,
}

/// Cost units one registry walk spends per hold of [`THREAD_REGISTRY_LOCK`]
/// before it releases the lock (and, in a syscall, opens an
/// `interrupt_window`): 64 threads passed, or 8 acted on. The live threads
/// are as many as their creators made, and a visit costs at most an
/// all-CPU-locks transition or a port-binding bitmap's rebuild, so each hold,
/// and each stretch with interrupts masked, is one such batch.
pub const REGISTRY_BATCH_COST: u32 = 64;

/// The units of a [`Visit::Acted`].
pub const VISIT_ACTED_COST: u32 = 8;

impl Visit
{
    const fn cost(self) -> u32
    {
        match self
        {
            Visit::Passed => 1,
            Visit::Acted => VISIT_ACTED_COST,
        }
    }
}

/// The registry, reached only under [`THREAD_REGISTRY_LOCK`].
///
/// # Safety
/// The caller holds [`THREAD_REGISTRY_LOCK`] and keeps no other reference
/// to the registry while it uses this one.
unsafe fn registry() -> &'static mut RegistryList<ThreadControlBlock>
{
    // SAFETY: the held lock makes this the only reference (contract).
    unsafe { &mut *core::ptr::addr_of_mut!(THREAD_REGISTRY) }
}

/// Splice `tcb` onto the head of the live-thread registry, behind every walk
/// in progress.
///
/// # Safety
/// `tcb` must be a valid, freshly-constructed TCB that is not already on the
/// registry.
pub unsafe fn register(tcb: *mut ThreadControlBlock)
{
    // SAFETY: lock serialises all registry access.
    let saved = unsafe { THREAD_REGISTRY_LOCK.lock_raw() };
    // SAFETY: the lock is held; tcb is valid and on no list (contract), and
    // unregister precedes its free.
    let list = unsafe { registry() };
    // SAFETY: as above.
    unsafe { list.push_front(tcb) };
    // SAFETY: paired with lock_raw above.
    unsafe { THREAD_REGISTRY_LOCK.unlock_raw(saved) };
}

/// Remove `tcb` from the live-thread registry, moving every walk whose next
/// thread it is on to the thread after it. A no-op for a TCB that was never
/// registered (both links null and not the head), so it is safe to call on the
/// dealloc path regardless of whether the thread was ever linked.
///
/// Must run before the TCB storage is freed: a walk dereferences a thread only
/// under [`THREAD_REGISTRY_LOCK`], and holds no pointer to one across a
/// release of it but its cursor, which this moves on, so an unlink that
/// precedes the free guarantees no walk observes a dangling node.
///
/// # Safety
/// `tcb` must be a valid TCB pointer that is not concurrently freed.
pub unsafe fn unregister(tcb: *mut ThreadControlBlock)
{
    // SAFETY: lock serialises all registry access.
    let saved = unsafe { THREAD_REGISTRY_LOCK.lock_raw() };
    // SAFETY: the lock is held; tcb is valid (contract), on the registry or
    // on none.
    let list = unsafe { registry() };
    // SAFETY: as above.
    let _ = unsafe { list.remove(tcb) };
    // SAFETY: paired with lock_raw above.
    unsafe { THREAD_REGISTRY_LOCK.unlock_raw(saved) };
}

/// How a walk ended.
#[derive(PartialEq, Eq)]
enum WalkEnd
{
    /// It reached the end of the registry.
    Complete,
    /// It met a cycle.
    Cycle,
    /// A non-blocking walk found the lock contended between two batches.
    Contended,
}

/// Walk the registry from its head with `cursor`, attached by the caller
/// under the held lock, calling `f` on every thread, a batch of
/// [`REGISTRY_BATCH_COST`] at a time. Between batches `between` releases
/// the lock (its argument is the `lock_raw` flags), does what the walk
/// allows without it, and returns the flags of a new hold, or `None` when it
/// could not take the lock again; the walk then ends `Contended`, holding
/// nothing. Otherwise the walk returns with the lock held and its flags in
/// `saved`.
///
/// # Safety
/// The caller holds [`THREAD_REGISTRY_LOCK`] with flags `saved`, and
/// `cursor` is attached to the registry. `between` releases the lock
/// passed to it and returns holding it again, or holding nothing on `None`.
unsafe fn walk_batched(
    cursor: *mut Cursor<ThreadControlBlock>,
    saved: &mut u64,
    mut f: impl FnMut(*mut ThreadControlBlock) -> Visit,
    mut between: impl FnMut(u64) -> Option<u64>,
) -> WalkEnd
{
    let mut spent = 0u32;
    loop
    {
        // SAFETY: the lock is held and the cursor attached (contract).
        if spent >= REGISTRY_BATCH_COST && unsafe { RegistryList::has_next(cursor) }
        {
            spent = 0;
            let Some(flags) = between(*saved)
            else
            {
                return WalkEnd::Contended;
            };
            *saved = flags;
        }
        // SAFETY: as above.
        match unsafe { RegistryList::step(cursor) }
        {
            Step::Node(tcb) =>
            {
                // A node a step returns is registered, and stays so while the
                // lock is held, so `f` is given a valid TCB.
                spent = spent.saturating_add(f(tcb).cost());
            }
            Step::End => return WalkEnd::Complete,
            Step::Cycle => return WalkEnd::Cycle,
        }
    }
}

/// The cursor of the non-blocking walk ([`try_for_each`]), in static
/// storage so that a walk which finds the lock contended between two batches
/// can return without the lock and leave it attached: an attached cursor
/// stays valid wherever it is, since [`unregister`] moves it off a thread it
/// unlinks. Owned by the holder of [`TRY_WALK_BUSY`]; its fields are reached
/// under [`THREAD_REGISTRY_LOCK`].
static mut TRY_WALK_CURSOR: Cursor<ThreadControlBlock> = Cursor::new();

/// Whether [`TRY_WALK_CURSOR`] is attached. Guarded by
/// [`THREAD_REGISTRY_LOCK`].
static mut TRY_WALK_ATTACHED: bool = false;

/// Set while a [`try_for_each`] walk owns [`TRY_WALK_CURSOR`].
static TRY_WALK_BUSY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Walk the live-thread registry, invoking `f` on each registered TCB pointer.
///
/// Best-effort: if the registry lock is contended — a `register`/`unregister`
/// or another walk's batch is in flight, or a CPU died holding it — returns
/// `false`, at the start without walking or between two batches with the
/// walk incomplete, rather than spinning; so does a walk that starts while
/// another non-blocking walk (on another CPU) is in progress. The watchdog
/// must never block. It releases the lock between batches, so no other CPU
/// waits on it for more than one, but opens no `interrupt_window`: it runs in
/// interrupt context. Returns `true` if the walk reached the end of the
/// registry or met a corrupt cycle (which ends it early, silently: this is the
/// stall dump's own diagnostic path).
///
/// # Safety
/// `f` must not register, unregister or free any thread (it runs under
/// [`THREAD_REGISTRY_LOCK`]), nor keep a TCB pointer past its return. It may
/// read through the TCB pointer, and it may take locks that order after
/// `THREAD_REGISTRY_LOCK` (the TCB's `sched_lock`, and under it the lock of
/// the source the TCB is bound to) only by try-lock, releasing each before it
/// returns. The one lock it may wait for is the kernel console's
/// `CONSOLE_LOCK` (`kprintln_direct!`), a leaf spin lock no holder keeps across an
/// acquisition of any other lock, so its holder never waits on this walk.
pub unsafe fn try_for_each(mut f: impl FnMut(*mut ThreadControlBlock)) -> bool
{
    use core::sync::atomic::Ordering;
    if TRY_WALK_BUSY.swap(true, Ordering::Acquire)
    {
        return false;
    }
    // SAFETY: try_lock_raw never blocks; None means contended, so we back off.
    let Some(mut saved) = (unsafe { THREAD_REGISTRY_LOCK.try_lock_raw() })
    else
    {
        TRY_WALK_BUSY.store(false, Ordering::Release);
        return false;
    };
    let cursor = core::ptr::addr_of_mut!(TRY_WALK_CURSOR);
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "the attach flag and the cursor, both owned by this walk (TRY_WALK_BUSY) and \
                  reached under the held registry lock"
    )]
    // SAFETY: the lock is held and TRY_WALK_BUSY makes this walk the cursor's
    // only user; a cursor left attached by a walk that found the lock
    // contended is detached before it is attached again.
    unsafe {
        if TRY_WALK_ATTACHED
        {
            registry().detach(cursor);
        }
        registry().attach(cursor);
        TRY_WALK_ATTACHED = true;
    }
    let visit = |tcb| {
        f(tcb);
        Visit::Passed
    };
    let between = |flags: u64| {
        // The cursor stays attached across the release, and if the lock is
        // not free again, after the walk too.
        // SAFETY: paired with the lock_raw or try_lock_raw that returned flags.
        unsafe { THREAD_REGISTRY_LOCK.unlock_raw(flags) };
        // SAFETY: try_lock_raw never blocks.
        unsafe { THREAD_REGISTRY_LOCK.try_lock_raw() }
    };
    // SAFETY: the lock is held with flags `saved`, the cursor is attached,
    // and `between` releases the lock and returns holding it again or holding
    // nothing.
    let end = unsafe { walk_batched(cursor, &mut saved, visit, between) };
    if end != WalkEnd::Contended
    {
        // A cycle ends the walk early; this is the stall dump's own diagnostic
        // path, so the truncation is not reported further.
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "the cursor and its attach flag, owned by this walk, under the held lock"
        )]
        // SAFETY: the lock is held and the cursor attached.
        unsafe {
            registry().detach(cursor);
            TRY_WALK_ATTACHED = false;
        }
        // SAFETY: paired with the last lock_raw or try_lock_raw.
        unsafe { THREAD_REGISTRY_LOCK.unlock_raw(saved) };
    }
    TRY_WALK_BUSY.store(false, Ordering::Release);
    end != WalkEnd::Contended
}

/// Walk the live-thread registry, invoking `f` on every registered TCB
/// pointer — the walk of an object teardown and of an address-space hold or
/// release.
///
/// Blocks on the lock (teardown must not skip a thread the way the watchdog
/// may) and visits every thread registered for the walk's whole span: a
/// registry corrupted into a cycle is a fatal invariant break, because a
/// thread this walk cannot reach could still be running on the object being
/// freed. A thread registered after the walk began may be missed, and one
/// unregistered before the walk reached it is not visited. The lock is held
/// for one batch of [`REGISTRY_BATCH_COST`] at a time; between batches it is
/// released and an `interrupt_window` opens, so the walk masks interrupts for
/// one batch at a time whatever the number of live threads. While `f` runs
/// its TCB cannot be unregistered — and so cannot be freed, since every free
/// is preceded by [`unregister`] — but `f` must not wait for another CPU: a
/// CPU spinning on this lock inside [`register`] cannot deschedule, so a wait
/// for it here deadlocks.
///
/// # Safety
/// No lock is held, and the caller may take interrupts (an
/// `interrupt_window` opens between batches). `f` must not register or
/// unregister any thread, nor keep a TCB pointer past its return; it returns
/// what its visit cost. It may take IPC-source, `SLEEP_LIST_LOCK`,
/// `sched_lock`, and run-queue locks (all ordered after this lock) but must
/// not block or spin on another CPU's progress.
pub unsafe fn for_each(f: impl FnMut(*mut ThreadControlBlock) -> Visit)
{
    // SAFETY: lock serialises all registry access.
    let mut saved = unsafe { THREAD_REGISTRY_LOCK.lock_raw() };
    let mut cursor = Cursor::new();
    let cursor_ptr: *mut Cursor<ThreadControlBlock> = &raw mut cursor;
    // SAFETY: the lock is held; the cursor stays on this frame until the
    // detach below.
    let list = unsafe { registry() };
    // SAFETY: as above.
    unsafe { list.attach(cursor_ptr) };
    let between = |flags: u64| {
        // The cursor stays attached across the window: an unregister moves it
        // off the thread it unlinks.
        // SAFETY: paired with the lock_raw that returned flags.
        unsafe { THREAD_REGISTRY_LOCK.unlock_raw(flags) };
        crate::cap::object::interrupt_window();
        // SAFETY: lock serialises all registry access.
        Some(unsafe { THREAD_REGISTRY_LOCK.lock_raw() })
    };
    // SAFETY: the lock is held with flags `saved`, the cursor is attached,
    // and `between` releases the lock, opens a window with none held (the
    // caller holds none, by the contract), and retakes it.
    let end = unsafe { walk_batched(cursor_ptr, &mut saved, f, between) };
    // SAFETY: the lock is held (`between` never returns None) and the cursor
    // attached.
    let list = unsafe { registry() };
    // SAFETY: as above.
    unsafe { list.detach(cursor_ptr) };
    // SAFETY: paired with the last lock_raw.
    unsafe { THREAD_REGISTRY_LOCK.unlock_raw(saved) };
    if end == WalkEnd::Cycle
    {
        crate::fatal("thread registry: cycle detected during object teardown walk");
    }
}
