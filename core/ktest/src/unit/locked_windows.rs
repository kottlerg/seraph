// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/locked_windows.rs

//! Interrupts taken inside the walks and wake-all drains that hold a lock.
//!
//! A registry walk (`sched::thread_registry::for_each`) holds the registry lock for
//! one batch of visits at a time and opens an interrupt window between batches;
//! its callers are the stop of every thread bound to a dying `CSpace` or
//! address space, `SYS_ASPACE_HOLD`, and the withdrawal of an `IoPort` object's bindings
//! (`arch::x86_64::ioport_withdraw_windows`). A wake-all drain releases the waiters of a
//! notification, an event queue, a wait set or an endpoint a fixed number to a
//! hold of the source's lock, with a window between holds
//! (core/kernel/docs/scheduling-internals.md § Lock Hierarchy, rules 3 and 5).
//! Each case builds one such stretch well past one batch, makes the call that
//! starts it on the `crate::latency` rig, and judges it by a [`Bracket`] where
//! kernel state shows the stretch from outside, or by the call's first half
//! where it does not.
//!
//! The drain cases park [`WAITERS`] threads of one fresh address space on one
//! source, in FIFO order, pinned to `latency::WAITER_CPU`, and the worker, on another
//! CPU, deletes the source. Each wake of a waiter on a CPU other than the
//! waker's counts in the waiter's `THREAD_PLACEMENT_REMOTE_WAKES`, committed
//! under the drain's hold, so the first waiter's count rising is the drain's
//! first step and the last waiter's its last. The stop cases bracket the
//! stretch by the threads' `Exited` state, which the walk commits at its visit of
//! each. `SYS_ASPACE_HOLD` shows no step of its walk, and opens one more window after
//! it (its settle spin), so it is judged by the call's first half.

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::{
    aspace_release, cap_create_aspace, cap_create_cspace, cap_create_endpoint,
    cap_create_notification, cap_create_thread, cap_delete, cap_derive, cap_info_thread_placement,
    event_queue_create, mem_map, mem_unmap, thread_configure, thread_set_affinity, thread_sleep,
    thread_start, thread_yield, wait_set_create,
};
use syscall_abi::{
    MAP_WRITABLE, RIGHTS_ALL, RIGHTS_EP_RECEIVE, SYS_EVENT_RECV, SYS_IPC_CALL, SYS_IPC_RECV,
    SYS_NOTIFICATION_WAIT, SYS_THREAD_EXIT, SYS_WAIT_SET_WAIT, THREAD_PLACEMENT_REMOTE_WAKES,
    ipc_call_count_arg,
};

use super::teardown_windows::{Owned, delete_bracketed, run};
use crate::latency::{self, Call, Measured};
use crate::{TestContext, TestResult};

/// Threads parked on one source by the drain cases: eight batches of the
/// kernel's `DRAIN_BATCH_WAITERS`.
const WAITERS: usize = 128;
/// Threads bound to the dying object of the stop, hold and withdrawal cases:
/// 256 acted visits of the registry walk, 32 batches of its
/// `REGISTRY_BATCH_COST`.
pub(crate) const BOUND: usize = 256;
/// Most threads a [`ThreadSet`] holds.
const THREADS_MAX: usize = BOUND;
const _: () = assert!(WAITERS <= THREADS_MAX);
/// Pages of the dying `CSpace` of the stop case; the threads bound to it take none.
const DYING_CSPACE_PAGES: u64 = 4;
/// Pages of the address space the hold case holds.
const HELD_SPACE_PAGES: u64 = 8;
/// Pages of the waiters' address space: its stub, its record page and their
/// tables.
const WAITER_SPACE_PAGES: u64 = 8;
/// VA of the stub page in the waiters' space. Canonical in every paging mode
/// (below the 2^38 Sv39 user half) and distinct from other tests' VAs.
const STUB_VA: u64 = 0x3E_7200_0000;
/// VA of the record page in the waiters' space.
const DATA_VA: u64 = 0x3E_7210_0000;
/// VA of the record page in ktest's own space, a scratch VA (crate docs
/// § Scratch VAs).
const HOST_DATA_VA: u64 = 0x3E_7300_0000;
/// Stack pointer of every waiter; the program touches no stack.
const STACK: u64 = STUB_VA + 0x800;
/// Words of one record: the syscall number, six arguments and the result.
const RECORD_WORDS: u64 = 8;
/// Milliseconds the waiters are given to park after the last start.
const SETTLE_MS: u64 = 10;
/// Poll bound for the waiters' exits, applied through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;
/// Label of the callers' messages.
const CALL_LABEL: u64 = 0x4C57;

/// The capabilities of the one live [`ThreadSet`], in static storage: the sets are
/// too large for init's stack, and a case holds at most one at a time.
static SET_CAPS: [AtomicU64; THREADS_MAX] = [const { AtomicU64::new(0) }; THREADS_MAX];
/// Every waiter's remote-wake count before the call ([`Waiters::snapshot`]).
static BEFORE: [AtomicU64; WAITERS] = [const { AtomicU64::new(0) }; WAITERS];

/// Thread capabilities of ktest's own `CSpace`, deleted on drop, in creation order.
/// At most one set is live at a time: its capabilities are in [`SET_CAPS`].
pub(crate) struct ThreadSet
{
    len: usize,
}

impl ThreadSet
{
    /// A set holding none.
    pub(crate) const fn new() -> Self
    {
        Self { len: 0 }
    }

    /// Keep `cap`, the next thread's.
    pub(crate) fn push(&mut self, cap: u64) -> TestResult
    {
        SET_CAPS
            .get(self.len)
            .ok_or("locked_windows: the thread set is full")?
            .store(cap, Ordering::Relaxed);
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// The capability of the `index`th thread created, or 0 past the last.
    pub(crate) fn get(&self, index: usize) -> u64
    {
        if index < self.len
        {
            SET_CAPS
                .get(index)
                .map_or(0, |cap| cap.load(Ordering::Relaxed))
        }
        else
        {
            0
        }
    }

    /// The threads' capabilities, in creation order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = u64> + '_
    {
        (0..self.len).map(|index| self.get(index))
    }

    /// The first and the last thread created.
    pub(crate) fn ends(&self) -> Result<(u64, u64), &'static str>
    {
        let last = self
            .len
            .checked_sub(1)
            .ok_or("locked_windows: the thread set is empty")?;
        Ok((self.get(0), self.get(last)))
    }

    /// Create `count` threads in `aspace` and `cspace`, never started.
    pub(crate) fn create(
        &mut self,
        ctx: &TestContext,
        aspace: u64,
        cspace: u64,
        count: usize,
    ) -> TestResult
    {
        for _ in 0..count
        {
            let thread = cap_create_thread(ctx.memory_base, aspace, cspace, 0, 0)
                .map_err(|_| "locked_windows: create a thread failed")?;
            self.push(thread)?;
        }
        Ok(())
    }

    /// Delete every thread now.
    pub(crate) fn release(&mut self)
    {
        for thread in self.iter()
        {
            cap_delete(thread).ok();
        }
        self.len = 0;
    }
}

impl Drop for ThreadSet
{
    fn drop(&mut self)
    {
        self.release();
    }
}

/// How a drain case reports its failures.
struct Case
{
    /// The log line of the case's measure.
    line: &'static str,
    /// The error of a worker delete that failed.
    delete_failed: &'static str,
    /// The error of a waiter that was not woken exactly once.
    not_woken: &'static str,
}

/// What a drain case parks its waiters on: the capability the worker deletes,
/// the blocking syscall's number and six arguments (ktest's handles, which the
/// waiters share), and a capability that outlives the delete.
struct Source
{
    owner: Owned,
    call: [u64; 7],
    _kept: Option<Owned>,
}

/// The parked waiters: one fresh address space with the syscall program in it
/// and a record page, and [`WAITERS`] threads of it. Everything is released on
/// drop, on every path.
struct Waiters
{
    /// ktest's own space, whose scratch mapping of the record page drop removes.
    host_aspace: u64,
    space: u64,
    stub: u64,
    data: u64,
    host_mapped: bool,
    threads: ThreadSet,
}

impl Waiters
{
    /// Build the space and its records (record 0 the blocking `call`, record 1
    /// `SYS_THREAD_EXIT`, record 2 the terminator) and park the threads on it in
    /// start order.
    fn new(ctx: &TestContext, call: [u64; 7]) -> Result<Self, &'static str>
    {
        let mut waiters = Self {
            host_aspace: ctx.aspace_cap,
            space: 0,
            stub: 0,
            data: 0,
            host_mapped: false,
            threads: ThreadSet::new(),
        };
        waiters.build_space(ctx)?;
        for (word, value) in (0u64..).zip(call)
        {
            write_word(word, value);
        }
        write_word(RECORD_WORDS, SYS_THREAD_EXIT);
        write_word(RECORD_WORDS.saturating_mul(2), u64::MAX);
        waiters.park(ctx)?;
        Ok(waiters)
    }

    /// Create the space, its stub and its record page, mapped in it and in
    /// ktest's own space.
    fn build_space(&mut self, ctx: &TestContext) -> TestResult
    {
        self.space = cap_create_aspace(ctx.memory_base, 0, WAITER_SPACE_PAGES)
            .map_err(|_| "locked_windows: create the waiters' space failed")?;
        self.stub = crate::spawn::install_stub(
            ctx,
            self.space,
            STUB_VA,
            &crate::arch::code_stub::syscall_program(),
        )?;
        self.data =
            crate::frame_pool::alloc().ok_or("locked_windows: frame_pool::alloc returned None")?;
        // SAFETY: `HOST_DATA_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        unsafe { mem_map(self.data, ctx.aspace_cap, HOST_DATA_VA, 0, 1, MAP_WRITABLE) }
            .map_err(|_| "locked_windows: map the record page in ktest failed")?;
        self.host_mapped = true;
        // SAFETY: the space is one this test created, not ktest's own, so the
        // call changes nothing ktest runs on.
        unsafe { mem_map(self.data, self.space, DATA_VA, 0, 1, MAP_WRITABLE) }
            .map_err(|_| "locked_windows: map the record page in the space failed")
    }

    /// Start [`WAITERS`] threads one by one, each pinned to `latency::WAITER_CPU`
    /// and given a yield to park, then let them settle.
    fn park(&mut self, ctx: &TestContext) -> TestResult
    {
        for _ in 0..WAITERS
        {
            let thread = cap_create_thread(ctx.memory_base, self.space, ctx.cspace_cap, 0, 0)
                .map_err(|_| "locked_windows: create a waiter failed")?;
            self.threads.push(thread)?;
            // SAFETY: the thread is bound to the space this test created, not
            // ktest's own, so its entry state touches nothing ktest runs on.
            unsafe { thread_configure(thread, STUB_VA, STACK, DATA_VA) }
                .map_err(|_| "locked_windows: configure a waiter failed")?;
            thread_set_affinity(thread, latency::WAITER_CPU)
                .map_err(|_| "locked_windows: pin a waiter failed")?;
            thread_start(thread).map_err(|_| "locked_windows: start a waiter failed")?;
            thread_yield().ok();
        }
        thread_sleep(SETTLE_MS).ok();
        Ok(())
    }

    /// Record every waiter's remote-wake count in [`BEFORE`].
    fn snapshot(&self) -> TestResult
    {
        for (count, thread) in BEFORE.iter().zip(self.threads.iter())
        {
            count.store(remote_wakes(thread)?, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Require every waiter to have exited and to have been woken exactly
    /// once since [`Waiters::snapshot`]; `why` is the error otherwise.
    fn check_woken_once(&self, why: &'static str) -> TestResult
    {
        for thread in self.threads.iter()
        {
            crate::spawn::wait_until_exited(thread, crate::scaled_polls(MAX_POLLS))
                .map_err(|_| why)?;
        }
        for (count, thread) in BEFORE.iter().zip(self.threads.iter())
        {
            if remote_wakes(thread)?.wrapping_sub(count.load(Ordering::Relaxed)) != 1
            {
                return Err(why);
            }
        }
        Ok(())
    }
}

impl Drop for Waiters
{
    fn drop(&mut self)
    {
        // The threads go first: each delete stops a thread still parked.
        self.threads.release();
        let space_gone = self.space == 0 || cap_delete(self.space).is_ok();
        let host_free = !self.host_mapped
            // SAFETY: `HOST_DATA_VA` is a scratch VA (crate docs § Scratch VAs), so
            // the span holds no Rust object or IPC page of ktest.
            || unsafe { mem_unmap(self.host_aspace, HOST_DATA_VA, 1) }.is_ok();
        // A frame still mapped somewhere stays out of the pool, which takes
        // only unmapped frames.
        if space_gone
        {
            free_frame(self.stub);
            if host_free
            {
                free_frame(self.data);
            }
        }
    }
}

/// Return `frame` to the pool; 0 holds none.
fn free_frame(frame: u64)
{
    if frame != 0
    {
        // SAFETY: the caller's frame came from the pool and every mapping of
        // it is gone.
        unsafe { crate::frame_pool::free(frame) };
    }
}

/// Store `value` as word `index` of the record page, through ktest's mapping.
fn write_word(index: u64, value: u64)
{
    let va = HOST_DATA_VA.wrapping_add(index.wrapping_mul(8));
    // SAFETY: `va` lies in the record page a live `Waiters` maps in ktest's own
    // space at a scratch VA, 8-aligned; a waiter may write the page, so the
    // write is volatile.
    unsafe { (va as *mut u64).write_volatile(value) };
}

/// The waiter `thread`'s `THREAD_PLACEMENT_REMOTE_WAKES` count.
fn remote_wakes(thread: u64) -> Result<u64, &'static str>
{
    cap_info_thread_placement(thread, THREAD_PLACEMENT_REMOTE_WAKES)
        .map_err(|_| "locked_windows: cap_info(THREAD_PLACEMENT) failed")
}

/// One attempt of a drain case: park the waiters on the source `make` gives,
/// have the worker delete it, judged by the first and the last waiter's wake.
fn drain_once(
    ctx: &TestContext,
    case: &Case,
    make: fn(&TestContext) -> Result<Source, &'static str>,
) -> Result<Measured, &'static str>
{
    let mut source = make(ctx)?;
    let waiters = Waiters::new(ctx, source.call)?;
    waiters.snapshot()?;
    let (first, last) = waiters.threads.ends()?;
    let (first_before, last_before) = (
        BEFORE.first().ok_or(case.not_woken)?,
        BEFORE.last().ok_or(case.not_woken)?,
    );
    let m = delete_bracketed(
        ctx,
        &mut source.owner,
        || Ok(remote_wakes(first)? != first_before.load(Ordering::Relaxed)),
        || Ok(remote_wakes(last)? != last_before.load(Ordering::Relaxed)),
        case.delete_failed,
    )?;
    waiters.check_woken_once(case.not_woken)?;
    Ok(m)
}

/// A drain case: skip without two CPUs, else run [`drain_once`] on the rig.
fn drain_case(
    ctx: &TestContext,
    case: &Case,
    make: fn(&TestContext) -> Result<Source, &'static str>,
) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    run(case.line, || drain_once(ctx, case, make))
}

/// The wake-all drain of a deleted notification takes interrupts between its
/// batches of waiters parked in `SYS_NOTIFICATION_WAIT`.
pub fn notification_drain_takes_interrupts(ctx: &TestContext) -> TestResult
{
    fn make(ctx: &TestContext) -> Result<Source, &'static str>
    {
        let sig = cap_create_notification(ctx.memory_base)
            .map_err(|_| "locked_windows::notification_drain: create the notification failed")?;
        Ok(Source {
            owner: Owned(sig),
            call: [SYS_NOTIFICATION_WAIT, sig, 0, 0, 0, 0, 0],
            _kept: None,
        })
    }
    let case = Case {
        line: "ktest: locked_windows call=notification_drain",
        delete_failed: "locked_windows::notification_drain: the worker's delete failed",
        not_woken: "locked_windows::notification_drain: a waiter was not woken once",
    };
    drain_case(ctx, &case, make)
}

/// The wake-all drain of a deleted event queue takes interrupts between its
/// batches of waiters parked in `SYS_EVENT_RECV`.
pub fn event_queue_drain_takes_interrupts(ctx: &TestContext) -> TestResult
{
    fn make(ctx: &TestContext) -> Result<Source, &'static str>
    {
        let queue = event_queue_create(ctx.memory_base, 1)
            .map_err(|_| "locked_windows::event_queue_drain: create the queue failed")?;
        Ok(Source {
            owner: Owned(queue),
            call: [SYS_EVENT_RECV, queue, 0, 0, 0, 0, 0],
            _kept: None,
        })
    }
    let case = Case {
        line: "ktest: locked_windows call=event_queue_drain",
        delete_failed: "locked_windows::event_queue_drain: the worker's delete failed",
        not_woken: "locked_windows::event_queue_drain: a waiter was not woken once",
    };
    drain_case(ctx, &case, make)
}

/// The wake-all drain of a deleted wait set takes interrupts between its
/// batches of waiters parked in `SYS_WAIT_SET_WAIT` on it, empty.
pub fn wait_set_drain_takes_interrupts(ctx: &TestContext) -> TestResult
{
    fn make(ctx: &TestContext) -> Result<Source, &'static str>
    {
        let set = wait_set_create(ctx.memory_base, 1)
            .map_err(|_| "locked_windows::wait_set_drain: create the wait set failed")?;
        Ok(Source {
            owner: Owned(set),
            call: [SYS_WAIT_SET_WAIT, set, 0, 0, 0, 0, 0],
            _kept: None,
        })
    }
    let case = Case {
        line: "ktest: locked_windows call=wait_set_drain",
        delete_failed: "locked_windows::wait_set_drain: the worker's delete failed",
        not_woken: "locked_windows::wait_set_drain: a waiter was not woken once",
    };
    drain_case(ctx, &case, make)
}

/// The release of an endpoint's receivers, when its last Receive-right slot
/// goes, takes interrupts between its batches: waiters parked in
/// `SYS_IPC_RECV` on ktest's only cap of it.
///
/// No IPC buffer is registered: parking reads none, and a wake with
/// `NoReceiver` delivers no message (core/kernel/src/syscall/ipc.rs
/// `sys_ipc_recv` reads `ipc_buffer` only to deliver one).
pub fn endpoint_receivers_drain_takes_interrupts(ctx: &TestContext) -> TestResult
{
    fn make(ctx: &TestContext) -> Result<Source, &'static str>
    {
        let ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "locked_windows::endpoint_receivers_drain: create the endpoint failed")?;
        Ok(Source {
            owner: Owned(ep),
            call: [SYS_IPC_RECV, ep, 0, 0, 0, 0, 0],
            _kept: None,
        })
    }
    let case = Case {
        line: "ktest: locked_windows call=endpoint_receivers_drain",
        delete_failed: "locked_windows::endpoint_receivers_drain: the worker's delete failed",
        not_woken: "locked_windows::endpoint_receivers_drain: a waiter was not woken once",
    };
    drain_case(ctx, &case, make)
}

/// The release of an endpoint's senders, when its last Receive-right slot goes,
/// takes interrupts between its batches: callers of a send-only copy, parked
/// in the send queue (the all-rights cap is a receiver slot, and nobody
/// receives), woken with `NoReceiver` when the worker deletes that cap.
///
/// No IPC buffer is registered: the calls carry no data word and no cap, which
/// is all `sys_ipc_call` reads the buffer for (core/kernel/src/syscall/ipc.rs,
/// the `data_count > 0` and `cap_count > 0` branches).
pub fn endpoint_callers_drain_takes_interrupts(ctx: &TestContext) -> TestResult
{
    fn make(ctx: &TestContext) -> Result<Source, &'static str>
    {
        let ep =
            Owned(cap_create_endpoint(ctx.memory_base).map_err(
                |_| "locked_windows::endpoint_callers_drain: create the endpoint failed",
            )?);
        let send_only =
            Owned(cap_derive(ep.0, RIGHTS_ALL & !RIGHTS_EP_RECEIVE).map_err(
                |_| "locked_windows::endpoint_callers_drain: derive the send cap failed",
            )?);
        let call = [
            SYS_IPC_CALL,
            send_only.0,
            CALL_LABEL,
            ipc_call_count_arg(0, 0),
            0,
            0,
            0,
        ];
        Ok(Source {
            owner: ep,
            call,
            _kept: Some(send_only),
        })
    }
    let case = Case {
        line: "ktest: locked_windows call=endpoint_callers_drain",
        delete_failed: "locked_windows::endpoint_callers_drain: the worker's delete failed",
        not_woken: "locked_windows::endpoint_callers_drain: a waiter was not woken once",
    };
    drain_case(ctx, &case, make)
}

/// A dying `CSpace`'s stop of the [`BOUND`] threads bound to it takes interrupts
/// between its batches of visits. The registry walk visits the newest thread
/// first, so the thread created last reads `Exited` at the walk's first step
/// and the one created first at its last.
pub fn bound_thread_stop_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    run("ktest: locked_windows call=bound_thread_stop", || {
        let mut dying = Owned(
            cap_create_cspace(ctx.memory_base, 0, DYING_CSPACE_PAGES)
                .map_err(|_| "locked_windows::bound_thread_stop: create the dying CSpace failed")?,
        );
        let mut bound = ThreadSet::new();
        bound.create(ctx, ctx.aspace_cap, dying.0, BOUND)?;
        let (oldest, newest) = bound.ends()?;
        let m = delete_bracketed(
            ctx,
            &mut dying,
            || crate::spawn::is_exited(newest),
            || crate::spawn::is_exited(oldest),
            "locked_windows::bound_thread_stop: the worker's delete failed",
        )?;
        for thread in bound.iter()
        {
            if !crate::spawn::is_exited(thread)?
            {
                return Err("locked_windows::bound_thread_stop: a thread outlived its CSpace");
            }
        }
        Ok(m)
    })
}

/// `SYS_ASPACE_HOLD`'s walk over the registry, with [`BOUND`] never-started threads
/// bound to the held space, takes interrupts between its batches. No step of
/// the walk shows from outside and the hold opens one more window after it, so
/// the call is judged by its first half.
pub fn aspace_hold_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    run("ktest: locked_windows call=aspace_hold", || {
        let space = Owned(
            cap_create_aspace(ctx.memory_base, 0, HELD_SPACE_PAGES)
                .map_err(|_| "locked_windows::aspace_hold: create the space failed")?,
        );
        let mut threads = ThreadSet::new();
        threads.create(ctx, space.0, ctx.cspace_cap, BOUND)?;
        let m = latency::measure_call(ctx, Call::Hold(space.0))?.judged_by_first_half();
        if m.result == u64::MAX
        {
            return Err("locked_windows::aspace_hold: the worker's hold failed");
        }
        aspace_release(space.0)
            .map_err(|_| "locked_windows::aspace_hold: the release of the held space failed")?;
        Ok(m)
    })
}
