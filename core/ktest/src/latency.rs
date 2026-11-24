// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/latency.rs

//! Interrupt-latency rig of the cases that show a syscall whose length the
//! caller chooses taking interrupts between its batches.
//!
//! A probe pinned to [`PROBE_CPU`] unmaps a page of ktest's address space in
//! a loop, each unmap a synchronous TLB shootdown of [`WORKER_CPU`], where a
//! worker makes the measured call ([`measure_call`]). Every probe the call
//! overlaps must be acknowledged within [`LATENCY_BOUND_US`], and a probe
//! issued once the call was under way must be acknowledged before the call
//! returned ([`check_measured`]); for a call too short to be sure of a probe
//! inside it, before one of several calls returned ([`attempt_until_acked`]).
//! A kernel that masks interrupts for the whole call acknowledges a probe
//! issued inside it only once the call returns, so it fails the second check
//! whatever the host's scheduling.
//!
//! A call that opens other windows besides the ones under test is judged by
//! a [`Bracket`] instead ([`measure_bracketed`]): two reads of kernel state
//! that the stretch under test changes, so that only a probe acknowledged
//! between the stretch's first and last steps passes it.
//!
//! The cases are `unit::retype`'s page-pool and placement cases,
//! `unit::cap_batches`'s derivation-lock cases, `unit::teardown_windows`'s
//! teardown cases and `unit::locked_windows`'s cases of the registry walks and
//! wake-all drains that hold a lock for one batch at a time. They run one at a time: the rig's words and the worker's
//! stack are this module's own.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use syscall::{
    aspace_hold, cap_create_aspace, cap_create_cspace, cap_create_thread, cap_delete, cap_insert,
    cap_move, cap_revoke, mem_map, mem_unmap, sched_split, system_info, thread_configure,
    thread_set_affinity, thread_start, thread_yield,
};
use syscall_abi::{MAP_WRITABLE, SystemInfoType};

use crate::{TestContext, TestResult};

/// Longest a probe that the measured call overlaps may wait for its
/// acknowledgement, in microseconds (stretched by `scaled_bound`). Every
/// case keeps the call's longest masked stretch to one batch: a walk of
/// `unit::retype`'s holes, or one derivation-lock batch of constant-time
/// edits.
pub const LATENCY_BOUND_US: u64 = 250_000;
/// Bound on the whole measured call and on the worker's readiness, in
/// microseconds (stretched by `scaled_bound`).
const CALL_DEADLINE_US: u64 = 60_000_000;
/// Conclusive calls of one kind [`attempt_until_acked`] makes, each on a
/// fresh fixture, until a probe is acknowledged inside one. A call that lasts
/// a few milliseconds is not much longer than one probe's scheduling delay on
/// a contended host, so one call can see no probe land inside it with
/// interrupts taken; a kernel that masks them for the whole call lets no
/// probe land inside any.
///
/// A call is conclusive when the first probe issued inside it (at least the
/// margin after its start and before its end) waited no longer than the whole
/// call. A call is inconclusive, and does not count here, when no probe was
/// issued inside it (the probe's CPU was off the host for the call) or when
/// that probe outwaited the whole call (a CPU was off the host for longer than
/// the call: a kernel that masks interrupts for the call holds a probe issued
/// inside it for at most the rest of the call, less than the call's span).
/// Only an acknowledgement inside a call passes the case, so an inconclusive
/// call cannot hide a masked stretch: under a kernel that masks the whole
/// call, the probe in flight is acknowledged only at the call's end, and the
/// call either counts here, when that probe was issued inside it, or is
/// inconclusive, when it was issued before; either way no call passes, and the
/// case fails once `ATTEMPTS` calls were conclusive or [`ATTEMPT_LIMIT`]
/// calls were made.
pub const ATTEMPTS: u32 = 4;
/// Calls of one kind [`attempt_until_acked`] makes at most, conclusive or
/// not: the bound that fails the case when the host keeps every call
/// inconclusive, or when a kernel that masks interrupts for the whole call
/// leaves every call inconclusive.
pub const ATTEMPT_LIMIT: u32 = 16;
/// The probe's page (crate docs § Scratch VAs).
const PROBE_VA: u64 = 0x1_6600_0000;
const PROBE_CPU: u32 = 0;
const WORKER_CPU: u32 = 1;
/// The CPU the cases of `unit::locked_windows` pin their parked waiters to: the
/// probe's, so the worker (on `WORKER_CPU`) wakes each of them remotely, and
/// each wake counts `THREAD_PLACEMENT_REMOTE_WAKES` of the waiter.
pub const WAITER_CPU: u32 = PROBE_CPU;

/// The call the worker makes, between two clock reads.
#[derive(Clone, Copy)]
pub enum Call
{
    /// `SYS_CAP_DELETE` of the cap.
    Delete(u64),
    /// `SYS_CAP_REVOKE` of the cap.
    Revoke(u64),
    /// `SYS_CAP_CREATE_CSPACE` from `memory` with `pages` pages.
    CreateCSpace
    {
        memory: u64, pages: u64
    },
    /// `SYS_CAP_CREATE_ASPACE` from `memory` with `pages` pages.
    CreateAspace
    {
        memory: u64, pages: u64
    },
    /// `SYS_CAP_COPY` of `cap` into `cspace` at `slot`, with `rights`.
    CopyAt
    {
        cap: u64,
        cspace: u64,
        slot: u32,
        rights: u64,
    },
    /// `SYS_CAP_MOVE` of `cap` into `cspace`, at a slot the kernel picks.
    Move
    {
        cap: u64, cspace: u64
    },
    /// `SYS_SCHED_SPLIT` of `cap` at priority `at`.
    SchedSplit
    {
        cap: u64, at: u8
    },
    /// `SYS_ASPACE_HOLD` of the address-space cap.
    Hold(u64),
    /// `SYS_THREAD_EXIT` of the worker itself, which never returns: made by
    /// [`measure_exit`] alone, which ends the probes once its bracket's stretch
    /// has ended and takes that time for the call's end.
    Exit,
}

impl Call
{
    /// The worker's words for the call: an op number and three arguments.
    fn encode(self) -> (u64, [u64; 3])
    {
        match self
        {
            Call::Delete(cap) => (1, [cap, 0, 0]),
            Call::Revoke(cap) => (2, [cap, 0, 0]),
            Call::CreateCSpace { memory, pages } => (3, [memory, pages, 0]),
            Call::CreateAspace { memory, pages } => (4, [memory, pages, 0]),
            Call::CopyAt {
                cap,
                cspace,
                slot,
                rights,
            } => (
                5,
                [
                    cap,
                    cspace,
                    (u64::from(slot) << 32) | (rights & 0xFFFF_FFFF),
                ],
            ),
            Call::Move { cap, cspace } => (6, [cap, cspace, 0]),
            Call::SchedSplit { cap, at } => (7, [cap, u64::from(at), 0]),
            Call::Exit => (8, [0; 3]),
            Call::Hold(cap) => (9, [cap, 0, 0]),
        }
    }
}

/// Make the call the worker's words name; `Err` on its error, or on an
/// unknown op.
fn make_call(op: u64, args: [u64; 3]) -> Result<(u64, u64), i64>
{
    let [a0, a1, a2] = args;
    match op
    {
        1 => cap_delete(a0).map(|()| (0, 0)),
        2 => cap_revoke(a0).map(|()| (0, 0)),
        3 => cap_create_cspace(a0, 0, a1).map(|c| (c, 0)),
        4 => cap_create_aspace(a0, 0, a1).map(|c| (c, 0)),
        // The slot is the high half of the third word (`Call::encode`).
        5 => cap_insert(a0, a1, (a2 >> 32) as u32, a2 & 0xFFFF_FFFF).map(|c| (c, 0)),
        6 => cap_move(a0, a1, 0).map(|c| (c, 0)),
        7 => u8::try_from(a1)
            .map_err(|_| 0)
            .and_then(|at| sched_split(a0, at)),
        8 => syscall::thread_exit(),
        9 => aspace_hold(a0).map(|()| (0, 0)),
        _ => Err(0),
    }
}

static OP: AtomicU64 = AtomicU64::new(0);
static ARGS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
/// The worker's shortest syscall round trip, in microseconds: how long its
/// CPU runs with interrupts enabled between two syscalls.
static GAP_US: AtomicU64 = AtomicU64::new(0);
static READY: AtomicBool = AtomicBool::new(false);
static GO: AtomicBool = AtomicBool::new(false);
/// `ElapsedUs` just before and just after the measured call; 0 until set.
static START: AtomicU64 = AtomicU64::new(0);
static END: AtomicU64 = AtomicU64::new(0);
/// The call's results: its return values, or `u64::MAX` in the first on an
/// error.
static RESULT: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static mut STACK: crate::ChildStack = crate::ChildStack::ZERO;

/// Worker entry: measure this CPU's syscall round trip, report ready, wait for
/// the probe, then make the call `OP` names between two clock reads.
extern "C" fn latency_worker(_arg: u64) -> !
{
    let mut gap = u64::MAX;
    let mut prev = crate::elapsed_us();
    for _ in 0..16
    {
        let now = crate::elapsed_us();
        gap = gap.min(now.saturating_sub(prev));
        prev = now;
    }
    GAP_US.store(gap, Ordering::Relaxed);
    READY.store(true, Ordering::Release);
    while !GO.load(Ordering::Acquire)
    {
        core::hint::spin_loop();
    }
    let op = OP.load(Ordering::Relaxed);
    let args = ARGS.each_ref().map(|word| word.load(Ordering::Relaxed));
    START.store(crate::elapsed_us(), Ordering::Release);
    let result = make_call(op, args);
    let end = crate::elapsed_us();
    let (first, second) = result.unwrap_or((u64::MAX, 0));
    RESULT[0].store(first, Ordering::Relaxed);
    RESULT[1].store(second, Ordering::Relaxed);
    END.store(end, Ordering::Release);
    syscall::thread_exit()
}

/// A stretch of the measured call that kernel state shows from outside it,
/// read through syscalls on the probe's CPU: `begun` reads true once the
/// stretch has made its first step, and `ended` once it has made its last;
/// each stays true from then on.
///
/// A probe is acknowledged inside the stretch when `begun` read true and
/// `ended` false before its unmap was issued, and `ended` read false again
/// once the unmap returned. The worker's CPU cannot take the shootdown before
/// it is sent, which is after the stretch's first step, and the unmap
/// returns only once that CPU has acknowledged it: had the CPU taken it after
/// the stretch's last step, the read after the acknowledgement would see that
/// step. So the CPU took it between two steps of the stretch, whatever the
/// host's scheduling and whatever windows the rest of the call opens. A call
/// in which no probe was issued inside the stretch is inconclusive.
pub struct Bracket<'a>
{
    pub begun: &'a mut dyn FnMut() -> Result<bool, &'static str>,
    pub ended: &'a mut dyn FnMut() -> Result<bool, &'static str>,
}

impl Bracket<'_>
{
    /// Whether the stretch has made its first step and not its last.
    fn under_way(&mut self) -> Result<bool, &'static str>
    {
        Ok((self.begun)()? && !(self.ended)()?)
    }
}

/// What the probes saw of a [`Bracket`]'s stretch.
#[derive(Clone, Copy, Default)]
struct Bracketed
{
    /// A probe was issued inside the stretch.
    issued: bool,
    /// A probe issued inside the stretch was acknowledged before it ended.
    acked: bool,
}

/// What the probe saw of one measured call.
pub struct Measured
{
    /// The call's duration.
    pub span_us: u64,
    /// The longest acknowledgement of a probe the call overlapped.
    pub max_wait_us: u64,
    /// Whether a probe issued once the call was under way was acknowledged
    /// before it returned.
    pub acked_inside: bool,
    /// Whether the call, unacknowledged, tells nothing about the kernel: no
    /// probe was issued inside it, or the first one issued inside it waited
    /// longer than the whole call ([`ATTEMPTS`]).
    pub inconclusive: bool,
    /// The call's return value, or `u64::MAX` on an error.
    pub result: u64,
    /// `ElapsedUs` just before and just after the call.
    start: u64,
    end: u64,
    /// How far from the call's ends a probe must be issued and acknowledged
    /// to count as inside it (`probe_worker`).
    margin: u64,
    /// The issue and acknowledgement times of the first probe issued
    /// `margin` after the call's start.
    first: Option<(u64, u64)>,
}

impl Measured
{
    /// Judge the call by its first probe: acknowledged inside when it was
    /// acknowledged by `ack_by`; when it was not, inconclusive when no probe
    /// was issued by `issue_by` or the first one waited longer than the
    /// whole call ([`ATTEMPTS`]).
    fn judge(&mut self, issue_by: u64, ack_by: u64)
    {
        self.acked_inside = self.first.is_some_and(|(_, t1)| t1 <= ack_by);
        self.inconclusive = !self.acked_inside
            && self
                .first
                .is_none_or(|(t0, t1)| t0 > issue_by || t1.saturating_sub(t0) > self.span_us);
    }

    /// The measure of a call whose kernel opens an interrupt window near
    /// its end whatever the windows under test do (a `CSpace` teardown
    /// returns its pool after the drain): the first probe counts as
    /// acknowledged inside only when it was acknowledged in the first half
    /// of the call, and the call is inconclusive when no probe was issued in
    /// its first quarter. A kernel that masks interrupts until that late
    /// window holds a probe issued in the first quarter past the half.
    #[must_use]
    pub fn judged_by_first_half(mut self) -> Self
    {
        let quarter = self.span_us / 4;
        let issue_by = self
            .start
            .saturating_add(quarter)
            .min(self.end.saturating_sub(self.margin));
        let ack_by = self.start.saturating_add(quarter.saturating_mul(2));
        self.judge(issue_by, ack_by);
        self
    }
}

/// Make `call` on a worker pinned to `WORKER_CPU`, probing it from
/// `PROBE_CPU` with unmaps of a frame-pool frame at `PROBE_VA`. The harness
/// thread is pinned to `PROBE_CPU` for the call and unpinned afterwards.
pub fn measure_call(ctx: &TestContext, call: Call) -> Result<Measured, &'static str>
{
    if matches!(call, Call::Exit)
    {
        return Err("latency: an exit is measured by measure_exit");
    }
    measure(ctx, call, None, None)
}

/// [`measure_call`], judged by `bracket`: acknowledged inside when a probe
/// was acknowledged inside its stretch, inconclusive when no probe was issued
/// inside it.
pub fn measure_bracketed(
    ctx: &TestContext,
    call: Call,
    bracket: &mut Bracket<'_>,
) -> Result<Measured, &'static str>
{
    if matches!(call, Call::Exit)
    {
        return Err("latency: an exit is measured by measure_exit");
    }
    measure(ctx, call, Some(bracket), None)
}

/// The worker's own `SYS_THREAD_EXIT` ([`Call::Exit`]), judged by `bracket`,
/// whose stretch must end in the exit: `setup` is given the worker's thread
/// capability before the worker starts, and the probes end once a read after
/// an acknowledgement sees the stretch ended.
pub fn measure_exit(
    ctx: &TestContext,
    setup: &mut dyn FnMut(u64) -> TestResult,
    bracket: &mut Bracket<'_>,
) -> Result<Measured, &'static str>
{
    measure(ctx, Call::Exit, Some(bracket), Some(setup))
}

/// [`measure_call`], judged by `bracket` when there is one, with `setup`
/// given the worker's thread capability before it starts.
fn measure(
    ctx: &TestContext,
    call: Call,
    bracket: Option<&mut Bracket<'_>>,
    setup: Option<&mut dyn FnMut(u64) -> TestResult>,
) -> Result<Measured, &'static str>
{
    for word in [&GAP_US, &START, &END, &RESULT[0], &RESULT[1]]
    {
        word.store(0, Ordering::Relaxed);
    }
    READY.store(false, Ordering::Relaxed);
    GO.store(false, Ordering::Relaxed);
    let (op, args) = call.encode();
    for (word, arg) in ARGS.iter().zip(args)
    {
        word.store(arg, Ordering::Relaxed);
    }
    OP.store(op, Ordering::Release);

    let frame = crate::frame_pool::alloc().ok_or("latency: frame pool exhausted")?;
    let measured = thread_set_affinity(ctx.thread_cap, PROBE_CPU)
        .map_err(|_| "latency: pin the probe failed")
        .and_then(|()| {
            let measured = thread_yield()
                .map_err(|_| "latency: yield failed")
                .and_then(|()| probe_worker(ctx, frame, bracket, setup));
            let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
                .map_err(|_| "latency: restore the probe's affinity failed");
            let measured = measured?;
            restore?;
            Ok(measured)
        });
    // SAFETY: the frame came from frame_pool::alloc, and every probe map of it
    // was undone by its unmap, or failed.
    unsafe { crate::frame_pool::free(frame) };
    measured
}

/// Create the worker in ktest's own `CSpace`, so the handles in its words
/// are its own, give its thread capability to `setup`, and start it pinned to
/// `WORKER_CPU`.
fn start_worker(
    ctx: &TestContext,
    setup: Option<&mut dyn FnMut(u64) -> TestResult>,
) -> Result<crate::spawn::SpawnedChild, &'static str>
{
    let worker = crate::spawn::SpawnedChild {
        th: cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "latency: create the worker failed")?,
        cs: 0,
    };
    if let Some(setup) = setup
    {
        setup(worker.th)?;
    }
    // SAFETY: `STACK` is a static stack, reached only through `addr_of!`.
    let stack = unsafe { crate::ChildStack::top(core::ptr::addr_of!(STACK)) };
    // SAFETY: the entry is an `extern "C" fn(u64) -> !` of the entry ABI, and
    // `STACK` is this rig's own stack, on which no other live thread runs
    // (the cases run one at a time and reap the worker before returning).
    unsafe { thread_configure(worker.th, latency_worker as *const () as u64, stack, 0) }
        .map_err(|_| "latency: configure the worker failed")?;
    thread_set_affinity(worker.th, WORKER_CPU).map_err(|_| "latency: pin the worker failed")?;
    thread_start(worker.th).map_err(|_| "latency: start the worker failed")?;
    Ok(worker)
}

/// Start the worker ([`start_worker`]), probe it until its call returns, or
/// until its exit's bracketed stretch has ended, and reap it.
fn probe_worker(
    ctx: &TestContext,
    frame: u64,
    mut bracket: Option<&mut Bracket<'_>>,
    setup: Option<&mut dyn FnMut(u64) -> TestResult>,
) -> Result<Measured, &'static str>
{
    let mut worker = start_worker(ctx, setup)?;
    let exits = OP.load(Ordering::Relaxed) == 8;

    let deadline = crate::scaled_bound(CALL_DEADLINE_US);
    let begun = crate::elapsed_us();
    while !READY.load(Ordering::Acquire)
    {
        if crate::elapsed_us().saturating_sub(begun) > deadline
        {
            return Err("latency: the worker never reported ready");
        }
        thread_yield().ok();
    }
    // A probe the worker's CPU could acknowledge between two of its syscalls,
    // just before or just after the call, is not counted against the call.
    let margin = GAP_US
        .load(Ordering::Relaxed)
        .checked_mul(8)
        .and_then(|gap| gap.checked_add(10))
        .ok_or("latency: probe margin out of range")?;

    let mut max_wait = 0u64;
    // The issue and acknowledgement times of the first probe issued `margin`
    // after the call's start. Probes run one at a time, so it is also the
    // first of them acknowledged.
    let mut first_after_start: Option<(u64, u64)> = None;
    let mut bracketed = Bracketed::default();
    // Whether a read after an acknowledgement saw the stretch ended.
    let stretch_ended = core::cell::Cell::new(false);
    let mut probe = || -> TestResult {
        // Whether the stretch was under way before this probe's unmap.
        let inside = bracket.as_mut().map(|b| b.under_way()).transpose()? == Some(true);
        // SAFETY: `PROBE_VA` is a scratch VA (crate docs § Scratch VAs), so
        // the page holds no Rust object or IPC page of ktest.
        unsafe { mem_map(frame, ctx.aspace_cap, PROBE_VA, 0, 1, MAP_WRITABLE) }
            .map_err(|_| "latency: probe map failed")?;
        let t0 = crate::elapsed_us();
        // SAFETY: as for the map.
        let unmapped = unsafe { mem_unmap(ctx.aspace_cap, PROBE_VA, 1) };
        let t1 = crate::elapsed_us();
        unmapped.map_err(|_| "latency: probe unmap failed")?;
        if let Some(b) = bracket.as_mut()
        {
            let ended = (b.ended)()?;
            stretch_ended.set(ended);
            if inside
            {
                bracketed.issued = true;
                bracketed.acked |= !ended;
            }
        }
        let start = START.load(Ordering::Acquire);
        if start != 0 && t1 >= start
        {
            max_wait = max_wait.max(t1.wrapping_sub(t0));
        }
        if start != 0 && t0 >= start.saturating_add(margin) && first_after_start.is_none()
        {
            first_after_start = Some((t0, t1));
        }
        Ok(())
    };
    GO.store(true, Ordering::Release);
    let probed = loop
    {
        if END.load(Ordering::Acquire) != 0
        {
            break Ok(());
        }
        if exits && stretch_ended.get()
        {
            // The worker's exit never returns to write its end.
            END.store(crate::elapsed_us(), Ordering::Release);
            break Ok(());
        }
        if let Err(e) = probe()
        {
            break Err(e);
        }
        if crate::elapsed_us().saturating_sub(begun) > deadline
        {
            break Err("latency: the measured call outlived its deadline");
        }
    };
    let exited = crate::spawn::wait_until_exited(worker.th, crate::scaled_polls(60_000));
    worker.delete_thread().ok();
    probed?;
    exited?;

    let (start, end) = (START.load(Ordering::Acquire), END.load(Ordering::Acquire));
    let mut measured = Measured {
        span_us: end.saturating_sub(start),
        max_wait_us: max_wait,
        acked_inside: false,
        inconclusive: false,
        result: RESULT[0].load(Ordering::Relaxed),
        start,
        end,
        margin,
        first: first_after_start,
    };
    if bracket.is_some()
    {
        measured.acked_inside = bracketed.acked;
        measured.inconclusive = !bracketed.acked && !bracketed.issued;
    }
    else
    {
        let inside_by = end.saturating_sub(margin);
        measured.judge(inside_by, inside_by);
    }
    Ok(measured)
}

/// The results of the worker's call, when it made the call: its return
/// values, or `u64::MAX` in the first on an error. `None` when the worker
/// never finished it, so the call's object was neither consumed (a delete) nor
/// created (a create). Read once [`measure_call`] has returned, whatever its
/// outcome: the worker is reaped by then, so the words no longer change.
pub fn worker_results() -> Option<(u64, u64)>
{
    (END.load(Ordering::Acquire) != 0).then(|| {
        (
            RESULT[0].load(Ordering::Relaxed),
            RESULT[1].load(Ordering::Relaxed),
        )
    })
}

/// Log `m`, the measure of `call` (a log line naming it), and check it against
/// the bounds.
pub fn check_measured(call: &'static str, m: &Measured) -> TestResult
{
    crate::log(call);
    crate::log_u64("ktest: latency span_us=", m.span_us);
    crate::log_u64("ktest: latency max_probe_wait_us=", m.max_wait_us);
    crate::log_u64("ktest: latency acked_inside=", u64::from(m.acked_inside));
    crate::log_u64("ktest: latency inconclusive=", u64::from(m.inconclusive));
    if m.max_wait_us > crate::scaled_bound(LATENCY_BOUND_US)
    {
        return Err("latency: a probe waited past LATENCY_BOUND_US for the call");
    }
    if !m.acked_inside
    {
        return Err("latency: no probe was acknowledged while the call ran");
    }
    Ok(())
}

/// Whether the guest has the two CPUs the rig pins to; logs the skip, which
/// a one-CPU configuration alone takes.
pub fn cpus_present() -> bool
{
    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    if cpus <= u64::from(WORKER_CPU)
    {
        crate::log("ktest: latency SKIP (need 2+ CPUs)");
        return false;
    }
    true
}

/// Make the calls `once` measures until one sees a probe acknowledged inside
/// it, `ATTEMPTS` of them were conclusive, or `ATTEMPT_LIMIT` were made, and
/// return the last call's measure with the longest probe wait of them all:
/// every call's probes count against `LATENCY_BOUND_US`, and only a
/// conclusive call counts against `ATTEMPTS`.
pub fn attempt_until_acked(
    mut once: impl FnMut() -> Result<Measured, &'static str>,
) -> Result<Measured, &'static str>
{
    let mut max_wait_us = 0;
    let mut conclusive = 0u32;
    let mut last = None;
    for _ in 0..ATTEMPT_LIMIT
    {
        let m = once()?;
        log_attempt(&m);
        max_wait_us = max_wait_us.max(m.max_wait_us);
        let (acked, inconclusive) = (m.acked_inside, m.inconclusive);
        last = Some(Measured { max_wait_us, ..m });
        if acked
        {
            break;
        }
        if !inconclusive
        {
            conclusive = conclusive.saturating_add(1);
            if conclusive == ATTEMPTS
            {
                break;
            }
        }
    }
    last.ok_or("latency: ATTEMPT_LIMIT made no call")
}

/// Log one attempt's own measure, before the attempts' longest probe wait is
/// folded into it.
fn log_attempt(m: &Measured)
{
    crate::log_u64("ktest: latency attempt span_us=", m.span_us);
    crate::log_u64("ktest: latency attempt max_probe_wait_us=", m.max_wait_us);
    crate::log_u64(
        "ktest: latency attempt inconclusive=",
        u64::from(m.inconclusive),
    );
}
