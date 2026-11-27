// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/memory_zero_preempt.rs

//! Integration: a `SYS_MEMORY_ZERO` stops at the batch after the wake of a
//! thread that outranks its caller, returning the pages zeroed so far, and
//! the woken thread runs before the caller resumes
//! (core/kernel/docs/syscalls.md § `SYS_MEMORY_ZERO` (79)).
//!
//! A zeroer at [`ZEROER_PRIORITY`] and a waiter at [`WAITER_PRIORITY`] are
//! pinned to [`TARGET_CPU`]; the waiter, started first, blocks on `wake`.
//! The zeroer zeroes all [`PIECE_PAGES`] pages of a piece in one call. A
//! signaller pinned to [`SIGNAL_CPU`] spins until the piece's first page
//! reads zero, so the call is under way, signals `wake`, and then reads the
//! first page of the second-last batch: when it still holds the pattern, the
//! wake was posted with at least two batches left, and the attempt is
//! conclusive. The waiter records whether the zeroer's call had returned when
//! it ran.
//!
//! A conclusive attempt passes when the call returned a count short of the
//! piece, at a batch boundary, with exactly that prefix zeroed and the rest
//! intact, and the waiter ran before the zeroer resumed. A kernel that runs
//! the call to its end whatever outranks it returns the whole piece and fails.
//! An attempt in which the signal came too late, or the call returned before
//! the wake (a stop the contract allows for other reasons), is inconclusive
//! and is made again, up to [`ATTEMPT_LIMIT`] attempts; a run with no
//! conclusive attempt fails.
//!
//! Needs 2 CPUs and the `SchedControl` cap (skips otherwise).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, cap_info, mem_map, mem_unmap, memory_merge,
    memory_split, memory_zero, notification_send, notification_wait, notification_wait_timeout,
    system_info, thread_exit,
};
use syscall_abi::{
    CAP_INFO_MEMORY_SIZE, MAP_WRITABLE, PAGE_SIZE, RIGHTS_MEM_MAP_RW, SystemInfoType,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Level of the waiter and the signaller: an RT level above
/// [`ZEROER_PRIORITY`] and below the harness's `INIT_PRIORITY` (30).
const WAITER_PRIORITY: u8 = 26;
/// Level of the zeroer, an RT level, so only a higher RT level outranks it.
const ZEROER_PRIORITY: u8 = 22;
/// The CPU of the zeroer and the waiter.
const TARGET_CPU: u32 = 1;
/// The CPU of the signaller.
const SIGNAL_CPU: u32 = 0;
/// Pages of the piece the zeroer zeroes: 32 MiB, 512 batches of 16 pages.
const PIECE_PAGES: u64 = 8192;
/// Pages of one batch of `SYS_MEMORY_ZERO` (core/kernel/docs/syscalls.md).
const BATCH_PAGES: u64 = 16;
/// The page the signaller reads after its signal: the first of the
/// second-last batch.
const LATE_PAGE: u64 = PIECE_PAGES - 2 * BATCH_PAGES;
/// The scratch VA the piece is mapped at (crate docs § Scratch VAs).
const PIECE_VA: u64 = 0x1_7400_0000;
/// The word the first and last word of every page hold before a zero.
const PATTERN: u64 = 0x5A5A_A5A5_3C3C_C3C3;
/// Attempts made at most before the case fails for want of a conclusive one.
const ATTEMPT_LIMIT: u32 = 16;
/// The signaller's wait for the first page to read zero (ms), applied through
/// [`crate::scaled_bound`]: far past the first batch of a call that started.
const FIRST_PAGE_TIMEOUT_MS: u64 = 10_000;
/// 5 s windows the harness waits, at most, for an attempt's children.
const REPORT_WINDOWS: u32 = 12;

/// `done` bits.
const ZEROER_DONE: u64 = 1 << 0;
const WAITER_BEFORE_RETURN: u64 = 1 << 1;
const WAITER_AFTER_RETURN: u64 = 1 << 2;
const SIGNAL_CONCLUSIVE: u64 = 1 << 3;
const SIGNAL_LATE: u64 = 1 << 4;
const SIGNAL_TIMED_OUT: u64 = 1 << 5;
const WAITER_BITS: u64 = WAITER_BEFORE_RETURN | WAITER_AFTER_RETURN;
const SIGNAL_BITS: u64 = SIGNAL_CONCLUSIVE | SIGNAL_LATE | SIGNAL_TIMED_OUT;

/// Set by the zeroer once its call has returned.
static RETURNED: AtomicU32 = AtomicU32::new(0);
/// The zeroer's count, or `u64::MAX` on an error.
static COUNT: AtomicU64 = AtomicU64::new(0);

/// The caps a child holds, in its own `CSpace`, and its deadline.
#[derive(Clone, Copy)]
struct Args
{
    /// The piece (the zeroer), or `wake` (the waiter and the signaller).
    cap: u64,
    /// `done` (notify).
    done: u64,
    /// The signaller's wait for the first page (ms).
    timeout_ms: u64,
}

const NO_ARGS: Args = Args {
    cap: 0,
    done: 0,
    timeout_ms: 0,
};

/// One entry per child: the waiter, the signaller, the zeroer.
static ARGS: spawn::ArgBlock<Args, 3> = spawn::ArgBlock::new(NO_ARGS);

/// Stacks, indexed as [`ARGS`].
static mut STACKS: [ChildStack; 3] = [const { ChildStack::ZERO }; 3];

/// The first word of page `page` of the piece's mapping.
fn first_word(page: u64) -> *mut u64
{
    // Bounded: `page` < PIECE_PAGES, so the address lies in the mapping.
    PIECE_VA.wrapping_add(page.wrapping_mul(PAGE_SIZE)) as *mut u64
}

/// The last word of page `page` of the piece's mapping.
fn last_word(page: u64) -> *mut u64
{
    // Bounded: `page` < PIECE_PAGES, so the address lies in the mapping.
    PIECE_VA
        .wrapping_add(page.wrapping_mul(PAGE_SIZE))
        .wrapping_add(PAGE_SIZE - 8) as *mut u64
}

/// Waiter: block on `wake`, report whether the zeroer's call had returned.
extern "C" fn waiter(arg: u64) -> !
{
    // SAFETY: arg is this child's ARGS entry, published before its start.
    let a: Args = unsafe { spawn::child_args(arg) };
    notification_wait(a.cap).ok();
    let seen = if RETURNED.load(Ordering::Acquire) == 0
    {
        WAITER_BEFORE_RETURN
    }
    else
    {
        WAITER_AFTER_RETURN
    };
    notification_send(a.done, seen).ok();
    thread_exit();
}

/// Signaller: wait for the first page to read zero, signal `wake`, and
/// report whether the second-last batch had begun.
extern "C" fn signaller(arg: u64) -> !
{
    // SAFETY: arg is this child's ARGS entry, published before its start.
    let a: Args = unsafe { spawn::child_args(arg) };
    let deadline = crate::elapsed_us().saturating_add(a.timeout_ms.saturating_mul(1000));
    let outcome = loop
    {
        // SAFETY: the piece is mapped at PIECE_VA for the attempt, and no
        // reference covers it. A word the zero is writing may read torn,
        // which is neither zero nor the pattern.
        let first = unsafe { first_word(0).read_volatile() };
        if first == 0
        {
            notification_send(a.cap, 1).ok();
            // SAFETY: as above.
            let late = unsafe { first_word(LATE_PAGE).read_volatile() };
            break if late == PATTERN
            {
                SIGNAL_CONCLUSIVE
            }
            else
            {
                SIGNAL_LATE
            };
        }
        if crate::elapsed_us() > deadline
        {
            break SIGNAL_TIMED_OUT;
        }
        core::hint::spin_loop();
    };
    notification_send(a.done, outcome).ok();
    thread_exit();
}

/// Zeroer: zero the whole piece in one call, record the count, report.
extern "C" fn zeroer(arg: u64) -> !
{
    // SAFETY: arg is this child's ARGS entry, published before its start.
    let a: Args = unsafe { spawn::child_args(arg) };
    // SAFETY: the piece's only mapping is the scratch one at PIECE_VA, which
    // no reference covers; the signaller's are volatile reads.
    let count = unsafe { memory_zero(a.cap, 0, PIECE_PAGES) }.unwrap_or(u64::MAX);
    COUNT.store(count, Ordering::Relaxed);
    RETURNED.store(1, Ordering::Release);
    notification_send(a.done, ZEROER_DONE).ok();
    thread_exit();
}

/// Spawn a child at `priority` holding `cap` with `rights` and `done`,
/// publish its arguments in entry `index`, and start it on `cpu`.
fn start_child(
    ctx: &TestContext,
    index: usize,
    priority: u8,
    entry: extern "C" fn(u64) -> !,
    (cap, rights): (u64, u64),
    done: u64,
    cpu: u32,
) -> Result<spawn::SpawnedChild, &'static str>
{
    let child = spawn::new_child_at(ctx, ctx.sched_control_cap, priority)
        .map_err(|_| "memory_zero_preempt: spawn::new_child_at failed")?;
    let cap =
        cap_copy(cap, child.cs, rights).map_err(|_| "memory_zero_preempt: cap_copy failed")?;
    let done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "memory_zero_preempt: cap_copy (done) failed")?;
    // SAFETY: index < 3, and no child reads the entry: each runs once, after
    // its publish, and is reaped before the next attempt publishes again.
    let arg = unsafe {
        ARGS.publish(
            index,
            Args {
                cap,
                done,
                timeout_ms: crate::scaled_bound(FIRST_PAGE_TIMEOUT_MS),
            },
        )
    };
    // SAFETY: `STACKS` is a static array of stacks, reached only through
    // `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), index) }?;
    // SAFETY: the stack is this child's own `ChildStack`, on which no other
    // live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(&child, entry, stack, arg, cpu) }
        .map_err(|_| "memory_zero_preempt: configure_and_start_pinned failed")?;
    Ok(child)
}

/// Wait on `done` until each mask of `groups` has a bit among the bits seen,
/// at most [`REPORT_WINDOWS`] 5 s windows; the bits seen.
fn await_groups(done: u64, mut seen: u64, groups: &[u64]) -> u64
{
    for _ in 0..REPORT_WINDOWS
    {
        if groups.iter().all(|&group| seen & group != 0)
        {
            break;
        }
        seen |= notification_wait_timeout(done, 5_000).unwrap_or(0);
    }
    seen
}

/// What one attempt showed.
enum Attempt
{
    /// The call stopped at a batch after the wake and the waiter ran first.
    Passed,
    /// The attempt tells nothing about the kernel: try again.
    Inconclusive,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("memory_zero_preempt: starting");
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: memory_zero_preempt SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "memory_zero_preempt: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: memory_zero_preempt SKIP (needs 2 CPUs)");
        return Ok(());
    }

    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "memory_zero_preempt: cap_info(memory_base, SIZE) failed")?;
    let keep = size
        .checked_sub(PIECE_PAGES * PAGE_SIZE)
        .ok_or("memory_zero_preempt: memory_base is smaller than the piece")?;
    let piece = memory_split(ctx.memory_base, keep)
        .map_err(|_| "memory_zero_preempt: split the piece off memory_base failed")?;
    let outcome = with_piece(ctx, piece);
    memory_merge(ctx.memory_base, piece)
        .map_err(|_| "memory_zero_preempt: merge the piece back failed")?;
    outcome
}

/// Map `piece`, make the attempts, and unmap it.
fn with_piece(ctx: &TestContext, piece: u64) -> TestResult
{
    // SAFETY: PIECE_VA is a scratch VA (crate docs § Scratch VAs), so the span
    // holds no Rust object or IPC page of ktest.
    unsafe {
        mem_map(
            piece,
            ctx.aspace_cap,
            PIECE_VA,
            0,
            PIECE_PAGES,
            MAP_WRITABLE,
        )
    }
    .map_err(|_| "memory_zero_preempt: map the piece failed")?;
    let outcome = attempts(ctx, piece);
    // SAFETY: the span is the scratch mapping above; every child that read it
    // has been reaped.
    unsafe { mem_unmap(ctx.aspace_cap, PIECE_VA, PIECE_PAGES) }
        .map_err(|_| "memory_zero_preempt: unmap the piece failed")?;
    outcome
}

/// Make attempts until one is conclusive, at most [`ATTEMPT_LIMIT`].
fn attempts(ctx: &TestContext, piece: u64) -> TestResult
{
    for _ in 0..ATTEMPT_LIMIT
    {
        if let Attempt::Passed = attempt(ctx, piece)?
        {
            return Ok(());
        }
        crate::log("ktest: memory_zero_preempt attempt inconclusive");
    }
    Err("memory_zero_preempt: no attempt of ATTEMPT_LIMIT was conclusive")
}

/// One attempt on a freshly patterned piece.
fn attempt(ctx: &TestContext, piece: u64) -> Result<Attempt, &'static str>
{
    for page in 0..PIECE_PAGES
    {
        // SAFETY: the piece is mapped at PIECE_VA, which no reference covers.
        unsafe { first_word(page).write_volatile(PATTERN) };
        // SAFETY: as above.
        unsafe { last_word(page).write_volatile(PATTERN) };
    }
    RETURNED.store(0, Ordering::Relaxed);
    COUNT.store(0, Ordering::Relaxed);
    let wake = cap_create_notification(ctx.memory_base)
        .map_err(|_| "memory_zero_preempt: cap_create_notification (wake) failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "memory_zero_preempt: cap_create_notification (done) failed")?;
    let outcome = (|| {
        let wait = (wake, syscall_abi::RIGHTS_NTF_WAIT);
        let notify = (wake, syscall_abi::RIGHTS_NTF_NOTIFY);
        // Started first on the zeroer's CPU and outranking it, the waiter
        // blocks on `wake` before the zeroer runs.
        let waiter = start_child(ctx, 0, WAITER_PRIORITY, waiter, wait, done, TARGET_CPU)?;
        let signaller = start_child(ctx, 1, WAITER_PRIORITY, signaller, notify, done, SIGNAL_CPU)?;
        let zeroer = start_child(
            ctx,
            2,
            ZEROER_PRIORITY,
            zeroer,
            (piece, RIGHTS_MEM_MAP_RW),
            done,
            TARGET_CPU,
        )?;
        let mut bits = await_groups(done, 0, &[ZEROER_DONE, SIGNAL_BITS]);
        if bits & WAITER_BITS == 0
        {
            // A signaller that timed out never woke the waiter.
            notification_send(wake, 1).ok();
            bits = await_groups(done, bits, &[ZEROER_DONE, SIGNAL_BITS, WAITER_BITS]);
        }
        drop(zeroer);
        drop(signaller);
        drop(waiter);
        judge(bits)
    })();
    cap_delete(wake).ok();
    cap_delete(done).ok();
    outcome
}

/// Judge an attempt from its children's `bits`, the zeroer's count and the
/// piece's pages.
fn judge(bits: u64) -> Result<Attempt, &'static str>
{
    if bits & ZEROER_DONE == 0 || bits & SIGNAL_BITS == 0 || bits & WAITER_BITS == 0
    {
        crate::log_u64("memory_zero_preempt: bits=", bits);
        return Err("memory_zero_preempt: the children did not report");
    }
    let count = COUNT.load(Ordering::Relaxed);
    if count == u64::MAX || count == 0
    {
        return Err("memory_zero_preempt: the zeroer's call failed");
    }
    if bits & SIGNAL_TIMED_OUT != 0
    {
        return Err("memory_zero_preempt: the piece's first page never read zero");
    }
    if bits & SIGNAL_LATE != 0
    {
        return Ok(Attempt::Inconclusive);
    }
    if count >= PIECE_PAGES
    {
        crate::log_u64("memory_zero_preempt: count=", count);
        return Err(
            "memory_zero_preempt: the call ran to its end past the wake of a thread that outranks it",
        );
    }
    if bits & WAITER_AFTER_RETURN != 0
    {
        // The call returned before the wake, or the stop did not let the
        // waiter run first; the first is allowed, so neither is judged.
        return Ok(Attempt::Inconclusive);
    }
    crate::log_u64("memory_zero_preempt: count=", count);
    if !count.is_multiple_of(BATCH_PAGES)
    {
        return Err("memory_zero_preempt: the call stopped inside a batch");
    }
    for page in 0..PIECE_PAGES
    {
        let want = if page < count { 0 } else { PATTERN };
        // SAFETY: the piece is mapped at PIECE_VA, which no reference covers,
        // and every child has been reaped.
        let first = unsafe { first_word(page).read_volatile() };
        // SAFETY: as above.
        let last = unsafe { last_word(page).read_volatile() };
        if first != want || last != want
        {
            crate::log_u64("memory_zero_preempt: page=", page);
            return Err("memory_zero_preempt: the pages zeroed are not the count's prefix");
        }
    }
    Ok(Attempt::Passed)
}
