// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/sleep_list_full.rs

//! Stress: with the kernel's sleep list held at capacity, check that timed
//! IPC waits time out at once, stop and restart a thread looping them, then
//! one looping `thread_sleep(1)`, and sleep once more after the list drains.
//!
//! ## The hazard
//!
//! `sys_thread_sleep` commits its park, then adds the thread to the sleep
//! list. When the list is full the add refuses (`SleepAddError::Full`) and
//! the sleeper withdraws the park. A stop or object-teardown stop that lands
//! between the commit and the withdrawal cancels the plain sleep through
//! `sleep_list_remove` under the sleeper's `sched_lock` and stamps the park
//! `INTERRUPTED`. The withdrawal must be the same claim: a sleeper that
//! returned `OutOfMemory` after the stop had claimed the park would leave
//! the stamp unconsumed and report a failure the stop superseded. The
//! sleeper withdraws through `sleep_list_remove` under its `sched_lock`, so
//! exactly one of the two sees the deadline still pending: a won
//! withdrawal returns `OutOfMemory`, a lost one deschedules and returns
//! `Interrupted` (`sys_thread_sleep` in core/kernel/src/syscall/mod.rs;
//! core/kernel/docs/thread-lifecycle-and-sleep.md § `sys_thread_sleep` and
//! the Plain-Sleep Path, invariant 3).
//!
//! A timed `notification_wait` or `event_recv` on a full list withdraws its
//! park under the source lock it has held since queuing itself
//! (`sched::withdraw_uncontested_park`), so no cancel can claim it: a stop
//! whose cancel snapshotted the park loses the unlink, one that snapshots
//! after the withdrawal finds the target `Running` and cancels nothing, and
//! either way its commit lands on the state the target's return left; the
//! target reports its timeout (`0` bits, `WouldBlock`) rather than
//! `Interrupted` (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep
//! List Invariants, invariant 4, and § `sys_thread_stop` Cross-CPU Stop
//! Protocol, step 2).
//!
//! ## How this exercises it
//!
//! [`FILLERS`] threads, one per sleep-list slot, each loop
//! `thread_sleep(FILL_SLEEP_MS)`; the controller, pinned to CPU 0, waits
//! until every filler has started and a probe `thread_sleep(1)` of its own
//! returns `OutOfMemory`, which proves every slot is held. A victim
//! pinned to CPU 1 then loops `thread_sleep(1)` while the controller issues
//! [`CYCLES`] stop/start pairs against it, each after a cycle-varying spin,
//! so stops land before, inside and after the victim's commit-to-withdrawal
//! window. With the list full no victim sleep can be listed, so every
//! result must be `OutOfMemory` or `Interrupted`. The controller then stops
//! the victim, stops every filler (each stop cancels the filler's sleep and
//! removes its entry), and restarts the victim. The victim reads QUIT
//! before and after each sleep: a sleep that started with QUIT set must
//! return `Ok`, and one during which QUIT rose (it may still have started on
//! the full list and been interrupted by the final stop) must return `Ok` or
//! be followed by one that does: the list has room again and no earlier
//! cancellation's stamp is left to report. The fillers are deleted last.
//!
//! With the list full, before the storm, a timed `notification_wait` and a
//! timed `event_recv` must each time out at once (`0` bits, `WouldBlock`):
//! a timed wait that cannot be armed reports its timeout rather than waiting
//! untimed (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
//! Invariants, invariant 4).
//!
//! Before the sleep storm, a second victim loops a timed `notification_wait`
//! and a timed `event_recv` on the full list while the controller stops and
//! restarts it, so stops race the waits' full-list withdrawal: every wait
//! must return its timeout (`0` bits, `WouldBlock`) or `Interrupted`.
//!
//! Required: every result read with QUIT clear is `OutOfMemory` or
//! `Interrupted`; some result is `OutOfMemory` (the full-list path ran); the
//! after-drain sleep, as above, returns `Ok`; every storm wait returns its
//! timeout or `Interrupted`, and some return the timeout. Userspace cannot tell a won
//! withdrawal that a stop then committed over from one no stop reached, so
//! the lost-withdrawal interleaving is reached statistically; the kernel's
//! debug assertions are its tripwire.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_cspace, cap_create_notification, cap_create_thread, cap_delete,
    event_queue_create, event_recv_timeout, notification_wait_timeout, system_info, thread_exit,
    thread_set_affinity, thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{RIGHTS_EQ_RECV, RIGHTS_NTF_WAIT, SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::sleep_list_full";

/// Sleep-list capacity: `MAX_SLEEPING` in core/kernel/src/sched/mod.rs.
const FILLERS: usize = 128;

/// How long each filler sleeps per iteration, in milliseconds; far longer
/// than the cell runs, so no filler frees its slot until it is deleted.
const FILL_SLEEP_MS: u64 = 600_000;

/// Timeout of the timed waits issued with the list full, in milliseconds;
/// they must return at once, long before it.
const TIMED_WAIT_MS: u64 = 60_000;

/// Stop/start pairs to issue against the timed-wait victim.
const WAIT_CYCLES: u32 = 1000;

/// Stop/start pairs to issue against the victim.
const CYCLES: u32 = 2000;

/// The controller's and the victim's CPUs.
const CONTROLLER_CPU: u32 = 0;
const VICTIM_CPU: u32 = 1;

/// Bound, in 1 ms polls, on each of the controller's waits.
const WAIT_POLLS: u32 = 5000;

/// A filler's stack: fillers only loop on one syscall.
#[repr(C, align(16))]
struct FillStack([u8; 8192]);

// SAFETY: each filler uses only its own element; fillers are deleted
// before this cell returns and stress cells run sequentially.
static mut FILL_STACKS: [FillStack; FILLERS] = [const { FillStack([0; 8192]) }; FILLERS];

/// Fillers that have started (counted just before their first sleep).
static FILLED: AtomicU32 = AtomicU32::new(0);
/// Set by the controller once the victim may stop looping.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Victim: set once it is looping, and once it has recorded its last sleep.
static RUNNING: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
/// Victim tallies during the storm.
static OOM: AtomicU64 = AtomicU64::new(0);
static INTERRUPTED: AtomicU64 = AtomicU64::new(0);
static BAD: AtomicU64 = AtomicU64::new(0);
/// Timed-wait victim: run and finish flags, quit request, and tallies.
static WAIT_RUNNING: AtomicU32 = AtomicU32::new(0);
static WAIT_DONE: AtomicU32 = AtomicU32::new(0);
static WAIT_QUIT: AtomicU32 = AtomicU32::new(0);
static WAIT_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static WAIT_INTERRUPTED: AtomicU64 = AtomicU64::new(0);
static WAIT_BAD: AtomicU64 = AtomicU64::new(0);
/// The victim's after-drain result (see `victim_entry`): 1 = `Ok`, 2 =
/// anything else.
static AFTER: AtomicU32 = AtomicU32::new(0);

/// Run the cell with `ctx`'s controller thread, address space and memory:
/// skip below 2 CPUs; otherwise fail if a timed wait on the full list did not
/// time out at once, if a stormed timed wait returned neither its timeout nor
/// `Interrupted`, if a storm sleep returned neither `OutOfMemory` nor
/// `Interrupted`, if none met the full list, or if the after-drain sleep did
/// not return `Ok`. Setup, a bounded wait, a stop or start, or teardown that
/// fails returns `Err` naming the step.
pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::sleep_list_full: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::sleep_list_full SKIP (need 2+ CPUs)");
        return Ok(());
    }
    for counter in [
        &FILLED,
        &QUIT,
        &RUNNING,
        &DONE,
        &AFTER,
        &WAIT_RUNNING,
        &WAIT_DONE,
        &WAIT_QUIT,
    ]
    {
        counter.store(0, Ordering::Release);
    }
    for tally in [
        &OOM,
        &INTERRUPTED,
        &BAD,
        &WAIT_TIMEOUTS,
        &WAIT_INTERRUPTED,
        &WAIT_BAD,
    ]
    {
        tally.store(0, Ordering::Release);
    }

    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::sleep_list_full: pin controller failed")?;
    let result = with_fillers(ctx);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::sleep_list_full: restore controller affinity failed");
    result?;
    restore?;

    crate::tally::log_cell_u64(CELL, " oom=", OOM.load(Ordering::Relaxed));
    crate::tally::log_cell_u64(CELL, " interrupted=", INTERRUPTED.load(Ordering::Relaxed));
    if BAD.load(Ordering::Relaxed) != 0
    {
        return Err(
            "stress::sleep_list_full: a sleep with the list full returned neither OutOfMemory nor \
             Interrupted",
        );
    }
    if OOM.load(Ordering::Relaxed) == 0
    {
        return Err("stress::sleep_list_full: no sleep met the full list (never armed)");
    }
    if AFTER.load(Ordering::Acquire) != 1
    {
        return Err("stress::sleep_list_full: the after-drain sleep did not return Ok");
    }
    Ok(())
}

/// Fill the sleep list, check the timed waits, run the timed-wait storm and
/// the sleep storm (each reaps its own victim), and delete every filler
/// whatever the outcome.
fn with_fillers(ctx: &TestContext) -> TestResult
{
    let cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "stress::sleep_list_full: create filler cspace failed")?;
    let mut fillers = [0u32; FILLERS];
    let mut created = 0usize;
    let mut result = spawn_fillers(ctx, cs, &mut fillers, &mut created)
        .and_then(|()| await_full())
        .and_then(|()| timed_waits_time_out(ctx))
        .and_then(|()| timed_wait_storm(ctx))
        .and_then(|()| with_victim(ctx, &fillers[..created]));
    // Deleting a filler removes its sleep entry if a failed storm left one.
    for &th in &fillers[..created]
    {
        if cap_delete(th).is_err() && result.is_ok()
        {
            result = Err("stress::sleep_list_full: delete filler failed");
        }
    }
    if cap_delete(cs).is_err() && result.is_ok()
    {
        result = Err("stress::sleep_list_full: delete filler cspace failed");
    }
    result
}

/// Create and start one filler per sleep-list slot in the shared `cs`.
fn spawn_fillers(
    ctx: &TestContext,
    cs: u32,
    fillers: &mut [u32; FILLERS],
    created: &mut usize,
) -> TestResult
{
    for (i, slot) in fillers.iter_mut().enumerate()
    {
        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
            .map_err(|_| "stress::sleep_list_full: create filler failed")?;
        *slot = th;
        *created = i + 1;
        // SAFETY: element i is this filler's alone (see FILL_STACKS).
        let base = unsafe { core::ptr::addr_of!(FILL_STACKS[i]) } as u64;
        let child = spawn::SpawnedChild { th, cs };
        spawn::configure_and_start(&child, filler_entry, base + 8192, 0)
            .map_err(|_| "stress::sleep_list_full: start filler failed")?;
    }
    Ok(())
}

/// Wait until every filler has entered its sleep, then until a probe sleep
/// of the controller's own meets the full list.
fn await_full() -> TestResult
{
    for _ in 0..WAIT_POLLS
    {
        if FILLED.load(Ordering::Acquire) as usize == FILLERS
        {
            break;
        }
        let _ = thread_sleep(1);
    }
    for _ in 0..WAIT_POLLS
    {
        match thread_sleep(1)
        {
            Err(e) if e == SyscallError::OutOfMemory as i64 => return Ok(()),
            _ =>
            {}
        }
    }
    Err("stress::sleep_list_full: the sleep list never filled")
}

/// With the list full, a timed notification wait and a timed event receive
/// must time out at once (0 bits, `WouldBlock`) rather than wait untimed: a
/// regression hangs here, which fails the boot.
fn timed_waits_time_out(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::sleep_list_full: create notification failed")?;
    let Ok(eq) = event_queue_create(ctx.memory_base, 4)
    else
    {
        let _ = cap_delete(sig);
        return Err("stress::sleep_list_full: create event queue failed");
    };
    let notified = notification_wait_timeout(sig, TIMED_WAIT_MS);
    let received = event_recv_timeout(eq, TIMED_WAIT_MS);
    let deleted = cap_delete(sig).and(cap_delete(eq));
    if notified != Ok(0)
    {
        return Err(
            "stress::sleep_list_full: a timed notification wait on the full list did not \
                    time out",
        );
    }
    if received != Err(SyscallError::WouldBlock as i64)
    {
        return Err(
            "stress::sleep_list_full: a timed event receive on the full list did not time \
                    out",
        );
    }
    deleted.map_err(|_| "stress::sleep_list_full: delete wait sources failed")
}

/// Spawn a victim looping a timed notification wait and a timed event
/// receive on the full list, storm it with stop/start pairs, and reap it:
/// every wait must return its timeout or `Interrupted`.
fn timed_wait_storm(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::sleep_list_full: create storm notification failed")?;
    let Ok(eq) = event_queue_create(ctx.memory_base, 4)
    else
    {
        let _ = cap_delete(sig);
        return Err("stress::sleep_list_full: create storm event queue failed");
    };
    let result = spawn::new_child(ctx)
        .map_err(|_| "stress::sleep_list_full: spawn wait victim failed")
        .and_then(|child| {
            let stormed = storm_waits(&child, sig, eq);
            let reaped = [cap_delete(child.th), cap_delete(child.cs)]
                .into_iter()
                .collect::<Result<(), i64>>()
                .map_err(|_| "stress::sleep_list_full: reap wait victim failed");
            stormed.and(reaped)
        });
    let deleted = cap_delete(sig)
        .and(cap_delete(eq))
        .map_err(|_| "stress::sleep_list_full: delete storm sources failed");
    result?;
    deleted?;
    crate::tally::log_cell_u64(
        CELL,
        " wait_timeouts=",
        WAIT_TIMEOUTS.load(Ordering::Relaxed),
    );
    crate::tally::log_cell_u64(
        CELL,
        " wait_interrupted=",
        WAIT_INTERRUPTED.load(Ordering::Relaxed),
    );
    if WAIT_BAD.load(Ordering::Relaxed) != 0
    {
        return Err(
            "stress::sleep_list_full: a timed wait on the full list returned neither its timeout \
             nor Interrupted",
        );
    }
    if WAIT_TIMEOUTS.load(Ordering::Relaxed) == 0
    {
        return Err("stress::sleep_list_full: no timed wait met the full list (never armed)");
    }
    Ok(())
}

fn storm_waits(child: &spawn::SpawnedChild, sig: u32, eq: u32) -> TestResult
{
    let c_sig = cap_copy(sig, child.cs, RIGHTS_NTF_WAIT)
        .map_err(|_| "stress::sleep_list_full: cap_copy storm notification failed")?;
    let c_eq = cap_copy(eq, child.cs, RIGHTS_EQ_RECV)
        .map_err(|_| "stress::sleep_list_full: cap_copy storm event queue failed")?;
    // SAFETY: stack index 0 is this cell's only STRESS_STACKS user; this
    // victim is deleted before the sleep victim reuses the stack.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
    let arg = u64::from(c_sig) | (u64::from(c_eq) << 32);
    spawn::configure_and_start_pinned(child, wait_victim_entry, stack, arg, VICTIM_CPU)
        .map_err(|_| "stress::sleep_list_full: start wait victim failed")?;
    await_flag(
        &WAIT_RUNNING,
        "stress::sleep_list_full: the wait victim never ran",
    )?;
    for cycle in 0..WAIT_CYCLES
    {
        for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
        {
            core::hint::spin_loop();
        }
        thread_stop(child.th).map_err(|_| "stress::sleep_list_full: stop wait victim failed")?;
        thread_start(child.th)
            .map_err(|_| "stress::sleep_list_full: start wait victim again failed")?;
    }
    WAIT_QUIT.store(1, Ordering::Release);
    await_flag(
        &WAIT_DONE,
        "stress::sleep_list_full: the wait victim never finished",
    )
}

/// Wait victim: alternate a timed notification wait and a timed event
/// receive on the full list until told to quit, tallying each result.
// cast_possible_truncation: the halves are 32-bit cap handles.
#[allow(clippy::cast_possible_truncation)]
fn wait_victim_entry(arg: u64) -> !
{
    let sig = arg as u32;
    let eq = (arg >> 32) as u32;
    WAIT_RUNNING.store(1, Ordering::Release);
    let interrupted = SyscallError::Interrupted as i64;
    while WAIT_QUIT.load(Ordering::Acquire) == 0
    {
        let tally = match notification_wait_timeout(sig, TIMED_WAIT_MS)
        {
            Ok(0) => &WAIT_TIMEOUTS,
            Err(e) if e == interrupted => &WAIT_INTERRUPTED,
            _ => &WAIT_BAD,
        };
        tally.fetch_add(1, Ordering::Relaxed);
        let tally = match event_recv_timeout(eq, TIMED_WAIT_MS)
        {
            Err(e) if e == SyscallError::WouldBlock as i64 => &WAIT_TIMEOUTS,
            Err(e) if e == interrupted => &WAIT_INTERRUPTED,
            _ => &WAIT_BAD,
        };
        tally.fetch_add(1, Ordering::Relaxed);
    }
    WAIT_DONE.store(1, Ordering::Release);
    thread_exit()
}

/// Start the victim, storm it, cancel the fillers' sleeps by stopping the
/// fillers, then let the victim sleep once more; always reap the victim.
fn with_victim(ctx: &TestContext, fillers: &[u32]) -> TestResult
{
    let child =
        spawn::new_child(ctx).map_err(|_| "stress::sleep_list_full: spawn victim failed")?;
    let result = storm(&child, fillers);
    let reaped = [cap_delete(child.th), cap_delete(child.cs)]
        .into_iter()
        .collect::<Result<(), i64>>();
    result?;
    reaped.map_err(|_| "stress::sleep_list_full: reap victim failed")
}

fn storm(child: &spawn::SpawnedChild, fillers: &[u32]) -> TestResult
{
    // SAFETY: stack index 0 is this cell's only STRESS_STACKS user; the
    // victim is deleted before this cell returns.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
    spawn::configure_and_start_pinned(child, victim_entry, stack, 0, VICTIM_CPU)
        .map_err(|_| "stress::sleep_list_full: start victim failed")?;
    await_flag(&RUNNING, "stress::sleep_list_full: the victim never ran")?;

    for cycle in 0..CYCLES
    {
        // Vary the stop's phase against the sleep loop: 0 to 4095 spins
        // (a multiplicative hash of the cycle) before each pair.
        for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
        {
            core::hint::spin_loop();
        }
        thread_stop(child.th).map_err(|_| "stress::sleep_list_full: thread_stop failed")?;
        thread_start(child.th).map_err(|_| "stress::sleep_list_full: thread_start failed")?;
    }

    // Stop the victim, raise QUIT, then free the slots: stopping a sleeping
    // filler cancels its sleep and removes its entry. QUIT rises while the
    // victim is stopped, so a sleep it starts after reading QUIT set starts
    // on the drained list and alone must return Ok, and one during which
    // QUIT rose may have started on the full list, so it or the next sleep
    // must return Ok.
    thread_stop(child.th).map_err(|_| "stress::sleep_list_full: stop victim failed")?;
    QUIT.store(1, Ordering::Release);
    for &th in fillers
    {
        thread_stop(th).map_err(|_| "stress::sleep_list_full: stop filler failed")?;
    }
    thread_start(child.th).map_err(|_| "stress::sleep_list_full: restart victim failed")?;
    await_flag(&DONE, "stress::sleep_list_full: the victim never finished")
}

/// Busy-wait, bounded, until `flag` is set. The controller spins rather
/// than sleeps: while the list is full a sleep returns `OutOfMemory` at once.
fn await_flag(flag: &AtomicU32, err: &'static str) -> TestResult
{
    for _ in 0..WAIT_POLLS
    {
        if flag.load(Ordering::Acquire) != 0
        {
            return Ok(());
        }
        for _ in 0..100_000
        {
            core::hint::spin_loop();
        }
    }
    Err(err)
}

/// Filler: count the first sleep's entry, then sleep until deleted.
fn filler_entry(_arg: u64) -> !
{
    FILLED.fetch_add(1, Ordering::AcqRel);
    loop
    {
        let _ = thread_sleep(FILL_SLEEP_MS);
    }
}

/// Victim: loop `thread_sleep(1)`, reading QUIT before and after each sleep
/// and tallying results with QUIT clear throughout. A sleep that started with
/// QUIT set must return `Ok`; one during which QUIT rose may still have
/// started on the full list, so it or the next sleep must return `Ok`.
fn victim_entry(_arg: u64) -> !
{
    RUNNING.store(1, Ordering::Release);
    let after = loop
    {
        let quit_before = QUIT.load(Ordering::Acquire) != 0;
        let slept = thread_sleep(1);
        if quit_before
        {
            // Started on the drained list: it alone must return Ok.
            break if slept.is_ok() { 1 } else { 2 };
        }
        if QUIT.load(Ordering::Acquire) != 0
        {
            // QUIT rose during this sleep, which may have started on the
            // full list and been interrupted by the final stop; the next
            // sleep starts on the drained list and must return Ok.
            break if slept.is_ok() || thread_sleep(1).is_ok()
            {
                1
            }
            else
            {
                2
            };
        }
        match slept
        {
            Err(e) if e == SyscallError::OutOfMemory as i64 => OOM.fetch_add(1, Ordering::Relaxed),
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {
                INTERRUPTED.fetch_add(1, Ordering::Relaxed)
            }
            _ => BAD.fetch_add(1, Ordering::Relaxed),
        };
    };
    AFTER.store(after, Ordering::Release);
    DONE.store(1, Ordering::Release);
    thread_exit()
}
