// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/stop_resume_race.rs

//! Stress: race `sys_thread_stop` against a concurrent `sys_thread_start`
//! (resume) on the same `Running` thread — the `thread_stop` cross-CPU drain
//! liveness invariant.
//!
//! ## The hazard
//!
//! `sys_thread_stop` on a `Running` remote target commits `Stopped` under all
//! CPU locks, then *drains* the target off the owning CPU's `current` (a
//! cross-CPU spin). The drain's termination rests on the target staying in a
//! state `schedule()`'s requeue denylist rejects (`Stopped`), so the owning CPU
//! deschedules it without re-linking. A concurrent `sys_thread_start` breaks
//! that: it resumes the target out of `Stopped` (last-writer-wins) and
//! re-dispatches it onto its pinned CPU, where a sole runnable spinner never
//! leaves `current`. Without a `state == Stopped` re-check the drain spins
//! forever — two CONTROL-cap holders racing stop/start wedge a CPU
//! (`thread.rs::sys_thread_stop`; see
//! `docs/thread-lifecycle-and-sleep.md § sys_thread_stop Cross-CPU Stop
//! Protocol`).
//!
//! ## How this exercises it
//!
//! Each cycle pins three children to three distinct CPUs:
//!   * VICTIM spins in pure userspace (no syscalls) so it stays `Running` on
//!     its CPU.
//!   * STOPPER issues `thread_stop(victim)` — opening the cross-CPU drain.
//!   * STARTER issues `thread_start(victim)` — the resume that, when it lands
//!     during the drain, re-dispatches the victim and (pre-fix) wedges the
//!     stopper.
//!
//! STOPPER and STARTER are released at the same instant by a shared-memory
//! barrier (the [`RELEASE`] `AtomicU32`), so the resume overlaps the drain.
//! The resume also drives `sys_thread_start`'s `await_descheduled`
//! resume-from-stop path (the #330 fix) on every armed cycle, a smoke check of
//! that code.
//!
//! This cell does **not** reproduce the #330 cross-CPU double-dispatch: the
//! resume force-links onto the victim's *own* CPU (`select_target_cpu` returns
//! the hard-affinity / save-window-pinned CPU), and the all-CPU-locks
//! discipline closes the force-link-while-`current` window. It targets the
//! sibling liveness invariant of the stop drain instead.
//!
//! ## Anti-vacuous guard
//!
//! A run that never armed (victim never `Running`, or a racer never issued)
//! would pass trivially. Each cycle proves the setup: VICTIM signals
//! [`BIT_VICTIM_RUNNING`] only after it is executing, STOPPER/STARTER signal
//! [`BIT_STOPPER_READY`]/[`BIT_STARTER_READY`] before parking on the barrier,
//! and [`BIT_STOP_DONE`]/[`BIT_START_DONE`] after their syscalls return. The
//! controller requires all five every cycle and asserts `armed_cycles ==
//! CYCLES`. As with `stop_reply_race`, this proves the armable setup, not the
//! exact wedging sub-interleaving — a regression surfaces as a kernel hang
//! (the stopper's `thread_stop` never returns, so `BIT_STOP_DONE` never
//! arrives; every CPU goes idle and the softlockup watchdog fires), not as a
//! test assertion.
//!
//! ## Pass criterion
//!
//! Needs **≥ 3 CPUs**: the three roles must occupy three distinct cores so the
//! stop is a real cross-CPU drain (stopper ≠ victim) and the resume runs
//! concurrently with it (starter ≠ stopper). On the post-fix kernel the
//! harness boots clean to `[ktest] ALL TESTS PASSED`. Reverting the drain's
//! `state == Stopped` re-check wedges the stopper and the run hangs (the
//! softlockup watchdog / harness timeout reports it) — raised by the kernel,
//! not by this test.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    system_info, thread_exit, thread_start, thread_stop,
};
use syscall_abi::{RIGHTS_CONTROL, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Stop-vs-resume races to run. 256 gives the drain/resume overlap many chances
/// across the CPU rotation while staying well under a second.
const CYCLES: usize = 256;

/// Notification signal right (bit 7) — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = 1 << 7;

/// Bounded barrier spin: a racer stops waiting after this many iterations even
/// if [`RELEASE`] never flips (defense-in-depth against a lost release — the
/// race still fires, just less synchronised). Large enough that a timer tick
/// preempts the spin long before it is reached on a healthy kernel.
const SPIN_BUDGET: u32 = 8_000_000;

/// VICTIM raises this once it is executing in its spin loop (proves `Running`).
const BIT_VICTIM_RUNNING: u64 = 1 << 0;
/// STOPPER raises this before parking on the barrier.
const BIT_STOPPER_READY: u64 = 1 << 1;
/// STARTER raises this before parking on the barrier.
const BIT_STARTER_READY: u64 = 1 << 2;
/// STOPPER raises this after `thread_stop` returns.
const BIT_STOP_DONE: u64 = 1 << 3;
/// STARTER raises this after `thread_start` returns.
const BIT_START_DONE: u64 = 1 << 4;

/// All three setup witnesses — required before the barrier is released.
const ALL_READY: u64 = BIT_VICTIM_RUNNING | BIT_STOPPER_READY | BIT_STARTER_READY;
/// Both post-release witnesses — required before the cycle is cleaned up.
const ALL_DONE: u64 = BIT_STOP_DONE | BIT_START_DONE;

/// Shared-memory release barrier. Children run in ktest's address space
/// (`ctx.aspace_cap`), so this module static is visible to all three. The
/// controller flips it to 1 to release STOPPER and STARTER at the same instant.
static RELEASE: AtomicU32 = AtomicU32::new(0);

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_resume_race: system_info(CpuCount) failed")?;
    // Three roles on three distinct CPUs: the stop must be a cross-CPU drain
    // (stopper ≠ victim) and the resume must run concurrently with it (starter
    // ≠ stopper). On 2 CPUs a role pairing collapses and the drain/resume
    // overlap is lost, so skip.
    if cpus < 3
    {
        crate::log("ktest: stress::stop_resume_race SKIP (need 3+ CPUs)");
        return Ok(());
    }
    let cpu_mod = u32::try_from(cpus).unwrap_or(1).max(1);

    // Anti-vacuous accumulator: every cycle must arm the setup exactly once.
    let mut armed_cycles = 0usize;

    for cycle in 0..CYCLES
    {
        // CYCLES is a compile-time constant well below u32::MAX; try_from keeps
        // the narrow cast clippy-clean.
        let cycle_u32 = u32::try_from(cycle).unwrap_or(0);
        // Distinct for cpus >= 3: offsets 0,1,2 never collide mod n.
        let victim_cpu = cycle_u32 % cpu_mod;
        let stop_cpu = (cycle_u32 + 1) % cpu_mod;
        let start_cpu = (cycle_u32 + 2) % cpu_mod;

        // Arm the barrier closed before the racers can read it.
        RELEASE.store(0, Ordering::Release);

        let done = cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::stop_resume_race: cap_create_notification failed")?;

        // ── VICTIM: spin Running on victim_cpu; signal on done. ──────────────
        let victim =
            spawn::new_child(ctx).map_err(|_| "stress::stop_resume_race: spawn victim failed")?;
        let victim_done = cap_copy(done, victim.cs, RIGHTS_SIGNAL)
            .map_err(|_| "stress::stop_resume_race: cap_copy victim done failed")?;
        // SAFETY: stack index 0 is the victim's; sequential cycles never alias
        // (cap_delete(victim.th) drains the spinner before the next cycle).
        let victim_stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
        spawn::configure_and_start_pinned(
            &victim,
            victim_entry,
            victim_stack,
            u64::from(victim_done),
            victim_cpu,
        )
        .map_err(|_| "stress::stop_resume_race: start victim failed")?;

        // ── STOPPER: CONTROL on victim + signal on done; pinned stop_cpu. ────
        let stopper =
            spawn::new_child(ctx).map_err(|_| "stress::stop_resume_race: spawn stopper failed")?;
        let stopper_victim = cap_copy(victim.th, stopper.cs, RIGHTS_CONTROL)
            .map_err(|_| "stress::stop_resume_race: cap_copy stopper victim failed")?;
        let stopper_done = cap_copy(done, stopper.cs, RIGHTS_SIGNAL)
            .map_err(|_| "stress::stop_resume_race: cap_copy stopper done failed")?;
        // arg packs victim_slot[15:0] | done_slot[31:16].
        let stopper_arg = u64::from(stopper_victim) | (u64::from(stopper_done) << 16);
        // SAFETY: stack index 1 is the stopper's; sequential cycles never alias.
        let stopper_stack =
            ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[1]) });
        spawn::configure_and_start_pinned(
            &stopper,
            stopper_entry,
            stopper_stack,
            stopper_arg,
            stop_cpu,
        )
        .map_err(|_| "stress::stop_resume_race: start stopper failed")?;

        // ── STARTER: CONTROL on victim + signal on done; pinned start_cpu. ───
        let starter =
            spawn::new_child(ctx).map_err(|_| "stress::stop_resume_race: spawn starter failed")?;
        let starter_victim = cap_copy(victim.th, starter.cs, RIGHTS_CONTROL)
            .map_err(|_| "stress::stop_resume_race: cap_copy starter victim failed")?;
        let starter_done = cap_copy(done, starter.cs, RIGHTS_SIGNAL)
            .map_err(|_| "stress::stop_resume_race: cap_copy starter done failed")?;
        // arg packs victim_slot[15:0] | done_slot[31:16].
        let starter_arg = u64::from(starter_victim) | (u64::from(starter_done) << 16);
        // SAFETY: stack index 2 is the starter's; sequential cycles never alias.
        let starter_stack =
            ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[2]) });
        spawn::configure_and_start_pinned(
            &starter,
            starter_entry,
            starter_stack,
            starter_arg,
            start_cpu,
        )
        .map_err(|_| "stress::stop_resume_race: start starter failed")?;

        // Wait until the victim is Running and both racers are parked on the
        // barrier — the armable setup. Notification sends coalesce (OR), so one
        // accumulator collects all three witnesses.
        let mut acc = 0u64;
        while acc & ALL_READY != ALL_READY
        {
            let bits = notification_wait(done)
                .map_err(|_| "stress::stop_resume_race: notification_wait(ready) failed")?;
            acc |= bits;
        }
        armed_cycles += 1;

        // Fire both racers at the same instant. Do NOT yield here — that would
        // narrow the stop-drain / resume overlap.
        RELEASE.store(1, Ordering::Release);

        // Wait for both racing syscalls to return. If a regression wedges the
        // stopper's thread_stop drain, BIT_STOP_DONE never arrives and the run
        // hangs (softlockup watchdog / harness timeout) — the FAIL signal.
        while acc & ALL_DONE != ALL_DONE
        {
            let bits = notification_wait(done)
                .map_err(|_| "stress::stop_resume_race: notification_wait(done) failed")?;
            acc |= bits;
        }

        // ── Per-cycle cleanup (order is load-bearing). ───────────────────────
        //
        // The victim Thread object has three refs (victim.th + the two CONTROL
        // copies in the racer CSpaces); it drains only when the LAST is
        // deleted. Reap the racer threads first (th before cs, the spawn
        // convention), then drop both racer CSpaces (releasing the two copies),
        // then victim.th — the last ref. Its dealloc commits the terminal
        // Exited state (which no concurrent start can resume), so the drain
        // deschedules the spinner and completes before the next cycle reuses its
        // stack.
        cap_delete(stopper.th)
            .map_err(|_| "stress::stop_resume_race: cap_delete stopper th failed")?;
        cap_delete(starter.th)
            .map_err(|_| "stress::stop_resume_race: cap_delete starter th failed")?;
        cap_delete(stopper.cs)
            .map_err(|_| "stress::stop_resume_race: cap_delete stopper cs failed")?;
        cap_delete(starter.cs)
            .map_err(|_| "stress::stop_resume_race: cap_delete starter cs failed")?;
        cap_delete(victim.th)
            .map_err(|_| "stress::stop_resume_race: cap_delete victim th failed")?;
        cap_delete(victim.cs)
            .map_err(|_| "stress::stop_resume_race: cap_delete victim cs failed")?;
        cap_delete(done).map_err(|_| "stress::stop_resume_race: cap_delete done failed")?;
    }

    // Non-vacuous: the setup armed on every cycle, so a clean boot reflects the
    // stop-vs-resume drain path actually executing, not a setup that no-op'd.
    if armed_cycles != CYCLES
    {
        return Err("stress::stop_resume_race: race never armed on some cycle");
    }

    Ok(())
}

// ── Child entries ─────────────────────────────────────────────────────────

/// VICTIM: announce `Running`, then spin in pure userspace forever. No
/// syscalls after the signal, so it stays `current` on its CPU until a stop
/// drains it or the controller `cap_delete`s it.
// cast_possible_truncation: done is a kernel cap slot index < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn victim_entry(arg: u64) -> !
{
    let done = (arg & 0xFFFF) as u32;
    notification_send(done, BIT_VICTIM_RUNNING).ok();
    loop
    {
        core::hint::spin_loop();
    }
}

/// STOPPER: park on the barrier, then `thread_stop(victim)` while the victim is
/// `Running` on another CPU — opening the cross-CPU drain the resume races.
// cast_possible_truncation: cap slots are < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn stopper_entry(arg: u64) -> !
{
    let victim = (arg & 0xFFFF) as u32;
    let done = ((arg >> 16) & 0xFFFF) as u32;
    notification_send(done, BIT_STOPPER_READY).ok();
    wait_for_release();
    let _ = thread_stop(victim);
    notification_send(done, BIT_STOP_DONE).ok();
    thread_exit()
}

/// STARTER: park on the barrier, then `thread_start(victim)` concurrently with
/// STOPPER — the resume that re-dispatches the victim mid-drain.
// cast_possible_truncation: cap slots are < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn starter_entry(arg: u64) -> !
{
    let victim = (arg & 0xFFFF) as u32;
    let done = ((arg >> 16) & 0xFFFF) as u32;
    notification_send(done, BIT_STARTER_READY).ok();
    wait_for_release();
    let _ = thread_start(victim);
    notification_send(done, BIT_START_DONE).ok();
    thread_exit()
}

/// Spin on the shared barrier until the controller releases it. Bounded by
/// [`SPIN_BUDGET`] so a lost release cannot hang the harness.
fn wait_for_release()
{
    let mut spins = 0u32;
    while RELEASE.load(Ordering::Acquire) == 0
    {
        if spins >= SPIN_BUDGET
        {
            break;
        }
        spins += 1;
        core::hint::spin_loop();
    }
}
