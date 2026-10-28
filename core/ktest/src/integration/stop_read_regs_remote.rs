// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/stop_read_regs_remote.rs

//! Integration: a thread stopped while it runs on another CPU has its
//! registers read and rewritten as soon as the stop returns.
//!
//! `SYS_THREAD_STOP` of a thread running on another CPU returns only once
//! that CPU has descheduled it and published its register save
//! (`drain_remote_stopped` in core/kernel/src/syscall/thread.rs), and
//! `SYS_THREAD_READ_REGS` / `SYS_THREAD_WRITE_REGS` act only on a thread held
//! still: off every CPU with its save published, else `InvalidState`
//! (`sched::with_held_frame`; core/kernel/docs/thread-lifecycle-and-sleep.md
//! § `sys_thread_stop` Cross-CPU Stop Protocol, and
//! core/kernel/docs/syscalls.md § `SYS_THREAD_READ_REGS`). A caller that
//! reads registers after its own stop returns is therefore never refused.
//! The test catches a stop that returns once the target's CPU has moved
//! `current` off it but before that CPU's switch publishes the save: the
//! read then lands in the gap and fails with `InvalidState`.
//!
//! A child pinned to CPU 1 spins in user mode, counting progress, with no
//! syscall in its loop, so every stop lands on it running there. The
//! controller, pinned to CPU 0, runs [`ROUNDS`] rounds: wait (bounded) for
//! the child to progress, stop it, read its registers at once (required to
//! succeed), check the saved instruction pointer lies in the child's spin
//! code, point it at [`redirected_entry`], write the registers back, and
//! restart the child. The redirected child records the round the controller
//! published before the restart, which it can learn only by entering
//! [`redirected_entry`] afresh, and spins on; the controller waits (bounded)
//! for that record, which proves the write took effect.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_delete, system_info, thread_read_regs, thread_set_affinity, thread_sleep, thread_start,
    thread_stop, thread_write_regs, thread_yield,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::arch::IP_OFFSET;
use crate::spawn::SpawnedChild;
use crate::tally::log_error;
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Rounds of stop, read, rewrite, and restart.
const ROUNDS: u32 = 50;

/// CPUs needed: one for the controller and one for the child.
const MIN_CPUS: u64 = 2;

/// The participants' CPUs.
const CONTROLLER_CPU: u32 = 0;
const CHILD_CPU: u32 = 1;

/// Bound on each wait for the child, in microseconds: for it to progress
/// before a stop, and to record a redirect after a restart. Either takes at
/// most a cross-CPU dispatch; a wait that outlasts the bound fails the test.
/// Applied through [`crate::scaled_bound`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs, where that dispatch waits for a host core.
const WAIT_US: u64 = 1_000_000;

/// Polls a bounded wait spins busily before it polls in 1 ms sleeps.
const BUSY_POLLS: u32 = 100_000;

/// Bytes from the start of each spin function within which a saved
/// instruction pointer counts as inside it: far more than either function's
/// few instructions, yet small enough that a zero, kernel, or stack address
/// fails the check.
const SPIN_CODE_BYTES: u64 = 4096;

/// Register-file buffer size; holds the arch `TrapFrame`
/// (`crate::arch::TRAP_FRAME_BYTES`) on every architecture, as the guard
/// below checks.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// Spins the child has counted.
static PROGRESS: AtomicU32 = AtomicU32::new(0);
/// The round the controller publishes before restarting a redirected child.
static ROUND: AtomicU32 = AtomicU32::new(0);
/// The round the child last read on entering [`redirected_entry`]; rounds
/// count from 1, so 0 is no redirect yet.
static REDIRECTED: AtomicU32 = AtomicU32::new(0);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "integration::stop_read_regs_remote: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: integration::stop_read_regs_remote SKIP (need 2+ CPUs)");
        return Ok(());
    }
    // The yield moves the controller onto its CPU now, not at its first
    // sleep, so the first stop already comes from another CPU than the
    // child's.
    let result = thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "integration::stop_read_regs_remote: pin controller failed")
        .and_then(|()| {
            thread_yield().map_err(|_| "integration::stop_read_regs_remote: yield failed")
        })
        .and_then(|()| scenario(ctx));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "integration::stop_read_regs_remote: restore controller affinity failed");
    result?;
    restore
}

/// Spawn the child, run the rounds, and release the child whatever the
/// outcome.
fn scenario(ctx: &TestContext) -> TestResult
{
    for counter in [&PROGRESS, &ROUND, &REDIRECTED]
    {
        counter.store(0, Ordering::Release);
    }
    let child = spawn::new_child(ctx)
        .map_err(|_| "integration::stop_read_regs_remote: spawn::new_child failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    let ran = spawn::configure_and_start_pinned(&child, spin_entry, stack_top, 0, CHILD_CPU)
        .and_then(|()| rounds(&child));
    let released = release(&child);
    ran?;
    released
}

/// Run [`ROUNDS`] rounds, stopping at the first that fails.
fn rounds(child: &SpawnedChild) -> TestResult
{
    for round in 1..=ROUNDS
    {
        let before = PROGRESS.load(Ordering::Acquire);
        await_child(
            child,
            || PROGRESS.load(Ordering::Acquire) != before,
            "integration::stop_read_regs_remote: the child did not progress before its stop",
        )?;
        thread_stop(child.th).map_err(|e| {
            log_error(
                "ktest: integration::stop_read_regs_remote thread_stop error=",
                e,
            );
            "integration::stop_read_regs_remote: thread_stop of the running child failed"
        })?;
        redirect(child, round)?;
        await_child(
            child,
            || REDIRECTED.load(Ordering::Acquire) == round,
            "integration::stop_read_regs_remote: the child never entered the redirect",
        )?;
    }
    Ok(())
}

/// Read the stopped child's registers, check its instruction pointer lies in
/// its spin code, point it at [`redirected_entry`] with `round` published,
/// write the registers back, and restart the child.
fn redirect(child: &SpawnedChild, round: u32) -> TestResult
{
    let mut regs = [0u8; BUF];
    thread_read_regs(child.th, regs.as_mut_ptr(), BUF).map_err(|e| {
        log_error(
            "ktest: integration::stop_read_regs_remote thread_read_regs error=",
            e,
        );
        "integration::stop_read_regs_remote: thread_read_regs refused the thread its stop \
         returned on"
    })?;
    let ip = u64::from_le_bytes(
        regs[IP_OFFSET..IP_OFFSET + 8]
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    if !in_spin_code(ip)
    {
        crate::log_u64("ktest: integration::stop_read_regs_remote saved ip=", ip);
        return Err("integration::stop_read_regs_remote: the saved IP is outside the spin code");
    }
    ROUND.store(round, Ordering::Release);
    let target = redirected_entry as *const () as u64;
    regs[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&target.to_le_bytes());
    thread_write_regs(child.th, regs.as_ptr(), BUF).map_err(|e| {
        log_error(
            "ktest: integration::stop_read_regs_remote thread_write_regs error=",
            e,
        );
        "integration::stop_read_regs_remote: thread_write_regs refused the stopped child"
    })?;
    thread_start(child.th).map_err(|e| {
        log_error(
            "ktest: integration::stop_read_regs_remote thread_start error=",
            e,
        );
        "integration::stop_read_regs_remote: thread_start of the stopped child failed"
    })
}

/// Whether `ip` lies within [`SPIN_CODE_BYTES`] of the start of either spin
/// function, the only code the child runs in user mode.
fn in_spin_code(ip: u64) -> bool
{
    [
        spin_entry as *const () as u64,
        redirected_entry as *const () as u64,
    ]
    .into_iter()
    .any(|start| (start..start.saturating_add(SPIN_CODE_BYTES)).contains(&ip))
}

/// Wait, for at most [`WAIT_US`], until `done` holds; fail with `stalled` if
/// it does not, or with the child's death if the child has exited (it never
/// exits on its own, so an exit is a kill).
fn await_child(child: &SpawnedChild, done: impl Fn() -> bool, stalled: &'static str) -> TestResult
{
    if await_within(crate::scaled_bound(WAIT_US), done)?
    {
        return Ok(());
    }
    if spawn::is_exited(child.th)?
    {
        return Err("integration::stop_read_regs_remote: the child died");
    }
    Err(stalled)
}

/// Poll `done` until it holds, for at most `bound_us` microseconds on the
/// `ElapsedUs` clock. The first [`BUSY_POLLS`] polls are busy; later ones
/// sleep 1 ms. Returns whether `done` held in time; a clock read that
/// fails, at the start or at a poll, is the wait's own failure, so a clock
/// the wait cannot read never leaves it unbounded.
fn await_within(bound_us: u64, done: impl Fn() -> bool) -> Result<bool, &'static str>
{
    let start = elapsed_us()?;
    let mut polls = 0u32;
    while !done()
    {
        if elapsed_us()?.saturating_sub(start) > bound_us
        {
            return Ok(false);
        }
        if polls < BUSY_POLLS
        {
            polls += 1;
            core::hint::spin_loop();
        }
        else
        {
            let _ = thread_sleep(1);
        }
    }
    Ok(true)
}

/// Microseconds since boot; the clock every bounded wait is measured on.
fn elapsed_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "integration::stop_read_regs_remote: system_info(ElapsedUs) failed")
}

/// Stop the child, so its deletion tears down a thread off its CPU, then
/// delete its Thread and `CSpace` caps. A stop refused with `InvalidState`
/// finds the child already stopped (a failed round) or dead.
fn release(child: &SpawnedChild) -> TestResult
{
    let stopped = match thread_stop(child.th)
    {
        Ok(()) => true,
        Err(e) => e == SyscallError::InvalidState as i64,
    };
    let thread_deleted = cap_delete(child.th).is_ok();
    let cspace_deleted = cap_delete(child.cs).is_ok();
    if stopped && thread_deleted && cspace_deleted
    {
        Ok(())
    }
    else
    {
        Err("integration::stop_read_regs_remote: teardown failed")
    }
}

/// Child entry: spin forever in user mode, counting progress, with no
/// syscall, so a stop always finds the child running on its CPU.
extern "C" fn spin_entry(_arg: u64) -> !
{
    loop
    {
        PROGRESS.fetch_add(1, Ordering::AcqRel);
        core::hint::spin_loop();
    }
}

/// Redirect target: record the round the controller published before the
/// restart, then spin on. Each redirect enters this on the stack the child
/// was stopped on, which grows by a few frames a round, far inside a
/// `ChildStack` across [`ROUNDS`] rounds.
fn redirected_entry() -> !
{
    REDIRECTED.store(ROUND.load(Ordering::Acquire), Ordering::Release);
    spin_entry(0)
}
