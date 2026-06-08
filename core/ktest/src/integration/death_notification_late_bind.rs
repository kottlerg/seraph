// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/death_notification_late_bind.rs

//! Integration: a death observer bound *after* the thread has already died
//! still receives the retained exit reason.
//!
//! The kernel records a thread's `exit_reason` when it becomes `Exited` and
//! retains it on the TCB. `SYS_THREAD_BIND_NOTIFICATION` serialises on the
//! thread's `sched_lock`: a bind onto an already-`Exited` thread re-delivers
//! that retained reason to the newly-bound `EventQueue` instead of walking an
//! empty observer set and dropping the event. This is the bind-after-start
//! window a supervisor (svcmgr) hits when it binds a service init had already
//! started (#106 Window 2).
//!
//! Three scenarios, all on the real exit/fault paths:
//!   1. A child exits cleanly with no observer bound; a later bind delivers
//!      the retained clean reason (`0`).
//!   2. A child faults with no observer bound; a later bind delivers the
//!      retained fault reason (`EXIT_FAULT_BASE + <vector>`).
//!   3. Negative control: an observer bound *before* start still fires
//!      exactly once — guarding the pre-existing path against a double-post
//!      from the new retained-delivery branch.

use syscall::{
    cap_delete, cap_info, event_queue_create, event_try_recv, thread_bind_notification,
    thread_exit, thread_sleep,
};
use syscall_abi::{CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, SyscallError, THREAD_STATE_EXITED};

use crate::{ChildStack, TestContext, TestResult};

/// A user-half VA no test maps (104 TiB, canonical), distinct from
/// `fault_kills_thread`'s `WILD_VA` so the two never share a mapping.
const WILD_VA: u64 = 0x6800_0000_0000;

/// Fault vector recorded in `exit_reason` for a not-present store.
#[cfg(target_arch = "x86_64")]
const FAULT_VECTOR: u64 = 14; // #PF
#[cfg(target_arch = "riscv64")]
const FAULT_VECTOR: u64 = 15; // store/AMO page fault

/// Distinct, non-zero correlators so a dropped or misrouted event surfaces as
/// a wrong high word rather than a coincidental zero.
const CORR_CLEAN: u32 = 0x1111;
const CORR_FAULT: u32 = 0x2222;
const CORR_LIVE: u32 = 0x3333;

/// Poll bound: ~2 s at 1 ms/poll before declaring a child never reached
/// `Exited` (a mis-classified fault would otherwise loop forever).
const MAX_POLLS: u32 = 2000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    // Scenario 1: clean exit, bind after death.
    late_bind_after_death(ctx, clean_exit_child, CORR_CLEAN, 0)?;

    // Scenario 2: fault, bind after death.
    late_bind_after_death(ctx, fault_child, CORR_FAULT, EXIT_FAULT_BASE + FAULT_VECTOR)?;

    // Scenario 3: negative control — bind before start fires exactly once.
    bind_before_start_fires_once(ctx)?;

    Ok(())
}

/// Spawn `entry`, wait until it is `Exited` with **no** observer bound, then
/// bind a fresh queue and assert the retained `expected_reason` is delivered
/// exactly once under `correlator`.
fn late_bind_after_death(
    ctx: &TestContext,
    entry: fn(u64) -> !,
    correlator: u32,
    expected_reason: u64,
) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "death_notification_late_bind: spawn::new_child failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, entry, stack_top, 0)
        .map_err(|_| "death_notification_late_bind: configure_and_start failed")?;

    wait_until_exited(child.th)?;

    // Bind a fresh queue onto the already-dead thread; the kernel delivers the
    // retained reason synchronously inside the bind syscall.
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "death_notification_late_bind: event_queue_create failed")?;
    thread_bind_notification(child.th, eq, correlator)
        .map_err(|_| "death_notification_late_bind: bind onto exited thread failed")?;

    let payload = event_try_recv(eq).map_err(
        |_| "death_notification_late_bind: no event delivered to late-bound observer (dropped)",
    )?;
    let expected = (u64::from(correlator) << 32) | (expected_reason & 0xFFFF_FFFF);
    if payload != expected
    {
        return Err("death_notification_late_bind: late-bound observer got wrong payload");
    }
    // Retained delivery must post exactly once.
    if event_try_recv(eq) != Err(SyscallError::WouldBlock as i64)
    {
        return Err("death_notification_late_bind: retained reason delivered more than once");
    }

    cap_delete(eq).ok();
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    Ok(())
}

/// Bind an observer while the child is still `Created`, then start it; the
/// death walk must post exactly once.
fn bind_before_start_fires_once(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "death_notification_late_bind: spawn::new_child (control) failed")?;
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "death_notification_late_bind: event_queue_create (control) failed")?;
    // Thread is Created (not started): the append path.
    thread_bind_notification(child.th, eq, CORR_LIVE)
        .map_err(|_| "death_notification_late_bind: bind before start failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, clean_exit_child, stack_top, 0)
        .map_err(|_| "death_notification_late_bind: configure_and_start (control) failed")?;

    wait_until_exited(child.th)?;

    // The death walk posts asynchronously on the child's CPU; poll for it.
    let payload = poll_event(eq)?;
    let expected = u64::from(CORR_LIVE) << 32; // clean exit, reason 0
    if payload != expected
    {
        return Err("death_notification_late_bind: bind-before-start got wrong payload");
    }
    if event_try_recv(eq) != Err(SyscallError::WouldBlock as i64)
    {
        return Err("death_notification_late_bind: bind-before-start delivered more than once");
    }

    cap_delete(eq).ok();
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    Ok(())
}

/// Poll `cap_info(CAP_INFO_THREAD_STATE)` until the thread reports `Exited`.
fn wait_until_exited(thread_cap: u32) -> TestResult
{
    let mut polls = 0;
    loop
    {
        let packed = cap_info(thread_cap, CAP_INFO_THREAD_STATE)
            .map_err(|_| "death_notification_late_bind: cap_info(THREAD_STATE) failed")?;
        // cast_possible_truncation: the kernel packs an 8-bit state code in the
        // high word and a 32-bit exit reason in the low word.
        #[allow(clippy::cast_possible_truncation)]
        let state = (packed >> 32) as u32;
        if state == THREAD_STATE_EXITED
        {
            return Ok(());
        }
        polls += 1;
        if polls >= MAX_POLLS
        {
            return Err("death_notification_late_bind: child never reached Exited");
        }
        thread_sleep(1).ok();
    }
}

/// Bounded poll for a death event the child posts asynchronously on its own CPU.
fn poll_event(eq: u32) -> Result<u64, &'static str>
{
    let mut polls = 0;
    loop
    {
        if let Ok(payload) = event_try_recv(eq)
        {
            return Ok(payload);
        }
        polls += 1;
        if polls >= MAX_POLLS
        {
            return Err("death_notification_late_bind: death event never arrived");
        }
        thread_sleep(1).ok();
    }
}

/// Child: exit immediately and cleanly (exit reason `0`), no observer bound.
fn clean_exit_child(_arg: u64) -> !
{
    thread_exit()
}

/// Child: store to an unmapped address, killed by the kernel with exit reason
/// `EXIT_FAULT_BASE + <vector>`. The trailing loop only satisfies `-> !`.
fn fault_child(_arg: u64) -> !
{
    let p = WILD_VA as *mut u64;
    // SAFETY: deliberately faulting — WILD_VA is unmapped, so this store raises
    // a page fault the kernel resolves by terminating this thread.
    unsafe {
        p.write_volatile(0xDEAD_BEEF);
    }
    loop
    {
        core::hint::spin_loop();
    }
}
