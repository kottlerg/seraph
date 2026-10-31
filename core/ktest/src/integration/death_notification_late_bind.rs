// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/death_notification_late_bind.rs

//! Integration: a death observer bound *after* the thread has already died
//! still receives the retained exit reason.
//!
//! A bind onto an already-`Exited` thread delivers the retained exit reason to
//! the newly bound `EventQueue` (see `core/kernel/docs/scheduling-internals.md`
//! § Process-Death and Parked-Thread Protocol and `core/kernel/docs/syscalls.md`
//! § `SYS_THREAD_BIND_NOTIFICATION` (47)). This is the bind-after-start window
//! a supervisor (svcmgr) hits when it binds a service init had already started
//! (#106 Window 2).
//!
//! Four scenarios, all on the real exit/fault paths:
//!   1. A child exits cleanly with no observer bound; a later bind delivers
//!      the retained clean reason (`0`).
//!   2. A child faults with no observer bound; a later bind delivers the
//!      retained fault reason (`EXIT_FAULT_BASE + <vector>`).
//!   3. Negative control: an observer bound *before* start still fires
//!      exactly once — guarding the append path against a double-post
//!      from the retained-delivery branch.
//!   4. A child voluntarily exits via `SYS_PROCESS_EXIT(code)` with no observer
//!      bound; a later bind delivers the retained `encode_exit_code(code)`,
//!      proving the process-exit syscall records the encoded code on the thread.

use syscall::{
    DeathEvent, cap_delete, event_queue_create, event_try_recv, event_try_recv_death, process_exit,
    thread_bind_notification, thread_exit, thread_sleep,
};
use syscall_abi::{EXIT_FAULT_BASE, SyscallError, encode_exit_code};

use crate::{ChildStack, TestContext, TestResult};

/// A user VA no test maps — canonical in every paging mode (below the 2^38
/// Sv39 user half), distinct from `fault_kills_thread`'s `WILD_VA` so the
/// two never share a mapping.
const WILD_VA: u64 = 0x3E_6000_0000;

/// Distinct, non-zero correlators so a dropped or misrouted event surfaces as
/// a wrong correlator rather than a coincidental zero. Each sets bits in both
/// halves, so a kernel that truncated the correlator to 32 bits fails the
/// compare.
const CORR_CLEAN: u64 = 0xC1EA_0000_0000_1111;
const CORR_FAULT: u64 = 0xFA17_0000_0000_2222;
const CORR_LIVE: u64 = 0x11FE_0000_0000_3333;
const CORR_PROC_EXIT: u64 = 0xE417_0000_0000_4444;

/// Voluntary exit code scenario 4's child passes to `process_exit`. Distinct
/// from the correlators and inside the voluntary range so `encode_exit_code`
/// returns it verbatim.
const PROC_EXIT_CODE: u32 = 0x0123;

/// Poll bound, ~2 s at 1 ms/poll, on each wait for a child to reach `Exited`
/// (a mis-classified fault would otherwise loop forever) and on the wait for
/// its death event. Applied through [`crate::scaled_polls`], which
/// stretches it past [`crate::UNSCALED_CPUS`] CPUs, where the child's CPU
/// waits for a host core.
const MAX_POLLS: u32 = 2000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    // Scenario 1: clean exit, bind after death.
    late_bind_after_death(ctx, clean_exit_child, CORR_CLEAN, 0)?;

    // Scenario 2: fault, bind after death.
    late_bind_after_death(
        ctx,
        fault_child,
        CORR_FAULT,
        EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR,
    )?;

    // Scenario 3: negative control — bind before start fires exactly once.
    bind_before_start_fires_once(ctx)?;

    // Scenario 4: voluntary process exit carries the encoded code, bind after death.
    late_bind_after_death(
        ctx,
        proc_exit_child,
        CORR_PROC_EXIT,
        encode_exit_code(PROC_EXIT_CODE),
    )?;

    Ok(())
}

/// Spawn `entry`, wait until it is `Exited` with **no** observer bound, then
/// bind a fresh queue and assert the retained `expected_reason` is delivered
/// exactly once under `correlator`.
fn late_bind_after_death(
    ctx: &TestContext,
    entry: extern "C" fn(u64) -> !,
    correlator: u64,
    expected_reason: u64,
) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "death_notification_late_bind: spawn::new_child failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, entry, stack_top, 0) }
        .map_err(|_| "death_notification_late_bind: configure_and_start failed")?;

    crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;

    // Bind a fresh queue onto the already-dead thread; the kernel delivers the
    // retained reason synchronously inside the bind syscall.
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "death_notification_late_bind: event_queue_create failed")?;
    thread_bind_notification(child.th, eq, correlator)
        .map_err(|_| "death_notification_late_bind: bind onto exited thread failed")?;

    let death = event_try_recv_death(eq).map_err(
        |_| "death_notification_late_bind: no event delivered to late-bound observer (dropped)",
    )?;
    let expected = DeathEvent {
        exit_reason: expected_reason,
        correlator,
    };
    if death != expected
    {
        return Err("death_notification_late_bind: late-bound observer got wrong payload");
    }
    // Retained delivery must post exactly once.
    if event_try_recv(eq) != Err(SyscallError::WouldBlock as i64)
    {
        return Err("death_notification_late_bind: retained reason delivered more than once");
    }

    cap_delete(eq).ok();
    child.delete_thread().ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Bind an observer while the child is still `Created`, then start it; the
/// death walk must post exactly once.
fn bind_before_start_fires_once(ctx: &TestContext) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "death_notification_late_bind: spawn::new_child (control) failed")?;
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "death_notification_late_bind: event_queue_create (control) failed")?;
    // Thread is Created (not started): the append path.
    thread_bind_notification(child.th, eq, CORR_LIVE)
        .map_err(|_| "death_notification_late_bind: bind before start failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, clean_exit_child, stack_top, 0) }
        .map_err(|_| "death_notification_late_bind: configure_and_start (control) failed")?;

    crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;

    // The death walk posts asynchronously on the child's CPU; poll for it.
    let death = poll_event(eq)?;
    // Clean exit: reason 0.
    let expected = DeathEvent {
        exit_reason: 0,
        correlator: CORR_LIVE,
    };
    if death != expected
    {
        return Err("death_notification_late_bind: bind-before-start got wrong payload");
    }
    if event_try_recv(eq) != Err(SyscallError::WouldBlock as i64)
    {
        return Err("death_notification_late_bind: bind-before-start delivered more than once");
    }

    cap_delete(eq).ok();
    child.delete_thread().ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Bounded poll for a death event the child posts asynchronously on its own CPU.
fn poll_event(eq: u32) -> Result<DeathEvent, &'static str>
{
    let bound = crate::scaled_polls(MAX_POLLS);
    let mut polls = 0;
    loop
    {
        if let Ok(death) = event_try_recv_death(eq)
        {
            return Ok(death);
        }
        polls += 1;
        if polls >= bound
        {
            return Err("death_notification_late_bind: death event never arrived");
        }
        thread_sleep(1).ok();
    }
}

/// Child: exit immediately and cleanly (exit reason `0`), no observer bound.
extern "C" fn clean_exit_child(_arg: u64) -> !
{
    thread_exit()
}

/// Child: exit the process voluntarily with `PROC_EXIT_CODE`; the kernel
/// records `encode_exit_code(PROC_EXIT_CODE)` as the thread's exit reason.
extern "C" fn proc_exit_child(_arg: u64) -> !
{
    process_exit(PROC_EXIT_CODE)
}

/// Child: store to an unmapped address, killed by the kernel with exit reason
/// `EXIT_FAULT_BASE + <vector>`. The trailing loop only satisfies `-> !`.
extern "C" fn fault_child(_arg: u64) -> !
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
