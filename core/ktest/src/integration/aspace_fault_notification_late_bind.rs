// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/aspace_fault_notification_late_bind.rs

//! Integration: an address-space terminal-fault observer bound *after* a thread
//! in that space already faulted still receives the retained fault reason.
//!
//! The address-space analogue of `death_notification_late_bind`. When a thread
//! terminal-faults, `post_aspace_death_notification` records the reason on the
//! `AddressSpace`, and `sys_aspace_bind_notification` serialises on the space's
//! `death_lock`: a bind onto an already-faulted space delivers the retained
//! reason instead of dropping it — closing the bind-after-fault window for an
//! observer bound after the space was running.
//!
//! Isolation: the faulting thread runs in a *dedicated* address space (not the
//! test's), so recording its terminal fault never touches shared state. The
//! thread is given an unmapped entry PC, so it terminal-faults on its first
//! instruction fetch with no observer bound and no user code to map.

use syscall::{
    aspace_bind_notification, cap_create_aspace, cap_create_cspace, cap_create_thread, cap_delete,
    cap_info, event_queue_create, event_try_recv, thread_configure, thread_sleep, thread_start,
};
use syscall_abi::{CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, SyscallError, THREAD_STATE_EXITED};

use crate::{TestContext, TestResult};

/// Unmapped canonical user-half VA used as the doomed thread's entry PC; the
/// first instruction fetch faults. Distinct from the other fault tests' VAs.
const UNMAPPED_ENTRY: u64 = 0x7000_0000_0000;
/// Unmapped stack pointer — never reached (the entry fetch faults first).
const UNMAPPED_STACK: u64 = 0x7000_0000_8000;

/// Distinct, non-zero correlator so a dropped/misrouted event surfaces as a
/// wrong high word rather than a coincidental zero.
const CORR: u32 = 0x4444;

/// Poll bound: ~2 s at 1 ms/poll before declaring the thread never faulted.
const MAX_POLLS: u32 = 2000;

pub fn run(ctx: &TestContext) -> TestResult
{
    // Dedicated address space + cspace + thread, so the recorded terminal fault
    // is isolated from the test's own address space.
    let aspace = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "aspace_fault_notification_late_bind: cap_create_aspace failed")?;
    let cspace = cap_create_cspace(ctx.memory_base, 0, 4, 16)
        .map_err(|_| "aspace_fault_notification_late_bind: cap_create_cspace failed")?;
    let thread = cap_create_thread(ctx.memory_base, aspace, cspace)
        .map_err(|_| "aspace_fault_notification_late_bind: cap_create_thread failed")?;

    // Entry PC is unmapped: the thread terminal-faults on its first instruction
    // fetch (no fault handler bound) with no aspace observer bound yet.
    thread_configure(thread, UNMAPPED_ENTRY, UNMAPPED_STACK, 0)
        .map_err(|_| "aspace_fault_notification_late_bind: thread_configure failed")?;
    thread_start(thread).map_err(|_| "aspace_fault_notification_late_bind: thread_start failed")?;

    // Poll until the thread is Exited; capture the kernel-recorded fault reason.
    let mut polls = 0;
    let fault_reason = loop
    {
        let packed = cap_info(thread, CAP_INFO_THREAD_STATE)
            .map_err(|_| "aspace_fault_notification_late_bind: cap_info(THREAD_STATE) failed")?;
        // cast_possible_truncation: 8-bit state in the high word, 32-bit reason low.
        #[allow(clippy::cast_possible_truncation)]
        let state = (packed >> 32) as u32;
        if state == THREAD_STATE_EXITED
        {
            break packed & 0xFFFF_FFFF;
        }
        polls += 1;
        if polls >= MAX_POLLS
        {
            return Err("aspace_fault_notification_late_bind: thread never faulted/exited");
        }
        thread_sleep(1).ok();
    };
    // It must be a real terminal fault, not a clean exit (reason 0).
    if fault_reason < EXIT_FAULT_BASE
    {
        return Err("aspace_fault_notification_late_bind: thread did not terminal-fault");
    }

    // Bind an aspace observer AFTER the fault; the kernel delivers the retained
    // reason synchronously inside the bind syscall.
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "aspace_fault_notification_late_bind: event_queue_create failed")?;
    aspace_bind_notification(aspace, eq, CORR)
        .map_err(|_| "aspace_fault_notification_late_bind: bind onto faulted aspace failed")?;

    let payload = event_try_recv(eq).map_err(|_| {
        "aspace_fault_notification_late_bind: no event delivered to late-bound observer (dropped)"
    })?;
    let expected = (u64::from(CORR) << 32) | fault_reason;
    if payload != expected
    {
        return Err("aspace_fault_notification_late_bind: late-bound observer got wrong payload");
    }
    // Retained delivery must post exactly once.
    if event_try_recv(eq) != Err(SyscallError::WouldBlock as i64)
    {
        return Err(
            "aspace_fault_notification_late_bind: retained reason delivered more than once",
        );
    }

    cap_delete(eq).ok();
    cap_delete(thread).ok();
    cap_delete(cspace).ok();
    cap_delete(aspace).ok();
    Ok(())
}
