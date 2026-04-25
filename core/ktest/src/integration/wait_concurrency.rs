// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/wait_concurrency.rs

//! Integration: wait set with concurrent signal and event queue sources.
//!
//! Registers two sources in one wait set — a signal (token 1) and an event
//! queue (token 2) — and verifies that the correct token is returned under
//! three distinct conditions:
//!
//!   A. Queue has a pre-posted entry → `wait_set_wait` returns immediately with token 2.
//!   B. A child thread fires the signal while we block → returns token 1.
//!   C. Signal removed; queue posted again → returns token 2 (only member remaining).
//!
//! This tests that:
//!   - The wait set correctly identifies which source woke it.
//!   - Blocking wake-up via a child thread works end-to-end.
//!   - `wait_set_remove` prevents the removed source from waking the set.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, event_post,
    event_queue_create, event_recv, signal_send, signal_wait, thread_configure, thread_exit,
    thread_start, wait_set_add, wait_set_create, wait_set_remove, wait_set_wait,
};

use crate::{ChildStack, TestContext, TestResult};

const RIGHTS_SIGNAL: u64 = 1 << 7; // SIGNAL right only.

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let ws =
        wait_set_create().map_err(|_| "integration::wait_concurrency: wait_set_create failed")?;
    let sig = cap_create_signal()
        .map_err(|_| "integration::wait_concurrency: cap_create_signal failed")?;
    let eq = event_queue_create(4)
        .map_err(|_| "integration::wait_concurrency: event_queue_create failed")?;

    wait_set_add(ws, sig, 1)
        .map_err(|_| "integration::wait_concurrency: wait_set_add(sig) failed")?;
    wait_set_add(ws, eq, 2)
        .map_err(|_| "integration::wait_concurrency: wait_set_add(eq) failed")?;

    // ── Part A: Queue pre-posted — immediate wake. ────────────────────────────
    event_post(eq, 0xEE)
        .map_err(|_| "integration::wait_concurrency: event_post (part A) failed")?;

    let tok_a = wait_set_wait(ws)
        .map_err(|_| "integration::wait_concurrency: wait_set_wait (part A) failed")?;
    if tok_a != 2
    {
        return Err(
            "integration::wait_concurrency: part A returned wrong token (expected 2 for queue)",
        );
    }
    event_recv(eq)
        .map_err(|_| "integration::wait_concurrency: event_recv (drain part A) failed")?;

    // ── Part B: Child fires signal — blocking wake. ───────────────────────────
    let cs = cap_create_cspace(16)
        .map_err(|_| "integration::wait_concurrency: cap_create_cspace failed")?;
    let child_sig = cap_copy(sig, cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::wait_concurrency: cap_copy sig failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "integration::wait_concurrency: cap_create_thread failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    thread_configure(
        th,
        sender_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "integration::wait_concurrency: thread_configure failed")?;
    thread_start(th).map_err(|_| "integration::wait_concurrency: thread_start failed")?;

    // Block until the child fires the signal.
    let tok_b = wait_set_wait(ws)
        .map_err(|_| "integration::wait_concurrency: wait_set_wait (part B) failed")?;
    if tok_b != 1
    {
        return Err(
            "integration::wait_concurrency: part B returned wrong token (expected 1 for signal)",
        );
    }
    // Drain the signal bits before proceeding.
    let bits = signal_wait(sig)
        .map_err(|_| "integration::wait_concurrency: signal_wait (drain part B) failed")?;
    if bits != 0xBEEF
    {
        return Err("integration::wait_concurrency: wrong signal bits in part B (expected 0xBEEF)");
    }

    // ── Part C: Remove signal; queue fires — only remaining member. ───────────
    wait_set_remove(ws, sig)
        .map_err(|_| "integration::wait_concurrency: wait_set_remove(sig) failed")?;

    event_post(eq, 0xFF)
        .map_err(|_| "integration::wait_concurrency: event_post (part C) failed")?;

    let tok_c = wait_set_wait(ws)
        .map_err(|_| "integration::wait_concurrency: wait_set_wait (part C) failed")?;
    if tok_c != 2
    {
        return Err(
            "integration::wait_concurrency: part C returned wrong token after signal removed (expected 2)",
        );
    }
    event_recv(eq)
        .map_err(|_| "integration::wait_concurrency: event_recv (drain part C) failed")?;

    // Cleanup.
    cap_delete(eq).ok();
    cap_delete(sig).ok();
    cap_delete(ws).ok();
    cap_delete(cs).ok();
    Ok(())
}

// cast_possible_truncation: sig_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn sender_entry(sig_slot: u64) -> !
{
    signal_send(sig_slot as u32, 0xBEEF).ok();
    thread_exit()
}
