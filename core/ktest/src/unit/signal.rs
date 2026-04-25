// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/signal.rs

//! Tier 1 tests for signal syscalls.
//!
//! Covers: `SYS_SIGNAL_SEND`, `SYS_SIGNAL_WAIT`.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, cap_derive,
    signal_send, signal_wait, thread_configure, thread_exit, thread_start,
};
use syscall_abi::SyscallError;

use crate::{ChildStack, TestContext, TestResult};

// SIGNAL right only — no WAIT. Child threads only need to send.
const RIGHTS_SIGNAL: u64 = 1 << 7;
// WAIT right only — no SIGNAL. For testing insufficient rights on send.
const RIGHTS_WAIT: u64 = 1 << 8;

// Child stack for blocking-wait test.
static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

// ── SYS_SIGNAL_SEND ───────────────────────────────────────────────────────────

/// `signal_send` ORs bits into a signal object. Non-blocking.
pub fn send(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for send test failed")?;
    signal_send(sig, 0xABCD).map_err(|_| "signal_send failed")?;
    // Drain the bits so subsequent tests are not surprised by a pre-set signal.
    signal_wait(sig).map_err(|_| "signal_wait after send failed")?;
    cap_delete(sig).map_err(|_| "cap_delete after send test failed")?;
    Ok(())
}

// ── SYS_SIGNAL_WAIT (blocking) ────────────────────────────────────────────────

/// `signal_wait` blocks until a child sends bits; returns the sent bitmask.
pub fn send_wait_blocking(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for blocking-wait test failed")?;

    // Create a child CSpace and copy the signal cap (SIGNAL right only).
    let cs = cap_create_cspace(16).map_err(|_| "create_cspace for blocking-wait test failed")?;
    let child_sig =
        cap_copy(sig, cs, RIGHTS_SIGNAL).map_err(|_| "cap_copy signal into child CSpace failed")?;

    let child_th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for blocking-wait test failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    thread_configure(
        child_th,
        sender_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "thread_configure for blocking-wait test failed")?;
    thread_start(child_th).map_err(|_| "thread_start for blocking-wait test failed")?;

    // Block until the child sends.
    let bits = signal_wait(sig).map_err(|_| "signal_wait (blocking) failed")?;
    if bits != 0xBEEF
    {
        return Err("signal_wait returned unexpected bits (expected 0xBEEF)");
    }

    cap_delete(sig).map_err(|_| "cap_delete sig after blocking-wait test failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after blocking-wait test failed")?;
    Ok(())
}

/// `signal_wait` returns immediately when bits are already set.
pub fn send_before_wait_immediate(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for immediate-wait test failed")?;
    signal_send(sig, 0x1234).map_err(|_| "signal_send failed")?;
    // Bits are already set — signal_wait must return without blocking.
    let bits = signal_wait(sig).map_err(|_| "signal_wait (immediate) failed")?;
    if bits != 0x1234
    {
        return Err("signal_wait returned unexpected bits (expected 0x1234)");
    }
    cap_delete(sig).map_err(|_| "cap_delete after immediate-wait test failed")?;
    Ok(())
}

// ── SYS_SIGNAL_WAIT negative ──────────────────────────────────────────────────

/// Calling `signal_wait` on a cap with SIGNAL-only rights (no WAIT) must fail
/// with `InsufficientRights`.
pub fn wait_insufficient_rights(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for rights test failed")?;
    // Derive a cap with SIGNAL (send) right only — no WAIT (receive) right.
    let send_only =
        cap_derive(sig, RIGHTS_SIGNAL).map_err(|_| "cap_derive for rights test failed")?;

    // Pre-set bits so the kernel would not block — we want to test the rights
    // check, not the blocking path.
    signal_send(sig, 0x1).map_err(|_| "signal_send for rights test failed")?;

    let err = signal_wait(send_only);
    if err != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("signal_wait on SIGNAL-only cap did not return InsufficientRights");
    }

    // Drain the pre-set bits via the full cap.
    signal_wait(sig).ok();
    cap_delete(send_only).map_err(|_| "cap_delete send_only failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after rights test failed")?;
    Ok(())
}

// ── SYS_SIGNAL_SEND (multiple sends) ─────────────────────────────────────────

/// Multiple `signal_send` calls before any `signal_wait` accumulate all bits.
///
/// Sends 0x1, 0x2, and 0x4 without waiting between them; `signal_wait` must
/// return the OR of all three (0x7), not just the last value.
pub fn multiple_sends_before_wait_accumulate_bits(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for multi-send test failed")?;

    signal_send(sig, 0x1).map_err(|_| "signal_send(0x1) failed")?;
    signal_send(sig, 0x2).map_err(|_| "signal_send(0x2) failed")?;
    signal_send(sig, 0x4).map_err(|_| "signal_send(0x4) failed")?;

    let bits = signal_wait(sig).map_err(|_| "signal_wait after multi-send failed")?;
    if bits != 0x7
    {
        return Err("signal_wait did not return accumulated bits (expected 0x7)");
    }

    cap_delete(sig).map_err(|_| "cap_delete after multi-send test failed")?;
    Ok(())
}

// ── SYS_SIGNAL_SEND with zero bits ────────────────────────────────────────────

/// `signal_send` with zero bits returns an error; signal state is unaffected.
///
/// The kernel rejects zero-bit sends (no-op sends are not valid). Verifies:
/// 1. `signal_send(sig, 0)` returns an error.
/// 2. A subsequent non-zero send arrives intact (error did not corrupt state).
pub fn send_zero_bits_is_noop(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for zero-send test failed")?;

    // Kernel rejects zero-bit send.
    let zero_err = signal_send(sig, 0);
    if zero_err.is_ok()
    {
        return Err("signal_send(0) should fail (kernel rejects zero-bit send)");
    }

    // State must be unaffected: a subsequent non-zero send must arrive intact.
    signal_send(sig, 0xAB).map_err(|_| "signal_send(0xAB) after zero-send failed")?;
    let bits = signal_wait(sig).map_err(|_| "signal_wait after zero-send failed")?;
    if bits != 0xAB
    {
        return Err("signal bits incorrect after zero-send error (expected 0xAB)");
    }

    cap_delete(sig).map_err(|_| "cap_delete after zero-send test failed")?;
    Ok(())
}

// ── SYS_SIGNAL_SEND (insufficient rights) ────────────────────────────────────

/// `signal_send` on a cap with only WAIT right (no SIGNAL) must fail.
pub fn send_insufficient_rights(_ctx: &TestContext) -> TestResult
{
    let sig =
        cap_create_signal().map_err(|_| "create_signal for send_insufficient_rights failed")?;

    // Derive a cap with WAIT right only — no SIGNAL (send) right.
    let wait_only = cap_derive(sig, RIGHTS_WAIT)
        .map_err(|_| "cap_derive for send_insufficient_rights failed")?;

    let err = signal_send(wait_only, 0x1);
    if err != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("signal_send on WAIT-only cap did not return InsufficientRights");
    }

    cap_delete(wait_only).map_err(|_| "cap_delete wait_only failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after send_insufficient_rights failed")?;
    Ok(())
}

// ── Child thread entry ────────────────────────────────────────────────────────

/// Child thread: sends 0xBEEF on `sig_slot` then exits.
// cast_possible_truncation: sig_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn sender_entry(sig_slot: u64) -> !
{
    signal_send(sig_slot as u32, 0xBEEF).ok();
    thread_exit()
}
