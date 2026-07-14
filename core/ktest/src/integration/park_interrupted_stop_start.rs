// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/park_interrupted_stop_start.rs

//! Integration: a thread stopped while parked in any non-call blocking
//! syscall and then restarted returns `Interrupted` — never a stale wake
//! deposit surfaced as success (#363).
//!
//! `cancel_ipc_block` stamps the park episode `INTERRUPTED` at each arm's
//! exclusive claim; the restarted thread's resume consumes the stamp instead
//! of reading `wakeup_value`/`ipc_msg` unconditionally. One phase per parking
//! surface:
//!
//!   1. **`notification_wait`** — pre-#363 a cancelled wait surfaced a 0-bits
//!      "success". Includes a post-restart sanity wait proving the cancel left
//!      the waiter slot and observer flag consistent (a genuine send still
//!      delivers).
//!   2. **`notification_wait_timeout`** — exercises the sleep-list claim
//!      gating (the cancelled timed wait must not surface a timeout).
//!   3. **`event_recv`** (indefinite) — stale payload surface.
//!   4. **`ipc_recv`** — pre-#363 the restarted server published a stale
//!      `ipc_msg` into its userspace buffer and returned success.
//!   5. **`wait_set_wait`** — stale badge surface.
//!   6. **`thread_sleep`** — pre-#363 a cancelled sleep returned `Ok`.
//!
//! In each phase the controller stops the parked child, restarts it, and the
//! child itself asserts the `Interrupted` contract — raising an OK bit on the
//! contract or a BAD bit on any other result.
//!
//! Runs on a single CPU (the children are timer-preempted peers).

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_endpoint, cap_create_notification, cap_delete,
    event_queue_create, event_recv, ipc_buffer_set, notification_send, notification_wait,
    notification_wait_timeout, thread_exit, thread_sleep, thread_start, thread_stop, wait_set_add,
    wait_set_create, wait_set_wait,
};
use syscall_abi::{RIGHTS_RECEIVE, SyscallError};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification signal right (bit 7) and wait right (bit 8).
const RIGHTS_SIGNAL: u64 = 1 << 7;
const RIGHTS_WAIT: u64 = 1 << 8;

/// Phase 1 (`notification_wait`) bits; OK2/BAD2 carry the post-restart sanity
/// verdict (a genuine send after the cancelled wait still delivers).
const BIT_N_READY: u64 = 1 << 0;
const BIT_N_OK: u64 = 1 << 1;
const BIT_N_BAD: u64 = 1 << 2;
const BIT_N_OK2: u64 = 1 << 3;
const BIT_N_BAD2: u64 = 1 << 4;

/// Phase 2 (`notification_wait_timeout`) bits.
const BIT_T_READY: u64 = 1 << 5;
const BIT_T_OK: u64 = 1 << 6;
const BIT_T_BAD: u64 = 1 << 7;

/// Phase 3 (`event_recv`) bits.
const BIT_E_READY: u64 = 1 << 8;
const BIT_E_OK: u64 = 1 << 9;
const BIT_E_BAD: u64 = 1 << 10;

/// Phase 4 (`ipc_recv`) bits.
const BIT_R_READY: u64 = 1 << 11;
const BIT_R_OK: u64 = 1 << 12;
const BIT_R_BAD: u64 = 1 << 13;

/// Phase 5 (`wait_set_wait`) bits.
const BIT_W_READY: u64 = 1 << 14;
const BIT_W_OK: u64 = 1 << 15;
const BIT_W_BAD: u64 = 1 << 16;

/// Phase 6 (`thread_sleep`) bits.
const BIT_S_READY: u64 = 1 << 17;
const BIT_S_OK: u64 = 1 << 18;
const BIT_S_BAD: u64 = 1 << 19;

/// Bits the phase-1 sanity send must deliver verbatim.
const SANITY_BITS: u64 = 0x55;

/// Parks that must never elapse on their own (the stop is the only exit).
const PARK_FOREVER_MS: u64 = 600_000;

/// Wall-clock settle after a child's READY signal so it provably reaches
/// its park before the stop lands (see `drive`). A stop that lands pre-park
/// stops a Running thread instead — the restart would then park with no
/// canceller and hang to the watchdog, so generous slack is cheap insurance.
const SETTLE_SLEEP_MS: u64 = 20;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// A page-aligned 4 KiB IPC buffer page for the `ipc_recv` phase's child.
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);

// SAFETY: used only by phase 4's single child (phases run sequentially).
static mut CHILD_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

// too_many_lines: six flat sequential phases, one per parking surface; each
// is independent and short, and splitting would scatter the shared
// done/acc bit plumbing.
#[allow(clippy::too_many_lines)]
pub fn run(ctx: &TestContext) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::park_interrupted_stop_start: create done failed")?;
    let mut acc = 0u64;

    // ── Phase 1: notification_wait, plus post-restart delivery sanity. ──────
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::park_interrupted_stop_start: create sig failed")?;
    let child = spawn_phase(ctx, done, sig, RIGHTS_WAIT, notif_entry)?;
    drive(
        child.th,
        done,
        &mut acc,
        BIT_N_READY,
        BIT_N_OK,
        BIT_N_BAD,
        "integration::park_interrupted_stop_start: cancelled notification_wait returned a \
         non-Interrupted result (stale 0-bits success — #363)",
    )?;
    // The child is now waiting again on `sig`; a genuine send must deliver.
    notification_send(sig, SANITY_BITS)
        .map_err(|_| "integration::park_interrupted_stop_start: sanity send failed")?;
    verdict(
        done,
        &mut acc,
        BIT_N_OK2 | BIT_N_BAD2,
        BIT_N_BAD2,
        "integration::park_interrupted_stop_start: post-cancel notification delivery broken \
         (cancel corrupted the waiter slot / observer flag)",
    )?;
    reap(&child)?;
    cap_delete(sig).map_err(|_| "integration::park_interrupted_stop_start: del sig failed")?;

    // ── Phase 2: notification_wait_timeout (sleep-list claim gating). ───────
    let sigt = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::park_interrupted_stop_start: create sigt failed")?;
    let child = spawn_phase(ctx, done, sigt, RIGHTS_WAIT, notif_timeout_entry)?;
    drive(
        child.th,
        done,
        &mut acc,
        BIT_T_READY,
        BIT_T_OK,
        BIT_T_BAD,
        "integration::park_interrupted_stop_start: cancelled timed notification_wait returned \
         a non-Interrupted result (stale success or fabricated timeout — #363)",
    )?;
    reap(&child)?;
    cap_delete(sigt).map_err(|_| "integration::park_interrupted_stop_start: del sigt failed")?;

    // ── Phase 3: event_recv (indefinite block). ─────────────────────────────
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "integration::park_interrupted_stop_start: create eq failed")?;
    let child = spawn_phase(ctx, done, eq, RIGHTS_ALL, event_entry)?;
    drive(
        child.th,
        done,
        &mut acc,
        BIT_E_READY,
        BIT_E_OK,
        BIT_E_BAD,
        "integration::park_interrupted_stop_start: cancelled event_recv returned a \
         non-Interrupted result (stale payload surfaced — #363)",
    )?;
    reap(&child)?;
    cap_delete(eq).map_err(|_| "integration::park_interrupted_stop_start: del eq failed")?;

    // ── Phase 4: ipc_recv (empty endpoint, no caller ever arrives). ─────────
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::park_interrupted_stop_start: create ep failed")?;
    let child = spawn_phase(ctx, done, ep, RIGHTS_RECEIVE, recv_entry)?;
    drive(
        child.th,
        done,
        &mut acc,
        BIT_R_READY,
        BIT_R_OK,
        BIT_R_BAD,
        "integration::park_interrupted_stop_start: cancelled ipc_recv returned a \
         non-Interrupted result (stale ipc_msg published to userspace — #363)",
    )?;
    reap(&child)?;
    cap_delete(ep).map_err(|_| "integration::park_interrupted_stop_start: del ep failed")?;

    // ── Phase 5: wait_set_wait (member registered, never ready). ────────────
    let ws = wait_set_create(ctx.memory_base)
        .map_err(|_| "integration::park_interrupted_stop_start: create ws failed")?;
    let member = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::park_interrupted_stop_start: create member failed")?;
    wait_set_add(ws, member, 0xB1D)
        .map_err(|_| "integration::park_interrupted_stop_start: wait_set_add failed")?;
    let child = spawn_phase(ctx, done, ws, RIGHTS_ALL, waitset_entry)?;
    drive(
        child.th,
        done,
        &mut acc,
        BIT_W_READY,
        BIT_W_OK,
        BIT_W_BAD,
        "integration::park_interrupted_stop_start: cancelled wait_set_wait returned a \
         non-Interrupted result (stale badge surfaced — #363)",
    )?;
    reap(&child)?;
    cap_delete(ws).map_err(|_| "integration::park_interrupted_stop_start: del ws failed")?;
    cap_delete(member)
        .map_err(|_| "integration::park_interrupted_stop_start: del member failed")?;

    // ── Phase 6: thread_sleep. ──────────────────────────────────────────────
    let child = spawn_phase(ctx, done, 0, 0, sleep_entry)?;
    drive(
        child.th,
        done,
        &mut acc,
        BIT_S_READY,
        BIT_S_OK,
        BIT_S_BAD,
        "integration::park_interrupted_stop_start: cancelled thread_sleep returned a \
         non-Interrupted result (truncated sleep reported as success — #363)",
    )?;
    reap(&child)?;

    cap_delete(done).map_err(|_| "integration::park_interrupted_stop_start: del done failed")?;
    Ok(())
}

/// Spawn one phase's child: copy the phase's source cap (skipped when
/// `source == 0`) and the `done` notification into its `CSpace`, then start it
/// on the shared stack with `source[15:0] | done[31:16]` as its argument.
fn spawn_phase(
    ctx: &TestContext,
    done: u32,
    source: u32,
    source_rights: u64,
    entry: fn(u64) -> !,
) -> Result<spawn::SpawnedChild, &'static str>
{
    let child = spawn::new_child(ctx)
        .map_err(|_| "integration::park_interrupted_stop_start: spawn child failed")?;
    let c_source = if source == 0
    {
        0
    }
    else
    {
        cap_copy(source, child.cs, source_rights)
            .map_err(|_| "integration::park_interrupted_stop_start: cap_copy source failed")?
    };
    let c_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::park_interrupted_stop_start: cap_copy done failed")?;
    let arg = u64::from(c_source) | (u64::from(c_done) << 16);
    // Phases run sequentially and each child is reaped before the next spawn,
    // so the shared stack has exactly one live user.
    let stack = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    spawn::configure_and_start(&child, entry, stack, arg)
        .map_err(|_| "integration::park_interrupted_stop_start: start child failed")?;
    Ok(child)
}

/// One phase's stop/restart sequence: wait for the child's READY signal, let
/// it provably reach its park, stop + restart it, then take its verdict.
fn drive(
    th: u32,
    done: u32,
    acc: &mut u64,
    ready: u64,
    ok: u64,
    bad: u64,
    msg: &'static str,
) -> Result<(), &'static str>
{
    wait_for(done, acc, ready)?;
    // Give the child wall-clock time to reach its park: a yield would not
    // cede the CPU to a lower-priority child, and under TCG the child's
    // vCPU thread can be host-descheduled for milliseconds regardless.
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    thread_stop(th).map_err(|_| "integration::park_interrupted_stop_start: thread_stop failed")?;
    thread_start(th)
        .map_err(|_| "integration::park_interrupted_stop_start: thread_start failed")?;
    verdict(done, acc, ok | bad, bad, msg)
}

/// Wait until any bit of `mask` arrives; fail with `msg` if `bad` is among
/// the accumulated bits.
fn verdict(
    done: u32,
    acc: &mut u64,
    mask: u64,
    bad: u64,
    msg: &'static str,
) -> Result<(), &'static str>
{
    wait_for(done, acc, mask)?;
    if *acc & bad != 0
    {
        return Err(msg);
    }
    Ok(())
}

/// Reap a phase's child (thread + `CSpace`).
fn reap(child: &spawn::SpawnedChild) -> Result<(), &'static str>
{
    cap_delete(child.th)
        .map_err(|_| "integration::park_interrupted_stop_start: reap child thread failed")?;
    cap_delete(child.cs)
        .map_err(|_| "integration::park_interrupted_stop_start: reap child cspace failed")?;
    Ok(())
}

/// Accumulate `done` bits into `acc` until any bit of `mask` is present.
fn wait_for(done: u32, acc: &mut u64, mask: u64) -> Result<(), &'static str>
{
    while *acc & mask == 0
    {
        let bits = notification_wait(done)
            .map_err(|_| "integration::park_interrupted_stop_start: notification_wait failed")?;
        *acc |= bits;
    }
    Ok(())
}

/// `true` iff the wrapper error is the kernel's `Interrupted`.
fn is_interrupted(e: i64) -> bool
{
    e == SyscallError::Interrupted as i64
}

// cast_possible_truncation: packed fields are cap slot indices < 2^16.
#[allow(clippy::cast_possible_truncation)]
fn unpack(arg: u64) -> (u32, u32)
{
    ((arg & 0xFFFF) as u32, ((arg >> 16) & 0xFFFF) as u32)
}

/// Phase 1 child: cancelled wait must return `Interrupted`; then a second,
/// genuine wait must deliver `SANITY_BITS` verbatim.
fn notif_entry(arg: u64) -> !
{
    let (sig, done) = unpack(arg);
    notification_send(done, BIT_N_READY).ok();
    let bit = match notification_wait(sig)
    {
        Err(e) if is_interrupted(e) => BIT_N_OK,
        _ => BIT_N_BAD,
    };
    notification_send(done, bit).ok();
    if bit == BIT_N_OK
    {
        let bit2 = match notification_wait(sig)
        {
            Ok(bits) if bits == SANITY_BITS => BIT_N_OK2,
            _ => BIT_N_BAD2,
        };
        notification_send(done, bit2).ok();
    }
    thread_exit()
}

/// Phase 2 child: the cancelled timed wait must return `Interrupted` — not a
/// 0-bits timeout, not a success.
fn notif_timeout_entry(arg: u64) -> !
{
    let (sig, done) = unpack(arg);
    notification_send(done, BIT_T_READY).ok();
    let bit = match notification_wait_timeout(sig, PARK_FOREVER_MS)
    {
        Err(e) if is_interrupted(e) => BIT_T_OK,
        _ => BIT_T_BAD,
    };
    notification_send(done, bit).ok();
    thread_exit()
}

/// Phase 3 child: cancelled blocking `event_recv` must return `Interrupted`.
fn event_entry(arg: u64) -> !
{
    let (eq, done) = unpack(arg);
    notification_send(done, BIT_E_READY).ok();
    let bit = match event_recv(eq)
    {
        Err(e) if is_interrupted(e) => BIT_E_OK,
        _ => BIT_E_BAD,
    };
    notification_send(done, bit).ok();
    thread_exit()
}

/// Phase 4 child: cancelled `ipc_recv` must return `Interrupted` (pre-#363 it
/// returned success and published a stale `ipc_msg` into the buffer).
fn recv_entry(arg: u64) -> !
{
    let (ep, done) = unpack(arg);
    // SAFETY: sole live user of CHILD_IPC_BUF (phases run sequentially).
    let buf = core::ptr::addr_of_mut!(CHILD_IPC_BUF).cast::<u64>();
    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }
    notification_send(done, BIT_R_READY).ok();
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let bit = match unsafe { ipc::ipc_recv(ep, buf) }
    {
        Err(e) if is_interrupted(e) => BIT_R_OK,
        _ => BIT_R_BAD,
    };
    notification_send(done, bit).ok();
    thread_exit()
}

/// Phase 5 child: cancelled `wait_set_wait` must return `Interrupted`.
fn waitset_entry(arg: u64) -> !
{
    let (ws, done) = unpack(arg);
    notification_send(done, BIT_W_READY).ok();
    let bit = match wait_set_wait(ws)
    {
        Err(e) if is_interrupted(e) => BIT_W_OK,
        _ => BIT_W_BAD,
    };
    notification_send(done, bit).ok();
    thread_exit()
}

/// Phase 6 child: cancelled `thread_sleep` must return `Interrupted`.
fn sleep_entry(arg: u64) -> !
{
    let (_, done) = unpack(arg);
    notification_send(done, BIT_S_READY).ok();
    let bit = match thread_sleep(PARK_FOREVER_MS)
    {
        Err(e) if is_interrupted(e) => BIT_S_OK,
        _ => BIT_S_BAD,
    };
    notification_send(done, bit).ok();
    thread_exit()
}
