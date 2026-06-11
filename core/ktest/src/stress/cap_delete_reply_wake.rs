// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/cap_delete_reply_wake.rs

//! Stress: `cap_delete` of a server that a client is `BlockedOnReply` on MUST
//! wake that client — the dealloc deferred reply-wake *liveness* invariant
//! (issue #351, the cap-delete / dealloc → wake lost-wakeup family).
//!
//! ## The hazard
//!
//! When a client issues `ipc_call` and the server `ipc_recv`s it, the client is
//! `BlockedOnReply` with `blocked_on_object = server TCB` and the server records
//! `reply_tcb = client`. If the server is then torn down without replying,
//! `cap_delete(server)` → `dealloc_object(Thread)` is the sole path that
//! releases the orphaned client: it CAS-claims `reply_tcb`, deposits an
//! `Interrupted` disposition, and *defers* the client's wake past the all-CPU
//! locks region through the gated `enqueue_and_wake` (see
//! `core/kernel/src/cap/object.rs`, the Thread arm's `server_reply_wake`). The
//! server's own `thread_exit` does **not** wake the client — only the dealloc
//! does.
//!
//! If that deferred cross-CPU wake is ever lost — coalesced against a stale
//! live/not-live classification, or enqueued without the target CPU ever
//! observing the reschedule — the client is stranded `BlockedOnReply` forever
//! with nothing armed to recover it. That is the #351 signature: a thread
//! reaches `Exited` inside `SYS_CAP_DELETE`, the wake it owed a blocked waiter
//! is dropped, and every CPU goes idle.
//!
//! ## How this exercises it
//!
//! Each cycle pins the client and server to **different** CPUs, so the dealloc
//! (running on the controller's CPU) and the client's wake-enqueue (targeting
//! the client's pinned CPU) cross cores — the cross-CPU wake path that strands
//! the waiter. The server receives the client (arming `reply_tcb = client`),
//! announces the armed window, then dies without replying. The controller then
//! `cap_delete`s the server, which owes the client an `Interrupted` wake.
//!
//! ## Liveness gate (not just anti-vacuous)
//!
//! Unlike `stop_reply_race` — which races `thread_stop(client)` against the
//! free and so *cannot* require the client to wake (a stopped client stays
//! `Stopped`) — this cell drives **only** the server dealloc. The kernel
//! contract therefore guarantees the client wakes with `Interrupted`, so the
//! controller **requires** `BIT_CLIENT_WOKE` every cycle. A lost wake never
//! arrives: the controller's `notification_wait` blocks, every CPU goes idle,
//! and the softlockup watchdog fires (its registry walk names the stranded
//! `BlockedOnReply` client and the server it is parked on). The hang is raised
//! by the kernel, not by a test assertion — `BIT_SERVER_ARMED` proves the race
//! armed, and `woke_cycles == CYCLES` proves the liveness path actually ran on
//! every cycle rather than passing vacuously.
//!
//! ## Pass criterion
//!
//! SMP-only (skips on `< 2` CPUs — the free and the wake-enqueue must run on
//! different cores to exercise the cross-CPU strand). On a correct kernel the
//! harness boots clean to `[ktest] ALL TESTS PASSED`.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, thread_exit, thread_yield,
};
use syscall_abi::{RIGHTS_RECEIVE, RIGHTS_SEND_GRANT, SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Reply-wake races to run. Higher than `stop_reply_race`'s 300: the lost wake
/// is rarer than the #317 UAF, so give the cross-CPU strand many chances.
const CYCLES: usize = 2000;

/// Notification signal right (bit 7) — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = 1 << 7;

/// `done` bit the server raises once `ipc_recv` has dequeued the client, i.e.
/// once the client is `BlockedOnReply` and the reply-wake is armed.
const BIT_SERVER_ARMED: u64 = 1 << 0;

/// `done` bit the client raises when its `ipc_call` returns `Interrupted` —
/// the wake AND disposition the server's dealloc owed it. **Required** every
/// cycle; a lost wake never sends it.
const BIT_CLIENT_WOKE: u64 = 1 << 1;

/// `done` bit the client raises when its `ipc_call` returns anything OTHER
/// than `Interrupted`: the dealloc wake delivered a wrong disposition (e.g.
/// stale `ipc_msg` bytes surfaced as a successful reply — the #361 clobber).
/// Immediate FAIL with a named error instead of a watchdog hang.
const BIT_CLIENT_BAD: u64 = 1 << 2;

/// Bound on the server's post-recv busy-spin, keeping the server TCB live for a
/// short window after it signals armed so the `cap_delete` lands while the
/// reply binding is on a still-running server (the harder interleaving).
const SERVER_SPIN: u32 = 200;

/// Bound on controller yields used to let the client reach `ipc_call` and park
/// on the endpoint send queue before the server receives it.
const SETTLE_YIELDS: usize = 8;

/// A page-aligned 4 KiB IPC buffer page. The server and client run concurrently
/// on different CPUs and each issues IPC, so they must not share one buffer page
/// (that would be a data race in the *test*). Each gets its own static, reused
/// across sequential cycles: both children are reaped before the next cycle.
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);

// SAFETY: written only by the single server child of the current cycle via its
// own IPC syscalls (kernel-synchronous), never aliased across cycles.
static mut SERVER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

// SAFETY: written only by the single client child of the current cycle via its
// own IPC syscalls (kernel-synchronous), never aliased across cycles.
static mut CLIENT_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::cap_delete_reply_wake: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::cap_delete_reply_wake SKIP (need 2+ CPUs)");
        return Ok(());
    }
    let cpu_mod = u32::try_from(cpus).unwrap_or(1).max(1);

    // Anti-vacuous accumulators: every cycle must arm the reply binding and then
    // observe the client's wake.
    let mut armed_cycles = 0usize;
    let mut woke_cycles = 0usize;

    for cycle in 0..CYCLES
    {
        // CYCLES is a compile-time constant well below u32::MAX; try_from keeps
        // the narrow cast clippy-clean.
        let cycle_u32 = u32::try_from(cycle).unwrap_or(0);
        let server_cpu = cycle_u32 % cpu_mod;
        // Different CPU from the server: the dealloc-free and the client's
        // wake-enqueue must run on different cores to exercise the cross-CPU
        // strand. With cpus >= 2, `(cycle + 1) % cpus != cycle % cpus`.
        let client_cpu = (cycle_u32 + 1) % cpu_mod;

        let ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_create_endpoint failed")?;
        let done = cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_create_notification failed")?;

        // ── Client child: SEND|GRANT on ep, signal on done. ─────────────────
        let client = spawn::new_child(ctx)
            .map_err(|_| "stress::cap_delete_reply_wake: spawn::new_child client failed")?;
        let client_ep = cap_copy(ep, client.cs, RIGHTS_SEND_GRANT)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_copy client ep failed")?;
        let client_done = cap_copy(done, client.cs, RIGHTS_SIGNAL)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_copy client done failed")?;
        // arg packs ep_slot[15:0] | done_slot[31:16]; the child reads its own
        // dedicated IPC buffer address from the static directly.
        let client_arg = u64::from(client_ep) | (u64::from(client_done) << 16);
        // SAFETY: stack index 1 is the client's; sequential cycles never alias.
        let client_stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[1]) });
        spawn::configure_and_start_pinned(
            &client,
            client_entry,
            client_stack,
            client_arg,
            client_cpu,
        )
        .map_err(|_| "stress::cap_delete_reply_wake: start client failed")?;

        // Let the client reach `ipc_call` and park on the endpoint send queue
        // before the server receives it.
        for _ in 0..SETTLE_YIELDS
        {
            let _ = thread_yield();
        }

        // ── Server child: RECEIVE on ep, signal on done. ────────────────────
        let server = spawn::new_child(ctx)
            .map_err(|_| "stress::cap_delete_reply_wake: spawn::new_child server failed")?;
        let server_ep = cap_copy(ep, server.cs, RIGHTS_RECEIVE)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_copy server ep failed")?;
        let server_done = cap_copy(done, server.cs, RIGHTS_SIGNAL)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_copy server done failed")?;
        let server_arg = u64::from(server_ep) | (u64::from(server_done) << 16);
        // SAFETY: stack index 0 is the server's; sequential cycles never alias.
        let server_stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
        spawn::configure_and_start_pinned(
            &server,
            server_entry,
            server_stack,
            server_arg,
            server_cpu,
        )
        .map_err(|_| "stress::cap_delete_reply_wake: start server failed")?;

        // Wait until the server has dequeued the client. The armed bit is raised
        // only after `ipc_recv` returns, so its arrival proves the client is
        // `BlockedOnReply` on this server — the live window in which
        // `reply_tcb = client` and the reply-wake is owed.
        let mut acc = 0u64;
        while acc & BIT_SERVER_ARMED == 0
        {
            let bits = notification_wait(done)
                .map_err(|_| "stress::cap_delete_reply_wake: notification_wait(armed) failed")?;
            acc |= bits;
        }
        armed_cycles += 1;

        // Delete the server Thread cap. This drives `dealloc_object(Thread)`,
        // which owes the orphaned client its deferred `Interrupted` wake.
        cap_delete(server.th)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_delete server th failed")?;

        // LIVENESS GATE: the client MUST wake. A lost reply-wake never sends
        // BIT_CLIENT_WOKE, so this `notification_wait` blocks, every CPU goes
        // idle, and the softlockup watchdog fires — the FAIL signal, raised by
        // the kernel (its registry walk names the stranded BlockedOnReply
        // client), not by a test assertion. DISPOSITION GATE: a wake that
        // surfaces anything but `Interrupted` raises BIT_CLIENT_BAD instead —
        // fail fast with a named error.
        while acc & (BIT_CLIENT_WOKE | BIT_CLIENT_BAD) == 0
        {
            let bits = notification_wait(done)
                .map_err(|_| "stress::cap_delete_reply_wake: notification_wait(woke) failed")?;
            acc |= bits;
        }
        if acc & BIT_CLIENT_BAD != 0
        {
            return Err(
                "stress::cap_delete_reply_wake: dealloc wake returned a non-Interrupted \
                 result (garbage reply — #361 disposition clobber)",
            );
        }
        woke_cycles += 1;

        // ── Per-cycle cleanup. ──────────────────────────────────────────────
        // The server Thread cap is already deleted; reap the rest. The client
        // has woken and is exiting; `cap_delete(client.th)` reaps its TCB.
        cap_delete(server.cs)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_delete server cs failed")?;
        cap_delete(client.th)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_delete client th failed")?;
        cap_delete(client.cs)
            .map_err(|_| "stress::cap_delete_reply_wake: cap_delete client cs failed")?;
        cap_delete(ep).map_err(|_| "stress::cap_delete_reply_wake: cap_delete ep failed")?;
        cap_delete(done).map_err(|_| "stress::cap_delete_reply_wake: cap_delete done failed")?;
    }

    // Non-vacuous on both halves: every cycle armed the reply binding and then
    // observed the owed wake, so a clean boot reflects the dealloc reply-wake
    // liveness path actually executing CYCLES times.
    if armed_cycles != CYCLES
    {
        return Err("stress::cap_delete_reply_wake: reply binding never armed on some cycle");
    }
    if woke_cycles != CYCLES
    {
        return Err("stress::cap_delete_reply_wake: client wake missing on some cycle");
    }

    Ok(())
}

// ── Child entries ───────────────────────────────────────────────────────────

/// Decode the two packed fields shared by both child entries:
/// `ep_slot[15:0]`, `done_slot[31:16]` (cap slot indices in the child's own
/// `CSpace`). Each child reads its dedicated IPC buffer from its module static.
// cast_possible_truncation: ep/done are kernel cap slot indices < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn decode(arg: u64) -> (u32, u32)
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    (ep_slot, done_slot)
}

/// Server: receive one caller (making it `BlockedOnReply`), announce the reply
/// binding is armed, busy-spin briefly to stay live, then exit **without
/// replying** — leaving the client parked on a server about to be deleted.
fn server_entry(arg: u64) -> !
{
    let (ep_slot, done_slot) = decode(arg);
    // SAFETY: the server child of the current cycle is the sole user of
    // SERVER_IPC_BUF; sequential cycles never alias it.
    let buf = core::ptr::addr_of_mut!(SERVER_IPC_BUF).cast::<u64>();

    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }

    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    if unsafe { ipc::ipc_recv(ep_slot, buf) }.is_ok()
    {
        // Recv succeeded ⇒ a client is now BlockedOnReply on us. Announce the
        // armed window before we die without replying.
        notification_send(done_slot, BIT_SERVER_ARMED).ok();
    }

    // Stay alive a short, bounded window so the `cap_delete` lands while the
    // reply binding is on a still-running server, then die without replying.
    for _ in 0..SERVER_SPIN
    {
        core::hint::spin_loop();
    }
    thread_exit()
}

/// Client: call the endpoint (blocking `BlockedOnReply` on the server TCB). The
/// call returns when the server's dealloc wakes it; the deposited disposition
/// MUST be `Interrupted` (the #361 contract) — anything else raises the bad
/// bit the controller fails fast on.
fn client_entry(arg: u64) -> !
{
    let (ep_slot, done_slot) = decode(arg);
    // SAFETY: the client child of the current cycle is the sole user of
    // CLIENT_IPC_BUF; sequential cycles never alias it.
    let buf = core::ptr::addr_of_mut!(CLIENT_IPC_BUF).cast::<u64>();

    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }

    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let bit = match unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0), buf) }
    {
        Err(e) if e == SyscallError::Interrupted as i64 => BIT_CLIENT_WOKE,
        _ => BIT_CLIENT_BAD,
    };
    notification_send(done_slot, bit).ok();
    thread_exit()
}
