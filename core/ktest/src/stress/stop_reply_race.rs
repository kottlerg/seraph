// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/stop_reply_race.rs

//! Stress: race `sys_thread_stop` on a reply-blocked client against the
//! death (`cap_delete(Thread)`) of the server it is parked on — issue #317.
//!
//! ## The hazard
//!
//! When a client issues `ipc_call` and the server `ipc_recv`s it, the client
//! becomes `BlockedOnReply` with `blocked_on_object = server TCB`, and the
//! server records `reply_tcb = client`. Two independent teardown paths then
//! both reach for `server.reply_tcb`:
//!
//!   * `thread_stop(client)` → `cancel_ipc_block`'s `BlockedOnReply` arm
//!     dereferences the *server* TCB and `compare_exchange`s `server.reply_tcb`
//!     from the client to null.
//!   * `cap_delete(server)` → `dealloc_object(Thread)` claims the server,
//!     CASes `reply_tcb`, defers the bound client's wake past the all-locks
//!     window, then `retype_free`s the server TCB.
//!
//! Pre-#317 the stop-path CAS was unguarded against the concurrent free, so a
//! `thread_stop(client)` that lost the timing read (or wrote) the server TCB
//! *after* `cap_delete(server)` freed it — a cross-CPU use-after-free that
//! tripped the magic-cookie debug-assert / `#PF` / double-enqueue tripwire.
//!
//! ## How this exercises it
//!
//! Each cycle pins a server and a client to **different** CPUs so the
//! cancel-CAS and the dealloc-free run on different cores. The server drains
//! the client (making `reply_tcb = client` live and the client
//! `BlockedOnReply`), signals an *armed* witness, then exits without replying.
//! The controller then fires `thread_stop(client)` and `cap_delete(server)`
//! as close to simultaneously as serial syscall issue allows, alternating
//! their order by cycle parity to cover both interleavings.
//!
//! ## Anti-vacuous guard
//!
//! A run that never armed the race (server never received, so no client was
//! ever `BlockedOnReply`) would pass trivially. To rule that out, the server
//! signals [`BIT_SERVER_ARMED`] *only after* `ipc_recv` succeeds — a
//! successful recv is itself proof the client reached `BlockedOnReply` on this
//! server. The controller waits for that bit every cycle and asserts it
//! collected exactly one per armed cycle; a missing bit fails the test rather
//! than passing vacuously. (The client's own wake is *not* required: whichever
//! teardown wins, a stopped client stays `Stopped` and never runs its tail, so
//! gating on a client-side bit would be racy. It signals [`BIT_CLIENT_WOKE`]
//! best-effort only.)
//!
//! ## Pass criterion
//!
//! SMP-only (skips on `< 2` CPUs — the free and the CAS must run on different
//! cores to race). Post-#317 the harness boots clean to
//! `[ktest] ALL TESTS PASSED`. Any use-after-free of the freed server TCB
//! surfaces as a kernel magic-cookie debug-assert / `#PF` / double-enqueue
//! panic that the harness reports as FAIL — it is raised by the kernel, not by
//! this test.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, thread_exit, thread_stop, thread_yield,
};
use syscall_abi::{RIGHTS_RECEIVE, RIGHTS_SEND_GRANT, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Number of stop-vs-free races to run. Tunable; 300 gives the cross-CPU
/// window many chances to land on either side of the free.
const CYCLES: usize = 300;

/// Notification signal right (bit 7) — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = 1 << 7;

/// `done` bit the server raises once `ipc_recv` has dequeued the client, i.e.
/// once the client is `BlockedOnReply` and the race is armed.
const BIT_SERVER_ARMED: u64 = 1 << 0;

/// `done` bit the client raises best-effort if its `ipc_call` returns (woken by
/// the server's death rather than stopped). Not gated on — see module docs.
const BIT_CLIENT_WOKE: u64 = 1 << 1;

/// Bound on the server's post-recv busy-spin, keeping the server TCB live for a
/// short window after it signals armed so the controller's race lands while the
/// TCB still exists.
const SERVER_SPIN: u32 = 200;

/// Bound on controller yields used to let a freshly started child reach its
/// blocking point before the next step.
const SETTLE_YIELDS: usize = 8;

/// A page-aligned 4 KiB IPC buffer page (`MSG_DATA_WORDS_MAX`-wide, like
/// ktest's own `IPC_BUF`). One per concurrent child.
///
/// The server and client run concurrently on different CPUs and each issues
/// IPC, so they must not share one buffer page (that would be a genuine
/// cross-CPU data race in the *test*, not the kernel bug under test). Each gets
/// its own static below, reused across sequential cycles: both children are
/// reaped before the next cycle, and the kernel snapshots in/out of the buffer
/// synchronously per syscall.
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
        .map_err(|_| "stress::stop_reply_race: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::stop_reply_race SKIP (need 2+ CPUs)");
        return Ok(());
    }
    let cpu_mod = u32::try_from(cpus).unwrap_or(1).max(1);

    // Anti-vacuous accumulator: every cycle must arm the race exactly once.
    let mut armed_cycles = 0usize;

    for cycle in 0..CYCLES
    {
        // CYCLES is a compile-time constant well below u32::MAX, so the narrow
        // cast is safe; try_from keeps clippy honest.
        let cycle_u32 = u32::try_from(cycle).unwrap_or(0);
        let server_cpu = cycle_u32 % cpu_mod;
        // Different CPU from the server: the cancel-CAS and the dealloc-free
        // must run on different cores to actually race. With cpus >= 2,
        // `(cycle + 1) % cpus != cycle % cpus`.
        let client_cpu = (cycle_u32 + 1) % cpu_mod;

        let ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "stress::stop_reply_race: cap_create_endpoint failed")?;
        let done = cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::stop_reply_race: cap_create_notification failed")?;

        // ── Client child: SEND|GRANT on ep, signal on done. ─────────────────
        let client = spawn::new_child(ctx)
            .map_err(|_| "stress::stop_reply_race: spawn::new_child client failed")?;
        let client_ep = cap_copy(ep, client.cs, RIGHTS_SEND_GRANT)
            .map_err(|_| "stress::stop_reply_race: cap_copy client ep failed")?;
        let client_done = cap_copy(done, client.cs, RIGHTS_SIGNAL)
            .map_err(|_| "stress::stop_reply_race: cap_copy client done failed")?;
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
        .map_err(|_| "stress::stop_reply_race: start client failed")?;

        // Let the client reach `ipc_call` and park on the endpoint send queue
        // before the server receives it.
        for _ in 0..SETTLE_YIELDS
        {
            let _ = thread_yield();
        }

        // ── Server child: RECEIVE on ep, signal on done. ────────────────────
        let server = spawn::new_child(ctx)
            .map_err(|_| "stress::stop_reply_race: spawn::new_child server failed")?;
        let server_ep = cap_copy(ep, server.cs, RIGHTS_RECEIVE)
            .map_err(|_| "stress::stop_reply_race: cap_copy server ep failed")?;
        let server_done = cap_copy(done, server.cs, RIGHTS_SIGNAL)
            .map_err(|_| "stress::stop_reply_race: cap_copy server done failed")?;
        // arg packs ep_slot[15:0] | done_slot[31:16]; the child reads its own
        // dedicated IPC buffer address from the static directly.
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
        .map_err(|_| "stress::stop_reply_race: start server failed")?;

        // Wait until the server has dequeued the client. The armed bit is
        // raised only after `ipc_recv` returns, so its arrival proves the
        // client is `BlockedOnReply` on this server — the live window in which
        // `reply_tcb = client` and the server is about to be deleted.
        let mut acc = 0u64;
        while acc & BIT_SERVER_ARMED == 0
        {
            let bits = notification_wait(done)
                .map_err(|_| "stress::stop_reply_race: notification_wait(armed) failed")?;
            acc |= bits;
        }
        armed_cycles += 1;

        // A couple more yields so the server is at/just-past recv and into its
        // short busy-spin (TCB still live) when the race fires.
        let _ = thread_yield();
        let _ = thread_yield();

        // ── The race. ───────────────────────────────────────────────────────
        //
        // A: thread_stop(client) → cancel_ipc_block BlockedOnReply arm → the
        //    (now-guarded) server.reply_tcb CAS, reading the server TCB.
        // B: cap_delete(server th) → dealloc(Thread) → claim-CAS → gates →
        //    deferred client wake → retype_free of the server TCB.
        //
        // Client and server are pinned to different CPUs, so A's CAS and B's
        // free execute on different cores. Alternate the issue order by parity
        // to cover both interleavings.
        if cycle % 2 == 0
        {
            let _ = thread_stop(client.th);
            cap_delete(server.th)
                .map_err(|_| "stress::stop_reply_race: cap_delete server th (A-first) failed")?;
        }
        else
        {
            cap_delete(server.th)
                .map_err(|_| "stress::stop_reply_race: cap_delete server th (B-first) failed")?;
            let _ = thread_stop(client.th);
        }

        // ── Per-cycle cleanup. ──────────────────────────────────────────────
        //
        // The client is now Stopped (if A won) or woken-and-exited (if B won);
        // either way `cap_delete` reaps its TCB — the BlockedOnReply twin arm
        // of dealloc(client) racing the same teardown. The server thread cap is
        // already deleted above; drop the rest.
        cap_delete(server.cs)
            .map_err(|_| "stress::stop_reply_race: cap_delete server cs failed")?;
        cap_delete(client.th)
            .map_err(|_| "stress::stop_reply_race: cap_delete client th failed")?;
        cap_delete(client.cs)
            .map_err(|_| "stress::stop_reply_race: cap_delete client cs failed")?;
        cap_delete(ep).map_err(|_| "stress::stop_reply_race: cap_delete ep failed")?;
        cap_delete(done).map_err(|_| "stress::stop_reply_race: cap_delete done failed")?;
    }

    // Non-vacuous: the race armed on every cycle, so a clean boot reflects the
    // stop-vs-free path actually executing, not a setup that silently no-op'd.
    if armed_cycles != CYCLES
    {
        return Err("stress::stop_reply_race: race never armed on some cycle");
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

/// Server: receive one caller (making it `BlockedOnReply`), announce that the
/// race is armed, busy-spin briefly to stay live, then exit **without
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

    // Stay alive a short, bounded window so the controller's race lands while
    // this TCB still exists, then die without replying.
    for _ in 0..SERVER_SPIN
    {
        core::hint::spin_loop();
    }
    thread_exit()
}

/// Client: call the endpoint (blocking `BlockedOnReply` on the server TCB). If
/// the call returns at all (woken by the server's death rather than stopped),
/// raise a best-effort woke bit. A stopped client never reaches this tail.
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
    let _ = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0), buf) };
    notification_send(done_slot, BIT_CLIENT_WOKE).ok();
    thread_exit()
}
