// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_reply_race.rs

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
//! The stop-path `reply_tcb` CAS dereferences the server TCB that a concurrent
//! `cap_delete(server)` frees; the guard that keeps that CAS on live memory
//! (#317) is specified in
//! [scheduling-internals.md](../../../kernel/docs/scheduling-internals.md)
//! § Cross-CPU TCB Ownership (Stop-path UAF — CLOSURE LEMMA). A regression is
//! a cross-CPU use-after-free of the server TCB.
//!
//! ## How this exercises it
//!
//! Each cycle pins a server and a client to **different** CPUs so the
//! cancel-CAS and the dealloc-free run on different cores. The client reports
//! that it is entering `ipc_call` before the controller starts the server, so
//! the call is usually queued first. The server drains the client (making
//! `reply_tcb = client` live and the client `BlockedOnReply`), signals an
//! *armed* witness, then reports that it is exiting and exits without
//! replying; the controller waits for that report and probes, bounded, for
//! the server's `Exited` state. The controller then fires
//! `thread_stop(client)` and `cap_delete(server)` as close to simultaneously
//! as serial syscall issue allows, alternating their order by cycle parity to
//! cover both interleavings.
//!
//! With four or more CPUs, the controller pins itself to CPU 0, the server,
//! the client and a second stopper take three distinct other CPUs, and the
//! second stopper stops the client too, released by the controller just
//! before its own stop and delete and after a cycle-varying spin, so two
//! cancels race one reply-blocked client while the server is freed. A cancel that wins the
//! `reply_tcb` CAS leaves the server's slot null, so the server's dealloc no
//! longer reaches the client; were the client's binding still naming the
//! server once the winner dropped the client's `sched_lock`, the other
//! cancel's `blocked_on == server` re-read would pass and its CAS would run
//! on the freed server. The winner clears the binding inside that same hold
//! (core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 7).
//!
//! ## Anti-vacuous guard
//!
//! A run that never armed the race (server never received, so no client was
//! ever `BlockedOnReply`) would pass trivially. To rule that out, the server
//! signals [`BIT_SERVER_ARMED`] *only after* `ipc_recv` succeeds — a
//! successful recv is itself proof the client reached `BlockedOnReply` on this
//! server. The controller waits for that bit every cycle, bounded, and a
//! cycle whose bit does not arrive fails the test rather than passing
//! vacuously. (The client's own wake is *not* required: whichever
//! teardown wins, a stopped client stays `Stopped` and never runs its tail, so
//! gating on a client-side bit would be racy. It signals [`BIT_CLIENT_WOKE`]
//! best-effort only.)
//!
//! ## Pass criterion
//!
//! SMP-only (skips on `< 2` CPUs — the free and the CAS must run on different
//! cores to race). Post-#317 the harness boots clean to
//! `[ktest] ALL TESTS PASSED`. With a second stopper, the cell also requires
//! every second stop to have finished before the cycle's cleanup, and some
//! second stop in a stop-first (A-first) cycle to have returned `Ok`. In
//! those cycles the client stays reply-blocked until a stop cancels it (the
//! controller's stop returns before its delete of the server), so an `Ok`
//! there shows the second stopper's cancel reached a reply-blocked client,
//! rather than always arriving late. In a delete-first (B-first) cycle an
//! `Ok` can also stop a client the server's death already woke, so those are
//! not counted. Userspace cannot observe that the two cancels overlapped
//! inside one client's `sched_lock` window, so that interleaving is reached
//! statistically across the cycles. Any use-after-free of the freed server TCB
//! surfaces as a kernel magic-cookie debug-assert / `#PF` / double-enqueue
//! panic that the harness reports as FAIL — it is raised by the kernel, not by
//! this test.

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, thread_exit, thread_set_affinity, thread_stop,
};
use syscall_abi::{RIGHTS_EP_RECEIVE, RIGHTS_EP_SEND_GRANT, RIGHTS_THREAD_CONTROL, SystemInfoType};

use crate::tally::await_report;
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Number of stop-vs-free races to run. Tunable; 300 gives the cross-CPU
/// window many chances to land on either side of the free.
const CYCLES: u32 = 300;

/// Fewest races at any width ([`super::scaled_attempts`]): enough stop-first
/// cycles for some second stop to reach a reply-blocked client.
const MIN_CYCLES: u32 = 64;

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// `done` bit the server raises once `ipc_recv` has dequeued the client, i.e.
/// once the client is `BlockedOnReply` and the race is armed.
const BIT_SERVER_ARMED: u64 = 1 << 0;

/// `done` bit the client raises best-effort if its `ipc_call` returns (woken by
/// the server's death rather than stopped). Not gated on — see module docs.
const BIT_CLIENT_WOKE: u64 = 1 << 1;

/// `done` bit the client raises immediately before its `ipc_call`.
const BIT_CLIENT_CALLING: u64 = 1 << 2;

/// `done` bit the server raises immediately before its `thread_exit`.
const BIT_SERVER_EXITING: u64 = 1 << 3;

/// `done` bit the second stopper raises once its stop has returned.
const BIT_STOPPER_DONE: u64 = 1 << 4;

/// Bound on the controller's back-to-back probes for the server's `Exited`
/// state after the server reports that it is exiting. The probes do not
/// block, so a server sharing the controller's CPU cannot finish meanwhile;
/// the race then lands on a server not yet `Exited`, an interleaving the
/// cell accepts.
const EXIT_PROBES: u32 = 4096;

/// Bound on the server's post-recv busy-spin before it exits without replying.
/// The spin does not keep the TCB alive: `thread_exit` only commits `Exited`
/// and leaves `reply_tcb` bound, so the server TCB's storage persists until the
/// controller's `cap_delete(server.th)` and the race always lands on an
/// allocated TCB.
const SERVER_SPIN: u32 = 200;

/// The controller's CPU while a second stopper runs.
const CONTROLLER_CPU: u32 = 0;

/// Bound on the second stopper's cycle-varying spin between its release and
/// its stop, so its cancel lands before, during, or after the controller's.
const STOPPER_SPIN_MAX: u32 = 64;

/// Controller → second stopper: the cycle, counted from 1, whose client it is
/// to stop now. The stopper spins on it rather than blocking, so its release
/// costs no wake latency.
static STOPPER_GO: AtomicU32 = AtomicU32::new(0);
/// Second stops that returned `Ok` in a stop-first cycle, where the client
/// is reply-blocked until a stop cancels it (see the module's § Pass
/// criterion).
static SECOND_STOPS_OK: AtomicU32 = AtomicU32::new(0);

/// The second stopper's arguments, handed to `stopper_entry` by address.
#[derive(Clone, Copy)]
struct StopperArgs
{
    /// CONTROL copy of the client's Thread cap.
    target: u32,
    /// Signal copy of the cycle's `done`.
    done: u32,
    /// The cycle, counted from 1.
    round: u32,
}

static STOPPER_ARGS: spawn::ArgBlock<StopperArgs, 1> = spawn::ArgBlock::new(StopperArgs {
    target: 0,
    done: 0,
    round: 0,
});

/// A page-aligned 4 KiB IPC buffer page (512 `u64` words, the same shape as
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
    let cpu_count = u32::try_from(cpus).unwrap_or(2);
    // Each race's starts, stops and dealloc cross CPUs, whose cost grows with
    // the width; the count shrinks with it and the placements stay spread.
    let count = super::scaled_attempts(CYCLES, MIN_CYCLES, cpus);
    let second_stopper = cpus >= 4;
    if !second_stopper
    {
        crate::log("ktest: stress::stop_reply_race second-stopper race SKIP (need 4+ CPUs)");
        return cycles(
            ctx,
            Placement {
                base: 0,
                span: cpu_count,
            },
            Stops::Single,
            count,
        );
    }
    // The controller takes CPU 0 so a floor-priority child never shares its
    // CPU and runs only after the controller's race.
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::stop_reply_race: pin controller failed")?;
    let result = cycles(
        ctx,
        Placement {
            base: CONTROLLER_CPU + 1,
            span: cpu_count - 1,
        },
        Stops::Double,
        count,
    );
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_reply_race: restore controller affinity failed");
    result?;
    restore
}

/// The CPUs a cycle's children take: `base + (slot + k) % span`, where `slot`
/// is the cycle's [`super::rotation_slot`] and `k` = 0 for the server, 1 for
/// the client and 2 for the second stopper, so the three are distinct
/// whenever `span >= 3` (and the server and client whenever `span >= 2`).
#[derive(Clone, Copy)]
struct Placement
{
    base: u32,
    span: u32,
}

impl Placement
{
    fn cpu(self, slot: u32, k: u32) -> u32
    {
        self.base + (slot + k) % self.span
    }
}

/// Who stops each cycle's client: the controller alone, or the controller and
/// a second stopper.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stops
{
    Single,
    Double,
}

/// Run `count` races with the children placed per `place` and stopped by
/// `stops`. Every cycle must arm its race ([`one_cycle`] fails one that does
/// not).
fn cycles(ctx: &TestContext, place: Placement, stops: Stops, count: u32) -> TestResult
{
    STOPPER_GO.store(0, Ordering::Release);
    SECOND_STOPS_OK.store(0, Ordering::Release);

    for cycle in 0..count
    {
        let slot = super::rotation_slot(cycle, count, place.span);
        one_cycle(ctx, place, stops, cycle, slot)?;
    }
    if stops == Stops::Double
    {
        check_second_stops()?;
    }
    Ok(())
}

/// One cycle's objects and children; [`reap_cycle`] deletes whichever exist.
#[derive(Default)]
struct CycleParts
{
    ep: Option<u32>,
    done: Option<u32>,
    client: Option<spawn::SpawnedChild>,
    stopper: Option<spawn::SpawnedChild>,
    server: Option<spawn::SpawnedChild>,
    /// Whether [`race`] has deleted the server's Thread cap, as the race's
    /// free.
    server_th_deleted: bool,
}

/// One cycle: create the endpoint and `done`, start the client, the second
/// stopper (if any) and the server on the CPUs `place` gives `slot`, wait for
/// the race to arm, race, and delete everything the cycle created on every
/// path, so a failed cycle leaves no child running on its CPU or stack.
fn one_cycle(ctx: &TestContext, place: Placement, stops: Stops, cycle: u32, slot: u32)
-> TestResult
{
    let mut parts = CycleParts::default();
    let result = arm_and_race(ctx, place, stops, (cycle, slot), &mut parts);
    let reaped = reap_cycle(&parts);
    result?;
    reaped
}

/// The body of [`one_cycle`] for the cycle and slot pair `at`, recording each
/// object and child in `parts` as soon as it exists.
fn arm_and_race(
    ctx: &TestContext,
    place: Placement,
    stops: Stops,
    at: (u32, u32),
    parts: &mut CycleParts,
) -> TestResult
{
    let (cycle, slot) = at;
    let server_cpu = place.cpu(slot, 0);
    // Different CPU from the server: the cancel-CAS and the dealloc-free
    // must run on different cores to actually race (see `Placement`).
    let client_cpu = place.cpu(slot, 1);

    let ep = *parts.ep.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "stress::stop_reply_race: cap_create_endpoint failed")?,
    );
    let done = *parts.done.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::stop_reply_race: cap_create_notification failed")?,
    );

    let client_th = spawn_client(ctx, ep, done, client_cpu, &mut parts.client)?;
    if stops == Stops::Double
    {
        spawn_stopper(
            ctx,
            StopperArgs {
                target: client_th,
                done,
                round: cycle + 1,
            },
            place.cpu(slot, 2),
            &mut parts.stopper,
        )?;
    }

    // Start the server once the client is entering `ipc_call`, so the call
    // is usually queued before the server receives. A server that receives
    // first takes the call when it comes; the armed wait below proves the
    // client parked either way.
    let mut acc = 0u64;
    await_report(
        done,
        &mut acc,
        BIT_CLIENT_CALLING,
        "stress::stop_reply_race: the client never reached its call",
    )?;

    let server_th = spawn_server(ctx, ep, done, server_cpu, &mut parts.server)?;

    // Wait until the server has dequeued the client. The armed bit is raised
    // only after `ipc_recv` returns, so its arrival proves the client is
    // `BlockedOnReply` on this server — the live window in which
    // `reply_tcb = client` and the server is about to be deleted. A server
    // that never receives fails the cycle (the race never armed) instead of
    // hanging the run.
    await_report(
        done,
        &mut acc,
        BIT_SERVER_ARMED,
        "stress::stop_reply_race: race never armed on some cycle",
    )?;

    // Race once the server has exited without replying: its TCB stays
    // allocated (Exited, `reply_tcb` still bound to the client) until `race`
    // deletes its Thread cap. The server reports just before its exit and
    // the probe closes the rest of that window; see [`EXIT_PROBES`].
    await_report(
        done,
        &mut acc,
        BIT_SERVER_EXITING,
        "stress::stop_reply_race: the server never reached its exit",
    )?;
    probe_exited(server_th)?;

    race(cycle, client_th, server_th, &mut parts.server_th_deleted)?;
    if parts.stopper.is_some()
    {
        await_report(
            done,
            &mut acc,
            BIT_STOPPER_DONE,
            "stress::stop_reply_race: the second stopper did not finish its stop",
        )?;
    }
    Ok(())
}

/// Probe, at most [`EXIT_PROBES`] times back to back, whether `server`
/// reports `Exited`; the race accepts either answer.
fn probe_exited(server: u32) -> TestResult
{
    for _ in 0..EXIT_PROBES
    {
        if spawn::is_exited(server)?
        {
            break;
        }
    }
    Ok(())
}

/// Per-cycle cleanup, on every path. On the passing path the client is now
/// Stopped (if A won) or woken-and-exited (if B won); either way `cap_delete`
/// reaps its TCB — the `BlockedOnReply` twin arm of dealloc(client) racing
/// the same teardown. Deleting a child's Thread cap stops it wherever it is,
/// so on a failing path no child outlives the cycle. Returns the first
/// delete that failed.
fn reap_cycle(parts: &CycleParts) -> TestResult
{
    let mut deletes: [Option<(u32, &'static str)>; 8] = [None; 8];
    if let Some(server) = &parts.server
    {
        if !parts.server_th_deleted
        {
            deletes[0] = Some((
                server.th,
                "stress::stop_reply_race: cap_delete server th failed",
            ));
        }
        deletes[1] = Some((
            server.cs,
            "stress::stop_reply_race: cap_delete server cs failed",
        ));
    }
    if let Some(stopper) = &parts.stopper
    {
        deletes[2] = Some((
            stopper.th,
            "stress::stop_reply_race: cap_delete stopper th failed",
        ));
        deletes[3] = Some((
            stopper.cs,
            "stress::stop_reply_race: cap_delete stopper cs failed",
        ));
    }
    if let Some(client) = &parts.client
    {
        deletes[4] = Some((
            client.th,
            "stress::stop_reply_race: cap_delete client th failed",
        ));
        deletes[5] = Some((
            client.cs,
            "stress::stop_reply_race: cap_delete client cs failed",
        ));
    }
    deletes[6] = parts
        .ep
        .map(|ep| (ep, "stress::stop_reply_race: cap_delete ep failed"));
    deletes[7] = parts
        .done
        .map(|done| (done, "stress::stop_reply_race: cap_delete done failed"));
    let mut result = Ok(());
    for (cap, err) in deletes.into_iter().flatten()
    {
        if cap_delete(cap).is_err() && result.is_ok()
        {
            result = Err(err);
        }
    }
    result
}

/// With a second stopper, some stop-first cycle's second stop must have
/// committed on the reply-blocked client ([`SECOND_STOPS_OK`]).
fn check_second_stops() -> TestResult
{
    let committed = SECOND_STOPS_OK.load(Ordering::Acquire);
    crate::log_u64(
        "ktest: stress::stop_reply_race stop-first second stops ok=",
        u64::from(committed),
    );
    if committed == 0
    {
        return Err(
            "stress::stop_reply_race: no second stop committed on a reply-blocked client (the \
             two-stop race never armed)",
        );
    }
    Ok(())
}

/// The race, A: `thread_stop(client)` → `cancel_ipc_block`'s
/// `BlockedOnReply` arm → the (guarded) `server.reply_tcb` CAS, reading the
/// server TCB; B: `cap_delete(server th)` → `dealloc_object(Thread)` →
/// claim-CAS → gates → deferred client wake → `retype_free` of the server
/// TCB. Client and server are pinned to different CPUs, so A's CAS and B's
/// free execute on different cores; the issue order alternates by cycle
/// parity to cover both interleavings. A second stopper, if any, is released
/// first and races A with a second cancel. Sets `server_th_deleted` once the
/// server's Thread cap is deleted.
fn race(cycle: u32, client_th: u32, server_th: u32, server_th_deleted: &mut bool) -> TestResult
{
    STOPPER_GO.store(cycle + 1, Ordering::Release);
    // The stop's outcome depends on which teardown reached the client first
    // (`Ok`, `InvalidState`, or an error for a client already exited); the
    // race, not its return, is what the cell exercises.
    if cycle.is_multiple_of(2)
    {
        let _ = thread_stop(client_th);
        cap_delete(server_th)
            .map_err(|_| "stress::stop_reply_race: cap_delete server th (A-first) failed")?;
        *server_th_deleted = true;
    }
    else
    {
        cap_delete(server_th)
            .map_err(|_| "stress::stop_reply_race: cap_delete server th (B-first) failed")?;
        *server_th_deleted = true;
        // As above: any outcome of this stop is accepted.
        let _ = thread_stop(client_th);
    }
    Ok(())
}

/// Spawn the cycle's client on `cpu`, holding SEND|GRANT on `ep` and a
/// signal copy of `done`, into `slot` (stored before anything can fail, so
/// the cycle's reap deletes it). Returns its Thread cap.
fn spawn_client(
    ctx: &TestContext,
    ep: u32,
    done: u32,
    cpu: u32,
    slot: &mut Option<spawn::SpawnedChild>,
) -> Result<u32, &'static str>
{
    let client = slot.insert(
        spawn::new_child(ctx)
            .map_err(|_| "stress::stop_reply_race: spawn::new_child client failed")?,
    );
    let client_ep = cap_copy(ep, client.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "stress::stop_reply_race: cap_copy client ep failed")?;
    let client_done = cap_copy(done, client.cs, RIGHTS_SIGNAL)
        .map_err(|_| "stress::stop_reply_race: cap_copy client done failed")?;
    // arg packs ep_slot[31:0] | done_slot[63:32]; the child reads its own
    // dedicated IPC buffer address from the static directly.
    let arg = u64::from(client_ep) | (u64::from(client_done) << 32);
    // SAFETY: stack index 1 is the client's; each cycle reaps its client
    // before the next starts.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[1]) });
    // SAFETY: the stack is `super::STRESS_STACKS[1]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(client, client_entry, stack, arg, cpu) }
        .map_err(|_| "stress::stop_reply_race: start client failed")?;
    Ok(client.th)
}

/// Spawn the cycle's server on `cpu`, holding RECEIVE on `ep` and a signal
/// copy of `done`, into `slot` (stored before anything can fail, so the
/// cycle's reap deletes it). Returns its Thread cap.
fn spawn_server(
    ctx: &TestContext,
    ep: u32,
    done: u32,
    cpu: u32,
    slot: &mut Option<spawn::SpawnedChild>,
) -> Result<u32, &'static str>
{
    let server = slot.insert(
        spawn::new_child(ctx)
            .map_err(|_| "stress::stop_reply_race: spawn::new_child server failed")?,
    );
    let server_ep = cap_copy(ep, server.cs, RIGHTS_EP_RECEIVE)
        .map_err(|_| "stress::stop_reply_race: cap_copy server ep failed")?;
    let server_done = cap_copy(done, server.cs, RIGHTS_SIGNAL)
        .map_err(|_| "stress::stop_reply_race: cap_copy server done failed")?;
    // arg packs ep_slot[31:0] | done_slot[63:32]; the child reads its own
    // dedicated IPC buffer address from the static directly.
    let arg = u64::from(server_ep) | (u64::from(server_done) << 32);
    // SAFETY: stack index 0 is the server's; each cycle reaps its server
    // before the next starts.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
    // SAFETY: the stack is `super::STRESS_STACKS[0]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(server, server_entry, stack, arg, cpu) }
        .map_err(|_| "stress::stop_reply_race: start server failed")?;
    Ok(server.th)
}

/// Spawn the cycle's second stopper on `cpu`, distinct from the server's, the
/// client's and the controller's (see `Placement`), holding a CONTROL copy of
/// the client's Thread capability (`args.target`) and a signal copy of the
/// cycle's `done` (`args.done`), into `slot` (stored before anything can
/// fail, so the cycle's reap deletes it).
fn spawn_stopper(
    ctx: &TestContext,
    args: StopperArgs,
    cpu: u32,
    slot: &mut Option<spawn::SpawnedChild>,
) -> TestResult
{
    let stopper = slot.insert(
        spawn::new_child(ctx)
            .map_err(|_| "stress::stop_reply_race: spawn::new_child stopper failed")?,
    );
    let target = cap_copy(args.target, stopper.cs, RIGHTS_THREAD_CONTROL)
        .map_err(|_| "stress::stop_reply_race: cap_copy stopper target failed")?;
    let done = cap_copy(args.done, stopper.cs, RIGHTS_SIGNAL)
        .map_err(|_| "stress::stop_reply_race: cap_copy stopper done failed")?;
    // SAFETY: entry 0 is the cycle's only stopper's, and the previous cycle's
    // stopper was deleted by that cycle's reap.
    let arg = unsafe {
        STOPPER_ARGS.publish(
            0,
            StopperArgs {
                target,
                done,
                round: args.round,
            },
        )
    };
    // SAFETY: stack index 2 is the stopper's; each cycle reaps its stopper
    // before the next starts.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[2]) });
    // SAFETY: the stack is `super::STRESS_STACKS[2]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(stopper, stopper_entry, stack, arg, cpu) }
        .map_err(|_| "stress::stop_reply_race: start stopper failed")
}

// ── Child entries ───────────────────────────────────────────────────────────

/// Decode the two packed fields shared by both child entries:
/// `ep_slot[31:0]`, `done_slot[63:32]` (cap handles in the child's own
/// `CSpace`). Each child reads its dedicated IPC buffer from its module static.
// cast_possible_truncation: ep/done are kernel cap slot indices < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn decode(arg: u64) -> (u32, u32)
{
    let ep_slot = (arg & 0xFFFF_FFFF) as u32;
    let done_slot = (arg >> 32) as u32;
    (ep_slot, done_slot)
}

/// Server: receive one caller (making it `BlockedOnReply`), announce that the
/// race is armed, busy-spin briefly to stay live, then exit **without
/// replying** — leaving the client parked on a server about to be deleted.
extern "C" fn server_entry(arg: u64) -> !
{
    let (ep_slot, done_slot) = decode(arg);
    // SAFETY: the server child of the current cycle is the sole user of
    // SERVER_IPC_BUF; sequential cycles never alias it.
    let buf = core::ptr::addr_of_mut!(SERVER_IPC_BUF).cast::<u64>();

    // SAFETY: `buf` is this thread's own page-aligned IPC page (the static above),
    // registered by one thread at a time; no Rust object lives in it, and the
    // thread reaches it only through the raw `buf` pointer.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
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

    // Spin a short, bounded window, then die without replying. The TCB stays
    // allocated (Exited, `reply_tcb` bound) until the controller's
    // `cap_delete(server.th)`, which is the free the stop path races.
    for _ in 0..SERVER_SPIN
    {
        core::hint::spin_loop();
    }
    notification_send(done_slot, BIT_SERVER_EXITING).ok();
    thread_exit()
}

/// Second stopper: spin until the controller releases this cycle, spin a
/// cycle-varying delay, stop the client, record the stop's return, and
/// report it on `done`.
extern "C" fn stopper_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `spawn_stopper` published for this stopper.
    let StopperArgs {
        target,
        done,
        round,
    } = unsafe { spawn::child_args(arg) };
    while STOPPER_GO.load(Ordering::Acquire) != round
    {
        core::hint::spin_loop();
    }
    for _ in 0..(round % STOPPER_SPIN_MAX)
    {
        core::hint::spin_loop();
    }
    // Ok: this stop reached the client first, or, in a delete-first cycle,
    // stopped a client the server's death already woke and that has not yet
    // exited. InvalidState: the controller's stop reached the client first.
    // Another error: the client was already woken and exited. Only an Ok in a
    // stop-first cycle (`race` stops before it deletes on even cycles, the
    // odd rounds), where the client is reply-blocked until a stop cancels it,
    // is tallied.
    if thread_stop(target).is_ok() && round % 2 == 1
    {
        SECOND_STOPS_OK.fetch_add(1, Ordering::AcqRel);
    }
    notification_send(done, BIT_STOPPER_DONE).ok();
    thread_exit()
}

/// Client: call the endpoint (blocking `BlockedOnReply` on the server TCB). If
/// the call returns at all (woken by the server's death rather than stopped),
/// raise a best-effort woke bit. A stopped client never reaches this tail.
extern "C" fn client_entry(arg: u64) -> !
{
    let (ep_slot, done_slot) = decode(arg);
    // SAFETY: the client child of the current cycle is the sole user of
    // CLIENT_IPC_BUF; sequential cycles never alias it.
    let buf = core::ptr::addr_of_mut!(CLIENT_IPC_BUF).cast::<u64>();

    // SAFETY: `buf` is this thread's own page-aligned IPC page (the static above),
    // registered by one thread at a time; no Rust object lives in it, and the
    // thread reaches it only through the raw `buf` pointer.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        thread_exit()
    }

    notification_send(done_slot, BIT_CLIENT_CALLING).ok();
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let _ = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0), buf) };
    notification_send(done_slot, BIT_CLIENT_WOKE).ok();
    thread_exit()
}
