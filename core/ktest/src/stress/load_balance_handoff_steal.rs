// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/load_balance_handoff_steal.rs

//! Stress: arm the load balancer stealing a mid-handoff thread — the
//! empirically-reproduced root of the cross-CPU double-dispatch class
//! (#314/#293, fixed by PR #330); issue #348.
//!
//! ## The hazard
//!
//! A thread that runs `ipc_call` on its CPU commits `BlockedOnReply` and clears
//! `context_saved = 0` in `commit_blocked_under_local_lock`, but is **still
//! physically `current`** on that CPU until it reaches its own `schedule()`. A
//! fast `ipc_reply` from a server on another CPU then `enqueue_and_wake`s the
//! caller `Ready` on its `preferred_cpu` (the same CPU, since `cs == 0` pins to
//! preferred) — now `Ready`+linked while still `current`. A legitimate
//! transient: the owning CPU's `schedule()` re-dispatches it.
//!
//! Pre-#330 the load balancer (`pull_unpinned_ready`, run on every timer tick)
//! stole such a thread — `find_runnable` checked only `cpu_affinity ==
//! AFFINITY_ANY`, never liveness — and linked it on an idle CPU, whose dispatch
//! marked it `Running` while the source CPU still owned it: cross-CPU
//! double-dispatch (torn context / double-enqueue). The fix gates
//! `pull_unpinned_ready` and `migrate_ready_thread` on `context_saved == 1`
//! (published by `switch()` only after the register save, so a `Ready`+`cs==1`
//! thread is `current` nowhere). See `core/kernel/src/sched/mod.rs`.
//!
//! ## How this exercises it
//!
//! [`NUM_PAIRS`] client↔server pairs run tight `ipc_call`/`ipc_reply`
//! round-trips concurrently on a private endpoint each, under oversubscription
//! (`2 * NUM_PAIRS` threads ≫ vCPUs):
//!   * **Clients are unpinned** (`AFFINITY_ANY`) — never affinity-set — so the
//!     load balancer is *eligible* to steal them. This is the distinction from
//!     `double_enqueue_storm`, which drives only `migrate_ready_thread` via
//!     explicit affinity flips, not the autonomous `pull_unpinned_ready` steal.
//!   * **Servers are pinned round-robin** across CPUs so a reply frequently
//!     arrives from a *different* CPU than the floating client's — the
//!     cross-CPU reply is what produces the `Ready`-while-`current` window (a
//!     same-CPU reply cannot run until the client deschedules, missing it).
//!
//! Synchronous IPC keeps the runnable set bursty, so CPUs idle between
//! ping-pong rounds and run the balancer against just-woken (mid-handoff)
//! clients — the exact `ipc_call`/`ipc_reply` interleaving PR #330 pinned.
//!
//! ## Anti-vacuous guard
//!
//! The `cs == 0` sub-window is not observable from userspace, so (as in
//! `stop_reply_race`/`stop_resume_race`) the guard proves the *armable setup*,
//! not the exact stolen interleaving:
//!   * **Churn volume** — clients fold completed round-trips into [`ROUNDTRIPS`];
//!     the controller asserts `== NUM_PAIRS * ITERS` (every client completed
//!     every round-trip ⇒ the mid-handoff transients were generated densely).
//!   * **Cross-CPU migration of unpinned threads** — each client samples
//!     `system_info(CurrentCpu)` and a client whose samples span ≥ 2 CPUs
//!     provably migrated; the controller asserts [`MIGRATIONS`] `>= 1` (≥ 1
//!     unpinned client was relocated across CPUs — the balancer's target
//!     behavior occurred) and logs the observed-CPU count for diagnostics.
//!
//! A regression surfaces as a **kernel** guard firing (the
//! `PerCpuScheduler::enqueue` `queued_on >= 0` single-link tripwire in debug
//! builds, a torn dispatch faulting at `rip=0`, or the all-idle watchdog) —
//! raised by the kernel, not by this test, before these assertions are reached.
//!
//! ## Pass criterion
//!
//! SMP-only (skips on `< 2` CPUs — no cross-CPU steal on UP). Post-#330 the
//! harness boots clean to `[ktest] ALL TESTS PASSED`. Probabilistic: primary
//! value is under the `burnin.yml` oversubscription matrix; a single ktest boot
//! is a smoke check. Reverting the `context_saved == 1` load-balancer gate
//! reintroduces the steal, surfaced by a kernel guard the harness reports as
//! FAIL.
//!
//! The migration assertion applies only at `cpus <= MIGRATION_GUARD_MAX_CPUS`:
//! above that the one-hot `u32` CPU witness aliases indices mod 32, and the
//! oversubscription premise (`2 * NUM_PAIRS ≫ cpus`) is inverted — run-queue
//! depths rarely exceed the balancer's imbalance threshold, so the steal path
//! legitimately may never arm and the guard becomes a coin flip. The kernel
//! guards above remain the regression signal at every CPU count; the witness
//! values are still logged.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, system_info, thread_exit, thread_yield,
};
use syscall_abi::{RIGHTS_RECEIVE, RIGHTS_SEND_GRANT, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Client↔server pairs. 16 ⇒ 32 concurrent threads (8× oversubscription at the
/// CI default of 4 vCPUs), within `MAX_STRESS_THREADS` (64) and the `u64`
/// per-client done bitmask. Both children of a pair stay alive for the whole
/// run, so all `2 * NUM_PAIRS` stacks/buffers are live at once.
const NUM_PAIRS: usize = 16;

/// Round-trips each client issues. Tuned empirically: with the
/// `pull_unpinned_ready` gate reverted this density trips the double-enqueue
/// tripwire in ~6% of x86 KVM boots (real-parallelism only — TCG's atomic
/// translation blocks never expose the still-`current` window), which the
/// burn-in matrix repetition amplifies to near-certain detection, while the
/// cell stays ~2–3 s on riscv64 TCG, well inside ktest's 180 s suite budget.
const ITERS: usize = 16000;

/// Sample `CurrentCpu` every this many round-trips (bounds the witness syscall
/// overhead while still catching migrations across the run).
const SAMPLE_EVERY: usize = 64;

/// Controller warmup yields so servers reach `ipc_recv` before clients call.
const SETTLE_YIELDS: usize = 8;

/// Widest guest for which the `migrations >= 1` guard is asserted: the bound of
/// the one-hot `u32` CPU witness (`sample_cpu_bit` masks indices mod 32), and
/// comfortably inside the oversubscription envelope the guard was tuned for
/// (see the module doc's Pass criterion).
const MIGRATION_GUARD_MAX_CPUS: u64 = 32;

/// Notification signal right (bit 7) — what a client needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = 1 << 7;

/// A page-aligned 4 KiB IPC buffer page (`MSG_DATA_WORDS_MAX`-wide, like ktest's
/// own `IPC_BUF`). One per concurrent child: clients and servers issue IPC
/// simultaneously on different CPUs, so they must not share a page (that would
/// be a data race in the *test*, not the kernel bug under test — see
/// `stop_reply_race`). Indices `[0, NUM_PAIRS)` are clients, `[NUM_PAIRS,
/// 2*NUM_PAIRS)` are servers.
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);

impl IpcBufPage
{
    const ZERO: IpcBufPage = IpcBufPage([0u64; 512]);
}

// SAFETY: each child of the current run is the sole user of its own
// `IPC_BUFS` index via its own (kernel-synchronous) IPC syscalls.
static mut IPC_BUFS: [IpcBufPage; 2 * NUM_PAIRS] = [IpcBufPage::ZERO; 2 * NUM_PAIRS];

/// Total `ipc_call` round-trips completed across all clients (churn witness).
static ROUNDTRIPS: AtomicU64 = AtomicU64::new(0);
/// Union of CPU indices any client observed itself running on (diagnostics).
static OBSERVED_CPUS: AtomicU32 = AtomicU32::new(0);
/// Count of clients that observed themselves on ≥ 2 distinct CPUs (migration
/// witness: an unpinned thread the balancer relocated).
static MIGRATIONS: AtomicU32 = AtomicU32::new(0);

// too_many_lines: spawn (servers + clients) + drain + teardown + the
// anti-vacuous guard are one linear scenario; splitting adds no clarity.
#[allow(clippy::too_many_lines)]
pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::load_balance_handoff_steal: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::load_balance_handoff_steal SKIP (need 2+ CPUs)");
        return Ok(());
    }
    let cpu_mod = u32::try_from(cpus).unwrap_or(1).max(1);

    // run() executes once per boot; reset the shared witnesses defensively.
    ROUNDTRIPS.store(0, Ordering::Relaxed);
    OBSERVED_CPUS.store(0, Ordering::Relaxed);
    MIGRATIONS.store(0, Ordering::Relaxed);

    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::load_balance_handoff_steal: cap_create_notification failed")?;

    let mut server_th = [0u32; NUM_PAIRS];
    let mut server_cs = [0u32; NUM_PAIRS];
    let mut client_th = [0u32; NUM_PAIRS];
    let mut client_cs = [0u32; NUM_PAIRS];
    let mut eps = [0u32; NUM_PAIRS];

    // ── Servers first: pinned round-robin, RECEIVE on a private endpoint. ────
    // Spawned before clients so they reach `ipc_recv` and reply fast.
    for j in 0..NUM_PAIRS
    {
        let ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "stress::load_balance_handoff_steal: cap_create_endpoint failed")?;
        eps[j] = ep;

        let server = spawn::new_child(ctx)
            .map_err(|_| "stress::load_balance_handoff_steal: spawn server failed")?;
        let server_ep = cap_copy(ep, server.cs, RIGHTS_RECEIVE)
            .map_err(|_| "stress::load_balance_handoff_steal: cap_copy server ep failed")?;
        // arg packs ep_slot[15:0] | buf_index[31:16]; servers use buffers
        // [NUM_PAIRS, 2*NUM_PAIRS).
        let buf_index = NUM_PAIRS + j;
        let server_arg = u64::from(server_ep) | ((buf_index as u64) << 16);
        // j < NUM_PAIRS <= u32::MAX; try_from keeps the narrow cast clippy-clean.
        let server_cpu = u32::try_from(j).unwrap_or(0) % cpu_mod;
        // SAFETY: server stacks occupy [NUM_PAIRS, 2*NUM_PAIRS); distinct per j.
        let stack =
            ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[NUM_PAIRS + j]) });
        spawn::configure_and_start_pinned(&server, server_entry, stack, server_arg, server_cpu)
            .map_err(|_| "stress::load_balance_handoff_steal: start server failed")?;
        server_th[j] = server.th;
        server_cs[j] = server.cs;
    }

    for _ in 0..SETTLE_YIELDS
    {
        let _ = thread_yield();
    }

    // ── Clients: UNPINNED (AFFINITY_ANY) so the balancer may steal them. ─────
    for i in 0..NUM_PAIRS
    {
        let client = spawn::new_child(ctx)
            .map_err(|_| "stress::load_balance_handoff_steal: spawn client failed")?;
        let client_ep = cap_copy(eps[i], client.cs, RIGHTS_SEND_GRANT)
            .map_err(|_| "stress::load_balance_handoff_steal: cap_copy client ep failed")?;
        let client_done = cap_copy(done, client.cs, RIGHTS_SIGNAL)
            .map_err(|_| "stress::load_balance_handoff_steal: cap_copy client done failed")?;
        // arg packs ep_slot[15:0] | done_slot[31:16] | client_index[47:32]; the
        // client uses buffer `i` and done bit `1 << i`.
        let client_arg = u64::from(client_ep) | (u64::from(client_done) << 16) | ((i as u64) << 32);
        // SAFETY: client stacks occupy [0, NUM_PAIRS); distinct per i.
        let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&client, client_entry, stack, client_arg)
            .map_err(|_| "stress::load_balance_handoff_steal: start client failed")?;
        client_th[i] = client.th;
        client_cs[i] = client.cs;
    }

    // Wait until every client has completed its ITERS round-trips and signaled.
    let all_done: u64 = if NUM_PAIRS >= 64
    {
        u64::MAX
    }
    else
    {
        (1u64 << NUM_PAIRS) - 1
    };
    let mut acc = 0u64;
    while acc != all_done
    {
        let bits = notification_wait(done)
            .map_err(|_| "stress::load_balance_handoff_steal: notification_wait(done) failed")?;
        acc |= bits;
    }

    // ── Teardown. Servers are blocked in `ipc_recv`; delete-while-blocked. ───
    // Reap server threads (and so the live receivers) before deleting the
    // endpoints they wait on. Clients have already exited.
    for j in 0..NUM_PAIRS
    {
        cap_delete(server_th[j])
            .map_err(|_| "stress::load_balance_handoff_steal: cap_delete server th failed")?;
        cap_delete(server_cs[j])
            .map_err(|_| "stress::load_balance_handoff_steal: cap_delete server cs failed")?;
    }
    for i in 0..NUM_PAIRS
    {
        cap_delete(client_th[i])
            .map_err(|_| "stress::load_balance_handoff_steal: cap_delete client th failed")?;
        cap_delete(client_cs[i])
            .map_err(|_| "stress::load_balance_handoff_steal: cap_delete client cs failed")?;
    }
    for &ep in &eps
    {
        cap_delete(ep).map_err(|_| "stress::load_balance_handoff_steal: cap_delete ep failed")?;
    }
    cap_delete(done).map_err(|_| "stress::load_balance_handoff_steal: cap_delete done failed")?;

    // ── Anti-vacuous guard. ──────────────────────────────────────────────────
    let roundtrips = ROUNDTRIPS.load(Ordering::Relaxed);
    let migrations = MIGRATIONS.load(Ordering::Relaxed);
    let observed = OBSERVED_CPUS.load(Ordering::Relaxed);
    crate::log_u64(
        "ktest: stress::load_balance_handoff_steal roundtrips=",
        roundtrips,
    );
    crate::log_u64(
        "ktest: stress::load_balance_handoff_steal cpus_observed=",
        u64::from(observed.count_ones()),
    );
    crate::log_u64(
        "ktest: stress::load_balance_handoff_steal migrations=",
        u64::from(migrations),
    );

    let expected = u64::try_from(NUM_PAIRS).unwrap_or(0) * u64::try_from(ITERS).unwrap_or(0);
    if roundtrips != expected
    {
        return Err("stress::load_balance_handoff_steal: not all round-trips completed");
    }
    if migrations == 0 && cpus <= MIGRATION_GUARD_MAX_CPUS
    {
        return Err(
            "stress::load_balance_handoff_steal: no client observed on 2+ CPUs (steal path unarmed)",
        );
    }

    Ok(())
}

// ── Child entries ───────────────────────────────────────────────────────────

/// Client: tight `ipc_call` loop on a private endpoint, sampling its CPU to
/// witness migration. Unpinned, so the balancer may steal it mid-handoff.
// cast_possible_truncation: cap slots and the client index are < 2^16; the CPU
// index is < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn client_entry(arg: u64) -> !
{
    let ep = (arg & 0xFFFF) as u32;
    let done = ((arg >> 16) & 0xFFFF) as u32;
    let idx = ((arg >> 32) & 0xFFFF) as usize;
    let done_bit = 1u64 << idx;

    // SAFETY: client `idx` is the sole user of IPC_BUFS[idx] this run.
    let buf = unsafe { core::ptr::addr_of_mut!(IPC_BUFS[idx]) }.cast::<u64>();
    if ipc_buffer_set(buf as u64).is_err()
    {
        notification_send(done, done_bit).ok();
        thread_exit()
    }

    let msg = IpcMessage::new(0);
    let mut completed = 0u64;
    let mut cpu_mask = sample_cpu_bit();
    for n in 0..ITERS
    {
        // SAFETY: `buf` was registered as this thread's IPC buffer above.
        if unsafe { ipc::ipc_call(ep, &msg, buf) }.is_ok()
        {
            completed += 1;
        }
        if n % SAMPLE_EVERY == 0
        {
            cpu_mask |= sample_cpu_bit();
        }
    }

    OBSERVED_CPUS.fetch_or(cpu_mask, Ordering::Relaxed);
    ROUNDTRIPS.fetch_add(completed, Ordering::Relaxed);
    if cpu_mask.count_ones() >= 2
    {
        MIGRATIONS.fetch_add(1, Ordering::Relaxed);
    }
    notification_send(done, done_bit).ok();
    thread_exit()
}

/// Server: reply to every call on its private endpoint until torn down. Pinned
/// round-robin so its reply tends to wake the client from a different CPU.
// cast_possible_truncation: ep slot and buffer index are < 2^16.
#[allow(clippy::cast_possible_truncation)]
fn server_entry(arg: u64) -> !
{
    let ep = (arg & 0xFFFF) as u32;
    let buf_index = ((arg >> 16) & 0xFFFF) as usize;

    // SAFETY: server `buf_index` is the sole user of IPC_BUFS[buf_index] this run.
    let buf = unsafe { core::ptr::addr_of_mut!(IPC_BUFS[buf_index]) }.cast::<u64>();
    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }

    let reply = IpcMessage::new(0);
    loop
    {
        // SAFETY: `buf` was registered as this thread's IPC buffer above.
        match unsafe { ipc::ipc_recv(ep, buf) }
        {
            Ok(_) =>
            {
                // SAFETY: same registered buffer; reply to the bound caller.
                let _ = unsafe { ipc::ipc_reply(&reply, buf) };
            }
            // Endpoint gone (teardown raced the delete) — nothing left to serve.
            Err(_) => thread_exit(),
        }
    }
}

/// Sample the CPU the calling thread is on as a one-hot `u32` mask bit, or 0 if
/// the query fails. CPU index is masked to 0..32 (ktest runs ≤ a handful).
// cast_possible_truncation: the masked CPU index is < 32.
#[allow(clippy::cast_possible_truncation)]
fn sample_cpu_bit() -> u32
{
    match system_info(SystemInfoType::CurrentCpu as u64)
    {
        Ok(c) => 1u32 << ((c & 31) as u32),
        Err(_) => 0,
    }
}
