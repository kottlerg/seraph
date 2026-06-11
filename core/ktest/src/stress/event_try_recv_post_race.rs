// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/event_try_recv_post_race.rs

//! Stress: a non-blocking `SYS_EVENT_RECV` try-once racing a concurrent
//! `event_post` MUST never make the poller wakeable (issue #352).
//!
//! ## The hazard
//!
//! The try-once mode (`timeout = u64::MAX`) was once implemented as
//! park-then-rollback: the poller transiently published itself as `eq.waiter`
//! and committed `Blocked`. A post landing in that window claimed the waiter
//! and linked it on a run queue via `enqueue_and_wake`; the try-once arm then
//! consumed the payload and returned to userspace WITHOUT `schedule()` —
//! leaking the link. The poller's next park committed Blocked-while-linked,
//! and the next wake double-linked it (the #352 panic), or the stale link was
//! dispatched and resumed the poller's park prematurely (the #352 spawn-failure
//! variant). The fix makes try-once a pure ring peek (`event_queue_try_recv`)
//! that never registers a waiter; this cell hammers the exact geometry to keep
//! it that way.
//!
//! ## How this exercises it
//!
//! POLLER (pinned CPU 0) and POSTER (pinned CPU 1) run `CYCLES` lockstep
//! rounds. Each round the poller samples `POST_SEQ`, publishes `POLLING`,
//! and hammers `event_try_recv` until the payload lands; the poster waits
//! for `POLLING`, then stores an odd `POST_SEQ`, posts one payload, stores
//! the even `POST_SEQ`, and signals a `gate` notification. Each poll's exit
//! `POST_SEQ` sample is the next poll's entry sample, so the witness
//! brackets tile the loop gaplessly: the poster's bracket — gated on
//! `POLLING`, hence opened strictly after the poller's first sample, and
//! closed before the consuming poll's exit sample — must land odd-or-changed
//! inside one of them, counting the round as ARMED. (The bracket opens in
//! userspace around the post syscall, so ARMED is an OUTER bound on true
//! kernel-window overlap — read it as "overlap candidate", not proven
//! in-kernel overlap.) The poller then parks for real on the gate
//! (`notification_wait`) — the second park that detonates a leaked link —
//! and asserts the queue is empty.
//!
//! ## Expected pre-fix failure modes (any one is the FAIL signal)
//!
//! 1. Kernel double-enqueue panic at `PerCpuScheduler::enqueue` — the leaked
//!    link collides with the poster's `notification_send` wake after the gate
//!    park commits Blocked-while-linked (the captured #352 signature).
//! 2. `notification_wait(gate)` returns zero/wrong bits — the stale link was
//!    dispatched by CPU 0's own `schedule()` (the unconditional next==current
//!    re-mark sets `Running` with no state check) and resumed the wait before
//!    any send deposited bits: the variant-B premature-resume shape.
//! 3. Payload-conservation or drain/empty assert — a lost or duplicated wake.
//! 4. Hang — softlockup watchdog / harness timeout (kernel-raised).
//!
//! A preemption tick on CPU 0 while the poller runs userspace Ready+linked can
//! consume the stale entry via that same next==current re-mark and silently
//! self-heal a round, so not every armed round detonates; with hundreds of
//! armed rounds per boot the old kernel still fails with near certainty. A
//! marginal detonation result means raise `CYCLES`, not vacuity.
//!
//! ## Anti-vacuous guards
//!
//! - `ARMED >= CYCLES / 4`: the `POLLING` handshake plus gapless brackets
//!   make arming structural — every completed round should arm regardless of
//!   how the host serialises the two vCPUs (TCG timeslicing cannot slide the
//!   post between brackets). The floor stays at a quarter as defence against
//!   an unforeseen witness gap; a breach means the handshake is broken, not
//!   that the floor should be lowered.
//! - `CONSUMED == CYCLES`: every round's payload consumed exactly once —
//!   conservation across the poll loop.
//!
//! ## Pass criterion
//!
//! SMP-only (skips on `< 2` CPUs — the poll and the post must run on different
//! cores). On a correct kernel the harness boots clean to
//! `[ktest] ALL TESTS PASSED`.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, event_post, event_queue_create, event_try_recv,
    notification_send, notification_wait, thread_exit,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Lockstep rounds. Sized so the `ARMED` floor leaves wide slack under TCG
/// timing jitter while keeping the cell inside the suite's time budget.
const CYCLES: u32 = 1024;

/// Notification signal right (bit 7) and wait right (bit 8). Each cap copy
/// carries only the right its one-directional use needs.
const RIGHTS_SIGNAL: u64 = 1 << 7;
const RIGHTS_WAIT: u64 = 1 << 8;

/// Event-queue post right (bit 9) and recv right (bit 10).
const RIGHTS_EQ_POST: u64 = 1 << 9;
const RIGHTS_EQ_RECV: u64 = 1 << 10;

/// `done` bits raised by each child on completion (clean or failed).
const BIT_POLLER_DONE: u64 = 1 << 0;
const BIT_POSTER_DONE: u64 = 1 << 1;

/// Round ticket: poster stores the round number, poller spins until it
/// appears. `u32::MAX` = no round published yet.
static GO: AtomicU32 = AtomicU32::new(u32::MAX);

/// Poll-loop handshake: the poller publishes the round number after taking
/// its first `POST_SEQ` sample; the poster opens its post bracket only after
/// observing it. Guarantees the bracket lands inside the poller's gapless
/// witness window on any host interleaving. `u32::MAX` = not polling yet.
static POLLING: AtomicU32 = AtomicU32::new(u32::MAX);

/// Post-syscall overlap witness: odd while the poster is inside its
/// `event_post` bracket for the current round, even otherwise.
static POST_SEQ: AtomicU32 = AtomicU32::new(0);

/// Rounds whose poll bracket provably overlapped the poster's bracket.
static ARMED: AtomicU32 = AtomicU32::new(0);

/// Payloads consumed by the poll loop. Must equal CYCLES.
static CONSUMED: AtomicU32 = AtomicU32::new(0);

/// First failure code observed by either child (0 = none). See
/// `failure_message` for the code map.
static FAILURE: AtomicU32 = AtomicU32::new(0);

fn fail(code: u32)
{
    let _ = FAILURE.compare_exchange(0, code, Ordering::AcqRel, Ordering::Relaxed);
}

fn failure_message(code: u32) -> &'static str
{
    match code
    {
        1 => "stress::event_try_recv_post_race: try_recv returned an unexpected error",
        2 => "stress::event_try_recv_post_race: poll hit returned the wrong payload",
        3 =>
        {
            "stress::event_try_recv_post_race: gate wait returned zero/wrong bits \
              (premature park resume — #352 variant B)"
        }
        5 => "stress::event_try_recv_post_race: queue not empty after consume (duplicated wake)",
        6 => "stress::event_try_recv_post_race: poster event_post failed",
        7 => "stress::event_try_recv_post_race: poster gate send failed",
        8 => "stress::event_try_recv_post_race: poller ack send failed",
        9 => "stress::event_try_recv_post_race: poster ack wait failed",
        _ => "stress::event_try_recv_post_race: unknown failure code",
    }
}

/// Spawn one pinned child with copies of the four shared caps (eq, gate, ack,
/// done) at the given per-cap rights, packing the child-side slots into the
/// entry arg 16 bits apiece in that order.
fn start_pinned_child(
    ctx: &TestContext,
    caps: [u32; 4],
    rights: [u64; 4],
    entry: fn(u64) -> !,
    stack_idx: usize,
    cpu: u32,
) -> Result<crate::spawn::SpawnedChild, &'static str>
{
    let child = spawn::new_child(ctx)
        .map_err(|_| "stress::event_try_recv_post_race: spawn child failed")?;
    let mut arg = 0u64;
    for (i, (&cap, &r)) in caps.iter().zip(rights.iter()).enumerate()
    {
        let slot = cap_copy(cap, child.cs, r)
            .map_err(|_| "stress::event_try_recv_post_race: cap_copy into child failed")?;
        arg |= u64::from(slot) << (16 * i);
    }
    // SAFETY: stack_idx is unique per child; the children live for the whole
    // cell and are reaped after both report done.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[stack_idx]) });
    spawn::configure_and_start_pinned(&child, entry, stack, arg, cpu)
        .map_err(|_| "stress::event_try_recv_post_race: start child failed")?;
    Ok(child)
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::event_try_recv_post_race: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::event_try_recv_post_race SKIP (need 2+ CPUs)");
        return Ok(());
    }

    // Reset shared state: ktest cells run sequentially, but make reruns clean.
    GO.store(u32::MAX, Ordering::Relaxed);
    POLLING.store(u32::MAX, Ordering::Relaxed);
    POST_SEQ.store(0, Ordering::Relaxed);
    ARMED.store(0, Ordering::Relaxed);
    CONSUMED.store(0, Ordering::Relaxed);
    FAILURE.store(0, Ordering::Relaxed);

    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "stress::event_try_recv_post_race: event_queue_create failed")?;
    let gate = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::event_try_recv_post_race: cap_create_notification gate failed")?;
    let ack = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::event_try_recv_post_race: cap_create_notification ack failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::event_try_recv_post_race: cap_create_notification done failed")?;

    // POLLER (CPU 0): try_recv polls + gate park. POSTER (CPU 1): ticket +
    // post + gate signal. Caps packed in (eq, gate, ack, done) order.
    let poller = start_pinned_child(
        ctx,
        [eq, gate, ack, done],
        [RIGHTS_EQ_RECV, RIGHTS_WAIT, RIGHTS_SIGNAL, RIGHTS_SIGNAL],
        poller_entry,
        0,
        0,
    )?;
    let poster = start_pinned_child(
        ctx,
        [eq, gate, ack, done],
        [RIGHTS_EQ_POST, RIGHTS_SIGNAL, RIGHTS_WAIT, RIGHTS_SIGNAL],
        poster_entry,
        1,
        1,
    )?;

    // Wait for both children. A child that fails an assert still raises its
    // done bit (after recording FAILURE); a kernel-level detonation instead
    // hangs here and the softlockup watchdog raises the FAIL.
    let mut acc = 0u64;
    while acc & (BIT_POLLER_DONE | BIT_POSTER_DONE) != (BIT_POLLER_DONE | BIT_POSTER_DONE)
    {
        let bits = notification_wait(done)
            .map_err(|_| "stress::event_try_recv_post_race: notification_wait(done) failed")?;
        acc |= bits;
    }

    // ── Cleanup. ─────────────────────────────────────────────────────────────
    cap_delete(poller.th)
        .map_err(|_| "stress::event_try_recv_post_race: cap_delete poller th failed")?;
    cap_delete(poller.cs)
        .map_err(|_| "stress::event_try_recv_post_race: cap_delete poller cs failed")?;
    cap_delete(poster.th)
        .map_err(|_| "stress::event_try_recv_post_race: cap_delete poster th failed")?;
    cap_delete(poster.cs)
        .map_err(|_| "stress::event_try_recv_post_race: cap_delete poster cs failed")?;
    cap_delete(eq).map_err(|_| "stress::event_try_recv_post_race: cap_delete eq failed")?;
    cap_delete(gate).map_err(|_| "stress::event_try_recv_post_race: cap_delete gate failed")?;
    cap_delete(ack).map_err(|_| "stress::event_try_recv_post_race: cap_delete ack failed")?;
    cap_delete(done).map_err(|_| "stress::event_try_recv_post_race: cap_delete done failed")?;

    let failure = FAILURE.load(Ordering::Acquire);
    if failure != 0
    {
        return Err(failure_message(failure));
    }

    let armed = ARMED.load(Ordering::Acquire);
    let consumed = CONSUMED.load(Ordering::Acquire);
    crate::log_u64(
        "ktest: stress::event_try_recv_post_race armed=",
        u64::from(armed),
    );

    if consumed != CYCLES
    {
        return Err(
            "stress::event_try_recv_post_race: payload conservation violated \
                    (CONSUMED != CYCLES)",
        );
    }
    if armed < CYCLES / 4
    {
        return Err(
            "stress::event_try_recv_post_race: under-armed (< CYCLES/4 overlap \
                    candidates) — the POLLING handshake is broken; do not lower \
                    the floor",
        );
    }

    Ok(())
}

// ── Child entries ───────────────────────────────────────────────────────────

/// Decode the four packed 16-bit cap slots shared by both child entries.
// cast_possible_truncation: each field is a cap slot index < 2^16.
#[allow(clippy::cast_possible_truncation)]
fn decode(arg: u64) -> (u32, u32, u32, u32)
{
    (
        (arg & 0xFFFF) as u32,
        ((arg >> 16) & 0xFFFF) as u32,
        ((arg >> 32) & 0xFFFF) as u32,
        ((arg >> 48) & 0xFFFF) as u32,
    )
}

/// POLLER: per round, spin until the ticket appears, publish the `POLLING`
/// handshake, hammer `event_try_recv` under gapless `POST_SEQ` witness
/// brackets until the payload lands, then park on the gate notification (the
/// second park that detonates a leaked link) and assert the queue is empty
/// before acking the round.
fn poller_entry(arg: u64) -> !
{
    let (eq, gate, ack, done) = decode(arg);
    let wouldblock = SyscallError::WouldBlock as i64;

    'rounds: for c in 0..CYCLES
    {
        while GO.load(Ordering::Acquire) != c
        {
            // A poster-side failure means the ticket never appears; bail
            // instead of spinning the pinned CPU forever.
            if FAILURE.load(Ordering::Acquire) != 0
            {
                break 'rounds;
            }
            core::hint::spin_loop();
        }

        // First witness sample, then the poll-loop handshake: the poster's
        // bracket opens strictly after this sample (Release/Acquire on
        // POLLING), and each poll's exit sample seeds the next poll's entry
        // sample, so the brackets tile gaplessly until the consuming poll —
        // the bracket must land odd-or-changed inside one of them.
        let mut s_prev = POST_SEQ.load(Ordering::Acquire);
        POLLING.store(c, Ordering::Release);

        let mut overlap = false;
        loop
        {
            let r = event_try_recv(eq);
            let s_now = POST_SEQ.load(Ordering::Acquire);
            if s_prev % 2 == 1 || s_prev != s_now
            {
                overlap = true;
            }
            s_prev = s_now;
            match r
            {
                Ok(payload) =>
                {
                    if payload != u64::from(c)
                    {
                        fail(2);
                        break 'rounds;
                    }
                    CONSUMED.fetch_add(1, Ordering::AcqRel);
                    break;
                }
                Err(e) if e == wouldblock =>
                {
                    // The handshaked poster owes this round's payload; every
                    // miss is one more try-once racing the post. A poster-side
                    // failure means it will never land — bail.
                    if FAILURE.load(Ordering::Acquire) != 0
                    {
                        break 'rounds;
                    }
                }
                Err(_) =>
                {
                    fail(1);
                    break 'rounds;
                }
            }
        }
        if overlap
        {
            ARMED.fetch_add(1, Ordering::AcqRel);
        }

        // THE SECOND PARK. On the old kernel a leaked try-once link detonates
        // here: either the poster's gate send double-links (kernel panic) or
        // the stale link resumes this wait prematurely with no bits deposited.
        let expected = 1u64 << (c % 2);
        match notification_wait(gate)
        {
            Ok(bits) if bits == expected =>
            {}
            _ =>
            {
                fail(3);
                break 'rounds;
            }
        }

        // Exactly one payload per round: the queue must now be empty.
        if event_try_recv(eq) != Err(wouldblock)
        {
            fail(5);
            break 'rounds;
        }

        if notification_send(ack, 1u64 << (c % 2)).is_err()
        {
            fail(8);
            break 'rounds;
        }
    }

    // On a failure exit the poster may be blocked in its ack wait; release it
    // so it observes FAILURE and terminates (the controller then reports the
    // stored code instead of hanging). FAILURE is published before this send.
    if FAILURE.load(Ordering::Acquire) != 0
    {
        notification_send(ack, 1).ok();
    }
    notification_send(done, BIT_POLLER_DONE).ok();
    thread_exit()
}

/// POSTER: per round, wait for the poller's previous-round ack, publish the
/// ticket, wait for the poller's `POLLING` handshake, post the payload inside
/// the `POST_SEQ` bracket, and signal the gate.
fn poster_entry(arg: u64) -> !
{
    let (eq, gate, ack, done) = decode(arg);

    'rounds: for c in 0..CYCLES
    {
        if c > 0
        {
            if notification_wait(ack).is_err()
            {
                fail(9);
                break 'rounds;
            }
            // A failed poller releases this wait once and stops acking;
            // observe its stored code and terminate instead of blocking on
            // the next round's ack.
            if FAILURE.load(Ordering::Acquire) != 0
            {
                break 'rounds;
            }
        }

        GO.store(c, Ordering::Release);

        // Open the bracket only once the poller is provably inside its
        // witness window (first sample taken, handshake published) — arming
        // is structural, not a timing bet. A poller-side failure means the
        // handshake never appears; bail instead of spinning forever.
        while POLLING.load(Ordering::Acquire) != c
        {
            if FAILURE.load(Ordering::Acquire) != 0
            {
                break 'rounds;
            }
            core::hint::spin_loop();
        }

        POST_SEQ.store(2 * c + 1, Ordering::Release);
        if event_post(eq, u64::from(c)).is_err()
        {
            fail(6);
            break 'rounds;
        }
        POST_SEQ.store(2 * c + 2, Ordering::Release);

        if notification_send(gate, 1u64 << (c % 2)).is_err()
        {
            fail(7);
            break 'rounds;
        }
    }

    // On a failure exit the poller may be blocked in its gate wait (a failed
    // post/gate-send never signals it); release it so it observes FAILURE and
    // terminates with the stored code instead of hanging to the watchdog. Its
    // subsequent assert no-ops (fail() keeps the first code).
    if FAILURE.load(Ordering::Acquire) != 0
    {
        notification_send(gate, 1).ok();
    }
    notification_send(done, BIT_POSTER_DONE).ok();
    thread_exit()
}
