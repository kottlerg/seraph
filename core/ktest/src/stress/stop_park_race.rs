// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_park_race.rs

//! Stress: stop a thread while it is entering a blocking syscall — a
//! notification wait, an IPC call, a sleep — and check that the restarted
//! thread's syscall returns either its genuine result or `Interrupted`.
//!
//! ## The hazard
//!
//! `sys_thread_stop` decides whether to cancel a park from the target's
//! state. A target read as `Running` that parks before the stop's commit
//! would have `Stopped` written over its `Blocked` park with nothing
//! cancelled: still registered as the source's waiter (or on the sleep list),
//! and, once restarted, resuming with no deposit — a notification wait
//! returning 0 bits nobody sent, a call tripping the spurious-resume
//! assertion. The stop now snapshots a per-TCB park generation with the
//! state, cancels the park it saw, and commits only if no park was committed
//! since, retrying otherwise
//! (core/kernel/docs/thread-lifecycle-and-sleep.md § `sys_thread_stop`
//! Cross-CPU Stop Protocol).
//!
//! ## How this exercises it
//!
//! One peer per wait kind, pinned to CPU 1, loops: publish "about to park"
//! (an atomic generation), park, publish its result. The controller, pinned
//! to CPU 0, waits for each "about to park", spins a varying few
//! microseconds, then stops and restarts the peer, landing the stop before,
//! during, and after the park commit. A peer whose park the stop missed is
//! released by its genuine waker: the controller's rescue notification, the
//! IPC server's reply, or the sleep's deadline. Results:
//!
//! - notification wait: `Ok(RESCUE_BITS)` or `Interrupted`;
//! - IPC call: `Ok` with the server's reply label, or `Interrupted`;
//! - sleep: `Ok` or `Interrupted`.
//!
//! A stop lands on a committed park only when the peer's CPU runs from its
//! announcement into its park within the controller's varying spin, and, for
//! the IPC call, before the server's CPU answers the call, which a host that
//! runs the guest's CPUs late may do in few rounds or none. So after a
//! kind's [`CYCLES`] fixed rounds, while no stop has cancelled one of its
//! parks, held rounds run, up to [`super::MAX_EXTRA_ROUNDS`] ([`HELD`] set):
//! the controller sleeps [`HOLD_MS`] after the announcement before its stop,
//! a sleep peer sleeps [`HELD_SLEEP_MS`] instead, so the hold ends inside
//! its sleep, and the IPC server holds its reply to each call it receives
//! until the controller has stopped and restarted the caller, which it does
//! once the server has published that it received the round's call
//! ([`RECEIVED`], bounded by [`APPROACH_WAIT_US`]), so the stop lands on a
//! caller waiting for its reply. The host must run the peer from its
//! announcement into its park within the hold in one held round (for the
//! call, run the server through one receive), not run CPUs at once
//! throughout. Each kind's log counts the held rounds run.
//!
//! Anything else fails the test, as does a kind for which no stop cancelled a
//! park (the race never armed for it, in the held rounds too), a peer that
//! never approaches its park within [`APPROACH_WAIT_US`] (one that exited,
//! such as a call peer whose IPC
//! buffer registration failed), and a peer that reports no result within
//! [`RESULT_WAIT_US`] (a call whose server has exited blocks for good). The
//! kernel's debug assertions (the spurious-resume tripwire, the pop-time
//! sleep-list checks) are tripwires too.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::IpcMessage;
use ipc::recv_guard::RecvGuard;
use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, system_info, thread_exit, thread_set_affinity,
    thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Fixed stop/start races per wait kind.
const CYCLES: u32 = 150;

/// Bits the controller's rescue send delivers to a notification peer.
const RESCUE_BITS: u64 = 0x5A;

/// Reply label the IPC server answers every call with.
const REPLY_LABEL: u64 = 0x5EED;

/// A sleep peer's sleep: long enough to be parked when the stop lands.
const SLEEP_MS: u64 = 2;

/// A sleep peer's sleep in a held round: longer than the controller's hold
/// ([`HOLD_MS`]), so a hold that the controller's own CPU stretches still
/// ends inside it.
const HELD_SLEEP_MS: u64 = 50;

/// The controller's hold, in a held round, between the peer's announcement
/// and its stop, in milliseconds (one `thread_sleep`).
const HOLD_MS: u64 = 1;

/// Controller spins this many rounds for a peer's result before yielding
/// (and, for a notification peer, rescuing it).
const RESULT_SPINS: u32 = 200_000;

/// Bound on the controller's wait for a peer's result, in microseconds;
/// past it the peer is taken as blocked for good (a call whose server has
/// exited, a park nothing wakes) and the race fails rather than hangs.
///
/// Applied through [`crate::scaled_bound`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs.
const RESULT_WAIT_US: u64 = 2_000_000;

/// Bound on the controller's wait for a peer to announce its next park, in
/// microseconds. A live peer announces at once after the controller's
/// acknowledgement; past the bound, or once the peer has exited, the race
/// fails rather than hangs.
///
/// Applied through [`crate::scaled_bound`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs.
const APPROACH_WAIT_US: u64 = 2_000_000;

/// Spins between the controller's polls of the peer's exit and the clock
/// (syscalls) while it waits for a park announcement; between polls it only
/// reads the handshake.
const POLL_SPINS: u32 = 1024;

/// Peer result codes.
const RESULT_GENUINE: u32 = 1;
const RESULT_INTERRUPTED: u32 = 2;
const RESULT_BAD: u32 = 3;

/// Peer → controller handshake: the cycle the peer is about to park in, and
/// the cycle whose result it has published in [`RESULT`]. Cycles count from
/// 1; a peer exits after publishing cycle [`CYCLES`].
static PARKING: AtomicU32 = AtomicU32::new(0);
static FINISHED: AtomicU32 = AtomicU32::new(0);
static RESULT: AtomicU32 = AtomicU32::new(0);
/// Controller → peer: the last cycle whose result the controller consumed. A
/// peer starts cycle `n + 1` only after `ACKED == n`, and exits only after
/// `ACKED == CYCLES`, so it never runs ahead of the race it is part of.
static ACKED: AtomicU32 = AtomicU32::new(0);
/// Controller → peer: the phase's last cycle, stored before that cycle's
/// [`ACKED`]; `u32::MAX` while the phase runs on. The peer exits once the
/// controller has consumed it.
static END: AtomicU32 = AtomicU32::new(u32::MAX);
/// Controller → peer and server: set before the [`ACKED`] that starts the
/// first held round, so every held round's park, and only a held round's,
/// sees it.
static HELD: AtomicU32 = AtomicU32::new(0);
/// Server → controller: the cycle of the call the IPC server last received
/// (the call's label).
static RECEIVED: AtomicU32 = AtomicU32::new(0);
/// Controller → server: in a held round, the server replies to the call of
/// cycle `n` only once this is at least `n`.
static REPLY_GATE: AtomicU32 = AtomicU32::new(0);

/// IPC buffers for the call peer and the server (one live user each).
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);
// Used only by the IPC phase's peer, which runs alone.
static mut PEER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);
// Used only by the IPC phase's server, which runs alone.
static mut SERVER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

/// Which park a phase's peer races.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind
{
    Notification,
    Call,
    Sleep,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_park_race: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::stop_park_race SKIP (need 2+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, 0)
        .map_err(|_| "stress::stop_park_race: pin controller failed")?;
    let server_cpu = u32::try_from(
        2u64.checked_rem(cpus)
            .ok_or("stress::stop_park_race: CpuCount is zero")?,
    )
    .unwrap_or(0);
    let result = all_phases(ctx, server_cpu);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_park_race: restore controller affinity failed");
    result?;
    restore
}

/// One kind's log labels and its never-armed failure.
struct KindLabels
{
    interrupted: &'static str,
    extra_rounds: &'static str,
    never_armed: &'static str,
}

/// Run one phase per kind; each must see at least one cancelled park.
fn all_phases(ctx: &TestContext, server_cpu: u32) -> TestResult
{
    for (kind, labels) in [
        (
            Kind::Notification,
            KindLabels {
                interrupted: "ktest: stress::stop_park_race notification interrupted=",
                extra_rounds: "ktest: stress::stop_park_race notification extra_rounds=",
                never_armed: "stress::stop_park_race: no stop cancelled a notification wait \
                              (never armed)",
            },
        ),
        (
            Kind::Call,
            KindLabels {
                interrupted: "ktest: stress::stop_park_race call interrupted=",
                extra_rounds: "ktest: stress::stop_park_race call extra_rounds=",
                never_armed: "stress::stop_park_race: no stop cancelled an IPC call (never armed)",
            },
        ),
        (
            Kind::Sleep,
            KindLabels {
                interrupted: "ktest: stress::stop_park_race sleep interrupted=",
                extra_rounds: "ktest: stress::stop_park_race sleep extra_rounds=",
                never_armed: "stress::stop_park_race: no stop cancelled a sleep (never armed)",
            },
        ),
    ]
    {
        let seen = phase(ctx, kind, server_cpu)?;
        crate::log_u64(labels.interrupted, seen.interrupted);
        crate::log_u64(labels.extra_rounds, u64::from(seen.extra_rounds));
        if seen.interrupted == 0
        {
            return Err(labels.never_armed);
        }
    }
    Ok(())
}

/// What a phase's rounds saw.
struct Seen
{
    /// Parks that ended `Interrupted`.
    interrupted: u64,
    /// Held rounds run after the fixed rounds.
    extra_rounds: u32,
}

/// When a round's controller stops the peer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Timing
{
    /// After a varying spin of its own once the peer has announced its park.
    Raced,
    /// Once the peer has been given time to park: [`HOLD_MS`] after its
    /// announcement, or, for the IPC call, once the server has received the
    /// call and holds its reply.
    Held,
}

/// The peer's source and, for the IPC kind, the server answering it.
struct PhaseObjects
{
    source: Option<u64>,
    server: Option<spawn::SpawnedChild>,
}

/// Run [`CYCLES`] stop/start races against one peer of `kind`, then held
/// rounds ([`rounds`]); returns what they saw. Everything the phase created
/// is deleted on every path, the race's own error taking precedence.
fn phase(ctx: &TestContext, kind: Kind, server_cpu: u32) -> Result<Seen, &'static str>
{
    for counter in [&PARKING, &FINISHED, &ACKED, &HELD, &RECEIVED, &REPLY_GATE]
    {
        counter.store(0, Ordering::Release);
    }
    END.store(u32::MAX, Ordering::Release);

    let mut objects = PhaseObjects {
        source: None,
        server: None,
    };
    let mut peer = None;
    let result = setup(ctx, kind, server_cpu, &mut objects, &mut peer).and_then(|()| {
        let peer_th = peer.as_ref().map_or(0, |p: &spawn::SpawnedChild| p.th);
        rounds(kind, peer_th, objects.source)
    });
    let torn_down = teardown(peer.as_mut(), &mut objects);
    let seen = result?;
    torn_down.map(|()| seen)
}

/// Run the [`CYCLES`] fixed rounds and then, while no stop has cancelled a
/// park, held rounds until one has or [`super::MAX_EXTRA_ROUNDS`] have run,
/// stopping at the first round that fails. Each round's result is consumed
/// ([`ACKED`]) only after the next round's kind is published: [`HELD`]
/// before the first held round, [`END`] after the last round.
fn rounds(kind: Kind, peer: u64, source: Option<u64>) -> Result<Seen, &'static str>
{
    let mut seen = Seen {
        interrupted: 0,
        extra_rounds: 0,
    };
    let mut cycle = 0u32;
    loop
    {
        cycle = cycle.saturating_add(1);
        let timing = if cycle > CYCLES
        {
            seen.extra_rounds = seen.extra_rounds.saturating_add(1);
            Timing::Held
        }
        else
        {
            Timing::Raced
        };
        if race_once(kind, peer, source, cycle, timing)?
        {
            seen.interrupted = seen.interrupted.saturating_add(1);
        }
        let more = cycle < CYCLES
            || (seen.interrupted == 0 && seen.extra_rounds < super::MAX_EXTRA_ROUNDS);
        if !more
        {
            END.store(cycle, Ordering::Release);
        }
        else if cycle == CYCLES
        {
            HELD.store(1, Ordering::Release);
        }
        ACKED.store(cycle, Ordering::Release);
        if !more
        {
            return Ok(seen);
        }
    }
}

/// Create the phase's source (and server), then start the peer pinned to
/// CPU 1. Each created object is recorded before the next step so the
/// teardown sees it whatever fails.
fn setup(
    ctx: &TestContext,
    kind: Kind,
    server_cpu: u32,
    objects: &mut PhaseObjects,
    peer: &mut Option<spawn::SpawnedChild>,
) -> TestResult
{
    objects.source = match kind
    {
        Kind::Notification => Some(
            cap_create_notification(ctx.memory_base)
                .map_err(|_| "stress::stop_park_race: create notification failed")?,
        ),
        Kind::Call => Some(
            cap_create_endpoint(ctx.memory_base)
                .map_err(|_| "stress::stop_park_race: create endpoint failed")?,
        ),
        Kind::Sleep => None,
    };
    if kind == Kind::Call
    {
        let ep = objects.source.unwrap_or(0);
        let s = spawn::new_child(ctx).map_err(|_| "stress::stop_park_race: spawn server failed")?;
        let s = objects.server.insert(s);
        let s_ep = cap_copy(ep, s.cs, RIGHTS_ALL)
            .map_err(|_| "stress::stop_park_race: cap_copy server ep failed")?;
        // SAFETY: `STRESS_STACKS` is a static array of stacks, reached only through `addr_of!`.
        let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(super::STRESS_STACKS), 1) }?;
        // SAFETY: the stack is `super::STRESS_STACKS[1]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start_pinned(s, server_entry, stack, s_ep, server_cpu) }
            .map_err(|_| "stress::stop_park_race: start server failed")?;
    }

    let p = spawn::new_child(ctx).map_err(|_| "stress::stop_park_race: spawn peer failed")?;
    let p = peer.insert(p);
    let p_source = match objects.source
    {
        Some(src) => cap_copy(src, p.cs, RIGHTS_ALL)
            .map_err(|_| "stress::stop_park_race: cap_copy peer source failed")?,
        None => 0,
    };
    let entry: extern "C" fn(u64) -> ! = match kind
    {
        Kind::Notification => notif_peer,
        Kind::Call => call_peer,
        Kind::Sleep => sleep_peer,
    };
    // SAFETY: `STRESS_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(super::STRESS_STACKS), 0) }?;
    // SAFETY: the stack is `super::STRESS_STACKS[0]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(p, entry, stack, p_source, 1) }
        .map_err(|_| "stress::stop_park_race: start peer failed")
}

/// Delete the peer, the server, and the source. Deleting a thread stops it
/// wherever it is, so the stacks are free for the next phase.
fn teardown(peer: Option<&mut spawn::SpawnedChild>, objects: &mut PhaseObjects) -> TestResult
{
    let mut ok = true;
    for child in peer.into_iter().chain(objects.server.as_mut())
    {
        ok &= child.delete_thread().is_ok();
        ok &= child.delete_cspace().is_ok();
    }
    if let Some(src) = objects.source
    {
        ok &= cap_delete(src).is_ok();
    }
    if ok
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_park_race: teardown failed")
    }
}

/// One race: wait for the peer to approach its park, stop and restart it
/// (`timing` says when), release it if the stop missed, and check its
/// result. Returns whether the park ended `Interrupted`; the caller consumes
/// the result ([`ACKED`]).
fn race_once(
    kind: Kind,
    peer: u64,
    source: Option<u64>,
    cycle: u32,
    timing: Timing,
) -> Result<bool, &'static str>
{
    await_parking(peer, cycle)?;
    match timing
    {
        Timing::Raced =>
        {
            // Vary the stop's phase against the park: 0 to 4095 spins (a
            // multiplicative hash of the cycle).
            for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
            {
                core::hint::spin_loop();
            }
        }
        Timing::Held => hold(kind, cycle)?,
    }
    thread_stop(peer).map_err(|_| "stress::stop_park_race: thread_stop failed")?;
    thread_start(peer).map_err(|_| "stress::stop_park_race: thread_start failed")?;
    // A held call's server replies only now, to a caller the stop cancelled.
    REPLY_GATE.store(cycle, Ordering::Release);
    await_result(kind, source, cycle)?;
    let result = RESULT.load(Ordering::Acquire);
    match result
    {
        RESULT_GENUINE => Ok(false),
        RESULT_INTERRUPTED => Ok(true),
        _ => Err(
            "stress::stop_park_race: a stopped park returned neither its genuine result \
                  nor Interrupted",
        ),
    }
}

/// A held round's wait before its stop: for the IPC call, until the server
/// has received the call of `cycle` ([`RECEIVED`]), bounded by
/// [`APPROACH_WAIT_US`]; it then holds its reply until the controller's
/// [`REPLY_GATE`]. For the other kinds, a [`HOLD_MS`] sleep.
fn hold(kind: Kind, cycle: u32) -> TestResult
{
    match kind
    {
        Kind::Call => super::require_within(
            crate::scaled_bound(APPROACH_WAIT_US),
            "stress::stop_park_race: the server did not receive a held round's call",
            || RECEIVED.load(Ordering::Acquire) == cycle,
        ),
        Kind::Notification | Kind::Sleep =>
        {
            thread_sleep(HOLD_MS).map_err(|_| "stress::stop_park_race: hold sleep failed")
        }
    }
}

/// Spin until the peer `peer` announces it is about to park in cycle `cycle`,
/// for at most [`APPROACH_WAIT_US`] on the `ElapsedUs` clock. The peer's exit
/// and the clock are polled every [`POLL_SPINS`] spins, so the reaction to
/// the announcement stays tight; a peer that exited, or that never
/// announced in time, fails the race.
fn await_parking(peer: u64, cycle: u32) -> TestResult
{
    let bound = crate::scaled_bound(APPROACH_WAIT_US);
    let start = elapsed_us()?;
    let mut spins = 0u32;
    while PARKING.load(Ordering::Acquire) != cycle
    {
        spins = spins.wrapping_add(1);
        if spins.is_multiple_of(POLL_SPINS)
            && (spawn::is_exited(peer)? || elapsed_us()?.saturating_sub(start) > bound)
        {
            return Err("stress::stop_park_race: the peer never approached its park");
        }
        core::hint::spin_loop();
    }
    Ok(())
}

/// Wait for the peer to publish cycle `cycle`'s result: spin [`RESULT_SPINS`]
/// rounds, then release a notification peer through its genuine waker
/// (once) and yield in 1 ms sleeps, for at most [`RESULT_WAIT_US`] on the
/// `ElapsedUs` clock.
fn await_result(kind: Kind, source: Option<u64>, cycle: u32) -> TestResult
{
    let bound = crate::scaled_bound(RESULT_WAIT_US);
    let start = elapsed_us()?;
    let mut spins = 0u32;
    let mut rescued = false;
    while FINISHED.load(Ordering::Acquire) != cycle
    {
        if spins < RESULT_SPINS
        {
            spins = spins.saturating_add(1);
            core::hint::spin_loop();
            continue;
        }
        // The stop missed the park, or the waker needs this CPU: release the
        // peer through its genuine waker, then yield until it reports.
        if kind == Kind::Notification && !rescued
        {
            notification_send(source.unwrap_or(0), RESCUE_BITS)
                .map_err(|_| "stress::stop_park_race: rescue send failed")?;
            rescued = true;
        }
        if elapsed_us()?.saturating_sub(start) > bound
        {
            return Err("stress::stop_park_race: the peer never reported its result");
        }
        let _ = thread_sleep(1);
    }
    Ok(())
}

/// Microseconds since boot; the clock the announcement and result waits are
/// bounded on.
fn elapsed_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "stress::stop_park_race: system_info(ElapsedUs) failed")
}

/// Peer loop: announce each cycle's park, run it, classify and publish,
/// until the controller has consumed the phase's last cycle ([`END`]). The
/// peer exits only then: a park that returned at once (a rescue left
/// pending by an earlier cycle) must not let the thread exit before the
/// controller's stop lands.
fn peer_loop(mut park: impl FnMut(u32) -> u32) -> !
{
    let mut cycle = 1u32;
    loop
    {
        let consumed = cycle.saturating_sub(1);
        while ACKED.load(Ordering::Acquire) != consumed
        {
            core::hint::spin_loop();
        }
        if END.load(Ordering::Acquire) == consumed
        {
            thread_exit()
        }
        PARKING.store(cycle, Ordering::Release);
        let result = park(cycle);
        RESULT.store(result, Ordering::Release);
        FINISHED.store(cycle, Ordering::Release);
        cycle = cycle.saturating_add(1);
    }
}

fn is_interrupted(e: i64) -> bool
{
    e == SyscallError::Interrupted as i64
}

extern "C" fn notif_peer(arg: u64) -> !
{
    let sig = arg;
    peer_loop(|_| match notification_wait(sig)
    {
        Ok(bits) if bits == RESCUE_BITS => RESULT_GENUINE,
        Err(e) if is_interrupted(e) => RESULT_INTERRUPTED,
        _ => RESULT_BAD,
    })
}

extern "C" fn call_peer(arg: u64) -> !
{
    let ep = arg;
    // Sole live user of PEER_IPC_BUF (phases run sequentially).
    let buf = core::ptr::addr_of_mut!(PEER_IPC_BUF).cast::<u64>();
    // SAFETY: `buf` is this thread's own page-aligned IPC page (the static above),
    // registered by one thread at a time; no Rust object lives in it, and the
    // thread reaches it only through the raw `buf` pointer.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        thread_exit()
    }
    peer_loop(|cycle| {
        // The label names the cycle, which the server publishes.
        // SAFETY: `buf` was registered as this thread's IPC buffer above.
        match unsafe { ipc::ipc_call(ep, &IpcMessage::new(u64::from(cycle)), buf) }
        {
            Ok(reply) if reply.label == REPLY_LABEL => RESULT_GENUINE,
            Err(e) if is_interrupted(e) => RESULT_INTERRUPTED,
            _ => RESULT_BAD,
        }
    })
}

extern "C" fn sleep_peer(_arg: u64) -> !
{
    peer_loop(|_| {
        let ms = if HELD.load(Ordering::Acquire) == 0
        {
            SLEEP_MS
        }
        else
        {
            HELD_SLEEP_MS
        };
        match thread_sleep(ms)
        {
            Ok(()) => RESULT_GENUINE,
            Err(e) if is_interrupted(e) => RESULT_INTERRUPTED,
            Err(_) => RESULT_BAD,
        }
    })
}

/// IPC server: answer every call with [`REPLY_LABEL`], publishing each
/// call's cycle (its label) in [`RECEIVED`] and, in a held round ([`HELD`]),
/// holding the reply until the controller's [`REPLY_GATE`] reaches it; a reply whose caller
/// was cancelled meanwhile fails and is ignored. Runs until deleted (or
/// until its endpoint goes first); a `RecvGuard` bounds the retries of a
/// failed receive (docs/ipc-design.md § Receive-Failure Policy).
extern "C" fn server_entry(arg: u64) -> !
{
    let ep = arg;
    // Sole live user of SERVER_IPC_BUF (phases run sequentially).
    let buf = core::ptr::addr_of_mut!(SERVER_IPC_BUF).cast::<u64>();
    // SAFETY: `buf` is this thread's own page-aligned IPC page (the static above),
    // registered by one thread at a time; no Rust object lives in it, and the
    // thread reaches it only through the raw `buf` pointer.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        thread_exit()
    }
    let mut guard = RecvGuard::new(crate::tally::recv_diag);
    loop
    {
        // SAFETY: `buf` was registered as this thread's IPC buffer above.
        match unsafe { ipc::ipc_recv(ep, buf) }
        {
            Ok(call) =>
            {
                guard.on_success();
                // Every call carries its cycle, a `u32`.
                let received = u32::try_from(call.label).unwrap_or(0);
                RECEIVED.store(received, Ordering::Release);
                // Sleeps, so a server sharing the controller's CPU leaves it
                // to the controller's stop.
                while HELD.load(Ordering::Acquire) != 0
                    && REPLY_GATE.load(Ordering::Acquire) < received
                {
                    let _ = thread_sleep(1);
                }
                // SAFETY: as above.
                let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(REPLY_LABEL), buf) };
            }
            Err(e) if e == SyscallError::InvalidCapability as i64 => thread_exit(),
            Err(e) => guard.on_failure(e),
        }
    }
}
