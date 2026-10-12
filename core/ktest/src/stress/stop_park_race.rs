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
//! Anything else fails the test, as does a run in which no stop cancelled a
//! park (the race never armed). The kernel's debug assertions (the
//! spurious-resume tripwire, the pop-time sleep-list checks) are tripwires too.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, system_info, thread_exit, thread_set_affinity,
    thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Stop/start races per wait kind.
const CYCLES: u32 = 150;

/// Bits the controller's rescue send delivers to a notification peer.
const RESCUE_BITS: u64 = 0x5A;

/// Reply label the IPC server answers every call with.
const REPLY_LABEL: u64 = 0x5EED;

/// A sleep peer's sleep: long enough to be parked when the stop lands.
const SLEEP_MS: u64 = 2;

/// Controller spins this many rounds for a peer's result before yielding
/// (and, for a notification peer, rescuing it).
const RESULT_SPINS: u32 = 200_000;

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

/// Total `Interrupted` results across kinds.
static INTERRUPTED: AtomicU64 = AtomicU64::new(0);

/// IPC buffers for the call peer and the server (one live user each).
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);
// SAFETY: used only by the IPC phase's peer, which runs alone.
static mut PEER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);
// SAFETY: used only by the IPC phase's server, which runs alone.
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
    INTERRUPTED.store(0, Ordering::Relaxed);
    thread_set_affinity(ctx.thread_cap, 0)
        .map_err(|_| "stress::stop_park_race: pin controller failed")?;
    let server_cpu = u32::try_from(2 % cpus).unwrap_or(0);
    let mut result = Ok(());
    for kind in [Kind::Notification, Kind::Call, Kind::Sleep]
    {
        result = phase(ctx, kind, server_cpu);
        if result.is_err()
        {
            break;
        }
    }
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_park_race: restore controller affinity failed");
    result?;
    restore?;

    let interrupted = INTERRUPTED.load(Ordering::Relaxed);
    crate::log_u64("ktest: stress::stop_park_race interrupted=", interrupted);
    if interrupted == 0
    {
        return Err("stress::stop_park_race: no stop ever cancelled a park (never armed)");
    }
    Ok(())
}

/// Run [`CYCLES`] stop/start races against one peer of `kind`.
fn phase(ctx: &TestContext, kind: Kind, server_cpu: u32) -> TestResult
{
    PARKING.store(0, Ordering::Release);
    FINISHED.store(0, Ordering::Release);
    ACKED.store(0, Ordering::Release);

    // The peer's source: a notification, or an endpoint a server answers.
    let source = match kind
    {
        Kind::Notification => cap_create_notification(ctx.memory_base).map(Some),
        Kind::Call => cap_create_endpoint(ctx.memory_base).map(Some),
        Kind::Sleep => Ok(None),
    }
    .map_err(|_| "stress::stop_park_race: create source failed")?;

    let server = if kind == Kind::Call
    {
        let ep = source.unwrap_or(0);
        let s = spawn::new_child(ctx).map_err(|_| "stress::stop_park_race: spawn server failed")?;
        let s_ep = cap_copy(ep, s.cs, RIGHTS_ALL)
            .map_err(|_| "stress::stop_park_race: cap_copy server ep failed")?;
        // SAFETY: stack index 1 is the server's; phases run sequentially.
        let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[1]) });
        spawn::configure_and_start_pinned(&s, server_entry, stack, u64::from(s_ep), server_cpu)
            .map_err(|_| "stress::stop_park_race: start server failed")?;
        Some(s)
    }
    else
    {
        None
    };

    let peer = spawn::new_child(ctx).map_err(|_| "stress::stop_park_race: spawn peer failed")?;
    let p_source = match source
    {
        Some(src) => cap_copy(src, peer.cs, RIGHTS_ALL)
            .map_err(|_| "stress::stop_park_race: cap_copy peer source failed")?,
        None => 0,
    };
    let entry: fn(u64) -> ! = match kind
    {
        Kind::Notification => notif_peer,
        Kind::Call => call_peer,
        Kind::Sleep => sleep_peer,
    };
    // SAFETY: stack index 0 is the peer's; phases run sequentially.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
    spawn::configure_and_start_pinned(&peer, entry, stack, u64::from(p_source), 1)
        .map_err(|_| "stress::stop_park_race: start peer failed")?;

    let mut result = Ok(());
    for cycle in 1..=CYCLES
    {
        result = race_once(kind, peer.th, source, cycle);
        if result.is_err()
        {
            break;
        }
    }

    cap_delete(peer.th).map_err(|_| "stress::stop_park_race: reap peer thread failed")?;
    cap_delete(peer.cs).map_err(|_| "stress::stop_park_race: reap peer cspace failed")?;
    if let Some(s) = server
    {
        cap_delete(s.th).map_err(|_| "stress::stop_park_race: reap server thread failed")?;
        cap_delete(s.cs).map_err(|_| "stress::stop_park_race: reap server cspace failed")?;
    }
    if let Some(src) = source
    {
        cap_delete(src).map_err(|_| "stress::stop_park_race: del source failed")?;
    }
    result
}

/// One race: wait for the peer to approach its park, stop and restart it,
/// release it if the stop missed, and check its result.
fn race_once(kind: Kind, peer: u32, source: Option<u32>, cycle: u32) -> TestResult
{
    while PARKING.load(Ordering::Acquire) != cycle
    {
        core::hint::spin_loop();
    }
    // Vary the stop's phase against the park: 0 to 4095 spins (a
    // multiplicative hash of the cycle).
    for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
    {
        core::hint::spin_loop();
    }
    thread_stop(peer).map_err(|_| "stress::stop_park_race: thread_stop failed")?;
    thread_start(peer).map_err(|_| "stress::stop_park_race: thread_start failed")?;

    let mut spins = 0u32;
    let mut rescued = false;
    while FINISHED.load(Ordering::Acquire) != cycle
    {
        if spins < RESULT_SPINS
        {
            spins += 1;
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
        let _ = thread_sleep(1);
    }
    let result = RESULT.load(Ordering::Acquire);
    ACKED.store(cycle, Ordering::Release);
    match result
    {
        RESULT_GENUINE => Ok(()),
        RESULT_INTERRUPTED =>
        {
            INTERRUPTED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        _ => Err(
            "stress::stop_park_race: a stopped park returned neither its genuine result \
                  nor Interrupted",
        ),
    }
}

/// Peer loop: announce each cycle's park, run it, classify and publish.
fn peer_loop(mut park: impl FnMut() -> u32) -> !
{
    for cycle in 1..=CYCLES
    {
        while ACKED.load(Ordering::Acquire) != cycle - 1
        {
            core::hint::spin_loop();
        }
        PARKING.store(cycle, Ordering::Release);
        let result = park();
        RESULT.store(result, Ordering::Release);
        FINISHED.store(cycle, Ordering::Release);
    }
    // Exit only once the last race is over: a park that returned at once (a
    // rescue left pending by an earlier cycle) must not let the thread exit
    // before the controller's stop lands.
    while ACKED.load(Ordering::Acquire) != CYCLES
    {
        core::hint::spin_loop();
    }
    thread_exit()
}

fn is_interrupted(e: i64) -> bool
{
    e == SyscallError::Interrupted as i64
}

// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
fn notif_peer(arg: u64) -> !
{
    let sig = arg as u32;
    peer_loop(|| match notification_wait(sig)
    {
        Ok(bits) if bits == RESCUE_BITS => RESULT_GENUINE,
        Err(e) if is_interrupted(e) => RESULT_INTERRUPTED,
        _ => RESULT_BAD,
    })
}

// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
fn call_peer(arg: u64) -> !
{
    let ep = arg as u32;
    // SAFETY: sole live user of PEER_IPC_BUF (phases run sequentially).
    let buf = core::ptr::addr_of_mut!(PEER_IPC_BUF).cast::<u64>();
    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }
    peer_loop(|| {
        // SAFETY: `buf` was registered as this thread's IPC buffer above.
        match unsafe { ipc::ipc_call(ep, &IpcMessage::new(1), buf) }
        {
            Ok(reply) if reply.label == REPLY_LABEL => RESULT_GENUINE,
            Err(e) if is_interrupted(e) => RESULT_INTERRUPTED,
            _ => RESULT_BAD,
        }
    })
}

fn sleep_peer(_arg: u64) -> !
{
    peer_loop(|| match thread_sleep(SLEEP_MS)
    {
        Ok(()) => RESULT_GENUINE,
        Err(e) if is_interrupted(e) => RESULT_INTERRUPTED,
        Err(_) => RESULT_BAD,
    })
}

/// IPC server: answer every call with [`REPLY_LABEL`]; a reply whose caller
/// was cancelled meanwhile fails and is ignored. Runs until deleted.
// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
fn server_entry(arg: u64) -> !
{
    let ep = arg as u32;
    // SAFETY: sole live user of SERVER_IPC_BUF (phases run sequentially).
    let buf = core::ptr::addr_of_mut!(SERVER_IPC_BUF).cast::<u64>();
    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }
    loop
    {
        // SAFETY: `buf` was registered as this thread's IPC buffer above.
        if unsafe { ipc::ipc_recv(ep, buf) }.is_ok()
        {
            // SAFETY: as above.
            let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(REPLY_LABEL), buf) };
        }
    }
}
