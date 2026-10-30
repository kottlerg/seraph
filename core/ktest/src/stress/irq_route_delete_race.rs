// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/irq_route_delete_race.rs

//! Stress: deleting an IRQ-routed notification on one CPU while its device
//! interrupt is delivered on another.
//!
//! ## The hazard
//!
//! `irq::dispatch_device_irq` reads a line's routed `NotificationState`
//! without a reference and signals it. The Notification teardown used to
//! clear the route with only the local CPU's interrupts masked and then free
//! the state, so a delivery already running on another CPU could lock, set
//! bits in, and wake through freed memory. The teardown now waits out every
//! line's in-flight deliveries before the free, including one that read a
//! route an earlier replace or clear removed (`irq::unregister_notification`;
//! core/kernel/docs/ipc-internals.md § Notification, Device IRQ delivery).
//!
//! ## How this exercises it
//!
//! The stand-in device is the UART ktest already owns: setting its
//! transmit-empty interrupt enable while the holding register is empty
//! raises its line (`crate::arch::serial::raise_tx_interrupt`). The cell
//! carves that one line from a derived copy of the root Interrupt cap and
//! first proves delivery: a raise must signal a routed notification. Then,
//! each round, the controller, pinned to CPU 0 (the CPU the x86-64 I/O APIC
//! entry targets), creates a notification and routes the line to it, then
//! repeatedly unmasks the line (`SYS_IRQ_ACK`; each delivery masks it again)
//! and raises the interrupt, so deliveries follow one another, while a
//! deleter pinned to CPU 1 waits a varying delay and deletes the
//! notification's only capability. On every other round the deleter first
//! reroutes the line to a spare notification (`SYS_IRQ_REGISTER`), so the
//! delete meets a route a replace already removed, the path whose teardown
//! must still wait out a delivery that read the old route. A raise after the
//! delete finds the line masked and unrouted (or routed to the spare).
//! Required: the kernel survives every round, and in some rounds of each kind
//! the controller began a raise while the deleter's delete (and, on a rerouted
//! round, its reroute before it) was running, and every reroute succeeded (the
//! race armed). The UART interrupt is disabled again when the cell ends.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use init_protocol::InitInfo;
use syscall::{
    RIGHTS_ALL, cap_create_notification, cap_create_thread, cap_delete, cap_derive, irq_ack,
    irq_register, irq_split, notification_wait_timeout, system_info, thread_configure, thread_exit,
    thread_set_affinity, thread_start,
};
use syscall_abi::SystemInfoType;

use crate::arch::serial::{UART_IRQ, quiet_tx_interrupt, raise_tx_interrupt};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Rounds at up to [`crate::UNSCALED_CPUS`] CPUs.
const CYCLES: u32 = 400;
/// Fewest rounds at any width ([`super::scaled_attempts`]).
const MIN_CYCLES: u32 = 40;
const MIN_CPUS: u64 = 2;
const CONTROLLER_CPU: u32 = 0;
const DELETER_CPU: u32 = 1;
/// Raises per round at most; a round ends sooner once the delete landed.
const MAX_RAISES: u32 = 20_000;
/// Raises after the delete was seen, so deliveries also meet a cleared route.
const TRAILING_RAISES: u32 = 16;
/// Wait for the delivery probe's signal, in ms, through [`crate::scaled_bound`].
const PROBE_TIMEOUT_MS: u64 = 1000;
/// Polls (1 ms each) for the deleter's exit, through [`crate::scaled_polls`].
const EXIT_POLLS: u32 = 10_000;

/// Round the controller has published; the deleter acts once per value.
static ROUND: AtomicU32 = AtomicU32::new(0);
/// Notification handle the deleter deletes this round.
static SIG: AtomicU32 = AtomicU32::new(0);
/// The carved line and the spare notification the deleter reroutes it to.
static LINE: AtomicU32 = AtomicU32::new(0);
static SPARE: AtomicU32 = AtomicU32::new(0);
/// Round whose delete (with its reroute, on a rerouted round) the deleter has
/// begun.
static DELETING: AtomicU32 = AtomicU32::new(0);
/// Reroutes the deleter's `SYS_IRQ_REGISTER` refused.
static REROUTE_FAILED: AtomicU32 = AtomicU32::new(0);
/// Last round whose delete the deleter finished.
static DELETED: AtomicU32 = AtomicU32::new(0);
/// Set by the controller to end the deleter.
static QUIT: AtomicU32 = AtomicU32::new(0);

static mut DELETER_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::irq_route_delete_race: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::irq_route_delete_race SKIP (need 2+ CPUs)");
        return Ok(());
    }
    if !crate::serial::is_ready()
    {
        return Err("stress::irq_route_delete_race: UART not initialised");
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::irq_route_delete_race: pin controller failed")?;
    let line = carve_line(ctx);
    let result = line.and_then(|line| {
        let raced = race(ctx, line, super::scaled_attempts(CYCLES, MIN_CYCLES, cpus));
        quiet_tx_interrupt();
        cap_delete(line).ok();
        raced
    });
    quiet_tx_interrupt();
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::irq_route_delete_race: restore controller affinity failed");
    result?;
    restore
}

/// An Interrupt cap naming exactly the UART's line, split from a derived copy
/// of the root Interrupt cap, so the root stays whole.
fn carve_line(ctx: &TestContext) -> Result<u32, &'static str>
{
    // SAFETY: the kernel maps the read-only InitInfo page at `init_info_va`
    // for ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    let copy = cap_derive(info.irq_range_cap, RIGHTS_ALL)
        .map_err(|_| "stress::irq_route_delete_race: derive root Interrupt cap failed")?;
    let Ok((below, from_line)) = irq_split(copy, UART_IRQ)
    else
    {
        cap_delete(copy).ok();
        return Err("stress::irq_route_delete_race: split at the UART line failed");
    };
    cap_delete(below).ok();
    match irq_split(from_line, UART_IRQ + 1)
    {
        Ok((line, above)) =>
        {
            cap_delete(above).ok();
            Ok(line)
        }
        // The range ends at the UART line: `from_line` is the line alone.
        Err(_) => Ok(from_line),
    }
}

/// Prove the stand-in delivers, then run `cycles` delete-during-delivery
/// rounds.
fn race(ctx: &TestContext, line: u32, cycles: u32) -> TestResult
{
    probe_delivery(ctx, line)?;

    let spare = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create spare notification failed")?;
    ROUND.store(0, Ordering::Release);
    DELETED.store(0, Ordering::Release);
    DELETING.store(0, Ordering::Release);
    REROUTE_FAILED.store(0, Ordering::Release);
    QUIT.store(0, Ordering::Release);
    LINE.store(line, Ordering::Release);
    SPARE.store(spare, Ordering::Release);
    let deleter = cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
        .map_err(|_| "stress::irq_route_delete_race: create deleter failed")?;
    let top = ChildStack::top(core::ptr::addr_of!(DELETER_STACK));
    // SAFETY: `deleter_entry` is an `extern "C" fn(u64) -> !` and
    // `DELETER_STACK` is this deleter's own stack for its lifetime.
    let started = unsafe { thread_configure(deleter, deleter_entry as *const () as u64, top, 0) }
        .and_then(|()| thread_set_affinity(deleter, DELETER_CPU))
        .and_then(|()| thread_start(deleter))
        .map_err(|_| "stress::irq_route_delete_race: start deleter failed");
    let raced = started.and_then(|()| rounds(ctx, line, cycles));
    QUIT.store(1, Ordering::Release);
    let exited = spawn::wait_until_exited(deleter, crate::scaled_polls(EXIT_POLLS));
    cap_delete(deleter).ok();
    cap_delete(spare).ok();
    let armed = raced?;
    if REROUTE_FAILED.load(Ordering::Acquire) != 0
    {
        return Err("stress::irq_route_delete_race: a reroute to the spare notification failed");
    }
    exited?;
    crate::log_u64(
        "stress::irq_route_delete_race: armed_routed=",
        u64::from(armed[0]),
    );
    crate::log_u64(
        "stress::irq_route_delete_race: armed_rerouted=",
        u64::from(armed[1]),
    );
    if armed.contains(&0)
    {
        return Err("stress::irq_route_delete_race: no raise overlapped a delete of some kind");
    }
    Ok(())
}

/// Route the line to a fresh notification and require one raise to signal
/// it, so the rounds below are not vacuous.
fn probe_delivery(ctx: &TestContext, line: u32) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create probe notification failed")?;
    let routed = irq_register(line, sig).and_then(|()| irq_ack(line));
    raise_tx_interrupt();
    let bits =
        routed.and_then(|()| notification_wait_timeout(sig, crate::scaled_bound(PROBE_TIMEOUT_MS)));
    quiet_tx_interrupt();
    cap_delete(sig).ok();
    match bits
    {
        Ok(bits) if bits & 1 != 0 => Ok(()),
        Ok(_) => Err("stress::irq_route_delete_race: UART interrupt never delivered"),
        Err(_) => Err("stress::irq_route_delete_race: route or wait on the UART line failed"),
    }
}

/// Whether the deleter reroutes the line to the spare before `round`'s delete.
fn rerouted(round: u32) -> bool
{
    round.is_multiple_of(2)
}

/// The rounds; returns, for direct and rerouted deletes, how many began a
/// raise while the delete was running.
fn rounds(ctx: &TestContext, line: u32, cycles: u32) -> Result<[u32; 2], &'static str>
{
    let mut armed = [0u32; 2];
    for round in 1..=cycles
    {
        let sig = cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::irq_route_delete_race: create notification failed")?;
        if irq_register(line, sig)
            .and_then(|()| irq_ack(line))
            .is_err()
        {
            cap_delete(sig).ok();
            return Err("stress::irq_route_delete_race: route the UART line failed");
        }
        SIG.store(sig, Ordering::Release);
        ROUND.store(round, Ordering::Release);
        let mut raises = 0u32;
        let mut overlapped = false;
        while DELETED.load(Ordering::Acquire) != round && raises < MAX_RAISES
        {
            // Sampled before the raise, so a raise counts as overlapping only
            // when it began while the delete was running (begun, not done).
            let during = DELETING.load(Ordering::Acquire) == round
                && DELETED.load(Ordering::Acquire) != round;
            // Unmask before each raise, since each delivery masks the line;
            // after the delete the ack may fail or find the line unrouted.
            irq_ack(line).ok();
            raise_tx_interrupt();
            raises += 1;
            overlapped |= during;
        }
        if overlapped
        {
            armed[usize::from(rerouted(round))] += 1;
        }
        if DELETED.load(Ordering::Acquire) == round
        {
            for _ in 0..TRAILING_RAISES
            {
                irq_ack(line).ok();
                raise_tx_interrupt();
            }
        }
        quiet_tx_interrupt();
        // Wait for this round's delete (bounded), so the handle is never
        // reused while the deleter still holds it.
        let mut polls = 0;
        while DELETED.load(Ordering::Acquire) != round
        {
            polls += 1;
            if polls > crate::scaled_polls(EXIT_POLLS)
            {
                return Err("stress::irq_route_delete_race: deleter never deleted");
            }
            syscall::thread_sleep(1).ok();
        }
    }
    Ok(armed)
}

/// Deleter: per published round, wait a varying delay, then delete the
/// round's notification; exit on `QUIT`.
extern "C" fn deleter_entry(_arg: u64) -> !
{
    let mut seen = 0u32;
    loop
    {
        let round = ROUND.load(Ordering::Acquire);
        if round == seen
        {
            if QUIT.load(Ordering::Acquire) != 0
            {
                thread_exit();
            }
            core::hint::spin_loop();
            continue;
        }
        seen = round;
        // 0 to 4095 spins (a multiplicative hash of the round), so the delete
        // lands at varying points in the raise sequence.
        for _ in 0..(round.wrapping_mul(2_654_435_761) >> 20)
        {
            core::hint::spin_loop();
        }
        // The window opens before the reroute on a rerouted round, so a raise
        // counted there may begin before the reroute lands and deliver
        // through the route it replaces. A failed delete leaves a route the
        // next round's register replaces; the controller's wait still ends.
        DELETING.store(round, Ordering::Release);
        // Reroute first on alternate rounds, so the delete finds its route
        // already replaced. A failed reroute is counted and fails the cell.
        if rerouted(round)
            && irq_register(LINE.load(Ordering::Acquire), SPARE.load(Ordering::Acquire)).is_err()
        {
            REROUTE_FAILED.fetch_add(1, Ordering::AcqRel);
        }
        cap_delete(SIG.load(Ordering::Acquire)).ok();
        DELETED.store(round, Ordering::Release);
    }
}
