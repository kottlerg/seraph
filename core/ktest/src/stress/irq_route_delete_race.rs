// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/irq_route_delete_race.rs

//! Stress: freeing an IRQ-bound notification, or a bound Interrupt object, on
//! one CPU while its device interrupt is delivered on another.
//!
//! ## The hazard
//!
//! `irq::dispatch_device_irq` walks a line's bindings, which live in the
//! Interrupt objects, and signals each binding's `NotificationState`, all
//! without a reference of its own. A bound binding holds a reference on its
//! notification, so a notification is freed only once the last binding naming
//! it lets it go: when its Interrupt object is freed (`irq::unregister`) or it
//! is rebound to another notification (`irq::register`). Freeing that
//! notification, or the Interrupt object, while a delivery on another CPU
//! still reads it would lock, set bits in, and wake through freed memory.
//! Every binding change therefore waits out the deliveries in flight on the
//! line before it releases the routing lock, and the reference is dropped
//! after (core/kernel/docs/ipc-internals.md § Notification, Device IRQ
//! delivery).
//!
//! ## How this exercises it
//!
//! The stand-in device is the UART ktest already owns: setting its
//! transmit-empty interrupt enable while the holding register is empty
//! raises its line (`crate::arch::serial::raise_tx_interrupt`). The cell
//! carves that one line from a derived copy of the root Interrupt cap and
//! first proves delivery: a raise must signal a bound notification. Then,
//! each round, the controller, pinned to CPU 0, creates a notification,
//! derives a copy of the line, routes the line through it (`SYS_IRQ_ROUTE`)
//! and binds it to the notification, and deletes the notification's only
//! capability, so the binding holds its last reference. It then repeatedly
//! acknowledges (`SYS_IRQ_ACK`; each delivery masks the line again) and
//! raises the interrupt, so deliveries follow one another, while a deleter
//! pinned to CPU 1 waits for a varying number of those raises to begin, then
//! a varying delay, and deletes the copy, which frees the notification with
//! the binding. Counting raises rather than time puts the delete among the
//! deliveries however long a raise takes: under KVM with the IOMMU attached,
//! QEMU emulates the I/O APIC outside the host kernel, and each
//! acknowledgement's unmask and each delivery's mask is many times slower
//! than with the in-kernel one. On every other
//! round the deleter first rebinds the copy to a spare notification
//! (`SYS_IRQ_REGISTER`), which drops the round's notification's last
//! reference and frees it while the line is still bound, and then deletes
//! the copy. Each round's copy is the line's only route holder and its only
//! binding, so its delete releases the line, and the next round's route
//! takes the next CPU in turn (core/kernel/docs/arch-interface.md
//! § `interrupts`). Most
//! rounds therefore deliver on a CPU other than the deleter's, where the
//! delivery and the change race; a round that delivers on CPU 1 serialises
//! them instead, and only the CPU count bounds how many do. A raise after the
//! delete finds the line masked and unbound.
//!
//! The binding rounds follow. Each derives two copies of the line, routes
//! the line through one and binds it to a keeper notification, binds the
//! other to a victim notification, and races the
//! same raises against the deleter's delete of the victim's Interrupt cap, so
//! a delivery walks the binding in the object being freed. After each delete
//! the keeper's binding must still be served: once it acknowledges, a raise
//! signals it.
//!
//! A round arms the race when one of its raises overlaps the deleter's delete
//! (with its rebind, on a rebound round): the delete was not done when the
//! raise began and had begun when it ended. The overlap is judged per raise
//! rather than sampled once per acknowledgement and raise, so a delete
//! shorter than one acknowledgement still counts when a raise meets it.
//!
//! Required: the kernel survives every round, every rebind succeeds, every
//! keeper is served after its round's delete, and in at least a quarter of
//! the rounds of each kind (direct, rebound, binding) the race armed
//! ([`MIN_ARMED_DIVISOR`]). The UART interrupt is disabled again when the
//! cell ends.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use init_protocol::InitInfo;
use syscall::{
    RIGHTS_ALL, cap_create_notification, cap_create_thread, cap_delete, cap_derive, irq_ack,
    irq_register, irq_route, irq_split, notification_wait_timeout, system_info, thread_configure,
    thread_exit, thread_set_affinity, thread_start,
};
use syscall_abi::SystemInfoType;

use crate::arch::serial::{UART_IRQ, quiet_tx_interrupt, raise_tx_interrupt};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Rounds to run.
const CYCLES: u32 = 400;
/// Binding rounds to run.
const BINDING_CYCLES: u32 = 200;
const MIN_CPUS: u64 = 2;
const CONTROLLER_CPU: u32 = 0;
const DELETER_CPU: u32 = 1;
/// Raises per round at most; a round ends sooner once the delete landed.
const MAX_RAISES: u32 = 20_000;
/// Raises after the delete was seen, so deliveries also meet a removed binding.
const TRAILING_RAISES: u32 = 16;
/// Raises the deleter waits for before its delay, at most: 1 to this many,
/// varying by round ([`lead`]).
const LEAD_RAISES: u32 = 4;
/// Each kind of round must arm the race in at least its rounds divided by
/// this: a quarter of them ([`armed_floors`]).
const MIN_ARMED_DIVISOR: u32 = 4;
/// Wait for the delivery probe's signal, in ms, through [`crate::scaled_bound`].
const PROBE_TIMEOUT_MS: u64 = 1000;
/// Polls (1 ms each) for the deleter's exit, through [`crate::scaled_polls`].
const EXIT_POLLS: u32 = 10_000;

/// Round the controller has published; the deleter acts once per value.
static ROUND: AtomicU32 = AtomicU32::new(0);
/// Capability handle the deleter deletes this round: a bound Interrupt cap.
static DOOMED: AtomicU64 = AtomicU64::new(0);
/// Whether the deleter rebinds the round's cap to the spare before its
/// delete; published before the round.
static REBIND: AtomicU32 = AtomicU32::new(0);
/// The spare notification the deleter rebinds a round's cap to.
static SPARE: AtomicU64 = AtomicU64::new(0);
/// Round whose delete (with its rebind, on a rebound round) the deleter has
/// begun.
static DELETING: AtomicU32 = AtomicU32::new(0);
/// Rebinds the deleter's `SYS_IRQ_REGISTER` refused.
static REBIND_FAILED: AtomicU32 = AtomicU32::new(0);
/// Last round whose delete the deleter finished.
static DELETED: AtomicU32 = AtomicU32::new(0);
/// Raises the controller has begun in the current round; reset before the
/// round is published. The deleter waits for its round's lead of them.
static RAISED: AtomicU32 = AtomicU32::new(0);
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
        let raced = race(ctx, line);
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
fn carve_line(ctx: &TestContext) -> Result<u64, &'static str>
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

/// Prove the stand-in delivers, then run [`CYCLES`] notification rounds and
/// [`BINDING_CYCLES`] binding rounds.
fn race(ctx: &TestContext, line: u64) -> TestResult
{
    probe_delivery(ctx, line)?;

    let spare = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create spare notification failed")?;
    ROUND.store(0, Ordering::Release);
    DELETED.store(0, Ordering::Release);
    DELETING.store(0, Ordering::Release);
    REBIND_FAILED.store(0, Ordering::Release);
    QUIT.store(0, Ordering::Release);
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
    let raced = match started
    {
        Ok(()) => phases(ctx, line, spare),
        Err(e) =>
        {
            cap_delete(spare).ok();
            Err(e)
        }
    };
    QUIT.store(1, Ordering::Release);
    let exited = spawn::wait_until_exited(deleter, crate::scaled_polls(EXIT_POLLS));
    cap_delete(deleter).ok();
    let armed = raced?;
    if REBIND_FAILED.load(Ordering::Acquire) != 0
    {
        return Err("stress::irq_route_delete_race: a rebind to the spare notification failed");
    }
    exited?;
    crate::log_u64(
        "stress::irq_route_delete_race: armed_direct=",
        u64::from(armed[0]),
    );
    crate::log_u64(
        "stress::irq_route_delete_race: armed_rebound=",
        u64::from(armed[1]),
    );
    crate::log_u64(
        "stress::irq_route_delete_race: armed_binding=",
        u64::from(armed[2]),
    );
    if armed
        .iter()
        .zip(armed_floors())
        .any(|(&got, floor)| got < floor)
    {
        return Err(
            "stress::irq_route_delete_race: fewer rounds of some kind armed the race than its floor",
        );
    }
    Ok(())
}

/// The fewest rounds of each kind (direct, rebound, binding) that must arm the
/// race: the kind's rounds divided by [`MIN_ARMED_DIVISOR`]. Rebound rounds are
/// the even ones of [`CYCLES`], direct rounds the odd ones.
const fn armed_floors() -> [u32; 3]
{
    let notified = CYCLES.wrapping_div(2).wrapping_div(MIN_ARMED_DIVISOR);
    [
        notified,
        notified,
        BINDING_CYCLES.wrapping_div(MIN_ARMED_DIVISOR),
    ]
}

/// The notification rounds, then the binding rounds; returns how many rounds
/// of each kind armed the race. The spare is deleted whatever the outcome.
fn phases(ctx: &TestContext, line: u64, spare: u64) -> Result<[u32; 3], &'static str>
{
    let notified = rounds(ctx, line);
    cap_delete(spare).ok();
    let notified = notified?;
    let bound = binding_rounds(ctx, line, CYCLES + 1)?;
    Ok([notified[0], notified[1], bound])
}

/// Route the line through a copy, bind the copy to a fresh notification and
/// require one raise to signal it, so the rounds below are not vacuous. The
/// copy's delete releases the line.
fn probe_delivery(ctx: &TestContext, line: u64) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create probe notification failed")?;
    let Ok(copy) = cap_derive(line, RIGHTS_ALL)
    else
    {
        cap_delete(sig).ok();
        return Err("stress::irq_route_delete_race: derive the probe's copy failed");
    };
    let bound = irq_route(copy, 0)
        .and_then(|()| irq_register(copy, sig, 0))
        .and_then(|()| irq_ack(copy));
    raise_tx_interrupt();
    let bits =
        bound.and_then(|()| notification_wait_timeout(sig, crate::scaled_bound(PROBE_TIMEOUT_MS)));
    quiet_tx_interrupt();
    cap_delete(copy).ok();
    cap_delete(sig).ok();
    match bits
    {
        Ok(bits) if bits & 1 != 0 => Ok(()),
        Ok(_) => Err("stress::irq_route_delete_race: UART interrupt never delivered"),
        Err(_) => Err("stress::irq_route_delete_race: bind or wait on the UART line failed"),
    }
}

/// Whether the deleter rebinds the round's cap to the spare before its delete.
fn rebound(round: u32) -> bool
{
    round.is_multiple_of(2)
}

/// The rounds; returns, for direct deletes and deletes after a rebind, how
/// many armed the race: a raise overlapped the rebind or the delete
/// ([`raise_sampled`]).
fn rounds(ctx: &TestContext, line: u64) -> Result<[u32; 2], &'static str>
{
    let mut armed = [0u32; 2];
    for round in 1..=CYCLES
    {
        let sig = cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::irq_route_delete_race: create notification failed")?;
        let Ok(copy) = cap_derive(line, RIGHTS_ALL)
        else
        {
            cap_delete(sig).ok();
            return Err("stress::irq_route_delete_race: derive the round's copy failed");
        };
        let bound = irq_route(copy, 0)
            .and_then(|()| irq_register(copy, sig, 0))
            .and_then(|()| irq_ack(copy));
        // The binding now holds the notification's last reference: the
        // deleter's rebind or delete frees it.
        cap_delete(sig).ok();
        if bound.is_err()
        {
            cap_delete(copy).ok();
            return Err("stress::irq_route_delete_race: bind the UART line failed");
        }
        DOOMED.store(copy, Ordering::Release);
        REBIND.store(u32::from(rebound(round)), Ordering::Release);
        RAISED.store(0, Ordering::Release);
        ROUND.store(round, Ordering::Release);
        let mut raises = 0u32;
        let mut overlapped = false;
        while DELETED.load(Ordering::Acquire) != round && raises < MAX_RAISES
        {
            // Unmask before each raise, since each delivery masks the line;
            // after the delete the ack fails.
            irq_ack(copy).ok();
            overlapped |= raise_sampled(round, &mut raises);
        }
        if overlapped
        {
            let slot = armed
                .get_mut(usize::from(rebound(round)))
                .ok_or("stress::irq_route_delete_race: rebind index out of range")?;
            *slot = slot.saturating_add(1);
        }
        if DELETED.load(Ordering::Acquire) == round
        {
            for _ in 0..TRAILING_RAISES
            {
                irq_ack(copy).ok();
                raise_tx_interrupt();
            }
        }
        quiet_tx_interrupt();
        await_delete(round)?;
    }
    Ok(armed)
}

/// Raise the line once in `round`, the acknowledgements before it made, and
/// count the raise in `raises` and, as it begins, in [`RAISED`]. Returns
/// whether the raise and the round's delete (with its rebind, on a rebound
/// round) overlapped: the delete was not done when the raise began, and had
/// begun when it ended.
fn raise_sampled(round: u32, raises: &mut u32) -> bool
{
    let not_done = DELETED.load(Ordering::Acquire) != round;
    *raises = raises.saturating_add(1);
    RAISED.store(*raises, Ordering::Release);
    raise_tx_interrupt();
    not_done && DELETING.load(Ordering::Acquire) == round
}

/// Raises the deleter waits for in `round` before its delay: 1 to
/// [`LEAD_RAISES`], so the delete begins once deliveries follow one another,
/// at a varying one of them. Taken from bits of a multiplicative hash of the
/// round that the deleter's delay does not use, so the lead varies apart from
/// the delay and from the round's kind ([`rebound`]).
fn lead(round: u32) -> u32
{
    (round.wrapping_mul(2_654_435_761) >> 8)
        .wrapping_rem(LEAD_RAISES)
        .saturating_add(1)
}

/// Wait for `round`'s delete (bounded), so the handle is never reused while
/// the deleter still holds it.
fn await_delete(round: u32) -> TestResult
{
    let mut polls = 0u32;
    while DELETED.load(Ordering::Acquire) != round
    {
        polls = polls.saturating_add(1);
        if polls > crate::scaled_polls(EXIT_POLLS)
        {
            return Err("stress::irq_route_delete_race: deleter never deleted");
        }
        syscall::thread_sleep(1).ok();
    }
    Ok(())
}

/// [`BINDING_CYCLES`] binding rounds numbered from `first`; returns how many
/// armed the race.
fn binding_rounds(ctx: &TestContext, line: u64, first: u32) -> Result<u32, &'static str>
{
    let last = first
        .checked_add(BINDING_CYCLES)
        .ok_or("stress::irq_route_delete_race: binding round numbers overflow")?;
    let keeper = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create keeper notification failed")?;
    let victim = cap_create_notification(ctx.memory_base);
    let result = victim
        .map_err(|_| "stress::irq_route_delete_race: create victim notification failed")
        .and_then(|victim| {
            (first..last).try_fold(0u32, |armed, round| {
                binding_round(line, round, [keeper, victim])
                    .map(|hit| armed.saturating_add(u32::from(hit)))
            })
        });
    if let Ok(victim) = victim
    {
        cap_delete(victim).ok();
    }
    cap_delete(keeper).ok();
    result
}

/// One binding round: a kept copy of the line, holding its route, bound to
/// `ntfs[0]` (the keeper) and a doomed copy bound to `ntfs[1]`, whose cap the deleter
/// deletes while the controller raises; then the kept binding must be served.
/// Returns whether a raise overlapped the delete ([`raise_sampled`]).
fn binding_round(line: u64, round: u32, ntfs: [u64; 2]) -> Result<bool, &'static str>
{
    let kept = cap_derive(line, RIGHTS_ALL)
        .map_err(|_| "stress::irq_route_delete_race: derive the kept copy failed")?;
    let result = cap_derive(line, RIGHTS_ALL)
        .map_err(|_| "stress::irq_route_delete_race: derive the doomed copy failed")
        .and_then(|doomed| race_binding_delete(round, kept, doomed, ntfs));
    quiet_tx_interrupt();
    // The kept copy is the line's route holder and last binding: its delete
    // releases the line, so the next round's route takes the next CPU.
    cap_delete(kept).ok();
    result
}

/// Route the line through `kept`, bind `kept` and `doomed`, hand `doomed` to
/// the deleter, raise until it is deleted, and require `kept`'s notification
/// to be signalled after.
fn race_binding_delete(
    round: u32,
    kept: u64,
    doomed: u64,
    ntfs: [u64; 2],
) -> Result<bool, &'static str>
{
    if irq_route(kept, 0)
        .and_then(|()| irq_register(kept, ntfs[0], 0))
        .and_then(|()| irq_register(doomed, ntfs[1], 0))
        .and_then(|()| irq_ack(kept))
        .and_then(|()| irq_ack(doomed))
        .is_err()
    {
        cap_delete(doomed).ok();
        return Err("stress::irq_route_delete_race: routing or binding the two copies failed");
    }
    DOOMED.store(doomed, Ordering::Release);
    REBIND.store(0, Ordering::Release);
    RAISED.store(0, Ordering::Release);
    ROUND.store(round, Ordering::Release);
    let mut raises = 0u32;
    let mut overlapped = false;
    while DELETED.load(Ordering::Acquire) != round && raises < MAX_RAISES
    {
        // Both bindings owe after each delivery; the doomed one's ack fails
        // once its cap is deleted.
        irq_ack(kept).ok();
        irq_ack(doomed).ok();
        overlapped |= raise_sampled(round, &mut raises);
    }
    if DELETED.load(Ordering::Acquire) == round
    {
        for _ in 0..TRAILING_RAISES
        {
            irq_ack(kept).ok();
            raise_tx_interrupt();
        }
    }
    quiet_tx_interrupt();
    await_delete(round)?;
    // Consume what the raises left, then require one more delivery: the
    // removal of the doomed binding must leave the kept one bound and served.
    notification_wait_timeout(ntfs[0], 1).ok();
    irq_ack(kept).ok();
    raise_tx_interrupt();
    let bits = notification_wait_timeout(ntfs[0], crate::scaled_bound(PROBE_TIMEOUT_MS));
    quiet_tx_interrupt();
    match bits
    {
        Ok(bits) if bits & 1 != 0 => Ok(overlapped),
        _ => Err("stress::irq_route_delete_race: the kept binding was not served after the delete"),
    }
}

/// Deleter: per published round, wait for the round's lead of raises
/// ([`lead`]) and a varying delay, then rebind the round's Interrupt cap to
/// the spare when the round asks, and delete it; exit on `QUIT`.
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
        // The round's lead of raises first, so the delete lands among the
        // deliveries however long each raise takes; the controller raises
        // until the delete is done, so they come.
        while RAISED.load(Ordering::Acquire) < lead(round) && QUIT.load(Ordering::Acquire) == 0
        {
            core::hint::spin_loop();
        }
        // Then 0 to 255 spins (the top bits of a multiplicative hash of the
        // round), a few microseconds at most, so the delete begins while the
        // lead raise runs, at a varying point of it: its removal of the
        // binding then meets the raise's delivery, before or after the
        // delivery reads it.
        for _ in 0..(round.wrapping_mul(2_654_435_761) >> 24)
        {
            core::hint::spin_loop();
        }
        // The window opens before the rebind on a rebound round, so a raise
        // counted there may begin before the rebind lands and deliver to the
        // notification it replaces, which the rebind frees.
        DELETING.store(round, Ordering::Release);
        let doomed = DOOMED.load(Ordering::Acquire);
        // Rebind first when the round asks, dropping the round's
        // notification's last reference while the line stays bound. A failed
        // rebind is counted and fails the cell.
        if REBIND.load(Ordering::Acquire) != 0
            && irq_register(doomed, SPARE.load(Ordering::Acquire), 0).is_err()
        {
            REBIND_FAILED.fetch_add(1, Ordering::AcqRel);
        }
        cap_delete(doomed).ok();
        DELETED.store(round, Ordering::Release);
    }
}
