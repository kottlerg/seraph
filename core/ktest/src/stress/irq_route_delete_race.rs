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
//! derives a copy of the line, routes the line through it (`SYS_IRQ_ROUTE`),
//! binds it to the notification and acknowledges (`SYS_IRQ_ACK`), which
//! unmasks the line, and a deleter pinned to CPU 1 deletes the
//! notification's only capability, so the binding holds its last reference,
//! and then deletes the copy, which frees the notification with the binding.
//! On every other round the deleter first rebinds the copy to a spare
//! notification (`SYS_IRQ_REGISTER`), which drops the round's notification's
//! last reference and frees it while the line is still bound, and then
//! deletes the copy. Each round's copy is the line's only route holder and
//! its only binding, so its delete releases the line, and the next round's
//! route takes the next CPU in turn (core/kernel/docs/arch-interface.md
//! § `interrupts`). After the delete the controller acknowledges and raises
//! [`TRAILING_RAISES`] times more, and each raise finds the line masked and
//! unbound.
//!
//! The binding rounds follow. Each derives two copies of the line, routes
//! the line through one and binds it to a keeper notification, binds the
//! other to a victim notification, and races the deleter's delete of the
//! victim's Interrupt cap against the deliveries the same way, so a delivery
//! walks the binding in the object being freed. After each delete the
//! keeper's binding must still be served: once it acknowledges, a raise
//! signals it.
//!
//! ## Two schedules
//!
//! Every kind of round (direct, rebound, binding) runs in two schedules,
//! about half its rounds in each ([`held`]), because where an
//! acknowledgement contends with a delivery differs by interrupt controller:
//!
//! - **Streamed:** the controller acknowledges and raises over and over, so
//!   deliveries follow one another, while the deleter waits a varying delay
//!   from the round's start and makes its change. Where an acknowledgement
//!   does not wait for a delivery (riscv64), deliveries run throughout the
//!   change. The round counts as overlapped when a raise overlapped the
//!   change: the change was not done when the raise began, and had begun when
//!   it ended. The counts are logged; they are not required.
//! - **Held:** the controller raises once and then waits, without
//!   acknowledging, until the change is done. An acknowledgement takes the
//!   routing lock, and on x86-64 its unmask waits for a delivery's mask
//!   (`IOAPIC_LOCK`), so in a streamed round the deleter gets the routing lock
//!   only once each delivery has all but ended, and the change seldom meets
//!   one. The deleter starts once the raise has returned, after a delay its
//!   rounds on that CPU have fitted to how long a delivery takes to signal on
//!   this platform ([`next_delay`]): tens of microseconds where KVM emulates
//!   the I/O APIC in the host kernel, hundreds where QEMU emulates it in
//!   userspace (the x86-64 launches with the IOMMU attached). Just before its
//!   change it takes the notification's bits:
//!   none means the raise's delivery had not yet signalled, so the change met
//!   it, pending or under way, and the round armed the race.
//!
//! A held round that delivers on CPU 0 runs its delivery on the controller
//! before the raise returns, and one that delivers on CPU 1 runs it on the
//! deleter before the deleter starts, so only the held rounds that deliver on
//! another CPU can arm: half of them at 4 CPUs, none at 2.
//!
//! Required: the kernel survives every round, every rebind succeeds, every
//! keeper is served after its round's delete, and, of each kind, the held
//! rounds that arm the race are at least a quarter of those that can
//! ([`armed_floor`]). The UART interrupt is disabled again when the cell
//! ends.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use init_protocol::InitInfo;
use syscall::{
    RIGHTS_ALL, cap_create_notification, cap_create_thread, cap_delete, cap_derive, irq_ack,
    irq_register, irq_route, irq_split, notification_try_wait, notification_wait_timeout,
    system_info, thread_configure, thread_exit, thread_set_affinity, thread_start,
};
use syscall_abi::SystemInfoType;

use crate::arch::serial::{UART_IRQ, quiet_tx_interrupt, raise_tx_interrupt};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification rounds to run: direct and rebound in turn, each streamed or
/// held ([`held`]).
const CYCLES: u32 = 600;
/// Binding rounds to run, each streamed or held.
const BINDING_CYCLES: u32 = 300;
const MIN_CPUS: u64 = 2;
const CONTROLLER_CPU: u32 = 0;
const DELETER_CPU: u32 = 1;
/// Raises per streamed round at most; the round ends sooner once the change
/// is done.
const MAX_RAISES: u32 = 20_000;
/// Raises after the delete, so deliveries also meet a removed binding.
const TRAILING_RAISES: u32 = 16;
/// The held rounds of each kind that can arm the race, divided by this, must
/// arm it ([`armed_floor`]): a quarter of them.
const MIN_ARMED_DIVISOR: u64 = 4;
/// Wait for the delivery probe's signal, in ms, through [`crate::scaled_bound`].
const PROBE_TIMEOUT_MS: u64 = 1000;
/// Polls (1 ms each) for the deleter's exit, through [`crate::scaled_polls`].
const EXIT_POLLS: u32 = 10_000;
/// CPUs whose delays the deleter keeps apart ([`delay_slot`]).
const DELAY_SLOTS: usize = 16;
/// Longest delay, in spins, the deleter waits after a held round's raise
/// ([`next_delay`]).
const MAX_DELAY_SPINS: u32 = 1 << 20;
/// Spins the controller waits for the round's change before it sleeps
/// between polls instead ([`await_delete`]).
const DELETE_SPINS: u32 = 1 << 20;

/// Round the controller has published; the deleter acts once per value.
static ROUND: AtomicU32 = AtomicU32::new(0);
/// Capability handle the deleter deletes this round: a bound Interrupt cap.
static DOOMED: AtomicU64 = AtomicU64::new(0);
/// The notification [`DOOMED`]'s binding signals: in a held round, the
/// deleter takes its bits just before its change.
static WATCHED: AtomicU64 = AtomicU64::new(0);
/// Whether the deleter deletes [`WATCHED`]'s capability before its change,
/// so the binding holds the notification's last reference.
static WATCHED_DOOMED: AtomicU32 = AtomicU32::new(0);
/// Whether the deleter rebinds the round's cap to the spare before its
/// delete; published before the round.
static REBIND: AtomicU32 = AtomicU32::new(0);
/// The spare notification the deleter rebinds a round's cap to.
static SPARE: AtomicU64 = AtomicU64::new(0);
/// Last held round whose raise has returned; the deleter starts after it.
static RAISED: AtomicU32 = AtomicU32::new(0);
/// Last held round that armed the race: [`WATCHED`] held no bit as its change
/// began.
static ARMED: AtomicU32 = AtomicU32::new(0);
/// Round whose change (its rebind, on a rebound round, then its delete) the
/// deleter has begun.
static DELETING: AtomicU32 = AtomicU32::new(0);
/// Rebinds the deleter's `SYS_IRQ_REGISTER` refused.
static REBIND_FAILED: AtomicU32 = AtomicU32::new(0);
/// Last round whose delete the deleter finished.
static DELETED: AtomicU32 = AtomicU32::new(0);
/// Set by the controller to end the deleter.
static QUIT: AtomicU32 = AtomicU32::new(0);

static mut DELETER_STACK: ChildStack = ChildStack::ZERO;

/// Per kind of round (direct, rebound, binding), how many rounds ran held,
/// how many of them armed the race, and how many streamed rounds overlapped
/// it.
#[derive(Default)]
struct Tally
{
    held: [u32; 3],
    armed: [u32; 3],
    overlapped: [u32; 3],
}

impl Tally
{
    /// Count `round`, of kind `kind`, which armed or overlapped the race when
    /// `hit`.
    fn count(&mut self, round: u32, kind: usize, hit: bool) -> TestResult
    {
        let (runs, hits) = if held(round)
        {
            (Some(&mut self.held), &mut self.armed)
        }
        else
        {
            (None, &mut self.overlapped)
        };
        if let Some(runs) = runs
        {
            let slot = runs
                .get_mut(kind)
                .ok_or("stress::irq_route_delete_race: round kind out of range")?;
            *slot = slot.saturating_add(1);
        }
        let slot = hits
            .get_mut(kind)
            .ok_or("stress::irq_route_delete_race: round kind out of range")?;
        *slot = slot.saturating_add(u32::from(hit));
        Ok(())
    }
}

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
        let raced = race(ctx, line, cpus);
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
/// [`BINDING_CYCLES`] binding rounds, and require each kind's floor of armed
/// held rounds at `cpus` CPUs.
fn race(ctx: &TestContext, line: u64, cpus: u64) -> TestResult
{
    probe_delivery(ctx, line)?;

    let spare = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create spare notification failed")?;
    ROUND.store(0, Ordering::Release);
    RAISED.store(0, Ordering::Release);
    ARMED.store(0, Ordering::Release);
    DELETING.store(0, Ordering::Release);
    DELETED.store(0, Ordering::Release);
    REBIND_FAILED.store(0, Ordering::Release);
    QUIT.store(0, Ordering::Release);
    SPARE.store(spare, Ordering::Release);
    let deleter = cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
        .map_err(|_| "stress::irq_route_delete_race: create deleter failed")?;
    let top = ChildStack::top(core::ptr::addr_of!(DELETER_STACK));
    // SAFETY: `deleter_entry` is an `extern "C" fn(u64) -> !` and
    // `DELETER_STACK` is this deleter's own stack for its lifetime.
    let started =
        unsafe { thread_configure(deleter, deleter_entry as *const () as u64, top, cpus) }
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
    let tally = raced?;
    if REBIND_FAILED.load(Ordering::Acquire) != 0
    {
        return Err("stress::irq_route_delete_race: a rebind to the spare notification failed");
    }
    exited?;
    let names = ["direct", "rebound", "binding"];
    let mut floor_missed = false;
    for (kind, name) in names.iter().enumerate()
    {
        let of = |counts: &[u32; 3]| counts.get(kind).copied().unwrap_or(0);
        let (held, armed) = (of(&tally.held), of(&tally.armed));
        let floor = armed_floor(held, cpus);
        crate::log_args(format_args!(
            "stress::irq_route_delete_race: armed_{name}={armed} of {held} held (floor {floor}), \
             overlapped_{name}={}",
            of(&tally.overlapped)
        ));
        floor_missed |= u64::from(armed) < floor;
    }
    if floor_missed
    {
        return Err(
            "stress::irq_route_delete_race: fewer held rounds of some kind armed the race than its floor",
        );
    }
    Ok(())
}

/// The fewest of `rounds` held rounds of one kind that must arm the race at
/// `cpus` CPUs: those that deliver on a CPU other than CPU 0 and CPU 1, which
/// the routes take in turn, divided by [`MIN_ARMED_DIVISOR`]. None at 2 CPUs.
fn armed_floor(rounds: u32, cpus: u64) -> u64
{
    u64::from(rounds)
        .saturating_mul(cpus.saturating_sub(2))
        .checked_div(cpus.saturating_mul(MIN_ARMED_DIVISOR))
        .unwrap_or(0)
}

/// The notification rounds, then the binding rounds. The spare is deleted
/// whatever the outcome.
fn phases(ctx: &TestContext, line: u64, spare: u64) -> Result<Tally, &'static str>
{
    let mut tally = Tally::default();
    let notified = rounds(ctx, line, &mut tally);
    cap_delete(spare).ok();
    notified?;
    binding_rounds(ctx, line, CYCLES + 1, &mut tally)?;
    Ok(tally)
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
    round <= CYCLES && round.is_multiple_of(2)
}

/// Whether `round` runs held rather than streamed (module doc § Two
/// schedules): about half the rounds of each kind, chosen by a bit of a
/// multiplicative hash of the round. A choice by the round number's low bits
/// would fall in step with the routes' turn over the CPUs, and hold a kind's
/// rounds on the same CPUs every time.
fn held(round: u32) -> bool
{
    round.wrapping_mul(2_654_435_761) & (1 << 16) != 0
}

/// The notification rounds, counted into `tally`.
fn rounds(ctx: &TestContext, line: u64, tally: &mut Tally) -> TestResult
{
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
        if irq_route(copy, 0)
            .and_then(|()| irq_register(copy, sig, 0))
            .and_then(|()| irq_ack(copy))
            .is_err()
        {
            cap_delete(copy).ok();
            cap_delete(sig).ok();
            return Err("stress::irq_route_delete_race: bind the UART line failed");
        }
        // The deleter deletes `sig`'s capability just before its change, and
        // the binding then holds the notification's last reference: the
        // deleter's rebind or delete frees it.
        WATCHED_DOOMED.store(1, Ordering::Release);
        let hit = race_delete(round, copy, sig, &[copy])?;
        tally.count(round, usize::from(rebound(round)), hit)?;
    }
    Ok(())
}

/// Hand `doomed`, whose binding signals `watched`, to the deleter for
/// `round`, with the line just unmasked, and raise in the round's schedule
/// ([`held`]), acknowledging through `acks`; then acknowledge and raise
/// [`TRAILING_RAISES`] times more. Returns whether a held round armed the
/// race, or a streamed one overlapped it (module doc § Two schedules).
fn race_delete(round: u32, doomed: u64, watched: u64, acks: &[u64]) -> Result<bool, &'static str>
{
    DOOMED.store(doomed, Ordering::Release);
    WATCHED.store(watched, Ordering::Release);
    REBIND.store(u32::from(rebound(round)), Ordering::Release);
    ROUND.store(round, Ordering::Release);
    let hit = if held(round)
    {
        raise_tx_interrupt();
        RAISED.store(round, Ordering::Release);
        await_delete(round)?;
        ARMED.load(Ordering::Acquire) == round
    }
    else
    {
        let mut raises = 0u32;
        let mut overlapped = false;
        while DELETED.load(Ordering::Acquire) != round && raises < MAX_RAISES
        {
            // Unmask before each raise, since each delivery masks the line;
            // after the delete the acknowledgement fails.
            for &cap in acks
            {
                irq_ack(cap).ok();
            }
            let not_done = DELETED.load(Ordering::Acquire) != round;
            raise_tx_interrupt();
            raises = raises.saturating_add(1);
            overlapped |= not_done && DELETING.load(Ordering::Acquire) == round;
        }
        await_delete(round)?;
        overlapped
    };
    for _ in 0..TRAILING_RAISES
    {
        for &cap in acks
        {
            irq_ack(cap).ok();
        }
        raise_tx_interrupt();
    }
    quiet_tx_interrupt();
    Ok(hit)
}

/// Wait for `round`'s delete (bounded), so the handle is never reused while
/// the deleter still holds it: spin first, since a change takes microseconds
/// to a millisecond, then sleep between polls.
fn await_delete(round: u32) -> TestResult
{
    let mut spins = 0u32;
    while DELETED.load(Ordering::Acquire) != round && spins < DELETE_SPINS
    {
        spins = spins.saturating_add(1);
        core::hint::spin_loop();
    }
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

/// [`BINDING_CYCLES`] binding rounds numbered from `first`, counted into
/// `tally`.
fn binding_rounds(ctx: &TestContext, line: u64, first: u32, tally: &mut Tally) -> TestResult
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
            (first..last).try_for_each(|round| {
                let hit = binding_round(line, round, [keeper, victim])?;
                tally.count(round, 2, hit)
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
/// `ntfs[0]` (the keeper) and a doomed copy bound to `ntfs[1]` (the victim),
/// whose cap the deleter deletes as the controller's raises are delivered;
/// then the kept binding must be served. Returns whether the round armed or
/// overlapped the race.
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

/// Route the line through `kept`, bind `kept` and `doomed`, race the deleter's
/// delete of `doomed` ([`race_delete`]), and require `kept`'s notification to
/// be signalled after.
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
    // The victim lives across the rounds: take what an earlier round left,
    // so its bits are this round's raises' alone.
    notification_try_wait(ntfs[1]).ok();
    WATCHED_DOOMED.store(0, Ordering::Release);
    // Both bindings owe after each delivery; the doomed one's acknowledgement
    // fails once its cap is deleted.
    let hit = race_delete(round, doomed, ntfs[1], &[kept, doomed])?;
    // Consume what the raises left, then require one more delivery: the
    // removal of the doomed binding must leave the kept one bound and served.
    notification_wait_timeout(ntfs[0], 1).ok();
    irq_ack(kept).ok();
    raise_tx_interrupt();
    let bits = notification_wait_timeout(ntfs[0], crate::scaled_bound(PROBE_TIMEOUT_MS));
    quiet_tx_interrupt();
    match bits
    {
        Ok(bits) if bits & 1 != 0 => Ok(hit),
        _ => Err("stress::irq_route_delete_race: the kept binding was not served after the delete"),
    }
}

/// The next delay, in spins, of the CPU whose held round waited `delay`
/// ([`delay_slot`]): a quarter longer when the change met the delivery
/// (`met`), half as long when the delivery had already signalled. Rounds that
/// meet it three times in four hold the delay there, before most deliveries
/// on that CPU signal.
fn next_delay(delay: u32, met: bool) -> u32
{
    if met
    {
        delay
            .saturating_add(delay / 4)
            .saturating_add(1)
            .min(MAX_DELAY_SPINS)
    }
    else
    {
        delay / 2
    }
}

/// The slot of the deleter's delays that `round` uses at `cpus` CPUs: the
/// routes take the CPUs in turn, one per round, so the round number modulo the
/// CPU count stands for the CPU that delivers it. Past [`DELAY_SLOTS`] CPUs,
/// CPUs share a slot, so each slot still sees enough rounds to fit its delay,
/// and CPU 0 and CPU 1, whose rounds cannot arm and so shorten the delay,
/// each share theirs with CPUs that can.
fn delay_slot(round: u32, cpus: u64) -> usize
{
    u64::from(round)
        .checked_rem(cpus.max(1))
        .and_then(|cpu| cpu.checked_rem(DELAY_SLOTS as u64))
        .and_then(|slot| usize::try_from(slot).ok())
        .unwrap_or(0)
}

/// Deleter, for a system of `cpus` CPUs: per published round, wait as the
/// round's schedule says ([`held`]), delete the watched notification's
/// capability when the round asks, then rebind the round's Interrupt cap to
/// the spare when the round asks, and delete it; exit on `QUIT`.
extern "C" fn deleter_entry(cpus: u64) -> !
{
    let mut delays = [0u32; DELAY_SLOTS];
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
        let watched = WATCHED.load(Ordering::Acquire);
        let met = if held(round)
        {
            // The controller raises once and then waits for this change.
            while RAISED.load(Ordering::Acquire) != round && QUIT.load(Ordering::Acquire) == 0
            {
                core::hint::spin_loop();
            }
            let slot = delays.get_mut(delay_slot(round, cpus));
            let delay = slot.as_deref().copied().unwrap_or(0);
            for _ in 0..delay
            {
                core::hint::spin_loop();
            }
            // No bit yet: the raise's delivery had not signalled, so the
            // change below meets it.
            let met = notification_try_wait(watched).is_err();
            if let Some(slot) = slot
            {
                *slot = next_delay(delay, met);
            }
            met
        }
        else
        {
            // 0 to 4095 spins (a multiplicative hash of the round), so the
            // change lands at varying points in the stream of raises.
            for _ in 0..(round.wrapping_mul(2_654_435_761) >> 20)
            {
                core::hint::spin_loop();
            }
            false
        };
        if WATCHED_DOOMED.load(Ordering::Acquire) != 0
        {
            cap_delete(watched).ok();
        }
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
        if met
        {
            ARMED.store(round, Ordering::Release);
        }
        DELETED.store(round, Ordering::Release);
    }
}
