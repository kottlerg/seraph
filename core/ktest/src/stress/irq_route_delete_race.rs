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
//! about half its fixed rounds in each ([`held`]), because where an
//! acknowledgement contends with a delivery differs by interrupt controller:
//!
//! - **Streamed:** the controller acknowledges and raises over and over, so
//!   deliveries follow one another, while the deleter waits a varying delay
//!   from the round's start and makes its change. Where an acknowledgement
//!   does not wait for a delivery (riscv64), deliveries run throughout the
//!   change. The round counts as overlapped when a raise overlapped the
//!   change: the change was not done when the raise began, and had begun when
//!   it ended. The counts are logged; they are not required.
//! - **Held:** the deleter raises once, waits a delay, and makes its change,
//!   while the controller sleeps on a notification ([`DONE`]) without
//!   acknowledging until the change is done. An acknowledgement takes the
//!   routing lock, and on x86-64 its unmask waits for a delivery's mask
//!   (`IOAPIC_LOCK`), so in a streamed round the deleter gets the routing lock
//!   only once each delivery has all but ended, and the change seldom meets
//!   one. The delay is one the rounds fit to where their changes meet
//!   deliveries on this platform ([`pace`]): tens of microseconds after the
//!   raise where KVM emulates the I/O APIC in the host kernel, hundreds where
//!   QEMU emulates it in userspace (the x86-64 launches with the IOMMU
//!   attached). The CPUs share that delay, so it fits within the first few
//!   dozen held rounds of a kind at any CPU count. The raise and the delay run
//!   on one CPU, so no handoff between CPUs stretches the delay, and the
//!   sleeping controller leaves CPU 0 free to deliver.
//!
//! In three of four held notification rounds, and in every held binding
//! round, the round is observed ([`Plan::fixed`]): the deleter keeps the
//! watched notification (the round's, or the victim) alive through the
//! change and takes its bits just before the change and again just after it.
//! No delivery reaches that notification through the binding once the change
//! has removed it or replaced its notification, so a bit in the second take
//! and none in the first means the raise's delivery read the binding or the
//! notification while the change ran, or in the moment between the first
//! take and the change's start: the change met it, and the round armed the
//! race ([`Outcome`]). The other held notification rounds delete the
//! notification's capability before the change, so the change frees it.
//!
//! A held round that delivers on CPU 1 runs its delivery on the deleter as
//! the raise returns, before the change, so it comes late; the held rounds
//! that deliver on any other CPU, CPU 0 included, can arm: three in four of
//! them at 4 CPUs, one in two at 2. A rebound round
//! arms only when the rebind's store lands between a delivery's load of the
//! notification and its signal, the last steps of a delivery that masks the
//! line first, and on x86-64, where the mask is the long step, it seldom does.
//!
//! ## What the host must give
//!
//! A held round arms only when CPU 1 and the CPU that delivers run at once,
//! within microseconds of each other. A host that runs fewer of the guest's
//! CPUs at a time than the guest has (a burn-in runner booting two 4-CPU
//! guests on four cores, or a boundary run past the host's core count) does
//! so in fewer rounds, and in some stretches in none. The check therefore
//! counts armed rounds rather than a share of them: after a phase's fixed
//! rounds, while fewer than [`MIN_ARMED`] observed held rounds of its kind
//! have armed the race, the phase runs held, observed rounds of that kind,
//! up to [`MAX_EXTRA_ROUNDS`] of them ([`extend`]). A slower host only takes
//! more of these extra rounds; the host must run CPU 1 and a delivering CPU
//! at once in [`MIN_ARMED`] of the rounds, not throughout.
//!
//! Required: the kernel survives every round, every rebind succeeds, every
//! keeper is served after its round's delete, and the observed held direct
//! and binding rounds that arm the race each number at least [`MIN_ARMED`]
//! once the extra rounds have run ([`armed_needed`]); the armed rebound
//! rounds are logged and not required. A change that no longer meets a
//! delivery in flight arms
//! none, and fails the check after every extra round. The log line of each
//! kind also counts the observed rounds that came late and early, and the
//! extra rounds run. The UART interrupt is disabled again when the cell
//! ends.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use init_protocol::InitInfo;
use syscall::{
    RIGHTS_ALL, cap_create_notification, cap_create_thread, cap_delete, cap_derive, irq_ack,
    irq_register, irq_route, irq_split, notification_send, notification_try_wait,
    notification_wait_timeout, system_info, thread_configure, thread_exit, thread_set_affinity,
    thread_start,
};
use syscall_abi::SystemInfoType;

use crate::arch::serial::{UART_IRQ, grant_tx_interrupt, quiet_tx_interrupt, raise_tx_interrupt};
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
/// Observed held rounds of each required kind (direct, binding) that must arm
/// the race ([`armed_needed`]).
const MIN_ARMED: u32 = 4;
/// Held, observed rounds of a required kind that run at most after its fixed
/// rounds, while fewer than [`MIN_ARMED`] of its rounds have armed the race
/// ([`extend`]).
const MAX_EXTRA_ROUNDS: u32 = 2000;
/// Wait for the delivery probe's signal, in ms, through [`crate::scaled_bound`].
const PROBE_TIMEOUT_MS: u64 = 1000;
/// Polls (1 ms each) for the deleter's exit, through [`crate::scaled_polls`].
const EXIT_POLLS: u32 = 10_000;
/// CPUs whose standing the deleter keeps apart ([`cpu_slot`]).
const CPU_SLOTS: usize = 16;
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
/// deleter takes its bits just before its change, and in an observed one just
/// after it too.
static WATCHED: AtomicU64 = AtomicU64::new(0);
/// Whether the deleter deletes [`WATCHED`]'s capability: before its change,
/// so the binding holds the notification's last reference, or, in an
/// observed round, after it.
static WATCHED_DOOMED: AtomicU32 = AtomicU32::new(0);
/// Whether the deleter rebinds the round's cap to the spare before its
/// delete; published before the round.
static REBIND: AtomicU32 = AtomicU32::new(0);
/// Whether the round is held ([`Plan::held`]); published before the round.
static HELD: AtomicU32 = AtomicU32::new(0);
/// Whether a held round is observed ([`Plan::observed`]); published before
/// the round.
static OBSERVED: AtomicU32 = AtomicU32::new(0);
/// The spare notification the deleter rebinds a round's cap to.
static SPARE: AtomicU64 = AtomicU64::new(0);
/// The notification the deleter signals once a held round's change is done,
/// which the controller waits on meanwhile ([`await_held`]).
static DONE: AtomicU64 = AtomicU64::new(0);
/// Where the last held round's change fell against its delivery
/// ([`Outcome::code`]), stored before [`DELETED`]; 0 for a round with no
/// outcome.
static OUTCOME: AtomicU32 = AtomicU32::new(0);
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

/// What a round's change does to the binding the delivery reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind
{
    /// The round's copy, bound to the round's notification, is deleted.
    Direct,
    /// The copy is rebound to the spare notification, then deleted.
    Rebound,
    /// The victim's copy is deleted beside the keeper's.
    Binding,
}

impl Kind
{
    const ALL: [Self; 3] = [Self::Direct, Self::Rebound, Self::Binding];

    /// The kind's slot in a [`Tally`] row.
    fn index(self) -> usize
    {
        match self
        {
            Self::Direct => 0,
            Self::Rebound => 1,
            Self::Binding => 2,
        }
    }

    fn name(self) -> &'static str
    {
        match self
        {
            Self::Direct => "direct",
            Self::Rebound => "rebound",
            Self::Binding => "binding",
        }
    }
}

/// How a round runs: its kind, its schedule (module doc § Two schedules), and
/// whether a held round is observed. The controller publishes it before the
/// round ([`REBIND`], [`HELD`], [`OBSERVED`]).
#[derive(Clone, Copy)]
struct Plan
{
    kind: Kind,
    /// The deleter raises once and makes its change while the controller
    /// waits; otherwise the controller streams raises.
    held: bool,
    /// In a held round, the deleter keeps the watched notification through
    /// the change and takes its bits after it too.
    observed: bool,
}

impl Plan
{
    /// The plan of fixed round `round` of kind `kind`: held by [`held`], and,
    /// when held, observed in every binding round and in the notification
    /// rounds [`observed`] picks.
    fn fixed(round: u32, kind: Kind) -> Self
    {
        Self {
            kind,
            held: held(round),
            observed: kind == Kind::Binding || observed(round),
        }
    }

    /// The plan of an extra round of kind `kind` ([`extend`]): held and
    /// observed, since only such a round can arm the race.
    fn extra(kind: Kind) -> Self
    {
        Self {
            kind,
            held: true,
            observed: true,
        }
    }
}

/// How a round's change fell against the deliveries.
#[derive(Clone, Copy)]
enum Ran
{
    /// A held round, with where its change fell against the raise's delivery
    /// when the deleter took the watched notification's bits before it.
    Held(Option<Outcome>),
    /// A streamed round, and whether a raise overlapped its change.
    Streamed
    {
        overlapped: bool
    },
}

/// Per kind of round (direct, rebound, binding): of the held rounds observed,
/// how many met their delivery (armed the race), came late or came early
/// ([`Outcome`]); how many streamed rounds overlapped the race; and how many
/// extra rounds ran ([`extend`]).
#[derive(Default)]
struct Tally
{
    held: [u32; 3],
    armed: [u32; 3],
    late: [u32; 3],
    early: [u32; 3],
    overlapped: [u32; 3],
    extra: [u32; 3],
}

impl Tally
{
    /// Count a round of `plan` that ran as `ran`. A held round that frees its
    /// notification is not observed and not counted.
    fn count(&mut self, plan: Plan, ran: Ran)
    {
        let kind = plan.kind;
        match ran
        {
            Ran::Held(Some(outcome)) if plan.observed =>
            {
                Self::bump(&mut self.held, kind);
                let row = match outcome
                {
                    Outcome::Late => &mut self.late,
                    Outcome::Met => &mut self.armed,
                    Outcome::Early => &mut self.early,
                };
                Self::bump(row, kind);
            }
            Ran::Streamed { overlapped: true } => Self::bump(&mut self.overlapped, kind),
            Ran::Held(_) | Ran::Streamed { overlapped: false } =>
            {}
        }
    }

    /// Add one to `row`'s count of `kind`.
    fn bump(row: &mut [u32; 3], kind: Kind)
    {
        if let Some(slot) = row.get_mut(kind.index())
        {
            *slot = slot.saturating_add(1);
        }
    }

    /// Of `row`, the count of `kind`.
    fn of(row: &[u32; 3], kind: Kind) -> u32
    {
        row.get(kind.index()).copied().unwrap_or(0)
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
/// [`BINDING_CYCLES`] binding rounds, each phase with the extra rounds its
/// required kind takes ([`extend`]), and require [`MIN_ARMED`] armed held
/// rounds of each required kind, on a system of `cpus` CPUs.
fn race(ctx: &TestContext, line: u64, cpus: u64) -> TestResult
{
    probe_delivery(ctx, line)?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create done notification failed")?;
    let raced = race_with(ctx, line, cpus, done);
    cap_delete(done).ok();
    raced
}

/// [`race`], with `done` the notification the deleter signals at the end of
/// each held round ([`DONE`]).
fn race_with(ctx: &TestContext, line: u64, cpus: u64, done: u64) -> TestResult
{
    let spare = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create spare notification failed")?;
    ROUND.store(0, Ordering::Release);
    OUTCOME.store(0, Ordering::Release);
    DELETING.store(0, Ordering::Release);
    DELETED.store(0, Ordering::Release);
    REBIND_FAILED.store(0, Ordering::Release);
    QUIT.store(0, Ordering::Release);
    SPARE.store(spare, Ordering::Release);
    DONE.store(done, Ordering::Release);
    let deleter = cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
        .map_err(|_| "stress::irq_route_delete_race: create deleter failed")?;
    // SAFETY: `DELETER_STACK` is a static stack, reached only through `addr_of!`.
    let top = unsafe { ChildStack::top(core::ptr::addr_of!(DELETER_STACK)) };
    // SAFETY: `deleter_entry` is an `extern "C" fn(u64) -> !` and
    // `DELETER_STACK` is this deleter's own stack for its lifetime.
    let started =
        unsafe { thread_configure(deleter, deleter_entry as *const () as u64, top, cpus) }
            .and_then(|()| thread_set_affinity(deleter, DELETER_CPU))
            .map_err(|_| "stress::irq_route_delete_race: configure deleter failed")
            .and_then(|()| {
                // The deleter raises the held rounds' interrupts itself.
                grant_tx_interrupt(deleter)
                    .then_some(())
                    .ok_or("stress::irq_route_delete_race: grant the deleter the UART failed")
            })
            .and_then(|()| {
                thread_start(deleter)
                    .map_err(|_| "stress::irq_route_delete_race: start deleter failed")
            });
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
    report(&tally)
}

/// Log each kind's counts, and require each kind's observed held rounds that
/// armed the race to number what it needs ([`armed_needed`]).
fn report(tally: &Tally) -> TestResult
{
    let mut short = false;
    for kind in Kind::ALL
    {
        let armed = Tally::of(&tally.armed, kind);
        let needed = armed_needed(kind);
        crate::log_args(format_args!(
            "stress::irq_route_delete_race: armed_{name}={armed} of {held} observed (needed \
             {needed}; late {late}, early {early}; {extra} extra rounds), \
             overlapped_{name}={overlapped}",
            name = kind.name(),
            held = Tally::of(&tally.held, kind),
            late = Tally::of(&tally.late, kind),
            early = Tally::of(&tally.early, kind),
            extra = Tally::of(&tally.extra, kind),
            overlapped = Tally::of(&tally.overlapped, kind),
        ));
        short |= armed < needed;
    }
    if short
    {
        return Err(
            "stress::irq_route_delete_race: fewer held rounds of some kind armed the race than it needs",
        );
    }
    Ok(())
}

/// The observed held rounds of `kind` that must arm the race: [`MIN_ARMED`],
/// or none for a rebound round, which arms only when the rebind's store lands
/// between a delivery's load of the notification and its signal, the last
/// steps of a delivery that masks the line first: too narrow a window to
/// require (module doc § Two schedules).
fn armed_needed(kind: Kind) -> u32
{
    if kind == Kind::Rebound { 0 } else { MIN_ARMED }
}

/// The notification rounds, then the binding rounds, each phase followed by
/// the extra rounds its required kind takes ([`extend`]). The spare is
/// deleted whatever the outcome.
fn phases(ctx: &TestContext, line: u64, spare: u64) -> Result<Tally, &'static str>
{
    let mut tally = Tally::default();
    // Every round routes the line once, so the rounds' numbers stay in step
    // with the routes' turn over the CPUs ([`cpu_slot`]).
    let mut round = 0;
    let notified = rounds(ctx, line, &mut round, &mut tally).and_then(|()| {
        extend(Kind::Direct, &mut round, &mut tally, |round, plan| {
            notification_round(ctx, line, round, plan)
        })
    });
    cap_delete(spare).ok();
    notified?;
    binding_rounds(ctx, line, &mut round, &mut tally)?;
    Ok(tally)
}

/// After a phase's fixed rounds, run held, observed rounds of `kind` through
/// `run`, numbered on from `round`, until the kind's armed rounds number what
/// it needs ([`armed_needed`]) or [`MAX_EXTRA_ROUNDS`] have run, and count
/// them into `tally`.
///
/// How often a held round arms depends on the host as much as on the kernel:
/// it needs the CPU that delivers and CPU 1 to run at once, which a host that
/// runs fewer of the guest's CPUs at a time than it has does in fewer rounds
/// (module doc § What the host must give). A change that no longer meets a
/// delivery in flight arms none, and fails the check after every extra round;
/// a slower host only takes more of them.
fn extend(
    kind: Kind,
    round: &mut u32,
    tally: &mut Tally,
    mut run: impl FnMut(u32, Plan) -> Result<Ran, &'static str>,
) -> TestResult
{
    let plan = Plan::extra(kind);
    let mut extra = 0;
    while Tally::of(&tally.armed, kind) < armed_needed(kind) && extra < MAX_EXTRA_ROUNDS
    {
        *round = round.saturating_add(1);
        extra = extra.saturating_add(1);
        let ran = run(*round, plan)?;
        tally.count(plan, ran);
    }
    if let Some(slot) = tally.extra.get_mut(kind.index())
    {
        *slot = extra;
    }
    Ok(())
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

/// Whether `round` runs held rather than streamed (module doc § Two
/// schedules): about half the fixed rounds of each kind, chosen by a bit of a
/// multiplicative hash of the round. A choice by the round number's low bits
/// would fall in step with the routes' turn over the CPUs, and hold a kind's
/// rounds on the same CPUs every time.
fn held(round: u32) -> bool
{
    round.wrapping_mul(2_654_435_761) & (1 << 16) != 0
}

/// Whether a held notification `round` is observed: the deleter keeps the
/// watched notification's capability through the change and takes its bits
/// after it (module doc § Two schedules). Three in four, by two more bits of
/// the hash, so the rest still have the change free the notification. Every
/// binding round is observed ([`Plan::fixed`]), since the victim outlives its
/// rounds.
fn observed(round: u32) -> bool
{
    round.wrapping_mul(2_654_435_761) & (3 << 13) != 0
}

/// The [`CYCLES`] fixed notification rounds, direct and rebound in turn,
/// numbered on from `round` and counted into `tally`.
fn rounds(ctx: &TestContext, line: u64, round: &mut u32, tally: &mut Tally) -> TestResult
{
    for cycle in 1..=CYCLES
    {
        *round = round.saturating_add(1);
        let kind = if cycle.is_multiple_of(2)
        {
            Kind::Rebound
        }
        else
        {
            Kind::Direct
        };
        let plan = Plan::fixed(*round, kind);
        let ran = notification_round(ctx, line, *round, plan)?;
        tally.count(plan, ran);
    }
    Ok(())
}

/// One notification round, `round`, run to `plan`: a fresh notification bound
/// through a fresh copy of the line, whose change the deleter races against
/// the deliveries ([`race_delete`]).
fn notification_round(
    ctx: &TestContext,
    line: u64,
    round: u32,
    plan: Plan,
) -> Result<Ran, &'static str>
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
    // The deleter deletes `sig`'s capability: just before its change, so the
    // binding holds the notification's last reference and the deleter's
    // rebind or delete frees it, or, in an observed round, just after it
    // ([`Plan::observed`]).
    WATCHED_DOOMED.store(1, Ordering::Release);
    race_delete(round, plan, copy, sig, &[copy])
}

/// Hand `doomed`, whose binding signals `watched`, to the deleter for
/// `round`, run to `plan`, with the line just unmasked, and raise in the
/// round's schedule, acknowledging through `acks`; then acknowledge and raise
/// [`TRAILING_RAISES`] times more. Returns how the round's change fell against
/// the deliveries (module doc § Two schedules).
fn race_delete(
    round: u32,
    plan: Plan,
    doomed: u64,
    watched: u64,
    acks: &[u64],
) -> Result<Ran, &'static str>
{
    DOOMED.store(doomed, Ordering::Release);
    WATCHED.store(watched, Ordering::Release);
    REBIND.store(u32::from(plan.kind == Kind::Rebound), Ordering::Release);
    HELD.store(u32::from(plan.held), Ordering::Release);
    OBSERVED.store(u32::from(plan.observed), Ordering::Release);
    ROUND.store(round, Ordering::Release);
    let ran = if plan.held
    {
        // The deleter raises and changes; this CPU sleeps meanwhile, so it
        // can take the delivery while the change runs.
        await_held(round)?;
        Ran::Held(Outcome::decode(OUTCOME.load(Ordering::Acquire)))
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
        Ran::Streamed { overlapped }
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
    Ok(ran)
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

/// Wait, blocked, for held `round`'s change: the deleter signals [`DONE`]
/// once it has stored the round's outcome and [`DELETED`]. A bit a round
/// before left only wakes the wait early. Bounded, as [`await_delete`].
fn await_held(round: u32) -> TestResult
{
    let done = DONE.load(Ordering::Acquire);
    let mut polls = 0u32;
    while DELETED.load(Ordering::Acquire) != round
    {
        polls = polls.saturating_add(1);
        if polls > crate::scaled_polls(EXIT_POLLS)
        {
            return Err("stress::irq_route_delete_race: deleter never deleted");
        }
        notification_wait_timeout(done, 1).ok();
    }
    Ok(())
}

/// The [`BINDING_CYCLES`] fixed binding rounds, then the extra ones the
/// binding rounds take ([`extend`]), numbered on from `round` and counted into
/// `tally`.
fn binding_rounds(ctx: &TestContext, line: u64, round: &mut u32, tally: &mut Tally) -> TestResult
{
    let keeper = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::irq_route_delete_race: create keeper notification failed")?;
    let victim = cap_create_notification(ctx.memory_base);
    let result = victim
        .map_err(|_| "stress::irq_route_delete_race: create victim notification failed")
        .and_then(|victim| {
            let ntfs = [keeper, victim];
            (0..BINDING_CYCLES).try_for_each(|_| {
                *round = round.saturating_add(1);
                let plan = Plan::fixed(*round, Kind::Binding);
                let ran = binding_round(line, *round, plan, ntfs)?;
                tally.count(plan, ran);
                Ok(())
            })?;
            extend(Kind::Binding, round, tally, |round, plan| {
                binding_round(line, round, plan, ntfs)
            })
        });
    if let Ok(victim) = victim
    {
        cap_delete(victim).ok();
    }
    cap_delete(keeper).ok();
    result
}

/// One binding round, `round`, run to `plan`: a kept copy of the line,
/// holding its route, bound to `ntfs[0]` (the keeper) and a doomed copy bound
/// to `ntfs[1]` (the victim), whose cap the deleter deletes as the
/// controller's raises are delivered; then the kept binding must be served.
/// Returns how the round's change fell against the deliveries.
fn binding_round(line: u64, round: u32, plan: Plan, ntfs: [u64; 2]) -> Result<Ran, &'static str>
{
    let kept = cap_derive(line, RIGHTS_ALL)
        .map_err(|_| "stress::irq_route_delete_race: derive the kept copy failed")?;
    let result = cap_derive(line, RIGHTS_ALL)
        .map_err(|_| "stress::irq_route_delete_race: derive the doomed copy failed")
        .and_then(|doomed| race_binding_delete(round, plan, [kept, doomed], ntfs));
    quiet_tx_interrupt();
    // The kept copy is the line's route holder and last binding: its delete
    // releases the line, so the next round's route takes the next CPU.
    cap_delete(kept).ok();
    result
}

/// Route the line through `caps[0]` (kept), bind it and `caps[1]` (doomed),
/// race the deleter's delete of the doomed copy ([`race_delete`]), and require
/// the kept copy's notification to be signalled after.
fn race_binding_delete(
    round: u32,
    plan: Plan,
    caps: [u64; 2],
    ntfs: [u64; 2],
) -> Result<Ran, &'static str>
{
    let [kept, doomed] = caps;
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
    let ran = race_delete(round, plan, doomed, ntfs[1], &caps)?;
    // Consume what the raises left, then require one more delivery: the
    // removal of the doomed binding must leave the kept one bound and served.
    notification_wait_timeout(ntfs[0], 1).ok();
    irq_ack(kept).ok();
    raise_tx_interrupt();
    let bits = notification_wait_timeout(ntfs[0], crate::scaled_bound(PROBE_TIMEOUT_MS));
    quiet_tx_interrupt();
    match bits
    {
        Ok(bits) if bits & 1 != 0 => Ok(ran),
        _ => Err("stress::irq_route_delete_race: the kept binding was not served after the delete"),
    }
}

/// Where a held round's change fell against the raise's delivery, as the
/// deleter's two takes of the watched notification's bits bracket it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome
{
    /// The delivery had signalled before the change began.
    Late,
    /// It signalled after the take before the change and by the take after
    /// it: it read the binding, or the notification, while the change ran.
    Met,
    /// It had not signalled when the change returned: the change came first.
    Early,
}

impl Outcome
{
    /// `outcome` as [`OUTCOME`] carries it to the controller: 0 for none.
    fn code(outcome: Option<Self>) -> u32
    {
        match outcome
        {
            None => 0,
            Some(Self::Late) => 1,
            Some(Self::Met) => 2,
            Some(Self::Early) => 3,
        }
    }

    /// The outcome [`Outcome::code`] gave `code`.
    fn decode(code: u32) -> Option<Self>
    {
        match code
        {
            1 => Some(Self::Late),
            2 => Some(Self::Met),
            3 => Some(Self::Early),
            _ => None,
        }
    }
}

/// The next delay, in spins, after a held round that waited `delay` and came
/// out as `outcome`: a quarter shorter when the change came late, a quarter
/// longer when it came early, the same when it met the delivery. The delay so
/// settles where the changes meet deliveries.
fn next_delay(delay: u32, outcome: Outcome) -> u32
{
    match outcome
    {
        Outcome::Late => delay.saturating_sub(delay / 4),
        Outcome::Met => delay,
        Outcome::Early => delay
            .saturating_add(delay / 4)
            .saturating_add(1)
            .min(MAX_DELAY_SPINS),
    }
}

/// The delay of a row of held rounds after one that waited `delay` and came
/// out as `outcome`, delivered on a CPU whose slot has `standing`: the slot's
/// rounds that met their delivery or came early, less those that came late.
///
/// A round that delivers on CPU 1 comes late whatever the delay
/// (module doc § Two schedules), so a late round shortens the delay only when
/// its slot stands above zero: one whose rounds have come early or met their
/// delivery more often than late. Every other round fits the delay. The CPUs
/// that can arm share one delay, which so fits in a few dozen of the row's
/// rounds at any CPU count, where a delay per CPU would take as many of each
/// CPU's.
fn pace(delay: u32, standing: &mut i32, outcome: Outcome) -> u32
{
    let counts = outcome != Outcome::Late || *standing > 0;
    *standing = if outcome == Outcome::Late
    {
        standing.saturating_sub(1)
    }
    else
    {
        standing.saturating_add(1)
    };
    if counts
    {
        next_delay(delay, outcome)
    }
    else
    {
        delay
    }
}

/// The standing slot ([`pace`]) of the CPU that delivers `round` at `cpus`
/// CPUs: the routes take the CPUs in turn, one per round, so the round number
/// modulo the CPU count stands for the CPU. Past [`CPU_SLOTS`] CPUs, CPUs
/// share a slot, and CPU 1 shares its with CPUs that can arm.
fn cpu_slot(round: u32, cpus: u64) -> usize
{
    u64::from(round)
        .checked_rem(cpus.max(1))
        .and_then(|cpu| cpu.checked_rem(CPU_SLOTS as u64))
        .and_then(|slot| usize::try_from(slot).ok())
        .unwrap_or(0)
}

/// Deleter, for a system of `cpus` CPUs: per published round, wait as the
/// round's schedule says ([`HELD`]), delete the watched notification's
/// capability when the round asks (before the change, or after it in an
/// observed round), rebind the round's Interrupt cap to the spare when the
/// round asks, and delete it; exit on `QUIT`.
extern "C" fn deleter_entry(cpus: u64) -> !
{
    // One delay for the rounds whose change removes a binding (direct and
    // binding rounds), carried over from the one phase to the other, and one
    // for the rebound rounds, whose rebind meets a delivery at another point
    // of it; each with the standing of every CPU slot ([`pace`]).
    let mut delays = [0u32; 2];
    let mut standings = [[0i32; CPU_SLOTS]; 2];
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
        let watched_doomed = WATCHED_DOOMED.load(Ordering::Acquire) != 0;
        let held = HELD.load(Ordering::Acquire) != 0;
        let observe = held && OBSERVED.load(Ordering::Acquire) != 0;
        let row = usize::from(REBIND.load(Ordering::Acquire) != 0);
        let mut delay = 0;
        // Whether the raise's delivery had not signalled just before the
        // change.
        let mut unsignalled = false;
        if held
        {
            // Raise here, not on the controller: the change's wait counts from
            // the raise with no handoff between CPUs, which a host that
            // preempts either CPU would stretch past the delivery, and the
            // controller sleeps meanwhile ([`await_held`]).
            raise_tx_interrupt();
            delay = delays.get(row).copied().unwrap_or(0);
            for _ in 0..delay
            {
                core::hint::spin_loop();
            }
            unsignalled = notification_try_wait(watched).is_err();
        }
        else
        {
            // 0 to 4095 spins (a multiplicative hash of the round), so the
            // change lands at varying points in the stream of raises.
            for _ in 0..(round.wrapping_mul(2_654_435_761) >> 20)
            {
                core::hint::spin_loop();
            }
        }
        // The binding then holds the notification's last reference, and the
        // change frees it.
        if watched_doomed && !observe
        {
            cap_delete(watched).ok();
        }
        DELETING.store(round, Ordering::Release);
        let doomed = DOOMED.load(Ordering::Acquire);
        // Rebind first when the round asks, dropping the round's
        // notification's last reference while the line stays bound (in an
        // observed round the deleter's capability keeps it). A failed rebind
        // is counted and fails the cell.
        if REBIND.load(Ordering::Acquire) != 0
            && irq_register(doomed, SPARE.load(Ordering::Acquire), 0).is_err()
        {
            REBIND_FAILED.fetch_add(1, Ordering::AcqRel);
        }
        cap_delete(doomed).ok();
        // After the change no delivery reaches the watched notification
        // through the removed binding or the replaced notification, so a bit
        // now came from one that signalled between the two takes: while the
        // change ran, or in the moment between the first take and the
        // change's start.
        let outcome = if !held
        {
            None
        }
        else if !unsignalled
        {
            Some(Outcome::Late)
        }
        else if !observe
        {
            None
        }
        else if notification_try_wait(watched).is_ok()
        {
            Some(Outcome::Met)
        }
        else
        {
            Some(Outcome::Early)
        };
        if watched_doomed && observe
        {
            cap_delete(watched).ok();
        }
        let standing = standings
            .get_mut(row)
            .and_then(|slots| slots.get_mut(cpu_slot(round, cpus)));
        if let (Some(next), Some(standing), Some(outcome)) =
            (delays.get_mut(row), standing, outcome)
        {
            *next = pace(delay, standing, outcome);
        }
        OUTCOME.store(Outcome::code(outcome), Ordering::Release);
        DELETED.store(round, Ordering::Release);
        if held
        {
            notification_send(DONE.load(Ordering::Acquire), 1).ok();
        }
    }
}
