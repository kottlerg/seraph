// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/msg_inject_delete_race.rs

//! Stress: deleting a message-signaled target's last capability on one CPU
//! while its interrupt is raised from another and delivered on a third.
//!
//! ## The hazard
//!
//! A message-signaled target's binding lives in its Interrupt object and is
//! anchored by the target's slot entry on its CPU; `irq::dispatch_device_irq`
//! reads the entry and signals the binding's notification inside that CPU's
//! delivery gate. Deleting the target's last capability frees the object:
//! `irq::unregister` clears the entry under the routing lock and waits out the
//! delivery in flight on the target's CPU before the object, and the
//! notification reference the binding held, go. A delivery that read the
//! entry before the clear and ran on after the free would signal through freed
//! memory (core/kernel/docs/ipc-internals.md § Notification, Device IRQ
//! delivery).
//!
//! ## How this exercises it
//!
//! On riscv64 a message is a write of the target's identity to the
//! `seteipnum` register of its hart's supervisor-level IMSIC file, which any
//! CPU can make through a mapping of the file: ktest maps the IMSIC aperture
//! that contains the target's message address, through a copy of its boot
//! `Mmio` cap, and writes the identity itself. Each round, the controller,
//! pinned to CPU 0, mints a target, binds it to a fresh notification, and
//! requires one write to signal it. An injector pinned to CPU 1 then writes
//! the identity in a loop while the controller waits a varying delay and
//! deletes the target's only capability. Mints take the CPUs in turn, so the
//! rounds deliver on every CPU, most of them neither the controller's nor the
//! injector's. Once the delete has returned the controller drains the
//! notification, lets the injector write [`TRAILING_WRITES`] more times into
//! the freed identity, and parks it.
//!
//! Required: the kernel survives every round, every round's first write
//! signals its notification, no signal reaches the notification after the
//! delete returned (a delivery the delete waited out signalled before it
//! returned, and any later one finds the slot free), and in some rounds an
//! injected write completed while the delete was running (the race armed).
//! The cell drives the interleaving on real CPUs; it does not by itself
//! prove the wait, since a delivery's span from the entry's read to its
//! signal is far shorter than anything a user thread can observe after the
//! delete. The host tests of `core/kernel/src/irq.rs` check the wait itself,
//! each failing when a change returns without waiting out the delivery.
//!
//! x86-64 has no counterpart: a message there is a write to the local APIC's
//! message window, which only a device's bus write reaches, and a CPU raises a
//! device vector only from ring 0, through the ICR. The same interleavings are
//! driven there by the host tests of `core/kernel/src/irq.rs`. The cell skips
//! where `crate::arch::MSG_INJECTABLE` is false.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use init_protocol::{CapType, InitInfo};
use syscall::{
    RIGHTS_ALL, cap_create_notification, cap_create_thread, cap_delete, cap_derive, irq_msg_alloc,
    irq_register, mem_unmap, notification_try_wait, notification_wait_timeout, system_info,
    thread_configure, thread_exit, thread_set_affinity, thread_start,
};
use syscall_abi::SystemInfoType;

use crate::unit::hw::{msg_authority, msg_of};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Rounds to run.
const CYCLES: u32 = 200;
const MIN_CPUS: u64 = 2;
const CONTROLLER_CPU: u32 = 0;
const INJECTOR_CPU: u32 = 1;
/// Writes the injector makes before the controller's delay starts.
const LEADING_WRITES: u64 = 8;
/// Writes after the delete returned, so injections also meet the freed slot.
const TRAILING_WRITES: u64 = 16;
/// Wait for a round's first signal, in ms, through [`crate::scaled_bound`].
const PROBE_TIMEOUT_MS: u64 = 1000;
/// Polls (1 ms each) for the injector's progress and exit, through
/// [`crate::scaled_polls`].
const WAIT_POLLS: u32 = 10_000;
/// Scratch VA the IMSIC aperture is mapped at (crate docs § Scratch VAs).
const FILE_VA: u64 = 0x1_7A00_0000;
/// Largest aperture the cell maps, in pages.
const MAX_APERTURE_PAGES: u64 = 1024;
const PAGE: u64 = 0x1000;

/// The VA the injector writes, the `seteipnum` register of the round's target;
/// 0 while the injector is parked.
static WRITE_VA: AtomicU64 = AtomicU64::new(0);
/// The identity the injector writes.
static IDENTITY: AtomicU32 = AtomicU32::new(0);
/// Writes the injector has made.
static WRITES: AtomicU64 = AtomicU64::new(0);
/// Set by the injector while it is between writes with [`WRITE_VA`] seen 0.
static PARKED: AtomicU32 = AtomicU32::new(0);
/// Set by the controller to end the injector.
static QUIT: AtomicU32 = AtomicU32::new(0);

static mut INJECTOR_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    if !crate::arch::MSG_INJECTABLE
    {
        crate::log(
            "ktest: stress::msg_inject_delete_race SKIP (no user-mode message write on this \
             architecture; the irq.rs host tests cover the race)",
        );
        return Ok(());
    }
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::msg_inject_delete_race: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::msg_inject_delete_race SKIP (need 2+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::msg_inject_delete_race: pin controller failed")?;
    let authority = msg_authority(ctx);
    let result = authority.and_then(|authority| {
        let raced = race(ctx, authority);
        cap_delete(authority).ok();
        raced
    });
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::msg_inject_delete_race: restore controller affinity failed");
    result?;
    restore
}

/// The boot `Mmio` aperture containing `address`: its descriptor's base, size
/// and capability handle.
fn aperture_of(ctx: &TestContext, address: u64) -> Option<(u64, u64, u64)>
{
    // SAFETY: the kernel maps the read-only InitInfo page at `init_info_va`
    // for ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    crate::init_info::descriptors(info)
        .iter()
        .find(|d| {
            d.cap_type == CapType::Mmio
                && address
                    .checked_sub(d.aux0)
                    .is_some_and(|offset| offset < d.aux1)
        })
        .map(|d| (d.aux0, d.aux1, d.slot))
}

/// The aperture mapped at [`FILE_VA`]: its base, its page count, and the copy
/// of its capability that maps it.
#[derive(Clone, Copy)]
struct Mapped
{
    base: u64,
    pages: u64,
    cap: u64,
}

/// Map the aperture containing `address` at [`FILE_VA`], replacing `current`
/// unless it already contains it; returns the VA of `address`.
fn map_file(
    ctx: &TestContext,
    current: &mut Option<Mapped>,
    address: u64,
) -> Result<u64, &'static str>
{
    if let Some(m) = *current
        && let Some(offset) = address.checked_sub(m.base)
        && let Some(span) = m.pages.checked_mul(PAGE)
        && offset < span
    {
        return FILE_VA
            .checked_add(offset)
            .ok_or("stress::msg_inject_delete_race: the file VA overflows");
    }
    unmap_file(ctx, current);
    let (base, size, slot) = aperture_of(ctx, address)
        .ok_or("stress::msg_inject_delete_race: no boot Mmio aperture holds the IMSIC file")?;
    let pages = size.div_ceil(PAGE);
    if pages > MAX_APERTURE_PAGES
    {
        return Err("stress::msg_inject_delete_race: the IMSIC aperture is too large to map");
    }
    let cap = cap_derive(slot, RIGHTS_ALL)
        .map_err(|_| "stress::msg_inject_delete_race: the IMSIC aperture's cap is gone")?;
    // SAFETY: `FILE_VA` is a scratch VA (crate docs § Scratch VAs) with room
    // for `MAX_APERTURE_PAGES` pages below the next band user, so the span
    // holds no Rust object or IPC page of ktest; the cell forms no reference
    // into it and unmaps it before the VA's next use (`mmio_map` § Safety).
    if unsafe { syscall::mmio_map(ctx.aspace_cap, cap, FILE_VA, 0) }.is_err()
    {
        cap_delete(cap).ok();
        return Err("stress::msg_inject_delete_race: mapping the IMSIC aperture failed");
    }
    *current = Some(Mapped { base, pages, cap });
    let offset = address
        .checked_sub(base)
        .ok_or("stress::msg_inject_delete_race: the address lies below its aperture")?;
    FILE_VA
        .checked_add(offset)
        .ok_or("stress::msg_inject_delete_race: the file VA overflows")
}

/// Unmap and drop the aperture `current` names, if any.
fn unmap_file(ctx: &TestContext, current: &mut Option<Mapped>)
{
    if let Some(m) = current.take()
    {
        // SAFETY: `FILE_VA` is a scratch VA (crate docs § Scratch VAs) that
        // only this cell maps, and it holds no Rust reference.
        let _ = unsafe { mem_unmap(ctx.aspace_cap, FILE_VA, m.pages) };
        cap_delete(m.cap).ok();
    }
}

/// Write `identity` to the `seteipnum` register at `va`.
fn inject(va: u64, identity: u32)
{
    // SAFETY: `va` lies in the IMSIC aperture mapped at `FILE_VA` and is the
    // 32-bit-aligned `seteipnum_le` register at the start of a file; the
    // write sets the identity's pending bit and touches no memory of ktest.
    unsafe { core::ptr::write_volatile(va as *mut u32, identity) };
}

/// Start the injector, run the rounds, stop it; then require some round to
/// have armed the race.
fn race(ctx: &TestContext, authority: u64) -> TestResult
{
    WRITE_VA.store(0, Ordering::Release);
    WRITES.store(0, Ordering::Release);
    PARKED.store(0, Ordering::Release);
    QUIT.store(0, Ordering::Release);
    let injector = cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
        .map_err(|_| "stress::msg_inject_delete_race: create injector failed")?;
    let top = ChildStack::top(core::ptr::addr_of!(INJECTOR_STACK));
    // SAFETY: `injector_entry` is an `extern "C" fn(u64) -> !` and
    // `INJECTOR_STACK` is this injector's own stack for its lifetime.
    let started = unsafe { thread_configure(injector, injector_entry as *const () as u64, top, 0) }
        .and_then(|()| thread_set_affinity(injector, INJECTOR_CPU))
        .and_then(|()| thread_start(injector))
        .map_err(|_| "stress::msg_inject_delete_race: start injector failed");
    let running = started.is_ok();
    let mut mapped = None;
    let raced = started.and_then(|()| {
        (1..=CYCLES).try_fold(0u32, |armed, round| {
            round_once(ctx, authority, round, &mut mapped)
                .map(|hit| armed.saturating_add(u32::from(hit)))
        })
    });
    WRITE_VA.store(0, Ordering::Release);
    QUIT.store(1, Ordering::Release);
    // An injector that never started is deleted without the wait.
    let exited = if running
    {
        spawn::wait_until_exited(injector, crate::scaled_polls(WAIT_POLLS)).map(|_| ())
    }
    else
    {
        Ok(())
    };
    cap_delete(injector).ok();
    unmap_file(ctx, &mut mapped);
    let armed = raced?;
    exited?;
    crate::log_u64("stress::msg_inject_delete_race: armed=", u64::from(armed));
    crate::log_u64(
        "stress::msg_inject_delete_race: writes=",
        WRITES.load(Ordering::Acquire),
    );
    if armed == 0
    {
        return Err("stress::msg_inject_delete_race: no write completed during a delete");
    }
    Ok(())
}

/// Wait (bounded) until the injector has made `count` writes in all.
fn await_writes(count: u64) -> TestResult
{
    let mut polls = 0u32;
    while WRITES.load(Ordering::Acquire) < count
    {
        polls = polls.saturating_add(1);
        if polls > crate::scaled_polls(WAIT_POLLS)
        {
            return Err("stress::msg_inject_delete_race: the injector stopped writing");
        }
        syscall::thread_sleep(1).ok();
    }
    Ok(())
}

/// Park the injector and wait (bounded) until it has seen the park.
fn park() -> TestResult
{
    PARKED.store(0, Ordering::Release);
    WRITE_VA.store(0, Ordering::Release);
    let mut polls = 0u32;
    while PARKED.load(Ordering::Acquire) == 0
    {
        polls = polls.saturating_add(1);
        if polls > crate::scaled_polls(WAIT_POLLS)
        {
            return Err("stress::msg_inject_delete_race: the injector never parked");
        }
        syscall::thread_sleep(1).ok();
    }
    Ok(())
}

/// One round: mint, bind and probe a target, then delete its capability while
/// the injector writes its identity. Returns whether a write completed while
/// the delete ran.
fn round_once(
    ctx: &TestContext,
    authority: u64,
    round: u32,
    mapped: &mut Option<Mapped>,
) -> Result<bool, &'static str>
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::msg_inject_delete_race: create notification failed")?;
    let result = (|| -> Result<bool, &'static str> {
        let target =
            irq_msg_alloc(authority).map_err(|_| "stress::msg_inject_delete_race: mint failed")?;
        let raced = race_delete(ctx, target, sig, round, mapped);
        // A failed step can leave the target live; its delete here is a
        // no-op once the race deleted it, since nothing is created after.
        cap_delete(target).ok();
        raced
    })();
    park().ok();
    cap_delete(sig).ok();
    result
}

/// The steps of [`round_once`] once `target` is minted.
fn race_delete(
    ctx: &TestContext,
    target: u64,
    sig: u64,
    round: u32,
    mapped: &mut Option<Mapped>,
) -> Result<bool, &'static str>
{
    let (address, data) =
        msg_of(target).map_err(|_| "stress::msg_inject_delete_race: no message")?;
    let identity =
        u32::try_from(data).map_err(|_| "stress::msg_inject_delete_race: identity past 32 bits")?;
    let va = map_file(ctx, mapped, address)?;
    irq_register(target, sig, 0).map_err(|_| "stress::msg_inject_delete_race: bind failed")?;
    // The round's first write must signal: the race below is not vacuous.
    inject(va, identity);
    match notification_wait_timeout(sig, crate::scaled_bound(PROBE_TIMEOUT_MS))
    {
        Ok(bits) if bits & 1 != 0 =>
        {}
        _ => return Err("stress::msg_inject_delete_race: an injected write was not delivered"),
    }
    IDENTITY.store(identity, Ordering::Release);
    WRITE_VA.store(va, Ordering::Release);
    await_writes(
        WRITES
            .load(Ordering::Acquire)
            .saturating_add(LEADING_WRITES),
    )?;
    // 0 to 4095 spins (a multiplicative hash of the round), so the delete
    // lands at varying points in the write sequence.
    for _ in 0..(round.wrapping_mul(2_654_435_761) >> 20)
    {
        core::hint::spin_loop();
    }
    let before = WRITES.load(Ordering::Acquire);
    cap_delete(target).map_err(|_| "stress::msg_inject_delete_race: delete failed")?;
    let after = WRITES.load(Ordering::Acquire);
    // Everything delivered up to the delete's return is drained; nothing may
    // follow it.
    let _ = notification_try_wait(sig);
    await_writes(after.saturating_add(TRAILING_WRITES))?;
    park()?;
    if notification_try_wait(sig).is_ok_and(|bits| bits != 0)
    {
        return Err("stress::msg_inject_delete_race: a delivery followed the delete");
    }
    // A write counted after `before` and before `after`, other than one that
    // was already under way at `before`, began and ended inside the delete.
    Ok(after > before.saturating_add(1))
}

/// Injector: while [`WRITE_VA`] is nonzero, write [`IDENTITY`] to it and count
/// the write; while it is 0, report itself parked; exit on [`QUIT`].
extern "C" fn injector_entry(_arg: u64) -> !
{
    loop
    {
        if QUIT.load(Ordering::Acquire) != 0
        {
            thread_exit();
        }
        let va = WRITE_VA.load(Ordering::Acquire);
        if va == 0
        {
            PARKED.store(1, Ordering::Release);
            core::hint::spin_loop();
            continue;
        }
        inject(va, IDENTITY.load(Ordering::Acquire));
        WRITES.fetch_add(1, Ordering::AcqRel);
    }
}
