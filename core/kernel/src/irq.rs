// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/irq.rs

//! Kernel IRQ routing table — maps interrupt lines to notification objects.
//!
//! When a device IRQ fires, the arch-specific interrupt handler calls
//! [`dispatch_device_irq`] with the interrupt line number. This module
//! looks up the registered [`NotificationState`], masks the IRQ at the controller
//! (preventing further delivery until the driver ACKs), ORs a notification
//! bit into the notification, and wakes any blocked waiter.
//!
//! Drivers register a notification via `SYS_IRQ_REGISTER` and re-enable delivery
//! via `SYS_IRQ_ACK` after handling.
//!
//! # Thread safety
//! The routing table uses atomic pointers, so registration and the
//! interrupt-context lookup in `dispatch_device_irq` are lock-free. Delivery
//! itself (`notification_send`, `sched::enqueue_and_wake`) takes the
//! notification's and the scheduler's spinlocks with interrupts disabled.
//!
//! A delivery holds no reference on the notification it signals. Instead each
//! route counts the deliveries in flight through it (`IrqRoute::in_flight`),
//! raised before the route is read and dropped after the woken waiter is
//! enqueued, and a Notification's teardown clears the routes naming it and
//! waits for every line's count to drain ([`unregister_notification`]) before
//! it frees the state, so no delivery on any CPU reaches freed memory, even
//! one that read a route an earlier replace or clear removed
//! (core/kernel/docs/ipc-internals.md § Notification).
//!
//! # Modification notes
//! - To support multiple notifications per IRQ line (e.g. shared interrupts): replace
//!   the single pointer with a small fixed-size list.

use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::ipc::notification::NotificationState;

// ── Routing table ─────────────────────────────────────────────────────────────

/// Maximum IRQ lines tracked. Covers x86-64 GSIs (0–255) and RISC-V PLIC
/// sources (1–127).
const MAX_IRQ: usize = 256;

// `SYS_IRQ_REGISTER` admits ids up to `MAX_IRQ_ID`, and `register` indexes the
// table by id: every admissible id must have an entry.
const _: () = assert!((crate::arch::current::MAX_IRQ_ID as usize) < MAX_IRQ);

/// Per-IRQ routing entry.
struct IrqRoute
{
    /// Atomic pointer to the `NotificationState` to notify, or null if unregistered.
    notification: AtomicPtr<NotificationState>,
    /// Number of `dispatch_device_irq` calls on this line between their raise
    /// (before reading `notification`) and their drop (after the last access
    /// to the state and to the woken waiter). The raise and the route read are
    /// `SeqCst`, as are every route write (`register`, `unregister`, and
    /// `unregister_notification`'s clears) and `unregister_notification`'s
    /// count reads, so a dispatcher that read a pointer a later write removed
    /// is counted when that notification's teardown reads the count.
    in_flight: AtomicU32,
}

impl IrqRoute
{
    const fn empty() -> Self
    {
        Self {
            notification: AtomicPtr::new(null_mut()),
            in_flight: AtomicU32::new(0),
        }
    }
}

/// Global IRQ routing table.
///
/// Entries are set at IRQ registration time and cleared on cap deallocation.
/// Uses atomic pointers for lock-free SMP-safe access from both registration
/// paths and interrupt handlers.
static IRQ_TABLE: [IrqRoute; MAX_IRQ] = {
    // const-initialise all entries to empty. IrqRoute contains AtomicPtr which
    // is not Copy, so we use a const block to evaluate the constructor for each
    // array element.
    [const { IrqRoute::empty() }; MAX_IRQ]
};

// ── Public interface ──────────────────────────────────────────────────────────

/// Register `notification` to receive notifications for interrupt line `irq`.
///
/// Replaces any previous registration for the same line. The store is
/// `SeqCst`: a delivery that read the replaced pointer is then ordered before
/// it, so the replaced notification's later teardown, whose in-flight scan is
/// `SeqCst` too, sees that delivery counted ([`unregister_notification`]).
///
/// # Safety
/// - `irq` must be < [`MAX_IRQ`].
/// - `notification` must be a valid, live `NotificationState` pointer (or null to clear).
#[cfg(not(test))]
pub unsafe fn register(irq: u32, notification: *mut NotificationState)
{
    debug_assert!((irq as usize) < MAX_IRQ, "irq out of range");
    // SeqCst, for the replaced pointer's teardown (rustdoc above). An
    // out-of-range `irq` panics at the index (the debug_assert reports it
    // first in debug builds).
    IRQ_TABLE[irq as usize]
        .notification
        .store(notification, Ordering::SeqCst);
}

/// Clear the routing entry for `irq` (called when the Interrupt cap is freed).
///
/// The store is `SeqCst`, as [`register`]'s is, so the teardown of the
/// notification the line routed to waits for a delivery that read it.
///
/// # Safety
/// - `irq` must be < [`MAX_IRQ`].
#[cfg(not(test))]
pub unsafe fn unregister(irq: u32)
{
    debug_assert!((irq as usize) < MAX_IRQ, "irq out of range");
    // SeqCst, for the cleared pointer's teardown (rustdoc above). An
    // out-of-range `irq` panics at the index (the debug_assert reports it
    // first in debug builds).
    IRQ_TABLE[irq as usize]
        .notification
        .store(null_mut(), Ordering::SeqCst);
}

/// Clear all routing entries that point to `notification` and wait out every
/// delivery that may have read it (called when a Notification object is being
/// freed, before its state is).
///
/// After this returns, no `dispatch_device_irq` on any CPU dereferences
/// `notification`. A delivery reads a route only after raising its line's
/// in-flight count, and every route write is `SeqCst`: this call's clears,
/// and the [`register`] replace or [`unregister`] clear that may have removed
/// `notification` from a line earlier. A delivery that read `notification` on
/// any line therefore precedes the write that removed it there, and so this
/// call's in-flight scan, which reads every line's count (`SeqCst`) and waits
/// while it is nonzero; a delivery that raises its count after a route stopped
/// naming `notification` reads a null or a different route. Each line this
/// call clears is masked, since it no longer has a handler.
///
/// The wait spins with interrupts enabled and preemption disabled, as
/// `sched::sleep_wakeups_quiesce` does, under the spin-site breadcrumb
/// `dealloc:irq-delivery` (`sched::SPIN_SITE_DEALLOC_IRQ_DELIVERY`), which the
/// softlockup watchdog names if the wait wedges. It is bounded: a counted
/// delivery runs with interrupts disabled from its raise to its drop, takes
/// only the notification's and the scheduler's spinlocks, and waits for
/// nothing this caller holds; and every delivery masks its line until its
/// driver's `SYS_IRQ_ACK`, so a line's count falls to zero between deliveries.
/// The wait is therefore at most one delivery per line in flight at the scan,
/// plus any that start on a line before its count is read zero.
///
/// O(`MAX_IRQ`) scan; acceptable since notification deallocation is infrequent.
///
/// # Safety
/// - `notification` must be a valid (still live) `NotificationState` pointer.
/// - Must be called outside interrupt context, with no IPC source, scheduler,
///   or sleep-list lock held: a counted delivery takes source and scheduler
///   locks.
#[cfg(not(test))]
pub unsafe fn unregister_notification(notification: *mut NotificationState)
{
    for (i, entry) in IRQ_TABLE.iter().enumerate()
    {
        // Pointer comparison on a possibly-stale value is safe (no deref).
        if entry
            .notification
            .compare_exchange(notification, null_mut(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // Mask the IRQ line since there's no longer a handler.
            // cast_possible_truncation: i < MAX_IRQ (= 256), which fits u32.
            #[allow(clippy::cast_possible_truncation)]
            crate::arch::current::interrupts::mask(i as u32);
        }
    }
    // A route a replace or an Interrupt-cap teardown removed earlier leaves no
    // line for the scan above to clear, so every line's count is read.
    if IRQ_TABLE
        .iter()
        .all(|entry| entry.in_flight.load(Ordering::SeqCst) == 0)
    {
        return;
    }
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    crate::sched::spin_site_enter(crate::sched::SPIN_SITE_DEALLOC_IRQ_DELIVERY);
    for entry in &IRQ_TABLE
    {
        // SeqCst pairs with the dispatcher's raise and route read: either the
        // dispatcher read a route that no longer names `notification`, or
        // this load sees its raise.
        while entry.in_flight.load(Ordering::SeqCst) != 0
        {
            core::hint::spin_loop();
        }
    }
    crate::sched::spin_site_exit();
    // SAFETY: saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
    crate::percpu::preempt_enable();
}

/// Dispatch a hardware interrupt for `irq` to its registered notification.
///
/// Called from the arch-specific device IRQ stub (x86-64: vectors 33–55;
/// RISC-V: PLIC external interrupt handler) with interrupts disabled.
///
/// Flow:
/// 1. Mask the IRQ at the controller (prevents re-entry until ACK).
/// 2. OR notification bit 0 into the registered notification.
/// 3. Acknowledge at the controller (send EOI / PLIC complete).
/// 4. If a waiter was unblocked, enqueue it on the scheduler.
///
/// If no notification is registered, the IRQ is masked, acknowledged at the
/// controller, and dropped.
///
/// # Safety
/// Must only be called from interrupt context with interrupts disabled.
#[cfg(not(test))]
pub unsafe fn dispatch_device_irq(irq: u32)
{
    if (irq as usize) >= MAX_IRQ
    {
        return;
    }

    // Fold an IRQ-arrival jitter sample (a distinct event class from timer
    // ticks) into this CPU's entropy accumulator. Allocation-free, lock-free.
    let jitter_cpu = crate::arch::current::cpu::current_cpu() as usize;
    crate::entropy::jitter::sample(
        jitter_cpu,
        crate::entropy::jitter::Source::Irq,
        crate::arch::current::entropy::read_cycle_counter(),
    );

    let route = &IRQ_TABLE[irq as usize];
    // Count this delivery before reading the route, so a Notification teardown
    // that clears the route waits for it (`unregister_notification`). SeqCst
    // on the raise and the read pairs with the clearer's SeqCst clear and
    // count read.
    route.in_flight.fetch_add(1, Ordering::SeqCst);
    let sig_ptr = route.notification.load(Ordering::SeqCst);
    // SAFETY: interrupt context with interrupts disabled (contract); sig_ptr
    // is null or a state this delivery's count keeps live.
    unsafe { deliver(irq, sig_ptr) };
    // Release: orders every access to the state and to the woken waiter before
    // a clearer's wait observes the drop.
    route.in_flight.fetch_sub(1, Ordering::Release);
}

/// The counted part of [`dispatch_device_irq`]: signal `sig_ptr` (or drop the
/// IRQ when it is null) and enqueue a waiter it woke.
///
/// # Safety
/// Interrupt context with interrupts disabled; `sig_ptr` null or a
/// `NotificationState` kept live by the line's in-flight count, which the
/// caller raised.
#[cfg(not(test))]
unsafe fn deliver(irq: u32, sig_ptr: *mut NotificationState)
{
    if sig_ptr.is_null()
    {
        // No handler registered — mask and drop. Must still acknowledge at the
        // controller: without this, the PLIC keeps the interrupt "in-service"
        // indefinitely, blocking all future external IRQs at the same priority
        // (all sources share priority 1 by default).
        crate::arch::current::interrupts::mask(irq);
        crate::arch::current::interrupts::acknowledge(irq);
        return;
    }

    // Mask the IRQ before delivering: prevents interrupt storm if the driver
    // is slow to ACK. The driver calls SYS_IRQ_ACK to unmask.
    crate::arch::current::interrupts::mask(irq);

    // Deliver notification bit 0: `SYS_IRQ_REGISTER` takes no bit argument,
    // so every registered line signals bit 0.
    // SAFETY: sig_ptr is non-null and live (the caller's in-flight count);
    // interrupts are disabled.
    let woken = unsafe { crate::ipc::notification::notification_send(sig_ptr, 1) };

    // Acknowledge at the interrupt controller (EOI / PLIC complete).
    crate::arch::current::interrupts::acknowledge(irq);

    // If notification_send woke a waiter, enqueue it so the scheduler picks it up.
    if let Some(tcb) = woken
    {
        // SAFETY: tcb is a valid ThreadControlBlock pointer returned by notification_send.
        let target_cpu = unsafe { crate::sched::select_target_cpu(tcb) };
        // SAFETY: tcb and target_cpu are valid; enqueue_and_wake sends wakeup IPI if needed.
        unsafe {
            crate::sched::enqueue_and_wake(tcb, target_cpu);
        }
    }
}
