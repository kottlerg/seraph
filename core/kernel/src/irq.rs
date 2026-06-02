// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/irq.rs

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
//! The routing table uses atomic pointers with Release/Acquire ordering for
//! SMP-safe registration and dispatch. `dispatch_device_irq` runs in interrupt
//! context and cannot spin on locks; atomic loads provide lock-free access.
//!
//! # Modification notes
//! - To support multiple notifications per IRQ line (e.g. shared interrupts): replace
//!   the single pointer with a small fixed-size list.

use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::ipc::notification::NotificationState;

// ── Routing table ─────────────────────────────────────────────────────────────

/// Maximum IRQ lines tracked. Covers x86-64 GSIs (0–255) and RISC-V PLIC
/// sources (1–127).
const MAX_IRQ: usize = 256;

/// Per-IRQ routing entry.
struct IrqRoute
{
    /// Atomic pointer to the `NotificationState` to notify, or null if unregistered.
    /// Uses Release/Acquire ordering for SMP-safe updates and reads.
    notification: AtomicPtr<NotificationState>,
}

impl IrqRoute
{
    const fn empty() -> Self
    {
        Self {
            notification: AtomicPtr::new(null_mut()),
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
/// Replaces any previous registration for the same line using atomic Release
/// ordering, ensuring visibility to all CPUs that later load the pointer.
///
/// # Safety
/// - `irq` must be < [`MAX_IRQ`].
/// - `notification` must be a valid, live `NotificationState` pointer (or null to clear).
#[cfg(not(test))]
pub unsafe fn register(irq: u32, notification: *mut NotificationState)
{
    debug_assert!((irq as usize) < MAX_IRQ, "irq out of range");
    // SAFETY: index is bounds-checked by debug_assert; Release ordering ensures
    // the stored pointer becomes visible to all CPUs that Acquire-load it.
    IRQ_TABLE[irq as usize]
        .notification
        .store(notification, Ordering::Release);
}

/// Clear the routing entry for `irq` (called when the Interrupt cap is freed).
///
/// # Safety
/// - `irq` must be < [`MAX_IRQ`].
#[cfg(not(test))]
pub unsafe fn unregister(irq: u32)
{
    debug_assert!((irq as usize) < MAX_IRQ, "irq out of range");
    // SAFETY: index is bounds-checked by debug_assert; Release ordering ensures
    // the null write becomes visible to all CPUs.
    IRQ_TABLE[irq as usize]
        .notification
        .store(null_mut(), Ordering::Release);
}

/// Clear all routing entries that point to `notification` (called when a Notification
/// object is being freed). Prevents use-after-free if a hardware IRQ fires
/// after the `NotificationState` has been deallocated.
///
/// O(`MAX_IRQ`) scan; acceptable since notification deallocation is infrequent.
///
/// # Safety
/// - `notification` must be a valid (still live) `NotificationState` pointer.
#[cfg(not(test))]
pub unsafe fn unregister_notification(notification: *mut NotificationState)
{
    for (i, entry) in IRQ_TABLE.iter().enumerate()
    {
        // SAFETY: Acquire ordering ensures we see the latest stored pointer value.
        // Pointer equality check is safe even if the pointer is dangling (no deref).
        let current = entry.notification.load(Ordering::Acquire);
        if core::ptr::eq(current, notification)
        {
            // SAFETY: Release ordering ensures the null write becomes visible to
            // all CPUs. Index is in bounds (iterator over IRQ_TABLE).
            entry.notification.store(null_mut(), Ordering::Release);
            // Mask the IRQ line since there's no longer a handler.
            // i is always < MAX_IRQ (= 256) which fits u32.
            #[allow(clippy::cast_possible_truncation)]
            crate::arch::current::interrupts::mask(i as u32);
        }
    }
}

/// Dispatch a hardware interrupt for `irq` to its registered notification.
///
/// Called from the arch-specific device IRQ stub (x86-64: vectors 33–55;
/// RISC-V: PLIC external interrupt handler) with interrupts disabled.
///
/// Flow:
/// 1. Mask the IRQ at the controller (prevents re-entry until ACK).
/// 2. OR notification bit 0 into the registered notification.
/// 3. If a waiter was unblocked, enqueue it on the scheduler.
/// 4. Acknowledge at the controller (send EOI / PLIC complete).
///
/// If no notification is registered, the IRQ is silently dropped (masked; no ACK).
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

    // SAFETY: index is bounds-checked; Acquire ordering ensures we see the
    // latest pointer stored by register/unregister on any CPU.
    let sig_ptr = IRQ_TABLE[irq as usize].notification.load(Ordering::Acquire);
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

    // Deliver one notification bit into the notification. Bit 0 is used for
    // single-IRQ-per-notification registration (the standard case).
    // SAFETY: sig_ptr is valid and non-null; interrupts are disabled.
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
