// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/irq.rs

//! Kernel IRQ routing table: maps interrupt lines to notification objects.
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
//! # Sizing
//! The table has one entry per line the discovered interrupt controllers
//! implement (`arch::current::interrupts::irq_line_count`: on x86-64 the GSIs the
//! I/O APICs cover, on riscv64 the PLIC's sources), allocated once at Phase 5 by
//! [`init_table`]. A line at or above that count is refused by [`register`] and
//! ignored by [`unregister`].
//!
//! # Sharing
//! A line routes to at most one notification. Every wired line the kernel serves
//! has a single owner: devmgr delegates a private Interrupt cap only for a line no
//! other device holds (docs/device-management.md § Interrupt Delivery); serving
//! shared lines is an open design (#664). A second registration on a line
//! replaces the first (`SYS_IRQ_REGISTER`, core/kernel/docs/syscalls.md).
//!
//! # Thread safety
//! The interrupt-context lookup in `dispatch_device_irq` is lock-free: it reads
//! the line's route through an atomic pointer. Every route change ([`register`],
//! [`unregister`], [`unregister_notification`]) and every unmask ([`ack`],
//! `SYS_IRQ_ACK`) runs under `ROUTING`'s lock, which also covers the controller
//! routing the change makes (`route_device_irq`, `unroute_device_irq`, `mask`,
//! `unmask`) and the set of routed lines, so an unmask never meets a line whose
//! route is being cleared.
//! Delivery itself (`notification_send`, `sched::enqueue_and_wake`) takes the
//! notification's and the scheduler's spinlocks with interrupts disabled.
//!
//! A delivery holds no reference on the notification it signals. Instead each
//! route counts the deliveries in flight through it (`IrqRoute::in_flight`),
//! raised before the route is read and dropped after the woken waiter is
//! enqueued. A route change that removes a notification from a line waits, under
//! the lock, for that line's count to drain before it returns, so once the lock
//! is free no delivery anywhere holds a notification that no line routes to. A
//! Notification's teardown therefore clears and drains only the lines that route
//! to it, found in the set of routed lines: it scales with the registrations, not
//! with the table, and no delivery on any CPU reaches the freed state
//! (core/kernel/docs/ipc-internals.md § Notification).

use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::ipc::notification::NotificationState;

// ── Routing table ─────────────────────────────────────────────────────────────

/// Per-IRQ routing entry.
///
/// The all-zero bit pattern is the empty entry (null route, no delivery in
/// flight), so a zero-filled allocation is a table of empty entries.
struct IrqRoute
{
    /// Atomic pointer to the `NotificationState` to notify, or null if unregistered.
    notification: AtomicPtr<NotificationState>,
    /// Number of `dispatch_device_irq` calls on this line between their raise
    /// (before reading `notification`) and their drop (after the last access
    /// to the state and to the woken waiter). The raise and the route read are
    /// `SeqCst`, as are a route change's store and its count reads, so a
    /// dispatcher that read a route a change since removed raised its count
    /// before the change reads it, and the change waits for it (`drain`).
    in_flight: AtomicU32,
}

/// Why a line could not be routed (`register`).
// dead_code: host test builds compile out `register` and the controller routing
// that construct the variants.
#[cfg_attr(test, allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError
{
    /// No discovered interrupt controller implements the line.
    NoSuchLine,
    /// The controller has no free delivery resource left for the line (on
    /// x86-64, every device IDT vector is assigned).
    Exhausted,
}

/// Dense set of line ids with constant-time insert and remove: the lines that
/// currently route to a notification.
///
/// `members[..len]` lists the lines; `slot_of[line]` is the line's index in
/// `members` plus one, or 0 when the line is not a member, so a zero-filled
/// `slot_of` is the empty set. Both slices have one entry per line.
struct LineSet<S>
{
    members: S,
    slot_of: S,
    len: usize,
}

impl<S: AsRef<[u32]> + AsMut<[u32]>> LineSet<S>
{
    /// Add `line` (a no-op when it is already a member). `line` must be below
    /// the set's line count.
    fn insert(&mut self, line: u32)
    {
        let index = line as usize;
        if self.slot_of.as_ref()[index] != 0
        {
            return;
        }
        self.members.as_mut()[self.len] = line;
        // The set holds at most one entry per line, so `len + 1` fits a line id.
        #[allow(clippy::cast_possible_truncation)]
        let slot = (self.len + 1) as u32;
        self.slot_of.as_mut()[index] = slot;
        self.len += 1;
    }

    /// Remove `line` (a no-op when it is not a member), moving the last member
    /// into its slot. `line` must be below the set's line count.
    fn remove(&mut self, line: u32)
    {
        let index = line as usize;
        let slot = self.slot_of.as_ref()[index] as usize;
        if slot == 0
        {
            return;
        }
        let last = self.members.as_ref()[self.len - 1];
        self.members.as_mut()[slot - 1] = last;
        // `slot` was a member index plus one, so it fits a line id.
        #[allow(clippy::cast_possible_truncation)]
        let moved = slot as u32;
        self.slot_of.as_mut()[last as usize] = moved;
        self.slot_of.as_mut()[index] = 0;
        self.len -= 1;
    }

    /// The member at `position` (below [`LineSet::len`]).
    fn member(&self, position: usize) -> u32
    {
        self.members.as_ref()[position]
    }

    /// The number of members.
    fn len(&self) -> usize
    {
        self.len
    }
}

/// The routing state a route change mutates: the table and the routed-line set.
#[cfg(not(test))]
struct Routing
{
    /// The table: `line_count` entries, or none before [`init_table`].
    routes: &'static [IrqRoute],
    /// The lines whose route is non-null.
    routed: LineSet<&'static mut [u32]>,
}

/// A value its spinlock serialises: the only access is [`Locked::with`], which
/// holds the lock (interrupts disabled) for the closure's duration.
#[cfg(not(test))]
struct Locked<T>
{
    lock: crate::sync::Spinlock,
    value: core::cell::UnsafeCell<T>,
}

// SAFETY: `value` is reached only through `with`, under `lock`.
#[cfg(not(test))]
unsafe impl<T: Send> Sync for Locked<T> {}

#[cfg(not(test))]
impl<T> Locked<T>
{
    const fn new(value: T) -> Self
    {
        Self {
            lock: crate::sync::Spinlock::new(),
            value: core::cell::UnsafeCell::new(value),
        }
    }

    /// Run `f` on the value with the lock held and interrupts disabled.
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R
    {
        // SAFETY: paired with unlock_raw below on the only path out.
        let saved = unsafe { self.lock.lock_raw() };
        // SAFETY: the lock is held, so this is the only reference to the value.
        let result = f(unsafe { &mut *self.value.get() });
        // SAFETY: paired with lock_raw above.
        unsafe { self.lock.unlock_raw(saved) };
        result
    }
}

/// The routing state, serialised by its lock. Lock order: this lock, then the
/// controller's leaf locks (x86-64 `IOAPIC_LOCK`, riscv64 `PLIC_LOCK`), which the
/// controller routing calls take. It is never taken in interrupt context.
#[cfg(not(test))]
static ROUTING: Locked<Routing> = Locked::new(Routing {
    routes: &[],
    routed: LineSet {
        members: &mut [],
        slot_of: &mut [],
        len: 0,
    },
});

/// The table, published once by [`init_table`] for the lock-free reads of
/// [`dispatch_device_irq`]: its base (null before) and its entry count.
#[cfg(not(test))]
static TABLE_BASE: AtomicPtr<IrqRoute> = AtomicPtr::new(null_mut());
#[cfg(not(test))]
static TABLE_LEN: AtomicU32 = AtomicU32::new(0);

/// The table entry for `irq`, or `None` for a line past the table (or before
/// [`init_table`]).
#[cfg(not(test))]
fn route_of(irq: u32) -> Option<&'static IrqRoute>
{
    if irq >= TABLE_LEN.load(Ordering::Acquire)
    {
        return None;
    }
    let base = TABLE_BASE.load(Ordering::Acquire);
    // SAFETY: `init_table` publishes the length after the base (Release), and
    // both before any line is routed; `irq` is below the published length, so
    // the entry lies in the table, which lives for the kernel's lifetime.
    Some(unsafe { &*base.add(irq as usize) })
}

// ── Initialisation ───────────────────────────────────────────────────────────

// `init_table` places the set's `u32` arrays directly after the routes, so the
// route size must keep them aligned.
const _: () =
    assert!(core::mem::size_of::<IrqRoute>().is_multiple_of(core::mem::align_of::<u32>()));

/// Bytes the table and the routed-line set take for `line_count` lines.
#[cfg(not(test))]
const fn table_bytes(line_count: usize) -> usize
{
    line_count * (core::mem::size_of::<IrqRoute>() + 2 * core::mem::size_of::<u32>())
}

/// Allocate the routing table and the routed-line set for `line_count` lines
/// from the buddy allocator, zero-filled, and publish them.
///
/// Called once on the BSP at Phase 5, after the interrupt controllers are
/// discovered (`arch::current::interrupts::init`) and before any line is
/// routed. The table lives for the kernel's lifetime.
#[cfg(not(test))]
pub fn init_table(line_count: u32, allocator: &mut crate::mm::BuddyAllocator)
{
    let lines = line_count as usize;
    let pages = table_bytes(lines).div_ceil(crate::mm::PAGE_SIZE).max(1);
    let order = pages.next_power_of_two().trailing_zeros() as usize;
    if order > crate::mm::buddy::MAX_ORDER
    {
        crate::fatal("irq: routing table exceeds the largest buddy block");
    }
    let phys = allocator
        .alloc(order)
        .unwrap_or_else(|| crate::fatal("irq: out of memory for the routing table"));
    // A buddy block is page-aligned, so the routes at its base are aligned.
    let routes_base = crate::mm::paging::phys_to_virt(phys) as *mut IrqRoute;
    let bytes = (1usize << order) * crate::mm::PAGE_SIZE;
    // SAFETY: the block covers `bytes` of mapped, kernel-owned RAM just allocated.
    unsafe { core::ptr::write_bytes(routes_base.cast::<u8>(), 0, bytes) };
    // SAFETY: the allocation holds `lines` routes followed by two `u32` arrays of
    // `lines` entries (`table_bytes`), zero-filled, which is the empty route and
    // the empty set; the `u32` arrays start at a multiple of the route size, so
    // they are aligned. Nothing else references the allocation.
    let (routes, members, slot_of) = unsafe {
        let members = routes_base.add(lines).cast::<u32>();
        (
            core::slice::from_raw_parts(routes_base, lines),
            core::slice::from_raw_parts_mut(members, lines),
            core::slice::from_raw_parts_mut(members.add(lines), lines),
        )
    };
    ROUTING.with(|routing| {
        routing.routes = routes;
        routing.routed = LineSet {
            members,
            slot_of,
            len: 0,
        };
    });
    TABLE_BASE.store(routes_base, Ordering::Release);
    TABLE_LEN.store(line_count, Ordering::Release);
    crate::kprintln!("irq: routing table for {} lines", line_count);
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Route interrupt line `irq` to `notification`: program the line at its
/// controller (masked, until the driver's `SYS_IRQ_ACK`) and record the route.
///
/// Replaces any previous registration for the same line. A delivery that read
/// the replaced pointer is waited out before this returns (module doc § Thread
/// safety). The store is `SeqCst`, as every route write is.
///
/// # Errors
/// [`RouteError::NoSuchLine`] when the line is past the table or no controller
/// implements it; [`RouteError::Exhausted`] when the controller cannot assign it
/// a delivery resource. The route is unchanged on error.
///
/// # Safety
/// - `notification` must be a valid, live `NotificationState` pointer.
/// - Must be called outside interrupt context, with no IPC source, scheduler,
///   or sleep-list lock held: the drain waits for a delivery that takes them.
#[cfg(not(test))]
pub unsafe fn register(irq: u32, notification: *mut NotificationState) -> Result<(), RouteError>
{
    ROUTING.with(|routing| {
        let route = routing
            .routes
            .get(irq as usize)
            .ok_or(RouteError::NoSuchLine)?;
        // SAFETY: called after Phase 5 with a line the table covers; serialised
        // with every other route change by the routing lock.
        unsafe { crate::arch::current::interrupts::route_device_irq(irq) }?;
        let previous = route.notification.swap(notification, Ordering::SeqCst);
        routing.routed.insert(irq);
        if !previous.is_null() && previous != notification
        {
            drain(route);
        }
        Ok(())
    })
}

/// Re-enable delivery on line `irq` after its driver handled an interrupt
/// (`SYS_IRQ_ACK`): unmask it at its controller, if a notification is routed to
/// it. A line with no route (never registered, or its route cleared) stays
/// masked; the check and the unmask run under the routing lock, so a concurrent
/// route clear cannot leave the line unmasked behind it.
///
/// # Safety
/// Same context as [`register`]: outside interrupt context, with no IPC source,
/// scheduler, or sleep-list lock held, since a holder of the routing lock may be
/// draining deliveries that take them.
#[cfg(not(test))]
pub unsafe fn ack(irq: u32)
{
    ROUTING.with(|routing| {
        let routed = routing
            .routes
            .get(irq as usize)
            .is_some_and(|route| !route.notification.load(Ordering::SeqCst).is_null());
        if routed
        {
            crate::arch::current::interrupts::unmask(irq);
        }
    });
}

/// Clear the routing entry for `irq` (called when the Interrupt cap is freed)
/// and release the line at its controller.
///
/// A delivery that read the cleared pointer is waited out before this returns,
/// as for [`register`]'s replace. A line past the table, or one with no route,
/// is left untouched.
///
/// # Safety
/// Same context as [`register`].
#[cfg(not(test))]
pub unsafe fn unregister(irq: u32)
{
    ROUTING.with(|routing| {
        let Some(route) = routing.routes.get(irq as usize)
        else
        {
            return;
        };
        if route
            .notification
            .swap(null_mut(), Ordering::SeqCst)
            .is_null()
        {
            return;
        }
        routing.routed.remove(irq);
        drain(route);
        // SAFETY: the line was routed; serialised by the routing lock.
        unsafe { crate::arch::current::interrupts::unroute_device_irq(irq) };
    });
}

/// Clear every route to `notification` and wait out every delivery that may
/// have read it (called when a Notification object is being freed, before its
/// state is).
///
/// After this returns, no `dispatch_device_irq` on any CPU dereferences
/// `notification`. Under the routing lock, every line that routes to it is in
/// the routed-line set; each is cleared (`SeqCst`), drained, masked, and
/// released at its controller. A line that routed to it earlier lost that route
/// through a [`register`] replace or an [`unregister`], each of which drained the
/// line before releasing the lock (module doc § Thread safety). The walk visits
/// the routed lines only.
///
/// # Safety
/// - `notification` must be a valid (still live) `NotificationState` pointer.
/// - Same context as [`register`].
#[cfg(not(test))]
pub unsafe fn unregister_notification(notification: *mut NotificationState)
{
    ROUTING.with(|routing| {
        let mut position = 0;
        while position < routing.routed.len()
        {
            let line = routing.routed.member(position);
            let route = &routing.routes[line as usize];
            if route.notification.load(Ordering::SeqCst) != notification
            {
                position += 1;
                continue;
            }
            route.notification.store(null_mut(), Ordering::SeqCst);
            // Swap-remove moves the last member into `position`; it is visited
            // next, so `position` does not advance.
            routing.routed.remove(line);
            drain(route);
            crate::arch::current::interrupts::mask(line);
            // SAFETY: the line was routed; serialised by the routing lock.
            unsafe { crate::arch::current::interrupts::unroute_device_irq(line) };
        }
    });
}

/// Wait until no delivery is in flight through `route`, whose route a change
/// just replaced or cleared (`SeqCst`).
///
/// Runs under the routing lock with interrupts disabled, under the spin-site
/// breadcrumb `irq:route-drain` (`sched::SPIN_SITE_IRQ_ROUTE_DRAIN`), which the
/// softlockup watchdog names if the wait wedges. It is bounded: a counted
/// delivery runs with interrupts disabled from its raise to its drop, takes only
/// the notification's and the scheduler's spinlocks, and waits for nothing the
/// caller holds; and every delivery masks its line until its driver's
/// `SYS_IRQ_ACK`, so the count falls to zero between deliveries. The wait is
/// therefore at most the deliveries already in flight on the line.
#[cfg(not(test))]
fn drain(route: &IrqRoute)
{
    // SeqCst pairs with the dispatcher's raise and route read: either the
    // dispatcher read the new route, or this load sees its raise.
    if route.in_flight.load(Ordering::SeqCst) == 0
    {
        return;
    }
    crate::sched::spin_site_enter(crate::sched::SPIN_SITE_IRQ_ROUTE_DRAIN);
    while route.in_flight.load(Ordering::SeqCst) != 0
    {
        core::hint::spin_loop();
    }
    crate::sched::spin_site_exit();
}

// ── Delivery target ───────────────────────────────────────────────────────────

/// The CPU the next routed line is delivered to, as a logical index; advanced
/// by [`next_target_cpu`].
#[cfg(not(test))]
static NEXT_TARGET_CPU: AtomicU32 = AtomicU32::new(0);

/// The first CPU at or after `start` (wrapping at `cpu_count`) that `eligible`
/// accepts, or `None` when it accepts none.
fn first_eligible_cpu(
    start: usize,
    cpu_count: usize,
    eligible: impl Fn(usize) -> bool,
) -> Option<usize>
{
    (0..cpu_count)
        .map(|offset| (start + offset) % cpu_count)
        .find(|&cpu| eligible(cpu))
}

/// The CPU a line being routed is delivered to: the boot CPUs in turn
/// (round-robin over the logical indices), skipping those `eligible` refuses,
/// so device interrupts spread over the CPUs rather than all landing on one.
/// Called by the controllers' `route_device_irq`, under the routing lock.
/// Returns `None` when `eligible` accepts no CPU.
#[cfg(not(test))]
pub fn next_target_cpu(eligible: impl Fn(usize) -> bool) -> Option<usize>
{
    let cpu_count = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
    let start = NEXT_TARGET_CPU.load(Ordering::Relaxed) as usize;
    let cpu = first_eligible_cpu(start, cpu_count.max(1), eligible)?;
    // The successor is below the CPU count, which fits u32.
    #[allow(clippy::cast_possible_truncation)]
    NEXT_TARGET_CPU.store(((cpu + 1) % cpu_count.max(1)) as u32, Ordering::Relaxed);
    Some(cpu)
}

/// Dispatch a hardware interrupt for `irq` to its registered notification.
///
/// Called from the arch-specific device IRQ path (x86-64: `idt::irq_dispatch`,
/// with the GSI its device vector is assigned to; RISC-V: the PLIC external
/// interrupt handler) with interrupts disabled.
///
/// Flow:
/// 1. Mask the IRQ at the controller (prevents re-entry until ACK).
/// 2. OR notification bit 0 into the registered notification.
/// 3. Acknowledge at the controller (send EOI / PLIC complete).
/// 4. If a waiter was unblocked, enqueue it on the scheduler.
///
/// If no notification is registered, or the line is past the table, the IRQ is
/// masked, acknowledged at the controller, and dropped.
///
/// # Safety
/// Must only be called from interrupt context with interrupts disabled.
#[cfg(not(test))]
pub unsafe fn dispatch_device_irq(irq: u32)
{
    let Some(route) = route_of(irq)
    else
    {
        // SAFETY: interrupt context with interrupts disabled (contract).
        unsafe { deliver(irq, null_mut()) };
        return;
    };

    // Fold an IRQ-arrival jitter sample (a distinct event class from timer
    // ticks) into this CPU's entropy accumulator. Allocation-free, lock-free.
    let jitter_cpu = crate::arch::current::cpu::current_cpu() as usize;
    crate::entropy::jitter::sample(
        jitter_cpu,
        crate::entropy::jitter::Source::Irq,
        crate::arch::current::entropy::read_cycle_counter(),
    );

    // Count this delivery before reading the route, so a route change that
    // removes the notification waits for it (`drain`). SeqCst on the raise and
    // the read pairs with the change's SeqCst store and count reads.
    route.in_flight.fetch_add(1, Ordering::SeqCst);
    let sig_ptr = route.notification.load(Ordering::SeqCst);
    // SAFETY: interrupt context with interrupts disabled (contract); sig_ptr
    // is null or a state this delivery's count keeps live.
    unsafe { deliver(irq, sig_ptr) };
    // Release: orders every access to the state and to the woken waiter before
    // a route change's drain observes the drop.
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
        // No handler registered: mask and drop. Must still acknowledge at the
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

#[cfg(test)]
mod tests
{
    use super::*;

    fn empty_set(lines: usize) -> LineSet<Vec<u32>>
    {
        LineSet {
            members: vec![0; lines],
            slot_of: vec![0; lines],
            len: 0,
        }
    }

    fn members(set: &LineSet<Vec<u32>>) -> Vec<u32>
    {
        let mut lines: Vec<u32> = (0..set.len()).map(|i| set.member(i)).collect();
        lines.sort_unstable();
        lines
    }

    #[test]
    fn zero_filled_set_is_empty_and_takes_line_zero()
    {
        // Line 0 is a valid GSI; a zero `slot_of` entry must mean "absent", not
        // "at slot 0".
        let mut set = empty_set(4);
        assert_eq!(set.len(), 0);
        set.insert(0);
        assert_eq!(members(&set), vec![0]);
    }

    #[test]
    fn inserting_a_member_again_keeps_one_entry()
    {
        let mut set = empty_set(8);
        set.insert(5);
        set.insert(5);
        assert_eq!(members(&set), vec![5]);
    }

    #[test]
    fn removing_a_middle_member_keeps_the_others_reachable()
    {
        // Swap-remove moves the last member into the freed slot; its slot index
        // must follow, or a later remove of it clears the wrong slot.
        let mut set = empty_set(8);
        for line in [1, 3, 6, 7]
        {
            set.insert(line);
        }
        set.remove(3);
        assert_eq!(members(&set), vec![1, 6, 7]);
        set.remove(7);
        assert_eq!(members(&set), vec![1, 6]);
        set.remove(1);
        set.remove(6);
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn removing_a_non_member_changes_nothing()
    {
        let mut set = empty_set(8);
        set.insert(2);
        set.remove(4);
        assert_eq!(members(&set), vec![2]);
    }

    #[test]
    fn target_selection_skips_ineligible_cpus_and_wraps()
    {
        // CPUs 1 and 2 ineligible (x86-64: an APIC id an I/O APIC cannot name).
        let eligible = |cpu: usize| cpu != 1 && cpu != 2;
        assert_eq!(first_eligible_cpu(1, 4, eligible), Some(3));
        assert_eq!(first_eligible_cpu(3, 4, eligible), Some(3));
        assert_eq!(first_eligible_cpu(0, 4, eligible), Some(0));
        // Wraps past the last CPU to the first eligible one.
        assert_eq!(first_eligible_cpu(2, 4, |cpu| cpu == 0), Some(0));
    }

    #[test]
    fn target_selection_with_no_eligible_cpu_is_none()
    {
        assert_eq!(first_eligible_cpu(0, 4, |_| false), None);
    }

    #[test]
    fn a_full_set_holds_every_line()
    {
        let mut set = empty_set(3);
        for line in 0..3
        {
            set.insert(line);
        }
        assert_eq!(members(&set), vec![0, 1, 2]);
    }
}
