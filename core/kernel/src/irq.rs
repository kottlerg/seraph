// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/irq.rs

//! Kernel IRQ routing table: maps interrupt lines to the notifications bound to
//! them.
//!
//! When a device IRQ fires, the arch-specific interrupt handler calls
//! [`dispatch_device_irq`] with the interrupt line number. This module masks
//! the line at its controller (no further delivery until every receiver has
//! acknowledged), marks every binding on the line as owing an acknowledgement,
//! ORs notification bit 0 into each bound notification, and wakes its waiter.
//!
//! Drivers bind a notification via `SYS_IRQ_REGISTER` and acknowledge via
//! `SYS_IRQ_ACK` after handling.
//!
//! # Sizing
//! The table has one entry per line the discovered interrupt controllers
//! implement (`arch::current::interrupts::irq_line_count`: on x86-64 the GSIs the
//! I/O APICs cover, on riscv64 the APLIC's sources), allocated once at Phase 5 by
//! [`init_table`]. A line at or above that count is refused by [`register`].
//!
//! # Sharing
//! A wired line is a source with up to [`MAX_IRQ_BINDINGS`] bindings. A binding
//! ([`IrqBinding`]) lives in an Interrupt object, and a copy or derivation of an
//! Interrupt capability is a fresh object (`cap::object::object_for_new_slot`),
//! so every capability to a line binds on its own. The line's bound mask and
//! owing mask ([`LineMasks`]) hold one bit per binding: a delivery sets every
//! bound bit in the owing mask, an acknowledgement clears its own, and the line
//! is unmasked only once none owes (docs/device-management.md § Interrupt
//! Delivery; `SYS_IRQ_REGISTER` and `SYS_IRQ_ACK` in
//! core/kernel/docs/syscalls.md).
//!
//! # Mode
//! A line carries one trigger and polarity mode (`IRQ_MODE_LEVEL`,
//! `IRQ_MODE_ACTIVE_LOW` in `abi/syscall`), which its controller is programmed
//! with when the first binding routes it. The first binding records the mode
//! its `SYS_IRQ_REGISTER` passed; a later binding, or a rebind, that passes
//! another is refused ([`RouteError::ModeMismatch`], [`mode_admits`]) and
//! changes nothing. The line's release forgets the mode, so the next first
//! binding may record another.
//!
//! # Thread safety
//! The interrupt-context walk in `dispatch_device_irq` is lock-free: it reads the
//! line's bindings through atomic pointers. Every binding change ([`register`],
//! [`unregister`], [`unregister_notification`]) and every acknowledgement
//! ([`ack`], `SYS_IRQ_ACK`) runs under `ROUTING`'s lock, which also covers the
//! controller routing the change makes (`route_device_irq`, `unroute_device_irq`,
//! `mask`, `unmask`) and the set of routed lines, so an unmask never meets a line
//! whose last binding is being removed. A delivery only sets bits in the owing
//! mask; acknowledgements and unbinds clear them, under the lock.
//! Delivery itself (`notification_send`, `sched::enqueue_and_wake`) takes the
//! notification's and the scheduler's spinlocks with interrupts disabled.
//!
//! A delivery holds no reference on the bindings it walks or the notifications it
//! signals. Instead each line counts the deliveries in flight on it
//! (`IrqRoute::in_flight`), raised before the line's masks and bindings are read
//! and dropped after the last woken waiter is enqueued. A change that removes a
//! binding from a line, or a notification from a binding, waits under the lock
//! for that line's count to drain before it returns, so once the lock is free no
//! delivery anywhere holds a binding no line links or a notification no binding
//! names. A Notification's teardown therefore unbinds and drains only the lines
//! that bind it, found in the set of routed lines: it scales with the bindings,
//! not with the table, and no delivery on any CPU reaches the freed state
//! (core/kernel/docs/ipc-internals.md § Notification).

use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::ipc::notification::NotificationState;

// ── Bindings ──────────────────────────────────────────────────────────────────

/// Most bindings one line holds at once: one bit each in the line's bound and
/// owing masks ([`LineMasks`]), atomic words a delivery sets lock-free. A
/// `SYS_IRQ_REGISTER` past it returns `QuotaExceeded`.
///
/// The bound is not reached on plausible hardware. The receivers sharing a
/// wired line are the PCI functions that use `INTx`: PCI Express requires every
/// function that interrupts to support MSI or MSI-X, SR-IOV virtual functions
/// have no `INTx`, and once message-signalled delivery is served (#325, design
/// intent) only legacy-only functions stay on wired lines, so more than 64 of
/// them on one line is not a machine anyone builds. Linux bounds the same set
/// the same way: its `IRQF_ONESHOT` `threads_oneshot` bitmask refuses a sharer
/// past `BITS_PER_LONG`.
pub const MAX_IRQ_BINDINGS: u32 = u64::BITS;

/// [`IrqBinding::bit`] of a binding that is not bound.
const UNBOUND: u32 = u32::MAX;

/// One receiver's binding of an interrupt line: the state an Interrupt object
/// carries (`cap::object::InterruptObject`), so each capability to a line binds
/// on its own.
///
/// While bound, the binding is linked in its line's list and owns one bit of
/// the line's masks. `bit` is read and written only under the routing lock;
/// `next` and `notification` are written under it and read lock-free by
/// [`dispatch_device_irq`].
pub struct IrqBinding
{
    /// The next binding on the line, or null at the list's end.
    next: AtomicPtr<IrqBinding>,
    /// The notification a delivery signals; null while unbound.
    notification: AtomicPtr<NotificationState>,
    /// The binding's bit in its line's masks, or [`UNBOUND`].
    bit: AtomicU32,
}

impl IrqBinding
{
    /// A binding that is not bound to any line.
    #[must_use]
    pub const fn unbound() -> Self
    {
        Self {
            next: AtomicPtr::new(null_mut()),
            notification: AtomicPtr::new(null_mut()),
            bit: AtomicU32::new(UNBOUND),
        }
    }
}

/// A line's bound mask (one bit per binding) and owing mask (the bindings that
/// owe an acknowledgement).
///
/// The transitions are kept here, apart from the routing that drives them, so
/// they are host-tested. A delivery calls [`LineMasks::bound`] and
/// [`LineMasks::deliver`] lock-free, and `deliver` only sets bits in `owing`;
/// every other method runs under the routing lock. A bit is set in `owing` only
/// while it is set in `bound`, or between an unbind's
/// [`LineMasks::unbind_begin`] and [`LineMasks::unbind_settle`], which clears it
/// once no delivery that read the old bound mask is in flight.
struct LineMasks
{
    bound: AtomicU64,
    owing: AtomicU64,
}

/// What an unbind leaves the line to do at its controller
/// ([`LineMasks::unbind_settle`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settle
{
    /// No binding remains: mask the line and release it.
    Release,
    /// Bindings remain and none owes: unmask the line.
    Unmask,
    /// A remaining binding owes: leave the line masked.
    StayMasked,
}

impl LineMasks
{
    /// The bound mask, read by a delivery after it raised the line's in-flight
    /// count.
    fn bound(&self) -> u64
    {
        self.bound.load(Ordering::SeqCst)
    }

    /// The lowest bit no binding holds, or `None` when [`MAX_IRQ_BINDINGS`] are
    /// bound.
    fn free_bit(&self) -> Option<u32>
    {
        let bit = (!self.bound.load(Ordering::SeqCst)).trailing_zeros();
        (bit < MAX_IRQ_BINDINGS).then_some(bit)
    }

    /// Mark `bit` bound and owing: a new receiver owes its first
    /// acknowledgement, so the line stays masked until it gives it.
    fn take(&self, bit: u32)
    {
        self.bound.fetch_or(1 << bit, Ordering::SeqCst);
        self.owing.fetch_or(1 << bit, Ordering::SeqCst);
    }

    /// A delivery: every binding in `bound` (the mask the delivery read) now
    /// owes an acknowledgement.
    fn deliver(&self, bound: u64)
    {
        self.owing.fetch_or(bound, Ordering::SeqCst);
    }

    /// `bit`'s acknowledgement: clear its debt, and return whether no binding
    /// owes one any more, so the line is to be unmasked. Clearing a bit that
    /// owes nothing changes nothing.
    fn ack(&self, bit: u32) -> bool
    {
        let rest = self.owing.fetch_and(!(1 << bit), Ordering::SeqCst) & !(1 << bit);
        rest == 0
    }

    /// The first step of removing `bit`, before the line's drain: a delivery
    /// that reads the bound mask after this no longer marks `bit` owing.
    fn unbind_begin(&self, bit: u32)
    {
        self.bound.fetch_and(!(1 << bit), Ordering::SeqCst);
    }

    /// The last step of removing `bit`, after the line's drain: clear the debt
    /// a delivery that read the old bound mask may have set, and say what the
    /// line is left to do.
    fn unbind_settle(&self, bit: u32) -> Settle
    {
        let owing = self.owing.fetch_and(!(1 << bit), Ordering::SeqCst) & !(1 << bit);
        if self.bound.load(Ordering::SeqCst) == 0
        {
            Settle::Release
        }
        else if owing == 0
        {
            Settle::Unmask
        }
        else
        {
            Settle::StayMasked
        }
    }
}

// ── Routing table ─────────────────────────────────────────────────────────────

/// Per-IRQ routing entry.
///
/// The all-zero bit pattern is the empty entry (no binding, no delivery in
/// flight), so a zero-filled allocation is a table of empty entries.
struct IrqRoute
{
    /// The first binding on the line, or null when none is bound. Bindings are
    /// linked at the head and unlinked under the routing lock; the stores are
    /// `SeqCst`, as are a delivery's loads of every link.
    bindings: AtomicPtr<IrqBinding>,
    /// Number of `dispatch_device_irq` calls on this line between their raise
    /// (before reading `masks` and `bindings`) and their drop (after the last
    /// access to a binding, a notification, and a woken waiter). The raise and
    /// the reads are `SeqCst`, as are a change's stores and its count reads, so
    /// a dispatcher that read a binding or a notification a change since removed
    /// raised its count before the change reads it, and the change waits for it
    /// (`drain`).
    in_flight: AtomicU32,
    /// The mode the line's first binding recorded (module doc § Mode);
    /// meaningful only while a binding is linked. Read and written only under
    /// the routing lock, so `Relaxed`.
    mode: AtomicU32,
    /// The line's bound and owing masks.
    masks: LineMasks,
}

// docs/limits.md states the routing table's per-line cost from this size (with
// the routed-line set's two `u32` entries, `table_bytes`): an 8-byte list head,
// the in-flight count and the mode (4 bytes each), and the two 8-byte masks.
const _: () = assert!(core::mem::size_of::<IrqRoute>() == 32);

/// Why a line could not be bound (`register`).
// dead_code: host test builds compile out `register` and the controller routing
// that construct the variants.
#[cfg_attr(test, allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError
{
    /// No discovered interrupt controller implements the line.
    NoSuchLine,
    /// The controller has no free delivery resource left for the line (on
    /// x86-64, every device IDT vector is assigned; on riscv64, no CPU's IMSIC
    /// file has a free identity).
    Exhausted,
    /// The line already holds [`MAX_IRQ_BINDINGS`] bindings.
    TooManyBindings,
    /// The binding's mode differs from the one the line's bindings recorded
    /// (module doc § Mode).
    ModeMismatch,
}

/// Whether a binding passing `requested` may bind on a line that has bindings
/// (`line_bound`) recorded with `recorded`: a line with none takes any mode,
/// which it then records; a line with bindings takes only its own.
const fn mode_admits(line_bound: bool, recorded: u32, requested: u32) -> bool
{
    !line_bound || recorded == requested
}

/// Dense set of line ids with constant-time insert and remove: the lines that
/// hold at least one binding.
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
    /// The lines that hold at least one binding.
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
/// controller's leaf lock (x86-64 `IOAPIC_LOCK`), which the controller routing
/// calls take; the riscv64 APLIC accesses take none, each being a single register
/// write. It is never taken in interrupt context.
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
    // `lines` entries (`table_bytes`), zero-filled, which is the empty entry and
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

/// Bind `binding` (the binding of an Interrupt object for line `irq`) to
/// `notification` (`SYS_IRQ_REGISTER`), with the line's trigger and polarity
/// `mode` (module doc § Mode).
///
/// An unbound binding is added to the line: the line's first binding records
/// `mode` and routes the line at its controller in that mode, which leaves it
/// masked; a later binding masks it. The
/// new binding takes the lowest free bit of the line's masks and owes an
/// acknowledgement, so the line stays masked until its receiver's first
/// `SYS_IRQ_ACK`. A binding already bound is rebound to `notification`: it
/// keeps its bit and whether it owes, and the line's mask is unchanged; a
/// delivery that read the notification it replaced is waited out before this
/// returns (module doc § Thread safety).
///
/// # Errors
/// [`RouteError::NoSuchLine`] when the line is past the table or no controller
/// implements it; [`RouteError::ModeMismatch`] when the line has bindings and
/// `mode` differs from the one they recorded; [`RouteError::Exhausted`] when the
/// controller cannot assign the line's first binding a delivery resource;
/// [`RouteError::TooManyBindings`] when the line holds [`MAX_IRQ_BINDINGS`]
/// bindings. Nothing changes on error.
///
/// # Safety
/// - `notification` must be a valid, live `NotificationState` pointer.
/// - `binding` must be the binding of a live Interrupt object whose line is
///   `irq`, and that object must call [`unregister`] before it is freed.
/// - Must be called outside interrupt context, with no IPC source, scheduler,
///   or sleep-list lock held: the drain waits for a delivery that takes them.
#[cfg(not(test))]
pub unsafe fn register(
    irq: u32,
    binding: &IrqBinding,
    notification: *mut NotificationState,
    mode: u32,
) -> Result<(), RouteError>
{
    ROUTING.with(|routing| {
        let route = routing
            .routes
            .get(irq as usize)
            .ok_or(RouteError::NoSuchLine)?;
        let head = route.bindings.load(Ordering::Relaxed);
        if !mode_admits(!head.is_null(), route.mode.load(Ordering::Relaxed), mode)
        {
            return Err(RouteError::ModeMismatch);
        }
        if binding.bit.load(Ordering::Relaxed) != UNBOUND
        {
            let previous = binding.notification.swap(notification, Ordering::SeqCst);
            if previous != notification
            {
                drain(route);
            }
            return Ok(());
        }
        let bit = route.masks.free_bit().ok_or(RouteError::TooManyBindings)?;
        if head.is_null()
        {
            // SAFETY: called after Phase 5 with a line the table covers; serialised
            // with every other binding change by the routing lock.
            unsafe { crate::arch::current::interrupts::route_device_irq(irq, mode) }?;
            route.mode.store(mode, Ordering::Relaxed);
        }
        else
        {
            crate::arch::current::interrupts::mask(irq);
        }
        route.masks.take(bit);
        binding.bit.store(bit, Ordering::Relaxed);
        binding.notification.store(notification, Ordering::SeqCst);
        binding.next.store(head, Ordering::SeqCst);
        // Publish last: a delivery that reads the new head sees the binding's
        // notification and link.
        route
            .bindings
            .store(core::ptr::from_ref(binding).cast_mut(), Ordering::SeqCst);
        routing.routed.insert(irq);
        Ok(())
    })
}

/// Acknowledge line `irq` through `binding` (`SYS_IRQ_ACK`): clear the
/// binding's debt, and unmask the line at its controller when no binding on it
/// owes an acknowledgement. An acknowledgement that owes nothing clears nothing;
/// through an unbound binding it changes nothing. The check and the unmask run
/// under the routing lock, so a concurrent unbind cannot leave the line
/// unmasked behind it.
///
/// # Safety
/// Same context as [`register`]: outside interrupt context, with no IPC source,
/// scheduler, or sleep-list lock held, since a holder of the routing lock may be
/// draining deliveries that take them. `binding` is the binding of a live
/// Interrupt object whose line is `irq`.
#[cfg(not(test))]
pub unsafe fn ack(irq: u32, binding: &IrqBinding)
{
    ROUTING.with(|routing| {
        let bit = binding.bit.load(Ordering::Relaxed);
        if bit == UNBOUND
        {
            return;
        }
        let Some(route) = routing.routes.get(irq as usize)
        else
        {
            return;
        };
        if route.masks.ack(bit)
        {
            crate::arch::current::interrupts::unmask(irq);
        }
    });
}

/// Remove `binding` from line `irq` (called when its Interrupt object is
/// freed); a binding that is not bound is left untouched.
///
/// A delivery that read the binding is waited out before this returns. The line
/// is then released at its controller when no binding remains, and unmasked
/// when the remaining bindings owe nothing, so a receiver that goes cannot
/// hold a shared line masked.
///
/// # Safety
/// Same context as [`register`]; `binding` is the binding of an Interrupt object
/// whose line is `irq` and whose memory stays live until this returns.
#[cfg(not(test))]
pub unsafe fn unregister(irq: u32, binding: &IrqBinding)
{
    ROUTING.with(|routing| {
        if binding.bit.load(Ordering::Relaxed) == UNBOUND
        {
            return;
        }
        let routes = routing.routes;
        let Some(route) = routes.get(irq as usize)
        else
        {
            return;
        };
        // SAFETY: the routing lock is held and `binding` is bound on `irq`.
        unsafe { unbind(&mut routing.routed, irq, route, binding) };
    });
}

/// Remove every binding to `notification` and wait out every delivery that may
/// have read it (called when a Notification object is being freed, before its
/// state is).
///
/// After this returns, no `dispatch_device_irq` on any CPU dereferences
/// `notification`. Under the routing lock, every line with a binding to it is
/// in the routed-line set; each such binding is removed as [`unregister`]
/// removes one, so its Interrupt object stays and is unbound. A binding that
/// named it earlier lost it through a [`register`] rebind, which drained the
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
        let routes = routing.routes;
        let mut position = 0;
        while position < routing.routed.len()
        {
            let line = routing.routed.member(position);
            let route = &routes[line as usize];
            let mut released = false;
            // SAFETY: the routing lock is held, so every linked binding is live.
            while let Some(binding) = unsafe { binding_naming(route, notification) }
            {
                // SAFETY: the routing lock is held and `binding` is bound on `line`.
                if unsafe { unbind(&mut routing.routed, line, route, binding) } == Settle::Release
                {
                    released = true;
                    break;
                }
            }
            // A release swap-removes the line, moving the last member into
            // `position`; it is visited next, so `position` does not advance.
            if !released
            {
                position += 1;
            }
        }
    });
}

/// The first binding on `route` that names `notification`.
///
/// # Safety
/// Called under the routing lock, which keeps every linked binding live.
#[cfg(not(test))]
unsafe fn binding_naming<'a>(
    route: &IrqRoute,
    notification: *mut NotificationState,
) -> Option<&'a IrqBinding>
{
    let mut cur = route.bindings.load(Ordering::Relaxed);
    // SAFETY: caller contract; a linked binding is live under the lock.
    while let Some(binding) = unsafe { cur.as_ref() }
    {
        if binding.notification.load(Ordering::Relaxed) == notification
        {
            return Some(binding);
        }
        cur = binding.next.load(Ordering::Relaxed);
    }
    None
}

/// Remove bound `binding` from line `irq`: unlink it, clear its bits, wait out
/// the deliveries in flight on the line, unbind it, and settle the line at its
/// controller ([`Settle`]). Returns what the line was left to do.
///
/// # Safety
/// Called under the routing lock, with the context [`register`] requires;
/// `binding` is bound on `irq`, whose entry is `route`, and `routed` is the
/// routed-line set.
#[cfg(not(test))]
unsafe fn unbind(
    routed: &mut LineSet<&'static mut [u32]>,
    irq: u32,
    route: &IrqRoute,
    binding: &IrqBinding,
) -> Settle
{
    let target = core::ptr::from_ref(binding).cast_mut();
    let mut link = &route.bindings;
    loop
    {
        let cur = link.load(Ordering::Relaxed);
        if cur.is_null()
        {
            break;
        }
        if cur == target
        {
            // The binding keeps its own link, so a delivery standing on it
            // walks on to the rest of the line.
            link.store(binding.next.load(Ordering::Relaxed), Ordering::SeqCst);
            break;
        }
        // SAFETY: a linked binding is live under the routing lock (contract).
        link = unsafe { &(*cur).next };
    }
    let bit = binding.bit.load(Ordering::Relaxed);
    route.masks.unbind_begin(bit);
    drain(route);
    binding.notification.store(null_mut(), Ordering::Relaxed);
    binding.next.store(null_mut(), Ordering::Relaxed);
    binding.bit.store(UNBOUND, Ordering::Relaxed);
    let settle = route.masks.unbind_settle(bit);
    match settle
    {
        Settle::Release =>
        {
            routed.remove(irq);
            // The next first binding records its own mode.
            route.mode.store(0, Ordering::Relaxed);
            // SAFETY: the line was routed; serialised by the routing lock. It
            // masks the line before releasing it.
            unsafe { crate::arch::current::interrupts::unroute_device_irq(irq) };
        }
        Settle::Unmask => crate::arch::current::interrupts::unmask(irq),
        Settle::StayMasked =>
        {}
    }
    settle
}

/// Wait until no delivery is in flight on `route`, from which a change just
/// unlinked a binding or replaced a binding's notification (`SeqCst`).
///
/// Runs under the routing lock with interrupts disabled, under the spin-site
/// breadcrumb `irq:route-drain` (`sched::SPIN_SITE_IRQ_ROUTE_DRAIN`), which the
/// softlockup watchdog names if the wait wedges. It is bounded: a counted
/// delivery runs with interrupts disabled from its raise to its drop, takes only
/// the notifications' and the scheduler's spinlocks, and waits for nothing the
/// caller holds; and every delivery masks its line until its receivers'
/// `SYS_IRQ_ACK`, so the count falls to zero between deliveries. The wait is
/// therefore at most the deliveries already in flight on the line.
#[cfg(not(test))]
fn drain(route: &IrqRoute)
{
    // SeqCst pairs with the dispatcher's raise and reads: either the
    // dispatcher read the changed state, or this load sees its raise.
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

/// Dispatch a hardware interrupt for `irq` to every notification bound to it.
///
/// Called from the arch-specific device IRQ path (x86-64: `idt::irq_dispatch`,
/// with the GSI its device vector is assigned to; RISC-V: the supervisor
/// external interrupt handler, with the APLIC source its IMSIC claim names) with
/// interrupts disabled.
///
/// Flow ([`deliver`]):
/// 1. Mask the line at the controller (no further delivery until every
///    receiver has acknowledged).
/// 2. Mark every bound binding as owing an acknowledgement.
/// 3. OR notification bit 0 into each binding's notification and enqueue the
///    waiter it woke.
/// 4. Acknowledge at the controller (the x86-64 EOI; nothing on RISC-V, whose
///    IMSIC claim cleared the identity).
///
/// If no binding is linked, or the line is past the table, the IRQ is masked,
/// acknowledged at the controller, and dropped.
///
/// # Safety
/// Must only be called from interrupt context with interrupts disabled.
#[cfg(not(test))]
pub unsafe fn dispatch_device_irq(irq: u32)
{
    let Some(route) = route_of(irq)
    else
    {
        crate::arch::current::interrupts::mask(irq);
        crate::arch::current::interrupts::acknowledge(irq);
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

    // Count this delivery before reading the masks and the bindings, so a
    // change that removes a binding or a notification waits for it (`drain`).
    // SeqCst on the raise and the reads pairs with the change's SeqCst stores
    // and count reads.
    route.in_flight.fetch_add(1, Ordering::SeqCst);
    // SAFETY: interrupt context with interrupts disabled (contract); the raise
    // above keeps every binding and notification the walk reads live.
    unsafe { deliver(irq, route) };
    // Release: orders every access to the bindings, the notifications, and the
    // woken waiters before a change's drain observes the drop.
    route.in_flight.fetch_sub(1, Ordering::Release);
}

/// The counted part of [`dispatch_device_irq`]: mask the line, mark every bound
/// binding owing, signal each binding's notification, and acknowledge at the
/// controller; with no binding linked, mask and drop the IRQ.
///
/// # Safety
/// Interrupt context with interrupts disabled; the caller raised the line's
/// in-flight count, which keeps every binding and notification reached through
/// `route` live.
#[cfg(not(test))]
unsafe fn deliver(irq: u32, route: &IrqRoute)
{
    // The bound mask is read before the list, both after the raise: a binding an
    // unbind removes is either missing from both or waited for by its drain.
    let bound = route.masks.bound();
    let mut cur = route.bindings.load(Ordering::SeqCst);

    // Mask before delivering, so the line stays quiet until every receiver
    // has acknowledged. With no binding the IRQ is dropped; it must still be
    // acknowledged at the controller: without the EOI, the x86-64 local APIC
    // keeps its vector in service, blocking every interrupt of its priority
    // class and below.
    crate::arch::current::interrupts::mask(irq);
    if !cur.is_null()
    {
        route.masks.deliver(bound);
    }
    // SAFETY: a binding reached from the line is live while the caller's
    // in-flight count is raised (contract).
    while let Some(binding) = unsafe { cur.as_ref() }
    {
        let notification = binding.notification.load(Ordering::SeqCst);
        if !notification.is_null()
        {
            // SAFETY: interrupt context with interrupts disabled; the
            // notification is live while the in-flight count is raised.
            unsafe { signal(notification) };
        }
        cur = binding.next.load(Ordering::SeqCst);
    }

    // Acknowledge at the interrupt controller (the x86-64 EOI).
    crate::arch::current::interrupts::acknowledge(irq);
}

/// OR notification bit 0 into `notification` and enqueue the waiter it woke.
/// `SYS_IRQ_REGISTER` takes no bit argument, so every binding signals bit 0.
///
/// # Safety
/// Interrupt context with interrupts disabled; `notification` is a live
/// `NotificationState`.
#[cfg(not(test))]
unsafe fn signal(notification: *mut NotificationState)
{
    // SAFETY: caller contract.
    let woken = unsafe { crate::ipc::notification::notification_send(notification, 1) };
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

    fn empty_masks() -> LineMasks
    {
        LineMasks {
            bound: AtomicU64::new(0),
            owing: AtomicU64::new(0),
        }
    }

    /// Bind a new receiver the way `register` does.
    fn bind(masks: &LineMasks) -> Option<u32>
    {
        let bit = masks.free_bit()?;
        masks.take(bit);
        Some(bit)
    }

    /// Remove a receiver the way `unbind` does, with no delivery in between.
    fn unbind(masks: &LineMasks, bit: u32) -> Settle
    {
        masks.unbind_begin(bit);
        masks.unbind_settle(bit)
    }

    #[test]
    fn a_line_with_no_binding_takes_any_mode()
    {
        assert!(mode_admits(false, 0, 0));
        assert!(mode_admits(false, 0, 3));
    }

    #[test]
    fn a_bound_line_takes_only_its_recorded_mode()
    {
        assert!(mode_admits(true, 1, 1));
        assert!(!mode_admits(true, 1, 0));
        assert!(!mode_admits(true, 0, 3));
    }

    #[test]
    fn bindings_take_distinct_bits_until_the_line_is_full()
    {
        let masks = empty_masks();
        let bits: Vec<u32> = (0..MAX_IRQ_BINDINGS)
            .map(|_| bind(&masks).unwrap())
            .collect();
        assert_eq!(bits, (0..MAX_IRQ_BINDINGS).collect::<Vec<_>>());
        assert_eq!(bind(&masks), None);
    }

    #[test]
    fn a_freed_bit_is_taken_by_the_next_binding()
    {
        let masks = empty_masks();
        for _ in 0..3
        {
            bind(&masks);
        }
        unbind(&masks, 1);
        assert_eq!(bind(&masks), Some(1));
    }

    #[test]
    fn a_new_binding_keeps_the_line_masked_until_its_own_first_ack()
    {
        // The second receiver binds while the first has already acknowledged:
        // the first's acknowledgement must not unmask past the newcomer.
        let masks = empty_masks();
        let first = bind(&masks).unwrap();
        assert!(masks.ack(first));
        let second = bind(&masks).unwrap();
        assert!(!masks.ack(first));
        assert!(masks.ack(second));
    }

    #[test]
    fn a_delivery_unmasks_only_at_the_last_receivers_ack()
    {
        let masks = empty_masks();
        let a = bind(&masks).unwrap();
        let b = bind(&masks).unwrap();
        masks.ack(a);
        masks.ack(b);
        masks.deliver(masks.bound());
        assert!(!masks.ack(a));
        // A repeated acknowledgement clears nothing and does not unmask.
        assert!(!masks.ack(a));
        assert!(masks.ack(b));
    }

    #[test]
    fn an_ack_with_no_delivery_since_unmasks_only_when_none_owes()
    {
        // The timeout-wake acknowledgement of a polling driver.
        let masks = empty_masks();
        let a = bind(&masks).unwrap();
        let b = bind(&masks).unwrap();
        masks.ack(a);
        masks.ack(b);
        assert!(masks.ack(a));
        masks.deliver(masks.bound());
        masks.ack(b);
        assert!(!masks.ack(b));
    }

    #[test]
    fn the_last_unbind_releases_the_line()
    {
        let masks = empty_masks();
        let a = bind(&masks).unwrap();
        assert_eq!(unbind(&masks, a), Settle::Release);
        assert_eq!(masks.owing.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_unbind_unmasks_when_the_remaining_bindings_owe_nothing()
    {
        // A receiver that dies owing must not hold the shared line masked.
        let masks = empty_masks();
        let a = bind(&masks).unwrap();
        let b = bind(&masks).unwrap();
        masks.deliver(masks.bound());
        masks.ack(b);
        assert_eq!(unbind(&masks, a), Settle::Unmask);
    }

    #[test]
    fn an_unbind_leaves_the_line_masked_while_another_binding_owes()
    {
        let masks = empty_masks();
        let a = bind(&masks).unwrap();
        bind(&masks);
        masks.deliver(masks.bound());
        assert_eq!(unbind(&masks, a), Settle::StayMasked);
    }

    #[test]
    fn a_delivery_racing_an_unbind_leaves_no_debt_on_the_removed_bit()
    {
        // A delivery read the bound mask before the unbind cleared the bit, and
        // marks it owing after: the settle, run after the drain, must clear it,
        // or the line would never unmask again.
        let masks = empty_masks();
        let a = bind(&masks).unwrap();
        let b = bind(&masks).unwrap();
        masks.ack(a);
        masks.ack(b);
        let stale = masks.bound();
        masks.unbind_begin(a);
        masks.deliver(stale);
        assert_eq!(masks.unbind_settle(a), Settle::StayMasked);
        assert!(masks.ack(b));
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
