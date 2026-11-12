// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/irq.rs

//! Kernel IRQ routing table: maps interrupt sources (wired lines and
//! message-signaled targets) to the notifications bound to them.
//!
//! When a device IRQ fires, the arch-specific interrupt handler calls
//! [`dispatch_device_irq`] with the source's id. For a wired line this module
//! masks the line at its controller (no further delivery until every receiver
//! has acknowledged), marks every binding on the line as owing an
//! acknowledgement, ORs notification bit 0 into each bound notification, and
//! wakes its waiter.
//!
//! Drivers bind a notification via `SYS_IRQ_REGISTER` and acknowledge via
//! `SYS_IRQ_ACK` after handling.
//!
//! # Sources
//! A source is named by its id, the `start` of the Interrupt capability that
//! names it. Ids below the Interrupt id space's width
//! (`arch::current::ROOT_IRQ_COUNT`) are wired lines: GSIs on x86-64, APLIC
//! sources on riscv64. Ids from [`MESSAGE_ID_BASE`] up are message-signaled
//! targets, which `SYS_IRQ_MSG_ALLOC` mints ([`alloc_message`]); no range of
//! the root Interrupt capability names one, so no split reaches one.
//!
//! A message target is a delivery slot on one CPU ([`Target`]: an IDT vector of
//! that CPU's local APIC on x86-64, an identity in that hart's IMSIC file on
//! riscv64), which a device raises by writing the message address and data
//! ([`message`]) the slot implies. It is never masked: a delivery
//! signals its binding and nothing else, and its `SYS_IRQ_ACK` does nothing
//! (masking, where a driver needs it, is the device's: MSI-X vector control).
//! It takes one binding, in mode 0 (edge). Its slot is held from the mint until
//! the last capability to it is gone ([`free_message`]), whether or not a
//! binding is linked.
//!
//! # Sizing
//! The table has one entry per line the discovered interrupt controllers
//! implement (`arch::current::interrupts::irq_line_count`: on x86-64 the GSIs the
//! I/O APICs cover, on riscv64 the APLIC's sources), then one per message target
//! ([`message_capacity`]: a slot of each CPU's delivery space, capped at
//! [`MAX_MESSAGE_TARGETS`]), allocated once at Phase 5 by [`init_table`]. A line
//! at or above the line count is refused by [`register`], and a mint past the
//! message capacity by [`alloc_message`].
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
//! signals. Instead each source counts the deliveries in flight on it
//! (`IrqRoute::in_flight`), raised before the source's masks and bindings are read
//! and dropped after the last woken waiter is enqueued. A change that removes a
//! binding from a source, or a notification from a binding, waits under the lock
//! for that source's count to drain before it returns, so once the lock is free no
//! delivery anywhere holds a binding no source links or a notification no binding
//! names. A Notification's teardown therefore unbinds and drains only the sources
//! that bind it, found in the set of routed sources: it scales with the bindings,
//! not with the table, and no delivery on any CPU reaches the freed state
//! (core/kernel/docs/ipc-internals.md § Notification). The message-target pool
//! ([`alloc_message`], [`free_message`]) is changed under the same lock.

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

// ── Delivery targets ──────────────────────────────────────────────────────────

/// Where a source is delivered: a CPU (logical index) and a slot of that CPU's
/// delivery space, an IDT vector on x86-64 or an IMSIC interrupt identity on
/// riscv64. The controllers' routing returns it
/// (`arch::current::interrupts::route_device_irq`,
/// `arch::current::interrupts::alloc_message_target`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target
{
    /// Logical index of the CPU.
    pub cpu: u32,
    /// The slot in that CPU's delivery space.
    pub slot: u32,
}

/// Bit marking a packed [`Target`] as present, so a zero word is none.
const TARGET_PRESENT: u32 = 1 << 31;

/// Bits of a packed [`Target`]'s slot: an x86-64 vector (below 256) or an IMSIC
/// identity (at most 2047).
const TARGET_SLOT_BITS: u32 = 11;

/// Bits of a packed [`Target`]'s CPU index.
const TARGET_CPU_BITS: u32 = 20;

// Every CPU index fits the packed CPU field.
const _: () = assert!(crate::sched::MAX_CPUS <= 1 << TARGET_CPU_BITS);
// The slot, the CPU and the present bit share one word.
const _: () = assert!(TARGET_SLOT_BITS + TARGET_CPU_BITS < u32::BITS);

impl Target
{
    /// The target packed into one word: the slot in bits 0..=10, the CPU above
    /// it, and [`TARGET_PRESENT`]; `None` when a field does not fit.
    const fn pack(self) -> Option<u32>
    {
        if self.slot >= 1 << TARGET_SLOT_BITS || self.cpu >= 1 << TARGET_CPU_BITS
        {
            return None;
        }
        Some(TARGET_PRESENT | (self.cpu << TARGET_SLOT_BITS) | self.slot)
    }

    /// The target a word [`Self::pack`] wrote, or `None` for a zero word.
    const fn unpack(word: u32) -> Option<Self>
    {
        if word & TARGET_PRESENT == 0
        {
            return None;
        }
        Some(Self {
            cpu: (word & !TARGET_PRESENT) >> TARGET_SLOT_BITS,
            slot: word & ((1 << TARGET_SLOT_BITS) - 1),
        })
    }
}

// ── Routing table ─────────────────────────────────────────────────────────────

/// Per-source routing entry.
///
/// The all-zero bit pattern is the empty entry (no binding, no delivery in
/// flight, no target), so a zero-filled allocation is a table of empty entries.
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
    /// Where the source is delivered ([`Target::pack`]), 0 when nowhere: a
    /// routed line's target, kept from its route to its release, and a message
    /// target's slot, kept from its mint to its free. Read and written only
    /// under the routing lock, so `Relaxed`.
    target: AtomicU32,
}

// docs/limits.md states the routing table's per-source cost from this size
// (with the routed-source set's two `u32` entries, `table_bytes`): an 8-byte
// list head, the in-flight count and the mode (4 bytes each), the two 8-byte
// masks, and the target (4 bytes, padded to the 8-byte alignment).
const _: () = assert!(core::mem::size_of::<IrqRoute>() == 40);

/// Why a line could not be bound (`register`).
// dead_code: host test builds compile out `register` and the controller routing
// that construct the variants.
#[cfg_attr(test, allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError
{
    /// No discovered interrupt controller implements the line.
    NoSuchLine,
    /// No eligible CPU has a free delivery slot left for the source (on x86-64,
    /// a free device IDT vector; on riscv64, a free identity in its IMSIC file).
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

/// The first message-target id: the Interrupt id space's width, so no range of
/// the root Interrupt capability, and no split of it, names a message target
/// (module doc § Sources).
pub const MESSAGE_ID_BASE: u32 = crate::arch::current::ROOT_IRQ_COUNT;

/// Most message targets the table holds, whatever the CPU count: the cap on
/// [`message_capacity`]. Sized for per-queue devices at one vector per CPU and
/// queue (an `NVMe` controller or a NIC takes one per CPU it serves); 16384 is
/// 64 such devices on 256 CPUs, at 52 bytes each (`table_bytes`: a route, two
/// routed-source set entries and a pool entry), 832 KiB.
pub const MAX_MESSAGE_TARGETS: u32 = 16384;

/// The message targets a table holds on `cpu_count` CPUs whose delivery spaces
/// hold `slots_per_cpu` slots each: one per slot, capped at
/// [`MAX_MESSAGE_TARGETS`]. Wired lines take slots of the same spaces, so a mint
/// can still find no free slot below the capacity
/// ([`RouteError::Exhausted`]).
#[must_use]
pub const fn message_capacity(cpu_count: u32, slots_per_cpu: u32) -> u32
{
    let slots = cpu_count.saturating_mul(slots_per_cpu);
    if slots < MAX_MESSAGE_TARGETS
    {
        slots
    }
    else
    {
        MAX_MESSAGE_TARGETS
    }
}

/// Whether `id` names a message target rather than a wired line.
#[must_use]
pub const fn is_message(id: u32) -> bool
{
    id >= MESSAGE_ID_BASE
}

/// The table's layout over the source ids: the wired lines `0..lines` at
/// entries `0..lines`, then the message targets `MESSAGE_ID_BASE..` at the
/// `messages` entries after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdSpace
{
    lines: u32,
    messages: u32,
}

impl IdSpace
{
    /// The table entry of source `id`, or `None` for an id the table does not
    /// cover (a line past the discovered ones, a message id past the capacity,
    /// or an id between the two ranges).
    const fn index_of(self, id: u32) -> Option<usize>
    {
        if id < self.lines
        {
            return Some(id as usize);
        }
        if is_message(id) && id - MESSAGE_ID_BASE < self.messages
        {
            return Some((self.lines + (id - MESSAGE_ID_BASE)) as usize);
        }
        None
    }

    /// The source id of table entry `index` (below `lines + messages`).
    // cast_possible_truncation: the table's entry count is a sum of two u32s
    // checked at init to fit u32.
    #[allow(clippy::cast_possible_truncation)]
    const fn id_of(self, index: usize) -> u32
    {
        let index = index as u32;
        if index < self.lines
        {
            index
        }
        else
        {
            MESSAGE_ID_BASE + (index - self.lines)
        }
    }

    /// The table's entry count.
    const fn entries(self) -> usize
    {
        self.lines as usize + self.messages as usize
    }
}

/// The message targets not minted: a stack of the offsets (`id -
/// MESSAGE_ID_BASE`) free to mint, which a zero-length stack, the state before
/// [`init_table`], reports as exhausted.
///
/// `free[..len]` holds the free offsets, the next to mint at `len - 1`;
/// [`IdPool::filled`] lays them out so the lowest is minted first.
struct IdPool<S>
{
    free: S,
    len: usize,
}

impl<S: AsRef<[u32]> + AsMut<[u32]>> IdPool<S>
{
    /// A pool over `free`'s length of offsets, all free, minted lowest first.
    fn filled(mut free: S) -> Self
    {
        let entries = free.as_mut();
        let len = entries.len();
        for (position, entry) in entries.iter_mut().enumerate()
        {
            // The pool has one entry per message target, a count that fits u32.
            #[allow(clippy::cast_possible_truncation)]
            let offset = (len - 1 - position) as u32;
            *entry = offset;
        }
        Self { free, len }
    }

    /// Take the next free offset, or `None` when every target is minted.
    fn take(&mut self) -> Option<u32>
    {
        let position = self.len.checked_sub(1)?;
        self.len = position;
        Some(self.free.as_ref()[position])
    }

    /// Return `offset`, minted by [`IdPool::take`], to the pool; the next take
    /// mints it. A return to a full pool changes nothing.
    fn give(&mut self, offset: u32)
    {
        let entries = self.free.as_mut();
        if self.len >= entries.len()
        {
            return;
        }
        entries[self.len] = offset;
        self.len += 1;
    }
}

/// The routing state a route change mutates: the table, the routed-source set,
/// and the free message targets.
#[cfg(not(test))]
struct Routing
{
    /// The table's layout over the source ids.
    space: IdSpace,
    /// The table: `space.entries()` entries, or none before [`init_table`].
    routes: &'static [IrqRoute],
    /// The table entries whose source holds at least one binding.
    routed: LineSet<&'static mut [u32]>,
    /// The message targets free to mint.
    pool: IdPool<&'static mut [u32]>,
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
    space: IdSpace {
        lines: 0,
        messages: 0,
    },
    routes: &[],
    routed: LineSet {
        members: &mut [],
        slot_of: &mut [],
        len: 0,
    },
    pool: IdPool {
        free: &mut [],
        len: 0,
    },
});

/// The table, published once by [`init_table`] for the lock-free reads of
/// [`dispatch_device_irq`]: its base (null before), and its layout
/// ([`IdSpace`]) packed in one word, the line count in the low half and the
/// message count in the high half, so a reader never pairs one count with the
/// other's earlier value.
#[cfg(not(test))]
static TABLE_BASE: AtomicPtr<IrqRoute> = AtomicPtr::new(null_mut());
#[cfg(not(test))]
static TABLE_SPACE: AtomicU64 = AtomicU64::new(0);

/// The table entry for source `id`, or `None` for an id the table does not
/// cover (or before [`init_table`]).
#[cfg(not(test))]
fn route_of(id: u32) -> Option<&'static IrqRoute>
{
    let word = TABLE_SPACE.load(Ordering::Acquire);
    // Each half is a u32 `init_table` packed.
    #[allow(clippy::cast_possible_truncation)]
    let space = IdSpace {
        lines: word as u32,
        messages: (word >> 32) as u32,
    };
    let index = space.index_of(id)?;
    let base = TABLE_BASE.load(Ordering::Acquire);
    // SAFETY: `init_table` publishes the layout after the base (Release), and
    // both before any source is routed; `index` is below the layout's entry
    // count, so the entry lies in the table, which lives for the kernel's
    // lifetime.
    Some(unsafe { &*base.add(index) })
}

// ── Initialisation ───────────────────────────────────────────────────────────

// `init_table` places the set's and the pool's `u32` arrays directly after the
// routes, so the route size must keep them aligned.
const _: () =
    assert!(core::mem::size_of::<IrqRoute>().is_multiple_of(core::mem::align_of::<u32>()));

/// Bytes the table, the routed-source set and the message pool take for
/// `space`: a route and two set entries per table entry, and a pool entry per
/// message target.
const fn table_bytes(space: IdSpace) -> usize
{
    space.entries() * (core::mem::size_of::<IrqRoute>() + 2 * core::mem::size_of::<u32>())
        + space.messages as usize * core::mem::size_of::<u32>()
}

/// Allocate the routing table, the routed-source set and the message pool for
/// `line_count` lines and the message targets of the boot CPUs
/// ([`message_capacity`] of `arch::current::interrupts::message_slots_per_cpu`)
/// from the buddy allocator, zero-filled, and publish them.
///
/// Called once on the BSP at Phase 5, after the interrupt controllers are
/// discovered (`arch::current::interrupts::init`) and the boot CPU count is
/// known (Phase 4), and before any source is routed. The table lives for the
/// kernel's lifetime.
#[cfg(not(test))]
pub fn init_table(line_count: u32, allocator: &mut crate::mm::BuddyAllocator)
{
    let space = IdSpace {
        lines: line_count,
        messages: message_capacity(
            crate::sched::CPU_COUNT.load(Ordering::Relaxed),
            crate::arch::current::interrupts::message_slots_per_cpu(),
        ),
    };
    let entries = space.entries();
    let messages = space.messages as usize;
    let pages = table_bytes(space).div_ceil(crate::mm::PAGE_SIZE).max(1);
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
    // SAFETY: the allocation holds `entries` routes followed by two `u32` arrays
    // of `entries` entries and one of `messages` (`table_bytes`), zero-filled,
    // which is the empty entry and the empty set; the `u32` arrays start at a
    // multiple of the route size, so they are aligned. Nothing else references
    // the allocation.
    let (routes, members, slot_of, free) = unsafe {
        let members = routes_base.add(entries).cast::<u32>();
        (
            core::slice::from_raw_parts(routes_base, entries),
            core::slice::from_raw_parts_mut(members, entries),
            core::slice::from_raw_parts_mut(members.add(entries), entries),
            core::slice::from_raw_parts_mut(members.add(2 * entries), messages),
        )
    };
    ROUTING.with(|routing| {
        routing.space = space;
        routing.routes = routes;
        routing.routed = LineSet {
            members,
            slot_of,
            len: 0,
        };
        routing.pool = IdPool::filled(free);
    });
    TABLE_BASE.store(routes_base, Ordering::Release);
    TABLE_SPACE.store(
        u64::from(space.lines) | (u64::from(space.messages) << 32),
        Ordering::Release,
    );
    crate::kprintln!(
        "irq: routing table for {} lines and {} message targets",
        space.lines,
        space.messages
    );
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Bind `binding` (the binding of an Interrupt object for source `irq`) to
/// `notification` (`SYS_IRQ_REGISTER`), with the source's trigger and polarity
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
/// A message target (module doc § Sources) takes one binding, in mode 0, and
/// is neither routed nor masked here: its slot was assigned at its mint.
///
/// # Errors
/// [`RouteError::NoSuchLine`] when the source is past the table, no controller
/// implements the line, or the message target is not minted;
/// [`RouteError::ModeMismatch`] when the line has bindings and `mode` differs
/// from the one they recorded, or a message target is passed a mode other than
/// 0; [`RouteError::Exhausted`] when the controller cannot assign the line's
/// first binding a delivery resource; [`RouteError::TooManyBindings`] when the
/// line holds [`MAX_IRQ_BINDINGS`] bindings, or the message target holds one.
/// Nothing changes on error.
///
/// # Safety
/// - `notification` must be a valid, live `NotificationState` pointer.
/// - `binding` must be the binding of a live Interrupt object whose source is
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
        let index = routing.space.index_of(irq).ok_or(RouteError::NoSuchLine)?;
        let route = &routing.routes[index];
        let message = is_message(irq);
        if message && route.target.load(Ordering::Relaxed) == 0
        {
            return Err(RouteError::NoSuchLine);
        }
        let head = route.bindings.load(Ordering::Relaxed);
        if !mode_admits(!head.is_null(), route.mode.load(Ordering::Relaxed), mode)
            || (message && mode != 0)
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
        if message && !head.is_null()
        {
            return Err(RouteError::TooManyBindings);
        }
        let bit = route.masks.free_bit().ok_or(RouteError::TooManyBindings)?;
        if head.is_null()
        {
            if !message
            {
                // SAFETY: called after Phase 5 with a line the table covers;
                // serialised with every other binding change by the routing lock.
                let target =
                    unsafe { crate::arch::current::interrupts::route_device_irq(irq, mode) }?;
                let Some(word) = target.pack()
                else
                {
                    // SAFETY: the line was just routed to `target`; serialised by
                    // the routing lock.
                    unsafe { crate::arch::current::interrupts::unroute_device_irq(irq, target) };
                    return Err(RouteError::Exhausted);
                };
                route.target.store(word, Ordering::Relaxed);
            }
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
        routing.routed.insert(entry_u32(index));
        Ok(())
    })
}

/// Acknowledge source `irq` through `binding` (`SYS_IRQ_ACK`): clear the
/// binding's debt, and unmask the line at its controller when no binding on it
/// owes an acknowledgement. An acknowledgement that owes nothing clears nothing;
/// through an unbound binding, or of a message target (never masked, module doc
/// § Sources), it changes nothing. The check and the unmask run under the
/// routing lock, so a concurrent unbind cannot leave the line unmasked behind
/// it.
///
/// # Safety
/// Same context as [`register`]: outside interrupt context, with no IPC source,
/// scheduler, or sleep-list lock held, since a holder of the routing lock may be
/// draining deliveries that take them. `binding` is the binding of a live
/// Interrupt object whose source is `irq`.
#[cfg(not(test))]
pub unsafe fn ack(irq: u32, binding: &IrqBinding)
{
    if is_message(irq)
    {
        return;
    }
    ROUTING.with(|routing| {
        let bit = binding.bit.load(Ordering::Relaxed);
        if bit == UNBOUND
        {
            return;
        }
        let Some(index) = routing.space.index_of(irq)
        else
        {
            return;
        };
        if routing.routes[index].masks.ack(bit)
        {
            crate::arch::current::interrupts::unmask(irq);
        }
    });
}

/// Remove `binding` from source `irq` (called when its Interrupt object is
/// freed); a binding that is not bound is left untouched.
///
/// A delivery that read the binding is waited out before this returns. A line
/// is then released at its controller when no binding remains, and unmasked
/// when the remaining bindings owe nothing, so a receiver that goes cannot
/// hold a shared line masked. A message target keeps its slot
/// ([`free_message`] releases it).
///
/// # Safety
/// Same context as [`register`]; `binding` is the binding of an Interrupt object
/// whose source is `irq` and whose memory stays live until this returns.
#[cfg(not(test))]
pub unsafe fn unregister(irq: u32, binding: &IrqBinding)
{
    ROUTING.with(|routing| {
        if binding.bit.load(Ordering::Relaxed) == UNBOUND
        {
            return;
        }
        let Some(index) = routing.space.index_of(irq)
        else
        {
            return;
        };
        let route = &routing.routes[index];
        // SAFETY: the routing lock is held and `binding` is bound on `irq`,
        // whose entry is `index`.
        unsafe { unbind(&mut routing.routed, irq, index, route, binding) };
    });
}

/// Remove every binding to `notification` and wait out every delivery that may
/// have read it (called when a Notification object is being freed, before its
/// state is).
///
/// After this returns, no `dispatch_device_irq` on any CPU dereferences
/// `notification`. Under the routing lock, every source with a binding to it is
/// in the routed-source set; each such binding is removed as [`unregister`]
/// removes one, so its Interrupt object stays and is unbound. A binding that
/// named it earlier lost it through a [`register`] rebind, which drained the
/// source before releasing the lock (module doc § Thread safety). The walk
/// visits the routed sources only.
///
/// # Safety
/// - `notification` must be a valid (still live) `NotificationState` pointer.
/// - Same context as [`register`].
#[cfg(not(test))]
pub unsafe fn unregister_notification(notification: *mut NotificationState)
{
    ROUTING.with(|routing| {
        let routes = routing.routes;
        let space = routing.space;
        let mut position = 0;
        while position < routing.routed.len()
        {
            let index = routing.routed.member(position) as usize;
            let route = &routes[index];
            let id = space.id_of(index);
            let mut released = false;
            // SAFETY: the routing lock is held, so every linked binding is live.
            while let Some(binding) = unsafe { binding_naming(route, notification) }
            {
                // SAFETY: the routing lock is held and `binding` is bound on `id`,
                // whose entry is `index`.
                if unsafe { unbind(&mut routing.routed, id, index, route, binding) }
                    == Settle::Release
                {
                    released = true;
                    break;
                }
            }
            // A release swap-removes the source, moving the last member into
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

/// Remove bound `binding` from source `irq`: unlink it, clear its bits, wait out
/// the deliveries in flight on the source, unbind it, and settle a line at its
/// controller ([`Settle`]); a message target is neither unmasked nor released
/// at its controller. Returns what the source was left to do.
///
/// # Safety
/// Called under the routing lock, with the context [`register`] requires;
/// `binding` is bound on `irq`, whose table entry is `index`, holding `route`,
/// and `routed` is the routed-source set.
#[cfg(not(test))]
unsafe fn unbind(
    routed: &mut LineSet<&'static mut [u32]>,
    irq: u32,
    index: usize,
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
    let message = is_message(irq);
    match settle
    {
        Settle::Release =>
        {
            routed.remove(entry_u32(index));
            // The next first binding records its own mode.
            route.mode.store(0, Ordering::Relaxed);
            if !message
            {
                match Target::unpack(route.target.swap(0, Ordering::Relaxed))
                {
                    Some(target) =>
                    {
                        // SAFETY: the line was routed to `target`; serialised by
                        // the routing lock. It masks the line before releasing it.
                        unsafe {
                            crate::arch::current::interrupts::unroute_device_irq(irq, target);
                        }
                    }
                    None => crate::arch::current::interrupts::mask(irq),
                }
            }
        }
        Settle::Unmask if !message => crate::arch::current::interrupts::unmask(irq),
        Settle::Unmask | Settle::StayMasked =>
        {}
    }
    settle
}

/// Table entry `index` as the `u32` the routed-source set holds: the table's
/// entry count is the sum of two `u32` counts that `init_table` bounds below
/// `u32::MAX` ([`MAX_MESSAGE_TARGETS`] past the Interrupt id space).
#[cfg(not(test))]
fn entry_u32(index: usize) -> u32
{
    // Bounded as above.
    #[allow(clippy::cast_possible_truncation)]
    let entry = index as u32;
    entry
}

// ── Message targets ───────────────────────────────────────────────────────────

/// Mint a message target (`SYS_IRQ_MSG_ALLOC`): take a free message id and have
/// the controller assign it a slot on the next CPU in turn with a free one
/// (`arch::current::interrupts::alloc_message_target`). The returned id names
/// the target, unbound, until [`free_message`].
///
/// # Errors
/// [`RouteError::Exhausted`] when every message target the table holds is
/// minted, or no CPU has a free slot. Nothing changes on error.
///
/// Outside interrupt context (it takes the routing lock).
#[cfg(not(test))]
pub fn alloc_message() -> Result<u32, RouteError>
{
    ROUTING.with(|routing| {
        let offset = routing.pool.take().ok_or(RouteError::Exhausted)?;
        let id = MESSAGE_ID_BASE + offset;
        let assigned = routing
            .space
            .index_of(id)
            .ok_or(RouteError::Exhausted)
            .and_then(|index| {
                let target = crate::arch::current::interrupts::alloc_message_target(id)?;
                let Some(word) = target.pack()
                else
                {
                    crate::arch::current::interrupts::free_message_target(id, target);
                    return Err(RouteError::Exhausted);
                };
                routing.routes[index].target.store(word, Ordering::Relaxed);
                Ok(id)
            });
        if assigned.is_err()
        {
            routing.pool.give(offset);
        }
        assigned
    })
}

/// Release message target `id` (called when the last Interrupt object naming
/// it is freed): free its slot at the controller, wait out a delivery that read
/// the slot's owner before the free, and return the id to the pool. An id that
/// names no minted target is left alone.
///
/// A delivery the device raised before the free and the CPU takes later finds
/// the slot free and is dropped, or, once a later mint has taken the slot,
/// reaches that target's receiver once. A delivery that read the slot's owner
/// but raised its in-flight count only after the wait finds this entry,
/// unbound or bound by a later mint of the id, and signals at most that
/// receiver once. A receiver reads its device's state on every delivery.
///
/// # Safety
/// Same context as [`register`]; no Interrupt object naming `id` is live, so
/// none is bound to it.
#[cfg(not(test))]
pub unsafe fn free_message(id: u32)
{
    if !is_message(id)
    {
        return;
    }
    ROUTING.with(|routing| {
        let Some(index) = routing.space.index_of(id)
        else
        {
            return;
        };
        let route = &routing.routes[index];
        let Some(target) = Target::unpack(route.target.swap(0, Ordering::Relaxed))
        else
        {
            return;
        };
        crate::arch::current::interrupts::free_message_target(id, target);
        drain(route);
        routing.pool.give(id - MESSAGE_ID_BASE);
    });
}

/// The message address and data a device writes to raise message target `id`
/// (`SYS_CAP_INFO`'s `CAP_INFO_IRQ_MSG_ADDRESS` and `CAP_INFO_IRQ_MSG_DATA`), or
/// `None` for an id that names no minted target.
///
/// Outside interrupt context (it takes the routing lock).
#[cfg(not(test))]
pub fn message(id: u32) -> Option<(u64, u32)>
{
    if !is_message(id)
    {
        return None;
    }
    ROUTING.with(|routing| {
        let index = routing.space.index_of(id)?;
        let target = Target::unpack(routing.routes[index].target.load(Ordering::Relaxed))?;
        let address = crate::arch::current::interrupts::message_address(target)?;
        Some((
            address,
            crate::arch::current::interrupts::message_data(target),
        ))
    })
}

/// Wait until no delivery is in flight on `route`, from which a change just
/// unlinked a binding or replaced a binding's notification (`SeqCst`).
///
/// Runs under the routing lock with interrupts disabled, under the spin-site
/// breadcrumb `irq:route-drain` (`sched::SPIN_SITE_IRQ_ROUTE_DRAIN`), which the
/// softlockup watchdog names if the wait wedges. It is bounded: a counted
/// delivery runs with interrupts disabled from its raise to its drop, takes only
/// the notifications' and the scheduler's spinlocks, and waits for nothing the
/// caller holds; and every delivery on a wired line masks it until its
/// receivers' `SYS_IRQ_ACK`, so the count falls to zero between deliveries. The
/// wait is therefore at most the deliveries already in flight on the line. A message
/// target is not masked, but its deliveries reach only its one CPU, each with
/// interrupts disabled from raise to drop, so they run one at a time and the
/// count is zero across each interrupt return and entry between two of them.
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

/// The CPU a source being routed or minted is delivered to: the boot CPUs in turn
/// (round-robin over the logical indices), skipping those `eligible` refuses,
/// so device interrupts spread over the CPUs rather than all landing on one.
/// Called by the controllers' `route_device_irq` and `alloc_message_target`,
/// under the routing lock.
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
/// with the source its device vector is assigned to on this CPU; RISC-V: the
/// supervisor external interrupt handler, with the source its IMSIC claim names)
/// with interrupts disabled. The source is a GSI or APLIC source, or a message
/// target's id.
///
/// Flow ([`deliver`]):
/// 1. Mask a line at the controller (no further delivery until every
///    receiver has acknowledged); a message target is not masked (module doc
///    § Sources).
/// 2. Mark every bound binding as owing an acknowledgement.
/// 3. OR notification bit 0 into each binding's notification and enqueue the
///    waiter it woke.
/// 4. Acknowledge at the controller (the x86-64 EOI; nothing on RISC-V, whose
///    IMSIC claim cleared the identity).
///
/// If no binding is linked, or the source is past the table, the IRQ is masked
/// (a line), acknowledged at the controller, and dropped.
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

/// The counted part of [`dispatch_device_irq`]: mask a line, mark every bound
/// binding owing, signal each binding's notification, and acknowledge at the
/// controller; with no binding linked, mask a line and drop the IRQ. A message
/// target is never masked.
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
    // class and below. A message target has no controller mask (module doc
    // § Sources).
    if !is_message(irq)
    {
        crate::arch::current::interrupts::mask(irq);
    }
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

    // Defect caught: a field lost or bled into another in the packed word, so a
    // line is released on another CPU's vector space or a message target reports
    // another slot's address; or a zero word read as a target.
    #[test]
    fn a_target_round_trips_and_zero_is_none()
    {
        let widest = Target {
            cpu: u32::try_from(crate::sched::MAX_CPUS).unwrap() - 1,
            slot: 2047,
        };
        assert_eq!(Target::unpack(widest.pack().unwrap()), Some(widest));
        let first = Target { cpu: 0, slot: 0 };
        assert_eq!(Target::unpack(first.pack().unwrap()), Some(first));
        assert_eq!(Target::unpack(0), None);
    }

    // Defect caught: a slot or CPU past its field packed, which would alias
    // another target.
    #[test]
    fn a_target_past_its_fields_does_not_pack()
    {
        assert_eq!(Target { cpu: 0, slot: 2048 }.pack(), None);
        assert_eq!(
            Target {
                cpu: 1 << TARGET_CPU_BITS,
                slot: 1
            }
            .pack(),
            None
        );
    }

    // Defect caught: a message id indexing a line's entry (so a mint or a
    // dispatch reaches a wired line's bindings), a line id past the discovered
    // lines or an id between the two ranges indexing anything, or an entry
    // mapped back to another id (so a notification teardown unbinds the wrong
    // source).
    #[test]
    fn the_id_space_keeps_lines_and_message_targets_apart()
    {
        let space = IdSpace {
            lines: 24,
            messages: 8,
        };
        assert_eq!(space.index_of(0), Some(0));
        assert_eq!(space.index_of(23), Some(23));
        assert_eq!(space.index_of(24), None);
        assert_eq!(space.index_of(MESSAGE_ID_BASE - 1), None);
        assert_eq!(space.index_of(MESSAGE_ID_BASE), Some(24));
        assert_eq!(space.index_of(MESSAGE_ID_BASE + 7), Some(31));
        assert_eq!(space.index_of(MESSAGE_ID_BASE + 8), None);
        for index in 0..space.entries()
        {
            assert_eq!(space.index_of(space.id_of(index)), Some(index));
        }
        assert!(!is_message(MESSAGE_ID_BASE - 1));
        assert!(is_message(MESSAGE_ID_BASE));
    }

    // Defect caught: a message id inside the root Interrupt capability's range,
    // which a split could name and bind as a wired line.
    #[test]
    fn message_ids_lie_past_the_interrupt_id_space()
    {
        assert_eq!(MESSAGE_ID_BASE, crate::arch::current::ROOT_IRQ_COUNT);
        assert!(MESSAGE_ID_BASE.checked_add(MAX_MESSAGE_TARGETS).is_some());
    }

    // Defect caught: an offset minted twice, a full pool not reported, or a
    // returned offset lost.
    #[test]
    fn the_pool_mints_each_offset_once_and_takes_returns_back()
    {
        let mut pool = IdPool::filled(vec![0; 3]);
        assert_eq!(pool.take(), Some(0));
        assert_eq!(pool.take(), Some(1));
        assert_eq!(pool.take(), Some(2));
        assert_eq!(pool.take(), None);
        pool.give(1);
        assert_eq!(pool.take(), Some(1));
        assert_eq!(pool.take(), None);
    }

    // Defect caught: a return to a full pool writing past its storage.
    #[test]
    fn a_return_to_a_full_pool_changes_nothing()
    {
        let mut pool = IdPool::filled(vec![0; 2]);
        pool.give(5);
        assert_eq!(pool.take(), Some(0));
        assert_eq!(pool.take(), Some(1));
        assert_eq!(pool.take(), None);
    }

    // Defect caught: the table sized past the cap on a large machine, or below
    // the slots a small one has.
    #[test]
    fn message_capacity_is_one_per_slot_up_to_the_cap()
    {
        assert_eq!(message_capacity(4, 217), 868);
        assert_eq!(message_capacity(1, 255), 255);
        assert_eq!(message_capacity(8192, 2047), MAX_MESSAGE_TARGETS);
        assert_eq!(message_capacity(u32::MAX, u32::MAX), MAX_MESSAGE_TARGETS);
        assert_eq!(message_capacity(0, 217), 0);
    }

    // Defect caught: the table's byte count missing the pool, so the pool's
    // array runs past the allocation.
    #[test]
    fn the_table_bytes_cover_routes_set_and_pool()
    {
        let space = IdSpace {
            lines: 24,
            messages: 868,
        };
        assert_eq!(table_bytes(space), 892 * (40 + 8) + 868 * 4);
    }
}
