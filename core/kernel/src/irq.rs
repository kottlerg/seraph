// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/irq.rs

//! Kernel IRQ routing table: maps interrupt sources (wired lines and
//! message-signaled targets) to the notifications bound to them.
//!
//! When a device IRQ fires, the arch-specific interrupt handler calls
//! [`dispatch_device_irq`] with the source's id. For a wired line this module
//! marks every binding on the line as owing an acknowledgement, masks the line
//! at its controller (the controller forwards no further interrupt of the line
//! until every receiver has acknowledged), ORs notification bit 0 into each
//! bound notification, and wakes its waiter. An interrupt the controller
//! forwarded before the mask took effect is delivered too, after this one, so a
//! receiver can be signalled again before it acknowledges.
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
//! ([`message_capacity`]: one per slot of every boot CPU's delivery space),
//! allocated once at Phase 5 by [`init_table`]. Every message target holds a slot
//! from its mint to its free, so the table holds every target the CPUs can
//! deliver, and a mint fails only when no CPU a message can reach has a free
//! slot. A line at or above the line count is refused by [`register`].
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
//! # Notification references
//! A bound binding holds a reference on its notification's object, taken by
//! [`register`] and released by the change that takes the notification from the
//! binding (a rebind to another notification, or the binding's removal when its
//! Interrupt object is freed, [`unregister`]), so a notification a binding names
//! is never freed and its teardown changes no route. The release is made once
//! no delivery can still hold the notification (§ Thread safety), outside the
//! routing lock, by [`register`]'s and [`unregister`]'s callers.
//!
//! # Thread safety
//! The interrupt-context walk in `dispatch_device_irq` is lock-free: it reads the
//! line's bindings through atomic pointers. Every binding change ([`register`],
//! [`unregister`]) and every acknowledgement
//! ([`ack`], `SYS_IRQ_ACK`) runs under `ROUTING`'s lock, which also covers the
//! controller routing the change makes (`route_device_irq`, `unroute_device_irq`,
//! `mask`, `unmask`), so an unmask never meets a line
//! whose last binding is being removed. A delivery only sets bits in the owing
//! mask; acknowledgements and unbinds clear them, under the lock.
//!
//! A delivery takes no lock, so its mask can meet an acknowledgement's or an
//! unbind's unmask. It marks its bindings owing before it masks the line, and
//! an unmask reads the owing mask again once the controller holds the unmask,
//! masking the line again when a bit is set ([`LineMasks::deliver`],
//! [`LineMasks::unmask_settled`]). Whichever order the two meet in, the line is
//! left masked while a binding owes. An interrupt forwarded in the moment
//! before that second mask is delivered as one forwarded before a delivery's
//! own mask is.
//!
//! A delivery's mask reaches the controller before its signals can be seen, so
//! a receiver's acknowledgement cannot unmask the line ahead of it: on riscv64
//! `aia::mask` orders the APLIC write before the hart's later memory writes,
//! and on x86-64 the mask and the unmask both take `IOAPIC_LOCK`. A delivery
//! that finds no binding masks the line and marks nothing; one can be in flight
//! while the line's first binding is linked (a stale delivery slot of the line
//! claimed as [`register`] routes it), so `register` waits it out once the
//! binding is linked, and its mask lands before the receiver's first
//! acknowledgement can unmask the line.
//!
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
//! names. The caller may then free the one and release its reference on the
//! other (§ Notification references), and no delivery on any CPU reaches the
//! freed state (core/kernel/docs/ipc-internals.md § Notification). The
//! message-target pool ([`alloc_message`], [`free_message`]) is changed under the
//! same lock.

use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::cap::object::KernelObjectHeader;
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
/// While bound, the binding is linked in its line's list, owns one bit of the
/// line's masks, and holds a reference on its notification's object (module
/// doc § Notification references). `bit` and `holder` are read and written only
/// under the routing lock; `next` and `notification` are written under it and
/// read lock-free by [`dispatch_device_irq`].
pub struct IrqBinding
{
    /// The next binding on the line, or null at the list's end.
    next: AtomicPtr<IrqBinding>,
    /// The notification a delivery signals; null while unbound.
    notification: AtomicPtr<NotificationState>,
    /// The object of `notification`, on which the binding holds a reference;
    /// null while unbound.
    holder: AtomicPtr<KernelObjectHeader>,
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
            holder: AtomicPtr::new(null_mut()),
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
    /// owes an acknowledgement, and then the line is masked through `mask`.
    /// Marking before masking lets an unmask that raced the mask see the debt
    /// ([`LineMasks::unmask_settled`]). `mask` must order this marking before
    /// its controller write.
    fn deliver(&self, bound: u64, mask: impl FnOnce())
    {
        self.owing.fetch_or(bound, Ordering::SeqCst);
        mask();
    }

    /// Unmask the line through `unmask`, for a caller that found no binding
    /// owing, then mask it again through `mask` if a delivery marked a binding
    /// owing meanwhile. `unmask` must order its controller write before this
    /// read of the owing mask. A delivery that marked its bindings after this
    /// read masks the line after the unmask itself ([`LineMasks::deliver`]), so
    /// either way the line is left masked while a binding owes.
    fn unmask_settled(&self, unmask: impl FnOnce(), mask: impl FnOnce())
    {
        unmask();
        if self.owing.load(Ordering::SeqCst) != 0
        {
            mask();
        }
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

// ── Delivery slots ────────────────────────────────────────────────────────────

/// What a delivery slot holds ([`SlotEntry`]).
// dead_code: the kernel build has no caller until the controllers' slot rows
// hold entries; the host tests use every item.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot
{
    /// No source owns the slot.
    Free,
    /// The wired line with this id is routed to the slot.
    Line(u32),
    /// A message target is minted on the slot and no binding is linked.
    Unbound,
    /// A message target is minted on the slot and this binding receives it.
    Bound(core::ptr::NonNull<IrqBinding>),
}

/// Low bits of a [`SlotEntry`] word that say what the rest holds.
// dead_code: as on `Slot` above.
#[cfg_attr(not(test), allow(dead_code))]
const SLOT_TAG_MASK: u64 = 0b11;
/// Tag of a [`Slot::Line`] word, whose line id sits above the tag.
// dead_code: as on `Slot` above.
#[cfg_attr(not(test), allow(dead_code))]
const SLOT_TAG_LINE: u64 = 0b01;
/// Tag of a [`Slot::Unbound`] word.
// dead_code: as on `Slot` above.
#[cfg_attr(not(test), allow(dead_code))]
const SLOT_TAG_UNBOUND: u64 = 0b10;

// A binding's address keeps the tag bits clear, so a [`Slot::Bound`] word is the
// address itself.
const _: () = assert!(core::mem::align_of::<IrqBinding>() as u64 > SLOT_TAG_MASK);

// dead_code: as on `Slot` above.
#[cfg_attr(not(test), allow(dead_code))]
impl Slot
{
    /// The word a [`SlotEntry`] holds for this slot; [`Slot::Free`] is zero, so
    /// a zero-filled row is a row of free slots.
    fn encode(self) -> u64
    {
        match self
        {
            Self::Free => 0,
            Self::Line(id) => (u64::from(id) << 2) | SLOT_TAG_LINE,
            Self::Unbound => SLOT_TAG_UNBOUND,
            Self::Bound(binding) => binding.as_ptr() as u64,
        }
    }

    /// The slot a word [`Slot::encode`] wrote. A word with both tag bits set is
    /// never written and reads as [`Slot::Free`].
    fn decode(word: u64) -> Self
    {
        match word & SLOT_TAG_MASK
        {
            SLOT_TAG_LINE =>
            {
                // A line word holds a u32 id above its tag.
                #[allow(clippy::cast_possible_truncation)]
                let id = (word >> 2) as u32;
                Self::Line(id)
            }
            SLOT_TAG_UNBOUND => Self::Unbound,
            0 => match core::ptr::NonNull::new(word as *mut IrqBinding)
            {
                Some(binding) => Self::Bound(binding),
                None => Self::Free,
            },
            _ => Self::Free,
        }
    }
}

/// One slot of a CPU's delivery space (an IDT vector of its local APIC on
/// x86-64, an identity in its IMSIC file on riscv64): the source the slot
/// delivers ([`Slot`]).
///
/// Every store is made under the routing lock, and is `SeqCst`, so a change
/// that clears or replaces an entry and then waits out the slot's CPU
/// ([`DeliveryGate::wait_out`]) has either been seen by a delivery or waits for
/// it. Every load is the slot's own CPU's, by a delivery that raised that CPU's
/// gate first ([`DeliveryGate::enter`]), or the routing lock's holder's.
// dead_code: as on `Slot` above.
#[cfg_attr(not(test), allow(dead_code))]
#[repr(transparent)]
pub struct SlotEntry(AtomicU64);

// dead_code: as on `Slot` above.
#[cfg_attr(not(test), allow(dead_code))]
impl SlotEntry
{
    /// A free slot.
    #[must_use]
    pub const fn free() -> Self
    {
        Self(AtomicU64::new(0))
    }

    /// What the slot holds.
    pub fn load(&self) -> Slot
    {
        Slot::decode(self.0.load(Ordering::SeqCst))
    }

    /// Make the slot hold `slot`. Called under the routing lock.
    pub fn store(&self, slot: Slot)
    {
        self.0.store(slot.encode(), Ordering::SeqCst);
    }
}

/// One CPU's count of the device deliveries it has begun and ended: odd while a
/// delivery runs on the CPU, even between two.
///
/// Only its own CPU changes the count, with interrupts disabled from
/// [`DeliveryGate::enter`] to [`DeliveryGate::exit`], so the CPU's deliveries
/// never overlap. A change that removed state a delivery reads after its entry
/// (a slot's entry, a binding from a line, a binding's notification) with a
/// `SeqCst` store, and is about to free what it removed, calls
/// [`DeliveryGate::wait_out`] on the CPU that delivers it: in the single total
/// order of the `SeqCst` operations, either the delivery's entry precedes the
/// change's store, so the wait's load sees the delivery's odd count or a later
/// one and waits for its exit, or it follows the store, so the delivery's own
/// loads see the change. Each gate fills a cache line of its own, which no
/// other CPU writes.
// dead_code: the kernel build has no caller until every device delivery runs
// under its CPU's gate; the host tests use every item.
#[cfg_attr(not(test), allow(dead_code))]
#[repr(align(64))]
pub struct DeliveryGate
{
    seq: AtomicU32,
}

impl Default for DeliveryGate
{
    fn default() -> Self
    {
        Self::new()
    }
}

// dead_code: as on `DeliveryGate` above.
#[cfg_attr(not(test), allow(dead_code))]
impl DeliveryGate
{
    /// A gate with no delivery begun.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            seq: AtomicU32::new(0),
        }
    }

    /// Begin a delivery on this gate's CPU, before its first read of routing
    /// state. Interrupts stay disabled until [`DeliveryGate::exit`].
    pub fn enter(&self)
    {
        self.seq.fetch_add(1, Ordering::SeqCst);
    }

    /// End the delivery [`DeliveryGate::enter`] began, after its last access to
    /// a binding, a notification, or a woken waiter. Release: a waiter that sees
    /// the new count sees every one of those accesses done.
    pub fn exit(&self)
    {
        self.seq.fetch_add(1, Ordering::Release);
    }

    /// Wait until the delivery running on this gate's CPU, if one is, has
    /// exited, calling `spin` on each turn of the wait; returns whether it
    /// waited. Called after the `SeqCst` store that removed what the caller
    /// will free.
    ///
    /// The wait ends at that one delivery's exit: a later delivery on the CPU
    /// began after the store, so it reads the changed state, and is not waited
    /// for. A wrap of the count inside one wait needs 2^32 deliveries.
    pub fn wait_out(&self, mut spin: impl FnMut()) -> bool
    {
        let seen = self.seq.load(Ordering::SeqCst);
        if seen & 1 == 0
        {
            return false;
        }
        // Acquire: pairs with the delivery's exit, so its accesses happen
        // before the caller's free.
        while self.seq.load(Ordering::Acquire) == seen
        {
            spin();
        }
        true
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
// (`table_bytes`): an 8-byte
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
    /// The notification's object holds as many references as it may
    /// (`cap::object::REF_COUNT_LIMIT`), so the binding cannot take one.
    ReferenceLimit,
}

/// Whether a binding passing `requested` may bind on a line that has bindings
/// (`line_bound`) recorded with `recorded`: a line with none takes any mode,
/// which it then records; a line with bindings takes only its own.
const fn mode_admits(line_bound: bool, recorded: u32, requested: u32) -> bool
{
    !line_bound || recorded == requested
}

/// The first message-target id: the Interrupt id space's width, so no range of
/// the root Interrupt capability, and no split of it, names a message target
/// (module doc § Sources).
pub const MESSAGE_ID_BASE: u32 = crate::arch::current::ROOT_IRQ_COUNT;

/// The message targets a table holds on `cpu_count` CPUs whose delivery spaces
/// hold `slots_per_cpu` slots each: one per slot, since a minted target holds
/// its slot until it is freed, so no mint finds a free slot past it. Wired lines
/// take slots of the same spaces, so a mint can still find no free slot below
/// the capacity ([`RouteError::Exhausted`]).
///
/// The count is clamped to the message ids a `u32` holds past
/// [`MESSAGE_ID_BASE`], which also keeps the table's entry count (the wired
/// lines, at most `MESSAGE_ID_BASE`, and the targets) in a `u32`. No boot
/// reaches the clamp: `MAX_CPUS` CPUs at the AIA's 2047 identities each are
/// about 2^24 slots.
#[must_use]
pub const fn message_capacity(cpu_count: u32, slots_per_cpu: u32) -> u32
{
    let slots = cpu_count.saturating_mul(slots_per_cpu);
    let ids = u32::MAX - MESSAGE_ID_BASE;
    if slots < ids { slots } else { ids }
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

    /// The source id of table entry `index` (below `lines + messages`), which
    /// the tests check [`IdSpace::index_of`] against.
    // cast_possible_truncation: the table's entry count is a sum of two u32s
    // checked at init to fit u32.
    #[cfg(test)]
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

/// The routing state a route change mutates: the table and the free message
/// targets.
#[cfg(not(test))]
struct Routing
{
    /// The table's layout over the source ids.
    space: IdSpace,
    /// The table: `space.entries()` entries, or none before [`init_table`].
    routes: &'static [IrqRoute],
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

// `init_table` places the pool's `u32` array directly after the routes, so the
// route size must keep it aligned.
const _: () =
    assert!(core::mem::size_of::<IrqRoute>().is_multiple_of(core::mem::align_of::<u32>()));

/// Bytes the table and the message pool take for `space`: a route per table
/// entry, and a pool entry per message target.
const fn table_bytes(space: IdSpace) -> usize
{
    space.entries() * core::mem::size_of::<IrqRoute>()
        + space.messages as usize * core::mem::size_of::<u32>()
}

/// Allocate the routing table and the message pool for
/// `line_count` lines and the message targets of the boot CPUs
/// ([`message_capacity`] of `arch::current::interrupts::message_slots_per_cpu`)
/// as one zero-filled run of pages (`sched::alloc_zeroed_slab`, which may span
/// several buddy blocks, so no CPU count is capped by the largest one), and
/// publish them. Halts the boot, naming the table, when no run is long enough.
///
/// Called once on the BSP at Phase 5, after the interrupt controllers are
/// discovered (`arch::current::interrupts::init`) and the boot CPU count is
/// known (Phase 4), and before any source is routed. The table lives for the
/// kernel's lifetime and is sized here for every target the boot CPUs can
/// deliver.
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
    // A slab is page-aligned, so the routes at its base are aligned.
    let routes_base = crate::sched::alloc_zeroed_slab::<IrqRoute>(
        table_bytes(space),
        allocator,
        "IRQ_ROUTING_TABLE",
    );
    // SAFETY: the allocation holds `entries` routes followed by a `u32` array of
    // `messages` entries (`table_bytes`), zero-filled, which is the empty entry;
    // the array starts at a multiple of the route size, so it is aligned.
    // Nothing else references the allocation.
    let (routes, free) = unsafe {
        (
            core::slice::from_raw_parts(routes_base, entries),
            core::slice::from_raw_parts_mut(routes_base.add(entries).cast::<u32>(), messages),
        )
    };
    ROUTING.with(|routing| {
        routing.space = space;
        routing.routes = routes;
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
/// `notification`, the state of the Notification object `holder`
/// (`SYS_IRQ_REGISTER`), with the source's trigger and polarity `mode` (module
/// doc § Mode).
///
/// An unbound binding takes a reference on `holder` and is added to the line:
/// the line's first binding records
/// `mode` and routes the line at its controller in that mode, which leaves it
/// masked; a later binding masks it. The
/// new binding takes the lowest free bit of the line's masks and owes an
/// acknowledgement, so the line stays masked until its receiver's first
/// `SYS_IRQ_ACK`. A binding already bound is rebound to `notification`: it
/// keeps its bit and whether it owes, and the line's mask is unchanged; it
/// takes a reference on `holder` and gives up the one it held, and a delivery
/// that read the notification it replaced is waited out before this returns
/// (module doc § Thread safety). A rebind to the notification the binding
/// already names changes nothing. A line's first binding also waits out
/// the deliveries in flight on the line, so one that found no binding has
/// masked the line before this returns.
///
/// A message target (module doc § Sources) takes one binding, in mode 0, and
/// is neither routed nor masked here: its slot was assigned at its mint.
///
/// Returns the object whose reference the binding gave up, which the caller
/// releases once the routing lock is free (`cap::object::release_ref`), or
/// `None`.
///
/// # Errors
/// [`RouteError::NoSuchLine`] when the source is past the table, no controller
/// implements the line, or the message target is not minted;
/// [`RouteError::ModeMismatch`] when the line has bindings and `mode` differs
/// from the one they recorded, or a message target is passed a mode other than
/// 0; [`RouteError::Exhausted`] when the controller cannot assign the line's
/// first binding a delivery resource; [`RouteError::TooManyBindings`] when the
/// line holds [`MAX_IRQ_BINDINGS`] bindings, or the message target holds one;
/// [`RouteError::ReferenceLimit`] when `holder` can take no further reference.
/// Nothing changes on error.
///
/// # Safety
/// - `notification` must be a valid, live `NotificationState` pointer, the
///   state of `holder`, on which the caller holds a reference for the call.
/// - `binding` must be the binding of a live Interrupt object whose source is
///   `irq`, and that object must call [`unregister`] before it is freed.
/// - Must be called outside interrupt context, with no IPC source, scheduler,
///   or sleep-list lock held: the drain waits for a delivery that takes them.
#[cfg(not(test))]
pub unsafe fn register(
    irq: u32,
    binding: &IrqBinding,
    notification: *mut NotificationState,
    holder: NonNull<KernelObjectHeader>,
    mode: u32,
) -> Result<Option<NonNull<KernelObjectHeader>>, RouteError>
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
            if binding.notification.load(Ordering::Relaxed) == notification
            {
                return Ok(None);
            }
            // SAFETY: caller contract.
            unsafe { take_reference(holder) }?;
            binding.notification.store(notification, Ordering::SeqCst);
            drain(route);
            let old = binding.holder.swap(holder.as_ptr(), Ordering::Relaxed);
            return Ok(NonNull::new(old));
        }
        if message && !head.is_null()
        {
            return Err(RouteError::TooManyBindings);
        }
        let bit = route.masks.free_bit().ok_or(RouteError::TooManyBindings)?;
        // SAFETY: caller contract.
        unsafe { take_reference(holder) }?;
        if head.is_null()
        {
            if !message
            {
                // SAFETY: called after Phase 5 with a line the table covers;
                // serialised with every other binding change by the routing lock.
                let routed =
                    unsafe { crate::arch::current::interrupts::route_device_irq(irq, mode) };
                let target = match routed
                {
                    Ok(target) => target,
                    Err(error) =>
                    {
                        // SAFETY: the reference taken above.
                        unsafe { give_back_reference(holder) };
                        return Err(error);
                    }
                };
                let Some(word) = target.pack()
                else
                {
                    // SAFETY: the line was just routed to `target`; serialised by
                    // the routing lock.
                    unsafe { crate::arch::current::interrupts::unroute_device_irq(irq, target) };
                    // SAFETY: the reference taken above.
                    unsafe { give_back_reference(holder) };
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
        binding.holder.store(holder.as_ptr(), Ordering::Relaxed);
        binding.bit.store(bit, Ordering::Relaxed);
        binding.notification.store(notification, Ordering::SeqCst);
        binding.next.store(head, Ordering::SeqCst);
        // Publish last: a delivery that reads the new head sees the binding's
        // notification and link.
        route
            .bindings
            .store(core::ptr::from_ref(binding).cast_mut(), Ordering::SeqCst);
        if head.is_null() && !message
        {
            // A delivery on a stale slot of the line can be in flight with an
            // empty list, its mask not yet at the controller. Waiting it out
            // lands that mask before the receiver's first acknowledgement can
            // unmask, so it cannot leave the line masked with none owing.
            drain(route);
        }
        Ok(None)
    })
}

/// Take a reference on `holder` for a binding, refused at the reference limit.
///
/// # Safety
/// The caller holds a reference on `holder`, so it is live.
#[cfg(not(test))]
unsafe fn take_reference(holder: NonNull<KernelObjectHeader>) -> Result<(), RouteError>
{
    // SAFETY: caller contract.
    unsafe { holder.as_ref() }
        .try_inc_ref()
        .map_err(|_| RouteError::ReferenceLimit)
}

/// Give back a reference [`take_reference`] took, for a step that then failed.
/// The caller still holds its own reference on `holder`, so the count stays
/// above zero.
///
/// # Safety
/// As [`take_reference`], whose reference this gives back.
#[cfg(not(test))]
unsafe fn give_back_reference(holder: NonNull<KernelObjectHeader>)
{
    // SAFETY: caller contract.
    let left = unsafe { holder.as_ref() }.dec_ref();
    debug_assert_ne!(
        left, 0,
        "irq: a bind's failed step released the last reference"
    );
}

/// Acknowledge source `irq` through `binding` (`SYS_IRQ_ACK`): clear the
/// binding's debt, and unmask the line at its controller when no binding on it
/// owes an acknowledgement. An acknowledgement that owes nothing clears nothing;
/// through an unbound binding, or of a message target (never masked, module doc
/// § Sources), it changes nothing. The check and the unmask run under the
/// routing lock, so a concurrent unbind cannot leave the line unmasked behind
/// it, and the unmask masks the line again when a delivery that raced it marked
/// a binding owing ([`unmask_settled`]).
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
        let route = &routing.routes[index];
        if route.masks.ack(bit)
        {
            unmask_settled(irq, route);
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
/// Returns the object of the notification the binding named, whose reference
/// the binding gave up, for the caller to release once the routing lock is
/// free; `None` for a binding that was not bound.
///
/// # Safety
/// Same context as [`register`]; `binding` is the binding of an Interrupt object
/// whose source is `irq` and whose memory stays live until this returns.
#[cfg(not(test))]
pub unsafe fn unregister(irq: u32, binding: &IrqBinding) -> Option<NonNull<KernelObjectHeader>>
{
    ROUTING.with(|routing| {
        if binding.bit.load(Ordering::Relaxed) == UNBOUND
        {
            return None;
        }
        if let Some(index) = routing.space.index_of(irq)
        {
            // SAFETY: the routing lock is held and `binding` is bound on `irq`,
            // whose entry is `index`.
            unsafe { unbind(irq, &routing.routes[index], binding) };
        }
        NonNull::new(binding.holder.swap(null_mut(), Ordering::Relaxed))
    })
}

/// Remove bound `binding` from source `irq`: unlink it, clear its bits, wait out
/// the deliveries in flight on the source, unbind it, and settle a line at its
/// controller ([`Settle`]); a message target is neither unmasked nor released
/// at its controller. Returns what the source was left to do.
///
/// # Safety
/// Called under the routing lock, with the context [`register`] requires;
/// `binding` is bound on `irq`, whose table entry is `route`.
#[cfg(not(test))]
unsafe fn unbind(irq: u32, route: &IrqRoute, binding: &IrqBinding) -> Settle
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
        Settle::Unmask if !message => unmask_settled(irq, route),
        Settle::Unmask | Settle::StayMasked =>
        {}
    }
    settle
}

// ── Message targets ───────────────────────────────────────────────────────────

/// Mint a message target (`SYS_IRQ_MSG_ALLOC`): take a free message id and have
/// the controller assign it a slot on the next CPU in turn with a free one
/// (`arch::current::interrupts::alloc_message_target`). The returned id names
/// the target, unbound, until [`free_message`].
///
/// # Errors
/// [`RouteError::Exhausted`] when no CPU the controller can deliver a message
/// to has a free slot. The table holds a target for every slot of every CPU
/// ([`message_capacity`]), so its free ids run out only when the slots have.
/// Nothing changes on error.
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

/// Unmask line `irq`, whose bindings were found owing nothing under the routing
/// lock, and mask it again if a delivery that raced the unmask marked a binding
/// owing ([`LineMasks::unmask_settled`]; module doc § Thread safety). On
/// riscv64 the APLIC writes are unlocked: `aia::unmask` fences them before the
/// owing mask's read, and a racing delivery's `aia::mask` orders the delivery's
/// marking before its write (`fence w,o`). On x86-64 the unmask and a racing delivery's mask
/// both take `IOAPIC_LOCK`: when the mask's critical section comes first, the
/// delivery marked its bindings before it, and the lock hands that write to the
/// read; when it comes second, the mask lands last.
#[cfg(not(test))]
fn unmask_settled(irq: u32, route: &IrqRoute)
{
    route.masks.unmask_settled(
        || crate::arch::current::interrupts::unmask(irq),
        || crate::arch::current::interrupts::mask(irq),
    );
}

/// Wait until no delivery is in flight on `route`, from which a change just
/// unlinked a binding or replaced a binding's notification, or to which it
/// linked a line's first binding (`SeqCst`).
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
/// 1. Mark every bound binding as owing an acknowledgement.
/// 2. Mask a line at the controller (no further interrupt of the line is
///    forwarded until every receiver has acknowledged; one forwarded before the
///    mask took effect is delivered after this one); a message target is not
///    masked (module doc § Sources).
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

/// The counted part of [`dispatch_device_irq`]: mark every bound binding owing,
/// mask a line, signal each binding's notification, and acknowledge at the
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

    // Mask before delivering, so the controller forwards no further interrupt
    // of the line until every receiver has acknowledged; the bindings are
    // marked owing before the mask, so an unmask that races it sees the debt
    // (module doc § Thread safety), and the mask is ordered before the signals
    // below, so a receiver's acknowledgement does not unmask the line ahead of
    // it. With no binding the IRQ is dropped; it must still be acknowledged at
    // the controller: without the EOI, the x86-64 local APIC keeps its vector
    // in service, blocking every interrupt of its priority class and below. A
    // message target has no controller mask (module doc § Sources).
    let message = is_message(irq);
    let mask = || {
        if !message
        {
            crate::arch::current::interrupts::mask(irq);
        }
    };
    if cur.is_null()
    {
        mask();
    }
    else
    {
        route.masks.deliver(bound, mask);
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
        masks.deliver(masks.bound(), || {});
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
        masks.deliver(masks.bound(), || {});
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
        masks.deliver(masks.bound(), || {});
        masks.ack(b);
        assert_eq!(unbind(&masks, a), Settle::Unmask);
    }

    #[test]
    fn an_unbind_leaves_the_line_masked_while_another_binding_owes()
    {
        let masks = empty_masks();
        let a = bind(&masks).unwrap();
        bind(&masks);
        masks.deliver(masks.bound(), || {});
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
        masks.deliver(stale, || {});
        assert_eq!(masks.unbind_settle(a), Settle::StayMasked);
        assert!(masks.ack(b));
    }

    /// A line's mask at its controller, for the tests of a delivery racing an
    /// unmask.
    struct Controller
    {
        masked: core::cell::Cell<bool>,
    }

    impl Controller
    {
        fn unmasked() -> Self
        {
            Self {
                masked: core::cell::Cell::new(false),
            }
        }

        fn mask(&self)
        {
            self.masked.set(true);
        }

        fn unmask(&self)
        {
            self.masked.set(false);
        }

        /// The invariant the races must keep: a line a binding owes is masked.
        fn masked_while_owing(&self, masks: &LineMasks) -> bool
        {
            masks.owing.load(Ordering::SeqCst) == 0 || self.masked.get()
        }
    }

    /// Two bound receivers that have both acknowledged, on an unmasked line.
    fn quiet_pair(masks: &LineMasks) -> (u32, u32)
    {
        let a = bind(masks).unwrap();
        let b = bind(masks).unwrap();
        masks.ack(a);
        masks.ack(b);
        (a, b)
    }

    #[test]
    fn an_unmask_landing_after_a_racing_deliverys_mask_masks_again()
    {
        // An acknowledgement that owes nothing (a polling driver's timeout
        // acknowledgement) finds no debt and decides to unmask; a delivery
        // then marks its bindings and masks the line before the unmask
        // reaches the controller. The unmask must not leave the line open.
        let masks = empty_masks();
        let controller = Controller::unmasked();
        let (a, _) = quiet_pair(&masks);
        assert!(masks.ack(a));
        masks.deliver(masks.bound(), || controller.mask());
        masks.unmask_settled(|| controller.unmask(), || controller.mask());
        assert!(controller.masked_while_owing(&masks));
    }

    #[test]
    fn an_ack_between_a_deliverys_marking_and_its_mask_sees_the_debt()
    {
        // The delivery marks its bindings before it masks, so an
        // acknowledgement that runs between the two finds the other binding
        // owing and leaves the line to the delivery's mask.
        let masks = empty_masks();
        let controller = Controller::unmasked();
        let (_, b) = quiet_pair(&masks);
        masks.deliver(masks.bound(), || {
            assert!(!masks.ack(b));
            controller.mask();
        });
        assert!(controller.masked_while_owing(&masks));
    }

    #[test]
    fn an_unmask_with_no_racing_delivery_leaves_the_line_unmasked()
    {
        let masks = empty_masks();
        let controller = Controller::unmasked();
        controller.mask();
        let (a, _) = quiet_pair(&masks);
        assert!(masks.ack(a));
        masks.unmask_settled(|| controller.unmask(), || controller.mask());
        assert!(!controller.masked.get());
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

    // Defect caught: a slot word read back as another kind of slot or another
    // line, so a delivery signals a binding through a line's id or walks a line
    // through a binding's address; or a zero-filled row read as owned.
    #[test]
    fn every_slot_round_trips_and_zero_is_free()
    {
        let binding = Box::new(IrqBinding::unbound());
        let address = core::ptr::NonNull::from(binding.as_ref());
        for slot in [
            Slot::Free,
            Slot::Line(0),
            Slot::Line(u32::MAX),
            Slot::Unbound,
            Slot::Bound(address),
        ]
        {
            let entry = SlotEntry::free();
            entry.store(slot);
            assert_eq!(entry.load(), slot);
        }
        assert_eq!(SlotEntry::free().load(), Slot::Free);
        assert_eq!(Slot::decode(0), Slot::Free);
    }

    // Defect caught: a word no store writes (both tag bits set) decoded as a
    // binding's address, which a delivery would dereference.
    #[test]
    fn a_word_with_both_tag_bits_reads_as_free()
    {
        assert_eq!(Slot::decode(SLOT_TAG_MASK), Slot::Free);
        assert_eq!(Slot::decode(0x1000 | SLOT_TAG_MASK), Slot::Free);
    }

    // Defect caught: a change waiting on a CPU with no delivery running, which
    // would spin with the routing lock held.
    #[test]
    fn a_wait_on_a_quiet_cpu_returns_at_once()
    {
        let gate = DeliveryGate::new();
        assert!(!gate.wait_out(|| panic!("waited on a quiet CPU")));
        gate.enter();
        gate.exit();
        assert!(!gate.wait_out(|| panic!("waited after the delivery exited")));
    }

    // Defect caught: a change returning while the delivery that may hold what
    // it removed still runs, so the caller frees a binding or a notification
    // under it.
    #[test]
    fn a_wait_lasts_until_the_running_delivery_exits()
    {
        let gate = DeliveryGate::new();
        gate.enter();
        let mut turns = 0;
        // Each turn of the wait is the delivering CPU running on; it exits on
        // the third.
        let waited = gate.wait_out(|| {
            turns += 1;
            if turns == 3
            {
                gate.exit();
            }
        });
        assert!(waited);
        assert_eq!(turns, 3);
    }

    // Defect caught: a change waiting for the CPU to fall quiet rather than for
    // the delivery it saw, which a CPU taking interrupts back to back would
    // never end.
    #[test]
    fn a_wait_ends_at_the_seen_delivery_even_when_another_begins()
    {
        let gate = DeliveryGate::new();
        gate.enter();
        let waited = gate.wait_out(|| {
            gate.exit();
            gate.enter();
        });
        assert!(waited);
        // The later delivery still runs; a fresh wait would wait for it.
        assert_eq!(gate.seq.load(Ordering::SeqCst) & 1, 1);
    }

    // Defect caught: the release protocol's two sides not meeting across CPUs,
    // so a change frees a binding a delivery on another CPU read before the
    // change cleared its slot. The delivery runs on this thread and the change
    // on another; the change reports each step over a channel, so the outcome
    // depends on no timing.
    #[test]
    fn a_change_on_another_cpu_frees_only_after_the_delivery_that_read_the_slot()
    {
        use std::sync::Arc;
        use std::sync::mpsc::channel;

        #[derive(Debug, PartialEq, Eq)]
        enum Step
        {
            Waiting,
            Returned,
            Freed,
        }

        let gate = Arc::new(DeliveryGate::new());
        let entry = Arc::new(SlotEntry::free());
        let binding = Box::new(IrqBinding::unbound());
        let live = Arc::new(AtomicU32::new(1));
        entry.store(Slot::Bound(core::ptr::NonNull::from(binding.as_ref())));

        // The delivery: enter, and read the slot's binding.
        gate.enter();
        assert!(matches!(entry.load(), Slot::Bound(_)));

        let (report, steps) = channel();
        let change = {
            let (gate, entry, live) = (Arc::clone(&gate), Arc::clone(&entry), Arc::clone(&live));
            std::thread::spawn(move || {
                entry.store(Slot::Unbound);
                let mut first = true;
                gate.wait_out(|| {
                    if first
                    {
                        report.send(Step::Waiting).unwrap();
                        first = false;
                    }
                    core::hint::spin_loop();
                });
                report.send(Step::Returned).unwrap();
                // The free.
                live.store(0, Ordering::SeqCst);
                report.send(Step::Freed).unwrap();
            })
        };

        // The change saw this delivery and waits for it.
        assert_eq!(steps.recv().unwrap(), Step::Waiting);
        // The delivery's use of the binding it read.
        assert_eq!(live.load(Ordering::SeqCst), 1);
        assert!(steps.try_recv().is_err());
        gate.exit();
        assert_eq!(steps.recv().unwrap(), Step::Returned);
        assert_eq!(steps.recv().unwrap(), Step::Freed);
        change.join().unwrap();

        // A delivery that begins after the change reads the cleared slot.
        gate.enter();
        assert_eq!(entry.load(), Slot::Unbound);
        gate.exit();
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
    // which a split could name and bind as a wired line, or a capacity whose
    // last id overflows a u32.
    #[test]
    fn message_ids_lie_past_the_interrupt_id_space()
    {
        assert_eq!(MESSAGE_ID_BASE, crate::arch::current::ROOT_IRQ_COUNT);
        assert!(
            MESSAGE_ID_BASE
                .checked_add(message_capacity(u32::MAX, u32::MAX))
                .is_some()
        );
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

    // Defect caught: the table sized below the slots the CPUs have, so a mint
    // fails while a CPU has a free slot.
    #[test]
    fn message_capacity_is_one_per_slot_of_every_cpu()
    {
        assert_eq!(message_capacity(4, 217), 868);
        assert_eq!(message_capacity(1, 255), 255);
        assert_eq!(message_capacity(128, 217), 27_776);
        assert_eq!(message_capacity(8192, 2047), 8192 * 2047);
        assert_eq!(message_capacity(0, 217), 0);
    }

    // Defect caught: a product past the id space wrapping to a small table, or
    // a capacity naming ids past u32.
    #[test]
    fn message_capacity_stops_at_the_message_id_space()
    {
        let ids = u32::MAX - MESSAGE_ID_BASE;
        assert_eq!(message_capacity(u32::MAX, u32::MAX), ids);
        assert_eq!(message_capacity(ids, 1), ids);
        assert_eq!(message_capacity(ids - 1, 1), ids - 1);
    }

    // Defect caught: the table's byte count missing the pool, so the pool's
    // array runs past the allocation.
    #[test]
    fn the_table_bytes_cover_routes_and_pool()
    {
        let space = IdSpace {
            lines: 24,
            messages: 868,
        };
        assert_eq!(table_bytes(space), 892 * 40 + 868 * 4);
    }
}
