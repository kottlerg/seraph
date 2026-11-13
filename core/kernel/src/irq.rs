// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/irq.rs

//! Kernel IRQ routing: maps interrupt sources (wired lines and message-signaled
//! targets) to the notifications bound to them.
//!
//! When a device interrupt arrives, the arch-specific handler finds the slot of
//! its delivery space the interrupt names (an IDT vector on x86-64, an IMSIC
//! identity on riscv64) and calls [`dispatch_device_irq`] with that slot's
//! [`SlotEntry`]. For a wired line this module marks every binding on the line as
//! owing an acknowledgement, masks the line at its controller (the controller
//! forwards no further interrupt of the line until every receiver has
//! acknowledged), ORs notification bit 0 into each bound notification, and wakes
//! its waiter. An interrupt the controller forwarded before the mask took effect
//! is delivered too, after this one, so a receiver can be signalled again before
//! it acknowledges. For a message-signaled target it signals the target's one
//! binding.
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
//! A message target is a delivery slot on one CPU ([`Target`]), which a device
//! raises by writing the message address and data ([`message`]) the slot
//! implies. Its id is computed from the slot ([`message_id`], [`message_target`]),
//! so the kernel keeps no table of targets: the slot's entry is the target's only
//! kernel state apart from the Interrupt objects that name it, whose lineage root
//! the minting `CSpace` funds. The slot is held from the mint until the last
//! capability to the target is gone ([`free_message`]), whether or not a binding
//! is linked. A target is never masked: a delivery signals its binding and
//! nothing else, and its `SYS_IRQ_ACK` does nothing (a driver holds its device's
//! messages off through the device's own interrupt controls; the MSI-X table and
//! its masks are devmgr's). It takes one binding, in mode 0 (edge), which its
//! slot's entry names ([`Slot::Bound`]).
//!
//! # Sizing
//! The routing table has one entry ([`IrqRoute`]) per line the discovered
//! interrupt controllers implement (`arch::current::interrupts::irq_line_count`:
//! on x86-64 the GSIs the I/O APICs cover, on riscv64 the APLIC's sources),
//! allocated once at Phase 5 by [`init_table`] with one [`DeliveryGate`] per boot
//! CPU. A line at or above the line count is refused by [`register`]. The slots
//! themselves are the controllers' per-CPU rows (x86-64 `ioapic`, riscv64
//! `aia`), allocated at Phase 4; wired lines and message targets take slots of
//! the same rows, and a route or a mint fails only when no eligible CPU has a
//! free slot.
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
//! # Routes
//! A wired line is routed by an explicit request of a holder of the minting
//! authority (`SYS_IRQ_ROUTE`, [`route`]), never by a binding: the request
//! takes the line a delivery slot on the next CPU in turn, programs the
//! controller in the request's mode with the line masked, and makes the
//! requesting Interrupt object a route holder (its `route_held` flag,
//! `cap::object::InterruptObject`). A binding is added only to a routed line
//! ([`RouteError::NotRouted`]). The line's target stays fixed from its route
//! until its release, once neither a holder nor a binding remains
//! ([`released`], [`drop_route_holder`], [`unbind_line`]), so an IOMMU entry
//! made for the target stays valid while anything names the line.
//!
//! # Mode
//! A line carries one trigger and polarity mode (`IRQ_MODE_LEVEL`,
//! `IRQ_MODE_ACTIVE_LOW` in `abi/syscall`), which its route records and its
//! controller is programmed with. A later route request, or a binding, that
//! passes another is refused ([`RouteError::ModeMismatch`], [`route_step`],
//! [`bind_admits`]) and changes nothing. The line's release forgets the mode,
//! so the next route may record another.
//!
//! # Remapping
//! With interrupt remapping switched on ([`set_remap`]), the controllers hand
//! out remappable formats: a message or an I/O APIC entry names a handle the
//! kernel derives from its slot, and an IOMMU entry for that handle, which
//! devmgr has the IOMMU driver write from [`remap_entry`], delivers it. The
//! switch moves only while no source holds a slot (`Routing::sources`).
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
//! A delivery takes no lock and holds no reference: it reads a slot's entry, a
//! line's masks and bindings, and a binding's notification through atomics.
//! Every binding change ([`register`], [`unregister`]), every acknowledgement
//! ([`ack`], `SYS_IRQ_ACK`) and every mint and free ([`alloc_message`],
//! [`free_message`]) runs under `ROUTING`'s lock, which also covers the
//! controller routing the change makes (`route_device_irq`, `unroute_device_irq`,
//! `mask`, `unmask`) and the controllers' slot rows, so an unmask never meets a
//! line whose last binding is being removed.
//!
//! Every delivery runs under its CPU's [`DeliveryGate`], entered before its first
//! read of the slot's entry and exited after its last access to a binding, a
//! notification and a woken waiter. A source is delivered only through its slot,
//! on the slot's CPU: a line through the slot its route took (`IrqRoute::target`),
//! kept from its route to its release, and a message target through the
//! slot its id names. A change that removes a binding from a slot or a line, or a
//! notification from a binding, makes the removal with a `SeqCst` store and then
//! waits out the delivery running on that CPU (`wait_out`, through
//! [`DeliveryGate::wait_out`]) before it releases the lock: either the delivery
//! entered after the store, and reads the change, or the wait sees it and lasts
//! until it exits. Once the lock is free, then, no delivery on any CPU holds a
//! binding no slot or line links or a notification no binding names, and the
//! caller may free the one and release its reference on the other. The wait
//! lasts at most one delivery: the waiter holds the routing lock, which no
//! delivery takes, with interrupts disabled, so it is in no delivery itself.
//!
//! A line's release clears its slot's entry and waits out its CPU the same way,
//! so no delivery that read the line from that slot outlives the release. A
//! line's first binding waits out the line's CPU once the binding is linked: an
//! interrupt latched for the slot's previous owner can be taken after the route
//! assigned the slot and before the link, find the line with no binding, and
//! mask it; the wait lands that mask before the receiver's first
//! acknowledgement can unmask the line.
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
//! and on x86-64 the mask and the unmask both take `IOAPIC_LOCK`.
//!
//! Delivery itself (`notification_send`, `sched::enqueue_and_wake`) takes the
//! notification's and the scheduler's spinlocks with interrupts disabled.

use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

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

/// [`IrqBinding::bit`] of a binding bound to a message target, which has no
/// masks.
const MESSAGE_BIT: u32 = 0;

/// One receiver's binding of an interrupt source: the state an Interrupt object
/// carries (`cap::object::InterruptObject`), so each capability to a line binds
/// on its own.
///
/// While bound to a line, the binding is linked in the line's list and owns one
/// bit of the line's masks; while bound to a message target, its slot's entry
/// names it ([`Slot::Bound`]). Bound to either, it holds a reference on its
/// notification's object (module doc § Notification references). `bit` and
/// `holder` are read and written only under the routing lock; `next` and
/// `notification` are written under it and read lock-free by
/// [`dispatch_device_irq`].
pub struct IrqBinding
{
    /// The next binding on the line, or null at the list's end.
    next: AtomicPtr<IrqBinding>,
    /// The notification a delivery signals; null while unbound.
    notification: AtomicPtr<NotificationState>,
    /// The object of `notification`, on which the binding holds a reference;
    /// null while unbound.
    holder: AtomicPtr<KernelObjectHeader>,
    /// The binding's bit in its line's masks, [`MESSAGE_BIT`] while bound to a
    /// message target, or [`UNBOUND`].
    bit: AtomicU32,
}

impl IrqBinding
{
    /// A binding that is not bound to any source.
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
/// once no delivery that read the old bound mask still runs.
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
    /// The bound mask, read by a delivery after it entered its CPU's gate.
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

    /// The first step of removing `bit`, before the wait on the line's CPU: a
    /// delivery
    /// that reads the bound mask after this no longer marks `bit` owing.
    fn unbind_begin(&self, bit: u32)
    {
        self.bound.fetch_and(!(1 << bit), Ordering::SeqCst);
    }

    /// The last step of removing `bit`, after the wait on the line's CPU: clear
    /// the debt
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
    Bound(NonNull<IrqBinding>),
}

/// Low bits of a [`SlotEntry`] word that say what the rest holds.
const SLOT_TAG_MASK: u64 = 0b11;
/// Tag of a [`Slot::Line`] word, whose line id sits above the tag.
const SLOT_TAG_LINE: u64 = 0b01;
/// Tag of a [`Slot::Unbound`] word.
const SLOT_TAG_UNBOUND: u64 = 0b10;

// A binding's address keeps the tag bits clear, so a [`Slot::Bound`] word is the
// address itself.
const _: () = assert!(core::mem::align_of::<IrqBinding>() as u64 > SLOT_TAG_MASK);

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
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "a line word holds a u32 id above its tag"
                )]
                let id = (word >> 2) as u32;
                Self::Line(id)
            }
            SLOT_TAG_UNBOUND => Self::Unbound,
            0 => match NonNull::new(word as *mut IrqBinding)
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
/// delivers ([`Slot`]). The controllers keep one row of them per CPU (x86-64
/// `ioapic`, riscv64 `aia`).
///
/// Every store is made under the routing lock, and is `SeqCst`, so a change
/// that clears or replaces an entry and then waits out the slot's CPU
/// ([`DeliveryGate::wait_out`]) has either been seen by a delivery or waits for
/// it. Every load is the slot's own CPU's, by a delivery that entered that CPU's
/// gate first ([`DeliveryGate::enter`]), or the routing lock's holder's.
#[repr(transparent)]
pub struct SlotEntry(AtomicU64);

// docs/limits.md states the slot rows' per-CPU costs (x86-64
// `DEVICE_VECTOR_ROWS`, riscv64 `IMSIC_EID_ROWS`) from this size: 8 bytes per
// slot.
const _: () = assert!(core::mem::size_of::<SlotEntry>() == 8);

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

    /// Whether no source owns the slot.
    pub fn is_free(&self) -> bool
    {
        self.load() == Slot::Free
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
#[repr(align(64))]
pub struct DeliveryGate
{
    seq: AtomicU32,
}

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

impl Default for DeliveryGate
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// The delivery-gate slab: one [`DeliveryGate`] per CPU.
const GATE_SLAB: crate::sched::PerCpuSlab =
    crate::sched::PerCpuSlab::of::<DeliveryGate>("IRQ_DELIVERY_GATES");
const _: () = assert!(
    GATE_SLAB.sized_at_every_width(),
    "IRQ_DELIVERY_GATES slab overflows"
);

// docs/limits.md states the gate slab's per-CPU cost from this size: one cache
// line per CPU.
const _: () = assert!(core::mem::size_of::<DeliveryGate>() == 64);

// ── Routing table ─────────────────────────────────────────────────────────────

/// Per-line routing entry.
///
/// The all-zero bit pattern is the empty entry (no binding, no target), so a
/// zero-filled allocation is a table of empty entries.
struct IrqRoute
{
    /// The first binding on the line, or null when none is bound. Bindings are
    /// linked at the head and unlinked under the routing lock; the stores are
    /// `SeqCst`, as are a delivery's loads of every link.
    bindings: AtomicPtr<IrqBinding>,
    /// The mode the line's route recorded (module doc § Mode); meaningful
    /// only while the line is routed. Read and written only under the routing
    /// lock, so `Relaxed`.
    mode: AtomicU32,
    /// Where the line is delivered ([`Target::pack`]), 0 when nowhere: kept
    /// from its route to its release. Read and written only under the routing
    /// lock, so `Relaxed`.
    target: AtomicU32,
    /// The Interrupt objects that hold the line's route (module doc § Routes).
    /// Read and written only under the routing lock, so `Relaxed`.
    holders: AtomicU32,
    /// The line's bound and owing masks.
    masks: LineMasks,
}

// docs/limits.md states the routing table's per-line cost from this size: an
// 8-byte list head, the mode, the target and the holder count (4 bytes each,
// padded to 8), and the two 8-byte masks.
const _: () = assert!(core::mem::size_of::<IrqRoute>() == 40);

/// Why a source could not be bound or minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError
{
    /// No discovered interrupt controller implements the line, or no minted
    /// message target has the id.
    NoSuchLine,
    /// No eligible CPU has a free delivery slot left for the source (on x86-64,
    /// a free device IDT vector; on riscv64, a free identity in its IMSIC file).
    Exhausted,
    /// The line already holds [`MAX_IRQ_BINDINGS`] bindings, or the message
    /// target holds its one.
    TooManyBindings,
    /// The binding's mode differs from the one the line's bindings recorded
    /// (module doc § Mode), or a message target is passed a mode other than 0.
    ModeMismatch,
    /// The notification's object holds as many references as it may
    /// (`cap::object::REF_COUNT_LIMIT`), so the binding cannot take one.
    ReferenceLimit,
    /// The line is not routed (module doc § Routes), so no binding can be added.
    NotRouted,
}

/// What a route request ([`route`]) does to a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteStep
{
    /// The line is not routed: route it, with the caller its first holder.
    Route,
    /// The line is routed in the requested mode: the caller holds it too.
    AddHolder,
    /// The caller already holds the line's route, in the requested mode.
    Held,
}

/// What a route request in `mode` through an object that does (`caller_holds`)
/// or does not hold the route does to a line routed in `routed` (`None` when
/// it is not routed). A request in another mode than the route's is refused.
const fn route_step(
    routed: Option<u32>,
    caller_holds: bool,
    mode: u32,
) -> Result<RouteStep, RouteError>
{
    match routed
    {
        None => Ok(RouteStep::Route),
        Some(recorded) if recorded != mode => Err(RouteError::ModeMismatch),
        Some(_) if caller_holds => Ok(RouteStep::Held),
        Some(_) => Ok(RouteStep::AddHolder),
    }
}

/// Whether a binding in `mode` may be added to a line routed in `routed`
/// (`None` when it is not routed): only to a routed line, in its route's mode.
const fn bind_admits(routed: Option<u32>, mode: u32) -> Result<(), RouteError>
{
    match routed
    {
        None => Err(RouteError::NotRouted),
        Some(recorded) if recorded != mode => Err(RouteError::ModeMismatch),
        Some(_) => Ok(()),
    }
}

/// Whether a line with `holders` route holders and the bound mask `bound` is
/// released: once neither a holder nor a binding remains.
const fn released(holders: u32, bound: u64) -> bool
{
    holders == 0 && bound == 0
}

// ── Message-target ids ────────────────────────────────────────────────────────

/// The first message-target id: the Interrupt id space's width, so no range of
/// the root Interrupt capability, and no split of it, names a message target
/// (module doc § Sources).
pub const MESSAGE_ID_BASE: u32 = crate::arch::current::ROOT_IRQ_COUNT;

// Every packed target's offset past the base is an id: the offset is a packed
// target without its present bit.
const _: () = assert!(MESSAGE_ID_BASE <= u32::MAX - (TARGET_PRESENT - 1));

/// Whether `id` names a message target rather than a wired line.
#[must_use]
pub const fn is_message(id: u32) -> bool
{
    id >= MESSAGE_ID_BASE
}

/// The id of the message target on `target`: [`MESSAGE_ID_BASE`] plus the
/// target packed without its present bit, the CPU above the slot's 11 bits.
/// `None` when a field does not fit its bits.
#[must_use]
pub const fn message_id(target: Target) -> Option<u32>
{
    match target.pack()
    {
        // The base plus any offset below `TARGET_PRESENT` fits a `u32` (the
        // assert above), so the sum does not wrap.
        Some(word) => Some(MESSAGE_ID_BASE.wrapping_add(word & !TARGET_PRESENT)),
        None => None,
    }
}

/// The slot message target `id` sits on ([`message_id`] read back), or `None`
/// for an id below [`MESSAGE_ID_BASE`] or past every packed target.
#[must_use]
pub const fn message_target(id: u32) -> Option<Target>
{
    // An id below the base is a wired line, not a message target.
    let Some(offset) = id.checked_sub(MESSAGE_ID_BASE)
    else
    {
        return None;
    };
    if offset & TARGET_PRESENT != 0
    {
        return None;
    }
    Target::unpack(offset | TARGET_PRESENT)
}

// ── Routing state ─────────────────────────────────────────────────────────────

/// The routing state a route change mutates: the table of lines and the count
/// of sources.
#[cfg(not(test))]
struct Routing
{
    /// The table: one entry per line, or none before [`init_table`].
    routes: &'static [IrqRoute],
    /// The sources that hold a delivery slot: routed lines and minted message
    /// targets. Interrupt remapping is switched only while it is zero
    /// ([`set_remap`]). The lines and slots bound it, so its saturating
    /// steps never clamp.
    sources: u32,
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
    sources: 0,
});

/// The table and the gates, published once by [`init_table`] for the lock-free
/// reads of [`dispatch_device_irq`]: the table's base (null before) and its line
/// count, and the gate slab's base (null before).
#[cfg(not(test))]
static TABLE_BASE: AtomicPtr<IrqRoute> = AtomicPtr::new(null_mut());
#[cfg(not(test))]
static TABLE_LINES: AtomicU32 = AtomicU32::new(0);
#[cfg(not(test))]
static GATES: AtomicPtr<DeliveryGate> = AtomicPtr::new(null_mut());

/// The table entry for line `id`, or `None` for an id the table does not cover
/// (or before [`init_table`]).
#[cfg(not(test))]
fn route_of(id: u32) -> Option<&'static IrqRoute>
{
    if id >= TABLE_LINES.load(Ordering::Acquire)
    {
        return None;
    }
    let base = TABLE_BASE.load(Ordering::Acquire);
    // SAFETY: `init_table` publishes the line count after the base (Release),
    // and both before any line is routed; `id` is below the count, so the
    // offset stays inside the table.
    let entry = unsafe { base.add(id as usize) };
    // SAFETY: `entry` lies in the table, which lives for the kernel's lifetime.
    Some(unsafe { &*entry })
}

/// CPU `cpu`'s delivery gate, or `None` for a CPU past the boot CPUs (or before
/// [`init_table`]).
#[cfg(not(test))]
fn gate(cpu: usize) -> Option<&'static DeliveryGate>
{
    let base = GATES.load(Ordering::Acquire);
    if base.is_null() || cpu >= crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize
    {
        return None;
    }
    // SAFETY: the slab holds a gate for each boot CPU, and `cpu` is below their
    // count, so the offset stays inside it.
    let slot = unsafe { base.add(cpu) };
    // SAFETY: `slot` holds a zero-initialised gate (an atomic, for which zero
    // is a valid value); the slab is never freed.
    Some(unsafe { &*slot })
}

// ── Initialisation ───────────────────────────────────────────────────────────

/// Allocate the routing table for `line_count` lines and one delivery gate per
/// boot CPU as zero-filled runs of pages (`sched::alloc_zeroed_slab`,
/// `sched::alloc_per_cpu_slab`, which may span several buddy blocks, so no line
/// or CPU count is capped by the largest one), and publish them. Halts the
/// boot, naming the slab, when no run is long enough.
///
/// Called once on the BSP at Phase 5, after the interrupt controllers are
/// discovered (`arch::current::interrupts::init`) and the boot CPU count is
/// known (Phase 4), and before any source is routed or minted. Both live for
/// the kernel's lifetime: the buddy is sealed at Phase 7.
#[cfg(not(test))]
pub fn init_table(line_count: u32, allocator: &mut crate::mm::BuddyAllocator)
{
    let lines = line_count as usize;
    // A slab is page-aligned, so the routes at its base are aligned; a table of
    // no lines still takes one zeroed entry, which no id reaches.
    let bytes = lines
        .max(1)
        .checked_mul(core::mem::size_of::<IrqRoute>())
        .unwrap_or_else(|| crate::fatal("init_table: IRQ_ROUTING_TABLE overflows"));
    let routes_base =
        crate::sched::alloc_zeroed_slab::<IrqRoute>(bytes, allocator, "IRQ_ROUTING_TABLE");
    let gates = crate::sched::alloc_per_cpu_slab::<DeliveryGate>(
        GATE_SLAB,
        crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize,
        allocator,
    );
    // SAFETY: the allocation holds at least `lines` routes, zero-filled, which
    // is the empty entry; nothing else references it.
    let routes = unsafe { core::slice::from_raw_parts(routes_base, lines) };
    ROUTING.with(|routing| routing.routes = routes);
    GATES.store(gates, Ordering::Release);
    TABLE_BASE.store(routes_base, Ordering::Release);
    TABLE_LINES.store(line_count, Ordering::Release);
    crate::kprintln!("irq: routing table for {} lines", line_count);
}

// ── Route changes ─────────────────────────────────────────────────────────────

/// The controller and gate operations a route change makes. The kernel's are
/// `Hardware`'s; the host tests drive the change steps below with stand-ins
/// that record each call and park at it.
trait Controls
{
    /// Mask line `irq` at its controller.
    fn mask(&self, irq: u32);

    /// Unmask line `irq` at its controller.
    fn unmask(&self, irq: u32);

    /// Release line `irq`'s route to `target` at its controller: mask the line
    /// and free the slot ([`Slot::Free`]).
    ///
    /// # Safety
    /// The line is routed to `target`, and the caller holds the routing lock.
    unsafe fn unroute(&self, irq: u32, target: Target);

    /// Wait out the delivery running on CPU `cpu`, if one is: called under the
    /// routing lock, after a change removed with a `SeqCst` store something
    /// that delivery may hold (module doc § Thread safety,
    /// [`DeliveryGate::wait_out`]).
    fn wait_out(&self, cpu: u32);
}

/// The kernel's [`Controls`]: the discovered controllers and the CPUs' gates.
#[cfg(not(test))]
struct Hardware;

#[cfg(not(test))]
impl Controls for Hardware
{
    fn mask(&self, irq: u32)
    {
        crate::arch::current::interrupts::mask(irq);
    }

    fn unmask(&self, irq: u32)
    {
        crate::arch::current::interrupts::unmask(irq);
    }

    unsafe fn unroute(&self, irq: u32, target: Target)
    {
        // SAFETY: caller contract: the line is routed to `target`, serialised
        // by the routing lock.
        unsafe { crate::arch::current::interrupts::unroute_device_irq(irq, target) };
    }

    /// Runs with interrupts disabled, under the spin-site breadcrumb
    /// `irq:route-drain` (`sched::SPIN_SITE_IRQ_ROUTE_DRAIN`), which the
    /// softlockup watchdog names if the wait wedges. It is bounded: the wait
    /// ends at that one delivery's exit, and a delivery runs with interrupts
    /// disabled from its entry to its exit, takes only the notifications' and
    /// the scheduler's spinlocks, and waits for nothing the caller holds.
    fn wait_out(&self, cpu: u32)
    {
        let Some(gate) = gate(cpu as usize)
        else
        {
            return;
        };
        let mut marked = false;
        gate.wait_out(|| {
            if !marked
            {
                crate::sched::spin_site_enter(crate::sched::SPIN_SITE_IRQ_ROUTE_DRAIN);
                marked = true;
            }
            core::hint::spin_loop();
        });
        if marked
        {
            crate::sched::spin_site_exit();
        }
    }
}

/// Link unbound `binding` at the head of `route`'s list with mask bit `bit`,
/// naming `notification`, and mark it bound and owing ([`LineMasks::take`]).
/// `first` is the target of a routed line that had no binding until this one,
/// whose CPU is then waited out: an interrupt latched for the slot's previous
/// owner can be delivered as the line with an empty list, its mask not yet at
/// the controller, and waiting it out lands that mask before the receiver's
/// first acknowledgement can unmask, so it cannot leave the line masked with
/// none owing.
///
/// Called under the routing lock.
fn link_line(
    controls: &impl Controls,
    route: &IrqRoute,
    binding: &IrqBinding,
    bit: u32,
    notification: *mut NotificationState,
    first: Option<Target>,
)
{
    let head = route.bindings.load(Ordering::Relaxed);
    route.masks.take(bit);
    binding.bit.store(bit, Ordering::Relaxed);
    binding.notification.store(notification, Ordering::SeqCst);
    binding.next.store(head, Ordering::SeqCst);
    // Publish last: a delivery that reads the new head sees the binding's
    // notification and link.
    route
        .bindings
        .store(core::ptr::from_ref(binding).cast_mut(), Ordering::SeqCst);
    if let Some(target) = first
    {
        controls.wait_out(target.cpu);
    }
}

/// Bind unbound `binding` to the message target whose slot's entry is
/// `entry`, naming `notification`.
///
/// Called under the routing lock, with `entry` [`Slot::Unbound`].
fn bind_message(entry: &SlotEntry, binding: &IrqBinding, notification: *mut NotificationState)
{
    binding.bit.store(MESSAGE_BIT, Ordering::Relaxed);
    binding.notification.store(notification, Ordering::SeqCst);
    // Publish last: a delivery that reads the entry sees the binding's
    // notification. A delivery that read the entry unbound signals nothing, so
    // none needs waiting out.
    entry.store(Slot::Bound(NonNull::from(binding)));
}

/// Point bound `binding` at `notification`, then wait out `cpu`, the CPU that
/// delivers the binding's source (`None` when the source is delivered
/// nowhere), so no delivery still holds the notification it replaced.
///
/// Called under the routing lock.
fn renotify(
    controls: &impl Controls,
    binding: &IrqBinding,
    notification: *mut NotificationState,
    cpu: Option<u32>,
)
{
    binding.notification.store(notification, Ordering::SeqCst);
    if let Some(cpu) = cpu
    {
        controls.wait_out(cpu);
    }
}

/// Remove `binding` from the message target whose slot's entry is `entry`, on
/// CPU `cpu`: leave the target unbound, then wait out the CPU, so no delivery
/// still holds the binding. Returns whether the entry named the binding.
///
/// Called under the routing lock.
fn unbind_message(
    controls: &impl Controls,
    entry: &SlotEntry,
    cpu: u32,
    binding: &IrqBinding,
) -> bool
{
    if entry.load() != Slot::Bound(NonNull::from(binding))
    {
        return false;
    }
    entry.store(Slot::Unbound);
    controls.wait_out(cpu);
    true
}

/// Remove bound `binding` from line `irq`, whose table entry is `route`:
/// unlink it, clear its bit from the bound mask, wait out the line's CPU, and
/// settle the line at its controller ([`Settle`]). When no binding remains,
/// a line an object still holds the route of stays routed, masked
/// ([`Settle::StayMasked`]), and any other is released ([`release_line`],
/// [`Settle::Release`]). Returns what the line was left to do. The caller
/// unbinds the binding's own fields.
///
/// # Safety
/// Called under the routing lock; `binding` is bound on `irq`, and every
/// binding linked on `route` is live.
unsafe fn unbind_line(
    controls: &impl Controls,
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
        // SAFETY: a linked binding is live (contract).
        link = unsafe { &(*cur).next };
    }
    let bit = binding.bit.load(Ordering::Relaxed);
    route.masks.unbind_begin(bit);
    let routed = Target::unpack(route.target.load(Ordering::Relaxed));
    if let Some(routed) = routed
    {
        controls.wait_out(routed.cpu);
    }
    match route.masks.unbind_settle(bit)
    {
        Settle::Release if !released(route.holders.load(Ordering::Relaxed), 0) =>
        {
            // A holder keeps the route: the line stays masked, with no receiver.
            controls.mask(irq);
            Settle::StayMasked
        }
        Settle::Release =>
        {
            // SAFETY: the routing lock is held (contract).
            unsafe { release_line(controls, irq, route) };
            Settle::Release
        }
        Settle::Unmask =>
        {
            unmask_settled(controls, irq, route);
            Settle::Unmask
        }
        Settle::StayMasked => Settle::StayMasked,
    }
}

/// Release line `irq`, whose table entry is `route` and which neither a
/// binding nor a route holder names: forget its mode and target, and free its
/// slot ([`Controls::unroute`]), then wait out its CPU again, so no delivery
/// that read the line from that slot outlives the release (module doc
/// § Thread safety). A line routed nowhere is masked.
///
/// # Safety
/// Called under the routing lock.
unsafe fn release_line(controls: &impl Controls, irq: u32, route: &IrqRoute)
{
    route.mode.store(0, Ordering::Relaxed);
    match Target::unpack(route.target.swap(0, Ordering::Relaxed))
    {
        Some(routed) =>
        {
            // SAFETY: the line was routed to `routed`; the routing lock is
            // held (contract).
            unsafe { controls.unroute(irq, routed) };
            controls.wait_out(routed.cpu);
        }
        None => controls.mask(irq),
    }
}

/// Unmask line `irq`, whose bindings were found owing nothing under the routing
/// lock, and mask it again if a delivery that raced the unmask marked a binding
/// owing ([`LineMasks::unmask_settled`]; module doc § Thread safety). On
/// riscv64 the APLIC writes are unlocked: `aia::unmask` fences them before the
/// owing mask's read, and a racing delivery's `aia::mask` orders the delivery's
/// marking before its write (`fence w,o`). On x86-64 the unmask and a racing
/// delivery's mask both take `IOAPIC_LOCK`: when the mask's critical section
/// comes first, the delivery marked its bindings before it, and the lock hands
/// that write to the read; when it comes second, the mask lands last.
fn unmask_settled(controls: &impl Controls, irq: u32, route: &IrqRoute)
{
    route
        .masks
        .unmask_settled(|| controls.unmask(irq), || controls.mask(irq));
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Bind `binding` (the binding of an Interrupt object for source `irq`) to
/// `notification`, the state of the Notification object `holder`
/// (`SYS_IRQ_REGISTER`), with the source's trigger and polarity `mode` (module
/// doc § Mode).
///
/// An unbound binding takes a reference on `holder` and is added to the
/// source. On a line, the line must be routed (`SYS_IRQ_ROUTE`, [`route`]) in
/// `mode`, and the binding masks it. The new binding takes the lowest free
/// bit of the line's masks and owes an acknowledgement, so the line stays
/// masked until its receiver's first `SYS_IRQ_ACK`. A line's first binding also waits out the line's CPU, so a
/// delivery that found no binding has masked the line before this returns
/// ([`link_line`]). A message target (module doc § Sources) takes one binding,
/// in mode 0, which its slot's entry then names; it is neither routed nor
/// masked here: its slot was assigned at its mint.
///
/// A binding already bound is rebound to `notification`: it keeps its bit and
/// whether it owes, and the line's mask is unchanged. It takes a reference on
/// `holder` and gives up the one it held, and a delivery that read the
/// notification it replaced is waited out before this returns. A rebind to the
/// notification the binding already names changes nothing.
///
/// Returns the object whose reference the binding gave up, which the caller
/// releases once the routing lock is free (`cap::object::release_ref`), or
/// `None`.
///
/// # Errors
/// [`RouteError::NoSuchLine`] when the line is past the table, or the message
/// target is not minted; [`RouteError::NotRouted`] when the line is not
/// routed, which a line no controller implements never is;
/// [`RouteError::ModeMismatch`] when `mode` differs from the one the line's
/// route recorded, or a message target is passed a mode other than 0;
/// [`RouteError::TooManyBindings`] when the line holds [`MAX_IRQ_BINDINGS`]
/// bindings, or the message target holds one;
/// [`RouteError::ReferenceLimit`] when `holder` can take no further reference.
/// Nothing changes on error.
///
/// # Safety
/// - `notification` must be a valid, live `NotificationState` pointer, the
///   state of `holder`, on which the caller holds a reference for the call.
/// - `binding` must be the binding of a live Interrupt object whose source is
///   `irq`, and that object must call [`unregister`] before it is freed.
/// - Must be called outside interrupt context, with no IPC source, scheduler,
///   or sleep-list lock held: the wait is for a delivery that takes them.
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
        if is_message(irq)
        {
            // SAFETY: the routing lock is held; caller contract.
            unsafe { register_message(irq, binding, notification, holder, mode) }
        }
        else
        {
            let route = routing
                .routes
                .get(irq as usize)
                .ok_or(RouteError::NoSuchLine)?;
            // SAFETY: the routing lock is held; caller contract.
            unsafe { register_line(irq, route, binding, notification, holder, mode) }
        }
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

/// Rebind bound `binding` to `notification` of `holder` ([`renotify`]), whose
/// source `cpu` delivers. Returns the object whose reference the binding gave
/// up.
///
/// # Safety
/// Under the routing lock, with [`register`]'s contract; `binding` is bound.
#[cfg(not(test))]
unsafe fn rebind(
    binding: &IrqBinding,
    notification: *mut NotificationState,
    holder: NonNull<KernelObjectHeader>,
    cpu: Option<u32>,
) -> Result<Option<NonNull<KernelObjectHeader>>, RouteError>
{
    if binding.notification.load(Ordering::Relaxed) == notification
    {
        return Ok(None);
    }
    // SAFETY: caller contract.
    unsafe { take_reference(holder) }?;
    renotify(&Hardware, binding, notification, cpu);
    let old = binding.holder.swap(holder.as_ptr(), Ordering::Relaxed);
    Ok(NonNull::new(old))
}

/// [`register`] for message target `id`.
///
/// # Safety
/// Under the routing lock, with [`register`]'s contract.
#[cfg(not(test))]
unsafe fn register_message(
    id: u32,
    binding: &IrqBinding,
    notification: *mut NotificationState,
    holder: NonNull<KernelObjectHeader>,
    mode: u32,
) -> Result<Option<NonNull<KernelObjectHeader>>, RouteError>
{
    let target = message_target(id).ok_or(RouteError::NoSuchLine)?;
    let entry =
        crate::arch::current::interrupts::slot_entry(target).ok_or(RouteError::NoSuchLine)?;
    match entry.load()
    {
        Slot::Unbound | Slot::Bound(_) if mode != 0 => Err(RouteError::ModeMismatch),
        Slot::Bound(bound) if bound == NonNull::from(binding) =>
        {
            // SAFETY: caller contract; the binding is bound, to this target.
            unsafe { rebind(binding, notification, holder, Some(target.cpu)) }
        }
        Slot::Bound(_) => Err(RouteError::TooManyBindings),
        Slot::Unbound =>
        {
            // SAFETY: caller contract.
            unsafe { take_reference(holder) }?;
            binding.holder.store(holder.as_ptr(), Ordering::Relaxed);
            bind_message(entry, binding, notification);
            Ok(None)
        }
        Slot::Free | Slot::Line(_) => Err(RouteError::NoSuchLine),
    }
}

/// [`register`] for wired line `irq`, whose table entry is `route`.
///
/// # Safety
/// Under the routing lock, with [`register`]'s contract.
#[cfg(not(test))]
unsafe fn register_line(
    irq: u32,
    route: &IrqRoute,
    binding: &IrqBinding,
    notification: *mut NotificationState,
    holder: NonNull<KernelObjectHeader>,
    mode: u32,
) -> Result<Option<NonNull<KernelObjectHeader>>, RouteError>
{
    let target = Target::unpack(route.target.load(Ordering::Relaxed));
    bind_admits(target.map(|_| route.mode.load(Ordering::Relaxed)), mode)?;
    let Some(target) = target
    else
    {
        return Err(RouteError::NotRouted);
    };
    if binding.bit.load(Ordering::Relaxed) != UNBOUND
    {
        // SAFETY: caller contract; the binding is bound, on this line.
        return unsafe { rebind(binding, notification, holder, Some(target.cpu)) };
    }
    let bit = route.masks.free_bit().ok_or(RouteError::TooManyBindings)?;
    // SAFETY: caller contract.
    unsafe { take_reference(holder) }?;
    // A routed line with no binding is masked already, and its first binding
    // waits out the line's CPU ([`link_line`]); a line with bindings is masked
    // until the new receiver's first acknowledgement.
    let first = if route.bindings.load(Ordering::Relaxed).is_null()
    {
        Some(target)
    }
    else
    {
        Hardware.mask(irq);
        None
    };
    binding.holder.store(holder.as_ptr(), Ordering::Relaxed);
    link_line(&Hardware, route, binding, bit, notification, first);
    Ok(None)
}

/// Route wired line `irq` in `mode` through the Interrupt object whose route
/// holder flag is `held` (`SYS_IRQ_ROUTE`; module doc § Routes).
///
/// A line not routed is routed at its controller in `mode`, masked, to the
/// next CPU in turn with a free slot, and the object becomes its first
/// holder. A line routed in `mode` gains the object as a holder; an object
/// that holds it already changes nothing. The target stays fixed until the
/// line's release, once neither a holder nor a binding remains.
///
/// # Errors
/// [`RouteError::NoSuchLine`] when the line is past the table or no
/// controller implements it; [`RouteError::ModeMismatch`] when the line is
/// routed in another mode; [`RouteError::Exhausted`] when no eligible CPU has
/// a free slot; [`RouteError::TooManyBindings`] when the holder count would
/// overflow. Nothing changes on error.
///
/// # Safety
/// `held` is the route holder flag of a live Interrupt object whose source is
/// `irq`, which calls [`drop_route_holder`] when it is freed with the flag set.
/// Same context as [`register`].
#[cfg(not(test))]
pub unsafe fn route(irq: u32, held: &AtomicBool, mode: u32) -> Result<(), RouteError>
{
    if is_message(irq)
    {
        return Err(RouteError::NoSuchLine);
    }
    ROUTING.with(|routing| {
        let route = routing
            .routes
            .get(irq as usize)
            .ok_or(RouteError::NoSuchLine)?;
        let routed = Target::unpack(route.target.load(Ordering::Relaxed))
            .map(|_| route.mode.load(Ordering::Relaxed));
        match route_step(routed, held.load(Ordering::Relaxed), mode)?
        {
            RouteStep::Held => Ok(()),
            RouteStep::AddHolder =>
            {
                let holders = route
                    .holders
                    .load(Ordering::Relaxed)
                    .checked_add(1)
                    .ok_or(RouteError::TooManyBindings)?;
                route.holders.store(holders, Ordering::Relaxed);
                held.store(true, Ordering::Relaxed);
                Ok(())
            }
            RouteStep::Route =>
            {
                // SAFETY: called after Phase 5 with a line the table covers;
                // serialised with every other route change by the routing lock.
                let target =
                    unsafe { crate::arch::current::interrupts::route_device_irq(irq, mode) }?;
                let Some(word) = target.pack()
                else
                {
                    // SAFETY: the line was just routed to `target`, under the
                    // routing lock; no binding is linked.
                    unsafe { Hardware.unroute(irq, target) };
                    return Err(RouteError::Exhausted);
                };
                route.target.store(word, Ordering::Relaxed);
                route.mode.store(mode, Ordering::Relaxed);
                route.holders.store(1, Ordering::Relaxed);
                held.store(true, Ordering::Relaxed);
                routing.sources = routing.sources.saturating_add(1);
                Ok(())
            }
        }
    })
}

/// Give up the route an Interrupt object of line `irq` held (called when the
/// object, its route holder flag set, is freed): the line is released when
/// neither another holder nor a binding remains ([`release_line`]).
///
/// # Safety
/// Same context as [`register`]; called once per object that [`route`] made a
/// holder, after its [`unregister`].
#[cfg(not(test))]
pub unsafe fn drop_route_holder(irq: u32)
{
    ROUTING.with(|routing| {
        let Some(route) = routing.routes.get(irq as usize)
        else
        {
            return;
        };
        let holders = route.holders.load(Ordering::Relaxed);
        debug_assert!(
            holders > 0,
            "irq: a route holder dropped from a line with none"
        );
        let holders = holders.saturating_sub(1);
        route.holders.store(holders, Ordering::Relaxed);
        if released(holders, route.masks.bound()) && route.target.load(Ordering::Relaxed) != 0
        {
            // SAFETY: the routing lock is held.
            unsafe { release_line(&Hardware, irq, route) };
            routing.sources = routing.sources.saturating_sub(1);
        }
    });
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
/// waiting out deliveries that take them. `binding` is the binding of a live
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
        let Some(route) = routing.routes.get(irq as usize)
        else
        {
            return;
        };
        if route.masks.ack(bit)
        {
            unmask_settled(&Hardware, irq, route);
        }
    });
}

/// Remove `binding` from source `irq` (called when its Interrupt object is
/// freed); a binding that is not bound is left untouched.
///
/// A delivery that read the binding is waited out before this returns. A line
/// is then released at its controller when no binding remains, and unmasked
/// when the remaining bindings owe nothing, so a receiver that goes cannot
/// hold a shared line masked ([`unbind_line`]). A message target keeps its
/// slot, unbound ([`free_message`] releases it).
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
        if is_message(irq)
        {
            if let Some(target) = message_target(irq)
                && let Some(entry) = crate::arch::current::interrupts::slot_entry(target)
            {
                unbind_message(&Hardware, entry, target.cpu, binding);
            }
        }
        else if let Some(route) = routing.routes.get(irq as usize)
        {
            // SAFETY: the routing lock is held, which keeps every linked
            // binding live, and `binding` is bound on `irq`, whose entry is
            // `route`.
            if unsafe { unbind_line(&Hardware, irq, route, binding) } == Settle::Release
            {
                routing.sources = routing.sources.saturating_sub(1);
            }
        }
        binding.notification.store(null_mut(), Ordering::Relaxed);
        binding.next.store(null_mut(), Ordering::Relaxed);
        binding.bit.store(UNBOUND, Ordering::Relaxed);
        NonNull::new(binding.holder.swap(null_mut(), Ordering::Relaxed))
    })
}

// ── Message targets ───────────────────────────────────────────────────────────

/// Mint a message target (`SYS_IRQ_MSG_ALLOC`): have the controller take a
/// free slot of the next CPU in turn with one
/// (`arch::current::interrupts::alloc_message_target`), which then holds the
/// target, unbound, until [`free_message`]. Returns the target's id
/// ([`message_id`]).
///
/// # Errors
/// [`RouteError::Exhausted`] when no CPU the controller can deliver a message
/// to has a free slot. Nothing changes on error.
///
/// Outside interrupt context (it takes the routing lock).
#[cfg(not(test))]
pub fn alloc_message() -> Result<u32, RouteError>
{
    ROUTING.with(|routing| {
        let target = crate::arch::current::interrupts::alloc_message_target()?;
        let Some(id) = message_id(target)
        else
        {
            crate::arch::current::interrupts::free_message_target(target);
            return Err(RouteError::Exhausted);
        };
        routing.sources = routing.sources.saturating_add(1);
        Ok(id)
    })
}

/// Release message target `id` (called when the last Interrupt object naming
/// it is freed): free its slot at the controller. An id that names no minted
/// target is left alone.
///
/// Every binding of the target was removed by its object's [`unregister`]
/// first, which waited out the deliveries that read it, so the slot is unbound
/// and no delivery dereferences anything through it. A delivery the device
/// raised before the free and the CPU takes later finds the slot free and is
/// dropped, or, once a later mint has taken the slot, reaches that target's
/// receiver once. A receiver reads its device's state on every delivery.
///
/// # Safety
/// Same context as [`register`]; no Interrupt object naming `id` is live, so
/// none is bound to it.
#[cfg(not(test))]
pub unsafe fn free_message(id: u32)
{
    let Some(target) = message_target(id)
    else
    {
        return;
    };
    ROUTING.with(|routing| {
        let Some(entry) = crate::arch::current::interrupts::slot_entry(target)
        else
        {
            return;
        };
        match entry.load()
        {
            Slot::Unbound =>
            {}
            Slot::Bound(_) =>
            {
                // No live object names the target (contract), so no binding
                // can be linked: clear it all the same, and wait out the CPU,
                // so no delivery reaches the binding's freed object.
                debug_assert!(false, "irq: a freed message target is still bound");
                entry.store(Slot::Unbound);
                Hardware.wait_out(target.cpu);
            }
            Slot::Free | Slot::Line(_) => return,
        }
        crate::arch::current::interrupts::free_message_target(target);
        routing.sources = routing.sources.saturating_sub(1);
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
    let target = message_target(id)?;
    ROUTING.with(|_| {
        let entry = crate::arch::current::interrupts::slot_entry(target)?;
        if !matches!(entry.load(), Slot::Unbound | Slot::Bound(_))
        {
            return None;
        }
        let address = crate::arch::current::interrupts::message_address(target)?;
        Some((
            address,
            crate::arch::current::interrupts::message_data(target),
        ))
    })
}

// ── Interrupt remapping ───────────────────────────────────────────────────────

/// Whether the kernel hands out interrupts in an IOMMU's remappable formats
/// (`SYS_IRQ_REMAP`), and how wide a remapped destination is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remap
{
    /// Compatibility formats: a message or an I/O APIC entry names its CPU
    /// and vector.
    Off,
    /// Remappable formats, each naming a handle, with destinations of 8 bits
    /// (`extended` clear) or 32 bits (`extended` set).
    On
    {
        /// Whether a remapped destination is a 32-bit (x2APIC) id.
        extended: bool,
    },
}

/// Why interrupt remapping could not be switched or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemapError
{
    /// The architecture has no interrupt remapping the kernel programs.
    NotSupported,
    /// A source exists ([`set_remap`]), or remapping is off, or the source
    /// holds no slot ([`remap_entry`]).
    State,
}

/// Switch the formats the kernel hands out (`SYS_IRQ_REMAP`): only while no
/// line is routed and no message target is minted, so every source's message
/// or entry is in the format of the switch's current setting, and none is
/// reprogrammed.
///
/// # Errors
/// [`RemapError::State`] while a source exists; [`RemapError::NotSupported`]
/// on an architecture with no interrupt remapping.
///
/// Outside interrupt context (it takes the routing lock).
#[cfg(not(test))]
pub fn set_remap(remap: Remap) -> Result<(), RemapError>
{
    ROUTING.with(|routing| {
        if routing.sources != 0
        {
            return Err(RemapError::State);
        }
        crate::arch::current::interrupts::set_remap(remap)
    })
}

/// The remapping entry an IOMMU needs for source `id`, a routed line or a
/// minted message target, packed for `SYS_CAP_INFO`'s
/// `CAP_INFO_IRQ_REMAP_ENTRY` (`arch::current::interrupts::remap_entry`).
///
/// # Errors
/// [`RemapError::State`] with remapping off or when `id` names no routed line
/// or minted target; [`RemapError::NotSupported`] on an architecture with no
/// interrupt remapping.
///
/// Outside interrupt context (it takes the routing lock).
#[cfg(not(test))]
pub fn remap_entry(id: u32) -> Result<u64, RemapError>
{
    ROUTING.with(|routing| {
        let target = if is_message(id)
        {
            let target = message_target(id).ok_or(RemapError::State)?;
            let entry =
                crate::arch::current::interrupts::slot_entry(target).ok_or(RemapError::State)?;
            if !matches!(entry.load(), Slot::Unbound | Slot::Bound(_))
            {
                return Err(RemapError::State);
            }
            target
        }
        else
        {
            let route = routing.routes.get(id as usize).ok_or(RemapError::State)?;
            Target::unpack(route.target.load(Ordering::Relaxed)).ok_or(RemapError::State)?
        };
        crate::arch::current::interrupts::remap_entry(target)
    })
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
    // `offset` < `cpu_count`, so the remainder is taken of a non-zero count.
    (0..cpu_count)
        .filter_map(|offset| start.wrapping_add(offset).checked_rem(cpu_count))
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
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the successor is below the CPU count, which fits u32"
    )]
    NEXT_TARGET_CPU.store(
        cpu.wrapping_add(1).checked_rem(cpu_count).unwrap_or(0) as u32,
        Ordering::Relaxed,
    );
    Some(cpu)
}

// ── Delivery ──────────────────────────────────────────────────────────────────

/// Dispatch a hardware interrupt that arrived through `entry`, a slot of the
/// executing CPU's delivery space, to the notifications bound to its source.
///
/// Called from the arch-specific device IRQ path (x86-64: `idt::irq_dispatch`,
/// with the entry of the vector in this CPU's row; RISC-V: the supervisor
/// external interrupt handler, with the entry of the identity its IMSIC claim
/// names) with interrupts disabled. The delivery runs under this CPU's gate
/// ([`deliver`]):
/// 1. A wired line ([`deliver_line`]): mark every bound binding as owing an
///    acknowledgement, mask the line at the controller (no further interrupt of
///    the line is forwarded until every receiver has acknowledged; one
///    forwarded before the mask took effect is delivered after this one), and
///    OR notification bit 0 into each binding's notification and enqueue the
///    waiter it woke. A line with no binding linked is masked.
/// 2. A bound message target: signal its binding's notification the same way.
/// 3. A free slot, or an unbound target: nothing (an interrupt latched before
///    its source released the slot).
///
/// Then acknowledge at the controller (the x86-64 EOI; nothing on RISC-V, whose
/// IMSIC claim cleared the identity).
///
/// # Safety
/// Must only be called from interrupt context with interrupts disabled, with an
/// entry of the executing CPU's row.
#[cfg(not(test))]
pub unsafe fn dispatch_device_irq(entry: &SlotEntry)
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;

    // Fold an IRQ-arrival jitter sample (a distinct event class from timer
    // ticks) into this CPU's entropy accumulator. Allocation-free, lock-free.
    crate::entropy::jitter::sample(
        cpu,
        crate::entropy::jitter::Source::Irq,
        crate::arch::current::entropy::read_cycle_counter(),
    );

    // SAFETY: interrupt context with interrupts disabled (contract); a binding
    // holds a reference on its notification's object, and a change that takes
    // the notification from the binding waits out this CPU's gate, inside
    // which every call is made.
    let signal_one = |notification| unsafe { signal(notification) };

    // Every slot is routed or minted after `init_table` published the gates, so
    // an entry that names a source always finds one.
    let mut line = 0;
    if let Some(gate) = gate(cpu)
    {
        let on_line = |irq| {
            line = irq;
            match route_of(irq)
            {
                Some(route) =>
                {
                    // SAFETY: called inside this CPU's gate, the gate of the
                    // CPU the line is routed to, since it arrived through its
                    // slot.
                    unsafe {
                        deliver_line(
                            route,
                            || crate::arch::current::interrupts::mask(irq),
                            signal_one,
                        );
                    }
                }
                None => crate::arch::current::interrupts::mask(irq),
            }
        };
        // SAFETY: interrupt context with interrupts disabled (contract); this
        // is the executing CPU's gate and `entry` a slot of its row.
        unsafe { deliver(gate, entry, on_line, signal_one) };
    }

    // Acknowledge at the interrupt controller (the x86-64 EOI). An interrupt
    // with no binding to signal must still be acknowledged: without the EOI,
    // the x86-64 local APIC keeps its vector in service, blocking every
    // interrupt of its priority class and below.
    crate::arch::current::interrupts::acknowledge(line);
}

/// One delivery through `entry` under `gate`: enter the gate, then deliver
/// what the entry holds, a line through `on_line` with its id or a bound
/// message target's notification through `on_bound`, then exit the gate.
///
/// # Safety
/// `gate` is the executing CPU's and `entry` a slot of its row, so every
/// change that clears the entry waits out this delivery before it frees the
/// binding it named; interrupts stay disabled for the call.
unsafe fn deliver(
    gate: &DeliveryGate,
    entry: &SlotEntry,
    on_line: impl FnOnce(u32),
    on_bound: impl FnOnce(*mut NotificationState),
)
{
    // Enter before the entry's read, so a change that removes what the
    // delivery reads waits for it (`DeliveryGate::wait_out`).
    gate.enter();
    match entry.load()
    {
        Slot::Line(irq) => on_line(irq),
        Slot::Bound(binding) =>
        {
            // SAFETY: a binding a slot names is live until a change clears the
            // entry and waits out this gate (contract).
            let notification = unsafe { binding.as_ref() }
                .notification
                .load(Ordering::SeqCst);
            if !notification.is_null()
            {
                on_bound(notification);
            }
        }
        Slot::Free | Slot::Unbound =>
        {}
    }
    // Release: orders every access to the bindings, the notifications, and the
    // woken waiters before a change's wait observes the exit.
    gate.exit();
}

/// The line part of a delivery: mark every bound binding of `route` owing,
/// mask the line through `mask`, and pass each binding's notification to
/// `signal`; with no binding linked, mask the line.
///
/// # Safety
/// Inside the gate of the CPU the line is routed to, which keeps every binding
/// reached through `route` live.
unsafe fn deliver_line(
    route: &IrqRoute,
    mask: impl FnOnce(),
    mut signal: impl FnMut(*mut NotificationState),
)
{
    // The bound mask is read before the list, both after the gate's entry: a
    // binding an unbind removes is either missing from both or waited for.
    let bound = route.masks.bound();
    let mut cur = route.bindings.load(Ordering::SeqCst);

    // Mask before delivering, so the controller forwards no further interrupt
    // of the line until every receiver has acknowledged; the bindings are
    // marked owing before the mask, so an unmask that races it sees the debt
    // (module doc § Thread safety), and the mask is ordered before the signals
    // below, so a receiver's acknowledgement does not unmask the line ahead of
    // it.
    if cur.is_null()
    {
        mask();
    }
    else
    {
        route.masks.deliver(bound, mask);
    }
    // SAFETY: a binding reached from the line is live while the caller's gate
    // is entered (contract).
    while let Some(binding) = unsafe { cur.as_ref() }
    {
        let notification = binding.notification.load(Ordering::SeqCst);
        if !notification.is_null()
        {
            signal(notification);
        }
        cur = binding.next.load(Ordering::SeqCst);
    }
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
    fn an_unrouted_line_is_routed_in_any_mode()
    {
        assert_eq!(route_step(None, false, 0), Ok(RouteStep::Route));
        assert_eq!(route_step(None, false, 3), Ok(RouteStep::Route));
    }

    #[test]
    fn a_routed_line_takes_holders_only_in_its_mode()
    {
        assert_eq!(route_step(Some(1), false, 1), Ok(RouteStep::AddHolder));
        assert_eq!(route_step(Some(1), true, 1), Ok(RouteStep::Held));
        assert_eq!(route_step(Some(1), false, 0), Err(RouteError::ModeMismatch));
        assert_eq!(route_step(Some(1), true, 3), Err(RouteError::ModeMismatch));
    }

    #[test]
    fn a_binding_needs_a_route_in_its_mode()
    {
        assert_eq!(bind_admits(None, 0), Err(RouteError::NotRouted));
        assert_eq!(bind_admits(Some(2), 2), Ok(()));
        assert_eq!(bind_admits(Some(2), 0), Err(RouteError::ModeMismatch));
    }

    #[test]
    fn a_line_is_released_once_no_holder_and_no_binding_remain()
    {
        assert!(released(0, 0));
        assert!(!released(1, 0));
        assert!(!released(0, 1));
        assert!(!released(2, 0b101));
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
        // marks it owing after: the settle, run after the wait, must clear it,
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

    // Defect caught: a message id mapped back to another slot, so a bind or a
    // free reaches another target's slot.
    #[test]
    fn a_message_id_names_its_slot()
    {
        let widest = Target {
            cpu: u32::try_from(crate::sched::MAX_CPUS).unwrap() - 1,
            slot: 2047,
        };
        for target in [
            Target { cpu: 0, slot: 0 },
            Target { cpu: 0, slot: 255 },
            Target { cpu: 3, slot: 32 },
            widest,
        ]
        {
            let id = message_id(target).unwrap();
            assert!(is_message(id));
            assert_eq!(message_target(id), Some(target));
        }
        assert_eq!(
            message_id(Target { cpu: 0, slot: 0 }),
            Some(MESSAGE_ID_BASE)
        );
        assert_eq!(message_id(Target { cpu: 0, slot: 2048 }), None);
    }

    // Defect caught: a message id inside the root Interrupt capability's range,
    // which a split could name and bind as a wired line, or a wired line's id
    // read as a message target's slot.
    #[test]
    fn message_ids_lie_past_the_interrupt_id_space()
    {
        assert_eq!(MESSAGE_ID_BASE, crate::arch::current::ROOT_IRQ_COUNT);
        assert!(!is_message(MESSAGE_ID_BASE - 1));
        assert!(is_message(MESSAGE_ID_BASE));
        assert_eq!(message_target(0), None);
        assert_eq!(message_target(MESSAGE_ID_BASE - 1), None);
        if let Some(past) = MESSAGE_ID_BASE.checked_add(TARGET_PRESENT)
        {
            assert_eq!(message_target(past), None);
        }
    }

    // ── Changes against a running delivery ────────────────────────────────────
    //
    // Each test runs one delivery on the test's thread through the kernel's own
    // `deliver` and `deliver_line`, parks it at a step, and runs a change on a
    // second thread through the kernel's own change steps, with `Stand` as the
    // controllers and the gate's CPU. The change reports when its wait finds the
    // delivery running, so the outcome depends on no timing.

    /// The one CPU's id in these tests.
    const CPU: u32 = 0;

    /// The line these tests route.
    const LINE: u32 = 5;

    /// The slot the line is routed to.
    const ROUTED: Target = Target { cpu: CPU, slot: 7 };

    /// A notification a test binding names: an address no test dereferences.
    fn note(n: usize) -> *mut NotificationState
    {
        core::ptr::without_provenance_mut(n * 64)
    }

    /// A line routed to [`ROUTED`] with no binding linked.
    fn routed_line() -> IrqRoute
    {
        IrqRoute {
            bindings: AtomicPtr::new(null_mut()),
            mode: AtomicU32::new(0),
            target: AtomicU32::new(ROUTED.pack().unwrap()),
            holders: AtomicU32::new(0),
            masks: empty_masks(),
        }
    }

    /// The controllers and the CPU of these tests: the line's mask, the slot the
    /// line is routed to, which `unroute` frees after running `before_unroute`,
    /// and the CPU's gate, a wait on which reports on `waiting` when it finds a
    /// delivery running.
    struct Stand<'a>
    {
        gate: &'a DeliveryGate,
        slot: &'a SlotEntry,
        masked: std::sync::atomic::AtomicBool,
        before_unroute: Box<dyn Fn() + Sync + 'a>,
        waiting: std::sync::mpsc::Sender<()>,
    }

    impl<'a> Stand<'a>
    {
        fn new(gate: &'a DeliveryGate, slot: &'a SlotEntry)
        -> (Self, std::sync::mpsc::Receiver<()>)
        {
            let (waiting, waits) = std::sync::mpsc::channel();
            let stand = Self {
                gate,
                slot,
                masked: std::sync::atomic::AtomicBool::new(false),
                before_unroute: Box::new(|| {}),
                waiting,
            };
            (stand, waits)
        }

        fn masked(&self) -> bool
        {
            self.masked.load(Ordering::SeqCst)
        }
    }

    /// Return once the change on `change` reports that its wait found the
    /// delivery running, which the calling thread holds open, so a change that
    /// waits cannot have returned; fail when it returns without reporting,
    /// which a change that skips its wait does.
    fn await_wait_out<T>(
        waits: &std::sync::mpsc::Receiver<()>,
        change: &std::thread::ScopedJoinHandle<'_, T>,
    )
    {
        while waits.try_recv().is_err()
        {
            assert!(
                !change.is_finished(),
                "the change returned without waiting out the delivery"
            );
            std::thread::yield_now();
        }
    }

    impl Controls for Stand<'_>
    {
        fn mask(&self, irq: u32)
        {
            assert_eq!(irq, LINE);
            self.masked.store(true, Ordering::SeqCst);
        }

        fn unmask(&self, irq: u32)
        {
            assert_eq!(irq, LINE);
            self.masked.store(false, Ordering::SeqCst);
        }

        unsafe fn unroute(&self, irq: u32, target: Target)
        {
            assert_eq!((irq, target), (LINE, ROUTED));
            (self.before_unroute)();
            self.masked.store(true, Ordering::SeqCst);
            self.slot.store(Slot::Free);
        }

        fn wait_out(&self, cpu: u32)
        {
            assert_eq!(cpu, CPU);
            let mut reported = false;
            self.gate.wait_out(|| {
                if !reported
                {
                    // The test may have stopped listening; the wait goes on.
                    let _ = self.waiting.send(());
                    reported = true;
                }
                core::hint::spin_loop();
            });
        }
    }

    // Defect caught: an unbind returning while a delivery on the line's CPU
    // still walks the binding it unlinked, so the Interrupt object is freed
    // under the walk; the walk losing the rest of the line at the unlinked
    // binding; or the settle, run after the wait, leaving the removed binding
    // owing.
    #[test]
    fn an_unbind_waits_for_a_walk_standing_on_its_binding()
    {
        let gate = DeliveryGate::new();
        let slot = SlotEntry::free();
        slot.store(Slot::Line(LINE));
        let (stand, waits) = Stand::new(&gate, &slot);
        let route = routed_line();
        let (a, b) = (IrqBinding::unbound(), IrqBinding::unbound());
        link_line(&stand, &route, &b, 0, note(1), None);
        link_line(&stand, &route, &a, 1, note(2), None);
        route.masks.ack(0);
        route.masks.ack(1);

        let mut signalled = Vec::new();
        std::thread::scope(|scope| {
            let mut change = None;
            let signal = |notification| {
                signalled.push(notification);
                if notification == note(2)
                {
                    // The walk stands on `a`: unbind it on another CPU.
                    // SAFETY: `a` is bound on the line, and both bindings
                    // outlive the scope.
                    let unbind = || unsafe { unbind_line(&stand, LINE, &route, &a) };
                    let handle = scope.spawn(unbind);
                    await_wait_out(&waits, &handle);
                    change = Some(handle);
                }
            };
            let on_line = |irq| {
                assert_eq!(irq, LINE);
                // SAFETY: inside the gate of the line's CPU.
                unsafe { deliver_line(&route, || stand.mask(irq), signal) };
            };
            // SAFETY: the slot and the bindings outlive the delivery.
            unsafe { deliver(&gate, &slot, on_line, |_| unreachable!()) };
            assert_eq!(change.unwrap().join().unwrap(), Settle::StayMasked);
        });

        assert_eq!(signalled, [note(2), note(1)]);
        assert_eq!(
            route.bindings.load(Ordering::SeqCst),
            (&raw const b).cast_mut()
        );
        assert_eq!(route.masks.owing.load(Ordering::SeqCst), 1 << 0);
        assert!(stand.masked());
        assert!(route.masks.ack(0));
    }

    // Defect caught: a line's last unbind releasing a route a holder object
    // still holds (`SYS_IRQ_ROUTE`), so the line's target moves under the
    // remapping entry devmgr had written for it, and the holder's next driver
    // binds a line that is not routed; or the unbind leaving the line unmasked
    // with no receiver.
    #[test]
    fn a_held_line_stays_routed_and_masked_after_its_last_unbind()
    {
        let gate = DeliveryGate::new();
        let slot = SlotEntry::free();
        slot.store(Slot::Line(LINE));
        let (stand, _waits) = Stand::new(&gate, &slot);
        let route = routed_line();
        route.holders.store(1, Ordering::SeqCst);
        let a = IrqBinding::unbound();
        link_line(&stand, &route, &a, 0, note(1), None);
        route.masks.ack(0);
        stand.unmask(LINE);

        // SAFETY: `a` is bound on the line and outlives the call; no delivery
        // runs.
        let settle = unsafe { unbind_line(&stand, LINE, &route, &a) };
        assert_eq!(settle, Settle::StayMasked);
        assert_eq!(
            Target::unpack(route.target.load(Ordering::SeqCst)),
            Some(ROUTED)
        );
        assert_eq!(slot.load(), Slot::Line(LINE));
        assert!(stand.masked());

        // With no holder left, the same last unbind releases the line.
        route.holders.store(0, Ordering::SeqCst);
        link_line(&stand, &route, &a, 0, note(1), None);
        // SAFETY: as above.
        let settle = unsafe { unbind_line(&stand, LINE, &route, &a) };
        assert_eq!(settle, Settle::Release);
        assert_eq!(route.target.load(Ordering::SeqCst), 0);
        assert_eq!(slot.load(), Slot::Free);
    }

    // Defect caught: a line's release returning while a delivery that read the
    // line from its old slot still runs, so the delivery's mask lands after the
    // line's next route is acknowledged and unmasked, leaving the line masked
    // with nobody owing; or a delivery through the freed slot reaching the line.
    #[test]
    fn a_release_waits_for_a_delivery_that_read_the_line_from_its_slot()
    {
        let gate = DeliveryGate::new();
        let slot = SlotEntry::free();
        slot.store(Slot::Line(LINE));
        let (unrouting, at_unroute) = std::sync::mpsc::channel();
        let (resume, go) = std::sync::mpsc::channel::<()>();
        let go = std::sync::Mutex::new(go);
        let (mut stand, waits) = Stand::new(&gate, &slot);
        stand.before_unroute = Box::new(move || {
            unrouting.send(()).unwrap();
            go.lock().unwrap().recv().unwrap();
        });
        let route = routed_line();
        let a = IrqBinding::unbound();
        link_line(&stand, &route, &a, 0, note(1), None);
        route.masks.ack(0);

        std::thread::scope(|scope| {
            // SAFETY: `a` is bound on the line and outlives the scope.
            let change = scope.spawn(|| unsafe { unbind_line(&stand, LINE, &route, &a) });
            // The change has unlinked the line's last binding and is about to
            // free the slot: a delivery reads the line from it now.
            at_unroute.recv().unwrap();
            let stale_mask = || {
                resume.send(()).unwrap();
                await_wait_out(&waits, &change);
                stand.mask(LINE);
            };
            let on_line = |irq| {
                assert_eq!(irq, LINE);
                // SAFETY: inside the gate of the line's CPU.
                unsafe { deliver_line(&route, stale_mask, |_| unreachable!()) };
            };
            // SAFETY: the slot and the binding outlive the delivery.
            unsafe { deliver(&gate, &slot, on_line, |_| unreachable!()) };
            assert_eq!(change.join().unwrap(), Settle::Release);
        });

        assert_eq!(slot.load(), Slot::Free);
        assert_eq!(route.target.load(Ordering::SeqCst), 0);
        // SAFETY: the slot outlives the delivery.
        unsafe {
            deliver(&gate, &slot, |_| unreachable!(), |_| unreachable!());
        }
    }

    // Defect caught: a line's first binding returning while a delivery that
    // found the line with no binding has yet to mask it, so the mask lands
    // after the receiver's first acknowledgement unmasked the line, leaving it
    // masked with nobody owing.
    #[test]
    fn a_first_binding_waits_for_a_delivery_that_found_no_binding()
    {
        let gate = DeliveryGate::new();
        let slot = SlotEntry::free();
        slot.store(Slot::Line(LINE));
        let (stand, waits) = Stand::new(&gate, &slot);
        let route = routed_line();
        let a = IrqBinding::unbound();

        std::thread::scope(|scope| {
            let mut change = None;
            let empty_list_mask = || {
                // The delivery found no binding; the first binds before its
                // mask lands.
                let bind = || link_line(&stand, &route, &a, 0, note(1), Some(ROUTED));
                let handle = scope.spawn(bind);
                await_wait_out(&waits, &handle);
                stand.mask(LINE);
                change = Some(handle);
            };
            let on_line = |irq| {
                assert_eq!(irq, LINE);
                // SAFETY: inside the gate of the line's CPU.
                unsafe { deliver_line(&route, empty_list_mask, |_| unreachable!()) };
            };
            // SAFETY: the slot and the binding outlive the delivery.
            unsafe { deliver(&gate, &slot, on_line, |_| unreachable!()) };
            change.unwrap().join().unwrap();
        });

        // The receiver's first acknowledgement, which the bind's return allows,
        // unmasks the line after the stale mask.
        assert!(stand.masked());
        assert!(route.masks.ack(0));
        unmask_settled(&stand, LINE, &route);
        assert!(!stand.masked());
    }

    // Defect caught: a message target's unbind returning while a delivery that
    // read the binding from the slot still runs, so the Interrupt object is
    // freed under it; or a later delivery still reaching the binding.
    #[test]
    fn a_message_unbind_waits_for_the_delivery_that_read_its_binding()
    {
        let gate = DeliveryGate::new();
        let slot = SlotEntry::free();
        slot.store(Slot::Unbound);
        let (stand, waits) = Stand::new(&gate, &slot);
        let a = IrqBinding::unbound();
        // A delivery through an unbound target signals nothing.
        // SAFETY: the slot outlives the delivery.
        unsafe { deliver(&gate, &slot, |_| unreachable!(), |_| unreachable!()) };
        bind_message(&slot, &a, note(1));

        std::thread::scope(|scope| {
            let mut change = None;
            let on_bound = |notification| {
                assert_eq!(notification, note(1));
                let handle = scope.spawn(|| unbind_message(&stand, &slot, CPU, &a));
                await_wait_out(&waits, &handle);
                change = Some(handle);
            };
            // SAFETY: the slot and the binding outlive the delivery.
            unsafe { deliver(&gate, &slot, |_| unreachable!(), on_bound) };
            assert!(change.unwrap().join().unwrap());
        });

        assert_eq!(slot.load(), Slot::Unbound);
        // SAFETY: the slot outlives the delivery.
        unsafe { deliver(&gate, &slot, |_| unreachable!(), |_| unreachable!()) };
        // A binding the slot no longer names is left alone.
        assert!(!unbind_message(&stand, &slot, CPU, &a));
    }

    // Defect caught: a rebind returning while a delivery that read the
    // binding's old notification still runs, so the old notification's last
    // reference is dropped and it is freed under the signal; or a later
    // delivery signalling the old notification.
    #[test]
    fn a_rebind_waits_for_the_delivery_that_read_the_old_notification()
    {
        let gate = DeliveryGate::new();
        let slot = SlotEntry::free();
        slot.store(Slot::Unbound);
        let (stand, waits) = Stand::new(&gate, &slot);
        let a = IrqBinding::unbound();
        bind_message(&slot, &a, note(1));

        std::thread::scope(|scope| {
            let mut change = None;
            let on_bound = |notification| {
                assert_eq!(notification, note(1));
                let handle = scope.spawn(|| renotify(&stand, &a, note(2), Some(CPU)));
                await_wait_out(&waits, &handle);
                change = Some(handle);
            };
            // SAFETY: the slot and the binding outlive the delivery.
            unsafe { deliver(&gate, &slot, |_| unreachable!(), on_bound) };
            change.unwrap().join().unwrap();
        });

        let mut signalled = None;
        // SAFETY: the slot and the binding outlive the delivery.
        unsafe {
            deliver(
                &gate,
                &slot,
                |_| unreachable!(),
                |notification| {
                    signalled = Some(notification);
                },
            );
        }
        assert_eq!(signalled, Some(note(2)));
    }
}
