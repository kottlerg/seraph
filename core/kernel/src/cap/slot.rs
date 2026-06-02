// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/slot.rs

//! Capability slot foundation types.
//!
//! [`CapabilitySlot`] is the fixed-size record stored in `CSpace` pages.
//! The layout is `#[repr(C)]` and exactly 72 bytes.
//!
//! ## Intrusive free list
//!
//! When a slot is free (`tag == Null`), the `deriv_parent` field is repurposed
//! to store the next-free index. Call [`CapabilitySlot::set_next_free`] and
//! [`CapabilitySlot::next_free`] to encode/decode; do not read `deriv_parent`
//! directly on a free slot. The `epoch` field of the encoded `SlotId` is the
//! free-list sentinel value `0` and MUST NOT appear in any live derivation
//! link — derivation links carry the registry epoch that was current when
//! they were stamped.
//!
//! ## Size derivation
//!
//! `SlotId` is 12 bytes: `(cspace_id: u32, epoch: u32, index: NonZeroU32)`.
//! `Option<SlotId>` is 12 bytes because `SlotId.index` is [`NonZeroU32`],
//! which provides a niche enabling the Option discriminant to be stored in
//! the zero value — no extra bytes needed. Verified by the size tests below.

use core::num::NonZeroU32;
use core::ptr::NonNull;

use super::object::KernelObjectHeader;

// ── Identifiers ───────────────────────────────────────────────────────────────

/// Unique identifier for a capability space.
pub type CSpaceId = u32;

/// A reference to a specific capability slot by `CSpace` ID, generation
/// epoch, and index.
///
/// `index` is [`NonZeroU32`] because slot 0 is permanently null and is never
/// a valid derivation target. This gives `Option<SlotId>` the same 12-byte
/// size as `SlotId` itself via niche optimization.
///
/// `epoch` is the generation counter from the `CSpace` registry at the time
/// this `SlotId` was stamped. Once `CSpaceId` recycling is enabled (see
/// #137), `lookup_cspace` compares the stamped epoch to the registry's
/// current epoch and fails fast on mismatch, so a stale `SlotId` referring
/// to a freed `CSpace` cannot mis-target a recycled tenant. The reserved
/// value `epoch == 0` is the free-list sentinel; it appears only in the
/// intrusive next-free encoding stored in a `CapTag::Null` slot's
/// `deriv_parent` and MUST NOT appear in any live derivation link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotId
{
    /// The `CSpace` this slot belongs to.
    pub cspace_id: CSpaceId,
    /// Registry generation counter stamped at construction. Compared on
    /// `lookup_cspace` once recycling is enabled.
    pub epoch: u32,
    /// Slot index within that `CSpace`. Never zero.
    pub index: NonZeroU32,
}

impl SlotId
{
    /// Construct a `SlotId` with epoch `0`.
    ///
    /// Used by call sites that do not yet thread a real registry epoch
    /// through. While `CSpaceId` recycling remains gated (no `free_cspace_id`
    /// has run, so every live entry has epoch `1`+ when registered), every
    /// site still works against a registry that ignores the supplied epoch
    /// on `lookup_cspace`. Sites that need to stamp a `SlotId` with the
    /// registry's current value should use [`Self::with_epoch`] together
    /// with `cap::registry_epoch`.
    ///
    /// Callers holding a raw `u32` must first convert via [`NonZeroU32::new`]
    /// and route the `None` case through their subsystem's error channel
    /// (e.g. `SyscallError::InvalidCapability`), so that user-controlled
    /// zero indices become graceful errors rather than kernel panics.
    pub fn new(cspace_id: CSpaceId, index: NonZeroU32) -> Self
    {
        Self {
            cspace_id,
            epoch: 0,
            index,
        }
    }

    /// Construct a `SlotId` with an explicit epoch.
    pub fn with_epoch(cspace_id: CSpaceId, epoch: u32, index: NonZeroU32) -> Self
    {
        Self {
            cspace_id,
            epoch,
            index,
        }
    }

    /// Construct a `SlotId` by snapshotting the registry's current epoch
    /// for `cspace_id`.
    ///
    /// The natural form for derivation-tree write sites: the link is being
    /// stamped now, so the current registry epoch is the correct value.
    /// Callers must hold a proof that the cspace is currently live (e.g.
    /// they just resolved a slot in it, or it is the caller's own cspace).
    /// If the registry has already retired this id, `registry_epoch`
    /// returns the bumped value and the `SlotId` stamps with that — but
    /// the caller's proof-of-life should make that case impossible.
    pub fn current(cspace_id: CSpaceId, index: NonZeroU32) -> Self
    {
        Self::with_epoch(cspace_id, crate::cap::registry_epoch(cspace_id), index)
    }
}

// ── Capability tag ────────────────────────────────────────────────────────────

/// Discriminant identifying the type of kernel object a capability refers to.
///
/// `Null` means the slot is empty. All other variants correspond to a specific
/// kernel object type with its own rights and operations.
///
/// To add a new type: append a variant here and handle it in `cspace.rs`
/// (`insert_cap`) and the relevant object creation path.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapTag
{
    /// Empty slot — no capability present.
    Null = 0,
    /// Physical memory frame(s).
    Frame = 1,
    /// Virtual address space.
    AddressSpace = 2,
    /// IPC endpoint.
    Endpoint = 3,
    /// Bitmask-based async signal.
    Signal = 4,
    /// Ordered event queue.
    EventQueue = 5,
    /// Hardware interrupt line.
    Interrupt = 6,
    /// Memory-mapped I/O region.
    MmioRegion = 7,
    /// Thread control block.
    Thread = 8,
    /// Capability space.
    CSpace = 9,
    /// Wait set (multi-object poll).
    WaitSet = 10,
    /// x86-64 I/O port range.
    IoPortRange = 11,
    /// Scheduling control authority.
    SchedControl = 12,
    /// SBI forwarding authority (RISC-V only).
    SbiControl = 13,
}

// ── Rights ────────────────────────────────────────────────────────────────────

/// Bitmask of rights attached to a capability slot.
///
/// Rights are type-specific; not every bit is meaningful for every capability
/// type. Rights can only be attenuated (removed) during derivation, never added.
///
/// To add a new right: add a `const` below and handle it in the relevant
/// capability operation. Existing bit assignments must not be renumbered.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(pub u32);

impl Rights
{
    /// No rights.
    pub const NONE: Rights = Rights(0);

    // ── Memory frame / address space ──────────────────────────────────────────
    /// May map frames into an address space.
    pub const MAP: Rights = Rights(1 << 0);
    /// Authority to create writable mappings from this frame.
    pub const WRITE: Rights = Rights(1 << 1);
    /// Authority to create executable mappings from this frame.
    pub const EXECUTE: Rights = Rights(1 << 2);
    /// May read/inspect mappings (`AddressSpace`).
    pub const READ: Rights = Rights(1 << 3);

    // ── IPC endpoint ──────────────────────────────────────────────────────────
    /// May call (send to) this endpoint.
    pub const SEND: Rights = Rights(1 << 4);
    /// May receive calls on this endpoint.
    pub const RECEIVE: Rights = Rights(1 << 5);
    /// May include capabilities in IPC messages.
    pub const GRANT: Rights = Rights(1 << 6);

    // ── Signal / event queue ──────────────────────────────────────────────────
    /// May deliver a signal notification.
    pub const SIGNAL: Rights = Rights(1 << 7);
    /// May wait on a signal or wait set.
    pub const WAIT: Rights = Rights(1 << 8);
    /// May post an entry to an event queue.
    pub const POST: Rights = Rights(1 << 9);
    /// May receive entries from an event queue.
    pub const RECV: Rights = Rights(1 << 10);

    // ── Thread ────────────────────────────────────────────────────────────────
    /// May start, stop, and configure a thread.
    pub const CONTROL: Rights = Rights(1 << 11);
    /// May read thread register state.
    pub const OBSERVE: Rights = Rights(1 << 12);

    // ── CSpace ────────────────────────────────────────────────────────────────
    /// May insert a capability into a slot.
    pub const INSERT: Rights = Rights(1 << 13);
    /// May clear a slot.
    pub const DELETE: Rights = Rights(1 << 14);
    /// May derive a new capability from an existing slot.
    pub const DERIVE: Rights = Rights(1 << 15);
    /// May revoke a capability and all its descendants.
    pub const REVOKE: Rights = Rights(1 << 16);

    // ── WaitSet ───────────────────────────────────────────────────────────────
    /// May add or remove wait set members.
    pub const MODIFY: Rights = Rights(1 << 17);

    // ── IoPortRange ───────────────────────────────────────────────────────────
    /// May bind port range to a thread for in/out access.
    pub const USE: Rights = Rights(1 << 18);

    // ── SchedControl ──────────────────────────────────────────────────────────
    /// May set thread priorities in the elevated range.
    pub const ELEVATE: Rights = Rights(1 << 19);

    // ── SbiControl ───────────────────────────────────────────────────────────
    /// May forward SBI calls to M-mode firmware (RISC-V only).
    pub const CALL: Rights = Rights(1 << 20);

    // ── Frame retype ──────────────────────────────────────────────────────────
    /// Authority to retype this Frame's memory into kernel objects.
    ///
    /// Stamped on RAM Frame caps minted from the buddy allocator at boot.
    /// Firmware-table / boot-module / init-segment Frame caps never hold this
    /// bit. Every retype-consuming syscall checks
    /// `tag == Frame && rights.contains(RETYPE)`.
    pub const RETYPE: Rights = Rights(1 << 21);

    /// Return `true` if all bits in `mask` are present in `self`.
    pub fn contains(self, mask: Rights) -> bool
    {
        (self.0 & mask.0) == mask.0
    }
}

impl core::ops::BitOr for Rights
{
    type Output = Rights;

    fn bitor(self, rhs: Rights) -> Rights
    {
        Rights(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Rights
{
    type Output = Rights;

    fn bitand(self, rhs: Rights) -> Rights
    {
        Rights(self.0 & rhs.0)
    }
}

impl core::ops::BitOrAssign for Rights
{
    fn bitor_assign(&mut self, rhs: Rights)
    {
        self.0 |= rhs.0;
    }
}

/// Return `true` if `rights` has both `WRITE` and `EXECUTE` set.
///
/// Used to enforce W^X at mapping time: no page may be simultaneously
/// writable and executable. A capability may carry both WRITE and EXECUTE
/// rights (representing independent authorities); this check applies when
/// those rights are exercised on a specific mapping.
#[cfg(test)]
pub fn violates_wx(rights: Rights) -> bool
{
    rights.contains(Rights::WRITE | Rights::EXECUTE)
}

// ── CapabilitySlot ────────────────────────────────────────────────────────────

/// A single capability slot in a `CSpace` page.
///
/// Fixed at 72 bytes (`#[repr(C)]`). Slot 0 in every `CSpace` is permanently
/// null. Non-null slots hold a typed reference to a kernel object and an
/// associated rights bitmask.
///
/// ## Layout (72 bytes)
///
/// ```text
///  offset  size  field
///       0     1  tag
///       1     3  pad   (aligns rights to offset 4)
///       4     4  rights
///       8     8  badge  (caller-identifying label; 0 = unbadged)
///      16     8  object (naturally 8-byte aligned at offset 16)
///      24    12  deriv_parent   (next_free index when tag == Null)
///      36    12  deriv_first_child
///      48    12  deriv_next_sibling
///      60    12  deriv_prev_sibling
/// total: 72 bytes
/// ```
///
/// Each `Option<SlotId>` derivation pointer is 12 bytes (3 × u32, niche on
/// `index: NonZeroU32`). Without explicit `pad`, `#[repr(C)]` would insert 2
/// bytes before `rights` (to satisfy 4-byte alignment) and 6 bytes before
/// `badge` (8-byte alignment); the 3-byte pad absorbs both gaps. The struct
/// alignment is 8 (from `badge` and `object`); 72 is already a multiple of 8
/// so no trailing pad is required.
#[repr(C)]
pub struct CapabilitySlot
{
    /// Capability type; `Null` means the slot is empty.
    pub tag: CapTag,
    /// Explicit padding: aligns `rights` to offset 4 and `badge` to offset 8.
    pad: [u8; 3],
    /// Rights bitmask (type-specific).
    pub rights: Rights,
    /// Caller-identifying badge, set via `SYS_CAP_DERIVE_BADGE`. Zero means
    /// unbadged. Immutable once set — re-badging a capability that already
    /// has a non-zero badge returns an error. Inherited by derivation and copy.
    /// For endpoint caps, the kernel delivers the badge to the receiver on
    /// `ipc_recv`.
    pub badge: u64,
    /// Pointer to the kernel object (None when tag == Null).
    pub object: Option<NonNull<KernelObjectHeader>>,
    /// Derivation parent, or next-free index when tag == Null.
    pub deriv_parent: Option<SlotId>,
    /// First child in the derivation tree (None if leaf).
    pub deriv_first_child: Option<SlotId>,
    /// Next sibling in the derivation tree.
    pub deriv_next_sibling: Option<SlotId>,
    /// Previous sibling in the derivation tree.
    pub deriv_prev_sibling: Option<SlotId>,
}

// SAFETY: CapabilitySlot holds NonNull pointers to kernel objects. During boot
// the kernel is single-threaded; after SMP, CSpace access is protected by the
// CSpace lock. Marking Send+Sync enables use in statics.
unsafe impl Send for CapabilitySlot {}
// SAFETY: CapabilitySlot is accessed only under CSpace lock; no Sync violation.
unsafe impl Sync for CapabilitySlot {}

impl CapabilitySlot
{
    /// Construct a canonical null (empty) slot.
    pub fn null() -> Self
    {
        Self {
            tag: CapTag::Null,
            pad: [0; 3],
            rights: Rights::NONE,
            badge: 0,
            object: None,
            deriv_parent: None,
            deriv_first_child: None,
            deriv_next_sibling: None,
            deriv_prev_sibling: None,
        }
    }

    /// Return `true` if this slot holds no capability.
    pub fn is_null(&self) -> bool
    {
        self.tag == CapTag::Null
    }

    /// Reset all fields to the null state.
    pub fn clear(&mut self)
    {
        *self = Self::null();
    }

    // ── Intrusive free-list helpers ───────────────────────────────────────────

    /// Encode the next-free-list successor index in `deriv_parent`.
    ///
    /// Sets tag to Null and stores `next` in `deriv_parent` (None = end of
    /// list). Only call when placing a slot on the free list; `deriv_parent`
    /// has a different meaning on occupied slots.
    ///
    /// The free list never contains slot 0 (it is permanently null), so the
    /// non-zero invariant is encoded in the argument type.
    ///
    /// `cspace_id` and `epoch` in the encoded `SlotId` are sentinel zeros —
    /// the free-list reader only consults `index`. A live derivation link is
    /// always stamped with the registry's non-zero epoch, so `epoch == 0`
    /// unambiguously distinguishes the two encodings.
    pub fn set_next_free(&mut self, next: Option<NonZeroU32>)
    {
        self.tag = CapTag::Null;
        self.pad = [0; 3];
        self.rights = Rights::NONE;
        self.badge = 0;
        self.object = None;
        self.deriv_first_child = None;
        self.deriv_next_sibling = None;
        self.deriv_prev_sibling = None;
        self.deriv_parent = next.map(|index| SlotId {
            cspace_id: 0,
            epoch: 0,
            index,
        });
    }

    /// Read the next-free-list successor index from `deriv_parent`.
    ///
    /// Only valid when `tag == Null`. Returns `None` if end of list.
    pub fn next_free(&self) -> Option<NonZeroU32>
    {
        debug_assert!(
            self.tag == CapTag::Null,
            "next_free called on occupied slot"
        );
        self.deriv_parent.map(|s| s.index)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::mem::size_of;

    #[test]
    fn capability_slot_is_72_bytes()
    {
        assert_eq!(size_of::<CapabilitySlot>(), 72);
    }

    #[test]
    fn slot_id_is_12_bytes()
    {
        assert_eq!(size_of::<SlotId>(), 12);
    }

    #[test]
    fn option_slot_id_is_12_bytes()
    {
        // Verifies niche optimization via NonZeroU32 survives the epoch widen.
        assert_eq!(size_of::<Option<SlotId>>(), 12);
    }

    #[test]
    fn cap_tag_discriminants()
    {
        assert_eq!(CapTag::Null as u8, 0);
        assert_eq!(CapTag::Frame as u8, 1);
        assert_eq!(CapTag::SchedControl as u8, 12);
    }

    #[test]
    fn rights_bitwise_or()
    {
        let r = Rights::MAP | Rights::WRITE;
        assert_eq!(r.0, 0b011);
    }

    #[test]
    fn rights_bitwise_and()
    {
        let r = (Rights::MAP | Rights::WRITE) & Rights::WRITE;
        assert_eq!(r, Rights::WRITE);
    }

    #[test]
    fn rights_bitor_assign()
    {
        let mut r = Rights::MAP;
        r |= Rights::WRITE;
        assert!(r.contains(Rights::MAP));
        assert!(r.contains(Rights::WRITE));
    }

    #[test]
    fn rights_contains()
    {
        let r = Rights::MAP | Rights::WRITE;
        assert!(r.contains(Rights::MAP));
        assert!(r.contains(Rights::WRITE));
        assert!(!r.contains(Rights::EXECUTE));
        assert!(r.contains(Rights::MAP | Rights::WRITE));
    }

    #[test]
    fn violates_wx_both_set()
    {
        assert!(violates_wx(Rights::WRITE | Rights::EXECUTE));
    }

    #[test]
    fn violates_wx_only_write()
    {
        assert!(!violates_wx(Rights::WRITE));
    }

    #[test]
    fn violates_wx_only_execute()
    {
        assert!(!violates_wx(Rights::EXECUTE));
    }

    #[test]
    fn null_slot_construction()
    {
        let s = CapabilitySlot::null();
        assert!(s.is_null());
        assert_eq!(s.tag, CapTag::Null);
        assert_eq!(s.rights, Rights::NONE);
        assert!(s.object.is_none());
        assert!(s.deriv_parent.is_none());
    }

    #[test]
    fn free_list_encoding_round_trip()
    {
        let mut s = CapabilitySlot::null();
        let next = NonZeroU32::new(42).unwrap();
        s.set_next_free(Some(next));
        assert_eq!(s.next_free(), Some(next));
        assert_eq!(s.tag, CapTag::Null);
    }

    #[test]
    fn free_list_encoding_none_round_trip()
    {
        let mut s = CapabilitySlot::null();
        s.set_next_free(None);
        assert_eq!(s.next_free(), None);
    }

    #[test]
    fn slot_id_new_nonzero()
    {
        let id = SlotId::new(1, NonZeroU32::new(5).unwrap());
        assert_eq!(id.cspace_id, 1);
        assert_eq!(id.epoch, 0);
        assert_eq!(id.index.get(), 5);
    }

    #[test]
    fn slot_id_with_epoch()
    {
        let id = SlotId::with_epoch(7, 42, NonZeroU32::new(3).unwrap());
        assert_eq!(id.cspace_id, 7);
        assert_eq!(id.epoch, 42);
        assert_eq!(id.index.get(), 3);
    }

    #[test]
    fn rights_retype_bit_position()
    {
        // Bit 21 — must match `RIGHTS_RETYPE` in `abi/syscall/src/lib.rs`
        // and remain disjoint from every other Rights bit (last existing bit
        // is CALL at 20).
        assert_eq!(Rights::RETYPE.0, 1 << 21);
        // Disjoint from all other rights.
        let combined = Rights::MAP
            | Rights::WRITE
            | Rights::EXECUTE
            | Rights::READ
            | Rights::SEND
            | Rights::RECEIVE
            | Rights::GRANT
            | Rights::SIGNAL
            | Rights::WAIT
            | Rights::POST
            | Rights::RECV
            | Rights::CONTROL
            | Rights::OBSERVE
            | Rights::INSERT
            | Rights::DELETE
            | Rights::DERIVE
            | Rights::REVOKE
            | Rights::MODIFY
            | Rights::USE
            | Rights::ELEVATE
            | Rights::CALL;
        assert_eq!((combined & Rights::RETYPE).0, 0);
    }
}
