// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/badge.rs

//! Node-cap badge packing.
//!
//! A node cap is a badged SEND on a server's namespace endpoint. The
//! kernel does not interpret badge bits; the namespace-protocol contract
//! owns the layout. This module is the single point at which that layout
//! is defined.
//!
//! The layout is specified in `shared/namespace-protocol/README.md`
//! § Badge shape.

// Under `rustc-dep-of-std` the crate root is `no_core` and the usual
// prelude is not auto-imported into submodules. Mirrors the
// `shared/ipc/src/bootstrap.rs` shape; no-op on regular no_std builds.
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use crate::rights::{NamespaceRights, RIGHTS_MASK};

/// Width of the `node_id` field within a node-cap badge, in bits. With the
/// 24 rights bits ([`crate::rights::RIGHTS_BITS`]) it fills the `u64` badge.
pub const NODE_ID_BITS: u32 = 40;

/// Mask of all bits valid in a [`NodeId`] backing value.
pub const NODE_ID_MASK: u64 = (1u64 << NODE_ID_BITS) - 1;

/// Server-private inode identifier carried in the low [`NODE_ID_BITS`]
/// of a node-cap badge.
///
/// `NodeId(0)` is reserved as "the root of this server's namespace" by
/// convention; backends MAY assign it any meaning they wish, but servers
/// conventionally mint root caps at `NodeId::ROOT`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[repr(transparent)]
pub struct NodeId(u64);

impl NodeId
{
    /// The root identifier, conventionally assigned to a backend's
    /// top-level directory.
    pub const ROOT: Self = Self(0);

    /// Construct a `NodeId` from a raw `u64`. Returns `None` if any
    /// bit beyond [`NODE_ID_BITS`] is set.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self>
    {
        if (value & !NODE_ID_MASK) == 0
        {
            Some(Self(value))
        }
        else
        {
            None
        }
    }

    /// Construct a `NodeId` from a raw `u64`, truncating bits beyond
    /// [`NODE_ID_BITS`]. Useful when the caller has already validated
    /// the value, or when reading from a wire format where reserved
    /// bits are by contract zero.
    #[must_use]
    pub const fn from_raw_truncated(value: u64) -> Self
    {
        Self(value & NODE_ID_MASK)
    }

    /// Returns the raw `u64` representation. The high
    /// `64 - NODE_ID_BITS` bits are zero.
    #[must_use]
    pub const fn raw(self) -> u64
    {
        self.0
    }
}

/// Pack `(node_id, rights)` into the node-cap badge's `u64` form.
#[must_use]
pub const fn pack(node_id: NodeId, rights: NamespaceRights) -> u64
{
    node_id.raw() | ((rights.raw() as u64) << NODE_ID_BITS)
}

/// Badge bit marking an **open-instance cap**: bit 8 of the rights field
/// (badge bit 48), the lowest bit [`crate::rights::DEFINED_MASK`] leaves
/// reserved. It is a badge-kind flag, not a right. On a badge that carries
/// it the low [`NODE_ID_BITS`] hold a server-private open identifier, not a
/// [`NodeId`], so [`crate::gate::gate`] and the `NS_*` dispatch refuse it
/// and only [`crate::gate::gate_open`] decodes it
/// (`shared/namespace-protocol/README.md` § Badge shape).
pub const OPEN_INSTANCE: u64 = 1 << (NODE_ID_BITS + 8);

/// Whether `badge` is an open-instance cap's ([`OPEN_INSTANCE`] set).
#[must_use]
pub const fn is_open_instance(badge: u64) -> bool
{
    badge & OPEN_INSTANCE != 0
}

/// Badge bit marking a **session cap**: bit 9 of the rights field (badge bit
/// 49), a badge-kind flag like [`OPEN_INSTANCE`] and not a right. On its own
/// it marks a filesystem session cap, which carries no rights; with
/// [`OPEN_INSTANCE`] it marks an open made in a session. A badge carrying
/// either flag holds a [`KIND_ID_BITS`]-bit server-private identifier, not a
/// [`NodeId`] (`shared/namespace-protocol/README.md` § Badge shape).
pub const SESSION: u64 = 1 << (NODE_ID_BITS + 9);

/// Width of the identifier a session cap, or an open made in a session,
/// carries: the low [`NODE_ID_BITS`] of the badge and the fourteen badge bits
/// above the two kind flags (50..64), which a node cap keeps reserved.
pub const KIND_ID_BITS: u32 = 54;

/// Mask of all bits valid in a [`KIND_ID_BITS`]-bit identifier.
pub const KIND_ID_MASK: u64 = (1u64 << KIND_ID_BITS) - 1;

/// Badge bit of an identifier's bit [`NODE_ID_BITS`]: the first above the
/// two kind flags.
const KIND_ID_HIGH_SHIFT: u32 = NODE_ID_BITS + 10;

/// Whether `badge` carries a badge-kind flag ([`OPEN_INSTANCE`] or
/// [`SESSION`]), so that its low bits are no [`NodeId`].
#[must_use]
pub const fn is_kind_flagged(badge: u64) -> bool
{
    badge & (OPEN_INSTANCE | SESSION) != 0
}

/// Spread a [`KIND_ID_BITS`]-bit identifier over its badge bits.
const fn spread_id(id: u64) -> u64
{
    (id & NODE_ID_MASK) | ((id >> NODE_ID_BITS) << KIND_ID_HIGH_SHIFT)
}

/// Gather the [`KIND_ID_BITS`]-bit identifier from its badge bits.
const fn gather_id(badge: u64) -> u64
{
    (badge & NODE_ID_MASK) | ((badge >> KIND_ID_HIGH_SHIFT) << NODE_ID_BITS)
}

/// Pack `session_id` into a session cap's badge: [`SESSION`] set, no
/// rights. `None` when `session_id` is zero or does not fit
/// [`KIND_ID_BITS`].
#[must_use]
pub const fn pack_session(session_id: u64) -> Option<u64>
{
    if session_id == 0 || (session_id & !KIND_ID_MASK) != 0
    {
        return None;
    }
    Some(spread_id(session_id) | SESSION)
}

/// The session id a session cap's badge carries; `None` for every other
/// badge (a node cap's, or an open's).
#[must_use]
pub const fn session_id(badge: u64) -> Option<u64>
{
    if badge & (SESSION | OPEN_INSTANCE) == SESSION
    {
        Some(gather_id(badge))
    }
    else
    {
        None
    }
}

/// Pack `(open_id, rights)` into the badge of an open made in a session:
/// [`OPEN_INSTANCE`] and [`SESSION`] set. `None` when `open_id` is zero or
/// does not fit [`KIND_ID_BITS`].
#[must_use]
pub const fn pack_session_open(open_id: u64, rights: NamespaceRights) -> Option<u64>
{
    if open_id == 0 || (open_id & !KIND_ID_MASK) != 0
    {
        return None;
    }
    Some(spread_id(open_id) | ((rights.raw() as u64) << NODE_ID_BITS) | OPEN_INSTANCE | SESSION)
}

/// The open an open-instance badge names, by the kind of open it is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum OpenRef
{
    /// An open made without a session ([`pack_open`]), with its
    /// [`NODE_ID_BITS`]-bit id.
    Unpaid(u64),
    /// An open made in a session ([`pack_session_open`]), with its
    /// [`KIND_ID_BITS`]-bit id.
    Session(u64),
}

/// The open an open-instance badge names; `None` when `badge` is not one.
#[must_use]
pub(crate) const fn open_ref(badge: u64) -> Option<OpenRef>
{
    if !is_open_instance(badge)
    {
        None
    }
    else if badge & SESSION != 0
    {
        Some(OpenRef::Session(gather_id(badge)))
    }
    else
    {
        Some(OpenRef::Unpaid(badge & NODE_ID_MASK))
    }
}

/// Pack `(open_id, rights)` into an open-instance cap's badge, with
/// [`OPEN_INSTANCE`] set. `None` when `open_id` is zero or does not fit
/// the low [`NODE_ID_BITS`].
#[must_use]
pub const fn pack_open(open_id: u64, rights: NamespaceRights) -> Option<u64>
{
    if open_id == 0 || (open_id & !NODE_ID_MASK) != 0
    {
        return None;
    }
    Some(open_id | ((rights.raw() as u64) << NODE_ID_BITS) | OPEN_INSTANCE)
}

/// Unpack a node-cap badge into `(node_id, rights)`. `pub(crate)` —
/// external callers go through [`crate::gate::gate`]. Bits beyond the
/// defined fields are masked off.
#[must_use]
pub(crate) const fn unpack(badge: u64) -> (NodeId, NamespaceRights)
{
    let node = NodeId::from_raw_truncated(badge);
    let rights_raw = ((badge >> NODE_ID_BITS) as u32) & RIGHTS_MASK;
    (node, NamespaceRights::from_raw(rights_raw))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::rights::{LOOKUP, READ, STAT};

    #[test]
    fn node_id_new_rejects_values_exceeding_field_width()
    {
        assert!(NodeId::new(NODE_ID_MASK).is_some());
        assert!(NodeId::new(NODE_ID_MASK + 1).is_none());
        assert!(NodeId::new(u64::MAX).is_none());
    }

    #[test]
    fn node_id_from_raw_truncated_clears_high_bits()
    {
        let n = NodeId::from_raw_truncated(u64::MAX);
        assert_eq!(n.raw(), NODE_ID_MASK);
    }

    #[test]
    fn root_node_id_has_raw_value_zero()
    {
        assert_eq!(NodeId::ROOT.raw(), 0);
    }

    #[test]
    fn pack_round_trips_through_unpack()
    {
        let node = NodeId::new(0xABCD_EF12).unwrap();
        let rights = NamespaceRights::from_raw(LOOKUP | READ | STAT);
        let badge = pack(node, rights);
        let (n2, r2) = unpack(badge);
        assert_eq!(n2, node);
        assert_eq!(r2, rights);
    }

    #[test]
    fn pack_places_rights_in_high_bits()
    {
        let badge = pack(NodeId::ROOT, NamespaceRights::from_raw(LOOKUP));
        assert_eq!(badge, u64::from(LOOKUP) << NODE_ID_BITS);
    }

    #[test]
    fn pack_places_node_id_in_low_bits()
    {
        let node = NodeId::new(0x1234_5678).unwrap();
        let badge = pack(node, NamespaceRights::NONE);
        assert_eq!(badge, node.raw());
    }

    #[test]
    fn unpack_strips_reserved_rights_bits()
    {
        // Bits 10..23 of the rights field are reserved: they MUST be
        // zero on derive and are ignored on read, so a badge carrying
        // one (set by a peer that minted it outside this crate) decodes
        // to the defined bits alone and cannot flow into a derived cap.
        let badge = (u64::from(LOOKUP | (1 << 23))) << NODE_ID_BITS;
        let (_, r) = unpack(badge);
        assert_eq!(r, NamespaceRights::from_raw(LOOKUP));
    }

    #[test]
    fn pack_open_sets_the_kind_flag_and_keeps_the_rights()
    {
        let rights = NamespaceRights::from_raw(READ | STAT);
        let badge = pack_open(0x12_3456, rights).expect("fits");
        assert!(is_open_instance(badge));
        assert!(!is_open_instance(pack(
            NodeId::new(0x12_3456).unwrap(),
            rights
        )));
        // The flag is not a right: decoding the field leaves it out.
        let (id, r) = unpack(badge);
        assert_eq!(id.raw(), 0x12_3456);
        assert_eq!(r, rights);
    }

    #[test]
    fn pack_open_refuses_an_identifier_outside_the_field()
    {
        let rights = NamespaceRights::from_raw(READ);
        assert_eq!(pack_open(0, rights), None);
        assert_eq!(pack_open(NODE_ID_MASK + 1, rights), None);
        assert!(pack_open(NODE_ID_MASK, rights).is_some());
    }

    #[test]
    fn a_session_badge_round_trips_its_full_id_and_carries_no_rights()
    {
        for id in [1, NODE_ID_MASK, NODE_ID_MASK + 1, KIND_ID_MASK]
        {
            let badge = pack_session(id).expect("fits");
            assert_eq!(session_id(badge), Some(id));
            assert!(is_kind_flagged(badge));
            assert!(!is_open_instance(badge));
            assert_eq!(open_ref(badge), None);
            assert_eq!(unpack(badge).1, NamespaceRights::NONE);
        }
        assert_eq!(pack_session(0), None);
        assert_eq!(pack_session(KIND_ID_MASK + 1), None);
    }

    #[test]
    fn a_session_open_badge_keeps_its_full_id_and_its_rights()
    {
        let rights = NamespaceRights::ALL;
        for id in [1, NODE_ID_MASK + 1, KIND_ID_MASK]
        {
            let badge = pack_session_open(id, rights).expect("fits");
            assert_eq!(open_ref(badge), Some(OpenRef::Session(id)));
            assert_eq!(session_id(badge), None);
            assert_eq!(unpack(badge).1, rights);
        }
        assert_eq!(pack_session_open(0, rights), None);
        assert_eq!(pack_session_open(KIND_ID_MASK + 1, rights), None);
    }

    #[test]
    fn the_kind_of_an_open_follows_its_session_flag()
    {
        let rights = NamespaceRights::from_raw(READ);
        let unpaid = pack_open(NODE_ID_MASK, rights).expect("fits");
        assert_eq!(open_ref(unpaid), Some(OpenRef::Unpaid(NODE_ID_MASK)));
        assert_eq!(session_id(unpaid), None);
        let node = pack(NodeId::new(5).unwrap(), rights);
        assert!(!is_kind_flagged(node));
        assert_eq!(open_ref(node), None);
        assert_eq!(session_id(node), None);
    }

    #[test]
    fn pack_max_node_id_with_full_rights_round_trips()
    {
        let node = NodeId::new(NODE_ID_MASK).unwrap();
        let rights = NamespaceRights::ALL;
        let (n, r) = unpack(pack(node, rights));
        assert_eq!(n, node);
        assert_eq!(r, rights);
    }
}
