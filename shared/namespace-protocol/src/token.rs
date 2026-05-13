// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/token.rs

//! Node-cap token packing.
//!
//! A node cap is a tokened SEND on a server's namespace endpoint. The
//! kernel does not interpret token bits; the namespace-protocol contract
//! owns the layout. This module is the single point at which that layout
//! is defined.
//!
//! Layout (`u64`, little-endian conceptual):
//!
//! ```text
//! bits  0..40  : node_id (server-private inode identifier; unique
//!                within this server's lifetime)
//! bits 40..64  : rights bits (see [`crate::rights`])
//! ```
//!
//! 40 bits of `node_id` provide ≈ 1.1 trillion distinct nodes per server.
//! 24 bits of rights cover the eight defined namespace rights with
//! sixteen reserved for future expansion.

// Under `rustc-dep-of-std` the crate root is `no_core` and the usual
// prelude is not auto-imported into submodules. Mirrors the
// `shared/ipc/src/bootstrap.rs` shape; no-op on regular no_std builds.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use crate::rights::{NamespaceRights, RIGHTS_MASK};

/// Width of the `node_id` field within a node-cap token, in bits.
pub const NODE_ID_BITS: u32 = 40;

/// Mask of all bits valid in a [`NodeId`] backing value.
pub const NODE_ID_MASK: u64 = (1u64 << NODE_ID_BITS) - 1;

/// Server-private inode identifier carried in the low [`NODE_ID_BITS`]
/// of a node-cap token.
///
/// `NodeId(0)` is reserved as "the root of this server's namespace" by
/// convention; backends MAY assign it any meaning they wish, but the
/// crate emits root caps with token bits 0..40 = 0 by default.
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

/// Pack `(node_id, rights)` into the node-cap token's `u64` form.
#[must_use]
pub const fn pack(node_id: NodeId, rights: NamespaceRights) -> u64
{
    node_id.raw() | ((rights.raw() as u64) << NODE_ID_BITS)
}

/// Unpack a node-cap token into `(node_id, rights)`. `pub(crate)` —
/// external callers go through [`crate::gate::gate`]. Bits beyond the
/// defined fields are masked off.
#[must_use]
pub(crate) const fn unpack(token: u64) -> (NodeId, NamespaceRights)
{
    let node = NodeId::from_raw_truncated(token);
    // Cast is range-safe: `RIGHTS_MASK` (24 bits) fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let rights_raw = ((token >> NODE_ID_BITS) as u32) & RIGHTS_MASK;
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
        let token = pack(node, rights);
        let (n2, r2) = unpack(token);
        assert_eq!(n2, node);
        assert_eq!(r2, rights);
    }

    #[test]
    fn pack_places_rights_in_high_bits()
    {
        let token = pack(NodeId::ROOT, NamespaceRights::from_raw(LOOKUP));
        assert_eq!(token, (LOOKUP as u64) << NODE_ID_BITS);
    }

    #[test]
    fn pack_places_node_id_in_low_bits()
    {
        let node = NodeId::new(0x1234_5678).unwrap();
        let token = pack(node, NamespaceRights::NONE);
        assert_eq!(token, node.raw());
    }

    #[test]
    fn unpack_preserves_reserved_rights_bits()
    {
        // Bits 8..23 of the rights field are reserved for future
        // expansion. Reserved bits set in a packed token MUST round-
        // trip through unpack: future protocol revisions assigning
        // these bits MUST NOT be silently stripped by an older decoder.
        let reserved = NamespaceRights::from_raw(1 << 23);
        let token = pack(NodeId::ROOT, reserved);
        let (_, r) = unpack(token);
        assert_eq!(r, reserved);
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
