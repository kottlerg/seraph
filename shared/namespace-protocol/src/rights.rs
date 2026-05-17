// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/rights.rs

//! Namespace rights newtype and bit constants.
//!
//! Namespace rights are packed into the high bits of a node-cap token
//! (see [`crate::token`]). They are distinct from kernel capability
//! rights (`RIGHTS_SEND`, `RIGHTS_MAP`, …): a node cap is always a SEND
//! cap from the kernel's perspective, and the namespace rights live
//! entirely in the cap's token bits, inspected only by the server.
//!
//! Bit assignments are defined by the namespace-protocol contract.
//! Servers MUST reject any operation requiring a bit not set in the
//! caller's token; rights MUST NOT be promoted at any operation.

// Under `rustc-dep-of-std` the crate root is `no_core` and the usual
// prelude is not auto-imported into submodules. Mirrors the
// `shared/ipc/src/bootstrap.rs` shape; no-op on regular no_std builds.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Sub};

/// Width of the namespace-rights field within a node-cap token, in bits.
///
/// 24 bits packed at token[40..64]. Eight defined; sixteen reserved
/// for future use (`APPEND`, `TRUNCATE`, `RENAME`, `UNLINK`,
/// `SYMLINK_FOLLOW`, `WATCH`, `SET_TIMES`, `XATTR_GET`, `XATTR_SET`,
/// `LOCK`, identity-related bits, MAC labels, …).
pub const RIGHTS_BITS: u32 = 24;

/// Mask of all bits valid in a [`NamespaceRights`] backing value.
pub const RIGHTS_MASK: u32 = (1 << RIGHTS_BITS) - 1;

/// `NS_LOOKUP` into this directory is permitted.
pub const LOOKUP: u32 = 1 << 0;
/// `NS_READDIR` enumeration of this directory is permitted.
pub const READDIR: u32 = 1 << 1;
/// `NS_STAT` on this node is permitted.
pub const STAT: u32 = 1 << 2;
/// `NS_READ` / `NS_READ_FRAME` on this file is permitted.
pub const READ: u32 = 1 << 3;
/// `FS_WRITE` / `FS_WRITE_FRAME` on this file is permitted.
pub const WRITE: u32 = 1 << 4;
/// File is executable; consumed by ELF loaders to gate spawn.
pub const EXEC: u32 = 1 << 5;
/// `FS_CREATE` / `FS_REMOVE` / `FS_MKDIR` / `FS_RENAME` in this
/// directory are permitted.
pub const MUTATE_DIR: u32 = 1 << 6;
/// Visibility-gating bit: entries whose `visible_requires` includes
/// `ADMIN` are hidden from callers without it (see the visibility
/// rule in `docs/namespace-model.md`).
pub const ADMIN: u32 = 1 << 7;

/// Set of namespace rights packed in a node-cap token.
///
/// 24-bit field; bits beyond [`RIGHTS_BITS`] MUST be zero in any
/// constructed value. The newtype is `Copy` and supports bitwise ops
/// (`&`, `|`, `-`) for composition; `const fn` equivalents
/// ([`Self::intersect`], [`Self::union`], [`Self::difference`]) cover
/// const contexts.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct NamespaceRights(u32);

impl NamespaceRights
{
    /// The empty rights set. A cap with [`Self::NONE`] permits nothing
    /// but exists as a structural value (e.g. derived intermediate).
    pub const NONE: Self = Self(0);
    /// Every defined and reserved bit set. Used by clients that ask for
    /// "everything I am allowed" at lookup; the server intersects with
    /// the parent's rights and the entry's `max_rights` ceiling.
    pub const ALL: Self = Self(RIGHTS_MASK);

    /// Construct from a raw `u32`. Bits beyond [`RIGHTS_BITS`] are
    /// truncated; this matches the wire convention that reserved bits
    /// are ignored on read.
    #[must_use]
    pub const fn from_raw(value: u32) -> Self
    {
        Self(value & RIGHTS_MASK)
    }

    /// Returns the raw `u32` representation. The high
    /// `32 - RIGHTS_BITS` bits are zero.
    #[must_use]
    pub const fn raw(self) -> u32
    {
        self.0
    }

    /// Intersection (`&`). Both caps must permit a bit for it to remain.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self
    {
        Self(self.0 & other.0)
    }

    /// Union (`|`). Either cap permitting a bit makes it permitted.
    #[must_use]
    pub const fn union(self, other: Self) -> Self
    {
        Self(self.0 | other.0)
    }

    /// Set difference (`a - b`): bits set in `self` but not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self
    {
        Self(self.0 & !other.0)
    }

    /// `true` iff every bit in `bits` is set in `self`.
    #[must_use]
    pub const fn contains(self, bits: u32) -> bool
    {
        (self.0 & bits) == bits
    }

    /// `true` iff the rights set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool
    {
        self.0 == 0
    }
}

impl BitAnd for NamespaceRights
{
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self
    {
        self.intersect(rhs)
    }
}

impl BitAndAssign for NamespaceRights
{
    fn bitand_assign(&mut self, rhs: Self)
    {
        self.0 &= rhs.0;
    }
}

impl BitOr for NamespaceRights
{
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self
    {
        self.union(rhs)
    }
}

impl BitOrAssign for NamespaceRights
{
    fn bitor_assign(&mut self, rhs: Self)
    {
        self.0 |= rhs.0;
    }
}

impl Sub for NamespaceRights
{
    type Output = Self;
    fn sub(self, rhs: Self) -> Self
    {
        self.difference(rhs)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn from_raw_truncates_reserved_bits()
    {
        let r = NamespaceRights::from_raw(0xFFFF_FFFF);
        assert_eq!(r.raw(), RIGHTS_MASK);
    }

    #[test]
    fn none_has_no_bits_set()
    {
        assert!(NamespaceRights::NONE.is_empty());
        assert_eq!(NamespaceRights::NONE.raw(), 0);
    }

    #[test]
    fn all_has_every_defined_bit_set()
    {
        let all = NamespaceRights::ALL;
        for bit in [LOOKUP, READDIR, STAT, READ, WRITE, EXEC, MUTATE_DIR, ADMIN]
        {
            assert!(all.contains(bit), "ALL missing bit {bit:#x}");
        }
    }

    #[test]
    fn intersect_keeps_only_common_bits()
    {
        let a = NamespaceRights::from_raw(LOOKUP | READ | STAT);
        let b = NamespaceRights::from_raw(READ | WRITE);
        assert_eq!(a.intersect(b).raw(), READ);
    }

    #[test]
    fn union_keeps_either_caps_bits()
    {
        let a = NamespaceRights::from_raw(LOOKUP);
        let b = NamespaceRights::from_raw(READ);
        assert_eq!(a.union(b).raw(), LOOKUP | READ);
    }

    #[test]
    fn difference_clears_bits_in_other()
    {
        let a = NamespaceRights::from_raw(LOOKUP | READ | STAT);
        let b = NamespaceRights::from_raw(READ);
        assert_eq!(a.difference(b).raw(), LOOKUP | STAT);
    }

    #[test]
    fn contains_returns_false_when_any_bit_missing()
    {
        let r = NamespaceRights::from_raw(LOOKUP | READ);
        assert!(r.contains(LOOKUP));
        assert!(r.contains(LOOKUP | READ));
        assert!(!r.contains(LOOKUP | WRITE));
    }

    #[test]
    fn bitand_operator_matches_intersect_method()
    {
        let a = NamespaceRights::from_raw(LOOKUP | READ);
        let b = NamespaceRights::from_raw(READ | WRITE);
        assert_eq!((a & b).raw(), a.intersect(b).raw());
    }

    #[test]
    fn sub_operator_matches_difference_method()
    {
        let a = NamespaceRights::from_raw(LOOKUP | READ | STAT);
        let b = NamespaceRights::from_raw(STAT);
        assert_eq!((a - b).raw(), a.difference(b).raw());
    }

    #[test]
    fn rights_mask_covers_exactly_the_field_width()
    {
        assert_eq!(RIGHTS_MASK, (1 << RIGHTS_BITS) - 1);
        assert_eq!(RIGHTS_MASK & !RIGHTS_MASK, 0);
        assert_eq!(RIGHTS_MASK.count_ones(), RIGHTS_BITS);
    }
}
