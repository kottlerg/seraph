// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/lib.rs

//! Codec and verifier of Seraph's signed objects: the signature trailer, the
//! certificate, the trust store, and the verification policy of
//! [docs/signing.md](../../../docs/signing.md).
//!
//! `no_std`, no allocation; its one dependency is `shared/crypto`. Every
//! parser is a total function over an arbitrary byte slice: it reads only
//! inside the slice, never panics, and refuses anything the format does not
//! define, so each is a fuzz entry point as it stands ([`split`],
//! [`TrustStore::parse`], [`Attributes::parse`], [`Certificate::parse`],
//! [`verify`]). The encoders write into a caller's buffer and refuse what
//! the parsers would refuse, so an encoded object always parses.
//!
//! - [`trailer`]: the signed object, `body || records || footer`; [`split`]
//!   parses it, [`encode_trailer`] writes a trailer.
//! - [`composite`]: the composite signature, Ed25519 and ML-DSA-65, that
//!   every record and certificate carries.
//! - [`attrs`]: the signed attributes a record's signature covers.
//! - [`cert`]: the fixed-layout certificate a root issues to a signing key.
//! - [`store`]: the trust store: anchors, revoked key ids, security floor.
//! - [`enrol`]: the trust store enrolled in firmware storage, the change
//!   request that alters it, and its merge with the built-in store.
//! - [`embed`]: the trust store as the bootloader image embeds it.
//! - [`name`]: the canonical form of the name an object is signed under.
//! - [`index`]: the signed index of a configuration directory's files.
//! - [`verify()`]: the verifier and its policy.

#![no_std]

pub mod attrs;
pub mod cert;
pub mod composite;
pub mod embed;
pub mod enrol;
pub mod index;
pub mod name;
pub mod store;
pub mod trailer;
pub mod verify;

mod wire;

#[cfg(test)]
mod testutil;

pub use attrs::Attributes;
pub use cert::{Certificate, CertificateBody};
pub use index::{INDEX_NAME, Index, IndexError};
pub use name::{NAME_MAX, name_is_canonical, name_is_component, name_is_install_path};
pub use store::{Anchor, AnchorSpec, TrustStore};
pub use trailer::{Record, RecordSpec, Records, Signed, encode_trailer, split, trailer_len};
pub use verify::{
    CERTIFICATE_CACHE_LEN, CertificateCache, Expectation, RecordFailure, Refusal, Verified, verify,
    verify_cached,
};

/// Length in bytes of a key id: the first 16 bytes of the SHA-512 of a key.
pub const KEY_ID_LEN: usize = 16;

/// A key id ([`KEY_ID_LEN`] bytes).
pub type KeyId = [u8; KEY_ID_LEN];

/// A composite public key: the Ed25519 public key, then the ML-DSA-65 public
/// key ([`composite`]).
pub type PublicKey = [u8; composite::PUBLIC_KEY_LEN];

/// A composite signature: the Ed25519 signature, then the ML-DSA-65 signature
/// ([`composite`]).
pub type Signature = [u8; composite::SIGNATURE_LEN];

/// The key id of a composite public key: the first [`KEY_ID_LEN`] bytes of
/// the SHA-512 of the whole key, both halves.
#[must_use]
pub fn key_id(key: &PublicKey) -> KeyId
{
    let mut id = [0u8; KEY_ID_LEN];
    for (out, byte) in id.iter_mut().zip(crypto::sha512(key))
    {
        *out = byte;
    }
    id
}

/// A role an object may be loaded in, which a record's role set grants
/// ([docs/signing.md](../../../docs/signing.md) § Signed Attributes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role
{
    /// The kernel image.
    Kernel = 1,
    /// The object of the bundle's `init` slot.
    Init = 2,
    /// An object the bootloader may load as a bundle entry other than
    /// `init` and outside `/config/`.
    BootModule = 3,
    /// A service image.
    Service = 4,
    /// A driver image.
    Driver = 5,
    /// A program image.
    Program = 6,
    /// A data file procmgr verifies for its reader.
    Data = 7,
    /// A policy-bearing configuration file procmgr verifies for its
    /// consumer, or the index of a directory of them; and a bundle entry
    /// under `/config/`, a platform table excepted, which the bootloader
    /// verifies.
    Configuration = 8,
    /// A change request to the trust store enrolled in firmware storage,
    /// which the bootloader applies with no one present
    /// ([`enrol`]).
    Enrolment = 9,
}

impl Role
{
    /// Every role, in bit order.
    pub const ALL: [Self; 9] = [
        Self::Kernel,
        Self::Init,
        Self::BootModule,
        Self::Service,
        Self::Driver,
        Self::Program,
        Self::Data,
        Self::Configuration,
        Self::Enrolment,
    ];

    /// The role's bit in a [`RoleSet`] and in a usage mask.
    const fn bit(self) -> u32
    {
        1u32.wrapping_shl(self as u32)
    }
}

/// The architecture a signed object is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Arch
{
    /// x86-64.
    X86_64 = 1,
    /// riscv64.
    Riscv64 = 2,
}

impl Arch
{
    /// The architecture a wire value names; `None` for a value no
    /// architecture has.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self>
    {
        match value
        {
            1 => Some(Self::X86_64),
            2 => Some(Self::Riscv64),
            _ => None,
        }
    }
}

/// A set of [`Role`]s: those a record grants, those a key may sign, or
/// those a caller accepts. Role `n` is bit `n` of the set's 32 bits, as in a
/// usage mask; bit 0, bit 31 (`CERTIFY` in a usage mask) and every bit no
/// role has are clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RoleSet(u32);

impl RoleSet
{
    /// No role.
    pub const EMPTY: Self = Self(0);

    /// Every role.
    pub const ALL: Self = Self(0x3fe);

    /// The set of the given roles.
    #[must_use]
    pub const fn of(roles: &[Role]) -> Self
    {
        let mut bits = 0u32;
        let mut rest = roles;
        while let [role, tail @ ..] = rest
        {
            bits |= role.bit();
            rest = tail;
        }
        Self(bits)
    }

    /// The set a signed `roles` field encodes; `None` unless it obeys
    /// docs/signing.md § Signed Attributes: no bit outside the roles', at
    /// least one role, and kernel, init or enrolment only alone.
    #[must_use]
    pub const fn from_signed(bits: u32) -> Option<Self>
    {
        let set = Self(bits);
        if set.is_signable() { Some(set) } else { None }
    }

    /// Whether the set may be a record's `roles`: no bit outside the
    /// roles', not empty, and a set holding kernel, init or enrolment holds
    /// no other role.
    #[must_use]
    pub const fn is_signable(self) -> bool
    {
        let slot = Self::of(&[Role::Kernel, Role::Init, Role::Enrolment]).0;
        self.0 & !Self::ALL.0 == 0
            && self.0 != 0
            && (self.0 & slot == 0 || self.0.is_power_of_two())
    }

    /// The set's bits, bit `n` for role `n`.
    #[must_use]
    pub const fn bits(self) -> u32
    {
        self.0
    }

    /// Whether the set holds `role`.
    #[must_use]
    pub const fn contains(self, role: Role) -> bool
    {
        self.0 & role.bit() != 0
    }

    /// Whether every role of the set is in `other`.
    #[must_use]
    pub const fn is_subset(self, other: Self) -> bool
    {
        self.0 & !other.0 == 0
    }

    /// Whether the set and `other` hold a role in common.
    #[must_use]
    pub const fn meets(self, other: Self) -> bool
    {
        self.0 & other.0 != 0
    }

    /// The roles both sets hold.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self
    {
        Self(self.0 & other.0)
    }

    /// The roles either set holds.
    #[must_use]
    pub const fn union(self, other: Self) -> Self
    {
        Self(self.0 | other.0)
    }
}

/// A key's usage mask: the roles it may sign, and whether it may issue
/// certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage
{
    /// The roles the key may sign.
    pub roles: RoleSet,
    /// Whether the key may issue certificates (`CERTIFY`, bit 31).
    pub certify: bool,
}

impl Usage
{
    /// The `CERTIFY` bit of a wire usage mask.
    pub const CERTIFY_BIT: u32 = 1 << 31;

    /// The usage a wire mask encodes; `None` when a bit other than a role's
    /// bit or `CERTIFY` is set.
    #[must_use]
    pub fn from_bits(bits: u32) -> Option<Self>
    {
        let roles = bits & !Self::CERTIFY_BIT;
        if roles & !RoleSet::ALL.0 != 0
        {
            return None;
        }
        Some(Self {
            roles: RoleSet(roles),
            certify: bits & Self::CERTIFY_BIT != 0,
        })
    }

    /// The wire mask of the usage.
    #[must_use]
    pub fn to_bits(self) -> u32
    {
        let certify = if self.certify { Self::CERTIFY_BIT } else { 0 };
        self.roles.0 | certify
    }
}

const _: () = assert!(
    RoleSet::ALL.0 & Usage::CERTIFY_BIT == 0,
    "no role takes the CERTIFY bit"
);

/// Why an encoder refused to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError
{
    /// The output buffer is shorter than the encoding.
    BufferTooSmall,
    /// A length does not fit its field, or the encoding would be longer
    /// than a `usize` holds.
    TooLong,
    /// A trailer would hold no record, or more than
    /// [`trailer::MAX_RECORDS`].
    RecordCount,
    /// A name is empty.
    EmptyName,
    /// A record's role set breaks a rule of [`RoleSet::is_signable`].
    Roles,
    /// A certificate's usage has `CERTIFY`, or its security-version range
    /// is empty.
    Certificate,
    /// A trust store holds no anchor, an anchor's label is empty, longer
    /// than [`store::LABEL_LEN`] or holds a NUL, or the anchors or revoked
    /// key ids are not sorted strictly ascending by key id.
    Store,
    /// A body ends in the trailer magic, so its signed object would parse as
    /// a nested trailer.
    NestedTrailer,
    /// A directory index would not parse (`index::Index::parse`).
    Index,
}

/// Why a signed object, a record, its attributes or its certificate do not
/// parse ([docs/signing.md](../../../docs/signing.md) § Signed Object Format
/// and § Certificate Format).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError
{
    /// The object is shorter than the footer.
    TooShort,
    /// The footer's magic is not `SERAPHSG`.
    Magic,
    /// The footer's version is not 2.
    Version,
    /// `record_count` is 0 or above [`trailer::MAX_RECORDS`].
    RecordCount,
    /// `records_len` is longer than the object less its footer.
    RecordsLength,
    /// The records overrun the record block or leave bytes of it unused.
    RecordBlock,
    /// A record's `record_len` is not 3,397 + `attrs_len` + 5,409 ×
    /// `cert_count`.
    RecordLength,
    /// A record's `algorithm` is not 2 (the composite).
    Algorithm,
    /// A record's `cert_count` is above 1.
    CertificateCount,
    /// The signed attributes are shorter than their fixed part, longer than
    /// a record holds, or not 99 + `name_len` bytes long.
    AttributesLength,
    /// The signed attributes do not begin with their domain tag.
    AttributesDomain,
    /// The signed `roles` is not a set [`RoleSet::from_signed`] accepts.
    Roles,
    /// The signed `arch` names no [`Arch`].
    Arch,
    /// The signed name is empty.
    EmptyName,
    /// A certificate does not begin with its domain tag.
    CertificateDomain,
    /// A certificate's usage has a bit no role and not `CERTIFY` has.
    CertificateUsage,
    /// A certificate's usage has `CERTIFY`.
    CertificateCertify,
    /// A certificate's `max_security_version` is below its
    /// `min_security_version`.
    CertificateRange,
    /// The body ends in the footer magic: the object holds a nested
    /// trailer.
    NestedTrailer,
}

/// Why a trust store does not parse
/// ([docs/signing.md](../../../docs/signing.md) § Trust Store).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError
{
    /// The blob is shorter than its header, or not exactly as long as its
    /// header, anchors and revoked key ids.
    Length,
    /// The magic is not `SRPHTRST`.
    Magic,
    /// The version is not 2.
    Version,
    /// `anchor_count` is 0.
    NoAnchor,
    /// An anchor's usage has a bit no role and not `CERTIFY` has.
    AnchorUsage,
    /// An anchor's flags have a bit other than `LOCAL`.
    AnchorFlags,
    /// An anchor's label is empty, is not UTF-8, or has a nonzero byte after
    /// its first NUL.
    Label,
    /// The anchors are not sorted strictly ascending by key id.
    AnchorOrder,
    /// The revoked key ids are not sorted strictly ascending.
    RevokedOrder,
}
