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
//! - [`attrs`]: the signed attributes a record's signature covers.
//! - [`cert`]: the fixed-layout certificate a root issues to a signing key.
//! - [`store`]: the trust store: anchors, revoked key ids, security floor.
//! - [`verify()`]: the verifier and its policy.

#![no_std]

pub mod attrs;
pub mod cert;
pub mod store;
pub mod trailer;
pub mod verify;

mod wire;

#[cfg(test)]
mod testutil;

pub use attrs::Attributes;
pub use cert::{Certificate, CertificateBody};
pub use store::{Anchor, AnchorSpec, TrustStore};
pub use trailer::{Record, RecordSpec, Records, Signed, encode_trailer, split, trailer_len};
pub use verify::{Expectation, RecordFailure, Refusal, Verified, verify};

/// Length in bytes of a key id: the first 16 bytes of the SHA-512 of a key.
pub const KEY_ID_LEN: usize = 16;

/// A key id ([`KEY_ID_LEN`] bytes).
pub type KeyId = [u8; KEY_ID_LEN];

/// An Ed25519 public key.
pub type PublicKey = [u8; 32];

/// An Ed25519 signature.
pub type Signature = [u8; 64];

/// The key id of an Ed25519 public key: the first [`KEY_ID_LEN`] bytes of
/// its SHA-512.
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

/// The kind of a signed object, which binds a signature to the role its
/// object is loaded in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind
{
    /// The kernel image.
    Kernel = 1,
    /// The bundle entry `init`.
    Init = 2,
    /// Every other bundle entry.
    BootModule = 3,
    /// A service image on the root filesystem.
    Service = 4,
    /// A driver image on the root filesystem.
    Driver = 5,
    /// A program image on the root filesystem.
    Program = 6,
    /// A data file on the root filesystem.
    Data = 7,
}

impl Kind
{
    /// Every kind, in wire order.
    pub const ALL: [Self; 7] = [
        Self::Kernel,
        Self::Init,
        Self::BootModule,
        Self::Service,
        Self::Driver,
        Self::Program,
        Self::Data,
    ];

    /// The kind a wire value names; `None` for a value no kind has.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self>
    {
        match value
        {
            1 => Some(Self::Kernel),
            2 => Some(Self::Init),
            3 => Some(Self::BootModule),
            4 => Some(Self::Service),
            5 => Some(Self::Driver),
            6 => Some(Self::Program),
            7 => Some(Self::Data),
            _ => None,
        }
    }

    /// The kind's bit in a [`KindSet`] and in a usage mask.
    const fn bit(self) -> u8
    {
        1u8.wrapping_shl(self as u32)
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

/// A set of [`Kind`]s: those a key may sign, or those a caller accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct KindSet(u8);

impl KindSet
{
    /// No kind.
    pub const EMPTY: Self = Self(0);

    /// Every kind.
    pub const ALL: Self = Self(0xfe);

    /// The set of the given kinds.
    #[must_use]
    pub const fn of(kinds: &[Kind]) -> Self
    {
        let mut bits = 0u8;
        let mut rest = kinds;
        while let [kind, tail @ ..] = rest
        {
            bits |= kind.bit();
            rest = tail;
        }
        Self(bits)
    }

    /// Whether the set holds `kind`.
    #[must_use]
    pub const fn contains(self, kind: Kind) -> bool
    {
        self.0 & kind.bit() != 0
    }

    /// The kinds both sets hold.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self
    {
        Self(self.0 & other.0)
    }
}

/// A key's usage mask: the kinds it may sign, and whether it may issue
/// certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage
{
    /// The kinds the key may sign.
    pub kinds: KindSet,
    /// Whether the key may issue certificates (`CERTIFY`, bit 31).
    pub certify: bool,
}

impl Usage
{
    /// The `CERTIFY` bit of a wire usage mask.
    pub const CERTIFY_BIT: u32 = 1 << 31;

    /// The usage a wire mask encodes; `None` when a bit other than a kind's
    /// bit or `CERTIFY` is set.
    #[must_use]
    pub fn from_bits(bits: u32) -> Option<Self>
    {
        let kinds = u8::try_from(bits & !Self::CERTIFY_BIT).ok()?;
        if kinds & !KindSet::ALL.0 != 0
        {
            return None;
        }
        Some(Self {
            kinds: KindSet(kinds),
            certify: bits & Self::CERTIFY_BIT != 0,
        })
    }

    /// The wire mask of the usage.
    #[must_use]
    pub fn to_bits(self) -> u32
    {
        let certify = if self.certify { Self::CERTIFY_BIT } else { 0 };
        u32::from(self.kinds.0) | certify
    }
}

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
    /// The footer's version is not 1.
    Version,
    /// `record_count` is 0 or above [`trailer::MAX_RECORDS`].
    RecordCount,
    /// `records_len` is longer than the object less its footer.
    RecordsLength,
    /// The records overrun the record block or leave bytes of it unused.
    RecordBlock,
    /// A record's `record_len` is not 88 + `attrs_len` + 148 ×
    /// `cert_count`.
    RecordLength,
    /// A record's `algorithm` is not 1 (Ed25519).
    Algorithm,
    /// A record's `cert_count` is above 1.
    CertificateCount,
    /// The signed attributes are shorter than their fixed part, longer than
    /// a record holds, or not 96 + `name_len` bytes long.
    AttributesLength,
    /// The signed attributes do not begin with their domain tag.
    AttributesDomain,
    /// The signed `kind` names no [`Kind`].
    Kind,
    /// The signed `arch` names no [`Arch`].
    Arch,
    /// The signed name is empty.
    EmptyName,
    /// A certificate does not begin with its domain tag.
    CertificateDomain,
    /// A certificate's usage has a bit no kind and not `CERTIFY` has.
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
    /// The version is not 1.
    Version,
    /// `anchor_count` is 0.
    NoAnchor,
    /// An anchor's usage has a bit no kind and not `CERTIFY` has.
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
