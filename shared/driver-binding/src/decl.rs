// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/driver-binding/src/decl.rs

//! The driver declaration: its source form ([`Declaration`]), which a driver
//! writes and [`encode`] turns into note bytes at compile time, and its
//! decoded form ([`DriverDecl`]), which devmgr reads ([`decode`]).
//!
//! # Wire format
//!
//! The note descriptor is at most [`MAX_DESC_BYTES`] bytes: a header of the
//! format version ([`DECL_VERSION`], `u16` little-endian) and a reserved
//! `u16` that is zero, then fields, each a kind byte, a length byte, and that
//! many payload bytes, filling the descriptor exactly. Multi-byte integers
//! are little-endian.
//!
//! | Kind | Field | Payload |
//! |---|---|---|
//! | `0x01` | Name | 1 to [`MAX_NAME_BYTES`] key bytes |
//! | `0x02` | Class | 1 to [`MAX_CLASS_BYTES`] class-name bytes |
//! | `0x10` | Match: PCI vendor and device | vendor `u16`, device `u16` |
//! | `0x11` | Match: PCI class under a mask | class code (3 bytes: programming interface, subclass, base class), mask (3 bytes, same order) |
//! | `0x12` | Match: ACPI `_HID` | 1 to [`MAX_ACPI_ID_BYTES`] key bytes |
//! | `0x13` | Match: ACPI `_CID` | 1 to [`MAX_ACPI_ID_BYTES`] key bytes |
//! | `0x14` | Match: SPCR interface type | one byte |
//! | `0x15` | Match: platform key | 1 to [`MAX_PLATFORM_KEY_BYTES`] key bytes |
//! | `0x16` | Match: IOMMU family key | 1 to [`MAX_IOMMU_FAMILY_BYTES`] key bytes |
//! | `0x17` | Match: `boot-framebuffer` | none |
//! | `0x20` | Instance limit | `u16`, at least 1 |
//! | `0x21` | Interrupt need | need (1 optional, 2 required), message-signaled vectors (0 to [`MAX_MSI_VECTORS`]) |
//! | `0x22` | DMA | none |
//! | `0x23` | Physical access | none |
//! | `0x24` | Withdrawal reset | 1 `VirtIO` status, 2 PCI Express Function Level Reset |
//! | `0x25` | Priority tier | 0 auxiliary, 1 boot |
//!
//! Name is required, and at least one and at most [`MAX_MATCHES`] match
//! fields; every other field appears at most once, and an absent one takes
//! its default (no class, no instance limit, no interrupt, no DMA, no
//! physical access, no reset, the auxiliary tier). Key bytes are printable
//! ASCII without a space; a class name is lowercase ASCII letters, digits,
//! `-`, and `_`. A descriptor that breaks any of this is rejected whole
//! ([`DeclError`]).

/// The declaration format this crate encodes and decodes.
pub const DECL_VERSION: u16 = 1;
/// Largest descriptor a declaration may encode to.
pub const MAX_DESC_BYTES: usize = 512;
/// Largest driver name, in bytes.
pub const MAX_NAME_BYTES: usize = 32;
/// Largest device class name, in bytes.
pub const MAX_CLASS_BYTES: usize = 32;
/// Most match entries one declaration carries.
pub const MAX_MATCHES: usize = 16;
/// Largest ACPI `_HID` or `_CID` key, in bytes.
pub const MAX_ACPI_ID_BYTES: usize = 16;
/// Largest platform key, in bytes.
pub const MAX_PLATFORM_KEY_BYTES: usize = 32;
/// Largest IOMMU family key, in bytes.
pub const MAX_IOMMU_FAMILY_BYTES: usize = 8;
/// Most message-signaled vectors a declaration requests.
pub const MAX_MSI_VECTORS: u8 = 64;

/// Bytes of the descriptor header: version and reserved word.
const HEADER_BYTES: usize = 4;

/// Field kinds.
mod kind
{
    pub const NAME: u8 = 0x01;
    pub const CLASS: u8 = 0x02;
    pub const PCI_ID: u8 = 0x10;
    pub const PCI_CLASS: u8 = 0x11;
    pub const ACPI_HID: u8 = 0x12;
    pub const ACPI_CID: u8 = 0x13;
    pub const SPCR: u8 = 0x14;
    pub const PLATFORM: u8 = 0x15;
    pub const IOMMU_FAMILY: u8 = 0x16;
    pub const BOOT_FRAMEBUFFER: u8 = 0x17;
    pub const INSTANCE_LIMIT: u8 = 0x20;
    pub const INTERRUPT: u8 = 0x21;
    pub const DMA: u8 = 0x22;
    pub const PHYS_ACCESS: u8 = 0x23;
    pub const RESET: u8 = 0x24;
    pub const TIER: u8 = 0x25;
}

// ── Bounded text ────────────────────────────────────────────────────────────

/// A name or key of 1 to `N` bytes that passed its field's character rule.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Text<const N: usize>
{
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> Text<N>
{
    /// `bytes` as a key: 1 to `N` printable ASCII bytes without a space.
    #[must_use]
    pub fn key(bytes: &[u8]) -> Option<Self>
    {
        valid_key(bytes, N).then(|| Self::copy(bytes))
    }

    /// `bytes` as a class name: 1 to `N` lowercase ASCII letters, digits,
    /// `-`, and `_`.
    #[must_use]
    pub fn class(bytes: &[u8]) -> Option<Self>
    {
        valid_class(bytes, N).then(|| Self::copy(bytes))
    }

    /// Copy `bytes`, already checked to hold 1 to `N` bytes.
    fn copy(bytes: &[u8]) -> Self
    {
        let mut out = [0u8; N];
        out[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: out,
            // A checked text holds at most `N` bytes, and every `N` this
            // crate uses fits a `u8`.
            len: u8::try_from(bytes.len()).unwrap_or(0),
        }
    }

    /// The text's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        &self.bytes[..usize::from(self.len)]
    }

    /// The text as a string; every byte the character rules admit is ASCII.
    #[must_use]
    pub fn as_str(&self) -> &str
    {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
}

impl<const N: usize> core::fmt::Debug for Text<N>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        f.write_str(self.as_str())
    }
}

/// A driver's name, as its log lines carry it.
pub type DriverName = Text<MAX_NAME_BYTES>;
/// A device class name (docs/driver-binding.md § Device Classes).
pub type ClassName = Text<MAX_CLASS_BYTES>;
/// An ACPI `_HID` or `_CID`.
pub type AcpiId = Text<MAX_ACPI_ID_BYTES>;
/// A platform description key.
pub type PlatformKey = Text<MAX_PLATFORM_KEY_BYTES>;
/// An IOMMU family key (`dmar`, `rimt`).
pub type IommuFamily = Text<MAX_IOMMU_FAMILY_BYTES>;

/// Whether `bytes` is a key of at most `max` bytes: 1 or more printable
/// ASCII bytes without a space.
const fn valid_key(bytes: &[u8], max: usize) -> bool
{
    if bytes.is_empty() || bytes.len() > max
    {
        return false;
    }
    let mut i = 0;
    while i < bytes.len()
    {
        if bytes[i] < 0x21 || bytes[i] > 0x7E
        {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `bytes` is a class name of at most `max` bytes: 1 or more
/// lowercase ASCII letters, digits, `-`, and `_`.
const fn valid_class(bytes: &[u8], max: usize) -> bool
{
    if bytes.is_empty() || bytes.len() > max
    {
        return false;
    }
    let mut i = 0;
    while i < bytes.len()
    {
        let b = bytes[i];
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return false;
        }
        i += 1;
    }
    true
}

// ── Field values ────────────────────────────────────────────────────────────

/// Whether the driver needs an interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptNeed
{
    /// The driver takes no interrupt.
    None,
    /// The driver uses an interrupt when the device has one and polls
    /// otherwise.
    Optional,
    /// The driver cannot run without an interrupt; a device devmgr can give
    /// none is not bound to it.
    Required,
}

/// A declaration's interrupt need and, for a message-signaled capable
/// driver, the vectors it requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupt
{
    pub need: InterruptNeed,
    /// Message-signaled vectors requested, 0 to [`MAX_MSI_VECTORS`]; 0 for a
    /// driver that takes the wired line only. Always 0 with
    /// [`InterruptNeed::None`].
    pub msi_vectors: u8,
}

impl Interrupt
{
    /// No interrupt.
    pub const NONE: Self = Self {
        need: InterruptNeed::None,
        msi_vectors: 0,
    };
    /// An optional wired interrupt.
    pub const OPTIONAL: Self = Self {
        need: InterruptNeed::Optional,
        msi_vectors: 0,
    };
    /// A required wired interrupt.
    pub const REQUIRED: Self = Self {
        need: InterruptNeed::Required,
        msi_vectors: 0,
    };
}

/// How devmgr stops the device when it withdraws the driver, beside the
/// interrupt disable every PCI function gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reset
{
    /// No reset.
    None,
    /// The `VirtIO` `device_status` reset (`VirtIO` 1.2 § 4.1.4.3.2).
    VirtioStatus,
    /// A PCI Express Function Level Reset.
    PcieFlr,
}

/// The priority tier the driver is created at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier
{
    /// `sched_policy::AUX_DRIVER_PRIORITY`.
    Auxiliary,
    /// `sched_policy::BOOT_DRIVER_PRIORITY`; accepted only from a boot-bundle
    /// declaration (docs/driver-binding.md § Declaration Bounds).
    Boot,
}

// ── Source form ─────────────────────────────────────────────────────────────

/// One match entry as a driver writes it.
#[derive(Clone, Copy, Debug)]
pub enum Match<'a>
{
    /// An exact PCI vendor and device ID.
    PciId
    {
        vendor: u16, device: u16
    },
    /// A PCI class code (base class `<< 16 |` subclass `<< 8 |` programming
    /// interface) compared under `mask` (the same layout; set bits are
    /// compared).
    PciClass
    {
        code: u32, mask: u32
    },
    /// An ACPI `_HID`.
    AcpiHid(&'a str),
    /// An ACPI `_CID`.
    AcpiCid(&'a str),
    /// An SPCR interface type.
    Spcr(u8),
    /// A platform description key.
    Platform(&'a str),
    /// An IOMMU family key.
    IommuFamily(&'a str),
    /// The firmware-initialised framebuffer.
    BootFramebuffer,
}

/// A driver's declaration as the driver writes it, for
/// [`driver_declaration!`](crate::driver_declaration).
#[derive(Clone, Copy, Debug)]
pub struct Declaration<'a>
{
    /// The driver's name in log lines.
    pub name: &'a str,
    /// The device class the driver serves; `None` for a driver devmgr
    /// alone calls (the IOMMU driver).
    pub class: Option<&'a str>,
    /// One to [`MAX_MATCHES`] keys of the devices the driver serves.
    pub matches: &'a [Match<'a>],
    /// The most devices of its match the driver is bound to; `None` for
    /// every one.
    pub instance_limit: Option<u16>,
    pub interrupt: Interrupt,
    /// Whether the device performs DMA.
    pub dma: bool,
    /// Whether the driver programs hardware with physical addresses.
    pub phys_access: bool,
    pub reset: Reset,
    pub tier: Tier,
}

// ── Decoded form ────────────────────────────────────────────────────────────

/// One decoded match entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchKey
{
    PciId
    {
        vendor: u16, device: u16
    },
    PciClass
    {
        code: u32, mask: u32
    },
    AcpiHid(AcpiId),
    AcpiCid(AcpiId),
    Spcr(u8),
    Platform(PlatformKey),
    IommuFamily(IommuFamily),
    BootFramebuffer,
}

/// A decoded declaration, every field within its bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverDecl
{
    pub name: DriverName,
    pub class: Option<ClassName>,
    matches: [MatchKey; MAX_MATCHES],
    match_count: usize,
    pub instance_limit: Option<u16>,
    pub interrupt: Interrupt,
    pub dma: bool,
    pub phys_access: bool,
    pub reset: Reset,
    pub tier: Tier,
}

impl DriverDecl
{
    /// The declaration's match entries, one or more.
    #[must_use]
    pub fn matches(&self) -> &[MatchKey]
    {
        &self.matches[..self.match_count]
    }
}

/// Why a descriptor was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclError
{
    /// Longer than [`MAX_DESC_BYTES`].
    TooLarge,
    /// Shorter than its header, or its reserved word is not zero.
    BadHeader,
    /// A format version other than [`DECL_VERSION`].
    UnknownVersion(u16),
    /// A field runs past the descriptor's end.
    Truncated,
    /// A field of a kind this format does not define.
    UnknownKind(u8),
    /// A second field of a kind that appears at most once.
    Duplicate(u8),
    /// A field whose payload has the wrong length, a value outside its range,
    /// or text that breaks its character rule.
    BadField(u8),
    /// More than [`MAX_MATCHES`] match fields.
    TooManyMatches,
    /// No name field.
    NoName,
    /// No match field.
    NoMatch,
}

/// Decode a note descriptor, rejecting it whole on any breach of the format
/// (the module documentation).
///
/// # Errors
/// [`DeclError`] naming the first breach found.
pub fn decode(desc: &[u8]) -> Result<DriverDecl, DeclError>
{
    if desc.len() > MAX_DESC_BYTES
    {
        return Err(DeclError::TooLarge);
    }
    let (Some(version), Some(reserved)) = (desc.get(0..2), desc.get(2..4))
    else
    {
        return Err(DeclError::BadHeader);
    };
    if reserved != [0, 0]
    {
        return Err(DeclError::BadHeader);
    }
    let version = u16::from_le_bytes([version[0], version[1]]);
    if version != DECL_VERSION
    {
        return Err(DeclError::UnknownVersion(version));
    }
    let mut builder = Builder::new();
    let mut at = HEADER_BYTES;
    while at < desc.len()
    {
        let (Some(&kind), Some(&len)) = (desc.get(at), desc.get(at + 1))
        else
        {
            return Err(DeclError::Truncated);
        };
        let start = at + 2;
        let Some(payload) = desc.get(start..start + usize::from(len))
        else
        {
            return Err(DeclError::Truncated);
        };
        builder.field(kind, payload)?;
        at = start + usize::from(len);
    }
    builder.finish()
}

/// A declaration being decoded: which singleton fields were seen, and the
/// values so far.
struct Builder
{
    decl: DriverDecl,
    name_seen: bool,
    /// One bit per singleton field kind seen, indexed by [`singleton_bit`].
    seen: u32,
}

impl Builder
{
    fn new() -> Self
    {
        Self {
            decl: DriverDecl {
                name: DriverName {
                    bytes: [0; MAX_NAME_BYTES],
                    len: 0,
                },
                class: None,
                matches: [MatchKey::BootFramebuffer; MAX_MATCHES],
                match_count: 0,
                instance_limit: None,
                interrupt: Interrupt::NONE,
                dma: false,
                phys_access: false,
                reset: Reset::None,
                tier: Tier::Auxiliary,
            },
            name_seen: false,
            seen: 0,
        }
    }

    /// Absorb one field.
    fn field(&mut self, kind: u8, payload: &[u8]) -> Result<(), DeclError>
    {
        let bad = DeclError::BadField(kind);
        if let Some(key) = match_key(kind, payload)?
        {
            if self.decl.match_count == MAX_MATCHES
            {
                return Err(DeclError::TooManyMatches);
            }
            self.decl.matches[self.decl.match_count] = key;
            self.decl.match_count += 1;
            return Ok(());
        }
        let bit = singleton_bit(kind).ok_or(DeclError::UnknownKind(kind))?;
        if self.seen & bit != 0
        {
            return Err(DeclError::Duplicate(kind));
        }
        self.seen |= bit;
        let d = &mut self.decl;
        match (kind, payload)
        {
            (kind::NAME, _) =>
            {
                d.name = DriverName::key(payload).ok_or(bad)?;
                self.name_seen = true;
            }
            (kind::CLASS, _) => d.class = Some(ClassName::class(payload).ok_or(bad)?),
            (kind::INSTANCE_LIMIT, &[lo, hi]) =>
            {
                let limit = u16::from_le_bytes([lo, hi]);
                if limit == 0
                {
                    return Err(bad);
                }
                d.instance_limit = Some(limit);
            }
            (kind::INTERRUPT, &[need, msi_vectors]) =>
            {
                let need = match need
                {
                    1 => InterruptNeed::Optional,
                    2 => InterruptNeed::Required,
                    _ => return Err(bad),
                };
                if msi_vectors > MAX_MSI_VECTORS
                {
                    return Err(bad);
                }
                d.interrupt = Interrupt { need, msi_vectors };
            }
            (kind::DMA, []) => d.dma = true,
            (kind::PHYS_ACCESS, []) => d.phys_access = true,
            (kind::RESET, &[1]) => d.reset = Reset::VirtioStatus,
            (kind::RESET, &[2]) => d.reset = Reset::PcieFlr,
            (kind::TIER, &[0]) => d.tier = Tier::Auxiliary,
            (kind::TIER, &[1]) => d.tier = Tier::Boot,
            _ => return Err(bad),
        }
        Ok(())
    }

    fn finish(self) -> Result<DriverDecl, DeclError>
    {
        if !self.name_seen
        {
            return Err(DeclError::NoName);
        }
        if self.decl.match_count == 0
        {
            return Err(DeclError::NoMatch);
        }
        Ok(self.decl)
    }
}

/// The bit of singleton field `kind` in [`Builder::seen`]; `None` for a kind
/// that is not a singleton field.
fn singleton_bit(kind: u8) -> Option<u32>
{
    let index = match kind
    {
        kind::NAME => 0,
        kind::CLASS => 1,
        kind::INSTANCE_LIMIT => 2,
        kind::INTERRUPT => 3,
        kind::DMA => 4,
        kind::PHYS_ACCESS => 5,
        kind::RESET => 6,
        kind::TIER => 7,
        _ => return None,
    };
    Some(1 << index)
}

/// Decode a match field: `Ok(None)` for a kind that is not a match kind.
fn match_key(kind: u8, payload: &[u8]) -> Result<Option<MatchKey>, DeclError>
{
    let bad = DeclError::BadField(kind);
    let key = match (kind, payload)
    {
        (kind::PCI_ID, &[v0, v1, d0, d1]) => MatchKey::PciId {
            vendor: u16::from_le_bytes([v0, v1]),
            device: u16::from_le_bytes([d0, d1]),
        },
        (kind::PCI_CLASS, &[c0, c1, c2, m0, m1, m2]) => MatchKey::PciClass {
            code: u32::from_le_bytes([c0, c1, c2, 0]),
            mask: u32::from_le_bytes([m0, m1, m2, 0]),
        },
        (kind::ACPI_HID, _) => MatchKey::AcpiHid(AcpiId::key(payload).ok_or(bad)?),
        (kind::ACPI_CID, _) => MatchKey::AcpiCid(AcpiId::key(payload).ok_or(bad)?),
        (kind::SPCR, &[interface]) => MatchKey::Spcr(interface),
        (kind::PLATFORM, _) => MatchKey::Platform(PlatformKey::key(payload).ok_or(bad)?),
        (kind::IOMMU_FAMILY, _) => MatchKey::IommuFamily(IommuFamily::key(payload).ok_or(bad)?),
        (kind::BOOT_FRAMEBUFFER, []) => MatchKey::BootFramebuffer,
        (
            kind::PCI_ID
            | kind::PCI_CLASS
            | kind::SPCR
            | kind::BOOT_FRAMEBUFFER,
            _,
        ) => return Err(bad),
        _ => return Ok(None),
    };
    Ok(Some(key))
}

// ── Encoder ─────────────────────────────────────────────────────────────────

/// A declaration's encoded descriptor: [`MAX_DESC_BYTES`] of room, of which
/// the first [`len`](Self::len) bytes are the descriptor.
#[derive(Clone, Copy)]
pub struct EncodedDesc
{
    bytes: [u8; MAX_DESC_BYTES],
    len: usize,
}

impl EncodedDesc
{
    /// The descriptor's length, the note's `descsz`.
    #[must_use]
    pub const fn len(&self) -> usize
    {
        self.len
    }

    /// Whether the descriptor is empty; never, as it holds at least its
    /// header.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// The descriptor's length rounded up to the note's 4-byte alignment.
    #[must_use]
    pub const fn padded_len(&self) -> usize
    {
        (self.len + 3) & !3
    }

    /// Byte `i` of the descriptor, 0 past its end.
    #[must_use]
    pub const fn byte(&self, i: usize) -> u8
    {
        if i < self.len { self.bytes[i] } else { 0 }
    }

    /// The descriptor.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        &self.bytes[..self.len]
    }
}

/// Encode `decl` into its note descriptor. A `const fn`, so the
/// [`driver_declaration!`](crate::driver_declaration) macro encodes at
/// compile time, and a declaration that breaks a bound fails the build.
///
/// # Panics
/// When `decl` breaks a bound of the format (the module documentation): an
/// invalid name, class, or key, no or too many match entries, an instance
/// limit of 0, a vector count past [`MAX_MSI_VECTORS`] or with no interrupt
/// need, or more than [`MAX_DESC_BYTES`] encoded. In a `const` context the
/// panic is a compile error.
#[must_use]
pub const fn encode(decl: &Declaration<'_>) -> EncodedDesc
{
    let mut w = Writer {
        out: EncodedDesc {
            bytes: [0; MAX_DESC_BYTES],
            len: 0,
        },
    };
    let version = DECL_VERSION.to_le_bytes();
    w.byte(version[0]);
    w.byte(version[1]);
    w.byte(0);
    w.byte(0);

    let name = decl.name.as_bytes();
    assert!(
        valid_key(name, MAX_NAME_BYTES),
        "driver declaration: invalid name"
    );
    w.field(kind::NAME, name);
    if let Some(class) = decl.class
    {
        let class = class.as_bytes();
        assert!(
            valid_class(class, MAX_CLASS_BYTES),
            "driver declaration: invalid class name"
        );
        w.field(kind::CLASS, class);
    }
    assert!(
        !decl.matches.is_empty() && decl.matches.len() <= MAX_MATCHES,
        "driver declaration: 1 to MAX_MATCHES match entries"
    );
    let mut i = 0;
    while i < decl.matches.len()
    {
        w.match_entry(&decl.matches[i]);
        i += 1;
    }
    if let Some(limit) = decl.instance_limit
    {
        assert!(limit != 0, "driver declaration: an instance limit of 0");
        let b = limit.to_le_bytes();
        w.field(kind::INSTANCE_LIMIT, &b);
    }
    let need = match decl.interrupt.need
    {
        InterruptNeed::None => 0,
        InterruptNeed::Optional => 1,
        InterruptNeed::Required => 2,
    };
    assert!(
        decl.interrupt.msi_vectors <= MAX_MSI_VECTORS && (need != 0 || decl.interrupt.msi_vectors == 0),
        "driver declaration: vectors past MAX_MSI_VECTORS or without an interrupt need"
    );
    if need != 0
    {
        w.field(kind::INTERRUPT, &[need, decl.interrupt.msi_vectors]);
    }
    if decl.dma
    {
        w.field(kind::DMA, &[]);
    }
    if decl.phys_access
    {
        w.field(kind::PHYS_ACCESS, &[]);
    }
    match decl.reset
    {
        Reset::None =>
        {}
        Reset::VirtioStatus => w.field(kind::RESET, &[1]),
        Reset::PcieFlr => w.field(kind::RESET, &[2]),
    }
    if let Tier::Boot = decl.tier
    {
        w.field(kind::TIER, &[1]);
    }
    w.out
}

/// The const encoder's output cursor.
struct Writer
{
    out: EncodedDesc,
}

impl Writer
{
    const fn byte(&mut self, b: u8)
    {
        assert!(
            self.out.len < MAX_DESC_BYTES,
            "driver declaration: encodes to more than MAX_DESC_BYTES"
        );
        self.out.bytes[self.out.len] = b;
        self.out.len += 1;
    }

    /// One field: kind, length, payload. Every payload the encoder writes is
    /// at most [`MAX_PLATFORM_KEY_BYTES`] long, so its length fits the byte.
    // cast_possible_truncation: the length is checked to fit a byte first.
    #[allow(clippy::cast_possible_truncation)]
    const fn field(&mut self, kind: u8, payload: &[u8])
    {
        assert!(payload.len() <= u8::MAX as usize, "driver declaration: field too long");
        self.byte(kind);
        self.byte(payload.len() as u8);
        let mut i = 0;
        while i < payload.len()
        {
            self.byte(payload[i]);
            i += 1;
        }
    }

    /// A key field, its text checked against the key rule.
    const fn key(&mut self, kind: u8, key: &str, max: usize)
    {
        assert!(
            valid_key(key.as_bytes(), max),
            "driver declaration: invalid match key"
        );
        self.field(kind, key.as_bytes());
    }

    const fn match_entry(&mut self, entry: &Match<'_>)
    {
        match *entry
        {
            Match::PciId { vendor, device } =>
            {
                let v = vendor.to_le_bytes();
                let d = device.to_le_bytes();
                self.field(kind::PCI_ID, &[v[0], v[1], d[0], d[1]]);
            }
            Match::PciClass { code, mask } =>
            {
                assert!(
                    code >> 24 == 0 && mask >> 24 == 0,
                    "driver declaration: a PCI class code or mask past 24 bits"
                );
                let c = code.to_le_bytes();
                let m = mask.to_le_bytes();
                self.field(kind::PCI_CLASS, &[c[0], c[1], c[2], m[0], m[1], m[2]]);
            }
            Match::AcpiHid(id) => self.key(kind::ACPI_HID, id, MAX_ACPI_ID_BYTES),
            Match::AcpiCid(id) => self.key(kind::ACPI_CID, id, MAX_ACPI_ID_BYTES),
            Match::Spcr(interface) => self.field(kind::SPCR, &[interface]),
            Match::Platform(key) => self.key(kind::PLATFORM, key, MAX_PLATFORM_KEY_BYTES),
            Match::IommuFamily(key) => self.key(kind::IOMMU_FAMILY, key, MAX_IOMMU_FAMILY_BYTES),
            Match::BootFramebuffer => self.field(kind::BOOT_FRAMEBUFFER, &[]),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const FULL: Declaration<'static> = Declaration {
        name: "virtio-blk",
        class: Some("block"),
        matches: &[
            Match::PciId {
                vendor: 0x1AF4,
                device: 0x1042,
            },
            Match::PciClass {
                code: 0x01_80_00,
                mask: 0xFF_FF_00,
            },
            Match::AcpiHid("PNP0501"),
            Match::AcpiCid("PNP0500"),
            Match::Spcr(0x12),
            Match::Platform("qemu-virt-rtc"),
            Match::IommuFamily("dmar"),
            Match::BootFramebuffer,
        ],
        instance_limit: Some(3),
        interrupt: Interrupt {
            need: InterruptNeed::Required,
            msi_vectors: 4,
        },
        dma: true,
        phys_access: true,
        reset: Reset::PcieFlr,
        tier: Tier::Boot,
    };

    const MINIMAL: Declaration<'static> = Declaration {
        name: "m",
        class: None,
        matches: &[Match::BootFramebuffer],
        instance_limit: None,
        interrupt: Interrupt::NONE,
        dma: false,
        phys_access: false,
        reset: Reset::None,
        tier: Tier::Auxiliary,
    };

    /// The descriptor `FULL` encodes to, built in a `const` as the macro
    /// builds it.
    const FULL_DESC: EncodedDesc = encode(&FULL);

    fn header() -> Vec<u8>
    {
        let mut d = DECL_VERSION.to_le_bytes().to_vec();
        d.extend([0, 0]);
        d
    }

    fn with_fields(fields: &[(u8, &[u8])]) -> Vec<u8>
    {
        let mut d = header();
        for &(kind, payload) in fields
        {
            d.push(kind);
            d.push(u8::try_from(payload.len()).unwrap_or(u8::MAX));
            d.extend_from_slice(payload);
        }
        d
    }

    fn named(fields: &[(u8, &[u8])]) -> Vec<u8>
    {
        let mut all = vec![(kind::NAME, &b"drv"[..]), (kind::BOOT_FRAMEBUFFER, &[][..])];
        all.extend_from_slice(fields);
        with_fields(&all)
    }

    #[test]
    fn every_field_round_trips()
    {
        let d = decode(FULL_DESC.as_bytes()).expect("FULL decodes");
        assert_eq!(d.name.as_str(), "virtio-blk");
        assert_eq!(d.class.map(|c| c.as_bytes().to_vec()), Some(b"block".to_vec()));
        let keys: Vec<MatchKey> = d.matches().to_vec();
        assert_eq!(keys.len(), FULL.matches.len());
        assert_eq!(
            keys[0],
            MatchKey::PciId {
                vendor: 0x1AF4,
                device: 0x1042
            }
        );
        assert_eq!(
            keys[1],
            MatchKey::PciClass {
                code: 0x01_80_00,
                mask: 0xFF_FF_00
            }
        );
        assert!(matches!(keys[2], MatchKey::AcpiHid(id) if id.as_str() == "PNP0501"));
        assert!(matches!(keys[3], MatchKey::AcpiCid(id) if id.as_str() == "PNP0500"));
        assert_eq!(keys[4], MatchKey::Spcr(0x12));
        assert!(matches!(keys[5], MatchKey::Platform(k) if k.as_str() == "qemu-virt-rtc"));
        assert!(matches!(keys[6], MatchKey::IommuFamily(k) if k.as_str() == "dmar"));
        assert_eq!(keys[7], MatchKey::BootFramebuffer);
        assert_eq!(d.instance_limit, Some(3));
        assert_eq!(
            d.interrupt,
            Interrupt {
                need: InterruptNeed::Required,
                msi_vectors: 4
            }
        );
        assert!(d.dma && d.phys_access);
        assert_eq!(d.reset, Reset::PcieFlr);
        assert_eq!(d.tier, Tier::Boot);
    }

    #[test]
    fn absent_fields_take_their_defaults()
    {
        let d = decode(encode(&MINIMAL).as_bytes()).expect("MINIMAL decodes");
        assert_eq!(d.name.as_str(), "m");
        assert_eq!(d.class, None);
        assert_eq!(d.matches(), &[MatchKey::BootFramebuffer]);
        assert_eq!(d.instance_limit, None);
        assert_eq!(d.interrupt, Interrupt::NONE);
        assert!(!d.dma && !d.phys_access);
        assert_eq!(d.reset, Reset::None);
        assert_eq!(d.tier, Tier::Auxiliary);
    }

    #[test]
    fn the_encoding_is_the_documented_wire_format()
    {
        let d = encode(&MINIMAL);
        assert_eq!(
            d.as_bytes(),
            &[1, 0, 0, 0, kind::NAME, 1, b'm', kind::BOOT_FRAMEBUFFER, 0][..]
        );
        assert_eq!(d.padded_len(), 12);
        assert_eq!(d.byte(8), 0);
        assert_eq!(d.byte(100), 0);
    }

    #[test]
    fn a_malformed_header_is_rejected()
    {
        assert_eq!(decode(&[1, 0]), Err(DeclError::BadHeader));
        assert_eq!(decode(&[1, 0, 1, 0]), Err(DeclError::BadHeader));
        assert_eq!(decode(&[2, 0, 0, 0]), Err(DeclError::UnknownVersion(2)));
    }

    #[test]
    fn an_oversized_descriptor_is_rejected()
    {
        let mut d = named(&[]);
        d.resize(MAX_DESC_BYTES + 1, 0);
        assert_eq!(decode(&d), Err(DeclError::TooLarge));
    }

    #[test]
    fn a_field_running_past_the_end_or_trailing_bytes_are_rejected()
    {
        let mut d = named(&[]);
        d.extend([kind::DMA]);
        assert_eq!(decode(&d), Err(DeclError::Truncated));
        let mut d = named(&[]);
        d.extend([kind::CLASS, 5, b'a']);
        assert_eq!(decode(&d), Err(DeclError::Truncated));
    }

    #[test]
    fn an_unknown_kind_is_rejected()
    {
        assert_eq!(
            decode(&named(&[(0x7F, &[])])),
            Err(DeclError::UnknownKind(0x7F))
        );
    }

    #[test]
    fn a_repeated_singleton_is_rejected()
    {
        assert_eq!(
            decode(&named(&[(kind::DMA, &[]), (kind::DMA, &[])])),
            Err(DeclError::Duplicate(kind::DMA))
        );
        assert_eq!(
            decode(&named(&[(kind::NAME, b"again")])),
            Err(DeclError::Duplicate(kind::NAME))
        );
    }

    #[test]
    fn a_field_out_of_its_bound_is_rejected()
    {
        let long = [b'a'; MAX_NAME_BYTES + 1];
        let cases: &[(u8, &[u8])] = &[
            (kind::CLASS, &long),
            (kind::CLASS, b"Block"),
            (kind::CLASS, b""),
            (kind::INSTANCE_LIMIT, &[0, 0]),
            (kind::INSTANCE_LIMIT, &[1]),
            (kind::INTERRUPT, &[0, 0]),
            (kind::INTERRUPT, &[3, 0]),
            (kind::INTERRUPT, &[1, MAX_MSI_VECTORS + 1]),
            (kind::DMA, &[1]),
            (kind::PHYS_ACCESS, &[0]),
            (kind::RESET, &[0]),
            (kind::RESET, &[3]),
            (kind::TIER, &[2]),
            (kind::PCI_ID, &[1, 2, 3]),
            (kind::PCI_CLASS, &[1, 2, 3, 4, 5]),
            (kind::ACPI_HID, b"PNP 0501"),
            (kind::ACPI_CID, &[b'A'; MAX_ACPI_ID_BYTES + 1]),
            (kind::SPCR, &[]),
            (kind::PLATFORM, &[0x80]),
            (kind::IOMMU_FAMILY, b"too-long-family"),
            (kind::BOOT_FRAMEBUFFER, &[0]),
        ];
        for &(kind, payload) in cases
        {
            assert_eq!(
                decode(&named(&[(kind, payload)])),
                Err(DeclError::BadField(kind)),
                "kind {kind:#x} payload {payload:?}"
            );
        }
        assert_eq!(
            decode(&with_fields(&[(kind::NAME, &long), (kind::SPCR, &[1])])),
            Err(DeclError::BadField(kind::NAME))
        );
    }

    #[test]
    fn match_entries_are_bounded()
    {
        let entry = (kind::SPCR, &[1u8][..]);
        let mut fields = vec![(kind::NAME, &b"drv"[..])];
        fields.extend(core::iter::repeat_n(entry, MAX_MATCHES));
        assert!(decode(&with_fields(&fields)).is_ok());
        fields.push(entry);
        assert_eq!(decode(&with_fields(&fields)), Err(DeclError::TooManyMatches));
    }

    #[test]
    fn a_declaration_needs_a_name_and_a_match()
    {
        assert_eq!(
            decode(&with_fields(&[(kind::SPCR, &[1])])),
            Err(DeclError::NoName)
        );
        assert_eq!(
            decode(&with_fields(&[(kind::NAME, b"drv")])),
            Err(DeclError::NoMatch)
        );
    }

    #[test]
    #[should_panic(expected = "invalid class name")]
    fn the_encoder_refuses_an_invalid_class()
    {
        let _ = encode(&Declaration {
            class: Some("Block"),
            ..MINIMAL
        });
    }

    #[test]
    #[should_panic(expected = "match entries")]
    fn the_encoder_refuses_a_declaration_without_a_match()
    {
        let _ = encode(&Declaration {
            matches: &[],
            ..MINIMAL
        });
    }

    #[test]
    #[should_panic(expected = "MAX_DESC_BYTES")]
    fn the_encoder_refuses_a_descriptor_past_its_bound()
    {
        let key = Match::Platform("platform-key-of-thirty-two-bytes");
        let _ = encode(&Declaration {
            matches: &[key; MAX_MATCHES],
            ..MINIMAL
        });
    }

    #[test]
    #[should_panic(expected = "without an interrupt need")]
    fn the_encoder_refuses_vectors_without_a_need()
    {
        let _ = encode(&Declaration {
            interrupt: Interrupt {
                need: InterruptNeed::None,
                msi_vectors: 1,
            },
            ..MINIMAL
        });
    }
}
