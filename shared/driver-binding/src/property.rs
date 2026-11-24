// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/driver-binding/src/property.rs

//! The contract of the declaration decoder as one property over any input,
//! [`decl_holds`], which the fuzz target `driver-binding`
//! (`xtask/fuzz/targets`) drives and the replay test of the checked-in
//! inputs under `fuzz/driver-binding/` runs on every `cargo xtask test`;
//! the `proofs` module of `decl.rs` proves its checks of each step of the
//! decode on every input up to their bounds (docs/testing.md § Fuzzing,
//! § Bounded verification). Each check judges a step against a reading of
//! the wire format the module documentation of [`crate::decl`] gives,
//! written apart from the decoder's: the first breach, in the order the
//! decoder documents, and the declaration it builds; and a declaration the
//! decoder takes encodes ([`decl::encode`]) to a descriptor that decodes to
//! it again.

use crate::decl::{
    self, Builder, ClassName, DeclError, Declaration, DriverDecl, Interrupt, InterruptNeed, Match,
    MatchKey, Reset, Text, Tier, VirtioDeviceConfig,
};

/// Check the contract of [`decl::decode`] on `desc`.
///
/// # Panics
///
/// When the decoder breaks its contract on `desc`: a defect of the decoder.
pub fn decl_holds(desc: &[u8])
{
    singleton_bits_hold();
    let decoded = decl::decode(desc);
    assert_eq!(
        decoded,
        decl_walk(desc),
        "a descriptor judged against its walk"
    );
    if let Ok(decoded) = decoded
    {
        round_trip_holds(&decoded);
    }
}

// ── Readings ────────────────────────────────────────────────────────────────

/// Whether `bytes` is a key of at most `max` bytes: 1 or more bytes from
/// `!` to `~`.
fn is_key(bytes: &[u8], max: usize) -> bool
{
    (1..=max).contains(&bytes.len()) && bytes.iter().all(|&byte| (b'!'..=b'~').contains(&byte))
}

/// Whether `bytes` is a class name of at most `max` bytes: 1 or more of
/// `a` to `z`, `0` to `9`, `-` and `_`.
fn is_class(bytes: &[u8], max: usize) -> bool
{
    (1..=max).contains(&bytes.len())
        && bytes
            .iter()
            .all(|&byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

/// The key of field `kind` in `payload`, of at most `N` bytes.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading of the field"
)]
fn key_of<const N: usize>(kind: u8, payload: &[u8]) -> Result<Text<N>, DeclError>
{
    if !is_key(payload, N)
    {
        return Err(DeclError::BadField(kind));
    }
    let key = Text::<N>::key(payload);
    assert!(
        key.is_some_and(|key| key.as_bytes() == payload),
        "a key the rule admits refused"
    );
    key.ok_or(DeclError::BadField(kind))
}

/// The `u16` of `payload` at `at`, little-endian.
fn le16(payload: &[u8], at: usize) -> u16
{
    let byte = |at: usize| payload.get(at).copied().unwrap_or(0);
    u16::from_le_bytes([byte(at), byte(at.saturating_add(1))])
}

/// The 3-byte value of `payload` at `at`, little-endian.
fn le24(payload: &[u8], at: usize) -> u32
{
    let byte = |at: usize| u32::from(payload.get(at).copied().unwrap_or(0));
    byte(at) | (byte(at.saturating_add(1)) << 8) | (byte(at.saturating_add(2)) << 16)
}

/// The kinds of the fields that appear at most once: name, class, then
/// `0x20` to `0x26`.
const SINGLETONS: [u8; 9] = [0x01, 0x02, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26];

/// [`decl::singleton_bit`] gives each field that appears at most once a bit
/// of its own, and every other kind none.
pub(crate) fn singleton_bits_hold()
{
    let mut all = 0u32;
    for kind in SINGLETONS
    {
        let bit = decl::singleton_bit(kind);
        assert!(
            bit.is_some_and(|bit| bit.is_power_of_two() && all & bit == 0),
            "a field that appears once without a bit of its own"
        );
        all |= bit.unwrap_or(0);
    }
    for kind in 0..=u8::MAX
    {
        assert!(
            SINGLETONS.contains(&kind) || decl::singleton_bit(kind).is_none(),
            "a bit for a field that may repeat"
        );
    }
}

// ── The header and the field walk ───────────────────────────────────────────

/// [`decl::fields`] refuses a descriptor past 512 bytes, then one shorter
/// than its 4-byte header or of a reserved word not zero, then a version
/// other than 1, and otherwise gives the bytes after the header, at their
/// place. Returns them.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn fields_holds(desc: &[u8]) -> Result<&[u8], DeclError>
{
    let version = le16(desc, 0);
    let expected = if desc.len() > 512
    {
        Err(DeclError::TooLarge)
    }
    else if desc.len() < 4 || le16(desc, 2) != 0
    {
        Err(DeclError::BadHeader)
    }
    else if version != 1
    {
        Err(DeclError::UnknownVersion(version))
    }
    else
    {
        Ok(desc.get(4..).unwrap_or_default())
    };
    match (decl::fields(desc), expected)
    {
        (Ok(rest), Ok(want)) => assert!(core::ptr::eq(rest, want), "fields cut at another place"),
        (read, expected) => assert_eq!(
            read.err(),
            expected.err(),
            "a header judged against its reading"
        ),
    }
    expected
}

/// [`decl::next_field`] cuts the field at the start of `rest` as its kind
/// byte, its length byte and that many payload bytes, the payload and the
/// bytes after it at their places; none in no bytes; and refuses a field
/// that runs past the end as `Truncated`. Returns the cut.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn next_field_holds(rest: &[u8]) -> Result<Option<decl::Field<'_>>, DeclError>
{
    let expected = match rest
    {
        [] => Ok(None),
        [kind, len, tail @ ..] if usize::from(*len) <= tail.len() =>
        {
            let (payload, after) = tail.split_at(usize::from(*len));
            Ok(Some((*kind, payload, after)))
        }
        _ => Err(DeclError::Truncated),
    };
    match (decl::next_field(rest), expected)
    {
        (Ok(Some((kind, payload, after))), Ok(Some((want_kind, want_payload, want_after)))) =>
        {
            assert!(
                kind == want_kind
                    && core::ptr::eq(payload, want_payload)
                    && core::ptr::eq(after, want_after),
                "a field cut otherwise"
            );
        }
        (read, expected) =>
        {
            assert_eq!(read.err(), expected.err(), "a field judged otherwise");
            assert_eq!(
                read.ok().map(|cut| cut.is_none()),
                expected.ok().map(|cut| cut.is_none())
            );
        }
    }
    expected
}

// ── The step ────────────────────────────────────────────────────────────────

/// What a field does to the declaration, as read.
#[derive(Clone, Copy)]
enum Effect
{
    Match(MatchKey),
    Name(decl::DriverName),
    Class(ClassName),
    InstanceLimit(u16),
    Interrupt(Interrupt),
    Dma,
    DmaWidth(u8),
    PhysAccess,
    Reset(Reset),
    Tier(Tier),
}

/// The match key of match field `kind` (`0x10` to `0x17`) in `payload`.
fn match_reading(kind: u8, payload: &[u8]) -> Result<MatchKey, DeclError>
{
    let bad = Err(DeclError::BadField(kind));
    match kind
    {
        0x10 if payload.len() == 4 => Ok(MatchKey::PciId {
            vendor: le16(payload, 0),
            device: le16(payload, 2),
        }),
        0x11 if payload.len() == 6 => Ok(MatchKey::PciClass {
            code: le24(payload, 0),
            mask: le24(payload, 3),
        }),
        0x12 => key_of(kind, payload).map(MatchKey::AcpiHid),
        0x13 => key_of(kind, payload).map(MatchKey::AcpiCid),
        0x14 if payload.len() == 1 => Ok(MatchKey::Spcr(payload.first().copied().unwrap_or(0))),
        0x15 => key_of(kind, payload).map(MatchKey::Platform),
        0x16 => key_of(kind, payload).map(MatchKey::IommuFamily),
        0x17 if payload.is_empty() => Ok(MatchKey::BootFramebuffer),
        _ => bad,
    }
}

/// The value of field `kind` that appears at most once, in `payload`.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading of the field"
)]
fn singleton_reading(kind: u8, payload: &[u8]) -> Result<Effect, DeclError>
{
    let bad = Err(DeclError::BadField(kind));
    match (kind, payload)
    {
        (0x01, _) => key_of(kind, payload).map(Effect::Name),
        (0x02, _) if is_class(payload, 32) =>
        {
            let class = ClassName::class(payload);
            assert!(
                class.is_some_and(|class| class.as_bytes() == payload),
                "a class name the rule admits refused"
            );
            class.map(Effect::Class).ok_or(DeclError::BadField(kind))
        }
        (0x20, &[_, _]) if le16(payload, 0) != 0 => Ok(Effect::InstanceLimit(le16(payload, 0))),
        (0x21, &[need @ (1 | 2), msi_vectors @ 0..=64]) => Ok(Effect::Interrupt(Interrupt {
            need: if need == 1
            {
                InterruptNeed::Optional
            }
            else
            {
                InterruptNeed::Required
            },
            msi_vectors,
        })),
        (0x22, []) => Ok(Effect::Dma),
        (0x23, []) => Ok(Effect::PhysAccess),
        (0x24, &[1]) => Ok(Effect::Reset(Reset::VirtioStatus {
            device_config: VirtioDeviceConfig::Required,
        })),
        (0x24, &[2]) => Ok(Effect::Reset(Reset::PcieFlr)),
        (0x24, &[3]) => Ok(Effect::Reset(Reset::VirtioStatus {
            device_config: VirtioDeviceConfig::Absent,
        })),
        (0x25, &[0]) => Ok(Effect::Tier(Tier::Auxiliary)),
        (0x25, &[1]) => Ok(Effect::Tier(Tier::Boot)),
        (0x26, &[bits @ 12..=64]) => Ok(Effect::DmaWidth(bits)),
        _ => bad,
    }
}

/// What field `kind` of `payload` does to the declaration `before` holds:
/// a match field's key, refused when its payload is not of its form, then
/// past 16 match fields; a field that appears at most once, refused when
/// one of its kind came before, then when its payload is not of its form;
/// any other kind refused as unknown.
fn field_reading(before: &Builder, kind: u8, payload: &[u8]) -> Result<Effect, DeclError>
{
    if (0x10..=0x17).contains(&kind)
    {
        let key = match_reading(kind, payload)?;
        if before.decl.match_count >= 16
        {
            return Err(DeclError::TooManyMatches);
        }
        return Ok(Effect::Match(key));
    }
    if !SINGLETONS.contains(&kind)
    {
        return Err(DeclError::UnknownKind(kind));
    }
    if decl::singleton_bit(kind).is_some_and(|bit| before.seen & bit != 0)
    {
        return Err(DeclError::Duplicate(kind));
    }
    singleton_reading(kind, payload)
}

/// `before` with `effect` of a field of `kind` applied: a match key in the
/// next slot, or the field's value with its kind marked seen.
fn applied(before: &Builder, kind: u8, effect: Effect) -> Builder
{
    let mut after = before.clone();
    let decl = &mut after.decl;
    if let Effect::Match(key) = effect
    {
        if let Some(slot) = decl.matches.get_mut(decl.match_count)
        {
            *slot = key;
        }
        decl.match_count = decl.match_count.saturating_add(1);
        return after;
    }
    after.seen |= decl::singleton_bit(kind).unwrap_or(0);
    match effect
    {
        Effect::Name(name) =>
        {
            decl.name = name;
            after.name_seen = true;
        }
        Effect::Class(class) => decl.class = Some(class),
        Effect::InstanceLimit(limit) => decl.instance_limit = Some(limit),
        Effect::Interrupt(interrupt) => decl.interrupt = interrupt,
        Effect::Dma => decl.dma = true,
        Effect::DmaWidth(bits) => decl.dma_width = Some(bits),
        Effect::PhysAccess => decl.phys_access = true,
        Effect::Reset(reset) => decl.reset = reset,
        Effect::Tier(tier) => decl.tier = tier,
        Effect::Match(_) =>
        {}
    }
    after
}

/// [`Builder::field`] absorbs field `kind` of `payload` into `builder` as
/// its reading does: the same refusal, or the builder with the field's
/// effect applied and nothing else changed.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn field_holds(builder: &mut Builder, kind: u8, payload: &[u8])
-> Result<(), DeclError>
{
    let before = builder.clone();
    let read = builder.field(kind, payload);
    let expected = field_reading(&before, kind, payload);
    match (read, expected)
    {
        (Ok(()), Ok(effect)) =>
        {
            assert_eq!(
                *builder,
                applied(&before, kind, effect),
                "a field absorbed otherwise"
            );
        }
        (read, expected) => assert_eq!(read.err(), expected.err(), "a field judged otherwise"),
    }
    expected.map(|_| ())
}

/// [`Builder::finish`] refuses a declaration without a name, then one
/// without a match field, then a DMA address width without DMA, and gives
/// any other as it stands.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn finish_holds(builder: Builder) -> Result<DriverDecl, DeclError>
{
    let refusal = if !builder.name_seen
    {
        Some(DeclError::NoName)
    }
    else if builder.decl.match_count == 0
    {
        Some(DeclError::NoMatch)
    }
    else if builder.decl.dma_width.is_some() && !builder.decl.dma
    {
        Some(DeclError::BadField(0x26))
    }
    else
    {
        None
    };
    let decl = builder.decl;
    let finished = builder.finish();
    assert!(
        match (&finished, refusal)
        {
            (Ok(finished), None) => *finished == decl,
            (Err(error), Some(refusal)) => *error == refusal,
            _ => false,
        },
        "a declaration finished otherwise"
    );
    finished
}

/// The walk of a descriptor by the checks above: its header, each field in
/// turn into a builder new as the decoder's, then the finish.
fn decl_walk(desc: &[u8]) -> Result<DriverDecl, DeclError>
{
    let mut rest = fields_holds(desc)?;
    let mut builder = Builder::new();
    while let Some((kind, payload, after)) = next_field_holds(rest)?
    {
        field_holds(&mut builder, kind, payload)?;
        rest = after;
    }
    finish_holds(builder)
}

// ── The round trip ──────────────────────────────────────────────────────────

/// The match entry a driver writes for `key`.
fn source_match(key: &MatchKey) -> Match<'_>
{
    match key
    {
        MatchKey::PciId { vendor, device } => Match::PciId {
            vendor: *vendor,
            device: *device,
        },
        MatchKey::PciClass { code, mask } => Match::PciClass {
            code: *code,
            mask: *mask,
        },
        MatchKey::AcpiHid(id) => Match::AcpiHid(id.as_str()),
        MatchKey::AcpiCid(id) => Match::AcpiCid(id.as_str()),
        MatchKey::Spcr(interface) => Match::Spcr(*interface),
        MatchKey::Platform(key) => Match::Platform(key.as_str()),
        MatchKey::IommuFamily(key) => Match::IommuFamily(key.as_str()),
        MatchKey::BootFramebuffer => Match::BootFramebuffer,
    }
}

/// A declaration the decoder took, written as its driver would write it,
/// encodes to a descriptor that decodes to it again.
fn round_trip_holds(decoded: &DriverDecl)
{
    let mut matches = [Match::BootFramebuffer; decl::MAX_MATCHES];
    for (slot, key) in matches.iter_mut().zip(decoded.matches())
    {
        *slot = source_match(key);
    }
    let source = Declaration {
        name: decoded.name.as_str(),
        class: decoded.class.as_ref().map(ClassName::as_str),
        matches: matches.get(..decoded.matches().len()).unwrap_or_default(),
        instance_limit: decoded.instance_limit,
        interrupt: decoded.interrupt,
        dma: decoded.dma,
        dma_width: decoded.dma_width,
        phys_access: decoded.phys_access,
        reset: decoded.reset,
        tier: decoded.tier,
    };
    let encoded = decl::encode(&source);
    assert_eq!(
        decl::decode(encoded.as_bytes()).as_ref(),
        Ok(decoded),
        "a declaration taken encodes to another"
    );
}
