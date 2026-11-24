// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/property.rs

//! The contract of the crate's parsers as one property over any input,
//! [`objsig_holds`], which the fuzz target `objsig` (`xtask/fuzz/targets`)
//! drives and the replay test of the checked-in inputs under `fuzz/objsig/`
//! runs on every `cargo xtask test`; the `proofs` modules of the parsers'
//! files prove its checks of each structure on every input up to their bounds
//! (docs/testing.md § Fuzzing, § Bounded verification). Each check judges a
//! parser against a reading of the format at its fixed offsets, written apart
//! from the parser's with the values docs/signing.md gives (§ Signed Object
//! Format, § Signed Attributes, § Certificate Format, § Trust Store): the
//! first rule the input breaks, in the order the parser documents, and every
//! field of what it accepts, each slice at its place in the input.

use core::ptr;

use crate::attrs::Attributes;
use crate::cert::{self, Certificate};
use crate::enrol::{self, EnrolError, EnrolledStore, Lists, TrustRequest};
use crate::store::{self, ANCHOR_LEN, TrustStore};
use crate::trailer::{self, Record, RecordParts};
use crate::{KeyId, ParseError, StoreError, key_id};

/// Check the contract of every parser of the crate on `input`: read as a
/// signed object, as signed attributes, as a certificate (its first 5,409
/// bytes, when it holds them), as a trust store, as an enrolled store and as
/// a trust request.
///
/// # Panics
///
/// When a parser breaks its contract on `input`: a defect of the parser.
pub fn objsig_holds(input: &[u8])
{
    split_holds(input);
    let _ = attributes_holds(input);
    if let Some(bytes) = input.first_chunk::<{ cert::LEN }>()
    {
        let _ = certificate_holds(bytes);
    }
    trust_store_holds(input);
    enrolled_store_holds(input);
    trust_request_holds(input);
}

// ── Readings ────────────────────────────────────────────────────────────────

/// The `N` bytes of `bytes` at `at`, or zeros when they pass its end.
fn bytes_at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N]
{
    bytes
        .get(at..)
        .and_then(<[u8]>::first_chunk::<N>)
        .copied()
        .unwrap_or([0; N])
}

/// The little-endian `u16` of `bytes` at `at`.
fn u16_at(bytes: &[u8], at: usize) -> u16
{
    u16::from_le_bytes(bytes_at(bytes, at))
}

/// The little-endian `u32` of `bytes` at `at`.
fn u32_at(bytes: &[u8], at: usize) -> u32
{
    u32::from_le_bytes(bytes_at(bytes, at))
}

/// The little-endian `u64` of `bytes` at `at`.
fn u64_at(bytes: &[u8], at: usize) -> u64
{
    u64::from_le_bytes(bytes_at(bytes, at))
}

/// The bytes of `bytes` from `from` for `len` bytes, empty when they pass
/// its end.
fn range(bytes: &[u8], from: usize, len: usize) -> &[u8]
{
    bytes
        .get(from..from.saturating_add(len))
        .unwrap_or_default()
}

/// Whether a usage mask holds a bit no role and not `CERTIFY` (bit 31) has:
/// the roles are bits 1 to 9.
const fn usage_is_foreign(bits: u32) -> bool
{
    bits & !(0x3fe | 0x8000_0000) != 0
}

// ── The signed object ───────────────────────────────────────────────────────

/// A footer as read: the body, the record block, and the record count.
type Footer<'a> = (&'a [u8], &'a [u8], u16);

/// The footer of `object`, read at its offsets from the end: `records_len`,
/// `record_count`, `version`, the magic `SERAPHSG`.
fn footer_reading(object: &[u8]) -> Result<Footer<'_>, ParseError>
{
    let Some(at) = object.len().checked_sub(16)
    else
    {
        return Err(ParseError::TooShort);
    };
    let records_len = u32_at(object, at);
    let count = u16_at(object, at.saturating_add(4));
    if bytes_at::<8>(object, at.saturating_add(8)) != *b"SERAPHSG"
    {
        return Err(ParseError::Magic);
    }
    if u16_at(object, at.saturating_add(6)) != 2
    {
        return Err(ParseError::Version);
    }
    if !(1..=8).contains(&count)
    {
        return Err(ParseError::RecordCount);
    }
    let Some(body_len) = usize::try_from(records_len)
        .ok()
        .and_then(|len| at.checked_sub(len))
    else
    {
        return Err(ParseError::RecordsLength);
    };
    Ok((
        range(object, 0, body_len),
        range(object, body_len, at.saturating_sub(body_len)),
        count,
    ))
}

/// [`trailer::parse_footer`] reads the footer of `object` as its reading
/// does: the same refusal, or the body, the block and the count, each slice
/// at its place. Returns the reading.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn footer_holds(object: &[u8]) -> Result<Footer<'_>, ParseError>
{
    let expected = footer_reading(object);
    match (trailer::parse_footer(object), expected)
    {
        (Ok((body, block, count)), Ok((want_body, want_block, want_count))) =>
        {
            assert!(
                ptr::eq(body, want_body) && ptr::eq(block, want_block) && count == want_count,
                "a footer read as another body, block or count"
            );
        }
        (read, expected) =>
        {
            assert_eq!(
                read.err(),
                expected.err(),
                "a footer judged against its reading"
            );
        }
    }
    expected
}

/// The record at the start of `block`, read at its offsets: `record_len`,
/// `algorithm` (2), `cert_count` (0 or 1), `attrs_len` and the signer's key
/// id, then the attributes, the certificate (5,409 bytes each) and the
/// signature (3,373 bytes) filling `record_len`.
fn parts_reading(block: &[u8]) -> Result<(RecordParts<'_>, &[u8]), ParseError>
{
    if block.len() < 24
    {
        return Err(ParseError::RecordBlock);
    }
    let [algorithm, cert_count] = bytes_at(block, 4);
    let attrs_len = usize::from(u16_at(block, 6));
    if algorithm != 2
    {
        return Err(ParseError::Algorithm);
    }
    let cert_len = match cert_count
    {
        0 => 0,
        1 => 5409,
        _ => return Err(ParseError::CertificateCount),
    };
    let len = attrs_len.saturating_add(cert_len).saturating_add(24 + 3373);
    if usize::try_from(u32_at(block, 0)) != Ok(len)
    {
        return Err(ParseError::RecordLength);
    }
    let Some((record, rest)) = block.split_at_checked(len)
    else
    {
        return Err(ParseError::RecordBlock);
    };
    let signature_at = attrs_len.saturating_add(cert_len).saturating_add(24);
    let Some(signature) = record
        .get(signature_at..)
        .and_then(|bytes| <&[u8; 3373]>::try_from(bytes).ok())
    else
    {
        return Err(ParseError::RecordBlock);
    };
    let parts = RecordParts {
        signer_key_id: bytes_at(block, 8),
        signed: range(record, 24, attrs_len),
        certificate: range(record, attrs_len.saturating_add(24), cert_len),
        signature,
    };
    Ok((parts, rest))
}

/// [`trailer::record_parts`] cuts the record at the start of `block` as its
/// reading does: the same refusal, or the same fields, each slice at its
/// place, and the same bytes after it. Returns the reading.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn parts_holds(block: &[u8]) -> Result<(RecordParts<'_>, &[u8]), ParseError>
{
    let expected = parts_reading(block);
    match (trailer::record_parts(block), expected)
    {
        (Ok((parts, rest)), Ok((want, want_rest))) =>
        {
            assert!(
                parts.signer_key_id == want.signer_key_id
                    && ptr::eq(parts.signed, want.signed)
                    && ptr::eq(parts.certificate, want.certificate)
                    && ptr::eq(parts.signature, want.signature)
                    && ptr::eq(rest, want_rest),
                "a record cut into other fields"
            );
        }
        (read, expected) =>
        {
            assert_eq!(
                read.err(),
                expected.err(),
                "a record judged against its reading"
            );
        }
    }
    expected
}

/// [`trailer::record_of`] decodes a record's fields into the record of its
/// attributes as [`attributes_holds`] judges them and its certificate as
/// [`Certificate::parse`] decodes it (which [`certificate_holds`] judges on
/// its own), the attributes' refusal first, and a certificate of neither
/// length refused as `RecordBlock`. Returns the record.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn record_of_holds(parts: RecordParts<'_>) -> Result<Record<'_>, ParseError>
{
    let record = trailer::record_of(parts);
    let attrs = attributes_holds(parts.signed);
    let certificate = if parts.certificate.is_empty()
    {
        Ok(None)
    }
    else
    {
        <&[u8; cert::LEN]>::try_from(parts.certificate)
            .map_err(|_| ParseError::RecordBlock)
            .and_then(Certificate::parse)
            .map(Some)
    };
    match (&record, attrs.and_then(|attrs| Ok((attrs, certificate?))))
    {
        (Ok(record), Ok((attrs, certificate))) =>
        {
            assert!(
                record.signer_key_id == parts.signer_key_id
                    && same_attributes(&record.attrs, &attrs)
                    && ptr::eq(record.signed, parts.signed)
                    && same_certificate(record.certificate, certificate)
                    && ptr::eq(record.signature, parts.signature),
                "a record decoded as other fields"
            );
        }
        (read, expected) =>
        {
            assert_eq!(
                read.as_ref().err(),
                expected.as_ref().err(),
                "a record judged against its fields"
            );
        }
    }
    record
}

/// Whether two attributes are one decode: their fields equal, the name at
/// one place.
fn same_attributes(left: &Attributes<'_>, right: &Attributes<'_>) -> bool
{
    left.body_len == right.body_len
        && left.security_version == right.security_version
        && left.roles == right.roles
        && left.arch == right.arch
        && left.body_hash == right.body_hash
        && ptr::eq(left.name, right.name)
}

/// Whether two certificates, or none, are one decode: their fields equal,
/// each slice at one place.
fn same_certificate(left: Option<Certificate<'_>>, right: Option<Certificate<'_>>) -> bool
{
    match (left, right)
    {
        (None, None) => true,
        (Some(left), Some(right)) =>
        {
            let (one, other) = (&left.body, &right.body);
            ptr::eq(left.as_bytes(), right.as_bytes())
                && ptr::eq(left.signed(), right.signed())
                && ptr::eq(left.signature, right.signature)
                && ptr::eq(one.subject_key, other.subject_key)
                && one.issuer_key_id == other.issuer_key_id
                && one.serial == other.serial
                && one.usage == other.usage
                && one.min_security_version == other.min_security_version
                && one.max_security_version == other.max_security_version
        }
        _ => false,
    }
}

/// [`trailer::close`] refuses exactly bytes of the block past the last
/// record, then a body ending in the magic `SERAPHSG`.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn close_holds(body: &[u8], rest: &[u8]) -> Result<(), ParseError>
{
    let expected = if !rest.is_empty()
    {
        Err(ParseError::RecordBlock)
    }
    else if body.len() >= 8 && bytes_at::<8>(body, body.len().saturating_sub(8)) == *b"SERAPHSG"
    {
        Err(ParseError::NestedTrailer)
    }
    else
    {
        Ok(())
    };
    assert_eq!(
        trailer::close(body, rest),
        expected,
        "a close judged otherwise"
    );
    expected
}

/// The walk of a signed object by the checks above: its footer, each record
/// in turn from the start of the block, then the close.
fn split_walk(object: &[u8]) -> Result<Footer<'_>, ParseError>
{
    let (body, block, count) = footer_holds(object)?;
    let mut cursor = block;
    for _ in 0..count
    {
        let (parts, tail) = parts_holds(cursor)?;
        record_of_holds(parts)?;
        cursor = tail;
    }
    close_holds(body, cursor)?;
    Ok((body, block, count))
}

/// [`trailer::split`] takes exactly the objects whose walk passes, with the
/// walk's body and its records in order, and refuses the others with the
/// walk's first refusal; and the trailer the records encode to is as long as
/// the object less its body.
pub(crate) fn split_holds(object: &[u8])
{
    match (trailer::split(object), split_walk(object))
    {
        (Ok(signed), Ok((body, block, count))) =>
        {
            assert!(
                ptr::eq(signed.body(), body),
                "an object split at another body"
            );
            let mut records = signed.records();
            let mut cursor = block;
            // The trailer's length: the footer's 16 bytes and each record's,
            // as the encoder gives a trailer of that record alone.
            let mut encoded: Result<usize, crate::EncodeError> = Ok(16);
            for _ in 0..count
            {
                let walked = trailer::record_parts(cursor).and_then(|(parts, tail)| {
                    cursor = tail;
                    trailer::record_of(parts)
                });
                let record = records.next();
                assert_eq!(
                    record.ok_or(ParseError::RecordBlock),
                    walked,
                    "a record yielded out of the walk"
                );
                if let Some(record) = record
                {
                    let alone = trailer::trailer_len(&[record.spec()]);
                    encoded =
                        encoded.and_then(|len| Ok(len.saturating_add(alone?.saturating_sub(16))));
                }
            }
            assert!(records.next().is_none(), "a record yielded past the count");
            assert_eq!(
                encoded,
                Ok(object.len().saturating_sub(body.len())),
                "the records encode to a trailer of another length"
            );
        }
        (read, walked) =>
        {
            assert_eq!(
                read.err(),
                walked.err(),
                "an object judged against its walk"
            );
        }
    }
}

// ── Attributes and certificate ──────────────────────────────────────────────

/// Signed attributes as read.
struct AttributesReading<'a>
{
    body_len: u64,
    security_version: u32,
    roles: u32,
    body_hash: [u8; 64],
    arch: u8,
    name: &'a [u8],
}

/// The signed attributes `bytes` fills, read at their offsets: the domain
/// tag `seraph/obj/v3`, `body_len`, `security_version`, `roles`,
/// `body_hash`, `name_len` and `arch`, then the name, 99 to 65,535 bytes in
/// all. A role set holds bits 1 to 9 only, at least one, and kernel (1), init
/// (2) or enrolment (9) only alone; `arch` is 1 or 2.
fn attributes_reading(bytes: &[u8]) -> Result<AttributesReading<'_>, ParseError>
{
    if !(99..=65_535).contains(&bytes.len())
    {
        return Err(ParseError::AttributesLength);
    }
    if bytes_at::<16>(bytes, 0) != *b"seraph/obj/v3\0\0\0"
    {
        return Err(ParseError::AttributesDomain);
    }
    let roles = u32_at(bytes, 28);
    let alone = (1 << 1) | (1 << 2) | (1 << 9);
    if roles & !0x3fe != 0 || roles == 0 || (roles & alone != 0 && roles.count_ones() != 1)
    {
        return Err(ParseError::Roles);
    }
    let [arch] = bytes_at(bytes, 98);
    if !matches!(arch, 1 | 2)
    {
        return Err(ParseError::Arch);
    }
    let name_len = usize::from(u16_at(bytes, 96));
    if name_len == 0
    {
        return Err(ParseError::EmptyName);
    }
    if bytes.len() != name_len.saturating_add(99)
    {
        return Err(ParseError::AttributesLength);
    }
    Ok(AttributesReading {
        body_len: u64_at(bytes, 16),
        security_version: u32_at(bytes, 24),
        roles,
        body_hash: bytes_at(bytes, 32),
        arch,
        name: bytes.get(99..).unwrap_or_default(),
    })
}

/// [`Attributes::parse`] decodes `bytes` as its reading does: the same
/// refusal, or the same fields, the name at its place; and attributes it
/// takes encode to as many bytes. Returns the parse.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn attributes_holds(bytes: &[u8]) -> Result<Attributes<'_>, ParseError>
{
    let parsed = Attributes::parse(bytes);
    match (&parsed, attributes_reading(bytes))
    {
        (Ok(attrs), Ok(want)) =>
        {
            assert!(
                attrs.body_len == want.body_len
                    && attrs.security_version == want.security_version
                    && attrs.roles.bits() == want.roles
                    && attrs.body_hash == want.body_hash
                    && attrs.arch as u8 == want.arch
                    && ptr::eq(attrs.name, want.name),
                "attributes decoded as other fields"
            );
            assert_eq!(
                attrs.encoded_len(),
                Ok(bytes.len()),
                "attributes taken encode to another length"
            );
        }
        (read, expected) =>
        {
            assert_eq!(
                read.as_ref().err(),
                expected.as_ref().err(),
                "attributes judged against their reading"
            );
        }
    }
    parsed
}

/// The refusal of a certificate, read at its offsets: the domain tag
/// `seraph/cert/v2`, a usage of no foreign bit and without `CERTIFY`, and a
/// security-version range `min` (at 2,028) to `max` (at 2,032) not empty.
fn certificate_refusal(bytes: &[u8; cert::LEN]) -> Option<ParseError>
{
    let usage = u32_at(bytes, 2024);
    if bytes_at::<16>(bytes, 0) != *b"seraph/cert/v2\0\0"
    {
        Some(ParseError::CertificateDomain)
    }
    else if usage_is_foreign(usage)
    {
        Some(ParseError::CertificateUsage)
    }
    else if usage & 0x8000_0000 != 0
    {
        Some(ParseError::CertificateCertify)
    }
    else if u32_at(bytes, 2032) < u32_at(bytes, 2028)
    {
        Some(ParseError::CertificateRange)
    }
    else
    {
        None
    }
}

/// [`Certificate::parse`] refuses `bytes` as its reading does, and decodes
/// a certificate it takes as its fields at their offsets: the subject key at
/// 16, the issuer's key id at 2,000, the serial at 2,016, the usage, the
/// range, and the signature after the 2,036 signed bytes, each slice at its
/// place. Returns the parse.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn certificate_holds(bytes: &[u8; cert::LEN]) -> Result<Certificate<'_>, ParseError>
{
    let parsed = Certificate::parse(bytes);
    match (&parsed, certificate_refusal(bytes))
    {
        (Ok(certificate), None) =>
        {
            let body = &certificate.body;
            assert!(
                ptr::eq(body.subject_key.as_slice(), range(bytes, 16, 1984))
                    && body.issuer_key_id == bytes_at::<16>(bytes, 2000)
                    && body.serial == u64_at(bytes, 2016)
                    && body.usage.to_bits() == u32_at(bytes, 2024)
                    && body.min_security_version == u32_at(bytes, 2028)
                    && body.max_security_version == u32_at(bytes, 2032)
                    && ptr::eq(certificate.signature.as_slice(), range(bytes, 2036, 3373))
                    && ptr::eq(certificate.signed().as_slice(), range(bytes, 0, 2036))
                    && ptr::eq(certificate.as_bytes(), bytes),
                "a certificate decoded as other fields"
            );
        }
        (read, refusal) =>
        {
            assert_eq!(
                read.as_ref().err().copied(),
                refusal,
                "a certificate judged against its reading"
            );
        }
    }
    parsed
}

// ── Trust stores ────────────────────────────────────────────────────────────

/// The key id of an anchor's encoding: that of its first 1,984 bytes.
fn anchor_key_id(raw: &[u8; ANCHOR_LEN]) -> KeyId
{
    raw.first_chunk().map_or([0; 16], key_id)
}

/// The label of an anchor's 32-byte field, read from its end: the text
/// before its trailing NUL bytes, which holds no NUL, at least one byte, and
/// is UTF-8.
fn label_reading(field: &[u8]) -> Option<&str>
{
    let end = field
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |at| at.saturating_add(1));
    let text = field.get(..end).unwrap_or_default();
    if text.is_empty() || text.contains(&0)
    {
        return None;
    }
    core::str::from_utf8(text).ok()
}

/// [`store::anchor_parts`] cuts an anchor into its fields where they lie:
/// the key at 0, the usage and flags words at 1,984 and 1,988, the label
/// field at 1,992. Returns the words and the label field.
pub(crate) fn anchor_parts_holds(raw: &[u8; ANCHOR_LEN]) -> (u32, u32, &[u8; 32])
{
    let parts = store::anchor_parts(raw);
    assert!(
        parts.is_some_and(|(key, usage, flags, label)| {
            ptr::eq(key.as_slice(), range(raw, 0, 1984))
                && usage == u32_at(raw, 1984)
                && flags == u32_at(raw, 1988)
                && ptr::eq(label.as_slice(), range(raw, 1992, 32))
        }),
        "an anchor cut elsewhere"
    );
    parts.map_or((0, 0, &[0; 32]), |(_, usage, flags, label)| {
        (usage, flags, label)
    })
}

/// [`store::anchor_checks`] judges an anchor's words and label field, of any
/// length, as a reading of them does: a usage of no foreign bit, flags of no bit but
/// `LOCAL`, then a label in its form; and decodes those it takes as that
/// usage, flag and label, the label in its place.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's step"
)]
pub(crate) fn anchor_checks_holds(usage: u32, flags: u32, field: &[u8]) -> Result<(), StoreError>
{
    let label = label_reading(field);
    let expected = if usage_is_foreign(usage)
    {
        Err(StoreError::AnchorUsage)
    }
    else if flags & !1 != 0
    {
        Err(StoreError::AnchorFlags)
    }
    else if label.is_none()
    {
        Err(StoreError::Label)
    }
    else
    {
        Ok(())
    };
    let checked = store::anchor_checks(usage, flags, field);
    assert_eq!(
        checked.map(|_| ()),
        expected,
        "an anchor's fields judged against their reading"
    );
    if let (Ok((read_usage, local, text)), Some(label)) = (checked, label)
    {
        assert!(
            read_usage.to_bits() == usage && local == (flags == 1) && ptr::eq(text, label),
            "an anchor's fields decoded otherwise"
        );
    }
    expected
}

/// [`store::in_order`] takes `id` exactly when it is above `previous`, or
/// nothing comes before it.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn in_order_holds(previous: Option<KeyId>, id: KeyId) -> Result<KeyId, StoreError>
{
    let expected = if previous.is_none_or(|before| before < id)
    {
        Ok(id)
    }
    else
    {
        Err(StoreError::AnchorOrder)
    };
    assert_eq!(
        store::in_order(previous, id),
        expected,
        "an order judged otherwise"
    );
    expected
}

/// The step of the walk of a store's anchors, as the loops of
/// [`TrustStore::parse`] and `Lists::parse` take it: the anchor's parts,
/// their checks, then the order of `id` after `previous`; returns `id`. And
/// [`store::decode_anchor`] decodes an anchor the step takes as those
/// fields, the key and the label at their places, and refuses one it
/// refuses as the checks do.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn anchor_holds(
    previous: Option<KeyId>,
    raw: &[u8; ANCHOR_LEN],
    id: KeyId,
) -> Result<KeyId, StoreError>
{
    let (usage, flags, field) = anchor_parts_holds(raw);
    let checked = anchor_checks_holds(usage, flags, field);
    let decoded = store::decode_anchor(raw);
    assert_eq!(
        decoded.as_ref().err(),
        checked.as_ref().err(),
        "an anchor decoded against its checks"
    );
    if let (Ok(anchor), Some(label)) = (decoded, label_reading(field))
    {
        assert!(
            ptr::eq(anchor.key.as_slice(), range(raw, 0, 1984)) && ptr::eq(anchor.label, label),
            "an anchor decoded as other fields"
        );
    }
    checked.and_then(|()| in_order_holds(previous, id))
}

/// [`store::ascending`] holds exactly for key ids each below the next.
pub(crate) fn ascending_holds(ids: &[KeyId]) -> bool
{
    let expected = (1..ids.len()).all(|at| ids.get(at.saturating_sub(1)) < ids.get(at));
    assert_eq!(store::ascending(ids), expected, "an order judged otherwise");
    expected
}

/// A store's anchors and revoked key ids, cut out as read.
type Cut<'a> = (&'a [u8], &'a [u8]);

/// The anchors and revoked key ids of a blob whose header is `header` bytes
/// long and holds the anchor count at `counts_at` and the revoked count
/// after it: 2,024 bytes an anchor and 16 a key id, filling the rest of the
/// blob exactly.
fn cut_reading(bytes: &[u8], header: usize, counts_at: usize) -> Option<Cut<'_>>
{
    let anchors = usize::from(u16_at(bytes, counts_at)).saturating_mul(2024);
    let revoked = usize::from(u16_at(bytes, counts_at.saturating_add(2))).saturating_mul(16);
    (bytes.len() == header.saturating_add(anchors).saturating_add(revoked)).then(|| {
        (
            range(bytes, header, anchors),
            range(bytes, header.saturating_add(anchors), revoked),
        )
    })
}

/// [`store::store_layout`] reads a trust store's header as its reading does:
/// at least 18 bytes, the magic `SRPHTRST`, version 2, an anchor, and as long
/// as its counts give; the floor, the anchors and the revoked key ids at
/// their places. Returns the layout.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn store_layout_holds(bytes: &[u8]) -> Result<TrustStore<'_>, StoreError>
{
    let layout = store::store_layout(bytes);
    let expected = if bytes.len() < 18
    {
        Err(StoreError::Length)
    }
    else if bytes_at::<8>(bytes, 0) != *b"SRPHTRST"
    {
        Err(StoreError::Magic)
    }
    else if u16_at(bytes, 8) != 2
    {
        Err(StoreError::Version)
    }
    else if u16_at(bytes, 10) == 0
    {
        Err(StoreError::NoAnchor)
    }
    else
    {
        cut_reading(bytes, 18, 10).ok_or(StoreError::Length)
    };
    match (&layout, expected)
    {
        (Ok(store), Ok((anchors, revoked))) =>
        {
            assert!(
                store.security_floor() == u32_at(bytes, 14)
                    && ptr::eq(store.raw_anchors().as_flattened(), anchors)
                    && ptr::eq(store.revoked().as_flattened(), revoked),
                "a store laid out as other lists"
            );
        }
        (read, expected) =>
        {
            assert_eq!(
                read.as_ref().err(),
                expected.err().as_ref(),
                "a store judged against its reading"
            );
        }
    }
    layout
}

/// The walk of a trust store by the checks above: its layout, each anchor
/// in turn, then the revoked key ids' order.
fn store_walk(bytes: &[u8]) -> Result<TrustStore<'_>, StoreError>
{
    let store = store_layout_holds(bytes)?;
    let mut previous = None;
    for raw in store.raw_anchors()
    {
        previous = Some(anchor_holds(previous, raw, anchor_key_id(raw))?);
    }
    if !ascending_holds(store.revoked())
    {
        return Err(StoreError::RevokedOrder);
    }
    Ok(store)
}

/// [`TrustStore::parse`] takes exactly the stores whose walk passes, as the
/// walk's store, and refuses the others with the walk's refusal; and a store
/// it takes finds each of its anchors by key id and each revoked key id.
pub(crate) fn trust_store_holds(bytes: &[u8])
{
    match (TrustStore::parse(bytes), store_walk(bytes))
    {
        (Ok(store), Ok(walked)) =>
        {
            assert_eq!(store, walked, "a store taken as another");
            for (anchor, raw) in store.anchors().zip(store.raw_anchors())
            {
                assert!(
                    anchor.key_id == anchor_key_id(raw)
                        && store.anchor(&anchor.key_id) == Some(anchor),
                    "an anchor not found by its key id"
                );
            }
            assert_eq!(store.anchors().count(), store.raw_anchors().len());
            for id in store.revoked()
            {
                assert!(store.is_revoked(id), "a revoked key id not found");
            }
        }
        (read, walked) =>
        {
            assert_eq!(read.err(), walked.err(), "a store judged against its walk");
        }
    }
}

/// [`enrol::lists_layout`] reads the header of a blob begun by `magic` as
/// its reading does: at least 14 bytes, the magic, version 1, and as long as
/// its counts give; the anchors and the revoked key ids at their places.
/// Returns the layout.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the parser by design; its Result is the reading it hands the walk's next step"
)]
pub(crate) fn lists_layout_holds(bytes: &[u8], magic: [u8; 8]) -> Result<Lists<'_>, EnrolError>
{
    let layout = enrol::lists_layout(bytes, magic);
    let expected = if bytes.len() < 14
    {
        Err(EnrolError::Length)
    }
    else if bytes_at::<8>(bytes, 0) != magic
    {
        Err(EnrolError::Magic)
    }
    else if u16_at(bytes, 8) != 1
    {
        Err(EnrolError::Version)
    }
    else
    {
        cut_reading(bytes, 14, 10).ok_or(EnrolError::Length)
    };
    match (&layout, expected)
    {
        (Ok(lists), Ok((anchors, revoked))) =>
        {
            assert!(
                ptr::eq(lists.anchors.as_flattened(), anchors)
                    && ptr::eq(lists.revoked.as_flattened(), revoked),
                "a blob laid out as other lists"
            );
        }
        (read, expected) =>
        {
            assert_eq!(
                read.as_ref().err(),
                expected.err().as_ref(),
                "a blob judged against its reading"
            );
        }
    }
    layout
}

/// [`Lists::is_revoked`] holds exactly for a key id among the revoked ones,
/// sorted strictly ascending as a parsed blob holds them.
pub(crate) fn revoked_holds(lists: &Lists<'_>, id: &KeyId) -> bool
{
    let expected = lists.revoked.iter().any(|revoked| revoked == id);
    assert_eq!(
        lists.is_revoked(id),
        expected,
        "a key id judged revoked otherwise"
    );
    expected
}

/// [`enrol::within_bound`] holds exactly for at most 3 anchors and 120
/// revoked key ids.
pub(crate) fn bound_holds(lists: &Lists<'_>) -> bool
{
    let expected = lists.anchors.len() <= 3 && lists.revoked.len() <= 120;
    assert_eq!(
        enrol::within_bound(lists),
        expected,
        "a bound judged otherwise"
    );
    expected
}

/// [`enrol::anchor_error`] maps the refusal of an anchor's step to the
/// blob's: `AnchorOrder` to the blob's own, any other within `Anchor`.
/// Returns the blob's refusal.
pub(crate) fn anchor_error_holds(error: StoreError) -> EnrolError
{
    let expected = match error
    {
        StoreError::AnchorOrder => EnrolError::AnchorOrder,
        StoreError::Length
        | StoreError::Magic
        | StoreError::Version
        | StoreError::NoAnchor
        | StoreError::AnchorUsage
        | StoreError::AnchorFlags
        | StoreError::Label
        | StoreError::RevokedOrder => EnrolError::Anchor(error),
    };
    assert_eq!(
        enrol::anchor_error(error),
        expected,
        "an anchor's refusal mapped otherwise"
    );
    expected
}

/// The walk of a blob of either format by the checks above: its layout, each
/// anchor in turn, the revoked key ids' order, then each anchor against the
/// revoked key ids.
fn lists_walk(bytes: &[u8], magic: [u8; 8]) -> Result<Lists<'_>, EnrolError>
{
    let lists = lists_layout_holds(bytes, magic)?;
    let mut previous = None;
    for raw in lists.anchors
    {
        let step = anchor_holds(previous, raw, anchor_key_id(raw));
        previous = Some(step.map_err(anchor_error_holds)?);
    }
    if !ascending_holds(lists.revoked)
    {
        return Err(EnrolError::RevokedOrder);
    }
    if lists
        .anchors
        .iter()
        .any(|raw| revoked_holds(&lists, &anchor_key_id(raw)))
    {
        return Err(EnrolError::RevokedAnchor);
    }
    Ok(lists)
}

/// A store or request taken holds the walk's revoked key ids, each found,
/// and its anchors, each of its key id.
fn lists_taken_hold<'a>(
    revoked: &[KeyId],
    anchors: impl Iterator<Item = store::Anchor<'a>>,
    walked: &Lists<'_>,
)
{
    assert!(
        ptr::eq(revoked, walked.revoked),
        "other revoked key ids taken"
    );
    let mut count = 0usize;
    for (anchor, raw) in anchors.zip(walked.anchors)
    {
        assert!(
            ptr::eq(anchor.key.as_slice(), range(raw, 0, 1984))
                && anchor.key_id == anchor_key_id(raw),
            "an anchor taken as another"
        );
        count = count.saturating_add(1);
    }
    assert_eq!(
        count,
        walked.anchors.len(),
        "anchors taken as another number"
    );
}

/// [`EnrolledStore::parse`] takes exactly the blobs whose walk passes within
/// the bound, and refuses the others with the walk's refusal, then `Bound`.
pub(crate) fn enrolled_store_holds(bytes: &[u8])
{
    let walked = lists_walk(bytes, *b"SRPHENRL").and_then(|lists| {
        if bound_holds(&lists)
        {
            Ok(lists)
        }
        else
        {
            Err(EnrolError::Bound)
        }
    });
    match (EnrolledStore::parse(bytes), walked)
    {
        (Ok(store), Ok(walked)) =>
        {
            lists_taken_hold(store.revoked(), store.anchors(), &walked);
            for id in store.revoked()
            {
                assert!(store.is_revoked(id), "a revoked key id not found");
            }
        }
        (read, walked) =>
        {
            assert_eq!(
                read.err(),
                walked.err(),
                "an enrolled store judged against its walk"
            );
        }
    }
}

/// [`TrustRequest::parse`] takes exactly the blobs whose walk passes, with
/// no bound, and refuses the others with the walk's refusal.
pub(crate) fn trust_request_holds(bytes: &[u8])
{
    match (TrustRequest::parse(bytes), lists_walk(bytes, *b"SRPHTREQ"))
    {
        (Ok(request), Ok(walked)) =>
        {
            lists_taken_hold(request.revocations(), request.additions(), &walked);
        }
        (read, walked) =>
        {
            assert_eq!(
                read.err(),
                walked.err(),
                "a trust request judged against its walk"
            );
        }
    }
}
