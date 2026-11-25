// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/trailer.rs

//! The signed object, `body || records || footer`: [`split`] parses it,
//! [`encode_trailer`] writes the trailer a body is followed by
//! ([docs/signing.md](../../../docs/signing.md) § Signed Object Format).
//!
//! [`split`] is also the parse-only split a consumer of a verified data
//! module takes its body through: it applies every parse check and no
//! signature check.

use crate::attrs::Attributes;
use crate::cert::{self, Certificate};
use crate::composite;
use crate::wire::{Reader, Writer};
use crate::{EncodeError, KeyId, ParseError, Signature};

/// The footer's magic.
pub const MAGIC: [u8; 8] = *b"SERAPHSG";

/// The trailer format's version.
pub const VERSION: u16 = 2;

/// The length of the footer.
pub const FOOTER_LEN: usize = 16;

/// The most records one object carries: a bound on the verifier's work per
/// object.
pub const MAX_RECORDS: u16 = 8;

/// The length of a record's fixed header.
pub const RECORD_HEADER_LEN: usize = 24;

/// The length of a record's signature, a composite signature.
pub const SIGNATURE_LEN: usize = composite::SIGNATURE_LEN;

/// The length of a record with no certificate, less its attributes.
const RECORD_FIXED_LEN: usize = RECORD_HEADER_LEN + SIGNATURE_LEN;

/// The length of a record with a certificate, less its attributes.
const RECORD_CERT_LEN: usize = RECORD_FIXED_LEN + cert::LEN;

/// The `algorithm` of a record: the composite of Ed25519 and ML-DSA-65, the
/// one algorithm a record carries. Value 1, Ed25519 alone, is retired and
/// refused like any other.
pub const ALGORITHM_ED25519_ML_DSA_65: u8 = 2;

/// A decoded record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a>
{
    /// The key id of the key that made [`Self::signature`].
    pub signer_key_id: KeyId,
    /// The decoded signed attributes.
    pub attrs: Attributes<'a>,
    /// The encoded signed attributes: the bytes the signature covers.
    pub signed: &'a [u8],
    /// The signing key's certificate, when the key is not a root.
    pub certificate: Option<Certificate<'a>>,
    /// The composite signature over [`Self::signed`].
    pub signature: &'a Signature,
}

impl<'a> Record<'a>
{
    /// The record as an encoder input, to write it into another trailer.
    #[must_use]
    pub fn spec(&self) -> RecordSpec<'a>
    {
        RecordSpec {
            signer_key_id: self.signer_key_id,
            attrs: self.attrs,
            certificate: self.certificate.map(|certificate| certificate.as_bytes()),
            signature: self.signature,
        }
    }
}

/// A record to encode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordSpec<'a>
{
    /// The key id of the key that made [`Self::signature`].
    pub signer_key_id: KeyId,
    /// The signed attributes.
    pub attrs: Attributes<'a>,
    /// The signing key's encoded certificate, when the key is not a root.
    pub certificate: Option<&'a [u8; cert::LEN]>,
    /// The composite signature over the encoded [`Self::attrs`].
    pub signature: &'a Signature,
}

impl RecordSpec<'_>
{
    /// The record's encoded length, 3,397 + `attrs_len` + 5,409 ×
    /// `cert_count`.
    fn encoded_len(&self) -> Result<usize, EncodeError>
    {
        let fixed = if self.certificate.is_some()
        {
            RECORD_CERT_LEN
        }
        else
        {
            RECORD_FIXED_LEN
        };
        self.attrs
            .encoded_len()?
            .checked_add(fixed)
            .ok_or(EncodeError::TooLong)
    }

    /// Append the record.
    fn write(&self, writer: &mut Writer<'_>) -> Result<(), EncodeError>
    {
        let record_len = u32::try_from(self.encoded_len()?).map_err(|_| EncodeError::TooLong)?;
        let attrs_len =
            u16::try_from(self.attrs.encoded_len()?).map_err(|_| EncodeError::TooLong)?;
        if let Some(certificate) = self.certificate
        {
            Certificate::parse(certificate).map_err(|_| EncodeError::Certificate)?;
        }
        writer.put(&record_len.to_le_bytes())?;
        writer.put(&[
            ALGORITHM_ED25519_ML_DSA_65,
            u8::from(self.certificate.is_some()),
        ])?;
        writer.put(&attrs_len.to_le_bytes())?;
        writer.put(&self.signer_key_id)?;
        self.attrs.write(writer)?;
        if let Some(certificate) = self.certificate
        {
            writer.put(certificate)?;
        }
        writer.put(self.signature)
    }
}

/// A parsed signed object: its body and its checked records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signed<'a>
{
    body: &'a [u8],
    block: &'a [u8],
    count: u16,
}

impl<'a> Signed<'a>
{
    /// The body: the object less its trailer.
    #[must_use]
    pub const fn body(&self) -> &'a [u8]
    {
        self.body
    }

    /// The records, in order.
    #[must_use]
    pub const fn records(&self) -> Records<'a>
    {
        Records {
            rest: self.block,
            remaining: self.count,
        }
    }
}

/// The records of a [`Signed`] object, in order.
#[derive(Clone, Debug)]
pub struct Records<'a>
{
    rest: &'a [u8],
    remaining: u16,
}

impl<'a> Iterator for Records<'a>
{
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Record<'a>>
    {
        self.remaining = self.remaining.checked_sub(1)?;
        // split has parsed every record, so these parses cannot fail; a
        // failure would end the iteration, never yield a record.
        let (parts, rest) = record_parts(self.rest).ok()?;
        let record = record_of(parts).ok()?;
        self.rest = rest;
        Some(record)
    }
}

/// Parse a signed object: the footer, then every record, strictly.
///
/// # Errors
///
/// The [`ParseError`] of the first rule the object breaks: the footer's
/// (`TooShort`, `Magic`, `Version`, `RecordCount`, `RecordsLength`),
/// then each record's in order (`RecordBlock`, `Algorithm`,
/// `CertificateCount`, `RecordLength`, then the errors of
/// [`Attributes::parse`] and [`Certificate::parse`]), `RecordBlock` for
/// bytes of the block no record uses, then `NestedTrailer`.
pub fn split(object: &[u8]) -> Result<Signed<'_>, ParseError>
{
    let (body, block, count) = parse_footer(object)?;
    let mut cursor = block;
    for _ in 0..count
    {
        let (parts, tail) = record_parts(cursor)?;
        record_of(parts)?;
        cursor = tail;
    }
    close(body, cursor)?;
    Ok(Signed { body, block, count })
}

/// Read the footer of `object`: returns the body, the record block and the
/// number of records the footer gives.
///
/// # Errors
///
/// `TooShort`, `Magic`, `Version`, `RecordCount` or `RecordsLength`, as
/// [`split`] orders them.
pub(crate) fn parse_footer(object: &[u8]) -> Result<(&[u8], &[u8], u16), ParseError>
{
    let (rest, footer) = object
        .split_last_chunk::<FOOTER_LEN>()
        .ok_or(ParseError::TooShort)?;
    let mut reader = Reader::new(footer);
    // The reads cannot run short: their lengths add up to FOOTER_LEN.
    let records_len = reader.u32().ok_or(ParseError::TooShort)?;
    let count = reader.u16().ok_or(ParseError::TooShort)?;
    let version = reader.u16().ok_or(ParseError::TooShort)?;
    let magic = reader.array::<8>().ok_or(ParseError::TooShort)?;
    if magic != MAGIC
    {
        return Err(ParseError::Magic);
    }
    if version != VERSION
    {
        return Err(ParseError::Version);
    }
    if count == 0 || count > MAX_RECORDS
    {
        return Err(ParseError::RecordCount);
    }
    let body_len = usize::try_from(records_len)
        .ok()
        .and_then(|records_len| rest.len().checked_sub(records_len))
        .ok_or(ParseError::RecordsLength)?;
    let (body, block) = rest
        .split_at_checked(body_len)
        .ok_or(ParseError::RecordsLength)?;
    Ok((body, block, count))
}

/// The checks after the walk of the records: `rest`, the bytes of the
/// block after the last record, is empty, and `body` does not end in the
/// footer magic.
///
/// # Errors
///
/// `RecordBlock`, then `NestedTrailer`.
pub(crate) fn close(body: &[u8], rest: &[u8]) -> Result<(), ParseError>
{
    if !rest.is_empty()
    {
        return Err(ParseError::RecordBlock);
    }
    if body.ends_with(&MAGIC)
    {
        return Err(ParseError::NestedTrailer);
    }
    Ok(())
}

/// The fields of a record, each at its place and of its length, not yet
/// decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordParts<'a>
{
    /// The key id of the key that made the signature.
    pub(crate) signer_key_id: KeyId,
    /// The encoded signed attributes.
    pub(crate) signed: &'a [u8],
    /// The certificate's bytes: none, or [`cert::LEN`].
    pub(crate) certificate: &'a [u8],
    /// The composite signature.
    pub(crate) signature: &'a Signature,
}

/// Read the header of the record at the start of `block` and cut the
/// record into its fields; returns them and the bytes after the record.
///
/// # Errors
///
/// `RecordBlock`, `Algorithm`, `CertificateCount` or `RecordLength`, as
/// [`split`] orders them.
pub(crate) fn record_parts(block: &[u8]) -> Result<(RecordParts<'_>, &[u8]), ParseError>
{
    let mut reader = Reader::new(block);
    let short = ParseError::RecordBlock;
    let record_len = reader.u32().ok_or(short)?;
    let algorithm = reader.u8().ok_or(short)?;
    let cert_count = reader.u8().ok_or(short)?;
    let attrs_len = reader.u16().ok_or(short)?;
    let signer_key_id = reader.array().ok_or(short)?;
    if algorithm != ALGORITHM_ED25519_ML_DSA_65
    {
        return Err(ParseError::Algorithm);
    }
    let (fixed, cert_len) = match cert_count
    {
        0 => (RECORD_FIXED_LEN, 0),
        1 => (RECORD_CERT_LEN, cert::LEN),
        _ => return Err(ParseError::CertificateCount),
    };
    let expected = usize::from(attrs_len).saturating_add(fixed);
    if usize::try_from(record_len) != Ok(expected)
    {
        return Err(ParseError::RecordLength);
    }
    let signed = reader.take(usize::from(attrs_len)).ok_or(short)?;
    let certificate = reader.take(cert_len).ok_or(short)?;
    let signature = reader.array_ref::<SIGNATURE_LEN>().ok_or(short)?;
    let parts = RecordParts {
        signer_key_id,
        signed,
        certificate,
        signature,
    };
    Ok((parts, reader.rest()))
}

/// Decode the fields of a record.
///
/// # Errors
///
/// The errors of [`Attributes::parse`], then those of
/// [`Certificate::parse`], and `RecordBlock` for a certificate of neither
/// length.
pub(crate) fn record_of(parts: RecordParts<'_>) -> Result<Record<'_>, ParseError>
{
    Ok(Record {
        signer_key_id: parts.signer_key_id,
        attrs: Attributes::parse(parts.signed)?,
        signed: parts.signed,
        certificate: parse_certificate(parts.certificate)?,
        signature: parts.signature,
    })
}

/// The certificate a record holds in `bytes`: none in 0 bytes, one in
/// [`cert::LEN`].
fn parse_certificate(bytes: &[u8]) -> Result<Option<Certificate<'_>>, ParseError>
{
    if bytes.is_empty()
    {
        return Ok(None);
    }
    let raw = <&[u8; cert::LEN]>::try_from(bytes).map_err(|_| ParseError::RecordBlock)?;
    Certificate::parse(raw).map(Some)
}

/// The length of the trailer of `records`.
///
/// # Errors
///
/// `RecordCount` for no record or more than [`MAX_RECORDS`]; the errors of
/// [`Attributes::encoded_len`]; `TooLong` when the record block is longer
/// than `records_len` holds.
pub fn trailer_len(records: &[RecordSpec<'_>]) -> Result<usize, EncodeError>
{
    if records.is_empty() || records.len() > usize::from(MAX_RECORDS)
    {
        return Err(EncodeError::RecordCount);
    }
    let mut records_len = 0usize;
    for record in records
    {
        records_len = records_len
            .checked_add(record.encoded_len()?)
            .ok_or(EncodeError::TooLong)?;
    }
    u32::try_from(records_len).map_err(|_| EncodeError::TooLong)?;
    records_len
        .checked_add(FOOTER_LEN)
        .ok_or(EncodeError::TooLong)
}

/// Encode the trailer of `records` at the start of `out`, to follow
/// `body`; returns its length. `body` followed by the trailer parses with
/// [`split`].
///
/// # Errors
///
/// `NestedTrailer` when `body` ends in the footer magic; the errors of
/// [`trailer_len`]; `Certificate` for a certificate [`Certificate::parse`]
/// refuses; `BufferTooSmall` when
/// `out` is shorter than the trailer.
pub fn encode_trailer(
    body: &[u8],
    records: &[RecordSpec<'_>],
    out: &mut [u8],
) -> Result<usize, EncodeError>
{
    if body.ends_with(&MAGIC)
    {
        return Err(EncodeError::NestedTrailer);
    }
    let len = trailer_len(records)?;
    let records_len =
        u32::try_from(len.saturating_sub(FOOTER_LEN)).map_err(|_| EncodeError::TooLong)?;
    let count = u16::try_from(records.len()).map_err(|_| EncodeError::RecordCount)?;
    let mut writer = Writer::new(out);
    for record in records
    {
        record.write(&mut writer)?;
    }
    writer.put(&records_len.to_le_bytes())?;
    writer.put(&count.to_le_bytes())?;
    writer.put(&VERSION.to_le_bytes())?;
    writer.put(&MAGIC)?;
    Ok(len)
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::boxed::Box;
    use std::sync::OnceLock;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::cert::CertificateBody;
    use crate::composite::PUBLIC_KEY_LEN;
    use crate::{Arch, Role, RoleSet, Usage};

    const BODY: &[u8] = b"\x7fELF and the rest of an image";

    static SUBJECT: crate::PublicKey = [0x55; PUBLIC_KEY_LEN];
    static SIGNATURE: Signature = [0x99; SIGNATURE_LEN];

    fn attrs(name: &[u8]) -> Attributes<'_>
    {
        Attributes {
            body_len: 31,
            security_version: 2,
            roles: RoleSet::of(&[Role::Kernel]),
            arch: Arch::X86_64,
            body_hash: [0x44; 64],
            name,
        }
    }

    fn certificate() -> &'static [u8; cert::LEN]
    {
        static CERT: OnceLock<Box<[u8; cert::LEN]>> = OnceLock::new();
        CERT.get_or_init(|| {
            let body = CertificateBody {
                subject_key: &SUBJECT,
                issuer_key_id: [0x66; 16],
                serial: 1,
                usage: Usage {
                    roles: RoleSet::ALL,
                    certify: false,
                },
                min_security_version: 0,
                max_security_version: u32::MAX,
            };
            let mut out = Box::new([0u8; cert::LEN]);
            body.encode(&[0x77; SIGNATURE_LEN], &mut out).unwrap();
            out
        })
    }

    fn record<'a>(name: &'a [u8], certificate: Option<&'a [u8; cert::LEN]>) -> RecordSpec<'a>
    {
        RecordSpec {
            signer_key_id: [0x88; 16],
            attrs: attrs(name),
            certificate,
            signature: &SIGNATURE,
        }
    }

    /// `BODY` followed by the trailer of `records`.
    fn object(records: &[RecordSpec<'_>]) -> Vec<u8>
    {
        let mut out = BODY.to_vec();
        let len = trailer_len(records).unwrap();
        out.resize(BODY.len() + len, 0);
        assert_eq!(
            encode_trailer(BODY, records, &mut out[BODY.len()..]),
            Ok(len)
        );
        out
    }

    #[test]
    fn layout_matches_the_specification()
    {
        let bytes = object(&[record(b"kernel", Some(certificate()))]);
        let record_len = 3397 + 99 + 6 + 5409;
        assert_eq!(record_len, 24 + 105 + cert::LEN + SIGNATURE_LEN);
        assert_eq!(bytes.len(), BODY.len() + record_len + 16);
        let r = &bytes[BODY.len()..];
        assert_eq!(&r[0..4], &u32::try_from(record_len).unwrap().to_le_bytes());
        assert_eq!(r[4], 2, "algorithm");
        assert_eq!(r[5], 1, "cert_count");
        assert_eq!(&r[6..8], &105u16.to_le_bytes());
        assert_eq!(&r[8..24], &[0x88; 16]);
        assert_eq!(&r[24..40], &crate::attrs::DOMAIN);
        assert_eq!(&r[123..129], b"kernel");
        assert_eq!(&r[129..5538], &certificate()[..]);
        assert_eq!(&r[5538..8911], &SIGNATURE[..]);
        let footer = &r[8911..];
        assert_eq!(
            &footer[0..4],
            &u32::try_from(record_len).unwrap().to_le_bytes()
        );
        assert_eq!(&footer[4..6], &1u16.to_le_bytes());
        assert_eq!(&footer[6..8], &2u16.to_le_bytes());
        assert_eq!(&footer[8..16], b"SERAPHSG");
    }

    #[test]
    fn round_trips()
    {
        let names: Vec<Vec<u8>> = (0..8u8)
            .map(|i| vec![b'a' + i; usize::from(i) + 1])
            .collect();
        let specs: Vec<RecordSpec<'_>> = names
            .iter()
            .enumerate()
            .map(|(i, name)| record(name, (i % 2 == 1).then(certificate)))
            .collect();
        for count in 1..=specs.len()
        {
            let bytes = object(&specs[..count]);
            let signed = split(&bytes).unwrap();
            assert_eq!(signed.body(), BODY);
            let records: Vec<Record<'_>> = signed.records().collect();
            assert_eq!(records.len(), count);
            for (record, spec) in records.iter().zip(&specs)
            {
                assert_eq!(record.spec(), *spec);
                let mut encoded = vec![0u8; spec.attrs.encoded_len().unwrap()];
                spec.attrs.encode(&mut encoded).unwrap();
                assert_eq!(record.signed, encoded.as_slice());
            }
            // A trailer re-encoded from the parsed records is the same bytes.
            let respecs: Vec<RecordSpec<'_>> = records.iter().map(Record::spec).collect();
            assert_eq!(object(&respecs), bytes);
        }
    }

    #[test]
    fn refuses_each_malformed_footer_field()
    {
        let good = object(&[record(b"kernel", None)]);
        let end = good.len();
        let refuse = |edit: &dyn Fn(&mut Vec<u8>), error| {
            let mut bytes = good.clone();
            edit(&mut bytes);
            assert_eq!(split(&bytes), Err(error));
        };
        assert_eq!(split(&good[end - 15..]), Err(ParseError::TooShort));
        assert_eq!(split(&[]), Err(ParseError::TooShort));
        refuse(&|b| b[end - 1] = b'g', ParseError::Magic);
        // Version 1, the retired Ed25519 format, and a version not defined.
        refuse(&|b| b[end - 10] = 1, ParseError::Version);
        refuse(&|b| b[end - 10] = 3, ParseError::Version);
        refuse(
            &|b| b[end - 12..end - 10].copy_from_slice(&0u16.to_le_bytes()),
            ParseError::RecordCount,
        );
        refuse(
            &|b| b[end - 12..end - 10].copy_from_slice(&9u16.to_le_bytes()),
            ParseError::RecordCount,
        );
        refuse(
            &|b| b[end - 16..end - 12].copy_from_slice(&u32::MAX.to_le_bytes()),
            ParseError::RecordsLength,
        );
        let available = u32::try_from(end - 16 + 1).unwrap();
        refuse(
            &|b| b[end - 16..end - 12].copy_from_slice(&available.to_le_bytes()),
            ParseError::RecordsLength,
        );
        // A record count above the records the block holds.
        refuse(&|b| b[end - 12] = 2, ParseError::RecordBlock);
        // A block longer than its records: the body's last byte joins it.
        let longer = u32::try_from(end - 16 - BODY.len() + 1).unwrap();
        refuse(
            &|b| b[end - 16..end - 12].copy_from_slice(&longer.to_le_bytes()),
            ParseError::Algorithm,
        );
        // A block shorter than its records.
        let shorter = u32::try_from(end - 16 - BODY.len() - 1).unwrap();
        refuse(
            &|b| b[end - 16..end - 12].copy_from_slice(&shorter.to_le_bytes()),
            ParseError::Algorithm,
        );
    }

    #[test]
    fn refuses_unused_bytes_of_the_block()
    {
        // Two records whose footer claims one: the second is unused.
        let mut bytes = object(&[record(b"kernel", None), record(b"init", None)]);
        let end = bytes.len();
        bytes[end - 12] = 1;
        assert_eq!(split(&bytes), Err(ParseError::RecordBlock));
    }

    #[test]
    fn refuses_each_malformed_record_field()
    {
        let good = object(&[record(b"kernel", Some(certificate()))]);
        let at = BODY.len();
        let cert_at = at + 129;
        let refuse = |edit: &dyn Fn(&mut Vec<u8>), error| {
            let mut bytes = good.clone();
            edit(&mut bytes);
            assert_eq!(split(&bytes), Err(error));
        };
        refuse(&|b| b[at] ^= 1, ParseError::RecordLength);
        refuse(&|b| b[at + 3] = 0x80, ParseError::RecordLength);
        refuse(&|b| b[at + 4] = 0, ParseError::Algorithm);
        // Algorithm 1, Ed25519 alone, is retired.
        refuse(&|b| b[at + 4] = 1, ParseError::Algorithm);
        refuse(&|b| b[at + 4] = 3, ParseError::Algorithm);
        refuse(&|b| b[at + 5] = 2, ParseError::CertificateCount);
        refuse(&|b| b[at + 5] = 0, ParseError::RecordLength);
        // attrs_len one more, record_len to match: the record overruns the
        // block by a byte.
        refuse(
            &|b| {
                b[at + 6] += 1;
                b[at] += 1;
            },
            ParseError::RecordBlock,
        );
        refuse(&|b| b[at + 24] = 0, ParseError::AttributesDomain);
        refuse(&|b| b[at + 24 + 28] = 9, ParseError::Roles);
        refuse(&|b| b[at + 24 + 98] = 9, ParseError::Arch);
        refuse(&|b| b[cert_at] = 0, ParseError::CertificateDomain);
        refuse(
            &|b| b[cert_at + 2027] = 0x80,
            ParseError::CertificateCertify,
        );
        refuse(&|b| b[cert_at + 2024] = 1, ParseError::CertificateUsage);
        refuse(
            &|b| {
                b[cert_at + 2028] = 1;
                b[cert_at + 2032..cert_at + 2036].fill(0);
            },
            ParseError::CertificateRange,
        );
    }

    #[test]
    fn refuses_a_nested_trailer()
    {
        let inner = object(&[record(b"init", None)]);
        let records = [record(b"init", None)];
        let len = trailer_len(&records).unwrap();
        let mut out = vec![0u8; len];
        assert_eq!(
            encode_trailer(&inner, &records, &mut out),
            Err(EncodeError::NestedTrailer)
        );
        let mut nested = inner.clone();
        nested.extend_from_slice(&inner[BODY.len()..]);
        assert_eq!(split(&nested), Err(ParseError::NestedTrailer));
    }

    #[test]
    fn encoder_refuses_what_the_parser_refuses()
    {
        let one = [record(b"kernel", None)];
        assert_eq!(trailer_len(&[]), Err(EncodeError::RecordCount));
        assert_eq!(trailer_len(&[one[0]; 9]), Err(EncodeError::RecordCount));
        assert_eq!(
            trailer_len(&[record(b"", None)]),
            Err(EncodeError::EmptyName)
        );
        // A certificate whose usage has CERTIFY, which no encoder of a
        // certificate writes.
        let mut certify = Box::new(*certificate());
        certify[2027] |= 0x80;
        let with_certify = [record(b"kernel", Some(&*certify))];
        let mut out = vec![0u8; trailer_len(&with_certify).unwrap()];
        assert_eq!(
            encode_trailer(BODY, &with_certify, &mut out),
            Err(EncodeError::Certificate)
        );
        let len = trailer_len(&one).unwrap();
        assert_eq!(
            encode_trailer(BODY, &one, &mut out[..len - 1]),
            Err(EncodeError::BufferTooSmall)
        );
    }
}

/// Bounded proofs of the signed object's parse (docs/testing.md § Bounded
/// verification, Parser proofs), each on every input up to the bounds its
/// comment states.
///
/// How they compose into the property's check of [`split`]
/// (`property::split_holds`). The walk of the records is a loop whose step
/// is [`record_parts`] then [`record_of`], its state the rest of the block,
/// and it is proven by induction: the footer proof shows that the walk
/// starts on the block the footer gives, the bytes between the body and the
/// footer; the record-cut proof runs the step's cut on any block, so the rest
/// it hands the next step is the block after the record, wherever the record
/// ends; the record-decode proofs run its decode on any fields of each
/// certificate length; and the close proof checks what the walk leaves. The
/// attributes and the certificate the decode reads are proven on any input by
/// the proofs of `attrs.rs` and `cert.rs`. What lies outside the proofs is
/// the loop that drives the steps, `count` times in [`split`] and one step
/// a call in [`Records::next`]; the fuzz target `objsig`, the replay of the
/// checked-in inputs and the unit tests check it.
#[cfg(kani)]
mod proofs
{
    use super::RecordParts;
    use crate::{cert, property};

    /// Every object of at most 40 bytes holds the footer's contract: shorter
    /// than the footer, each refusal of its fields, and a block of up to 24
    /// bytes after a body of up to 24, a records length past them among them.
    /// The footer's fields are read at fixed offsets from the end, so 40 bytes
    /// reach each; the length check is one subtraction from the bytes before
    /// the footer, of any count.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_footer_reads_as_its_fields()
    {
        let bytes: [u8; 40] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::footer_holds(&bytes[..len]);
    }

    /// Every block of at most 8,908 bytes is cut into the fields of the
    /// record at its start, or refused as the record's header and length
    /// judge it: 8,908 bytes hold a record with a certificate whose
    /// attributes are 100 bytes (the fixed part and a one-byte name), and one
    /// byte after it, so each refusal, a record with and without a
    /// certificate, a record overrunning the block and one leaving bytes
    /// after it are reached. No loop: the fields are cut by length.
    #[kani::proof]
    fn every_block_cuts_into_its_record_fields()
    {
        let bytes: [u8; 8908] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::parts_holds(&bytes[..len]);
    }

    /// A record's fields of any signer, any signature, any `certificate`, and
    /// attributes of any of at most 103 bytes (the fixed part, a name of up
    /// to 3 and one more: every refusal of `Attributes::parse` but the one of
    /// a length past 65,535, a compare the unit tests check at the bound),
    /// decode into the record of their decodes, or the first refusal.
    fn record_decodes_its_fields<const N: usize>(certificate: &[u8])
    {
        let signed: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= signed.len());
        let signature: crate::Signature = kani::any();
        let parts = RecordParts {
            signer_key_id: kani::any(),
            signed: &signed[..len],
            certificate,
            signature: &signature,
        };
        let _ = property::record_of_holds(parts);
    }

    /// [`record_decodes_its_fields`] for a record without a certificate.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_record_without_a_certificate_decodes_its_fields()
    {
        record_decodes_its_fields::<103>(&[]);
    }

    /// [`record_decodes_its_fields`] for a record with any certificate.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_record_with_a_certificate_decodes_its_fields()
    {
        let certificate: [u8; cert::LEN] = kani::any();
        record_decodes_its_fields::<103>(&certificate);
    }

    /// [`record_decodes_its_fields`] for a certificate of neither length,
    /// which [`super::record_parts`] never cuts: one byte stands for any.
    #[kani::proof]
    #[kani::unwind(65)]
    fn a_certificate_of_another_length_is_refused()
    {
        let certificate: [u8; 1] = kani::any();
        record_decodes_its_fields::<103>(&certificate);
    }

    /// Every body of at most 9 bytes and every rest of at most one holds the
    /// close's contract: the magic is 8 bytes, so 9 hold a body ending in it
    /// after another byte, and one byte stands for any rest left.
    #[kani::proof]
    #[kani::unwind(10)]
    fn every_close_holds()
    {
        let body: [u8; 9] = kani::any();
        let body_len: usize = kani::any();
        kani::assume(body_len <= body.len());
        let rest: [u8; 1] = kani::any();
        let rest_len: usize = kani::any();
        kani::assume(rest_len <= rest.len());
        let _ = property::close_holds(&body[..body_len], &rest[..rest_len]);
    }
}
