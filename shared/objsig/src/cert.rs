// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/cert.rs

//! The certificate: a fixed 5,409-byte record by which a root lets a signing
//! key sign objects in some roles within a range of security versions
//! ([docs/signing.md](../../../docs/signing.md) § Certificate Format).
//!
//! A parsed [`Certificate`] borrows its key and signature from the bytes it
//! was parsed from, so a verifier copies neither.

use crate::composite::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::wire::{Reader, Writer};
use crate::{EncodeError, KEY_ID_LEN, KeyId, ParseError, PublicKey, Signature, Usage};

/// The domain tag a certificate begins with: `seraph/cert/v2`, padded with
/// NUL bytes to 16.
pub const DOMAIN: [u8; 16] = *b"seraph/cert/v2\0\0";

/// The length of the bytes the issuer signs: everything before the
/// signature, 2,036 bytes.
pub const SIGNED_LEN: usize = DOMAIN.len() + PUBLIC_KEY_LEN + KEY_ID_LEN + 8 + 4 + 4 + 4;

/// The length of a certificate: its signed bytes and the issuer's
/// signature, 5,409 bytes.
pub const LEN: usize = SIGNED_LEN + SIGNATURE_LEN;

/// What a certificate says: everything but the issuer's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateBody<'a>
{
    /// The signing key's composite public key.
    pub subject_key: &'a PublicKey,
    /// The key id of the root that issued the certificate.
    pub issuer_key_id: KeyId,
    /// The issuer's serial number of the certificate.
    pub serial: u64,
    /// The roles the signing key may sign; `certify` is always false.
    pub usage: Usage,
    /// The lowest security version the key may sign.
    pub min_security_version: u32,
    /// The highest security version the key may sign.
    pub max_security_version: u32,
}

impl CertificateBody<'_>
{
    /// Write into `out` the bytes the issuer signs, bytes 0 to 2,035 of the
    /// certificate. The encoders write into the caller's buffer: the
    /// certificate is larger than a stack frame of a `shared/` crate may
    /// hold.
    ///
    /// # Errors
    ///
    /// `Certificate` when the usage has `CERTIFY` or the security-version
    /// range is empty: a certificate the parser refuses.
    pub fn encode_signed(&self, out: &mut [u8; SIGNED_LEN]) -> Result<(), EncodeError>
    {
        self.write_signed(&mut Writer::new(out))
    }

    /// Write into `out` the certificate of this body with the issuer's
    /// `signature` over the bytes [`Self::encode_signed`] writes.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::encode_signed`].
    pub fn encode(&self, signature: &Signature, out: &mut [u8; LEN]) -> Result<(), EncodeError>
    {
        let mut writer = Writer::new(out);
        self.write_signed(&mut writer)?;
        writer.put(signature)
    }

    /// Append the signed bytes, refusing a body the parser refuses.
    fn write_signed(&self, writer: &mut Writer<'_>) -> Result<(), EncodeError>
    {
        if self.usage.certify || self.max_security_version < self.min_security_version
        {
            return Err(EncodeError::Certificate);
        }
        writer.put(&DOMAIN)?;
        writer.put(self.subject_key)?;
        writer.put(&self.issuer_key_id)?;
        writer.put(&self.serial.to_le_bytes())?;
        writer.put(&self.usage.to_bits().to_le_bytes())?;
        writer.put(&self.min_security_version.to_le_bytes())?;
        writer.put(&self.max_security_version.to_le_bytes())
    }

    /// Whether `version` lies in the certificate's security-version range.
    #[must_use]
    pub const fn allows(&self, version: u32) -> bool
    {
        self.min_security_version <= version && version <= self.max_security_version
    }
}

/// A decoded certificate, borrowing the bytes it was parsed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Certificate<'a>
{
    /// What the certificate says.
    pub body: CertificateBody<'a>,
    /// The issuer's composite signature over [`Self::signed`].
    pub signature: &'a Signature,
    bytes: &'a [u8; LEN],
    signed: &'a [u8; SIGNED_LEN],
}

impl<'a> Certificate<'a>
{
    /// Decode a certificate.
    ///
    /// # Errors
    ///
    /// The [`ParseError`] of the first rule `bytes` breaks:
    /// `CertificateDomain`, `CertificateUsage`, `CertificateCertify` or
    /// `CertificateRange`.
    pub fn parse(bytes: &'a [u8; LEN]) -> Result<Self, ParseError>
    {
        // The reads cannot run short: their lengths add up to LEN.
        let short = ParseError::CertificateDomain;
        let mut outer = Reader::new(bytes);
        let signed = outer.array_ref::<SIGNED_LEN>().ok_or(short)?;
        let signature = outer.array_ref::<SIGNATURE_LEN>().ok_or(short)?;
        let mut reader = Reader::new(signed);
        let domain = reader.array::<16>().ok_or(short)?;
        let subject_key = reader.array_ref::<PUBLIC_KEY_LEN>().ok_or(short)?;
        let issuer_key_id = reader.array().ok_or(short)?;
        let serial = reader.u64().ok_or(short)?;
        let usage = reader.u32().ok_or(short)?;
        let min_security_version = reader.u32().ok_or(short)?;
        let max_security_version = reader.u32().ok_or(short)?;
        if domain != DOMAIN
        {
            return Err(ParseError::CertificateDomain);
        }
        let usage = Usage::from_bits(usage).ok_or(ParseError::CertificateUsage)?;
        if usage.certify
        {
            return Err(ParseError::CertificateCertify);
        }
        if max_security_version < min_security_version
        {
            return Err(ParseError::CertificateRange);
        }
        Ok(Self {
            body: CertificateBody {
                subject_key,
                issuer_key_id,
                serial,
                usage,
                min_security_version,
                max_security_version,
            },
            signature,
            bytes,
            signed,
        })
    }

    /// The bytes the issuer signed: the certificate less its signature.
    #[must_use]
    pub const fn signed(&self) -> &'a [u8; SIGNED_LEN]
    {
        self.signed
    }

    /// The certificate's encoding, as it was parsed.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8; LEN]
    {
        self.bytes
    }
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::boxed::Box;

    use super::*;
    use crate::{Role, RoleSet};

    static SUBJECT: PublicKey = [0x11; PUBLIC_KEY_LEN];
    static SIGNATURE: Signature = [0x33; SIGNATURE_LEN];

    fn sample() -> CertificateBody<'static>
    {
        CertificateBody {
            subject_key: &SUBJECT,
            issuer_key_id: [0x22; 16],
            serial: 0x0102_0304_0506_0708,
            usage: Usage {
                roles: RoleSet::of(&[Role::Service, Role::Driver]),
                certify: false,
            },
            min_security_version: 3,
            max_security_version: 9,
        }
    }

    fn encoded(body: &CertificateBody<'_>) -> Box<[u8; LEN]>
    {
        let mut out = Box::new([0u8; LEN]);
        body.encode(&SIGNATURE, &mut out).unwrap();
        out
    }

    #[test]
    fn layout_matches_the_specification()
    {
        assert_eq!((SIGNED_LEN, LEN), (2036, 5409));
        let bytes = encoded(&sample());
        assert_eq!(&bytes[0..16], b"seraph/cert/v2\0\0");
        assert_eq!(&bytes[16..2000], &SUBJECT[..]);
        assert_eq!(&bytes[2000..2016], &[0x22; 16]);
        assert_eq!(&bytes[2016..2024], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&bytes[2024..2028], &((1u32 << 4) | (1 << 5)).to_le_bytes());
        assert_eq!(&bytes[2028..2032], &3u32.to_le_bytes());
        assert_eq!(&bytes[2032..2036], &9u32.to_le_bytes());
        assert_eq!(&bytes[2036..5409], &SIGNATURE[..]);
        let mut signed = Box::new([0u8; SIGNED_LEN]);
        sample().encode_signed(&mut signed).unwrap();
        assert_eq!(signed[..], bytes[..SIGNED_LEN]);
    }

    #[test]
    fn round_trips()
    {
        let bytes = encoded(&sample());
        let cert = Certificate::parse(&bytes).unwrap();
        assert_eq!(cert.body, sample());
        assert_eq!(cert.signature, &SIGNATURE);
        assert_eq!(cert.as_bytes(), &*bytes);
        assert_eq!(&cert.signed()[..], &bytes[..SIGNED_LEN]);
        let mut equal = sample();
        equal.max_security_version = equal.min_security_version;
        let bytes = encoded(&equal);
        assert_eq!(Certificate::parse(&bytes).unwrap().body, equal);
    }

    #[test]
    fn refuses_each_malformed_field()
    {
        let good = encoded(&sample());
        let refuse = |edit: &dyn Fn(&mut [u8; LEN]), error| {
            let mut bytes = good.clone();
            edit(&mut bytes);
            assert_eq!(Certificate::parse(&bytes), Err(error));
        };
        refuse(&|b| b[0] = b'x', ParseError::CertificateDomain);
        refuse(&|b| b[13] = b'1', ParseError::CertificateDomain);
        refuse(&|b| b[15] = 1, ParseError::CertificateDomain);
        refuse(&|b| b[2024] |= 1, ParseError::CertificateUsage);
        refuse(&|b| b[2025] |= 1, ParseError::CertificateUsage);
        refuse(&|b| b[2027] |= 0x40, ParseError::CertificateUsage);
        refuse(&|b| b[2027] |= 0x80, ParseError::CertificateCertify);
        refuse(&|b| b[2032] = 2, ParseError::CertificateRange);
    }

    #[test]
    fn allows_its_range_only()
    {
        let body = sample();
        assert!(!body.allows(2));
        assert!(body.allows(3));
        assert!(body.allows(9));
        assert!(!body.allows(10));
    }

    #[test]
    fn encoder_refuses_what_the_parser_refuses()
    {
        let mut out = Box::new([0u8; LEN]);
        let mut signed = Box::new([0u8; SIGNED_LEN]);
        let mut certify = sample();
        certify.usage.certify = true;
        let mut empty = sample();
        empty.max_security_version = 2;
        for body in [certify, empty]
        {
            assert_eq!(
                body.encode(&SIGNATURE, &mut out),
                Err(EncodeError::Certificate)
            );
            assert_eq!(
                body.encode_signed(&mut signed),
                Err(EncodeError::Certificate)
            );
        }
    }
}
