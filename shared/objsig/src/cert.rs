// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/cert.rs

//! The certificate: a fixed 148-byte record by which a root lets a signing
//! key sign objects in some roles within a range of security versions
//! ([docs/signing.md](../../../docs/signing.md) § Certificate Format).

use crate::wire::{Reader, concat};
use crate::{EncodeError, KeyId, ParseError, PublicKey, Signature, Usage};

/// The domain tag a certificate begins with: `seraph/cert/v1`, padded with
/// NUL bytes to 16.
pub const DOMAIN: [u8; 16] = *b"seraph/cert/v1\0\0";

/// The length of a certificate.
pub const LEN: usize = 148;

/// The length of the bytes the issuer signs: everything before the
/// signature.
pub const SIGNED_LEN: usize = 84;

/// What a certificate says: everything but the issuer's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateBody
{
    /// The signing key's Ed25519 public key.
    pub subject_key: PublicKey,
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

impl CertificateBody
{
    /// The bytes the issuer signs, bytes 0 to 83 of the certificate.
    ///
    /// # Errors
    ///
    /// `Certificate` when the usage has `CERTIFY` or the security-version
    /// range is empty: a certificate the parser refuses.
    pub fn signed_bytes(&self) -> Result<[u8; SIGNED_LEN], EncodeError>
    {
        if self.usage.certify || self.max_security_version < self.min_security_version
        {
            return Err(EncodeError::Certificate);
        }
        Ok(self.to_signed())
    }

    /// Whether `version` lies in the certificate's security-version range.
    #[must_use]
    pub const fn allows(&self, version: u32) -> bool
    {
        self.min_security_version <= version && version <= self.max_security_version
    }

    /// The signed bytes, unchecked: the caller has checked the body.
    pub(crate) fn to_signed(self) -> [u8; SIGNED_LEN]
    {
        concat(&[
            &DOMAIN,
            &self.subject_key,
            &self.issuer_key_id,
            &self.serial.to_le_bytes(),
            &self.usage.to_bits().to_le_bytes(),
            &self.min_security_version.to_le_bytes(),
            &self.max_security_version.to_le_bytes(),
        ])
    }
}

/// A decoded certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Certificate
{
    /// What the certificate says.
    pub body: CertificateBody,
    /// The issuer's Ed25519 signature over [`CertificateBody::signed_bytes`].
    pub signature: Signature,
}

impl Certificate
{
    /// Decode a certificate.
    ///
    /// # Errors
    ///
    /// The [`ParseError`] of the first rule `bytes` breaks:
    /// `CertificateDomain`, `CertificateUsage`, `CertificateCertify` or
    /// `CertificateRange`.
    pub fn parse(bytes: &[u8; LEN]) -> Result<Self, ParseError>
    {
        let mut reader = Reader::new(bytes);
        // The reads cannot run short: their lengths add up to LEN.
        let short = ParseError::CertificateDomain;
        let domain = reader.array::<16>().ok_or(short)?;
        let subject_key = reader.array().ok_or(short)?;
        let issuer_key_id = reader.array().ok_or(short)?;
        let serial = reader.u64().ok_or(short)?;
        let usage = reader.u32().ok_or(short)?;
        let min_security_version = reader.u32().ok_or(short)?;
        let max_security_version = reader.u32().ok_or(short)?;
        let signature = reader.array().ok_or(short)?;
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
        })
    }

    /// Encode the certificate.
    ///
    /// # Errors
    ///
    /// The errors of [`CertificateBody::signed_bytes`].
    pub fn encode(&self) -> Result<[u8; LEN], EncodeError>
    {
        let signed = self.body.signed_bytes()?;
        Ok(concat(&[&signed, &self.signature]))
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::{Role, RoleSet};

    fn sample() -> Certificate
    {
        Certificate {
            body: CertificateBody {
                subject_key: [0x11; 32],
                issuer_key_id: [0x22; 16],
                serial: 0x0102_0304_0506_0708,
                usage: Usage {
                    roles: RoleSet::of(&[Role::Service, Role::Driver]),
                    certify: false,
                },
                min_security_version: 3,
                max_security_version: 9,
            },
            signature: [0x33; 64],
        }
    }

    #[test]
    fn layout_matches_the_specification()
    {
        let bytes = sample().encode().unwrap();
        assert_eq!(&bytes[0..16], b"seraph/cert/v1\0\0");
        assert_eq!(&bytes[16..48], &[0x11; 32]);
        assert_eq!(&bytes[48..64], &[0x22; 16]);
        assert_eq!(&bytes[64..72], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&bytes[72..76], &((1u32 << 4) | (1 << 5)).to_le_bytes());
        assert_eq!(&bytes[76..80], &3u32.to_le_bytes());
        assert_eq!(&bytes[80..84], &9u32.to_le_bytes());
        assert_eq!(&bytes[84..148], &[0x33; 64]);
        assert_eq!(sample().body.signed_bytes().unwrap(), bytes[..SIGNED_LEN]);
    }

    #[test]
    fn round_trips()
    {
        let cert = sample();
        assert_eq!(Certificate::parse(&cert.encode().unwrap()), Ok(cert));
        let mut equal = sample();
        equal.body.max_security_version = equal.body.min_security_version;
        assert_eq!(Certificate::parse(&equal.encode().unwrap()), Ok(equal));
    }

    #[test]
    fn refuses_each_malformed_field()
    {
        let good = sample().encode().unwrap();
        let refuse = |edit: &dyn Fn(&mut [u8; LEN]), error| {
            let mut bytes = good;
            edit(&mut bytes);
            assert_eq!(Certificate::parse(&bytes), Err(error));
        };
        refuse(&|b| b[0] = b'x', ParseError::CertificateDomain);
        refuse(&|b| b[15] = 1, ParseError::CertificateDomain);
        refuse(&|b| b[72] |= 1, ParseError::CertificateUsage);
        refuse(&|b| b[73] |= 1, ParseError::CertificateUsage);
        refuse(&|b| b[75] |= 0x40, ParseError::CertificateUsage);
        refuse(&|b| b[75] |= 0x80, ParseError::CertificateCertify);
        refuse(&|b| b[80] = 2, ParseError::CertificateRange);
    }

    #[test]
    fn allows_its_range_only()
    {
        let body = sample().body;
        assert!(!body.allows(2));
        assert!(body.allows(3));
        assert!(body.allows(9));
        assert!(!body.allows(10));
    }

    #[test]
    fn encoder_refuses_what_the_parser_refuses()
    {
        let mut certify = sample();
        certify.body.usage.certify = true;
        assert_eq!(certify.encode(), Err(EncodeError::Certificate));
        let mut empty = sample();
        empty.body.max_security_version = 2;
        assert_eq!(empty.encode(), Err(EncodeError::Certificate));
    }
}
