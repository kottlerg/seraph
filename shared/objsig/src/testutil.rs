// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/testutil.rs

//! Test fixtures: an Ed25519 signer, and builders of stores and signed
//! objects.
//!
//! The signer computes RFC 8032 § 5.1.6 signatures with the testkit's
//! edwards25519 arithmetic, which is independent of `shared/crypto` and not
//! constant time: it signs only fixed test keys.

extern crate std;
use std::sync::OnceLock;
use std::vec;
use std::vec::Vec;

use crypto_testkit::generate::edwards::{Point, scalars};
use crypto_testkit::generate::nat::U256;

use crate::attrs::Attributes;
use crate::cert::{Certificate, CertificateBody};
use crate::store::{AnchorSpec, TrustStore};
use crate::trailer::{RecordSpec, encode_trailer, trailer_len};
use crate::{Arch, KeyId, PublicKey, Role, RoleSet, Signature, Usage, key_id};

/// An Ed25519 key pair.
pub(crate) struct Key
{
    pub(crate) public: PublicKey,
    scalar: U256,
    prefix: [u8; 32],
}

impl Key
{
    /// The key of a 32-byte seed (RFC 8032 § 5.1.5).
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self
    {
        let digest = crypto::sha512(seed);
        let mut scalar: [u8; 32] = digest[..32].try_into().unwrap();
        scalar[0] &= 0xf8;
        scalar[31] &= 0x7f;
        scalar[31] |= 0x40;
        let scalar = U256::from_le_bytes(&scalar);
        Self {
            public: Point::base().mul(scalar).encode(),
            scalar,
            prefix: digest[32..].try_into().unwrap(),
        }
    }

    pub(crate) fn id(&self) -> KeyId
    {
        key_id(&self.public)
    }

    /// The signature of `message` (RFC 8032 § 5.1.6).
    pub(crate) fn sign(&self, message: &[u8]) -> Signature
    {
        let l = scalars();
        let r = l.reduce_le_bytes(&hash(&[&self.prefix, message]));
        let big_r = Point::base().mul(r).encode();
        let k = l.reduce_le_bytes(&hash(&[&big_r, &self.public, message]));
        let s = l.add(r, l.mul(k, l.reduce(self.scalar)));
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(&s.to_le_bytes());
        signature
    }
}

fn hash(parts: &[&[u8]]) -> [u8; 64]
{
    let mut state = crypto::Sha512::new();
    for part in parts
    {
        state.update(part);
    }
    state.finalize()
}

/// The fixed test keys: the trusted root, a signing key, a root no store
/// trusts, and a second trusted root.
pub(crate) struct Keys
{
    pub(crate) root: Key,
    pub(crate) signer: Key,
    pub(crate) stranger: Key,
    pub(crate) second_root: Key,
}

pub(crate) fn keys() -> &'static Keys
{
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys {
        root: Key::from_seed(&[1; 32]),
        signer: Key::from_seed(&[2; 32]),
        stranger: Key::from_seed(&[3; 32]),
        second_root: Key::from_seed(&[4; 32]),
    })
}

/// A root's usage: every role, and `CERTIFY`.
pub(crate) const ROOT: Usage = Usage {
    roles: RoleSet::ALL,
    certify: true,
};

/// A store of `anchors` (sorted here) and `revoked` (sorted here).
pub(crate) fn store(floor: u32, anchors: &[(&Key, Usage)], revoked: &[KeyId]) -> Vec<u8>
{
    let mut specs: Vec<AnchorSpec<'_>> = anchors
        .iter()
        .map(|(key, usage)| AnchorSpec {
            key: key.public,
            usage: *usage,
            local: true,
            label: "test root",
        })
        .collect();
    specs.sort_by_key(|spec| key_id(&spec.key));
    let mut revoked = revoked.to_vec();
    revoked.sort_unstable();
    let mut out = vec![0u8; TrustStore::encoded_len(specs.len(), revoked.len()).unwrap()];
    TrustStore::encode(floor, &specs, &revoked, &mut out).unwrap();
    out
}

/// A certificate `issuer` issues to `subject`.
pub(crate) fn certify(
    issuer: &Key,
    subject: &Key,
    roles: RoleSet,
    min: u32,
    max: u32,
) -> Certificate
{
    let body = CertificateBody {
        subject_key: subject.public,
        issuer_key_id: issuer.id(),
        serial: 7,
        usage: Usage {
            roles,
            certify: false,
        },
        min_security_version: min,
        max_security_version: max,
    };
    Certificate {
        body,
        signature: issuer.sign(&body.signed_bytes().unwrap()),
    }
}

/// The attributes of `body` with the set of `roles`, named `name`, for
/// x86-64.
pub(crate) fn attrs<'n>(
    body: &[u8],
    roles: &[Role],
    name: &'n [u8],
    security_version: u32,
) -> Attributes<'n>
{
    Attributes {
        body_len: u64::try_from(body.len()).unwrap(),
        security_version,
        roles: RoleSet::of(roles),
        arch: Arch::X86_64,
        body_hash: crypto::sha512(body),
        name,
    }
}

/// A record of `attrs` signed by `key`, with `certificate`.
pub(crate) fn record<'n>(
    key: &Key,
    certificate: Option<Certificate>,
    attrs: Attributes<'n>,
) -> RecordSpec<'n>
{
    let mut signed = vec![0u8; attrs.encoded_len().unwrap()];
    attrs.encode(&mut signed).unwrap();
    RecordSpec {
        signer_key_id: key.id(),
        attrs,
        certificate,
        signature: key.sign(&signed),
    }
}

/// `body` followed by the trailer of `records`.
pub(crate) fn object(body: &[u8], records: &[RecordSpec<'_>]) -> Vec<u8>
{
    let len = trailer_len(records).unwrap();
    let mut out = body.to_vec();
    out.resize(body.len() + len, 0);
    encode_trailer(body, records, &mut out[body.len()..]).unwrap();
    out
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// RFC 8032 § 7.1, TEST 2.
    #[test]
    fn signer_matches_rfc_8032()
    {
        let hex = |text: &str| crypto_testkit::hex::decode(text).unwrap();
        let seed: [u8; 32] =
            hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .try_into()
                .unwrap();
        let key = Key::from_seed(&seed);
        assert_eq!(
            key.public.to_vec(),
            hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        );
        assert_eq!(
            key.sign(&[0x72]).to_vec(),
            hex(concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ))
        );
        assert_eq!(
            crypto::ed25519_verify(&key.public, b"m", &key.sign(b"m")),
            Ok(())
        );
    }
}
