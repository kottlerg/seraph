// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/testutil.rs

//! Test fixtures: composite keys, and builders of stores and signed objects.
//!
//! The keys sign with [`crate::composite::sign`], whose halves are
//! `shared/crypto`'s signers, tested there against their reference vectors;
//! the tests here test the formats and the verifier's policy. A signature or
//! certificate a fixture builds is leaked, so a record spec can borrow it for
//! the life of the test process.

extern crate std;
use std::boxed::Box;
use std::sync::OnceLock;
use std::vec;
use std::vec::Vec;

use crate::attrs::Attributes;
use crate::cert::{self, CertificateBody};
use crate::composite::{self, SEED_LEN};
use crate::store::{AnchorSpec, TrustStore};
use crate::trailer::{RecordSpec, encode_trailer, trailer_len};
use crate::{Arch, KeyId, PublicKey, Role, RoleSet, Signature, Usage, key_id};

/// `value`, leaked for the rest of the test process.
pub(crate) fn leak<T>(value: T) -> &'static T
{
    Box::leak(Box::new(value))
}

/// A composite key pair.
pub(crate) struct Key
{
    pub(crate) public: PublicKey,
    seed: [u8; SEED_LEN],
}

impl Key
{
    /// The key of a 64-byte seed, both halves' seeds.
    pub(crate) fn from_seed(seed: [u8; SEED_LEN]) -> Self
    {
        Self {
            public: composite::public_key(&seed),
            seed,
        }
    }

    pub(crate) fn id(&self) -> KeyId
    {
        key_id(&self.public)
    }

    /// The composite signature of `message`, leaked.
    pub(crate) fn sign(&self, message: &[u8]) -> &'static Signature
    {
        leak(composite::sign(&self.seed, message).unwrap())
    }
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
        root: Key::from_seed([1; SEED_LEN]),
        signer: Key::from_seed([2; SEED_LEN]),
        stranger: Key::from_seed([3; SEED_LEN]),
        second_root: Key::from_seed([4; SEED_LEN]),
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
            key: &key.public,
            usage: *usage,
            local: true,
            label: "test root",
        })
        .collect();
    specs.sort_by_key(|spec| key_id(spec.key));
    let mut revoked = revoked.to_vec();
    revoked.sort_unstable();
    let mut out = vec![0u8; TrustStore::encoded_len(specs.len(), revoked.len()).unwrap()];
    TrustStore::encode(floor, &specs, &revoked, &mut out).unwrap();
    out
}

/// The encoded certificate `issuer` issues to `subject`, leaked.
pub(crate) fn certify(
    issuer: &Key,
    subject: &'static Key,
    roles: RoleSet,
    min: u32,
    max: u32,
) -> &'static [u8; cert::LEN]
{
    certify_as(issuer, issuer.id(), subject, roles, min, max)
}

/// The encoded certificate `issuer` signs for `subject` naming
/// `issuer_key_id` as its issuer, leaked.
pub(crate) fn certify_as(
    issuer: &Key,
    issuer_key_id: KeyId,
    subject: &'static Key,
    roles: RoleSet,
    min: u32,
    max: u32,
) -> &'static [u8; cert::LEN]
{
    let body = CertificateBody {
        subject_key: &subject.public,
        issuer_key_id,
        serial: 7,
        usage: Usage {
            roles,
            certify: false,
        },
        min_security_version: min,
        max_security_version: max,
    };
    let mut signed = Box::new([0u8; cert::SIGNED_LEN]);
    body.encode_signed(&mut signed).unwrap();
    let mut out = Box::new([0u8; cert::LEN]);
    body.encode(issuer.sign(&signed[..]), &mut out).unwrap();
    Box::leak(out)
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
    certificate: Option<&'static [u8; cert::LEN]>,
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
