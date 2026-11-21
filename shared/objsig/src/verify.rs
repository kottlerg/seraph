// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/verify.rs

//! The verifier: an object passes on the first record that chains to an
//! anchor of the trust store and passes every check of the policy
//! ([docs/signing.md](../../../docs/signing.md) § Verification).

use crate::attrs::{Attributes, HASH_LEN};
use crate::cert::Certificate;
use crate::composite;
use crate::store::{Anchor, TrustStore};
use crate::trailer::{Record, split};
use crate::{Arch, ParseError, PublicKey, RoleSet, key_id};

/// What the caller expects of the object it loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expectation<'a>
{
    /// The roles the caller accepts: the record's set must hold one of
    /// them.
    pub roles: RoleSet,
    /// The slot name or install path the caller is loading.
    pub name: &'a [u8],
    /// The architecture the caller runs.
    pub arch: Arch,
}

/// An object the verifier accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified<'a, 's>
{
    /// The body: the only bytes a loader uses.
    pub body: &'a [u8],
    /// The signed attributes of the record that passed.
    pub attrs: Attributes<'a>,
    /// The anchor the record chained to.
    pub anchor: Anchor<'s>,
}

/// Why the verifier refused an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal
{
    /// The object does not parse; no record was checked.
    Parse(ParseError),
    /// No record chained to an anchor.
    Untrusted,
    /// A record chained to an anchor and failed a check: the failure of the
    /// first such record.
    Failed(RecordFailure),
}

/// The check a record that chained to an anchor failed, in the order the
/// verifier checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordFailure
{
    /// The record's certificate was issued by an anchor without `CERTIFY`.
    IssuerCannotCertify,
    /// The record's `signer_key_id` is not the key id of its certificate's
    /// subject key.
    SignerMismatch,
    /// The anchor's key id or the signing key's is revoked.
    Revoked,
    /// The signing key may not sign every role of the signed set: the
    /// anchor's usage, or with a certificate the certificate's and the
    /// anchor's, lack one.
    KeyUsage,
    /// The signed set holds no role the caller accepts.
    Role,
    /// The signed name is not the caller's.
    Name,
    /// The signed architecture is not the caller's.
    Arch,
    /// The signed `body_len` is not the body's length.
    BodyLength,
    /// The signed `body_hash` is not the body's SHA-512.
    BodyHash,
    /// The signed security version is below the store's floor.
    SecurityFloor,
    /// The signed security version is outside the certificate's range.
    SecurityRange,
    /// The certificate's composite signature does not verify under the
    /// anchor's key: either half, or both, is invalid.
    CertificateSignature,
    /// The record's composite signature does not verify under the signing
    /// key: either half, or both, is invalid.
    Signature,
}

/// Why a record did not pass.
enum Miss
{
    /// It chained to no anchor.
    Untrusted,
    /// It chained to an anchor and failed a check.
    Failed(RecordFailure),
}

/// Verify `object` against `store` and what the caller expects.
///
/// Every record is parsed first, and a parse error anywhere refuses the
/// object. The records are then checked in order, and the object passes on
/// the first that passes.
///
/// # Errors
///
/// A [`Refusal`]: the object's parse error, `Untrusted` when no record
/// chained to an anchor, or the failure of the first record that did.
pub fn verify<'a, 's>(
    object: &'a [u8],
    store: &TrustStore<'s>,
    expect: &Expectation<'_>,
) -> Result<Verified<'a, 's>, Refusal>
{
    verify_cached(object, store, expect, &mut CertificateCache::new())
}

/// [`verify`], taking a certificate's signature as verified when `cache`
/// holds the certificate under the same issuer key, and adding each
/// certificate whose signature verifies to `cache`.
///
/// A caller that verifies several objects keeps one cache across them, so the
/// certificate every object of one signer carries is verified once. The
/// result is the one [`verify`] returns: the signature check is a function
/// of the issuer key and the certificate alone, and every other check is made
/// for every record.
///
/// # Errors
///
/// As [`verify`].
pub fn verify_cached<'a, 's>(
    object: &'a [u8],
    store: &TrustStore<'s>,
    expect: &Expectation<'_>,
    cache: &mut CertificateCache,
) -> Result<Verified<'a, 's>, Refusal>
{
    let signed = split(object).map_err(Refusal::Parse)?;
    let body = signed.body();
    let hash = crypto::sha512(body);
    let mut first_failure = None;
    for record in signed.records()
    {
        match check(&record, body, &hash, store, expect, cache)
        {
            Ok(anchor) =>
            {
                return Ok(Verified {
                    body,
                    attrs: record.attrs,
                    anchor,
                });
            }
            Err(Miss::Failed(failure)) =>
            {
                first_failure.get_or_insert(failure);
            }
            Err(Miss::Untrusted) =>
            {}
        }
    }
    Err(first_failure.map_or(Refusal::Untrusted, Refusal::Failed))
}

/// Check one record; returns the anchor it chained to when it passes.
fn check<'s>(
    record: &Record<'_>,
    body: &[u8],
    hash: &[u8; HASH_LEN],
    store: &TrustStore<'s>,
    expect: &Expectation<'_>,
    cache: &mut CertificateCache,
) -> Result<Anchor<'s>, Miss>
{
    let fail = Miss::Failed;
    let attrs = &record.attrs;
    let (anchor, signing_key, usable) = match &record.certificate
    {
        None =>
        {
            let anchor = store.anchor(&record.signer_key_id).ok_or(Miss::Untrusted)?;
            (anchor, anchor.key, anchor.usage.roles)
        }
        Some(certificate) =>
        {
            let cert = &certificate.body;
            let anchor = store.anchor(&cert.issuer_key_id).ok_or(Miss::Untrusted)?;
            if !anchor.usage.certify
            {
                return Err(fail(RecordFailure::IssuerCannotCertify));
            }
            if key_id(cert.subject_key) != record.signer_key_id
            {
                return Err(fail(RecordFailure::SignerMismatch));
            }
            (
                anchor,
                cert.subject_key,
                cert.usage.roles.intersection(anchor.usage.roles),
            )
        }
    };
    // Without a certificate the signing key is the anchor, so its id is the
    // anchor's; with one, signer_key_id was checked against the subject key.
    if store.is_revoked(&anchor.key_id) || store.is_revoked(&record.signer_key_id)
    {
        return Err(fail(RecordFailure::Revoked));
    }
    if !attrs.roles.is_subset(usable)
    {
        return Err(fail(RecordFailure::KeyUsage));
    }
    if !attrs.roles.meets(expect.roles)
    {
        return Err(fail(RecordFailure::Role));
    }
    if attrs.name != expect.name
    {
        return Err(fail(RecordFailure::Name));
    }
    if attrs.arch != expect.arch
    {
        return Err(fail(RecordFailure::Arch));
    }
    if u64::try_from(body.len()) != Ok(attrs.body_len)
    {
        return Err(fail(RecordFailure::BodyLength));
    }
    if attrs.body_hash != *hash
    {
        return Err(fail(RecordFailure::BodyHash));
    }
    if attrs.security_version < store.security_floor()
    {
        return Err(fail(RecordFailure::SecurityFloor));
    }
    if let Some(certificate) = &record.certificate
    {
        if !certificate.body.allows(attrs.security_version)
        {
            return Err(fail(RecordFailure::SecurityRange));
        }
        if !cache.verify(anchor.key, certificate)
        {
            return Err(fail(RecordFailure::CertificateSignature));
        }
    }
    composite::verify(signing_key, record.signed, record.signature)
        .map_err(|_| fail(RecordFailure::Signature))?;
    Ok(anchor)
}

/// How many certificates a [`CertificateCache`] holds.
pub const CERTIFICATE_CACHE_LEN: usize = 4;

/// Certificates whose signature has verified, each with the issuer key it
/// verified under ([`verify_cached`]).
///
/// It holds [`CERTIFICATE_CACHE_LEN`] entries, the oldest replaced first.
/// An entry is the SHA-512 of the issuer key followed by the certificate's
/// encoding, 64 bytes, so the cache holds no copy of a 1,984-byte key or a
/// 5,409-byte certificate. An entry matches only the same issuer key and the
/// same certificate, signed bytes and signature, unless SHA-512 collides, on
/// which every signature already rests. It holds no trust decision: the
/// anchor, `CERTIFY`, revocation, usage and range checks are made for every
/// record.
#[derive(Clone, Copy, Debug)]
pub struct CertificateCache
{
    entries: [Option<[u8; HASH_LEN]>; CERTIFICATE_CACHE_LEN],
    next: usize,
}

impl CertificateCache
{
    /// An empty cache.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: [None; CERTIFICATE_CACHE_LEN],
            next: 0,
        }
    }

    /// Whether `certificate`'s signature verifies under `issuer_key`: true
    /// at once for a pair the cache holds; otherwise verified, and held when
    /// it verifies.
    fn verify(&mut self, issuer_key: &PublicKey, certificate: &Certificate<'_>) -> bool
    {
        let entry = Some(Self::entry(issuer_key, certificate));
        if self.entries.contains(&entry)
        {
            return true;
        }
        if composite::verify(issuer_key, certificate.signed(), certificate.signature).is_err()
        {
            return false;
        }
        if let Some(slot) = self.entries.get_mut(self.next)
        {
            *slot = entry;
        }
        self.next = self.next.wrapping_add(1) % CERTIFICATE_CACHE_LEN;
        true
    }
}

impl CertificateCache
{
    /// The entry of `certificate` under `issuer_key`: the SHA-512 of the key
    /// followed by the certificate's encoding.
    fn entry(issuer_key: &PublicKey, certificate: &Certificate<'_>) -> [u8; HASH_LEN]
    {
        let mut state = crypto::Sha512::new();
        state.update(issuer_key);
        state.update(certificate.as_bytes());
        state.finalize()
    }
}

impl Default for CertificateCache
{
    fn default() -> Self
    {
        Self::new()
    }
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use crate::testutil::{ROOT, attrs, certify, certify_as, keys, leak, object, record, store};
    use crate::trailer::RecordSpec;
    use crate::{Role, Usage};
    use crypto_testkit::rng::Rng;

    const BODY: &[u8] = b"\x7fELF the body of a service image, any bytes at all";
    const NAME: &[u8] = b"/services/svcmgr";

    const EXPECT: Expectation<'static> = Expectation {
        roles: RoleSet::of(&[Role::Service]),
        name: NAME,
        arch: Arch::X86_64,
    };

    /// The store that trusts the root alone, floor 0.
    fn root_store() -> Vec<u8>
    {
        store(0, &[(&keys().root, ROOT)], &[])
    }

    /// A service record signed by the root directly.
    fn direct(security_version: u32) -> RecordSpec<'static>
    {
        record(
            &keys().root,
            None,
            attrs(BODY, &[Role::Service], NAME, security_version),
        )
    }

    /// A service record signed by the signing key, certified by the root
    /// for services and drivers at security versions 2 to 5.
    fn certified(security_version: u32) -> RecordSpec<'static>
    {
        let k = keys();
        let cert = certify(
            &k.root,
            &k.signer,
            RoleSet::of(&[Role::Service, Role::Driver]),
            2,
            5,
        );
        record(
            &k.signer,
            Some(cert),
            attrs(BODY, &[Role::Service], NAME, security_version),
        )
    }

    /// A service record signed by a root no store trusts.
    fn stranger() -> RecordSpec<'static>
    {
        record(
            &keys().stranger,
            None,
            attrs(BODY, &[Role::Service], NAME, 3),
        )
    }

    fn run(
        store_bytes: &[u8],
        records: &[RecordSpec<'_>],
        expect: &Expectation<'_>,
    ) -> Result<(), Refusal>
    {
        let store = TrustStore::parse(store_bytes).unwrap();
        let bytes = object(BODY, records);
        verify(&bytes, &store, expect).map(|verified| {
            assert_eq!(verified.body, BODY);
            assert_eq!(verified.anchor.key, &keys().root.public);
        })
    }

    fn failed(failure: RecordFailure) -> Result<(), Refusal>
    {
        Err(Refusal::Failed(failure))
    }

    #[test]
    fn passes_a_record_of_a_root()
    {
        let store_bytes = root_store();
        let store = TrustStore::parse(&store_bytes).unwrap();
        let bytes = object(BODY, &[direct(3)]);
        let verified = verify(&bytes, &store, &EXPECT).unwrap();
        assert_eq!(verified.body, BODY);
        assert_eq!(verified.attrs, direct(3).attrs);
        assert_eq!(verified.anchor.key_id, keys().root.id());
    }

    #[test]
    fn passes_a_record_of_a_certified_key()
    {
        assert_eq!(run(&root_store(), &[certified(2)], &EXPECT), Ok(()));
        assert_eq!(run(&root_store(), &[certified(5)], &EXPECT), Ok(()));
    }

    #[test]
    fn passes_on_any_one_record()
    {
        let root = root_store();
        assert_eq!(run(&root, &[stranger(), direct(3)], &EXPECT), Ok(()));
        let wrong_name = record(&keys().root, None, attrs(BODY, &[Role::Service], b"/x", 3));
        assert_eq!(
            run(&root, &[wrong_name, stranger(), certified(3)], &EXPECT),
            Ok(())
        );
        // A second trusted root: either record passes alone.
        let both = store(0, &[(&keys().root, ROOT), (&keys().second_root, ROOT)], &[]);
        let second = record(
            &keys().second_root,
            None,
            attrs(BODY, &[Role::Service], NAME, 3),
        );
        let store_view = TrustStore::parse(&both).unwrap();
        let bytes = object(BODY, &[second]);
        let verified = verify(&bytes, &store_view, &EXPECT).unwrap();
        assert_eq!(verified.anchor.key, &keys().second_root.public);
    }

    #[test]
    fn refuses_records_of_untrusted_roots()
    {
        assert_eq!(
            run(&root_store(), &[stranger()], &EXPECT),
            Err(Refusal::Untrusted)
        );
        let k = keys();
        let cert = certify(&k.stranger, &k.signer, RoleSet::ALL, 0, 9);
        let by_stranger = record(
            &k.signer,
            Some(cert),
            attrs(BODY, &[Role::Service], NAME, 3),
        );
        assert_eq!(
            run(&root_store(), &[stranger(), by_stranger], &EXPECT),
            Err(Refusal::Untrusted)
        );
    }

    #[test]
    fn reports_the_first_trusted_failure()
    {
        let store = root_store();
        let wrong_name = record(&keys().root, None, attrs(BODY, &[Role::Service], b"/x", 3));
        let wrong_role = record(&keys().root, None, attrs(BODY, &[Role::Driver], NAME, 3));
        assert_eq!(
            run(&store, &[stranger(), wrong_name, wrong_role], &EXPECT),
            failed(RecordFailure::Name)
        );
        assert_eq!(
            run(&store, &[wrong_role, stranger(), wrong_name], &EXPECT),
            failed(RecordFailure::Role)
        );
    }

    #[test]
    fn refuses_a_certificate_of_a_root_without_certify()
    {
        let usage = Usage {
            roles: RoleSet::ALL,
            certify: false,
        };
        let store_bytes = store(0, &[(&keys().root, usage)], &[]);
        assert_eq!(run(&store_bytes, &[direct(3)], &EXPECT), Ok(()));
        assert_eq!(
            run(&store_bytes, &[certified(3)], &EXPECT),
            failed(RecordFailure::IssuerCannotCertify)
        );
    }

    #[test]
    fn refuses_a_signer_id_other_than_the_subject_key()
    {
        let mut spec = certified(3);
        spec.signer_key_id = keys().root.id();
        assert_eq!(
            run(&root_store(), &[spec], &EXPECT),
            failed(RecordFailure::SignerMismatch)
        );
    }

    #[test]
    fn refuses_a_revoked_root_or_signing_key()
    {
        let k = keys();
        let revoked_root = store(0, &[(&k.root, ROOT)], &[k.root.id()]);
        assert_eq!(
            run(&revoked_root, &[direct(3)], &EXPECT),
            failed(RecordFailure::Revoked)
        );
        assert_eq!(
            run(&revoked_root, &[certified(3)], &EXPECT),
            failed(RecordFailure::Revoked)
        );
        let revoked_signer = store(0, &[(&k.root, ROOT)], &[k.signer.id(), [0xff; 16]]);
        assert_eq!(run(&revoked_signer, &[direct(3)], &EXPECT), Ok(()));
        assert_eq!(
            run(&revoked_signer, &[certified(3)], &EXPECT),
            failed(RecordFailure::Revoked)
        );
    }

    #[test]
    fn refuses_a_role_the_key_may_not_sign()
    {
        let k = keys();
        let programs_only = Usage {
            roles: RoleSet::of(&[Role::Program]),
            certify: true,
        };
        let narrow = store(0, &[(&k.root, programs_only)], &[]);
        assert_eq!(
            run(&narrow, &[direct(3)], &EXPECT),
            failed(RecordFailure::KeyUsage)
        );
        // The certificate allows services, but its issuer does not.
        assert_eq!(
            run(&narrow, &[certified(3)], &EXPECT),
            failed(RecordFailure::KeyUsage)
        );
        // The issuer allows services, but the certificate does not.
        let drivers = certify(&k.root, &k.signer, RoleSet::of(&[Role::Driver]), 0, 9);
        let spec = record(
            &k.signer,
            Some(drivers),
            attrs(BODY, &[Role::Service], NAME, 3),
        );
        assert_eq!(
            run(&root_store(), &[spec], &EXPECT),
            failed(RecordFailure::KeyUsage)
        );
    }

    #[test]
    fn refuses_what_the_caller_does_not_expect()
    {
        let store = root_store();
        let drivers = Expectation {
            roles: RoleSet::of(&[Role::Driver, Role::Program]),
            ..EXPECT
        };
        assert_eq!(
            run(&store, &[direct(3)], &drivers),
            failed(RecordFailure::Role)
        );
        let other_name = Expectation {
            name: b"/services/svcmgr2",
            ..EXPECT
        };
        assert_eq!(
            run(&store, &[direct(3)], &other_name),
            failed(RecordFailure::Name)
        );
        let riscv = Expectation {
            arch: Arch::Riscv64,
            ..EXPECT
        };
        assert_eq!(
            run(&store, &[direct(3)], &riscv),
            failed(RecordFailure::Arch)
        );
    }

    /// A record of several roles needs every one in the key's usage: one
    /// role the key may not sign refuses it, whichever role the caller
    /// asks for.
    #[test]
    fn refuses_a_set_one_role_of_which_the_key_may_not_sign()
    {
        let k = keys();
        let both = &[Role::Service, Role::BootModule];
        let services = Usage {
            roles: RoleSet::of(&[Role::Service]),
            certify: true,
        };
        let narrow = store(0, &[(&k.root, services)], &[]);
        let spec = record(&k.root, None, attrs(BODY, both, NAME, 3));
        assert_eq!(
            run(&narrow, &[spec], &EXPECT),
            failed(RecordFailure::KeyUsage)
        );
        assert_eq!(run(&root_store(), &[spec], &EXPECT), Ok(()));
        // The certificate allows services and drivers, not boot modules.
        let cert = certify(
            &k.root,
            &k.signer,
            RoleSet::of(&[Role::Service, Role::Driver]),
            0,
            9,
        );
        let spec = record(&k.signer, Some(cert), attrs(BODY, both, NAME, 3));
        assert_eq!(
            run(&root_store(), &[spec], &EXPECT),
            failed(RecordFailure::KeyUsage)
        );
    }

    /// A record of several roles passes for a caller whose set meets its
    /// own, in any one of them, and only for such a caller.
    #[test]
    fn accepts_a_caller_whose_set_meets_the_records()
    {
        let spec = record(
            &keys().root,
            None,
            attrs(BODY, &[Role::Service, Role::BootModule], NAME, 3),
        );
        for accepted in [
            &[Role::Service][..],
            &[Role::BootModule],
            &[Role::Driver, Role::Service],
            &[Role::Service, Role::BootModule],
        ]
        {
            let expect = Expectation {
                roles: RoleSet::of(accepted),
                ..EXPECT
            };
            assert_eq!(run(&root_store(), &[spec], &expect), Ok(()), "{accepted:?}");
        }
        for refused in [&[Role::Driver, Role::Program][..], &[Role::Init], &[]]
        {
            let expect = Expectation {
                roles: RoleSet::of(refused),
                ..EXPECT
            };
            assert_eq!(
                run(&root_store(), &[spec], &expect),
                failed(RecordFailure::Role),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn refuses_a_record_of_another_body()
    {
        let k = keys();
        let mut longer = attrs(BODY, &[Role::Service], NAME, 3);
        longer.body_len += 1;
        assert_eq!(
            run(&root_store(), &[record(&k.root, None, longer)], &EXPECT),
            failed(RecordFailure::BodyLength)
        );
        let mut other = BODY.to_vec();
        other[0] ^= 1;
        let spec = record(&k.root, None, attrs(&other, &[Role::Service], NAME, 3));
        assert_eq!(
            run(&root_store(), &[spec], &EXPECT),
            failed(RecordFailure::BodyHash)
        );
    }

    #[test]
    fn refuses_a_security_version_out_of_bounds()
    {
        let k = keys();
        let floor_4 = store(4, &[(&k.root, ROOT)], &[]);
        assert_eq!(
            run(&floor_4, &[direct(3)], &EXPECT),
            failed(RecordFailure::SecurityFloor)
        );
        assert_eq!(run(&floor_4, &[direct(4)], &EXPECT), Ok(()));
        assert_eq!(
            run(&floor_4, &[certified(3)], &EXPECT),
            failed(RecordFailure::SecurityFloor)
        );
        assert_eq!(
            run(&root_store(), &[certified(1)], &EXPECT),
            failed(RecordFailure::SecurityRange)
        );
        assert_eq!(
            run(&root_store(), &[certified(6)], &EXPECT),
            failed(RecordFailure::SecurityRange)
        );
    }

    #[test]
    fn refuses_a_bad_certificate_signature()
    {
        let k = keys();
        let tampered = with_certificate_byte_flipped(certified(3), 0);
        assert_eq!(
            run(&root_store(), &[tampered], &EXPECT),
            failed(RecordFailure::CertificateSignature)
        );
        // A certificate the stranger signed that names the root as issuer.
        let forged = certify_as(&k.stranger, k.root.id(), &k.signer, RoleSet::ALL, 0, 9);
        let spec = record(
            &k.signer,
            Some(forged),
            attrs(BODY, &[Role::Service], NAME, 3),
        );
        assert_eq!(
            run(&root_store(), &[spec], &EXPECT),
            failed(RecordFailure::CertificateSignature)
        );
    }

    /// The cache entry of the certificate of a record that passes, under
    /// the root's key.
    fn held(security_version: u32) -> [u8; HASH_LEN]
    {
        let cert = Certificate::parse(certified(security_version).certificate.unwrap()).unwrap();
        CertificateCache::entry(&keys().root.public, &cert)
    }

    /// The record of `spec` with its certificate's signature byte `at`
    /// flipped.
    fn with_certificate_byte_flipped(spec: RecordSpec<'static>, at: usize) -> RecordSpec<'static>
    {
        let mut cert = *spec.certificate.unwrap();
        cert[crate::cert::SIGNED_LEN + at] ^= 1;
        RecordSpec {
            certificate: Some(leak(cert)),
            ..spec
        }
    }

    #[test]
    fn a_cache_holds_each_certificate_that_verifies_and_only_those()
    {
        let store_bytes = root_store();
        let store = TrustStore::parse(&store_bytes).unwrap();
        let mut cache = CertificateCache::new();
        let bytes = object(BODY, &[certified(3)]);
        verify_cached(&bytes, &store, &EXPECT, &mut cache).unwrap();
        assert_eq!(cache.entries[0], Some(held(3)));
        // The same certificate with another signature is no match, and is
        // refused and not held.
        let tampered = with_certificate_byte_flipped(certified(3), 0);
        let bytes = object(BODY, &[tampered]);
        assert_eq!(
            verify_cached(&bytes, &store, &EXPECT, &mut cache).map(|_| ()),
            failed(RecordFailure::CertificateSignature)
        );
        assert_eq!(cache.entries[1], None);
        // The held certificate under another issuer key is no match.
        let cert = Certificate::parse(certified(3).certificate.unwrap()).unwrap();
        assert!(!cache.verify(&keys().second_root.public, &cert));
        assert!(cache.verify(&keys().root.public, &cert));
    }

    #[test]
    fn a_held_certificate_is_not_verified_again()
    {
        let store_bytes = root_store();
        let store = TrustStore::parse(&store_bytes).unwrap();
        let tampered = with_certificate_byte_flipped(certified(3), 0);
        let bytes = object(BODY, &[tampered]);
        // A cache that holds the pair answers for it without the signature
        // check, which this signature would fail.
        let mut cache = CertificateCache::new();
        let cert = Certificate::parse(tampered.certificate.unwrap()).unwrap();
        cache.entries[0] = Some(CertificateCache::entry(&keys().root.public, &cert));
        verify_cached(&bytes, &store, &EXPECT, &mut cache).unwrap();
        assert_eq!(
            verify(&bytes, &store, &EXPECT).map(|_| ()),
            failed(RecordFailure::CertificateSignature)
        );
    }

    #[test]
    fn a_full_cache_replaces_its_oldest_certificate()
    {
        let k = keys();
        let issued: Vec<Certificate<'_>> = (9u32..)
            .take(CERTIFICATE_CACHE_LEN + 1)
            .map(|max| {
                Certificate::parse(certify(&k.root, &k.signer, RoleSet::ALL, 0, max)).unwrap()
            })
            .collect();
        let mut cache = CertificateCache::new();
        for cert in &issued
        {
            assert!(cache.verify(&k.root.public, cert));
        }
        let entry = |cert| CertificateCache::entry(&k.root.public, cert);
        let held: Vec<_> = cache.entries.iter().flatten().copied().collect();
        assert_eq!(held.len(), CERTIFICATE_CACHE_LEN);
        assert!(!held.contains(&entry(&issued[0])));
        assert!(issued[1..].iter().all(|cert| held.contains(&entry(cert))));
    }

    /// The refusal test of a record's composite signature: a record whose
    /// signature has either half invalid, the other half valid, is refused.
    #[test]
    fn refuses_a_record_signature_with_either_half_invalid()
    {
        for at in [0, 63, 64, 64 + 1700, crate::trailer::SIGNATURE_LEN - 1]
        {
            for spec in [direct(3), certified(3)]
            {
                let mut signature = *spec.signature;
                signature[at] ^= 0x10;
                let tampered = RecordSpec {
                    signature: leak(signature),
                    ..spec
                };
                assert_eq!(
                    run(&root_store(), &[tampered], &EXPECT),
                    failed(RecordFailure::Signature),
                    "byte {at}"
                );
            }
        }
    }

    /// The refusal test of a certificate's composite signature: a record
    /// whose certificate's signature has either half invalid, the other half
    /// valid, is refused.
    #[test]
    fn refuses_a_certificate_signature_with_either_half_invalid()
    {
        for at in [0, 63, 64, 64 + 1700, crate::trailer::SIGNATURE_LEN - 1]
        {
            let tampered = with_certificate_byte_flipped(certified(3), at);
            assert_eq!(
                run(&root_store(), &[tampered], &EXPECT),
                failed(RecordFailure::CertificateSignature),
                "byte {at}"
            );
        }
    }

    #[test]
    fn refuses_a_bad_record_signature()
    {
        let k = keys();
        // The stranger's signature under the root's key id.
        let mut forged = stranger();
        forged.signer_key_id = k.root.id();
        assert_eq!(
            run(&root_store(), &[forged], &EXPECT),
            failed(RecordFailure::Signature)
        );
        // A record whose signature covers other attributes.
        let mut swapped = direct(3);
        swapped.signature = direct(4).signature;
        assert_eq!(
            run(&root_store(), &[swapped], &EXPECT),
            failed(RecordFailure::Signature)
        );
    }

    #[test]
    fn refuses_a_parse_error_beside_a_valid_record()
    {
        let store_bytes = root_store();
        let store = TrustStore::parse(&store_bytes).unwrap();
        let mut bytes = object(BODY, &[direct(3), stranger()]);
        // The second record's algorithm byte.
        let second = BODY.len()
            + usize::try_from(u32::from_le_bytes(
                bytes[BODY.len()..BODY.len() + 4].try_into().unwrap(),
            ))
            .unwrap();
        bytes[second + 4] = 1;
        assert_eq!(
            verify(&bytes, &store, &EXPECT),
            Err(Refusal::Parse(ParseError::Algorithm))
        );
        let mut bytes = object(BODY, &[direct(3)]);
        let end = bytes.len();
        bytes[end - 10] = 1;
        assert_eq!(
            verify(&bytes, &store, &EXPECT),
            Err(Refusal::Parse(ParseError::Version))
        );
        assert_eq!(
            verify(BODY, &store, &EXPECT),
            Err(Refusal::Parse(ParseError::Magic))
        );
    }

    /// Every bit of a signed object is bound: a flip anywhere refuses it.
    /// Each bit of the body, the record's fixed fields, its attributes, its
    /// certificate's fields and the footer is flipped. In the 1,984-byte
    /// subject key and the two 3,373-byte signatures, which the signature
    /// scheme binds rather than the format, one bit of the first and last
    /// byte and of every 61st byte between, the bit varying from byte to
    /// byte: one flip of each byte would be some 8,700 more composite
    /// verifications, minutes under the riscv64 test emulator. The
    /// either-half refusal tests cover both halves of both signatures.
    #[test]
    fn refuses_every_bit_flip()
    {
        let store_bytes = root_store();
        let store = TrustStore::parse(&store_bytes).unwrap();
        let good = object(BODY, &[certified(3)]);
        verify(&good, &store, &EXPECT).unwrap();
        let record = BODY.len();
        let cert = record + 24 + crate::attrs::FIXED_LEN + NAME.len();
        let key = cert + 16..cert + 16 + crate::composite::PUBLIC_KEY_LEN;
        let cert_signature = cert + crate::cert::SIGNED_LEN..cert + crate::cert::LEN;
        let signature = cert + crate::cert::LEN..good.len() - 16;
        for index in 0..good.len()
        {
            let sampled = [&key, &cert_signature, &signature]
                .into_iter()
                .find(|region| region.contains(&index));
            if let Some(region) = sampled
                && index != region.start
                && index != region.end - 1
                && (index - region.start) % 61 != 0
            {
                continue;
            }
            for bit in 0..8
            {
                if sampled.is_some() && bit != index % 8
                {
                    continue;
                }
                let mut bytes = good.clone();
                bytes[index] ^= 1 << bit;
                verify(&bytes, &store, &EXPECT).expect_err("a flipped bit verified");
            }
        }
    }

    /// The parsers are total: arbitrary and mutated inputs are refused or
    /// parsed, never a panic. A mutated object of one trusted record never
    /// verifies; one that also carries an untrusted record may, since nothing
    /// binds the bytes of a record no anchor vouches for.
    #[test]
    fn parsers_take_arbitrary_input()
    {
        let store_bytes = root_store();
        let store = TrustStore::parse(&store_bytes).unwrap();
        let single = object(BODY, &[certified(3)]);
        let pair = object(BODY, &[stranger(), certified(3)]);
        let mut rng = Rng::new(0x0b75_1960);
        for round in 0..4000
        {
            let good = if round % 2 == 0 { &single } else { &pair };
            let mut bytes = good.clone();
            for _ in 0..=rng.below(4)
            {
                match rng.below(4)
                {
                    0 => bytes.truncate(rng.below(bytes.len() + 1)),
                    1 => bytes.insert(rng.below(bytes.len() + 1), rng.array::<1>()[0]),
                    _ if !bytes.is_empty() =>
                    {
                        let index = rng.below(bytes.len());
                        bytes[index] = rng.array::<1>()[0];
                    }
                    _ =>
                    {}
                }
            }
            let verdict = verify(&bytes, &store, &EXPECT);
            if good == &single && bytes != single
            {
                verdict.expect_err("a mutated object verified");
            }
            let _ = split(&bytes);
            let _ = TrustStore::parse(&bytes);
            let _ = Attributes::parse(&bytes);
            let mut mutated_store = store_bytes.clone();
            let index = rng.below(mutated_store.len());
            mutated_store[index] = rng.array::<1>()[0];
            let _ = TrustStore::parse(&mutated_store);
            let noise_len = rng.below(512);
            let noise = rng.bytes(noise_len);
            verify(&noise, &store, &EXPECT).expect_err("noise verified");
            let _ = TrustStore::parse(&noise);
            let _ = Attributes::parse(&noise);
        }
    }
}
