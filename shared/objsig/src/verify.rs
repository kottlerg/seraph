// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/verify.rs

//! The verifier: an object passes on the first record that chains to an
//! anchor of the trust store and passes every check of the policy
//! ([docs/signing.md](../../../docs/signing.md) § Verification).

use crypto::ed25519_verify;

use crate::attrs::{Attributes, HASH_LEN};
use crate::store::{Anchor, TrustStore};
use crate::trailer::{Record, split};
use crate::{Arch, KindSet, ParseError, key_id};

/// What the caller expects of the object it loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expectation<'a>
{
    /// The kinds the caller accepts.
    pub kinds: KindSet,
    /// The bundle entry name or install path the caller is loading.
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
    /// The signing key may not sign the signed kind: the anchor's usage, or
    /// with a certificate the certificate's and the anchor's, lack it.
    KeyUsage,
    /// The caller does not accept the signed kind.
    Kind,
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
    /// The certificate's signature does not verify under the anchor's key.
    CertificateSignature,
    /// The record's signature does not verify under the signing key.
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
    let signed = split(object).map_err(Refusal::Parse)?;
    let body = signed.body();
    let hash = crypto::sha512(body);
    let mut first_failure = None;
    for record in signed.records()
    {
        match check(&record, body, &hash, store, expect)
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
) -> Result<Anchor<'s>, Miss>
{
    let fail = Miss::Failed;
    let attrs = &record.attrs;
    let (anchor, signing_key, kinds) = match &record.certificate
    {
        None =>
        {
            let anchor = store.anchor(&record.signer_key_id).ok_or(Miss::Untrusted)?;
            (anchor, anchor.key, anchor.usage.kinds)
        }
        Some(certificate) =>
        {
            let cert = &certificate.body;
            let anchor = store.anchor(&cert.issuer_key_id).ok_or(Miss::Untrusted)?;
            if !anchor.usage.certify
            {
                return Err(fail(RecordFailure::IssuerCannotCertify));
            }
            if key_id(&cert.subject_key) != record.signer_key_id
            {
                return Err(fail(RecordFailure::SignerMismatch));
            }
            (
                anchor,
                cert.subject_key,
                cert.usage.kinds.intersection(anchor.usage.kinds),
            )
        }
    };
    // Without a certificate the signing key is the anchor, so its id is the
    // anchor's; with one, signer_key_id was checked against the subject key.
    if store.is_revoked(&anchor.key_id) || store.is_revoked(&record.signer_key_id)
    {
        return Err(fail(RecordFailure::Revoked));
    }
    if !kinds.contains(attrs.kind)
    {
        return Err(fail(RecordFailure::KeyUsage));
    }
    if !expect.kinds.contains(attrs.kind)
    {
        return Err(fail(RecordFailure::Kind));
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
        ed25519_verify(
            &anchor.key,
            &certificate.body.to_signed(),
            &certificate.signature,
        )
        .map_err(|_| fail(RecordFailure::CertificateSignature))?;
    }
    ed25519_verify(&signing_key, record.signed, &record.signature)
        .map_err(|_| fail(RecordFailure::Signature))?;
    Ok(anchor)
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use crate::testutil::{ROOT, attrs, certify, keys, object, record, store};
    use crate::trailer::RecordSpec;
    use crate::{Kind, Usage};
    use crypto_testkit::rng::Rng;

    const BODY: &[u8] = b"\x7fELF the body of a service image, any bytes at all";
    const NAME: &[u8] = b"/services/svcmgr";

    const EXPECT: Expectation<'static> = Expectation {
        kinds: KindSet::of(&[Kind::Service]),
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
        record(&keys().root, None, attrs(BODY, Kind::Service, NAME, security_version))
    }

    /// A service record signed by the signing key, certified by the root
    /// for services and drivers at security versions 2 to 5.
    fn certified(security_version: u32) -> RecordSpec<'static>
    {
        let k = keys();
        let cert = certify(&k.root, &k.signer, KindSet::of(&[Kind::Service, Kind::Driver]), 2, 5);
        record(&k.signer, Some(cert), attrs(BODY, Kind::Service, NAME, security_version))
    }

    /// A service record signed by a root no store trusts.
    fn stranger() -> RecordSpec<'static>
    {
        record(&keys().stranger, None, attrs(BODY, Kind::Service, NAME, 3))
    }

    fn run(store_bytes: &[u8], records: &[RecordSpec<'_>], expect: &Expectation<'_>) -> Result<(), Refusal>
    {
        let store = TrustStore::parse(store_bytes).unwrap();
        let bytes = object(BODY, records);
        verify(&bytes, &store, expect).map(|verified| {
            assert_eq!(verified.body, BODY);
            assert_eq!(verified.anchor.key, keys().root.public);
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
        let wrong_name = record(&keys().root, None, attrs(BODY, Kind::Service, b"/x", 3));
        assert_eq!(run(&root, &[wrong_name, stranger(), certified(3)], &EXPECT), Ok(()));
        // A second trusted root: either record passes alone.
        let both = store(0, &[(&keys().root, ROOT), (&keys().second_root, ROOT)], &[]);
        let second = record(&keys().second_root, None, attrs(BODY, Kind::Service, NAME, 3));
        let store_view = TrustStore::parse(&both).unwrap();
        let bytes = object(BODY, &[second]);
        let verified = verify(&bytes, &store_view, &EXPECT).unwrap();
        assert_eq!(verified.anchor.key, keys().second_root.public);
    }

    #[test]
    fn refuses_records_of_untrusted_roots()
    {
        assert_eq!(run(&root_store(), &[stranger()], &EXPECT), Err(Refusal::Untrusted));
        let k = keys();
        let cert = certify(&k.stranger, &k.signer, KindSet::ALL, 0, 9);
        let by_stranger = record(&k.signer, Some(cert), attrs(BODY, Kind::Service, NAME, 3));
        assert_eq!(
            run(&root_store(), &[stranger(), by_stranger], &EXPECT),
            Err(Refusal::Untrusted)
        );
    }

    #[test]
    fn reports_the_first_trusted_failure()
    {
        let store = root_store();
        let wrong_name = record(&keys().root, None, attrs(BODY, Kind::Service, b"/x", 3));
        let wrong_kind = record(&keys().root, None, attrs(BODY, Kind::Driver, NAME, 3));
        assert_eq!(
            run(&store, &[stranger(), wrong_name, wrong_kind], &EXPECT),
            failed(RecordFailure::Name)
        );
        assert_eq!(
            run(&store, &[wrong_kind, stranger(), wrong_name], &EXPECT),
            failed(RecordFailure::Kind)
        );
    }

    #[test]
    fn refuses_a_certificate_of_a_root_without_certify()
    {
        let usage = Usage {
            kinds: KindSet::ALL,
            certify: false,
        };
        let store_bytes = store(0, &[(&keys().root, usage)], &[]);
        assert_eq!(run(&store_bytes, &[direct(3)], &EXPECT), Ok(()));
        assert_eq!(run(&store_bytes, &[certified(3)], &EXPECT), failed(RecordFailure::IssuerCannotCertify));
    }

    #[test]
    fn refuses_a_signer_id_other_than_the_subject_key()
    {
        let mut spec = certified(3);
        spec.signer_key_id = keys().root.id();
        assert_eq!(run(&root_store(), &[spec], &EXPECT), failed(RecordFailure::SignerMismatch));
    }

    #[test]
    fn refuses_a_revoked_root_or_signing_key()
    {
        let k = keys();
        let revoked_root = store(0, &[(&k.root, ROOT)], &[k.root.id()]);
        assert_eq!(run(&revoked_root, &[direct(3)], &EXPECT), failed(RecordFailure::Revoked));
        assert_eq!(run(&revoked_root, &[certified(3)], &EXPECT), failed(RecordFailure::Revoked));
        let revoked_signer = store(0, &[(&k.root, ROOT)], &[k.signer.id(), [0xff; 16]]);
        assert_eq!(run(&revoked_signer, &[direct(3)], &EXPECT), Ok(()));
        assert_eq!(run(&revoked_signer, &[certified(3)], &EXPECT), failed(RecordFailure::Revoked));
    }

    #[test]
    fn refuses_a_kind_the_key_may_not_sign()
    {
        let k = keys();
        let programs_only = Usage {
            kinds: KindSet::of(&[Kind::Program]),
            certify: true,
        };
        let narrow = store(0, &[(&k.root, programs_only)], &[]);
        assert_eq!(run(&narrow, &[direct(3)], &EXPECT), failed(RecordFailure::KeyUsage));
        // The certificate allows services, but its issuer does not.
        assert_eq!(run(&narrow, &[certified(3)], &EXPECT), failed(RecordFailure::KeyUsage));
        // The issuer allows services, but the certificate does not.
        let drivers = certify(&k.root, &k.signer, KindSet::of(&[Kind::Driver]), 0, 9);
        let spec = record(&k.signer, Some(drivers), attrs(BODY, Kind::Service, NAME, 3));
        assert_eq!(run(&root_store(), &[spec], &EXPECT), failed(RecordFailure::KeyUsage));
    }

    #[test]
    fn refuses_what_the_caller_does_not_expect()
    {
        let store = root_store();
        let drivers = Expectation {
            kinds: KindSet::of(&[Kind::Driver, Kind::Program]),
            ..EXPECT
        };
        assert_eq!(run(&store, &[direct(3)], &drivers), failed(RecordFailure::Kind));
        let other_name = Expectation {
            name: b"/services/svcmgr2",
            ..EXPECT
        };
        assert_eq!(run(&store, &[direct(3)], &other_name), failed(RecordFailure::Name));
        let riscv = Expectation {
            arch: Arch::Riscv64,
            ..EXPECT
        };
        assert_eq!(run(&store, &[direct(3)], &riscv), failed(RecordFailure::Arch));
    }

    #[test]
    fn refuses_a_record_of_another_body()
    {
        let k = keys();
        let mut longer = attrs(BODY, Kind::Service, NAME, 3);
        longer.body_len += 1;
        assert_eq!(
            run(&root_store(), &[record(&k.root, None, longer)], &EXPECT),
            failed(RecordFailure::BodyLength)
        );
        let mut other = BODY.to_vec();
        other[0] ^= 1;
        let spec = record(&k.root, None, attrs(&other, Kind::Service, NAME, 3));
        assert_eq!(run(&root_store(), &[spec], &EXPECT), failed(RecordFailure::BodyHash));
    }

    #[test]
    fn refuses_a_security_version_out_of_bounds()
    {
        let k = keys();
        let floor_4 = store(4, &[(&k.root, ROOT)], &[]);
        assert_eq!(run(&floor_4, &[direct(3)], &EXPECT), failed(RecordFailure::SecurityFloor));
        assert_eq!(run(&floor_4, &[direct(4)], &EXPECT), Ok(()));
        assert_eq!(run(&floor_4, &[certified(3)], &EXPECT), failed(RecordFailure::SecurityFloor));
        assert_eq!(run(&root_store(), &[certified(1)], &EXPECT), failed(RecordFailure::SecurityRange));
        assert_eq!(run(&root_store(), &[certified(6)], &EXPECT), failed(RecordFailure::SecurityRange));
    }

    #[test]
    fn refuses_a_bad_certificate_signature()
    {
        let k = keys();
        let mut tampered = certified(3);
        if let Some(cert) = tampered.certificate.as_mut()
        {
            cert.signature[0] ^= 1;
        }
        assert_eq!(run(&root_store(), &[tampered], &EXPECT), failed(RecordFailure::CertificateSignature));
        // A certificate the stranger signed that names the root as issuer.
        let mut forged = certify(&k.stranger, &k.signer, KindSet::ALL, 0, 9);
        forged.body.issuer_key_id = k.root.id();
        let spec = record(&k.signer, Some(forged), attrs(BODY, Kind::Service, NAME, 3));
        assert_eq!(run(&root_store(), &[spec], &EXPECT), failed(RecordFailure::CertificateSignature));
    }

    #[test]
    fn refuses_a_bad_record_signature()
    {
        let k = keys();
        let mut tampered = direct(3);
        tampered.signature[63] ^= 0x10;
        assert_eq!(run(&root_store(), &[tampered], &EXPECT), failed(RecordFailure::Signature));
        // The stranger's signature under the root's key id.
        let mut forged = stranger();
        forged.signer_key_id = k.root.id();
        assert_eq!(run(&root_store(), &[forged], &EXPECT), failed(RecordFailure::Signature));
        // A record whose signature covers other attributes.
        let mut swapped = direct(3);
        swapped.signature = direct(4).signature;
        assert_eq!(run(&root_store(), &[swapped], &EXPECT), failed(RecordFailure::Signature));
    }

    #[test]
    fn refuses_a_parse_error_beside_a_valid_record()
    {
        let store_bytes = root_store();
        let store = TrustStore::parse(&store_bytes).unwrap();
        let mut bytes = object(BODY, &[direct(3), stranger()]);
        // The second record's algorithm byte.
        let second = BODY.len() + usize::try_from(u32::from_le_bytes(bytes[BODY.len()..BODY.len() + 4].try_into().unwrap())).unwrap();
        bytes[second + 4] = 2;
        assert_eq!(verify(&bytes, &store, &EXPECT), Err(Refusal::Parse(ParseError::Algorithm)));
        let mut bytes = object(BODY, &[direct(3)]);
        let end = bytes.len();
        bytes[end - 10] = 2;
        assert_eq!(verify(&bytes, &store, &EXPECT), Err(Refusal::Parse(ParseError::Version)));
        assert_eq!(verify(BODY, &store, &EXPECT), Err(Refusal::Parse(ParseError::Magic)));
    }

    /// Every bit of a signed object is bound: a flip anywhere refuses it.
    #[test]
    fn refuses_every_bit_flip()
    {
        let store_bytes = root_store();
        let store = TrustStore::parse(&store_bytes).unwrap();
        let good = object(BODY, &[certified(3)]);
        verify(&good, &store, &EXPECT).unwrap();
        for index in 0..good.len()
        {
            for bit in 0..8
            {
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
                    _ => {}
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
