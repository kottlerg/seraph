// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/tests.rs

//! Host tests of ML-DSA-65 against its references: the known-answer tests,
//! the vendored Wycheproof files, OpenSSL's reference vectors, and the
//! verifier's stack bound.

use std::vec;

use crypto_testkit::differential;
use crypto_testkit::ml_dsa::{self as reference, SignInput, Verdict, VerifyInput};
use crypto_testkit::wycheproof::{self, MLDSA_65_SIGN_SEED, MLDSA_65_VERIFY, mldsa};

use super::params::TR_LEN;
use super::sign::{expand_key, sign_mu};
use super::verify::message_representative;
use super::*;

#[test]
fn kats_pass()
{
    assert_eq!(run_ml_dsa_kats(), Ok(()));
}

/// The reference's verdict for the verifier's outcome.
fn verdict(outcome: Result<(), VerifyError>) -> Verdict
{
    match outcome
    {
        Ok(()) => Verdict::Accept,
        Err(VerifyError::MalformedHint) => Verdict::MalformedHint,
        Err(VerifyError::ZOutOfRange) => Verdict::ZOutOfRange,
        Err(VerifyError::Mismatch | VerifyError::ContextTooLong) => Verdict::Mismatch,
    }
}

/// Verify an input whose key and signature may be of any length: one of
/// another length is refused, as no ML-DSA-65 key or signature has it.
fn verify_any(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError>
{
    match (
        <&[u8; PUBLIC_KEY_LEN]>::try_from(public_key),
        <&[u8; SIGNATURE_LEN]>::try_from(signature),
    )
    {
        (Ok(public_key), Ok(signature)) => verify(public_key, message, context, signature),
        _ => Err(VerifyError::Mismatch),
    }
}

#[test]
fn wycheproof_verification_cases_pass()
{
    let file = wycheproof::load::<mldsa::VerifyGroup>(&MLDSA_65_VERIFY).unwrap();
    assert_eq!(file.number_of_tests, 210);
    let report = wycheproof::run(
        &file,
        "ml-dsa-65 verify",
        |group, case| verify_any(&group.public_key, &case.msg, &case.ctx, &case.sig).is_ok(),
        |_, _| unreachable!("the file has no acceptable case"),
    );
    assert!(report.agrees(), "{report}");
}

/// The signature a Wycheproof signing case asks for, or `None` when its
/// seed or context is refused.
fn wycheproof_signature(
    group: &mldsa::SignGroup,
    case: &mldsa::SignCase,
) -> Option<[u8; SIGNATURE_LEN]>
{
    let seed = <&[u8; SEED_LEN]>::try_from(group.private_seed.as_slice()).ok()?;
    let mut public = [0u8; PUBLIC_KEY_LEN];
    let key = expand_key(seed, &mut public);
    assert_eq!(public, public_key(seed));
    assert_eq!(
        Some(public.as_slice()),
        group.public_key.as_deref(),
        "the group's key"
    );
    let rnd = match &case.rnd
    {
        Some(rnd) => <[u8; 32]>::try_from(rnd.as_slice()).ok()?,
        None => [0; 32],
    };
    let mu = match &case.msg
    {
        Some(message) =>
        {
            let context_len = u8::try_from(case.ctx.len()).ok()?;
            let mu = message_representative(&public, &[&[0, context_len], &case.ctx, message]);
            if let Some(expected) = &case.mu
            {
                assert_eq!(mu.as_slice(), expected, "mu of tcId with msg and mu");
            }
            if case.rnd.is_none()
            {
                let signed = sign(seed, message, &case.ctx).ok()?;
                assert_eq!(signed, sign_mu(&key, &mu, &rnd));
            }
            mu
        }
        None => <[u8; TR_LEN]>::try_from(case.mu.as_deref()?).ok()?,
    };
    Some(sign_mu(&key, &mu, &rnd))
}

#[test]
fn wycheproof_signing_cases_pass()
{
    let file = wycheproof::load::<mldsa::SignGroup>(&MLDSA_65_SIGN_SEED).unwrap();
    assert_eq!(file.number_of_tests, 105);
    let report = wycheproof::run(
        &file,
        "ml-dsa-65 sign",
        |group, case| {
            wycheproof_signature(group, case).is_some_and(|signature| {
                let produced = signature.as_slice() == case.sig;
                if produced && let Some(message) = &case.msg
                {
                    let public = public_key(group.private_seed.as_slice().try_into().unwrap());
                    assert_eq!(verify(&public, message, &case.ctx, &signature), Ok(()));
                }
                produced
            })
        },
        |_, _| unreachable!("the file has no acceptable case"),
    );
    assert!(report.agrees(), "{report}");
}

#[test]
fn signing_agrees_with_the_reference()
{
    let vectors = reference::load().unwrap();
    assert_eq!(
        vectors.signing.len(),
        crypto_testkit::generate::ML_DSA_ROUNDS
    );
    let report = differential::compare(
        "ml-dsa-65 signing",
        vectors.signing.iter(),
        |input: &&SignInput| {
            let public = public_key(&input.seed);
            let signature = sign(&input.seed, &input.message, &input.context).unwrap();
            let verified = verify(&public, &input.message, &input.context, &signature);
            (public.to_vec(), signature.to_vec(), verified)
        },
        |input| (input.public_key.clone(), input.signature.clone(), Ok(())),
    );
    assert!(report.agrees(), "{report}");
}

#[test]
fn verification_agrees_with_the_reference()
{
    let vectors = reference::load().unwrap();
    let report = differential::compare(
        "ml-dsa-65 verification",
        vectors.verification.iter(),
        |case: &&VerifyInput| {
            let input = &case.input;
            verdict(verify_any(
                &input.public_key,
                &input.message,
                &input.context,
                &input.signature,
            ))
        },
        |case| case.verdict,
    );
    assert!(report.agrees(), "{report}");
    for expected in [
        Verdict::Accept,
        Verdict::MalformedHint,
        Verdict::ZOutOfRange,
        Verdict::Mismatch,
    ]
    {
        assert!(
            vectors
                .verification
                .iter()
                .any(|case| case.verdict == expected),
            "no {expected:?} case"
        );
    }
}

#[test]
fn signing_refuses_an_over_long_context()
{
    let context = [0u8; MAX_CONTEXT_LEN + 1];
    assert_eq!(
        sign(&[7; SEED_LEN], b"m", &context),
        Err(SignError::ContextTooLong)
    );
    let signature = sign(&[7; SEED_LEN], b"m", &context[..MAX_CONTEXT_LEN]).unwrap();
    assert_eq!(
        verify(
            &public_key(&[7; SEED_LEN]),
            b"m",
            &context[..MAX_CONTEXT_LEN],
            &signature
        ),
        Ok(())
    );
}

/// The stack the verifier is run on: init's (`INIT_STACK_PAGES`), the
/// smallest it runs on, in the ktest run of its known answers. Its frames do
/// not grow with the message, which is absorbed as it is read.
const VERIFY_STACK: usize = 16 * 1024;

#[test]
fn verification_runs_on_a_bounded_stack_whatever_the_message_length()
{
    let seed = [3u8; SEED_LEN];
    let message = vec![0x5a; 1 << 20];
    let signature = sign(&seed, &message, b"ctx").unwrap();
    let public = public_key(&seed);
    // Scoped, so the thread borrows the key and signature instead of holding
    // copies of them on its stack.
    let verified = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(VERIFY_STACK)
            .spawn_scoped(scope, || verify(&public, &message, b"ctx", &signature))
            .unwrap()
            .join()
            .unwrap()
    });
    assert_eq!(verified, Ok(()));
}
