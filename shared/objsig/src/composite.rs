// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/composite.rs

//! The composite signature every record and certificate carries: Ed25519 and
//! ML-DSA-65 over the same message, valid only when both verify
//! ([docs/signing.md](../../../docs/signing.md) § Composite Signature).
//!
//! A key is the Ed25519 public key followed by the ML-DSA-65 public key, and a
//! signature the Ed25519 signature followed by the ML-DSA-65 signature. The
//! Ed25519 half is RFC 8032's pure Ed25519 of the message; the ML-DSA half is
//! FIPS 204's pure, deterministic ML-DSA-65 of the message with the context
//! string [`CONTEXT`]. [`verify`] checks the Ed25519 half first, the cheaper,
//! and the ML-DSA half only when the Ed25519 half verifies.
//!
//! [`public_key`] and [`sign`], compiled only with the `sign` feature, which
//! only a host tool enables, derive a key from its two seeds and sign with it.

use crypto::ml_dsa;

use crate::{PublicKey, Signature};

/// The length of the Ed25519 half of a key.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// The length of the Ed25519 half of a signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// The length of a composite public key: 32 + 1,952 bytes.
pub const PUBLIC_KEY_LEN: usize = ED25519_PUBLIC_KEY_LEN + ml_dsa::PUBLIC_KEY_LEN;

/// The length of a composite signature: 64 + 3,309 bytes.
pub const SIGNATURE_LEN: usize = ED25519_SIGNATURE_LEN + ml_dsa::SIGNATURE_LEN;

/// The length of a composite key's secret: the Ed25519 seed, then the
/// ML-DSA-65 seed, 32 bytes each and drawn independently.
pub const SEED_LEN: usize = 32 + ml_dsa::SEED_LEN;

/// The context string of the ML-DSA half: it binds that half to this
/// composite, so it is never a valid ML-DSA-65 signature under another
/// context.
pub const CONTEXT: &[u8] = b"seraph/sig/ed25519+ml-dsa-65";

const _: () = assert!(
    CONTEXT.len() <= ml_dsa::MAX_CONTEXT_LEN,
    "the context string fits ML-DSA's"
);

/// The half of a composite signature that did not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError
{
    /// The Ed25519 half.
    Ed25519,
    /// The ML-DSA-65 half (checked only when the Ed25519 half verified).
    MlDsa,
}

/// Verify the composite `signature` of `message` under `key`: both halves
/// must verify.
///
/// # Errors
///
/// The [`VerifyError`] of the first half that does not verify.
pub fn verify(key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), VerifyError>
{
    let (ed_key, ml_key) = halves(key).ok_or(VerifyError::Ed25519)?;
    let (ed_signature, ml_signature) = halves(signature).ok_or(VerifyError::Ed25519)?;
    crypto::ed25519_verify(ed_key, message, ed_signature).map_err(|_| VerifyError::Ed25519)?;
    ml_dsa::verify(ml_key, message, CONTEXT, ml_signature).map_err(|_| VerifyError::MlDsa)
}

/// `bytes` as its first `A` bytes and the `B` after them; `None` unless it
/// is `A + B` bytes long, which the callers' array lengths make it.
fn halves<const A: usize, const B: usize>(bytes: &[u8]) -> Option<(&[u8; A], &[u8; B])>
{
    let (head, tail) = bytes.split_first_chunk::<A>()?;
    Some((head, tail.try_into().ok()?))
}

/// The composite public key of `seed`, the Ed25519 seed then the ML-DSA-65
/// seed.
#[cfg(any(test, feature = "sign"))]
#[expect(
    clippy::large_stack_frames,
    reason = "the key, and the ML-DSA key derivation inlined into it, on the stack of the host \
              thread that signs: the signer is compiled for the build host only (the sign \
              feature), whose threads have 2 MiB"
)]
#[must_use]
pub fn public_key(seed: &[u8; SEED_LEN]) -> PublicKey
{
    let mut key = [0u8; PUBLIC_KEY_LEN];
    if let Some((ed_seed, ml_seed)) = halves::<32, { ml_dsa::SEED_LEN }>(seed)
        && let Some((ed_key, ml_key)) = key.split_first_chunk_mut::<ED25519_PUBLIC_KEY_LEN>()
    {
        *ed_key = crypto::ed25519_public_key(ed_seed);
        ml_key.copy_from_slice(&ml_dsa::public_key(ml_seed));
    }
    key
}

/// The composite signature of `message` under the key of `seed`, the
/// Ed25519 seed then the ML-DSA-65 seed. Deterministic: one key and one
/// message give one signature.
///
/// # Errors
///
/// None in practice: the ML-DSA signer's one error, a context string longer
/// than it takes, is excluded by a compile-time assertion on [`CONTEXT`].
#[cfg(any(test, feature = "sign"))]
#[expect(
    clippy::large_stack_frames,
    reason = "the signature, and the ML-DSA signer inlined into it, on the stack of the host \
              thread that signs: the signer is compiled for the build host only (the sign \
              feature), whose threads have 2 MiB"
)]
pub fn sign(seed: &[u8; SEED_LEN], message: &[u8]) -> Result<Signature, ml_dsa::SignError>
{
    let mut signature = [0u8; SIGNATURE_LEN];
    if let Some((ed_seed, ml_seed)) = halves::<32, { ml_dsa::SEED_LEN }>(seed)
        && let Some((ed_half, ml_half)) = signature.split_first_chunk_mut::<ED25519_SIGNATURE_LEN>()
    {
        *ed_half = crypto::ed25519_sign(ed_seed, message);
        ml_half.copy_from_slice(&ml_dsa::sign(ml_seed, message, CONTEXT)?);
    }
    Ok(signature)
}

#[cfg(test)]
mod tests
{
    use super::*;

    const SEED: [u8; SEED_LEN] = {
        let mut seed = [0u8; SEED_LEN];
        let mut i = 0;
        while i < SEED_LEN
        {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "i is below SEED_LEN, 64, so it fits a byte"
            )]
            {
                seed[i] = i as u8;
            }
            i += 1;
        }
        seed
    };
    const MESSAGE: &[u8] = b"seraph/obj/v3 and the rest of a record's attributes";

    // Defect caught: a composite assembled in another order, under another
    // context string, or from one seed for both halves, which a verifier of
    // the stated construction refuses or which binds a half to nothing.
    #[test]
    fn halves_are_the_primitives_signatures_under_the_stated_context()
    {
        let (ed_seed, ml_seed) = halves::<32, 32>(&SEED).unwrap();
        let key = public_key(&SEED);
        assert_eq!(key[..32], crypto::ed25519_public_key(ed_seed));
        assert_eq!(key[32..], ml_dsa::public_key(ml_seed));
        let signature = sign(&SEED, MESSAGE).unwrap();
        assert_eq!(signature[..64], crypto::ed25519_sign(ed_seed, MESSAGE));
        assert_eq!(
            signature[64..],
            ml_dsa::sign(ml_seed, MESSAGE, b"seraph/sig/ed25519+ml-dsa-65").unwrap()
        );
        assert_eq!(verify(&key, MESSAGE, &signature), Ok(()));
        assert_eq!(sign(&SEED, MESSAGE).unwrap(), signature, "deterministic");
    }

    // Defect caught: a composite accepted on one valid half, the defect the
    // composite exists to exclude.
    #[test]
    fn either_half_invalid_refuses_the_signature()
    {
        let key = public_key(&SEED);
        let signature = sign(&SEED, MESSAGE).unwrap();
        for at in [0, 31, 32, 63]
        {
            let mut bad = signature;
            bad[at] ^= 1;
            assert_eq!(
                verify(&key, MESSAGE, &bad),
                Err(VerifyError::Ed25519),
                "{at}"
            );
        }
        for at in [64, 64 + 1000, SIGNATURE_LEN - 1]
        {
            let mut bad = signature;
            bad[at] ^= 1;
            assert_eq!(verify(&key, MESSAGE, &bad), Err(VerifyError::MlDsa), "{at}");
        }
        // Two valid halves, of two messages.
        let other = sign(&SEED, b"another message").unwrap();
        let mut mixed = signature;
        mixed[64..].copy_from_slice(&other[64..]);
        assert_eq!(verify(&key, MESSAGE, &mixed), Err(VerifyError::MlDsa));
        let mut mixed = signature;
        mixed[..64].copy_from_slice(&other[..64]);
        assert_eq!(verify(&key, MESSAGE, &mixed), Err(VerifyError::Ed25519));
        // A key with either half of another key's.
        let mut stranger_seed = SEED;
        stranger_seed[0] ^= 1;
        stranger_seed[32] ^= 1;
        let stranger = public_key(&stranger_seed);
        let mut wrong = key;
        wrong[..32].copy_from_slice(&stranger[..32]);
        assert_eq!(
            verify(&wrong, MESSAGE, &signature),
            Err(VerifyError::Ed25519)
        );
        let mut wrong = key;
        wrong[32..].copy_from_slice(&stranger[32..]);
        assert_eq!(verify(&wrong, MESSAGE, &signature), Err(VerifyError::MlDsa));
    }

    // Defect caught: an ML-DSA half signed under the empty context, or one a
    // verifier under the empty context accepts, so the half is valid outside
    // the composite.
    #[test]
    fn the_ml_dsa_half_is_bound_to_the_context()
    {
        let (_, ml_seed) = halves::<32, 32>(&SEED).unwrap();
        let signature = sign(&SEED, MESSAGE).unwrap();
        let ml_signature: &[u8; ml_dsa::SIGNATURE_LEN] = signature[64..].try_into().unwrap();
        let ml_key = ml_dsa::public_key(ml_seed);
        assert_eq!(
            ml_dsa::verify(&ml_key, MESSAGE, b"", ml_signature),
            Err(ml_dsa::VerifyError::Mismatch)
        );
    }
}
