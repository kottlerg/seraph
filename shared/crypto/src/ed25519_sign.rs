// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ed25519_sign.rs

//! Ed25519 key generation and signing (RFC 8032 § 5.1.5, § 5.1.6), compiled
//! only with the crate's `sign` feature.
//!
//! The caller passes the 32-byte secret seed on every call: the crate draws no
//! randomness and keeps no key. A signature is deterministic, so one seed and
//! one message give one signature.
//!
//! No branch and no memory index depends on a secret value (the seed, the
//! secret scalar, the nonce prefix, the nonce), only on the message length; the
//! crate's README, § Design notes, gives the argument for every function this
//! module calls.

use crate::edwards;
use crate::scalar;
use crate::sha512::{self, Sha512};

/// The two halves of a seed's hash (RFC 8032 § 5.1.5 steps 1 and 2).
struct Expanded
{
    /// The secret scalar: the low half, clamped.
    scalar: [u8; 32],
    /// The nonce prefix: the high half.
    prefix: [u8; 32],
}

/// Hash `seed` and clamp the low half into the secret scalar: the low three
/// bits cleared, bit 255 cleared and bit 254 set.
fn expand(seed: &[u8; 32]) -> Expanded
{
    let hash = sha512::sha512(seed);
    let mut key = Expanded {
        scalar: [0; 32],
        prefix: [0; 32],
    };
    for (dst, src) in key.scalar.iter_mut().chain(key.prefix.iter_mut()).zip(hash)
    {
        *dst = src;
    }
    key.scalar[0] &= 0xf8;
    key.scalar[31] &= 0x7f;
    key.scalar[31] |= 0x40;
    key
}

/// The public key of a secret scalar: the encoding of `[scalar]B`.
fn public_key_of(key: &Expanded) -> [u8; 32]
{
    edwards::pack(&edwards::scalar_mul_base(&key.scalar))
}

/// The SHA-512 of the concatenation of `parts`, reduced modulo L.
fn hash_to_scalar(parts: &[&[u8]]) -> [u8; 32]
{
    let mut hasher = Sha512::new();
    for part in parts
    {
        hasher.update(part);
    }
    scalar::reduce_512(&hasher.finalize())
}

/// The Ed25519 public key of the secret `seed` (RFC 8032 § 5.1.5).
#[must_use]
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32]
{
    public_key_of(&expand(seed))
}

/// The Ed25519 signature `R ‖ S` of `message` under the secret `seed`
/// (RFC 8032 § 5.1.6).
///
/// The signature is deterministic, and its S is below the group order L, so
/// it verifies under [`ed25519_public_key`]`(seed)` with
/// [`ed25519_verify`](crate::ed25519_verify).
#[must_use]
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64]
{
    let key = expand(seed);
    let public_key = public_key_of(&key);
    let nonce = hash_to_scalar(&[&key.prefix, message]);
    let r = edwards::pack(&edwards::scalar_mul_base(&nonce));
    let challenge = hash_to_scalar(&[&r, &public_key, message]);
    let s = scalar::mul_add(&challenge, &key.scalar, &nonce);
    let mut signature = [0u8; 64];
    for (dst, src) in signature.iter_mut().zip(r.iter().chain(&s))
    {
        *dst = *src;
    }
    signature
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::ed25519_verify;
    use crate::field::op_count;
    use crypto_testkit::differential;
    use crypto_testkit::ed25519 as reference;
    use crypto_testkit::rng::Rng;

    /// The key and the signature equal, byte for byte, the ones OpenSSL
    /// derives for every seed and message of the reference vectors.
    #[test]
    fn keys_and_signatures_equal_the_openssl_reference()
    {
        let report = differential::compare(
            "ed25519 signing",
            reference::load().unwrap().signing,
            |input| {
                (
                    ed25519_public_key(&input.seed),
                    ed25519_sign(&input.seed, &input.message),
                )
            },
            |input| (input.public_key, input.signature),
        );
        assert!(report.agrees(), "{report}");
    }

    #[test]
    fn every_signature_verifies_under_its_public_key()
    {
        let mut rng = Rng::new(0x5e4a_5167);
        for round in 0..64
        {
            let seed: [u8; 32] = rng.array();
            let len = rng.below(600);
            let message = rng.bytes(len);
            let signature = ed25519_sign(&seed, &message);
            assert_eq!(
                ed25519_verify(&ed25519_public_key(&seed), &message, &signature),
                Ok(()),
                "round {round}"
            );
        }
    }

    /// The first 32-byte message, counting up from zero in its first four
    /// bytes, whose nonce under `seed` has top byte `top`.
    fn message_with_nonce_top(seed: &[u8; 32], top: u8) -> [u8; 32]
    {
        let prefix = expand(seed).prefix;
        (0..=u32::MAX)
            .map(|n| {
                let mut message = [0x5a; 32];
                message[..4].copy_from_slice(&n.to_le_bytes());
                message
            })
            .find(|message| hash_to_scalar(&[&prefix, message])[31] == top)
            .unwrap()
    }

    /// Signing performs the same field multiplications and conditional
    /// swaps whatever the seed, the secret scalar and the nonce: a nonce
    /// whose top byte is zero (where a ladder that skips leading zero bits
    /// would do less work), one whose top byte is its largest (0x0f, below
    /// L), and the all-zero and all-one seeds.
    #[test]
    fn signing_does_the_same_field_work_for_every_secret()
    {
        let seed = [0x3c; 32];
        let cases = [
            ([0u8; 32], [0u8; 32]),
            ([0xff; 32], [0xff; 32]),
            (seed, message_with_nonce_top(&seed, 0)),
            (seed, message_with_nonce_top(&seed, 0x0f)),
        ];
        let work = cases.map(|(seed, message)| op_count::of(|| ed25519_sign(&seed, &message)));
        assert!(work.iter().all(|w| *w == work[0]), "{work:?}");
    }
}
