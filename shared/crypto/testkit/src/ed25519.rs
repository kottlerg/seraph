// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/ed25519.rs

//! The Ed25519 reference verdict and the differential inputs: generated
//! signatures with their one-bit corruptions, and a corpus of edge cases.
//!
//! [`reference`] is an RFC 8032 verifier assembled from `ed25519-dalek` and
//! `curve25519-dalek`, an implementation independent of `shared/crypto`. It
//! returns which check fails, in RFC order, so a differential run checks the
//! reason for a rejection as well as the rejection:
//!
//! 1. S at or above the group order L (§ 5.1.7): [`Verdict::NonCanonicalS`].
//! 2. A public key that is not the canonical encoding of a point (§ 5.1.3: a
//!    y at or above p, a y with no x, or x = 0 with the sign bit set):
//!    [`Verdict::BadPublicKey`]. `ed25519-dalek` decodes such keys leniently
//!    (it reduces y and ignores the sign bit of x = 0), so the reference
//!    checks the encoding itself: a key is canonical when it decompresses and
//!    re-encodes to the same bytes.
//! 3. The cofactorless equation `[S]B = R + [k]A`, R compared as the
//!    encoding the signature carries: `ed25519-dalek`'s `verify`, which
//!    rejects as [`Verdict::Mismatch`].
//!
//! The cofactorless equation is the one RFC 8032 § 5.1.7 permits beside the
//! cofactored one; it accepts a subset of what the cofactored equation
//! accepts, and is the equation `shared/crypto` checks.

use std::fmt;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};

use crate::hex;
use crate::rng::Rng;

/// The outcome of verifying one input: acceptance, or the first check that
/// failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict
{
    /// The signature is valid.
    Accept,
    /// S is not below the group order L.
    NonCanonicalS,
    /// The public key is not the canonical encoding of a point.
    BadPublicKey,
    /// The verification equation does not hold.
    Mismatch,
}

/// The group order L = 2^252 + 27742317777372353535851937790883648493,
/// little-endian.
pub const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// The canonical encoding of a point of order 8; its multiples are the whole
/// torsion subgroup.
const ORDER_8: [u8; 32] = [
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
];

/// The reference verdict on `signature` over `message` under `public_key`.
#[must_use]
pub fn reference(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Verdict
{
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature[32..]);
    if bool::from(Scalar::from_canonical_bytes(s).is_none())
    {
        return Verdict::NonCanonicalS;
    }
    if !is_canonical_point(public_key)
    {
        return Verdict::BadPublicKey;
    }
    let Ok(key) = VerifyingKey::from_bytes(public_key)
    else
    {
        return Verdict::BadPublicKey;
    };
    if key
        .verify(message, &Signature::from_bytes(signature))
        .is_ok()
    {
        Verdict::Accept
    }
    else
    {
        Verdict::Mismatch
    }
}

/// Whether `encoding` is the canonical encoding of a curve point.
fn is_canonical_point(encoding: &[u8; 32]) -> bool
{
    CompressedEdwardsY(*encoding)
        .decompress()
        .is_some_and(|point| point.compress().0 == *encoding)
}

/// The public key of the private key `seed`, and its signature over
/// `message` (RFC 8032 § 5.1.6).
#[must_use]
pub fn sign(seed: &[u8; 32], message: &[u8]) -> ([u8; 32], [u8; 64])
{
    let key = SigningKey::from_bytes(seed);
    (key.verifying_key().to_bytes(), key.sign(message).to_bytes())
}

/// One verification input.
#[derive(Clone, PartialEq, Eq)]
pub struct Input
{
    /// What the input exercises.
    pub label: String,
    /// The 32-byte public key A.
    pub public_key: [u8; 32],
    /// The message.
    pub message: Vec<u8>,
    /// The 64-byte signature R ‖ S.
    pub signature: [u8; 64],
}

impl fmt::Debug for Input
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "{}: pk {} msg {} sig {}",
            self.label,
            hex::encode(&self.public_key),
            hex::encode(&self.message),
            hex::encode(&self.signature)
        )
    }
}

impl Input
{
    fn new(
        label: impl Into<String>,
        public_key: [u8; 32],
        message: &[u8],
        signature: [u8; 64],
    ) -> Self
    {
        Self {
            label: label.into(),
            public_key,
            message: message.to_vec(),
            signature,
        }
    }

    /// This input's reference verdict.
    #[must_use]
    pub fn reference(&self) -> Verdict
    {
        reference(&self.public_key, &self.message, &self.signature)
    }
}

/// `count` generated rounds from `seed`. Each round signs a random message
/// (empty, short, or up to a few blocks of the hash) under a random key and
/// yields the valid signature, one-bit flips of the signature, the message
/// and the key, the signature under a random 32-byte key, and a random
/// 64-byte signature.
#[must_use]
pub fn generated(seed: u64, count: usize) -> Vec<Input>
{
    let mut rng = Rng::new(seed);
    let mut out = Vec::new();
    for round in 0..count
    {
        let secret: [u8; 32] = rng.array();
        let len = match rng.below(4)
        {
            0 => 0,
            1 => rng.below(4096),
            _ => rng.below(300),
        };
        let message = rng.bytes(len);
        let (pk, sig) = sign(&secret, &message);
        out.push(Input::new(
            format!("round {round} valid"),
            pk,
            &message,
            sig,
        ));

        let mut flipped = sig;
        flip_bit(&mut flipped, rng.below(512));
        out.push(Input::new(
            format!("round {round} signature bit"),
            pk,
            &message,
            flipped,
        ));

        if !message.is_empty()
        {
            let mut flipped = message.clone();
            flip_bit(&mut flipped, rng.below(len.wrapping_mul(8)));
            out.push(Input::new(
                format!("round {round} message bit"),
                pk,
                &flipped,
                sig,
            ));
        }

        let mut flipped = pk;
        flip_bit(&mut flipped, rng.below(256));
        out.push(Input::new(
            format!("round {round} key bit"),
            flipped,
            &message,
            sig,
        ));

        out.push(Input::new(
            format!("round {round} random key"),
            rng.array(),
            &message,
            sig,
        ));
        out.push(Input::new(
            format!("round {round} random signature"),
            pk,
            &message,
            rng.array(),
        ));
    }
    out
}

fn flip_bit(bytes: &mut [u8], bit: usize)
{
    if let Some(byte) = bytes.get_mut(bit / 8)
    {
        *byte ^= 1 << (bit % 8);
    }
}

/// The eight points of the torsion subgroup, the identity first.
#[must_use]
pub fn torsion() -> Vec<EdwardsPoint>
{
    let Some(generator) = CompressedEdwardsY(ORDER_8).decompress()
    else
    {
        return Vec::new();
    };
    let mut points = vec![EdwardsPoint::identity()];
    let mut next = generator;
    for _ in 1..8
    {
        points.push(next);
        next += generator;
    }
    points
}

/// Every encoding whose y field (the low 255 bits) is at or above p, with
/// and without the sign bit: no such encoding is canonical.
fn y_at_or_above_p() -> Vec<[u8; 32]>
{
    let mut out = Vec::new();
    for low in 0xedu8..=0xff
    {
        for top in [0x7fu8, 0xff]
        {
            let mut encoding = [0xff; 32];
            encoding[0] = low;
            encoding[31] = top;
            out.push(encoding);
        }
    }
    out
}

/// The two points with x = 0 (y = 1 and y = -1), encoded with the sign bit
/// set: neither encoding is canonical.
fn x_zero_with_sign() -> Vec<[u8; 32]>
{
    let mut one = [0u8; 32];
    one[0] = 1;
    let mut minus_one = [0xff; 32];
    minus_one[0] = 0xec;
    [one, minus_one]
        .into_iter()
        .map(|mut encoding| {
            encoding[31] |= 0x80;
            encoding
        })
        .collect()
}

/// `a + b` for 256-bit little-endian integers, or `None` on overflow.
fn add_256(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]>
{
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for ((o, x), y) in out.iter_mut().zip(a).zip(b)
    {
        let sum = u16::from(*x)
            .wrapping_add(u16::from(*y))
            .wrapping_add(carry);
        *o = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    (carry == 0).then_some(out)
}

fn with_s(signature: &[u8; 64], s: &[u8; 32]) -> [u8; 64]
{
    let mut out = *signature;
    out[32..].copy_from_slice(s);
    out
}

fn with_r(signature: &[u8; 64], r: &[u8; 32]) -> [u8; 64]
{
    let mut out = *signature;
    out[..32].copy_from_slice(r);
    out
}

/// `k = SHA-512(R ‖ A ‖ M) mod L`.
fn challenge(r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> Scalar
{
    let mut hash = Sha512::new();
    hash.update(r);
    hash.update(a);
    hash.update(message);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Whether a crafted signature satisfies the cofactorless equation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Equation
{
    Holds,
    Fails,
}

/// The first message `stem ‖ n` (n counting up from 0) whose challenge under
/// `nonce_point` and `key` makes `[k]torsion` the identity exactly when the
/// equation is to hold: the term that decides the cofactorless equation for
/// the crafted signatures below.
fn message_where(
    stem: &[u8],
    nonce_point: &[u8; 32],
    key: &[u8; 32],
    torsion: &EdwardsPoint,
    equation: Equation,
) -> Vec<u8>
{
    let mut n = 0u32;
    loop
    {
        let mut message = stem.to_vec();
        message.extend_from_slice(&n.to_le_bytes());
        let k = challenge(nonce_point, key, &message);
        let killed = k * torsion == EdwardsPoint::identity();
        if killed == (equation == Equation::Holds)
        {
            return message;
        }
        n = n.wrapping_add(1);
    }
}

/// The valid signature the edge cases corrupt.
struct Base
{
    secret: [u8; 32],
    message: &'static [u8],
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl Base
{
    fn input(&self, label: impl Into<String>, signature: [u8; 64]) -> Input
    {
        Input::new(label, self.public_key, self.message, signature)
    }
}

/// `R = O, S = 0`: valid under the identity key for every message.
fn identity_signature() -> [u8; 64]
{
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&EdwardsPoint::identity().compress().0);
    signature
}

/// S: malleability (S + kL for every k that keeps it below 2^256), the range
/// boundary, and canonical but wrong values.
fn s_cases(base: &Base, out: &mut Vec<Input>)
{
    let mut s = [0u8; 32];
    s.copy_from_slice(&base.signature[32..]);
    let mut k = 1;
    let mut shifted = add_256(&s, &L);
    while let Some(value) = shifted
    {
        out.push(base.input(format!("S + {k}L"), with_s(&base.signature, &value)));
        k += 1;
        shifted = add_256(&value, &L);
    }
    let mut l_minus_one = L;
    l_minus_one[0] -= 1;
    let mut l_plus_one = L;
    l_plus_one[0] += 1;
    let mut two_252 = [0u8; 32];
    two_252[31] = 0x10;
    let mut high_bit = s;
    high_bit[31] |= 0x80;
    for (label, value) in [
        ("S = L", L),
        ("S = L - 1", l_minus_one),
        ("S = L + 1", l_plus_one),
        ("S = 2^252", two_252),
        ("S = 2^256 - 1", [0xff; 32]),
        ("S = 0", [0; 32]),
        ("S with bit 255 set", high_bit),
    ]
    {
        out.push(base.input(label, with_s(&base.signature, &value)));
    }
}

/// R: every non-canonical encoding, the torsion points, and R with its sign
/// bit flipped.
fn r_cases(base: &Base, out: &mut Vec<Input>)
{
    for encoding in y_at_or_above_p().into_iter().chain(x_zero_with_sign())
    {
        out.push(base.input("R not canonical", with_r(&base.signature, &encoding)));
    }
    for (i, point) in torsion().iter().enumerate()
    {
        let encoding = point.compress().0;
        out.push(base.input(
            format!("R = torsion {i}"),
            with_r(&base.signature, &encoding),
        ));
    }
    let mut flipped = base.signature;
    flipped[31] ^= 0x80;
    out.push(base.input("R sign bit flipped", flipped));
}

/// A: every non-canonical encoding and a y with no x, each with the base
/// signature and with `R = O, S = 0` (which `ed25519-dalek` alone accepts
/// under a key it decodes to the identity).
fn non_canonical_key_cases(base: &Base, out: &mut Vec<Input>)
{
    let mut no_x = [0u8; 32];
    no_x[0] = 2;
    for encoding in y_at_or_above_p()
        .into_iter()
        .chain(x_zero_with_sign())
        .chain([no_x])
    {
        out.push(Input::new(
            "A not canonical",
            encoding,
            base.message,
            base.signature,
        ));
        out.push(Input::new(
            "A not canonical, R = O, S = 0",
            encoding,
            base.message,
            identity_signature(),
        ));
    }
}

/// A in the torsion subgroup: the base signature, and `R = O, S = 0` under a
/// message whose challenge kills A (the cofactorless equation holds) and one
/// whose challenge does not.
fn small_order_key_cases(base: &Base, out: &mut Vec<Input>)
{
    let identity = EdwardsPoint::identity().compress().0;
    for (i, point) in torsion().iter().enumerate()
    {
        let key = point.compress().0;
        out.push(Input::new(
            format!("A = torsion {i}"),
            key,
            base.message,
            base.signature,
        ));
        for equation in [Equation::Holds, Equation::Fails]
        {
            if i == 0 && equation == Equation::Fails
            {
                // [k]O is the identity for every k.
                continue;
            }
            let crafted = message_where(b"small order A", &identity, &key, point, equation);
            out.push(Input::new(
                format!("A = torsion {i}, R = O, S = 0, equation {equation:?}"),
                key,
                &crafted,
                identity_signature(),
            ));
        }
    }
}

/// A of mixed order (A + T for each torsion point T): signatures made with
/// A's private scalar, under a message whose challenge kills T (the
/// cofactorless equation holds) and one whose challenge does not (only the
/// cofactored equation holds).
fn mixed_order_key_cases(base: &Base, out: &mut Vec<Input>)
{
    let scalar = SigningKey::from_bytes(&base.secret).to_scalar();
    let point = EdwardsPoint::mul_base(&scalar);
    let nonce = Scalar::from_bytes_mod_order_wide(&[0x3c; 64]);
    let nonce_point = EdwardsPoint::mul_base(&nonce).compress().0;
    for (i, torsion) in torsion().iter().enumerate().skip(1)
    {
        let key = (point + torsion).compress().0;
        for equation in [Equation::Holds, Equation::Fails]
        {
            let crafted = message_where(b"mixed order A", &nonce_point, &key, torsion, equation);
            let s = nonce + challenge(&nonce_point, &key, &crafted) * scalar;
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&nonce_point);
            signature[32..].copy_from_slice(s.as_bytes());
            out.push(Input::new(
                format!("A + torsion {i}, equation {equation:?}"),
                key,
                &crafted,
                signature,
            ));
        }
    }
}

/// The edge-case corpus: signature malleability and the S range check,
/// non-canonical and small-order R, and degenerate public keys (the torsion
/// points, every non-canonical encoding, a y with no x, and mixed-order keys
/// with signatures crafted to satisfy, or fail, the cofactorless equation).
#[must_use]
pub fn edge_cases() -> Vec<Input>
{
    let secret = [0x5e; 32];
    let message = b"seraph ed25519 edge case".as_slice();
    let (public_key, signature) = sign(&secret, message);
    let base = Base {
        secret,
        message,
        public_key,
        signature,
    };
    let mut out = vec![base.input("base", base.signature)];
    s_cases(&base, &mut out);
    r_cases(&base, &mut out);
    non_canonical_key_cases(&base, &mut out);
    small_order_key_cases(&base, &mut out);
    mixed_order_key_cases(&base, &mut out);
    out.push(Input::new("all zero", [0; 32], message, [0; 64]));
    out
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn l_is_the_group_order()
    {
        let mut below = L;
        below[0] -= 1;
        assert!(bool::from(Scalar::from_canonical_bytes(L).is_none()));
        assert!(bool::from(Scalar::from_canonical_bytes(below).is_some()));
    }

    #[test]
    fn torsion_is_eight_distinct_small_order_points()
    {
        let points = torsion();
        let encodings: std::collections::HashSet<[u8; 32]> =
            points.iter().map(|p| p.compress().0).collect();
        assert_eq!(encodings.len(), 8);
        assert!(points.iter().all(EdwardsPoint::is_small_order));
    }

    #[test]
    fn reference_names_the_first_failing_check()
    {
        let (pk, sig) = sign(&[1; 32], b"m");
        assert_eq!(reference(&pk, b"m", &sig), Verdict::Accept);
        assert_eq!(reference(&pk, b"n", &sig), Verdict::Mismatch);
        // S = L fails the range check before the key is looked at.
        assert_eq!(
            reference(&[0xff; 32], b"m", &with_s(&sig, &L)),
            Verdict::NonCanonicalS
        );
        // y = p + 1 encodes the identity non-canonically: ed25519-dalek alone
        // accepts R = O, S = 0 under it, and the reference refuses the key.
        let mut identity_plus_p = [0xff; 32];
        identity_plus_p[0] = 0xee;
        identity_plus_p[31] = 0x7f;
        let mut r_identity = [0u8; 64];
        r_identity[0] = 1;
        let dalek = VerifyingKey::from_bytes(&identity_plus_p).unwrap();
        dalek
            .verify(b"m", &Signature::from_bytes(&r_identity))
            .unwrap();
        assert_eq!(
            reference(&identity_plus_p, b"m", &r_identity),
            Verdict::BadPublicKey
        );
    }

    #[test]
    fn the_crafted_edge_cases_reach_the_outcomes_they_are_built_for()
    {
        let cases = edge_cases();
        let verdict = |label: &str| {
            cases
                .iter()
                .find(|c| c.label == label)
                .map(Input::reference)
                .unwrap()
        };
        assert_eq!(verdict("base"), Verdict::Accept);
        assert_eq!(verdict("A + torsion 1, equation Holds"), Verdict::Accept);
        assert_eq!(verdict("A + torsion 1, equation Fails"), Verdict::Mismatch);
        assert_eq!(
            verdict("A = torsion 3, R = O, S = 0, equation Holds"),
            Verdict::Accept
        );
        assert_eq!(
            verdict("A = torsion 3, R = O, S = 0, equation Fails"),
            Verdict::Mismatch
        );
        assert_eq!(verdict("S + 1L"), Verdict::NonCanonicalS);
    }
}
