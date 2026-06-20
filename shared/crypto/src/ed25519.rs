// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ed25519.rs

//! Ed25519 signature verification (RFC 8032).
//!
//! [`ed25519_verify`] checks `[S]B = R + [k]A` with `k = SHA512(R‖A‖M) mod L`,
//! using the cofactorless equation and a canonical re-encoding compare so the
//! result matches the RFC 8032 §7.1 test vectors exactly. The mandatory
//! `S < L` range check (RFC 8032 §5.1.7) runs first. Every failure path is a
//! single terminal `Err`; there is no fallback or warn-and-continue.

use crate::edwards;
use crate::scalar;
use crate::sha512::Sha512;

/// Why a signature failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError
{
    /// The public key did not decode to a curve point.
    BadPublicKey,
    /// The signature scalar S was not in `{0, …, L-1}` (RFC 8032 §5.1.7).
    NonCanonicalS,
    /// The verification equation did not hold.
    Mismatch,
}

/// Verify an Ed25519 signature over `message`.
///
/// # Errors
///
/// Returns [`VerifyError`] identifying the first failing check. A returned
/// `Ok(())` means the signature is valid for `public_key` and `message`.
pub fn ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), VerifyError>
{
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    // RFC 8032 §5.1.7: reject S ∉ {0, …, L-1} before any curve work.
    if !scalar::is_canonical(&s_bytes)
    {
        return Err(VerifyError::NonCanonicalS);
    }

    // Decode the public key to -A so the equation becomes a single addition.
    let Some(neg_a) = edwards::decompress_neg(public_key)
    else
    {
        return Err(VerifyError::BadPublicKey);
    };

    // k = SHA512(R ‖ A ‖ M) mod L. Order is load-bearing; stream to avoid
    // buffering the (possibly large) message.
    let mut hasher = Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let k = scalar::reduce_512(&hasher.finalize());

    // r_check = [S]B + [k](-A) = [S]B - [k]A.
    let mut r_check = edwards::scalar_mul(&neg_a, &k);
    let sb = edwards::scalar_mul_base(&s_bytes);
    edwards::add(&mut r_check, &sb);

    if edwards::pack(&r_check) == r_bytes
    {
        Ok(())
    }
    else
    {
        Err(VerifyError::Mismatch)
    }
}

// ── Known-answer tests ───────────────────────────────────────────────────────

/// One RFC 8032 §7.1 verification vector, stored as hex to keep the byte
/// layout auditable against the RFC.
struct Ed25519Vec
{
    public_key: &'static str,
    message: &'static str,
    signature: &'static str,
}

/// RFC 8032 §7.1 vectors: TEST 1/2/3, the 1024-byte message, and SHA(abc).
const RFC8032_VECTORS: &[Ed25519Vec] = &[
    Ed25519Vec {
        public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        message: "",
        signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    Ed25519Vec {
        public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        message: "72",
        signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    Ed25519Vec {
        public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        message: "af82",
        signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
    Ed25519Vec {
        public_key: "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        message: "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        signature: "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    },
    Ed25519Vec {
        public_key: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        message: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        signature: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    },
];

/// Maximum message length across the vectors (the 1024-byte test is 1023 B).
const MSG_SCRATCH: usize = 1024;

fn hex_nibble(c: u8) -> Option<u8>
{
    match c
    {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode `hex` into `out`, returning the byte count, or `None` on bad input
/// or overflow.
fn parse_hex(hex: &str, out: &mut [u8]) -> Option<usize>
{
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) || bytes.len() / 2 > out.len()
    {
        return None;
    }
    let mut i = 0;
    while i < bytes.len() / 2
    {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(bytes.len() / 2)
}

/// Parse a vector's fields and run verification.
fn verify_vector(
    v: &Ed25519Vec,
    msg_buf: &mut [u8; MSG_SCRATCH],
) -> Result<Result<(), VerifyError>, &'static str>
{
    let mut pk = [0u8; 32];
    let mut sig = [0u8; 64];
    let pk_len = parse_hex(v.public_key, &mut pk).ok_or("ed25519: bad pk hex")?;
    let sig_len = parse_hex(v.signature, &mut sig).ok_or("ed25519: bad sig hex")?;
    let msg_len = parse_hex(v.message, msg_buf).ok_or("ed25519: bad msg hex")?;
    if pk_len != 32 || sig_len != 64
    {
        return Err("ed25519: wrong field length");
    }
    Ok(ed25519_verify(&pk, &msg_buf[..msg_len], &sig))
}

/// Run the Ed25519 known-answer tests (RFC 8032 §7.1 positives plus tamper
/// negatives). Returns the first failure as an error string. Compiled in all
/// builds so host and on-target (ktest) runs share identical logic.
///
/// # Errors
///
/// Returns a descriptive `&'static str` on the first failing case.
pub fn run_ed25519_kats() -> Result<(), &'static str>
{
    let mut msg = [0u8; MSG_SCRATCH];

    // Positive: every RFC vector must verify.
    for v in RFC8032_VECTORS
    {
        if verify_vector(v, &mut msg)? != Ok(())
        {
            return Err("ed25519: valid signature rejected");
        }
    }

    // Reparse TEST 2 (non-empty, short) as a base for tamper tests.
    let base = &RFC8032_VECTORS[1];
    let mut pk = [0u8; 32];
    let mut sig = [0u8; 64];
    let _ = parse_hex(base.public_key, &mut pk).ok_or("ed25519: bad pk hex")?;
    let _ = parse_hex(base.signature, &mut sig).ok_or("ed25519: bad sig hex")?;
    let mut bmsg = [0u8; MSG_SCRATCH];
    let bmsg_len = parse_hex(base.message, &mut bmsg).ok_or("ed25519: bad msg hex")?;

    // Flipped R byte of the signature → Mismatch.
    let mut bad_sig = sig;
    bad_sig[0] ^= 0x01;
    if ed25519_verify(&pk, &bmsg[..bmsg_len], &bad_sig) != Err(VerifyError::Mismatch)
    {
        return Err("ed25519: tampered signature accepted");
    }

    // Flipped message byte → Mismatch.
    let mut bad_msg = bmsg;
    bad_msg[0] ^= 0x01;
    if ed25519_verify(&pk, &bad_msg[..bmsg_len], &sig) != Err(VerifyError::Mismatch)
    {
        return Err("ed25519: tampered message accepted");
    }

    // Different valid public key → Mismatch.
    let mut other_pk = [0u8; 32];
    let _ = parse_hex(RFC8032_VECTORS[2].public_key, &mut other_pk).ok_or("ed25519: bad pk hex")?;
    if ed25519_verify(&other_pk, &bmsg[..bmsg_len], &sig) != Err(VerifyError::Mismatch)
    {
        return Err("ed25519: wrong-key signature accepted");
    }

    // S == L → NonCanonicalS (the mandatory range check).
    let mut sl_sig = sig;
    sl_sig[32..].copy_from_slice(&scalar::L);
    if ed25519_verify(&pk, &bmsg[..bmsg_len], &sl_sig) != Err(VerifyError::NonCanonicalS)
    {
        return Err("ed25519: non-canonical S accepted");
    }

    // Public key that is not a curve point → BadPublicKey.
    let mut not_a_point = [0u8; 32];
    not_a_point[0] = 2;
    if ed25519_verify(&not_a_point, &bmsg[..bmsg_len], &sig) != Err(VerifyError::BadPublicKey)
    {
        return Err("ed25519: invalid public key accepted");
    }

    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn kats_pass()
    {
        assert_eq!(run_ed25519_kats(), Ok(()));
    }
}
