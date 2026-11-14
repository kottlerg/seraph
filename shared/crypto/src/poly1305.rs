// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/poly1305.rs

//! The Poly1305 one-time authenticator (RFC 8439 § 2.5).
//!
//! The accumulator and the clamped key half `r` are held in three limbs of
//! radix 2^44 (44, 44 and 42 bits), so each product of a limb and a key limb
//! fits a `u128` with room for the sums of three. Every operation on the key,
//! the accumulator and the message is an addition, a multiplication, a shift
//! or rotation by a constant, or a mask: no branch and no index depends on
//! them. The final reduction modulo 2^130 - 5 picks between two candidates
//! with a mask, which [`core::hint::black_box`] hides from the optimiser so it
//! cannot turn the pick into a branch.

/// Key length in bytes: `r` and `s`, 16 bytes each.
pub(crate) const KEY_LEN: usize = 32;

/// Tag length in bytes.
pub(crate) const TAG_LEN: usize = 16;

/// Message block length in bytes.
const BLOCK_LEN: usize = 16;

/// The low 44 bits.
const MASK44: u64 = 0x0fff_ffff_ffff;

/// The low 42 bits.
const MASK42: u64 = 0x03ff_ffff_ffff;

/// The bit a full block adds above its 128 bits, 2^128, in the top limb.
const FULL_BLOCK_BIT: u64 = 1 << 40;

/// The low 64 bits of `value`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the truncation to the low 64 bits is the operation; every caller masks or \
              shifts the result to a limb"
)]
fn low64(value: u128) -> u64
{
    value as u64
}

/// The product of two limbs.
fn mul(a: u64, b: u64) -> u128
{
    u128::from(a).wrapping_mul(u128::from(b))
}

/// `bytes` read as little-endian 64-bit words, as many as fit.
fn le_words<const N: usize>(bytes: &[u8]) -> [u64; N]
{
    let mut words = [0u64; N];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0)
    {
        *word = u64::from_le_bytes(*chunk);
    }
    words
}

/// A Poly1305 computation under one key.
pub(crate) struct Poly1305
{
    /// The clamped `r`, in three limbs.
    r0: u64,
    r1: u64,
    r2: u64,
    /// `20 r1` and `20 r2`: a product's part at or above 2^130, reduced by
    /// 2^130 = 5 (mod p), lands in the limbs below shifted by 2 bits.
    s1: u64,
    s2: u64,
    /// The accumulator, in three limbs, partially reduced.
    h0: u64,
    h1: u64,
    h2: u64,
    /// `s`, the half of the key added at the end, as two words.
    pad0: u64,
    pad1: u64,
}

impl Poly1305
{
    /// Start a computation under the one-time `key` (`r` then `s`), clamping
    /// `r` as RFC 8439 § 2.5 requires.
    pub(crate) fn new(key: &[u8; KEY_LEN]) -> Self
    {
        let [t0, t1, pad0, pad1] = le_words::<4>(key);
        // The clamp, split into limbs: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff.
        let r0 = t0 & 0x0ffc_0fff_ffff;
        let r1 = ((t0 >> 44) | (t1 << 20)) & 0x0fff_ffc0_ffff;
        let r2 = (t1 >> 24) & 0x000f_ffff_fc0f;
        Self {
            r0,
            r1,
            r2,
            s1: r1.wrapping_mul(20),
            s2: r2.wrapping_mul(20),
            h0: 0,
            h1: 0,
            h2: 0,
            pad0,
            pad1,
        }
    }

    /// Absorb one 16-byte block, `top_bit` being [`FULL_BLOCK_BIT`] for a
    /// full block and 0 for a final partial one, which carries its own 1
    /// byte: h = (h + block) * r, partially reduced.
    fn compress(&mut self, block: &[u8; BLOCK_LEN], top_bit: u64)
    {
        let [t0, t1] = le_words::<2>(block);
        let h0 = self.h0.wrapping_add(t0 & MASK44);
        let h1 = self.h1.wrapping_add(((t0 >> 44) | (t1 << 20)) & MASK44);
        let h2 = self.h2.wrapping_add(((t1 >> 24) & MASK42) | top_bit);

        let (r0, r1, r2, s1, s2) = (self.r0, self.r1, self.r2, self.s1, self.s2);
        let d0 = mul(h0, r0)
            .wrapping_add(mul(h1, s2))
            .wrapping_add(mul(h2, s1));
        let d1 = mul(h0, r1)
            .wrapping_add(mul(h1, r0))
            .wrapping_add(mul(h2, s2));
        let d2 = mul(h0, r2)
            .wrapping_add(mul(h1, r1))
            .wrapping_add(mul(h2, r0));

        let d1 = d1.wrapping_add(d0 >> 44);
        let d2 = d2.wrapping_add(d1 >> 44);
        // The part at or above 2^130 folds back in times 5.
        let h0 = (low64(d0) & MASK44).wrapping_add(low64(d2 >> 42).wrapping_mul(5));
        self.h0 = h0 & MASK44;
        self.h1 = (low64(d1) & MASK44).wrapping_add(h0 >> 44);
        self.h2 = low64(d2) & MASK42;
    }

    /// Absorb `data` as the AEAD construction does (RFC 8439 § 2.8): in full
    /// 16-byte blocks, the last one zero-padded to 16 bytes.
    pub(crate) fn update_padded(&mut self, data: &[u8])
    {
        let (blocks, rest) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks
        {
            self.compress(block, FULL_BLOCK_BIT);
        }
        if !rest.is_empty()
        {
            let mut last = [0u8; BLOCK_LEN];
            for (dst, src) in last.iter_mut().zip(rest)
            {
                *dst = *src;
            }
            self.compress(&last, FULL_BLOCK_BIT);
        }
    }

    /// Absorb `message` whole, as the authenticator alone does (RFC 8439
    /// § 2.5): a final partial block takes a 1 byte after its last byte in
    /// place of the bit above a full block.
    fn update_message(&mut self, message: &[u8])
    {
        let (blocks, rest) = message.as_chunks::<BLOCK_LEN>();
        for block in blocks
        {
            self.compress(block, FULL_BLOCK_BIT);
        }
        if !rest.is_empty()
        {
            let mut last = [0u8; BLOCK_LEN];
            for (dst, src) in last.iter_mut().zip(rest)
            {
                *dst = *src;
            }
            // `rest` is shorter than a block, so the byte after it exists.
            if let Some(one) = last.get_mut(rest.len())
            {
                *one = 1;
            }
            self.compress(&last, 0);
        }
    }

    /// The tag: the accumulator fully reduced modulo 2^130 - 5, plus `s`,
    /// modulo 2^128, little-endian.
    ///
    /// Out of line so that its compiled body, the one place a candidate is
    /// picked by a mask, can be read on its own.
    #[inline(never)]
    pub(crate) fn finalize(self) -> [u8; TAG_LEN]
    {
        let (h0, h1, h2) = self.carried();

        // g = h + 5 - 2^130, which is non-negative exactly when h >= p.
        let g0 = h0.wrapping_add(5);
        let g1 = h1.wrapping_add(g0 >> 44);
        let g2 = h2.wrapping_add(g1 >> 44).wrapping_sub(1 << 42);
        let (g0, g1) = (g0 & MASK44, g1 & MASK44);

        // All ones when g's sign bit is clear (h >= p: take g), else zero.
        let take_g = core::hint::black_box((g2 >> 63).wrapping_sub(1));
        let h0 = (h0 & !take_g) | (g0 & take_g);
        let h1 = (h1 & !take_g) | (g1 & take_g);
        let h2 = (h2 & !take_g) | (g2 & take_g);

        // h + s, modulo 2^128.
        let (t0, t1) = (self.pad0, self.pad1);
        let h0 = h0.wrapping_add(t0 & MASK44);
        let h1 = h1
            .wrapping_add(((t0 >> 44) | (t1 << 20)) & MASK44)
            .wrapping_add(h0 >> 44);
        let h2 = h2.wrapping_add((t1 >> 24) & MASK42).wrapping_add(h1 >> 44);
        let (h0, h1, h2) = (h0 & MASK44, h1 & MASK44, h2 & MASK42);

        let low = h0 | (h1 << 44);
        let high = (h1 >> 20) | (h2 << 24);
        let mut tag = [0u8; TAG_LEN];
        for (bytes, word) in tag.as_chunks_mut::<8>().0.iter_mut().zip([low, high])
        {
            *bytes = word.to_le_bytes();
        }
        tag
    }

    /// The accumulator with every carry propagated twice, each limb within its
    /// width and the whole below 2^130.
    fn carried(&self) -> (u64, u64, u64)
    {
        let (mut h0, mut h1, mut h2) = (self.h0, self.h1, self.h2);
        for _ in 0..2
        {
            h2 = h2.wrapping_add(h1 >> 44);
            h1 &= MASK44;
            h0 = h0.wrapping_add((h2 >> 42).wrapping_mul(5));
            h2 &= MASK42;
            h1 = h1.wrapping_add(h0 >> 44);
            h0 &= MASK44;
        }
        (h0, h1, h2)
    }
}

/// The Poly1305 tag of `message` under the one-time `key` (RFC 8439 § 2.5).
pub(crate) fn mac(key: &[u8; KEY_LEN], message: &[u8]) -> [u8; TAG_LEN]
{
    let mut state = Poly1305::new(key);
    state.update_message(message);
    state.finalize()
}
