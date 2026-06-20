// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/sha512.rs

//! SHA-512 (FIPS 180-4).
//!
//! 1024-bit (128-byte) blocks, 64-bit words, 80 rounds, big-endian byte and
//! word convention throughout. Provides a one-shot [`sha512`] and an
//! incremental [`Sha512`] so large inputs hash without being buffered whole.
//!
//! Correctness is anchored by the known-answer tests in [`run_sha512_kats`]
//! (FIPS 180-4 Appendix C vectors plus incremental/padding-boundary
//! self-consistency checks).

/// Output length in bytes.
pub const DIGEST_LEN: usize = 64;

/// Block length in bytes (1024-bit).
const BLOCK_LEN: usize = 128;

/// Initial hash value (FIPS 180-4 §5.3.5): first 64 bits of the fractional
/// parts of the square roots of the first eight primes.
const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Round constants (FIPS 180-4 §4.2.3): first 64 bits of the fractional parts
/// of the cube roots of the first eighty primes.
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64
{
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64
{
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn big_sigma0(x: u64) -> u64
{
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline]
fn big_sigma1(x: u64) -> u64
{
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline]
fn small_sigma0(x: u64) -> u64
{
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline]
fn small_sigma1(x: u64) -> u64
{
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// Compress one 128-byte block into the chaining state `h` (FIPS 180-4 §6.4).
// many_single_char_names: a..h are the FIPS 180-4 working-variable names;
// renaming them would obscure the published algorithm.
#[allow(clippy::many_single_char_names)]
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_LEN])
{
    let mut w = [0u64; 80];
    let mut t = 0;
    while t < 16
    {
        let off = t * 8;
        w[t] = u64::from_be_bytes([
            block[off],
            block[off + 1],
            block[off + 2],
            block[off + 3],
            block[off + 4],
            block[off + 5],
            block[off + 6],
            block[off + 7],
        ]);
        t += 1;
    }
    while t < 80
    {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
        t += 1;
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    let mut i = 0;
    while i < 80
    {
        let t1 = hh
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Incremental SHA-512 state.
#[derive(Clone)]
pub struct Sha512
{
    h: [u64; 8],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    total_len: u128,
}

impl Sha512
{
    /// Start a fresh hash.
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            h: IV,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Absorb `data`. May be called any number of times.
    pub fn update(&mut self, data: &[u8])
    {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);
        let mut data = data;

        // Top up a partial buffer first.
        if self.buf_len > 0
        {
            let take = core::cmp::min(BLOCK_LEN - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_LEN
            {
                let block = self.buf;
                compress(&mut self.h, &block);
                self.buf_len = 0;
            }
        }

        // Consume whole blocks straight from the input.
        while data.len() >= BLOCK_LEN
        {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(&data[..BLOCK_LEN]);
            compress(&mut self.h, &block);
            data = &data[BLOCK_LEN..];
        }

        // Stash the remainder.
        if !data.is_empty()
        {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Pad and emit the 64-byte digest, consuming the state.
    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_LEN]
    {
        // FIPS 180-4 §5.1.2: append 0x80, zero-pad so the length lands in the
        // final 16 bytes of a block, then the 128-bit big-endian bit length.
        let bit_len: u128 = self.total_len << 3;

        let mut pad = self.buf_len;
        self.buf[pad] = 0x80;
        pad += 1;

        if pad > BLOCK_LEN - 16
        {
            // Length field spills into a second block: flush this one first.
            for byte in &mut self.buf[pad..BLOCK_LEN]
            {
                *byte = 0;
            }
            let block = self.buf;
            compress(&mut self.h, &block);
            pad = 0;
        }

        for byte in &mut self.buf[pad..BLOCK_LEN - 16]
        {
            *byte = 0;
        }
        self.buf[BLOCK_LEN - 16..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        compress(&mut self.h, &block);

        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in self.h.iter().enumerate()
        {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl Default for Sha512
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// One-shot SHA-512 of `data`.
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; DIGEST_LEN]
{
    let mut s = Sha512::new();
    s.update(data);
    s.finalize()
}

// ── Known-answer tests ───────────────────────────────────────────────────────

struct Sha512Kat
{
    msg: &'static [u8],
    digest: [u8; DIGEST_LEN],
}

/// FIPS 180-4 Appendix C vectors plus the empty-string vector.
const SHA512_KATS: &[Sha512Kat] = &[
    // SHA-512("")
    Sha512Kat {
        msg: b"",
        digest: [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ],
    },
    // FIPS 180-4 C.1: SHA-512("abc")
    Sha512Kat {
        msg: b"abc",
        digest: [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ],
    },
    // FIPS 180-4 C.2: the 112-byte two-block message.
    Sha512Kat {
        msg: b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        digest: [
            0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc,
            0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad,
            0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b,
            0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
            0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
        ],
    },
];

/// Run the SHA-512 known-answer tests. Returns the first failing case as an
/// error string, or `Ok(())` if all pass. Compiled in all builds so host and
/// on-target (ktest) runs share identical logic.
///
/// # Errors
///
/// Returns a descriptive `&'static str` on the first mismatch.
pub fn run_sha512_kats() -> Result<(), &'static str>
{
    for kat in SHA512_KATS
    {
        if sha512(kat.msg) != kat.digest
        {
            return Err("sha512: KAT digest mismatch");
        }
    }

    // Incremental must equal one-shot regardless of chunk boundaries.
    let mut s = Sha512::new();
    s.update(b"a");
    s.update(b"bc");
    if s.finalize() != sha512(b"abc")
    {
        return Err("sha512: incremental != one-shot");
    }

    // Padding-boundary self-consistency: one-shot must equal byte-at-a-time for
    // lengths around the 112/128 padding edges and across multiple blocks.
    let scratch = [0x61u8; 300];
    for &len in &[
        0usize, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 200, 256, 300,
    ]
    {
        let msg = &scratch[..len];
        let mut inc = Sha512::new();
        for b in msg
        {
            inc.update(core::slice::from_ref(b));
        }
        if inc.finalize() != sha512(msg)
        {
            return Err("sha512: padding-boundary inconsistency");
        }
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
        assert_eq!(run_sha512_kats(), Ok(()));
    }
}
