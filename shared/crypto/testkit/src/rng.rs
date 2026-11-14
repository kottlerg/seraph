// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/rng.rs

//! A seeded, deterministic generator for differential inputs.
//!
//! Tests are deterministic (docs/coding-standards.md § D, Form): every
//! generated input comes from a fixed seed, so a failing case is reproduced by
//! running the test again. `SplitMix64` (Steele, Lea and Flood, 2014) is not a
//! cryptographic generator, and need not be: it only spreads inputs over the
//! space under test.

/// `SplitMix64`: a 64-bit state advanced by a constant, output through a mixer.
#[derive(Debug, Clone)]
pub struct Rng
{
    state: u64,
}

impl Rng
{
    /// A generator whose output is fixed by `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self
    {
        Self { state: seed }
    }

    /// The next 64 output bits.
    pub fn next_u64(&mut self) -> u64
    {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`; 0 when `bound` is 0. The modulo bias is
    /// immaterial to input generation.
    pub fn below(&mut self, bound: usize) -> usize
    {
        let bound = u64::try_from(bound).unwrap_or(u64::MAX);
        let value = self.next_u64().checked_rem(bound).unwrap_or(0);
        usize::try_from(value).unwrap_or(0)
    }

    /// Fill `out` with output bytes.
    pub fn fill(&mut self, out: &mut [u8])
    {
        for chunk in out.chunks_mut(8)
        {
            let word = self.next_u64().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(word)
            {
                *dst = src;
            }
        }
    }

    /// `len` output bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8>
    {
        let mut out = vec![0; len];
        self.fill(&mut out);
        out
    }

    /// An array of output bytes.
    pub fn array<const N: usize>(&mut self) -> [u8; N]
    {
        let mut out = [0; N];
        self.fill(&mut out);
        out
    }
}
