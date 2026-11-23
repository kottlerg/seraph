// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/rng.rs

//! The engine's pseudo-random number generator: xoshiro256** seeded through
//! `SplitMix64`, so the one `u64` seed of a run fixes every choice it makes.

/// A xoshiro256** generator (Blackman and Vigna).
pub struct Rng
{
    state: [u64; 4],
}

impl Rng
{
    /// The generator of `seed`: its four words are the first four outputs of
    /// `SplitMix64` from `seed`, which are never all zero.
    #[must_use]
    pub fn new(seed: u64) -> Self
    {
        let mut x = seed;
        let mut next = || {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ z.wrapping_shr(30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ z.wrapping_shr(27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ z.wrapping_shr(31)
        };
        Self {
            state: [next(), next(), next(), next()],
        }
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64
    {
        let [mut s0, mut s1, mut s2, mut s3] = self.state;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1.wrapping_shl(17);
        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;
        s2 ^= t;
        s3 = s3.rotate_left(45);
        self.state = [s0, s1, s2, s3];
        result
    }

    /// A number below `bound` (Lemire's multiply-shift), or 0 when `bound`
    /// is 0.
    pub fn below(&mut self, bound: u64) -> u64
    {
        let wide = u128::from(self.next_u64()).wrapping_mul(u128::from(bound));
        u64::try_from(wide.wrapping_shr(64)).unwrap_or(0)
    }

    /// An index below `bound`, or 0 when `bound` is 0.
    pub fn index(&mut self, bound: usize) -> usize
    {
        let bound = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.below(bound)).unwrap_or(0)
    }

    /// True with probability `1 / denominator`.
    pub fn one_in(&mut self, denominator: u64) -> bool
    {
        self.below(denominator) == 0
    }

    /// A random byte.
    pub fn byte(&mut self) -> u8
    {
        let [byte, ..] = self.next_u64().to_le_bytes();
        byte
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a generator whose output depends on anything but the
    // seed, which would make a fixed-seed run irreproducible.
    #[test]
    fn one_seed_gives_one_sequence_and_another_seed_another()
    {
        let draw = |seed| {
            let mut rng = Rng::new(seed);
            (0..8).map(|_| rng.next_u64()).collect::<Vec<u64>>()
        };
        assert_eq!(draw(0), draw(0));
        assert_ne!(draw(0), draw(1));
    }

    #[test]
    fn below_stays_under_its_bound_and_reaches_every_value()
    {
        let mut rng = Rng::new(7);
        let mut seen = [false; 5];
        for _ in 0..1000
        {
            let value = rng.below(5);
            assert!(value < 5, "{value}");
            seen[usize::try_from(value).unwrap()] = true;
        }
        assert_eq!(seen, [true; 5]);
        assert_eq!(rng.below(0), 0);
        assert_eq!(rng.index(0), 0);
    }
}
