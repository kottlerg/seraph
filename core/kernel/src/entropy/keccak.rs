// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/entropy/keccak.rs

//! Keccak-f[1600] permutation (FIPS 202).
//!
//! The single cryptographic primitive underlying the entropy subsystem. The
//! sponge layer in [`super::sponge`] builds the SHAKE256 XOF and the
//! forward-secure duplex PRNG on top of this permutation, so correctness here
//! is load-bearing for the whole subsystem and is anchored by known-answer
//! tests (raw zero-state vector and `SHAKE256("")`).
//!
//! The implementation is the canonical compact form (24 rounds; θ, ρ, π, χ, ι).
//! State lanes are 64-bit, addressed `lane(x, y) = state[x + 5*y]`, with bytes
//! mapped little-endian when the sponge loads or stores rate blocks.

/// Round constants for the ι step (one per round).
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for the ρ step, in π-traversal order.
const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane permutation indices for the π step, in traversal order.
const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Number of 64-bit lanes in the Keccak-f[1600] state.
pub const LANES: usize = 25;

/// Apply the Keccak-f[1600] permutation in place.
pub fn keccak_f1600(state: &mut [u64; LANES])
{
    let mut bc = [0u64; 5];

    for &rc in &RC
    {
        // θ
        for i in 0..5
        {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for i in 0..5
        {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            let mut j = 0;
            while j < LANES
            {
                state[j + i] ^= t;
                j += 5;
            }
        }

        // ρ and π
        let mut t = state[1];
        for i in 0..24
        {
            let j = PILN[i];
            let tmp = state[j];
            state[j] = t.rotate_left(ROTC[i]);
            t = tmp;
        }

        // χ
        let mut j = 0;
        while j < LANES
        {
            bc.copy_from_slice(&state[j..j + 5]);
            for i in 0..5
            {
                state[j + i] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
            j += 5;
        }

        // ι
        state[0] ^= rc;
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Keccak-f[1600] applied to the all-zero state — the FIPS 202 / XKCP
    /// intermediate-value vector for lanes (0,0) and (1,0).
    #[test]
    fn zero_state_vector()
    {
        let mut st = [0u64; LANES];
        keccak_f1600(&mut st);
        assert_eq!(st[0], 0xF125_8F79_40E1_DDE7);
        assert_eq!(st[1], 0x84D5_CCF9_33C0_478A);
    }

    /// Two applications differ from one (sanity that rounds are not idempotent).
    #[test]
    fn not_idempotent()
    {
        let mut a = [0u64; LANES];
        keccak_f1600(&mut a);
        let mut b = a;
        keccak_f1600(&mut b);
        assert_ne!(a, b);
    }
}
