// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/entropy/keccak.rs

//! Keccak-f[1600] permutation (FIPS 202).
//!
//! The single cryptographic primitive underlying the entropy subsystem. The
//! sponge layer in [`super::sponge`] builds the forward-secure duplex PRNG on
//! top of this permutation (its plumbing is anchored by a test-only SHAKE256),
//! so correctness here is load-bearing for the whole subsystem and is anchored
//! by known-answer tests (raw zero-state vector and `SHAKE256("")`).
//!
//! The implementation is the canonical compact form (24 rounds; θ, ρ, π, χ, ι),
//! with the ρ and π lane walk unrolled.
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

/// Number of 64-bit lanes in the Keccak-f[1600] state.
pub const LANES: usize = 25;

/// The ρ and π steps, unrolled: each `(j, r)` pair, in π-traversal order,
/// moves the carried lane into `state[j]` rotated left by `r` and carries the
/// lane it replaces to the next pair; the last pair closes the cycle, so its
/// lane is dropped. The literal indices keep every lane access a constant
/// index into the state array.
macro_rules! rho_pi {
    ($state:ident, $carry:ident; ($j:literal, $r:literal)) => {
        $state[$j] = $carry.rotate_left($r);
    };
    ($state:ident, $carry:ident; ($j:literal, $r:literal), $($rest:tt)+) => {
        let next = $state[$j];
        $state[$j] = $carry.rotate_left($r);
        $carry = next;
        rho_pi!($state, $carry; $($rest)+);
    };
}

/// Apply the Keccak-f[1600] permutation in place.
pub fn keccak_f1600(state: &mut [u64; LANES])
{
    for &rc in &RC
    {
        // θ: the parity of each column, folded over the five rows.
        let mut c = [0u64; 5];
        for row in state.as_chunks::<5>().0
        {
            for (parity, &lane) in c.iter_mut().zip(row)
            {
                *parity ^= lane;
            }
        }
        let d = [
            c[4] ^ c[1].rotate_left(1),
            c[0] ^ c[2].rotate_left(1),
            c[1] ^ c[3].rotate_left(1),
            c[2] ^ c[4].rotate_left(1),
            c[3] ^ c[0].rotate_left(1),
        ];
        for row in state.as_chunks_mut::<5>().0
        {
            for (lane, &dx) in row.iter_mut().zip(&d)
            {
                *lane ^= dx;
            }
        }

        // ρ and π
        let mut carry = state[1];
        rho_pi!(state, carry;
            (10, 1), (7, 3), (11, 6), (17, 10), (18, 15), (3, 21), (5, 28), (16, 36),
            (8, 45), (21, 55), (24, 2), (4, 14), (15, 27), (23, 41), (19, 56), (13, 8),
            (12, 25), (2, 43), (20, 62), (14, 18), (22, 39), (9, 61), (6, 20), (1, 44)
        );

        // χ
        for row in state.as_chunks_mut::<5>().0
        {
            let b = *row;
            row[0] ^= !b[1] & b[2];
            row[1] ^= !b[2] & b[3];
            row[2] ^= !b[3] & b[4];
            row[3] ^= !b[4] & b[0];
            row[4] ^= !b[0] & b[1];
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
