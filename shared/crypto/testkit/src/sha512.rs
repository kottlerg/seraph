// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/sha512.rs

//! The SHA-512 reference digest and the differential inputs: messages of
//! every length around the padding and block boundaries, and generated
//! messages with the points at which an incremental hasher is fed.
//!
//! The reference is `RustCrypto`'s `sha2`, an implementation independent of
//! `shared/crypto`.

use std::fmt;

use sha2::{Digest, Sha512};

use crate::hex;
use crate::rng::Rng;

/// The reference SHA-512 digest of `data`.
#[must_use]
pub fn reference(data: &[u8]) -> [u8; 64]
{
    let mut out = [0u8; 64];
    out.copy_from_slice(&Sha512::digest(data));
    out
}

/// One message, and the ascending offsets at which an incremental hasher
/// splits it into `update` calls.
#[derive(Clone, PartialEq, Eq)]
pub struct Input
{
    /// The message.
    pub data: Vec<u8>,
    /// The split offsets, ascending, each at most `data.len()`.
    pub cuts: Vec<usize>,
}

impl fmt::Debug for Input
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "{} bytes, cuts {:?}: {}",
            self.data.len(),
            self.cuts,
            hex::encode(&self.data)
        )
    }
}

impl Input
{
    /// The message split at `cuts`: the pieces an incremental hasher is fed,
    /// empty pieces included.
    #[must_use]
    pub fn pieces(&self) -> Vec<&[u8]>
    {
        let mut pieces = Vec::new();
        let mut start = 0;
        for &cut in &self.cuts
        {
            pieces.push(self.data.get(start..cut).unwrap_or_default());
            start = cut;
        }
        pieces.push(self.data.get(start..).unwrap_or_default());
        pieces
    }
}

/// Every length from 0 to 300 bytes (the 111/112-byte padding boundary and
/// the 128- and 256-byte block boundaries among them), and longer messages
/// of several blocks, from `seed`; each split at random offsets, one of them
/// on a block boundary when the message reaches it.
#[must_use]
pub fn generated(seed: u64, long: usize) -> Vec<Input>
{
    let mut rng = Rng::new(seed);
    let mut lengths: Vec<usize> = (0..=300).collect();
    lengths.extend((0..long).map(|_| rng.below(8192)));
    lengths
        .into_iter()
        .map(|len| {
            let data = rng.bytes(len);
            let mut cuts: Vec<usize> = (0..rng.below(4))
                .map(|_| rng.below(len.wrapping_add(1)))
                .collect();
            if len >= 128
            {
                cuts.push(128);
            }
            cuts.sort_unstable();
            Input { data, cuts }
        })
        .collect()
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn pieces_cover_the_message_in_order_with_empty_pieces_kept()
    {
        let input = Input {
            data: b"abcdef".to_vec(),
            cuts: vec![0, 2, 2, 6],
        };
        let pieces: Vec<&[u8]> = input.pieces();
        assert_eq!(pieces, [&b""[..], b"ab", b"", b"cdef", b""]);
    }
}
