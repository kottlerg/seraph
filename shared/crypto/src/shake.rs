// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/shake.rs

//! SHAKE128 and SHAKE256 (FIPS 202 § 6.2), the extendable-output functions
//! ML-DSA hashes and samples with.
//!
//! [`Shake`] absorbs input in any number of pieces; [`Shake::finalize`] pads
//! it and returns an [`XofReader`], which squeezes output in any number of
//! pieces. The type change keeps a caller from absorbing after squeezing.
//! [`shake128`] and [`shake256`] are the one-shot forms.
//!
//! Every branch and index depends on the input and output lengths only, and
//! the permutation is constant-time ([`crate::keccak`]), so the signer may pass
//! secret values through it.
//!
//! Correctness is anchored by the known-answer tests in [`run_shake_kats`]
//! (the Keccak-f[1600] zero-state vector, the empty-message outputs and NIST
//! ACVP SHAKE cases), run on the host and on target.

use crate::kat_hex::hex;
use crate::keccak::{LANES, keccak_f1600};

/// The SHAKE128 rate in bytes (1344 bits; capacity 256 bits).
pub const SHAKE128_RATE: usize = 168;

/// The SHAKE256 rate in bytes (1088 bits; capacity 512 bits).
pub const SHAKE256_RATE: usize = 136;

/// The first padding byte: SHAKE's domain-separation suffix `1111` followed by
/// the first bit of `pad10*1` (FIPS 202 § 6.2 and § 5.1), in the
/// little-endian bit order of the state.
const SUFFIX: u8 = 0x1f;

/// The last bit of `pad10*1`, in the final byte of the rate.
const LAST_PAD: u8 = 0x80;

/// An extendable-output function in its absorbing phase: SHAKE128 or SHAKE256
/// by its rate.
#[derive(Clone)]
pub struct Shake<const RATE: usize>
{
    state: [u64; LANES],
    /// Bytes of the current block absorbed so far; always below `RATE`.
    offset: usize,
}

/// SHAKE128 (FIPS 202 § 6.2).
pub type Shake128 = Shake<SHAKE128_RATE>;

/// SHAKE256 (FIPS 202 § 6.2).
pub type Shake256 = Shake<SHAKE256_RATE>;

/// An extendable-output function in its squeezing phase.
#[derive(Clone)]
pub struct XofReader<const RATE: usize>
{
    state: [u64; LANES],
    /// Bytes of the current block squeezed so far; at most `RATE`.
    offset: usize,
}

/// XOR `byte` into byte `index` of the state, little-endian within each lane.
/// An index past the state is ignored; every caller passes one below the rate.
fn xor_byte(state: &mut [u64; LANES], index: usize, byte: u8)
{
    if let Some(lane) = state.get_mut(index / 8)
    {
        let mut bytes = lane.to_le_bytes();
        if let Some(b) = bytes.get_mut(index % 8)
        {
            *b ^= byte;
        }
        *lane = u64::from_le_bytes(bytes);
    }
}

/// Byte `index` of the state, little-endian within each lane; 0 past the state,
/// which no caller reaches since every index is below the rate.
fn state_byte(state: &[u64; LANES], index: usize) -> u8
{
    state
        .get(index / 8)
        .and_then(|lane| lane.to_le_bytes().get(index % 8).copied())
        .unwrap_or(0)
}

/// XOR a block of whole lanes into the front of the state.
fn xor_lanes(state: &mut [u64; LANES], block: &[u8])
{
    for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0)
    {
        *lane ^= u64::from_le_bytes(*bytes);
    }
}

impl<const RATE: usize> Shake<RATE>
{
    /// An empty input.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            state: [0; LANES],
            offset: 0,
        }
    }

    /// Absorb `data`. May be called any number of times.
    pub fn update(&mut self, data: &[u8])
    {
        let mut data = data;
        // Top up a partial block a byte at a time.
        while self.offset != 0
        {
            let Some((&byte, rest)) = data.split_first()
            else
            {
                return;
            };
            xor_byte(&mut self.state, self.offset, byte);
            self.offset = self.offset.saturating_add(1);
            data = rest;
            if self.offset == RATE
            {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
        }
        // Whole blocks a lane at a time (both rates are whole lanes).
        while let (Some(block), Some(rest)) = (data.get(..RATE), data.get(RATE..))
        {
            xor_lanes(&mut self.state, block);
            keccak_f1600(&mut self.state);
            data = rest;
        }
        // The remainder, shorter than a block.
        for (index, &byte) in data.iter().enumerate()
        {
            xor_byte(&mut self.state, index, byte);
        }
        self.offset = data.len();
    }

    /// Pad the input and start squeezing.
    #[must_use]
    pub fn finalize(mut self) -> XofReader<RATE>
    {
        xor_byte(&mut self.state, self.offset, SUFFIX);
        xor_byte(&mut self.state, RATE.saturating_sub(1), LAST_PAD);
        keccak_f1600(&mut self.state);
        XofReader {
            state: self.state,
            offset: 0,
        }
    }
}

impl<const RATE: usize> Default for Shake<RATE>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<const RATE: usize> XofReader<RATE>
{
    /// Fill `out` with the next output bytes. May be called any number of
    /// times; the output continues where the previous call stopped.
    pub fn read(&mut self, out: &mut [u8])
    {
        let mut out = out;
        while !out.is_empty()
        {
            if self.offset == RATE
            {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
            let take = core::cmp::min(RATE.saturating_sub(self.offset), out.len());
            let (head, rest) = out.split_at_mut(take);
            for (index, byte) in head.iter_mut().enumerate()
            {
                *byte = state_byte(&self.state, self.offset.saturating_add(index));
            }
            self.offset = self.offset.saturating_add(take);
            out = rest;
        }
    }
}

/// One-shot SHAKE128: `out.len()` bytes of output for `data`.
pub fn shake128(data: &[u8], out: &mut [u8])
{
    let mut xof = Shake128::new();
    xof.update(data);
    xof.finalize().read(out);
}

/// One-shot SHAKE256: `out.len()` bytes of output for `data`.
pub fn shake256(data: &[u8], out: &mut [u8])
{
    let mut xof = Shake256::new();
    xof.update(data);
    xof.finalize().read(out);
}

// ── Known-answer tests ───────────────────────────────────────────────────────

/// Keccak-f[1600] applied to the all-zero state: the first two lanes of the
/// FIPS 202 / XKCP intermediate-value vector.
static ZERO_STATE_LANES: [u64; 2] = [0xF125_8F79_40E1_DDE7, 0x84D5_CCF9_33C0_478A];

/// SHAKE128 of the empty message, the first 32 bytes.
static SHAKE128_EMPTY: [u8; 32] =
    hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");

/// SHAKE256 of the empty message, the first 64 bytes.
static SHAKE256_EMPTY: [u8; 64] = hex(concat!(
    "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
    "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
));

// NIST ACVP-Server, gen-val/json-files/SHAKE-{128,256}-FIPS202/internalProjection.json at
// commit 975de31eb83d87039ec88934fdc47d8c312b892d (AFT cases, whole-byte lengths).

// SHAKE128, tcId 15: a 33-byte message, 47 bytes of output.
static SHAKE128_TC15_MSG: [u8; 33] =
    hex("8feb2504b174870c1f7d1f93a3e5e117738e0c30e7ecd735e0d2a3c36b2dcc321d");
static SHAKE128_TC15_OUT: [u8; 47] = hex(
    "0d91c894748e13f58bff97d48abae783f5cb6ed4fca76a3002a1592d9acbc38c6f3f0806f9518af7fcfee24b2964df",
);
// SHAKE128, tcId 20: a 681-byte message, 42 bytes of output.
static SHAKE128_TC20_MSG: [u8; 681] = hex(concat!(
    "02902fb50244d5043050aa9116870e944478a3bfe8fc37a76f69d850831eb3a77f70fae88af237ed9e2eb0b766429e13",
    "16ac9fe4b9458cfc79b9a839327333e10810d4b59b2441e45c5d0575f9b16118a30ac4b600bbb75325950ccbd7934aa3",
    "a4aa68c75b411eda639fa07098b192868480cd7d17d78b71d72ff6bafea484fccd9d268c37e5987087db8e8c2d8e821b",
    "4f0b6f5b901841ca36a0acf3b2a6b5f12ccdff1bcde291f4db5d9559a2c2118422a860b495b0c9cdb9f36ec8d974ce1c",
    "34304e3f13a5c4b0bf050c5ae5fbbea468866780c3ea227a0c12c0919250f9e8b87a5461677a0b8a29239eb82bd6df7a",
    "850019d35c86978992b5b91e2fedd35ebd3731c57543a5825ac3075a73b430c630f07e65afb71fe93fc9a50cfc654d30",
    "7e126d5b9d106b0366c88b7b70d75237c2b6837d1d51702a92ced5e0470c4ae53f7832c6ecf27db46e9cb720e2b2b715",
    "aaec19474b8da8b0d8594d1ac4d99f1de86d2d28ecfd24dbfece0ac6014984e0e99abae62a33536da01ec310ce7b8378",
    "62b8696692a1af64d3447a9efa49ce9c691c96485202d652d4c0c99b61f71f796d050fd0e6eefc7fe20ce90186272d69",
    "ba2508eef4f07e72894f548f209170bc4500c528b289c1720a8b38d07460a22950e92cd2b4657a332dc259a760070a1b",
    "dc5d6128507d53e7f7bd536e24ab34e3f7b5962bac4d1aa62916a60570b82f5ef95c7ba84399dee614d920cf0ca349d3",
    "c8ca60906504775806a4c22e6468c0178c5f126d7efcad5745fc2f24a6204beb450b6e31d0bcbe0ccafaa5f0f124e344",
    "fdc6ef578f8fde36fb304c24104253ab95b35348acbede7cb7a2fc5d32a88792204067facce19f98531befae3876aec7",
    "58d89979b6048564c0bb392f273251eade849abf0aac832f2c094c31239e37f1d1248f84936617bbff71a64f10cca1a0",
    "4d124d70677fece85c",
));
static SHAKE128_TC20_OUT: [u8; 42] =
    hex("99a0c2d891dac6ae6da5aac77cac3e14e12695498421964a321d87904ec205f5bb5148e8b642442ed376");
// SHAKE256, tcId 34: a 5-byte message, 258 bytes of output.
static SHAKE256_TC34_MSG: [u8; 5] = hex("3ed3ac6f01");
static SHAKE256_TC34_OUT: [u8; 258] = hex(concat!(
    "2cfa669dc2130f33e47733993838908404c4d46f6e7a5c6ce9cb73bc952b0e45982fb0618411e4ed7589217734ba268f",
    "ad7ff30f62d83f78cffec21ed4b2c96d76924bc2c302b19d760e84fadb7433bec65085ad9c7a2815e29fe6606ca98916",
    "b9f107f57f024ed788433b97aeed802c207258d037a59ba27ab18496c706746a2ab1325723823ea1a56d733aee658460",
    "f367b73232dc090bb7bc5bbe478c4283d67496b721e0bfc7e55dcd63c49cc5a78c152aec0c94cfbc19247884e6249018",
    "368e30365a7271eb09811a34c707950435f09c95f6f7bda6ea7b13848df1f51656c343d904c175445bd2feb2a9615ecb",
    "5165e051e94d651f32e2b54f219d892f5bd6",
));
// SHAKE256, tcId 116: a 281-byte message, 22 bytes of output.
static SHAKE256_TC116_MSG: [u8; 281] = hex(concat!(
    "b3d1943aa44c6d554fc9c56487995827ce5766538e1e73de4a9f34d32cdb479b88a8f3218594391872369d6575a8cbd6",
    "af0d9cd1a40d62a6f31acfde65e08bed2e3b0d536f07356b290a61f0c467f8197d99b3b7c975d795fc6329bb006323d4",
    "2662cc6ec2487062c565477ba35e091cd5cf4188b4b24ffaaacf9ce06afbd07185044fcd83cde9be226869186f816598",
    "4393b6d0d4a9d876304f3cab0792cb2f7eb7fc08f74db08ba016318d288049e67ba473352a4f28820d461b345989d453",
    "f69299b968e03db7c9e020fd2be6bd4b839535dce6c1c1177164e834047a6cc1135d73e5cbcd7cb08059f7eb679ae7f5",
    "7b1faec54ae8b069786487e490bd10c0cc879712dc386a325b80c4962b397cf84979f2143b3848ab6f",
));
static SHAKE256_TC116_OUT: [u8; 22] = hex("3a8c1911a3594cca6b7354e85a4077ce28419b083250");

/// Run the SHAKE known-answer tests, the Keccak-f[1600] permutation's among
/// them. Returns the first failing case as an error string, or `Ok(())` if all
/// pass. Compiled in all builds so host and on-target (ktest) runs share
/// identical logic.
///
/// # Errors
///
/// Returns a descriptive `&'static str` on the first mismatch.
pub fn run_shake_kats() -> Result<(), &'static str>
{
    let mut state = [0u64; LANES];
    keccak_f1600(&mut state);
    if state.get(..2) != Some(ZERO_STATE_LANES.as_slice())
    {
        return Err("keccak: zero-state vector mismatch");
    }

    let mut out128 = [0u8; 32];
    shake128(b"", &mut out128);
    let mut out256 = [0u8; 64];
    shake256(b"", &mut out256);
    if out128 != SHAKE128_EMPTY || out256 != SHAKE256_EMPTY
    {
        return Err("shake: empty-message output mismatch");
    }

    let mut out = [0u8; 258];
    for (msg, expected, rate) in [
        (
            SHAKE128_TC15_MSG.as_slice(),
            SHAKE128_TC15_OUT.as_slice(),
            SHAKE128_RATE,
        ),
        (
            SHAKE128_TC20_MSG.as_slice(),
            SHAKE128_TC20_OUT.as_slice(),
            SHAKE128_RATE,
        ),
        (
            SHAKE256_TC34_MSG.as_slice(),
            SHAKE256_TC34_OUT.as_slice(),
            SHAKE256_RATE,
        ),
        (
            SHAKE256_TC116_MSG.as_slice(),
            SHAKE256_TC116_OUT.as_slice(),
            SHAKE256_RATE,
        ),
    ]
    {
        let Some(out) = out.get_mut(..expected.len())
        else
        {
            return Err("shake: KAT output longer than its buffer");
        };
        if rate == SHAKE128_RATE
        {
            shake128(msg, out);
        }
        else
        {
            shake256(msg, out);
        }
        if out != expected
        {
            return Err("shake: ACVP KAT output mismatch");
        }
    }

    // Absorbing and squeezing in pieces must equal the one-shot form, across
    // the rate boundary on both sides.
    let mut xof = Shake256::new();
    let (head, tail) = SHAKE128_TC20_MSG.split_at(SHAKE256_RATE.saturating_sub(1));
    xof.update(head);
    xof.update(tail);
    let mut reader = xof.finalize();
    let mut pieces = [0u8; 300];
    let (first, rest) = pieces.split_at_mut(SHAKE256_RATE.saturating_add(1));
    reader.read(first);
    reader.read(rest);
    let mut whole = [0u8; 300];
    shake256(&SHAKE128_TC20_MSG, &mut whole);
    if pieces != whole
    {
        return Err("shake: incremental != one-shot");
    }

    Ok(())
}

#[cfg(test)]
mod tests
{
    use std::vec;

    use super::*;

    use crypto_testkit::differential;
    use crypto_testkit::shake::{self as reference, Function, Input};

    #[test]
    fn kats_pass()
    {
        assert_eq!(run_shake_kats(), Ok(()));
    }

    #[test]
    fn one_shot_and_incremental_outputs_agree_with_the_reference()
    {
        let inputs = reference::load().unwrap();
        let one_shot = differential::compare(
            "shake one-shot",
            inputs.iter(),
            |i: &&Input| {
                let mut out = vec![0u8; i.output.len()];
                match i.function
                {
                    Function::Shake128 => shake128(&i.data, &mut out),
                    Function::Shake256 => shake256(&i.data, &mut out),
                }
                out
            },
            |i| i.output.clone(),
        );
        assert!(one_shot.agrees(), "{one_shot}");
        let incremental = differential::compare(
            "shake incremental",
            inputs.iter(),
            |i: &&Input| {
                let mut out = vec![0u8; i.output.len()];
                match i.function
                {
                    Function::Shake128 => squeeze_in_pieces::<SHAKE128_RATE>(i, &mut out),
                    Function::Shake256 => squeeze_in_pieces::<SHAKE256_RATE>(i, &mut out),
                }
                out
            },
            |i| i.output.clone(),
        );
        assert!(incremental.agrees(), "{incremental}");
    }

    /// Absorb `input` in its pieces and squeeze `out` in its output pieces.
    fn squeeze_in_pieces<const RATE: usize>(input: &Input, out: &mut [u8])
    {
        let mut xof = Shake::<RATE>::new();
        for piece in input.pieces()
        {
            xof.update(piece);
        }
        let mut reader = xof.finalize();
        let mut rest = out;
        for len in input.read_lengths()
        {
            let (head, tail) = rest.split_at_mut(len.min(rest.len()));
            reader.read(head);
            rest = tail;
        }
    }
}
