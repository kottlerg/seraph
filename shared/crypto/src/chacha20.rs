// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/chacha20.rs

//! The `ChaCha20` stream cipher (RFC 8439 § 2.3 and § 2.4).
//!
//! A 256-bit key, a 96-bit nonce and a 32-bit block counter fill the 16-word
//! state; 20 rounds of quarter rounds mix it, and the mixed state plus the
//! input state, serialized little-endian, is one 64-byte keystream block.
//! Every operation is an addition modulo 2^32, an exclusive or, or a rotation
//! by a constant, so the time taken depends on the input lengths only.

/// Key length in bytes.
pub(crate) const KEY_LEN: usize = 32;

/// Nonce length in bytes.
pub(crate) const NONCE_LEN: usize = 12;

/// Keystream block length in bytes.
const BLOCK_LEN: usize = 64;

/// The number of distinct values of the 32-bit block counter.
const COUNTER_SPAN: u64 = 0x1_0000_0000;

/// The state's first four words, "expand 32-byte k" (RFC 8439 § 2.3).
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The keystream from the requested block counter on does not cover the
/// buffer before the 32-bit counter wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterOverflow;

/// The `ChaCha` quarter round (RFC 8439 § 2.1).
fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32)
{
    *a = a.wrapping_add(*b);
    *d = (*d ^ *a).rotate_left(16);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_left(12);
    *a = a.wrapping_add(*b);
    *d = (*d ^ *a).rotate_left(8);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_left(7);
}

/// The input state: the constants, the key, the block counter and the nonce,
/// each word read little-endian (RFC 8439 § 2.3).
fn initial_state(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u32; 16]
{
    let key_words = key
        .as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes(*w));
    let nonce_words = nonce
        .as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes(*w));
    let words = SIGMA
        .iter()
        .copied()
        .chain(key_words)
        .chain(core::iter::once(counter))
        .chain(nonce_words);
    let mut state = [0u32; 16];
    for (slot, word) in state.iter_mut().zip(words)
    {
        *slot = word;
    }
    state
}

/// The `ChaCha20` block function (RFC 8439 § 2.3): the 64-byte keystream block
/// for `key`, `counter` and `nonce`.
pub(crate) fn block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; BLOCK_LEN]
{
    let input = initial_state(key, counter, nonce);
    let [
        mut x0,
        mut x1,
        mut x2,
        mut x3,
        mut x4,
        mut x5,
        mut x6,
        mut x7,
        mut x8,
        mut x9,
        mut x10,
        mut x11,
        mut x12,
        mut x13,
        mut x14,
        mut x15,
    ] = input;
    // Ten double rounds: a column round, then a diagonal round.
    for _ in 0..10
    {
        quarter_round(&mut x0, &mut x4, &mut x8, &mut x12);
        quarter_round(&mut x1, &mut x5, &mut x9, &mut x13);
        quarter_round(&mut x2, &mut x6, &mut x10, &mut x14);
        quarter_round(&mut x3, &mut x7, &mut x11, &mut x15);
        quarter_round(&mut x0, &mut x5, &mut x10, &mut x15);
        quarter_round(&mut x1, &mut x6, &mut x11, &mut x12);
        quarter_round(&mut x2, &mut x7, &mut x8, &mut x13);
        quarter_round(&mut x3, &mut x4, &mut x9, &mut x14);
    }
    let mixed = [
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
    ];
    let mut out = [0u8; BLOCK_LEN];
    for ((bytes, word), start) in out.as_chunks_mut::<4>().0.iter_mut().zip(mixed).zip(input)
    {
        *bytes = word.wrapping_add(start).to_le_bytes();
    }
    out
}

/// Whether the keystream from block `counter` on covers `len` bytes before
/// the 32-bit block counter wraps, which would repeat keystream.
pub(crate) fn fits(counter: u32, len: usize) -> bool
{
    u64::try_from(len.div_ceil(BLOCK_LEN))
        .is_ok_and(|blocks| blocks <= COUNTER_SPAN.wrapping_sub(u64::from(counter)))
}

/// `ChaCha20` encryption and decryption (RFC 8439 § 2.4): exclusive-or
/// `buffer` in place with the keystream of `key` and `nonce`, starting at
/// block `counter`.
///
/// # Errors
///
/// [`CounterOverflow`] when the keystream from `counter` on does not cover
/// `buffer` ([`fits`]); `buffer` is then unchanged.
pub(crate) fn xor_keystream(
    key: &[u8; KEY_LEN],
    counter: u32,
    nonce: &[u8; NONCE_LEN],
    buffer: &mut [u8],
) -> Result<(), CounterOverflow>
{
    if !fits(counter, buffer.len())
    {
        return Err(CounterOverflow);
    }
    let mut counter = counter;
    for chunk in buffer.chunks_mut(BLOCK_LEN)
    {
        for (byte, key_byte) in chunk.iter_mut().zip(block(key, counter, nonce))
        {
            *byte ^= key_byte;
        }
        // Wraps only past the last block, whose successor is never used.
        counter = counter.wrapping_add(1);
    }
    Ok(())
}
