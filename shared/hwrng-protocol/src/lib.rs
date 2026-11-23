// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/hwrng-protocol/src/lib.rs

//! The `hwrng` device class protocol.
//!
//! A hardware-RNG driver declares the `hwrng` class and serves this protocol
//! on its service endpoint; a consumer reaches each driver of the class
//! through `devmgr_labels::QUERY_DEVICE` on its `devmgr.class.hwrng` class
//! SEND, which devmgr answers with a SEND stamped with the class file's verb
//! bits (docs/driver-binding.md § Device Classes). The protocol is one label,
//! [`READ`]: the consumer asks for up to `n` bytes, and the driver answers
//! with at most `n` bytes the device produced, never more than
//! [`MAX_READ_BYTES`], the bytes one reply's data words carry beside the count.
//!
//! The protocol says nothing of the quality of the bytes. A consumer mixes
//! them into a pool that credits them with no entropy, as the kernel's
//! contribution path does (`core/kernel/docs/entropy.md`).

#![cfg_attr(not(test), no_std)]

use syscall_abi::MSG_DATA_WORDS_MAX;

#[cfg(any(test, kani, fuzzing))]
pub mod property;

/// Wire-protocol version of the class. Marker-only, as the RTC class's is:
/// no request carries it, and `PROCESS_ABI_VERSION`, checked at process
/// start, covers the driver and its consumers, which build together. Bumped
/// on any breaking change (a label added, removed, or repurposed, or a
/// payload shape changed), per docs/conventions.md § ABI / wire-protocol
/// versions.
pub const HWRNG_LABELS_VERSION: u32 = 1;

/// Read random bytes from the device.
///
/// Request: `data[0]` is `n`, the most bytes the caller takes; a request
/// with no data word asks for 0. Caps the request carries are deleted by the
/// driver, never kept. The caller's badge must carry [`READ_AUTHORITY`];
/// the driver replies [`errors::UNAUTHORIZED`] otherwise.
///
/// Reply [`errors::SUCCESS`]: `data[0]` is the byte count `k`, at most
/// `min(n, MAX_READ_BYTES)`, and the `k` bytes follow from `data[1]`, packed
/// little-endian, as [`encode_reply`] writes them and [`decode_reply`]
/// reads them. `k` is 0 for `n` = 0, and may be below `n` when the device
/// produced fewer bytes. Reply [`errors::NOT_READY`], with no data, when the
/// device produced no bytes within the driver's wait bound; the caller asks
/// again later.
pub const READ: u64 = 1;

/// Verb bit in the badge of a SEND on a driver of the class, gating
/// [`READ`]: devmgr stamps it on the SEND a `QUERY_DEVICE` through the
/// `hwrng` class SEND returns, from the class file's verb mask. Shares the
/// `1 << 63` position of the other classes' first verb bit.
pub const READ_AUTHORITY: u64 = 1u64 << 63;

/// Most bytes one [`READ`] reply carries: every data word of a message but
/// the count word, eight bytes each.
pub const MAX_READ_BYTES: usize = (MSG_DATA_WORDS_MAX - 1) * 8;

/// Error replies of a driver of the class, in the reply label.
pub mod errors
{
    /// The request was served.
    pub const SUCCESS: u64 = 0;
    /// The driver does not implement the label.
    pub const UNKNOWN_OPCODE: u64 = 1;
    /// The caller's badge lacks [`READ_AUTHORITY`](crate::READ_AUTHORITY).
    pub const UNAUTHORIZED: u64 = 2;
    /// The device produced no bytes within the driver's wait bound.
    pub const NOT_READY: u64 = 3;
}

/// The byte count a [`READ`] request asks for, from its data words: `data[0]`,
/// or 0 when the request carries no word, capped at [`MAX_READ_BYTES`].
#[must_use]
pub fn requested_len(words: &[u64]) -> usize
{
    words
        .first()
        .map_or(0, |&n| usize::try_from(n).unwrap_or(usize::MAX))
        .min(MAX_READ_BYTES)
}

/// The data words of a [`READ`] reply carrying `bytes`: the count in word 0,
/// the bytes packed little-endian from word 1, the last word zero-padded.
/// Returns the number of words written into `words`, or `None` when `bytes`
/// is longer than [`MAX_READ_BYTES`].
#[must_use]
pub fn encode_reply(bytes: &[u8], words: &mut [u64; MSG_DATA_WORDS_MAX]) -> Option<usize>
{
    if bytes.len() > MAX_READ_BYTES
    {
        return None;
    }
    let (count, payload) = words.split_first_mut()?;
    *count = bytes.len() as u64;
    let mut used = 1usize;
    for (word, chunk) in payload.iter_mut().zip(bytes.chunks(8))
    {
        *word = pack_word(chunk);
        // At most MSG_DATA_WORDS_MAX iterations: no saturation.
        used = used.saturating_add(1);
    }
    Some(used)
}

/// The word that carries `chunk`, at most 8 bytes of a reply: the chunk's
/// bytes in little-endian order, zero-padded past its end. [`encode_reply`]
/// packs each word of a reply with it.
fn pack_word(chunk: &[u8]) -> u64
{
    let mut le = [0u8; 8];
    for (dst, &src) in le.iter_mut().zip(chunk)
    {
        *dst = src;
    }
    u64::from_le_bytes(le)
}

/// The bytes of a [`READ`] reply's data words, copied into the front of
/// `out`, whose length is the most the caller asked for. Returns the byte
/// count, or `None` when the reply carries no count word, counts more bytes
/// than `out` holds or than [`MAX_READ_BYTES`], or delivers too few words to
/// hold the bytes it counts. The words are another process's, so each of
/// these is checked rather than trusted.
#[must_use]
pub fn decode_reply(words: &[u64], out: &mut [u8]) -> Option<usize>
{
    let (&count, payload) = words.split_first()?;
    let count = reply_count(count, payload.len(), out.len())?;
    let dst = out.get_mut(..count)?;
    for (chunk, &word) in dst.chunks_mut(8).zip(payload)
    {
        unpack_word(word, chunk);
    }
    Some(count)
}

/// The byte count a reply's count word `count` names, when the reply can
/// carry it: at most `out_len`, the length of the caller's buffer, at most
/// [`MAX_READ_BYTES`], and at most the bytes `words` words after the count
/// hold. `None` otherwise. [`decode_reply`] checks a reply with it before
/// it unpacks any word.
fn reply_count(count: u64, words: usize, out_len: usize) -> Option<usize>
{
    let count = usize::try_from(count).ok()?;
    (count <= out_len && count <= MAX_READ_BYTES && words >= count.div_ceil(8)).then_some(count)
}

/// Unpack `word` into `chunk`, at most 8 bytes of a reply: the word's bytes
/// in little-endian order, as many as the chunk holds. [`decode_reply`]
/// unpacks each word of a reply with it.
fn unpack_word(word: u64, chunk: &mut [u8])
{
    for (byte, src) in chunk.iter_mut().zip(word.to_le_bytes())
    {
        *byte = src;
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn reply_round_trips_a_partial_last_word()
    {
        let bytes: [u8; 13] = core::array::from_fn(|i| u8::try_from(i * 19 + 1).unwrap());
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        let used = encode_reply(&bytes, &mut words).unwrap();
        assert_eq!(used, 3);
        let mut out = [0u8; 16];
        assert_eq!(decode_reply(&words[..used], &mut out), Some(13));
        assert_eq!(&out[..13], &bytes);
        assert_eq!(&out[13..], &[0, 0, 0]);
    }

    #[test]
    fn reply_round_trips_the_largest_read()
    {
        let bytes: [u8; MAX_READ_BYTES] = core::array::from_fn(|i| u8::try_from(i % 251).unwrap());
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        assert_eq!(encode_reply(&bytes, &mut words), Some(MSG_DATA_WORDS_MAX));
        let mut out = [0u8; MAX_READ_BYTES];
        assert_eq!(decode_reply(&words, &mut out), Some(MAX_READ_BYTES));
        assert_eq!(out, bytes);
    }

    #[test]
    fn empty_reply_is_the_count_word_alone()
    {
        let mut words = [7u64; MSG_DATA_WORDS_MAX];
        assert_eq!(encode_reply(&[], &mut words), Some(1));
        assert_eq!(words[0], 0);
        assert_eq!(decode_reply(&words[..1], &mut []), Some(0));
    }

    #[test]
    fn encode_refuses_more_than_one_reply_carries()
    {
        let bytes = [0u8; MAX_READ_BYTES + 1];
        assert_eq!(encode_reply(&bytes, &mut [0; MSG_DATA_WORDS_MAX]), None);
    }

    #[test]
    fn decode_refuses_a_count_past_the_callers_buffer()
    {
        // A driver answering more than was asked must not overrun the caller.
        let words = [9u64, 0, 0];
        assert_eq!(decode_reply(&words, &mut [0u8; 8]), None);
    }

    #[test]
    fn decode_refuses_a_count_past_the_words_delivered()
    {
        let words = [9u64, 0];
        assert_eq!(decode_reply(&words, &mut [0u8; 16]), None);
    }

    #[test]
    fn decode_refuses_a_count_past_the_protocol_bound()
    {
        let words = [MAX_READ_BYTES as u64 + 1; MSG_DATA_WORDS_MAX];
        assert_eq!(decode_reply(&words, &mut [0u8; 1024]), None);
    }

    #[test]
    fn decode_refuses_a_reply_without_a_count_word()
    {
        assert_eq!(decode_reply(&[], &mut [0u8; 8]), None);
    }

    #[test]
    fn requested_len_caps_at_the_protocol_bound_and_defaults_to_zero()
    {
        assert_eq!(requested_len(&[]), 0);
        assert_eq!(requested_len(&[17]), 17);
        assert_eq!(requested_len(&[u64::MAX]), MAX_READ_BYTES);
    }

    /// The checked-in inputs of the fuzz target `hwrng-protocol` of the `kinds`
    /// given (`seeds`, `regressions`).
    fn fuzz_inputs(kinds: &[&str]) -> Vec<Vec<u8>>
    {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/hwrng-protocol");
        let mut inputs = Vec::new();
        for kind in kinds
        {
            let Ok(entries) = std::fs::read_dir(dir.join(kind))
            else
            {
                continue;
            };
            for entry in entries
            {
                inputs.push(std::fs::read(entry.unwrap().path()).unwrap());
            }
        }
        inputs
    }

    // Defect caught: a parser change that breaks its contract on an input
    // the fuzz target once found or started from; `cargo xtask test` replays
    // every checked-in input of fuzz/hwrng-protocol/ on each change.
    #[test]
    fn every_checked_in_fuzz_input_holds_the_parser_contract()
    {
        let inputs = fuzz_inputs(&["seeds", "regressions"]);
        assert!(
            !inputs.is_empty(),
            "no checked-in input under fuzz/hwrng-protocol"
        );
        for bytes in &inputs
        {
            property::hwrng_protocol_holds(bytes);
        }
    }

    // Defect caught: seeds that no longer reach a decoded reply (a count
    // past its words after an edit, say), so the fuzz target starts from
    // the refusals alone.
    #[test]
    fn a_seed_decodes_as_a_reply_of_a_partial_last_word()
    {
        let decoded = fuzz_inputs(&["seeds"]).iter().any(|bytes| {
            let out_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            let words: Vec<u64> = bytes[2..]
                .as_chunks::<8>()
                .0
                .iter()
                .map(|w| u64::from_le_bytes(*w))
                .collect();
            let mut out = vec![0u8; out_len];
            decode_reply(&words, &mut out).is_some_and(|count| count % 8 != 0)
        });
        assert!(decoded, "no seed decodes as a reply of a partial last word");
    }
}

/// Proofs of the parsers' contract (docs/testing.md § Bounded verification,
/// Parser proofs), in the induction form over a reply's words.
///
/// The request proof covers every request: `requested_len` reads the first
/// word alone. The decoder checks a reply's count word with `reply_count`,
/// then walks the counted bytes of the caller's buffer eight at a time beside
/// the words after the count, and unpacks each word into its chunk with
/// `unpack_word`; the encoder walks the bytes eight at a time beside the
/// words after the count, and packs each chunk into its word with
/// `pack_word`. The count proof proves the check on every count word, every
/// number of words after it and every buffer length. The step proofs prove the
/// unpacking and the packing on every word and every chunk of up to eight
/// bytes, so each word of a reply of any length gives, or receives, exactly
/// the bytes of its chunk, which is the property's check of each byte at its
/// own index. The base proofs run the whole decoder and encoder on replies of
/// up to two words after the count, a whole word and a partial last one, with
/// every count word, every buffer of up to one byte past those two words and
/// every byte string of that length: the walks start, step to the next word,
/// and end as the property asks. The encoder's refusal of an over-long reply
/// comes before any loop and is proven at its threshold. What lies outside
/// the proofs is the code that drives the steps over the replies longer than
/// the base proofs': the two walks, `chunks` and `chunks_mut` zipped with
/// the words, the encoder's count of the words it walks, and the loop that
/// hands the property its words. The fuzz target `hwrng-protocol` and the
/// replay of the checked-in inputs check them on replies of every length.
#[cfg(kani)]
mod proofs
{
    use super::MAX_READ_BYTES;
    use super::property;

    /// The most words after the count a base reply holds: a whole word and a
    /// partial last one.
    const WORDS_AFTER_COUNT: usize = 2;

    /// The longest buffer a base reply is decoded into: one byte past the
    /// bytes `WORDS_AFTER_COUNT` words carry.
    const OUT_BOUND: usize = WORDS_AFTER_COUNT * 8 + 1;

    /// The request contract holds on every request: none, or a first word of
    /// any value. No loop.
    #[kani::proof]
    fn every_request_holds_the_request_contract()
    {
        let words: [u64; 1] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= words.len());
        property::request_holds(&words[..len]);
    }

    /// The decoder's check of a reply's count holds on every count word,
    /// every number of words after it and every buffer length. No loop.
    #[kani::proof]
    fn every_count_word_is_checked_before_the_walk()
    {
        property::count_holds(kani::any(), kani::any(), kani::any());
    }

    /// Step of the decoder's walk: any word unpacks into a chunk of any length
    /// up to 8 as its little-endian bytes, and writes nothing past the chunk.
    /// The longest loops are the unpacking and the check of the 8 bytes, so
    /// an unwind bound of 9 covers them.
    #[kani::proof]
    #[kani::unwind(9)]
    fn each_word_unpacks_into_its_chunk()
    {
        let len: usize = kani::any();
        kani::assume(len <= 8);
        property::unpack_holds(kani::any(), len);
    }

    /// Step of the encoder's walk: any chunk of up to 8 bytes packs into the
    /// word of its little-endian bytes, zero-padded. The longest loops are
    /// the packing and the check of the 8 bytes, so an unwind bound of 9
    /// covers them.
    #[kani::proof]
    #[kani::unwind(9)]
    fn each_chunk_packs_into_its_word()
    {
        let chunk: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= chunk.len());
        property::pack_holds(&chunk[..len]);
    }

    /// Base of the decoder's walk: the reply contract holds on the first
    /// `len` of any count word and `WORDS_AFTER_COUNT` words after it,
    /// decoded into a buffer of every length up to `OUT_BOUND`. The longest
    /// loop is the check of the `OUT_BOUND` bytes of the buffer, so an unwind
    /// bound of `OUT_BOUND + 1` (18) covers every loop.
    #[kani::proof]
    #[kani::unwind(18)]
    fn every_bounded_reply_holds_the_reply_contract()
    {
        const _: () = assert!(OUT_BOUND + 1 == 18);
        let words: [u64; WORDS_AFTER_COUNT + 1] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= words.len());
        let out_len: usize = kani::any();
        kani::assume(out_len <= OUT_BOUND);
        property::reply_holds(&words[..len], out_len);
    }

    /// Base of the encoder's walk: the encode contract holds on every byte
    /// string of up to `OUT_BOUND` bytes, which the encoder packs into at
    /// most `WORDS_AFTER_COUNT + 1` words after the count, the last partial.
    /// The longest loops are the packing of a word's 8 bytes, so an unwind
    /// bound of 9 covers every loop.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_bounded_reply_encodes_to_its_words()
    {
        let bytes: [u8; OUT_BOUND] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::encode_holds(&bytes[..len]);
    }

    /// The encoder refuses a reply one byte longer than `MAX_READ_BYTES`, of
    /// any bytes, as it refuses every longer one: on its length alone, before
    /// any loop.
    #[kani::proof]
    fn a_reply_past_the_largest_is_refused()
    {
        let bytes: [u8; MAX_READ_BYTES + 1] = kani::any();
        property::encode_holds(&bytes);
    }
}
