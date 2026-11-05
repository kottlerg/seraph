// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/create_blobs.rs

//! Argv/env checks for procmgr's create requests.
//!
//! A `CREATE_PROCESS` or `CREATE_FROM_FILE` that sets
//! `procmgr_labels::CREATE_ARGV_ENV` carries the child's argv and env in a
//! Memory cap the caller sized, with their byte lengths and counts in an
//! [`ArgvEnvHeader`] of four data words (see
//! `services/procmgr/docs/ipc-interface.md` § Label 1: `CREATE_PROCESS`).
//! Every field and every blob byte is client input. procmgr decodes the
//! header ([`decode_header`]) and bounds the blobs by the cap and by the
//! argv/env region ([`checked_total`]) before it acquires anything for the
//! child. It then copies the blobs, a window at a time, into pages only it
//! and the child will map, and checks each blob's strings on that copy
//! ([`ArgvEnvTally`]), so a request it cannot deliver intact is refused with
//! `INVALID_ARGUMENT` rather than degraded, and a caller that rewrites its
//! pages during the copy cannot change what is checked.

use ipc::IpcMessage;
use ipc::procmgr_labels::{ARGV_ENV_HEADER_WORDS, ArgvEnvHeader};

/// Why procmgr refuses a create request's argv and env. Every refusal is
/// replied as `procmgr_errors::INVALID_ARGUMENT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgvEnvRefusal
{
    /// Fewer data words arrived than the header occupies.
    MissingHeader,
    /// The argv/env cap is not a Memory cap procmgr can size.
    NotMemory,
    /// The argv and env lengths sum past a `u64`.
    LengthOverflow,
    /// The blobs reach past the end of the cap that carries them.
    PastCap,
    /// The blobs exceed the argv/env region
    /// (`process_abi::ARGV_ENV_MAX_BYTES`).
    PastRegion,
    /// A blob's NULs disagree with its declared count, or a nonempty blob
    /// does not end in a NUL.
    Malformed,
}

/// Decode the [`ArgvEnvHeader`] from `req`'s data words, starting at
/// `first_word`: 0 for `CREATE_PROCESS`, 1 for `CREATE_FROM_FILE` (which
/// carries `file_size` in word 0).
///
/// # Errors
/// [`ArgvEnvRefusal::MissingHeader`] when the request delivered fewer than
/// `first_word + ARGV_ENV_HEADER_WORDS` words, so no header field is read
/// from the zero tail past the delivered words.
pub fn decode_header(req: &IpcMessage, first_word: usize) -> Result<ArgvEnvHeader, ArgvEnvRefusal>
{
    if req.word_count() < first_word + ARGV_ENV_HEADER_WORDS
    {
        return Err(ArgvEnvRefusal::MissingHeader);
    }
    let mut words = [0u64; ARGV_ENV_HEADER_WORDS];
    for (i, word) in words.iter_mut().enumerate()
    {
        *word = req.word(first_word + i);
    }
    Ok(ArgvEnvHeader::from_words(words))
}

/// The combined byte length of `header`'s blobs, checked against the
/// `cap_bytes` the carrying cap holds and the `region_bytes` the child's
/// argv/env region can map.
///
/// # Errors
/// [`ArgvEnvRefusal::LengthOverflow`] when the two lengths overflow a
/// `u64`, [`ArgvEnvRefusal::PastRegion`] when they exceed the region, and
/// [`ArgvEnvRefusal::PastCap`] when they reach past the cap.
pub fn checked_total(
    header: ArgvEnvHeader,
    cap_bytes: u64,
    region_bytes: u64,
) -> Result<u64, ArgvEnvRefusal>
{
    let total = header.total_bytes().ok_or(ArgvEnvRefusal::LengthOverflow)?;
    if total > region_bytes
    {
        return Err(ArgvEnvRefusal::PastRegion);
    }
    if total > cap_bytes
    {
        return Err(ArgvEnvRefusal::PastCap);
    }
    Ok(total)
}

/// One blob's NUL count and whether its last byte, once fed, was a NUL.
#[derive(Clone, Copy, Debug, Default)]
struct BlobTally
{
    nuls: u64,
    ends_in_nul: bool,
}

impl BlobTally
{
    fn feed(&mut self, bytes: &[u8])
    {
        self.nuls += bytes.iter().fold(0u64, |n, &b| n + u64::from(b == 0));
        if let Some(&last) = bytes.last()
        {
            self.ends_in_nul = last == 0;
        }
    }

    /// Whether the blob, of `len` bytes, holds exactly `count`
    /// NUL-terminated strings. An empty blob holds zero.
    fn holds(self, len: u64, count: u64) -> bool
    {
        self.nuls == count && (len == 0 || self.ends_in_nul)
    }
}

/// The string check of a create request's argv and env, fed the blobs'
/// bytes in order (argv, then env) in chunks of any size, as procmgr copies
/// them a window at a time. [`Self::finish`] accepts only when every byte the
/// header declares was fed and each blob holds exactly its declared count of
/// NUL-terminated strings.
#[derive(Clone, Copy, Debug)]
pub struct ArgvEnvTally
{
    header: ArgvEnvHeader,
    fed: u64,
    args: BlobTally,
    env: BlobTally,
}

impl ArgvEnvTally
{
    /// A tally of the blobs `header` declares, none of their bytes fed yet.
    #[must_use]
    pub fn new(header: ArgvEnvHeader) -> Self
    {
        Self {
            header,
            fed: 0,
            args: BlobTally::default(),
            env: BlobTally::default(),
        }
    }

    /// Feed the next `chunk` of the concatenated blobs. Bytes past the
    /// declared lengths (a window's page tail) are ignored.
    pub fn feed(&mut self, chunk: &[u8])
    {
        let total = self.header.args_bytes.saturating_add(self.header.env_bytes);
        let take = usize::try_from(total.saturating_sub(self.fed))
            .map_or(chunk.len(), |left| left.min(chunk.len()));
        let chunk = &chunk[..take];
        let args_left = usize::try_from(self.header.args_bytes.saturating_sub(self.fed))
            .map_or(chunk.len(), |left| left.min(chunk.len()));
        let (args, env) = chunk.split_at(args_left);
        self.args.feed(args);
        self.env.feed(env);
        self.fed += take as u64;
    }

    /// Check the fed blobs against the header.
    ///
    /// # Errors
    /// [`ArgvEnvRefusal::Malformed`] when fewer bytes were fed than the
    /// header declares, or either blob's NULs disagree with its count, or a
    /// nonempty blob does not end in a NUL.
    pub fn finish(self) -> Result<(), ArgvEnvRefusal>
    {
        let h = self.header;
        let complete = Some(self.fed) == h.total_bytes();
        if complete
            && self.args.holds(h.args_bytes, h.args_count)
            && self.env.holds(h.env_bytes, h.env_count)
        {
            Ok(())
        }
        else
        {
            Err(ArgvEnvRefusal::Malformed)
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const CREATE_PROCESS_FIRST_WORD: usize = 0;
    const FROM_FILE_FIRST_WORD: usize = 1;
    const CAP: u64 = 4096;
    const REGION: u64 = 1 << 30;

    fn header(args_bytes: u64, args_count: u64, env_bytes: u64, env_count: u64) -> ArgvEnvHeader
    {
        ArgvEnvHeader {
            args_bytes,
            args_count,
            env_bytes,
            env_count,
        }
    }

    /// Run `blobs` (argv then env, concatenated) through a tally in chunks of
    /// `chunk` bytes.
    fn tally(blobs: &[u8], header: ArgvEnvHeader, chunk: usize) -> Result<(), ArgvEnvRefusal>
    {
        let mut t = ArgvEnvTally::new(header);
        for piece in blobs.chunks(chunk)
        {
            t.feed(piece);
        }
        t.finish()
    }

    // Defect guarded: a sender encoding or procmgr decoding the header words
    // in a different order or position, so a child receives argv lengths as
    // env lengths, or a CREATE_FROM_FILE header read over `file_size`.
    #[test]
    fn header_round_trips_through_the_create_request_words()
    {
        let sent = header(9000, 3, 5000, 2);
        let msg = IpcMessage::builder(0)
            .word(0, 0x1234)
            .words(FROM_FILE_FIRST_WORD, &sent.to_words())
            .build();
        assert_eq!(decode_header(&msg, FROM_FILE_FIRST_WORD), Ok(sent));

        let msg = IpcMessage::builder(0)
            .words(CREATE_PROCESS_FIRST_WORD, &sent.to_words())
            .build();
        assert_eq!(decode_header(&msg, CREATE_PROCESS_FIRST_WORD), Ok(sent));
    }

    // Defect guarded: a header read from the zero tail past the delivered
    // words, which would accept a truncated request as empty blobs.
    #[test]
    fn a_header_short_of_its_words_is_refused()
    {
        let msg = IpcMessage::builder(0).word(0, 7).word(3, 1).build();
        assert_eq!(
            decode_header(&msg, FROM_FILE_FIRST_WORD),
            Err(ArgvEnvRefusal::MissingHeader)
        );
        assert_eq!(
            decode_header(&IpcMessage::new(0), CREATE_PROCESS_FIRST_WORD),
            Err(ArgvEnvRefusal::MissingHeader)
        );
    }

    // Defect guarded: procmgr mapping or copying past the caller's cap, or
    // past the region the child's layout leaves, on lengths a client chose.
    #[test]
    fn lengths_past_the_cap_the_region_or_a_u64_are_refused()
    {
        assert_eq!(checked_total(header(4000, 1, 96, 1), CAP, REGION), Ok(CAP));
        assert_eq!(
            checked_total(header(4000, 1, 97, 1), CAP, REGION),
            Err(ArgvEnvRefusal::PastCap)
        );
        assert_eq!(
            checked_total(header(REGION, 1, 1, 1), u64::MAX, REGION),
            Err(ArgvEnvRefusal::PastRegion)
        );
        assert_eq!(
            checked_total(header(u64::MAX, 1, 1, 1), u64::MAX, u64::MAX),
            Err(ArgvEnvRefusal::LengthOverflow)
        );
        assert_eq!(checked_total(header(0, 0, 0, 0), 0, REGION), Ok(0));
    }

    // Defect guarded: a tally that splits argv from env at the wrong byte,
    // or loses a NUL or a blob's last byte at a chunk boundary, so a
    // well-formed request is refused only when its blobs straddle a window.
    #[test]
    fn a_well_formed_request_passes_in_any_chunking()
    {
        let blobs = b"a\0bc\0K=v\0\0\0\0";
        let h = header(5, 2, 4, 1);
        for chunk in 1..=blobs.len()
        {
            assert_eq!(tally(blobs, h, chunk), Ok(()), "chunk {chunk}");
        }
        assert_eq!(tally(b"", header(0, 0, 0, 0), 1), Ok(()));
    }

    // Defect guarded: a child started with argv or env its readers would
    // split differently from what the spawner declared, or a copy that
    // stopped short being accepted.
    #[test]
    fn blobs_whose_strings_disagree_with_their_counts_are_refused()
    {
        let malformed = Err(ArgvEnvRefusal::Malformed);
        assert_eq!(tally(b"a\0b\0", header(4, 1, 0, 0), 3), malformed);
        assert_eq!(tally(b"a\0b\0", header(4, 3, 0, 0), 3), malformed);
        assert_eq!(tally(b"a\0b", header(3, 1, 0, 0), 2), malformed);
        assert_eq!(tally(b"", header(0, 1, 0, 0), 1), malformed);
        assert_eq!(tally(b"a\0K=v", header(2, 1, 3, 1), 4), malformed);
        assert_eq!(tally(b"a\0K=v\0", header(2, 1, 4, 2), 4), malformed);
        // The argv blob's last byte is a NUL only in the env blob's bytes.
        assert_eq!(tally(b"ab\0", header(2, 0, 1, 1), 1), malformed);
        // Fewer bytes fed than declared.
        assert_eq!(tally(b"a\0", header(2, 1, 4, 1), 1), malformed);
    }
}
