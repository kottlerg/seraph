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
//! header ([`decode_header`]), bounds the blobs by the cap and by the
//! argv/env region ([`checked_total`]) before it maps or allocates anything,
//! and checks each blob's strings ([`ChildArgvEnv::check`]) before the child
//! is created and again on the child's copy, so a request it cannot deliver
//! intact is refused with `INVALID_ARGUMENT` rather than degraded.

use ipc::IpcMessage;
use ipc::procmgr_labels::{ARGV_ENV_HEADER_WORDS, ArgvEnvHeader};

/// Why procmgr refuses a create request's argv and env. Every refusal is
/// replied as `procmgr_errors::INVALID_ARGUMENT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgvEnvRefusal
{
    /// Fewer data words arrived than the header occupies.
    MissingHeader,
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
/// `u64`, [`ArgvEnvRefusal::PastCap`] when the blobs reach past the cap, and
/// [`ArgvEnvRefusal::PastRegion`] when they exceed the region.
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

/// Whether `blob` holds exactly `count` NUL-terminated strings: its NULs
/// number `count` and, when nonempty, its last byte is one. An empty blob
/// holds zero strings.
fn blob_holds(blob: &[u8], count: u64) -> bool
{
    let nuls = blob.iter().fold(0u64, |n, &b| n + u64::from(b == 0));
    nuls == count && blob.last().is_none_or(|&b| b == 0)
}

/// The argv and env a child receives: the two blobs, each a concatenation
/// of NUL-terminated UTF-8 strings (env entries `KEY=VALUE`), and their
/// string counts. Both empty, with zero counts, means no argv and no env.
/// The blob format is defined by the argv section comment above
/// `ProcessInfo::args_offset` in `abi/process-abi/src/lib.rs`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChildArgvEnv<'a>
{
    /// The argv blob.
    pub args: &'a [u8],
    /// Strings in [`Self::args`].
    pub args_count: u64,
    /// The env blob.
    pub env: &'a [u8],
    /// Strings in [`Self::env`].
    pub env_count: u64,
}

impl<'a> ChildArgvEnv<'a>
{
    /// Split `region`, the caller's cap bytes, into the argv and env blobs
    /// `header` declares: argv at byte 0, env directly after it. `None` when
    /// `region` is shorter than the two lengths, which [`checked_total`]
    /// rules out for a header it accepted.
    #[must_use]
    pub fn split(region: &'a [u8], header: ArgvEnvHeader) -> Option<Self>
    {
        let args_end = usize::try_from(header.args_bytes).ok()?;
        let env_end = args_end.checked_add(usize::try_from(header.env_bytes).ok()?)?;
        Some(Self {
            args: region.get(..args_end)?,
            args_count: header.args_count,
            env: region.get(args_end..env_end)?,
            env_count: header.env_count,
        })
    }

    /// Both blobs' combined byte length, the size of the child's argv/env
    /// region before page rounding.
    #[must_use]
    pub fn total_bytes(&self) -> usize
    {
        self.args.len() + self.env.len()
    }

    /// Check that each blob holds exactly its declared count of
    /// NUL-terminated strings.
    ///
    /// # Errors
    /// [`ArgvEnvRefusal::Malformed`] when either blob's NULs disagree with
    /// its count or a nonempty blob does not end in a NUL.
    pub fn check(&self) -> Result<(), ArgvEnvRefusal>
    {
        if blob_holds(self.args, self.args_count) && blob_holds(self.env, self.env_count)
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

    // Defect guarded: env taken from the wrong offset of the cap, or the
    // split reading past a region shorter than the header declares.
    #[test]
    fn split_places_env_directly_after_argv()
    {
        let region = b"a\0bc\0K=v\0tail";
        let blobs = ChildArgvEnv::split(region, header(5, 2, 4, 1)).expect("split fits");
        assert_eq!(blobs.args, b"a\0bc\0");
        assert_eq!(blobs.env, b"K=v\0");
        assert_eq!(blobs.total_bytes(), 9);
        assert_eq!(blobs.check(), Ok(()));
        assert_eq!(ChildArgvEnv::split(region, header(5, 2, 9, 1)), None);
    }

    // Defect guarded: a child started with argv or env its readers would
    // split differently from what the spawner declared.
    #[test]
    fn blobs_whose_strings_disagree_with_their_counts_are_refused()
    {
        let check = |args: &[u8], args_count, env: &[u8], env_count| {
            ChildArgvEnv {
                args,
                args_count,
                env,
                env_count,
            }
            .check()
        };
        assert_eq!(check(b"", 0, b"", 0), Ok(()));
        assert_eq!(check(b"a\0b\0", 1, b"", 0), Err(ArgvEnvRefusal::Malformed));
        assert_eq!(check(b"a\0b\0", 3, b"", 0), Err(ArgvEnvRefusal::Malformed));
        assert_eq!(check(b"a\0b", 1, b"", 0), Err(ArgvEnvRefusal::Malformed));
        assert_eq!(check(b"", 1, b"", 0), Err(ArgvEnvRefusal::Malformed));
        assert_eq!(check(b"a\0", 1, b"K=v", 0), Err(ArgvEnvRefusal::Malformed));
        assert_eq!(
            check(b"a\0", 1, b"K=v\0", 2),
            Err(ArgvEnvRefusal::Malformed)
        );
    }
}
