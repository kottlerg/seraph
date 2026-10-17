// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/create_blobs.rs

//! Argv/env blob decoder for procmgr's create requests.
//!
//! `CREATE_PROCESS` and `CREATE_FROM_FILE` carry the child's argv and env as
//! NUL-packed blobs inside the message data area, with their byte lengths
//! and counts bit-packed into the label (see
//! `services/procmgr/docs/ipc-interface.md`). Every field is client input,
//! so this decoder never indexes the message with a client-derived offset it
//! has not first bounded: a declaration that does not fit degrades the blob
//! to empty, matching the wire contract, instead of panicking procmgr.

use ipc::{ARGS_BLOB_MAX, IpcMessage};

/// Program arguments delivered to a child process at spawn time.
///
/// `blob` is a concatenation of `count` NUL-terminated UTF-8 strings. Empty
/// slice + zero count means "no argv". The blob format is defined by the
/// argv section comment above `ProcessInfo::args_offset` in
/// `abi/process-abi/src/lib.rs`; the bound is the wire limit the decoder
/// enforces — at most `ipc::ARGS_BLOB_MAX` bytes per blob, argv and env
/// together within `MSG_DATA_WORDS_MAX`, an oversize blob degraded to empty.
#[derive(Clone, Copy, Default)]
pub struct ChildArgs<'a>
{
    pub blob: &'a [u8],
    pub count: u32,
}

/// Environment variables delivered to a child process at spawn time.
///
/// Same shape as [`ChildArgs`] except each entry is `KEY=VALUE`. Empty
/// slice + zero count means "no env". Same wire bound.
#[derive(Clone, Copy, Default)]
pub struct ChildEnv<'a>
{
    pub blob: &'a [u8],
    pub count: u32,
}

/// Argv/env blobs extracted from a create request's label fields and data
/// words, owning the staging buffers so both create handlers share one
/// extraction path.
pub struct CreateBlobs
{
    args_buf: [u8; ARGS_BLOB_MAX],
    args_len: usize,
    args_count: u32,
    env_buf: [u8; ARGS_BLOB_MAX],
    env_len: usize,
    env_count: u32,
}

impl CreateBlobs
{
    /// Extract the blobs from `req`. `first_word` is the data-word offset
    /// of the argv blob: 0 for `CREATE_PROCESS`, 1 for `CREATE_FROM_FILE`
    /// (which carries `file_size` in word 0).
    ///
    /// Oversized or absent blobs degrade to empty, matching the wire
    /// contract. The env header word sits after the argv words, so its
    /// position derives from the client's `args_bytes`: an `args_bytes` over
    /// `ARGS_BLOB_MAX` degrades env along with argv, and a header position
    /// past the delivered word count degrades env, so no client-derived
    /// index ever reaches the data array unbounded. Blob bytes declared
    /// beyond the delivered words read as zero.
    #[must_use]
    pub fn extract(req: &IpcMessage, first_word: usize) -> Self
    {
        // Label layout, low to high: [32..48] args_bytes, [48..56]
        // args_count, [56..64] env_count. Byte-wise extraction keeps the
        // fields at their exact widths without truncating casts.
        let label = req.label.to_le_bytes();
        let args_bytes = usize::from(u16::from_le_bytes([label[4], label[5]]));
        let mut blobs = Self {
            args_buf: [0u8; ARGS_BLOB_MAX],
            args_len: 0,
            args_count: u32::from(label[6]),
            env_buf: [0u8; ARGS_BLOB_MAX],
            env_len: 0,
            env_count: u32::from(label[7]),
        };
        let args_fit = args_bytes <= ARGS_BLOB_MAX;
        if args_bytes > 0 && args_fit
        {
            copy_bytes_from_msg(req, first_word, args_bytes, &mut blobs.args_buf);
            blobs.args_len = args_bytes;
        }
        // With `args_fit`, the header index is at most `first_word + 32`;
        // the delivered-count check then keeps the read inside the words
        // the client actually sent rather than the zero tail.
        let env_header = first_word + args_bytes.div_ceil(8);
        if blobs.env_count > 0 && args_fit && env_header < req.word_count()
        {
            let header = req.word(env_header).to_le_bytes();
            let env_bytes = usize::from(u16::from_le_bytes([header[0], header[1]]));
            if env_bytes > 0 && env_bytes <= ARGS_BLOB_MAX
            {
                copy_bytes_from_msg(req, env_header + 1, env_bytes, &mut blobs.env_buf);
                blobs.env_len = env_bytes;
            }
        }
        blobs
    }

    /// The argv blob and its declared count. An empty blob with a non-zero
    /// count is the degraded shape; the `ProcessInfo` writer records it as
    /// "no argv".
    #[must_use]
    pub fn args(&self) -> ChildArgs<'_>
    {
        ChildArgs {
            blob: &self.args_buf[..self.args_len],
            count: self.args_count,
        }
    }

    /// The env blob and its declared count; same degraded shape as
    /// [`CreateBlobs::args`].
    #[must_use]
    pub fn env(&self) -> ChildEnv<'_>
    {
        ChildEnv {
            blob: &self.env_buf[..self.env_len],
            count: self.env_count,
        }
    }
}

/// Copy up to `len` bytes from the IPC message's data-byte view into `dst`,
/// starting at word offset `word_offset`. Bounded by the delivered words on
/// the source side and by `dst` on the destination side, so a declared
/// length past either is clipped rather than read out of range.
fn copy_bytes_from_msg(msg: &IpcMessage, word_offset: usize, len: usize, dst: &mut [u8])
{
    let bytes = msg.data_bytes();
    let src_start = word_offset * 8;
    let avail = bytes.len().saturating_sub(src_start);
    let copy_len = len.min(dst.len()).min(avail);
    if copy_len > 0
    {
        dst[..copy_len].copy_from_slice(&bytes[src_start..src_start + copy_len]);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Pack the create-request label fields the decoder reads; the low 32
    /// bits (opcode and scheduling fields) are irrelevant to it.
    fn label(args_bytes: u64, args_count: u64, env_count: u64) -> u64
    {
        (args_bytes << 32) | (args_count << 48) | (env_count << 56)
    }

    /// `CREATE_FROM_FILE` layout: `file_size` in word 0, argv from word 1.
    const FROM_FILE_FIRST_WORD: usize = 1;

    #[test]
    fn populated_argv_and_env_extract_after_the_file_size_word()
    {
        let argv = b"a\0bc\0";
        let env = b"K=V\0";
        let msg = IpcMessage::builder(label(argv.len() as u64, 2, 1))
            .word(0, 4096)
            .bytes(FROM_FILE_FIRST_WORD, argv)
            .word(FROM_FILE_FIRST_WORD + 1, env.len() as u64)
            .bytes(FROM_FILE_FIRST_WORD + 2, env)
            .build();
        let blobs = CreateBlobs::extract(&msg, FROM_FILE_FIRST_WORD);
        assert_eq!(blobs.args().blob, argv);
        assert_eq!(blobs.args().count, 2);
        assert_eq!(blobs.env().blob, env);
        assert_eq!(blobs.env().count, 1);
    }

    #[test]
    fn argv_declared_past_the_blob_max_degrades_argv_and_env_to_empty()
    {
        // The crafted label any badged child could send: an argv length
        // whose env-header index lands far past the data array.
        let msg = IpcMessage::builder(label(0xFFFF, 1, 1))
            .word(0, 4096)
            .word(FROM_FILE_FIRST_WORD, 0x61)
            .build();
        let blobs = CreateBlobs::extract(&msg, FROM_FILE_FIRST_WORD);
        assert!(blobs.args().blob.is_empty());
        assert!(blobs.env().blob.is_empty());
    }

    #[test]
    fn argv_at_the_blob_max_keeps_the_env_header_in_range()
    {
        let argv = [b'a'; ARGS_BLOB_MAX];
        let env = b"K=VALUE\0";
        let env_header = FROM_FILE_FIRST_WORD + ARGS_BLOB_MAX / 8;
        let msg = IpcMessage::builder(label(ARGS_BLOB_MAX as u64, 1, 1))
            .word(0, 4096)
            .bytes(FROM_FILE_FIRST_WORD, &argv)
            .word(env_header, env.len() as u64)
            .bytes(env_header + 1, env)
            .build();
        let blobs = CreateBlobs::extract(&msg, FROM_FILE_FIRST_WORD);
        assert_eq!(blobs.args().blob, &argv[..]);
        assert_eq!(blobs.env().blob, env);
    }

    #[test]
    fn env_header_past_the_delivered_words_degrades_env_to_empty()
    {
        // A valid env header and blob sit in the data array at words 1..3,
        // but the delivered count stops at the argv word. Without the
        // delivered-count gate the decoder would read the header anyway and
        // report a 4-byte env blob (zero-filled, as the bytes are past the
        // delivered view), so only the gate makes env empty here.
        let argv = b"arg0\0\0\0\0";
        let env = b"K=V\0";
        let msg = IpcMessage::builder(label(argv.len() as u64, 1, 1))
            .bytes(0, argv)
            .word(1, env.len() as u64)
            .bytes(2, env)
            .word_count(1)
            .build();
        assert_eq!(msg.word_count(), 1);
        let blobs = CreateBlobs::extract(&msg, 0);
        assert_eq!(blobs.args().blob, argv);
        assert!(blobs.env().blob.is_empty());
    }

    #[test]
    fn env_at_the_blob_max_with_empty_argv_extracts_fully()
    {
        // No argv puts the env header at the first word; the blob fills the
        // per-blob bound exactly and must come through intact.
        let env = [b'e'; ARGS_BLOB_MAX];
        let msg = IpcMessage::builder(label(0, 0, 1))
            .word(0, ARGS_BLOB_MAX as u64)
            .bytes(1, &env)
            .build();
        let blobs = CreateBlobs::extract(&msg, 0);
        assert!(blobs.args().blob.is_empty());
        assert_eq!(blobs.env().blob, &env[..]);
        assert_eq!(blobs.env().count, 1);
    }

    #[test]
    fn env_one_past_the_blob_max_degrades_env_to_empty()
    {
        // The whole oversize blob is delivered, so only the bound (not a
        // short message) can make the decoder drop it.
        let argv = b"arg0\0";
        let env = [b'e'; ARGS_BLOB_MAX + 1];
        let msg = IpcMessage::builder(label(argv.len() as u64, 1, 1))
            .bytes(0, argv)
            .word(1, env.len() as u64)
            .bytes(2, &env)
            .build();
        let blobs = CreateBlobs::extract(&msg, 0);
        assert_eq!(blobs.args().blob, argv);
        assert!(blobs.env().blob.is_empty());
    }

    #[test]
    fn blob_bytes_declared_past_the_delivered_words_read_as_zero()
    {
        // argv: 16 bytes declared, one word delivered. The blob keeps its
        // declared length and the undelivered tail is zero; without the
        // delivered-words clip the copy would slice past the message view.
        let argv = b"arg0\0\0\0\0";
        let msg = IpcMessage::builder(label(16, 1, 0)).bytes(0, argv).build();
        assert_eq!(msg.word_count(), 1);
        let blobs = CreateBlobs::extract(&msg, 0);
        assert_eq!(blobs.args().blob.len(), 16);
        assert_eq!(&blobs.args().blob[..8], argv);
        assert_eq!(&blobs.args().blob[8..], &[0u8; 8]);

        // env: header declares 16 bytes over one delivered env word.
        let argv = b"a\0";
        let env = b"K=V\0\0\0\0\0";
        let msg = IpcMessage::builder(label(argv.len() as u64, 1, 1))
            .bytes(0, argv)
            .word(1, 16)
            .bytes(2, env)
            .build();
        assert_eq!(msg.word_count(), 3);
        let blobs = CreateBlobs::extract(&msg, 0);
        assert_eq!(blobs.env().blob.len(), 16);
        assert_eq!(&blobs.env().blob[..8], env);
        assert_eq!(&blobs.env().blob[8..], &[0u8; 8]);
    }
}
