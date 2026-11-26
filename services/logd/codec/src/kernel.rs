// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/kernel.rs

//! The kernel's log records as both log receivers keep and write them
//! ([ipc-interface.md](../../docs/ipc-interface.md) § Kernel log).
//!
//! init-logd, then logd, reads the kernel's console lines as records
//! (`SYS_KERNEL_LOG_READ`) and writes each to the console among the lines
//! its senders send, whole, under the reserved sender name [`KERNEL_NAME`]:
//! the record's time, its level ([`level`]), and its text, split into
//! parts a receiver's line holds ([`KernelLine::parts`]). [`Cursor`]
//! follows the reader through the log's sequence numbers, names the records
//! it never read, and gives the acknowledgement of the next read.

use core::fmt::Write;

use ipc::stream_labels::{LEVEL_DEBUG, LEVEL_ERROR, LEVEL_INFO, LEVEL_WARN};
use syscall_abi::{KLOG_FLAG_TRUNCATED, KLOG_LINE_MAX, KernelLogRecord};

use crate::{BoundedStr, LINE_BUF_SIZE};

/// The sender name the kernel's lines are written and kept under.
pub const KERNEL_NAME: &[u8] = b"kernel";

/// The name a sender that registers [`KERNEL_NAME`] is stored under, so no
/// process writes lines that read as the kernel's.
pub const KERNEL_NAME_TAKEN: &[u8] = b"kernel_";

/// What a record the kernel cut at `KLOG_LINE_MAX` bytes ends with.
pub const TRUNCATED_SUFFIX: &[u8] = b" [truncated]";

/// The name a receiver stores for a sender that registers `requested`: the
/// name itself, or [`KERNEL_NAME_TAKEN`] for [`KERNEL_NAME`].
#[must_use]
pub fn stored_name(requested: &[u8]) -> &[u8]
{
    if requested == KERNEL_NAME
    {
        KERNEL_NAME_TAKEN
    }
    else
    {
        requested
    }
}

/// The `ipc::stream_labels::LEVEL_*` code of a record's RFC 5424
/// `severity`: emergency to error are errors, warning a warning, notice and
/// informational info, and debug, or any value past it, debug.
#[must_use]
pub fn level(severity: u8) -> u64
{
    match severity
    {
        0..=3 => LEVEL_ERROR,
        4 => LEVEL_WARN,
        5 | 6 => LEVEL_INFO,
        _ => LEVEL_DEBUG,
    }
}

/// Bytes of a [`KernelLine`]: the longest record's text and the suffix.
const LINE_BYTES: usize = KLOG_LINE_MAX + TRUNCATED_SUFFIX.len();

/// One record's text as a receiver writes it: the text, cut at
/// `KLOG_LINE_MAX` bytes, then [`TRUNCATED_SUFFIX`] when the kernel cut it.
pub struct KernelLine
{
    buf: [u8; LINE_BYTES],
    len: usize,
}

impl KernelLine
{
    /// The line of `record`.
    #[must_use]
    pub fn new(record: &KernelLogRecord<'_>) -> Self
    {
        let mut line = Self {
            buf: [0; LINE_BYTES],
            len: 0,
        };
        line.push(record.text.get(..KLOG_LINE_MAX).unwrap_or(record.text));
        if record.flags & KLOG_FLAG_TRUNCATED != 0
        {
            line.push(TRUNCATED_SUFFIX);
        }
        line
    }

    fn push(&mut self, bytes: &[u8])
    {
        let room = self.buf.get_mut(self.len..).unwrap_or_default();
        let n = bytes.len().min(room.len());
        if let (Some(dst), Some(src)) = (room.get_mut(..n), bytes.get(..n))
        {
            dst.copy_from_slice(src);
            // `n` fits the room after `len`, so the sum is at most the
            // buffer's length.
            self.len = self.len.saturating_add(n);
        }
    }

    /// The whole line.
    #[must_use]
    pub fn bytes(&self) -> &[u8]
    {
        self.buf.get(..self.len).unwrap_or_default()
    }

    /// The line in parts of at most `LINE_BUF_SIZE` bytes, each cut before
    /// a UTF-8 continuation byte where one lies within the last three bytes
    /// of the part, so no character of valid text is split. An empty line is
    /// one empty part. A receiver writes each part as a line of its own,
    /// with the full prefix, as it splits a sender's over-long line.
    #[must_use]
    pub fn parts(&self) -> Parts<'_>
    {
        Parts {
            rest: self.bytes(),
            first: true,
        }
    }
}

/// The parts of a [`KernelLine`]; see [`KernelLine::parts`].
pub struct Parts<'a>
{
    rest: &'a [u8],
    first: bool,
}

impl<'a> Iterator for Parts<'a>
{
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]>
    {
        if self.rest.is_empty() && !self.first
        {
            return None;
        }
        self.first = false;
        let mut cut = self.rest.len().min(LINE_BUF_SIZE);
        if cut < self.rest.len()
        {
            // Back off at most three bytes: a UTF-8 character is at most four.
            let boundary = (cut.saturating_sub(3)..=cut)
                .rev()
                .find(|&i| self.rest.get(i).is_some_and(|&b| b & 0xC0 != 0x80));
            if let Some(i) = boundary
                && i > 0
            {
                cut = i;
            }
        }
        let (part, rest) = self.rest.split_at(cut);
        self.rest = rest;
        Some(part)
    }
}

/// What [`Cursor::accept`] makes of the next record a read returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Accept
{
    /// Not newer than the last record accepted: already written, so skipped.
    Stale,
    /// The record after the last one accepted, or the reader's first.
    InOrder,
    /// Newer than the one after the last accepted: the records `first` to
    /// `last` were never read, overwritten in the ring before the reader came
    /// to them, or written by a kernel flush
    /// (`core/kernel/docs/kernel-log.md` § Flush).
    AfterGap
    {
        /// The first record not read.
        first: u64,
        /// The last record not read.
        last: u64,
    },
}

/// A reader's place in the kernel log: the last record it accepted, which
/// its next read acknowledges.
#[derive(Clone, Copy, Default, Debug)]
pub struct Cursor
{
    accepted: u64,
}

impl Cursor
{
    /// A reader that has accepted no record.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { accepted: 0 }
    }

    /// The `ack_seq` of the reader's next read: the last record accepted,
    /// `0` before the first.
    #[must_use]
    pub const fn ack(&self) -> u64
    {
        self.accepted
    }

    /// Take record `seq` as the next to write, unless it is [`Accept::Stale`].
    /// The first record a reader accepts is never after a gap: what came
    /// before it is the earlier reader's.
    pub fn accept(&mut self, seq: u64) -> Accept
    {
        if seq <= self.accepted
        {
            return Accept::Stale;
        }
        let expected = self.accepted.saturating_add(1);
        let first_read = self.accepted == 0;
        self.accepted = seq;
        if first_read || seq == expected
        {
            Accept::InOrder
        }
        else
        {
            Accept::AfterGap {
                first: expected,
                last: seq.saturating_sub(1),
            }
        }
    }
}

/// The text of the receiver's own line naming the records `first` to `last`
/// it never read ([`Accept::AfterGap`]).
#[must_use]
pub fn gap_text(first: u64, last: u64) -> BoundedStr<LINE_BUF_SIZE>
{
    let mut text = BoundedStr::new();
    let count = last.saturating_sub(first).saturating_add(1);
    let _ = write!(
        text,
        "{count} kernel log lines not read (records {first}-{last}): overwritten in the \
         kernel's ring, or written by the kernel itself"
    );
    text
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn record(text: &[u8], flags: u8) -> KernelLogRecord<'_>
    {
        KernelLogRecord {
            seq: 1,
            us: 2,
            level: 6,
            flags,
            text,
        }
    }

    #[test]
    fn a_sender_cannot_take_the_kernels_name()
    {
        assert_eq!(stored_name(b"kernel"), b"kernel_");
        assert_eq!(stored_name(b"kernel_"), b"kernel_");
        assert_eq!(stored_name(b"kern"), b"kern");
        assert_eq!(stored_name(b"kernel2"), b"kernel2");
        assert_eq!(stored_name(b""), b"");
    }

    #[test]
    fn severities_map_to_receiver_levels()
    {
        for s in 0..=3
        {
            assert_eq!(level(s), LEVEL_ERROR);
        }
        assert_eq!(level(4), LEVEL_WARN);
        assert_eq!(level(5), LEVEL_INFO);
        assert_eq!(level(6), LEVEL_INFO);
        assert_eq!(level(7), LEVEL_DEBUG);
        assert_eq!(level(200), LEVEL_DEBUG);
    }

    #[test]
    fn a_short_line_is_one_part()
    {
        let line = KernelLine::new(&record(b"cspace 0: slot-page pool exhausted", 0));
        let parts: Vec<&[u8]> = line.parts().collect();
        assert_eq!(parts, vec![&b"cspace 0: slot-page pool exhausted"[..]]);
    }

    #[test]
    fn an_empty_line_is_one_empty_part()
    {
        let line = KernelLine::new(&record(b"", 0));
        assert_eq!(line.parts().collect::<Vec<_>>(), vec![&b""[..]]);
    }

    #[test]
    fn a_truncated_record_ends_with_the_suffix()
    {
        let line = KernelLine::new(&record(b"abc", KLOG_FLAG_TRUNCATED));
        assert_eq!(line.bytes(), b"abc [truncated]");
    }

    #[test]
    fn a_long_line_splits_at_the_receivers_line_width()
    {
        let text = [b'x'; KLOG_LINE_MAX];
        let line = KernelLine::new(&record(&text, KLOG_FLAG_TRUNCATED));
        let parts: Vec<&[u8]> = line.parts().collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.len() <= LINE_BUF_SIZE));
        assert_eq!(parts.concat(), line.bytes());
        assert!(parts[2].ends_with(TRUNCATED_SUFFIX));
    }

    #[test]
    fn no_part_splits_a_character()
    {
        // A two-byte character straddling the width, at every offset.
        for pad in 0..4
        {
            let mut text = vec![b'a'; LINE_BUF_SIZE - 1 - pad];
            while text.len() < KLOG_LINE_MAX - 4
            {
                text.extend_from_slice("é".as_bytes());
                text.extend_from_slice("€".as_bytes());
            }
            let line = KernelLine::new(&record(&text, 0));
            let parts: Vec<&[u8]> = line.parts().collect();
            assert_eq!(parts.concat(), text);
            for part in parts
            {
                assert!(part.len() <= LINE_BUF_SIZE);
                assert!(core::str::from_utf8(part).is_ok(), "pad {pad}");
            }
        }
    }

    #[test]
    fn text_past_the_record_bound_is_clipped()
    {
        let text = [b'y'; KLOG_LINE_MAX + 10];
        let line = KernelLine::new(&record(&text, 0));
        assert_eq!(line.bytes().len(), KLOG_LINE_MAX);
    }

    #[test]
    fn a_cursor_names_the_records_it_never_read()
    {
        let mut c = Cursor::new();
        assert_eq!(c.ack(), 0);
        // The first record after another reader's is in order.
        assert_eq!(c.accept(40), Accept::InOrder);
        assert_eq!(c.accept(41), Accept::InOrder);
        assert_eq!(c.ack(), 41);
        assert_eq!(c.accept(41), Accept::Stale);
        assert_eq!(c.accept(12), Accept::Stale);
        assert_eq!(
            c.accept(45),
            Accept::AfterGap {
                first: 42,
                last: 44
            }
        );
        assert_eq!(c.ack(), 45);
        assert_eq!(c.accept(46), Accept::InOrder);
    }

    #[test]
    fn the_gap_line_counts_the_records()
    {
        assert_eq!(
            gap_text(42, 44).as_str(),
            "3 kernel log lines not read (records 42-44): overwritten in the kernel's ring, or \
             written by the kernel itself"
        );
    }
}
