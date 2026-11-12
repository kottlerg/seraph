// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/log_query.rs

//! The wire format of logd's two query labels,
//! [`QUERY_SLOTS`](crate::log_labels::QUERY_SLOTS) and
//! [`QUERY_HISTORY`](crate::log_labels::QUERY_HISTORY)
//! (`services/logd/docs/ipc-interface.md` § Queries).
//!
//! A request carries [`LOG_LABELS_VERSION`](crate::LOG_LABELS_VERSION) in
//! `data[0]` and a resume point after it. A reply's label carries its status,
//! its entry count, and whether more entries follow ([`reply_label`]); its data
//! words carry the entries: fixed [`SLOT_ENTRY_WORDS`]-word slot entries
//! ([`SlotPage`], [`slot_entry`]), or word-aligned history entries of a
//! [`HISTORY_HEADER_WORDS`]-word header and their bytes ([`HistoryPage`],
//! [`HistoryEntries`]). The server builds a page and the client reads it with
//! the same definitions.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use syscall_abi::MSG_DATA_WORDS_MAX;

use crate::log_labels::{QUERY_HISTORY, QUERY_SLOTS};
use crate::log_record::RECORD_MAX_BYTES;
use crate::{IpcMessage, LOG_LABELS_VERSION};

/// Reply status: the page follows.
pub const QUERY_OK: u64 = 0;
/// Reply status: the request's badge carries no
/// [`LOG_QUERY_AUTHORITY`](crate::log_labels::LOG_QUERY_AUTHORITY).
pub const QUERY_DENIED: u64 = 1;
/// Reply status: `data[0]` is not the receiver's
/// [`LOG_LABELS_VERSION`](crate::LOG_LABELS_VERSION).
pub const QUERY_VERSION_MISMATCH: u64 = 2;
/// Reply status: a request word holds a value the label does not define.
pub const QUERY_INVALID: u64 = 3;

/// Slot state: the slot is in logd's badge table.
pub const SLOT_LIVE: u8 = 0;
/// Slot state: a death procmgr posted evicted the slot; the entry carries the
/// death's exit reason.
pub const SLOT_EVICTED_DEATH: u8 = 1;
/// Slot state: a death-queue resync evicted the slot.
pub const SLOT_EVICTED_RESYNC: u8 = 2;

/// Longest display name a slot entry carries, in bytes: logd's
/// `MAX_NAME_LEN`, which `logd-codec` asserts equal.
pub const SLOT_NAME_MAX: usize = 48;

/// Data words one slot entry takes: the badge, the state and name length, the
/// exit reason, and the name.
pub const SLOT_ENTRY_WORDS: usize = 3 + SLOT_NAME_MAX / 8;

/// Slot entries one [`QUERY_SLOTS`] reply carries at most.
pub const SLOTS_PAGE: usize = MSG_DATA_WORDS_MAX / SLOT_ENTRY_WORDS;

/// History entry kind: a text line.
pub const ENTRY_TEXT: u8 = 0;
/// History entry kind: a log record, whose bytes are its `STREAM_RECORD`
/// payload ([`crate::log_record`]).
pub const ENTRY_RECORD: u8 = 1;

/// Header words of one history entry: `seq`, `us`, the badge, and the level,
/// kind, and byte length.
pub const HISTORY_HEADER_WORDS: usize = 4;

/// Longest entry bytes one reply holds: the data words a header leaves.
pub const HISTORY_BYTES_MAX: usize = (MSG_DATA_WORDS_MAX - HISTORY_HEADER_WORDS) * 8;

// Every retained entry fits one reply, so a walk always advances.
const _: () = assert!(HISTORY_BYTES_MAX >= RECORD_MAX_BYTES);
// The name length fits its byte of the state word.
const _: () = assert!(SLOT_NAME_MAX <= 0xFF && SLOT_NAME_MAX % 8 == 0);

/// Bit 0 of a [`QUERY_HISTORY`] request's `data[1]`: one badge's entries only.
const HISTORY_ONE_BADGE: u64 = 1;
/// Bit 1 of a [`QUERY_HISTORY`] request's `data[1]`: resume before a `seq`.
const HISTORY_RESUME: u64 = 2;

/// Bit of a reply label saying more entries follow the page.
const REPLY_MORE: u64 = 1 << 32;

/// A reply label: `status` in bits 0-15, `count` in bits 16-31, `more` in
/// bit 32.
#[must_use]
pub const fn reply_label(status: u64, count: usize, more: bool) -> u64
{
    (status & 0xFFFF) | (((count as u64) & 0xFFFF) << 16) | if more { REPLY_MORE } else { 0 }
}

/// The status a reply label carries.
#[must_use]
pub const fn reply_status(label: u64) -> u64
{
    label & 0xFFFF
}

/// The entry count a reply label carries.
#[must_use]
pub const fn reply_count(label: u64) -> usize
{
    ((label >> 16) & 0xFFFF) as usize
}

/// Whether a reply label says more entries follow its page.
#[must_use]
pub const fn reply_more(label: u64) -> bool
{
    label & REPLY_MORE != 0
}

/// A refusal: `status` and no entries.
#[must_use]
pub const fn refusal(status: u64) -> IpcMessage
{
    IpcMessage::new(reply_label(status, 0, false))
}

/// Where a [`QUERY_SLOTS`] walk resumes: after the entry of this badge and
/// state (entries ascend by badge, then state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotCursor
{
    pub badge: u64,
    pub state: u8,
}

/// A [`QUERY_SLOTS`] request: from the start, or after `after`.
#[must_use]
pub fn slots_request(after: Option<SlotCursor>) -> IpcMessage
{
    let (resume, badge, state) = match after
    {
        Some(c) => (1, c.badge, u64::from(c.state)),
        None => (0, 0, 0),
    };
    IpcMessage::builder(QUERY_SLOTS)
        .word(0, u64::from(LOG_LABELS_VERSION))
        .word(1, resume)
        .word(2, badge)
        .word(3, state)
        .build()
}

/// Read a [`QUERY_SLOTS`] request: its resume point, or the refusal status.
///
/// # Errors
/// [`QUERY_VERSION_MISMATCH`] for another version, [`QUERY_INVALID`] for a
/// `data[1]` other than 0 or 1 or a resume state no slot has.
pub fn decode_slots_request(msg: &IpcMessage) -> Result<Option<SlotCursor>, u64>
{
    if msg.word(0) != u64::from(LOG_LABELS_VERSION)
    {
        return Err(QUERY_VERSION_MISMATCH);
    }
    match msg.word(1)
    {
        0 => Ok(None),
        1 => match u8::try_from(msg.word(3))
        {
            Ok(state @ SLOT_LIVE..=SLOT_EVICTED_RESYNC) => Ok(Some(SlotCursor {
                badge: msg.word(2),
                state,
            })),
            _ => Err(QUERY_INVALID),
        },
        _ => Err(QUERY_INVALID),
    }
}

/// A [`QUERY_HISTORY`] request: every sender's entries or one badge's, from
/// the newest or before a `seq`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryRequest
{
    /// One badge's entries only, its live slot's and its retired slot's.
    pub badge: Option<u64>,
    /// Only entries older than this `seq`: the last one a page carried.
    pub before: Option<u64>,
}

impl HistoryRequest
{
    /// The request message.
    #[must_use]
    pub fn message(&self) -> IpcMessage
    {
        let mut flags = 0;
        if self.badge.is_some()
        {
            flags |= HISTORY_ONE_BADGE;
        }
        if self.before.is_some()
        {
            flags |= HISTORY_RESUME;
        }
        IpcMessage::builder(QUERY_HISTORY)
            .word(0, u64::from(LOG_LABELS_VERSION))
            .word(1, flags)
            .word(2, self.badge.unwrap_or(0))
            .word(3, self.before.unwrap_or(0))
            .build()
    }

    /// Read a request message.
    ///
    /// # Errors
    /// [`QUERY_VERSION_MISMATCH`] for another version, [`QUERY_INVALID`] for a
    /// `data[1]` with a bit the label does not define.
    pub fn decode(msg: &IpcMessage) -> Result<Self, u64>
    {
        if msg.word(0) != u64::from(LOG_LABELS_VERSION)
        {
            return Err(QUERY_VERSION_MISMATCH);
        }
        let flags = msg.word(1);
        if flags & !(HISTORY_ONE_BADGE | HISTORY_RESUME) != 0
        {
            return Err(QUERY_INVALID);
        }
        Ok(Self {
            badge: (flags & HISTORY_ONE_BADGE != 0).then(|| msg.word(2)),
            before: (flags & HISTORY_RESUME != 0).then(|| msg.word(3)),
        })
    }
}

/// One slot entry of a [`QUERY_SLOTS`] reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotEntry
{
    pub badge: u64,
    /// [`SLOT_LIVE`], [`SLOT_EVICTED_DEATH`], or [`SLOT_EVICTED_RESYNC`].
    pub state: u8,
    /// The exit reason of the death that evicted the slot; 0 for any other
    /// state.
    pub exit_reason: u64,
    name: [u8; SLOT_NAME_MAX],
    name_len: usize,
}

impl SlotEntry
{
    /// The slot's display name; empty for a slot that registered none.
    #[must_use]
    pub fn name(&self) -> &[u8]
    {
        // `slot_entry` keeps `name_len <= SLOT_NAME_MAX`, so `get` always finds
        // the range.
        self.name.get(..self.name_len).unwrap_or_default()
    }

    /// The resume point after this entry.
    #[must_use]
    pub const fn cursor(&self) -> SlotCursor
    {
        SlotCursor {
            badge: self.badge,
            state: self.state,
        }
    }
}

/// A [`QUERY_SLOTS`] reply under construction.
pub struct SlotPage
{
    words: [u64; MSG_DATA_WORDS_MAX],
    count: usize,
}

impl Default for SlotPage
{
    fn default() -> Self
    {
        Self {
            words: [0; MSG_DATA_WORDS_MAX],
            count: 0,
        }
    }
}

impl SlotPage
{
    /// Whether the page holds [`SLOTS_PAGE`] entries.
    #[must_use]
    pub const fn is_full(&self) -> bool
    {
        self.count == SLOTS_PAGE
    }

    /// Append one entry; a name past [`SLOT_NAME_MAX`] bytes is truncated.
    /// Returns `false`, writing nothing, when the page is full.
    pub fn push(&mut self, badge: u64, state: u8, exit_reason: u64, name: &[u8]) -> bool
    {
        if self.is_full()
        {
            return false;
        }
        let name = name.get(..SLOT_NAME_MAX).unwrap_or(name);
        // A page short of `SLOTS_PAGE` entries has room for one more.
        let Some([badge_word, state_word, reason_word, name_words @ ..]) = self
            .count
            .checked_mul(SLOT_ENTRY_WORDS)
            .and_then(|base| self.words.get_mut(base..)?.get_mut(..SLOT_ENTRY_WORDS))
        else
        {
            return false;
        };
        *badge_word = badge;
        *state_word = u64::from(state) | ((name.len() as u64) << 8);
        *reason_word = exit_reason;
        pack_bytes(name_words, name);
        // The count is below `SLOTS_PAGE`, so this cannot saturate.
        self.count = self.count.saturating_add(1);
        true
    }

    /// The reply: [`QUERY_OK`], the entries, and `more`.
    #[must_use]
    pub fn reply(&self, more: bool) -> IpcMessage
    {
        // `count <= SLOTS_PAGE`, so the entries' words fit `words`.
        let used = self.count.saturating_mul(SLOT_ENTRY_WORDS);
        IpcMessage::builder(reply_label(QUERY_OK, self.count, more))
            .words(0, self.words.get(..used).unwrap_or_default())
            .build()
    }
}

/// Entry `index` of a [`QUERY_SLOTS`] reply. `None` when `index` is past the
/// label's count or the reply's words, or the entry's name length is past
/// [`SLOT_NAME_MAX`].
#[must_use]
pub fn slot_entry(reply: &IpcMessage, index: usize) -> Option<SlotEntry>
{
    if index >= reply_count(reply.label)
    {
        return None;
    }
    let [badge, state_word, exit_reason, name_words @ ..] = reply
        .words()
        .get(index.checked_mul(SLOT_ENTRY_WORDS)?..)?
        .get(..SLOT_ENTRY_WORDS)?
    else
    {
        return None;
    };
    let name_len = usize::try_from((state_word >> 8) & 0xFF)
        .ok()
        .filter(|&l| l <= SLOT_NAME_MAX)?;
    let mut name = [0u8; SLOT_NAME_MAX];
    for (chunk, word) in name.chunks_mut(8).zip(name_words)
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Some(SlotEntry {
        badge: *badge,
        state: (state_word & 0xFF) as u8,
        exit_reason: *exit_reason,
        name,
        name_len,
    })
}

/// One history entry, as a [`QUERY_HISTORY`] reply carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryEntryView<'a>
{
    /// logd-wide arrival sequence; the resume point after this entry.
    pub seq: u64,
    /// Receipt time, microseconds since boot.
    pub us: u64,
    /// The sender's badge.
    pub badge: u64,
    /// An `ipc::stream_labels::LEVEL_*` code.
    pub level: u8,
    /// [`ENTRY_TEXT`] or [`ENTRY_RECORD`].
    pub kind: u8,
    /// A text line's bytes, or a record's payload.
    pub bytes: &'a [u8],
}

/// A [`QUERY_HISTORY`] reply under construction.
pub struct HistoryPage
{
    words: [u64; MSG_DATA_WORDS_MAX],
    used: usize,
    count: usize,
}

impl Default for HistoryPage
{
    fn default() -> Self
    {
        Self {
            words: [0; MSG_DATA_WORDS_MAX],
            used: 0,
            count: 0,
        }
    }
}

impl HistoryPage
{
    /// Append one entry. Returns `false`, writing nothing, when it does not
    /// fit the words left, or its bytes are longer than [`HISTORY_BYTES_MAX`].
    pub fn push(&mut self, entry: &HistoryEntryView<'_>) -> bool
    {
        if entry.bytes.len() > HISTORY_BYTES_MAX
        {
            return false;
        }
        // The bytes are at most `HISTORY_BYTES_MAX`, so `need` cannot
        // saturate.
        let need = HISTORY_HEADER_WORDS.saturating_add(entry.bytes.len().div_ceil(8));
        let Some([seq, us, badge, meta, byte_words @ ..]) = self
            .words
            .get_mut(self.used..)
            .and_then(|rest| rest.get_mut(..need))
        else
        {
            return false;
        };
        *seq = entry.seq;
        *us = entry.us;
        *badge = entry.badge;
        *meta = u64::from(entry.level)
            | (u64::from(entry.kind) << 8)
            | ((entry.bytes.len() as u64) << 16);
        pack_bytes(byte_words, entry.bytes);
        // `used + need` and the count stay within the page's
        // `MSG_DATA_WORDS_MAX` words, so neither saturates.
        self.used = self.used.saturating_add(need);
        self.count = self.count.saturating_add(1);
        true
    }

    /// Whether the page holds no entry.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.count == 0
    }

    /// The reply: [`QUERY_OK`], the entries, and `more`.
    #[must_use]
    pub fn reply(&self, more: bool) -> IpcMessage
    {
        IpcMessage::builder(reply_label(QUERY_OK, self.count, more))
            // `used <= MSG_DATA_WORDS_MAX`, so `get` always finds the range.
            .words(0, self.words.get(..self.used).unwrap_or_default())
            .build()
    }
}

/// The entries of a [`QUERY_HISTORY`] reply, in the reply's order (newest
/// first). Ends after the label's count of entries, or at the first entry
/// whose header or bytes overrun the reply; a caller that needs the whole
/// page compares the entries it read with [`reply_count`].
pub struct HistoryEntries<'a>
{
    words: &'a [u64],
    bytes: &'a [u8],
    offset: usize,
    left: usize,
}

impl<'a> HistoryEntries<'a>
{
    /// Iterate `reply`'s entries.
    #[must_use]
    pub fn new(reply: &'a IpcMessage) -> Self
    {
        Self {
            words: reply.words(),
            bytes: reply.data_bytes(),
            offset: 0,
            left: reply_count(reply.label),
        }
    }
}

impl<'a> Iterator for HistoryEntries<'a>
{
    type Item = HistoryEntryView<'a>;

    fn next(&mut self) -> Option<Self::Item>
    {
        if self.left == 0
        {
            return None;
        }
        let &[seq, us, badge, meta] = self
            .words
            .get(self.offset..)?
            .first_chunk::<HISTORY_HEADER_WORDS>()?;
        let len = ((meta >> 16) & 0xFFFF) as usize;
        // The header was found, so `body` (its end) fits a `usize`.
        let body = self.offset.saturating_add(HISTORY_HEADER_WORDS);
        let Some(bytes) = body
            .checked_mul(8)
            .and_then(|start| self.bytes.get(start..)?.get(..len))
        else
        {
            self.left = 0;
            return None;
        };
        let view = HistoryEntryView {
            seq,
            us,
            badge,
            level: (meta & 0xFF) as u8,
            kind: ((meta >> 8) & 0xFF) as u8,
            bytes,
        };
        // The bytes were found, so the next offset is within the reply.
        self.offset = body.saturating_add(len.div_ceil(8));
        self.left = self.left.saturating_sub(1);
        Some(view)
    }
}

/// Pack `bytes` little-endian into `words`, zero-padding the last word and
/// zeroing the words after it; `words` must hold `bytes.len().div_ceil(8)`.
fn pack_bytes(words: &mut [u64], bytes: &[u8])
{
    words.fill(0);
    for (word, chunk) in words.iter_mut().zip(bytes.chunks(8))
    {
        *word = u64::from_le_bytes(crate::padded_word(chunk));
    }
}

#[cfg(test)]
mod tests
{
    extern crate std;

    use std::vec::Vec;

    use super::*;

    #[test]
    fn reply_label_round_trips()
    {
        let label = reply_label(QUERY_INVALID, 7, true);
        assert_eq!(reply_status(label), QUERY_INVALID);
        assert_eq!(reply_count(label), 7);
        assert!(reply_more(label));
        let label = reply_label(QUERY_OK, 0, false);
        assert_eq!(label, 0);
        assert!(!reply_more(label));
    }

    #[test]
    fn slots_request_round_trips()
    {
        let start = slots_request(None);
        assert_eq!(start.label, QUERY_SLOTS);
        assert_eq!(decode_slots_request(&start), Ok(None));
        let cursor = SlotCursor {
            badge: u64::MAX - 3,
            state: SLOT_EVICTED_RESYNC,
        };
        assert_eq!(
            decode_slots_request(&slots_request(Some(cursor))),
            Ok(Some(cursor))
        );
    }

    #[test]
    fn slots_request_refuses_bad_words()
    {
        let msg = IpcMessage::builder(QUERY_SLOTS)
            .word(0, u64::from(LOG_LABELS_VERSION) + 1)
            .build();
        assert_eq!(decode_slots_request(&msg), Err(QUERY_VERSION_MISMATCH));
        let msg = IpcMessage::builder(QUERY_SLOTS)
            .word(0, u64::from(LOG_LABELS_VERSION))
            .word(1, 2)
            .build();
        assert_eq!(decode_slots_request(&msg), Err(QUERY_INVALID));
        let msg = IpcMessage::builder(QUERY_SLOTS)
            .word(0, u64::from(LOG_LABELS_VERSION))
            .word(1, 1)
            .word(3, u64::from(SLOT_EVICTED_RESYNC) + 1)
            .build();
        assert_eq!(decode_slots_request(&msg), Err(QUERY_INVALID));
        // An empty message, no version word, is refused too.
        assert_eq!(
            decode_slots_request(&IpcMessage::new(QUERY_SLOTS)),
            Err(QUERY_VERSION_MISMATCH)
        );
    }

    #[test]
    fn history_request_round_trips()
    {
        for req in [
            HistoryRequest::default(),
            HistoryRequest {
                badge: Some(0),
                before: None,
            },
            HistoryRequest {
                badge: Some(77),
                before: Some(0),
            },
            HistoryRequest {
                badge: None,
                before: Some(u64::MAX),
            },
        ]
        {
            let msg = req.message();
            assert_eq!(msg.label, QUERY_HISTORY);
            assert_eq!(HistoryRequest::decode(&msg), Ok(req));
        }
    }

    #[test]
    fn history_request_refuses_bad_words()
    {
        let msg = IpcMessage::builder(QUERY_HISTORY)
            .word(0, u64::from(LOG_LABELS_VERSION))
            .word(1, 4)
            .build();
        assert_eq!(HistoryRequest::decode(&msg), Err(QUERY_INVALID));
        let msg = IpcMessage::builder(QUERY_HISTORY).word(0, 4).build();
        assert_eq!(HistoryRequest::decode(&msg), Err(QUERY_VERSION_MISMATCH));
    }

    #[test]
    fn slot_page_fills_and_reads_back()
    {
        let mut page = SlotPage::default();
        let long = [b'n'; SLOT_NAME_MAX + 5];
        for i in 0..SLOTS_PAGE
        {
            let name: &[u8] = match i
            {
                0 => b"",
                1 => &long,
                _ => b"svc x=1",
            };
            assert!(page.push(100 + i as u64, (i % 3) as u8, i as u64 * 7, name));
        }
        assert!(page.is_full());
        assert!(!page.push(1, SLOT_LIVE, 0, b"over"));
        let reply = page.reply(true);
        assert!(reply.word_count() <= MSG_DATA_WORDS_MAX);
        assert_eq!(reply_count(reply.label), SLOTS_PAGE);
        assert!(reply_more(reply.label));
        let e = slot_entry(&reply, 0).expect("entry 0");
        assert_eq!(
            (e.badge, e.state, e.exit_reason, e.name()),
            (100, 0, 0, &b""[..])
        );
        let e = slot_entry(&reply, 1).expect("entry 1");
        assert_eq!(e.name(), &long[..SLOT_NAME_MAX]);
        let e = slot_entry(&reply, SLOTS_PAGE - 1).expect("last entry");
        assert_eq!(e.badge, 100 + SLOTS_PAGE as u64 - 1);
        assert_eq!(e.name(), b"svc x=1");
        assert_eq!(e.cursor().badge, e.badge);
        assert!(slot_entry(&reply, SLOTS_PAGE).is_none());
    }

    #[test]
    fn slot_entry_refuses_overruns()
    {
        // A count past the words carried.
        let reply = IpcMessage::builder(reply_label(QUERY_OK, 2, false))
            .words(0, &[0; SLOT_ENTRY_WORDS])
            .build();
        assert!(slot_entry(&reply, 0).is_some());
        assert!(slot_entry(&reply, 1).is_none());
        // A name length past the limit.
        let mut words = [0u64; SLOT_ENTRY_WORDS];
        words[1] = ((SLOT_NAME_MAX as u64) + 1) << 8;
        let reply = IpcMessage::builder(reply_label(QUERY_OK, 1, false))
            .words(0, &words)
            .build();
        assert!(slot_entry(&reply, 0).is_none());
        // init-logd's empty answer reads as an empty last page.
        let empty = IpcMessage::new(0);
        assert_eq!(reply_status(empty.label), QUERY_OK);
        assert!(slot_entry(&empty, 0).is_none());
        assert!(!reply_more(empty.label));
    }

    fn view(seq: u64, kind: u8, bytes: &[u8]) -> HistoryEntryView<'_>
    {
        HistoryEntryView {
            seq,
            us: seq * 10,
            badge: seq + 1000,
            level: 3,
            kind,
            bytes,
        }
    }

    #[test]
    fn history_page_round_trips()
    {
        let mut page = HistoryPage::default();
        assert!(page.is_empty());
        let a = view(9, ENTRY_TEXT, b"hello");
        let b = view(8, ENTRY_RECORD, &[1, 0, b'm']);
        let c = view(7, ENTRY_TEXT, b"");
        let d = view(6, ENTRY_TEXT, b"exactly8");
        for e in [&a, &b, &c, &d]
        {
            assert!(page.push(e));
        }
        let reply = page.reply(false);
        let read: Vec<_> = HistoryEntries::new(&reply).collect();
        assert_eq!(read, [a, b, c, d]);
        assert!(!reply_more(reply.label));
    }

    #[test]
    fn largest_entry_fills_one_reply()
    {
        let bytes = [0xA5u8; RECORD_MAX_BYTES];
        let big = view(1, ENTRY_RECORD, &bytes);
        let mut page = HistoryPage::default();
        assert!(page.push(&big));
        // Nothing else fits after it.
        assert!(!page.push(&view(0, ENTRY_TEXT, b"")));
        let reply = page.reply(true);
        assert_eq!(reply.word_count(), MSG_DATA_WORDS_MAX);
        let read: Vec<_> = HistoryEntries::new(&reply).collect();
        assert_eq!(read, [big]);
        // Bytes past the reply's room are refused, not cut.
        let over = [0u8; HISTORY_BYTES_MAX + 1];
        assert!(!HistoryPage::default().push(&view(2, ENTRY_TEXT, &over)));
    }

    #[test]
    fn history_entries_stop_at_an_overrun()
    {
        // The header claims more bytes than the reply carries.
        let words = [5, 50, 1005, 3 | (100 << 16), 0];
        let reply = IpcMessage::builder(reply_label(QUERY_OK, 1, false))
            .words(0, &words)
            .build();
        assert_eq!(HistoryEntries::new(&reply).count(), 0);
        // A count past the entries carried.
        let mut page = HistoryPage::default();
        assert!(page.push(&view(4, ENTRY_TEXT, b"x")));
        let mut reply = page.reply(false);
        reply.label = reply_label(QUERY_OK, 3, false);
        assert_eq!(HistoryEntries::new(&reply).count(), 1);
    }
}
