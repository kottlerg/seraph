// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/log_query.rs

//! The wire format of logd's query labels,
//! [`QUERY_SLOTS`](crate::log_labels::QUERY_SLOTS),
//! [`QUERY_HISTORY`](crate::log_labels::QUERY_HISTORY) and
//! [`LOG_SUBSCRIBE`](crate::log_labels::LOG_SUBSCRIBE)
//! (`services/logd/docs/ipc-interface.md` § Queries, § Subscriptions).
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
use core::prelude::rust_2024::*;

use syscall_abi::MSG_DATA_WORDS_MAX;

use crate::log_labels::{LOG_SUBSCRIBE, QUERY_HISTORY, QUERY_SLOTS};
use crate::log_record::RECORD_MAX_BYTES;
use crate::{IpcMessage, LOG_LABELS_VERSION};

/// Reply status: the page follows.
pub const QUERY_OK: u64 = 0;
/// Reply status: the request's badge carries none of the verb bits that
/// authorise its label ([`crate::log_labels`]).
pub const QUERY_DENIED: u64 = 1;
/// Reply status: `data[0]` is not the receiver's
/// [`LOG_LABELS_VERSION`](crate::LOG_LABELS_VERSION).
pub const QUERY_VERSION_MISMATCH: u64 = 2;
/// Reply status: a request word holds a value the label does not define, or
/// the request carries other capabilities than the label takes.
pub const QUERY_INVALID: u64 = 3;
/// Reply status: an ascending [`QUERY_HISTORY`] walk names an instance epoch
/// that is not the answering logd's: the logd instance the caller followed is
/// gone, and with it the `seq` numbering of its cursor.
pub const QUERY_STALE: u64 = 4;
/// Reply status: the [`LOG_SUBSCRIBE`] pool the request's badge draws from is
/// full.
pub const QUERY_FULL: u64 = 5;
/// Reply status: a [`SINK_SET`](crate::log_labels::SINK_SET) names no device
/// sink of logd's.
pub const QUERY_NO_SINK: u64 = 6;

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
/// exit reason, the name, the slot serial and the name generation.
pub const SLOT_ENTRY_WORDS: usize = 5 + SLOT_NAME_MAX / 8;

/// Slot entries one [`QUERY_SLOTS`] reply carries at most.
pub const SLOTS_PAGE: usize = MSG_DATA_WORDS_MAX / SLOT_ENTRY_WORDS;

/// History entry kind: a text line.
pub const ENTRY_TEXT: u8 = 0;
/// History entry kind: a log record, whose bytes are its `STREAM_RECORD`
/// payload ([`crate::log_record`]).
pub const ENTRY_RECORD: u8 = 1;

/// History entry origin: retained by the answering logd instance.
pub const ORIGIN_LIVE: u8 = 0;
/// History entry origin: installed from init-logd's handover, which wrote it
/// to the console itself.
pub const ORIGIN_RELAYED: u8 = 1;

/// Header words of one history entry: `seq`, `us`, the slot serial, and the
/// level, kind, origin, byte length and name generation.
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
/// Bit 2 of a [`QUERY_HISTORY`] request's `data[1]`: walk ascending from a
/// `seq`, that entry included.
const HISTORY_ASCENDING: u64 = 4;
/// Bit 3 of a [`QUERY_HISTORY`] request's `data[1]`: only entries at or more
/// severe than a level.
const HISTORY_LEAST: u64 = 8;
/// The most verbose level a filter names, `ipc::stream_labels::LEVEL_DEBUG`.
const LEVEL_MAX: u8 = crate::stream_labels::LEVEL_DEBUG as u8;

/// Bit of a reply label saying more entries follow the page.
const REPLY_MORE: u64 = 1 << 32;

/// A reply label: `status` in bits 0-15, `count` in bits 16-31, `more` in
/// bit 32.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`more` is the reply label's more-entries bit (bit 32)"
)]
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

/// The order and start of a [`QUERY_HISTORY`] walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walk
{
    /// Newest first: from the newest entry, or only entries older than
    /// `before`, the last one a page carried.
    Down
    {
        before: Option<u64>
    },
    /// Oldest first, from the entry `from`, that entry included (0: from the
    /// oldest), so a reader asks for the `seq` after the last one it read.
    /// `epoch` is the instance epoch the caller follows
    /// ([`Subscribed::epoch`]); logd answers [`QUERY_STALE`] when it is not
    /// its own, and 0 asks no check.
    Up
    {
        from: u64, epoch: u64
    },
}

impl Default for Walk
{
    fn default() -> Self
    {
        Self::Down { before: None }
    }
}

/// A [`QUERY_HISTORY`] request: every sender's entries or one badge's, at
/// every level or at a level and the more severe, newest first or oldest
/// first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryRequest
{
    /// One badge's entries only, its live slot's and its retired slot's.
    pub badge: Option<u64>,
    /// The order and the start of the walk.
    pub walk: Walk,
    /// Only entries at this level or more severe: an
    /// `ipc::stream_labels::LEVEL_*` code, 0 to 7.
    pub least: Option<u8>,
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
        let (seq, epoch) = match self.walk
        {
            Walk::Down { before } =>
            {
                if before.is_some()
                {
                    flags |= HISTORY_RESUME;
                }
                (before.unwrap_or(0), 0)
            }
            Walk::Up { from, epoch } =>
            {
                flags |= HISTORY_ASCENDING;
                (from, epoch)
            }
        };
        if self.least.is_some()
        {
            flags |= HISTORY_LEAST;
        }
        IpcMessage::builder(QUERY_HISTORY)
            .words(
                0,
                &[
                    u64::from(LOG_LABELS_VERSION),
                    flags,
                    self.badge.unwrap_or(0),
                    seq,
                    self.least.map_or(0, u64::from),
                    epoch,
                ],
            )
            .build()
    }

    /// Read a request message.
    ///
    /// # Errors
    /// [`QUERY_VERSION_MISMATCH`] for another version, [`QUERY_INVALID`] for a
    /// `data[1]` with a bit the label does not define or with both the resume
    /// and the ascending bit, or a level past 7.
    pub fn decode(msg: &IpcMessage) -> Result<Self, u64>
    {
        if msg.word(0) != u64::from(LOG_LABELS_VERSION)
        {
            return Err(QUERY_VERSION_MISMATCH);
        }
        let flags = msg.word(1);
        if flags & !(HISTORY_ONE_BADGE | HISTORY_RESUME | HISTORY_ASCENDING | HISTORY_LEAST) != 0
            || flags & (HISTORY_RESUME | HISTORY_ASCENDING) == HISTORY_RESUME | HISTORY_ASCENDING
        {
            return Err(QUERY_INVALID);
        }
        let least = if flags & HISTORY_LEAST == 0
        {
            None
        }
        else
        {
            match u8::try_from(msg.word(4))
            {
                Ok(level) if level <= LEVEL_MAX => Some(level),
                _ => return Err(QUERY_INVALID),
            }
        };
        let walk = if flags & HISTORY_ASCENDING == 0
        {
            Walk::Down {
                before: (flags & HISTORY_RESUME != 0).then(|| msg.word(3)),
            }
        }
        else
        {
            Walk::Up {
                from: msg.word(3),
                epoch: msg.word(5),
            }
        };
        Ok(Self {
            badge: (flags & HISTORY_ONE_BADGE != 0).then(|| msg.word(2)),
            walk,
            least,
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
    /// The slot serial, which the slot's history entries carry: from 1, never
    /// reused within a logd instance.
    pub serial: u64,
    /// The slot's name generation: how many names it registered.
    pub generation: u32,
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

/// One slot as [`SlotPage::push`] writes it.
#[derive(Clone, Copy, Debug)]
pub struct SlotFields<'a>
{
    pub badge: u64,
    /// [`SLOT_LIVE`], [`SLOT_EVICTED_DEATH`], or [`SLOT_EVICTED_RESYNC`].
    pub state: u8,
    pub exit_reason: u64,
    pub serial: u64,
    pub generation: u32,
    /// Truncated to [`SLOT_NAME_MAX`] bytes.
    pub name: &'a [u8],
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
    pub fn push(&mut self, slot: &SlotFields<'_>) -> bool
    {
        if self.is_full()
        {
            return false;
        }
        let name = slot.name.get(..SLOT_NAME_MAX).unwrap_or(slot.name);
        // A page short of `SLOTS_PAGE` entries has room for one more.
        let Some(
            [
                badge_word,
                state_word,
                reason_word,
                name_words @ ..,
                serial_word,
                generation_word,
            ],
        ) = self
            .count
            .checked_mul(SLOT_ENTRY_WORDS)
            .and_then(|base| self.words.get_mut(base..)?.get_mut(..SLOT_ENTRY_WORDS))
        else
        {
            return false;
        };
        *badge_word = slot.badge;
        *state_word = u64::from(slot.state) | ((name.len() as u64) << 8);
        *reason_word = slot.exit_reason;
        pack_bytes(name_words, name);
        *serial_word = slot.serial;
        *generation_word = u64::from(slot.generation);
        // The count is below `SLOTS_PAGE`, so this cannot saturate.
        self.count = self.count.saturating_add(1);
        true
    }

    /// The reply: [`QUERY_OK`], the entries, and `more`.
    #[must_use]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`more` is the reply label's more-entries bit (bit 32)"
    )]
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
/// label's count or the reply's words, the entry's name length is past
/// [`SLOT_NAME_MAX`], or its name generation past `u32::MAX`.
#[must_use]
pub fn slot_entry(reply: &IpcMessage, index: usize) -> Option<SlotEntry>
{
    if index >= reply_count(reply.label)
    {
        return None;
    }
    let [
        badge,
        state_word,
        exit_reason,
        name_words @ ..,
        serial,
        generation,
    ] = reply
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
        serial: *serial,
        generation: u32::try_from(*generation).ok()?,
        name,
        name_len,
    })
}

/// A [`LOG_SUBSCRIBE`] request: the signal, a capability to a Notification of
/// the subscriber's with the notify right, which logd signals when it retains
/// an entry, and the token, a capability to an object of the subscriber's that
/// nobody waits on, whose sole reference ends the subscription
/// (`services/logd/docs/ipc-interface.md` § Subscriptions).
#[must_use]
pub fn subscribe_request(signal: u64, token: u64) -> IpcMessage
{
    IpcMessage::builder(LOG_SUBSCRIBE)
        .word(0, u64::from(LOG_LABELS_VERSION))
        .cap(signal)
        .cap(token)
        .build()
}

/// The capabilities a [`LOG_SUBSCRIBE`] request carries.
pub const SUBSCRIBE_CAPS: usize = 2;

/// Read a [`LOG_SUBSCRIBE`] request: its signal and token capabilities, in
/// the receiver's capability space.
///
/// # Errors
/// [`QUERY_VERSION_MISMATCH`] for another version, [`QUERY_INVALID`] for a
/// request with other than [`SUBSCRIBE_CAPS`] capabilities.
pub fn decode_subscribe_request(msg: &IpcMessage) -> Result<(u64, u64), u64>
{
    if msg.word(0) != u64::from(LOG_LABELS_VERSION)
    {
        return Err(QUERY_VERSION_MISMATCH);
    }
    match *msg.caps()
    {
        [signal, token] => Ok((signal, token)),
        _ => Err(QUERY_INVALID),
    }
}

/// A subscription logd accepted: the [`QUERY_OK`] reply to [`LOG_SUBSCRIBE`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Subscribed
{
    /// The subscription's place in its pool.
    pub index: u64,
    /// The instance epoch: the monotonic time, in microseconds since boot,
    /// the answering logd started, which no other instance shares; never 0.
    pub epoch: u64,
    /// The `seq` of the oldest entry held, or [`Self::next`] when none is.
    pub oldest: u64,
    /// The `seq` the next entry retained takes.
    pub next: u64,
}

impl Subscribed
{
    /// The reply message.
    #[must_use]
    pub fn reply(&self) -> IpcMessage
    {
        IpcMessage::builder(reply_label(QUERY_OK, 0, false))
            .word(0, self.index)
            .word(1, self.epoch)
            .word(2, self.oldest)
            .word(3, self.next)
            .build()
    }

    /// Read a reply.
    ///
    /// # Errors
    /// The reply's status, when it is not [`QUERY_OK`].
    pub fn decode(reply: &IpcMessage) -> Result<Self, u64>
    {
        match reply_status(reply.label)
        {
            QUERY_OK => Ok(Self {
                index: reply.word(0),
                epoch: reply.word(1),
                oldest: reply.word(2),
                next: reply.word(3),
            }),
            status => Err(status),
        }
    }
}

/// One history entry, as a [`QUERY_HISTORY`] reply carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryEntryView<'a>
{
    /// logd-wide arrival sequence; the resume point after this entry.
    pub seq: u64,
    /// Receipt time, microseconds since boot.
    pub us: u64,
    /// The serial of the sender's slot, which the slot's [`QUERY_SLOTS`] row
    /// carries with its badge and name.
    pub serial: u64,
    /// The slot's name generation when the entry was retained.
    pub generation: u32,
    /// The entry's level, an `ipc::stream_labels::LEVEL_*` code: its RFC 5424
    /// severity, 0 to 7.
    pub level: u8,
    /// [`ENTRY_TEXT`] or [`ENTRY_RECORD`], 0 to 15.
    pub kind: u8,
    /// [`ORIGIN_LIVE`] or [`ORIGIN_RELAYED`], 0 to 15.
    pub origin: u8,
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
        let Some([seq, us, serial, meta, byte_words @ ..]) = self
            .words
            .get_mut(self.used..)
            .and_then(|rest| rest.get_mut(..need))
        else
        {
            return false;
        };
        *seq = entry.seq;
        *us = entry.us;
        *serial = entry.serial;
        *meta = u64::from(entry.level)
            | (u64::from(entry.kind & 0xF) << 8)
            | (u64::from(entry.origin & 0xF) << 12)
            | ((entry.bytes.len() as u64) << 16)
            | (u64::from(entry.generation) << 32);
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
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`more` is the reply label's more-entries bit (bit 32)"
    )]
    pub fn reply(&self, more: bool) -> IpcMessage
    {
        IpcMessage::builder(reply_label(QUERY_OK, self.count, more))
            // `used <= MSG_DATA_WORDS_MAX`, so `get` always finds the range.
            .words(0, self.words.get(..self.used).unwrap_or_default())
            .build()
    }
}

/// The entries of a [`QUERY_HISTORY`] reply, in the reply's order (the
/// walk's). Ends after the label's count of entries, or at the first entry
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
        let &[seq, us, serial, meta] = self
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
            serial,
            generation: (meta >> 32) as u32,
            level: (meta & 0xFF) as u8,
            kind: ((meta >> 8) & 0xF) as u8,
            origin: ((meta >> 12) & 0xF) as u8,
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
                ..HistoryRequest::default()
            },
            HistoryRequest {
                badge: Some(77),
                walk: Walk::Down { before: Some(0) },
                least: Some(0),
            },
            HistoryRequest {
                badge: None,
                walk: Walk::Down {
                    before: Some(u64::MAX),
                },
                least: Some(LEVEL_MAX),
            },
            HistoryRequest {
                badge: None,
                walk: Walk::Up { from: 0, epoch: 0 },
                least: None,
            },
            HistoryRequest {
                badge: Some(5),
                walk: Walk::Up {
                    from: u64::MAX,
                    epoch: 123_456,
                },
                least: Some(3),
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
        let version = u64::from(LOG_LABELS_VERSION);
        // A flag the label does not define; resume and ascending together; a
        // level past 7.
        for (flags, level) in [
            (16, 0),
            (HISTORY_RESUME | HISTORY_ASCENDING, 0),
            (HISTORY_LEAST, 8),
        ]
        {
            let msg = IpcMessage::builder(QUERY_HISTORY)
                .word(0, version)
                .word(1, flags)
                .word(4, level)
                .build();
            assert_eq!(HistoryRequest::decode(&msg), Err(QUERY_INVALID));
        }
        // A level word is read only under its flag.
        let msg = IpcMessage::builder(QUERY_HISTORY)
            .word(0, version)
            .word(4, 99)
            .build();
        assert_eq!(HistoryRequest::decode(&msg), Ok(HistoryRequest::default()));
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
            assert!(page.push(&SlotFields {
                badge: 100 + i as u64,
                state: (i % 3) as u8,
                exit_reason: i as u64 * 7,
                serial: 1 + i as u64,
                generation: if i == 1 { u32::MAX } else { i as u32 },
                name,
            }));
        }
        assert!(page.is_full());
        assert!(!page.push(&SlotFields {
            badge: 1,
            state: SLOT_LIVE,
            exit_reason: 0,
            serial: 99,
            generation: 0,
            name: b"over",
        }));
        let reply = page.reply(true);
        assert!(reply.word_count() <= MSG_DATA_WORDS_MAX);
        assert_eq!(reply_count(reply.label), SLOTS_PAGE);
        assert!(reply_more(reply.label));
        let e = slot_entry(&reply, 0).expect("entry 0");
        assert_eq!(
            (e.badge, e.state, e.exit_reason, e.name()),
            (100, 0, 0, &b""[..])
        );
        assert_eq!((e.serial, e.generation), (1, 0));
        let e = slot_entry(&reply, 1).expect("entry 1");
        assert_eq!(e.name(), &long[..SLOT_NAME_MAX]);
        assert_eq!((e.serial, e.generation), (2, u32::MAX));
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
        // A name generation past a `u32`.
        let mut words = [0u64; SLOT_ENTRY_WORDS];
        words[SLOT_ENTRY_WORDS - 1] = u64::from(u32::MAX) + 1;
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
            serial: seq + 1000,
            generation: (seq as u32).wrapping_mul(0x9E37_79B9),
            level: crate::stream_labels::LEVEL_ERROR as u8,
            kind,
            origin: (seq % 2) as u8,
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

    // Defect caught: an entry's severity lost or moved to another level on
    // its way through a query reply.
    #[test]
    fn each_severity_round_trips_through_a_history_page()
    {
        let mut page = HistoryPage::default();
        let entries: Vec<_> = (0u8..=7)
            .map(|level| HistoryEntryView {
                level,
                ..view(u64::from(level), ENTRY_TEXT, b"x")
            })
            .collect();
        for e in &entries
        {
            assert!(page.push(e));
        }
        let reply = page.reply(false);
        let read: Vec<_> = HistoryEntries::new(&reply).collect();
        assert_eq!(read, entries);
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

    #[test]
    fn subscribe_request_round_trips()
    {
        let msg = subscribe_request(41, 42);
        assert_eq!(msg.label, LOG_SUBSCRIBE);
        assert_eq!(decode_subscribe_request(&msg), Ok((41, 42)));
        let one = IpcMessage::builder(LOG_SUBSCRIBE)
            .word(0, u64::from(LOG_LABELS_VERSION))
            .cap(41)
            .build();
        assert_eq!(decode_subscribe_request(&one), Err(QUERY_INVALID));
        let old = IpcMessage::builder(LOG_SUBSCRIBE).cap(1).cap(2).build();
        assert_eq!(decode_subscribe_request(&old), Err(QUERY_VERSION_MISMATCH));
    }

    #[test]
    fn subscribed_reply_round_trips()
    {
        let s = Subscribed {
            index: 3,
            epoch: 1_234_567,
            oldest: 10,
            next: u64::MAX,
        };
        assert_eq!(Subscribed::decode(&s.reply()), Ok(s));
        assert_eq!(Subscribed::decode(&refusal(QUERY_FULL)), Err(QUERY_FULL));
    }

    // Defect caught: the origin or the name generation of an entry lost, or
    // spilling into the kind or the length, on its way through a reply.
    #[test]
    fn entry_meta_fields_round_trip_at_their_limits()
    {
        let entries = [
            HistoryEntryView {
                generation: u32::MAX,
                origin: ORIGIN_RELAYED,
                kind: ENTRY_RECORD,
                level: 7,
                ..view(1, ENTRY_TEXT, b"edge")
            },
            HistoryEntryView {
                generation: 0,
                origin: ORIGIN_LIVE,
                serial: u64::MAX,
                ..view(2, ENTRY_TEXT, b"")
            },
        ];
        let mut page = HistoryPage::default();
        for e in &entries
        {
            assert!(page.push(e));
        }
        let reply = page.reply(false);
        let read: Vec<_> = HistoryEntries::new(&reply).collect();
        assert_eq!(read, entries);
    }
}
