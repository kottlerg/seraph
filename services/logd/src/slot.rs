// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/src/slot.rs

//! Per-sender state: display name, partial-line buffer, and the bounded
//! history ring of completed text lines and records retained for future
//! query/disk/syslog sinks (the stored form is
//! `services/logd/docs/ipc-interface.md` § History).
//!
//! Slots are keyed by the kernel-delivered badge on every IPC message —
//! the same `u64` procmgr uses as the child's process badge and posts as
//! the correlator of the child's death to logd's death queue. Slot
//! eviction is driven by the death event drained inside logd's main loop.

use std::collections::HashMap;

use ipc::log_record::{FieldSpan, Record, Span};
pub use logd_codec::{LINE_BUF_SIZE, MAX_NAME_LEN};

/// Number of completed log entries retained per slot for future query
/// surfaces. Bounded to keep total memory predictable at ~10k senders
/// (10k * 16 * 480 ≈ 75 MiB worst case if every sender saturates with
/// records of the longest length; in practice most slots stay near empty).
/// A retention tuning value that bounds no capacity: `push_entry` drops the
/// oldest entry, never a sender.
pub const PER_SLOT_HISTORY: usize = 16;

/// What a retained entry holds.
// The spans are read by the history query surface (#720), which has no
// caller yet.
#[allow(dead_code)]
#[derive(Clone)]
pub enum EntryKind
{
    /// A text line from `STREAM_BYTES`.
    Text,
    /// A log record from `STREAM_RECORD`: the entry's bytes are its payload
    /// (`ipc::log_record`), and these spans into them its field table.
    Record
    {
        /// The message text.
        message: Span,
        /// Each field's key and value, in the sender's order. At most one
        /// per four payload bytes, so bounded by the record limit.
        fields: Vec<FieldSpan>,
    },
}

/// One retained completed entry. Fields are written when the line flushes or
/// the record arrives, and read by the history query surface (#720) and
/// future disk-persistence / network-syslog sinks, none of which has a
/// caller yet, so they are dead-code-flagged.
#[allow(dead_code)]
#[derive(Clone)]
pub struct HistoryEntry
{
    /// Receipt microseconds since boot
    /// (`system_info(ElapsedUs)`-derived).
    pub us: u64,
    /// The entry's level, an `ipc::stream_labels::LEVEL_*` code.
    pub level: u64,
    /// Whether the entry is a text line or a record, with a record's field
    /// table.
    pub kind: EntryKind,
    /// A text line's bytes, no trailing `\n`, at most [`LINE_BUF_SIZE`];
    /// or a record's payload, at most `ipc::log_record::RECORD_MAX_BYTES`.
    pub bytes: Vec<u8>,
}

/// Per-sender bucket. Stores the display name registered via
/// `STREAM_REGISTER_NAME`, the in-progress line buffer and its level, and
/// the bounded ring of completed entries.
#[derive(Default)]
pub struct Slot
{
    pub name: Vec<u8>,
    pub partial: Vec<u8>,
    /// Level of the in-progress line: that of the `STREAM_BYTES` message
    /// that carried its first byte. Meaningful only once that byte has
    /// arrived ([`Self::begin_byte`]).
    pub partial_level: u64,
    pub history: std::collections::VecDeque<HistoryEntry>,
}

impl Slot
{
    /// Note that the next byte, a line byte or the newline that ends the
    /// line, arrived in a message at `level`; it sets the line's level when
    /// it is the line's first.
    pub fn begin_byte(&mut self, level: u64)
    {
        if self.partial.is_empty()
        {
            self.partial_level = level;
        }
    }

    /// Retain a completed text line.
    pub fn push_history(&mut self, us: u64, level: u64, bytes: &[u8])
    {
        self.push_entry(HistoryEntry {
            us,
            level,
            kind: EntryKind::Text,
            bytes: bytes.to_vec(),
        });
    }

    /// Retain a record, with its field table.
    pub fn push_record(&mut self, us: u64, level: u64, record: &Record<'_>)
    {
        self.push_entry(HistoryEntry {
            us,
            level,
            kind: EntryKind::Record {
                message: record.message_span(),
                fields: record.fields().map(|f| f.spans).collect(),
            },
            bytes: record.payload().to_vec(),
        });
    }

    /// Append `entry`, dropping the oldest one when the ring is full.
    fn push_entry(&mut self, entry: HistoryEntry)
    {
        if self.history.len() == PER_SLOT_HISTORY
        {
            self.history.pop_front();
        }
        self.history.push_back(entry);
    }
}

/// Badge-keyed slot map. `Default::default()` is the empty state at
/// boot; the ingested handover state from init-logd is merged in via
/// [`Self::install_from_handover`].
#[derive(Default)]
pub struct SlotTable
{
    /// Live slots by badge. Grows with the sender count, so it sets no ceiling.
    pub slots: HashMap<u64, Slot>,
}

impl SlotTable
{
    pub fn get_or_create(&mut self, badge: u64) -> &mut Slot
    {
        self.slots.entry(badge).or_default()
    }

    /// Look up `badge`, returning `None` when the sender has been
    /// evicted (by death-EQ) or never logged. Used by future query
    /// surfaces; kept for symmetry with `get_or_create` even though
    /// no caller in this PR exercises it.
    #[allow(dead_code)]
    pub fn get(&self, badge: u64) -> Option<&Slot>
    {
        self.slots.get(&badge)
    }

    /// Evict the slot for `badge` and return it, for the reclaim line to
    /// name. Called with each death event's correlator, and by the resync.
    /// Idempotent on unknown badges, which return `None`.
    pub fn evict(&mut self, badge: u64) -> Option<Slot>
    {
        self.slots.remove(&badge)
    }

    /// Install one slot's (badge, name) pair from the init-logd
    /// handover replies. History lines arrive separately as
    /// [`Self::install_history_line`].
    pub fn install_from_handover(&mut self, badge: u64, name: &[u8])
    {
        let slot = self.get_or_create(badge);
        let n = name.len().min(MAX_NAME_LEN);
        slot.name.clear();
        slot.name.extend_from_slice(&name[..n]);
    }

    /// Append one history line from the init-logd handover into the
    /// matching slot's ring. Creates the slot if absent (some history
    /// lines may have originated from senders whose slot was evicted
    /// from init-logd's small ring; the line itself still attributes
    /// to its badge).
    pub fn install_history_line(&mut self, badge: u64, us: u64, level: u64, bytes: &[u8])
    {
        self.get_or_create(badge).push_history(us, level, bytes);
    }

    /// Append one history record from the init-logd handover into the
    /// matching slot's ring, creating the slot if absent, as
    /// [`Self::install_history_line`] does.
    pub fn install_history_record(&mut self, badge: u64, us: u64, level: u64, record: &Record<'_>)
    {
        self.get_or_create(badge).push_record(us, level, record);
    }
}
