// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/src/slot.rs

//! Per-sender state: display name, partial-line buffer, and the bounded
//! history ring of completed text lines and records (the stored form is
//! `services/logd/docs/ipc-interface.md` § History), and the retired slots
//! eviction leaves (§ Retired slots), which logd's queries read (§ Queries).
//!
//! Slots are keyed by the kernel-delivered badge on every IPC message —
//! the same `u64` procmgr uses as the child's process badge and posts as
//! the correlator of the child's death to logd's death queue. Slot
//! eviction is driven by the death events logd drains
//! (`services/logd/docs/ipc-interface.md` § Wait-set).

use std::collections::{HashMap, VecDeque};

use ipc::log_query::{
    ENTRY_RECORD, ENTRY_TEXT, HistoryEntryView, SLOT_EVICTED_DEATH, SLOT_EVICTED_RESYNC, SLOT_LIVE,
};
use ipc::log_record::{FieldSpan, Record, Span};
use logd_codec::query::SlotRow;
pub use logd_codec::{LINE_BUF_SIZE, MAX_NAME_LEN};

/// Number of completed log entries retained per slot. Bounded to keep total
/// memory predictable at ~10k senders. The largest entry is a 480-byte record
/// of 119 fields, each a one-byte key and an empty value (four payload bytes),
/// whose field table adds 119 * 8 bytes: about 1.5 KiB with the entry itself,
/// so 10k * 16 * 1.5 KiB ≈ 230 MiB worst case if every sender saturates with
/// such records; in practice most slots stay near empty.
/// A retention tuning value that bounds no capacity: `push_entry` drops the
/// oldest entry, never a sender.
pub const PER_SLOT_HISTORY: usize = 16;

/// Number of evicted slots logd retains, with their names and history, for
/// its queries. A retention tuning value that bounds no capacity: retiring a
/// slot into a full set drops the oldest retired slot, never a live one. At
/// most 64 * [`PER_SLOT_HISTORY`] * 1.5 KiB ≈ 1.5 MiB worst case.
pub const RETIRED_SLOTS: usize = 64;

/// Number of evicted badges logd remembers, with or without a slot, so a
/// sender's message a receive worker received before the sender's eviction
/// and serves after it does not create its slot again
/// ([`SlotTable::sender_slot`]). A tuning value that bounds no capacity: past
/// it, such a message creates a live slot, which the next resync evicts. Its
/// cost, 1 KiB, is paid as evictions occur.
pub const EVICTED_BADGES: usize = 128;

/// What a retained entry holds.
#[derive(Clone)]
pub enum EntryKind
{
    /// A text line from `STREAM_BYTES`.
    Text,
    /// A log record from `STREAM_RECORD`: the entry's bytes are its payload
    /// (`ipc::log_record`), and these spans into them its field table.
    // The field table is the stored form a reader selecting by a key's value
    // reads (ipc-interface.md § History); `QUERY_HISTORY` sends the payload,
    // which its client decodes, so nothing in logd reads the spans yet.
    #[allow(dead_code)]
    Record
    {
        /// The message text.
        message: Span,
        /// Each field's key and value, in the sender's order. At most one
        /// per four payload bytes, so bounded by the record limit.
        fields: Vec<FieldSpan>,
    },
}

impl EntryKind
{
    /// The kind code a `QUERY_HISTORY` entry carries.
    const fn wire(&self) -> u8
    {
        match self
        {
            Self::Text => ENTRY_TEXT,
            Self::Record { .. } => ENTRY_RECORD,
        }
    }
}

/// One retained completed entry, written when the line flushes or the record
/// arrives.
#[derive(Clone)]
pub struct HistoryEntry
{
    /// logd-wide arrival sequence ([`SlotTable::next_seq`]).
    pub seq: u64,
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
    pub history: VecDeque<HistoryEntry>,
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

    /// Retain a completed text line as entry `seq`.
    pub fn push_history(&mut self, seq: u64, us: u64, level: u64, bytes: &[u8])
    {
        self.push_entry(HistoryEntry {
            seq,
            us,
            level,
            kind: EntryKind::Text,
            bytes: bytes.to_vec(),
        });
    }

    /// Retain a record, with its field table, as entry `seq`.
    pub fn push_record(&mut self, seq: u64, us: u64, level: u64, record: &Record<'_>)
    {
        self.push_entry(HistoryEntry {
            seq,
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

/// How a slot left the badge table.
#[derive(Clone, Copy)]
pub enum Eviction
{
    /// A death procmgr posted, with its exit reason.
    Death
    {
        exit_reason: u64
    },
    /// A death-queue resync: procmgr no longer listed the badge.
    Resync,
}

/// An evicted slot logd retains for its queries.
struct Retired
{
    badge: u64,
    cause: Eviction,
    slot: Slot,
}

/// Badge-keyed slot map, with the retired slots eviction leaves and the
/// badges it recently evicted.
/// `Default::default()` is the empty state at boot; the ingested handover
/// state from init-logd is merged in via [`Self::install_from_handover`].
#[derive(Default)]
pub struct SlotTable
{
    /// Live slots by badge. Grows with the sender count, so it sets no ceiling.
    pub slots: HashMap<u64, Slot>,
    /// Evicted slots, oldest first, at most [`RETIRED_SLOTS`], each badge at
    /// most once.
    retired: VecDeque<Retired>,
    /// The badges of the most recent evictions, oldest first, at most
    /// [`EVICTED_BADGES`], each at most once; a badge evicted with no live slot
    /// is among them.
    evicted: VecDeque<u64>,
    /// The `seq` the next retained entry takes.
    seq: u64,
}

impl SlotTable
{
    pub fn get_or_create(&mut self, badge: u64) -> &mut Slot
    {
        self.slots.entry(badge).or_default()
    }

    /// The slot for `badge`, created when absent, and the table's sequence,
    /// for a caller that retains entries in the slot while it holds it
    /// ([`Self::next_seq`]).
    pub fn get_or_create_with_seq(&mut self, badge: u64) -> (&mut Slot, &mut u64)
    {
        (self.slots.entry(badge).or_default(), &mut self.seq)
    }

    /// The live slot of the sender `badge`, created when absent, and the
    /// table's sequence, as [`Self::get_or_create_with_seq`] lends them; `None`
    /// when the badge has no live slot and is among the recent evictions
    /// ([`EVICTED_BADGES`]). A receive worker may serve a sender's message
    /// after another thread evicted the sender, its death having been taken
    /// between the message's receipt and the worker's turn at the state lock;
    /// the message is then the dead sender's, and logd drops it rather than
    /// give the badge a live slot again (`services/logd/docs/ipc-interface.md`
    /// § Wait-set). procmgr draws process badges at random, so a new process
    /// takes a recently evicted badge only by chance.
    pub fn sender_slot(&mut self, badge: u64) -> Option<(&mut Slot, &mut u64)>
    {
        if !self.slots.contains_key(&badge) && self.evicted.contains(&badge)
        {
            return None;
        }
        Some(self.get_or_create_with_seq(badge))
    }

    /// Take the next entry sequence from `seq`, the table's counter as
    /// [`Self::get_or_create_with_seq`] lends it. A `u64` counting one per
    /// retained entry does not wrap.
    pub fn next_seq(seq: &mut u64) -> u64
    {
        let s = *seq;
        *seq += 1;
        s
    }

    /// Evict the slot for `badge` into the retired slots and return it, for
    /// the reclaim line to name. Called with each death event's correlator,
    /// and by the resync. The badge joins the recent evictions
    /// ([`Self::sender_slot`]) whether or not it has a slot; an unknown badge
    /// returns `None`. A retired slot of the same badge is replaced; a full
    /// set drops its oldest.
    pub fn retire(&mut self, badge: u64, cause: Eviction) -> Option<&Slot>
    {
        self.evicted.retain(|&b| b != badge);
        if self.evicted.len() == EVICTED_BADGES
        {
            self.evicted.pop_front();
        }
        self.evicted.push_back(badge);
        let mut slot = self.slots.remove(&badge)?;
        // An unfinished line is never retained; free its buffer.
        slot.partial = Vec::new();
        self.retired.retain(|r| r.badge != badge);
        if self.retired.len() == RETIRED_SLOTS
        {
            self.retired.pop_front();
        }
        self.retired.push_back(Retired { badge, cause, slot });
        self.retired.back().map(|r| &r.slot)
    }

    /// Every live and retired slot, as `QUERY_SLOTS` reports it, in no
    /// order.
    pub fn slot_rows(&self) -> impl Iterator<Item = SlotRow<'_>>
    {
        let live = self.slots.iter().map(|(&badge, slot)| SlotRow {
            badge,
            state: SLOT_LIVE,
            exit_reason: 0,
            name: &slot.name,
        });
        let retired = self.retired.iter().map(|r| {
            let (state, exit_reason) = match r.cause
            {
                Eviction::Death { exit_reason } => (SLOT_EVICTED_DEATH, exit_reason),
                Eviction::Resync => (SLOT_EVICTED_RESYNC, 0),
            };
            SlotRow {
                badge: r.badge,
                state,
                exit_reason,
                name: &r.slot.name,
            }
        });
        live.chain(retired)
    }

    /// Every history entry of every live and retired slot, as
    /// `QUERY_HISTORY` carries it, in no order.
    pub fn history_views(&self) -> impl Iterator<Item = HistoryEntryView<'_>>
    {
        self.slots
            .iter()
            .map(|(&badge, slot)| (badge, slot))
            .chain(self.retired.iter().map(|r| (r.badge, &r.slot)))
            .flat_map(|(badge, slot)| {
                slot.history.iter().map(move |e| HistoryEntryView {
                    seq: e.seq,
                    us: e.us,
                    badge,
                    level: e.level as u8,
                    kind: e.kind.wire(),
                    bytes: &e.bytes,
                })
            })
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
        let (slot, seq) = self.get_or_create_with_seq(badge);
        slot.push_history(Self::next_seq(seq), us, level, bytes);
    }

    /// Append one history record from the init-logd handover into the
    /// matching slot's ring, creating the slot if absent, as
    /// [`Self::install_history_line`] does.
    pub fn install_history_record(&mut self, badge: u64, us: u64, level: u64, record: &Record<'_>)
    {
        let (slot, seq) = self.get_or_create_with_seq(badge);
        slot.push_record(Self::next_seq(seq), us, level, record);
    }
}
