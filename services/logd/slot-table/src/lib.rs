// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/slot-table/src/lib.rs

//! logd's sender state, as pure host-tested logic: each sender's display
//! name and partial-line buffer, the history of completed text lines and
//! records logd keeps for every sender under one byte bound
//! ([`HISTORY_BYTES`]; the stored form is
//! `services/logd/docs/ipc-interface.md` § History), and the retired slots
//! eviction leaves (§ Retired slots), which logd's queries read (§ Queries).
//! Nothing here makes a syscall: logd's receive workers and main thread drive
//! it under logd's state lock.
//!
//! Slots are keyed by the kernel-delivered badge on every IPC message —
//! the same `u64` procmgr uses as the child's process badge and posts as
//! the correlator of the child's death to logd's death queue. Slot
//! eviction is driven by the death events logd drains
//! (`services/logd/docs/ipc-interface.md` § Wait-set).

use std::collections::{BTreeMap, HashMap, VecDeque};

use ipc::log_query::{
    ENTRY_RECORD, ENTRY_TEXT, HistoryEntryView, SLOT_EVICTED_DEATH, SLOT_EVICTED_RESYNC, SLOT_LIVE,
};
use ipc::log_record::{FieldSpan, RECORD_MAX_BYTES, Record, Span};
use logd_codec::history::ENTRY_MAX_BYTES;
use logd_codec::query::SlotRow;
pub use logd_codec::{LINE_BUF_SIZE, MAX_NAME_LEN};

/// Bytes of history logd retains, every live and retired slot's entries
/// together, each charged [`HistoryEntry::charge`]. Retaining an entry past
/// it drops the oldest entries logd-wide until the new one fits, so what the
/// history holds is bounded whatever the number of senders, and a logd
/// restarted while memory is critical, whose every live sender is new to it,
/// holds no more. logd's budget node is a system-reserve node
/// (`services/logd/README.md` § Role), and 256 KiB is under 4% of the reserve
/// of a 512 MiB machine (`pool_total / 64`). A retention tuning value that
/// bounds no capacity: past it the oldest entry is dropped, never a sender
/// or a line's output.
pub const HISTORY_BYTES: usize = 256 * 1024;

/// Number of completed log entries a slot keeps at most, of those
/// [`HISTORY_BYTES`] retains: one sender logging without pause holds this
/// many, so it cannot drop the last lines of a quieter or a dead sender from
/// the history alone. A retention tuning value that bounds no capacity: past
/// it the slot's oldest entry is dropped, never a sender.
pub const PER_SLOT_HISTORY: usize = 16;

/// Number of evicted slots logd retains, with their names, for its queries;
/// their history counts toward [`HISTORY_BYTES`]. A retention tuning value
/// that bounds no capacity: retiring a slot into a full set drops the oldest
/// retired slot and its history, never a live one.
pub const RETIRED_SLOTS: usize = 64;

/// Number of evicted badges logd remembers, with or without a slot, so a
/// sender's message a receive worker received before the sender's eviction
/// and serves after it does not create its slot again
/// ([`SlotTable::sender_slot`]). A tuning value that bounds no capacity: past
/// it, such a message creates a live slot, which the next resync evicts. Its
/// cost, 1 KiB, is paid as evictions occur.
pub const EVICTED_BADGES: usize = 128;

/// Most fields a record holds: each takes at least four payload bytes (a key
/// length, a one-byte key and a value length), after the message length.
const RECORD_FIELDS_MAX: usize = (RECORD_MAX_BYTES - 2) / 4;

/// What every entry is charged beside its bytes and field table: its key and
/// its value in the history map.
const ENTRY_FIXED_BYTES: usize = size_of::<u64>() + size_of::<HistoryEntry>();

/// The largest [`HistoryEntry::charge`]: a record of `RECORD_MAX_BYTES` with
/// the most fields.
const ENTRY_CHARGE_MAX: usize =
    ENTRY_FIXED_BYTES + ENTRY_MAX_BYTES + RECORD_FIELDS_MAX * size_of::<FieldSpan>();

// The history holds any one entry, so retaining one never drops it at once.
const _: () = assert!(ENTRY_CHARGE_MAX <= HISTORY_BYTES);

/// What a retained entry holds.
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
        /// Each field's key and value, in the sender's order. At most
        /// [`RECORD_FIELDS_MAX`].
        fields: Box<[FieldSpan]>,
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
/// arrives. Its `seq` is its key in [`History`].
#[derive(Clone)]
pub struct HistoryEntry
{
    /// The sender's badge.
    pub badge: u64,
    /// Receipt microseconds since boot
    /// (`system_info(ElapsedUs)`-derived).
    pub us: u64,
    /// The entry's level, an `ipc::stream_labels::LEVEL_*` code: its RFC 5424
    /// severity, 0 to 7.
    pub level: u64,
    /// Whether the entry is a text line or a record, with a record's field
    /// table.
    pub kind: EntryKind,
    /// A text line's bytes, no trailing `\n`, at most [`LINE_BUF_SIZE`];
    /// or a record's payload, at most `ipc::log_record::RECORD_MAX_BYTES`.
    pub bytes: Box<[u8]>,
}

impl HistoryEntry
{
    /// The bytes the entry counts toward [`HISTORY_BYTES`]: its key and value
    /// in the history map, its bytes, and its field table. Fixed once the
    /// entry is built, so retaining and dropping it count the same.
    fn charge(&self) -> usize
    {
        let fields = match &self.kind
        {
            EntryKind::Text => 0,
            EntryKind::Record { fields, .. } => size_of_val::<[FieldSpan]>(fields),
        };
        ENTRY_FIXED_BYTES
            .saturating_add(self.bytes.len())
            .saturating_add(fields)
    }
}

/// Per-sender bucket. Stores the display name registered via
/// `STREAM_REGISTER_NAME`, the in-progress line buffer and its level, and
/// the sequence numbers of the sender's entries in the [`History`].
#[derive(Default)]
pub struct Slot
{
    pub name: Vec<u8>,
    pub partial: Vec<u8>,
    /// Level of the in-progress line: that of the `STREAM_BYTES` message
    /// that carried its first byte. Meaningful only once that byte has
    /// arrived ([`Self::begin_byte`]).
    pub partial_level: u64,
    /// The `seq` of each of the sender's last [`PER_SLOT_HISTORY`] entries,
    /// oldest first. An entry [`HISTORY_BYTES`] has dropped since keeps its
    /// number here until the slot's later entries push it out.
    seqs: VecDeque<u64>,
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
}

/// The completed entries of every live and retired slot, by `seq`, and the
/// bytes they are charged ([`HISTORY_BYTES`]).
#[derive(Default)]
pub struct History
{
    /// Entries by logd-wide arrival sequence, so the first is the oldest.
    entries: BTreeMap<u64, HistoryEntry>,
    /// The sum of the entries' [`HistoryEntry::charge`], at most
    /// [`HISTORY_BYTES`].
    bytes: usize,
    /// The `seq` the next retained entry takes. A `u64` counting one per
    /// retained entry does not wrap.
    next_seq: u64,
}

impl History
{
    /// Retain a completed text line of `slot`, the slot of sender `badge`.
    pub fn push_text(&mut self, slot: &mut Slot, badge: u64, us: u64, level: u64, bytes: &[u8])
    {
        self.push(
            slot,
            HistoryEntry {
                badge,
                us,
                level,
                kind: EntryKind::Text,
                bytes: bytes.into(),
            },
        );
    }

    /// Retain a record, with its field table, of `slot`, the slot of sender
    /// `badge`.
    pub fn push_record(
        &mut self,
        slot: &mut Slot,
        badge: u64,
        us: u64,
        level: u64,
        record: &Record<'_>,
    )
    {
        self.push(
            slot,
            HistoryEntry {
                badge,
                us,
                level,
                kind: EntryKind::Record {
                    message: record.message_span(),
                    fields: record.fields().map(|f| f.spans).collect(),
                },
                bytes: record.payload().into(),
            },
        );
    }

    /// Retain `entry` as `slot`'s newest, under the next `seq`: drop the
    /// slot's oldest entry when it holds [`PER_SLOT_HISTORY`], then the
    /// oldest entries logd-wide until the new one fits in [`HISTORY_BYTES`].
    fn push(&mut self, slot: &mut Slot, entry: HistoryEntry)
    {
        if slot.seqs.len() >= PER_SLOT_HISTORY
            && let Some(oldest) = slot.seqs.pop_front()
        {
            self.remove(oldest);
        }
        let charge = entry.charge();
        while self.bytes.saturating_add(charge) > HISTORY_BYTES
        {
            let Some((_, dropped)) = self.entries.pop_first()
            else
            {
                break;
            };
            self.bytes = self.bytes.saturating_sub(dropped.charge());
        }
        let seq = self.next_seq;
        self.next_seq = seq.saturating_add(1);
        // At most `HISTORY_BYTES` after the loop above, which the const
        // assert on `ENTRY_CHARGE_MAX` lets every entry reach.
        self.bytes = self.bytes.saturating_add(charge);
        self.entries.insert(seq, entry);
        slot.seqs.push_back(seq);
    }

    /// Drop entry `seq`, when the history still holds it.
    fn remove(&mut self, seq: u64)
    {
        if let Some(entry) = self.entries.remove(&seq)
        {
            self.bytes = self.bytes.saturating_sub(entry.charge());
        }
    }

    /// Drop every entry of `slot`, a slot leaving the table.
    fn forget(&mut self, slot: &Slot)
    {
        for &seq in &slot.seqs
        {
            self.remove(seq);
        }
    }

    /// Number of entries retained.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.entries.len()
    }

    /// Whether no entry is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.entries.is_empty()
    }

    /// The bytes the retained entries are charged, at most
    /// [`HISTORY_BYTES`].
    #[must_use]
    pub fn bytes(&self) -> usize
    {
        self.bytes
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

/// Badge-keyed slot map, with the history of its slots, the retired slots
/// eviction leaves and the badges it recently evicted.
/// `Default::default()` is the empty state at boot; the ingested handover
/// state from init-logd is merged in via [`Self::install_from_handover`].
#[derive(Default)]
pub struct SlotTable
{
    /// Live slots by badge. Grows with the sender count, so it sets no
    /// ceiling; each slot's own part is bounded (its name, its partial line
    /// and the numbers of its entries), and its entries are in the history.
    pub slots: HashMap<u64, Slot>,
    /// Evicted slots, oldest first, at most [`RETIRED_SLOTS`], each badge at
    /// most once.
    retired: VecDeque<Retired>,
    /// The badges of the most recent evictions, oldest first, at most
    /// [`EVICTED_BADGES`], each at most once; a badge evicted with no live slot
    /// is among them.
    evicted: VecDeque<u64>,
    /// Every live and retired slot's entries.
    history: History,
}

impl SlotTable
{
    /// The slot for `badge`, created when absent, and the history it retains
    /// its entries in.
    fn slot_with_history(&mut self, badge: u64) -> (&mut Slot, &mut History)
    {
        (self.slots.entry(badge).or_default(), &mut self.history)
    }

    /// The live slot of the sender `badge`, created when absent, and the
    /// history, for a caller that retains entries of the slot while it holds
    /// it; `None` when the badge has no live slot and is among the recent
    /// evictions ([`EVICTED_BADGES`]). A receive worker may serve a sender's
    /// message after another thread evicted the sender, its death having been
    /// taken between the message's receipt and the worker's turn at the state
    /// lock; the message is then the dead sender's, and logd drops it rather
    /// than give the badge a live slot again
    /// (`services/logd/docs/ipc-interface.md` § Wait-set). procmgr draws
    /// process badges at random, so a new process takes a recently evicted
    /// badge only by chance.
    pub fn sender_slot(&mut self, badge: u64) -> Option<(&mut Slot, &mut History)>
    {
        if !self.slots.contains_key(&badge) && self.evicted.contains(&badge)
        {
            return None;
        }
        Some(self.slot_with_history(badge))
    }

    /// Whether a message from `badge` that says its sender registered a
    /// display name (`ipc::stream_labels::SENDER_NAMED`) finds no name for
    /// it: the badge's live slot holds none, or the badge has no live slot and
    /// is not among the recent evictions, so its message would create an
    /// unnamed one. A restarted logd's fresh table holds no sender's name
    /// (`services/logd/docs/ipc-interface.md`
    /// § `stream_labels::STREAM_REGISTER_NAME`). An evicted sender's badge
    /// finds its name, so its message is dropped as [`Self::sender_slot`]
    /// says, not refused.
    #[must_use]
    pub fn name_lost(&self, badge: u64) -> bool
    {
        match self.slots.get(&badge)
        {
            Some(slot) => slot.name.is_empty(),
            None => !self.evicted.contains(&badge),
        }
    }

    /// The history of every live and retired slot.
    #[must_use]
    pub fn history(&self) -> &History
    {
        &self.history
    }

    /// Evict the slot for `badge` into the retired slots and return it, for
    /// the reclaim line to name. Called with each death event's correlator,
    /// and by the resync. The badge joins the recent evictions
    /// ([`Self::sender_slot`]) whether or not it has a slot; an unknown badge
    /// returns `None`. A retired slot of the same badge is replaced; a full
    /// set drops its oldest. A replaced or dropped retired slot's entries
    /// leave the history.
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
        if let Some(at) = self.retired.iter().position(|r| r.badge == badge)
            && let Some(replaced) = self.retired.remove(at)
        {
            self.history.forget(&replaced.slot);
        }
        if self.retired.len() == RETIRED_SLOTS
            && let Some(dropped) = self.retired.pop_front()
        {
            self.history.forget(&dropped.slot);
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
    /// `QUERY_HISTORY` carries it, oldest first.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "an entry's level is a `LEVEL_*` code, a severity of 0 to 7, which a `u8` holds"
    )]
    pub fn history_views(&self) -> impl Iterator<Item = HistoryEntryView<'_>>
    {
        self.history
            .entries
            .iter()
            .map(|(&seq, e)| HistoryEntryView {
                seq,
                us: e.us,
                badge: e.badge,
                level: e.level as u8,
                kind: e.kind.wire(),
                bytes: &e.bytes,
            })
    }

    /// Install one slot's (badge, name) pair from the init-logd
    /// handover replies. History lines arrive separately as
    /// [`Self::install_history_line`].
    pub fn install_from_handover(&mut self, badge: u64, name: &[u8])
    {
        let (slot, _) = self.slot_with_history(badge);
        let n = name.len().min(MAX_NAME_LEN);
        slot.name.clear();
        slot.name
            .extend_from_slice(name.get(..n).unwrap_or_default());
    }

    /// Append one history line from the init-logd handover as an entry of
    /// the matching slot, under the bounds a line logd receives takes.
    /// Creates the slot if absent (some history lines may have originated
    /// from senders whose slot was evicted from init-logd's small ring; the
    /// line itself still attributes to its badge).
    pub fn install_history_line(&mut self, badge: u64, us: u64, level: u64, bytes: &[u8])
    {
        let (slot, history) = self.slot_with_history(badge);
        history.push_text(slot, badge, us, level, bytes);
    }

    /// Append one history record from the init-logd handover as an entry of
    /// the matching slot, creating the slot if absent, as
    /// [`Self::install_history_line`] does.
    pub fn install_history_record(&mut self, badge: u64, us: u64, level: u64, record: &Record<'_>)
    {
        let (slot, history) = self.slot_with_history(badge);
        history.push_record(slot, badge, us, level, record);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::log_record::RecordWriter;
    use ipc::stream_labels::LEVEL_INFO as INFO;

    /// A record of `RECORD_MAX_BYTES` with `RECORD_FIELDS_MAX` fields, so the
    /// largest entry charge.
    fn largest_record() -> RecordWriter
    {
        let mut w = RecordWriter::with_message_bytes(b"");
        for _ in 0..RECORD_FIELDS_MAX
        {
            w.field_bytes(b"k", b"");
        }
        assert_eq!(
            w.as_bytes().len(),
            RECORD_MAX_BYTES - (RECORD_MAX_BYTES - 2) % 4
        );
        w
    }

    /// The history's charge, counted again from its entries.
    fn recount(table: &SlotTable) -> usize
    {
        table
            .history
            .entries
            .values()
            .map(HistoryEntry::charge)
            .sum()
    }

    /// The `seq`s of `badge`'s retained entries, oldest first.
    fn seqs_of(table: &SlotTable, badge: u64) -> Vec<u64>
    {
        table
            .history_views()
            .filter(|e| e.badge == badge)
            .map(|e| e.seq)
            .collect()
    }

    #[test]
    fn history_stays_within_its_bound_with_more_senders_than_it_admits()
    {
        // A fresh table, as a restarted logd's, with every sender new to it,
        // each filling its slot with the largest records: 1000 * 16 such
        // entries are over a hundred times the bound.
        let w = largest_record();
        let record = Record::decode(w.as_bytes()).unwrap();
        let mut table = SlotTable::default();
        let mut last = 0;
        for round in 0..PER_SLOT_HISTORY as u64
        {
            for badge in 1..=1000u64
            {
                let (slot, history) = table.sender_slot(badge).unwrap();
                history.push_record(slot, badge, round, INFO, &record);
                assert!(history.bytes() <= HISTORY_BYTES);
                last = history.next_seq - 1;
            }
        }
        assert_eq!(table.history.bytes(), recount(&table));
        // The newest entries are the ones kept, as many as the bound holds.
        let kept: Vec<u64> = table.history_views().map(|e| e.seq).collect();
        assert_eq!(kept.last(), Some(&last));
        assert_eq!(
            kept.len(),
            HISTORY_BYTES / table.history.entries[&last].charge()
        );
        assert!(kept.windows(2).all(|p| p[1] == p[0] + 1));
    }

    #[test]
    fn the_bound_drops_the_oldest_entry_logd_wide()
    {
        let mut table = SlotTable::default();
        let line = [b'x'; LINE_BUF_SIZE];
        table.install_history_line(1, 0, INFO, &line);
        // Senders 2.. fill the history past the bound, each within its own
        // slot's limit.
        let mut badge = 2;
        while table.history.bytes() + ENTRY_FIXED_BYTES + LINE_BUF_SIZE <= HISTORY_BYTES
        {
            table.install_history_line(badge, 0, INFO, &line);
            badge += 1;
        }
        assert_eq!(seqs_of(&table, 1), [0]);
        table.install_history_line(badge, 0, INFO, &line);
        assert_eq!(seqs_of(&table, 1), [0u64; 0], "the oldest entry is dropped");
        assert_eq!(seqs_of(&table, 2), [1], "and only it");
        assert_eq!(table.history.bytes(), recount(&table));
        // The dropped entry's sender logs on, with its slot kept.
        table.install_history_line(1, 0, INFO, b"later");
        assert_eq!(seqs_of(&table, 1).len(), 1);
    }

    #[test]
    fn a_sender_keeps_its_last_per_slot_history_entries()
    {
        let mut table = SlotTable::default();
        table.install_history_line(9, 0, INFO, b"other");
        for i in 0..PER_SLOT_HISTORY as u64 + 4
        {
            table.install_history_line(1, i, INFO, b"line");
        }
        let us: Vec<u64> = table
            .history_views()
            .filter(|e| e.badge == 1)
            .map(|e| e.us)
            .collect();
        assert_eq!(us, (4..PER_SLOT_HISTORY as u64 + 4).collect::<Vec<_>>());
        assert_eq!(seqs_of(&table, 9), [0]);
        assert_eq!(table.history.bytes(), recount(&table));
    }

    #[test]
    fn a_retired_slot_that_leaves_the_set_takes_its_history_with_it()
    {
        let mut table = SlotTable::default();
        // Badge 1 is retired, lives again and is retired again: the second
        // retirement replaces the first, whose entry leaves the history.
        table.install_history_line(1, 0, INFO, b"first life");
        table.retire(1, Eviction::Resync);
        table.install_history_line(1, 1, INFO, b"second life");
        table.retire(1, Eviction::Death { exit_reason: 0 });
        let us: Vec<u64> = table.history_views().map(|e| e.us).collect();
        assert_eq!(us, [1]);
        // A full set of retired slots drops its oldest, badge 1, and its
        // entry.
        for badge in 2..=RETIRED_SLOTS as u64 + 1
        {
            table.install_history_line(badge, badge, INFO, b"line");
            table.retire(badge, Eviction::Resync);
        }
        assert_eq!(seqs_of(&table, 1), [0u64; 0]);
        assert_eq!(table.history.len(), RETIRED_SLOTS);
        assert_eq!(table.history.bytes(), recount(&table));
    }

    // The defect caught: a child whose death post logd's full death queue
    // dropped that keeps its live slot for the life of logd (a drain whose
    // watch misses the drop, a resync that evicts nothing, or one that
    // evicts a live sender or a system special). The drain takes as logd's
    // does, each take through one `death_set::OverflowWatch`, from a model
    // of the kernel's queue (`death_set::model`), and the resync decides as
    // logd's does (`logd_codec::resync`).
    #[test]
    fn a_resync_evicts_every_slot_whose_death_a_full_queue_dropped()
    {
        use death_set::OverflowWatch;
        use death_set::model::KernelQueue;
        use ipc::log_badges::{LOG_BADGE_FIRST_CHILD, LOG_BADGE_PROCMGR};
        use logd_codec::resync::{WalkGate, evictable, is_resync_candidate};

        const RING: u32 = 2;
        let mut table = SlotTable::default();
        let children: Vec<u64> = (0..6).map(|n| LOG_BADGE_FIRST_CHILD + n).collect();
        table.install_from_handover(LOG_BADGE_PROCMGR, b"procmgr");
        for &badge in &children
        {
            table.install_from_handover(badge, b"child");
        }
        // procmgr's live processes. Five children die before logd drains,
        // more than the ring holds; procmgr takes each out of its table
        // before it posts the death to logd's queue.
        let mut live = children.clone();
        let mut queue = KernelQueue::new(RING);
        for &badge in &children[..5]
        {
            live.retain(|&b| b != badge);
            let _ = queue.post((badge, 0));
        }

        let mut watch = OverflowWatch::new(RING);
        let mut gate = WalkGate::new();
        let mut walk_started = false;
        while let Some((badge, exit_reason)) = queue.try_recv()
        {
            if watch.took()
            {
                walk_started |= gate.request();
            }
            table.retire(badge, Eviction::Death { exit_reason });
        }
        watch.found_empty();
        assert!(
            walk_started,
            "the drain that gave up a full ring starts a walk"
        );

        // The walk: the snapshot of child slots, procmgr's live list, and the
        // evictions.
        let mut snapshot: Vec<u64> = table
            .slots
            .keys()
            .copied()
            .filter(|&b| is_resync_candidate(b))
            .collect();
        snapshot.sort_unstable();
        let missing: Vec<u64> = evictable(&snapshot, &live).collect();
        for badge in missing
        {
            table.retire(badge, Eviction::Resync);
        }
        assert!(!gate.finished(), "no further resync was asked for");
        let mut left: Vec<u64> = table.slots.keys().copied().collect();
        left.sort_unstable();
        assert_eq!(left, [LOG_BADGE_PROCMGR, children[5]]);
    }
}
