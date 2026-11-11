// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/history.rs

//! init-logd's captured-history ring: completed log entries, text lines and
//! records, packed variable-length into a fixed byte buffer, read back in
//! push order by the handover drain.
//!
//! Each ring record is a header (sender badge, receipt microseconds, entry
//! length, level, kind) followed by the entry's bytes: a text line's bytes,
//! or a log record's payload (`ipc::log_record`), whose length prefixes are
//! its field table. A ring record may wrap around the end of the buffer. A
//! push that does not fit evicts the oldest ring records until it does, so
//! the ring's entry capacity follows the entries' lengths instead of being
//! paid for at [`ENTRY_MAX_BYTES`] per entry. Entries carry absolute push
//! sequence numbers, as the handover's `HEADER`, `LINE`, and `RECORD` chunks
//! require ([handover-protocol.md](../../docs/handover-protocol.md)
//! § `LINE`).

use crate::LINE_BUF_SIZE;
use ipc::log_record::RECORD_MAX_BYTES;
use ipc::stream_labels::LEVEL_MASK;

/// Bytes of a ring record's header: badge (8), receipt microseconds (8),
/// entry length (2; an entry is at most [`ENTRY_MAX_BYTES`] bytes, which a
/// `u16` holds), level (1; an `ipc::stream_labels::LEVEL_*` code), and kind
/// (1; [`EntryKind`]).
pub const RECORD_HEADER_BYTES: usize = 20;

/// Longest entry the ring holds: a text line of [`LINE_BUF_SIZE`] bytes or a
/// record of `ipc::log_record::RECORD_MAX_BYTES`, whichever is longer.
pub const ENTRY_MAX_BYTES: usize = if LINE_BUF_SIZE > RECORD_MAX_BYTES
{
    LINE_BUF_SIZE
}
else
{
    RECORD_MAX_BYTES
};

const _: () = assert!(ENTRY_MAX_BYTES <= u16::MAX as usize);

/// What a history entry holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind
{
    /// A text line from `STREAM_BYTES`, without its newline.
    Text,
    /// A log record's payload from `STREAM_RECORD` (`ipc::log_record`).
    Record,
}

impl EntryKind
{
    /// The kind's header byte.
    const fn byte(self) -> u8
    {
        match self
        {
            Self::Text => 0,
            Self::Record => 1,
        }
    }

    /// The kind a header byte names. The ring writes only the two bytes
    /// [`Self::byte`] returns.
    const fn from_byte(b: u8) -> Self
    {
        if b == 1 { Self::Record } else { Self::Text }
    }
}

/// One entry read back from the ring.
#[derive(Debug, PartialEq, Eq)]
pub struct HistoryEntry
{
    /// Absolute push sequence number of the entry.
    pub seq: u64,
    /// Sender badge at receipt time.
    pub badge: u64,
    /// Receipt time in microseconds since boot.
    pub us: u64,
    /// The entry's level, an `ipc::stream_labels::LEVEL_*` code.
    pub level: u64,
    /// Whether the entry is a text line or a record.
    pub kind: EntryKind,
    /// Number of entry bytes copied into the caller's buffer.
    pub len: usize,
}

/// A reader's position in a [`HistoryRing`]: the sequence number of the next
/// entry to read and the byte offset of its ring record. The offset stays
/// valid while that entry is live; once the ring evicts it, the next read
/// restarts at the oldest live entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryCursor
{
    seq: u64,
    off: usize,
}

impl HistoryCursor
{
    /// A cursor at the start of the ring: its first read returns the oldest
    /// live entry.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { seq: 0, off: 0 }
    }
}

/// A byte ring of `BYTES` bytes holding completed log entries.
pub struct HistoryRing<const BYTES: usize>
{
    buf: [u8; BYTES],
    /// Byte offset of the oldest live record.
    head: usize,
    /// Byte offset the next record is written at.
    tail: usize,
    /// Bytes the live records occupy.
    used: usize,
    /// Sequence number of the oldest live record.
    first_seq: u64,
    /// Entries ever pushed: the sequence number of the next push. `u64`, the
    /// handover's sequence width; an entry count cannot wrap it within a boot.
    total: u64,
}

impl<const BYTES: usize> HistoryRing<BYTES>
{
    /// An empty ring.
    #[must_use]
    pub const fn new() -> Self
    {
        const {
            assert!(
                BYTES >= RECORD_HEADER_BYTES + ENTRY_MAX_BYTES,
                "a history ring must hold at least one entry of the longest kind"
            );
        };
        Self {
            buf: [0u8; BYTES],
            head: 0,
            tail: 0,
            used: 0,
            first_seq: 0,
            total: 0,
        }
    }

    /// Entries ever pushed, the exclusive upper bound of the sequence
    /// numbers.
    #[must_use]
    pub fn total(&self) -> u64
    {
        self.total
    }

    /// Append one text line at `level` (an `ipc::stream_labels::LEVEL_*`
    /// code, kept to the level field's bits), evicting the oldest entries
    /// until it fits. An empty line is not recorded; a line longer than
    /// [`LINE_BUF_SIZE`] is clipped to it.
    pub fn push(&mut self, badge: u64, us: u64, level: u64, line: &[u8])
    {
        if line.is_empty()
        {
            return;
        }
        self.push_entry(
            badge,
            us,
            level,
            EntryKind::Text,
            &line[..line.len().min(LINE_BUF_SIZE)],
        );
    }

    /// Append one record's payload at `level`, evicting the oldest entries
    /// until it fits. The caller passes a payload `ipc::log_record` accepted;
    /// one longer than `RECORD_MAX_BYTES` is not recorded, since clipping it
    /// would break its framing.
    pub fn push_record(&mut self, badge: u64, us: u64, level: u64, record: &[u8])
    {
        if record.len() > RECORD_MAX_BYTES
        {
            return;
        }
        self.push_entry(badge, us, level, EntryKind::Record, record);
    }

    /// Append one entry of at most [`ENTRY_MAX_BYTES`].
    fn push_entry(&mut self, badge: u64, us: u64, level: u64, kind: EntryKind, line: &[u8])
    {
        let need = RECORD_HEADER_BYTES + line.len();
        while BYTES - self.used < need
        {
            self.evict_oldest();
        }
        let mut header = [0u8; RECORD_HEADER_BYTES];
        header[0..8].copy_from_slice(&badge.to_le_bytes());
        header[8..16].copy_from_slice(&us.to_le_bytes());
        // At most ENTRY_MAX_BYTES, which the const assert above fits in a
        // u16.
        #[allow(clippy::cast_possible_truncation)]
        header[16..18].copy_from_slice(&(line.len() as u16).to_le_bytes());
        // Masked to the three-bit level field, so it fits a byte.
        #[allow(clippy::cast_possible_truncation)]
        {
            header[18] = (level & LEVEL_MASK) as u8;
        }
        header[19] = kind.byte();
        self.write_at(self.tail, &header);
        self.write_at((self.tail + RECORD_HEADER_BYTES) % BYTES, line);
        self.tail = (self.tail + need) % BYTES;
        self.used += need;
        self.total += 1;
    }

    /// Read the entry at `cursor` into `out` and advance the cursor past it.
    /// A cursor whose entry was evicted restarts at the oldest live entry.
    /// Returns `None` when the cursor has caught up with the last push; a
    /// later push makes the same cursor read again.
    pub fn read_next(
        &self,
        cursor: &mut HistoryCursor,
        out: &mut [u8; ENTRY_MAX_BYTES],
    ) -> Option<HistoryEntry>
    {
        if cursor.seq < self.first_seq
        {
            cursor.seq = self.first_seq;
            cursor.off = self.head;
        }
        if cursor.seq >= self.total
        {
            return None;
        }
        let (badge, us, level, kind, len) = self.header_at(cursor.off);
        self.read_at((cursor.off + RECORD_HEADER_BYTES) % BYTES, &mut out[..len]);
        let line = HistoryEntry {
            seq: cursor.seq,
            badge,
            us,
            level,
            kind,
            len,
        };
        cursor.seq += 1;
        cursor.off = (cursor.off + RECORD_HEADER_BYTES + len) % BYTES;
        Some(line)
    }

    /// Drop the oldest live record. Called only while a record is live: a
    /// push evicts only while the free space is short of one record, which
    /// the const assert in [`Self::new`] keeps below `BYTES`.
    fn evict_oldest(&mut self)
    {
        let (_, _, _, _, len) = self.header_at(self.head);
        let size = RECORD_HEADER_BYTES + len;
        self.head = (self.head + size) % BYTES;
        self.used -= size;
        self.first_seq += 1;
    }

    /// Decode the ring record header at `off`: badge, microseconds, level,
    /// kind, length.
    fn header_at(&self, off: usize) -> (u64, u64, u64, EntryKind, usize)
    {
        let mut header = [0u8; RECORD_HEADER_BYTES];
        self.read_at(off, &mut header);
        let mut word = [0u8; 8];
        word.copy_from_slice(&header[0..8]);
        let badge = u64::from_le_bytes(word);
        word.copy_from_slice(&header[8..16]);
        let us = u64::from_le_bytes(word);
        let len = usize::from(u16::from_le_bytes([header[16], header[17]]));
        (
            badge,
            us,
            u64::from(header[18]),
            EntryKind::from_byte(header[19]),
            len.min(ENTRY_MAX_BYTES),
        )
    }

    /// Copy `bytes` into the buffer from `off`, wrapping at the end.
    fn write_at(&mut self, off: usize, bytes: &[u8])
    {
        let first = bytes.len().min(BYTES - off);
        self.buf[off..off + first].copy_from_slice(&bytes[..first]);
        self.buf[..bytes.len() - first].copy_from_slice(&bytes[first..]);
    }

    /// Fill `out` from the buffer at `off`, wrapping at the end.
    fn read_at(&self, off: usize, out: &mut [u8])
    {
        let first = out.len().min(BYTES - off);
        out[..first].copy_from_slice(&self.buf[off..off + first]);
        let rest = out.len() - first;
        out[first..].copy_from_slice(&self.buf[..rest]);
    }
}

impl<const BYTES: usize> Default for HistoryRing<BYTES>
{
    fn default() -> Self
    {
        Self::new()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::stream_labels::{LEVEL_INFO as INFO, LEVEL_WARN};

    /// Room for exactly three 160-byte lines, and for one entry of the
    /// longest kind.
    const SMALL: usize = 3 * (RECORD_HEADER_BYTES + 160);

    fn read_all<const B: usize>(
        ring: &HistoryRing<B>,
        cursor: &mut HistoryCursor,
    ) -> Vec<(u64, u64, Vec<u8>)>
    {
        let mut out = [0u8; ENTRY_MAX_BYTES];
        let mut lines = Vec::new();
        while let Some(l) = ring.read_next(cursor, &mut out)
        {
            lines.push((l.seq, l.badge, out[..l.len].to_vec()));
        }
        lines
    }

    #[test]
    fn lines_read_back_in_push_order_with_their_badge_and_time()
    {
        let mut ring = HistoryRing::<SMALL>::new();
        ring.push(7, 11, INFO, b"first");
        ring.push(8, 12, INFO, b"second");
        let mut cursor = HistoryCursor::default();
        let mut out = [0u8; ENTRY_MAX_BYTES];
        let a = ring.read_next(&mut cursor, &mut out).unwrap();
        assert_eq!(
            (a.seq, a.badge, a.us, &out[..a.len]),
            (0, 7, 11, &b"first"[..])
        );
        let b = ring.read_next(&mut cursor, &mut out).unwrap();
        assert_eq!(
            (b.seq, b.badge, b.us, &out[..b.len]),
            (1, 8, 12, &b"second"[..])
        );
        assert_eq!(ring.read_next(&mut cursor, &mut out), None);
    }

    #[test]
    fn a_line_reads_back_with_its_level()
    {
        let mut ring = HistoryRing::<SMALL>::new();
        ring.push(1, 0, LEVEL_WARN, b"w");
        ring.push(1, 0, INFO, b"i");
        let mut cursor = HistoryCursor::default();
        let mut out = [0u8; ENTRY_MAX_BYTES];
        assert_eq!(
            ring.read_next(&mut cursor, &mut out).unwrap().level,
            LEVEL_WARN
        );
        assert_eq!(ring.read_next(&mut cursor, &mut out).unwrap().level, INFO);
    }

    #[test]
    fn a_record_reads_back_whole_with_its_kind_beside_text_lines()
    {
        use ipc::log_record::RecordWriter;
        let mut ring = HistoryRing::<SMALL>::new();
        let mut w = RecordWriter::new(format_args!("reclaim:"));
        w.field_bytes(b"name", b"x exit_reason=0x0");
        ring.push(1, 5, INFO, b"text");
        ring.push_record(2, 6, LEVEL_WARN, w.as_bytes());
        let mut cursor = HistoryCursor::default();
        let mut out = [0u8; ENTRY_MAX_BYTES];
        let a = ring.read_next(&mut cursor, &mut out).unwrap();
        assert_eq!((a.kind, &out[..a.len]), (EntryKind::Text, &b"text"[..]));
        let b = ring.read_next(&mut cursor, &mut out).unwrap();
        assert_eq!(
            (b.badge, b.us, b.level, b.kind),
            (2, 6, LEVEL_WARN, EntryKind::Record)
        );
        assert_eq!(&out[..b.len], w.as_bytes());
    }

    #[test]
    fn a_record_of_the_longest_length_is_kept_and_a_longer_one_is_not()
    {
        let mut ring = HistoryRing::<{ RECORD_HEADER_BYTES + ENTRY_MAX_BYTES }>::new();
        ring.push_record(1, 0, INFO, &[0; RECORD_MAX_BYTES + 1]);
        assert_eq!(ring.total(), 0);
        ring.push_record(1, 0, INFO, &[0; RECORD_MAX_BYTES]);
        let mut out = [0u8; ENTRY_MAX_BYTES];
        let e = ring
            .read_next(&mut HistoryCursor::default(), &mut out)
            .unwrap();
        assert_eq!((e.kind, e.len), (EntryKind::Record, RECORD_MAX_BYTES));
    }

    #[test]
    fn a_push_that_does_not_fit_evicts_the_oldest_lines()
    {
        let mut ring = HistoryRing::<SMALL>::new();
        for i in 0..4u8
        {
            ring.push(u64::from(i), 0, INFO, &[i; 160]);
        }
        let lines = read_all(&ring, &mut HistoryCursor::default());
        let seqs: Vec<u64> = lines.iter().map(|l| l.0).collect();
        assert_eq!(seqs, [1, 2, 3]);
        assert_eq!(ring.total(), 4);
    }

    #[test]
    fn short_lines_are_packed_beyond_the_full_line_count()
    {
        // Three full lines fit; short lines fit many more.
        let mut ring = HistoryRing::<SMALL>::new();
        for i in 0..10u64
        {
            ring.push(i, 0, INFO, b"0123456789");
        }
        assert_eq!(read_all(&ring, &mut HistoryCursor::default()).len(), 10);
    }

    #[test]
    fn records_that_wrap_the_buffer_end_read_back_intact()
    {
        let mut ring = HistoryRing::<SMALL>::new();
        let mut expected = Vec::new();
        for i in 0..20u8
        {
            let line: Vec<u8> = (0..(37 + usize::from(i) * 7) % 120 + 1)
                .map(|k| i.wrapping_add(k as u8))
                .collect();
            ring.push(u64::from(i), u64::from(i) * 3, INFO, &line);
            expected.push((u64::from(i), line));
        }
        let lines = read_all(&ring, &mut HistoryCursor::default());
        let first = lines[0].0 as usize;
        assert!(first > 0, "the ring wrapped and evicted");
        for (seq, badge, bytes) in lines
        {
            assert_eq!(badge, seq);
            assert_eq!(bytes, expected[seq as usize].1);
        }
    }

    #[test]
    fn a_cursor_behind_the_ring_restarts_at_the_oldest_live_line()
    {
        let mut ring = HistoryRing::<SMALL>::new();
        ring.push(0, 0, INFO, &[0; 160]);
        let mut cursor = HistoryCursor::default();
        let mut out = [0u8; ENTRY_MAX_BYTES];
        assert_eq!(ring.read_next(&mut cursor, &mut out).unwrap().seq, 0);
        // The cursor now sits at sequence 1; push enough to evict 1 and 2.
        for i in 1..6u8
        {
            ring.push(u64::from(i), 0, INFO, &[i; 160]);
        }
        let seqs: Vec<u64> = read_all(&ring, &mut cursor).iter().map(|l| l.0).collect();
        assert_eq!(seqs, [3, 4, 5]);
    }

    #[test]
    fn a_caught_up_cursor_reads_lines_pushed_later()
    {
        let mut ring = HistoryRing::<SMALL>::new();
        ring.push(1, 0, INFO, b"a");
        let mut cursor = HistoryCursor::default();
        assert_eq!(read_all(&ring, &mut cursor).len(), 1);
        ring.push(2, 0, INFO, b"b");
        let lines = read_all(&ring, &mut cursor);
        assert_eq!(lines, [(1, 2, b"b".to_vec())]);
    }

    #[test]
    fn empty_lines_are_not_recorded_and_long_lines_are_clipped()
    {
        let mut ring = HistoryRing::<SMALL>::new();
        ring.push(1, 0, INFO, b"");
        ring.push(2, 0, INFO, &[9; LINE_BUF_SIZE + 10]);
        let lines = read_all(&ring, &mut HistoryCursor::default());
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].2.len(), LINE_BUF_SIZE);
    }
}
