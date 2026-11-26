// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/klog/ring.rs

//! The kernel log ring: records in a fixed array of atomic words, and the
//! reader cursor state that decides attach, acknowledgement and stall.
//!
//! The layout, the overwrite order and the lock-free read are specified in
//! `core/kernel/docs/kernel-log.md` § The ring. The appending side runs under
//! the kernel log lock (`klog::KLOG_LOCK`); [`Ring::read_unlocked`] runs
//! without it, on the panic, `fatal` and watchdog paths.

use core::sync::atomic::{AtomicU64, Ordering, fence};

use syscall::{KLOG_FLAG_TRUNCATED, KLOG_HEADER_BYTES, KLOG_LINE_MAX};

/// [`KLOG_HEADER_BYTES`] as a byte position offset.
const HEADER: u64 = KLOG_HEADER_BYTES as u64;

/// Bytes of one record at its longest: the header and [`KLOG_LINE_MAX`] bytes
/// of text.
pub const RECORD_MAX: u64 = HEADER + KLOG_LINE_MAX as u64;

/// The tag in the top byte of a header's sequence word. No UTF-8 text word
/// holds `0xFF` in any byte and a text word's unused bytes are zero, so a
/// text word is never taken for a header.
const SEQ_TAG: u64 = 0xFF << 56;

/// The sequence-number bits of a header's sequence word.
const SEQ_MASK: u64 = (1 << 56) - 1;

/// Bytes a record of `len` text bytes takes: the header and the text, rounded
/// up to whole words. `len` is at most [`KLOG_LINE_MAX`] for every record.
pub fn record_bytes(len: usize) -> u64
{
    let text = u64::try_from(len.min(KLOG_LINE_MAX).next_multiple_of(8)).unwrap_or(0);
    HEADER.wrapping_add(text)
}

/// The header's third word: the level, the flags and the text length.
fn meta_word(level: u8, flags: u8, len: usize) -> u64
{
    let len = u64::try_from(len.min(KLOG_LINE_MAX)).unwrap_or(0);
    u64::from(level) | (u64::from(flags) << 8) | (len << 16)
}

/// The text length a header's third word holds.
fn meta_len(meta: u64) -> usize
{
    usize::try_from((meta >> 16) & 0xFFFF).unwrap_or(usize::MAX)
}

/// A ring of `W` words of records, oldest first. `W * 8` bytes hold at least
/// two records of [`RECORD_MAX`] bytes.
pub struct Ring<const W: usize>
{
    words: [AtomicU64; W],
    /// Byte position of the oldest record. Positions only grow; a position
    /// names word `(pos / 8) % W`.
    tail: AtomicU64,
    /// Byte position one past the newest record.
    head: AtomicU64,
    /// The sequence number the next record takes. The first record is 1.
    next_seq: AtomicU64,
}

/// One record read out of the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordMeta
{
    /// The record's sequence number.
    pub seq: u64,
    /// The kernel's time when the line was formed, in microseconds.
    pub us: u64,
    /// The line's RFC 5424 severity.
    pub level: u8,
    /// `KLOG_FLAG_*` bits.
    pub flags: u8,
    /// Text bytes.
    pub len: usize,
}

impl<const W: usize> Ring<W>
{
    /// The ring's size in bytes.
    const BYTES: u64 = (W as u64) * 8;

    /// The ring holds two records of the longest line.
    const FITS_TWO: () = assert!(Self::BYTES >= 2 * RECORD_MAX);

    /// An empty ring.
    pub const fn new() -> Self
    {
        let () = Self::FITS_TWO;
        Self {
            words: [const { AtomicU64::new(0) }; W],
            tail: AtomicU64::new(0),
            head: AtomicU64::new(0),
            next_seq: AtomicU64::new(1),
        }
    }

    /// The word byte position `pos` names.
    fn word(&self, pos: u64) -> &AtomicU64
    {
        let idx = usize::try_from((pos >> 3).checked_rem(W as u64).unwrap_or(0)).unwrap_or(0);
        let fallback = self.words.first();
        // `idx` is below `W`, and `W` is non-zero (`FITS_TWO`).
        self.words
            .get(idx)
            .or(fallback)
            .unwrap_or_else(|| unreachable_word())
    }

    /// The sequence number of the newest record, or 0 when none has been
    /// appended.
    pub fn newest_seq(&self) -> u64
    {
        self.next_seq.load(Ordering::Relaxed).saturating_sub(1)
    }

    /// Start a record: drop the oldest records until one of [`RECORD_MAX`]
    /// bytes fits, and return a writer for its text. Under the ring's lock.
    ///
    /// Each dropped record's sequence word is cleared before a release fence,
    /// and the new record's words are written only after it, so a lock-free
    /// reader that took a dropped record's sequence number finds it changed.
    pub fn begin(&self) -> LineWriter<'_, W>
    {
        let head = self.head.load(Ordering::Relaxed);
        let mut tail = self.tail.load(Ordering::Relaxed);
        while head.wrapping_sub(tail).wrapping_add(RECORD_MAX) > Self::BYTES
        {
            let len = meta_len(self.word(tail.wrapping_add(16)).load(Ordering::Relaxed));
            self.word(tail).store(0, Ordering::Relaxed);
            tail = tail.wrapping_add(record_bytes(len));
        }
        self.tail.store(tail, Ordering::Relaxed);
        fence(Ordering::Release);
        LineWriter {
            ring: self,
            start: head,
            len: 0,
            acc: 0,
            truncated: false,
        }
    }

    /// Finish the record `w` began: write its header, the sequence word last
    /// with release ordering, and return its sequence number. Under the ring's
    /// lock.
    pub fn commit(&self, mut w: LineWriter<'_, W>, us: u64, level: u8) -> u64
    {
        w.flush_partial();
        let flags = if w.truncated { KLOG_FLAG_TRUNCATED } else { 0 };
        self.word(w.start.wrapping_add(8))
            .store(us, Ordering::Relaxed);
        self.word(w.start.wrapping_add(16))
            .store(meta_word(level, flags, w.len), Ordering::Relaxed);
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        self.word(w.start)
            .store(SEQ_TAG | (seq & SEQ_MASK), Ordering::Release);
        self.head
            .store(w.start.wrapping_add(record_bytes(w.len)), Ordering::Release);
        seq
    }

    /// Read the record at byte position `pos` without the ring's lock, into
    /// `text`. `expect` is the sequence number the caller's walk expects there,
    /// or `None` for the first record of a walk.
    ///
    /// The read is a sequence-lock read: the sequence word with acquire
    /// ordering, the header and text, an acquire fence, and the sequence word
    /// again. It returns `None` when the first sequence read is not a header,
    /// the two differ, the first differs from `expect`, or the length is past
    /// [`KLOG_LINE_MAX`]: the appender overwrote or is writing the record.
    pub fn read_unlocked(
        &self,
        pos: u64,
        expect: Option<u64>,
        text: &mut [u8; KLOG_LINE_MAX],
    ) -> Option<RecordMeta>
    {
        let s1 = self.word(pos).load(Ordering::Acquire);
        if s1 & SEQ_TAG != SEQ_TAG
        {
            return None;
        }
        let seq = s1 & SEQ_MASK;
        if expect.is_some_and(|e| e != seq)
        {
            return None;
        }
        let us = self.word(pos.wrapping_add(8)).load(Ordering::Relaxed);
        let meta = self.word(pos.wrapping_add(16)).load(Ordering::Relaxed);
        let len = meta_len(meta);
        if len > KLOG_LINE_MAX
        {
            return None;
        }
        self.copy_text(pos, len, text);
        fence(Ordering::Acquire);
        if self.word(pos).load(Ordering::Relaxed) != s1
        {
            return None;
        }
        let [level, flags, ..] = meta.to_le_bytes();
        Some(RecordMeta {
            seq,
            us,
            level,
            flags,
            len,
        })
    }

    /// Copy the `len` text bytes of the record at `pos` into `text`.
    fn copy_text(&self, pos: u64, len: usize, text: &mut [u8; KLOG_LINE_MAX])
    {
        let mut at = pos.wrapping_add(HEADER);
        for chunk in text.chunks_mut(8).take(len.div_ceil(8))
        {
            let w = self.word(at).load(Ordering::Relaxed).to_le_bytes();
            for (d, s) in chunk.iter_mut().zip(w)
            {
                *d = s;
            }
            at = at.wrapping_add(8);
        }
    }

    /// The positions a walk over the ring starts and ends at: the oldest
    /// record and one past the newest.
    pub fn bounds(&self) -> (u64, u64)
    {
        // Head first: a record committed after this read is outside the walk.
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        (tail, head.max(tail))
    }

    /// Copy the records from sequence number `from` on (from the oldest when it
    /// is older than the ring holds) into `out`, whole records only, in the
    /// ABI's form: the header with an untagged sequence number, then the text
    /// padded to whole words. Under the ring's lock.
    ///
    /// Returns the bytes written and the sequence number of the last record
    /// written, 0 when none was.
    pub fn copy_out(&self, from: u64, out: &mut [u8]) -> (usize, u64)
    {
        let mut text = [0u8; KLOG_LINE_MAX];
        let (mut pos, head) = self.bounds();
        let mut written = 0usize;
        let mut last = 0u64;
        while pos < head
        {
            // Under the lock no record changes, so every read succeeds.
            let Some(m) = self.read_unlocked(pos, None, &mut text)
            else
            {
                break;
            };
            let rec = record_bytes(m.len);
            pos = pos.wrapping_add(rec);
            if m.seq < from
            {
                continue;
            }
            let rec = usize::try_from(rec).unwrap_or(usize::MAX);
            let Some(dst) = out.get_mut(written..written.saturating_add(rec))
            else
            {
                break;
            };
            encode_record(&m, text.get(..m.len).unwrap_or_default(), dst);
            written = written.saturating_add(rec);
            last = m.seq;
        }
        (written, last)
    }
}

/// The word [`Ring::word`] can never fail to find: a ring has at least one.
#[cold]
fn unreachable_word() -> &'static AtomicU64
{
    static ZERO: AtomicU64 = AtomicU64::new(0);
    &ZERO
}

/// Write one record in the ABI's form into `dst`, which is
/// [`record_bytes`]`(m.len)` long.
fn encode_record(m: &RecordMeta, text: &[u8], dst: &mut [u8])
{
    dst.fill(0);
    let (hdr, body) = dst.split_at_mut(KLOG_HEADER_BYTES.min(dst.len()));
    let words = [m.seq, m.us, meta_word(m.level, m.flags, m.len)];
    for (chunk, w) in hdr.chunks_mut(8).zip(words)
    {
        for (d, s) in chunk.iter_mut().zip(w.to_le_bytes())
        {
            *d = s;
        }
    }
    for (d, s) in body.iter_mut().zip(text)
    {
        *d = *s;
    }
}

/// The text of one record being formed, written straight into the ring.
pub struct LineWriter<'r, const W: usize>
{
    ring: &'r Ring<W>,
    start: u64,
    len: usize,
    acc: u64,
    truncated: bool,
}

impl<const W: usize> LineWriter<'_, W>
{
    /// Append one byte to the text.
    fn push(&mut self, byte: u8)
    {
        let shift = (self.len & 7) << 3;
        self.acc |= u64::from(byte) << shift;
        self.len = self.len.wrapping_add(1);
        if self.len.trailing_zeros() >= 3
        {
            self.store_acc();
        }
    }

    /// Store the word being filled, which holds the last text byte.
    fn store_acc(&mut self)
    {
        let word_off = u64::try_from(self.len.saturating_sub(1) & !7).unwrap_or(0);
        let pos = self.start.wrapping_add(HEADER).wrapping_add(word_off);
        self.ring.word(pos).store(self.acc, Ordering::Relaxed);
        self.acc = 0;
    }

    /// Store a last word the text only partly fills.
    fn flush_partial(&mut self)
    {
        if self.len & 7 != 0
        {
            self.store_acc();
        }
    }
}

impl<const W: usize> core::fmt::Write for LineWriter<'_, W>
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result
    {
        if self.truncated
        {
            return Ok(());
        }
        let room = KLOG_LINE_MAX.saturating_sub(self.len);
        let take = if s.len() <= room
        {
            s.len()
        }
        else
        {
            self.truncated = true;
            // The longest prefix that ends on a character boundary.
            (0..=room)
                .rev()
                .find(|&i| s.is_char_boundary(i))
                .unwrap_or(0)
        };
        for &b in s.as_bytes().get(..take).unwrap_or_default()
        {
            self.push(b);
        }
        Ok(())
    }
}

/// The reader's side of the log: whether a reader is attached, what it has
/// acknowledged and read, and when its stall bound started. Changed under the
/// ring's lock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor
{
    /// A reader is attached: a print becomes a record.
    pub attached: bool,
    /// The highest sequence number a reader has reported written or given up.
    pub committed: u64,
    /// The highest sequence number a read has returned.
    pub last_read_seq: u64,
    /// The kernel's time the stall bound runs from, in microseconds: the
    /// later of the last read that attached the reader or returned a record
    /// past `last_read_seq`, and the append of the oldest record no read has
    /// returned.
    pub since_us: u64,
}

impl Cursor
{
    /// The sequence number a read with `from_seq` starts at: the record after
    /// the committed one for 0, else `from_seq`.
    pub fn start_seq(&self, from_seq: u64) -> u64
    {
        if from_seq == 0
        {
            self.committed.saturating_add(1)
        }
        else
        {
            from_seq
        }
    }

    /// Raise the committed mark to `ack_seq`, with `newest` the ring's newest
    /// sequence number: the mark only grows, and never past `newest`.
    pub fn acknowledge(&mut self, ack_seq: u64, newest: u64)
    {
        self.committed = self.committed.max(ack_seq.min(newest));
    }

    /// Record a read that completed at `now_us`, which acknowledged `ack_seq`
    /// and returned records up to `returned_last` (0 for none), with `newest`
    /// the ring's newest sequence number. Attaches the reader; the committed
    /// mark only grows, and never past `newest`. The stall bound starts again
    /// only when the read attached the reader or returned a record it had not
    /// read: a read that returns nothing new leaves it running.
    pub fn on_read(&mut self, ack_seq: u64, returned_last: u64, newest: u64, now_us: u64)
    {
        if !self.attached || returned_last > self.last_read_seq
        {
            self.since_us = now_us;
        }
        self.attached = true;
        self.acknowledge(ack_seq, newest);
        self.last_read_seq = self.last_read_seq.max(returned_last);
    }

    /// Record the append of record `seq` at `us`: when no record was unread
    /// before it, the stall bound starts at its append.
    pub fn on_append(&mut self, seq: u64, us: u64)
    {
        if seq == self.last_read_seq.saturating_add(1)
        {
            self.since_us = self.since_us.max(us);
        }
    }

    /// Whether the attached reader has stalled at `now_us`: records it has not
    /// read exist, and more than `stall_us` has passed since the oldest of them
    /// was appended and since the reader last attached or read a new record.
    pub fn stalled(&self, newest: u64, now_us: u64, stall_us: u64) -> bool
    {
        self.attached
            && newest > self.last_read_seq
            && now_us.saturating_sub(self.since_us) > stall_us
    }
}

#[cfg(test)]
mod tests
{
    use core::fmt::Write;

    use super::*;

    /// The smallest ring the type allows: two records of the longest line.
    /// In words: twice the header's three and the text's.
    const SMALL: usize = 2 * (3 + KLOG_LINE_MAX / 8);
    const _: () = assert!((SMALL * 8) as u64 == 2 * RECORD_MAX);

    fn append<const W: usize>(r: &Ring<W>, text: &str) -> u64
    {
        let mut w = r.begin();
        w.write_str(text).unwrap();
        r.commit(w, 7, 6)
    }

    fn records<const W: usize>(r: &Ring<W>, from: u64) -> Vec<(u64, String)>
    {
        // Decoded with the ABI's own reader, so the two forms cannot drift.
        let mut out = vec![0u8; W * 8];
        let (n, last) = r.copy_out(from, &mut out);
        let recs: Vec<(u64, String)> = syscall::kernel_log_records(&out[..n])
            .map(|rec| (rec.seq, String::from_utf8(rec.text.to_vec()).unwrap()))
            .collect();
        assert_eq!(recs.last().map_or(0, |r| r.0), last);
        recs
    }

    // Defect guarded: sequence numbers that skip or restart, or a record's
    // text, time or level not read back as written.
    #[test]
    fn records_read_back_in_order_with_their_fields()
    {
        let r = Ring::<SMALL>::new();
        assert_eq!(r.newest_seq(), 0);
        assert_eq!(append(&r, "one"), 1);
        assert_eq!(append(&r, "two words"), 2);
        assert_eq!(
            records(&r, 0),
            vec![(1, "one".into()), (2, "two words".into())]
        );
        assert_eq!(records(&r, 2), vec![(2, "two words".into())]);
        let mut text = [0u8; KLOG_LINE_MAX];
        let (tail, _) = r.bounds();
        let m = r.read_unlocked(tail, Some(1), &mut text).unwrap();
        assert_eq!((m.seq, m.us, m.level, m.flags, m.len), (1, 7, 6, 0, 3));
    }

    // Defect guarded: a full ring that overwrites a record it still needs,
    // or keeps one it dropped, so the gap a reader sees is wrong.
    #[test]
    fn a_full_ring_drops_the_oldest_and_the_reader_sees_the_gap()
    {
        let r = Ring::<SMALL>::new();
        let line = "x".repeat(100);
        for _ in 0..40
        {
            append(&r, &line);
        }
        let recs = records(&r, 1);
        let first = recs.first().unwrap().0;
        assert!(first > 1, "the oldest records were dropped");
        assert_eq!(recs.last().unwrap().0, 40);
        for (i, (seq, text)) in recs.iter().enumerate()
        {
            assert_eq!(*seq, first + i as u64);
            assert_eq!(text, &line);
        }
        // Before each append, room for a record of the longest line was made:
        // the live records and that room, less the last record, fit.
        let (tail, head) = r.bounds();
        assert!(head - tail + RECORD_MAX - record_bytes(line.len()) <= (SMALL * 8) as u64);
    }

    // Defect guarded: a line past the limit written past the record, or cut
    // inside a character so the text is not UTF-8.
    #[test]
    fn a_long_line_is_cut_at_a_character_boundary_and_flagged()
    {
        let r = Ring::<SMALL>::new();
        let mut w = r.begin();
        w.write_str(&"a".repeat(KLOG_LINE_MAX - 1)).unwrap();
        w.write_str("étail").unwrap();
        r.commit(w, 0, 6);
        let mut text = [0u8; KLOG_LINE_MAX];
        let (tail, _) = r.bounds();
        let m = r.read_unlocked(tail, None, &mut text).unwrap();
        assert_eq!(m.len, KLOG_LINE_MAX - 1);
        assert_eq!(m.flags, KLOG_FLAG_TRUNCATED);
        core::str::from_utf8(&text[..m.len]).unwrap();
    }

    // Defect guarded: a lock-free reader that took a record's sequence number
    // and copied its text while the appender overwrote it at the same offset
    // (a seqlock with no invalidation of the overwritten record) accepting
    // the torn text. Every point at which the appender's steps can fall
    // between the reader's two sequence reads is driven here.
    #[test]
    fn a_reader_never_accepts_a_record_overwritten_under_it()
    {
        for steps in 1..=3
        {
            let r = Ring::<SMALL>::new();
            let old = "o".repeat(KLOG_LINE_MAX);
            append(&r, &old);
            append(&r, &old);
            let (pos, _) = r.bounds();
            let s1 = r.word(pos).load(Ordering::Acquire);
            // The appender's steps between the reader's first sequence read
            // and its second: invalidate (begin), write the text, commit.
            let mut w = r.begin();
            if steps >= 2
            {
                w.write_str(&"n".repeat(KLOG_LINE_MAX)).unwrap();
            }
            if steps >= 3
            {
                r.commit(w, 0, 6);
            }
            let s2 = r.word(pos).load(Ordering::Relaxed);
            assert_ne!(
                s1, s2,
                "steps={steps}: the overwritten record still validates"
            );
            let mut text = [0u8; KLOG_LINE_MAX];
            assert!(
                r.read_unlocked(pos, Some(1), &mut text).is_none(),
                "steps={steps}"
            );
        }
    }

    /// The text the stress test's appenders write for record `seq`: its
    /// number, then a letter chosen by it, at a length chosen by it, so a
    /// reader can check a record's every byte against its sequence number.
    fn stress_text(seq: u64) -> String
    {
        let fill = usize::try_from(seq.wrapping_mul(37)).unwrap() % (KLOG_LINE_MAX - 16);
        let letter = char::from(b'a' + u8::try_from(seq % 26).unwrap());
        format!("{seq}:{}", letter.to_string().repeat(fill))
    }

    // Defect guarded: a lock-free read that accepts a record an appender on
    // another thread is overwriting, or has overwritten, under it (a torn
    // text, a header from one record and text from another, or a stale
    // length). Two appenders take a lock around each append, as the kernel's
    // `KLOG_LOCK` does, on the smallest ring, so nearly every append
    // overwrites a record; a reader walks the ring without the lock, as the
    // flush does, until both have finished, and checks every record it accepts
    // against what was written for its sequence number. The run is bounded by
    // the record count, not by time.
    #[test]
    fn concurrent_appends_never_give_the_lock_free_reader_a_torn_record()
    {
        const APPENDERS: usize = 2;
        const PER_APPENDER: u64 = 20_000;
        let r = Ring::<SMALL>::new();
        let lock = std::sync::Mutex::new(());
        let done = std::sync::atomic::AtomicUsize::new(0);
        let accepted = std::thread::scope(|s| {
            for _ in 0..APPENDERS
            {
                s.spawn(|| {
                    for _ in 0..PER_APPENDER
                    {
                        let _held = lock.lock().unwrap();
                        let seq = r.newest_seq() + 1;
                        let mut w = r.begin();
                        w.write_str(&stress_text(seq)).unwrap();
                        assert_eq!(r.commit(w, seq, 6), seq);
                    }
                    done.fetch_add(1, Ordering::Release);
                });
            }
            let reader = s.spawn(|| {
                let mut accepted = 0u64;
                let mut text = [0u8; KLOG_LINE_MAX];
                loop
                {
                    let finished = done.load(Ordering::Acquire) == APPENDERS;
                    let (mut pos, head) = r.bounds();
                    let mut expect = None;
                    while pos < head
                    {
                        let Some(m) = r.read_unlocked(pos, expect, &mut text)
                        else
                        {
                            break;
                        };
                        let want = stress_text(m.seq);
                        assert_eq!(m.len, want.len(), "seq {}: length", m.seq);
                        assert_eq!(&text[..m.len], want.as_bytes(), "seq {}: text", m.seq);
                        assert_eq!(m.us, m.seq, "seq {}: time", m.seq);
                        accepted += 1;
                        expect = Some(m.seq + 1);
                        pos += record_bytes(m.len);
                    }
                    if finished
                    {
                        return accepted;
                    }
                }
            });
            reader.join().unwrap()
        });
        assert_eq!(
            r.newest_seq(),
            PER_APPENDER * u64::try_from(APPENDERS).unwrap()
        );
        assert!(accepted > 0, "the reader accepted no record");
    }

    // Defect guarded: a header found in a text word (a short text whose word
    // reads as a small number), so a walk takes text for a record.
    #[test]
    fn a_text_word_never_reads_as_a_header()
    {
        let r = Ring::<SMALL>::new();
        append(&r, "");
        let (pos, _) = r.bounds();
        let mut text = [0u8; KLOG_LINE_MAX];
        assert!(
            r.read_unlocked(pos + KLOG_HEADER_BYTES as u64, None, &mut text)
                .is_none()
        );
    }

    // Defect guarded: a committed mark that moves back, or past the newest
    // record, under a reader's acknowledgement.
    #[test]
    fn the_committed_mark_only_grows_and_never_past_the_newest()
    {
        let mut c = Cursor::default();
        assert_eq!(c.start_seq(0), 1);
        c.on_read(5, 0, 3, 10);
        assert!(c.attached);
        assert_eq!(c.committed, 3);
        c.on_read(2, 0, 9, 11);
        assert_eq!(c.committed, 3);
        c.on_read(u64::MAX, 9, 9, 12);
        assert_eq!(c.committed, 9);
        assert_eq!(c.start_seq(0), 10);
        assert_eq!(c.start_seq(4), 4);
    }

    // Defect guarded: a read whose acknowledgement is applied after its start
    // is chosen, so a reader asking for the records after the committed mark
    // gets again the ones it has just acknowledged.
    #[test]
    fn an_acknowledgement_moves_the_start_of_the_same_read()
    {
        let mut c = Cursor::default();
        c.on_read(0, 4, 4, 10);
        assert_eq!(c.start_seq(0), 1);
        c.acknowledge(4, 6);
        assert!(c.attached, "an acknowledgement leaves the attach as it is");
        assert_eq!(c.start_seq(0), 5);
        c.acknowledge(9, 6);
        assert_eq!(c.start_seq(0), 7, "never past the newest");
        assert_eq!(c.start_seq(3), 3, "an explicit start is the reader's");
    }

    // Defect guarded: a reader taken as stalled while it keeps up, or with no
    // unread record, so the kernel goes back to direct writes for no reason.
    #[test]
    fn a_reader_stalls_only_with_unread_records_past_the_bound()
    {
        let mut c = Cursor::default();
        assert!(!c.stalled(5, 10_000_000, 1_000_000), "not attached");
        c.on_read(0, 5, 5, 1_000_000);
        assert!(!c.stalled(5, 9_000_000, 1_000_000), "nothing unread");
        c.on_append(6, 1_500_000);
        assert!(!c.stalled(6, 2_500_000, 1_000_000), "within the bound");
        assert!(c.stalled(6, 2_500_001, 1_000_000));
    }

    // Defect guarded: the bound measured from the reader's last read, so the
    // first record after a quiet period longer than the bound is taken as a
    // stall on the tick that signals the reader, before it could read.
    #[test]
    fn the_first_record_after_a_quiet_period_is_not_a_stall()
    {
        let mut c = Cursor::default();
        c.on_read(0, 5, 5, 1_000_000);
        c.on_append(6, 11_000_000);
        c.on_append(7, 11_200_000);
        assert!(!c.stalled(7, 11_010_000, 1_000_000), "the next tick");
        assert!(!c.stalled(7, 12_000_000, 1_000_000), "at the bound");
        assert!(
            c.stalled(7, 12_000_001, 1_000_000),
            "the oldest unread is past it"
        );
    }

    // Defect guarded: a read that returns nothing new (an acknowledgement
    // alone, or a read that starts past the unread records) taken as progress,
    // so a reader that never reads its records again is never detached.
    #[test]
    fn a_read_that_returns_nothing_new_leaves_the_bound_running()
    {
        let mut c = Cursor::default();
        c.on_read(0, 5, 5, 1_000_000);
        c.on_append(6, 2_000_000);
        c.on_read(5, 0, 6, 2_800_000);
        c.on_read(5, 5, 6, 2_900_000);
        assert!(c.stalled(6, 3_000_001, 1_000_000));
        // A read that returns a new record starts the bound again, though
        // records stay unread after it.
        c.on_append(7, 3_100_000);
        c.on_read(5, 6, 7, 3_200_000);
        assert!(!c.stalled(7, 4_200_000, 1_000_000), "a new record read");
        assert!(c.stalled(7, 4_200_001, 1_000_000));
    }

    // Defect guarded: a reader that attaches again after a stall, with the
    // records of the gap still unread, detached again on the next tick.
    #[test]
    fn an_attach_starts_the_bound_again()
    {
        let mut c = Cursor::default();
        c.on_read(0, 5, 5, 1_000_000);
        c.on_append(6, 2_000_000);
        assert!(c.stalled(6, 3_000_001, 1_000_000));
        c.attached = false;
        c.on_read(5, 0, 6, 9_000_000);
        assert!(c.attached);
        assert!(
            !c.stalled(6, 10_000_000, 1_000_000),
            "within the bound of the attach"
        );
        assert!(c.stalled(6, 10_000_001, 1_000_000));
    }
}
