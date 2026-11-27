// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/sink.rs

//! logd's queue of rendered lines for one output driver, and the rule that
//! decides when a line offered to a full queue waits and when it is dropped.
//!
//! Each of logd's output drivers (the serial driver, the framebuffer driver)
//! has one writer thread, the only thread that calls the driver on the steady
//! path, and a [`SinkQueue`] between it and every thread that renders a line.
//! A line's producer waits, for at most logd's stall bound, until the writer
//! has written its line, or for space when the queue is full, so a sink whose
//! driver answers shows a line before its sender's log call returns, as a
//! synchronous write would; a producer that waits out the bound stalls the
//! sink, as does a write the writer gives up. While it is stalled, producers
//! wait for nothing: a line is queued when it fits and dropped, counted, when
//! it does not, until the writer next completes a write. The count travels with the queue, so the writer reports
//! it at the point in the stream where the lines went missing. A sink with no
//! driver to write to is unserved: its producers wait for nothing, as for a
//! stalled one, and the writer holds the queued lines, and the count of those
//! that did not fit, for the driver resolved next
//! ([`SinkQueue::offer_unserved`]).
//! See `services/logd/docs/ipc-interface.md` § Output sinks.

/// Bytes of each of logd's output drivers' queues: how much rendered output
/// waits for a driver that is slow or stopped. A tuning value, not a ceiling:
/// a full queue holds a line's producer while its writer makes progress, and
/// drops and counts lines only once the sink is stalled ([`SINK_STALL_MS`]);
/// every line is retained in its sender's history whatever its sinks do.
/// logd's queues are static, so their memory is fixed at startup
/// (docs/limits.md § init and logd).
pub const SINK_QUEUE_BYTES: usize = 16 * 1024;

/// The bound, in milliseconds, on what an output driver that does not answer
/// costs any of logd's threads but its own writer: the longest a line's
/// producer waits on one sink for its line to be queued and written, after
/// which a sink that has not written it is stalled ([`SinkQueue::stall`]);
/// the bound on the whole inline write of a line to a sink with no writer,
/// its wait for its turn included; and the bound on each call of logd's
/// panic sink. Long enough
/// that a driver merely slowed by load completes the lines queued ahead within
/// it; short enough that both sinks stopped together hold a sender's log call
/// for less than half its own bound (`log::LOG_CALL_TIMEOUT_MS`, 5000).
pub const SINK_STALL_MS: u32 = 1000;

/// Bytes of the header each queued line carries: its length (`u16`), the
/// count of lines dropped just before it was queued (`u32`), and its
/// [`LineKind`] (`u8`).
pub const HEADER_BYTES: usize = 7;

/// The longest line a [`SinkQueue`] takes: its header's length field.
pub const LINE_MAX_BYTES: usize = u16::MAX as usize;

/// What [`SinkQueue::offer`] did with a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offer
{
    /// The line is queued for the writer, as the sink's line number `.0`
    /// ([`SinkQueue::is_written`]).
    Queued(u64),
    /// The queue is full and the sink is not stalled: the producer waits for
    /// the writer to free space, then offers the line again.
    Wait,
    /// The line is dropped and counted: the sink is stalled, or the producer
    /// waited out the stall bound, which stalls it.
    Dropped,
}

/// What a queued line is, which decides whether the writer counts it as
/// dropped when it gives its write up ([`SinkQueue::not_written`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind
{
    /// A line a sender logged, or one of logd's own: counted when given up.
    Logged,
    /// logd's other sink's drop line, naming lines that sink did not write:
    /// not counted when given up, so two sinks whose drivers both refuse do
    /// not count and report each other's drop lines without end.
    PeerDrops,
}

impl LineKind
{
    const fn to_byte(self) -> u8
    {
        match self
        {
            Self::Logged => 0,
            Self::PeerDrops => 1,
        }
    }

    const fn from_byte(byte: u8) -> Self
    {
        if byte == 1
        {
            Self::PeerDrops
        }
        else
        {
            Self::Logged
        }
    }
}

/// One line taken from a [`SinkQueue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Popped
{
    /// Bytes of the line copied out.
    pub len: usize,
    /// Lines dropped just before this one was queued, and lines the writer
    /// gave up since it took the line before ([`SinkQueue::not_written`]),
    /// for the writer to report ahead of it.
    pub dropped_before: u32,
    /// What the line is.
    pub kind: LineKind,
}

/// A FIFO of whole lines in a fixed `N`-byte ring, each behind a
/// [`HEADER_BYTES`] header, with the sink's drop count, stall mark, and the
/// numbers of the lines queued and written.
///
/// A line is queued whole or not at all. Lines dropped since the last queued
/// one are counted at the tail and attached to the next line queued
/// ([`Popped::dropped_before`]); lines the writer gave up are counted at the
/// head and reported ahead of the next line it takes; the writer takes a count
/// still at the tail or the head once it has written every queued line
/// ([`Self::take_tail_drops`]).
pub struct SinkQueue<const N: usize>
{
    buf: [u8; N],
    /// Offset of the oldest queued byte.
    head: usize,
    /// Bytes queued, headers included.
    used: usize,
    /// Lines dropped since the last one queued.
    dropped: u32,
    /// Lines the writer gave up since it last took one: they went missing
    /// ahead of every queued line.
    given_up: u32,
    /// Set when a producer waits out the stall bound, or the writer gives a
    /// write up ([`Self::not_written`]); cleared when the writer completes a
    /// write ([`Self::written`]).
    stalled: bool,
    /// Lines queued since the queue was made: the number of the last one.
    queued: u64,
    /// Lines the writer has taken ([`Self::pop`]).
    taken: u64,
    /// Lines the writer is done with: every line taken before its last
    /// completed write ([`Self::written`]) or its last write it gave up
    /// ([`Self::not_written`]).
    done: u64,
}

impl<const N: usize> SinkQueue<N>
{
    /// An empty queue of a sink that is not stalled.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            buf: [0u8; N],
            head: 0,
            used: 0,
            dropped: 0,
            given_up: 0,
            stalled: false,
            queued: 0,
            taken: 0,
            done: 0,
        }
    }

    /// Whether no line is queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.used == 0
    }

    /// Whether the sink is stalled ([`Self::offer`]).
    #[must_use]
    pub const fn is_stalled(&self) -> bool
    {
        self.stalled
    }

    /// Offer `line`, of `kind`, to the queue. Queued when it fits; otherwise
    /// [`Offer::Wait`] while the sink is not stalled and `waited_out` is
    /// false, and [`Offer::Dropped`], counted, when the sink is stalled or the
    /// producer has waited out the stall bound (`waited_out`), which stalls
    /// the sink. A line longer than [`LINE_MAX_BYTES`] or than the ring less
    /// one header never fits, and is dropped without waiting.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`waited_out` is the outcome of the producer's bounded wait, which the queue \
                  records as the sink's stall mark"
    )]
    pub fn offer(&mut self, line: &[u8], kind: LineKind, waited_out: bool) -> Offer
    {
        let need = HEADER_BYTES.saturating_add(line.len());
        if line.len() > LINE_MAX_BYTES || need > N
        {
            self.dropped = self.dropped.saturating_add(1);
            return Offer::Dropped;
        }
        if need <= N.saturating_sub(self.used)
        {
            self.push(line, kind);
            self.queued = self.queued.wrapping_add(1);
            return Offer::Queued(self.queued);
        }
        if waited_out
        {
            self.stalled = true;
        }
        if self.stalled
        {
            self.dropped = self.dropped.saturating_add(1);
            return Offer::Dropped;
        }
        Offer::Wait
    }

    /// Offer `line`, of `kind`, to the queue of a sink that has no driver to
    /// write to: queued when it fits, and otherwise dropped and counted at
    /// once, which stalls the sink, as for a producer that waited out the stall
    /// bound ([`Self::offer`]); never [`Offer::Wait`], since no writer frees
    /// space until a driver is resolved. The writer writes the queued lines and
    /// the count to that driver, and its first completed write ends the stall
    /// ([`Self::written`]).
    pub fn offer_unserved(&mut self, line: &[u8], kind: LineKind) -> Offer
    {
        self.offer(line, kind, true)
    }

    /// Queue `line`, which fits, carrying the tail's drop count.
    fn push(&mut self, line: &[u8], kind: LineKind)
    {
        let mut header = [0u8; HEADER_BYTES];
        // `offer` admits no line longer than `LINE_MAX_BYTES`.
        let len = u16::try_from(line.len()).unwrap_or(u16::MAX);
        let [l0, l1, d0, d1, d2, d3, k] = &mut header;
        [*l0, *l1] = len.to_le_bytes();
        [*d0, *d1, *d2, *d3] = core::mem::take(&mut self.dropped).to_le_bytes();
        *k = kind.to_byte();
        let tail = Self::wrap(self.head, self.used);
        self.write_at(tail, &header);
        self.write_at(Self::wrap(tail, HEADER_BYTES), line);
        self.used = self
            .used
            .saturating_add(HEADER_BYTES.saturating_add(line.len()));
    }

    /// Take the oldest line into `out`, cut to `out`'s length, with the
    /// count of lines dropped just before it, the lines given up since the
    /// last pop among them; `None` when the queue is empty.
    pub fn pop(&mut self, out: &mut [u8]) -> Option<Popped>
    {
        if self.used == 0
        {
            return None;
        }
        let mut header = [0u8; HEADER_BYTES];
        self.read_at(self.head, &mut header);
        let [l0, l1, d0, d1, d2, d3, k] = header;
        let len = usize::from(u16::from_le_bytes([l0, l1]));
        let dropped_before = u32::from_le_bytes([d0, d1, d2, d3])
            .saturating_add(core::mem::take(&mut self.given_up));
        let copied = len.min(out.len());
        let body = Self::wrap(self.head, HEADER_BYTES);
        self.read_at(body, out.get_mut(..copied).unwrap_or_default());
        let size = HEADER_BYTES.saturating_add(len);
        self.head = Self::wrap(self.head, size);
        self.used = self.used.saturating_sub(size);
        self.taken = self.taken.wrapping_add(1);
        Some(Popped {
            len: copied,
            dropped_before,
            kind: LineKind::from_byte(k),
        })
    }

    /// The count of lines dropped after every queued line, and of lines
    /// given up, taken once the queue is empty (0 while a line is queued,
    /// which will carry them).
    pub fn take_tail_drops(&mut self) -> u32
    {
        if self.used == 0
        {
            core::mem::take(&mut self.dropped).saturating_add(core::mem::take(&mut self.given_up))
        }
        else
        {
            0
        }
    }

    /// The writer completed a write: every line it has taken is written, and
    /// the driver answers, so the sink is not stalled.
    pub fn written(&mut self)
    {
        self.done = self.taken;
        self.stalled = false;
    }

    /// The writer gave up a write: the driver did not take all of it, or took
    /// it but did not complete it. No producer waits any longer for a line
    /// the writer has taken, and `lost` lines, those of the write the driver
    /// did not take, are counted as dropped where they went missing: ahead of
    /// the next line the writer takes ([`Popped::dropped_before`]), or at
    /// the tail once none is queued. The sink is stalled, as when a producer
    /// waits out the stall bound, since the driver did not complete the write:
    /// only a completed write ([`Self::written`]) shows that it takes lines
    /// again.
    pub fn not_written(&mut self, lost: u32)
    {
        self.done = self.taken;
        self.given_up = self.given_up.saturating_add(lost);
        self.stalled = true;
    }

    /// Whether line number `line` ([`Offer::Queued`]) is written, or given
    /// up ([`Self::not_written`]).
    #[must_use]
    pub const fn is_written(&self, line: u64) -> bool
    {
        // Numbers wrap after 2^64 lines; the distance stays below 2^63.
        self.done.wrapping_sub(line) < 1 << 63
    }

    /// The number of the last line queued, 0 before the first: the token of a
    /// flush started now (`services/logd/docs/ipc-interface.md` § Flush
    /// barrier).
    #[must_use]
    pub const fn last_queued(&self) -> u64
    {
        self.queued
    }

    /// The lines numbered up to `token` ([`Self::last_queued`]) that the
    /// writer is still to write: 0 once it has written or given up line
    /// `token`, while the sink is stalled, and for a token above every number
    /// this queue has issued, which only another queue can have issued (that
    /// of a logd instance that has since restarted).
    #[must_use]
    pub const fn unwritten_through(&self, token: u64) -> u64
    {
        // Numbers wrap after 2^64 lines; the distance stays below 2^63.
        if self.stalled || self.is_written(token) || self.queued.wrapping_sub(token) >= 1 << 63
        {
            0
        }
        else
        {
            token.wrapping_sub(self.done)
        }
    }

    /// A producer waited out the stall bound for its line's write: the sink
    /// is stalled until the writer next completes a write.
    pub fn stall(&mut self)
    {
        self.stalled = true;
    }

    /// The ring offset `by` bytes past `off`, for `off < N` and `by <= N`.
    fn wrap(off: usize, by: usize) -> usize
    {
        let to_end = N.saturating_sub(off);
        if by < to_end
        {
            off.saturating_add(by)
        }
        else
        {
            by.saturating_sub(to_end)
        }
    }

    /// Copy `bytes` into the ring from `off`, wrapping at the end.
    fn write_at(&mut self, off: usize, bytes: &[u8])
    {
        let (front, back) = self.buf.split_at_mut(off.min(N));
        for (dst, src) in back.iter_mut().chain(front.iter_mut()).zip(bytes)
        {
            *dst = *src;
        }
    }

    /// Fill `out` from the ring at `off`, wrapping at the end.
    fn read_at(&self, off: usize, out: &mut [u8])
    {
        let (front, back) = self.buf.split_at(off.min(N));
        for (dst, src) in out.iter_mut().zip(back.iter().chain(front))
        {
            *dst = *src;
        }
    }
}

/// Whether a write the writer started at `started_us` (`None` while it
/// writes nothing) has run past [`SINK_STALL_MS`] at `now_us`, on one
/// microsecond clock: the writer is then stalled in it, and a flush waits on
/// the sink for nothing.
#[must_use]
pub const fn write_overdue(started_us: Option<u64>, now_us: u64) -> bool
{
    match started_us
    {
        Some(start) => now_us.saturating_sub(start) > SINK_STALL_MS as u64 * 1000,
        None => false,
    }
}

/// The retry hint, in milliseconds, of a flush that waits on `lines` lines of
/// a sink whose writer took `line_us` microseconds for its last line: their
/// expected time, rounded up, at least 1 ms, so a waiter does not ask again
/// at once, and at most [`SINK_STALL_MS`], after which a writer that has not
/// finished is stalled and the flush answers at once.
#[must_use]
pub fn flush_hint_ms(lines: u64, line_us: u64) -> u32
{
    let ms = lines.saturating_mul(line_us).div_ceil(1000);
    u32::try_from(ms.clamp(1, u64::from(SINK_STALL_MS))).unwrap_or(SINK_STALL_MS)
}

impl<const N: usize> Default for SinkQueue<N>
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

    /// Pop every queued line as (bytes, dropped before it).
    fn drain<const N: usize>(q: &mut SinkQueue<N>) -> Vec<(Vec<u8>, u32)>
    {
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        while let Some(p) = q.pop(&mut buf)
        {
            out.push((buf[..p.len].to_vec(), p.dropped_before));
        }
        out
    }

    // Defect caught: lines written to a sink out of the order logd rendered
    // them, or cut, or a line split across the ring's end read back wrong.
    #[test]
    fn lines_come_out_whole_and_in_order_across_the_ring_end()
    {
        // Two lines of 4 bytes and their headers fit, with 5 bytes to spare,
        // so the third and later lines wrap the end.
        let mut q: SinkQueue<{ 2 * (HEADER_BYTES + 4) + 5 }> = SinkQueue::new();
        let mut buf = [0u8; 8];
        for i in 0u8..20
        {
            let line = [i, i.wrapping_add(1), i.wrapping_add(2), i.wrapping_add(3)];
            assert!(matches!(
                q.offer(&line, LineKind::Logged, false),
                Offer::Queued(_)
            ));
            let p = q.pop(&mut buf).unwrap();
            assert_eq!((&buf[..p.len], p.dropped_before), (&line[..], 0));
        }
        assert!(q.is_empty());
        assert_eq!(q.pop(&mut buf), None);
    }

    // Defect caught: a write the driver refused (the serial driver's
    // `STALLED` on a wedged UART) taken as written, which loses the line
    // uncounted and ends the stall, so every later line holds its producer
    // for the bound again; or its count reported behind the lines queued
    // after it rather than where it went missing.
    #[test]
    fn a_write_given_up_counts_its_line_ahead_of_the_next_and_leaves_the_stall()
    {
        let mut q: SinkQueue<64> = SinkQueue::new();
        let Offer::Queued(first) = q.offer(b"line", LineKind::Logged, false)
        else
        {
            panic!("an empty queue takes a line");
        };
        assert!(matches!(
            q.offer(b"next", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        assert!(!q.is_stalled());
        q.not_written(1);
        assert!(q.is_written(first), "no producer waits on a write given up");
        assert!(
            q.is_stalled(),
            "no later line holds its producer for the bound"
        );
        // A line queued after the one given up carries none of its count.
        assert!(matches!(
            q.offer(b"late", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(q.take_tail_drops(), 0, "a queued line carries the count");
        assert_eq!(
            drain(&mut q),
            [(b"next".to_vec(), 1), (b"late".to_vec(), 0)],
            "the count comes out where the line went missing"
        );
        // With nothing queued, the count is taken at the tail.
        q.not_written(1);
        assert_eq!(q.take_tail_drops(), 1);
        // A write given up that lost no line counts nothing.
        q.not_written(0);
        assert_eq!(q.take_tail_drops(), 0);
        assert!(q.is_stalled());
        // The next completed write ends the stall.
        q.written();
        assert!(!q.is_stalled());
    }

    // Defect caught: the other sink's drop line queued as an ordinary line,
    // so a writer that gives it up counts it and reports it back without end.
    #[test]
    fn a_line_keeps_its_kind_through_the_queue()
    {
        let mut q: SinkQueue<64> = SinkQueue::new();
        assert!(matches!(
            q.offer(b"peer", LineKind::PeerDrops, false),
            Offer::Queued(_)
        ));
        assert!(matches!(
            q.offer_unserved(b"own", LineKind::Logged),
            Offer::Queued(_)
        ));
        let mut buf = [0u8; 8];
        assert_eq!(q.pop(&mut buf).unwrap().kind, LineKind::PeerDrops);
        assert_eq!(q.pop(&mut buf).unwrap().kind, LineKind::Logged);
    }

    // Defect caught: a full queue that drops a line while the writer still
    // makes progress (serial output lost under mere load), or that overwrites
    // a queued line.
    #[test]
    fn a_full_queue_makes_the_producer_wait_until_the_writer_frees_space()
    {
        let mut q: SinkQueue<{ 2 * (HEADER_BYTES + 4) }> = SinkQueue::new();
        assert!(matches!(
            q.offer(b"aaaa", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert!(matches!(
            q.offer(b"bbbb", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(q.offer(b"cccc", LineKind::Logged, false), Offer::Wait);
        assert!(!q.is_stalled());
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        assert!(matches!(
            q.offer(b"cccc", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(
            drain(&mut q),
            [(b"bbbb".to_vec(), 0), (b"cccc".to_vec(), 0)]
        );
    }

    // Defect caught: a stopped driver holding every producer for the bound on
    // every line, or a stall that outlives the driver's next answer.
    #[test]
    fn a_waited_out_bound_stalls_the_sink_until_the_writer_next_writes()
    {
        let mut q: SinkQueue<{ 2 * (HEADER_BYTES + 4) }> = SinkQueue::new();
        assert!(matches!(
            q.offer(b"aaaa", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert!(matches!(
            q.offer(b"bbbb", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(q.offer(b"cccc", LineKind::Logged, true), Offer::Dropped);
        assert!(q.is_stalled());
        // Stalled: a full queue drops at once, without a wait.
        assert_eq!(q.offer(b"dddd", LineKind::Logged, false), Offer::Dropped);
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        // Space alone does not end the stall's drops of lines that fit: they
        // are queued, since the ring has room.
        assert!(matches!(
            q.offer(b"eeee", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(q.offer(b"ffff", LineKind::Logged, false), Offer::Dropped);
        q.written();
        assert!(!q.is_stalled());
        assert_eq!(q.offer(b"gggg", LineKind::Logged, false), Offer::Wait);
    }

    // Defect caught: lines dropped from a sink without a count, a count
    // reported twice, or reported at the wrong point in the stream.
    #[test]
    fn drops_are_reported_before_the_next_queued_line_or_at_the_tail()
    {
        let mut q: SinkQueue<{ 2 * (HEADER_BYTES + 4) }> = SinkQueue::new();
        assert!(matches!(
            q.offer(b"aaaa", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert!(matches!(
            q.offer(b"bbbb", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(q.offer(b"xxxx", LineKind::Logged, true), Offer::Dropped);
        assert_eq!(q.offer(b"yyyy", LineKind::Logged, false), Offer::Dropped);
        // Two lines queued: the tail's count is not taken yet.
        assert_eq!(q.take_tail_drops(), 0);
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        assert!(matches!(
            q.offer(b"cccc", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(q.offer(b"zzzz", LineKind::Logged, false), Offer::Dropped);
        assert_eq!(
            drain(&mut q),
            [(b"bbbb".to_vec(), 0), (b"cccc".to_vec(), 2)]
        );
        assert_eq!(q.take_tail_drops(), 1);
        assert_eq!(q.take_tail_drops(), 0);
    }

    // Defect caught: a sink with no driver dropping every line, so a driver
    // resolved late (one whose start failed once, a restarted one) is written
    // nothing from before it, or holding a producer for the stall bound on
    // each line while no writer can free space.
    #[test]
    fn an_unserved_sink_queues_without_a_wait_and_counts_the_overflow()
    {
        let mut q: SinkQueue<{ 2 * (HEADER_BYTES + 4) }> = SinkQueue::new();
        assert!(matches!(
            q.offer_unserved(b"aaaa", LineKind::Logged),
            Offer::Queued(_)
        ));
        assert!(!q.is_stalled());
        assert!(matches!(
            q.offer_unserved(b"bbbb", LineKind::Logged),
            Offer::Queued(_)
        ));
        assert_eq!(q.offer_unserved(b"cccc", LineKind::Logged), Offer::Dropped);
        assert_eq!(q.offer_unserved(b"dddd", LineKind::Logged), Offer::Dropped);
        assert!(q.is_stalled());
        // A driver is resolved: the writer takes the held lines in order, and
        // its first completed write ends the stall, so a served sink's
        // producers wait again.
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        q.written();
        assert!(!q.is_stalled());
        assert!(matches!(
            q.offer(b"eeee", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(
            drain(&mut q),
            [(b"bbbb".to_vec(), 0), (b"eeee".to_vec(), 2)]
        );
        assert_eq!(q.take_tail_drops(), 0);
    }

    // Defect caught: a line the ring can never hold making its producer wait
    // for space that will never be enough.
    #[test]
    fn a_line_longer_than_the_ring_is_dropped_without_a_wait()
    {
        let mut q: SinkQueue<{ HEADER_BYTES + 10 }> = SinkQueue::new();
        assert_eq!(q.offer(&[0u8; 11], LineKind::Logged, false), Offer::Dropped);
        assert!(!q.is_stalled());
        assert!(matches!(
            q.offer(&[0u8; 10], LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert_eq!(q.take_tail_drops(), 0);
        assert_eq!(drain(&mut q), [(vec![0u8; 10], 1)]);
    }

    // Defect caught: a producer released before the writer has written its
    // line (a sender's line missing from the console when its log call
    // returns), or held after it; a stall that outlives the writer's next
    // completed write.
    #[test]
    fn a_line_is_written_once_the_writer_completes_a_write_after_taking_it()
    {
        let mut q: SinkQueue<64> = SinkQueue::new();
        let Offer::Queued(first) = q.offer(b"aaaa", LineKind::Logged, false)
        else
        {
            panic!("not queued");
        };
        let Offer::Queued(second) = q.offer(b"bbbb", LineKind::Logged, false)
        else
        {
            panic!("not queued");
        };
        assert!(!q.is_written(first));
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        // Taken, but its write has not completed.
        assert!(!q.is_written(first));
        q.stall();
        assert!(q.is_stalled());
        q.written();
        assert!(q.is_written(first));
        assert!(!q.is_written(second));
        assert!(!q.is_stalled());
        q.pop(&mut buf).unwrap();
        q.written();
        assert!(q.is_written(second));
    }

    // Defect caught: a pop into a short buffer overrunning it or losing the
    // next line's framing.
    #[test]
    fn a_pop_into_a_short_buffer_cuts_the_line_and_keeps_the_next()
    {
        let mut q: SinkQueue<32> = SinkQueue::new();
        assert!(matches!(
            q.offer(b"abcdef", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        assert!(matches!(
            q.offer(b"gh", LineKind::Logged, false),
            Offer::Queued(_)
        ));
        let mut short = [0u8; 3];
        let p = q.pop(&mut short).unwrap();
        assert_eq!(&short[..p.len], b"abc");
        assert_eq!(drain(&mut q), [(b"gh".to_vec(), 0)]);
    }

    // Defect caught: a flush answered flushed while a line queued before it
    // was still unwritten, or held on a line queued after it.
    #[test]
    fn a_flush_waits_for_the_lines_queued_before_it_alone()
    {
        let mut q: SinkQueue<{ 4 * (HEADER_BYTES + 4) }> = SinkQueue::new();
        // Nothing queued: token 0, flushed.
        assert_eq!(q.last_queued(), 0);
        assert_eq!(q.unwritten_through(0), 0);
        for _ in 0..2
        {
            assert!(matches!(
                q.offer(b"line", LineKind::Logged, false),
                Offer::Queued(_)
            ));
        }
        let token = q.last_queued();
        assert_eq!(token, 2);
        assert_eq!(q.unwritten_through(token), 2);
        // A line queued after the token is not waited for.
        assert!(matches!(
            q.offer(b"late", LineKind::Logged, false),
            Offer::Queued(3)
        ));
        let mut buf = [0u8; 8];
        assert!(q.pop(&mut buf).is_some());
        // Taken is not written: the write may still fail to leave the device.
        assert_eq!(q.unwritten_through(token), 2);
        q.written();
        assert_eq!(q.unwritten_through(token), 1);
        assert!(q.pop(&mut buf).is_some());
        q.written();
        assert_eq!(q.unwritten_through(token), 0);
        assert_eq!(q.unwritten_through(3), 1);
    }

    // Defect caught: a flush that waits on a sink whose writer gave up a
    // line, or that is stalled, until its caller's bound.
    #[test]
    fn a_flush_does_not_wait_on_a_stalled_sink_or_a_line_given_up()
    {
        let mut q: SinkQueue<{ 4 * (HEADER_BYTES + 4) }> = SinkQueue::new();
        let _ = q.offer(b"one", LineKind::Logged, false);
        let _ = q.offer(b"two", LineKind::Logged, false);
        let token = q.last_queued();
        q.stall();
        assert_eq!(q.unwritten_through(token), 0, "stalled");
        let mut buf = [0u8; 8];
        assert!(q.pop(&mut buf).is_some());
        q.written();
        assert_eq!(q.unwritten_through(token), 1, "the stall ends with a write");
        assert!(q.pop(&mut buf).is_some());
        q.not_written(1);
        assert!(q.is_stalled());
        q.written();
        assert_eq!(q.unwritten_through(token), 0, "given up counts as done");
    }

    // Defect caught: a token from a logd instance before its restart, above
    // every number the new queue has issued, held its caller to its bound.
    #[test]
    fn a_token_this_queue_did_not_issue_is_flushed()
    {
        let mut q: SinkQueue<{ 4 * (HEADER_BYTES + 4) }> = SinkQueue::new();
        let _ = q.offer(b"one", LineKind::Logged, false);
        assert_eq!(q.unwritten_through(1), 1);
        assert_eq!(q.unwritten_through(2), 0);
        assert_eq!(q.unwritten_through(u64::MAX), 0);
    }

    #[test]
    fn a_write_is_overdue_only_past_the_stall_bound()
    {
        let bound_us = u64::from(SINK_STALL_MS) * 1000;
        assert!(!write_overdue(None, u64::MAX));
        assert!(!write_overdue(Some(5), 5 + bound_us));
        assert!(write_overdue(Some(5), 6 + bound_us));
        // A start after the reading (another thread's clock read) is not overdue.
        assert!(!write_overdue(Some(10), 5));
    }

    #[test]
    fn the_flush_hint_is_the_expected_time_within_its_clamp()
    {
        assert_eq!(flush_hint_ms(0, 500), 1);
        assert_eq!(flush_hint_ms(3, 0), 1);
        assert_eq!(flush_hint_ms(3, 400), 2);
        assert_eq!(flush_hint_ms(10, 2_000), 20);
        assert_eq!(flush_hint_ms(u64::MAX, u64::MAX), SINK_STALL_MS);
    }
}
