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
//! sink. While it is stalled, producers wait for nothing: a line is queued
//! when it fits and dropped, counted, when it does not, until the writer next
//! completes a write. The count travels with the queue, so the writer reports
//! it at the point in the stream where the lines went missing.
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
/// and the bound on each call logd makes to a driver outside its writer (its
/// panic sink, and the inline write of a sink with no writer). Long enough
/// that a driver merely slowed by load completes the lines queued ahead within
/// it; short enough that both sinks stopped together hold a sender's log call
/// for less than half its own bound (`log::LOG_CALL_TIMEOUT_MS`, 5000).
pub const SINK_STALL_MS: u32 = 1000;

/// Bytes of the header each queued line carries: its length (`u16`) and the
/// count of lines dropped just before it was queued (`u32`).
pub const HEADER_BYTES: usize = 6;

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

/// One line taken from a [`SinkQueue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Popped
{
    /// Bytes of the line copied out.
    pub len: usize,
    /// Lines dropped just before this one was queued, for the writer to
    /// report ahead of it.
    pub dropped_before: u32,
}

/// A FIFO of whole lines in a fixed `N`-byte ring, each behind a
/// [`HEADER_BYTES`] header, with the sink's drop count, stall mark, and the
/// numbers of the lines queued and written.
///
/// A line is queued whole or not at all. Lines dropped since the last queued
/// one are counted at the tail and attached to the next line queued
/// ([`Popped::dropped_before`]); the writer takes a count still at the tail
/// once it has written every queued line ([`Self::take_tail_drops`]).
pub struct SinkQueue<const N: usize>
{
    buf: [u8; N],
    /// Offset of the oldest queued byte.
    head: usize,
    /// Bytes queued, headers included.
    used: usize,
    /// Lines dropped since the last one queued.
    dropped: u32,
    /// Set when a producer waits out the stall bound; cleared when the writer
    /// completes a write ([`Self::written`]).
    stalled: bool,
    /// Lines queued since the queue was made: the number of the last one.
    queued: u64,
    /// Lines the writer has taken ([`Self::pop`]).
    taken: u64,
    /// Lines the writer has written: every line taken before its last
    /// completed write ([`Self::written`]).
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

    /// Offer `line` to the queue. Queued when it fits; otherwise
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
    pub fn offer(&mut self, line: &[u8], waited_out: bool) -> Offer
    {
        let need = HEADER_BYTES.saturating_add(line.len());
        if line.len() > LINE_MAX_BYTES || need > N
        {
            self.dropped = self.dropped.saturating_add(1);
            return Offer::Dropped;
        }
        if need <= N.saturating_sub(self.used)
        {
            self.push(line);
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

    /// Queue `line`, which fits, carrying the tail's drop count.
    fn push(&mut self, line: &[u8])
    {
        let mut header = [0u8; HEADER_BYTES];
        // `offer` admits no line longer than `LINE_MAX_BYTES`.
        let len = u16::try_from(line.len()).unwrap_or(u16::MAX);
        let (len_bytes, drop_bytes) = header.split_at_mut(2);
        len_bytes.copy_from_slice(&len.to_le_bytes());
        drop_bytes.copy_from_slice(&core::mem::take(&mut self.dropped).to_le_bytes());
        let tail = Self::wrap(self.head, self.used);
        self.write_at(tail, &header);
        self.write_at(Self::wrap(tail, HEADER_BYTES), line);
        self.used = self
            .used
            .saturating_add(HEADER_BYTES.saturating_add(line.len()));
    }

    /// Take the oldest line into `out`, cut to `out`'s length, with the
    /// count of lines dropped just before it; `None` when the queue is empty.
    pub fn pop(&mut self, out: &mut [u8]) -> Option<Popped>
    {
        if self.used == 0
        {
            return None;
        }
        let mut header = [0u8; HEADER_BYTES];
        self.read_at(self.head, &mut header);
        let [l0, l1, d0, d1, d2, d3] = header;
        let len = usize::from(u16::from_le_bytes([l0, l1]));
        let dropped_before = u32::from_le_bytes([d0, d1, d2, d3]);
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
        })
    }

    /// The count of lines dropped after every queued line, taken once the
    /// queue is empty (0 while a line is queued, which will carry it).
    pub fn take_tail_drops(&mut self) -> u32
    {
        if self.used == 0
        {
            core::mem::take(&mut self.dropped)
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

    /// Whether line number `line` ([`Offer::Queued`]) is written.
    #[must_use]
    pub const fn is_written(&self, line: u64) -> bool
    {
        // Numbers wrap after 2^64 lines; the distance stays below 2^63.
        self.done.wrapping_sub(line) < 1 << 63
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
        // 6-byte header + 4-byte line = 10 bytes per line; 25 bytes hold two,
        // so the third and later lines wrap the end.
        let mut q: SinkQueue<25> = SinkQueue::new();
        let mut buf = [0u8; 8];
        for i in 0u8..20
        {
            let line = [i, i.wrapping_add(1), i.wrapping_add(2), i.wrapping_add(3)];
            assert!(matches!(q.offer(&line, false), Offer::Queued(_)));
            let p = q.pop(&mut buf).unwrap();
            assert_eq!((&buf[..p.len], p.dropped_before), (&line[..], 0));
        }
        assert!(q.is_empty());
        assert_eq!(q.pop(&mut buf), None);
    }

    // Defect caught: a full queue that drops a line while the writer still
    // makes progress (serial output lost under mere load), or that overwrites
    // a queued line.
    #[test]
    fn a_full_queue_makes_the_producer_wait_until_the_writer_frees_space()
    {
        let mut q: SinkQueue<20> = SinkQueue::new();
        assert!(matches!(q.offer(b"aaaa", false), Offer::Queued(_)));
        assert!(matches!(q.offer(b"bbbb", false), Offer::Queued(_)));
        assert_eq!(q.offer(b"cccc", false), Offer::Wait);
        assert!(!q.is_stalled());
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        assert!(matches!(q.offer(b"cccc", false), Offer::Queued(_)));
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
        let mut q: SinkQueue<20> = SinkQueue::new();
        assert!(matches!(q.offer(b"aaaa", false), Offer::Queued(_)));
        assert!(matches!(q.offer(b"bbbb", false), Offer::Queued(_)));
        assert_eq!(q.offer(b"cccc", true), Offer::Dropped);
        assert!(q.is_stalled());
        // Stalled: a full queue drops at once, without a wait.
        assert_eq!(q.offer(b"dddd", false), Offer::Dropped);
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        // Space alone does not end the stall's drops of lines that fit: they
        // are queued, since the ring has room.
        assert!(matches!(q.offer(b"eeee", false), Offer::Queued(_)));
        assert_eq!(q.offer(b"ffff", false), Offer::Dropped);
        q.written();
        assert!(!q.is_stalled());
        assert_eq!(q.offer(b"gggg", false), Offer::Wait);
    }

    // Defect caught: lines dropped from a sink without a count, a count
    // reported twice, or reported at the wrong point in the stream.
    #[test]
    fn drops_are_reported_before_the_next_queued_line_or_at_the_tail()
    {
        let mut q: SinkQueue<20> = SinkQueue::new();
        assert!(matches!(q.offer(b"aaaa", false), Offer::Queued(_)));
        assert!(matches!(q.offer(b"bbbb", false), Offer::Queued(_)));
        assert_eq!(q.offer(b"xxxx", true), Offer::Dropped);
        assert_eq!(q.offer(b"yyyy", false), Offer::Dropped);
        // Two lines queued: the tail's count is not taken yet.
        assert_eq!(q.take_tail_drops(), 0);
        let mut buf = [0u8; 8];
        q.pop(&mut buf).unwrap();
        assert!(matches!(q.offer(b"cccc", false), Offer::Queued(_)));
        assert_eq!(q.offer(b"zzzz", false), Offer::Dropped);
        assert_eq!(
            drain(&mut q),
            [(b"bbbb".to_vec(), 0), (b"cccc".to_vec(), 2)]
        );
        assert_eq!(q.take_tail_drops(), 1);
        assert_eq!(q.take_tail_drops(), 0);
    }

    // Defect caught: a line the ring can never hold making its producer wait
    // for space that will never be enough.
    #[test]
    fn a_line_longer_than_the_ring_is_dropped_without_a_wait()
    {
        let mut q: SinkQueue<16> = SinkQueue::new();
        assert_eq!(q.offer(&[0u8; 11], false), Offer::Dropped);
        assert!(!q.is_stalled());
        assert!(matches!(q.offer(&[0u8; 10], false), Offer::Queued(_)));
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
        let Offer::Queued(first) = q.offer(b"aaaa", false)
        else
        {
            panic!("not queued");
        };
        let Offer::Queued(second) = q.offer(b"bbbb", false)
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
        assert!(matches!(q.offer(b"abcdef", false), Offer::Queued(_)));
        assert!(matches!(q.offer(b"gh", false), Offer::Queued(_)));
        let mut short = [0u8; 3];
        let p = q.pop(&mut short).unwrap();
        assert_eq!(&short[..p.len], b"abc");
        assert_eq!(drain(&mut q), [(b"gh".to_vec(), 0)]);
    }
}
