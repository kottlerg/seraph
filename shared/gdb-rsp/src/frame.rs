// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/gdb-rsp/src/frame.rs

//! Packet framing: splitting the received byte stream into events, the
//! acknowledgement mode, binary escaping, and writing packets with the reply
//! bodies a stub sends.
//!
//! A packet is `$<body>#<checksum>`, the checksum two hex digits of the
//! modulo-256 sum of the body's bytes as sent. Binary data in a body escapes
//! `$`, `#`, `}` and `*` as `}` followed by the byte XOR `0x20`; the checksum
//! covers the escaped bytes. Outside a packet `+` acknowledges a packet, `-`
//! asks for it again, and `0x03` interrupts the target.

use crate::hex::{DIGITS, nibble};
use crate::{Error, PACKET_SIZE};

/// The escape byte of binary data.
const ESCAPE: u8 = b'}';

/// What [`PacketReader::push`] recognised once a byte completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a>
{
    /// A packet whose checksum matches: its body as sent, escapes included.
    Packet(&'a [u8]),
    /// `+`: the peer received the last packet.
    Ack,
    /// `-`: the peer asks for the last packet again.
    Nack,
    /// `0x03` outside a packet: GDB asks the stub to stop the target.
    Interrupt,
    /// A packet whose checksum does not match the body, or whose checksum is
    /// not two hex digits.
    BadChecksum,
    /// A packet whose checksum matches but whose body did not fit the
    /// reader's buffer. The stub acknowledges it and refuses it with an error
    /// reply: asking for it again would bring the same packet back.
    Overflow,
}

/// Where the reader is in the byte stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State
{
    /// Between packets.
    Idle,
    /// Inside a body, after `$`.
    Body,
    /// After `#`, before the first checksum digit.
    Sum,
    /// After the first checksum digit, its value held.
    SumLow(u8),
}

/// Splits a received byte stream into [`Event`]s, one byte at a time, holding
/// a packet body of up to `N` bytes.
pub struct PacketReader<const N: usize>
{
    buf: [u8; N],
    len: usize,
    sum: u8,
    overflowed: bool,
    state: State,
}

impl<const N: usize> Default for PacketReader<N>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<const N: usize> PacketReader<N>
{
    /// A reader between packets.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            buf: [0; N],
            len: 0,
            sum: 0,
            overflowed: false,
            state: State::Idle,
        }
    }

    /// Take one received byte; returns the event it completes, if any.
    ///
    /// A `$` inside a body starts the body again, since GDB never sends one
    /// unescaped there: the reader resynchronises on the newer packet. A byte
    /// between packets other than `$`, `+`, `-` and `0x03` is dropped.
    pub fn push(&mut self, byte: u8) -> Option<Event<'_>>
    {
        match self.state
        {
            State::Idle => match byte
            {
                b'$' =>
                {
                    self.start_body();
                    None
                }
                b'+' => Some(Event::Ack),
                b'-' => Some(Event::Nack),
                0x03 => Some(Event::Interrupt),
                _ => None,
            },
            State::Body =>
            {
                match byte
                {
                    b'$' => self.start_body(),
                    b'#' => self.state = State::Sum,
                    _ =>
                    {
                        self.sum = self.sum.wrapping_add(byte);
                        if let Some(slot) = self.buf.get_mut(self.len)
                        {
                            *slot = byte;
                            self.len += 1;
                        }
                        else
                        {
                            self.overflowed = true;
                        }
                    }
                }
                None
            }
            State::Sum =>
            {
                if let Some(hi) = nibble(byte)
                {
                    self.state = State::SumLow(hi);
                    None
                }
                else
                {
                    self.state = State::Idle;
                    Some(Event::BadChecksum)
                }
            }
            State::SumLow(hi) =>
            {
                self.state = State::Idle;
                match nibble(byte)
                {
                    Some(lo) if (hi << 4) | lo == self.sum =>
                    {
                        if self.overflowed
                        {
                            Some(Event::Overflow)
                        }
                        else
                        {
                            Some(Event::Packet(&self.buf[..self.len]))
                        }
                    }
                    _ => Some(Event::BadChecksum),
                }
            }
        }
    }

    fn start_body(&mut self)
    {
        self.len = 0;
        self.sum = 0;
        self.overflowed = false;
        self.state = State::Body;
    }
}

/// The acknowledgement mode of a connection: acknowledged until the stub
/// accepts `QStartNoAckMode`, then unacknowledged for the rest of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AckMode
{
    no_ack: bool,
}

impl AckMode
{
    /// The byte the stub sends on `event`: `+` for a received packet (an
    /// overflowing one included, which the stub then refuses), `-` for a bad
    /// checksum, and nothing for the other events or in no-ack mode.
    #[must_use]
    pub fn response(self, event: &Event<'_>) -> Option<u8>
    {
        if self.no_ack
        {
            return None;
        }
        match event
        {
            Event::Packet(_) | Event::Overflow => Some(b'+'),
            Event::BadChecksum => Some(b'-'),
            Event::Ack | Event::Nack | Event::Interrupt => None,
        }
    }

    /// Enter no-ack mode, once the stub has sent its `OK` to
    /// `QStartNoAckMode`. GDB acknowledges that `OK`; from then on neither
    /// side acknowledges, and a stray `+` arrives as an [`Event::Ack`] the
    /// stub ignores.
    pub fn enter_no_ack(&mut self)
    {
        self.no_ack = true;
    }

    /// Whether the connection is in no-ack mode, so the stub sends no
    /// acknowledgement and awaits none after its own packets.
    #[must_use]
    pub fn no_ack(self) -> bool
    {
        self.no_ack
    }
}

/// The number of bytes `escaped` holds once its escapes are undone.
///
/// # Errors
/// - `Malformed`: `escaped` ends with an escape byte.
pub fn unescaped_len(escaped: &[u8]) -> Result<usize, Error>
{
    let mut n = 0;
    let mut i = 0;
    while i < escaped.len()
    {
        if escaped[i] == ESCAPE
        {
            i += 1;
            if i == escaped.len()
            {
                return Err(Error::Malformed);
            }
        }
        n += 1;
        i += 1;
    }
    Ok(n)
}

/// Undo the escapes of binary data `escaped` into the front of `out`; returns
/// the byte count.
///
/// # Errors
/// - `Malformed`: `escaped` ends with an escape byte.
/// - `Overflow`: `out` is shorter than the unescaped bytes.
pub fn unescape(escaped: &[u8], out: &mut [u8]) -> Result<usize, Error>
{
    let mut n = 0;
    let mut bytes = escaped.iter();
    while let Some(&b) = bytes.next()
    {
        let value = if b == ESCAPE
        {
            bytes.next().ok_or(Error::Malformed)? ^ 0x20
        }
        else
        {
            b
        };
        *out.get_mut(n).ok_or(Error::Overflow)? = value;
        n += 1;
    }
    Ok(n)
}

/// Writes one packet, `$`, body and checksum, into a caller's buffer.
///
/// Every body byte goes through the escape, so a body never carries a bare
/// `$`, `#`, `}` or `*`; text and hex bodies hold none, so their bytes go out
/// unchanged. A write past the buffer is recorded and reported by
/// [`Self::finish`], so the encoders chain without checking each step.
pub struct PacketWriter<'a>
{
    out: &'a mut [u8],
    len: usize,
    sum: u8,
    overflowed: bool,
}

impl<'a> PacketWriter<'a>
{
    /// Start a packet at the front of `out`.
    pub fn new(out: &'a mut [u8]) -> Self
    {
        let mut w = Self {
            out,
            len: 0,
            sum: 0,
            overflowed: false,
        };
        w.put(b'$');
        w
    }

    /// Append `bytes` to the body, escaping each byte that needs it.
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self
    {
        for &b in bytes
        {
            if matches!(b, b'$' | b'#' | ESCAPE | b'*')
            {
                self.body(ESCAPE);
                self.body(b ^ 0x20);
            }
            else
            {
                self.body(b);
            }
        }
        self
    }

    /// Append `data` as two hex digits per byte, in order.
    pub fn hex(&mut self, data: &[u8]) -> &mut Self
    {
        for &b in data
        {
            self.hex_u8(b);
        }
        self
    }

    /// Append `value` as exactly two hex digits.
    pub fn hex_u8(&mut self, value: u8) -> &mut Self
    {
        self.body(DIGITS[usize::from(value >> 4)]);
        self.body(DIGITS[usize::from(value & 0xF)]);
        self
    }

    /// Append `value` in hex, most significant digit first, without leading
    /// zeros (`0` for zero).
    pub fn hex_u64(&mut self, value: u64) -> &mut Self
    {
        let digits = (64 - value.leading_zeros()).div_ceil(4).max(1);
        for i in (0..digits).rev()
        {
            // The mask keeps one nibble, so the index is below 16.
            let nib = usize::try_from((value >> (i * 4)) & 0xF).unwrap_or(0);
            self.body(DIGITS[nib]);
        }
        self
    }

    /// Append `count` bytes of register data the stub cannot read, as `xx`
    /// each: GDB shows those registers as unavailable.
    pub fn unavailable(&mut self, count: usize) -> &mut Self
    {
        for _ in 0..count * 2
        {
            self.body(b'x');
        }
        self
    }

    /// End the packet with `#` and the checksum; returns the packet's length.
    ///
    /// # Errors
    /// - `Overflow`: the packet did not fit the buffer.
    pub fn finish(mut self) -> Result<usize, Error>
    {
        let sum = self.sum;
        self.put(b'#');
        self.put(DIGITS[usize::from(sum >> 4)]);
        self.put(DIGITS[usize::from(sum & 0xF)]);
        if self.overflowed
        {
            return Err(Error::Overflow);
        }
        Ok(self.len)
    }

    // ── Reply bodies ───────────────────────────────────────────────────────

    /// `OK`: the command succeeded.
    pub fn ok(&mut self) -> &mut Self
    {
        self.bytes(b"OK")
    }

    /// `E<code>`: the command failed. GDB gives the code no meaning of its
    /// own; it reports the failure.
    pub fn error(&mut self, code: u8) -> &mut Self
    {
        self.bytes(b"E").hex_u8(code)
    }

    /// `S<signal>`: the target stopped with `signal` (GDB's numbering: 5 for
    /// a trap, 2 for an interrupt, 11 for a segmentation fault).
    pub fn stop_signal(&mut self, signal: u8) -> &mut Self
    {
        self.bytes(b"S").hex_u8(signal)
    }

    /// `T<signal>thread:<id>;`: the target stopped with `signal`, `thread`
    /// being the thread that stopped.
    pub fn stop_thread(&mut self, signal: u8, thread: u64) -> &mut Self
    {
        self.bytes(b"T")
            .hex_u8(signal)
            .bytes(b"thread:")
            .hex_u64(thread)
            .bytes(b";")
    }

    /// `W<code>`: the process exited with `code`.
    pub fn exited(&mut self, code: u8) -> &mut Self
    {
        self.bytes(b"W").hex_u8(code)
    }

    /// `X<signal>`: the process was terminated with `signal`.
    pub fn terminated(&mut self, signal: u8) -> &mut Self
    {
        self.bytes(b"X").hex_u8(signal)
    }

    /// The `qfThreadInfo` reply: `m` and the thread ids, comma-separated, or
    /// `l` (the end of the list) when `threads` is empty. A stub that sends
    /// every thread in one reply answers the following `qsThreadInfo` with
    /// `l`, through this call with no threads.
    pub fn thread_list(&mut self, threads: &[u64]) -> &mut Self
    {
        let Some((first, rest)) = threads.split_first()
        else
        {
            return self.bytes(b"l");
        };
        self.bytes(b"m").hex_u64(*first);
        for &t in rest
        {
            self.bytes(b",").hex_u64(t);
        }
        self
    }

    /// The `qC` reply: `QC<id>`, the current thread.
    pub fn current_thread(&mut self, thread: u64) -> &mut Self
    {
        self.bytes(b"QC").hex_u64(thread)
    }

    /// The `qOffsets` reply: `Text=<offset>;Data=<offset>;Bss=<offset>`, the
    /// amount the image's sections were loaded above their link addresses.
    /// One offset serves all three for an image loaded as one block, which a
    /// position-independent image is.
    pub fn offsets(&mut self, offset: u64) -> &mut Self
    {
        self.bytes(b"Text=")
            .hex_u64(offset)
            .bytes(b";Data=")
            .hex_u64(offset)
            .bytes(b";Bss=")
            .hex_u64(offset)
    }

    /// The `qSupported` reply of a stub using this crate: its packet size
    /// ([`PACKET_SIZE`]), no-ack mode, the target description through
    /// `qXfer:features:read`, and `vCont`.
    pub fn supported(&mut self) -> &mut Self
    {
        // PACKET_SIZE is a small constant; widening it to u64 is lossless.
        self.bytes(b"PacketSize=")
            .hex_u64(PACKET_SIZE as u64)
            .bytes(b";QStartNoAckMode+;qXfer:features:read+;vContSupported+")
    }

    /// The `vCont?` reply: the actions `vCont` takes. GDB uses `vCont` only
    /// when `c`, `C`, `s` and `S` are all listed; a stub delivers no signal,
    /// so it takes `C` and `S` as `c` and `s`.
    pub fn vcont_actions(&mut self) -> &mut Self
    {
        self.bytes(b"vCont;c;C;s;S;t")
    }

    /// The `qXfer:...:read` reply for `len` bytes of `document` from
    /// `offset`: `m` and the bytes when the document goes on past them, `l`
    /// and the bytes when they reach its end (`l` alone past its end).
    pub fn xfer_chunk(&mut self, document: &[u8], offset: u64, len: u64) -> &mut Self
    {
        let start = usize::try_from(offset).map_or(document.len(), |o| o.min(document.len()));
        let rest = &document[start..];
        let take = usize::try_from(len).map_or(rest.len(), |l| l.min(rest.len()));
        let more = take < rest.len();
        self.bytes(if more { b"m" } else { b"l" })
            .bytes(&rest[..take])
    }

    fn body(&mut self, byte: u8)
    {
        self.sum = self.sum.wrapping_add(byte);
        self.put(byte);
    }

    fn put(&mut self, byte: u8)
    {
        if let Some(slot) = self.out.get_mut(self.len)
        {
            *slot = byte;
            self.len += 1;
        }
        else
        {
            self.overflowed = true;
        }
    }
}

/// The modulo-256 sum of `bytes`: a packet's checksum over its body as sent.
#[must_use]
pub fn checksum(bytes: &[u8]) -> u8
{
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Push every byte of `stream`; return the events, packets as owned
    /// bodies.
    fn events<const N: usize>(reader: &mut PacketReader<N>, stream: &[u8]) -> Vec<Owned>
    {
        stream
            .iter()
            .filter_map(|&b| reader.push(b).map(Owned::from))
            .collect()
    }

    extern crate std;
    use std::vec::Vec;

    #[derive(Debug, PartialEq, Eq)]
    enum Owned
    {
        Packet(Vec<u8>),
        Ack,
        Nack,
        Interrupt,
        BadChecksum,
        Overflow,
    }

    impl From<Event<'_>> for Owned
    {
        fn from(e: Event<'_>) -> Self
        {
            match e
            {
                Event::Packet(b) => Self::Packet(b.to_vec()),
                Event::Ack => Self::Ack,
                Event::Nack => Self::Nack,
                Event::Interrupt => Self::Interrupt,
                Event::BadChecksum => Self::BadChecksum,
                Event::Overflow => Self::Overflow,
            }
        }
    }

    fn packet(out: &mut [u8], f: impl FnOnce(&mut PacketWriter<'_>)) -> usize
    {
        let mut w = PacketWriter::new(out);
        f(&mut w);
        w.finish().unwrap()
    }

    #[test]
    fn a_packet_with_its_checksum_yields_its_body()
    {
        let mut r = PacketReader::<64>::new();
        assert_eq!(events(&mut r, b"$g#67"), [Owned::Packet(b"g".to_vec())]);
        assert_eq!(
            events(&mut r, b"$qSupported:multiprocess+#C6"),
            [Owned::Packet(b"qSupported:multiprocess+".to_vec())]
        );
    }

    #[test]
    fn a_checksum_that_differs_or_is_not_hex_is_refused()
    {
        let mut r = PacketReader::<64>::new();
        assert_eq!(events(&mut r, b"$g#68"), [Owned::BadChecksum]);
        assert_eq!(events(&mut r, b"$g#z7"), [Owned::BadChecksum]);
        assert_eq!(events(&mut r, b"$g#6z"), [Owned::BadChecksum]);
        // The reader is back between packets afterwards.
        assert_eq!(events(&mut r, b"$g#67"), [Owned::Packet(b"g".to_vec())]);
    }

    #[test]
    fn control_bytes_between_packets_are_events_and_others_are_dropped()
    {
        let mut r = PacketReader::<64>::new();
        assert_eq!(
            events(&mut r, b"+x-\x03\r\n+"),
            [Owned::Ack, Owned::Nack, Owned::Interrupt, Owned::Ack]
        );
    }

    #[test]
    fn an_interrupt_byte_inside_a_body_is_body_data()
    {
        let mut r = PacketReader::<64>::new();
        let mut buf = [0u8; 16];
        let body = [b'X', 0x03];
        let n = packet(&mut buf, |w| {
            w.bytes(&body);
        });
        assert_eq!(events(&mut r, &buf[..n]), [Owned::Packet(body.to_vec())]);
    }

    #[test]
    fn a_dollar_inside_a_body_restarts_on_the_newer_packet()
    {
        let mut r = PacketReader::<64>::new();
        assert_eq!(
            events(&mut r, b"$m10,$g#67"),
            [Owned::Packet(b"g".to_vec())]
        );
    }

    #[test]
    fn a_body_past_the_buffer_with_a_good_checksum_is_an_overflow()
    {
        let mut r = PacketReader::<4>::new();
        let mut buf = [0u8; 32];
        let n = packet(&mut buf, |w| {
            w.bytes(b"m1000,40");
        });
        assert_eq!(events(&mut r, &buf[..n]), [Owned::Overflow]);
        // A body of exactly the buffer's size fits.
        let n = packet(&mut buf, |w| {
            w.bytes(b"m0,4");
        });
        assert_eq!(events(&mut r, &buf[..n]), [Owned::Packet(b"m0,4".to_vec())]);
    }

    #[test]
    fn a_body_past_the_buffer_with_a_bad_checksum_is_refused()
    {
        let mut r = PacketReader::<4>::new();
        assert_eq!(events(&mut r, b"$m1000,40#00"), [Owned::BadChecksum]);
    }

    #[test]
    fn acknowledgements_stop_once_no_ack_mode_is_entered()
    {
        let mut mode = AckMode::default();
        assert_eq!(mode.response(&Event::Packet(b"g")), Some(b'+'));
        assert_eq!(mode.response(&Event::Overflow), Some(b'+'));
        assert_eq!(mode.response(&Event::BadChecksum), Some(b'-'));
        assert_eq!(mode.response(&Event::Ack), None);
        assert_eq!(mode.response(&Event::Interrupt), None);
        assert!(!mode.no_ack());
        mode.enter_no_ack();
        assert!(mode.no_ack());
        assert_eq!(mode.response(&Event::Packet(b"g")), None);
        assert_eq!(mode.response(&Event::BadChecksum), None);
    }

    #[test]
    fn binary_data_round_trips_through_escape_framing_and_unescape()
    {
        let data: Vec<u8> = (0u8..=255).collect();
        let mut buf = [0u8; 1024];
        let n = packet(&mut buf, |w| {
            w.bytes(b"X0,100:").bytes(&data);
        });
        let wire = &buf[..n];
        // The body between `$` and `#` holds no bare framing byte.
        let body = &wire[1..n - 3];
        assert!(!body.iter().any(|&b| b == b'$' || b == b'#' || b == b'*'));
        let mut r = PacketReader::<1024>::new();
        let got = events(&mut r, wire);
        let [Owned::Packet(got)] = got.as_slice()
        else
        {
            panic!("expected one packet, got {got:?}");
        };
        let escaped = &got[b"X0,100:".len()..];
        assert_eq!(unescaped_len(escaped), Ok(256));
        let mut out = [0u8; 256];
        assert_eq!(unescape(escaped, &mut out), Ok(256));
        assert_eq!(out.as_slice(), data.as_slice());
    }

    #[test]
    fn escaped_data_that_ends_with_the_escape_byte_is_malformed()
    {
        let mut out = [0u8; 4];
        assert_eq!(unescaped_len(b"a}"), Err(Error::Malformed));
        assert_eq!(unescape(b"a}", &mut out), Err(Error::Malformed));
    }

    #[test]
    fn unescaped_data_longer_than_the_output_overflows()
    {
        let mut out = [0u8; 1];
        assert_eq!(unescape(b"a}\x03", &mut out), Err(Error::Overflow));
    }

    #[test]
    fn a_written_packet_carries_the_checksum_of_its_body()
    {
        let mut buf = [0u8; 16];
        let n = packet(&mut buf, |w| {
            w.ok();
        });
        assert_eq!(&buf[..n], b"$OK#9a");
        assert_eq!(checksum(b"OK"), 0x9a);
    }

    #[test]
    fn a_packet_past_the_buffer_reports_overflow()
    {
        let mut buf = [0u8; 6];
        let mut w = PacketWriter::new(&mut buf);
        w.bytes(b"OKK");
        assert_eq!(w.finish(), Err(Error::Overflow));
        let mut buf = [0u8; 6];
        let mut w = PacketWriter::new(&mut buf);
        w.ok();
        assert_eq!(w.finish(), Ok(6));
    }

    #[test]
    fn numbers_are_written_without_leading_zeros()
    {
        let mut buf = [0u8; 64];
        let n = packet(&mut buf, |w| {
            w.hex_u64(0)
                .bytes(b",")
                .hex_u64(0x10)
                .bytes(b",")
                .hex_u64(u64::MAX);
        });
        assert_eq!(&buf[1..n - 3], b"0,10,ffffffffffffffff");
    }

    #[test]
    fn a_thread_list_is_comma_separated_or_ends_the_list_when_empty()
    {
        let mut buf = [0u8; 64];
        let n = packet(&mut buf, |w| {
            w.thread_list(&[1, 0x2b, 3]);
        });
        assert_eq!(&buf[1..n - 3], b"m1,2b,3");
        let n = packet(&mut buf, |w| {
            w.thread_list(&[]);
        });
        assert_eq!(&buf[1..n - 3], b"l");
    }

    #[test]
    fn register_bytes_the_stub_cannot_read_are_marked_unavailable()
    {
        let mut buf = [0u8; 64];
        let n = packet(&mut buf, |w| {
            w.hex(&[0x01, 0xab]).unavailable(2);
        });
        assert_eq!(&buf[1..n - 3], b"01abxxxx");
    }

    #[test]
    fn a_document_reads_in_chunks_marked_more_or_last()
    {
        let doc = b"<target>}</target>";
        let mut buf = [0u8; 64];
        let mut chunk = |offset, len| {
            let n = packet(&mut buf, |w| {
                w.xfer_chunk(doc, offset, len);
            });
            buf[1..n - 3].to_vec()
        };
        assert_eq!(chunk(0, 8), b"m<target>");
        // The `}` is escaped in the chunk.
        assert_eq!(chunk(8, 100), b"l}]</target>");
        assert_eq!(chunk(100, 8), b"l");
        assert_eq!(chunk(u64::MAX, u64::MAX), b"l");
    }
}
