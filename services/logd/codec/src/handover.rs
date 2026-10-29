// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/handover.rs

//! init-logd → real-logd handover wire contract.
//!
//! Both ends build against these definitions: init-logd
//! (`services/init/src/logging.rs`) packs replies with the `encode_*`
//! functions, walks its history ring with [`next_history_seq`], and tracks
//! the names it must send again ([`NameResend`]); real-logd
//! (`services/logd/src/handover.rs`) decodes replies with [`decode`]. The
//! wire format is specified in
//! [handover-protocol.md](../../docs/handover-protocol.md).

use ipc::IpcMessage;
use syscall_abi::MSG_DATA_WORDS_MAX;

/// `HANDOVER_PULL` reply status: more chunks follow.
pub const REPLY_MORE: u64 = 0;
/// `HANDOVER_PULL` reply status: no more data. Does not end init-logd.
pub const REPLY_DONE: u64 = 1;

/// Chunk kind in `word(0)`: header (`word(1)` = total history lines pushed,
/// `word(2)` = active slot count).
pub const KIND_HEADER: u64 = 1;
/// Chunk kind in `word(0)`: one slot (`word(1)` = badge, `word(2)` = name
/// length, name bytes from word [`SLOT_NAME_WORD`]).
pub const KIND_SLOT: u64 = 2;
/// Chunk kind in `word(0)`: one history line (`word(1)` = badge, `word(2)` =
/// receipt microseconds, `word(3)` = byte length, line bytes from word
/// [`LINE_BYTES_WORD`]).
pub const KIND_LINE: u64 = 3;

/// First data word of a `SLOT` chunk's inline name bytes.
pub const SLOT_NAME_WORD: usize = 3;
/// First data word of a `LINE` chunk's inline line bytes.
pub const LINE_BYTES_WORD: usize = 4;

/// `HANDOVER_RELEASE` reply status: released; init-logd exits.
pub const RELEASE_ACK: u64 = 0;
/// `HANDOVER_RELEASE` reply status: a display name changed after its slot was
/// sent; init-logd keeps serving and real-logd pulls again before releasing.
pub const RELEASE_PENDING: u64 = 1;

/// Number of times init-logd answers `HANDOVER_RELEASE` with
/// [`RELEASE_PENDING`] before it acknowledges regardless, so a sender that
/// keeps registering names cannot hold the handover open. Real-logd issues at
/// most `MAX_RELEASE_DEFERRALS + 1` pull-and-release rounds, the last of which
/// init-logd acknowledges.
pub const MAX_RELEASE_DEFERRALS: u32 = 8;

/// Mask selecting a reply's status code; the bits above carry an inline byte
/// length on `SLOT` and `LINE` chunks.
const STATUS_MASK: u64 = 0xFFFF;

/// One decoded `HANDOVER_PULL` reply chunk.
#[derive(Debug, PartialEq, Eq)]
pub enum Chunk<'a>
{
    /// The informational first chunk.
    Header,
    /// One sender slot: its badge and display name.
    Slot
    {
        /// Sender badge (the kernel-delivered identity on every IPC).
        badge: u64,
        /// Display name, clipped to the carried payload.
        name: &'a [u8],
    },
    /// One history line: its sender badge, receipt microseconds, and bytes.
    Line
    {
        /// Sender badge at receipt time.
        badge: u64,
        /// Receipt time in microseconds since boot.
        us: u64,
        /// Line bytes (no trailing `\n`), clipped to the carried payload.
        bytes: &'a [u8],
    },
    /// An unknown kind, or a `SLOT` / `LINE` chunk with no inline payload
    /// words; the receiver skips it.
    Skip,
}

/// Decode one `HANDOVER_PULL` reply.
///
/// The declared name or line length is the peer's word and is not trusted:
/// the returned bytes are clipped to the payload the message carries, however
/// large the declared length.
#[must_use]
pub fn decode(reply: &IpcMessage) -> Chunk<'_>
{
    match reply.word(0)
    {
        KIND_HEADER => Chunk::Header,
        KIND_SLOT =>
        {
            inline_bytes(reply, SLOT_NAME_WORD, reply.word(2)).map_or(Chunk::Skip, |name| {
                Chunk::Slot {
                    badge: reply.word(1),
                    name,
                }
            })
        }
        KIND_LINE =>
        {
            inline_bytes(reply, LINE_BYTES_WORD, reply.word(3)).map_or(Chunk::Skip, |bytes| {
                Chunk::Line {
                    badge: reply.word(1),
                    us: reply.word(2),
                    bytes,
                }
            })
        }
        _ => Chunk::Skip,
    }
}

/// Encode the `HEADER` chunk: `total` history lines ever pushed and `active`
/// occupied slots.
#[must_use]
pub fn encode_header(total: u64, active: u64) -> IpcMessage
{
    IpcMessage::builder(REPLY_MORE)
        .word(0, KIND_HEADER)
        .word(1, total)
        .word(2, active)
        .build()
}

/// Encode one `SLOT` chunk. A name longer than the message's payload area
/// past [`SLOT_NAME_WORD`] is clipped to it, and the declared length (word 2
/// and the label's upper bits) is the clipped length.
#[must_use]
pub fn encode_slot(badge: u64, name: &[u8]) -> IpcMessage
{
    let name = clip_to_payload(name, SLOT_NAME_WORD);
    IpcMessage::builder(with_length(REPLY_MORE, name.len()))
        .word(0, KIND_SLOT)
        .word(1, badge)
        .word(2, name.len() as u64)
        .bytes(SLOT_NAME_WORD, name)
        .build()
}

/// Encode one `LINE` chunk. Line bytes past the message's payload area after
/// [`LINE_BYTES_WORD`] are clipped, and the declared length is the clipped
/// length.
#[must_use]
pub fn encode_line(badge: u64, us: u64, line: &[u8]) -> IpcMessage
{
    let line = clip_to_payload(line, LINE_BYTES_WORD);
    IpcMessage::builder(with_length(REPLY_MORE, line.len()))
        .word(0, KIND_LINE)
        .word(1, badge)
        .word(2, us)
        .word(3, line.len() as u64)
        .bytes(LINE_BYTES_WORD, line)
        .build()
}

/// Encode the terminal `DONE` reply (no data words).
#[must_use]
pub fn encode_done() -> IpcMessage
{
    IpcMessage::new(REPLY_DONE)
}

/// The next history-ring sequence number init-logd sends, or `None` when the
/// drain has caught up.
///
/// Sequence numbers are absolute push counts: sequence `s` lives in ring slot
/// `s % ring_len` until `ring_len` later pushes overwrite it, so with `total`
/// lines ever pushed the live sequences are
/// `total.saturating_sub(ring_len)..total`. `next` is the first sequence not
/// yet sent. A sequence overwritten before it was sent is skipped, and lines
/// pushed after the drain caught up are returned by a later call, so a
/// deferred release's further drain carries them.
#[must_use]
pub fn next_history_seq(next: u64, total: u64, ring_len: u64) -> Option<u64>
{
    let seq = next.max(total.saturating_sub(ring_len));
    (seq < total).then_some(seq)
}

/// `bytes`, clipped to the payload area from data word `start_word` to the
/// end of the message.
fn clip_to_payload(bytes: &[u8], start_word: usize) -> &[u8]
{
    let room = MSG_DATA_WORDS_MAX.saturating_sub(start_word) * 8;
    &bytes[..bytes.len().min(room)]
}

/// `status` with an inline byte length packed into the label's upper bits
/// (the stream-protocol convention).
fn with_length(status: u64, len: usize) -> u64
{
    status | ((len as u64 & STATUS_MASK) << 16)
}

/// Whether a `HANDOVER_PULL` reply label carries [`REPLY_DONE`], ignoring the
/// length bits packed above the status.
#[must_use]
pub fn is_done(label: u64) -> bool
{
    label & STATUS_MASK == REPLY_DONE
}

/// Whether a `HANDOVER_RELEASE` reply label carries [`RELEASE_PENDING`].
#[must_use]
pub fn is_release_pending(label: u64) -> bool
{
    label & STATUS_MASK == RELEASE_PENDING
}

/// The payload bytes from data word `start_word`, at most `declared_len` of
/// them; `None` when the message carries no word at or past `start_word`.
fn inline_bytes(reply: &IpcMessage, start_word: usize, declared_len: u64) -> Option<&[u8]>
{
    let bytes = reply.data_bytes();
    let start = start_word * 8;
    if start >= bytes.len()
    {
        return None;
    }
    let len = usize::try_from(declared_len).unwrap_or(usize::MAX);
    let end = start.saturating_add(len).min(bytes.len());
    Some(&bytes[start..end])
}

/// init-logd's record of slots whose display name changed after the handover
/// began, which it must send again before it releases.
///
/// The handover sends every slot once, before the history lines; a sender that
/// registers or changes its name after that (during the history drain, or
/// between `DONE` and `HANDOVER_RELEASE`) would otherwise reach real-logd with
/// no name. `N` is init-logd's slot-table size.
pub struct NameResend<const N: usize>
{
    started: bool,
    pending: [bool; N],
    deferrals: u32,
}

impl<const N: usize> NameResend<N>
{
    /// No handover in progress, nothing pending.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            started: false,
            pending: [false; N],
            deferrals: 0,
        }
    }

    /// Mark the handover as begun (the header chunk was sent). Name changes
    /// before this need no resend: the slot pass that follows carries them.
    pub fn start(&mut self)
    {
        self.started = true;
    }

    /// Record that slot `slot`'s display name changed. Ignored before
    /// [`Self::start`] and for an index outside the table.
    pub fn note_name_change(&mut self, slot: usize)
    {
        if self.started
            && let Some(p) = self.pending.get_mut(slot)
        {
            *p = true;
        }
    }

    /// Take the lowest-indexed slot still to be sent again.
    pub fn take_next(&mut self) -> Option<usize>
    {
        let slot = self.pending.iter().position(|&p| p)?;
        self.pending[slot] = false;
        Some(slot)
    }

    /// The status to answer `HANDOVER_RELEASE` with: [`RELEASE_PENDING`] while
    /// a slot is still to be sent and fewer than [`MAX_RELEASE_DEFERRALS`]
    /// releases were deferred, else [`RELEASE_ACK`].
    pub fn release_status(&mut self) -> u64
    {
        if self.pending.contains(&true) && self.deferrals < MAX_RELEASE_DEFERRALS
        {
            self.deferrals += 1;
            RELEASE_PENDING
        }
        else
        {
            RELEASE_ACK
        }
    }
}

impl<const N: usize> Default for NameResend<N>
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

    /// A `SLOT` chunk whose declared length the test chooses freely, unlike
    /// [`encode_slot`]'s (a malformed or hostile peer).
    fn malformed_slot(badge: u64, declared_len: u64, name: &[u8]) -> IpcMessage
    {
        IpcMessage::builder(REPLY_MORE)
            .word(0, KIND_SLOT)
            .word(1, badge)
            .word(2, declared_len)
            .bytes(SLOT_NAME_WORD, name)
            .build()
    }

    /// A `LINE` chunk with a freely chosen declared length.
    fn malformed_line(badge: u64, us: u64, declared_len: u64, line: &[u8]) -> IpcMessage
    {
        IpcMessage::builder(REPLY_MORE)
            .word(0, KIND_LINE)
            .word(1, badge)
            .word(2, us)
            .word(3, declared_len)
            .bytes(LINE_BYTES_WORD, line)
            .build()
    }

    #[test]
    fn slot_chunk_round_trips_badge_and_name()
    {
        let reply = encode_slot(0x1234, b"svctest");
        assert_eq!(reply.label >> 16, 7);
        assert_eq!(
            decode(&reply),
            Chunk::Slot {
                badge: 0x1234,
                name: b"svctest",
            }
        );
    }

    #[test]
    fn line_chunk_round_trips_badge_timestamp_and_bytes()
    {
        let reply = encode_line(9, 2_742_215, b"phase=start");
        assert_eq!(reply.label >> 16, 11);
        assert_eq!(
            decode(&reply),
            Chunk::Line {
                badge: 9,
                us: 2_742_215,
                bytes: b"phase=start",
            }
        );
    }

    #[test]
    fn header_chunk_round_trips()
    {
        let reply = encode_header(110, 14);
        assert_eq!(decode(&reply), Chunk::Header);
        assert_eq!((reply.word(1), reply.word(2)), (110, 14));
        assert!(!is_done(reply.label));
    }

    #[test]
    fn done_reply_ends_the_drain_and_carries_no_chunk()
    {
        let reply = encode_done();
        assert!(is_done(reply.label));
        assert_eq!(decode(&reply), Chunk::Skip);
    }

    #[test]
    fn line_longer_than_the_payload_area_is_clipped_when_encoded()
    {
        let long = [b'x'; 600];
        let reply = encode_line(1, 0, &long);
        let Chunk::Line { bytes, .. } = decode(&reply)
        else
        {
            panic!("expected a line chunk");
        };
        assert_eq!(bytes.len(), (MSG_DATA_WORDS_MAX - LINE_BYTES_WORD) * 8);
        assert_eq!(reply.word(3), bytes.len() as u64);
    }

    #[test]
    fn slot_name_length_past_the_address_space_is_clipped_to_the_payload()
    {
        // `start + len` overflows usize for this declared length.
        let reply = malformed_slot(1, u64::MAX, b"init");
        let Chunk::Slot { name, .. } = decode(&reply)
        else
        {
            panic!("expected a slot chunk");
        };
        // The payload word is zero-padded past the four name bytes.
        assert_eq!(name, b"init\0\0\0\0");
    }

    #[test]
    fn line_length_past_the_address_space_is_clipped_to_the_payload()
    {
        let reply = malformed_line(1, 0, u64::MAX - 3, b"ok");
        let Chunk::Line { bytes, .. } = decode(&reply)
        else
        {
            panic!("expected a line chunk");
        };
        assert_eq!(bytes, b"ok\0\0\0\0\0\0");
    }

    #[test]
    fn slot_chunk_without_payload_words_is_skipped()
    {
        // An empty name packs no payload word, so the message ends at word 3.
        let reply = encode_slot(1, b"");
        assert_eq!(decode(&reply), Chunk::Skip);
    }

    #[test]
    fn unknown_chunk_kind_is_skipped()
    {
        let reply = IpcMessage::builder(REPLY_MORE).word(0, 99).build();
        assert_eq!(decode(&reply), Chunk::Skip);
    }

    #[test]
    fn done_status_is_read_below_the_packed_length()
    {
        assert!(is_done(REPLY_DONE | (24 << 16)));
        assert!(!is_done(REPLY_MORE | (1 << 16)));
    }

    #[test]
    fn history_seq_walks_an_unwrapped_ring_in_order()
    {
        assert_eq!(next_history_seq(0, 3, 4), Some(0));
        assert_eq!(next_history_seq(2, 3, 4), Some(2));
        assert_eq!(next_history_seq(3, 3, 4), None);
    }

    #[test]
    fn history_seq_skips_lines_overwritten_before_they_were_sent()
    {
        // Ten pushes into a four-slot ring leave sequences 6..10 live.
        assert_eq!(next_history_seq(1, 10, 4), Some(6));
    }

    #[test]
    fn history_seq_returns_lines_pushed_after_the_drain_caught_up()
    {
        assert_eq!(next_history_seq(10, 10, 4), None);
        assert_eq!(next_history_seq(10, 11, 4), Some(10));
    }

    #[test]
    fn name_change_before_the_handover_starts_is_not_resent()
    {
        let mut resend = NameResend::<4>::new();
        resend.note_name_change(2);
        assert_eq!(resend.take_next(), None);
    }

    #[test]
    fn name_change_after_the_handover_starts_is_resent_once()
    {
        let mut resend = NameResend::<4>::new();
        resend.start();
        resend.note_name_change(2);
        assert_eq!(resend.take_next(), Some(2));
        assert_eq!(resend.take_next(), None);
    }

    #[test]
    fn release_is_deferred_while_a_name_is_unsent()
    {
        let mut resend = NameResend::<4>::new();
        resend.start();
        resend.note_name_change(0);
        assert!(is_release_pending(resend.release_status()));
        assert_eq!(resend.take_next(), Some(0));
        assert_eq!(resend.release_status(), RELEASE_ACK);
    }

    #[test]
    fn release_deferrals_are_bounded()
    {
        let mut resend = NameResend::<4>::new();
        resend.start();
        for _ in 0..MAX_RELEASE_DEFERRALS
        {
            resend.note_name_change(1);
            assert_eq!(resend.release_status(), RELEASE_PENDING);
        }
        resend.note_name_change(1);
        assert_eq!(resend.release_status(), RELEASE_ACK);
    }

    #[test]
    fn name_change_outside_the_table_is_ignored()
    {
        let mut resend = NameResend::<4>::new();
        resend.start();
        resend.note_name_change(4);
        assert_eq!(resend.take_next(), None);
    }
}
