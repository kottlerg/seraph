// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/log_control.rs

//! The wire format of logd's sink control labels,
//! [`SINK_LIST`](crate::log_labels::SINK_LIST) and
//! [`SINK_SET`](crate::log_labels::SINK_SET)
//! (`services/logd/docs/ipc-interface.md` § Sink control).
//!
//! A request carries [`LOG_LABELS_VERSION`](crate::LOG_LABELS_VERSION) in
//! `data[0]`. A reply's label is a [`crate::log_query`] reply label: its
//! status, its entry count and whether more entries follow
//! ([`reply_label`]). A sink's name and a settings string travel as bytes
//! after the fixed words, the name padded to a whole word, their lengths in
//! one word before them.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use syscall_abi::MSG_DATA_WORDS_MAX;

use crate::log_labels::{SINK_LIST, SINK_SET};
use crate::log_query::{
    QUERY_INVALID, QUERY_OK, QUERY_VERSION_MISMATCH, reply_count, reply_label, reply_more,
    reply_status,
};
use crate::{IpcMessage, LOG_LABELS_VERSION};

/// Sink state: its driver is resolved and its writes are answered.
pub const SINK_SERVED: u8 = 0;
/// Sink state: no driver of its device class is resolved; the sink holds
/// nobody back and writes nothing until one is.
pub const SINK_UNSERVED: u8 = 1;
/// Sink state: its driver stopped answering within the stall bound; the sink
/// holds nobody back until it answers again.
pub const SINK_STALLED: u8 = 2;

/// Longest sink name the labels carry, in bytes.
pub const SINK_NAME_MAX: usize = 16;

/// Longest settings string the labels carry, in bytes: every key of the
/// recipe syntax at its longest value fits.
pub const SETTINGS_TEXT_MAX: usize = 256;

/// Fixed words of a [`SINK_LIST`] entry: the state and the two lengths, the
/// cursor, and the drop count.
const LIST_FIXED_WORDS: usize = 3;

/// Fixed words of a [`SINK_SET`] request: the version and the two lengths.
const SET_FIXED_WORDS: usize = 2;

// The longest entry and the longest request fit one message.
const _: () = assert!(
    LIST_FIXED_WORDS + SINK_NAME_MAX / 8 + SETTINGS_TEXT_MAX / 8 <= MSG_DATA_WORDS_MAX
        && SET_FIXED_WORDS + SINK_NAME_MAX / 8 + SETTINGS_TEXT_MAX / 8 <= MSG_DATA_WORDS_MAX
        && SINK_NAME_MAX % 8 == 0
        && SETTINGS_TEXT_MAX % 8 == 0
        && SETTINGS_TEXT_MAX <= 0xFFFF
);

/// A [`SINK_LIST`] request for the sink at `index`, from 0.
#[must_use]
pub fn list_request(index: u64) -> IpcMessage
{
    IpcMessage::builder(SINK_LIST)
        .word(0, u64::from(LOG_LABELS_VERSION))
        .word(1, index)
        .build()
}

/// Read a [`SINK_LIST`] request: the index it asks for.
///
/// # Errors
/// [`QUERY_VERSION_MISMATCH`] for another version.
pub fn decode_list_request(msg: &IpcMessage) -> Result<u64, u64>
{
    if msg.word(0) != u64::from(LOG_LABELS_VERSION)
    {
        return Err(QUERY_VERSION_MISMATCH);
    }
    Ok(msg.word(1))
}

/// One device sink, as a [`SINK_LIST`] reply carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkView<'a>
{
    /// [`SINK_SERVED`], [`SINK_UNSERVED`] or [`SINK_STALLED`].
    pub state: u8,
    /// The `seq` of the next entry the sink considers.
    pub cursor: u64,
    /// The entries the sink owed and lost since logd started.
    pub drops: u64,
    /// The sink's name, at most [`SINK_NAME_MAX`] bytes.
    pub name: &'a [u8],
    /// The sink's settings in the recipe's syntax, at most
    /// [`SETTINGS_TEXT_MAX`] bytes.
    pub settings: &'a [u8],
}

impl SinkView<'_>
{
    /// The [`QUERY_OK`] reply carrying this sink, `more` when a sink follows
    /// it; `None` when the name or the settings are past their limit.
    #[must_use]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`more` is the reply label's more-entries bit (bit 32)"
    )]
    pub fn reply(&self, more: bool) -> Option<IpcMessage>
    {
        if self.name.len() > SINK_NAME_MAX || self.settings.len() > SETTINGS_TEXT_MAX
        {
            return None;
        }
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        let [state, cursor, drops, rest @ ..] = &mut words;
        *state = u64::from(self.state)
            | ((self.name.len() as u64) << 8)
            | ((self.settings.len() as u64) << 16);
        *cursor = self.cursor;
        *drops = self.drops;
        let used = pack_two(rest, self.name, self.settings)?;
        Some(
            IpcMessage::builder(reply_label(QUERY_OK, 1, more))
                .words(0, words.get(..LIST_FIXED_WORDS.saturating_add(used))?)
                .build(),
        )
    }
}

/// The [`QUERY_OK`] reply to a [`SINK_LIST`] request past the last sink: no
/// entry, and no more.
#[must_use]
pub const fn list_end() -> IpcMessage
{
    IpcMessage::new(reply_label(QUERY_OK, 0, false))
}

/// Read a [`SINK_LIST`] reply: its sink and whether another follows, or
/// `None` past the last sink.
///
/// # Errors
/// The reply's status when it is not [`QUERY_OK`]; [`QUERY_INVALID`] for an
/// entry whose lengths are past their limits or the reply's words.
pub fn decode_list_reply(reply: &IpcMessage) -> Result<Option<(SinkView<'_>, bool)>, u64>
{
    match reply_status(reply.label)
    {
        QUERY_OK => (),
        status => return Err(status),
    }
    if reply_count(reply.label) == 0
    {
        return Ok(None);
    }
    let head = reply.word(0);
    let name_len = ((head >> 8) & 0xFF) as usize;
    let settings_len = ((head >> 16) & 0xFFFF) as usize;
    let (name, settings) = unpack_two(reply, LIST_FIXED_WORDS, name_len, settings_len)
        .filter(|_| name_len <= SINK_NAME_MAX && settings_len <= SETTINGS_TEXT_MAX)
        .ok_or(QUERY_INVALID)?;
    Ok(Some((
        SinkView {
            state: (head & 0xFF) as u8,
            cursor: reply.word(1),
            drops: reply.word(2),
            name,
            settings,
        },
        reply_more(reply.label),
    )))
}

/// A [`SINK_SET`] request: a sink's name and a settings string in the
/// recipe's syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetRequest<'a>
{
    pub name: &'a [u8],
    pub settings: &'a [u8],
}

impl<'a> SetRequest<'a>
{
    /// The request message; `None` when the name or the settings are past
    /// their limit.
    #[must_use]
    pub fn message(&self) -> Option<IpcMessage>
    {
        if self.name.len() > SINK_NAME_MAX || self.settings.len() > SETTINGS_TEXT_MAX
        {
            return None;
        }
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        let [version, lengths, rest @ ..] = &mut words;
        *version = u64::from(LOG_LABELS_VERSION);
        *lengths = (self.name.len() as u64) | ((self.settings.len() as u64) << 16);
        let used = pack_two(rest, self.name, self.settings)?;
        Some(
            IpcMessage::builder(SINK_SET)
                .words(0, words.get(..SET_FIXED_WORDS.saturating_add(used))?)
                .build(),
        )
    }

    /// Read a request message.
    ///
    /// # Errors
    /// [`QUERY_VERSION_MISMATCH`] for another version, [`QUERY_INVALID`] for
    /// lengths past their limits or the message's words.
    pub fn decode(msg: &'a IpcMessage) -> Result<Self, u64>
    {
        if msg.word(0) != u64::from(LOG_LABELS_VERSION)
        {
            return Err(QUERY_VERSION_MISMATCH);
        }
        let lengths = msg.word(1);
        let name_len = usize::try_from(lengths & 0xFFFF).map_err(|_| QUERY_INVALID)?;
        let settings_len = usize::try_from((lengths >> 16) & 0xFFFF).map_err(|_| QUERY_INVALID)?;
        if lengths >> 32 != 0 || name_len > SINK_NAME_MAX || settings_len > SETTINGS_TEXT_MAX
        {
            return Err(QUERY_INVALID);
        }
        let (name, settings) =
            unpack_two(msg, SET_FIXED_WORDS, name_len, settings_len).ok_or(QUERY_INVALID)?;
        Ok(Self { name, settings })
    }
}

/// Pack `first`, padded to a whole word, then `second` into `words`; the
/// words used, or `None` when they do not fit.
fn pack_two(words: &mut [u64], first: &[u8], second: &[u8]) -> Option<usize>
{
    let first_words = first.len().div_ceil(8);
    let used = first_words.checked_add(second.len().div_ceil(8))?;
    let (head, tail) = words.get_mut(..used)?.split_at_mut(first_words);
    for (word, chunk) in head.iter_mut().zip(first.chunks(8))
    {
        *word = u64::from_le_bytes(crate::padded_word(chunk));
    }
    for (word, chunk) in tail.iter_mut().zip(second.chunks(8))
    {
        *word = u64::from_le_bytes(crate::padded_word(chunk));
    }
    Some(used)
}

/// The two byte runs [`pack_two`] wrote from word `at` of `msg`.
fn unpack_two(
    msg: &IpcMessage,
    at: usize,
    first_len: usize,
    second_len: usize,
) -> Option<(&[u8], &[u8])>
{
    let first_at = at.checked_mul(8)?;
    let second_at = first_at.checked_add(first_len.div_ceil(8).checked_mul(8)?)?;
    let bytes = msg.data_bytes();
    let first = bytes.get(first_at..)?.get(..first_len)?;
    let second = bytes.get(second_at..)?.get(..second_len)?;
    Some((first, second))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::log_query::{QUERY_DENIED, refusal};

    #[test]
    fn list_request_round_trips()
    {
        assert_eq!(decode_list_request(&list_request(3)), Ok(3));
        let old = IpcMessage::builder(SINK_LIST).word(1, 3).build();
        assert_eq!(decode_list_request(&old), Err(QUERY_VERSION_MISMATCH));
    }

    #[test]
    fn list_reply_round_trips()
    {
        let settings = [b'x'; SETTINGS_TEXT_MAX];
        for view in [
            SinkView {
                state: SINK_STALLED,
                cursor: u64::MAX,
                drops: 17,
                name: b"framebuffer",
                settings: b"level=info,pace=skip",
            },
            SinkView {
                state: SINK_SERVED,
                cursor: 0,
                drops: 0,
                name: &[b'n'; SINK_NAME_MAX],
                settings: &settings,
            },
            SinkView {
                state: SINK_UNSERVED,
                cursor: 1,
                drops: 2,
                name: b"",
                settings: b"",
            },
        ]
        {
            let reply = view.reply(true).expect("fits");
            assert!(reply.word_count() <= MSG_DATA_WORDS_MAX);
            assert_eq!(decode_list_reply(&reply), Ok(Some((view, true))));
        }
        assert_eq!(decode_list_reply(&list_end()), Ok(None));
        assert_eq!(decode_list_reply(&refusal(QUERY_DENIED)), Err(QUERY_DENIED));
    }

    #[test]
    fn list_reply_refuses_overruns()
    {
        let long = [0u8; SETTINGS_TEXT_MAX + 1];
        let view = SinkView {
            state: SINK_SERVED,
            cursor: 0,
            drops: 0,
            name: b"serial",
            settings: &long,
        };
        assert!(view.reply(false).is_none());
        // Lengths past the words the reply carries.
        let reply = IpcMessage::builder(reply_label(QUERY_OK, 1, false))
            .words(0, &[(6 << 8) | (100 << 16), 0, 0, 0])
            .build();
        assert_eq!(decode_list_reply(&reply), Err(QUERY_INVALID));
    }

    #[test]
    fn set_request_round_trips()
    {
        for req in [
            SetRequest {
                name: b"serial",
                settings: b"level=debug",
            },
            SetRequest {
                name: &[b'a'; SINK_NAME_MAX],
                settings: &[b'b'; SETTINGS_TEXT_MAX],
            },
            SetRequest {
                name: b"",
                settings: b"",
            },
        ]
        {
            let msg = req.message().expect("fits");
            assert_eq!(msg.label, SINK_SET);
            assert_eq!(SetRequest::decode(&msg), Ok(req));
        }
    }

    #[test]
    fn set_request_refuses_bad_words()
    {
        let over = SetRequest {
            name: &[0; SINK_NAME_MAX + 1],
            settings: b"",
        };
        assert!(over.message().is_none());
        let version = u64::from(LOG_LABELS_VERSION);
        for lengths in [
            (SINK_NAME_MAX as u64) + 1,
            ((SETTINGS_TEXT_MAX as u64) + 1) << 16,
            1 << 32,
            // Within the limits, past the words carried.
            6 | (40 << 16),
        ]
        {
            let msg = IpcMessage::builder(SINK_SET)
                .word(0, version)
                .word(1, lengths)
                .build();
            assert_eq!(SetRequest::decode(&msg), Err(QUERY_INVALID));
        }
        let msg = IpcMessage::builder(SINK_SET).word(0, version + 1).build();
        assert_eq!(SetRequest::decode(&msg), Err(QUERY_VERSION_MISMATCH));
    }
}
