// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/log_flush.rs

//! The wire format of logd's flush barrier,
//! [`LOG_FLUSH`](crate::log_labels::LOG_FLUSH)
//! (`services/logd/docs/ipc-interface.md` § Flush barrier).
//!
//! A request carries [`LOG_LABELS_VERSION`](crate::LOG_LABELS_VERSION) in
//! `data[0]`, whether it asks again for a token in `data[1]` (0 for a new
//! flush, 1 to ask again), and that token in `data[2]`. A reply's label is its
//! status alone: [`FLUSHED`] or [`FLUSH_PENDING`] with the token in `data[0]`
//! and, for [`FLUSH_PENDING`], the retry hint in milliseconds in `data[1]`, or
//! a refusal with no data. The token is logd's: a client hands it back
//! unread, and it holds only for the logd instance that issued it. An
//! instance reads every token as its own number, so one from before a logd
//! restart is answered [`FLUSHED`] while it is above every number the new
//! instance has issued, and is otherwise waited on as the new instance's.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use crate::log_labels::LOG_FLUSH;
use crate::{IpcMessage, LOG_LABELS_VERSION};

/// Reply status: every line before the token is written, or no sink holds
/// the log for it. `0`, so an empty reply reads as flushed.
pub const FLUSHED: u64 = 0;
/// Reply status: lines before the token are still to be written; ask again
/// with the token after the retry hint.
pub const FLUSH_PENDING: u64 = 1;
/// Reply status: the request's badge carries no
/// [`LOG_FLUSH_AUTHORITY`](crate::log_labels::LOG_FLUSH_AUTHORITY).
pub const FLUSH_DENIED: u64 = 2;
/// Reply status: `data[0]` is not the receiver's
/// [`LOG_LABELS_VERSION`](crate::LOG_LABELS_VERSION).
pub const FLUSH_VERSION_MISMATCH: u64 = 3;
/// Reply status: `data[1]` is neither 0 nor 1.
pub const FLUSH_INVALID: u64 = 4;

/// `data[1]` of a request that asks again for the token in `data[2]`.
const AGAIN: u64 = 1;

/// A [`LOG_FLUSH`] request: a new flush (`None`), or the token a reply gave,
/// to ask again.
#[must_use]
pub fn request(token: Option<u64>) -> IpcMessage
{
    let (again, token) = match token
    {
        Some(t) => (AGAIN, t),
        None => (0, 0),
    };
    IpcMessage::builder(LOG_FLUSH)
        .word(0, u64::from(LOG_LABELS_VERSION))
        .word(1, again)
        .word(2, token)
        .build()
}

/// Read a [`LOG_FLUSH`] request: the token it asks again for, `None` for a
/// new flush, or the refusal status.
///
/// # Errors
/// [`FLUSH_VERSION_MISMATCH`] for another version, [`FLUSH_INVALID`] for a
/// `data[1]` other than 0 or 1.
pub fn decode_request(msg: &IpcMessage) -> Result<Option<u64>, u64>
{
    if msg.word(0) != u64::from(LOG_LABELS_VERSION)
    {
        return Err(FLUSH_VERSION_MISMATCH);
    }
    match msg.word(1)
    {
        0 => Ok(None),
        AGAIN => Ok(Some(msg.word(2))),
        _ => Err(FLUSH_INVALID),
    }
}

/// logd's answer to a [`LOG_FLUSH`] request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushAnswer
{
    /// The log is flushed for `token` ([`FLUSHED`]).
    Flushed
    {
        token: u64
    },
    /// It is not yet: ask again with `token` after `retry_ms` milliseconds
    /// ([`FLUSH_PENDING`]).
    Pending
    {
        token: u64, retry_ms: u32
    },
}

impl FlushAnswer
{
    /// The reply that carries the answer.
    #[must_use]
    pub fn reply(self) -> IpcMessage
    {
        match self
        {
            Self::Flushed { token } => IpcMessage::builder(FLUSHED).word(0, token).build(),
            Self::Pending { token, retry_ms } => IpcMessage::builder(FLUSH_PENDING)
                .word(0, token)
                .word(1, u64::from(retry_ms))
                .build(),
        }
    }

    /// Read a reply: the answer, or the refusal status. A retry hint past
    /// `u32::MAX` milliseconds reads as `u32::MAX`.
    ///
    /// # Errors
    /// The reply's status when it is neither [`FLUSHED`] nor
    /// [`FLUSH_PENDING`].
    pub fn decode(reply: &IpcMessage) -> Result<Self, u64>
    {
        match reply.label
        {
            FLUSHED => Ok(Self::Flushed {
                token: reply.word(0),
            }),
            FLUSH_PENDING => Ok(Self::Pending {
                token: reply.word(0),
                retry_ms: u32::try_from(reply.word(1)).unwrap_or(u32::MAX),
            }),
            status => Err(status),
        }
    }
}

/// A refusal: `status` and no data.
#[must_use]
pub const fn refusal(status: u64) -> IpcMessage
{
    IpcMessage::new(status)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn request_round_trips()
    {
        let start = request(None);
        assert_eq!(start.label, LOG_FLUSH);
        assert_eq!(decode_request(&start), Ok(None));
        // Token 0 is a token: asking again for it is not a new flush.
        assert_eq!(decode_request(&request(Some(0))), Ok(Some(0)));
        assert_eq!(decode_request(&request(Some(u64::MAX))), Ok(Some(u64::MAX)));
    }

    #[test]
    fn request_refuses_bad_words()
    {
        let msg = IpcMessage::builder(LOG_FLUSH)
            .word(0, u64::from(LOG_LABELS_VERSION) + 1)
            .build();
        assert_eq!(decode_request(&msg), Err(FLUSH_VERSION_MISMATCH));
        let msg = IpcMessage::builder(LOG_FLUSH)
            .word(0, u64::from(LOG_LABELS_VERSION))
            .word(1, 2)
            .build();
        assert_eq!(decode_request(&msg), Err(FLUSH_INVALID));
    }

    #[test]
    fn answer_round_trips()
    {
        for answer in [
            FlushAnswer::Flushed { token: 0 },
            FlushAnswer::Flushed { token: u64::MAX },
            FlushAnswer::Pending {
                token: 41,
                retry_ms: 1,
            },
            FlushAnswer::Pending {
                token: 7,
                retry_ms: u32::MAX,
            },
        ]
        {
            assert_eq!(FlushAnswer::decode(&answer.reply()), Ok(answer));
        }
    }

    // An empty reply, which a receiver that does not serve the label gives,
    // reads as flushed, so a client never waits on one.
    #[test]
    fn empty_reply_reads_as_flushed()
    {
        assert_eq!(
            FlushAnswer::decode(&IpcMessage::new(0)),
            Ok(FlushAnswer::Flushed { token: 0 })
        );
    }

    #[test]
    fn refusals_decode_as_their_status()
    {
        for status in [FLUSH_DENIED, FLUSH_VERSION_MISMATCH, FLUSH_INVALID]
        {
            assert_eq!(FlushAnswer::decode(&refusal(status)), Err(status));
        }
    }

    #[test]
    fn oversized_hint_reads_as_the_largest()
    {
        let reply = IpcMessage::builder(FLUSH_PENDING)
            .word(0, 3)
            .word(1, u64::MAX)
            .build();
        assert_eq!(
            FlushAnswer::decode(&reply),
            Ok(FlushAnswer::Pending {
                token: 3,
                retry_ms: u32::MAX
            })
        );
    }
}
