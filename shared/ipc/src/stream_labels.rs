// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/stream_labels.rs

//! IPC labels for the system log stream: the badged SEND cap on the master
//! log endpoint each process holds (`ProcessInfo.log_send_cap`).
//!
//! Text is a byte stream. The producer issues
//! `ipc_call(cap, label=STREAM_BYTES | (byte_len << 16) | (level << 32), …)`
//! per write (chunked at `MSG_DATA_WORDS_MAX * 8` per call). The receiver
//! reads `byte_len.div_ceil(8)` data words from its IPC buffer and unpacks
//! `byte_len` bytes. The receiver replies with label 0 and no payload to
//! unblock the writer, or with [`stream_labels::NAME_UNKNOWN`](crate::stream_labels::NAME_UNKNOWN) to a message
//! it did not consume (bit 35 below).
//! No multi-chunk reassembly framing on the wire — line buffering
//! (e.g. logd's `[name]` per-newline prefix) lives in the receiver.
//!
//! A record ([`STREAM_RECORD`]) is one complete log line whose message text
//! and fields are framed apart, in one message ([`crate::log_record`]).
//!
//! # Label encoding
//! - Bits 0-15: label ID ([`STREAM_BYTES`] or [`STREAM_RECORD`])
//! - Bits 16-31: byte length of the payload in this call (0..=512; at most
//!   [`crate::log_record::RECORD_MAX_BYTES`] for a record).
//! - Bits 32-34 ([`LEVEL_SHIFT`], [`LEVEL_MASK`]): the log level, a
//!   `LEVEL_*` code. A text line takes the level of the message that
//!   carries its first byte (`services/logd/docs/ipc-interface.md`
//!   § `stream_labels::STREAM_BYTES`); a record carries its own.
//! - Bit 35 ([`SENDER_NAMED`]): the sender has registered a display name
//!   ([`STREAM_REGISTER_NAME`]), so a receiver that holds none for its badge
//!   answers [`NAME_UNKNOWN`] and consumes nothing.

/// Base label ID for stream-bytes messages (bits 0-15).
pub const STREAM_BYTES: u64 = 10;
/// Shift of the level field in a [`STREAM_BYTES`] label.
pub const LEVEL_SHIFT: u32 = 32;
/// Mask of the level field, applied after [`LEVEL_SHIFT`].
pub const LEVEL_MASK: u64 = 0x7;
/// No level given (a sender that sets none, such as init's own log
/// writer): read as [`LEVEL_INFO`].
pub const LEVEL_UNSPECIFIED: u64 = 0;
/// A failure: work was lost or the process cannot go on.
pub const LEVEL_ERROR: u64 = 1;
/// An unexpected condition the process handles.
pub const LEVEL_WARN: u64 = 2;
/// Normal operation: the level of a bare `seraph::log!`.
pub const LEVEL_INFO: u64 = 3;
/// Detail for diagnosing a component.
pub const LEVEL_DEBUG: u64 = 4;
/// Step-by-step detail.
pub const LEVEL_TRACE: u64 = 5;

/// The level a [`STREAM_BYTES`] or [`STREAM_RECORD`] label carries:
/// [`LEVEL_ERROR`] to [`LEVEL_TRACE`], with [`LEVEL_UNSPECIFIED`] and the
/// unassigned codes 6 and 7 read as [`LEVEL_INFO`].
#[must_use]
pub const fn level_of(label: u64) -> u64
{
    match (label >> LEVEL_SHIFT) & LEVEL_MASK
    {
        code @ LEVEL_ERROR..=LEVEL_TRACE => code,
        _ => LEVEL_INFO,
    }
}

/// [`STREAM_BYTES`] and [`STREAM_RECORD`] label bit: the sender has
/// registered a display name ([`STREAM_REGISTER_NAME`]) on the cap it
/// sends on. logd answers a message carrying it, from a badge whose slot
/// holds no name, with [`NAME_UNKNOWN`] and consumes nothing: its table
/// lost the name, as a restarted logd's fresh table has
/// (`services/logd/docs/ipc-interface.md`
/// § `stream_labels::STREAM_REGISTER_NAME`). init-logd ignores it.
pub const SENDER_NAMED: u64 = 1 << 35;

/// Whether a [`STREAM_BYTES`] or [`STREAM_RECORD`] label carries
/// [`SENDER_NAMED`].
#[must_use]
pub const fn sender_named(label: u64) -> bool
{
    label & SENDER_NAMED != 0
}

/// [`STREAM_BYTES`] and [`STREAM_RECORD`] reply label: the message
/// carries [`SENDER_NAMED`] and the receiver holds no name for the
/// sender's badge, so it consumed nothing. The sender registers its name
/// again and sends the message once more without the bit.
pub const NAME_UNKNOWN: u64 = 2;
/// Register (or update) the display name for the sender's log stream.
///
/// Payload: name bytes via `.bytes(0, name)` with byte length in bits
/// 16-31 of the label, same encoding as `STREAM_BYTES`. The mediator
/// looks up the slot for the sender's badge (delivered by the kernel
/// from the badged SEND cap) and stores the bytes as that slot's
/// display name, truncated to the mediator's per-slot buffer.
/// Collision handling is the mediator's: init's bootstrap log thread
/// stores a colliding name with a `.2` / `.3` / … suffix, while logd
/// stores names as given (`services/logd/docs/ipc-interface.md`
/// § `stream_labels::STREAM_REGISTER_NAME`).
pub const STREAM_REGISTER_NAME: u64 = 11;

/// One log record: a message and its fields, framed apart
/// ([`crate::log_record`]). Payload: the record via `.bytes(0, record)`,
/// its byte length in bits 16-31 and its level in bits 32-34, as on
/// [`STREAM_BYTES`]. A record is complete in its message, so it does not
/// join the sender's partial text line. The receiver replies
/// [`RECORD_ACCEPTED`], or [`RECORD_REJECTED`] for a payload that is not a
/// record, which it neither renders nor stores
/// (`services/logd/docs/ipc-interface.md`
/// § `stream_labels::STREAM_RECORD`).
pub const STREAM_RECORD: u64 = 15;
/// [`STREAM_RECORD`] reply label: the record was rendered and stored.
pub const RECORD_ACCEPTED: u64 = 0;
/// [`STREAM_RECORD`] reply label: the payload is not a record (its
/// length is over the limit or disagrees with the label, or
/// `log_record::Record::decode` refuses it).
pub const RECORD_REJECTED: u64 = 1;
