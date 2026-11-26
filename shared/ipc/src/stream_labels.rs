// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/stream_labels.rs

//! IPC labels for the system log stream: the badged SEND cap on the master
//! log endpoint each process holds (`ProcessInfo.log_send_cap`).
//!
//! Text is a byte stream. The producer issues
//! `ipc_call(cap, label=STREAM_BYTES | (byte_len << 16) | level_bits(level), …)`
//! per write (chunked at `MSG_DATA_WORDS_MAX * 8` per call). The receiver
//! reads `byte_len.div_ceil(8)` data words from its IPC buffer and unpacks
//! `byte_len` bytes. The receiver replies with label 0 and no payload to
//! unblock the writer, or with [`stream_labels::NAME_UNKNOWN`](crate::stream_labels::NAME_UNKNOWN) to a message
//! it did not consume (bit 36 below).
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
//! - Bits 32-35 ([`LEVEL_SHIFT`], [`LEVEL_MASK`]): the log level, the RFC 5424
//!   severity plus one ([`level_bits`]), 0 when the sender gives none, which
//!   reads as informational ([`level_of`]). A text line takes the level of
//!   the message that carries its first byte
//!   (`services/logd/docs/ipc-interface.md` § `stream_labels::STREAM_BYTES`);
//!   a record carries its own.
//! - Bit 36 ([`SENDER_NAMED`]): the sender has registered a display name
//!   ([`STREAM_REGISTER_NAME`]), so a receiver that holds none for its badge
//!   answers [`NAME_UNKNOWN`] and consumes nothing.

/// Base label ID for stream-bytes messages (bits 0-15).
pub const STREAM_BYTES: u64 = 10;
/// Shift of the level field in a [`STREAM_BYTES`] or [`STREAM_RECORD`] label.
pub const LEVEL_SHIFT: u32 = 32;
/// Mask of the level field, applied after [`LEVEL_SHIFT`].
pub const LEVEL_MASK: u64 = 0xF;

// The levels are the eight RFC 5424 severities, each code the severity's
// number, from the most severe to the least (`services/logd/docs/ipc-interface.md`
// § Levels).

/// RFC 5424 severity 0, emergency: the system cannot go on.
pub const LEVEL_EMERGENCY: u64 = 0;
/// RFC 5424 severity 1, alert: an operator must act now.
pub const LEVEL_ALERT: u64 = 1;
/// RFC 5424 severity 2, critical: a component is lost and the system
/// degrades around it.
pub const LEVEL_CRITICAL: u64 = 2;
/// RFC 5424 severity 3, error: work was lost or the component cannot go on.
pub const LEVEL_ERROR: u64 = 3;
/// RFC 5424 severity 4, warning: an unexpected condition the component
/// handles.
pub const LEVEL_WARN: u64 = 4;
/// RFC 5424 severity 5, notice: a significant normal event, logged once.
pub const LEVEL_NOTICE: u64 = 5;
/// RFC 5424 severity 6, informational: normal operation, the level of a bare
/// `seraph::log!` and of a label that gives none.
pub const LEVEL_INFO: u64 = 6;
/// RFC 5424 severity 7, debug: detail for diagnosing a component.
pub const LEVEL_DEBUG: u64 = 7;

/// `level` when it is one of the eight `LEVEL_*` codes, [`LEVEL_INFO`] for any
/// other code, as a receiver reads a label that carries none of them.
#[must_use]
pub const fn level_or_info(level: u64) -> u64
{
    if level <= LEVEL_DEBUG
    {
        level
    }
    else
    {
        LEVEL_INFO
    }
}

/// The level field of a [`STREAM_BYTES`] or [`STREAM_RECORD`] label carrying
/// `level`, a `LEVEL_*` code, already shifted: the code plus one, so that a
/// field of 0 means that no level was given. A code past [`LEVEL_DEBUG`]
/// gives the field 0, which [`level_of`] reads as [`LEVEL_INFO`].
#[must_use]
pub const fn level_bits(level: u64) -> u64
{
    if level <= LEVEL_DEBUG
    {
        // `level` is at most `LEVEL_DEBUG`, so the sum fits the field.
        level.saturating_add(1) << LEVEL_SHIFT
    }
    else
    {
        0
    }
}

/// The level a [`STREAM_BYTES`] or [`STREAM_RECORD`] label carries, a
/// `LEVEL_*` code from [`LEVEL_EMERGENCY`] to [`LEVEL_DEBUG`]: the field
/// less one, with a field of 0 (no level given) and the unassigned fields 9
/// to 15 read as [`LEVEL_INFO`].
#[must_use]
pub const fn level_of(label: u64) -> u64
{
    match (label >> LEVEL_SHIFT) & LEVEL_MASK
    {
        field @ 1..=8 => field.saturating_sub(1),
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
pub const SENDER_NAMED: u64 = 1 << 36;

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
/// its byte length in bits 16-31 and its level in bits 32-35, as on
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

#[cfg(test)]
mod tests
{
    use crate::stream_labels;

    /// The eight levels, most severe first.
    const LEVELS: [u64; 8] = [
        stream_labels::LEVEL_EMERGENCY,
        stream_labels::LEVEL_ALERT,
        stream_labels::LEVEL_CRITICAL,
        stream_labels::LEVEL_ERROR,
        stream_labels::LEVEL_WARN,
        stream_labels::LEVEL_NOTICE,
        stream_labels::LEVEL_INFO,
        stream_labels::LEVEL_DEBUG,
    ];

    // Defect caught: a severity that reads back as another, emergency (0)
    // above all, which a field without the offset would confuse with a label
    // that gives no level.
    #[test]
    fn each_severity_reads_back_from_its_label()
    {
        use stream_labels::{STREAM_BYTES, level_bits, level_of};
        for level in LEVELS
        {
            let label = STREAM_BYTES | (40 << 16) | level_bits(level);
            assert_eq!(level_of(label), level);
            // The level field leaves the id and the length intact.
            assert_eq!(label & 0xFFFF, STREAM_BYTES);
            assert_eq!((label >> 16) & 0xFFFF, 40);
        }
    }

    // Defect caught: a label that gives no level, or an unassigned field,
    // read as emergency or as any level but informational.
    #[test]
    fn a_label_without_a_level_and_an_unassigned_field_read_as_info()
    {
        use stream_labels::{
            LEVEL_DEBUG, LEVEL_INFO, LEVEL_SHIFT, STREAM_BYTES, level_bits, level_of, level_or_info,
        };
        assert_eq!(level_of(STREAM_BYTES | (40 << 16)), LEVEL_INFO);
        for field in 9..=15u64
        {
            assert_eq!(level_of(STREAM_BYTES | (field << LEVEL_SHIFT)), LEVEL_INFO);
        }
        // A code past debug is kept as info, and sent as no level.
        assert_eq!(level_or_info(LEVEL_DEBUG + 1), LEVEL_INFO);
        assert_eq!(level_or_info(LEVEL_DEBUG), LEVEL_DEBUG);
        assert_eq!(level_bits(LEVEL_DEBUG + 1), 0);
        assert_eq!(level_bits(u64::MAX), 0);
    }

    // Defect caught: a named-sender bit inside the id, length, or level field,
    // which would change a line's label, length, or level, or a full field
    // that reads as the bit.
    #[test]
    fn the_named_sender_bit_lies_outside_every_other_label_field()
    {
        use stream_labels::{
            LEVEL_MASK, LEVEL_SHIFT, LEVEL_WARN, SENDER_NAMED, STREAM_RECORD, level_bits, level_of,
            sender_named,
        };
        let full = 0xFFFF | (0xFFFF << 16) | (LEVEL_MASK << LEVEL_SHIFT);
        assert!(!sender_named(full));
        assert_eq!(full & SENDER_NAMED, 0);
        let label = STREAM_RECORD | (37 << 16) | level_bits(LEVEL_WARN) | SENDER_NAMED;
        assert!(sender_named(label));
        assert_eq!(label & 0xFFFF, STREAM_RECORD);
        assert_eq!((label >> 16) & 0xFFFF, 37);
        assert_eq!(level_of(label), LEVEL_WARN);
    }
}
