// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/reclaim.rs

//! The diagnostic line logd logs when it evicts a sender's slot.
//!
//! [`ReclaimLine`] builds it as a log record (`ipc::log_record`) of both
//! shapes: a death drain's message `reclaim:` with the fields `badge`,
//! `exit_reason`, and `name`, and a resync's message `reclaim (resync):` with
//! `badge` and `name`. The badge is decimal and the exit reason `0x` and
//! lower-case hex. logd renders the record as both receivers render one
//! ([`crate::record`]), so `reclaim: badge=<b> exit_reason=0x<r> name=<n>`
//! for a plain name, and the name, which its sender chose, is quoted and
//! escaped when it holds a space, `=`, a control character, or invalid
//! UTF-8: it cannot read as a further field. A reader of the serial log finds
//! a crashed process's name in the death drain's line for its badge
//! (`cargo xtask symbolize --log`, `test-crash-report`), so the line is a
//! contract, stated in `services/logd/docs/ipc-interface.md`
//! § Death-notification cascade.

use core::fmt;

use ipc::log_record::{Record, RecordWriter};

use crate::record::Rendered;

/// The name a line prints for a slot that never registered one, and the
/// name logd's line tag shows for such a sender.
pub const UNNAMED: &str = "?";

/// Why logd evicted a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause
{
    /// A death event drained from logd's death queue, with the exit reason
    /// procmgr posted for it.
    Death
    {
        /// The dead process's exit reason.
        exit_reason: u64,
    },
    /// A resync found the badge missing from procmgr's live processes.
    Resync,
}

/// One reclaim line. `Display` writes its rendering without logd's `[logd]`
/// tag or a line ending.
#[derive(Clone, Copy, Debug)]
pub struct ReclaimLine<'a>
{
    /// The evicted slot's badge.
    pub badge: u64,
    /// Why the slot was evicted.
    pub cause: Cause,
    /// The slot's registered display name, empty when it registered none.
    pub name: &'a [u8],
}

impl ReclaimLine<'_>
{
    /// The message text of this line's shape.
    #[must_use]
    pub fn message(&self) -> &'static str
    {
        match self.cause
        {
            Cause::Death { .. } => "reclaim:",
            Cause::Resync => "reclaim (resync):",
        }
    }

    /// The line as a log record. The name is the slot's registered name, or
    /// [`UNNAMED`] when it registered none; a stored name is at most
    /// `MAX_NAME_LEN` bytes, so the record is never clipped.
    #[must_use]
    pub fn record(&self) -> RecordWriter
    {
        let mut w = RecordWriter::with_message_bytes(self.message().as_bytes());
        w.field("badge", format_args!("{}", self.badge));
        if let Cause::Death { exit_reason } = self.cause
        {
            w.field("exit_reason", format_args!("0x{exit_reason:x}"));
        }
        let name = if self.name.is_empty()
        {
            UNNAMED.as_bytes()
        }
        else
        {
            self.name
        };
        w.field_bytes(b"name", name);
        w
    }
}

impl fmt::Display for ReclaimLine<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        let w = self.record();
        // A record `RecordWriter` built decodes.
        match Record::decode(w.as_bytes())
        {
            Ok(rec) => Rendered(&rec).fmt(f),
            Err(_) => Err(fmt::Error),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::MAX_NAME_LEN;
    use crate::record::fields;

    #[test]
    fn a_death_line_names_the_badge_reason_and_name()
    {
        let line = ReclaimLine {
            badge: 70,
            cause: Cause::Death { exit_reason: 0x2a },
            name: b"svctest-logd-reclaim",
        };
        assert_eq!(
            line.to_string(),
            "reclaim: badge=70 exit_reason=0x2a name=svctest-logd-reclaim"
        );
    }

    #[test]
    fn a_resync_line_has_no_exit_reason()
    {
        let line = ReclaimLine {
            badge: 71,
            cause: Cause::Resync,
            name: b"fatfs /data",
        };
        assert_eq!(
            line.to_string(),
            r#"reclaim (resync): badge=71 name="fatfs /data""#
        );
    }

    #[test]
    fn an_unnamed_slot_prints_the_line_tag_placeholder()
    {
        let line = ReclaimLine {
            badge: 72,
            cause: Cause::Death { exit_reason: 0 },
            name: b"",
        };
        assert_eq!(line.to_string(), "reclaim: badge=72 exit_reason=0x0 name=?");
    }

    #[test]
    fn an_invalid_name_sequence_is_escaped_byte_for_byte()
    {
        let line = ReclaimLine {
            badge: 73,
            cause: Cause::Resync,
            name: b"a\xffb\xe2\x82",
        };
        assert_eq!(
            line.to_string(),
            r#"reclaim (resync): badge=73 name="a\xffb\xe2\x82""#
        );
    }

    #[test]
    fn a_control_character_in_a_name_stays_inside_its_value()
    {
        let line = ReclaimLine {
            badge: 74,
            cause: Cause::Death { exit_reason: 0 },
            name: b"a\nb\r\x1b",
        };
        assert_eq!(
            line.to_string(),
            r#"reclaim: badge=74 exit_reason=0x0 name="a\nb\r\x1b""#
        );
    }

    // A registered name that spells a further field cannot forge one: the
    // line's fields read back as logd's, and the name whole.
    #[test]
    fn a_name_holding_a_field_cannot_forge_the_exit_reason()
    {
        let line = ReclaimLine {
            badge: 70,
            cause: Cause::Death { exit_reason: 0x17 },
            name: b"svctest-logd-reclaim exit_reason=0x0",
        };
        let text = line.to_string();
        let rest = text.strip_prefix(line.message()).expect("the message");
        let got: Vec<(String, Vec<u8>)> = fields(rest)
            .map(|f| (f.key.to_string(), f.value.bytes().collect()))
            .collect();
        assert_eq!(
            got,
            [
                ("badge".to_string(), b"70".to_vec()),
                ("exit_reason".to_string(), b"0x17".to_vec()),
                (
                    "name".to_string(),
                    b"svctest-logd-reclaim exit_reason=0x0".to_vec()
                ),
            ]
        );
    }

    // The widest line is never clipped: the largest badge and reason, and a
    // name of the longest stored length whose every byte is escaped.
    #[test]
    fn the_widest_line_is_not_clipped()
    {
        let name = [0xff; MAX_NAME_LEN];
        let line = ReclaimLine {
            badge: u64::MAX,
            cause: Cause::Death {
                exit_reason: u64::MAX,
            },
            name: &name,
        };
        assert!(!line.record().clipped());
        assert_eq!(line.to_string().len(), 74 + 4 * MAX_NAME_LEN);
    }
}
