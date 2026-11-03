// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/reclaim.rs

//! The diagnostic line logd logs when it evicts a sender's slot.
//!
//! [`ReclaimLine`] formats both shapes: a death drain's
//! `reclaim: badge=<b> exit_reason=0x<r> name=<n>` and a resync's
//! `reclaim (resync): badge=<b> name=<n>`. The badge is decimal, the exit
//! reason lower-case hex, and the name, the last field, runs to the end of
//! the line. `cargo xtask test-logd-reclaim` reads the death drain's shape
//! from the serial log, so the shape is a contract, stated in
//! `services/logd/docs/ipc-interface.md` § Death-notification cascade.

use core::fmt::{self, Write as _};

/// The name a line prints for a slot that never registered one: the `?`
/// logd's line tag shows for such a sender.
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

/// One reclaim line. `Display` writes it without logd's `[logd]` tag or a
/// line ending.
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

impl fmt::Display for ReclaimLine<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self.cause
        {
            Cause::Death { exit_reason } => write!(
                f,
                "reclaim: badge={} exit_reason=0x{exit_reason:x} name=",
                self.badge
            )?,
            Cause::Resync => write!(f, "reclaim (resync): badge={} name=", self.badge)?,
        }
        write_name(f, self.name)
    }
}

/// Write `name`, or [`UNNAMED`] when it is empty. A registered name is
/// sender input and need not be UTF-8: each invalid sequence is written as
/// U+FFFD.
fn write_name(f: &mut fmt::Formatter<'_>, name: &[u8]) -> fmt::Result
{
    if name.is_empty()
    {
        return f.write_str(UNNAMED);
    }
    for chunk in name.utf8_chunks()
    {
        f.write_str(chunk.valid())?;
        if !chunk.invalid().is_empty()
        {
            f.write_char(char::REPLACEMENT_CHARACTER)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::{BoundedStr, LINE_BUF_SIZE, MAX_NAME_LEN};

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
            "reclaim (resync): badge=71 name=fatfs /data"
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
    fn each_invalid_name_sequence_becomes_one_replacement_character()
    {
        let line = ReclaimLine {
            badge: 73,
            cause: Cause::Resync,
            name: b"a\xffb\xe2\x82",
        };
        assert_eq!(
            line.to_string(),
            "reclaim (resync): badge=73 name=a\u{fffd}b\u{fffd}"
        );
    }

    // The widest line, with the largest badge and reason and a name of the
    // longest stored length, fits logd's diagnostic buffer untruncated.
    #[test]
    fn the_widest_line_fits_the_diagnostic_buffer()
    {
        let name = [b'n'; MAX_NAME_LEN];
        let line = ReclaimLine {
            badge: u64::MAX,
            cause: Cause::Death {
                exit_reason: u64::MAX,
            },
            name: &name,
        };
        let mut buf = BoundedStr::<LINE_BUF_SIZE>::new();
        write!(buf, "{line}").expect("BoundedStr writes never fail");
        assert_eq!(buf.as_str(), line.to_string());
    }
}
