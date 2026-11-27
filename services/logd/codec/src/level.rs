// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/level.rs

//! The level tag both log receivers render in a console line's prefix
//! ([`crate::prefix`]; [ipc-interface.md](../../docs/ipc-interface.md)
//! § Levels).
//!
//! A level is an `ipc::stream_labels::LEVEL_*` code, one of the eight RFC 5424
//! severities, read from a label with `ipc::stream_labels::level_of`.

use ipc::stream_labels::{
    LEVEL_ALERT, LEVEL_CRITICAL, LEVEL_DEBUG, LEVEL_EMERGENCY, LEVEL_ERROR, LEVEL_NOTICE,
    LEVEL_WARN, level_or_info,
};

/// Columns a tag is padded to: the longest tag, `NOTICE`.
pub const TAG_WIDTH: usize = 6;

/// The tag of `level`: `EMERG`, `ALERT`, `CRIT`, `ERROR`, `WARN`,
/// `NOTICE`, `INFO`, or `DEBUG`; any other code is tagged `INFO`, as a
/// receiver reads it ([`level_or_info`]). At most [`TAG_WIDTH`] bytes.
#[must_use]
pub fn tag(level: u64) -> &'static str
{
    match level_or_info(level)
    {
        LEVEL_EMERGENCY => "EMERG",
        LEVEL_ALERT => "ALERT",
        LEVEL_CRITICAL => "CRIT",
        LEVEL_ERROR => "ERROR",
        LEVEL_WARN => "WARN",
        LEVEL_NOTICE => "NOTICE",
        LEVEL_DEBUG => "DEBUG",
        _ => "INFO",
    }
}

/// The palette index of the colour `level`'s tag is drawn in on a sink that
/// colours it ([sinks.md](../../docs/sinks.md) § Colour), an index of the
/// terminal's 16-colour palette (`shared/ansi`): error to emergency red (1),
/// warning yellow (3), notice bright white (15), debug bright black (8), and
/// informational, and any other code, [`DEFAULT_COLOUR`].
#[must_use]
pub fn colour(level: u64) -> u8
{
    match level_or_info(level)
    {
        LEVEL_EMERGENCY | LEVEL_ALERT | LEVEL_CRITICAL | LEVEL_ERROR => 1,
        LEVEL_WARN => 3,
        LEVEL_NOTICE => 15,
        LEVEL_DEBUG => 8,
        _ => DEFAULT_COLOUR,
    }
}

/// The palette index of the default foreground (`shared/ansi`'s
/// `DEFAULT_FG`), which an informational tag is drawn in and the rest of a
/// line is.
pub const DEFAULT_COLOUR: u8 = 15;

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::stream_labels::{LEVEL_INFO, STREAM_BYTES, level_of};

    // Defect caught: a level rendered with another's tag, or a tag wider
    // than the column the prefix pads to.
    #[test]
    fn each_level_has_its_own_tag_within_the_column()
    {
        let tags = [
            (LEVEL_EMERGENCY, "EMERG"),
            (LEVEL_ALERT, "ALERT"),
            (LEVEL_CRITICAL, "CRIT"),
            (LEVEL_ERROR, "ERROR"),
            (LEVEL_WARN, "WARN"),
            (LEVEL_NOTICE, "NOTICE"),
            (LEVEL_INFO, "INFO"),
            (LEVEL_DEBUG, "DEBUG"),
        ];
        for (level, want) in tags
        {
            assert_eq!(tag(level), want);
            assert!(want.len() <= TAG_WIDTH);
        }
    }

    // Defect caught: a line whose sender gave no level, or a code past the
    // eight, rendered as anything but informational.
    #[test]
    fn a_label_without_a_level_and_an_unknown_code_are_tagged_info()
    {
        assert_eq!(tag(level_of(STREAM_BYTES | (5 << 16))), "INFO");
        assert_eq!(tag(LEVEL_DEBUG + 1), "INFO");
    }

    // Defect caught: a severe tag drawn in a quiet colour, or an
    // informational one coloured, against the approved mapping.
    #[test]
    fn each_level_takes_its_tag_colour()
    {
        for level in [LEVEL_EMERGENCY, LEVEL_ALERT, LEVEL_CRITICAL, LEVEL_ERROR]
        {
            assert_eq!(colour(level), 1);
        }
        assert_eq!(colour(LEVEL_WARN), 3);
        assert_eq!(colour(LEVEL_NOTICE), 15);
        assert_eq!(colour(LEVEL_INFO), DEFAULT_COLOUR);
        assert_eq!(colour(LEVEL_DEBUG), 8);
        assert_eq!(colour(LEVEL_DEBUG + 1), DEFAULT_COLOUR);
    }
}
