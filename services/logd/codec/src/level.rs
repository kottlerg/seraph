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

/// The colours a level tag is drawn in, each an index of the terminal's
/// 16-colour palette (`shared/ansi`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TagColour
{
    /// The text's colour.
    pub fg: u8,
    /// The colour behind the text.
    pub bg: u8,
}

/// The colours `level`'s tag is drawn in on a sink that colours it
/// ([sinks.md](../../docs/sinks.md) § Colour): emergency and alert bright
/// white (15) on red (1), critical and error red (1), warning yellow (3),
/// notice bright cyan (14), debug bright black (8), each of these on the
/// default background, and informational, and any other code,
/// [`DEFAULT_COLOUR`].
#[must_use]
pub fn colour(level: u64) -> TagColour
{
    let fg = |fg| TagColour {
        fg,
        bg: DEFAULT_COLOUR.bg,
    };
    match level_or_info(level)
    {
        LEVEL_EMERGENCY | LEVEL_ALERT => TagColour { fg: 15, bg: 1 },
        LEVEL_CRITICAL | LEVEL_ERROR => fg(1),
        LEVEL_WARN => fg(3),
        LEVEL_NOTICE => fg(14),
        LEVEL_DEBUG => fg(8),
        _ => DEFAULT_COLOUR,
    }
}

/// The default colours (`shared/ansi`'s `DEFAULT_FG` on `DEFAULT_BG`),
/// which an informational tag is drawn in and the rest of a line is.
pub const DEFAULT_COLOUR: TagColour = TagColour { fg: 15, bg: 0 };

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

    // Defect caught: a level's tag drawn in another level's colours against
    // the approved mapping: a severe tag in a quiet colour, emergency or
    // alert without their red background, an informational tag coloured, or
    // a notice tag drawn like an informational one (the default foreground
    // is bright white).
    #[test]
    fn each_level_takes_its_tag_colour()
    {
        let on_default = |fg| TagColour { fg, bg: 0 };
        let cases = [
            (LEVEL_EMERGENCY, TagColour { fg: 15, bg: 1 }),
            (LEVEL_ALERT, TagColour { fg: 15, bg: 1 }),
            (LEVEL_CRITICAL, on_default(1)),
            (LEVEL_ERROR, on_default(1)),
            (LEVEL_WARN, on_default(3)),
            (LEVEL_NOTICE, on_default(14)),
            (LEVEL_INFO, DEFAULT_COLOUR),
            (LEVEL_DEBUG, on_default(8)),
            (LEVEL_DEBUG + 1, DEFAULT_COLOUR),
        ];
        for (level, expected) in cases
        {
            assert_eq!(colour(level), expected, "level {level}");
        }
        assert_eq!(DEFAULT_COLOUR, TagColour { fg: 15, bg: 0 });
        assert_ne!(colour(LEVEL_NOTICE), DEFAULT_COLOUR);
    }
}
