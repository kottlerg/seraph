// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/level.rs

//! The log level both receivers render: the tag a line of each level carries
//! after its `[name]` prefix
//! ([ipc-interface.md](../../docs/ipc-interface.md)
//! § `stream_labels::STREAM_BYTES`).
//!
//! A level is an `ipc::stream_labels::LEVEL_*` code, read from a
//! `STREAM_BYTES` label with `ipc::stream_labels::level_of`.

use ipc::stream_labels::{LEVEL_DEBUG, LEVEL_ERROR, LEVEL_TRACE, LEVEL_WARN};

/// The tag rendered between a line's `[name] ` prefix and its text, followed
/// by one space; `None` for the info level and any code `level_of` does not
/// return, whose lines render untagged, as every line did before levels
/// existed.
#[must_use]
pub fn tag(level: u64) -> Option<&'static str>
{
    match level
    {
        LEVEL_ERROR => Some("ERROR"),
        LEVEL_WARN => Some("WARN"),
        LEVEL_DEBUG => Some("DEBUG"),
        LEVEL_TRACE => Some("TRACE"),
        _ => None,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::stream_labels::{LEVEL_INFO, LEVEL_UNSPECIFIED, STREAM_BYTES, level_of};

    #[test]
    fn every_level_but_info_is_tagged()
    {
        assert_eq!(tag(LEVEL_ERROR), Some("ERROR"));
        assert_eq!(tag(LEVEL_WARN), Some("WARN"));
        assert_eq!(tag(LEVEL_DEBUG), Some("DEBUG"));
        assert_eq!(tag(LEVEL_TRACE), Some("TRACE"));
        assert_eq!(tag(LEVEL_INFO), None);
    }

    #[test]
    fn a_label_without_a_level_renders_untagged()
    {
        assert_eq!(tag(level_of(STREAM_BYTES | (5 << 16))), None);
        assert_eq!(tag(LEVEL_UNSPECIFIED), None);
    }
}
