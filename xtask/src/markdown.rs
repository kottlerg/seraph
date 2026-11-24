// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/markdown.rs

//! Fenced code blocks of Markdown text, as `lint-docs` and the pull-request
//! and Issue checks tell prose from quoted code.

/// Every line with its zero-based index and whether it is prose: outside a
/// fenced code block, and no fence's opening or closing line. A fence opens
/// with a run of three or more backticks or tildes (a backtick run whose info
/// string contains a backtick is not a fence) and closes only on a run of the
/// same character at least as long with nothing after it but whitespace (a
/// line carrying an info string is content).
pub fn marked_lines(text: &str) -> impl Iterator<Item = (usize, &str, bool)>
{
    let mut open: Option<(char, usize)> = None;
    text.lines().enumerate().map(move |(idx, line)| {
        let trimmed = line.trim_start();
        let fence = trimmed
            .chars()
            .next()
            .filter(|c| *c == '`' || *c == '~')
            .map(|c| {
                let after = trimmed.trim_start_matches(c);
                (c, trimmed.chars().take_while(|x| *x == c).count(), after)
            });
        let prose = match (open, fence)
        {
            (None, Some((c, n, after))) if n >= 3 && (c != '`' || !after.contains('`')) =>
            {
                open = Some((c, n));
                false
            }
            (Some((oc, on)), Some((c, n, after)))
                if c == oc && n >= on && after.trim().is_empty() =>
            {
                open = None;
                false
            }
            (Some(_), _) => false,
            (None, _) => true,
        };
        (idx, line, prose)
    })
}
