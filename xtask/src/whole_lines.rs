// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/whole_lines.rs

//! The `cargo xtask run --whole-lines <TAG>` check of a passing run's log:
//! the console stays whole while userspace and the kernel write at once
//! (docs/console-model.md; svctest's `console_whole_lines` phase).
//!
//! The window runs from the first line whose text is `<TAG> begin` to the
//! first line after it whose text starts `<TAG> end `. Every line inside it
//! must be one console line: a `[sec.usec] ` stamp at its start, then a
//! `[name] ` tag or the kernel's own `kernel: `, and no second stamp after
//! it. A numbered line, text `<TAG> t=<t> n=<n> len=<len> <payload>`, must
//! carry `len` lowercase letters as its payload, and each `t`'s numbers must
//! run 0, 1, 2, ... with none missing. The end line, `<TAG> end senders=<s>
//! lines=<l>`, must name as many senders and lines as the window holds.

use std::collections::BTreeMap;

use crate::error::{Result, bail, err};

/// The longest excerpt of a line an error quotes.
const EXCERPT: usize = 120;

/// What the window held, for the run's report.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Summary
{
    /// Console lines inside the window.
    pub(crate) lines: usize,
    /// Numbered lines inside the window.
    pub(crate) numbered: u64,
}

/// Check `log` for the window of `tag`: see the module documentation.
pub(crate) fn check_log(log: &str, tag: &str) -> Result<Summary>
{
    let begin = format!("{tag} begin");
    let end = format!("{tag} end ");
    let numbered_prefix = format!("{tag} t=");
    // Each line with its 1-based number in the log.
    let mut lines = (1usize..).zip(log.lines().map(|l| l.trim_end_matches('\r')));
    if !lines
        .by_ref()
        .any(|(_, l)| console_text(l).is_some_and(|text| text == begin))
    {
        bail!("no line reads {begin:?}");
    }
    let mut next: BTreeMap<u64, u64> = BTreeMap::new();
    let mut numbered = 0u64;
    let mut inside = 0usize;
    for (number, line) in lines
    {
        let Some(text) = console_text(line)
        else
        {
            bail!(
                "log line {number}: not one console line: {:?}",
                excerpt(line)
            );
        };
        if let Some(stamp) = second_stamp(line)
        {
            bail!(
                "log line {number}: a second line starts at byte {stamp}: {:?}",
                excerpt(line)
            );
        }
        if let Some(rest) = text.strip_prefix(&end)
        {
            check_end(rest, &next, numbered).map_err(|e| err!("log line {number}: {e}"))?;
            return Ok(Summary {
                lines: inside,
                numbered,
            });
        }
        inside = inside.saturating_add(1);
        if let Some(rest) = text.strip_prefix(&numbered_prefix)
        {
            let (t, n) = parse_numbered(rest).ok_or_else(|| {
                err!(
                    "log line {number}: a cut numbered line: {:?}",
                    excerpt(line)
                )
            })?;
            let want = next.entry(t).or_insert(0);
            if n != *want
            {
                bail!("log line {number}: sender {t}'s line {n} where its line {want} was due");
            }
            *want = want.saturating_add(1);
            numbered = numbered.saturating_add(1);
        }
    }
    bail!("no line after {begin:?} starts {:?}", end.trim_end());
}

/// The text of a console line, after its stamp and its `[name] ` tag or
/// `kernel: `; `None` for a line of any other shape.
fn console_text(line: &str) -> Option<&str>
{
    let rest = strip_stamp(line)?;
    if let Some(text) = rest.strip_prefix("kernel: ")
    {
        return Some(text);
    }
    let name_and_text = rest.strip_prefix('[')?;
    let close = name_and_text.find(']')?;
    let name = name_and_text.get(..close)?;
    if name.is_empty() || name.contains(|c: char| c.is_whitespace() || c == '[')
    {
        return None;
    }
    name_and_text
        .get(close.saturating_add(1)..)?
        .strip_prefix(' ')
}

/// `line` after a leading `[<digits>.<6 digits>] ` stamp.
fn strip_stamp(line: &str) -> Option<&str>
{
    let rest = line.strip_prefix('[')?;
    let (stamp, after) = rest.split_once("] ")?;
    let (sec, frac) = stamp.split_once('.')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    (digits(sec) && frac.len() == 6 && digits(frac)).then_some(after)
}

/// The byte offset of a stamp after the start of `line`, the sign of a line
/// written into another.
fn second_stamp(line: &str) -> Option<usize>
{
    line.match_indices('[')
        .map(|(at, _)| at)
        .filter(|&at| at > 0)
        .find(|&at| line.get(at..).and_then(strip_stamp).is_some())
}

/// `(t, n)` of a numbered line's text after `<TAG> t=`, when its payload
/// holds as many lowercase letters as its `len` says.
fn parse_numbered(rest: &str) -> Option<(u64, u64)>
{
    let mut words = rest.splitn(4, ' ');
    let t = words.next()?.parse().ok()?;
    let n = words.next()?.strip_prefix("n=")?.parse().ok()?;
    let len: usize = words.next()?.strip_prefix("len=")?.parse().ok()?;
    let payload = words.next()?;
    (payload.len() == len && payload.bytes().all(|b| b.is_ascii_lowercase())).then_some((t, n))
}

/// Check the end line's `senders=<s> lines=<l>` against the window.
fn check_end(rest: &str, next: &BTreeMap<u64, u64>, numbered: u64) -> Result<()>
{
    let field = |key: &str| -> Option<u64> {
        rest.split(' ')
            .find_map(|w| w.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
    };
    let (Some(senders), Some(lines)) = (field("senders"), field("lines"))
    else
    {
        bail!("the end line names no senders= and lines=: {rest:?}");
    };
    let seen = u64::try_from(next.len()).unwrap_or(u64::MAX);
    if seen != senders
    {
        bail!("{senders} senders logged, {seen} seen");
    }
    if numbered != lines
    {
        bail!("{lines} numbered lines logged, {numbered} seen whole");
    }
    Ok(())
}

/// At most [`EXCERPT`] characters of `line`.
fn excerpt(line: &str) -> String
{
    line.chars().take(EXCERPT).collect()
}

#[cfg(test)]
mod tests
{
    use super::*;

    const TAG: &str = "whole-lines";

    fn numbered(t: u64, n: u64) -> String
    {
        format!("[1.000100] [svctest] whole-lines t={t} n={n} len=3 abc")
    }

    fn window(body: &[String], senders: u64, lines: u64) -> String
    {
        let mut log = vec![
            "OpenSBI v1.5".to_string(),
            "[0.900000] [svctest] whole-lines begin".to_string(),
        ];
        log.extend(body.iter().cloned());
        log.push(format!(
            "[2.000000] [svctest] whole-lines end senders={senders} lines={lines}"
        ));
        log.push("[2.100000] [svctest] ALL TESTS PASSED".to_string());
        log.join("\r\n")
    }

    #[test]
    fn whole_window_passes()
    {
        let body = vec![
            numbered(0, 0),
            "[1.000200] [kernel] fault unhandled: tid=7 handler declined".to_string(),
            numbered(1, 0),
            "[1.000300] kernel: USERSPACE FAULT: tid=7".to_string(),
            numbered(0, 1),
            "[1.000400] [crashd] WARN CRASH id=1 kind=vm".to_string(),
        ];
        assert_eq!(
            check_log(&window(&body, 2, 3), TAG).unwrap(),
            Summary {
                lines: 6,
                numbered: 3
            }
        );
    }

    #[test]
    fn kernel_text_inside_a_line_fails()
    {
        let body = vec![
            "[1.000100] [svctest] whole-lines t=0 n=0 len=3 a[1.000150] kernel: x".to_string(),
        ];
        let err = check_log(&window(&body, 1, 1), TAG).unwrap_err();
        assert!(format!("{err}").contains("second line starts"), "{err}");
    }

    #[test]
    fn a_line_split_by_another_fails()
    {
        let body = vec![
            "[1.000100] [svctest] whole-lines t=0 n=0 len=3 a".to_string(),
            "[1.000150] kernel: fault unhandled".to_string(),
            "bc".to_string(),
        ];
        let err = check_log(&window(&body, 1, 1), TAG).unwrap_err();
        assert!(format!("{err}").contains("cut numbered line"), "{err}");
    }

    #[test]
    fn a_fragment_line_fails()
    {
        let body = vec![numbered(0, 0), "ra=0x0 sp=0x0".to_string()];
        let err = check_log(&window(&body, 1, 1), TAG).unwrap_err();
        assert!(format!("{err}").contains("not one console line"), "{err}");
    }

    #[test]
    fn a_missing_number_fails()
    {
        let body = vec![numbered(0, 0), numbered(0, 2)];
        let err = check_log(&window(&body, 1, 2), TAG).unwrap_err();
        assert!(format!("{err}").contains("line 1 was due"), "{err}");
    }

    #[test]
    fn counts_must_match_the_end_line()
    {
        let body = vec![numbered(0, 0), numbered(1, 0)];
        let senders = check_log(&window(&body, 3, 2), TAG).unwrap_err();
        assert!(
            format!("{senders}").contains("3 senders logged, 2 seen"),
            "{senders}"
        );
        let lines = check_log(&window(&body, 2, 5), TAG).unwrap_err();
        assert!(
            format!("{lines}").contains("5 numbered lines logged, 2 seen"),
            "{lines}"
        );
    }

    #[test]
    fn missing_markers_fail()
    {
        let err = check_log("[1.000000] [svctest] hello", TAG).unwrap_err();
        assert!(format!("{err}").contains("no line reads"), "{err}");
        let err = check_log("[1.000000] [svctest] whole-lines begin\n", TAG).unwrap_err();
        assert!(format!("{err}").contains("no line after"), "{err}");
    }

    #[test]
    fn a_wrong_payload_length_fails()
    {
        let body = vec!["[1.000100] [svctest] whole-lines t=0 n=0 len=4 abc".to_string()];
        let err = check_log(&window(&body, 1, 1), TAG).unwrap_err();
        assert!(format!("{err}").contains("cut numbered line"), "{err}");
    }
}
