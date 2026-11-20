// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/regex/mod.rs

//! xtask's regular expressions: a Pike VM over a restricted syntax, for the patterns xtask's
//! checks compile and those a caller passes to `run --runs`.
//!
//! The syntax is documented in `xtask/README.md` § Pattern syntax. A search costs at most a
//! constant amount of work per instruction of the compiled pattern per character of the text,
//! whatever the two hold (see [`vm`]), so text from outside (a `gh` answer, a guest's serial
//! log, a PR body) cannot make a match run long; a pattern's program is bounded by
//! [`compile::MAX_INSTS`]. Iterating over the matches restarts the search after each match, and a
//! search reads past its match only while a thread preferred to it is still running, so an
//! iteration costs at most that bound once per match.
//!
//! The match reported is the leftmost-first one: the earliest start, and at that start the
//! match a backtracking engine would find first. In-tree code replaces a registry crate here
//! (`docs/coding-standards.md` § Dependencies).

mod compile;
mod parse;
mod vm;

use std::borrow::Cow;
use std::fmt;

use compile::Program;
use vm::{Search, Stop};

/// A compiled pattern.
#[derive(Clone, Debug)]
pub struct Regex
{
    program: Program,
}

impl Regex
{
    /// Compile `pattern`.
    ///
    /// # Errors
    ///
    /// The pattern is outside the syntax, nests groups more than 64 deep, counts a repetition
    /// above 1000, or compiles to more than [`compile::MAX_INSTS`] instructions.
    pub fn new(pattern: &str) -> Result<Self, Error>
    {
        let parsed = parse::parse(pattern)?;
        Ok(Self {
            program: compile::compile(pattern, &parsed)?,
        })
    }

    /// Whether the pattern matches anywhere in `text`.
    pub fn is_match(&self, text: &str) -> bool
    {
        self.search(text, 0, 2, Stop::Earliest).is_some()
    }

    /// The leftmost-first match in `text`.
    pub fn find<'t>(&self, text: &'t str) -> Option<Match<'t>>
    {
        self.search(text, 0, 2, Stop::LeftmostFirst)
            .and_then(|slots| Match::of(text, &slots, 0))
    }

    /// The groups of the leftmost-first match in `text`.
    pub fn captures<'t>(&self, text: &'t str) -> Option<Captures<'t>>
    {
        self.search(text, 0, self.program.slots, Stop::LeftmostFirst)
            .map(|slots| Captures { text, slots })
    }

    /// The successive non-overlapping matches in `text`.
    pub fn find_iter<'r, 't>(&'r self, text: &'t str) -> Matches<'r, 't>
    {
        Matches(Searches::new(self, text, 2))
    }

    /// The groups of each successive non-overlapping match in `text`.
    pub fn captures_iter<'r, 't>(&'r self, text: &'t str) -> CaptureMatches<'r, 't>
    {
        CaptureMatches(Searches::new(self, text, self.program.slots))
    }

    /// `text` with every match replaced by `replacement`, taken literally.
    pub fn replace_all<'t>(&self, text: &'t str, replacement: &str) -> Cow<'t, str>
    {
        let mut out = String::new();
        let mut copied = 0;
        let mut replaced = false;
        for found in self.find_iter(text)
        {
            out.push_str(text.get(copied..found.start).unwrap_or_default());
            out.push_str(replacement);
            copied = found.end;
            replaced = true;
        }
        if !replaced
        {
            return Cow::Borrowed(text);
        }
        out.push_str(text.get(copied..).unwrap_or_default());
        Cow::Owned(out)
    }

    /// The first `slots` capture slots of the match from `start` that `stop` asks for.
    fn search(
        &self,
        text: &str,
        start: usize,
        slots: usize,
        stop: Stop,
    ) -> Option<Vec<Option<usize>>>
    {
        let mut steps = 0;
        Search {
            program: &self.program,
            text,
            start,
            slots,
            stop,
        }
        .run(&mut steps)
    }
}

/// `text` with every character the syntax gives a meaning escaped, so the result matches
/// `text` literally.
pub fn escape(text: &str) -> String
{
    let mut out = String::with_capacity(text.len());
    for c in text.chars()
    {
        if r"\.+*?()|[]{}^$#&-~".contains(c)
        {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A match: its byte span in the text searched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match<'t>
{
    text: &'t str,
    start: usize,
    end: usize,
}

impl<'t> Match<'t>
{
    /// Group `group`'s span in `slots`, when it took part in the match.
    fn of(text: &'t str, slots: &[Option<usize>], group: usize) -> Option<Self>
    {
        let first = group.checked_mul(2)?;
        let start = (*slots.get(first)?)?;
        let end = (*slots.get(first.checked_add(1)?)?)?;
        Some(Self { text, start, end })
    }

    /// The byte offset of the match's start.
    pub fn start(&self) -> usize
    {
        self.start
    }

    /// The byte offset just past the match's end.
    pub fn end(&self) -> usize
    {
        self.end
    }

    /// The matched text.
    pub fn as_str(&self) -> &'t str
    {
        // The VM records only positions between characters.
        self.text.get(self.start..self.end).unwrap_or_default()
    }
}

/// The groups of one match.
#[derive(Clone, Debug)]
pub struct Captures<'t>
{
    text: &'t str,
    slots: Vec<Option<usize>>,
}

impl<'t> Captures<'t>
{
    /// Group `group` (0 is the whole match), or `None` when it took no part in the match or
    /// the pattern has no such group.
    pub fn get(&self, group: usize) -> Option<Match<'t>>
    {
        Match::of(self.text, &self.slots, group)
    }
}

/// The matches of [`Regex::find_iter`].
pub struct Matches<'r, 't>(Searches<'r, 't>);

impl<'t> Iterator for Matches<'_, 't>
{
    type Item = Match<'t>;

    fn next(&mut self) -> Option<Match<'t>>
    {
        let text = self.0.text;
        self.0.next().and_then(|slots| Match::of(text, &slots, 0))
    }
}

/// The groups of each match of [`Regex::captures_iter`].
pub struct CaptureMatches<'r, 't>(Searches<'r, 't>);

impl<'t> Iterator for CaptureMatches<'_, 't>
{
    type Item = Captures<'t>;

    fn next(&mut self) -> Option<Captures<'t>>
    {
        let text = self.0.text;
        self.0.next().map(|slots| Captures { text, slots })
    }
}

/// Successive searches of one text, each from where the last match ended. An empty match
/// moves the next search on by one character, and an empty match where the previous match
/// ended is not reported.
struct Searches<'r, 't>
{
    regex: &'r Regex,
    text: &'t str,
    slots: usize,
    /// Where the next search starts; `None` when the text is exhausted.
    at: Option<usize>,
    /// Where the last match reported ended.
    last_end: Option<usize>,
}

impl<'r, 't> Searches<'r, 't>
{
    fn new(regex: &'r Regex, text: &'t str, slots: usize) -> Self
    {
        Self {
            regex,
            text,
            slots,
            at: Some(0),
            last_end: None,
        }
    }

    /// The character boundary after `at`, or `None` at the end of the text.
    fn step_past(&self, at: usize) -> Option<usize>
    {
        let c = self.text.get(at..)?.chars().next()?;
        Some(at.saturating_add(c.len_utf8()))
    }
}

impl Iterator for Searches<'_, '_>
{
    type Item = Vec<Option<usize>>;

    fn next(&mut self) -> Option<Vec<Option<usize>>>
    {
        loop
        {
            let at = self.at?;
            let slots = self
                .regex
                .search(self.text, at, self.slots, Stop::LeftmostFirst);
            let Some((start, end)) = slots
                .as_ref()
                .and_then(|slots| Some(((*slots.first()?)?, (*slots.get(1)?)?)))
            else
            {
                self.at = None;
                return None;
            };
            if start == end
            {
                self.at = self.step_past(end);
                if self.last_end == Some(end)
                {
                    continue;
                }
            }
            else
            {
                self.at = Some(end);
            }
            self.last_end = Some(end);
            return slots;
        }
    }
}

/// A pattern the engine refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error
{
    pattern: String,
    /// The byte offset of the construct at fault, when one is.
    offset: Option<usize>,
    reason: String,
}

impl Error
{
    /// `pattern` is outside the syntax at byte `offset`, for `reason`.
    fn syntax(pattern: &str, offset: usize, reason: &str) -> Self
    {
        Self {
            pattern: pattern.to_owned(),
            offset: Some(offset),
            reason: reason.to_owned(),
        }
    }

    /// `pattern` compiles to more than [`compile::MAX_INSTS`] instructions.
    fn size(pattern: &str) -> Self
    {
        Self {
            pattern: pattern.to_owned(),
            offset: None,
            reason: format!(
                "the pattern compiles to more than {} instructions",
                compile::MAX_INSTS
            ),
        }
    }
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self.offset
        {
            Some(offset) => write!(f, "{} at byte {offset} of {:?}", self.reason, self.pattern),
            None => write!(f, "{} ({:?})", self.reason, self.pattern),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests
{
    use super::*;

    fn spans(pattern: &str, text: &str) -> Vec<(usize, usize)>
    {
        Regex::new(pattern)
            .unwrap()
            .find_iter(text)
            .map(|m| (m.start(), m.end()))
            .collect()
    }

    #[test]
    fn a_group_that_took_no_part_in_the_match_is_none()
    {
        let re = Regex::new(r"(a)|(b)(c)?").unwrap();
        let caps = re.captures("xb").unwrap();
        assert_eq!(caps.get(0).map(|m| m.as_str()), Some("b"));
        assert!(caps.get(1).is_none());
        assert_eq!(caps.get(2).map(|m| (m.start(), m.end())), Some((1, 2)));
        assert!(caps.get(3).is_none());
        assert!(caps.get(4).is_none(), "no such group");
    }

    #[test]
    fn a_group_inside_a_repetition_holds_its_last_iteration()
    {
        let re = Regex::new(r"(?:(\d)-)+").unwrap();
        let caps = re.captures("1-2-3-").unwrap();
        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("3"));
    }

    #[test]
    fn iteration_reports_non_overlapping_matches_in_order()
    {
        assert_eq!(spans("aa", "aaaaa"), vec![(0, 2), (2, 4)]);
        assert_eq!(spans(r"#(\d+)", "#1, #23 and #"), vec![(0, 2), (4, 7)]);
        assert_eq!(spans("z", "abc"), Vec::new());
    }

    #[test]
    fn iteration_steps_past_empty_matches_and_skips_one_at_a_previous_end()
    {
        assert_eq!(spans("a*", "baab"), vec![(0, 0), (1, 3), (4, 4)]);
        assert_eq!(spans("", "é"), vec![(0, 0), (2, 2)]);
    }

    #[test]
    fn a_repetition_of_a_node_that_can_match_empty_takes_the_empty_iteration_first()
    {
        // A backtracking engine, and the `regex` crate, take the empty alternative first and
        // stop there.
        assert_eq!(spans("(?:|a)*", "aa"), vec![(0, 0), (1, 1), (2, 2)]);
        assert_eq!(spans("(?:x?|y)*", "y"), vec![(0, 0), (1, 1)]);
        assert_eq!(spans("(?:|a)+", "aa"), vec![(0, 0), (1, 1), (2, 2)]);
        assert_eq!(spans("(?:|a){2,}", "a"), vec![(0, 0), (1, 1)]);
        // Preferring fewer, or a node that cannot match empty, is unchanged.
        assert_eq!(spans("(?:a|)*", "aa"), vec![(0, 2)]);
        assert_eq!(spans("(?:|a)*?", "a"), vec![(0, 0), (1, 1)]);
        assert_eq!(spans("(?:ab)*", "abab"), vec![(0, 4)]);
    }

    #[test]
    fn a_group_in_a_repetition_of_a_node_that_can_match_empty_holds_its_last_consuming_iteration()
    {
        let group = |pattern: &str, text: &str| {
            let caps = Regex::new(pattern).unwrap().captures(text).unwrap();
            caps.get(1).map(|m| (m.start(), m.end()))
        };
        assert_eq!(group("(a*)+", "aa"), Some((0, 2)));
        assert_eq!(group("(a|)+b", "ab"), Some((0, 1)));
        assert_eq!(group("(a*){2,}", "aa"), Some((2, 2)));
        assert_eq!(group("(a*)*", "aa"), Some((0, 2)));
    }

    #[test]
    fn captures_iter_numbers_each_matchs_groups()
    {
        let re = Regex::new(r"(\w)=(\d)").unwrap();
        let pairs: Vec<(&str, &str)> = re
            .captures_iter("a=1 b=x c=3")
            .map(|c| (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str()))
            .collect();
        assert_eq!(pairs, vec![("a", "1"), ("c", "3")]);
    }

    #[test]
    fn replace_all_substitutes_each_match_and_borrows_when_none_matches()
    {
        let re = Regex::new("<[^<>]*>").unwrap();
        assert_eq!(re.replace_all("a <b> c <d>", "_"), "a _ c _");
        assert_eq!(re.replace_all("<b>", ""), "");
        assert!(matches!(
            re.replace_all("plain", ""),
            Cow::Borrowed("plain")
        ));
    }

    #[test]
    fn is_match_answers_as_find_does()
    {
        let re = Regex::new(r"PANIC( at |: )|FATAL:").unwrap();
        for text in ["x PANIC at y", "FATAL: z", "PANIC!", "", "fatal:"]
        {
            assert_eq!(re.is_match(text), re.find(text).is_some(), "{text:?}");
        }
    }

    #[test]
    fn an_escaped_text_matches_itself_literally()
    {
        let text = r"a.b*c+d?(e)[f]{g}^h$i|j\k#l&m-n~o p";
        let re = Regex::new(&escape(text)).unwrap();
        assert_eq!(re.find(&format!("xx{text}yy")).map(|m| m.start()), Some(2));
        assert!(!re.is_match("a_b"));
    }

    #[test]
    fn case_insensitivity_folds_ascii_letters_only()
    {
        let re = Regex::new("(?i)straße").unwrap();
        assert!(re.is_match("STRAßE") && re.is_match("Straße"));
        assert!(!re.is_match("STRASSE") && !re.is_match("STRAẞE"));
        let scoped = Regex::new("(?i:a)b|(?i)c").unwrap();
        assert!(scoped.is_match("Ab") && scoped.is_match("C") && !scoped.is_match("aB"));
    }

    #[test]
    fn a_refused_pattern_names_the_reason_and_the_place()
    {
        let error = Regex::new("ab(c").unwrap_err();
        assert_eq!(error.to_string(), "an unclosed group at byte 2 of \"ab(c\"");
    }
}
