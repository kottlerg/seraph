// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/regex/vm.rs

//! The Pike VM: a search that runs every thread of the program in lockstep over the text.
//!
//! Each position of the text is read once. At each, a thread list holds at most one thread per
//! instruction, so a step does at most a constant amount of work per instruction (following
//! the instruction once into the next list, and running it once from this one): a search
//! costs O(instructions × characters), whatever the pattern and the text, with no
//! backtracking. Threads are kept in priority order, so the match reported is the one a
//! backtracking engine would find first (leftmost-first): the earliest start, and at that start
//! the preferred alternative and repetition.

use super::compile::{Inst, Program};
use super::parse::Look;

/// A search of `text` from byte `start`.
pub struct Search<'a>
{
    pub program: &'a Program,
    pub text: &'a str,
    pub start: usize,
    /// Capture slots to track: 2 for the match's bounds alone, `program.slots` for every group.
    pub slots: usize,
    pub stop: Stop,
}

/// Which match a search reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop
{
    /// The leftmost-first match.
    LeftmostFirst,
    /// The first match the search reaches: enough to tell whether there is one.
    Earliest,
}

impl Search<'_>
{
    /// The capture slots of the match, or `None` when there is none; `steps` counts the work.
    pub fn run(&self, steps: &mut usize) -> Option<Vec<Option<usize>>>
    {
        let insts = self.program.insts.len();
        let mut current = Threads::new(insts, self.slots);
        let mut next = Threads::new(insts, self.slots);
        let mut scratch = vec![None; self.slots];
        let mut stack = Vec::new();
        let mut matched = None;
        let mut at = self.start;
        loop
        {
            if matched.is_none()
            {
                if current.is_empty()
                {
                    if self.program.anchored && at > 0
                    {
                        break;
                    }
                    at = self.program.next_start(self.text, at)?;
                }
                // A new thread at each position, last: it has the lowest priority.
                scratch.fill(None);
                self.follow(&mut current, 0, at, &mut scratch, &mut stack, steps);
            }
            let c = self.text.get(at..).and_then(|rest| rest.chars().next());
            let after = at.saturating_add(c.map_or(0, char::len_utf8));
            for &pc in current.active()
            {
                *steps = steps.saturating_add(1);
                let accepts = match self.program.insts.get(pc)
                {
                    Some(Inst::Match) =>
                    {
                        matched = Some(current.slots(pc).to_vec());
                        if self.stop == Stop::Earliest
                        {
                            return matched;
                        }
                        // Every thread after this one has a lower priority.
                        break;
                    }
                    Some(Inst::Char(want)) => c == Some(*want),
                    Some(Inst::Class(ranges)) => c.is_some_and(|c| in_class(ranges, c)),
                    Some(Inst::Look(_) | Inst::Split(..) | Inst::Jump(_) | Inst::Save(_))
                    | None => false,
                };
                if accepts
                {
                    scratch.copy_from_slice(current.slots(pc));
                    let pc = pc.saturating_add(1);
                    self.follow(&mut next, pc, after, &mut scratch, &mut stack, steps);
                }
            }
            if c.is_none() || (matched.is_some() && next.is_empty())
            {
                break;
            }
            at = after;
            std::mem::swap(&mut current, &mut next);
            next.clear();
        }
        matched
    }

    /// Add to `list` the thread at `pc` and every thread it reaches at `at` without consuming,
    /// in priority order, each instruction once; `scratch` holds the thread's slots and is
    /// restored on return.
    fn follow(
        &self,
        list: &mut Threads,
        pc: usize,
        at: usize,
        scratch: &mut [Option<usize>],
        stack: &mut Vec<Frame>,
        steps: &mut usize,
    )
    {
        stack.push(Frame::Explore(pc));
        while let Some(frame) = stack.pop()
        {
            let pc = match frame
            {
                Frame::Explore(pc) => pc,
                Frame::Restore(slot, value) =>
                {
                    if let Some(entry) = scratch.get_mut(slot)
                    {
                        *entry = value;
                    }
                    continue;
                }
            };
            if !list.insert(pc)
            {
                continue;
            }
            *steps = steps.saturating_add(1);
            match self.program.insts.get(pc)
            {
                Some(Inst::Jump(target)) => stack.push(Frame::Explore(*target)),
                Some(Inst::Split(first, second)) =>
                {
                    stack.push(Frame::Explore(*second));
                    stack.push(Frame::Explore(*first));
                }
                Some(Inst::Save(slot)) =>
                {
                    if let Some(entry) = scratch.get_mut(*slot)
                    {
                        stack.push(Frame::Restore(*slot, *entry));
                        *entry = Some(at);
                    }
                    stack.push(Frame::Explore(pc.saturating_add(1)));
                }
                Some(Inst::Look(look)) =>
                {
                    if holds(*look, self.text, at)
                    {
                        stack.push(Frame::Explore(pc.saturating_add(1)));
                    }
                }
                Some(Inst::Char(_) | Inst::Class(_) | Inst::Match) =>
                {
                    list.slots_mut(pc).copy_from_slice(scratch);
                }
                None =>
                {}
            }
        }
    }
}

/// A pending step of [`Search::follow`].
enum Frame
{
    /// Follow the instruction.
    Explore(usize),
    /// Put the slot back to its value before a `Save` the walk has left.
    Restore(usize, Option<usize>),
}

/// The threads at one position: a sparse set of instructions in insertion (priority) order,
/// and the capture slots of each.
struct Threads
{
    dense: Vec<usize>,
    sparse: Vec<usize>,
    len: usize,
    width: usize,
    slots: Vec<Option<usize>>,
}

impl Threads
{
    fn new(insts: usize, width: usize) -> Self
    {
        Self {
            dense: vec![0; insts],
            sparse: vec![0; insts],
            len: 0,
            width,
            slots: vec![None; insts.saturating_mul(width)],
        }
    }

    fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    fn clear(&mut self)
    {
        self.len = 0;
    }

    /// Add `pc`; false when it was already present.
    fn insert(&mut self, pc: usize) -> bool
    {
        let present = self
            .sparse
            .get(pc)
            .is_some_and(|&i| i < self.len && self.dense.get(i) == Some(&pc));
        if present
        {
            return false;
        }
        if let (Some(dense), Some(sparse)) = (self.dense.get_mut(self.len), self.sparse.get_mut(pc))
        {
            *dense = pc;
            *sparse = self.len;
            self.len = self.len.saturating_add(1);
        }
        true
    }

    /// The instructions, highest priority first.
    fn active(&self) -> &[usize]
    {
        self.dense.get(..self.len).unwrap_or_default()
    }

    fn slots(&self, pc: usize) -> &[Option<usize>]
    {
        let from = pc.saturating_mul(self.width);
        self.slots
            .get(from..from.saturating_add(self.width))
            .unwrap_or_default()
    }

    fn slots_mut(&mut self, pc: usize) -> &mut [Option<usize>]
    {
        let from = pc.saturating_mul(self.width);
        self.slots
            .get_mut(from..from.saturating_add(self.width))
            .unwrap_or_default()
    }
}

/// Whether `c` is in the sorted `ranges`.
fn in_class(ranges: &[(u32, u32)], c: char) -> bool
{
    let code = u32::from(c);
    ranges
        .iter()
        .any(|&(low, high)| low <= code && code <= high)
}

/// Whether `look` holds at byte `at` of `text`.
fn holds(look: Look, text: &str, at: usize) -> bool
{
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let boundary = || {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = text.get(at..).and_then(|s| s.chars().next());
        word(before) != word(after)
    };
    match look
    {
        Look::Start => at == 0,
        Look::End => at == text.len(),
        Look::WordBoundary => boundary(),
        Look::NotWordBoundary => !boundary(),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::regex::compile::compile;
    use crate::regex::parse::parse;

    /// The match's bounds and the work the search took.
    fn search(pattern: &str, text: &str) -> (Option<(usize, usize)>, usize)
    {
        let program = compile(pattern, &parse(pattern).unwrap()).unwrap();
        let mut steps = 0;
        let found = Search {
            program: &program,
            text,
            start: 0,
            slots: 2,
            stop: Stop::LeftmostFirst,
        }
        .run(&mut steps)
        .map(|slots| (slots[0].unwrap(), slots[1].unwrap()));
        (found, steps)
    }

    /// The most work a search may do: two steps per instruction per position.
    fn bound(pattern: &str, text: &str) -> usize
    {
        let insts = compile(pattern, &parse(pattern).unwrap())
            .unwrap()
            .insts
            .len();
        2 * insts * (text.chars().count() + 1)
    }

    #[test]
    fn patterns_that_backtrack_exponentially_take_linear_work()
    {
        let long = "a".repeat(5000);
        for (pattern, text) in [
            ("(a+)+$", format!("{long}!")),
            ("(a|a)*b", long.clone()),
            ("(a*)*b", long.clone()),
            ("(x+x+)+y", "x".repeat(5000)),
            (r"(?:\w+\W+){0,2}$", "word ".repeat(1000) + "!"),
            ("(.*a){20}", long.clone()),
        ]
        {
            let (_, steps) = search(pattern, &text);
            assert!(steps <= bound(pattern, &text), "{pattern}: {steps} steps");
        }
    }

    #[test]
    fn the_leftmost_start_wins_and_then_the_preferred_alternative()
    {
        assert_eq!(search("b|ab", "xab").0, Some((1, 3)));
        assert_eq!(search("a|ab", "xab").0, Some((1, 2)));
        assert_eq!(search("ab|a", "xab").0, Some((1, 3)));
    }

    #[test]
    fn greedy_repetition_takes_the_most_and_lazy_the_least()
    {
        assert_eq!(search("<.*>", "<a><b>").0, Some((0, 6)));
        assert_eq!(search("<.*?>", "<a><b>").0, Some((0, 3)));
        assert_eq!(search("a{2,3}", "aaaa").0, Some((0, 3)));
        assert_eq!(search("a{2,3}?", "aaaa").0, Some((0, 2)));
    }

    #[test]
    fn assertions_hold_only_where_they_should()
    {
        assert_eq!(search(r"\bcat\b", "concat cat").0, Some((7, 10)));
        assert_eq!(search(r"\Bcat", "cat concat").0, Some((7, 10)));
        assert_eq!(search("^a", "ba").0, None);
        assert_eq!(search("a$", "a\nb a").0, Some((4, 5)));
        assert_eq!(search("$.^", "anything").0, None);
        // A non-ASCII letter is not a word character: `\b` divides `é` from `t`.
        assert_eq!(search(r"\bt", "ét").0, Some((2, 3)));
    }

    #[test]
    fn an_empty_match_is_found_at_the_start_and_at_the_end()
    {
        assert_eq!(search("x*", "abc").0, Some((0, 0)));
        assert_eq!(search("$", "abc").0, Some((3, 3)));
        assert_eq!(search("", "").0, Some((0, 0)));
    }

    #[test]
    fn dot_matches_any_character_but_newline_and_whole_characters_only()
    {
        assert_eq!(search("a.c", "a\ncabc").0, Some((3, 6)));
        assert_eq!(search(".", "é").0, Some((0, 2)));
        assert_eq!(search("[^x]", "€").0, Some((0, 3)));
    }
}
