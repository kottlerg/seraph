// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/regex/compile.rs

//! The compiler: a syntax tree into the program the Pike VM runs, and the prefilter that lets a
//! search skip text no match can start in.
//!
//! The program is bounded by [`MAX_INSTS`], so the work of a search, at most a constant number
//! of steps per instruction per character, is bounded by the pattern's size as well as the
//! text's.

use super::Error;
use super::parse::{Look, Node, Parsed, Prefer};

/// Most instructions a program may hold.
pub const MAX_INSTS: usize = 10_000;

/// An instruction of the Pike VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inst
{
    /// Consume one character equal to this one.
    Char(char),
    /// Consume one character in these sorted, disjoint inclusive ranges of scalar values.
    Class(Box<[(u32, u32)]>),
    /// Go on only where the assertion holds.
    Look(Look),
    /// Go on at both targets, the first preferred.
    Split(usize, usize),
    /// Go on at the target.
    Jump(usize),
    /// Record the current position in the slot.
    Save(usize),
    /// A match.
    Match,
}

impl Inst
{
    /// The split of a repetition between its `body` and the `skip` past it, in the order the
    /// repetition prefers.
    fn split(prefer: Prefer, body: usize, skip: usize) -> Self
    {
        match prefer
        {
            Prefer::More => Self::Split(body, skip),
            Prefer::Fewer => Self::Split(skip, body),
        }
    }
}

/// A compiled pattern.
#[derive(Clone, Debug)]
pub struct Program
{
    pub insts: Vec<Inst>,
    /// Capture slots: two per group, group 0 (the whole match) included.
    pub slots: usize,
    /// Every match starts at the start of the text (the pattern opens with `^`).
    pub anchored: bool,
    /// The characters every match starts with.
    pub prefix: String,
    /// For each byte, whether a match can start at a character that begins with it; `None`
    /// when the table would rule out too little to be worth consulting.
    pub first_bytes: Option<Box<[bool; 256]>>,
}

impl Program
{
    /// The first position at or after `at` where a match can start, or `None` when none can.
    pub fn next_start(&self, text: &str, at: usize) -> Option<usize>
    {
        if !self.prefix.is_empty()
        {
            return text
                .get(at..)?
                .find(&self.prefix)
                .map(|i| at.saturating_add(i));
        }
        let Some(table) = &self.first_bytes
        else
        {
            return (at <= text.len()).then_some(at);
        };
        // The table marks ASCII and UTF-8 lead bytes only, so the byte found begins a
        // character.
        text.as_bytes()
            .get(at..)?
            .iter()
            .position(|&b| table.get(usize::from(b)).copied().unwrap_or(false))
            .map(|i| at.saturating_add(i))
    }
}

/// Compile `parsed`, the parse of `pattern`.
///
/// # Errors
///
/// The program would exceed [`MAX_INSTS`].
pub fn compile(pattern: &str, parsed: &Parsed) -> Result<Program, Error>
{
    let mut compiler = Compiler {
        pattern,
        insts: Vec::new(),
    };
    compiler.emit(Inst::Save(0))?;
    compiler.node(&parsed.node)?;
    compiler.emit(Inst::Save(1))?;
    compiler.emit(Inst::Match)?;
    let insts = compiler.insts;
    let anchored = matches!(
        insts.iter().find(|inst| !matches!(inst, Inst::Save(_))),
        Some(Inst::Look(Look::Start))
    );
    Ok(Program {
        prefix: prefix(&insts),
        first_bytes: first_bytes(&insts),
        anchored,
        insts,
        slots: parsed.groups.saturating_add(1).saturating_mul(2),
    })
}

struct Compiler<'p>
{
    pattern: &'p str,
    insts: Vec<Inst>,
}

impl Compiler<'_>
{
    /// Append `inst`; its index.
    fn emit(&mut self, inst: Inst) -> Result<usize, Error>
    {
        if self.insts.len() >= MAX_INSTS
        {
            return Err(Error::size(self.pattern));
        }
        self.insts.push(inst);
        Ok(self.insts.len().saturating_sub(1))
    }

    /// Point the split or jump at `at` to `target`: a split's second target, which a split
    /// emitted before its alternatives leaves open, or a jump's.
    fn patch(&mut self, at: usize, target: usize)
    {
        match self.insts.get_mut(at)
        {
            Some(Inst::Split(_, second) | Inst::Jump(second)) => *second = target,
            Some(Inst::Char(_) | Inst::Class(_) | Inst::Look(_) | Inst::Save(_) | Inst::Match)
            | None =>
            {}
        }
    }

    fn node(&mut self, node: &Node) -> Result<(), Error>
    {
        match node
        {
            Node::Empty =>
            {}
            Node::Literal(c) =>
            {
                self.emit(Inst::Char(*c))?;
            }
            Node::Class(ranges) =>
            {
                self.emit(Inst::Class(ranges.clone().into_boxed_slice()))?;
            }
            Node::Look(look) =>
            {
                self.emit(Inst::Look(*look))?;
            }
            Node::Group(Some(index), inner) =>
            {
                let slot = index.saturating_mul(2);
                self.emit(Inst::Save(slot))?;
                self.node(inner)?;
                self.emit(Inst::Save(slot.saturating_add(1)))?;
            }
            Node::Group(None, inner) => self.node(inner)?,
            Node::Concat(items) =>
            {
                for item in items
                {
                    self.node(item)?;
                }
            }
            Node::Alternate(alternatives) => self.alternate(alternatives)?,
            Node::Repeat {
                node,
                min,
                max,
                prefer,
            } => self.repeat(node, *min, *max, *prefer)?,
        }
        Ok(())
    }

    /// `a|b|c`: a split before each alternative but the last, preferring it, and a jump past
    /// the rest after it.
    fn alternate(&mut self, alternatives: &[Node]) -> Result<(), Error>
    {
        let mut jumps = Vec::new();
        let Some((last, rest)) = alternatives.split_last()
        else
        {
            return Ok(());
        };
        for alternative in rest
        {
            let split = self.emit(Inst::Split(self.insts.len().saturating_add(1), 0))?;
            self.node(alternative)?;
            jumps.push(self.emit(Inst::Jump(0))?);
            let next = self.insts.len();
            self.patch(split, next);
        }
        self.node(last)?;
        let end = self.insts.len();
        for jump in jumps
        {
            self.patch(jump, end);
        }
        Ok(())
    }

    /// `node` `min` times, then without bound (a loop) or up to `max` times (nested optional
    /// copies).
    fn repeat(
        &mut self,
        node: &Node,
        min: u32,
        max: Option<u32>,
        prefer: Prefer,
    ) -> Result<(), Error>
    {
        if max.is_none() && can_be_empty(node)
        {
            return self.at_least_of_nullable(node, min, prefer);
        }
        for _ in 0..min
        {
            self.node(node)?;
        }
        let Some(max) = max
        else
        {
            let split = self.emit(Inst::Split(0, 0))?;
            self.node(node)?;
            self.emit(Inst::Jump(split))?;
            let end = self.insts.len();
            self.set(split, Inst::split(prefer, split.saturating_add(1), end));
            return Ok(());
        };
        let mut splits = Vec::new();
        for _ in min..max
        {
            let split = self.emit(Inst::Split(0, 0))?;
            splits.push(split);
            self.node(node)?;
        }
        let end = self.insts.len();
        for split in splits
        {
            self.set(split, Inst::split(prefer, split.saturating_add(1), end));
        }
        Ok(())
    }

    /// `node{min,}` for a node that can match empty: `(?:node+)?` when `min` is 0, and otherwise
    /// `min - 1` copies and then `node+`, whose split after the last copy loops back to it. In
    /// the plain loop, a path through `node` that consumes nothing returns to the loop's split,
    /// which the position has already visited, so it dies, and the exit is reached only after
    /// the node's consuming paths: a repetition that prefers more would then outrank the empty
    /// iteration a backtracking engine takes first. Here that path reaches the split after the
    /// copy and takes its exit at its own priority. The `regex` crate compiles the same form,
    /// so the groups inside `node` hold the text they hold there.
    fn at_least_of_nullable(&mut self, node: &Node, min: u32, prefer: Prefer) -> Result<(), Error>
    {
        let entry = match min.checked_sub(1)
        {
            None => Some(self.emit(Inst::Split(0, 0))?),
            Some(copies) =>
            {
                for _ in 0..copies
                {
                    self.node(node)?;
                }
                None
            }
        };
        let body = self.insts.len();
        self.node(node)?;
        let again = self.emit(Inst::Split(0, 0))?;
        let end = self.insts.len();
        if let Some(entry) = entry
        {
            self.set(entry, Inst::split(prefer, body, end));
        }
        self.set(again, Inst::split(prefer, body, end));
        Ok(())
    }

    /// Replace the instruction at `at`, emitted earlier as a placeholder.
    fn set(&mut self, at: usize, inst: Inst)
    {
        if let Some(slot) = self.insts.get_mut(at)
        {
            *slot = inst;
        }
    }
}

/// Whether `node` matches some text in a way that consumes none of it.
fn can_be_empty(node: &Node) -> bool
{
    match node
    {
        Node::Empty | Node::Look(_) => true,
        Node::Literal(_) | Node::Class(_) => false,
        Node::Group(_, inner) => can_be_empty(inner),
        Node::Concat(items) => items.iter().all(can_be_empty),
        Node::Alternate(alternatives) => alternatives.iter().any(can_be_empty),
        Node::Repeat { node, min, .. } => *min == 0 || can_be_empty(node),
    }
}

/// The literal characters every path through `insts` consumes first: the run of `Char`
/// instructions from the start, past the saves and the assertions that precede it.
fn prefix(insts: &[Inst]) -> String
{
    let mut out = String::new();
    for inst in insts
    {
        match inst
        {
            Inst::Save(_) =>
            {}
            Inst::Look(_) if out.is_empty() =>
            {}
            Inst::Char(c) => out.push(*c),
            Inst::Look(_) | Inst::Class(_) | Inst::Split(..) | Inst::Jump(_) | Inst::Match =>
            {
                break;
            }
        }
    }
    out
}

/// The bytes a match can start with: the first byte of each character a consuming instruction
/// reachable from the start without consuming accepts. `None` when a match can be empty, or
/// when every ASCII byte is possible.
fn first_bytes(insts: &[Inst]) -> Option<Box<[bool; 256]>>
{
    let mut table = Box::new([false; 256]);
    let mut seen = vec![false; insts.len()];
    let mut stack = vec![0usize];
    while let Some(pc) = stack.pop()
    {
        match seen.get_mut(pc)
        {
            Some(seen) if !*seen => *seen = true,
            _ => continue,
        }
        match insts.get(pc)?
        {
            Inst::Save(_) | Inst::Look(_) => stack.push(pc.saturating_add(1)),
            Inst::Jump(target) => stack.push(*target),
            Inst::Split(first, second) => stack.extend([*first, *second]),
            Inst::Char(c) =>
            {
                let mut buf = [0u8; 4];
                let lead = c
                    .encode_utf8(&mut buf)
                    .as_bytes()
                    .first()
                    .copied()
                    .unwrap_or(0);
                mark(&mut table, u32::from(lead), u32::from(lead));
            }
            Inst::Class(ranges) =>
            {
                for &(low, high) in ranges
                {
                    mark(&mut table, low, high.min(0x7F));
                    if high >= 0x80
                    {
                        // Every non-ASCII lead byte: coarse, and still exact for ASCII text.
                        mark(&mut table, 0xC2, 0xF4);
                    }
                }
            }
            Inst::Match => return None,
        }
    }
    let every_ascii = table.iter().take(0x80).all(|&b| b);
    (!every_ascii).then_some(table)
}

/// Set the entries `low..=high` of `table`; nothing when `low > high`.
fn mark(table: &mut [bool; 256], low: u32, high: u32)
{
    for b in low..=high
    {
        if let Some(entry) = usize::try_from(b).ok().and_then(|b| table.get_mut(b))
        {
            *entry = true;
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::regex::parse::parse;

    fn program(pattern: &str) -> Program
    {
        compile(pattern, &parse(pattern).unwrap()).unwrap()
    }

    #[test]
    fn a_literal_prefix_past_leading_assertions_is_extracted()
    {
        assert_eq!(program(r"\bfoo_[a-z]+\b").prefix, "foo_");
        assert_eq!(program("(ab)c|d").prefix, "");
        assert_eq!(program("^abc").prefix, "abc");
        assert_eq!(program(r"a\bb").prefix, "a");
    }

    #[test]
    fn the_first_byte_table_holds_each_alternative_and_is_dropped_when_useless()
    {
        let table = program("SOME|KERNEL|(?i)x").first_bytes.unwrap();
        let held: Vec<u8> = (0..=255u8).filter(|&b| table[usize::from(b)]).collect();
        assert_eq!(held, b"KSXx");
        assert!(program("a*").first_bytes.is_none(), "a match can be empty");
        assert!(
            program(r"\D|\d").first_bytes.is_none(),
            "every ASCII byte can start one"
        );
        let wide = program("é|a").first_bytes.unwrap();
        assert!(wide[0xC3] && wide[usize::from(b'a')] && !wide[usize::from(b'b')]);
    }

    #[test]
    fn next_start_finds_candidates_and_reports_none_past_the_last()
    {
        let p = program("x|y");
        assert_eq!(p.next_start("aaxay", 0), Some(2));
        assert_eq!(p.next_start("aaxay", 3), Some(4));
        assert_eq!(p.next_start("aaxay", 5), None);
        let q = program("ab");
        assert_eq!(q.next_start("xxabab", 3), Some(4));
        assert_eq!(q.next_start("xxab", 3), None);
    }

    #[test]
    fn a_pattern_past_the_instruction_limit_is_refused()
    {
        compile("a{1000}", &parse("a{1000}").unwrap()).unwrap();
        let big = "(?:a{1000}){20}";
        let error = compile(big, &parse(big).unwrap()).unwrap_err();
        assert!(error.to_string().contains("10000 instructions"), "{error}");
    }

    #[test]
    fn a_pattern_is_anchored_only_when_it_opens_with_start_before_any_branch()
    {
        assert!(!program("^a|^b").anchored);
        assert!(program("(^a)").anchored);
        assert!(!program("a^").anchored);
    }
}
