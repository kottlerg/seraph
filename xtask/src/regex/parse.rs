// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/regex/parse.rs

//! The pattern parser: the restricted syntax of [`super`] into a syntax tree.
//!
//! The parser is recursive descent over the pattern's characters. Its recursion is bounded by
//! [`MAX_DEPTH`], the deepest group nesting it accepts, and a counted repetition by
//! [`MAX_REPEAT`], so a hostile pattern can neither exhaust the stack nor ask for an unbounded
//! program before the compiler's own size limit is reached.

use super::Error;

/// Deepest group nesting the parser accepts.
pub const MAX_DEPTH: usize = 64;

/// Largest count a counted repetition (`{n}`, `{n,}`, `{n,m}`) accepts.
pub const MAX_REPEAT: u32 = 1000;

/// The largest Unicode scalar value.
const MAX_CHAR: u32 = 0x10_FFFF;

/// `\d`: the ASCII digits.
const DIGIT: &[(u32, u32)] = &[(0x30, 0x39)];

/// `\w`: the ASCII word characters, the characters `\b` divides at.
const WORD: &[(u32, u32)] = &[(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)];

/// `\s`: Unicode's `White_Space` characters, those [`char::is_whitespace`] accepts.
const SPACE: &[(u32, u32)] = &[
    (0x09, 0x0D),
    (0x20, 0x20),
    (0x85, 0x85),
    (0xA0, 0xA0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
];

/// A zero-width assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look
{
    /// `^`: the start of the text.
    Start,
    /// `$`: the end of the text.
    End,
    /// `\b`: a word character on exactly one side.
    WordBoundary,
    /// `\B`: a word character on both sides or on neither.
    NotWordBoundary,
}

/// A node of the syntax tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node
{
    /// Matches the empty string.
    Empty,
    /// One character, matched exactly.
    Literal(char),
    /// One character of a set, held as sorted, disjoint, non-adjacent inclusive ranges of
    /// scalar values.
    Class(Vec<(u32, u32)>),
    /// A zero-width assertion.
    Look(Look),
    /// A group; `Some(i)` is capture group `i`, numbered from 1 by its opening parenthesis.
    Group(Option<usize>, Box<Node>),
    /// The nodes in sequence.
    Concat(Vec<Node>),
    /// The first of the nodes that leads to a match, tried in order.
    Alternate(Vec<Node>),
    /// The node repeated `min` to `max` times (no bound for `None`).
    Repeat
    {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
        prefer: Prefer,
    },
}

/// Which count of repetitions a repetition prefers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefer
{
    /// As many as lead to a match (greedy: `*`, `+`, `?`, `{n,m}`).
    More,
    /// As few as lead to a match (lazy: `*?`, `+?`, `??`, `{n,m}?`).
    Fewer,
}

/// A parsed pattern: its tree and the number of capture groups it opens.
#[derive(Debug)]
pub struct Parsed
{
    pub node: Node,
    pub groups: usize,
}

/// Parse `pattern`.
///
/// # Errors
///
/// A pattern outside the restricted syntax, with the byte offset of the construct at fault.
pub fn parse(pattern: &str) -> Result<Parsed, Error>
{
    let mut parser = Parser {
        pattern,
        pos: 0,
        fold: false,
        groups: 0,
    };
    let node = parser.alternation(0)?;
    if parser.peek().is_some()
    {
        // Only an unopened `)` stops the top-level alternation before the end.
        return Err(parser.error(parser.pos, "a `)` that closes no group"));
    }
    Ok(Parsed {
        node,
        groups: parser.groups,
    })
}

/// An item of a bracketed class: one character, or a set (`\d` and the like).
enum ClassItem
{
    Char(char),
    Set(Vec<(u32, u32)>),
}

struct Parser<'p>
{
    pattern: &'p str,
    /// Byte offset of the next character.
    pos: usize,
    /// Whether `(?i)` is in force: ASCII letters match either case.
    fold: bool,
    /// Capture groups opened so far.
    groups: usize,
}

impl Parser<'_>
{
    fn error(&self, at: usize, reason: &str) -> Error
    {
        Error::syntax(self.pattern, at, reason)
    }

    fn peek(&self) -> Option<char>
    {
        self.pattern.get(self.pos..)?.chars().next()
    }

    /// The character after the next one.
    fn peek_second(&self) -> Option<char>
    {
        self.pattern.get(self.pos..)?.chars().nth(1)
    }

    fn bump(&mut self) -> Option<char>
    {
        let c = self.peek()?;
        self.pos = self.pos.saturating_add(c.len_utf8());
        Some(c)
    }

    fn eat(&mut self, want: char) -> bool
    {
        let found = self.peek() == Some(want);
        if found
        {
            self.bump();
        }
        found
    }

    /// Alternatives separated by `|`, up to a `)` or the end.
    fn alternation(&mut self, depth: usize) -> Result<Node, Error>
    {
        let mut alternatives = vec![self.concatenation(depth)?];
        while self.eat('|')
        {
            alternatives.push(self.concatenation(depth)?);
        }
        Ok(match alternatives.pop()
        {
            Some(only) if alternatives.is_empty() => only,
            Some(last) =>
            {
                alternatives.push(last);
                Node::Alternate(alternatives)
            }
            None => Node::Empty,
        })
    }

    /// Repeated atoms up to a `|`, a `)` or the end.
    fn concatenation(&mut self, depth: usize) -> Result<Node, Error>
    {
        let mut items = Vec::new();
        while let Some(c) = self.peek()
            && c != '|'
            && c != ')'
        {
            // A flag group sets flags and matches nothing; it takes no repetition.
            if let Some(atom) = self.atom(depth)?
            {
                items.push(self.repetition(atom)?);
            }
        }
        Ok(match items.pop()
        {
            Some(only) if items.is_empty() => only,
            Some(last) =>
            {
                items.push(last);
                Node::Concat(items)
            }
            None => Node::Empty,
        })
    }

    /// One atom, or `None` for a flag group such as `(?i)`.
    fn atom(&mut self, depth: usize) -> Result<Option<Node>, Error>
    {
        let at = self.pos;
        let Some(c) = self.bump()
        else
        {
            return Ok(Some(Node::Empty));
        };
        let node = match c
        {
            '(' => return self.group(at, depth),
            '[' => self.class(at)?,
            '.' => Node::Class(complement(&[(0x0A, 0x0A)])),
            '^' => Node::Look(Look::Start),
            '$' => Node::Look(Look::End),
            '\\' => self.escape(at)?,
            '*' | '+' | '?' | '{' =>
            {
                return Err(self.error(at, "a repetition with nothing to repeat"));
            }
            c => self.literal(c),
        };
        Ok(Some(node))
    }

    /// `c`, matched in either case when `(?i)` is in force and it is an ASCII letter.
    fn literal(&self, c: char) -> Node
    {
        if self.fold && c.is_ascii_alphabetic()
        {
            let code = u32::from(c);
            let mut ranges = vec![(code, code)];
            fold_ascii(&mut ranges);
            Node::Class(normalize(ranges))
        }
        else
        {
            Node::Literal(c)
        }
    }

    /// A group, its `(` at `at` already read.
    fn group(&mut self, at: usize, depth: usize) -> Result<Option<Node>, Error>
    {
        if depth >= MAX_DEPTH
        {
            return Err(self.error(at, "groups nested more than 64 deep"));
        }
        let saved = self.fold;
        let index = if self.eat('?')
        {
            let Some(fold) = self.flags(at)?
            else
            {
                // A flag group: its flags hold to the end of the enclosing group.
                return Ok(None);
            };
            self.fold = fold;
            None
        }
        else
        {
            self.groups = self.groups.saturating_add(1);
            Some(self.groups)
        };
        let inner = self.alternation(depth.saturating_add(1))?;
        self.fold = saved;
        if !self.eat(')')
        {
            return Err(self.error(at, "an unclosed group"));
        }
        Ok(Some(Node::Group(index, Box::new(inner))))
    }

    /// The flags after `(?`: `Some(fold)` for a non-capturing group (`(?:`, `(?i:`), whose body
    /// follows, or `None` for a flag group (`(?i)`), whose flags are applied.
    fn flags(&mut self, at: usize) -> Result<Option<bool>, Error>
    {
        let mut fold = self.fold;
        let mut negated = false;
        let mut named = false;
        loop
        {
            let flag_at = self.pos;
            match self.bump()
            {
                Some('i') =>
                {
                    fold = !negated;
                    named = true;
                }
                Some('-') if !negated => negated = true,
                Some(':') if named || !negated => return Ok(Some(fold)),
                Some(')') if named =>
                {
                    self.fold = fold;
                    return Ok(None);
                }
                Some(':' | ')') => return Err(self.error(at, "a flag group that names no flag")),
                Some(_) =>
                {
                    return Err(self.error(flag_at, "an unsupported group flag (only `i` is)"));
                }
                None => return Err(self.error(at, "an unclosed group")),
            }
        }
    }

    /// An escape outside a class, its `\` at `at` already read.
    fn escape(&mut self, at: usize) -> Result<Node, Error>
    {
        match self.bump()
        {
            Some('b') => Ok(Node::Look(Look::WordBoundary)),
            Some('B') => Ok(Node::Look(Look::NotWordBoundary)),
            Some(c) => match self.escaped(at, c)?
            {
                ClassItem::Char(c) => Ok(self.literal(c)),
                ClassItem::Set(ranges) => Ok(Node::Class(ranges)),
            },
            None => Err(self.error(at, "a trailing backslash")),
        }
    }

    /// What `\c` stands for, in a class or outside one.
    fn escaped(&self, at: usize, c: char) -> Result<ClassItem, Error>
    {
        Ok(match c
        {
            'd' => ClassItem::Set(DIGIT.to_vec()),
            'D' => ClassItem::Set(complement(DIGIT)),
            'w' => ClassItem::Set(WORD.to_vec()),
            'W' => ClassItem::Set(complement(WORD)),
            's' => ClassItem::Set(SPACE.to_vec()),
            'S' => ClassItem::Set(complement(SPACE)),
            'n' => ClassItem::Char('\n'),
            'r' => ClassItem::Char('\r'),
            't' => ClassItem::Char('\t'),
            c if c.is_ascii_punctuation() => ClassItem::Char(c),
            _ => return Err(self.error(at, "an unsupported escape")),
        })
    }

    /// A bracketed class, its `[` at `at` already read.
    fn class(&mut self, at: usize) -> Result<Node, Error>
    {
        let negated = self.eat('^');
        let mut ranges = Vec::new();
        let mut first = true;
        loop
        {
            let item_at = self.pos;
            let item = match self.bump()
            {
                None => return Err(self.error(at, "an unclosed character class")),
                // A `]` first in the class is a member, as in `[]a]`.
                Some(']') if !first => break,
                Some('[') =>
                {
                    return Err(self.error(item_at, "a nested class, which is unsupported"));
                }
                Some('&') if self.peek() == Some('&') =>
                {
                    return Err(self.error(item_at, "a class set operation, which is unsupported"));
                }
                Some('\\') =>
                {
                    let Some(c) = self.bump()
                    else
                    {
                        return Err(self.error(at, "an unclosed character class"));
                    };
                    self.escaped(item_at, c)?
                }
                Some(c) => ClassItem::Char(c),
            };
            first = false;
            match item
            {
                ClassItem::Set(set) => ranges.extend(set),
                ClassItem::Char(low) =>
                {
                    let high = self.range_end(at)?.unwrap_or(low);
                    if high < low
                    {
                        return Err(
                            self.error(item_at, "a class range whose end precedes its start")
                        );
                    }
                    ranges.push((u32::from(low), u32::from(high)));
                }
            }
        }
        if self.fold
        {
            fold_ascii(&mut ranges);
        }
        let ranges = normalize(ranges);
        Ok(Node::Class(
            if negated { complement(&ranges) } else { ranges },
        ))
    }

    /// The end of a class range, when a `-` that is not the class's last member follows its
    /// start; `at` is the class's `[`.
    fn range_end(&mut self, at: usize) -> Result<Option<char>, Error>
    {
        if self.peek() != Some('-') || matches!(self.peek_second(), Some(']') | None)
        {
            return Ok(None);
        }
        self.bump();
        let end_at = self.pos;
        let end = match self.bump()
        {
            Some('\\') => match self.bump()
            {
                Some(c) => self.escaped(end_at, c)?,
                None => return Err(self.error(at, "an unclosed character class")),
            },
            Some('[') => return Err(self.error(end_at, "a nested class, which is unsupported")),
            Some(c) => ClassItem::Char(c),
            None => return Err(self.error(at, "an unclosed character class")),
        };
        match end
        {
            ClassItem::Char(c) => Ok(Some(c)),
            ClassItem::Set(_) => Err(self.error(end_at, "a class range that ends in a set")),
        }
    }

    /// The repetition operator after `atom`, if one follows.
    fn repetition(&mut self, atom: Node) -> Result<Node, Error>
    {
        let at = self.pos;
        let (min, max) = match self.peek()
        {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            // The counts follow the `{`.
            Some('{') => (0, Some(0)),
            _ => return Ok(atom),
        };
        let (min, max) = if self.bump() == Some('{')
        {
            self.counts(at)?
        }
        else
        {
            (min, max)
        };
        let prefer = if self.eat('?')
        {
            Prefer::Fewer
        }
        else
        {
            Prefer::More
        };
        if matches!(self.peek(), Some('*' | '+' | '?' | '{'))
        {
            return Err(self.error(
                self.pos,
                "a repetition of a repetition; group the inner one",
            ));
        }
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
            prefer,
        })
    }

    /// The counts of `{n}`, `{n,}` or `{n,m}` through the `}`, its `{` at `at` already read.
    fn counts(&mut self, at: usize) -> Result<(u32, Option<u32>), Error>
    {
        let min = self.count(at)?;
        let max = if self.eat(',')
        {
            if self.peek() == Some('}')
            {
                None
            }
            else
            {
                Some(self.count(at)?)
            }
        }
        else
        {
            Some(min)
        };
        if !self.eat('}')
        {
            return Err(self.error(at, "a malformed counted repetition"));
        }
        if max.is_some_and(|max| max < min)
        {
            return Err(self.error(
                at,
                "a counted repetition whose maximum is below its minimum",
            ));
        }
        Ok((min, max))
    }

    /// A decimal count of at most [`MAX_REPEAT`].
    fn count(&mut self, at: usize) -> Result<u32, Error>
    {
        let mut value: Option<u32> = None;
        while let Some(digit) = self.peek().and_then(|c| c.to_digit(10))
        {
            self.bump();
            let next = value.unwrap_or(0).saturating_mul(10).saturating_add(digit);
            if next > MAX_REPEAT
            {
                return Err(self.error(at, "a repetition count above 1000"));
            }
            value = Some(next);
        }
        value.ok_or_else(|| self.error(at, "a malformed counted repetition"))
    }
}

/// Add to `ranges` the other case of every ASCII letter they hold.
fn fold_ascii(ranges: &mut Vec<(u32, u32)>)
{
    const CASE_BIT: u32 = 0x20;
    let mut other = Vec::new();
    for &(low, high) in ranges.iter()
    {
        for (from, to) in [(0x41, 0x5A), (0x61, 0x7A)]
        {
            let (start, end) = (low.max(from), high.min(to));
            if start <= end
            {
                other.push((start ^ CASE_BIT, end ^ CASE_BIT));
            }
        }
    }
    ranges.extend(other);
}

/// `ranges` sorted, with overlapping and adjacent ranges merged.
fn normalize(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)>
{
    ranges.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (low, high) in ranges
    {
        match out.last_mut()
        {
            Some(last) if low <= last.1.saturating_add(1) => last.1 = last.1.max(high),
            _ => out.push((low, high)),
        }
    }
    out
}

/// Every scalar value outside the normalized `ranges`.
fn complement(ranges: &[(u32, u32)]) -> Vec<(u32, u32)>
{
    let mut out = Vec::new();
    let mut next = 0u32;
    for &(low, high) in ranges
    {
        if low > next
        {
            out.push((next, low.saturating_sub(1)));
        }
        next = high.saturating_add(1);
    }
    if next <= MAX_CHAR
    {
        out.push((next, MAX_CHAR));
    }
    out
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn class(pattern: &str) -> Vec<(u32, u32)>
    {
        let Node::Class(ranges) = parse(pattern).unwrap().node
        else
        {
            panic!("{pattern:?} is not a class");
        };
        ranges
    }

    fn reason(pattern: &str) -> String
    {
        parse(pattern).unwrap_err().to_string()
    }

    #[test]
    fn space_is_exactly_the_characters_std_calls_whitespace()
    {
        let ranges = class(r"\s");
        let held = |c: u32| ranges.iter().any(|&(low, high)| low <= c && c <= high);
        for c in (0..=MAX_CHAR).filter_map(char::from_u32)
        {
            assert_eq!(held(u32::from(c)), c.is_whitespace(), "{c:?}");
        }
    }

    #[test]
    fn a_negated_class_holds_every_other_character_newline_included()
    {
        let ranges = class(r"[^\]a-c]");
        let held = |c: char| {
            ranges
                .iter()
                .any(|&(l, h)| l <= u32::from(c) && u32::from(c) <= h)
        };
        assert!(!held(']') && !held('a') && !held('b') && !held('c'));
        assert!(held('d') && held('\n') && held('\u{10FFFF}') && held('\0'));
    }

    #[test]
    fn a_dash_first_or_last_in_a_class_is_a_member()
    {
        assert_eq!(class("[- ]"), vec![(0x20, 0x20), (0x2D, 0x2D)]);
        assert_eq!(
            class(r"[\w.-]"),
            normalize([WORD, &[(0x2D, 0x2E)]].concat())
        );
        assert_eq!(class("[]a]"), vec![(0x5D, 0x5D), (0x61, 0x61)]);
    }

    #[test]
    fn case_folding_holds_inside_its_group_and_reaches_classes()
    {
        let parsed = parse("(?i:a[b-c])d").unwrap();
        let Node::Concat(items) = parsed.node
        else
        {
            panic!("not a concatenation");
        };
        let Some(Node::Group(None, inner)) = items.first()
        else
        {
            panic!("no group first");
        };
        assert_eq!(
            **inner,
            Node::Concat(vec![
                Node::Class(vec![(0x41, 0x41), (0x61, 0x61)]),
                Node::Class(vec![(0x42, 0x43), (0x62, 0x63)]),
            ])
        );
        assert_eq!(items.get(1), Some(&Node::Literal('d')));
    }

    #[test]
    fn capture_groups_are_numbered_by_their_opening_parenthesis()
    {
        let parsed = parse("((a)(?:b)(c))").unwrap();
        assert_eq!(parsed.groups, 3);
        let Node::Group(Some(1), outer) = parsed.node
        else
        {
            panic!("outer group is not group 1");
        };
        let Node::Concat(items) = *outer
        else
        {
            panic!("outer group is not a concatenation");
        };
        assert!(matches!(items.first(), Some(Node::Group(Some(2), _))));
        assert!(matches!(items.get(1), Some(Node::Group(None, _))));
        assert!(matches!(items.get(2), Some(Node::Group(Some(3), _))));
    }

    #[test]
    fn counted_repetitions_parse_their_bounds()
    {
        let bounds = |pattern: &str| {
            let Node::Repeat {
                min, max, prefer, ..
            } = parse(pattern).unwrap().node
            else
            {
                panic!("{pattern:?} is not a repetition");
            };
            (min, max, prefer)
        };
        assert_eq!(bounds("a{3}"), (3, Some(3), Prefer::More));
        assert_eq!(bounds("a{3,}"), (3, None, Prefer::More));
        assert_eq!(bounds("a{0,2}?"), (0, Some(2), Prefer::Fewer));
        assert_eq!(bounds("a+?"), (1, None, Prefer::Fewer));
        assert_eq!(bounds("a{1000}"), (1000, Some(1000), Prefer::More));
    }

    #[test]
    fn constructs_outside_the_syntax_are_refused_with_their_reason()
    {
        for (pattern, why) in [
            ("(", "an unclosed group"),
            ("a)", "a `)` that closes no group"),
            ("*a", "nothing to repeat"),
            ("a**", "a repetition of a repetition"),
            ("a{2", "a malformed counted repetition"),
            ("a{,2}", "a malformed counted repetition"),
            ("a{3,2}", "maximum is below its minimum"),
            ("a{1001}", "above 1000"),
            ("[a", "an unclosed character class"),
            ("[z-a]", "end precedes its start"),
            (r"[a-\d]", "ends in a set"),
            ("[[:alpha:]]", "a nested class"),
            ("[a&&b]", "set operation"),
            (r"\1", "an unsupported escape"),
            (r"\p{L}", "an unsupported escape"),
            ("a\\", "a trailing backslash"),
            ("(?m)a", "an unsupported group flag"),
            ("(?-u:a)", "an unsupported group flag"),
            ("(?P<n>a)", "an unsupported group flag"),
            ("(?=a)", "an unsupported group flag"),
            ("(?)a", "names no flag"),
        ]
        {
            let error = reason(pattern);
            assert!(error.contains(why), "{pattern:?}: {error}");
        }
    }

    #[test]
    fn nesting_is_refused_past_the_depth_limit_without_exhausting_the_stack()
    {
        let deep = |n: usize| format!("{}a{}", "(".repeat(n), ")".repeat(n));
        parse(&deep(MAX_DEPTH)).unwrap();
        assert!(reason(&deep(MAX_DEPTH + 1)).contains("nested more than 64 deep"));
        assert!(reason(&deep(100_000)).contains("nested more than 64 deep"));
    }
}
