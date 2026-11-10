// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crash-report/src/parse.rs

//! The parser of a boot log's crash-report blocks.
//!
//! A block's lines may sit among other lines, and among the lines of other
//! blocks: each line is found by its tag wherever it starts on a log line
//! (logd prefixes it with `[crashd] `), and a field line joins the open block
//! whose id it carries.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{Arch, BEGIN_TAG, END_TAG, FIELD_TAG, MAX_FRAMES};

/// One block read back from a log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block
{
    /// The id its markers carry.
    pub id: u64,
    /// The format version its begin marker carries.
    pub version: u32,
    fields: Vec<(String, String)>,
    end: Option<usize>,
}

/// Why [`Block::check`] refuses a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Defect
{
    /// No end marker, or an end marker whose count is not the number of field
    /// lines read.
    Incomplete,
    /// A field the block's kind, thread, and status require is absent.
    Missing(String),
    /// A field's value does not parse as its encoding.
    Malformed(String),
}

impl Block
{
    /// The value of the field `key`, the first when it repeats.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str>
    {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The value of the field `key` as a `0x`-prefixed hexadecimal word.
    #[must_use]
    pub fn hex(&self, key: &str) -> Option<u64>
    {
        parse_hex(self.get(key)?)
    }

    /// The field lines in the order read, as `(key, value)` pairs.
    #[must_use]
    pub fn fields(&self) -> &[(String, String)]
    {
        &self.fields
    }

    /// The stack walk's frames, `frame.0` on, up to the first absent index.
    #[must_use]
    pub fn frames(&self) -> Vec<u64>
    {
        let mut frames = Vec::new();
        for n in 0..MAX_FRAMES
        {
            match self.hex(&alloc::format!("frame.{n}"))
            {
                Some(frame) => frames.push(frame),
                None => break,
            }
        }
        frames
    }

    /// Whether the block ended with an end marker counting exactly the field
    /// lines read.
    #[must_use]
    pub fn is_complete(&self) -> bool
    {
        self.end == Some(self.fields.len())
    }

    /// Check that the block is complete and holds every field its kind,
    /// thread, and status require (services/crashd/docs/block-format.md),
    /// each in its encoding. `code` is never required, since the bytes at a
    /// fetch fault's pointer are often unmapped. Keys it does not know are
    /// not checked.
    ///
    /// # Errors
    /// The first [`Defect`] found.
    pub fn check(&self) -> Result<(), Defect>
    {
        if !self.is_complete()
        {
            return Err(Defect::Incomplete);
        }
        self.require_dec("badge")?;
        let arch = Arch::from_name(self.require("arch")?)
            .ok_or_else(|| Defect::Malformed("arch".to_string()))?;
        // A `thread` value this reader does not know is a thread it requires
        // no registers of, as for `unidentified`: a value a later writer adds
        // does not bump the format's version (block-format.md § Lines).
        let thread = self.require("thread")?;
        let status = self.require_one_of("status", &["complete", "unattached", "timeout"])?;
        if self.require_one_of("kind", &["vm", "exception"])? == "vm"
        {
            self.require_one_of("access", &["read", "write", "fetch"])?;
            self.require_hex("addr")?;
        }
        else
        {
            self.require("exception")?;
            self.require_hex("aux")?;
        }
        self.require_hex("ip")?;
        if status == "complete"
        {
            self.require_hex("load_bias")?;
            let text = self.require("text")?;
            text.split_once('-')
                .and_then(|(a, b)| Some((parse_hex(a)?, parse_hex(b)?)))
                .ok_or_else(|| Defect::Malformed("text".to_string()))?;
            if matches!(thread, "main" | "spawned")
            {
                for name in arch.register_names()
                {
                    self.require_hex(&alloc::format!("reg.{name}"))?;
                }
                self.require_one_of("walk", &["scan"])?;
                self.require_hex("frame.0")?;
            }
        }
        Ok(())
    }

    fn require(&self, key: &str) -> Result<&str, Defect>
    {
        self.get(key)
            .ok_or_else(|| Defect::Missing(key.to_string()))
    }

    fn require_hex(&self, key: &str) -> Result<u64, Defect>
    {
        parse_hex(self.require(key)?).ok_or_else(|| Defect::Malformed(key.to_string()))
    }

    fn require_dec(&self, key: &str) -> Result<u64, Defect>
    {
        self.require(key)?
            .parse()
            .map_err(|_| Defect::Malformed(key.to_string()))
    }

    fn require_one_of<'s>(&'s self, key: &str, allowed: &[&str]) -> Result<&'s str, Defect>
    {
        let value = self.require(key)?;
        if allowed.contains(&value)
        {
            Ok(value)
        }
        else
        {
            Err(Defect::Malformed(key.to_string()))
        }
    }
}

/// Every block in `log`, in the order of their begin markers. A block whose
/// end marker never comes is returned incomplete; a field or end line whose id
/// no open block carries is ignored, and so is a second begin marker for an
/// id already open, which restarts nothing. A field line that repeats one
/// already read, key and value alike, is read once: crashd writes a line
/// again when its first write was cancelled, and may have landed.
#[must_use]
pub fn parse(log: &str) -> Vec<Block>
{
    let mut blocks: Vec<Block> = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    for line in log.lines()
    {
        let Some(record) = record_of(line)
        else
        {
            continue;
        };
        match record
        {
            Record::Begin { id, version } =>
            {
                if !open.iter().any(|&i| blocks[i].id == id)
                {
                    open.push(blocks.len());
                    blocks.push(Block {
                        id,
                        version,
                        fields: Vec::new(),
                        end: None,
                    });
                }
            }
            Record::Field { id, key, value } =>
            {
                if let Some(&i) = open.iter().find(|&&i| blocks[i].id == id)
                {
                    // A line written again after a cancelled write, which
                    // may have landed, counts once.
                    let fields = &mut blocks[i].fields;
                    if !fields.iter().any(|(k, v)| k == key && v == value)
                    {
                        fields.push((key.to_string(), value.to_string()));
                    }
                }
            }
            Record::End { id, count } =>
            {
                if let Some(pos) = open.iter().position(|&i| blocks[i].id == id)
                {
                    let i = open.remove(pos);
                    blocks[i].end = Some(count);
                }
            }
        }
    }
    blocks
}

/// One tagged line.
enum Record<'a>
{
    Begin
    {
        id: u64, version: u32
    },
    Field
    {
        id: u64,
        key: &'a str,
        value: &'a str,
    },
    End
    {
        id: u64, count: usize
    },
}

/// The record a log line carries, found by its tag wherever it starts.
fn record_of(line: &str) -> Option<Record<'_>>
{
    // The end and begin tags both begin with the field tag, so they are tried
    // first.
    if let Some(at) = line.find(BEGIN_TAG)
    {
        let rest = line[at + BEGIN_TAG.len()..].trim();
        let (id, rest) = id_word(rest)?;
        let version = rest.trim().strip_prefix("version=")?.parse().ok()?;
        return Some(Record::Begin { id, version });
    }
    if let Some(at) = line.find(END_TAG)
    {
        let rest = line[at + END_TAG.len()..].trim();
        let (id, rest) = id_word(rest)?;
        let count = rest.trim().strip_prefix("lines=")?.parse().ok()?;
        return Some(Record::End { id, count });
    }
    let at = line.find(FIELD_TAG)?;
    let rest = line[at + FIELD_TAG.len()..].strip_prefix(' ')?;
    let (id, rest) = id_word(rest)?;
    let (key, value) = rest.trim().split_once('=')?;
    if key.is_empty() || key.contains(' ')
    {
        return None;
    }
    Some(Record::Field { id, key, value })
}

/// Split a leading `id=<16 hex digits>` word off `text`.
fn id_word(text: &str) -> Option<(u64, &str)>
{
    let rest = text.strip_prefix("id=")?;
    let (word, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    if word.len() != 16
    {
        return None;
    }
    Some((u64::from_str_radix(word, 16).ok()?, rest))
}

/// A `0x`-prefixed hexadecimal word.
fn parse_hex(text: &str) -> Option<u64>
{
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}
