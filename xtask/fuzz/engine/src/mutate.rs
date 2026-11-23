// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/mutate.rs

//! The mutator: AFL-style havoc (a stack of random edits), splice, a
//! dictionary of the constants the target compares against, and
//! input-to-state replacement from the compare operands of recent executions
//! ([`crate::cmp`]).

use std::collections::BTreeSet;

use crate::cmp::Operands;
use crate::rng::Rng;

/// Values that sit on the boundaries parsers test: zero, one, the signed and
/// unsigned limits of each width, and common sizes.
const INTERESTING: [u64; 24] = [
    0,
    1,
    2,
    0x10,
    0x20,
    0x40,
    0x7F,
    0x80,
    0xFF,
    0x100,
    0x200,
    0x400,
    0x1000,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x1_0000,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0x1_0000_0000,
    0x7FFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000,
    u64::MAX,
];

/// The widths, in bytes, of the integers the mutator writes.
const WIDTHS: [usize; 4] = [1, 2, 4, 8];

/// The most entries the dictionary holds.
const MAX_DICTIONARY: usize = 1024;

/// The largest block a block edit inserts, deletes or copies.
const MAX_BLOCK: usize = 64;

/// The byte order an integer is written in.
#[derive(Clone, Copy)]
enum Endian
{
    Little,
    Big,
}

/// The low `width` bytes of `value` in `endian` order; `width` is at most 8.
fn encode(value: u64, width: usize, endian: Endian) -> Vec<u8>
{
    match endian
    {
        Endian::Little => value.to_le_bytes().into_iter().take(width).collect(),
        Endian::Big => value
            .to_be_bytes()
            .into_iter()
            .skip(8usize.saturating_sub(width))
            .collect(),
    }
}

/// The `width`-byte integer at `offset` in `endian` order, or `None` when it
/// runs past the end of `data`.
fn decode(data: &[u8], offset: usize, width: usize, endian: Endian) -> Option<u64>
{
    let bytes = data.get(offset..offset.checked_add(width)?)?;
    let mut word = [0u8; 8];
    match endian
    {
        Endian::Little =>
        {
            word.get_mut(..width)?.copy_from_slice(bytes);
            Some(u64::from_le_bytes(word))
        }
        Endian::Big =>
        {
            word.get_mut(8usize.checked_sub(width)?..)?
                .copy_from_slice(bytes);
            Some(u64::from_be_bytes(word))
        }
    }
}

/// Write `bytes` over `data` from `offset`, cut at the end of `data`.
fn overwrite(data: &mut [u8], offset: usize, bytes: &[u8])
{
    let Some(tail) = data.get_mut(offset..)
    else
    {
        return;
    };
    for (dst, &src) in tail.iter_mut().zip(bytes)
    {
        *dst = src;
    }
}

/// The offsets of up to 16 occurrences of `needle` in `data`.
fn occurrences(data: &[u8], needle: &[u8]) -> Vec<usize>
{
    if needle.is_empty()
    {
        return Vec::new();
    }
    data.windows(needle.len())
        .enumerate()
        .filter(|&(_, window)| window == needle)
        .map(|(offset, _)| offset)
        .take(16)
        .collect()
}

/// The edits havoc chooses from.
#[derive(Clone, Copy)]
enum Edit
{
    FlipBit,
    RandomByte,
    Interesting,
    Arithmetic,
    DeleteBlock,
    InsertBlock,
    CopyBlock,
    DictionaryInsert,
    DictionaryOverwrite,
    Replace,
}

/// Every [`Edit`], each equally likely.
const EDITS: [Edit; 10] = [
    Edit::FlipBit,
    Edit::RandomByte,
    Edit::Interesting,
    Edit::Arithmetic,
    Edit::DeleteBlock,
    Edit::InsertBlock,
    Edit::CopyBlock,
    Edit::DictionaryInsert,
    Edit::DictionaryOverwrite,
    Edit::Replace,
];

/// The mutator of one run: its length bound and the dictionary it has learnt.
pub struct Mutator
{
    max_len: usize,
    dictionary: Vec<Vec<u8>>,
    known: BTreeSet<Vec<u8>>,
}

impl Mutator
{
    /// A mutator whose outputs are at most `max_len` bytes long.
    #[must_use]
    pub fn new(max_len: usize) -> Self
    {
        Self {
            max_len,
            dictionary: Vec::new(),
            known: BTreeSet::new(),
        }
    }

    /// The number of dictionary entries learnt so far.
    #[must_use]
    pub fn dictionary_len(&self) -> usize
    {
        self.dictionary.len()
    }

    /// Learn the constants among `operands`: each constant wider than one
    /// byte and above 1, in both byte orders, until the dictionary is full.
    pub fn learn(&mut self, operands: &[Operands])
    {
        for op in operands
            .iter()
            .filter(|op| op.constant && op.width > 1 && op.left > 1)
        {
            for endian in [Endian::Little, Endian::Big]
            {
                let token = encode(op.left, usize::from(op.width), endian);
                if self.dictionary.len() < MAX_DICTIONARY && self.known.insert(token.clone())
                {
                    self.dictionary.push(token);
                }
            }
        }
    }

    /// Mutate `data` in place: splice it with `other` when given, then apply a
    /// stack of 1 to 16 random edits, `operands` being the compare pairs the
    /// replacement edit draws from; the result is cut to the length bound.
    pub fn mutate(
        &self,
        rng: &mut Rng,
        data: &mut Vec<u8>,
        other: Option<&[u8]>,
        operands: &[Operands],
    )
    {
        if let Some(other) = other
        {
            splice(rng, data, other);
        }
        let edits = 1u32.wrapping_shl(u32::try_from(rng.below(5)).unwrap_or(0));
        for _ in 0..edits
        {
            let edit = EDITS
                .get(rng.index(EDITS.len()))
                .copied()
                .unwrap_or(Edit::FlipBit);
            self.apply(rng, data, edit, operands);
        }
        data.truncate(self.max_len);
    }

    /// Apply one `edit` to `data`.
    fn apply(&self, rng: &mut Rng, data: &mut Vec<u8>, edit: Edit, operands: &[Operands])
    {
        match edit
        {
            Edit::FlipBit =>
            {
                let bit = u32::try_from(rng.below(8)).unwrap_or(0);
                let at = rng.index(data.len());
                if let Some(byte) = data.get_mut(at)
                {
                    *byte ^= 1u8.wrapping_shl(bit);
                }
            }
            Edit::RandomByte =>
            {
                let value = rng.byte();
                let at = rng.index(data.len());
                if let Some(byte) = data.get_mut(at)
                {
                    *byte = value;
                }
            }
            Edit::Interesting => write_interesting(rng, data),
            Edit::Arithmetic => arithmetic(rng, data),
            Edit::DeleteBlock => delete_block(rng, data),
            Edit::InsertBlock => self.insert_block(rng, data),
            Edit::CopyBlock => copy_block(rng, data),
            Edit::DictionaryInsert | Edit::DictionaryOverwrite =>
            {
                let Some(token) = self.dictionary.get(rng.index(self.dictionary.len()))
                else
                {
                    return;
                };
                let at = rng.index(data.len().saturating_add(1));
                if matches!(edit, Edit::DictionaryInsert)
                {
                    self.insert(data, at, token);
                }
                else
                {
                    overwrite(data, at, token);
                }
            }
            Edit::Replace =>
            {
                if let Some(&pair) = operands.get(rng.index(operands.len()))
                {
                    replace(rng, data, pair);
                }
            }
        }
    }

    /// Insert `bytes` at `at`, within the length bound.
    fn insert(&self, data: &mut Vec<u8>, at: usize, bytes: &[u8])
    {
        let room = self.max_len.saturating_sub(data.len());
        let bytes = bytes.get(..bytes.len().min(room)).unwrap_or_default();
        if at <= data.len()
        {
            data.splice(at..at, bytes.iter().copied());
        }
    }

    /// Insert a block of up to [`MAX_BLOCK`] bytes, random or copied from
    /// `data` itself, at a random offset.
    fn insert_block(&self, rng: &mut Rng, data: &mut Vec<u8>)
    {
        let len = rng.index(MAX_BLOCK).saturating_add(1);
        let block: Vec<u8> = if data.is_empty() || rng.one_in(2)
        {
            (0..len).map(|_| rng.byte()).collect()
        }
        else
        {
            let from = rng.index(data.len());
            data.iter().skip(from).take(len).copied().collect()
        };
        let at = rng.index(data.len().saturating_add(1));
        self.insert(data, at, &block);
    }
}

/// Cut `data` at a random point and append the tail of `other` from another.
fn splice(rng: &mut Rng, data: &mut Vec<u8>, other: &[u8])
{
    let keep = rng.index(data.len().saturating_add(1));
    let from = rng.index(other.len().saturating_add(1));
    data.truncate(keep);
    data.extend_from_slice(other.get(from..).unwrap_or_default());
}

/// Write an [`INTERESTING`] value of a random width and byte order at a random
/// offset.
fn write_interesting(rng: &mut Rng, data: &mut [u8])
{
    let value = INTERESTING
        .get(rng.index(INTERESTING.len()))
        .copied()
        .unwrap_or(0);
    let width = WIDTHS.get(rng.index(WIDTHS.len())).copied().unwrap_or(1);
    let endian = if rng.one_in(2)
    {
        Endian::Little
    }
    else
    {
        Endian::Big
    };
    let at = rng.index(data.len());
    overwrite(data, at, &encode(value, width, endian));
}

/// Add or subtract 1 to 16 from the integer of a random width and byte order at
/// a random offset.
fn arithmetic(rng: &mut Rng, data: &mut [u8])
{
    let width = WIDTHS.get(rng.index(WIDTHS.len())).copied().unwrap_or(1);
    let endian = if rng.one_in(2)
    {
        Endian::Little
    }
    else
    {
        Endian::Big
    };
    let at = rng.index(data.len());
    let delta = rng.below(16).wrapping_add(1);
    if let Some(value) = decode(data, at, width, endian)
    {
        let value = if rng.one_in(2)
        {
            value.wrapping_add(delta)
        }
        else
        {
            value.wrapping_sub(delta)
        };
        overwrite(data, at, &encode(value, width, endian));
    }
}

/// Remove a block of up to [`MAX_BLOCK`] bytes at a random offset.
fn delete_block(rng: &mut Rng, data: &mut Vec<u8>)
{
    let len = rng.index(MAX_BLOCK.min(data.len())).saturating_add(1);
    let at = rng.index(data.len().saturating_sub(len).saturating_add(1));
    if let Some(end) = at.checked_add(len).filter(|&end| end <= data.len())
    {
        data.drain(at..end);
    }
}

/// Copy a block of up to [`MAX_BLOCK`] bytes of `data` over another place in it.
fn copy_block(rng: &mut Rng, data: &mut [u8])
{
    let from = rng.index(data.len());
    let to = rng.index(data.len());
    let len = rng
        .index(MAX_BLOCK)
        .saturating_add(1)
        .min(data.len().saturating_sub(from))
        .min(data.len().saturating_sub(to));
    if let Some(end) = from.checked_add(len).filter(|&end| end <= data.len())
        && to.checked_add(len).is_some_and(|end| end <= data.len())
    {
        data.copy_within(from..end, to);
    }
}

/// The fewest bytes of 1, 2, 4 and 8 that hold both `a` and `b`.
fn narrowest(a: u64, b: u64) -> usize
{
    match a | b
    {
        0..=0xFF => 1,
        0x100..=0xFFFF => 2,
        0x1_0000..=0xFFFF_FFFF => 4,
        _ => 8,
    }
}

/// Input-to-state replacement: where `data` holds one operand of `pair` in
/// either byte order, write the other there (or the other plus or minus one,
/// to cross a less-than comparison); where it holds neither, write the
/// constant (or either operand) at a random offset. Half the time the
/// operands are read at the fewest bytes that hold them, so a field the
/// target widens before it compares (a length byte held to a `usize`) is
/// found too.
fn replace(rng: &mut Rng, data: &mut [u8], pair: Operands)
{
    let full = usize::from(pair.width);
    let width = if rng.one_in(2)
    {
        narrowest(pair.left, pair.right).min(full)
    }
    else
    {
        full
    };
    let first = if rng.one_in(2)
    {
        Endian::Little
    }
    else
    {
        Endian::Big
    };
    let second = match first
    {
        Endian::Little => Endian::Big,
        Endian::Big => Endian::Little,
    };
    let directions = if rng.one_in(2)
    {
        [(pair.left, pair.right), (pair.right, pair.left)]
    }
    else
    {
        [(pair.right, pair.left), (pair.left, pair.right)]
    };
    let nudge = match rng.below(4)
    {
        0 => 1u64,
        1 => u64::MAX,
        _ => 0,
    };
    for endian in [first, second]
    {
        for (found, wanted) in directions
        {
            let places = occurrences(data, &encode(found, width, endian));
            if let Some(&at) = places.get(rng.index(places.len()))
            {
                overwrite(data, at, &encode(wanted.wrapping_add(nudge), width, endian));
                return;
            }
        }
    }
    let value = if pair.constant || rng.one_in(2)
    {
        pair.left
    }
    else
    {
        pair.right
    };
    let at = rng.index(data.len());
    overwrite(data, at, &encode(value, width, first));
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a length byte the target compares as a `usize` never
    // matched, since its eight-byte encoding is not in the input.
    #[test]
    fn replacement_finds_a_widened_field_at_its_own_width()
    {
        let pair = Operands {
            width: 8,
            left: 0x30,
            right: 0x05,
            constant: false,
        };
        let replaced = (0..64).any(|seed| {
            let mut rng = Rng::new(seed);
            let mut data = vec![0xEE, 0x30, 0xEE, 0xEE];
            replace(&mut rng, &mut data, pair);
            data == [0xEE, 0x05, 0xEE, 0xEE]
        });
        assert!(replaced);
        assert_eq!(narrowest(0xFF, 1), 1);
        assert_eq!(narrowest(0x100, 1), 2);
        assert_eq!(narrowest(0x1_0000, 0), 4);
        assert_eq!(narrowest(1 << 32, 0), 8);
    }

    #[test]
    fn integers_encode_and_decode_at_every_width_in_both_orders()
    {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        assert_eq!(decode(&data, 1, 2, Endian::Little), Some(0x3322));
        assert_eq!(decode(&data, 1, 2, Endian::Big), Some(0x2233));
        assert_eq!(
            decode(&data, 1, 8, Endian::Little),
            Some(0x9988_7766_5544_3322)
        );
        assert_eq!(decode(&data, 2, 8, Endian::Little), None);
        for width in WIDTHS
        {
            for endian in [Endian::Little, Endian::Big]
            {
                let bytes = encode(0x0102_0304_0506_0708, width, endian);
                assert_eq!(bytes.len(), width);
                let back = decode(&bytes, 0, width, endian).unwrap();
                let mask = u64::MAX >> (64 - 8 * width);
                assert_eq!(back, 0x0102_0304_0506_0708 & mask);
            }
        }
    }

    // Defect caught: input-to-state replacement that misses the operand the
    // input holds, so a multi-byte magic is only ever found by chance.
    #[test]
    fn replacement_writes_the_constant_where_the_input_holds_the_compared_value()
    {
        let pair = Operands {
            width: 4,
            left: 0x4D41_4749,
            right: 0x0403_0201,
            constant: true,
        };
        for seed in 0..32
        {
            let mut rng = Rng::new(seed);
            let mut data = vec![0xEE, 0x01, 0x02, 0x03, 0x04, 0xEE];
            replace(&mut rng, &mut data, pair);
            let magic = 0x4D41_4749u64;
            let near = [magic, magic + 1, magic - 1];
            let value = decode(&data, 1, 4, Endian::Little).unwrap();
            assert!(near.contains(&value), "seed {seed}: {data:x?}");
        }
    }

    #[test]
    fn mutation_is_reproducible_and_stays_within_the_length_bound()
    {
        let mut mutator = Mutator::new(32);
        mutator.learn(&[Operands {
            width: 8,
            left: 0x5452_4150_2049_4645,
            right: 0,
            constant: true,
        }]);
        assert_eq!(mutator.dictionary_len(), 2);
        let run = |seed| {
            let mut rng = Rng::new(seed);
            let mut data = b"seed input".to_vec();
            let mut outputs = Vec::new();
            for _ in 0..200
            {
                mutator.mutate(&mut rng, &mut data, Some(b"other input of more bytes"), &[]);
                assert!(data.len() <= 32, "{}", data.len());
                outputs.push(data.clone());
            }
            outputs
        };
        assert_eq!(run(3), run(3));
    }

    // Defect caught: a dictionary that learns the input's own values, or
    // single bytes and zero, which crowd out the constants.
    #[test]
    fn the_dictionary_learns_only_wide_constants_once_each()
    {
        let mut mutator = Mutator::new(64);
        let constant = Operands {
            width: 2,
            left: 0x1234,
            right: 5,
            constant: true,
        };
        mutator.learn(&[
            constant,
            constant,
            Operands {
                width: 4,
                left: 0x9999,
                right: 1,
                constant: false,
            },
            Operands {
                width: 1,
                left: 0x42,
                right: 1,
                constant: true,
            },
            Operands {
                width: 8,
                left: 1,
                right: 7,
                constant: true,
            },
        ]);
        assert_eq!(mutator.dictionary, [vec![0x34, 0x12], vec![0x12, 0x34]]);
    }
}
