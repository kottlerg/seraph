// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/stack_sizes.rs

//! The riscv64 kernel frame check: every function's fixed frame, read from the
//! linked image's `.stack_sizes` section, against
//! [`RISCV64_KERNEL_FRAME_MAX`].
//!
//! rustc writes the section under `-Z emit-stack-sizes`: one entry per
//! function, its address (eight bytes, little-endian) and its frame size in
//! bytes (ULEB128). The linker keeps an entry only for a function it keeps.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind};

/// The largest fixed frame, in bytes, of a function in the riscv64 kernel
/// image (docs/coding-standards.md § Kernel Stack Frames).
///
/// A riscv64 `call` writes nothing to the stack, and a larger frame's split
/// prologue leaves up to 6120 bytes below its return-address save unwritten
/// (the rest of its first, 2032-byte adjustment and up to a page of the
/// second, which no stack probe touches), so such a frame can step over a
/// stack's guard page. Each function stores only inside its
/// own frame, and a function that calls saves its return address in its own,
/// so with every frame at most this size two consecutive stack stores are
/// less than `2 * 2032 = 4064` bytes apart and no 4 KiB guard page lies
/// between them. 2032 is also the largest frame LLVM allocates in one
/// adjustment whose register saves stay within the 12-bit immediate, so no
/// frame within the bound is split.
pub const RISCV64_KERNEL_FRAME_MAX: u64 = 2032;

/// One `.stack_sizes` entry: a function's address and its frame size.
#[derive(Debug, PartialEq, Eq)]
struct Entry
{
    address: u64,
    frame: u64,
}

/// A function whose frame passes the bound.
#[derive(Debug, PartialEq, Eq)]
pub struct Oversized
{
    /// The demangled name of the function's symbol, or its address in hex
    /// when the symbol table names none there.
    pub name: String,
    pub frame: u64,
}

/// Decode a `.stack_sizes` section's contents.
///
/// # Errors
///
/// Fails on a truncated entry, or on a size whose ULEB128 encoding does not
/// fit in 64 bits.
fn parse_entries(mut data: &[u8]) -> Result<Vec<Entry>>
{
    let mut entries = Vec::new();
    while !data.is_empty()
    {
        let Some((address, rest)) = data.split_first_chunk::<8>()
        else
        {
            bail!("truncated .stack_sizes entry: {} address bytes", data.len());
        };
        let (frame, rest) = read_uleb128(rest)?;
        entries.push(Entry {
            address: u64::from_le_bytes(*address),
            frame,
        });
        data = rest;
    }
    Ok(entries)
}

/// Read one ULEB128 value from the front of `data`; return it and the rest.
fn read_uleb128(data: &[u8]) -> Result<(u64, &[u8])>
{
    let mut value: u64 = 0;
    for (index, &byte) in data.iter().enumerate()
    {
        let shift = index.saturating_mul(7);
        let bits = u64::from(byte & 0x7f);
        // The tenth byte holds bit 63 alone; anything above it overflows.
        if shift >= 64 || (shift == 63 && bits > 1)
        {
            bail!("a .stack_sizes frame size does not fit in 64 bits");
        }
        value |= bits << shift;
        if byte & 0x80 == 0
        {
            return Ok((
                value,
                data.get(index.saturating_add(1)..).unwrap_or_default(),
            ));
        }
    }
    bail!("truncated .stack_sizes frame size")
}

/// Every function of the ELF image `data` whose frame exceeds `max` bytes,
/// largest first.
///
/// # Errors
///
/// Fails when `data` is not an ELF image, when it has no `.stack_sizes`
/// section (the build did not pass `-Z emit-stack-sizes`), or when the
/// section is malformed.
pub fn oversized_frames(data: &[u8], max: u64) -> Result<Vec<Oversized>>
{
    let file = object::File::parse(data).context("not an ELF image")?;
    let section = file.section_by_name(".stack_sizes").context(
        "the image has no .stack_sizes section; it was built without -Z emit-stack-sizes",
    )?;
    let entries = parse_entries(section.data()?)?;
    let mut oversized: Vec<Oversized> = entries
        .into_iter()
        .filter(|entry| entry.frame > max)
        .map(|entry| Oversized {
            name: function_name(&file, entry.address),
            frame: entry.frame,
        })
        .collect();
    oversized.sort_by(|a, b| b.frame.cmp(&a.frame).then_with(|| a.name.cmp(&b.name)));
    Ok(oversized)
}

/// The demangled name of the function symbol at `address`, or the address in
/// hex when there is none.
fn function_name(file: &object::File<'_>, address: u64) -> String
{
    file.symbols()
        .filter(|sym| sym.kind() == SymbolKind::Text && sym.is_definition())
        .find(|sym| sym.address() == address)
        .and_then(|sym| sym.name().ok())
        .map_or_else(|| format!("{address:#x}"), crate::symbolize::demangle)
}

/// Fail when a function of the riscv64 kernel image at `image` has a frame
/// above [`RISCV64_KERNEL_FRAME_MAX`], naming each.
///
/// # Errors
///
/// Fails when the image cannot be read or parsed, or when a frame passes the
/// bound.
pub fn check_riscv64_kernel(image: &Path) -> Result<()>
{
    let data = std::fs::read(image).with_context(|| format!("reading {}", image.display()))?;
    let oversized = oversized_frames(&data, RISCV64_KERNEL_FRAME_MAX)
        .with_context(|| format!("checking the frames of {}", image.display()))?;
    if oversized.is_empty()
    {
        return Ok(());
    }
    let list: Vec<String> = oversized
        .iter()
        .map(|o| format!("  {:>6} B  {}", o.frame, o.name))
        .collect();
    bail!(
        "{} riscv64 kernel function(s) have a frame above {RISCV64_KERNEL_FRAME_MAX} B, the \
         bound docs/coding-standards.md § Kernel Stack Frames sets:\n{}",
        oversized.len(),
        list.join("\n")
    )
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::symbolize::fixture::{Architecture, KERNEL_BASE, LEAF, OUTER, elf};

    /// A `.stack_sizes` section with one entry per `(address, frame)`.
    fn section(entries: &[(u64, u64)]) -> Vec<u8>
    {
        let mut data = Vec::new();
        for &(address, mut frame) in entries
        {
            data.extend_from_slice(&address.to_le_bytes());
            loop
            {
                let byte = (frame & 0x7f) as u8;
                frame >>= 7;
                if frame == 0
                {
                    data.push(byte);
                    break;
                }
                data.push(byte | 0x80);
            }
        }
        data
    }

    fn image(entries: &[(u64, u64)]) -> Vec<u8>
    {
        elf(
            Architecture::Riscv64,
            KERNEL_BASE,
            vec![(".stack_sizes", section(entries), 0)],
        )
    }

    // Defect guarded: a check that passes a frame above the bound, the one
    // that lets a riscv64 kernel frame step over a stack's guard page, or
    // that names the wrong function.
    #[test]
    fn a_frame_above_the_bound_is_reported_by_name_and_one_at_it_is_not()
    {
        let data = image(&[
            (KERNEL_BASE + OUTER, 4176),
            (KERNEL_BASE + LEAF, RISCV64_KERNEL_FRAME_MAX),
        ]);
        let oversized = oversized_frames(&data, RISCV64_KERNEL_FRAME_MAX).unwrap();
        assert_eq!(
            oversized,
            vec![Oversized {
                name: "fixture::outer".into(),
                frame: 4176,
            }]
        );
    }

    // Defect guarded: a frame size decoded from the wrong bytes, so a
    // multi-byte ULEB128 size (any frame of 128 B or more) reads small, and
    // an entry with no symbol at its address dropped from the report.
    #[test]
    fn every_entry_is_decoded_and_an_unnamed_one_is_reported_by_address()
    {
        let data = image(&[
            (KERNEL_BASE + LEAF, 16),
            (KERNEL_BASE + 0x10, 9648),
            (KERNEL_BASE + OUTER, 2033),
        ]);
        let oversized = oversized_frames(&data, RISCV64_KERNEL_FRAME_MAX).unwrap();
        assert_eq!(
            oversized,
            vec![
                Oversized {
                    name: format!("{:#x}", KERNEL_BASE + 0x10),
                    frame: 9648,
                },
                Oversized {
                    name: "fixture::outer".into(),
                    frame: 2033,
                },
            ]
        );
    }

    // Defect guarded: an image built without the flag passing the check
    // because it has no entries to fail on.
    #[test]
    fn an_image_without_the_section_is_refused()
    {
        let data = elf(Architecture::Riscv64, KERNEL_BASE, Vec::new());
        let err = oversized_frames(&data, RISCV64_KERNEL_FRAME_MAX).unwrap_err();
        assert!(err.to_string().contains("emit-stack-sizes"), "{err}");
    }

    // Defect guarded: a truncated or overlong section read as fewer or
    // smaller frames instead of refused.
    #[test]
    fn a_malformed_section_is_refused()
    {
        let mut truncated_size = section(&[(KERNEL_BASE + OUTER, 4176)]);
        truncated_size.pop();
        let truncated_address = vec![0u8; 5];
        let mut overlong = (KERNEL_BASE + OUTER).to_le_bytes().to_vec();
        overlong.extend_from_slice(&[0xff; 10]);
        overlong.push(0x01);
        for data in [truncated_size, truncated_address, overlong]
        {
            assert!(parse_entries(&data).is_err(), "{data:?}");
        }
    }
}
