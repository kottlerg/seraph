// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/lib.rs

//! The ACPI Machine Language (AML) of ACPI 6.5 § 20: its encodings, the
//! resource-template decoder, the term parser and the namespace a DSDT and
//! its SSDTs load into.
//!
//! - [`encoding`]: `PkgLength`, `NameString`, integer and string data and
//!   the EISA ID; alloc-free, shared with devmgr's static walk.
//! - [`resource`]: the resource-template decoder; alloc-free.
//! - [`term`] and [`parse`]: the parsed form of AML code and the parser that
//!   produces it, which takes each method's argument count from the
//!   namespace.
//! - [`namespace`]: the object tree, the name search rules of ACPI 6.5
//!   § 5.3, the objects a table load creates and the predefined ones, and
//!   the method-local objects an evaluator adds and removes.
//!
//! Every bound is a constant of this crate, stated in docs/limits.md.
//! Every allocation is fallible, every read is bounds-checked, and every
//! loop advances, so any byte string loads or parses to a result or a
//! [`Fault`], never a panic.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod encoding;
mod load;
pub mod namespace;
pub mod parse;
pub mod resource;
pub mod term;

#[cfg(test)]
mod tests;

pub use load::LoadReport;
pub use namespace::Namespace;

/// The deepest nesting of terms the parser follows: an operand inside an
/// operand, a term list inside an `If`, a package inside a package. The
/// table loader's nesting of `Scope`, `Device` and the other object bodies
/// counts against it too.
pub const MAX_PARSE_DEPTH: usize = 64;

/// The stack a thread that loads and parses AML needs: enough for a table
/// load whose object bodies nest to [`MAX_PARSE_DEPTH`] and, at that depth,
/// a parse nested to it. The host tests load and parse such a table on a
/// thread of this size; it needs about 104 KiB on x86-64 and 116 KiB on
/// riscv64, so this is a little over twice the measured peak.
pub const PARSE_STACK_BYTES: usize = 256 * 1024;

/// The most live nodes a namespace holds, the predefined ones included.
pub const MAX_NODES: usize = 65_536;

/// The largest `BufferSize` of a buffer a `Name` in a table declares.
pub const MAX_BUFFER_BYTES: usize = 65_536;

/// The largest element count of a package a `Name` in a table declares.
pub const MAX_PACKAGE_ELEMENTS: usize = 4096;

/// The value of `Revision` (`RevisionOp`): this interpreter's revision.
pub const REVISION: u64 = 1;

/// Why a term could not be parsed or loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind
{
    /// An encoding runs past the end of its package or table.
    Truncated,
    /// An opcode this position does not allow, or no opcode at all.
    BadOpcode,
    /// A malformed `NameString`.
    BadName,
    /// A statement where an operand was expected.
    NotOperand,
    /// An `Else` that follows no `If`.
    StrayElse,
    /// Nesting deeper than [`MAX_PARSE_DEPTH`].
    Depth,
    /// An allocation failed.
    NoMemory,
    /// A bound of this crate was reached: [`MAX_NODES`],
    /// [`MAX_BUFFER_BYTES`] or [`MAX_PACKAGE_ELEMENTS`].
    Bound,
    /// A `Name` in a table whose data is not constant.
    NotConstant,
    /// A definition of a name that is already defined.
    Exists,
    /// A name that does not resolve where it must: a `Scope`, a definition's
    /// parent, a field's region.
    NotFound,
    /// A table whose header is short or whose length is out of range.
    BadTable,
}

/// A fault and the table offset of the term it was found in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault
{
    /// What went wrong.
    pub kind: FaultKind,
    /// The table offset of the term, or of the encoding, at fault.
    pub offset: u32,
}

impl Fault
{
    /// A fault of `kind` at table offset `offset`.
    #[must_use]
    pub fn at(kind: FaultKind, offset: usize) -> Self
    {
        Self {
            kind,
            offset: u32::try_from(offset).unwrap_or(u32::MAX),
        }
    }
}

/// Append `value` to `v`, failing with [`FaultKind::NoMemory`] instead of
/// aborting when the allocation fails.
pub(crate) fn push<T>(v: &mut alloc::vec::Vec<T>, value: T) -> Result<(), FaultKind>
{
    v.try_reserve(1).map_err(|_| FaultKind::NoMemory)?;
    v.push(value);
    Ok(())
}
