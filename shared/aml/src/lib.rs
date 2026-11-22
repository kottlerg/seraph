// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/lib.rs

//! The ACPI Machine Language (AML) of ACPI 6.5 § 20: its encodings, the
//! resource-template decoder, the term parser, the namespace a DSDT and its
//! SSDTs load into, and the evaluator that runs their code.
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
//! - [`value`]: the values of data objects and of evaluation, and the
//!   implicit and explicit conversions of ACPI 6.5 § 19.3.5.
//! - [`eval`]: the evaluator, which runs control methods and module-level
//!   code, and [`host`], the trait through which it reaches operation
//!   regions, notifications, delays and the global lock.
//!
//! Every bound is a constant of this crate, stated in docs/limits.md.
//! Every allocation is fallible, every read is bounds-checked, and every
//! loop advances, so any byte string loads or parses to a result or a
//! [`Fault`], never a panic, and any code evaluates to a value or a fault.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod encoding;
pub mod eval;
pub mod host;
mod load;
pub mod namespace;
pub mod parse;
pub mod resource;
pub mod term;
pub mod value;

#[cfg(test)]
mod tests;

pub use eval::{Evaluator, ModuleReport};
pub use host::{Host, HostError};
pub use load::LoadReport;
pub use namespace::Namespace;
pub use value::Data;

/// The deepest nesting of terms the parser follows: an operand inside an
/// operand, a term list inside an `If`, a package inside a package. The
/// table loader's nesting of `Scope`, `Device` and the other object bodies
/// counts against it too.
///
/// Unreachable on real tables: term nesting is the nesting of the ASL
/// source's expressions and blocks, which no machine's size deepens. The one
/// construct whose depth grows with a count, an `Else` whose body is one
/// `If` (a compiled `Switch` makes one per `Case`), is parsed at the depth
/// of the `If` it follows ([`term::Op::ElseIf`]). Object bodies nest as the
/// device hierarchy does, a level or two per bridge.
pub const MAX_PARSE_DEPTH: usize = 64;

/// The stack a thread that loads and parses AML needs: enough for a table
/// load whose object bodies nest to [`MAX_PARSE_DEPTH`] and, at that depth,
/// a parse nested to it. The host tests load and parse such a table on a
/// thread of this size; it needs about 104 KiB on x86-64 and 116 KiB on
/// riscv64, so this is a little over twice the measured peak.
pub const PARSE_STACK_BYTES: usize = 256 * 1024;

/// The largest buffer or string: the `BufferSize` of a buffer a `Name` in a
/// table declares, the length of a string in a table's AML, and the length
/// of a buffer or string an evaluation makes.
///
/// It bounds the size of one data object, which the firmware's source fixes
/// and the machine's size does not enlarge, so that a few bytes of a
/// malformed table cannot make the loader allocate gigabytes.
pub const MAX_BUFFER_BYTES: usize = 65_536;

/// The longest chain of aliases a name is followed through, an `Alias` of
/// an `Alias` counting two. Past it the name resolves to nothing: a call
/// through it parses as a reference, and its evaluation faults `NotFound`.
///
/// Firmware aliases an object directly, or through one alias; the length of
/// a chain is the ASL source's, which the machine's size does not lengthen.
pub const MAX_ALIAS_CHAIN: usize = 8;

/// The largest element count of a package: one a `Name` in a table
/// declares, and one an evaluation makes.
///
/// A `Package`'s count is one byte by the encoding; a `VarPackage`'s is a
/// term, which this bounds as [`MAX_BUFFER_BYTES`] bounds a buffer.
pub const MAX_PACKAGE_ELEMENTS: usize = 4096;

/// The deepest nesting of method calls an evaluation follows.
///
/// ACPI code calls a few levels deep: a method calls helpers that read
/// fields, which may run an index field's own accesses. A machine's size
/// adds devices, not depth.
pub const MAX_CALL_DEPTH: usize = 32;

/// The deepest nesting on the stack of one evaluation: the terms being
/// evaluated, an operand inside an operand inside a statement, summed over
/// every method call in progress, and the field accesses that reach other
/// fields. The parser's [`MAX_PARSE_DEPTH`] bounds each method's own nesting;
/// this bounds their sum across calls, so the stack an evaluation needs is
/// bounded whatever the code ([`EVAL_STACK_BYTES`]).
pub const MAX_EVAL_DEPTH: usize = 256;

/// The stack a thread that runs the evaluator needs: enough for an
/// evaluation nested to [`MAX_EVAL_DEPTH`] and, at that depth, the parse of
/// a called method's code nested to [`MAX_PARSE_DEPTH`]. The host tests run
/// such an evaluation on a thread of this size; the evaluation needs about
/// 210 KiB on x86-64 and 217 KiB on riscv64, so this is a little over twice
/// that peak plus [`PARSE_STACK_BYTES`].
pub const EVAL_STACK_BYTES: usize = 768 * 1024;

/// The most terms one evaluation runs. It bounds every loop: a `While`
/// whose predicate never fails ends here.
///
/// Firmware loops poll hardware for at most some milliseconds, a few
/// thousand passes; a method that walks a table runs as many terms as the
/// table has entries.
pub const MAX_EVAL_STEPS: usize = 1_000_000;

/// The most bytes of values one evaluation makes. Each string, buffer,
/// package or reference an operator, a read or a call gives is counted
/// once, where it is made, whether or not it is kept; the copy a store
/// writes to its target is not counted again. It bounds the memory a loop
/// that builds values can use.
pub const MAX_EVAL_ALLOC: usize = 16 * 1024 * 1024;

/// The deepest nesting of packages in one value: a package whose element is
/// a package. Firmware nests two or three levels (`_PRT`, `_PSS`, `_DSD`).
pub const MAX_VALUE_DEPTH: usize = 64;

/// The most objects one evaluation creates. Method-local objects are
/// removed when their method returns and are subtracted again; the bound
/// limits those alive at once and the objects module-level code adds.
pub const MAX_EVAL_OBJECTS: usize = 4096;

/// The longest `Stall`, in microseconds, as ACPI 6.5 § 19.6.129 limits it.
pub const MAX_STALL_US: u64 = 255;

/// The most time one evaluation spends in `Sleep`, `Stall`, the timeouts
/// of `Wait` and waits for the global lock, in milliseconds. Firmware
/// sleeps to let hardware settle, for at most some hundreds of milliseconds
/// per method.
pub const MAX_EVAL_DELAY_MS: u64 = 10_000;

/// The value of `Revision` (`RevisionOp`): this interpreter's revision.
pub const REVISION: u64 = 1;

/// Why a term could not be parsed, loaded or evaluated.
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
    /// Nesting deeper than [`MAX_PARSE_DEPTH`], [`MAX_CALL_DEPTH`] or
    /// [`MAX_EVAL_DEPTH`].
    Depth,
    /// An allocation failed.
    NoMemory,
    /// A bound of this crate was reached: [`MAX_BUFFER_BYTES`],
    /// [`MAX_PACKAGE_ELEMENTS`], an evaluation bound ([`MAX_EVAL_STEPS`],
    /// [`MAX_EVAL_ALLOC`], [`MAX_VALUE_DEPTH`], [`MAX_EVAL_OBJECTS`],
    /// [`MAX_EVAL_DELAY_MS`]), or the width of an id or a table offset.
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
    /// An operand of a type the operator does not take, or that cannot be
    /// converted to one it does.
    Type,
    /// An index, a length or a value outside what its operand allows.
    Range,
    /// A `Divide` or `Mod` by zero.
    DivideByZero,
    /// A read of a local, an argument or a result that holds no value.
    Uninitialized,
    /// An `Acquire` or `Release` that breaks the mutex ordering rule, or a
    /// `Release` of a mutex not held.
    MutexOrder,
    /// A call with more arguments than a method takes, or a read of a
    /// method that takes arguments as an operand.
    Args,
    /// An operator, a region space or a field this evaluator does not
    /// support: `Load`, `LoadTable`, `Unload`, `DataTableRegion`,
    /// `Connection`, and the region spaces other than `SystemMemory`,
    /// `SystemIO` and `PCI_Config`.
    Unsupported,
    /// The code ran `Fatal`.
    Fatal,
    /// A `Wait` with no timeout on an event nothing can signal.
    Deadlock,
    /// The host refused or failed a region access, a notification or the
    /// global lock.
    Host(HostError),
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
