// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/term.rs

//! The parsed form of AML code: a tree of [`Term`]s, one per opcode, name
//! reference or data object, each with an immediate ([`Imm`]) and its
//! operands in encoding order.
//!
//! Every term's operands are its `kids`. A fixed-size operand (a `ByteData`
//! flag, a `WordData` timeout) is an [`Op::Integer`] kid; a term list (the
//! body of an `If`, a `While`, a `Method` or a `Device`) is an [`Op::List`]
//! kid; the name an object definition declares, and the name a reference
//! names, are the term's [`Imm::Name`]. [`Op`] documents the kids of each
//! opcode whose layout the grammar alone does not make plain.

use alloc::vec::Vec;

use crate::encoding::Seg;

/// A `NameString` as written: the scope it is resolved from is the one of
/// the code that holds it, so it is kept unresolved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Name
{
    /// Whether the name starts at the root (`\`).
    pub root: bool,
    /// The number of parent prefixes (`^`).
    pub up: u8,
    /// The segments in order; empty for `NullName`.
    pub segs: Vec<Seg>,
}

impl Name
{
    /// Whether the search rules of ACPI 6.5 § 5.3 apply: a relative name of
    /// one segment with no parent prefix.
    #[must_use]
    pub fn searches(&self) -> bool
    {
        !self.root && self.up == 0 && self.segs.len() == 1
    }
}

/// The immediate of a term: the part that is not an operand term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Imm
{
    /// None.
    None,
    /// An integer: the value of an [`Op::Integer`], the index of an
    /// [`Op::Local`] or [`Op::Arg`].
    Int(u64),
    /// A name: the one a reference or a call names, or the one a definition
    /// declares.
    Name(Name),
    /// Bytes: a string's characters (without its NUL), a buffer's
    /// initializer.
    Bytes(Vec<u8>),
    /// The field list of a `Field`, `IndexField` or `BankField`.
    Fields(FieldList),
}

/// The flags and elements of a field list (ACPI 6.5 § 20.2.5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldList
{
    /// `FieldFlags`: access type (bits 3:0), lock rule (bit 4), update rule
    /// (bits 6:5).
    pub flags: u8,
    /// The elements in order.
    pub elems: Vec<FieldElem>,
}

/// One element of a field list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldElem
{
    /// A field unit of `bits` bits.
    Named
    {
        /// The field unit's name.
        name: Seg,
        /// Its width in bits.
        bits: u32,
    },
    /// `bits` bits skipped (`Offset` and unnamed fields).
    Reserved
    {
        /// The bits skipped.
        bits: u32,
    },
    /// `AccessAs`: the access type and attribute for the elements after it.
    Access
    {
        /// `AccessType`: access width (bits 3:0) and attribute kind (7:6).
        kind: u8,
        /// `AccessAttrib`.
        attrib: u8,
    },
    /// Extended `AccessAs`, with an access length.
    ExtendedAccess
    {
        /// `AccessType`.
        kind: u8,
        /// `ExtendedAccessAttrib`.
        attrib: u8,
        /// `AccessLength`.
        len: u8,
    },
    /// `Connection`: an [`Op::NameRef`] or an [`Op::Buffer`] term.
    Connect(Term),
}

/// What a term is. Ops other than the pseudo-ops at the top map one to one
/// onto AML opcodes, under the names of ACPI 6.5 § 20.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op
{
    // ── Pseudo-ops ────────────────────────────────────────────────────
    /// A constant integer (`Zero`, `One`, `Ones`, a prefixed constant), or a
    /// fixed-size operand; [`Imm::Int`].
    Integer,
    /// A string; [`Imm::Bytes`].
    String,
    /// A name that is not invoked: a reference, a `Target`, a package
    /// element; [`Imm::Name`].
    NameRef,
    /// A method invocation; [`Imm::Name`], the arguments as kids.
    Call,
    /// `Local0`-`Local7`; [`Imm::Int`] the index.
    Local,
    /// `Arg0`-`Arg6`; [`Imm::Int`] the index.
    Arg,
    /// `NullName` as a `Target`: the result is discarded.
    Null,
    /// A term list; the terms as kids.
    List,

    // ── Data objects ──────────────────────────────────────────────────
    /// kids: buffer size; [`Imm::Bytes`] the initializer.
    Buffer,
    /// kids: the elements; [`Imm::Int`] `NumElements`.
    Package,
    /// kids: the element count, then the elements.
    VarPackage,
    /// `Revision`.
    Revision,
    /// `Debug`.
    Debug,

    // ── Named objects ─────────────────────────────────────────────────
    /// [`Imm::Name`] the alias; kids: [`Op::NameRef`] the source.
    Alias,
    /// [`Imm::Name`]; kids: the data object.
    Name,
    /// [`Imm::Name`]; kids: the body list.
    Scope,
    /// [`Imm::Name`]; kids: `MethodFlags`, the body list.
    Method,
    /// [`Imm::Name`]; kids: object type, argument count.
    External,
    /// [`Imm::Name`]; kids: `SyncFlags`.
    Mutex,
    /// [`Imm::Name`].
    Event,
    /// [`Imm::Name`]; kids: region space, offset, length.
    OpRegion,
    /// [`Imm::Fields`]; kids: [`Op::NameRef`] the region.
    Field,
    /// [`Imm::Name`]; kids: the body list.
    Device,
    /// [`Imm::Name`]; kids: processor ID, `PBLK` address, `PBLK` length,
    /// the body list.
    Processor,
    /// [`Imm::Name`]; kids: system level, resource order, the body list.
    PowerRes,
    /// [`Imm::Name`]; kids: the body list.
    ThermalZone,
    /// [`Imm::Fields`]; kids: [`Op::NameRef`] the index and data fields.
    IndexField,
    /// [`Imm::Fields`]; kids: [`Op::NameRef`] the region and bank field,
    /// the bank value.
    BankField,
    /// [`Imm::Name`]; kids: signature, OEM ID, OEM table ID.
    DataRegion,
    /// [`Imm::Name`]; kids: source buffer, bit index.
    CreateBitField,
    /// [`Imm::Name`]; kids: source buffer, byte index.
    CreateByteField,
    /// [`Imm::Name`]; kids: source buffer, byte index.
    CreateWordField,
    /// [`Imm::Name`]; kids: source buffer, byte index.
    CreateDWordField,
    /// [`Imm::Name`]; kids: source buffer, byte index.
    CreateQWordField,
    /// [`Imm::Name`]; kids: source buffer, bit index, bit count.
    CreateField,

    // ── Statements ────────────────────────────────────────────────────
    /// kids: predicate, body list, an [`Op::ElseIf`] for each `Else` of the
    /// chain that follows it whose body is one `If`, and the [`Op::Else`]
    /// that ends the chain, if any.
    If,
    /// An `Else` whose body is one `If`, folded into the `If` it follows so
    /// that a chain of them (a compiled `Switch`) does not nest; kids:
    /// predicate, body list. Its offset is the inner `If`'s.
    ElseIf,
    /// kids: body list.
    Else,
    /// kids: predicate, body list.
    While,
    /// `Noop`.
    Noop,
    /// kids: the value.
    Return,
    /// `Break`.
    Break,
    /// `Continue`.
    Continue,
    /// `BreakPoint`.
    BreakPoint,
    /// kids: object, value.
    Notify,
    /// kids: mutex.
    Release,
    /// kids: event.
    Reset,
    /// kids: event.
    Signal,
    /// kids: milliseconds.
    Sleep,
    /// kids: microseconds.
    Stall,
    /// kids: type, code, argument.
    Fatal,
    /// kids: [`Op::NameRef`] the region or field, the handle target.
    Load,
    /// kids: the handle.
    Unload,

    // ── Expressions ───────────────────────────────────────────────────
    /// kids: source, destination.
    Store,
    /// kids: the object.
    RefOf,
    /// kids: operand, operand, target.
    Add,
    /// kids: operand, operand, target.
    Concat,
    /// kids: operand, operand, target.
    Subtract,
    /// kids: the object.
    Increment,
    /// kids: the object.
    Decrement,
    /// kids: operand, operand, target.
    Multiply,
    /// kids: dividend, divisor, remainder target, quotient target.
    Divide,
    /// kids: operand, count, target.
    ShiftLeft,
    /// kids: operand, count, target.
    ShiftRight,
    /// kids: operand, operand, target.
    And,
    /// kids: operand, operand, target.
    Nand,
    /// kids: operand, operand, target.
    Or,
    /// kids: operand, operand, target.
    Nor,
    /// kids: operand, operand, target.
    Xor,
    /// kids: operand, target.
    Not,
    /// kids: operand, target.
    FindSetLeftBit,
    /// kids: operand, target.
    FindSetRightBit,
    /// kids: the reference.
    DerefOf,
    /// kids: template, template, target.
    ConcatRes,
    /// kids: dividend, divisor, target.
    Mod,
    /// kids: the object.
    SizeOf,
    /// kids: source, index, target.
    Index,
    /// kids: package, op, operand, op, operand, start index.
    Match,
    /// kids: the object.
    ObjectType,
    /// kids: operand, operand.
    LAnd,
    /// kids: operand, operand.
    LOr,
    /// kids: operand.
    LNot,
    /// kids: operand, operand.
    LEqual,
    /// kids: operand, operand.
    LGreater,
    /// kids: operand, operand.
    LLess,
    /// kids: operand, target.
    ToBuffer,
    /// kids: operand, target.
    ToDecimalString,
    /// kids: operand, target.
    ToHexString,
    /// kids: operand, target.
    ToInteger,
    /// kids: buffer, length, target.
    ToString,
    /// kids: source, destination.
    CopyObject,
    /// kids: source, index, length, target.
    Mid,
    /// kids: the object, target.
    CondRefOf,
    /// kids: signature, OEM ID, OEM table ID, root path, parameter path,
    /// parameter data.
    LoadTable,
    /// kids: mutex, timeout.
    Acquire,
    /// kids: event, timeout.
    Wait,
    /// kids: operand, target.
    FromBcd,
    /// kids: operand, target.
    ToBcd,
    /// `Timer`.
    Timer,
}

/// One parsed term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term
{
    /// What the term is.
    pub op: Op,
    /// Its immediate.
    pub imm: Imm,
    /// Its operands, in encoding order.
    pub kids: Vec<Term>,
    /// The offset of its first byte in its table.
    pub offset: u32,
}

impl Term
{
    /// The integer immediate, if any.
    #[must_use]
    pub const fn int(&self) -> Option<u64>
    {
        match self.imm
        {
            Imm::Int(v) => Some(v),
            Imm::None | Imm::Name(_) | Imm::Bytes(_) | Imm::Fields(_) => None,
        }
    }

    /// The name immediate, if any.
    #[must_use]
    pub const fn name(&self) -> Option<&Name>
    {
        match &self.imm
        {
            Imm::Name(n) => Some(n),
            Imm::None | Imm::Int(_) | Imm::Bytes(_) | Imm::Fields(_) => None,
        }
    }

    /// The number of terms in this tree, itself included.
    #[must_use]
    pub fn count(&self) -> usize
    {
        let fields = match &self.imm
        {
            Imm::Fields(list) => list
                .elems
                .iter()
                .map(|e| match e
                {
                    FieldElem::Connect(t) => t.count(),
                    FieldElem::Named { .. }
                    | FieldElem::Reserved { .. }
                    | FieldElem::Access { .. }
                    | FieldElem::ExtendedAccess { .. } => 0,
                })
                .fold(0usize, usize::saturating_add),
            Imm::None | Imm::Int(_) | Imm::Name(_) | Imm::Bytes(_) => 0,
        };
        self.kids
            .iter()
            .map(Self::count)
            .fold(fields.saturating_add(1), usize::saturating_add)
    }
}
