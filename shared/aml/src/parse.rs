// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/parse.rs

//! The term parser: AML bytes to [`Term`]s.
//!
//! The grammar of ACPI 6.5 § 20.2 is context-free but for one point: a name
//! in an operand position is a method invocation when it names a method,
//! and the argument terms that follow it are as many as the method takes.
//! The parser asks the [`Namespace`] for that count, resolving the name from
//! the scope of the code it parses by the search rules (an alias is
//! followed, and an `External` of a method gives its count). A name that
//! resolves to nothing else, or to nothing, is a reference.
//!
//! Each operand position takes the kind of operand its opcode's grammar
//! names: a `TermArg` (a name may be a call), a `SuperName` or a `Target` (a
//! name may be a call, and a `Target` may be `NullName`), a name or reference
//! (`RefOf`, `CondRefOf`, `ObjectType`: a name is never invoked), or a
//! `SimpleName` (`CopyObject`'s destination). `LNotEqual`, `LLessEqual` and
//! `LGreaterEqual` are encoded as `LNot` of `LEqual`, `LLess` and `LGreater`,
//! and parse as such. An `Else` that follows an `If` is the `If`'s last kid.
//!
//! Every read is bounded by the end of the package being parsed, nesting is
//! bounded by [`MAX_PARSE_DEPTH`], every term consumes at least one byte, and
//! every allocation is fallible, so any byte string parses to terms or a
//! [`Fault`] without a panic.

use alloc::vec::Vec;

use crate::encoding::{
    self, NameStr, OP_BUFFER, OP_BYTE, OP_DWORD, OP_ELSE, OP_EXT_PREFIX, OP_IF, OP_ONE, OP_ONES,
    OP_PACKAGE, OP_QWORD, OP_STRING, OP_VAR_PACKAGE, OP_WORD, OP_ZERO,
};
use crate::namespace::{Namespace, NodeId};
use crate::term::{FieldElem, FieldList, Imm, Name, Op, Term};
use crate::{Fault, FaultKind, MAX_PARSE_DEPTH, push};

/// `Local0`.
const LOCAL0: u8 = 0x60;
/// `Arg0`.
const ARG0: u8 = 0x68;
/// `Arg6`.
const ARG6: u8 = 0x6E;

/// The kind of operand an operand position takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arg
{
    /// `TermArg`.
    Term,
    /// `SuperName`.
    Super,
    /// `Target`.
    Target,
    /// A name or reference that is never invoked.
    Ref,
    /// `SimpleName`.
    Simple,
    /// A `NameString` that is never invoked.
    Name,
    /// A `DataRefObject` or a name, as a `Name` declares and a package holds.
    Data,
    /// `ByteData`.
    Byte,
    /// `WordData`.
    Word,
    /// `DWordData`.
    DWord,
}

use Arg::{Byte, DWord, Data, Name as N, Ref, Simple, Super, Target as Tg, Term as T, Word};

/// The layout of an opcode's encoding after the opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape
{
    /// Operands.
    Ops(&'static [Arg]),
    /// The name it declares, then operands.
    Decl(&'static [Arg]),
    /// Operands, then the name it declares.
    DeclAfter(&'static [Arg]),
    /// `PkgLength`, the name it declares, operands, then a term list.
    Scoped(&'static [Arg]),
    /// `PkgLength`, a predicate, then a term list.
    Cond,
    /// `PkgLength`, operands, `FieldFlags`, then a field list.
    Fields(&'static [Arg]),
}

/// Whether a name in an operand position may be a method invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Invoke
{
    /// A name of a method is an invocation.
    Call,
    /// A name is a reference whatever it names.
    Never,
}

/// Whether a term is parsed as a statement of a term list or as an operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want
{
    Statement,
    Operand,
}

/// The op and layout of a one-byte opcode other than a data object, a local
/// or an argument.
fn decode(b: u8) -> Option<(Op, Shape)>
{
    const BINARY: Shape = Shape::Ops(&[T, T, Tg]);
    const UNARY: Shape = Shape::Ops(&[T, Tg]);
    const BUFFER_FIELD: Shape = Shape::DeclAfter(&[T, T]);
    Some(match b
    {
        0x06 => (Op::Alias, Shape::DeclAfter(&[N])),
        0x08 => (Op::Name, Shape::Decl(&[Data])),
        0x10 => (Op::Scope, Shape::Scoped(&[])),
        0x14 => (Op::Method, Shape::Scoped(&[Byte])),
        0x15 => (Op::External, Shape::Decl(&[Byte, Byte])),
        0x70 => (Op::Store, Shape::Ops(&[T, Super])),
        0x71 => (Op::RefOf, Shape::Ops(&[Ref])),
        0x72 => (Op::Add, BINARY),
        0x73 => (Op::Concat, BINARY),
        0x74 => (Op::Subtract, BINARY),
        0x75 => (Op::Increment, Shape::Ops(&[Super])),
        0x76 => (Op::Decrement, Shape::Ops(&[Super])),
        0x77 => (Op::Multiply, BINARY),
        0x78 => (Op::Divide, Shape::Ops(&[T, T, Tg, Tg])),
        0x79 => (Op::ShiftLeft, BINARY),
        0x7A => (Op::ShiftRight, BINARY),
        0x7B => (Op::And, BINARY),
        0x7C => (Op::Nand, BINARY),
        0x7D => (Op::Or, BINARY),
        0x7E => (Op::Nor, BINARY),
        0x7F => (Op::Xor, BINARY),
        0x80 => (Op::Not, UNARY),
        0x81 => (Op::FindSetLeftBit, UNARY),
        0x82 => (Op::FindSetRightBit, UNARY),
        0x83 => (Op::DerefOf, Shape::Ops(&[T])),
        0x84 => (Op::ConcatRes, BINARY),
        0x85 => (Op::Mod, BINARY),
        0x86 => (Op::Notify, Shape::Ops(&[Super, T])),
        0x87 => (Op::SizeOf, Shape::Ops(&[Super])),
        0x88 => (Op::Index, BINARY),
        0x89 => (Op::Match, Shape::Ops(&[T, Byte, T, Byte, T, T])),
        0x8A => (Op::CreateDWordField, BUFFER_FIELD),
        0x8B => (Op::CreateWordField, BUFFER_FIELD),
        0x8C => (Op::CreateByteField, BUFFER_FIELD),
        0x8D => (Op::CreateBitField, BUFFER_FIELD),
        0x8E => (Op::ObjectType, Shape::Ops(&[Ref])),
        0x8F => (Op::CreateQWordField, BUFFER_FIELD),
        0x90 => (Op::LAnd, Shape::Ops(&[T, T])),
        0x91 => (Op::LOr, Shape::Ops(&[T, T])),
        0x92 => (Op::LNot, Shape::Ops(&[T])),
        0x93 => (Op::LEqual, Shape::Ops(&[T, T])),
        0x94 => (Op::LGreater, Shape::Ops(&[T, T])),
        0x95 => (Op::LLess, Shape::Ops(&[T, T])),
        0x96 => (Op::ToBuffer, UNARY),
        0x97 => (Op::ToDecimalString, UNARY),
        0x98 => (Op::ToHexString, UNARY),
        0x99 => (Op::ToInteger, UNARY),
        0x9C => (Op::ToString, BINARY),
        0x9D => (Op::CopyObject, Shape::Ops(&[T, Simple])),
        0x9E => (Op::Mid, Shape::Ops(&[T, T, T, Tg])),
        0x9F => (Op::Continue, Shape::Ops(&[])),
        0xA0 => (Op::If, Shape::Cond),
        0xA2 => (Op::While, Shape::Cond),
        0xA3 => (Op::Noop, Shape::Ops(&[])),
        0xA4 => (Op::Return, Shape::Ops(&[T])),
        0xA5 => (Op::Break, Shape::Ops(&[])),
        0xCC => (Op::BreakPoint, Shape::Ops(&[])),
        _ => return None,
    })
}

/// The op and layout of an `ExtOpPrefix` opcode.
fn decode_ext(b: u8) -> Option<(Op, Shape)>
{
    Some(match b
    {
        0x01 => (Op::Mutex, Shape::Decl(&[Byte])),
        0x02 => (Op::Event, Shape::Decl(&[])),
        0x12 => (Op::CondRefOf, Shape::Ops(&[Ref, Tg])),
        0x13 => (Op::CreateField, Shape::DeclAfter(&[T, T, T])),
        0x1F => (Op::LoadTable, Shape::Ops(&[T, T, T, T, T, T])),
        0x20 => (Op::Load, Shape::Ops(&[Ref, Super])),
        0x21 => (Op::Stall, Shape::Ops(&[T])),
        0x22 => (Op::Sleep, Shape::Ops(&[T])),
        0x23 => (Op::Acquire, Shape::Ops(&[Super, Word])),
        0x24 => (Op::Signal, Shape::Ops(&[Super])),
        0x25 => (Op::Wait, Shape::Ops(&[Super, T])),
        0x26 => (Op::Reset, Shape::Ops(&[Super])),
        0x27 => (Op::Release, Shape::Ops(&[Super])),
        0x28 => (Op::FromBcd, Shape::Ops(&[T, Tg])),
        0x29 => (Op::ToBcd, Shape::Ops(&[T, Tg])),
        0x2A => (Op::Unload, Shape::Ops(&[Super])),
        0x30 => (Op::Revision, Shape::Ops(&[])),
        0x31 => (Op::Debug, Shape::Ops(&[])),
        0x32 => (Op::Fatal, Shape::Ops(&[Byte, DWord, T])),
        0x33 => (Op::Timer, Shape::Ops(&[])),
        0x80 => (Op::OpRegion, Shape::Decl(&[Byte, T, T])),
        0x81 => (Op::Field, Shape::Fields(&[N])),
        0x82 => (Op::Device, Shape::Scoped(&[])),
        0x83 => (Op::Processor, Shape::Scoped(&[Byte, DWord, Byte])),
        0x84 => (Op::PowerRes, Shape::Scoped(&[Byte, Word])),
        0x85 => (Op::ThermalZone, Shape::Scoped(&[])),
        0x86 => (Op::IndexField, Shape::Fields(&[N, N])),
        0x87 => (Op::BankField, Shape::Fields(&[N, N, T])),
        0x88 => (Op::DataRegion, Shape::Decl(&[T, T, T])),
        _ => return None,
    })
}

/// Whether `op` may only stand as a statement of a term list: a `Type1Opcode`
/// or an object definition.
const fn statement_only(op: Op) -> bool
{
    matches!(
        op,
        Op::Noop
            | Op::Return
            | Op::Break
            | Op::Continue
            | Op::BreakPoint
            | Op::Notify
            | Op::Release
            | Op::Reset
            | Op::Signal
            | Op::Sleep
            | Op::Stall
            | Op::Fatal
            | Op::Unload
            | Op::If
            | Op::ElseIf
            | Op::Else
            | Op::While
            | Op::Alias
            | Op::Name
            | Op::Scope
            | Op::Method
            | Op::External
            | Op::Mutex
            | Op::Event
            | Op::OpRegion
            | Op::Field
            | Op::Device
            | Op::Processor
            | Op::PowerRes
            | Op::ThermalZone
            | Op::IndexField
            | Op::BankField
            | Op::DataRegion
            | Op::CreateBitField
            | Op::CreateByteField
            | Op::CreateWordField
            | Op::CreateDWordField
            | Op::CreateQWordField
            | Op::CreateField
    )
}

/// Whether `b` starts a data object a package may hold: an integer, a
/// string, a buffer or a package.
const fn starts_data(b: u8) -> bool
{
    matches!(
        b,
        OP_ZERO
            | OP_ONE
            | OP_ONES
            | OP_BYTE
            | OP_WORD
            | OP_DWORD
            | OP_QWORD
            | OP_STRING
            | OP_BUFFER
            | OP_PACKAGE
            | OP_VAR_PACKAGE
    )
}

/// The owned form of an encoded name.
///
/// # Errors
///
/// [`FaultKind::BadName`] for more than 255 parent prefixes, and
/// [`FaultKind::NoMemory`] when an allocation fails.
pub fn to_name(name: &NameStr<'_>) -> Result<Name, FaultKind>
{
    let mut segs = Vec::new();
    segs.try_reserve_exact(name.len())
        .map_err(|_| FaultKind::NoMemory)?;
    segs.extend(name.segments());
    Ok(Name {
        root: name.root,
        up: u8::try_from(name.up).map_err(|_| FaultKind::BadName)?,
        segs,
    })
}

/// A term with no kids.
const fn leaf(op: Op, imm: Imm, offset: u32) -> Term
{
    Term {
        op,
        imm,
        kids: Vec::new(),
        offset,
    }
}

/// An owned copy of `bytes`.
fn copy(bytes: &[u8]) -> Result<Vec<u8>, FaultKind>
{
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| FaultKind::NoMemory)?;
    v.extend_from_slice(bytes);
    Ok(v)
}

/// A parser over a span of one table's bytes.
#[derive(Debug)]
pub struct Parser<'a>
{
    ns: &'a Namespace,
    buf: &'a [u8],
    pos: usize,
    end: usize,
    scope: NodeId,
    depth: usize,
}

impl<'a> Parser<'a>
{
    /// A parser of `buf[start..end]`, a span of a table whose first byte is
    /// `buf[0]`, for code whose scope is `scope`. Terms carry their offset
    /// in `buf`.
    #[must_use]
    pub fn new(ns: &'a Namespace, buf: &'a [u8], start: usize, end: usize, scope: NodeId) -> Self
    {
        Self {
            ns,
            buf,
            pos: start,
            end: end.min(buf.len()),
            scope,
            depth: 0,
        }
    }

    /// The offset of the next byte to parse.
    #[must_use]
    pub const fn position(&self) -> usize
    {
        self.pos
    }

    /// Parse the whole span as a term list.
    ///
    /// # Errors
    ///
    /// The first [`Fault`]; the terms before it are dropped.
    pub fn term_list(mut self) -> Result<Vec<Term>, Fault>
    {
        let end = self.end;
        self.list_until(end)
    }

    /// Parse the next statement of the span: one term of a term list, with
    /// the `Else` that follows an `If`. `None` at the end of the span.
    pub fn next_statement(&mut self) -> Option<Result<Term, Fault>>
    {
        (self.pos < self.end).then(|| self.list_item())
    }

    // ── Reads ─────────────────────────────────────────────────────────

    fn fault(&self, kind: FaultKind) -> Fault
    {
        Fault::at(kind, self.pos)
    }

    /// The bytes up to the end of the package being parsed.
    fn view(&self) -> &'a [u8]
    {
        self.buf.get(..self.end).unwrap_or(&[])
    }

    fn peek_at(&self, ahead: usize) -> Option<u8>
    {
        self.view().get(self.pos.checked_add(ahead)?).copied()
    }

    fn peek(&self) -> Result<u8, Fault>
    {
        self.peek_at(0)
            .ok_or_else(|| self.fault(FaultKind::Truncated))
    }

    fn offset(&self) -> u32
    {
        u32::try_from(self.pos).unwrap_or(u32::MAX)
    }

    /// Advance by `n` bytes, which must lie within the package.
    fn advance(&mut self, n: usize) -> Result<(), Fault>
    {
        let next = self
            .pos
            .checked_add(n)
            .filter(|p| *p <= self.end)
            .ok_or_else(|| self.fault(FaultKind::Truncated))?;
        self.pos = next;
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, Fault>
    {
        let b = self.peek()?;
        self.advance(1)?;
        Ok(b)
    }

    /// A little-endian integer of `n` bytes as an [`Op::Integer`] term.
    fn fixed(&mut self, n: usize) -> Result<Term, Fault>
    {
        let offset = self.offset();
        let v = encoding::le(self.view(), self.pos, n)
            .ok_or_else(|| self.fault(FaultKind::Truncated))?;
        self.advance(n)?;
        Ok(leaf(Op::Integer, Imm::Int(v), offset))
    }

    /// The package at the current position (its `PkgLength` first): its end.
    fn package(&mut self) -> Result<usize, Fault>
    {
        let (body, end) = encoding::package(self.view(), self.pos)
            .ok_or_else(|| self.fault(FaultKind::Truncated))?;
        self.pos = body;
        Ok(end)
    }

    /// The encoded name at the current position, without consuming it.
    fn peek_name(&self) -> Result<NameStr<'a>, Fault>
    {
        encoding::name_str(self.view(), self.pos)
            .map(|(name, _)| name)
            .ok_or_else(|| self.fault(FaultKind::BadName))
    }

    /// Consume a `NameString`.
    fn name(&mut self) -> Result<Name, Fault>
    {
        let (name, size) = encoding::name_str(self.view(), self.pos)
            .ok_or_else(|| self.fault(FaultKind::BadName))?;
        let owned = to_name(&name).map_err(|k| self.fault(k))?;
        self.advance(size)?;
        Ok(owned)
    }

    fn push_kid(&self, term: &mut Term, kid: Term) -> Result<(), Fault>
    {
        push(&mut term.kids, kid).map_err(|k| self.fault(k))
    }

    /// Run `f` with the package end at `end` and the scope at `scope`,
    /// restoring both after it.
    fn within<R>(
        &mut self,
        end: usize,
        scope: NodeId,
        f: impl FnOnce(&mut Self) -> Result<R, Fault>,
    ) -> Result<R, Fault>
    {
        let (saved_end, saved_scope) = (self.end, self.scope);
        self.end = end;
        self.scope = scope;
        let r = f(self);
        self.end = saved_end;
        self.scope = saved_scope;
        r
    }

    /// Run `f` one nesting level deeper.
    fn nested<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R, Fault>) -> Result<R, Fault>
    {
        if self.depth >= MAX_PARSE_DEPTH
        {
            return Err(self.fault(FaultKind::Depth));
        }
        self.depth = self.depth.saturating_add(1);
        let r = f(self);
        self.depth = self.depth.saturating_sub(1);
        r
    }

    // ── Term lists ────────────────────────────────────────────────────

    /// The terms up to `end`.
    fn list_until(&mut self, end: usize) -> Result<Vec<Term>, Fault>
    {
        let scope = self.scope;
        self.within(end, scope, |p| {
            let mut terms = Vec::new();
            while p.pos < end
            {
                let t = p.list_item()?;
                push(&mut terms, t).map_err(|k| p.fault(k))?;
            }
            Ok(terms)
        })
    }

    /// An [`Op::List`] term of the terms up to `end`, in `scope`.
    fn list_term(&mut self, end: usize, scope: NodeId) -> Result<Term, Fault>
    {
        let offset = self.offset();
        let kids = self.within(end, scope, |p| p.list_until(end))?;
        Ok(Term {
            op: Op::List,
            imm: Imm::None,
            kids,
            offset,
        })
    }

    /// One statement of a term list, with the `Else` that follows an `If`.
    fn list_item(&mut self) -> Result<Term, Fault>
    {
        let mut t = self.term(Want::Statement)?;
        if t.op == Op::If && self.peek_at(0) == Some(OP_ELSE)
        {
            let saved = self.end;
            let chain = self.else_chain(&mut t);
            self.end = saved;
            chain?;
        }
        Ok(t)
    }

    /// The `Else` at the current position, which follows the `If` `t`, added
    /// to `t`. While an `Else`'s body is one `If`, that `If` is added as an
    /// [`Op::ElseIf`] parsed at the depth of `t`, and the `Else` that follows
    /// it continues the chain, so a chain of any length nests no deeper.
    fn else_chain(&mut self, t: &mut Term) -> Result<(), Fault>
    {
        loop
        {
            let Some(end) = self.else_if_end()
            else
            {
                let e = self.nested(Self::else_term)?;
                return self.push_kid(t, e);
            };
            self.end = end;
            self.advance(1)?;
            self.package()?;
            let mut e = self.term(Want::Statement)?;
            e.op = Op::ElseIf;
            self.push_kid(t, e)?;
            if self.pos >= end
            {
                return Ok(());
            }
        }
    }

    /// When the `Else` at the current position has a body that is one `If`,
    /// alone or with the `Else` that follows it, the end of that body.
    fn else_if_end(&self) -> Option<usize>
    {
        let view = self.view();
        let (body, end) = encoding::package(view, self.pos.checked_add(1)?)?;
        if view.get(body) != Some(&OP_IF)
        {
            return None;
        }
        let (_, if_end) = encoding::package(view, body.checked_add(1)?)?;
        if if_end == end
        {
            return Some(end);
        }
        if if_end > end || view.get(if_end) != Some(&OP_ELSE)
        {
            return None;
        }
        let (_, else_end) = encoding::package(view, if_end.checked_add(1)?)?;
        (else_end == end).then_some(end)
    }

    /// The `Else` at the current position.
    fn else_term(&mut self) -> Result<Term, Fault>
    {
        let offset = self.offset();
        self.advance(1)?;
        let end = self.package()?;
        let scope = self.scope;
        let body = self.list_term(end, scope)?;
        let mut e = leaf(Op::Else, Imm::None, offset);
        self.push_kid(&mut e, body)?;
        Ok(e)
    }

    // ── Terms ─────────────────────────────────────────────────────────

    fn term(&mut self, want: Want) -> Result<Term, Fault>
    {
        self.nested(|p| {
            let start = p.pos;
            let t = p.term_at()?;
            if want == Want::Operand && statement_only(t.op)
            {
                return Err(Fault::at(FaultKind::NotOperand, start));
            }
            Ok(t)
        })
    }

    /// Parse the term at the current position.
    fn term_at(&mut self) -> Result<Term, Fault>
    {
        let b0 = self.peek()?;
        if encoding::starts_name(b0)
        {
            return self.name_term(Invoke::Call);
        }
        match b0
        {
            OP_ZERO | OP_ONE | OP_ONES | OP_BYTE | OP_WORD | OP_DWORD | OP_QWORD => self.integer(),
            OP_STRING => self.string(),
            OP_BUFFER => self.buffer(),
            OP_PACKAGE | OP_VAR_PACKAGE => self.package_term(b0),
            LOCAL0..=ARG6 => self.local(b0),
            OP_ELSE => Err(self.fault(FaultKind::StrayElse)),
            OP_EXT_PREFIX =>
            {
                let b1 = self.peek_at(1).unwrap_or(0);
                let (op, shape) = decode_ext(b1).ok_or_else(|| self.fault(FaultKind::BadOpcode))?;
                self.shaped(op, 2, shape)
            }
            _ =>
            {
                let (op, shape) = decode(b0).ok_or_else(|| self.fault(FaultKind::BadOpcode))?;
                self.shaped(op, 1, shape)
            }
        }
    }

    /// The term of `op`, whose opcode is `len` bytes, laid out as `shape`.
    fn shaped(&mut self, op: Op, len: usize, shape: Shape) -> Result<Term, Fault>
    {
        let offset = self.offset();
        self.advance(len)?;
        match shape
        {
            Shape::Ops(args) =>
            {
                let mut t = leaf(op, Imm::None, offset);
                self.operands(&mut t, args)?;
                Ok(t)
            }
            Shape::Decl(args) =>
            {
                let mut t = leaf(op, Imm::Name(self.name()?), offset);
                self.operands(&mut t, args)?;
                Ok(t)
            }
            Shape::DeclAfter(args) =>
            {
                let mut t = leaf(op, Imm::None, offset);
                self.operands(&mut t, args)?;
                t.imm = Imm::Name(self.name()?);
                Ok(t)
            }
            Shape::Scoped(args) => self.scoped(op, offset, args),
            Shape::Cond => self.conditional(op, offset),
            Shape::Fields(args) => self.field(op, offset, args),
        }
    }

    /// Append the operands `args` to `t`'s kids.
    fn operands(&mut self, t: &mut Term, args: &[Arg]) -> Result<(), Fault>
    {
        t.kids
            .try_reserve_exact(args.len())
            .map_err(|_| self.fault(FaultKind::NoMemory))?;
        for arg in args
        {
            let kid = self.operand(*arg)?;
            t.kids.push(kid);
        }
        Ok(())
    }

    fn operand(&mut self, arg: Arg) -> Result<Term, Fault>
    {
        match arg
        {
            Arg::Term => self.term(Want::Operand),
            Arg::Super => self.super_name(Invoke::Call),
            Arg::Target =>
            {
                if self.peek_at(0) == Some(OP_ZERO)
                {
                    let offset = self.offset();
                    self.advance(1)?;
                    return Ok(leaf(Op::Null, Imm::None, offset));
                }
                self.super_name(Invoke::Call)
            }
            Arg::Ref => self.super_name(Invoke::Never),
            Arg::Simple =>
            {
                let b0 = self.peek()?;
                if encoding::starts_name(b0)
                {
                    self.nested(Self::ref_name)
                }
                else if (LOCAL0..=ARG6).contains(&b0)
                {
                    self.term(Want::Operand)
                }
                else
                {
                    Err(self.fault(FaultKind::BadOpcode))
                }
            }
            Arg::Name => self.nested(Self::ref_name),
            Arg::Data => self.element(),
            Arg::Byte => self.fixed(1),
            Arg::Word => self.fixed(2),
            Arg::DWord => self.fixed(4),
        }
    }

    /// A `SuperName`: a local, an argument, `Debug`, a name (a call when
    /// `invoke` allows and it names a method), or a reference-producing
    /// expression.
    fn super_name(&mut self, invoke: Invoke) -> Result<Term, Fault>
    {
        if encoding::starts_name(self.peek()?)
        {
            return self.nested(|p| p.name_term(invoke));
        }
        self.term(Want::Operand)
    }

    /// A name that is never invoked, as an [`Op::NameRef`] term.
    fn ref_name(&mut self) -> Result<Term, Fault>
    {
        let offset = self.offset();
        let name = self.name()?;
        Ok(leaf(Op::NameRef, Imm::Name(name), offset))
    }

    /// The name at the current position: a call with its arguments when
    /// `invoke` allows and it names a method, else a reference.
    fn name_term(&mut self, invoke: Invoke) -> Result<Term, Fault>
    {
        let offset = self.offset();
        let args = match invoke
        {
            Invoke::Call => self.ns.method_args(self.scope, &self.peek_name()?),
            Invoke::Never => None,
        };
        let name = self.name()?;
        let Some(args) = args
        else
        {
            return Ok(leaf(Op::NameRef, Imm::Name(name), offset));
        };
        let mut t = leaf(Op::Call, Imm::Name(name), offset);
        t.kids
            .try_reserve_exact(usize::from(args))
            .map_err(|_| self.fault(FaultKind::NoMemory))?;
        for _ in 0..args
        {
            let kid = self.term(Want::Operand)?;
            t.kids.push(kid);
        }
        Ok(t)
    }

    /// A `PackageElement` or `DataRefObject`: a data object or a name.
    fn element(&mut self) -> Result<Term, Fault>
    {
        let b0 = self.peek()?;
        if encoding::starts_name(b0)
        {
            return self.nested(Self::ref_name);
        }
        let revision = b0 == OP_EXT_PREFIX && self.peek_at(1) == Some(encoding::EXT_REVISION);
        if !starts_data(b0) && !revision
        {
            return Err(self.fault(FaultKind::BadOpcode));
        }
        self.term(Want::Operand)
    }

    /// An integer constant.
    fn integer(&mut self) -> Result<Term, Fault>
    {
        let offset = self.offset();
        let (v, size) = encoding::integer(self.view(), self.pos)
            .ok_or_else(|| self.fault(FaultKind::Truncated))?;
        self.advance(size)?;
        Ok(leaf(Op::Integer, Imm::Int(v), offset))
    }

    /// A string.
    fn string(&mut self) -> Result<Term, Fault>
    {
        let offset = self.offset();
        let (bytes, size) = encoding::string(self.view(), self.pos)
            .ok_or_else(|| self.fault(FaultKind::Truncated))?;
        let owned = copy(bytes).map_err(|k| self.fault(k))?;
        self.advance(size)?;
        Ok(leaf(Op::String, Imm::Bytes(owned), offset))
    }

    /// `Local0`-`Local7` or `Arg0`-`Arg6`, whose opcode is `b0`.
    fn local(&mut self, b0: u8) -> Result<Term, Fault>
    {
        let offset = self.offset();
        self.advance(1)?;
        let (op, index) = if b0 >= ARG0
        {
            (Op::Arg, b0.saturating_sub(ARG0))
        }
        else
        {
            (Op::Local, b0.saturating_sub(LOCAL0))
        };
        Ok(leaf(op, Imm::Int(u64::from(index)), offset))
    }

    /// `Buffer`: the size, then the initializer up to the package end.
    fn buffer(&mut self) -> Result<Term, Fault>
    {
        let offset = self.offset();
        self.advance(1)?;
        let end = self.package()?;
        let scope = self.scope;
        let size = self.within(end, scope, |p| p.term(Want::Operand))?;
        let bytes = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| self.fault(FaultKind::Truncated))?;
        let init = copy(bytes).map_err(|k| self.fault(k))?;
        self.pos = end;
        let mut t = leaf(Op::Buffer, Imm::Bytes(init), offset);
        self.push_kid(&mut t, size)?;
        Ok(t)
    }

    /// `Package` (its count a byte) or `VarPackage` (its count a term), by
    /// the opcode `b0`, and the elements up to the package end.
    fn package_term(&mut self, b0: u8) -> Result<Term, Fault>
    {
        let offset = self.offset();
        self.advance(1)?;
        let end = self.package()?;
        let scope = self.scope;
        self.within(end, scope, |p| {
            let mut t = if b0 == OP_VAR_PACKAGE
            {
                let mut t = leaf(Op::VarPackage, Imm::None, offset);
                let count = p.term(Want::Operand)?;
                p.push_kid(&mut t, count)?;
                t
            }
            else
            {
                let count = p.byte()?;
                leaf(Op::Package, Imm::Int(u64::from(count)), offset)
            };
            while p.pos < end
            {
                let e = p.element()?;
                p.push_kid(&mut t, e)?;
            }
            Ok(t)
        })
    }

    /// `If` or `While`: the predicate, then the body.
    fn conditional(&mut self, op: Op, offset: u32) -> Result<Term, Fault>
    {
        let end = self.package()?;
        let scope = self.scope;
        let mut t = leaf(op, Imm::None, offset);
        let pred = self.within(end, scope, |p| p.term(Want::Operand))?;
        self.push_kid(&mut t, pred)?;
        let body = self.list_term(end, scope)?;
        self.push_kid(&mut t, body)?;
        Ok(t)
    }

    /// An object with a `PkgLength`, a name, the operands `args`, and a body
    /// term list: `Scope`, `Method`, `Device`, `Processor`, `PowerResource`,
    /// `ThermalZone`. The body is parsed in the scope the name gives (a
    /// `Scope`'s name by the search rules, a definition's as a path), or in
    /// the enclosing scope when that node does not exist yet.
    fn scoped(&mut self, op: Op, offset: u32, args: &[Arg]) -> Result<Term, Fault>
    {
        let end = self.package()?;
        let outer = self.scope;
        self.within(end, outer, |p| {
            let encoded = p.peek_name()?;
            let found = if op == Op::Scope
            {
                p.ns.resolve_str(outer, &encoded)
            }
            else
            {
                p.ns.declared(outer, &encoded)
            };
            let mut t = leaf(op, Imm::Name(p.name()?), offset);
            p.operands(&mut t, args)?;
            let body = p.list_term(end, found.unwrap_or(outer))?;
            p.push_kid(&mut t, body)?;
            Ok(t)
        })
    }

    /// `Field`, `IndexField` or `BankField`: the operands `args`, the flags,
    /// and the field list.
    fn field(&mut self, op: Op, offset: u32, args: &[Arg]) -> Result<Term, Fault>
    {
        let end = self.package()?;
        let scope = self.scope;
        self.within(end, scope, |p| {
            let mut t = leaf(op, Imm::None, offset);
            p.operands(&mut t, args)?;
            let flags = p.byte()?;
            let elems = p.field_elements(end)?;
            t.imm = Imm::Fields(FieldList { flags, elems });
            Ok(t)
        })
    }

    /// The elements of a field list up to `end`.
    fn field_elements(&mut self, end: usize) -> Result<Vec<FieldElem>, Fault>
    {
        let mut elems = Vec::new();
        while self.pos < end
        {
            let elem = self.field_element()?;
            push(&mut elems, elem).map_err(|k| self.fault(k))?;
        }
        Ok(elems)
    }

    /// One element of a field list.
    fn field_element(&mut self) -> Result<FieldElem, Fault>
    {
        Ok(match self.byte()?
        {
            0x00 => FieldElem::Reserved {
                bits: self.bit_length()?,
            },
            0x01 => FieldElem::Access {
                kind: self.byte()?,
                attrib: self.byte()?,
            },
            0x02 =>
            {
                let b = self.peek()?;
                if encoding::starts_name(b)
                {
                    FieldElem::Connect(self.ref_name()?)
                }
                else if b == OP_BUFFER
                {
                    FieldElem::Connect(self.nested(Self::buffer)?)
                }
                else
                {
                    return Err(self.fault(FaultKind::BadOpcode));
                }
            }
            0x03 => FieldElem::ExtendedAccess {
                kind: self.byte()?,
                attrib: self.byte()?,
                len: self.byte()?,
            },
            b0 => FieldElem::Named {
                name: self.field_name(b0)?,
                bits: self.bit_length()?,
            },
        })
    }

    /// The `NameSeg` of a named field whose first byte, `b0`, is consumed.
    fn field_name(&mut self, b0: u8) -> Result<[u8; 4], Fault>
    {
        if !encoding::is_lead_name_char(b0)
        {
            return Err(self.fault(FaultKind::BadOpcode));
        }
        let mut seg = [b0, 0, 0, 0];
        for slot in seg.iter_mut().skip(1)
        {
            let b = self.byte()?;
            if !encoding::is_name_char(b)
            {
                return Err(self.fault(FaultKind::BadName));
            }
            *slot = b;
        }
        Ok(seg)
    }

    /// A field element's width: a `PkgLength` that counts bits.
    fn bit_length(&mut self) -> Result<u32, Fault>
    {
        let (bits, size) = encoding::pkg_length(self.view(), self.pos)
            .ok_or_else(|| self.fault(FaultKind::Truncated))?;
        self.advance(size)?;
        Ok(bits)
    }
}
