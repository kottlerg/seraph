// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/eval/expr.rs

//! Expressions: the value of each operand term, and the operators of ACPI
//! 6.5 § 19.6 that compute one.

use alloc::vec::Vec;
use core::cmp::Ordering;

use super::place::Mode;
use super::{Evaluator, at, by, imm_int, imm_name, kid};
use crate::namespace::{NodeId, Object};
use crate::term::{Imm, Name, Op, Term};
use crate::value::{self, Data, Radix, Ref};
use crate::{Fault, FaultKind, MAX_VALUE_DEPTH, REVISION};

/// A fault placed at `t` unless an inner term already placed it.
fn placed(t: &Term) -> impl Fn(Fault) -> Fault + '_
{
    move |f| if f.offset == 0 { at(t, f.kind) } else { f }
}

/// A binary integer operator.
#[derive(Clone, Copy, Debug)]
enum Bin
{
    Add,
    Subtract,
    Multiply,
    Mod,
    ShiftLeft,
    ShiftRight,
    And,
    Nand,
    Or,
    Nor,
    Xor,
}

/// A unary integer operator.
#[derive(Clone, Copy, Debug)]
enum Unary
{
    Not,
    LeftBit,
    RightBit,
    FromBcd,
    ToBcd,
}

/// A conversion or string operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conv
{
    Concat,
    ConcatRes,
    ToBuffer,
    ToDecimalString,
    ToHexString,
    ToInteger,
    ToString,
    Mid,
}

/// The `ObjectType` number of a node's object (ACPI 6.5 § 19.6.97).
pub(super) fn object_type(object: &Object) -> u64
{
    match object
    {
        Object::Data(d) => d.type_number(),
        Object::Field(_) => 5,
        Object::Device => 6,
        Object::Event { .. } => 7,
        Object::Method(_) => 8,
        Object::Mutex { .. } => 9,
        Object::Region(_) | Object::DataRegion(_) => 10,
        Object::PowerResource { .. } => 11,
        Object::Processor { .. } => 12,
        Object::ThermalZone => 13,
        Object::BufferField(_) => 14,
        Object::External { kind, .. } => u64::from(*kind),
        Object::Scope | Object::Alias(_) => 0,
    }
}

/// The name a string spells: `\`, `^`s, then segments separated by dots,
/// each padded with `_` to four characters.
pub(super) fn name_of_text(text: &[u8]) -> Result<Name, FaultKind>
{
    let (root, mut rest) = match text
    {
        [b'\\', rest @ ..] => (true, rest),
        _ => (false, text),
    };
    let mut up = 0u8;
    while let [b'^', r @ ..] = rest
    {
        up = up.checked_add(1).ok_or(FaultKind::BadName)?;
        rest = r;
    }
    let mut segs = Vec::new();
    if !rest.is_empty()
    {
        for part in rest.split(|c| *c == b'.')
        {
            if part.is_empty() || part.len() > 4
            {
                return Err(FaultKind::BadName);
            }
            let mut seg = *b"____";
            for (slot, c) in seg.iter_mut().zip(part)
            {
                *slot = c.to_ascii_uppercase();
            }
            crate::push(&mut segs, seg)?;
        }
    }
    Ok(Name { root, up, segs })
}

impl Evaluator<'_>
{
    /// The value of the operand `t`, counted against
    /// [`crate::MAX_EVAL_ALLOC`] unless it was counted where it was made.
    pub(super) fn eval(&mut self, t: &Term) -> Result<Data, Fault>
    {
        self.enter(t)?;
        let r = self.eval_op(t).map_err(placed(t));
        self.leave();
        let v = r?;
        self.count_made(t, &v)?;
        Ok(v)
    }

    /// Count the value `v` the term `t` gave against
    /// [`crate::MAX_EVAL_ALLOC`], unless it was counted where it was made.
    pub(super) fn count_made(&mut self, t: &Term, v: &Data) -> Result<(), Fault>
    {
        if matches!(v, Data::Uninitialized | Data::Integer(_)) || self.counted(t)
        {
            return Ok(());
        }
        self.charge(v).map_err(by(t))
    }

    /// Whether the value of `t` was counted as it was made: a package,
    /// which counts its own slots and whose elements were counted as they
    /// were evaluated; a method's result, counted as the operand of its
    /// `Return`; and the result of `Store` and `CopyObject`, their
    /// operand's value.
    fn counted(&self, t: &Term) -> bool
    {
        if matches!(
            t.op,
            Op::Package | Op::VarPackage | Op::Store | Op::CopyObject
        )
        {
            return true;
        }
        matches!(t.op, Op::NameRef | Op::Call)
            && imm_name(t)
                .ok()
                .and_then(|name| self.lookup(name))
                .is_some_and(|node| matches!(self.ns.object(node), Some(Object::Method(_))))
    }

    /// The value of the operand `t`, an index reference replaced by the
    /// value it refers to.
    pub(super) fn eval_value(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let v = self.eval(t)?;
        self.computational(v).map_err(placed(t))
    }

    /// The value of the operand `t` as an integer.
    pub(super) fn int(&mut self, t: &Term) -> Result<u64, Fault>
    {
        let v = self.eval_value(t)?;
        value::integer(&v, self.width()).map_err(by(t))
    }

    /// `v`, or, when it is a reference `Index` made, the value it refers to.
    pub(super) fn computational(&mut self, v: Data) -> Result<Data, Fault>
    {
        match v
        {
            Data::Ref(r) if !r.path.is_empty() => self.read_ref(&r),
            Data::Uninitialized
            | Data::Integer(_)
            | Data::String(_)
            | Data::Buffer(_)
            | Data::Package(_)
            | Data::Name(_)
            | Data::Ref(_) => Ok(v),
        }
    }

    /// The object a reference or a string naming one refers to (`DerefOf`).
    pub(super) fn deref(&mut self, v: &Data) -> Result<Data, Fault>
    {
        match v
        {
            Data::Ref(r) => self.read_ref(r),
            Data::String(s) =>
            {
                let name = name_of_text(s).map_err(super::bare)?;
                let node = self.lookup(&name).ok_or(super::bare(FaultKind::NotFound))?;
                self.node_value(node)
            }
            Data::Uninitialized => Err(super::bare(FaultKind::Uninitialized)),
            Data::Integer(_) | Data::Buffer(_) | Data::Package(_) | Data::Name(_) =>
            {
                Err(super::bare(FaultKind::Type))
            }
        }
    }

    /// Store `v` to the target at kid `i` of `t`, and return it.
    fn result(&mut self, t: &Term, i: usize, v: Data) -> Result<Data, Fault>
    {
        let target = kid(t, i)?;
        if target.op != Op::Null
        {
            let copy = v.try_clone().map_err(by(t))?;
            let place = self.place(target)?;
            self.store(place, copy, Mode::Store)
                .map_err(placed(target))?;
        }
        Ok(v)
    }

    /// An integer result, stored to the target at kid `i` of `t`.
    fn int_result(&mut self, t: &Term, i: usize, v: u64) -> Result<Data, Fault>
    {
        let mask = self.width().mask();
        self.result(t, i, Data::Integer(v & mask))
    }

    /// A logical result: `Ones` for true, `Zero` for false.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`b` is the truth value the result encodes, data"
    )]
    fn truth(&self, b: bool) -> Data
    {
        Data::Integer(if b { self.width().mask() } else { 0 })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per opcode of ACPI 6.5 § 20.2.5.4, each a call or a one-liner"
    )]
    pub(super) fn eval_op(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let width = self.width();
        match t.op
        {
            Op::Integer => Ok(Data::Integer(imm_int(t)? & width.mask())),
            Op::String => match &t.imm
            {
                Imm::Bytes(b) => Ok(Data::String(value::bytes_of(b).map_err(by(t))?)),
                Imm::None | Imm::Int(_) | Imm::Name(_) | Imm::Fields(_) =>
                {
                    Err(at(t, FaultKind::BadOpcode))
                }
            },
            Op::Buffer => self.buffer_term(t),
            Op::Package | Op::VarPackage => self.package_term(t),
            Op::Revision => Ok(Data::Integer(REVISION)),
            Op::NameRef =>
            {
                let node = self
                    .lookup(imm_name(t)?)
                    .ok_or(at(t, FaultKind::NotFound))?;
                self.node_value(node)
            }
            Op::Call => self.call_term(t),
            Op::Local | Op::Arg => self.slot_value(t),
            Op::Store | Op::CopyObject =>
            {
                let v = self.eval(kid(t, 0)?)?;
                let mode = if t.op == Op::Store
                {
                    Mode::Store
                }
                else
                {
                    Mode::Copy
                };
                let copy = v.try_clone().map_err(by(t))?;
                let place = self.place(kid(t, 1)?)?;
                self.store(place, copy, mode)?;
                Ok(v)
            }
            Op::RefOf => Ok(Data::Ref(self.reference(kid(t, 0)?)?)),
            Op::CondRefOf => self.cond_ref_of(t),
            Op::DerefOf =>
            {
                let v = self.eval(kid(t, 0)?)?;
                self.deref(&v)
            }
            Op::Index => self.index(t),
            Op::Add => self.binary(t, Bin::Add),
            Op::Subtract => self.binary(t, Bin::Subtract),
            Op::Multiply => self.binary(t, Bin::Multiply),
            Op::Mod => self.binary(t, Bin::Mod),
            Op::ShiftLeft => self.binary(t, Bin::ShiftLeft),
            Op::ShiftRight => self.binary(t, Bin::ShiftRight),
            Op::And => self.binary(t, Bin::And),
            Op::Nand => self.binary(t, Bin::Nand),
            Op::Or => self.binary(t, Bin::Or),
            Op::Nor => self.binary(t, Bin::Nor),
            Op::Xor => self.binary(t, Bin::Xor),
            Op::Divide => self.divide(t),
            Op::Not => self.unary(t, Unary::Not),
            Op::FindSetLeftBit => self.unary(t, Unary::LeftBit),
            Op::FindSetRightBit => self.unary(t, Unary::RightBit),
            Op::FromBcd => self.unary(t, Unary::FromBcd),
            Op::ToBcd => self.unary(t, Unary::ToBcd),
            Op::Increment | Op::Decrement => self.increment(t),
            Op::LNot =>
            {
                let a = self.int(kid(t, 0)?)?;
                Ok(self.truth(a == 0))
            }
            Op::LAnd | Op::LOr =>
            {
                let a = self.int(kid(t, 0)?)? != 0;
                let b = self.int(kid(t, 1)?)? != 0;
                let v = if t.op == Op::LAnd { a && b } else { a || b };
                Ok(self.truth(v))
            }
            Op::LEqual => self.compare(t, Ordering::Equal),
            Op::LGreater => self.compare(t, Ordering::Greater),
            Op::LLess => self.compare(t, Ordering::Less),
            Op::Concat => self.convert(t, Conv::Concat),
            Op::ConcatRes => self.convert(t, Conv::ConcatRes),
            Op::ToBuffer => self.convert(t, Conv::ToBuffer),
            Op::ToDecimalString => self.convert(t, Conv::ToDecimalString),
            Op::ToHexString => self.convert(t, Conv::ToHexString),
            Op::ToInteger => self.convert(t, Conv::ToInteger),
            Op::ToString => self.convert(t, Conv::ToString),
            Op::Mid => self.convert(t, Conv::Mid),
            Op::SizeOf => self.size_of(t),
            Op::ObjectType => self.object_type_of(t),
            Op::Match => self.match_op(t),
            Op::Acquire | Op::Wait => self.sync_expr(t),
            Op::Timer => Ok(Data::Integer(self.host.timer() & width.mask())),
            Op::LoadTable => Err(at(t, FaultKind::Unsupported)),
            Op::Debug | Op::Null => Err(at(t, FaultKind::Type)),
            Op::List
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
            | Op::If
            | Op::ElseIf
            | Op::Else
            | Op::While
            | Op::Noop
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
            | Op::Load
            | Op::Unload => Err(at(t, FaultKind::BadOpcode)),
        }
    }

    // ── Data objects and names ────────────────────────────────────────

    /// `Buffer`: as long as the larger of its size and its initializer.
    fn buffer_term(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let size = self.int(kid(t, 0)?)?;
        let size = usize::try_from(size).map_err(|_| at(t, FaultKind::Bound))?;
        let init: &[u8] = match &t.imm
        {
            Imm::Bytes(b) => b,
            Imm::None | Imm::Int(_) | Imm::Name(_) | Imm::Fields(_) => &[],
        };
        let len = size.max(init.len());
        value::check_len(len).map_err(by(t))?;
        let mut out = value::vec_with(len).map_err(by(t))?;
        out.extend_from_slice(init);
        out.resize(len, 0);
        Ok(Data::Buffer(out))
    }

    /// `Package` and `VarPackage`: as many elements as the count, those its
    /// list omits uninitialized and those past the count dropped. A name
    /// element is a reference to the object it names from the running
    /// scope, or stays a name when it names nothing.
    fn package_term(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let (count, elems) = if t.op == Op::VarPackage
        {
            (self.int(kid(t, 0)?)?, t.kids.get(1..).unwrap_or(&[]))
        }
        else
        {
            (imm_int(t)?, t.kids.as_slice())
        };
        let count = usize::try_from(count).map_err(|_| at(t, FaultKind::Bound))?;
        value::check_count(count).map_err(by(t))?;
        let mut out = value::vec_with(count).map_err(by(t))?;
        // The bytes this package makes: its own and every slot's, and the
        // names it holds. An element evaluated that is not an integer was
        // counted, its slot with it, where it was made.
        let slot = size_of::<Data>();
        let mut made = slot.saturating_add(slot.saturating_mul(count));
        for e in elems.iter().take(count)
        {
            let v = if e.op == Op::NameRef
            {
                let name = imm_name(e)?;
                if let Some(node) = self.lookup(name)
                {
                    Data::Ref(self.node_ref(node)?)
                }
                else
                {
                    let mut segs = value::vec_with(name.segs.len()).map_err(by(e))?;
                    segs.extend_from_slice(&name.segs);
                    Data::Name(Name {
                        root: name.root,
                        up: name.up,
                        segs,
                    })
                }
            }
            else
            {
                let v = self.eval(e)?;
                if !matches!(v, Data::Uninitialized | Data::Integer(_))
                {
                    made = made.saturating_sub(slot);
                }
                v
            };
            if e.op == Op::NameRef
            {
                made = made.saturating_add(v.weight().saturating_sub(slot));
            }
            out.push(v);
        }
        self.charge_bytes(made).map_err(by(t))?;
        out.resize(count, Data::Uninitialized);
        let v = Data::Package(out);
        if v.depth() > MAX_VALUE_DEPTH
        {
            return Err(at(t, FaultKind::Bound));
        }
        Ok(v)
    }

    /// A method invocation.
    fn call_term(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let node = self
            .lookup(imm_name(t)?)
            .ok_or(at(t, FaultKind::NotFound))?;
        let Some(Object::Method(m)) = self.ns.object(node)
        else
        {
            if t.kids.is_empty()
            {
                return self.node_value(node);
            }
            return Err(at(t, FaultKind::Args));
        };
        let m = *m;
        let mut args = value::vec_with(t.kids.len()).map_err(by(t))?;
        for a in &t.kids
        {
            args.push(self.eval(a)?);
        }
        let w = self.width();
        self.call(node, m, args, w)
    }

    /// The value of a local or an argument.
    fn slot_value(&self, t: &Term) -> Result<Data, Fault>
    {
        let i = usize::try_from(imm_int(t)?).map_err(|_| at(t, FaultKind::BadOpcode))?;
        let frame = self.frame().map_err(by(t))?;
        let slot = if t.op == Op::Local
        {
            frame.locals.get(i)
        }
        else
        {
            frame.args.get(i)
        };
        slot.ok_or(at(t, FaultKind::BadOpcode))?
            .try_clone()
            .map_err(by(t))
    }

    // ── References ────────────────────────────────────────────────────

    /// `CondRefOf`: whether the object exists, and a reference to it stored
    /// to the target when it does.
    fn cond_ref_of(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let source = kid(t, 0)?;
        if source.op == Op::NameRef && self.lookup(imm_name(source)?).is_none()
        {
            return Ok(self.truth(false));
        }
        let r = self.reference(source)?;
        let target = kid(t, 1)?;
        if target.op != Op::Null
        {
            let place = self.place(target)?;
            self.store(place, Data::Ref(r), Mode::Store)?;
        }
        Ok(self.truth(true))
    }

    /// `Index`: a reference to an element of a package or a byte of a buffer
    /// or string.
    fn index(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let mut r = self.source_ref(kid(t, 0)?)?;
        let i = self.int(kid(t, 1)?)?;
        let len = self.ref_len(&r).map_err(placed(t))?;
        let i = u32::try_from(i).map_err(|_| at(t, FaultKind::Range))?;
        if u64::from(i) >= len
        {
            return Err(at(t, FaultKind::Range));
        }
        crate::push(&mut r.path, i).map_err(by(t))?;
        self.result(t, 2, Data::Ref(r))
    }

    // ── Integer operators ─────────────────────────────────────────────

    fn binary(&mut self, t: &Term, op: Bin) -> Result<Data, Fault>
    {
        let a = self.int(kid(t, 0)?)?;
        let b = self.int(kid(t, 1)?)?;
        let bits = self.width().bits();
        let shift = |b: u64| u32::try_from(b).ok().filter(|s| *s < bits);
        let v = match op
        {
            Bin::Add => a.wrapping_add(b),
            Bin::Subtract => a.wrapping_sub(b),
            Bin::Multiply => a.wrapping_mul(b),
            Bin::Mod => a.checked_rem(b).ok_or(at(t, FaultKind::DivideByZero))?,
            Bin::ShiftLeft => shift(b).and_then(|s| a.checked_shl(s)).unwrap_or(0),
            Bin::ShiftRight => shift(b).and_then(|s| a.checked_shr(s)).unwrap_or(0),
            Bin::And => a & b,
            Bin::Nand => !(a & b),
            Bin::Or => a | b,
            Bin::Nor => !(a | b),
            Bin::Xor => a ^ b,
        };
        self.int_result(t, 2, v)
    }

    /// `Divide`: the remainder to the first target, the quotient to the
    /// second and as the result.
    fn divide(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let dividend = self.int(kid(t, 0)?)?;
        let divisor = self.int(kid(t, 1)?)?;
        let quotient = dividend
            .checked_div(divisor)
            .ok_or(at(t, FaultKind::DivideByZero))?;
        let remainder = dividend
            .checked_rem(divisor)
            .ok_or(at(t, FaultKind::DivideByZero))?;
        self.int_result(t, 2, remainder)?;
        self.int_result(t, 3, quotient)
    }

    fn unary(&mut self, t: &Term, op: Unary) -> Result<Data, Fault>
    {
        let w = self.width();
        let a = self.int(kid(t, 0)?)? & w.mask();
        let v = match op
        {
            Unary::Not => !a,
            Unary::LeftBit => u64::from(64u32.saturating_sub(a.leading_zeros())),
            Unary::RightBit =>
            {
                if a == 0
                {
                    0
                }
                else
                {
                    u64::from(a.trailing_zeros().saturating_add(1))
                }
            }
            Unary::FromBcd => value::from_bcd(a, w).map_err(by(t))?,
            Unary::ToBcd => value::to_bcd(a, w).map_err(by(t))?,
        };
        self.int_result(t, 1, v)
    }

    /// `Increment` and `Decrement` of the object a `SuperName` names.
    fn increment(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let target = kid(t, 0)?;
        let place = self.place(target)?;
        let v = self.read_place(&place).map_err(placed(target))?;
        let v = self.computational(v)?;
        let width = self.width();
        let old = value::integer(&v, width).map_err(by(t))?;
        let new = if t.op == Op::Increment
        {
            old.wrapping_add(1)
        }
        else
        {
            old.wrapping_sub(1)
        } & width.mask();
        self.store(place, Data::Integer(new), Mode::Store)
            .map_err(placed(t))?;
        Ok(Data::Integer(new))
    }

    // ── Logical operators ─────────────────────────────────────────────

    /// `LEqual`, `LGreater`, `LLess`: whether the first operand compares
    /// to the second, converted to its type, as `want`.
    fn compare(&mut self, t: &Term, want: Ordering) -> Result<Data, Fault>
    {
        let a = self.eval_value(kid(t, 0)?)?;
        let b = self.eval_value(kid(t, 1)?)?;
        let ord = value::compare(&a, &b, self.width()).map_err(by(t))?;
        Ok(self.truth(ord == want))
    }

    // ── Conversions and string operators ──────────────────────────────

    fn convert(&mut self, t: &Term, op: Conv) -> Result<Data, Fault>
    {
        let arg = self.eval_value(kid(t, 0)?)?;
        let (v, target) = if matches!(op, Conv::Concat | Conv::ConcatRes)
        {
            let other = self.eval_value(kid(t, 1)?)?;
            (self.concat(t, op, &arg, &other)?, 2)
        }
        else
        {
            self.conversion(t, op, arg)?
        };
        self.result(t, target, v)
    }

    /// `Concat` and `ConcatRes` of `arg` and `other`.
    fn concat(&self, t: &Term, op: Conv, arg: &Data, other: &Data) -> Result<Data, Fault>
    {
        let width = self.width();
        let err = by(t);
        if op == Conv::Concat
        {
            return value::concat(arg, other, width).map_err(err);
        }
        let left = value::buffer(arg, width).map_err(&err)?;
        let right = value::buffer(other, width).map_err(&err)?;
        Ok(Data::Buffer(
            value::concat_templates(&left, &right).map_err(err)?,
        ))
    }

    /// The conversions of one operand, and the kid their target is at.
    fn conversion(&mut self, t: &Term, op: Conv, arg: Data) -> Result<(Data, usize), Fault>
    {
        let width = self.width();
        let err = by(t);
        Ok(match op
        {
            Conv::Concat | Conv::ConcatRes => return Err(at(t, FaultKind::BadOpcode)),
            Conv::ToBuffer => (Data::Buffer(value::buffer(&arg, width).map_err(err)?), 1),
            Conv::ToDecimalString => (
                Data::String(value::string(&arg, width, Radix::Decimal).map_err(err)?),
                1,
            ),
            Conv::ToHexString => (
                Data::String(value::string(&arg, width, Radix::Hex).map_err(err)?),
                1,
            ),
            Conv::ToInteger => (
                Data::Integer(value::explicit_integer(&arg, width).map_err(err)?),
                1,
            ),
            Conv::ToString =>
            {
                let len = self.int(kid(t, 1)?)?;
                let bytes = value::buffer(&arg, width).map_err(&err)?;
                (
                    Data::String(value::bytes_to_string(&bytes, len).map_err(err)?),
                    2,
                )
            }
            Conv::Mid =>
            {
                let index = self.int(kid(t, 1)?)?;
                let len = self.int(kid(t, 2)?)?;
                let source = match arg
                {
                    Data::Integer(_) => Data::Buffer(value::buffer(&arg, width).map_err(&err)?),
                    Data::Uninitialized
                    | Data::String(_)
                    | Data::Buffer(_)
                    | Data::Package(_)
                    | Data::Name(_)
                    | Data::Ref(_) => arg,
                };
                (value::mid(&source, index, len).map_err(err)?, 3)
            }
        })
    }

    /// `SizeOf`: the length of a string or buffer, the element count of a
    /// package, through any reference.
    fn size_of(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let mut v = self.eval(kid(t, 0)?)?;
        if let Data::Ref(_) = v
        {
            v = self.deref(&v).map_err(placed(t))?;
            self.charge(&v).map_err(by(t))?;
        }
        let n = match &v
        {
            Data::String(b) | Data::Buffer(b) => b.len(),
            Data::Package(p) => p.len(),
            Data::Uninitialized => return Err(at(t, FaultKind::Uninitialized)),
            Data::Integer(_) | Data::Name(_) | Data::Ref(_) => return Err(at(t, FaultKind::Type)),
        };
        Ok(Data::Integer(u64::try_from(n).unwrap_or(u64::MAX)))
    }

    /// `ObjectType` of a name, a local or argument (through the reference it
    /// holds), or a reference an expression makes.
    fn object_type_of(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let source = kid(t, 0)?;
        if source.op == Op::Debug
        {
            return Ok(Data::Integer(16));
        }
        if source.op == Op::NameRef
        {
            let node = self
                .lookup(imm_name(source)?)
                .ok_or(at(t, FaultKind::NotFound))?;
            return Ok(Data::Integer(self.node_type(node)));
        }
        let v = self.eval(source)?;
        let ty = match &v
        {
            Data::Ref(r) => self.ref_type(r).map_err(placed(t))?,
            Data::Uninitialized
            | Data::Integer(_)
            | Data::String(_)
            | Data::Buffer(_)
            | Data::Package(_)
            | Data::Name(_) => v.type_number(),
        };
        Ok(Data::Integer(ty))
    }

    /// The `ObjectType` of `node`'s object.
    pub(super) fn node_type(&self, node: NodeId) -> u64
    {
        self.ns
            .follow(node)
            .and_then(|n| self.ns.object(n))
            .map_or(0, object_type)
    }

    /// The `ObjectType` of the object `r` refers to.
    fn ref_type(&mut self, r: &Ref) -> Result<u64, Fault>
    {
        if r.path.is_empty()
            && let crate::value::Base::Node { node, .. } = r.base
        {
            self.check_ref(r).map_err(super::bare)?;
            return Ok(self.node_type(node));
        }
        Ok(self.read_ref(r)?.type_number())
    }

    /// `Match`: the index of the first package element from the start index
    /// that both comparisons hold for, or `Ones`.
    fn match_op(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let pkg = self.eval_value(kid(t, 0)?)?;
        let op1 = imm_int(kid(t, 1)?)?;
        let obj1 = self.eval_value(kid(t, 2)?)?;
        let op2 = imm_int(kid(t, 3)?)?;
        let obj2 = self.eval_value(kid(t, 4)?)?;
        let start = self.int(kid(t, 5)?)?;
        let Data::Package(elems) = pkg
        else
        {
            return Err(at(t, FaultKind::Type));
        };
        if op1 > 5 || op2 > 5
        {
            return Err(at(t, FaultKind::Range));
        }
        let start = usize::try_from(start).unwrap_or(usize::MAX);
        if start >= elems.len()
        {
            return Err(at(t, FaultKind::Range));
        }
        let w = self.width();
        let holds = |e: &Data, op: u64, obj: &Data| -> bool {
            let Ok(ord) = value::convert_like(obj, e, w).and_then(|o| value::compare(e, &o, w))
            else
            {
                return false;
            };
            match op
            {
                0 => true,
                1 => ord == Ordering::Equal,
                2 => ord != Ordering::Greater,
                3 => ord == Ordering::Less,
                4 => ord != Ordering::Less,
                _ => ord == Ordering::Greater,
            }
        };
        for (i, e) in elems.iter().enumerate().skip(start)
        {
            if e.is_computational() && holds(e, op1, &obj1) && holds(e, op2, &obj2)
            {
                return Ok(Data::Integer(u64::try_from(i).unwrap_or(u64::MAX)));
            }
        }
        Ok(Data::Integer(w.mask()))
    }
}
