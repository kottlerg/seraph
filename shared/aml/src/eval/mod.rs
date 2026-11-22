// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/eval/mod.rs

//! The evaluator: runs control methods and module-level code over a
//! [`Namespace`], reaching hardware through a [`Host`].
//!
//! It walks the parsed terms of a method's code. Each call pushes a frame
//! that holds the method's arguments and locals and owns the objects the
//! method creates, which are removed when it returns. Values are owned
//! ([`Data`]); an object reference ([`crate::value::Ref`]) names a node, a
//! frame's local or argument, or a temporary it owns, and an index path, so
//! that a store through it reaches the object in place.
//!
//! Every evaluation is bounded: the call depth ([`MAX_CALL_DEPTH`]), the
//! nesting of terms and calls on the stack ([`MAX_EVAL_DEPTH`]), the terms
//! evaluated ([`MAX_EVAL_STEPS`]), the bytes of the values it makes
//! ([`MAX_EVAL_ALLOC`]), the nesting of packages ([`MAX_VALUE_DEPTH`]), the
//! objects it creates ([`MAX_EVAL_OBJECTS`]) and its delays
//! ([`MAX_STALL_US`], [`MAX_EVAL_DELAY_MS`]). Past a bound, as on any other
//! error, the evaluation ends with a [`Fault`]: nothing panics, and the
//! namespace holds what the code did up to the fault, its frames' objects
//! removed.

mod expr;
mod field;
mod place;
mod sync;

use alloc::vec::Vec;

use crate::encoding::{self, Seg};
use crate::host::Host;
use crate::namespace::{Body, Method, Namespace, Native, NodeId, Object, Owner, TableId};
use crate::parse::Parser;
use crate::term::{Name, Op, Term};
use crate::value::{self, Base, Data, IntWidth, Radix, Ref};
use crate::{
    Fault, FaultKind, MAX_CALL_DEPTH, MAX_EVAL_ALLOC, MAX_EVAL_DEPTH, MAX_EVAL_OBJECTS,
    MAX_EVAL_STEPS, push,
};

/// The number of arguments a frame holds, `Arg0`-`Arg6`.
const ARGS: usize = 7;
/// The number of locals a frame holds, `Local0`-`Local7`.
const LOCALS: usize = 8;

/// A method frame, or the frame module-level code and a top-level read run
/// in.
#[derive(Debug)]
struct Frame
{
    /// Never reused within an evaluator, so a reference to a local of a
    /// returned frame finds none.
    serial: u64,
    /// The scope names resolve from and objects are created in.
    scope: NodeId,
    /// The table whose code runs, for the span of a method it defines.
    table: Option<TableId>,
    /// The integer width of the code.
    width: IntWidth,
    /// The owner of the objects the frame creates.
    owner: Owner,
    /// Whether the frame has created an object that its return removes.
    created: bool,
    args: [Data; ARGS],
    locals: [Data; LOCALS],
}

impl Frame
{
    /// A frame whose arguments and locals hold no value.
    fn new(
        serial: u64,
        scope: NodeId,
        table: Option<TableId>,
        width: IntWidth,
        owner: Owner,
    ) -> Self
    {
        Self {
            serial,
            scope,
            table,
            width,
            owner,
            created: false,
            args: Default::default(),
            locals: Default::default(),
        }
    }
}

/// What ends a term list early.
#[derive(Debug)]
enum Flow
{
    /// Nothing: run the next term.
    Next,
    /// `Break`.
    Break,
    /// `Continue`.
    Continue,
    /// `Return`, with the value.
    Return(Data),
}

/// The counts that each evaluation's bounds limit.
#[derive(Clone, Copy, Debug, Default)]
struct Budget
{
    steps: usize,
    alloc: usize,
    depth: usize,
    objects: usize,
    delay_us: u64,
}

/// The outcome of [`Evaluator::run_module_code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleReport
{
    /// The module-level terms run.
    pub terms: usize,
    /// The terms that ended in a fault.
    pub faults: usize,
    /// The first fault.
    pub first_fault: Option<Fault>,
}

/// An evaluator over a namespace and a host.
pub struct Evaluator<'a>
{
    ns: &'a mut Namespace,
    host: &'a mut dyn Host,
    frames: Vec<Frame>,
    serial: u64,
    held: Vec<sync::Held>,
    global: u32,
    gl: Option<NodeId>,
    budget: Budget,
    /// The most entries `held` has had, for the tests.
    #[cfg(test)]
    held_peak: usize,
}

impl core::fmt::Debug for Evaluator<'_>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        f.debug_struct("Evaluator")
            .field("frames", &self.frames.len())
            .field("held", &self.held.len())
            .finish_non_exhaustive()
    }
}

/// The fault of kind `kind` at the term `t`.
const fn at(t: &Term, kind: FaultKind) -> Fault
{
    Fault {
        kind,
        offset: t.offset,
    }
}

/// A closure mapping a [`FaultKind`] to a fault at the term `t`.
fn by(t: &Term) -> impl Fn(FaultKind) -> Fault + '_
{
    move |k| at(t, k)
}

/// A fault with no term to place it at.
const fn bare(kind: FaultKind) -> Fault
{
    Fault { kind, offset: 0 }
}

/// The kid `i` of `t`.
fn kid(t: &Term, i: usize) -> Result<&Term, Fault>
{
    t.kids.get(i).ok_or(at(t, FaultKind::Truncated))
}

/// The integer immediate of `t`.
fn imm_int(t: &Term) -> Result<u64, Fault>
{
    t.int().ok_or(at(t, FaultKind::BadOpcode))
}

/// The name immediate of `t`.
fn imm_name(t: &Term) -> Result<&Name, Fault>
{
    t.name().ok_or(at(t, FaultKind::BadName))
}

impl<'a> Evaluator<'a>
{
    /// An evaluator of the code in `ns`, reaching hardware through `host`.
    pub fn new(ns: &'a mut Namespace, host: &'a mut dyn Host) -> Self
    {
        let gl = ns.find("\\_GL_");
        Self {
            ns,
            host,
            frames: Vec::new(),
            serial: 0,
            held: Vec::new(),
            global: 0,
            gl,
            budget: Budget::default(),
            #[cfg(test)]
            held_peak: 0,
        }
    }

    /// The most mutexes held at once, stale entries included.
    #[cfg(test)]
    pub(crate) const fn held_peak(&self) -> usize
    {
        self.held_peak
    }

    /// The namespace.
    #[must_use]
    pub fn namespace(&self) -> &Namespace
    {
        self.ns
    }

    /// Evaluate the object `node`: call a method with `args`, or read any
    /// other object's value (a data object's data, a field's contents, a
    /// reference to a device).
    ///
    /// Each evaluation starts with the full budget of every bound, and the
    /// mutexes the code acquires and leaves held are released when it ends.
    ///
    /// # Errors
    ///
    /// The [`Fault`] that ended the evaluation, at the table offset of its
    /// term where there is one.
    pub fn evaluate(&mut self, node: NodeId, args: Vec<Data>) -> Result<Data, Fault>
    {
        self.budget = Budget::default();
        let node = self.ns.follow(node).ok_or(bare(FaultKind::NotFound))?;
        let scope = self.ns.parent(node).unwrap_or(NodeId::ROOT);
        let width = self.owner_width(node);
        let r = self.with_frame(scope, None, width, Owner::Frame(0), |ev| {
            if let Some(Object::Method(m)) = ev.ns.object(node)
            {
                let m = *m;
                return ev.call(node, m, args, width);
            }
            ev.node_value(node)
        });
        self.release_all();
        r
    }

    /// Evaluate the object an absolute path names (`\_SB.PCI0._CRS`), as
    /// [`Evaluator::evaluate`] does.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NotFound`] when nothing has that path, and the faults of
    /// [`Evaluator::evaluate`].
    pub fn evaluate_path(&mut self, path: &str, args: Vec<Data>) -> Result<Data, Fault>
    {
        let node = self.ns.find(path).ok_or(bare(FaultKind::NotFound))?;
        self.evaluate(node, args)
    }

    /// Run the module-level code of every table loaded, once, in load order:
    /// the terms a table holds outside its methods that define no object at
    /// load. The objects they create belong to their table. A term that
    /// faults is counted and the next runs; each term is one evaluation.
    pub fn run_module_code(&mut self) -> ModuleReport
    {
        let module = core::mem::take(&mut self.ns.module);
        let mut report = ModuleReport {
            terms: 0,
            faults: 0,
            first_fault: None,
        };
        for m in &module
        {
            self.budget = Budget::default();
            let width = self.table_width(m.table);
            let r = self.with_frame(m.scope, Some(m.table), width, Owner::Table(m.table), |ev| {
                ev.exec(&m.term).map(drop)
            });
            self.release_all();
            report.terms = report.terms.saturating_add(1);
            if let Err(f) = r
            {
                report.faults = report.faults.saturating_add(1);
                report.first_fault.get_or_insert(f);
            }
        }
        let added = core::mem::replace(&mut self.ns.module, module);
        drop(added);
        report
    }

    // ── Frames ────────────────────────────────────────────────────────

    /// The integer width of `table`'s code.
    fn table_width(&self, table: TableId) -> IntWidth
    {
        match self.ns.table_int64(table)
        {
            Some(false) => IntWidth::Bits32,
            Some(true) | None => IntWidth::Bits64,
        }
    }

    /// The integer width of the code that created `node`.
    fn owner_width(&self, node: NodeId) -> IntWidth
    {
        match self.ns.owner(node)
        {
            Some(Owner::Table(t)) => self.table_width(t),
            Some(Owner::Predefined | Owner::Frame(_)) | None =>
            {
                self.frames.last().map_or(IntWidth::Bits64, |f| f.width)
            }
        }
    }

    /// Run `f` in a new frame, removing the objects it creates as its owner
    /// says when it ends.
    fn with_frame<R>(
        &mut self,
        scope: NodeId,
        table: Option<TableId>,
        width: IntWidth,
        owner: Owner,
        f: impl FnOnce(&mut Self) -> Result<R, Fault>,
    ) -> Result<R, Fault>
    {
        self.serial = self.serial.wrapping_add(1);
        push(
            &mut self.frames,
            Frame::new(self.serial, scope, table, width, owner),
        )
        .map_err(bare)?;
        let r = f(self);
        let ending = self.frames.last().map(|fr| (fr.created, fr.owner));
        self.frames.truncate(self.frames.len().saturating_sub(1));
        let removed = match ending
        {
            Some((true, owner @ Owner::Frame(_))) => self.ns.remove_owned(owner).map_err(bare),
            Some(_) | None => Ok(0),
        };
        self.budget.objects = self
            .budget
            .objects
            .saturating_sub(*removed.as_ref().unwrap_or(&0));
        let r = r?;
        removed?;
        Ok(r)
    }

    /// The running frame.
    fn frame(&self) -> Result<&Frame, FaultKind>
    {
        self.frames.last().ok_or(FaultKind::NotFound)
    }

    /// The running frame, to change.
    fn frame_mut(&mut self) -> Result<&mut Frame, FaultKind>
    {
        self.frames.last_mut().ok_or(FaultKind::NotFound)
    }

    /// The integer width of the running code.
    fn width(&self) -> IntWidth
    {
        self.frames.last().map_or(IntWidth::Bits64, |f| f.width)
    }

    /// The scope of the running code.
    fn scope(&self) -> NodeId
    {
        self.frames.last().map_or(NodeId::ROOT, |f| f.scope)
    }

    /// The serial of the running frame.
    fn serial(&self) -> u64
    {
        self.frames.last().map_or(0, |f| f.serial)
    }

    // ── Bounds ────────────────────────────────────────────────────────

    /// Count one term against [`MAX_EVAL_STEPS`] and enter one level of
    /// [`MAX_EVAL_DEPTH`]; [`Evaluator::leave`] leaves it.
    fn enter(&mut self, t: &Term) -> Result<(), Fault>
    {
        if self.budget.steps >= MAX_EVAL_STEPS
        {
            return Err(at(t, FaultKind::Bound));
        }
        if self.budget.depth >= MAX_EVAL_DEPTH
        {
            return Err(at(t, FaultKind::Depth));
        }
        self.budget.steps = self.budget.steps.saturating_add(1);
        self.budget.depth = self.budget.depth.saturating_add(1);
        Ok(())
    }

    /// Leave the level [`Evaluator::enter`] entered.
    fn leave(&mut self)
    {
        self.budget.depth = self.budget.depth.saturating_sub(1);
    }

    /// Count the bytes of the value `d` against [`MAX_EVAL_ALLOC`].
    fn charge(&mut self, d: &Data) -> Result<(), FaultKind>
    {
        if matches!(d, Data::Uninitialized | Data::Integer(_))
        {
            return Ok(());
        }
        self.charge_bytes(d.weight())
    }

    /// Count `bytes` against [`MAX_EVAL_ALLOC`].
    fn charge_bytes(&mut self, bytes: usize) -> Result<(), FaultKind>
    {
        self.budget.alloc = self.budget.alloc.saturating_add(bytes);
        if self.budget.alloc > MAX_EVAL_ALLOC
        {
            return Err(FaultKind::Bound);
        }
        Ok(())
    }

    // ── Code ──────────────────────────────────────────────────────────

    /// Run the term list `terms`.
    fn run_list(&mut self, terms: &[Term]) -> Result<Flow, Fault>
    {
        for t in terms
        {
            match self.exec(t)?
            {
                Flow::Next =>
                {}
                flow @ (Flow::Break | Flow::Continue | Flow::Return(_)) => return Ok(flow),
            }
        }
        Ok(Flow::Next)
    }

    /// Run the body list of `t` at kid `i`.
    fn run_body(&mut self, t: &Term, i: usize) -> Result<Flow, Fault>
    {
        let body = kid(t, i)?;
        self.run_list(&body.kids)
    }

    /// Whether the predicate `t` holds: its value as an integer is not 0.
    fn holds(&mut self, t: &Term) -> Result<bool, Fault>
    {
        Ok(self.int(t)? != 0)
    }

    /// Run the statement `t`.
    fn exec(&mut self, t: &Term) -> Result<Flow, Fault>
    {
        self.enter(t)?;
        let r = self.exec_op(t);
        self.leave();
        r
    }

    fn exec_op(&mut self, t: &Term) -> Result<Flow, Fault>
    {
        match t.op
        {
            Op::If => self.exec_if(t),
            Op::While => self.exec_while(t),
            Op::Return =>
            {
                let v = self.eval(kid(t, 0)?)?;
                Ok(Flow::Return(v))
            }
            Op::Break => Ok(Flow::Break),
            Op::Continue => Ok(Flow::Continue),
            Op::Noop | Op::BreakPoint | Op::External => Ok(Flow::Next),
            Op::Notify => self.notify(t).map(|()| Flow::Next),
            Op::Release | Op::Reset | Op::Signal | Op::Sleep | Op::Stall =>
            {
                self.sync_statement(t).map(|()| Flow::Next)
            }
            Op::Fatal => Err(at(t, FaultKind::Fatal)),
            Op::Load | Op::Unload | Op::DataRegion => Err(at(t, FaultKind::Unsupported)),
            Op::Scope | Op::Device | Op::Processor | Op::PowerRes | Op::ThermalZone =>
            {
                self.exec_scoped(t)
            }
            Op::Name
            | Op::Alias
            | Op::Mutex
            | Op::Event
            | Op::OpRegion
            | Op::Field
            | Op::IndexField
            | Op::BankField
            | Op::Method
            | Op::CreateBitField
            | Op::CreateByteField
            | Op::CreateWordField
            | Op::CreateDWordField
            | Op::CreateQWordField
            | Op::CreateField => self.define(t).map(|()| Flow::Next),
            Op::Integer
            | Op::String
            | Op::NameRef
            | Op::Call
            | Op::Local
            | Op::Arg
            | Op::Null
            | Op::List
            | Op::Buffer
            | Op::Package
            | Op::VarPackage
            | Op::Revision
            | Op::Debug
            | Op::ElseIf
            | Op::Else
            | Op::Store
            | Op::RefOf
            | Op::Add
            | Op::Concat
            | Op::Subtract
            | Op::Increment
            | Op::Decrement
            | Op::Multiply
            | Op::Divide
            | Op::ShiftLeft
            | Op::ShiftRight
            | Op::And
            | Op::Nand
            | Op::Or
            | Op::Nor
            | Op::Xor
            | Op::Not
            | Op::FindSetLeftBit
            | Op::FindSetRightBit
            | Op::DerefOf
            | Op::ConcatRes
            | Op::Mod
            | Op::SizeOf
            | Op::Index
            | Op::Match
            | Op::ObjectType
            | Op::LAnd
            | Op::LOr
            | Op::LNot
            | Op::LEqual
            | Op::LGreater
            | Op::LLess
            | Op::ToBuffer
            | Op::ToDecimalString
            | Op::ToHexString
            | Op::ToInteger
            | Op::ToString
            | Op::CopyObject
            | Op::Mid
            | Op::CondRefOf
            | Op::LoadTable
            | Op::Acquire
            | Op::Wait
            | Op::FromBcd
            | Op::ToBcd
            | Op::Timer => self.exec_expr(t),
        }
    }

    /// An expression run as a statement, its value discarded once counted.
    fn exec_expr(&mut self, t: &Term) -> Result<Flow, Fault>
    {
        let v = self.eval_op(t)?;
        self.count_made(t, &v)?;
        Ok(Flow::Next)
    }

    /// `If`, with its `ElseIf`s and `Else`.
    fn exec_if(&mut self, t: &Term) -> Result<Flow, Fault>
    {
        if self.holds(kid(t, 0)?)?
        {
            return self.run_body(t, 1);
        }
        for branch in t.kids.iter().skip(2)
        {
            if branch.op != Op::ElseIf
            {
                return self.run_body(branch, 0);
            }
            if self.holds(kid(branch, 0)?)?
            {
                return self.run_body(branch, 1);
            }
        }
        Ok(Flow::Next)
    }

    /// `While`.
    fn exec_while(&mut self, t: &Term) -> Result<Flow, Fault>
    {
        let pred = kid(t, 0)?;
        loop
        {
            // Each pass evaluates the predicate, which counts against
            // MAX_EVAL_STEPS, so the loop ends.
            if !self.holds(pred)?
            {
                return Ok(Flow::Next);
            }
            match self.run_body(t, 1)?
            {
                Flow::Next | Flow::Continue =>
                {}
                Flow::Break => return Ok(Flow::Next),
                flow @ Flow::Return(_) => return Ok(flow),
            }
        }
    }

    // ── Calls ─────────────────────────────────────────────────────────

    /// Call the method `m` at `node` with `args`, from code of width
    /// `caller`.
    fn call(
        &mut self,
        node: NodeId,
        m: Method,
        args: Vec<Data>,
        caller: IntWidth,
    ) -> Result<Data, Fault>
    {
        let (table, start, end) = match m.body
        {
            Body::Native(Native::Osi) =>
            {
                let name = args.first().ok_or(bare(FaultKind::Args))?;
                let name = value::string(name, caller, Radix::Implicit).map_err(bare)?;
                let yes = self.host.osi(&name);
                return Ok(Data::Integer(if yes { caller.mask() } else { 0 }));
            }
            Body::Aml { table, start, end } => (table, start, end),
        };
        if self.frames.len() > MAX_CALL_DEPTH
        {
            return Err(bare(FaultKind::Depth));
        }
        if args.len() > ARGS
        {
            return Err(bare(FaultKind::Args));
        }
        let serialized = m.flags & 8 != 0;
        if serialized
        {
            self.acquire_method(node, m.flags >> 4).map_err(bare)?;
        }
        let (code, id) = match self.code(node, table, start, end)
        {
            Ok(c) => c,
            Err(f) =>
            {
                if serialized
                {
                    self.release_method(node);
                }
                return Err(f);
            }
        };
        let width = self.table_width(table);
        let depth = u32::try_from(self.frames.len()).unwrap_or(u32::MAX);
        let r = self.with_frame(node, Some(table), width, Owner::Frame(depth), |ev| {
            let frame = ev.frame_mut().map_err(bare)?;
            for (slot, a) in frame.args.iter_mut().zip(args)
            {
                *slot = a;
            }
            match ev.run_list(&code)?
            {
                Flow::Return(v) => ev.detach(v),
                Flow::Next | Flow::Break | Flow::Continue => Ok(Data::Uninitialized),
            }
        });
        if let Some(id) = id
        {
            self.ns.put_code(id, code);
        }
        if serialized
        {
            self.release_method(node);
        }
        r
    }

    /// The value a method returns, made independent of its frame: a
    /// reference to one of the frame's locals or arguments is replaced by
    /// the value it refers to.
    fn detach(&mut self, v: Data) -> Result<Data, Fault>
    {
        let serial = self.serial();
        match &v
        {
            Data::Ref(Ref {
                base: Base::Local { frame, .. } | Base::Arg { frame, .. },
                ..
            }) if *frame == serial =>
            {
                let d = self.deref(&v)?;
                self.charge(&d).map_err(bare)?;
                Ok(d)
            }
            Data::Uninitialized
            | Data::Integer(_)
            | Data::String(_)
            | Data::Buffer(_)
            | Data::Package(_)
            | Data::Name(_)
            | Data::Ref(_) => Ok(v),
        }
    }

    /// The parsed code of the method at `node` whose body is
    /// `table[start..end]`, and the store id to return it to: taken from the
    /// namespace's store when it is there, else parsed now.
    fn code(
        &mut self,
        node: NodeId,
        table: TableId,
        start: u32,
        end: u32,
    ) -> Result<(Vec<Term>, Option<crate::namespace::CodeId>), Fault>
    {
        if matches!(
            self.ns.owner(node),
            Some(Owner::Table(_) | Owner::Predefined)
        )
        {
            let id = self.ns.method_code(node)?;
            if let Some(code) = self.ns.take_code(id)
            {
                return Ok((code, Some(id)));
            }
        }
        let bytes = self
            .ns
            .table_bytes(table)
            .ok_or(bare(FaultKind::NotFound))?;
        let start = usize::try_from(start).map_err(|_| bare(FaultKind::Bound))?;
        let end = usize::try_from(end).map_err(|_| bare(FaultKind::Bound))?;
        let code = Parser::new(self.ns, bytes, start, end, node).term_list()?;
        Ok((code, None))
    }

    /// The value of `node` read as an operand: a data object's data (each
    /// name a package holds resolved, from the scope its definition appeared
    /// in (`Namespace::scope_of`), to a reference
    /// when it names an object), a field's contents, the result of a method
    /// that takes no argument, or a reference to any other object.
    fn node_value(&mut self, node: NodeId) -> Result<Data, Fault>
    {
        let object = self.ns.object(node).ok_or(bare(FaultKind::NotFound))?;
        let v = match object
        {
            Object::Data(d) =>
            {
                let mut v = d.try_clone().map_err(bare)?;
                let scope = self.ns.scope_of(node).unwrap_or(NodeId::ROOT);
                self.resolve_names(&mut v, scope);
                v
            }
            Object::Field(_) => return self.read_field(node),
            Object::BufferField(_) => return self.read_buffer_field(node),
            Object::Method(m) =>
            {
                let m = *m;
                if m.args != 0
                {
                    return Err(bare(FaultKind::Args));
                }
                let w = self.width();
                return self.call(node, m, Vec::new(), w);
            }
            Object::External { .. } => return Err(bare(FaultKind::NotFound)),
            Object::Alias(target) =>
            {
                let target = self.ns.follow(*target).ok_or(bare(FaultKind::NotFound))?;
                return self.node_value(target);
            }
            Object::Scope
            | Object::Device
            | Object::Processor { .. }
            | Object::PowerResource { .. }
            | Object::ThermalZone
            | Object::Mutex { .. }
            | Object::Event { .. }
            | Object::Region(_)
            | Object::DataRegion(_) => Data::Ref(self.node_ref(node)?),
        };
        Ok(v)
    }

    /// A reference to the whole of `node`.
    fn node_ref(&self, node: NodeId) -> Result<Ref, Fault>
    {
        let generation = self.ns.generation(node).ok_or(bare(FaultKind::NotFound))?;
        Ok(Ref::node(node, generation))
    }

    /// Replace each name `v`'s packages hold that resolves from `scope` with
    /// a reference to the object it names.
    fn resolve_names(&self, v: &mut Data, scope: NodeId)
    {
        match v
        {
            Data::Package(p) =>
            {
                for e in p
                {
                    self.resolve_names(e, scope);
                }
            }
            Data::Name(n) =>
            {
                let found = self.ns.resolve(scope, n).and_then(|id| self.ns.follow(id));
                if let Some(id) = found
                    && let Ok(r) = self.node_ref(id)
                {
                    *v = Data::Ref(r);
                }
            }
            Data::Uninitialized
            | Data::Integer(_)
            | Data::String(_)
            | Data::Buffer(_)
            | Data::Ref(_) =>
            {}
        }
    }

    /// The node `name` names from the running scope, through aliases.
    fn lookup(&self, name: &Name) -> Option<NodeId>
    {
        self.ns
            .resolve(self.scope(), name)
            .and_then(|id| self.ns.follow(id))
    }

    /// The value of the child `seg` of `node`, as an integer; `None` when
    /// there is no such child.
    fn child_int(&mut self, node: NodeId, seg: Seg) -> Result<Option<u64>, Fault>
    {
        let Some(child) = self.ns.child(node, seg).and_then(|c| self.ns.follow(c))
        else
        {
            return Ok(None);
        };
        let v = self.node_value(child)?;
        let w = self.width();
        Ok(Some(value::integer(&v, w).map_err(bare)?))
    }

    /// The value of the child `seg` of `node`; `None` when there is none.
    fn child_value(&mut self, node: NodeId, seg: Seg) -> Result<Option<Data>, Fault>
    {
        let Some(child) = self.ns.child(node, seg).and_then(|c| self.ns.follow(c))
        else
        {
            return Ok(None);
        };
        self.node_value(child).map(Some)
    }

    // ── Definitions ───────────────────────────────────────────────────

    /// Create the object `name` declares from the running scope, owned by the
    /// running frame.
    fn create(&mut self, name: &Name, object: Object) -> Result<NodeId, FaultKind>
    {
        if self.budget.objects >= MAX_EVAL_OBJECTS
        {
            return Err(FaultKind::Bound);
        }
        let (scope, owner) = {
            let f = self.frame()?;
            (f.scope, f.owner)
        };
        let node = self.ns.create(scope, name, object, owner)?;
        self.budget.objects = self.budget.objects.saturating_add(1);
        self.frame_mut()?.created = true;
        Ok(node)
    }

    /// `Scope`, `Device`, `Processor`, `PowerResource`, `ThermalZone`: run
    /// the body in the scope the term names, creating the object first.
    fn exec_scoped(&mut self, t: &Term) -> Result<Flow, Fault>
    {
        let name = imm_name(t)?;
        let int = |i: usize| -> Result<u64, Fault> { imm_int(kid(t, i)?) };
        let (object, body) = if t.op == Op::Scope
        {
            (None, 0)
        }
        else if t.op == Op::Processor
        {
            let object = Object::Processor {
                id: u8::try_from(int(0)? & 0xFF).unwrap_or(0),
                pblk: u32::try_from(int(1)? & 0xFFFF_FFFF).unwrap_or(0),
                pblk_len: u8::try_from(int(2)? & 0xFF).unwrap_or(0),
            };
            (Some(object), 3)
        }
        else if t.op == Op::PowerRes
        {
            let object = Object::PowerResource {
                level: u8::try_from(int(0)? & 0xFF).unwrap_or(0),
                order: u16::try_from(int(1)? & 0xFFFF).unwrap_or(0),
            };
            (Some(object), 2)
        }
        else if t.op == Op::ThermalZone
        {
            (Some(Object::ThermalZone), 0)
        }
        else
        {
            (Some(Object::Device), 0)
        };
        let node = match object
        {
            Some(object) => self.create(name, object).map_err(by(t))?,
            None => self.lookup(name).ok_or(at(t, FaultKind::NotFound))?,
        };
        let saved = self.frame().map_err(by(t))?.scope;
        self.frame_mut().map_err(by(t))?.scope = node;
        let r = self.run_body(t, body);
        if let Ok(f) = self.frame_mut()
        {
            f.scope = saved;
        }
        r
    }

    /// An object definition other than one with a body.
    fn define(&mut self, t: &Term) -> Result<(), Fault>
    {
        let name = imm_name(t);
        let object = if t.op == Op::Name
        {
            Object::Data(self.eval(kid(t, 0)?)?)
        }
        else if t.op == Op::Alias
        {
            let source = imm_name(kid(t, 0)?)?;
            Object::Alias(self.lookup(source).ok_or(at(t, FaultKind::NotFound))?)
        }
        else if t.op == Op::Mutex
        {
            Object::Mutex {
                sync: u8::try_from(imm_int(kid(t, 0)?)? & 0xF).unwrap_or(0),
            }
        }
        else if t.op == Op::Event
        {
            Object::Event { pending: 0 }
        }
        else if t.op == Op::OpRegion
        {
            self.region_object(t)?
        }
        else if t.op == Op::Method
        {
            self.method_object(t)?
        }
        else if matches!(t.op, Op::Field | Op::IndexField | Op::BankField)
        {
            return self.define_fields(t);
        }
        else
        {
            self.buffer_field_object(t)?
        };
        self.create(name?, object).map_err(by(t))?;
        Ok(())
    }

    /// The object of a `Method` a running method defines: its body's span in
    /// the running table.
    fn method_object(&self, t: &Term) -> Result<Object, Fault>
    {
        let table = self
            .frame()
            .map_err(by(t))?
            .table
            .ok_or(at(t, FaultKind::NotFound))?;
        let bytes = self
            .ns
            .table_bytes(table)
            .ok_or(at(t, FaultKind::NotFound))?;
        let pos = usize::try_from(t.offset).map_err(|_| at(t, FaultKind::Bound))?;
        let (body, end) =
            encoding::package(bytes, pos.saturating_add(1)).ok_or(at(t, FaultKind::Truncated))?;
        let (_, size) = encoding::name_str(bytes, body).ok_or(at(t, FaultKind::BadName))?;
        let flags_at = body.saturating_add(size);
        let flags = *bytes.get(flags_at).ok_or(at(t, FaultKind::Truncated))?;
        let span = |v: usize| u32::try_from(v).map_err(|_| at(t, FaultKind::Bound));
        Ok(Object::Method(Method {
            args: flags & 7,
            flags,
            body: Body::Aml {
                table,
                start: span(flags_at.saturating_add(1))?,
                end: span(end)?,
            },
            code: None,
        }))
    }
}
