// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/load.rs

//! Loading a DSDT or SSDT into the namespace.
//!
//! The loader walks the table's term list in order, twice. It enters the
//! bodies of `Scope`, `Device`, `Processor`, `PowerResource` and
//! `ThermalZone` itself, and records a `Method` with its body's span, which
//! [`Namespace::method_code`] parses on first use.
//!
//! The first walk declares the names the table defines at load: it creates
//! the `Device`, `Processor`, `PowerResource` and `ThermalZone` objects, the
//! methods and the `External`s, and a placeholder node, holding
//! [`Data::Uninitialized`], for each name that `Name`, `Alias`, `Mutex`,
//! `Event`, `OperationRegion`, `DataRegion` and the field definitions
//! declare. The second walk defines: it parses every other term again, now
//! that the table's names are in the namespace and its methods have their
//! argument counts, gives each of the table's placeholders that a
//! definition names its object (a `Name`'s data folded to a constant), and
//! keeps any other term as module-level code ([`Namespace::module_terms`])
//! for an evaluator to run. So a call to a method defined later in the table
//! parses as a call, and a data object the first walk declared hides a
//! method of the same name in an enclosing scope.
//!
//! The first walk reads in table order too, so a reference it meets before
//! the definition of the data object it names resolves, in that walk, to a
//! method of that name in an enclosing scope defined earlier, and reads as a
//! call of it. When that reading ends the term list with a fault whose end
//! is not known, the data object is not declared, and the second walk reads
//! the same call. Otherwise the first walk goes on to declare the data
//! object, and the second reads the name as a reference to it. Where the
//! walks read a term differently, the first may declare a name the second
//! never defines. A node is never removed: a
//! placeholder the second walk does not define, by a fault or by such a
//! reading, keeps [`Data::Uninitialized`], so every reference resolved to it
//! stays valid.
//!
//! A fault ends only the term list it is found in: a term whose end its
//! `PkgLength` gives is skipped and the list continues after it, and any
//! other ends the list, whose enclosing list continues. The second walk
//! counts the faults of both and keeps the first; the first walk records
//! none, since the second meets each of its faults again.

use alloc::vec::Vec;

use crate::encoding::{
    self, EXT_BANK_FIELD, EXT_DEVICE, EXT_FIELD, EXT_INDEX_FIELD, EXT_POWER_RES, EXT_PROCESSOR,
    EXT_THERMAL_ZONE, OP_ELSE, OP_EXT_PREFIX, OP_IF, OP_METHOD, OP_SCOPE, OP_WHILE, Seg,
};
use crate::namespace::{
    AccessAs, Body, Data, FieldKind, FieldUnit, Method, Namespace, NodeId, Object, Owner, Region,
    Table, TableId,
};
use crate::parse::{Parser, to_name};
use crate::term::{FieldElem, FieldList, Imm, Name, Op, Term};
use crate::{
    Fault, FaultKind, MAX_BUFFER_BYTES, MAX_PACKAGE_ELEMENTS, MAX_PARSE_DEPTH, REVISION, push,
};

/// Length of the common header of an ACPI system description table.
pub const SDT_HEADER_LEN: usize = 36;

/// The outcome of a table load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadReport
{
    /// The table's id.
    pub table: TableId,
    /// The nodes the load created, and the `External`s it defined. An
    /// `External` of a name that already exists creates nothing.
    pub objects: usize,
    /// The module-level terms it kept.
    pub module_terms: usize,
    /// The faults it met.
    pub faults: usize,
    /// The first fault.
    pub first_fault: Option<Fault>,
}

impl Namespace
{
    /// Load the DSDT or SSDT `table` (its header, then its AML up to the
    /// header's length). The namespace keeps a copy of the table.
    ///
    /// # Errors
    ///
    /// [`FaultKind::BadTable`] for a table shorter than its header or than
    /// its length field, or whose length field is below the header's size,
    /// and [`FaultKind::NoMemory`] or [`FaultKind::Bound`] when the copy
    /// cannot be kept. A fault in the AML is counted in the report instead.
    pub fn load_table(&mut self, table: &[u8]) -> Result<LoadReport, Fault>
    {
        let bad = Fault::at(FaultKind::BadTable, 0);
        let len = encoding::le(table, 4, 4)
            .and_then(|l| usize::try_from(l).ok())
            .ok_or(bad)?;
        if len < SDT_HEADER_LEN || len > table.len()
        {
            return Err(bad);
        }
        let int64 = table.get(8).is_some_and(|rev| *rev >= 2);
        let id = self.next_table().map_err(|k| Fault::at(k, 0))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| Fault::at(FaultKind::NoMemory, 0))?;
        bytes.extend_from_slice(table.get(..len).ok_or(bad)?);
        push(
            &mut self.tables,
            Table {
                bytes: Vec::new(),
                int64,
            },
        )
        .map_err(|k| Fault::at(k, 0))?;
        let mut loader = Loader {
            ns: self,
            bytes: &bytes,
            mask: if int64 { u64::MAX } else { 0xFFFF_FFFF },
            declaring: true,
            declared: Vec::new(),
            report: LoadReport {
                table: id,
                objects: 0,
                module_terms: 0,
                faults: 0,
                first_fault: None,
            },
        };
        loader.list(SDT_HEADER_LEN, len, NodeId::ROOT, 0);
        loader.declaring = false;
        loader.list(SDT_HEADER_LEN, len, NodeId::ROOT, 0);
        let report = loader.report;
        if let Some(t) = self.tables.last_mut()
        {
            t.bytes = bytes;
        }
        Ok(report)
    }

    /// Parse the code of every method the loaded tables define, in arena
    /// order, keeping it as [`Namespace::method_code`] does. Returns the
    /// number of methods parsed and the faults met, with the node of the
    /// first.
    pub fn parse_methods(&mut self) -> (usize, usize, Option<(NodeId, Fault)>)
    {
        let mut methods = Vec::new();
        for id in self.nodes()
        {
            if let Some(Object::Method(Method {
                body: Body::Aml { .. },
                ..
            })) = self.object(id)
                && push(&mut methods, id).is_err()
            {
                break;
            }
        }
        let (mut parsed, mut faults, mut first) = (0usize, 0usize, None);
        for id in methods
        {
            match self.method_code(id)
            {
                Ok(_) => parsed = parsed.saturating_add(1),
                Err(f) =>
                {
                    faults = faults.saturating_add(1);
                    first.get_or_insert((id, f));
                }
            }
        }
        (parsed, faults, first)
    }
}

/// The state of one table load.
struct Loader<'a, 'b>
{
    ns: &'a mut Namespace,
    bytes: &'b [u8],
    /// The table's integer width as a mask: 64 bits from revision 2, else
    /// 32.
    mask: u64,
    /// Whether this is the first walk, which declares.
    declaring: bool,
    /// Each object body and method the first walk created: the table
    /// offset of its term and its node, in offset order.
    declared: Vec<(usize, NodeId)>,
    report: LoadReport,
}

/// A fault, and the offset to resume the list at, if the faulting term's
/// end is known.
type Stop = (Fault, Option<usize>);

impl Loader<'_, '_>
{
    fn owner(&self) -> Owner
    {
        Owner::Table(self.report.table)
    }

    /// Count `fault`, in the second walk.
    fn record(&mut self, fault: Fault)
    {
        if self.declaring
        {
            return;
        }
        self.report.faults = self.report.faults.saturating_add(1);
        self.report.first_fault.get_or_insert(fault);
    }

    /// The node the first walk created for the object body or method at
    /// `pos`, in the second walk.
    fn declared_at(&self, pos: usize) -> Option<NodeId>
    {
        if self.declaring
        {
            return None;
        }
        let i = self.declared.binary_search_by_key(&pos, |d| d.0).ok()?;
        self.declared.get(i).map(|d| d.1)
    }

    /// In the first walk, a placeholder for `name` in `scope`. A name that
    /// exists already, or whose parent does not, gets none.
    fn placeholder(&mut self, scope: NodeId, name: &Name)
    {
        let owner = self.owner();
        if self.ns.declare(scope, name, owner).is_ok()
        {
            self.report.objects = self.report.objects.saturating_add(1);
        }
    }

    /// In the first walk, a placeholder for each name the definition `term`
    /// declares.
    fn declare_names(&mut self, term: &Term, scope: NodeId)
    {
        match (term.op, &term.imm)
        {
            (
                Op::Name | Op::Alias | Op::Mutex | Op::Event | Op::OpRegion | Op::DataRegion,
                Imm::Name(name),
            ) => self.placeholder(scope, name),
            (Op::Field | Op::IndexField | Op::BankField, Imm::Fields(list)) =>
            {
                for elem in &list.elems
                {
                    if let FieldElem::Named { name, .. } = elem
                        && let Ok(name) = seg_name(*name)
                    {
                        self.placeholder(scope, &name);
                    }
                }
            }
            _ =>
            {}
        }
    }

    /// Create the object body or method `name` at `pos` in `scope`, or, in
    /// the second walk, take the node the first created for it. A node the
    /// first walk cannot record is a fault there, so its body is not
    /// entered; the second walk then meets the node as an existing name.
    fn declare(
        &mut self,
        scope: NodeId,
        name: &Name,
        object: Object,
        pos: usize,
    ) -> Result<NodeId, Fault>
    {
        if let Some(node) = self.declared_at(pos)
        {
            return Ok(node);
        }
        let node = self.create(scope, name, object, pos)?;
        if self.declaring
        {
            push(&mut self.declared, (pos, node)).map_err(|k| Fault::at(k, pos))?;
        }
        Ok(node)
    }

    /// Load the term list `start..end` in `scope`, at nesting `depth`.
    fn list(&mut self, start: usize, end: usize, scope: NodeId, depth: usize)
    {
        if depth >= MAX_PARSE_DEPTH
        {
            self.record(Fault::at(FaultKind::Depth, start));
            return;
        }
        let mut pos = start;
        while pos < end
        {
            match self.term(pos, end, scope, depth)
            {
                Ok(next) if next > pos => pos = next,
                Ok(_) => return,
                Err((fault, resume)) =>
                {
                    self.record(fault);
                    match resume
                    {
                        Some(next) if next > pos => pos = next,
                        Some(_) | None => return,
                    }
                }
            }
        }
    }

    /// Load the term at `pos` of a list ending at `end`; the offset after it.
    fn term(&mut self, pos: usize, end: usize, scope: NodeId, depth: usize) -> Result<usize, Stop>
    {
        let view = self.bytes.get(..end).unwrap_or(&[]);
        let b0 = view.get(pos).copied();
        let b1 = view.get(pos.saturating_add(1)).copied();
        match (b0, b1)
        {
            (Some(OP_SCOPE), _) => self.scope_term(pos, end, scope, depth),
            (Some(OP_METHOD), _) => self.method(pos, end, scope),
            (
                Some(OP_EXT_PREFIX),
                Some(EXT_DEVICE | EXT_PROCESSOR | EXT_POWER_RES | EXT_THERMAL_ZONE),
            ) => self.object_body(pos, end, scope, depth),
            _ => self.statement(pos, end, scope),
        }
    }

    /// The package whose `PkgLength` is at `lead`, in a list ending at `end`:
    /// its body's start and its end.
    fn package(&self, lead: usize, end: usize) -> Result<(usize, usize), Stop>
    {
        let view = self.bytes.get(..end).unwrap_or(&[]);
        encoding::package(view, lead).ok_or((Fault::at(FaultKind::Truncated, lead), None))
    }

    /// The name at `pos` of a package ending at `end`, owned, and its size.
    fn name_at(&self, pos: usize, end: usize, resume: usize) -> Result<(Name, usize), Stop>
    {
        let view = self.bytes.get(..end).unwrap_or(&[]);
        let (encoded, size) = encoding::name_str(view, pos)
            .ok_or((Fault::at(FaultKind::BadName, pos), Some(resume)))?;
        let name = to_name(&encoded).map_err(|k| (Fault::at(k, pos), Some(resume)))?;
        Ok((name, size))
    }

    /// `Scope`: enter the body in the scope the name resolves to.
    fn scope_term(
        &mut self,
        pos: usize,
        end: usize,
        scope: NodeId,
        depth: usize,
    ) -> Result<usize, Stop>
    {
        let (body, pkg_end) = self.package(pos.saturating_add(1), end)?;
        let (name, size) = self.name_at(body, pkg_end, pkg_end)?;
        let target = self
            .ns
            .resolve(scope, &name)
            .and_then(|n| self.ns.follow(n))
            .ok_or((Fault::at(FaultKind::NotFound, pos), Some(pkg_end)))?;
        self.list(
            body.saturating_add(size),
            pkg_end,
            target,
            depth.saturating_add(1),
        );
        Ok(pkg_end)
    }

    /// `Method`: record it with its body's span.
    fn method(&mut self, pos: usize, end: usize, scope: NodeId) -> Result<usize, Stop>
    {
        let (body, pkg_end) = self.package(pos.saturating_add(1), end)?;
        let (name, size) = self.name_at(body, pkg_end, pkg_end)?;
        let flags_at = body.saturating_add(size);
        let flags = *self
            .bytes
            .get(..pkg_end)
            .and_then(|v| v.get(flags_at))
            .ok_or((Fault::at(FaultKind::Truncated, flags_at), Some(pkg_end)))?;
        let span = |v: usize| {
            u32::try_from(v).map_err(|_| (Fault::at(FaultKind::Bound, pos), Some(pkg_end)))
        };
        let method = Method {
            args: flags & 7,
            flags,
            body: Body::Aml {
                table: self.report.table,
                start: span(flags_at.saturating_add(1))?,
                end: span(pkg_end)?,
            },
            code: None,
        };
        self.declare(scope, &name, Object::Method(method), pos)
            .map_err(|f| (f, Some(pkg_end)))?;
        Ok(pkg_end)
    }

    /// `Device`, `Processor`, `PowerResource`, `ThermalZone`: create the
    /// object and enter its body.
    fn object_body(
        &mut self,
        pos: usize,
        end: usize,
        scope: NodeId,
        depth: usize,
    ) -> Result<usize, Stop>
    {
        let op = self.bytes.get(pos.saturating_add(1)).copied();
        let (body, pkg_end) = self.package(pos.saturating_add(2), end)?;
        let (name, size) = self.name_at(body, pkg_end, pkg_end)?;
        let mut at = body.saturating_add(size);
        let short = (Fault::at(FaultKind::Truncated, pos), Some(pkg_end));
        let view = self.bytes.get(..pkg_end).unwrap_or(&[]);
        let mut fixed = |n: usize| -> Result<u64, Stop> {
            let v = encoding::le(view, at, n).ok_or(short)?;
            at = at.saturating_add(n);
            Ok(v)
        };
        let object = match op
        {
            Some(EXT_PROCESSOR) => Object::Processor {
                id: u8::try_from(fixed(1)?).unwrap_or(0),
                pblk: u32::try_from(fixed(4)?).unwrap_or(0),
                pblk_len: u8::try_from(fixed(1)?).unwrap_or(0),
            },
            Some(EXT_POWER_RES) => Object::PowerResource {
                level: u8::try_from(fixed(1)?).unwrap_or(0),
                order: u16::try_from(fixed(2)?).unwrap_or(0),
            },
            Some(EXT_THERMAL_ZONE) => Object::ThermalZone,
            Some(_) | None => Object::Device,
        };
        let node = self
            .declare(scope, &name, object, pos)
            .map_err(|f| (f, Some(pkg_end)))?;
        self.list(at, pkg_end, node, depth.saturating_add(1));
        Ok(pkg_end)
    }

    /// Create `name` in `scope`, counting it.
    fn create(
        &mut self,
        scope: NodeId,
        name: &Name,
        object: Object,
        pos: usize,
    ) -> Result<NodeId, Fault>
    {
        let owner = self.owner();
        let node = self
            .ns
            .create(scope, name, object, owner)
            .map_err(|k| Fault::at(k, pos))?;
        self.report.objects = self.report.objects.saturating_add(1);
        Ok(node)
    }

    /// Any other term: parse it, then define the object it declares or keep
    /// it as module-level code. The first walk declares an `External`, and
    /// a placeholder for each name any other definition declares.
    fn statement(&mut self, pos: usize, end: usize, scope: NodeId) -> Result<usize, Stop>
    {
        let mut parser = Parser::new(self.ns, self.bytes, pos, end, scope);
        let parsed = parser.next_statement();
        let next = parser.position();
        let term = match parsed
        {
            Some(Ok(t)) => t,
            Some(Err(f)) => return Err((f, self.package_end(pos, end))),
            None => return Ok(end),
        };
        if self.declaring && term.op != Op::External
        {
            self.declare_names(&term, scope);
            return Ok(next);
        }
        self.define(term, scope, pos).map_err(|f| (f, Some(next)))?;
        Ok(next)
    }

    /// The end of the term at `pos` when its `PkgLength` gives it.
    fn package_end(&self, pos: usize, end: usize) -> Option<usize>
    {
        let view = self.bytes.get(..end)?;
        let lead = match (view.get(pos)?, view.get(pos.checked_add(1)?))
        {
            (&(OP_IF | OP_WHILE | OP_ELSE), _) => pos.checked_add(1)?,
            (&OP_EXT_PREFIX, Some(&(EXT_FIELD | EXT_INDEX_FIELD | EXT_BANK_FIELD))) =>
            {
                pos.checked_add(2)?
            }
            _ => return None,
        };
        encoding::package(view, lead).map(|(_, e)| e)
    }

    /// Define the object `term` declares in `scope`, or keep it as
    /// module-level code.
    fn define(&mut self, term: Term, scope: NodeId, pos: usize) -> Result<(), Fault>
    {
        let fault = |k: FaultKind| Fault::at(k, pos);
        let Term { op, imm, kids, .. } = term;
        let mut kids = kids.into_iter();
        let (name, object) = match (op, imm)
        {
            (Op::Name, Imm::Name(name)) => (name, self.data(&mut kids)),
            (Op::Alias, Imm::Name(name)) => (name, self.alias(scope, &mut kids)),
            (Op::External, Imm::Name(name)) => return self.external(scope, &name, &mut kids, pos),
            (Op::Mutex, Imm::Name(name)) => (name, mutex(&mut kids)),
            (Op::Event, Imm::Name(name)) => (name, Ok(Object::Event)),
            (Op::OpRegion, Imm::Name(name)) => (name, self.region(&mut kids)),
            (Op::DataRegion, Imm::Name(name)) => (name, self.data_region(&mut kids)),
            (Op::Field, Imm::Fields(list)) =>
            {
                let kind = self.region_field(scope, &mut kids).map_err(fault)?;
                return self.fields(scope, kind, list, pos);
            }
            (Op::IndexField, Imm::Fields(list)) =>
            {
                let kind = self.index_field(scope, &mut kids).map_err(fault)?;
                return self.fields(scope, kind, list, pos);
            }
            (Op::BankField, Imm::Fields(list)) =>
            {
                let kind = self.bank_field(scope, &mut kids).map_err(fault)?;
                return self.fields(scope, kind, list, pos);
            }
            (op, imm) =>
            {
                let term = Term {
                    op,
                    imm,
                    kids: kids.collect(),
                    offset: u32::try_from(pos).unwrap_or(u32::MAX),
                };
                return self.keep(term, scope).map_err(fault);
            }
        };
        self.place(scope, &name, object.map_err(fault)?, pos)
    }

    /// Give `name`'s placeholder in `scope`, which the first walk created,
    /// its `object`, or create `name` when it has none.
    fn place(&mut self, scope: NodeId, name: &Name, object: Object, pos: usize)
    -> Result<(), Fault>
    {
        let owner = self.owner();
        if let Some(slot) = self
            .ns
            .placeholder(scope, name, owner)
            .and_then(|node| self.ns.object_mut(node))
        {
            *slot = object;
            return Ok(());
        }
        self.create(scope, name, object, pos).map(drop)
    }

    /// Keep `term` as module-level code run in `scope`.
    fn keep(&mut self, term: Term, scope: NodeId) -> Result<(), FaultKind>
    {
        let module = crate::namespace::ModuleTerm {
            table: self.report.table,
            scope,
            term,
        };
        push(&mut self.ns.module, module)?;
        self.report.module_terms = self.report.module_terms.saturating_add(1);
        Ok(())
    }

    /// The object of a `Name`: its data folded to a constant.
    fn data(&self, kids: &mut Kids) -> Result<Object, FaultKind>
    {
        Ok(Object::Data(fold(next(kids)?, self.mask)?))
    }

    /// The object of an `Alias`: the node its source names from `scope`.
    fn alias(&self, scope: NodeId, kids: &mut Kids) -> Result<Object, FaultKind>
    {
        let source = ref_name(next(kids)?).ok_or(FaultKind::BadName)?;
        let target = self.ns.resolve(scope, &source).ok_or(FaultKind::NotFound)?;
        Ok(Object::Alias(target))
    }

    /// `External`. An External is a declaration: one whose parent is not
    /// defined yet, or whose name already exists, declares nothing, and is
    /// no fault.
    fn external(
        &mut self,
        scope: NodeId,
        name: &Name,
        kids: &mut Kids,
        pos: usize,
    ) -> Result<(), Fault>
    {
        let fault = |k: FaultKind| Fault::at(k, pos);
        let kind = small(&next(kids).map_err(fault)?);
        let args = small(&next(kids).map_err(fault)?) & 7;
        match self.create(scope, name, Object::External { kind, args }, pos)
        {
            Ok(_) => Ok(()),
            Err(f) if matches!(f.kind, FaultKind::NotFound | FaultKind::Exists) => Ok(()),
            Err(f) => Err(f),
        }
    }

    /// The object of an `OperationRegion`: its space, and its offset and
    /// length kept as expressions.
    fn region(&mut self, kids: &mut Kids) -> Result<Object, FaultKind>
    {
        let space = small(&next(kids)?);
        let offset = self.ns.add_expr(next(kids)?)?;
        let length = self.ns.add_expr(next(kids)?)?;
        Ok(Object::Region(Region {
            space,
            offset,
            length,
        }))
    }

    /// The object of a `DataTableRegion`: its three operands kept as
    /// expressions.
    fn data_region(&mut self, kids: &mut Kids) -> Result<Object, FaultKind>
    {
        let a = self.ns.add_expr(next(kids)?)?;
        let b = self.ns.add_expr(next(kids)?)?;
        let c = self.ns.add_expr(next(kids)?)?;
        Ok(Object::DataRegion([a, b, c]))
    }

    /// The kind of a `Field`: its region.
    fn region_field(&self, scope: NodeId, kids: &mut Kids) -> Result<FieldKind, FaultKind>
    {
        Ok(FieldKind::Region(self.resolve(scope, next(kids)?)?))
    }

    /// The kind of an `IndexField`: its index and data fields.
    fn index_field(&self, scope: NodeId, kids: &mut Kids) -> Result<FieldKind, FaultKind>
    {
        let index = self.resolve(scope, next(kids)?)?;
        let data = self.resolve(scope, next(kids)?)?;
        Ok(FieldKind::Index { index, data })
    }

    /// The kind of a `BankField`: its region, its bank field, and the bank
    /// value kept as an expression.
    fn bank_field(&mut self, scope: NodeId, kids: &mut Kids) -> Result<FieldKind, FaultKind>
    {
        let region = self.resolve(scope, next(kids)?)?;
        let bank = self.resolve(scope, next(kids)?)?;
        let value = self.ns.add_expr(next(kids)?)?;
        Ok(FieldKind::Bank {
            region,
            bank,
            value,
        })
    }

    /// The node the [`Op::NameRef`] term `t` names from `scope`.
    fn resolve(&self, scope: NodeId, t: Term) -> Result<NodeId, FaultKind>
    {
        let name = ref_name(t).ok_or(FaultKind::BadName)?;
        self.ns.resolve(scope, &name).ok_or(FaultKind::NotFound)
    }

    /// Create the field units of `list` in `scope`.
    fn fields(
        &mut self,
        scope: NodeId,
        kind: FieldKind,
        list: FieldList,
        pos: usize,
    ) -> Result<(), Fault>
    {
        let fault = |k: FaultKind| Fault::at(k, pos);
        let mut bit = 0u32;
        let mut access_as = None;
        let mut connection = None;
        for elem in list.elems
        {
            match elem
            {
                FieldElem::Named { name, bits } =>
                {
                    let unit = FieldUnit {
                        kind,
                        flags: list.flags,
                        access_as,
                        bit_offset: bit,
                        bit_len: bits,
                        connection,
                    };
                    let name = seg_name(name).map_err(fault)?;
                    self.place(scope, &name, Object::Field(unit), pos)?;
                    bit = bit.checked_add(bits).ok_or(fault(FaultKind::Bound))?;
                }
                FieldElem::Reserved { bits } =>
                {
                    bit = bit.checked_add(bits).ok_or(fault(FaultKind::Bound))?;
                }
                FieldElem::Access { kind, attrib } =>
                {
                    access_as = Some(AccessAs {
                        kind,
                        attrib,
                        len: 0,
                    });
                }
                FieldElem::ExtendedAccess { kind, attrib, len } =>
                {
                    access_as = Some(AccessAs { kind, attrib, len });
                }
                FieldElem::Connect(t) =>
                {
                    connection = Some(self.ns.add_expr(t).map_err(fault)?);
                }
            }
        }
        Ok(())
    }
}

/// The operand terms of a parsed declaration, in order.
type Kids = alloc::vec::IntoIter<Term>;

/// The relative name of one segment `seg`, as a field element declares it.
fn seg_name(seg: Seg) -> Result<Name, FaultKind>
{
    let mut segs = Vec::new();
    push(&mut segs, seg)?;
    Ok(Name {
        root: false,
        up: 0,
        segs,
    })
}

/// The next operand term.
fn next(kids: &mut Kids) -> Result<Term, FaultKind>
{
    kids.next().ok_or(FaultKind::Truncated)
}

/// The object of a `Mutex`: its sync level.
fn mutex(kids: &mut Kids) -> Result<Object, FaultKind>
{
    Ok(Object::Mutex {
        sync: small(&next(kids)?) & 0xF,
    })
}

/// The low byte of an [`Op::Integer`] term; 0 for any other.
fn small(t: &Term) -> u8
{
    t.int().map_or(0, |v| u8::try_from(v & 0xFF).unwrap_or(0))
}

/// The name of an [`Op::NameRef`] term.
fn ref_name(t: Term) -> Option<Name>
{
    match (t.op, t.imm)
    {
        (Op::NameRef, Imm::Name(n)) => Some(n),
        _ => None,
    }
}

/// The value of a constant integer term, masked to the table's integer
/// width by `mask`.
fn constant(t: &Term, mask: u64) -> Result<u64, FaultKind>
{
    match (t.op, t.int())
    {
        (Op::Integer, Some(v)) => Ok(v & mask),
        (Op::Revision, _) => Ok(REVISION),
        _ => Err(FaultKind::NotConstant),
    }
}

/// Fold the data object `t` of a `Name` to its value. A buffer is as long as
/// the larger of its size and its initializer; a package holds as many
/// elements as its count, those its list omits uninitialized and those past
/// the count dropped. Integers are masked to the table's integer width by
/// `mask`.
fn fold(t: Term, mask: u64) -> Result<Data, FaultKind>
{
    let Term { op, imm, kids, .. } = t;
    match (op, imm)
    {
        (Op::Integer, Imm::Int(v)) => Ok(Data::Integer(v & mask)),
        (Op::Revision, _) => Ok(Data::Integer(REVISION)),
        (Op::String, Imm::Bytes(b)) => Ok(Data::String(b)),
        (Op::NameRef, Imm::Name(n)) => Ok(Data::Reference(n)),
        (Op::Buffer, Imm::Bytes(mut bytes)) =>
        {
            let size = kids
                .first()
                .ok_or(FaultKind::Truncated)
                .and_then(|k| constant(k, mask))?;
            let size = usize::try_from(size).map_err(|_| FaultKind::Bound)?;
            if size > MAX_BUFFER_BYTES || bytes.len() > MAX_BUFFER_BYTES
            {
                return Err(FaultKind::Bound);
            }
            if size > bytes.len()
            {
                bytes
                    .try_reserve_exact(size.saturating_sub(bytes.len()))
                    .map_err(|_| FaultKind::NoMemory)?;
                bytes.resize(size, 0);
            }
            Ok(Data::Buffer(bytes))
        }
        (Op::Package, Imm::Int(count)) => package(count, kids.into_iter(), mask),
        (Op::VarPackage, _) =>
        {
            let mut kids = kids.into_iter();
            let first = kids.next().ok_or(FaultKind::Truncated)?;
            package(constant(&first, mask)?, kids, mask)
        }
        _ => Err(FaultKind::NotConstant),
    }
}

/// Fold a package of `count` elements from the element terms `kids`.
fn package(count: u64, kids: impl Iterator<Item = Term>, mask: u64) -> Result<Data, FaultKind>
{
    let count = usize::try_from(count).map_err(|_| FaultKind::Bound)?;
    if count > MAX_PACKAGE_ELEMENTS
    {
        return Err(FaultKind::Bound);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(count)
        .map_err(|_| FaultKind::NoMemory)?;
    for k in kids.take(count)
    {
        out.push(fold(k, mask)?);
    }
    out.resize(count, Data::Uninitialized);
    Ok(Data::Package(out))
}
