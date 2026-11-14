// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/namespace.rs

//! The ACPI namespace: a tree of named objects rooted at `\`.
//!
//! Nodes live in an arena and link to their parent, first child and next
//! sibling; [`NodeId`] indexes it. The arena grows as nodes are created, so
//! a table's load adds nodes in proportion to its bytes: every object a
//! table declares takes at least its four-byte name segment. Every node has an [`Owner`]: the
//! predefined objects, the table whose load created it, or an evaluator's
//! method frame, whose objects [`Namespace::remove_owned`] deletes when the
//! method returns. A removed node's slot, and its id, are reused.
//!
//! Names resolve as ACPI 6.5 § 5.3 says: a name with a root or parent prefix,
//! or of more than one segment, is a path from the scope it starts at; a
//! relative name of one segment is looked up in the scope and then in each
//! enclosing scope up to the root.
//!
//! A method's code is kept apart from the nodes, in a store indexed by
//! [`CodeId`], and the expressions an object definition keeps (a region's
//! offset and length, a bank value, a connection) in one indexed by
//! [`ExprId`], so an evaluator can borrow the code it runs and change the
//! nodes it acts on at the same time.

use alloc::vec::Vec;

use crate::encoding::{NameStr, Seg};
use crate::parse::Parser;
use crate::term::{Name, Term};
use crate::{Fault, FaultKind, push};

/// A node of the namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId
{
    /// The root, `\`.
    pub const ROOT: Self = Self(0);

    fn index(self) -> usize
    {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

/// A table loaded into the namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableId(u16);

/// A method's parsed code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodeId(u32);

/// An expression an object definition keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExprId(u32);

/// Who created a node, and so when it is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner
{
    /// The predefined objects; never removed.
    Predefined,
    /// A table's load.
    Table(TableId),
    /// An evaluator's method frame, by the evaluator's own numbering.
    Frame(u32),
}

/// The data of a `Name` a table declares, its value folded at load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data
{
    /// An integer, already truncated to 32 bits in a table of revision 1.
    Integer(u64),
    /// A string's characters.
    String(Vec<u8>),
    /// A buffer.
    Buffer(Vec<u8>),
    /// A package.
    Package(Vec<Data>),
    /// A name in a package, unresolved: it is resolved from the scope of the
    /// `Name` that holds the package.
    Reference(Name),
    /// A package element the package's count declares but its list omits.
    Uninitialized,
}

/// A method the interpreter itself implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Native
{
    /// `\_OSI`.
    Osi,
}

/// Where a method's code is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body
{
    /// AML: the term list's span in a table.
    Aml
    {
        /// The table.
        table: TableId,
        /// The offset of its first byte.
        start: u32,
        /// The offset one past its last byte.
        end: u32,
    },
    /// Implemented by the interpreter.
    Native(Native),
}

/// A control method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Method
{
    /// The argument count, 0 to 7.
    pub args: u8,
    /// `MethodFlags` as encoded: bits 2:0 the argument count, bit 3 set when
    /// serialized, bits 7:4 the sync level.
    pub flags: u8,
    /// Its code.
    pub body: Body,
    /// The parsed code, once [`Namespace::method_code`] has parsed it.
    pub code: Option<CodeId>,
}

/// An operation region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region
{
    /// `RegionSpace`.
    pub space: u8,
    /// The offset expression.
    pub offset: ExprId,
    /// The length expression.
    pub length: ExprId,
}

/// What a field unit is a part of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind
{
    /// A `Field` of an operation region.
    Region(NodeId),
    /// An `IndexField`: its index and data field units.
    Index
    {
        /// The index field unit.
        index: NodeId,
        /// The data field unit.
        data: NodeId,
    },
    /// A `BankField`: its region, its bank field unit, and the bank value.
    Bank
    {
        /// The operation region.
        region: NodeId,
        /// The bank selection field unit.
        bank: NodeId,
        /// The bank value expression.
        value: ExprId,
    },
}

/// An `AccessAs` element of a field list, which applies to the field units
/// after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessAs
{
    /// `AccessType`: access width (bits 3:0) and attribute kind (bits 7:6).
    pub kind: u8,
    /// `AccessAttrib`.
    pub attrib: u8,
    /// `AccessLength` of an extended `AccessAs`; 0 for the plain form.
    pub len: u8,
}

/// A field unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldUnit
{
    /// What it is a part of.
    pub kind: FieldKind,
    /// The field list's `FieldFlags`: access type (bits 3:0), lock rule
    /// (bit 4), update rule (bits 6:5).
    pub flags: u8,
    /// The last `AccessAs` before the unit, which overrides the access type
    /// of `flags`.
    pub access_as: Option<AccessAs>,
    /// Its first bit.
    pub bit_offset: u32,
    /// Its width in bits.
    pub bit_len: u32,
    /// The last `Connection` before it.
    pub connection: Option<ExprId>,
}

/// The object a node holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object
{
    /// A scope (`Scope`, and the predefined `\_GPE`, `\_PR_`, `\_SI_`,
    /// `\_TZ_`).
    Scope,
    /// A device (and `\_SB_`).
    Device,
    /// A processor (`Processor`, deprecated).
    Processor
    {
        /// The processor ID.
        id: u8,
        /// The `PBLK` address.
        pblk: u32,
        /// The `PBLK` length.
        pblk_len: u8,
    },
    /// A power resource.
    PowerResource
    {
        /// The deepest system sleep level it supports.
        level: u8,
        /// Its resource order.
        order: u16,
    },
    /// A thermal zone.
    ThermalZone,
    /// A named data object.
    Data(Data),
    /// A control method.
    Method(Method),
    /// A mutex.
    Mutex
    {
        /// Its sync level, 0 to 15.
        sync: u8,
    },
    /// An event.
    Event,
    /// An operation region.
    Region(Region),
    /// A field unit.
    Field(FieldUnit),
    /// A data table region: signature, OEM ID, OEM table ID.
    DataRegion([ExprId; 3]),
    /// An alias of another node.
    Alias(NodeId),
    /// A name an `External` declares and no table has yet defined.
    External
    {
        /// `ObjectType`.
        kind: u8,
        /// The argument count, for a method.
        args: u8,
    },
}

/// The `ObjectType` of a method, as `External` gives it.
const EXTERNAL_METHOD: u8 = 8;

/// The longest alias chain followed.
const MAX_ALIAS_CHAIN: usize = 8;

#[derive(Clone, Debug)]
struct Node
{
    name: Seg,
    parent: NodeId,
    child: Option<NodeId>,
    sibling: Option<NodeId>,
    owner: Owner,
    object: Object,
    live: bool,
}

/// A table's bytes and its integer width.
#[derive(Clone, Debug)]
pub(crate) struct Table
{
    pub(crate) bytes: Vec<u8>,
    pub(crate) int64: bool,
}

/// A term of a table's top level, or of an object body in it, that is
/// neither an object definition the load creates nor a `Name`: code an
/// evaluator runs once, in table order, after the load.
#[derive(Clone, Debug)]
pub struct ModuleTerm
{
    /// The table it is in.
    pub table: TableId,
    /// The scope it runs in.
    pub scope: NodeId,
    /// The term.
    pub term: Term,
}

/// The namespace.
#[derive(Debug)]
pub struct Namespace
{
    nodes: Vec<Node>,
    free: Vec<u32>,
    live: usize,
    pub(crate) tables: Vec<Table>,
    codes: Vec<Vec<Term>>,
    exprs: Vec<Term>,
    pub(crate) module: Vec<ModuleTerm>,
}

impl Namespace
{
    /// A namespace holding the predefined objects: `\`, `\_GPE`, `\_PR_`,
    /// `\_SB_`, `\_SI_`, `\_TZ_`, the global lock mutex `\_GL_`, the native
    /// method `\_OSI` (one argument), and the data objects `\_OS_` and
    /// `\_REV`.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NoMemory`] when an allocation fails.
    pub fn new() -> Result<Self, FaultKind>
    {
        let mut ns = Self {
            nodes: Vec::new(),
            free: Vec::new(),
            live: 0,
            tables: Vec::new(),
            codes: Vec::new(),
            exprs: Vec::new(),
            module: Vec::new(),
        };
        push(
            &mut ns.nodes,
            Node {
                name: *b"\\___",
                parent: NodeId::ROOT,
                child: None,
                sibling: None,
                owner: Owner::Predefined,
                object: Object::Scope,
                live: true,
            },
        )?;
        ns.live = 1;
        let mut os = Vec::new();
        os.try_reserve(20).map_err(|_| FaultKind::NoMemory)?;
        os.extend_from_slice(b"Microsoft Windows NT");
        let predefined = [
            (*b"_GPE", Object::Scope),
            (*b"_PR_", Object::Scope),
            (*b"_SB_", Object::Device),
            (*b"_SI_", Object::Scope),
            (*b"_TZ_", Object::Scope),
            (*b"_GL_", Object::Mutex { sync: 0 }),
            (
                *b"_OSI",
                Object::Method(Method {
                    args: 1,
                    flags: 1,
                    body: Body::Native(Native::Osi),
                    code: None,
                }),
            ),
            (*b"_OS_", Object::Data(Data::String(os))),
            (*b"_REV", Object::Data(Data::Integer(2))),
        ];
        for (name, object) in predefined
        {
            ns.add_child(NodeId::ROOT, name, object, Owner::Predefined)?;
        }
        Ok(ns)
    }

    // ── Nodes ─────────────────────────────────────────────────────────

    fn node(&self, id: NodeId) -> Option<&Node>
    {
        self.nodes.get(id.index()).filter(|n| n.live)
    }

    fn node_mut(&mut self, id: NodeId) -> Option<&mut Node>
    {
        self.nodes.get_mut(id.index()).filter(|n| n.live)
    }

    /// The number of live nodes, the root included.
    #[must_use]
    pub const fn len(&self) -> usize
    {
        self.live
    }

    /// Whether the namespace holds only the root; never true of one
    /// [`Namespace::new`] built.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.live <= 1
    }

    /// The object `id` holds.
    #[must_use]
    pub fn object(&self, id: NodeId) -> Option<&Object>
    {
        self.node(id).map(|n| &n.object)
    }

    /// The object `id` holds, to change.
    pub fn object_mut(&mut self, id: NodeId) -> Option<&mut Object>
    {
        self.node_mut(id).map(|n| &mut n.object)
    }

    /// The name segment of `id`.
    #[must_use]
    pub fn name(&self, id: NodeId) -> Option<Seg>
    {
        self.node(id).map(|n| n.name)
    }

    /// The parent of `id`; `None` for the root.
    #[must_use]
    pub fn parent(&self, id: NodeId) -> Option<NodeId>
    {
        if id == NodeId::ROOT
        {
            return None;
        }
        self.node(id).map(|n| n.parent)
    }

    /// The owner of `id`.
    #[must_use]
    pub fn owner(&self, id: NodeId) -> Option<Owner>
    {
        self.node(id).map(|n| n.owner)
    }

    /// The children of `id`, most recently added first.
    pub fn children(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_
    {
        let mut next = self.node(id).and_then(|n| n.child);
        core::iter::from_fn(move || {
            let cur = next?;
            next = self.node(cur).and_then(|n| n.sibling);
            Some(cur)
        })
    }

    /// The child of `parent` named `seg`.
    #[must_use]
    pub fn child(&self, parent: NodeId, seg: Seg) -> Option<NodeId>
    {
        self.children(parent)
            .find(|c| self.node(*c).is_some_and(|n| n.name == seg))
    }

    /// Every live node, in arena order: the root first, then the
    /// predefined objects, then each table's objects in load order, except
    /// where a reused slot breaks that order.
    pub fn nodes(&self) -> impl Iterator<Item = NodeId> + '_
    {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.live)
            .filter_map(|(i, _)| u32::try_from(i).ok().map(NodeId))
    }

    /// The absolute path of `id`, root first, the root itself excluded.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NoMemory`] when an allocation fails, and
    /// [`FaultKind::NotFound`] when `id` is not live.
    pub fn path(&self, id: NodeId) -> Result<Vec<Seg>, FaultKind>
    {
        let mut out = Vec::new();
        let mut cur = id;
        while cur != NodeId::ROOT
        {
            let n = self.node(cur).ok_or(FaultKind::NotFound)?;
            push(&mut out, n.name)?;
            cur = n.parent;
        }
        out.reverse();
        Ok(out)
    }

    /// Add a node named `name` under `parent`, holding `object`.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NoMemory`] when an allocation fails,
    /// [`FaultKind::Bound`] when the arena holds as many nodes as a
    /// [`NodeId`] can name, [`FaultKind::NotFound`] when `parent` is not
    /// live, and [`FaultKind::Exists`] when `parent` has a child of that
    /// name.
    pub fn add_child(
        &mut self,
        parent: NodeId,
        name: Seg,
        object: Object,
        owner: Owner,
    ) -> Result<NodeId, FaultKind>
    {
        if self.node(parent).is_none()
        {
            return Err(FaultKind::NotFound);
        }
        if self.child(parent, name).is_some()
        {
            return Err(FaultKind::Exists);
        }
        let sibling = self.node(parent).and_then(|n| n.child);
        let node = Node {
            name,
            parent,
            child: None,
            sibling,
            owner,
            object,
            live: true,
        };
        let id = if let Some(slot) = self.free.pop()
        {
            let id = NodeId(slot);
            let Some(n) = self.nodes.get_mut(id.index())
            else
            {
                return Err(FaultKind::NotFound);
            };
            *n = node;
            id
        }
        else
        {
            let id = NodeId(u32::try_from(self.nodes.len()).map_err(|_| FaultKind::Bound)?);
            push(&mut self.nodes, node)?;
            id
        };
        if let Some(p) = self.node_mut(parent)
        {
            p.child = Some(id);
        }
        self.live = self.live.saturating_add(1);
        Ok(id)
    }

    /// Remove every node `owner` created, with its subtree.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NoMemory`] when the free list cannot grow; the nodes
    /// removed before the failure stay removed.
    pub fn remove_owned(&mut self, owner: Owner) -> Result<(), FaultKind>
    {
        if owner == Owner::Predefined
        {
            return Ok(());
        }
        let mut i = 0;
        while i < self.nodes.len()
        {
            if let Some(n) = self.nodes.get(i)
                && n.live
                && n.owner == owner
            {
                let id = NodeId(u32::try_from(i).map_err(|_| FaultKind::Bound)?);
                self.remove(id)?;
            }
            i = i.saturating_add(1);
        }
        Ok(())
    }

    /// Unlink `id` from its parent and free it and its subtree.
    fn remove(&mut self, id: NodeId) -> Result<(), FaultKind>
    {
        if id == NodeId::ROOT
        {
            return Ok(());
        }
        let Some(n) = self.node(id)
        else
        {
            return Ok(());
        };
        let (parent, sibling) = (n.parent, n.sibling);
        if self.node(parent).and_then(|p| p.child) == Some(id)
        {
            if let Some(p) = self.node_mut(parent)
            {
                p.child = sibling;
            }
        }
        else
        {
            let prev = self
                .children(parent)
                .find(|c| self.node(*c).and_then(|n| n.sibling) == Some(id));
            if let Some(prev) = prev.and_then(|p| self.node_mut(p))
            {
                prev.sibling = sibling;
            }
        }
        // Free the subtree with an explicit stack of first children: each
        // freed node's children are pushed before it is marked dead.
        let mut stack = Vec::new();
        push(&mut stack, id)?;
        while let Some(cur) = stack.pop()
        {
            let kids: Option<NodeId> = self.node(cur).and_then(|n| n.child);
            let mut next = kids;
            while let Some(k) = next
            {
                next = self.node(k).and_then(|n| n.sibling);
                push(&mut stack, k)?;
            }
            if let Some(n) = self.node_mut(cur)
            {
                n.live = false;
                n.child = None;
                n.object = Object::Scope;
            }
            push(&mut self.free, cur.0)?;
            self.live = self.live.saturating_sub(1);
        }
        Ok(())
    }

    // ── Names ─────────────────────────────────────────────────────────

    /// The node `up` levels above `scope`; `None` past the root.
    fn ancestor(&self, scope: NodeId, up: usize) -> Option<NodeId>
    {
        let mut cur = scope;
        for _ in 0..up
        {
            cur = self.parent(cur)?;
        }
        Some(cur)
    }

    /// Resolve a name given as its parts from `scope`, by the search rules
    /// when `search`, else as a path.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`root` is the name's root prefix, data; `search` selects the lookup rule"
    )]
    fn resolve_parts(
        &self,
        scope: NodeId,
        root: bool,
        up: usize,
        segs: impl Iterator<Item = Seg> + Clone,
        search: bool,
    ) -> Option<NodeId>
    {
        let start = if root
        {
            NodeId::ROOT
        }
        else
        {
            self.ancestor(scope, up)?
        };
        let mut probe = segs.clone();
        let first = probe.next();
        if search
            && !root
            && up == 0
            && probe.next().is_none()
            && let Some(seg) = first
        {
            let mut cur = Some(start);
            while let Some(s) = cur
            {
                if let Some(found) = self.child(s, seg)
                {
                    return Some(found);
                }
                cur = self.parent(s);
            }
            return None;
        }
        segs.into_iter()
            .try_fold(start, |node, seg| self.child(node, seg))
    }

    /// Resolve `name` from `scope` by the search rules.
    #[must_use]
    pub fn resolve(&self, scope: NodeId, name: &Name) -> Option<NodeId>
    {
        self.resolve_parts(
            scope,
            name.root,
            usize::from(name.up),
            name.segs.iter().copied(),
            true,
        )
    }

    /// Resolve the encoded `name` from `scope` by the search rules.
    #[must_use]
    pub fn resolve_str(&self, scope: NodeId, name: &NameStr<'_>) -> Option<NodeId>
    {
        self.resolve_parts(scope, name.root, name.up, name.segments(), true)
    }

    /// The node the encoded `name` declares from `scope`: the name as a path,
    /// with no search, as a definition places it.
    #[must_use]
    pub fn declared(&self, scope: NodeId, name: &NameStr<'_>) -> Option<NodeId>
    {
        self.resolve_parts(scope, name.root, name.up, name.segments(), false)
    }

    /// The node an absolute path names: `\` then dot-separated segments,
    /// each padded with `_` to four characters (`\_SB.PCI0`).
    #[must_use]
    pub fn find(&self, path: &str) -> Option<NodeId>
    {
        let rest = path.strip_prefix('\\')?;
        if rest.is_empty()
        {
            return Some(NodeId::ROOT);
        }
        rest.split('.').try_fold(NodeId::ROOT, |node, part| {
            let bytes = part.as_bytes();
            if bytes.is_empty() || bytes.len() > 4
            {
                return None;
            }
            let mut seg = *b"____";
            seg.get_mut(..bytes.len())?.copy_from_slice(bytes);
            self.child(node, seg)
        })
    }

    /// Follow `id` through aliases to the object it stands for.
    #[must_use]
    pub fn follow(&self, id: NodeId) -> Option<NodeId>
    {
        let mut cur = id;
        for _ in 0..MAX_ALIAS_CHAIN
        {
            let Object::Alias(target) = self.object(cur)?
            else
            {
                return Some(cur);
            };
            cur = *target;
        }
        None
    }

    /// The argument count of the method `name` names from `scope`, when it
    /// names a method or an `External` method; `None` when it names
    /// anything else or nothing.
    #[must_use]
    pub fn method_args(&self, scope: NodeId, name: &NameStr<'_>) -> Option<u8>
    {
        let id = self.follow(self.resolve_str(scope, name)?)?;
        let object = self.object(id)?;
        if let Object::Method(m) = object
        {
            return Some(m.args);
        }
        if let Object::External {
            kind: EXTERNAL_METHOD,
            args,
        } = object
        {
            return Some(*args);
        }
        None
    }

    /// Create the node `name` declares from `scope`, holding `object`. Every
    /// segment but the last must resolve; the last is created under it. A
    /// definition replaces an `External` of the same name.
    ///
    /// # Errors
    ///
    /// [`FaultKind::BadName`] for a name of no segment,
    /// [`FaultKind::NotFound`] when the parent does not resolve,
    /// [`FaultKind::Exists`] for a name already defined, or for an
    /// `External` of a name that already exists, which changes nothing, and
    /// the faults of [`Namespace::add_child`].
    pub fn create(
        &mut self,
        scope: NodeId,
        name: &Name,
        object: Object,
        owner: Owner,
    ) -> Result<NodeId, FaultKind>
    {
        let last = *name.segs.last().ok_or(FaultKind::BadName)?;
        let start = if name.root
        {
            NodeId::ROOT
        }
        else
        {
            self.ancestor(scope, usize::from(name.up))
                .ok_or(FaultKind::NotFound)?
        };
        let parents = name.segs.len().saturating_sub(1);
        let parent = name
            .segs
            .iter()
            .copied()
            .take(parents)
            .try_fold(start, |node, seg| self.child(node, seg))
            .ok_or(FaultKind::NotFound)?;
        if let Some(existing) = self.child(parent, last)
        {
            let placeholder = matches!(self.object(existing), Some(Object::External { .. }));
            if !placeholder || matches!(object, Object::External { .. })
            {
                return Err(FaultKind::Exists);
            }
            if let Some(n) = self.node_mut(existing)
            {
                n.object = object;
                n.owner = owner;
            }
            return Ok(existing);
        }
        self.add_child(parent, last, object, owner)
    }

    // ── Code ──────────────────────────────────────────────────────────

    /// The bytes of `table`.
    #[must_use]
    pub fn table_bytes(&self, table: TableId) -> Option<&[u8]>
    {
        self.tables
            .get(usize::from(table.0))
            .map(|t| t.bytes.as_slice())
    }

    /// Whether `table` uses 64-bit integers (its revision is 2 or more).
    #[must_use]
    pub fn table_int64(&self, table: TableId) -> Option<bool>
    {
        self.tables.get(usize::from(table.0)).map(|t| t.int64)
    }

    /// The tables loaded, in load order.
    pub fn tables(&self) -> impl Iterator<Item = TableId> + '_
    {
        (0..self.tables.len()).filter_map(|i| u16::try_from(i).ok().map(TableId))
    }

    /// The id the next table loaded gets.
    pub(crate) fn next_table(&self) -> Result<TableId, FaultKind>
    {
        u16::try_from(self.tables.len())
            .map(TableId)
            .map_err(|_| FaultKind::Bound)
    }

    /// Keep `term` and return its id.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NoMemory`] or [`FaultKind::Bound`] when it cannot be kept.
    pub fn add_expr(&mut self, term: Term) -> Result<ExprId, FaultKind>
    {
        let id = ExprId(u32::try_from(self.exprs.len()).map_err(|_| FaultKind::Bound)?);
        push(&mut self.exprs, term)?;
        Ok(id)
    }

    /// The expression `id`.
    #[must_use]
    pub fn expr(&self, id: ExprId) -> Option<&Term>
    {
        self.exprs.get(usize::try_from(id.0).ok()?)
    }

    /// The parsed code `id`.
    #[must_use]
    pub fn code(&self, id: CodeId) -> Option<&[Term]>
    {
        self.codes
            .get(usize::try_from(id.0).ok()?)
            .map(Vec::as_slice)
    }

    /// The code of the method `id`, parsed on the first call and kept.
    ///
    /// The parse resolves each name's argument count in the namespace as it
    /// is at the call, so a method is parsed after every table that defines
    /// a method it calls has loaded.
    ///
    /// # Errors
    ///
    /// The parse's [`Fault`], or one of [`FaultKind::NotFound`] when `id`
    /// is not an AML method. A fault anywhere in the body is the method's,
    /// and the method keeps no code: no part of a faulting body is kept.
    pub fn method_code(&mut self, id: NodeId) -> Result<CodeId, Fault>
    {
        let not_found = Fault::at(FaultKind::NotFound, 0);
        let Some(Object::Method(m)) = self.object(id)
        else
        {
            return Err(not_found);
        };
        if let Some(code) = m.code
        {
            return Ok(code);
        }
        let Body::Aml { table, start, end } = m.body
        else
        {
            return Err(not_found);
        };
        let bytes = self.table_bytes(table).ok_or(not_found)?;
        let start = usize::try_from(start).map_err(|_| not_found)?;
        let end = usize::try_from(end).map_err(|_| not_found)?;
        let terms = Parser::new(self, bytes, start, end, id).term_list()?;
        let code = CodeId(
            u32::try_from(self.codes.len()).map_err(|_| Fault::at(FaultKind::Bound, start))?,
        );
        push(&mut self.codes, terms).map_err(|k| Fault::at(k, start))?;
        if let Some(Object::Method(m)) = self.object_mut(id)
        {
            m.code = Some(code);
        }
        Ok(code)
    }

    /// The module-level terms of every table loaded, in load order.
    #[must_use]
    pub fn module_terms(&self) -> &[ModuleTerm]
    {
        &self.module
    }
}
