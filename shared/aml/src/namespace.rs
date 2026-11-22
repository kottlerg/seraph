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
//! method returns. A removed node's slot, and its id, are reused. A node a
//! table created is never removed: a method frame that defines a name a table
//! declared `External` holds that node only until it returns, when the
//! `External` and its owner are given back, and a frame's nodes hold only
//! nodes of that frame or of frames it called, since no table loads while a
//! method runs.
//!
//! Names resolve as ACPI 6.5 § 5.3 says: a name with a root or parent prefix,
//! or of more than one segment, is a path from the scope it starts at; a
//! relative name of one segment is looked up in the scope and then in each
//! enclosing scope up to the root.
//!
//! A method's code is kept apart from the nodes, in a store indexed by
//! [`CodeId`], and the expressions an object definition keeps (a region's
//! offset and length, a bank value, a connection) in one indexed by
//! [`ExprId`]. An evaluator takes the code it runs out of its store and
//! puts it back when it is done, so it can change the nodes while it runs
//! the code; a method called again while its code is out is parsed anew.
//!
//! Each node slot counts its reuses ([`Namespace::generation`]), so a
//! reference that names a node with the generation it saw fails once the
//! node is removed, even when the slot holds another node, or once a frame's
//! object over an `External` has ended.

use alloc::vec::Vec;

use crate::encoding::{NameStr, Seg};
use crate::host::PciAddress;
use crate::parse::Parser;
use crate::term::{Name, Op, Term};
pub use crate::value::Data;
use crate::value::Ref;
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
    /// An evaluator's method frame, by its call depth: the frame's objects
    /// are removed when it returns, before a frame of the same depth runs.
    Frame(u32),
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

/// An operand of an object definition: an expression a table load keeps,
/// which an evaluator evaluates on first use, or its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand
{
    /// The expression, not yet evaluated.
    Expr(ExprId),
    /// The value.
    Value(u64),
}

/// An operation region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region
{
    /// `RegionSpace`.
    pub space: u8,
    /// The offset.
    pub offset: Operand,
    /// The length.
    pub length: Operand,
    /// The PCI function of a `PCI_Config` region, once an evaluator has
    /// found it.
    pub pci: Option<PciAddress>,
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
        /// The bank value.
        value: Operand,
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

/// A buffer field: bits of a buffer that `CreateField` and its kin name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferField
{
    /// The buffer.
    pub source: Ref,
    /// The first bit.
    pub bit_offset: u64,
    /// The width in bits.
    pub bit_len: u64,
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
    Event
    {
        /// The signals not yet waited for.
        pending: u32,
    },
    /// An operation region.
    Region(Region),
    /// A field unit.
    Field(FieldUnit),
    /// A buffer field.
    BufferField(BufferField),
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

/// A node whose `External` a method frame's definition replaced, and the
/// `External` to give back when the frame ends.
#[derive(Clone, Copy, Debug)]
struct Lent
{
    node: NodeId,
    frame: Owner,
    owner: Owner,
    kind: u8,
    args: u8,
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
    /// The scope its definition appeared in ([`Namespace::scope_of`]).
    scope: NodeId,
    child: Option<NodeId>,
    sibling: Option<NodeId>,
    owner: Owner,
    object: Object,
    live: bool,
    /// The number of times the slot has been freed or has had a frame's
    /// object over an `External` end.
    generation: u32,
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
    /// The nodes method frames hold over an `External`.
    lent: Vec<Lent>,
    /// Each method's code; `None` while an evaluator runs it.
    codes: Vec<Option<Vec<Term>>>,
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
            lent: Vec::new(),
            codes: Vec::new(),
            exprs: Vec::new(),
            module: Vec::new(),
        };
        push(
            &mut ns.nodes,
            Node {
                name: *b"\\___",
                parent: NodeId::ROOT,
                scope: NodeId::ROOT,
                child: None,
                sibling: None,
                owner: Owner::Predefined,
                object: Object::Scope,
                live: true,
                generation: 0,
            },
        )?;
        ns.live = 1;
        let mut os = Vec::new();
        os.try_reserve(20).map_err(|_| FaultKind::NoMemory)?;
        os.extend_from_slice(b"Microsoft Windows NT");
        // One call each: an array of the objects would hold them all on the
        // stack at once.
        for name in [*b"_GPE", *b"_PR_"]
        {
            ns.add_child(NodeId::ROOT, name, Object::Scope, Owner::Predefined)?;
        }
        ns.add_child(NodeId::ROOT, *b"_SB_", Object::Device, Owner::Predefined)?;
        for name in [*b"_SI_", *b"_TZ_"]
        {
            ns.add_child(NodeId::ROOT, name, Object::Scope, Owner::Predefined)?;
        }
        ns.add_child(
            NodeId::ROOT,
            *b"_GL_",
            Object::Mutex { sync: 0 },
            Owner::Predefined,
        )?;
        let osi = Object::Method(Method {
            args: 1,
            flags: 1,
            body: Body::Native(Native::Osi),
            code: None,
        });
        ns.add_child(NodeId::ROOT, *b"_OSI", osi, Owner::Predefined)?;
        let os = Object::Data(Data::String(os));
        ns.add_child(NodeId::ROOT, *b"_OS_", os, Owner::Predefined)?;
        let rev = Object::Data(Data::Integer(2));
        ns.add_child(NodeId::ROOT, *b"_REV", rev, Owner::Predefined)?;
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

    /// The generation of the live node `id`: the number of times its slot
    /// has been freed before, or has had a frame's object over an
    /// `External` end.
    #[must_use]
    pub fn generation(&self, id: NodeId) -> Option<u32>
    {
        self.node(id).map(|n| n.generation)
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

    /// The scope the definition of `id` appeared in, from which the names
    /// of its kept terms (a region's offset and length, a bank field's
    /// value) and of its package's elements resolve: its parent, but for a
    /// definition by a path, such as `Name (\_SB.PCI0.PRT0, ...)` in
    /// `Scope (\_SB)`, which is placed under the path's node.
    #[must_use]
    pub fn scope_of(&self, id: NodeId) -> Option<NodeId>
    {
        self.node(id).map(|n| n.scope)
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
        let mut node = Node {
            name,
            parent,
            scope: parent,
            child: None,
            sibling,
            owner,
            object,
            live: true,
            generation: 0,
        };
        let id = if let Some(slot) = self.free.pop()
        {
            let id = NodeId(slot);
            let Some(n) = self.nodes.get_mut(id.index())
            else
            {
                return Err(FaultKind::NotFound);
            };
            node.generation = n.generation;
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

    /// Remove every node `owner` created, with its subtree, and give back
    /// the `External` of each node `owner` holds over one; the number of
    /// nodes removed or given back.
    ///
    /// The nodes a frame holds over an `External` are given back first, so
    /// the nodes removed are those the frame created, whose subtrees hold
    /// only nodes of that frame or of frames it called, which have returned:
    /// no table's node is removed.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NoMemory`] when the free list cannot grow; the nodes
    /// removed before the failure stay removed, and each subtree not yet
    /// removed stays whole and linked.
    pub fn remove_owned(&mut self, owner: Owner) -> Result<usize, FaultKind>
    {
        if owner == Owner::Predefined
        {
            return Ok(0);
        }
        let given = self.give_back(owner);
        let before = self.live.saturating_add(given);
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
        Ok(before.saturating_sub(self.live))
    }

    /// Give back the `External` of each node `frame` holds over one, with
    /// its owner and a new generation, so that a reference to the frame's
    /// object fails; the number given back.
    fn give_back(&mut self, frame: Owner) -> usize
    {
        let mut given = 0usize;
        let mut i = 0;
        while let Some(l) = self.lent.get(i).copied()
        {
            if l.frame != frame
            {
                i = i.saturating_add(1);
                continue;
            }
            self.lent.swap_remove(i);
            if let Some(n) = self.node_mut(l.node)
            {
                n.object = Object::External {
                    kind: l.kind,
                    args: l.args,
                };
                n.owner = l.owner;
                n.generation = n.generation.wrapping_add(1);
                given = given.saturating_add(1);
            }
        }
        given
    }

    /// Unlink `id` from its parent and free it and its subtree. Every
    /// allocation comes before the first change, so a failed one leaves the
    /// subtree whole and linked, and the count of live nodes true.
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
        // The subtree, each node before its children, and room on the free
        // list for every node of it.
        let mut subtree = Vec::new();
        push(&mut subtree, id)?;
        let mut at = 0;
        while let Some(&cur) = subtree.get(at)
        {
            let mut next = self.node(cur).and_then(|n| n.child);
            while let Some(k) = next
            {
                next = self.node(k).and_then(|n| n.sibling);
                push(&mut subtree, k)?;
            }
            at = at.saturating_add(1);
        }
        self.free
            .try_reserve(subtree.len())
            .map_err(|_| FaultKind::NoMemory)?;
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
        for cur in subtree
        {
            if let Some(n) = self.node_mut(cur)
            {
                n.live = false;
                n.child = None;
                n.object = Object::Scope;
                n.generation = n.generation.wrapping_add(1);
            }
            // Within the room reserved above: no allocation.
            self.free.push(cur.0);
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
    /// definition replaces an `External` of the same name: a table's takes
    /// the node, and a method frame's holds it until
    /// [`Namespace::remove_owned`] gives the `External` back to its owner.
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
        let (parent, last) = self.parent_of(scope, name)?;
        if let Some(existing) = self.child(parent, last)
        {
            let Some(&Object::External { kind, args }) = self.object(existing)
            else
            {
                return Err(FaultKind::Exists);
            };
            if matches!(object, Object::External { .. })
            {
                return Err(FaultKind::Exists);
            }
            if let Owner::Frame(_) = owner
            {
                let held = self.owner(existing).ok_or(FaultKind::NotFound)?;
                push(
                    &mut self.lent,
                    Lent {
                        node: existing,
                        frame: owner,
                        owner: held,
                        kind,
                        args,
                    },
                )?;
            }
            if let Some(n) = self.node_mut(existing)
            {
                n.object = object;
                n.owner = owner;
                n.scope = scope;
            }
            return Ok(existing);
        }
        let id = self.add_child(parent, last, object, owner)?;
        if let Some(n) = self.node_mut(id)
        {
            n.scope = scope;
        }
        Ok(id)
    }

    /// Create the node `name` declares from `scope` as a placeholder that
    /// holds [`Data::Uninitialized`], for a table load to define later;
    /// [`FaultKind::Exists`] when the name exists in any form, and the
    /// other faults of [`Namespace::create`].
    pub(crate) fn declare(
        &mut self,
        scope: NodeId,
        name: &Name,
        owner: Owner,
    ) -> Result<NodeId, FaultKind>
    {
        let (parent, last) = self.parent_of(scope, name)?;
        if self.child(parent, last).is_some()
        {
            return Err(FaultKind::Exists);
        }
        let id = self.add_child(parent, last, Object::Data(Data::Uninitialized), owner)?;
        if let Some(n) = self.node_mut(id)
        {
            n.scope = scope;
        }
        Ok(id)
    }

    /// The placeholder [`Namespace::declare`] created for `name` from
    /// `scope` on behalf of `owner`, while it still holds
    /// [`Data::Uninitialized`].
    pub(crate) fn placeholder(&self, scope: NodeId, name: &Name, owner: Owner) -> Option<NodeId>
    {
        let (parent, last) = self.parent_of(scope, name).ok()?;
        let node = self.child(parent, last)?;
        let n = self.node(node)?;
        (n.owner == owner && n.object == Object::Data(Data::Uninitialized)).then_some(node)
    }

    /// The node under which `name`, declared from `scope`, is placed, and
    /// its last segment. Every segment but the last must resolve.
    fn parent_of(&self, scope: NodeId, name: &Name) -> Result<(NodeId, Seg), FaultKind>
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
        Ok((parent, last))
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

    /// Take the expression `id` out of its store, leaving a `Noop` until
    /// [`Namespace::put_expr`] returns it.
    pub(crate) fn take_expr(&mut self, id: ExprId) -> Option<Term>
    {
        let slot = self.exprs.get_mut(usize::try_from(id.0).ok()?)?;
        let noop = Term {
            op: Op::Noop,
            imm: crate::term::Imm::None,
            kids: Vec::new(),
            offset: slot.offset,
        };
        Some(core::mem::replace(slot, noop))
    }

    /// Return the expression [`Namespace::take_expr`] took.
    pub(crate) fn put_expr(&mut self, id: ExprId, term: Term)
    {
        if let Some(slot) = usize::try_from(id.0)
            .ok()
            .and_then(|i| self.exprs.get_mut(i))
        {
            *slot = term;
        }
    }

    /// The parsed code `id`; `None` while an evaluator runs it.
    #[must_use]
    pub fn code(&self, id: CodeId) -> Option<&[Term]>
    {
        self.codes.get(usize::try_from(id.0).ok()?)?.as_deref()
    }

    /// Take the parsed code `id` out of its store, until
    /// [`Namespace::put_code`] returns it; `None` while it is out.
    pub(crate) fn take_code(&mut self, id: CodeId) -> Option<Vec<Term>>
    {
        self.codes.get_mut(usize::try_from(id.0).ok()?)?.take()
    }

    /// Return the code [`Namespace::take_code`] took.
    pub(crate) fn put_code(&mut self, id: CodeId, code: Vec<Term>)
    {
        if let Some(slot) = usize::try_from(id.0)
            .ok()
            .and_then(|i| self.codes.get_mut(i))
        {
            *slot = Some(code);
        }
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
        push(&mut self.codes, Some(terms)).map_err(|k| Fault::at(k, start))?;
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
