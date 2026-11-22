// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/eval/place.rs

//! Targets and references: where a `Store` or `CopyObject` writes, how a
//! reference is read and written through, and the store rules of ACPI 6.5
//! § 19.3.5.
//!
//! A store to a named data object of type integer, string or buffer
//! converts the value to that type, a buffer keeping its length (the value
//! zero-extended or truncated); a store to a named object of any other data
//! type replaces it. A store to a local replaces it; a store to an argument
//! that holds a reference stores through the reference, and to any other
//! argument replaces it. A store to a field or a buffer field writes it.
//! `CopyObject` replaces without converting, writes a field, and may
//! replace a method.

use super::{Evaluator, at, bare, imm_int, imm_name, kid};
use crate::namespace::{NodeId, Object};
use crate::term::{Op, Term};
use crate::value::{self, Base, Data, Radix, Ref};
use crate::{Fault, FaultKind, MAX_VALUE_DEPTH};

/// How a value is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode
{
    /// `Store` and the result of an operator: convert to a named target's
    /// type, store through an argument's reference.
    Store,
    /// `CopyObject`: replace.
    Copy,
}

/// Where a target writes.
#[derive(Debug)]
pub(super) enum Place
{
    /// `NullName` or `Debug`: the value is discarded.
    Discard,
    /// A named object.
    Node(NodeId),
    /// A local of the running frame.
    Local(usize),
    /// An argument of the running frame.
    Arg(usize),
    /// The object a reference refers to.
    Ref(Ref),
}

/// The byte a value gives a store to an element of a buffer or a string: an
/// integer's low byte, a buffer's or string's first.
fn byte_of(v: &Data, w: value::IntWidth) -> Result<u8, FaultKind>
{
    match v
    {
        Data::String(b) | Data::Buffer(b) => Ok(b.first().copied().unwrap_or(0)),
        Data::Integer(_)
        | Data::Uninitialized
        | Data::Package(_)
        | Data::Name(_)
        | Data::Ref(_) => Ok(u8::try_from(value::integer(v, w)? & 0xFF).unwrap_or(0)),
    }
}

/// The element `path` selects in `d`, each index a package element.
fn navigate<'d>(d: &'d Data, path: &[u32]) -> Result<&'d Data, FaultKind>
{
    path.iter().try_fold(d, |cur, i| match cur
    {
        Data::Package(p) => p
            .get(usize::try_from(*i).unwrap_or(usize::MAX))
            .ok_or(FaultKind::Range),
        Data::Uninitialized
        | Data::Integer(_)
        | Data::String(_)
        | Data::Buffer(_)
        | Data::Name(_)
        | Data::Ref(_) => Err(FaultKind::Type),
    })
}

/// The element `path` selects in `d`, to change.
pub(super) fn navigate_mut<'d>(d: &'d mut Data, path: &[u32]) -> Result<&'d mut Data, FaultKind>
{
    path.iter().try_fold(d, |cur, i| match cur
    {
        Data::Package(p) => p
            .get_mut(usize::try_from(*i).unwrap_or(usize::MAX))
            .ok_or(FaultKind::Range),
        Data::Uninitialized
        | Data::Integer(_)
        | Data::String(_)
        | Data::Buffer(_)
        | Data::Name(_)
        | Data::Ref(_) => Err(FaultKind::Type),
    })
}

/// The element `i` of `container`: a package's element, or a buffer's or
/// string's byte as an integer.
fn element(container: &Data, i: u32) -> Result<Data, FaultKind>
{
    let i = usize::try_from(i).unwrap_or(usize::MAX);
    match container
    {
        Data::Package(p) => p.get(i).ok_or(FaultKind::Range)?.try_clone(),
        Data::Buffer(b) | Data::String(b) =>
        {
            Ok(Data::Integer(u64::from(*b.get(i).ok_or(FaultKind::Range)?)))
        }
        Data::Uninitialized => Err(FaultKind::Uninitialized),
        Data::Integer(_) | Data::Name(_) | Data::Ref(_) => Err(FaultKind::Type),
    }
}

/// The length an `Index` into `d` is checked against.
fn len_of(d: &Data) -> Result<u64, FaultKind>
{
    let n = match d
    {
        Data::Package(p) => p.len(),
        Data::Buffer(b) | Data::String(b) => b.len(),
        Data::Uninitialized => return Err(FaultKind::Uninitialized),
        Data::Integer(_) | Data::Name(_) | Data::Ref(_) => return Err(FaultKind::Type),
    };
    Ok(u64::try_from(n).unwrap_or(u64::MAX))
}

impl Evaluator<'_>
{
    /// The place the target or `SuperName` `t` names.
    pub(super) fn place(&mut self, t: &Term) -> Result<Place, Fault>
    {
        let index = || usize::try_from(imm_int(t)?).map_err(|_| at(t, FaultKind::BadOpcode));
        if matches!(t.op, Op::Null | Op::Debug)
        {
            return Ok(Place::Discard);
        }
        if t.op == Op::Local
        {
            return Ok(Place::Local(index()?));
        }
        if t.op == Op::Arg
        {
            return Ok(Place::Arg(index()?));
        }
        if t.op == Op::NameRef
        {
            let node = self
                .lookup(imm_name(t)?)
                .ok_or(at(t, FaultKind::NotFound))?;
            return Ok(Place::Node(node));
        }
        let v = if t.op == Op::DerefOf
        {
            self.eval(kid(t, 0)?)?
        }
        else
        {
            self.eval(t)?
        };
        match v
        {
            Data::Ref(r) if t.op == Op::DerefOf && !r.path.is_empty() =>
            {
                self.element_place(r).map_err(|f| at(t, f.kind))
            }
            Data::Ref(r) => Ok(Place::Ref(r)),
            Data::String(_) if t.op == Op::DerefOf =>
            {
                let Data::Ref(r) = self.string_ref(&v).map_err(|f| at(t, f.kind))?
                else
                {
                    return Err(at(t, FaultKind::Type));
                };
                Ok(Place::Ref(r))
            }
            Data::Uninitialized
            | Data::Integer(_)
            | Data::String(_)
            | Data::Buffer(_)
            | Data::Package(_)
            | Data::Name(_) => Err(at(t, FaultKind::Type)),
        }
    }

    /// The place `DerefOf` of the element reference `r` names: the object
    /// the element refers to when it is a reference or a name, else the
    /// element itself, in place.
    fn element_place(&mut self, r: Ref) -> Result<Place, Fault>
    {
        let Some((last, prefix)) = r.path.split_last()
        else
        {
            return Ok(Place::Ref(r));
        };
        let i = usize::try_from(*last).unwrap_or(usize::MAX);
        let names = match navigate(self.root(&r).map_err(bare)?, prefix).map_err(bare)?
        {
            Data::Package(p) => matches!(p.get(i), Some(Data::Ref(_) | Data::Name(_))),
            Data::Uninitialized
            | Data::Integer(_)
            | Data::String(_)
            | Data::Buffer(_)
            | Data::Name(_)
            | Data::Ref(_) => false,
        };
        if !names
        {
            return Ok(Place::Ref(r));
        }
        match self.read_ref(&r)?
        {
            Data::Ref(inner) => Ok(Place::Ref(inner)),
            // A name that resolves to nothing.
            Data::Uninitialized
            | Data::Integer(_)
            | Data::String(_)
            | Data::Buffer(_)
            | Data::Package(_)
            | Data::Name(_) => Err(bare(FaultKind::NotFound)),
        }
    }

    /// A reference to the object a string names from the running scope.
    fn string_ref(&self, v: &Data) -> Result<Data, Fault>
    {
        let Data::String(s) = v
        else
        {
            return Err(bare(FaultKind::Type));
        };
        let name = super::expr::name_of_text(s).map_err(bare)?;
        let node = self.lookup(&name).ok_or(bare(FaultKind::NotFound))?;
        Ok(Data::Ref(self.node_ref(node)?))
    }

    /// The value at `place`.
    pub(super) fn read_place(&mut self, place: &Place) -> Result<Data, Fault>
    {
        match place
        {
            Place::Discard => Err(bare(FaultKind::Type)),
            Place::Node(n) => self.node_value(*n),
            Place::Local(i) | Place::Arg(i) =>
            {
                let frame = self.frame().map_err(bare)?;
                let slot = if matches!(place, Place::Local(_))
                {
                    frame.locals.get(*i)
                }
                else
                {
                    frame.args.get(*i)
                };
                let v = slot
                    .ok_or(bare(FaultKind::BadOpcode))?
                    .try_clone()
                    .map_err(bare)?;
                match v
                {
                    Data::Ref(r) if matches!(place, Place::Arg(_)) => self.read_ref(&r),
                    Data::Uninitialized
                    | Data::Integer(_)
                    | Data::String(_)
                    | Data::Buffer(_)
                    | Data::Package(_)
                    | Data::Name(_)
                    | Data::Ref(_) => Ok(v),
                }
            }
            Place::Ref(r) => self.read_ref(r),
        }
    }

    /// Store `v` at `place` as `mode` says.
    pub(super) fn store(&mut self, place: Place, v: Data, mode: Mode) -> Result<(), Fault>
    {
        match place
        {
            Place::Discard => Ok(()),
            Place::Node(n) => self.store_node(n, v, mode),
            Place::Local(i) =>
            {
                let slot = self.frame_mut().map_err(bare)?.locals.get_mut(i);
                *slot.ok_or(bare(FaultKind::BadOpcode))? = v;
                Ok(())
            }
            Place::Arg(i) =>
            {
                let frame = self.frame_mut().map_err(bare)?;
                let slot = frame.args.get_mut(i).ok_or(bare(FaultKind::BadOpcode))?;
                if mode == Mode::Store
                    && let Data::Ref(r) = slot
                {
                    let r = r.try_clone().map_err(bare)?;
                    return self.write_ref(&r, v, mode);
                }
                *slot = v;
                Ok(())
            }
            Place::Ref(r) => self.write_ref(&r, v, mode),
        }
    }

    /// Store `v` to the named object `node`.
    fn store_node(&mut self, node: NodeId, v: Data, mode: Mode) -> Result<(), Fault>
    {
        let w = self.width();
        let object = self.ns.object(node).ok_or(bare(FaultKind::NotFound))?;
        let new = match (object, mode)
        {
            (Object::Field(_), _) => return self.write_field(node, v),
            (Object::BufferField(_), _) => return self.write_buffer_field(node, v),
            (Object::Data(_) | Object::Method(_), Mode::Copy) => v,
            (Object::Data(cur), Mode::Store) => match cur
            {
                Data::Integer(_) =>
                {
                    let v = self.computational(v)?;
                    Data::Integer(value::integer(&v, w).map_err(bare)?)
                }
                Data::String(_) =>
                {
                    let v = self.computational(v)?;
                    Data::String(value::string(&v, w, Radix::Implicit).map_err(bare)?)
                }
                Data::Buffer(b) =>
                {
                    let len = b.len();
                    let v = self.computational(v)?;
                    let mut bytes = value::buffer(&v, w).map_err(bare)?;
                    bytes.truncate(len);
                    bytes
                        .try_reserve(len.saturating_sub(bytes.len()))
                        .map_err(|_| bare(FaultKind::NoMemory))?;
                    bytes.resize(len, 0);
                    Data::Buffer(bytes)
                }
                Data::Uninitialized | Data::Package(_) | Data::Name(_) | Data::Ref(_) => v,
            },
            (
                Object::Method(_)
                | Object::Scope
                | Object::Device
                | Object::Processor { .. }
                | Object::PowerResource { .. }
                | Object::ThermalZone
                | Object::Mutex { .. }
                | Object::Event { .. }
                | Object::Region(_)
                | Object::DataRegion(_)
                | Object::Alias(_)
                | Object::External { .. },
                _,
            ) => return Err(bare(FaultKind::Type)),
        };
        let slot = self.ns.object_mut(node).ok_or(bare(FaultKind::NotFound))?;
        *slot = Object::Data(new);
        Ok(())
    }

    // ── References ────────────────────────────────────────────────────

    /// A reference to the object the operand `t` of `RefOf` or `CondRefOf`
    /// names.
    pub(super) fn reference(&mut self, t: &Term) -> Result<Ref, Fault>
    {
        let serial = self.serial();
        let index = || u8::try_from(imm_int(t)?).map_err(|_| at(t, FaultKind::BadOpcode));
        if t.op == Op::NameRef
        {
            let node = self
                .lookup(imm_name(t)?)
                .ok_or(at(t, FaultKind::NotFound))?;
            return self.node_ref(node);
        }
        if matches!(t.op, Op::Local | Op::Arg)
        {
            let index = index()?;
            let base = if t.op == Op::Local
            {
                Base::Local {
                    frame: serial,
                    index,
                }
            }
            else
            {
                Base::Arg {
                    frame: serial,
                    index,
                }
            };
            return Ok(Ref {
                base,
                path: alloc::vec::Vec::new(),
            });
        }
        match self.eval(t)?
        {
            Data::Ref(r) => Ok(r),
            Data::Uninitialized
            | Data::Integer(_)
            | Data::String(_)
            | Data::Buffer(_)
            | Data::Package(_)
            | Data::Name(_) => Err(at(t, FaultKind::Type)),
        }
    }

    /// A reference to the object the source operand `t` of `Index` or of a
    /// buffer field holds: a named data object, a local or an argument (or
    /// the reference it holds), or a temporary holding an expression's
    /// value.
    pub(super) fn source_ref(&mut self, t: &Term) -> Result<Ref, Fault>
    {
        let serial = self.serial();
        let slot_ref = |ev: &Self, base: Base, local: bool, i: usize| -> Result<Ref, Fault> {
            let frame = ev.frame().map_err(bare)?;
            let slot = if local
            {
                frame.locals.get(i)
            }
            else
            {
                frame.args.get(i)
            };
            match slot.ok_or(at(t, FaultKind::BadOpcode))?
            {
                Data::Ref(r) => r.try_clone().map_err(bare),
                Data::Uninitialized
                | Data::Integer(_)
                | Data::String(_)
                | Data::Buffer(_)
                | Data::Package(_)
                | Data::Name(_) => Ok(Ref {
                    base,
                    path: alloc::vec::Vec::new(),
                }),
            }
        };
        if t.op == Op::NameRef
        {
            let node = self
                .lookup(imm_name(t)?)
                .ok_or(at(t, FaultKind::NotFound))?;
            if let Some(Object::Data(Data::Ref(r))) = self.ns.object(node)
            {
                return r.try_clone().map_err(bare);
            }
            if let Some(Object::Data(_)) = self.ns.object(node)
            {
                return self.node_ref(node);
            }
        }
        if matches!(t.op, Op::Local | Op::Arg)
        {
            let i = imm_int(t)?;
            let index = u8::try_from(i).map_err(|_| at(t, FaultKind::BadOpcode))?;
            let i = usize::from(index);
            return if t.op == Op::Local
            {
                slot_ref(
                    self,
                    Base::Local {
                        frame: serial,
                        index,
                    },
                    true,
                    i,
                )
            }
            else
            {
                slot_ref(
                    self,
                    Base::Arg {
                        frame: serial,
                        index,
                    },
                    false,
                    i,
                )
            };
        }
        // The object a DerefOf refers to, in place: an element of an
        // element is the original's.
        if t.op == Op::DerefOf
            && let Place::Ref(r) = self.place(t)?
        {
            return Ok(r);
        }
        let v = self.eval(t)?;
        if let Data::Ref(r) = v
        {
            return Ok(r);
        }
        let mut temp = value::vec_with(1).map_err(bare)?;
        temp.push(v);
        Ok(Ref {
            base: Base::Value(temp),
            path: alloc::vec::Vec::new(),
        })
    }

    /// Check that the node reference `r` names is the one it was made to.
    pub(super) fn check_ref(&self, r: &Ref) -> Result<(), FaultKind>
    {
        if let Base::Node { node, generation } = r.base
            && self.ns.generation(node) != Some(generation)
        {
            return Err(FaultKind::NotFound);
        }
        Ok(())
    }

    /// The value at the base of `r`, which must be data: a named data
    /// object's, a local's or an argument's, or the temporary's.
    fn root<'r>(&'r self, r: &'r Ref) -> Result<&'r Data, FaultKind>
    {
        self.check_ref(r)?;
        match &r.base
        {
            Base::Node { node, .. } => match self.ns.object(*node)
            {
                Some(Object::Data(d)) => Ok(d),
                Some(_) => Err(FaultKind::Type),
                None => Err(FaultKind::NotFound),
            },
            Base::Local { frame, index } | Base::Arg { frame, index } =>
            {
                let f = self
                    .frames
                    .iter()
                    .rev()
                    .find(|f| f.serial == *frame)
                    .ok_or(FaultKind::NotFound)?;
                let i = usize::from(*index);
                let slot = if matches!(r.base, Base::Local { .. })
                {
                    f.locals.get(i)
                }
                else
                {
                    f.args.get(i)
                };
                slot.ok_or(FaultKind::BadOpcode)
            }
            Base::Value(v) => v.first().ok_or(FaultKind::Uninitialized),
        }
    }

    /// The value at the base of `r`, to change; `None` for a temporary,
    /// whose changes no one can read.
    fn root_mut(&mut self, r: &Ref) -> Result<Option<&mut Data>, FaultKind>
    {
        self.check_ref(r)?;
        match &r.base
        {
            Base::Node { node, .. } => match self.ns.object_mut(*node)
            {
                Some(Object::Data(d)) => Ok(Some(d)),
                Some(_) => Err(FaultKind::Type),
                None => Err(FaultKind::NotFound),
            },
            Base::Local { frame, index } | Base::Arg { frame, index } =>
            {
                let local = matches!(r.base, Base::Local { .. });
                let f = self
                    .frames
                    .iter_mut()
                    .rev()
                    .find(|f| f.serial == *frame)
                    .ok_or(FaultKind::NotFound)?;
                let i = usize::from(*index);
                let slot = if local
                {
                    f.locals.get_mut(i)
                }
                else
                {
                    f.args.get_mut(i)
                };
                slot.ok_or(FaultKind::BadOpcode).map(Some)
            }
            Base::Value(_) => Ok(None),
        }
    }

    /// The length of the package, buffer or string `r` refers to.
    pub(super) fn ref_len(&mut self, r: &Ref) -> Result<u64, Fault>
    {
        if r.path.is_empty()
            && let Base::Node { node, .. } = r.base
            && !matches!(self.ns.object(node), Some(Object::Data(_)))
        {
            self.check_ref(r).map_err(bare)?;
            let v = self.node_value(node)?;
            return len_of(&v).map_err(bare);
        }
        let d = self.root(r).map_err(bare)?;
        len_of(navigate(d, &r.path).map_err(bare)?).map_err(bare)
    }

    /// The object `r` refers to.
    pub(super) fn read_ref(&mut self, r: &Ref) -> Result<Data, Fault>
    {
        let Some((last, prefix)) = r.path.split_last()
        else
        {
            if let Base::Node { node, .. } = r.base
            {
                self.check_ref(r).map_err(bare)?;
                return self.node_value(node);
            }
            return self.root(r).and_then(Data::try_clone).map_err(bare);
        };
        let root = self.root(r).map_err(bare)?;
        let mut v = element(navigate(root, prefix).map_err(bare)?, *last).map_err(bare)?;
        if let Base::Node { node, .. } = r.base
        {
            let scope = self.ns.scope_of(node).unwrap_or(NodeId::ROOT);
            self.resolve_names(&mut v, scope);
        }
        Ok(v)
    }

    /// Store `v` to the object `r` refers to.
    pub(super) fn write_ref(&mut self, r: &Ref, v: Data, mode: Mode) -> Result<(), Fault>
    {
        let width = self.width();
        let Some((last, prefix)) = r.path.split_last()
        else
        {
            if let Base::Node { node, .. } = r.base
            {
                self.check_ref(r).map_err(bare)?;
                return self.store_node(node, v, mode);
            }
            if let Some(slot) = self.root_mut(r).map_err(bare)?
            {
                *slot = v;
            }
            return Ok(());
        };
        let v = self.computational(v)?;
        let byte = byte_of(&v, width);
        let depth = prefix.len().saturating_add(1).saturating_add(v.depth());
        let Some(root) = self.root_mut(r).map_err(bare)?
        else
        {
            return Ok(());
        };
        let container = navigate_mut(root, prefix).map_err(bare)?;
        let index = usize::try_from(*last).unwrap_or(usize::MAX);
        match container
        {
            Data::Package(p) =>
            {
                if depth > MAX_VALUE_DEPTH
                {
                    return Err(bare(FaultKind::Bound));
                }
                *p.get_mut(index).ok_or(bare(FaultKind::Range))? = v;
            }
            Data::Buffer(b) | Data::String(b) =>
            {
                *b.get_mut(index).ok_or(bare(FaultKind::Range))? = byte.map_err(bare)?;
            }
            Data::Uninitialized => return Err(bare(FaultKind::Uninitialized)),
            Data::Integer(_) | Data::Name(_) | Data::Ref(_) => return Err(bare(FaultKind::Type)),
        }
        Ok(())
    }

    /// The bytes of the buffer `r` refers to, to change; `None` for a
    /// temporary.
    pub(super) fn buffer_mut(
        &mut self,
        r: &Ref,
    ) -> Result<Option<&mut alloc::vec::Vec<u8>>, FaultKind>
    {
        let Some(root) = self.root_mut(r)?
        else
        {
            return Ok(None);
        };
        match navigate_mut(root, &r.path)?
        {
            Data::Buffer(b) => Ok(Some(b)),
            Data::Uninitialized => Err(FaultKind::Uninitialized),
            Data::Integer(_)
            | Data::String(_)
            | Data::Package(_)
            | Data::Name(_)
            | Data::Ref(_) => Err(FaultKind::Type),
        }
    }

    /// The bytes of the buffer `r` refers to.
    pub(super) fn buffer_of<'r>(&'r self, r: &'r Ref) -> Result<&'r [u8], FaultKind>
    {
        match navigate(self.root(r)?, &r.path)?
        {
            Data::Buffer(b) => Ok(b),
            Data::Uninitialized => Err(FaultKind::Uninitialized),
            Data::Integer(_)
            | Data::String(_)
            | Data::Package(_)
            | Data::Name(_)
            | Data::Ref(_) => Err(FaultKind::Type),
        }
    }
}
