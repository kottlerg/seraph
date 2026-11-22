// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/eval/field.rs

//! Operation regions, field units and buffer fields (ACPI 6.5 § 19.6.48,
//! § 19.6.64, § 19.6.18).
//!
//! A field unit is read and written in datums of its access width
//! (`AccessAs`, else its field list's access type; `AnyAcc` and
//! `BufferAcc` access bytes), each aligned to that width from the start of
//! its region: a datum the unit covers only in part is written as the
//! update rule says (preserve: read first; write as ones; write as zeros).
//! A unit of a `BankField` writes the bank value to its bank field first,
//! and a unit of an `IndexField` writes each datum's byte offset to its
//! index field and moves the datum through its data field. The lock rule
//! holds the global lock across the whole access. A unit wider than an
//! integer reads as a buffer, a narrower one as an integer; one wider than
//! [`MAX_BUFFER_BYTES`] is neither read nor written.
//!
//! A region is `SystemMemory`, `SystemIO` or `PCI_Config`; any other space
//! fails with [`FaultKind::Unsupported`], as a field with a `Connection`
//! does. Every access lies inside its region's span.

use alloc::vec::Vec;

use super::place::navigate_mut;
use super::{Evaluator, at, bare, by, imm_int, imm_name, kid};
use crate::encoding::{self, Seg};
use crate::host::{HostError, PciAddress, Span, Width};
use crate::load::FieldWalk;
use crate::namespace::{
    BufferField, ExprId, FieldKind, FieldUnit, NodeId, Object, Operand, Owner, Region,
};
use crate::term::{FieldElem, Imm, Name, Op, Term};
use crate::value::{self, Base, Data, IntWidth, Ref};
use crate::{Fault, FaultKind, MAX_BUFFER_BYTES, MAX_EVAL_DEPTH};

/// `SystemMemory`.
const SPACE_MEMORY: u8 = 0;
/// `SystemIO`.
const SPACE_IO: u8 = 1;
/// `PCI_Config`.
const SPACE_PCI: u8 = 2;

/// The field flags' lock rule bit.
const LOCK: u8 = 0x10;

/// The value of the bits of a field `bit_len` wide, given as bytes: an
/// integer when they fit one, else a buffer.
fn bits_value(bytes: Vec<u8>, bit_len: u64, w: IntWidth) -> Data
{
    if bit_len <= u64::from(w.bits())
    {
        Data::Integer(value::buffer_integer(&bytes, IntWidth::Bits64))
    }
    else
    {
        Data::Buffer(bytes)
    }
}

/// The bytes a value writes to a field: an integer's, little-endian; a
/// buffer's; a string's characters.
fn write_bytes(v: &Data) -> Result<Vec<u8>, FaultKind>
{
    match v
    {
        Data::Integer(i) => value::bytes_of(&i.to_le_bytes()),
        Data::Buffer(b) | Data::String(b) => value::bytes_of(b),
        Data::Uninitialized => Err(FaultKind::Uninitialized),
        Data::Package(_) | Data::Name(_) | Data::Ref(_) => Err(FaultKind::Type),
    }
}

/// Bit `at` of `bytes`; 0 past their end.
fn bit(bytes: &[u8], at: u64) -> u64
{
    let byte = usize::try_from(at / 8)
        .ok()
        .and_then(|i| bytes.get(i))
        .copied()
        .unwrap_or(0);
    u64::from(
        byte.checked_shr(u32::try_from(at % 8).unwrap_or(0))
            .unwrap_or(0)
            & 1,
    )
}

/// Set bit `at` of `bytes` to `v` (0 or 1).
fn set_bit(bytes: &mut [u8], at: u64, v: u64)
{
    let Some(byte) = usize::try_from(at / 8).ok().and_then(|i| bytes.get_mut(i))
    else
    {
        return;
    };
    let mask = 1u8
        .checked_shl(u32::try_from(at % 8).unwrap_or(0))
        .unwrap_or(0);
    if v & 1 == 0
    {
        *byte &= !mask;
    }
    else
    {
        *byte |= mask;
    }
}

/// The `n` bits (at most 64) of `bytes` from bit `at`, as an integer.
fn take_bits(bytes: &[u8], at: u64, n: u64) -> u64
{
    (0..n.min(64)).fold(0u64, |acc, j| {
        acc | bit(bytes, at.saturating_add(j))
            .checked_shl(u32::try_from(j).unwrap_or(0))
            .unwrap_or(0)
    })
}

/// Write the `n` bits (at most 64) of `v` to `bytes` from bit `at`.
fn put_bits(bytes: &mut [u8], at: u64, n: u64, v: u64)
{
    for j in 0..n.min(64)
    {
        let b = v.checked_shr(u32::try_from(j).unwrap_or(0)).unwrap_or(0) & 1;
        set_bit(bytes, at.saturating_add(j), b);
    }
}

/// A zeroed buffer to hold `bit_len` bits.
fn bit_buffer(bit_len: u64) -> Result<Vec<u8>, FaultKind>
{
    let len = usize::try_from(bit_len.div_ceil(8)).map_err(|_| FaultKind::Bound)?;
    if len > MAX_BUFFER_BYTES
    {
        return Err(FaultKind::Bound);
    }
    let mut out = value::vec_with(len)?;
    out.resize(len, 0);
    Ok(out)
}

/// Write the `len` bits of `src` to `buf` from bit `off`, all inside it.
fn put_field_bits(buf: &mut [u8], off: u64, len: u64, src: &[u8]) -> Result<(), Fault>
{
    let end = off.checked_add(len).ok_or(bare(FaultKind::Range))?;
    if end
        > u64::try_from(buf.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(8)
    {
        return Err(bare(FaultKind::Range));
    }
    for j in 0..len
    {
        set_bit(buf, off.saturating_add(j), bit(src, j));
    }
    Ok(())
}

/// The width of a field unit's datums.
fn access_width(unit: &FieldUnit) -> Result<Width, FaultKind>
{
    let kind = unit.access_as.map_or(unit.flags, |a| a.kind) & 0xF;
    match kind
    {
        0 | 1 | 5 => Ok(Width::Byte),
        2 => Ok(Width::Word),
        3 => Ok(Width::DWord),
        4 => Ok(Width::QWord),
        _ => Err(FaultKind::Unsupported),
    }
}

/// The mask of bits `shift..shift + n` of a datum.
fn datum_mask(n: u64, shift: u64) -> u64
{
    let ones = if n >= 64
    {
        u64::MAX
    }
    else
    {
        1u64.checked_shl(u32::try_from(n).unwrap_or(0))
            .unwrap_or(0)
            .wrapping_sub(1)
    };
    ones.checked_shl(u32::try_from(shift).unwrap_or(64))
        .unwrap_or(0)
}

/// The EISA ids of the PCI host bridges, `PNP0A03` and `PNP0A08`.
const HOST_BRIDGES: [&[u8; 7]; 2] = [b"PNP0A03", b"PNP0A08"];

/// Whether the hardware id `v` (`_HID` or one `_CID`) names a PCI host
/// bridge.
fn is_host_bridge_id(v: &Data) -> bool
{
    match v
    {
        Data::Integer(i) => u32::try_from(*i)
            .ok()
            .and_then(encoding::eisa_id)
            .is_some_and(|id| HOST_BRIDGES.iter().any(|h| **h == id)),
        Data::String(s) => HOST_BRIDGES.iter().any(|h| h.as_slice() == s.as_slice()),
        Data::Package(p) => p.iter().any(is_host_bridge_id),
        Data::Uninitialized | Data::Buffer(_) | Data::Name(_) | Data::Ref(_) => false,
    }
}

/// The device and function an `_ADR` gives.
fn device_function(adr: u64, segment: u16, bus: u8) -> PciAddress
{
    PciAddress {
        segment,
        bus,
        device: u8::try_from((adr >> 16) & 0x1F).unwrap_or(0),
        function: u8::try_from(adr & 0x7).unwrap_or(0),
    }
}

impl Evaluator<'_>
{
    /// Count one level of [`MAX_EVAL_DEPTH`] for a field access, which may
    /// reach other fields.
    fn nest(&mut self) -> Result<(), Fault>
    {
        if self.budget.depth >= MAX_EVAL_DEPTH
        {
            return Err(bare(FaultKind::Depth));
        }
        self.budget.depth = self.budget.depth.saturating_add(1);
        Ok(())
    }

    // ── Definitions ───────────────────────────────────────────────────

    /// The object of an `OperationRegion` a running method defines, its
    /// offset and length evaluated now.
    pub(super) fn region_object(&mut self, t: &Term) -> Result<Object, Fault>
    {
        let space = u8::try_from(imm_int(kid(t, 0)?)? & 0xFF).unwrap_or(0);
        let offset = self.int(kid(t, 1)?)?;
        let length = self.int(kid(t, 2)?)?;
        Ok(Object::Region(Region {
            space,
            offset: Operand::Value(offset),
            length: Operand::Value(length),
            pci: None,
        }))
    }

    /// The node the name operand `t` names.
    fn named(&self, t: &Term) -> Result<NodeId, Fault>
    {
        self.lookup(imm_name(t)?).ok_or(at(t, FaultKind::NotFound))
    }

    /// `Field`, `IndexField`, `BankField` in a running method: create the
    /// units. A `Connection` is not supported.
    pub(super) fn define_fields(&mut self, t: &Term) -> Result<(), Fault>
    {
        let Imm::Fields(list) = &t.imm
        else
        {
            return Err(at(t, FaultKind::BadOpcode));
        };
        let kind = if t.op == Op::Field
        {
            FieldKind::Region(self.named(kid(t, 0)?)?)
        }
        else if t.op == Op::IndexField
        {
            FieldKind::Index {
                index: self.named(kid(t, 0)?)?,
                data: self.named(kid(t, 1)?)?,
            }
        }
        else
        {
            FieldKind::Bank {
                region: self.named(kid(t, 0)?)?,
                bank: self.named(kid(t, 1)?)?,
                value: Operand::Value(self.int(kid(t, 2)?)?),
            }
        };
        let mut walk = FieldWalk::new(kind, list.flags);
        for elem in &list.elems
        {
            if matches!(elem, FieldElem::Connect(_))
            {
                return Err(at(t, FaultKind::Unsupported));
            }
            let Some((seg, unit)) = walk.step(elem).map_err(by(t))?
            else
            {
                continue;
            };
            let mut segs = value::vec_with(1).map_err(by(t))?;
            segs.push(seg);
            let name = Name {
                root: false,
                up: 0,
                segs,
            };
            self.create(&name, Object::Field(unit)).map_err(by(t))?;
        }
        Ok(())
    }

    /// The object of a `CreateField` or one of its fixed-width forms.
    pub(super) fn buffer_field_object(&mut self, t: &Term) -> Result<Object, Fault>
    {
        let source = self.source_ref(kid(t, 0)?)?;
        let index = self.int(kid(t, 1)?)?;
        let bytes = |i: u64| i.checked_mul(8).ok_or(at(t, FaultKind::Range));
        let (bit_offset, bit_len) = if t.op == Op::CreateBitField
        {
            (index, 1)
        }
        else if t.op == Op::CreateByteField
        {
            (bytes(index)?, 8)
        }
        else if t.op == Op::CreateWordField
        {
            (bytes(index)?, 16)
        }
        else if t.op == Op::CreateDWordField
        {
            (bytes(index)?, 32)
        }
        else if t.op == Op::CreateQWordField
        {
            (bytes(index)?, 64)
        }
        else
        {
            (index, self.int(kid(t, 2)?)?)
        };
        let len = u64::try_from(self.buffer_of(&source).map_err(by(t))?.len()).unwrap_or(u64::MAX);
        let end = bit_offset
            .checked_add(bit_len)
            .ok_or(at(t, FaultKind::Range))?;
        if bit_len == 0 || end > len.saturating_mul(8)
        {
            return Err(at(t, FaultKind::Range));
        }
        Ok(Object::BufferField(BufferField {
            source,
            bit_offset,
            bit_len,
        }))
    }

    // ── Buffer fields ─────────────────────────────────────────────────

    /// Read the buffer field `node`.
    pub(super) fn read_buffer_field(&mut self, node: NodeId) -> Result<Data, Fault>
    {
        let w = self.width();
        let Some(Object::BufferField(bf)) = self.ns.object(node)
        else
        {
            return Err(bare(FaultKind::NotFound));
        };
        let buf = self.buffer_of(&bf.source).map_err(bare)?;
        let (off, len) = (bf.bit_offset, bf.bit_len);
        let end = off.checked_add(len).ok_or(bare(FaultKind::Range))?;
        if end
            > u64::try_from(buf.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(8)
        {
            return Err(bare(FaultKind::Range));
        }
        let mut out = bit_buffer(len).map_err(bare)?;
        for j in 0..len
        {
            set_bit(&mut out, j, bit(buf, off.saturating_add(j)));
        }
        Ok(bits_value(out, len, w))
    }

    /// Write `v` to the buffer field `node`.
    pub(super) fn write_buffer_field(&mut self, node: NodeId, v: Data) -> Result<(), Fault>
    {
        let v = self.computational(v)?;
        let src = write_bytes(&v).map_err(bare)?;
        let Some(Object::BufferField(bf)) = self.ns.object_mut(node)
        else
        {
            return Err(bare(FaultKind::NotFound));
        };
        let (off, len) = (bf.bit_offset, bf.bit_len);
        // A field over a temporary owns its buffer; any other refers to one.
        if let BufferField {
            source:
                Ref {
                    base: Base::Value(temp),
                    path,
                },
            ..
        } = bf
        {
            let root = temp.first_mut().ok_or(bare(FaultKind::Type))?;
            let Data::Buffer(buf) = navigate_mut(root, path).map_err(bare)?
            else
            {
                return Err(bare(FaultKind::Type));
            };
            return put_field_bits(buf, off, len, &src);
        }
        let source = bf.source.try_clone().map_err(bare)?;
        let buf = self
            .buffer_mut(&source)
            .map_err(bare)?
            .ok_or(bare(FaultKind::Type))?;
        put_field_bits(buf, off, len, &src)
    }

    // ── Field units ───────────────────────────────────────────────────

    /// The field unit `node` holds.
    fn unit(&self, node: NodeId) -> Result<FieldUnit, Fault>
    {
        match self.ns.object(node)
        {
            Some(Object::Field(u)) => Ok(*u),
            Some(_) => Err(bare(FaultKind::Type)),
            None => Err(bare(FaultKind::NotFound)),
        }
    }

    /// Read the field unit `node`.
    pub(super) fn read_field(&mut self, node: NodeId) -> Result<Data, Fault>
    {
        let unit = self.unit(node)?;
        let w = self.width();
        self.nest()?;
        let r = self.locked(node, &unit, None);
        self.leave();
        Ok(bits_value(r?, u64::from(unit.bit_len), w))
    }

    /// Write `v` to the field unit `node`.
    pub(super) fn write_field(&mut self, node: NodeId, v: Data) -> Result<(), Fault>
    {
        let unit = self.unit(node)?;
        let v = self.computational(v)?;
        let src = write_bytes(&v).map_err(bare)?;
        self.nest()?;
        let r = self.locked(node, &unit, Some(&src));
        self.leave();
        r.map(drop)
    }

    /// The access of `unit`, holding the global lock when its lock rule
    /// says.
    fn locked(
        &mut self,
        node: NodeId,
        unit: &FieldUnit,
        src: Option<&[u8]>,
    ) -> Result<Vec<u8>, Fault>
    {
        if unit.flags & LOCK == 0
        {
            return self.field_io(node, unit, src);
        }
        // No limit: the wait ends with the lock or fails at the delay budget.
        if !self.global_acquire(0xFFFF).map_err(bare)?
        {
            return Err(bare(FaultKind::Bound));
        }
        let r = self.field_io(node, unit, src);
        let released = self.global_release().map_err(bare);
        let out = r?;
        released?;
        Ok(out)
    }

    /// Read `unit` (`src` `None`), or write `src` to it, a datum at a time.
    fn field_io(
        &mut self,
        node: NodeId,
        unit: &FieldUnit,
        src: Option<&[u8]>,
    ) -> Result<Vec<u8>, Fault>
    {
        if unit.connection.is_some()
        {
            return Err(bare(FaultKind::Unsupported));
        }
        let width = access_width(unit).map_err(bare)?;
        let wb = width.bytes();
        let wbits = wb.saturating_mul(8);
        let bit_offset = u64::from(unit.bit_offset);
        let bit_len = u64::from(unit.bit_len);
        // A unit is read into, or written from, at most a buffer's bytes.
        let most = u64::try_from(MAX_BUFFER_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_mul(8);
        if bit_len > most
        {
            return Err(bare(FaultKind::Bound));
        }
        let mut out = match src
        {
            None => bit_buffer(bit_len).map_err(bare)?,
            Some(_) => Vec::new(),
        };
        let first = (bit_offset / 8)
            .checked_div(wb)
            .unwrap_or(0)
            .saturating_mul(wb);
        let start = bit_offset.saturating_sub(first.saturating_mul(8));
        let total = start.saturating_add(bit_len);
        let datums = total.div_ceil(wbits);
        for d in 0..datums
        {
            let off = first.saturating_add(d.saturating_mul(wb));
            let lo = d.saturating_mul(wbits);
            let a = start.max(lo);
            let b = total.min(lo.saturating_add(wbits));
            let n = b.saturating_sub(a);
            let shift = a.saturating_sub(lo);
            let mask = datum_mask(n, shift) & width.mask();
            let field_bit = a.saturating_sub(start);
            match src
            {
                None =>
                {
                    let raw = self.datum(node, unit, off, width, None)?;
                    let bits = (raw & mask).checked_shr(u32::try_from(shift).unwrap_or(64));
                    put_bits(&mut out, field_bit, n, bits.unwrap_or(0));
                }
                Some(src) =>
                {
                    let bits = take_bits(src, field_bit, n);
                    let new = bits
                        .checked_shl(u32::try_from(shift).unwrap_or(64))
                        .unwrap_or(0)
                        & mask;
                    let old = if mask == width.mask()
                    {
                        0
                    }
                    else
                    {
                        match (unit.flags >> 5) & 3
                        {
                            1 => width.mask(),
                            2 => 0,
                            _ => self.datum(node, unit, off, width, None)?,
                        }
                    };
                    let raw = (old & !mask) | new;
                    self.datum(node, unit, off, width, Some(raw & width.mask()))?;
                }
            }
        }
        Ok(out)
    }

    /// Read (`value` `None`) or write the datum at byte offset `off` of
    /// `unit`.
    fn datum(
        &mut self,
        node: NodeId,
        unit: &FieldUnit,
        off: u64,
        width: Width,
        value: Option<u64>,
    ) -> Result<u64, Fault>
    {
        match unit.kind
        {
            FieldKind::Region(region) => self.region_io(region, off, width, value),
            FieldKind::Bank {
                region,
                bank,
                value: bank_value,
            } =>
            {
                let scope = self.ns.scope_of(node).unwrap_or(NodeId::ROOT);
                let v = self.operand(bank_value, scope, node)?;
                self.write_field(bank, Data::Integer(v))?;
                self.region_io(region, off, width, value)
            }
            FieldKind::Index { index, data } =>
            {
                self.write_field(index, Data::Integer(off))?;
                match value
                {
                    None =>
                    {
                        let v = self.read_field(data)?;
                        value::integer(&v, IntWidth::Bits64).map_err(bare)
                    }
                    Some(v) => self.write_field(data, Data::Integer(v)).map(|()| 0),
                }
            }
        }
    }

    // ── Regions ───────────────────────────────────────────────────────

    /// The value of an operand of the definition of `node`, whose scope is
    /// `scope`: an expression a table load kept is evaluated now.
    fn operand(&mut self, op: Operand, scope: NodeId, node: NodeId) -> Result<u64, Fault>
    {
        match op
        {
            Operand::Value(v) => Ok(v),
            Operand::Expr(id) => self.eval_expr(id, scope, node),
        }
    }

    /// Evaluate the kept expression `id` in `scope`, as code of the table
    /// that created `node`.
    fn eval_expr(&mut self, id: ExprId, scope: NodeId, node: NodeId) -> Result<u64, Fault>
    {
        let term = self.ns.take_expr(id).ok_or(bare(FaultKind::NotFound))?;
        let table = match self.ns.owner(node)
        {
            Some(Owner::Table(t)) => Some(t),
            Some(Owner::Predefined | Owner::Frame(_)) | None => None,
        };
        let width = self.owner_width(node);
        let depth = u32::try_from(self.frames.len()).unwrap_or(u32::MAX);
        let r = self.with_frame(scope, table, width, Owner::Frame(depth), |ev| ev.int(&term));
        self.ns.put_expr(id, term);
        r
    }

    /// The span of the region `node`, evaluated on first use and kept.
    fn region(&mut self, node: NodeId) -> Result<(Region, Span), Fault>
    {
        let r = match self.ns.object(node)
        {
            Some(Object::Region(r)) => *r,
            Some(_) => return Err(bare(FaultKind::Type)),
            None => return Err(bare(FaultKind::NotFound)),
        };
        let scope = self.ns.scope_of(node).unwrap_or(NodeId::ROOT);
        let base = self.operand(r.offset, scope, node)?;
        let len = self.operand(r.length, scope, node)?;
        if let Some(Object::Region(kept)) = self.ns.object_mut(node)
        {
            kept.offset = Operand::Value(base);
            kept.length = Operand::Value(len);
        }
        Ok((r, Span { base, len }))
    }

    /// Read (`value` `None`) or write `width` bytes at offset `off` of the
    /// region `node`.
    fn region_io(
        &mut self,
        node: NodeId,
        off: u64,
        width: Width,
        value: Option<u64>,
    ) -> Result<u64, Fault>
    {
        let (r, span) = self.region(node)?;
        let end = off
            .checked_add(width.bytes())
            .ok_or(bare(FaultKind::Range))?;
        if end > span.len
        {
            return Err(bare(FaultKind::Range));
        }
        let addr = span.base.checked_add(off).ok_or(bare(FaultKind::Range))?;
        let host = |e: HostError| bare(FaultKind::Host(e));
        let v = match (r.space, value)
        {
            (SPACE_MEMORY, None) => self.host.mem_read(span, addr, width).map_err(host)?,
            (SPACE_MEMORY, Some(v)) => self
                .host
                .mem_write(span, addr, width, v)
                .map(|()| 0)
                .map_err(host)?,
            (SPACE_IO, None) => self.host.io_read(span, addr, width).map_err(host)?,
            (SPACE_IO, Some(v)) => self
                .host
                .io_write(span, addr, width, v)
                .map(|()| 0)
                .map_err(host)?,
            (SPACE_PCI, value) =>
            {
                let pci = self.pci_address(node, r)?;
                match value
                {
                    None => self.host.pci_read(pci, addr, width).map_err(host)?,
                    Some(v) => self
                        .host
                        .pci_write(pci, addr, width, v)
                        .map(|()| 0)
                        .map_err(host)?,
                }
            }
            _ => return Err(bare(FaultKind::Unsupported)),
        };
        Ok(v & width.mask())
    }

    /// Whether `node` is a PCI host bridge: its `_HID` or a `_CID` is
    /// `PNP0A03` or `PNP0A08`.
    fn is_host_bridge(&mut self, node: NodeId) -> Result<bool, Fault>
    {
        for seg in [*b"_HID", *b"_CID"]
        {
            if let Some(v) = self.child_value(node, seg)?
                && is_host_bridge_id(&v)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The PCI function of the `PCI_Config` region `node`, found on first
    /// use and kept.
    fn pci_address(&mut self, node: NodeId, r: Region) -> Result<PciAddress, Fault>
    {
        if let Some(pci) = r.pci
        {
            return Ok(pci);
        }
        let device = self.ns.parent(node).unwrap_or(NodeId::ROOT);
        let adr: u64 = self.child_int(device, *b"_ADR")?.unwrap_or(0);
        let mut chain: Vec<NodeId> = Vec::new();
        let mut cur = Some(device);
        let mut bridge = None;
        while let Some(c) = cur
        {
            if self.is_host_bridge(c)?
            {
                bridge = Some(c);
                break;
            }
            crate::push(&mut chain, c).map_err(bare)?;
            cur = self.ns.parent(c);
        }
        let (segment, mut bus) = match bridge
        {
            Some(b) =>
            {
                let seg: Seg = *b"_SEG";
                let segment = self.child_int(b, seg)?.unwrap_or(0);
                let bus = self.child_int(b, *b"_BBN")?.unwrap_or(0);
                (
                    u16::try_from(segment & 0xFFFF).unwrap_or(0),
                    u8::try_from(bus & 0xFF).unwrap_or(0),
                )
            }
            None => (0, 0),
        };
        let host = |e: HostError| bare(FaultKind::Host(e));
        for b in chain.iter().skip(1).rev()
        {
            let Some(badr) = self.child_int(*b, *b"_ADR")?
            else
            {
                continue;
            };
            let at = device_function(badr, segment, bus);
            let header = self.host.pci_read(at, 0x0E, Width::Byte).map_err(host)?;
            if matches!(header & 0x7F, 1 | 2)
            {
                let secondary = self.host.pci_read(at, 0x19, Width::Byte).map_err(host)?;
                bus = u8::try_from(secondary & 0xFF).unwrap_or(0);
            }
        }
        let pci = device_function(adr, segment, bus);
        if let Some(Object::Region(kept)) = self.ns.object_mut(node)
        {
            kept.pci = Some(pci);
        }
        Ok(pci)
    }
}
