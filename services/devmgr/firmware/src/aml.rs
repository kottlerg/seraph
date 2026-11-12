// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/aml.rs

//! A static walk of a DSDT or SSDT's AML namespace, and the decoder for the
//! resource templates it finds.
//!
//! devmgr reports every `Device` object whose `_HID`, `_CID`, `_UID`, and
//! `_CRS` are `Name` objects as a device record
//! (`docs/driver-binding.md` § Device Records), except one whose `_STA` is a
//! `Name` with its present bit (bit 0) clear; a `_STA` method is not
//! evaluated, so its device is reported. No AML is executed: the walk
//! follows the AML grammar of ACPI 6.5 § 20 through the term lists that hold
//! `Scope`, `Device`, `Name`, and `Method` objects, skips every other
//! construct by its `PkgLength`, and stops a term list at the first construct
//! it cannot size. A fault inside one package ends that package's walk only;
//! the enclosing package continues after it. Every read is bounds-checked
//! against the caller's slice, nesting is bounded by [`MAX_DEPTH`], and each
//! step advances, so any byte string terminates without a panic. No alloc.

use crate::acpi::{SDT_HDR_LEN, sdt_length};

// ── Bounds ────────────────────────────────────────────────────────────

/// Longest `_HID` or `_CID` string kept, in bytes.
pub const MAX_ID_BYTES: usize = 16;
/// `_CID` entries kept per device; further entries are ignored.
pub const MAX_CIDS: usize = 4;
/// `Scope` and `Device` nesting followed.
pub const MAX_DEPTH: usize = 16;
/// Resources [`crs_resources`] reports for one template.
pub const MAX_CRS_RESOURCES: usize = 8;

const _: () = assert!(MAX_ID_BYTES == driver_binding::decl::MAX_ACPI_ID_BYTES);

// ── Opcodes ───────────────────────────────────────────────────────────

const OP_ZERO: u8 = 0x00;
const OP_ONE: u8 = 0x01;
const OP_ALIAS: u8 = 0x06;
const OP_NAME: u8 = 0x08;
const OP_BYTE: u8 = 0x0A;
const OP_WORD: u8 = 0x0B;
const OP_DWORD: u8 = 0x0C;
const OP_STRING: u8 = 0x0D;
const OP_QWORD: u8 = 0x0E;
const OP_SCOPE: u8 = 0x10;
const OP_BUFFER: u8 = 0x11;
const OP_PACKAGE: u8 = 0x12;
const OP_VAR_PACKAGE: u8 = 0x13;
const OP_METHOD: u8 = 0x14;
const OP_EXTERNAL: u8 = 0x15;
const OP_EXT_PREFIX: u8 = 0x5B;
const OP_IF: u8 = 0xA0;
const OP_ELSE: u8 = 0xA1;
const OP_WHILE: u8 = 0xA2;
const OP_ONES: u8 = 0xFF;

const EXT_MUTEX: u8 = 0x01;
const EXT_EVENT: u8 = 0x02;
const EXT_REVISION: u8 = 0x30;
const EXT_OP_REGION: u8 = 0x80;
const EXT_FIELD: u8 = 0x81;
const EXT_DEVICE: u8 = 0x82;
const EXT_PROCESSOR: u8 = 0x83;
const EXT_POWER_RES: u8 = 0x84;
const EXT_THERMAL_ZONE: u8 = 0x85;
const EXT_INDEX_FIELD: u8 = 0x86;
const EXT_BANK_FIELD: u8 = 0x87;

// ── Types ─────────────────────────────────────────────────────────────

/// A `_HID` or `_CID` string: 1 to [`MAX_ID_BYTES`] printable ASCII bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id
{
    bytes: [u8; MAX_ID_BYTES],
    len: u8,
}

impl Id
{
    /// Build an identifier from `bytes`: 1 to [`MAX_ID_BYTES`] graphic ASCII
    /// bytes, else `None`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self>
    {
        if bytes.is_empty() || bytes.len() > MAX_ID_BYTES || !bytes.iter().all(u8::is_ascii_graphic)
        {
            return None;
        }
        let mut out = [0u8; MAX_ID_BYTES];
        out.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self {
            bytes: out,
            len: u8::try_from(bytes.len()).ok()?,
        })
    }

    /// The identifier's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// One `Device` object with a static identity.
#[derive(Clone, Copy, Debug)]
pub struct AmlDevice<'a>
{
    /// The `_HID`, if it is a static integer (EISA ID) or string.
    pub hid: Option<Id>,
    /// The first [`MAX_CIDS`] static `_CID` entries.
    pub cids: [Option<Id>; MAX_CIDS],
    /// The `_UID`, if it is an integer; a string `_UID` is ignored.
    pub uid: Option<u64>,
    /// The `_CRS` Buffer's byte list (the resource template).
    pub crs: Option<&'a [u8]>,
}

/// The device being collected while its body is walked.
#[derive(Default)]
struct Collect<'a>
{
    hid: Option<Id>,
    cids: [Option<Id>; MAX_CIDS],
    uid: Option<u64>,
    crs: Option<&'a [u8]>,
    sta: Option<u64>,
    dynamic: bool,
}

// ── Grammar helpers ───────────────────────────────────────────────────

/// Bounds of the package whose `PkgLength` lead byte is at `lead`: the offset
/// of the first body byte and the offset one past the package's end. The end
/// must lie within `buf`.
fn package(buf: &[u8], lead: usize) -> Option<(usize, usize)>
{
    let b0 = *buf.get(lead)?;
    let extra = usize::from(b0 >> 6);
    let len = if extra == 0
    {
        usize::from(b0 & 0x3F)
    }
    else
    {
        let mut v = usize::from(b0 & 0x0F);
        for i in 0..extra
        {
            let b = *buf.get(lead.checked_add(1)?.checked_add(i)?)?;
            v |= usize::from(b) << i.saturating_mul(8).saturating_add(4);
        }
        v
    };
    if len < extra.saturating_add(1)
    {
        return None;
    }
    let end = lead.checked_add(len)?;
    if end > buf.len()
    {
        return None;
    }
    Some((lead.checked_add(1)?.checked_add(extra)?, end))
}

/// Size and last `NameSeg` of the `NameString` at `pos`. The last segment is
/// `None` for a `NullName` or an empty multi-name.
fn name_string(buf: &[u8], pos: usize) -> Option<(usize, Option<[u8; 4]>)>
{
    let mut p = pos;
    match *buf.get(p)?
    {
        0x5C => p = p.saturating_add(1),
        0x5E =>
        {
            while buf.get(p) == Some(&0x5E)
            {
                p = p.saturating_add(1);
            }
        }
        _ =>
        {}
    }
    let (segs, skip) = match *buf.get(p)?
    {
        0x00 => return Some((p.checked_add(1)?.checked_sub(pos)?, None)),
        0x2E => (2, 1),
        0x2F => (usize::from(*buf.get(p.saturating_add(1))?), 2),
        _ => (1, 0),
    };
    p = p.saturating_add(skip);
    let mut last = None;
    for _ in 0..segs
    {
        let seg = buf.get(p..p.checked_add(4)?)?;
        let (first, rest) = seg.split_first()?;
        if !(first.is_ascii_uppercase() || *first == b'_')
            || !rest
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        {
            return None;
        }
        let &[s0, s1, s2, s3] = seg
        else
        {
            return None;
        };
        last = Some([s0, s1, s2, s3]);
        p = p.saturating_add(4);
    }
    Some((p.checked_sub(pos)?, last))
}

/// Little-endian integer of `n` bytes at `off`.
fn le(buf: &[u8], off: usize, n: usize) -> Option<u64>
{
    let bytes = buf.get(off..off.checked_add(n)?)?;
    Some(
        bytes
            .iter()
            .rev()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)),
    )
}

/// Integer `DataObject` at `pos`: its value and encoded size.
fn integer(buf: &[u8], pos: usize) -> Option<(u64, usize)>
{
    match *buf.get(pos)?
    {
        OP_ZERO => Some((0, 1)),
        OP_ONE => Some((1, 1)),
        OP_ONES => Some((u64::MAX, 1)),
        OP_BYTE => Some((le(buf, pos.saturating_add(1), 1)?, 2)),
        OP_WORD => Some((le(buf, pos.saturating_add(1), 2)?, 3)),
        OP_DWORD => Some((le(buf, pos.saturating_add(1), 4)?, 5)),
        OP_QWORD => Some((le(buf, pos.saturating_add(1), 8)?, 9)),
        _ => None,
    }
}

/// Encoded size of the `DataRefObject` at `pos`.
fn data_size(buf: &[u8], pos: usize) -> Option<usize>
{
    if let Some((_, size)) = integer(buf, pos)
    {
        return Some(size);
    }
    match *buf.get(pos)?
    {
        OP_STRING =>
        {
            let rest = buf.get(pos.saturating_add(1)..)?;
            let nul = rest.iter().position(|b| *b == 0)?;
            nul.checked_add(2)
        }
        OP_BUFFER | OP_PACKAGE | OP_VAR_PACKAGE =>
        {
            let (_, end) = package(buf, pos.saturating_add(1))?;
            end.checked_sub(pos)
        }
        OP_EXT_PREFIX if buf.get(pos.saturating_add(1)) == Some(&EXT_REVISION) => Some(2),
        _ => None,
    }
}

/// Decode a 32-bit EISA ID as AML stores it.
fn eisa_id(value: u32) -> Option<Id>
{
    let s = value.swap_bytes();
    let mut text = [0u8; 7];
    for (i, shift) in [26u32, 21, 16].into_iter().enumerate()
    {
        let letter = u8::try_from((s >> shift) & 0x1F).ok()?;
        if !(1..=26).contains(&letter)
        {
            return None;
        }
        *text.get_mut(i)? = letter.checked_add(0x40)?;
    }
    for (i, shift) in [12u32, 8, 4, 0].into_iter().enumerate()
    {
        let digit = u8::try_from((s >> shift) & 0xF).ok()?;
        *text.get_mut(3usize.checked_add(i)?)? =
            b"0123456789ABCDEF".get(usize::from(digit)).copied()?;
    }
    Id::new(&text)
}

/// A `_HID`/`_CID` value at `pos`: an EISA-ID integer or a string.
fn id_value(buf: &[u8], pos: usize) -> Option<Id>
{
    if let Some((value, _)) = integer(buf, pos)
    {
        return eisa_id(u32::try_from(value).ok()?);
    }
    if *buf.get(pos)? == OP_STRING
    {
        let rest = buf.get(pos.saturating_add(1)..)?;
        let nul = rest.iter().position(|b| *b == 0)?;
        return Id::new(rest.get(..nul)?);
    }
    None
}

// ── Walk ──────────────────────────────────────────────────────────────

struct Walker<F>
{
    visit: F,
    count: usize,
}

impl<'a, F: FnMut(&AmlDevice<'a>)> Walker<F>
{
    /// Walk the term list `buf` at nesting `depth`; `dev` is the device whose
    /// own objects the list holds, if any.
    fn term_list(&mut self, buf: &'a [u8], depth: usize, mut dev: Option<&mut Collect<'a>>)
    {
        if depth > MAX_DEPTH
        {
            return;
        }
        let mut pos = 0;
        while pos < buf.len()
        {
            match self.term(buf, pos, depth, &mut dev)
            {
                Some(next) if next > pos => pos = next,
                _ => break,
            }
        }
    }

    /// Handle the term at `pos`; the offset after it, or `None` to stop the list.
    fn term(
        &mut self,
        buf: &'a [u8],
        pos: usize,
        depth: usize,
        dev: &mut Option<&mut Collect<'a>>,
    ) -> Option<usize>
    {
        match *buf.get(pos)?
        {
            OP_SCOPE =>
            {
                let (body, end, _) = Self::named_package(buf, pos.saturating_add(1))?;
                self.term_list(buf.get(body..end)?, depth.saturating_add(1), None);
                Some(end)
            }
            OP_NAME => Self::def_name(buf, pos, dev),
            OP_METHOD =>
            {
                let (_, end, name) = Self::named_package(buf, pos.saturating_add(1))?;
                if let Some(c) = dev.as_deref_mut()
                    && matches!(name, Some(n) if is_dynamic_name(n))
                {
                    c.dynamic = true;
                }
                Some(end)
            }
            OP_IF | OP_ELSE | OP_WHILE =>
            {
                let (_, end) = package(buf, pos.saturating_add(1))?;
                Some(end)
            }
            OP_EXTERNAL =>
            {
                let (nl, _) = name_string(buf, pos.saturating_add(1))?;
                let end = pos.checked_add(1)?.checked_add(nl)?.checked_add(2)?;
                (end <= buf.len()).then_some(end)
            }
            OP_ALIAS =>
            {
                let (a, _) = name_string(buf, pos.saturating_add(1))?;
                let after_a = pos.checked_add(1)?.checked_add(a)?;
                let (b, _) = name_string(buf, after_a)?;
                after_a.checked_add(b)
            }
            OP_EXT_PREFIX => self.ext_term(buf, pos, depth),
            _ => None,
        }
    }

    /// Handle the `0x5B`-prefixed term at `pos`.
    fn ext_term(&mut self, buf: &'a [u8], pos: usize, depth: usize) -> Option<usize>
    {
        match *buf.get(pos.saturating_add(1))?
        {
            EXT_DEVICE =>
            {
                let (body, end, _) = Self::named_package(buf, pos.saturating_add(2))?;
                let mut c = Collect::default();
                self.term_list(buf.get(body..end)?, depth.saturating_add(1), Some(&mut c));
                self.report(&c);
                Some(end)
            }
            EXT_FIELD | EXT_INDEX_FIELD | EXT_BANK_FIELD | EXT_PROCESSOR | EXT_POWER_RES
            | EXT_THERMAL_ZONE =>
            {
                let (_, end) = package(buf, pos.saturating_add(2))?;
                Some(end)
            }
            EXT_OP_REGION =>
            {
                let (nl, _) = name_string(buf, pos.saturating_add(2))?;
                let mut p = pos.checked_add(2)?.checked_add(nl)?.checked_add(1)?;
                for _ in 0..2
                {
                    p = p.checked_add(integer(buf, p)?.1)?;
                }
                Some(p)
            }
            EXT_MUTEX =>
            {
                let (nl, _) = name_string(buf, pos.saturating_add(2))?;
                let end = pos.checked_add(2)?.checked_add(nl)?.checked_add(1)?;
                (end <= buf.len()).then_some(end)
            }
            EXT_EVENT =>
            {
                let (nl, _) = name_string(buf, pos.saturating_add(2))?;
                pos.checked_add(2)?.checked_add(nl)
            }
            _ => None,
        }
    }

    /// For a package whose `PkgLength` is at `lead` and whose `NameString`
    /// follows it: the offset of the first byte after the name, the package's
    /// end, and the name's last segment.
    fn named_package(buf: &[u8], lead: usize) -> Option<(usize, usize, Option<[u8; 4]>)>
    {
        let (name_at, end) = package(buf, lead)?;
        let (nl, last) = name_string(buf.get(..end)?, name_at)?;
        Some((name_at.checked_add(nl)?, end, last))
    }

    /// `DefName` at `pos`.
    fn def_name(buf: &'a [u8], pos: usize, dev: &mut Option<&mut Collect<'a>>) -> Option<usize>
    {
        let (nl, last) = name_string(buf, pos.saturating_add(1))?;
        let value = pos.checked_add(1)?.checked_add(nl)?;
        let size = data_size(buf, value)?;
        if let (Some(c), Some(name)) = (dev.as_deref_mut(), last)
        {
            record(c, name, buf, value, size);
        }
        value.checked_add(size)
    }

    /// Report a finished device if it qualifies.
    fn report(&mut self, c: &Collect<'a>)
    {
        let static_id = c.hid.is_some() || c.cids.iter().any(Option::is_some);
        let absent = c.sta.is_some_and(|sta| sta & 1 == 0);
        if c.dynamic || absent || !static_id
        {
            return;
        }
        let device = AmlDevice {
            hid: c.hid,
            cids: c.cids,
            uid: c.uid,
            crs: c.crs,
        };
        (self.visit)(&device);
        self.count = self.count.saturating_add(1);
    }
}

/// Whether a `Method` of this name makes the device's identity dynamic.
fn is_dynamic_name(name: [u8; 4]) -> bool
{
    matches!(&name, b"_HID" | b"_CID" | b"_CRS")
}

/// Record the value of `Name(name, <data at value..value+size>)` into `c`.
fn record<'a>(c: &mut Collect<'a>, name: [u8; 4], buf: &'a [u8], value: usize, size: usize)
{
    let Some(data) = value.checked_add(size).and_then(|end| buf.get(..end))
    else
    {
        return;
    };
    match &name
    {
        b"_HID" =>
        {
            if let Some(id) = id_value(data, value)
            {
                c.hid = Some(id);
            }
        }
        b"_CID" => record_cids(c, data, value),
        b"_UID" =>
        {
            if let Some((v, _)) = integer(data, value)
            {
                c.uid = Some(v);
            }
        }
        b"_CRS" => c.crs = crs_buffer(data, value),
        b"_STA" => c.sta = integer(data, value).map(|(v, _)| v),
        _ =>
        {}
    }
}

/// Store the `_CID` value at `pos`: one ID, or the IDs of a Package.
fn record_cids(c: &mut Collect<'_>, buf: &[u8], pos: usize)
{
    let mut n = 0;
    let mut keep = |id: Option<Id>| {
        if let Some(id) = id
            && let Some(slot) = c.cids.get_mut(n)
        {
            *slot = Some(id);
            n = n.saturating_add(1);
        }
    };
    if buf.get(pos) != Some(&OP_PACKAGE)
    {
        keep(id_value(buf, pos));
        return;
    }
    let Some((body, end)) = package(buf, pos.saturating_add(1))
    else
    {
        return;
    };
    let Some(&count) = buf.get(body)
    else
    {
        return;
    };
    let Some(limited) = buf.get(..end)
    else
    {
        return;
    };
    let mut p = body.saturating_add(1);
    for _ in 0..count
    {
        let Some(size) = data_size(limited, p)
        else
        {
            break;
        };
        keep(id_value(limited, p));
        p = p.saturating_add(size);
    }
}

/// The byte list of the Buffer at `pos`, truncated to its `BufferSize`.
fn crs_buffer(buf: &[u8], pos: usize) -> Option<&[u8]>
{
    if *buf.get(pos)? != OP_BUFFER
    {
        return None;
    }
    let (body, end) = package(buf, pos.saturating_add(1))?;
    let (declared, isz) = integer(buf, body)?;
    let list = buf.get(body.checked_add(isz)?..end)?;
    let keep = usize::try_from(declared).map_or(list.len(), |d| d.min(list.len()));
    list.get(..keep)
}

/// Walk `table` (an SDT: 36-byte header, then the AML term list up to the
/// header's length, bounded by the slice) and call `visit` for every Device
/// that has a static `_HID` or at least one static `_CID` and defines none of
/// `_HID`/`_CID`/`_CRS` as a Method. Returns the number of devices visited.
///
/// A table shorter than its header, or whose length field is below 36, visits
/// nothing.
pub fn devices<'a>(table: &'a [u8], visit: impl FnMut(&AmlDevice<'a>)) -> usize
{
    let Some(length) = sdt_length(table)
    else
    {
        return 0;
    };
    let end = usize::try_from(length).map_or(table.len(), |l| l.min(table.len()));
    let Some(body) = table.get(SDT_HDR_LEN..end)
    else
    {
        return 0;
    };
    let mut walker = Walker { visit, count: 0 };
    walker.term_list(body, 0, None);
    walker.count
}

// ── Resource template ─────────────────────────────────────────────────

/// One resource of a `_CRS` template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrsResource
{
    /// A memory range.
    Mmio
    {
        /// Physical base.
        base: u64,
        /// Size in bytes.
        size: u64,
    },
    /// An I/O port range.
    IoPort
    {
        /// First port.
        base: u16,
        /// Number of ports.
        count: u16,
    },
    /// An interrupt line. `isa` is true for a small IRQ descriptor (an ISA
    /// IRQ number, which devmgr routes through the MADT overrides on x86-64),
    /// false for an Extended Interrupt descriptor (a GSI / APLIC
    /// source). `mode` uses `syscall_abi::IRQ_MODE_LEVEL` and
    /// `syscall_abi::IRQ_MODE_ACTIVE_LOW`.
    Interrupt
    {
        /// The IRQ number or GSI.
        line: u32,
        /// `IRQ_MODE_*` bits.
        mode: u64,
        /// Whether the line may be shared.
        shared: bool,
        /// Whether `line` is an ISA IRQ number.
        isa: bool,
    },
}

/// Counts and bounds the resources reported.
struct Emit<F>
{
    visit: F,
    n: usize,
}

impl<F: FnMut(CrsResource)> Emit<F>
{
    /// Report `r`; false when the bound is already reached.
    fn push(&mut self, r: CrsResource) -> bool
    {
        if self.n >= MAX_CRS_RESOURCES
        {
            return false;
        }
        (self.visit)(r);
        self.n = self.n.saturating_add(1);
        true
    }
}

/// `IRQ_MODE_*` bits from the level and polarity flags.
const fn irq_mode(level: bool, active_low: bool) -> u64
{
    let mut mode = 0;
    if level
    {
        mode |= syscall_abi::IRQ_MODE_LEVEL;
    }
    if active_low
    {
        mode |= syscall_abi::IRQ_MODE_ACTIVE_LOW;
    }
    mode
}

/// Decode the resource template `crs` and call `visit` for each resource, in
/// template order, at most [`MAX_CRS_RESOURCES`]. Stops at the End Tag, at a
/// descriptor running past the slice, or at the bound. Returns how many it
/// visited.
pub fn crs_resources(crs: &[u8], visit: impl FnMut(CrsResource)) -> usize
{
    let mut em = Emit { visit, n: 0 };
    let mut pos = 0;
    while let Some(&tag) = crs.get(pos)
    {
        let (kind, body, next) = if tag & 0x80 == 0
        {
            let len = usize::from(tag & 7);
            let body_at = pos.saturating_add(1);
            let next = body_at.saturating_add(len);
            let Some(body) = crs.get(body_at..next)
            else
            {
                break;
            };
            ((tag >> 3) & 0xF, body, next)
        }
        else
        {
            let Some(len) = le(crs, pos.saturating_add(1), 2)
            else
            {
                break;
            };
            let Ok(len) = usize::try_from(len)
            else
            {
                break;
            };
            let body_at = pos.saturating_add(3);
            let next = body_at.saturating_add(len);
            let Some(body) = crs.get(body_at..next)
            else
            {
                break;
            };
            (tag & 0x7F, body, next)
        };
        let ok = if tag & 0x80 == 0
        {
            if kind == 0xF
            {
                break;
            }
            small(&mut em, kind, body)
        }
        else
        {
            large(&mut em, kind, body)
        };
        if !ok
        {
            break;
        }
        pos = next;
    }
    em.n
}

/// Decode a small descriptor; false when the bound is reached.
fn small<F: FnMut(CrsResource)>(em: &mut Emit<F>, kind: u8, body: &[u8]) -> bool
{
    match (kind, body.len())
    {
        (0x4, 2 | 3) =>
        {
            let mask = le(body, 0, 2).unwrap_or(0);
            let flags = body.get(2).copied();
            let (level, active_low, shared) = flags.map_or((false, false, false), |f| {
                (f & 1 == 0, f & (1 << 3) != 0, f & (1 << 4) != 0)
            });
            for bit in 0..16u32
            {
                if mask & (1 << bit) != 0
                    && !em.push(CrsResource::Interrupt {
                        line: bit,
                        mode: irq_mode(level, active_low),
                        shared,
                        isa: true,
                    })
                {
                    return false;
                }
            }
            true
        }
        (0x8, 7) =>
        {
            let base = le(body, 1, 2).and_then(|v| u16::try_from(v).ok());
            port(em, base, body.get(6).copied())
        }
        (0x9, 3) =>
        {
            let base = le(body, 0, 2).and_then(|v| u16::try_from(v & 0x3FF).ok());
            port(em, base, body.get(2).copied())
        }
        _ => true,
    }
}

/// Report an I/O port range if its length is non-zero.
fn port<F: FnMut(CrsResource)>(em: &mut Emit<F>, base: Option<u16>, count: Option<u8>) -> bool
{
    match (base, count)
    {
        (Some(base), Some(count)) if count > 0 => em.push(CrsResource::IoPort {
            base,
            count: u16::from(count),
        }),
        _ => true,
    }
}

/// Report a memory range if its size is non-zero.
fn mem<F: FnMut(CrsResource)>(em: &mut Emit<F>, base: Option<u64>, size: Option<u64>) -> bool
{
    match (base, size)
    {
        (Some(base), Some(size)) if size > 0 => em.push(CrsResource::Mmio { base, size }),
        _ => true,
    }
}

/// Whether an Address descriptor body is a memory range the device consumes
/// (resource type 0, general flags bit 0 set), not a window it produces.
fn is_consumed_memory(body: &[u8]) -> bool
{
    body.first() == Some(&0) && body.get(1).is_some_and(|f| f & 1 != 0)
}

/// Decode a large descriptor; false when the bound is reached.
fn large<F: FnMut(CrsResource)>(em: &mut Emit<F>, kind: u8, body: &[u8]) -> bool
{
    match (kind, body.len())
    {
        (0x06, 9) => mem(em, le(body, 1, 4), le(body, 5, 4)),
        (0x05, 17) =>
        {
            let (min, max) = (le(body, 1, 4), le(body, 5, 4));
            if min == max
            {
                mem(em, min, le(body, 13, 4))
            }
            else
            {
                true
            }
        }
        (0x09, 6..) =>
        {
            let flags = body.first().copied().unwrap_or(0);
            let count = usize::from(body.get(1).copied().unwrap_or(0));
            let avail = body.len().saturating_sub(2) / 4;
            for i in 0..count.min(avail)
            {
                let Some(line) = le(body, i.saturating_mul(4).saturating_add(2), 4)
                    .and_then(|v| u32::try_from(v).ok())
                else
                {
                    break;
                };
                if !em.push(CrsResource::Interrupt {
                    line,
                    mode: irq_mode(flags & (1 << 1) == 0, flags & (1 << 2) != 0),
                    shared: flags & (1 << 3) != 0,
                    isa: false,
                })
                {
                    return false;
                }
            }
            true
        }
        (0x07, 23..) if is_consumed_memory(body) => mem(em, le(body, 7, 4), le(body, 19, 4)),
        (0x0A, 43..) if is_consumed_memory(body) => mem(em, le(body, 11, 8), le(body, 35, 8)),
        _ => true,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // ── Builders ──────────────────────────────────────────────────────

    /// `PkgLength` of `payload` following bytes, forced to `n` encoded bytes.
    fn pkg_n(payload: usize, n: usize) -> Vec<u8>
    {
        let len = payload + n;
        if n == 1
        {
            assert!(len <= 63);
            return vec![len as u8];
        }
        let mut out = vec![(((n - 1) as u8) << 6) | (len & 0xF) as u8];
        for i in 0..n - 1
        {
            out.push((len >> (4 + 8 * i)) as u8);
        }
        out
    }

    /// `PkgLength` in its shortest form.
    fn pkg(payload: usize) -> Vec<u8>
    {
        let n = if payload + 1 <= 63
        {
            1
        }
        else if payload + 2 < (1 << 12)
        {
            2
        }
        else
        {
            3
        };
        pkg_n(payload, n)
    }

    fn seg(s: &str) -> Vec<u8>
    {
        assert_eq!(s.len(), 4);
        s.as_bytes().to_vec()
    }

    fn package_obj(op: &[u8], name: &str, body: &[u8], n: Option<usize>) -> Vec<u8>
    {
        let payload = 4 + body.len();
        let mut out = op.to_vec();
        out.extend(n.map_or_else(|| pkg(payload), |n| pkg_n(payload, n)));
        out.extend(seg(name));
        out.extend_from_slice(body);
        out
    }

    fn scope(name: &str, body: &[u8]) -> Vec<u8>
    {
        package_obj(&[OP_SCOPE], name, body, None)
    }

    fn device(name: &str, body: &[u8]) -> Vec<u8>
    {
        package_obj(&[0x5B, EXT_DEVICE], name, body, None)
    }

    fn method(name: &str) -> Vec<u8>
    {
        package_obj(&[OP_METHOD], name, &[0], None)
    }

    fn named(name: &str, value: &[u8]) -> Vec<u8>
    {
        let mut out = vec![OP_NAME];
        out.extend(seg(name));
        out.extend_from_slice(value);
        out
    }

    fn eisa(id: &str) -> Vec<u8>
    {
        let b = id.as_bytes();
        let s = (u32::from(b[0] - 0x40) << 26)
            | (u32::from(b[1] - 0x40) << 21)
            | (u32::from(b[2] - 0x40) << 16)
            | u32::from_str_radix(&id[3..], 16).unwrap();
        let mut out = vec![OP_DWORD];
        out.extend(s.swap_bytes().to_le_bytes());
        out
    }

    fn string(s: &str) -> Vec<u8>
    {
        let mut out = vec![OP_STRING];
        out.extend(s.as_bytes());
        out.push(0);
        out
    }

    fn buffer(list: &[u8]) -> Vec<u8>
    {
        let mut out = vec![OP_BUFFER];
        out.extend(pkg(2 + list.len()));
        out.extend([OP_BYTE, list.len() as u8]);
        out.extend_from_slice(list);
        out
    }

    fn package_val(items: &[Vec<u8>]) -> Vec<u8>
    {
        let body: Vec<u8> = items.iter().flatten().copied().collect();
        let mut out = vec![OP_PACKAGE];
        out.extend(pkg(1 + body.len()));
        out.push(items.len() as u8);
        out.extend(body);
        out
    }

    fn table(aml: &[u8]) -> Vec<u8>
    {
        let mut t = b"DSDT".to_vec();
        t.extend(((SDT_HDR_LEN + aml.len()) as u32).to_le_bytes());
        t.resize(SDT_HDR_LEN, 0);
        t.extend_from_slice(aml);
        t
    }

    fn collect(t: &[u8]) -> Vec<AmlDevice<'_>>
    {
        let mut v = Vec::new();
        let n = devices(t, |d| v.push(*d));
        assert_eq!(n, v.len());
        v
    }

    fn hid_str(d: &AmlDevice<'_>) -> Vec<u8>
    {
        d.hid.map(|i| i.as_bytes().to_vec()).unwrap_or_default()
    }

    /// A DWord Address Space descriptor of type memory with `flags`.
    fn addr32(flags: u8, min: u32, len: u32) -> Vec<u8>
    {
        let mut d = vec![0x87, 23, 0, 0, flags, 0];
        d.extend([0; 4]);
        d.extend(min.to_le_bytes());
        d.extend([0; 8]);
        d.extend(len.to_le_bytes());
        d
    }

    /// A QWord Address Space descriptor of type memory with `flags`.
    fn addr64(flags: u8, min: u64, len: u64) -> Vec<u8>
    {
        let mut d = vec![0x8A, 43, 0, 0, flags, 0];
        d.extend([0; 8]);
        d.extend(min.to_le_bytes());
        d.extend([0; 16]);
        d.extend(len.to_le_bytes());
        d
    }

    fn crs_list(crs: &[u8]) -> Vec<CrsResource>
    {
        let mut v = Vec::new();
        let n = crs_resources(crs, |r| v.push(r));
        assert_eq!(n, v.len());
        v
    }

    const COM1_CRS: [u8; 14] = [
        0x47, 1, 0xF8, 0x03, 0xF8, 0x03, 0, 8, // IO 0x3F8 count 8
        0x22, 0x10, 0x00, // IRQ 4
        0x79, 0, 0,
    ];

    fn com1_table() -> Vec<u8>
    {
        let com1 = device(
            "COM1",
            &[
                named("_HID", &eisa("PNP0501")),
                named("_UID", &[OP_ONE]),
                named("_STA", &[OP_BYTE, 0x0F]),
                named("_CRS", &buffer(&COM1_CRS[..13])),
            ]
            .concat(),
        );
        let rtc = device(
            "RTC_",
            &[
                named("_HID", &eisa("PNP0B00")),
                named(
                    "_CRS",
                    &buffer(&[0x47, 1, 0x70, 0, 0x70, 0, 0, 8, 0x22, 0x00, 0x01, 0x79, 0]),
                ),
            ]
            .concat(),
        );
        table(&scope("_SB_", &[com1, rtc].concat()))
    }

    // ── EISA, names, packages ─────────────────────────────────────────

    #[test]
    fn eisa_decode()
    {
        assert_eq!(eisa_id(0x0105_D041).unwrap().as_bytes(), b"PNP0501");
        assert_eq!(eisa_id(0x000B_D041).unwrap().as_bytes(), b"PNP0B00");
        assert_eq!(eisa_id(0), None);
        assert_eq!(eisa_id(0x0105_D0FF), None);
        assert_eq!(eisa("PNP0501"), vec![OP_DWORD, 0x41, 0xD0, 0x05, 0x01]);
    }

    #[test]
    fn package_forms()
    {
        for n in 1..=4
        {
            let mut b = pkg_n(5, n);
            let lead = b.len();
            b.extend([0; 5]);
            assert_eq!(package(&b, 0), Some((lead, lead + 5)), "n={n}");
        }
        // Hand-checked two-byte form: lead 0x41, next 0x02 -> len 0x21.
        assert_eq!(package(&[0x41, 0x02], 0), None);
        let mut big = vec![0x41, 0x02];
        big.resize(0x21, 0);
        assert_eq!(package(&big, 0), Some((2, 0x21)));
        // Past the end of the enclosing list.
        assert_eq!(package(&[0x0A, 0, 0], 0), None);
        assert_eq!(package(&[0x00], 0), None);
    }

    #[test]
    fn name_string_forms()
    {
        assert_eq!(name_string(b"\\_SB_", 0), Some((5, Some(*b"_SB_"))));
        assert_eq!(name_string(b"^^ABCD", 0), Some((6, Some(*b"ABCD"))));
        let mut dual = vec![0x2E];
        dual.extend(b"ABCDEFGH");
        assert_eq!(name_string(&dual, 0), Some((9, Some(*b"EFGH"))));
        let mut multi = vec![0x5C, 0x2F, 3];
        multi.extend(b"AAAABBBBCCC1");
        assert_eq!(name_string(&multi, 0), Some((15, Some(*b"CCC1"))));
        assert_eq!(name_string(&[0x00], 0), Some((1, None)));
        assert_eq!(name_string(b"1ABC", 0), None);
        assert_eq!(name_string(b"AB", 0), None);
        assert_eq!(name_string(b"\\", 0), None);
    }

    // ── Walk ──────────────────────────────────────────────────────────

    #[test]
    fn com1_and_rtc()
    {
        let t = com1_table();
        let devs = collect(&t);
        assert_eq!(devs.len(), 2);
        assert_eq!(hid_str(&devs[0]), b"PNP0501");
        assert_eq!(devs[0].uid, Some(1));
        assert_eq!(
            crs_list(devs[0].crs.unwrap()),
            vec![
                CrsResource::IoPort {
                    base: 0x3F8,
                    count: 8
                },
                CrsResource::Interrupt {
                    line: 4,
                    mode: 0,
                    shared: false,
                    isa: true
                },
            ]
        );
        assert_eq!(hid_str(&devs[1]), b"PNP0B00");
        assert_eq!(devs[1].uid, None);
        assert_eq!(
            crs_list(devs[1].crs.unwrap()),
            vec![
                CrsResource::IoPort {
                    base: 0x70,
                    count: 8
                },
                CrsResource::Interrupt {
                    line: 8,
                    mode: 0,
                    shared: false,
                    isa: true
                },
            ]
        );
    }

    #[test]
    fn string_hid_memory_and_ext_interrupt()
    {
        let crs = [
            0x86, 9, 0, 0, 0x00, 0x00, 0x10, 0x10, 0x00, 0x10, 0x00, 0x00, // Mem32Fixed
            0x89, 6, 0, 1, 0x01, 0x0A, 0x00, 0x00, 0x00, // ExtIRQ level high line 10
            0x79, 0,
        ];
        let t = table(&device(
            "UAR0",
            &[
                named("_HID", &string("PNP0501")),
                named("_CRS", &buffer(&crs)),
            ]
            .concat(),
        ));
        let devs = collect(&t);
        assert_eq!(devs.len(), 1);
        assert_eq!(hid_str(&devs[0]), b"PNP0501");
        assert_eq!(
            crs_list(devs[0].crs.unwrap()),
            vec![
                CrsResource::Mmio {
                    base: 0x1010_0000,
                    size: 0x1000
                },
                CrsResource::Interrupt {
                    line: 10,
                    mode: syscall_abi::IRQ_MODE_LEVEL,
                    shared: false,
                    isa: false
                },
            ]
        );
    }

    #[test]
    fn cid_package()
    {
        let cids = package_val(&[eisa("PNP0501"), eisa("PNP0500")]);
        let t = table(&device("DEV0", &named("_CID", &cids)));
        let devs = collect(&t);
        assert_eq!(devs.len(), 1);
        assert!(devs[0].hid.is_none());
        assert_eq!(devs[0].cids[0].unwrap().as_bytes(), b"PNP0501");
        assert_eq!(devs[0].cids[1].unwrap().as_bytes(), b"PNP0500");
        assert!(devs[0].cids[2].is_none());

        let many = package_val(&(0..6).map(|_| string("ACPI0001")).collect::<Vec<_>>());
        let t = table(&device("DEV0", &named("_CID", &many)));
        let devs = collect(&t);
        assert!(devs[0].cids.iter().all(Option::is_some));
    }

    #[test]
    fn dynamic_identity_not_reported()
    {
        let crs_method = device(
            "DEV1",
            &[named("_HID", &eisa("PNP0501")), method("_CRS")].concat(),
        );
        let hid_method = device(
            "DEV2",
            &[method("_HID"), named("_UID", &[OP_ZERO])].concat(),
        );
        let ok = device("DEV3", &named("_HID", &eisa("PNP0501")));
        let t = table(&[crs_method, hid_method, ok].concat());
        let devs = collect(&t);
        assert_eq!(devs.len(), 1);
    }

    #[test]
    fn nested_device()
    {
        let inner = device("INNR", &named("_HID", &string("ACPI0002")));
        let outer = device(
            "OUTR",
            &[named("_HID", &string("ACPI0001")), inner].concat(),
        );
        let t = table(&outer);
        let devs = collect(&t);
        assert_eq!(devs.len(), 2);
        assert_eq!(hid_str(&devs[0]), b"ACPI0002");
        assert_eq!(hid_str(&devs[1]), b"ACPI0001");
    }

    #[test]
    fn region_and_field_then_devices()
    {
        let mut region = vec![0x5B, EXT_OP_REGION];
        region.extend(seg("REG0"));
        region.extend([1, OP_WORD, 0xF8, 0x03, OP_BYTE, 8]);
        let mut field = vec![0x5B, EXT_FIELD];
        field.extend(pkg(6));
        field.extend(seg("REG0"));
        field.extend([0x01, 0x00]);
        let dev = device("DEV0", &named("_HID", &eisa("PNP0501")));
        let t = table(&scope("_SB_", &[region, field, dev].concat()));
        assert_eq!(collect(&t).len(), 1);
    }

    #[test]
    fn other_constructs_skipped()
    {
        let mut ext = vec![OP_EXTERNAL];
        ext.extend(seg("EXT0"));
        ext.extend([0x08, 0]);
        let mut mutex = vec![0x5B, EXT_MUTEX];
        mutex.extend(seg("MTX0"));
        mutex.push(0);
        let mut event = vec![0x5B, EXT_EVENT];
        event.extend(seg("EVT0"));
        let mut alias = vec![OP_ALIAS];
        alias.extend(seg("ALI0"));
        alias.extend(seg("ALI1"));
        let mut iff = vec![OP_IF];
        iff.extend(pkg(2));
        iff.extend([0, 0]);
        let dev = device("DEV0", &named("_HID", &eisa("PNP0501")));
        let t = table(&[ext, mutex, event, alias, iff, dev].concat());
        assert_eq!(collect(&t).len(), 1);
    }

    #[test]
    fn unknown_opcode_loses_only_its_scope()
    {
        let dev = |n: &str| device(n, &named("_HID", &eisa("PNP0501")));
        let a = scope("SCPA", &[dev("DEV1"), vec![0xEE], dev("DEV2")].concat());
        let b = scope("SCPB", &dev("DEV3"));
        let t = table(&[a, b].concat());
        assert_eq!(collect(&t).len(), 2);
    }

    #[test]
    fn depth_bound()
    {
        let nest = |n: usize| {
            let mut body = device("DEV0", &named("_HID", &eisa("PNP0501")));
            for _ in 0..n
            {
                body = scope("SCP0", &body);
            }
            table(&body)
        };
        assert_eq!(collect(&nest(MAX_DEPTH - 1)).len(), 1);
        assert_eq!(collect(&nest(MAX_DEPTH)).len(), 0);
        assert_eq!(collect(&nest(200)).len(), 0);
    }

    #[test]
    fn pkg_length_forms_in_devices()
    {
        for n in 1..=4
        {
            let body = named("_HID", &eisa("PNP0501"));
            let d = package_obj(&[0x5B, EXT_DEVICE], "DEV0", &body, Some(n));
            let t = table(&d);
            assert_eq!(collect(&t).len(), 1, "n={n}");
        }
    }

    #[test]
    fn package_past_parent_end()
    {
        let mut s = scope("SCP0", &device("DEV0", &named("_HID", &eisa("PNP0501"))));
        s[1] += 10;
        assert_eq!(collect(&table(&s)).len(), 0);
    }

    #[test]
    fn unterminated_string()
    {
        let mut v = vec![OP_STRING];
        v.extend(b"PNP05");
        let t = table(&device("DEV0", &named("_HID", &v)));
        assert_eq!(collect(&t).len(), 0);
    }

    #[test]
    fn long_or_empty_string_hid_ignored()
    {
        let t = table(&device(
            "DEV0",
            &named("_HID", &string("ABCDEFGHIJKLMNOPQ")),
        ));
        assert_eq!(collect(&t).len(), 0);
        let t = table(&device("DEV0", &named("_HID", &string(""))));
        assert_eq!(collect(&t).len(), 0);
    }

    #[test]
    fn string_uid_ignored()
    {
        let t = table(&device(
            "DEV0",
            &[named("_HID", &eisa("PNP0501")), named("_UID", &string("A"))].concat(),
        ));
        assert_eq!(collect(&t)[0].uid, None);
    }

    #[test]
    fn crs_truncated_to_buffer_size()
    {
        let mut b = vec![OP_BUFFER];
        b.extend(pkg(2 + 4));
        b.extend([OP_BYTE, 2, 1, 2, 3, 4]);
        let t = table(&device(
            "DEV0",
            &[named("_HID", &eisa("PNP0501")), named("_CRS", &b)].concat(),
        ));
        assert_eq!(collect(&t)[0].crs, Some(&[1_u8, 2][..]));
    }

    #[test]
    fn short_or_bad_header()
    {
        assert_eq!(devices(&[0; 10], |_| {}), 0);
        let mut t = com1_table();
        t[4..8].copy_from_slice(&20_u32.to_le_bytes());
        assert_eq!(devices(&t, |_| {}), 0);
    }

    #[test]
    fn every_prefix_is_safe()
    {
        let t = com1_table();
        let full = devices(&t, |_| {});
        assert_eq!(full, 2);
        for k in 0..=t.len()
        {
            assert!(devices(&t[..k], |_| {}) <= full, "k={k}");
        }
        let cids = package_val(&[eisa("PNP0501"), string("ACPI0001")]);
        let t2 = table(&scope(
            "SCP0",
            &device(
                "DEV0",
                &[named("_CID", &cids), named("_CRS", &buffer(&[0x79, 0]))].concat(),
            ),
        ));
        let full = devices(&t2, |_| {});
        for k in 0..=t2.len()
        {
            assert!(devices(&t2[..k], |_| {}) <= full, "k={k}");
        }
    }

    // ── Resource template ─────────────────────────────────────────────

    #[test]
    fn crs_irq_flags()
    {
        let l = crs_list(&[0x23, 0x00, 0x08, 0b0001_1000, 0x79, 0]);
        assert_eq!(
            l,
            vec![CrsResource::Interrupt {
                line: 11,
                mode: syscall_abi::IRQ_MODE_LEVEL | syscall_abi::IRQ_MODE_ACTIVE_LOW,
                shared: true,
                isa: true
            }]
        );
        let l = crs_list(&[0x23, 0x03, 0x00, 0x01, 0x79, 0]);
        assert_eq!(l.len(), 2);
        assert_eq!(
            l[1],
            CrsResource::Interrupt {
                line: 1,
                mode: 0,
                shared: false,
                isa: true
            }
        );
    }

    #[test]
    fn crs_descriptor_kinds()
    {
        let mut t = vec![0x4B, 0x60, 0x00, 0x05]; // fixed I/O 0x60 count 5
        t.extend([0x4B, 0x70, 0x00, 0x00]); // zero count: skipped
        t.extend([
            0x86, 9, 0, 0, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x10, 0x00, 0x00,
        ]); // Mem32Fixed
        // Memory32 with min == max: info, min, max, alignment, size.
        t.extend([
            0x85, 17, 0, 0, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
        ]);
        t.extend([0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00]);
        t.extend(addr32(1, 0x3000_0000, 0x1000));
        t.extend(addr64(1, 0x4000_0000, 0x8000));
        t.extend([0x79, 0]);
        let l = crs_list(&t);
        assert_eq!(l.len(), 5, "{l:?}");
        assert_eq!(
            l[0],
            CrsResource::IoPort {
                base: 0x60,
                count: 5
            }
        );
        assert_eq!(
            l[1],
            CrsResource::Mmio {
                base: 0xFE00_0000,
                size: 0x1000
            }
        );
        assert_eq!(
            l[2],
            CrsResource::Mmio {
                base: 0x2000,
                size: 0x400
            }
        );
        assert_eq!(
            l[3],
            CrsResource::Mmio {
                base: 0x3000_0000,
                size: 0x1000
            }
        );
        assert_eq!(
            l[4],
            CrsResource::Mmio {
                base: 0x4000_0000,
                size: 0x8000
            }
        );
    }

    #[test]
    fn crs_producer_window_ignored()
    {
        assert!(crs_list(&addr32(0, 0x3000_0000, 0x1000)).is_empty());
        assert!(crs_list(&addr64(0, 0x4000_0000, 0x8000)).is_empty());
        assert_eq!(crs_list(&addr32(1, 0x3000_0000, 0x1000)).len(), 1);
        assert_eq!(crs_list(&addr64(1, 0x4000_0000, 0x8000)).len(), 1);
    }

    #[test]
    fn sta_absent_device_not_reported()
    {
        let dev =
            |n: &str, sta: Vec<u8>| device(n, &[named("_HID", &eisa("PNP0501")), sta].concat());
        let t = table(
            &[
                dev("DEV1", named("_STA", &[OP_ZERO])),
                dev("DEV2", named("_STA", &[OP_BYTE, 0x0F])),
                dev("DEV3", method("_STA")),
                dev("DEV4", named("_STA", &[OP_BYTE, 0x0E])),
                dev("DEV5", Vec::new()),
            ]
            .concat(),
        );
        assert_eq!(collect(&t).len(), 3);
    }

    #[test]
    fn crs_bounds()
    {
        // Descriptor longer than the slice.
        assert!(crs_list(&[0x86, 9, 0, 0, 0]).is_empty());
        // Missing End Tag: ends with the slice.
        assert_eq!(crs_list(&[0x4B, 0x60, 0x00, 0x05]).len(), 1);
        // The 8-resource bound.
        let mut t = Vec::new();
        for _ in 0..12
        {
            t.extend([0x4B, 0x60, 0x00, 0x05]);
        }
        assert_eq!(crs_list(&t).len(), MAX_CRS_RESOURCES);
        // Extended interrupt count past its length.
        assert_eq!(crs_list(&[0x89, 6, 0, 1, 9, 0, 0, 0, 0, 0]).len(), 1);
        assert!(crs_list(&[]).is_empty());
    }
}
