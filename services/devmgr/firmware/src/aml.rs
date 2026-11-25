// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/aml.rs

//! A static walk of a DSDT or SSDT's AML namespace, and the adapter from the
//! resource templates it finds to the resources devmgr carves caps for.
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
//!
//! The AML encodings (`PkgLength`, `NameString`, data objects, the EISA ID)
//! and the resource-template decoder are those of the `aml` crate
//! (`shared/aml`); the walk and [`crs_resources`] use only its alloc-free
//! modules.

use ::aml::encoding::{
    self, EXT_BANK_FIELD, EXT_DEVICE, EXT_EVENT, EXT_FIELD, EXT_INDEX_FIELD, EXT_MUTEX,
    EXT_OP_REGION, EXT_POWER_RES, EXT_PROCESSOR, EXT_THERMAL_ZONE, OP_ALIAS, OP_BUFFER, OP_ELSE,
    OP_EXT_PREFIX, OP_EXTERNAL, OP_IF, OP_METHOD, OP_NAME, OP_PACKAGE, OP_SCOPE, OP_WHILE,
    data_object_len, integer, name_string, package,
};
use ::aml::resource::{self, AddressWidth, Resource, SPACE_MEMORY};

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Collect<'a>
{
    /// The last static `_HID`.
    pub(crate) hid: Option<Id>,
    /// The static `_CID` entries.
    pub(crate) cids: [Option<Id>; MAX_CIDS],
    /// The last integer `_UID`.
    pub(crate) uid: Option<u64>,
    /// The `_CRS` Buffer's byte list.
    pub(crate) crs: Option<&'a [u8]>,
    /// The `_STA` integer.
    pub(crate) sta: Option<u64>,
    /// Whether `_HID`, `_CID` or `_CRS` is a Method.
    pub(crate) dynamic: bool,
}

// ── Values ────────────────────────────────────────────────────────────

/// Decode a 32-bit EISA ID as AML stores it.
fn eisa_id(value: u32) -> Option<Id>
{
    Id::new(&encoding::eisa_id(value)?)
}

/// A `_HID`/`_CID` value at `pos`: an EISA-ID integer or a string.
fn id_value(buf: &[u8], pos: usize) -> Option<Id>
{
    if let Some((value, _)) = integer(buf, pos)
    {
        return eisa_id(u32::try_from(value).ok()?);
    }
    Id::new(encoding::string(buf, pos)?.0)
}

// ── Walk ────────────────────────────────────────────────────────────

/// One term of a term list, as the walk reads it (offsets into the list).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Term
{
    /// A `Scope` whose term list is `body..end`.
    Scope
    {
        /// The first byte after the scope's name.
        body: usize,
        /// The scope's end.
        end: usize,
    },
    /// A `Device` whose term list is `body..end`.
    Device
    {
        /// The first byte after the device's name.
        body: usize,
        /// The device's end.
        end: usize,
    },
    /// A `Name` whose value is the data object of `size` bytes at `value`.
    Name
    {
        /// The name's last segment.
        name: Option<[u8; 4]>,
        /// The offset of the value.
        value: usize,
        /// The value's encoded size.
        size: usize,
    },
    /// A `Method`, which is not entered.
    Method
    {
        /// The method name's last segment.
        name: Option<[u8; 4]>,
        /// The method's end.
        end: usize,
    },
    /// Any other construct the walk sizes and skips.
    Skip
    {
        /// The construct's end.
        end: usize,
    },
}

impl Term
{
    /// The offset after the term.
    pub(crate) const fn end(&self) -> Option<usize>
    {
        match *self
        {
            Self::Scope { end, .. }
            | Self::Device { end, .. }
            | Self::Method { end, .. }
            | Self::Skip { end } => Some(end),
            Self::Name { value, size, .. } => value.checked_add(size),
        }
    }
}

/// Read the term at `pos` of the term list `buf`; `None` for a construct the
/// walk cannot size, which stops the list.
pub(crate) fn term_step(buf: &[u8], pos: usize) -> Option<Term>
{
    match *buf.get(pos)?
    {
        OP_SCOPE =>
        {
            let (body, end, _) = named_package(buf, pos.saturating_add(1))?;
            Some(Term::Scope { body, end })
        }
        OP_NAME =>
        {
            let (nl, name) = name_string(buf, pos.saturating_add(1))?;
            let value = pos.checked_add(1)?.checked_add(nl)?;
            let size = data_object_len(buf, value)?;
            Some(Term::Name { name, value, size })
        }
        OP_METHOD =>
        {
            let (_, end, name) = named_package(buf, pos.saturating_add(1))?;
            Some(Term::Method { name, end })
        }
        OP_IF | OP_ELSE | OP_WHILE =>
        {
            let (_, end) = package(buf, pos.saturating_add(1))?;
            Some(Term::Skip { end })
        }
        OP_EXTERNAL =>
        {
            let (nl, _) = name_string(buf, pos.saturating_add(1))?;
            let end = pos.checked_add(1)?.checked_add(nl)?.checked_add(2)?;
            (end <= buf.len()).then_some(Term::Skip { end })
        }
        OP_ALIAS =>
        {
            let (a, _) = name_string(buf, pos.saturating_add(1))?;
            let after_a = pos.checked_add(1)?.checked_add(a)?;
            let (b, _) = name_string(buf, after_a)?;
            Some(Term::Skip {
                end: after_a.checked_add(b)?,
            })
        }
        OP_EXT_PREFIX => ext_term_step(buf, pos),
        _ => None,
    }
}

/// Read the `0x5B`-prefixed term at `pos`.
fn ext_term_step(buf: &[u8], pos: usize) -> Option<Term>
{
    let skip = |end| Some(Term::Skip { end });
    match *buf.get(pos.saturating_add(1))?
    {
        EXT_DEVICE =>
        {
            let (body, end, _) = named_package(buf, pos.saturating_add(2))?;
            Some(Term::Device { body, end })
        }
        EXT_FIELD | EXT_INDEX_FIELD | EXT_BANK_FIELD | EXT_PROCESSOR | EXT_POWER_RES
        | EXT_THERMAL_ZONE =>
        {
            let (_, end) = package(buf, pos.saturating_add(2))?;
            skip(end)
        }
        EXT_OP_REGION =>
        {
            let (nl, _) = name_string(buf, pos.saturating_add(2))?;
            let mut p = pos.checked_add(2)?.checked_add(nl)?.checked_add(1)?;
            for _ in 0..2
            {
                p = p.checked_add(integer(buf, p)?.1)?;
            }
            skip(p)
        }
        EXT_MUTEX =>
        {
            let (nl, _) = name_string(buf, pos.saturating_add(2))?;
            let end = pos.checked_add(2)?.checked_add(nl)?.checked_add(1)?;
            if end > buf.len()
            {
                return None;
            }
            skip(end)
        }
        EXT_EVENT =>
        {
            let (nl, _) = name_string(buf, pos.saturating_add(2))?;
            skip(pos.checked_add(2)?.checked_add(nl)?)
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

/// The device record of a finished device, if it qualifies: a static `_HID`
/// or at least one static `_CID`, none of `_HID`/`_CID`/`_CRS` a Method,
/// and no `_STA` Name with its present bit clear.
pub(crate) fn qualify<'a>(c: &Collect<'a>) -> Option<AmlDevice<'a>>
{
    let static_id = c.hid.is_some() || c.cids.iter().any(Option::is_some);
    let absent = c.sta.is_some_and(|sta| sta & 1 == 0);
    if c.dynamic || absent || !static_id
    {
        return None;
    }
    Some(AmlDevice {
        hid: c.hid,
        cids: c.cids,
        uid: c.uid,
        crs: c.crs,
    })
}

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
        let term = term_step(buf, pos)?;
        match term
        {
            Term::Scope { body, end } =>
            {
                self.term_list(buf.get(body..end)?, depth.saturating_add(1), None);
            }
            Term::Device { body, end } =>
            {
                let mut c = Collect::default();
                self.term_list(buf.get(body..end)?, depth.saturating_add(1), Some(&mut c));
                if let Some(device) = qualify(&c)
                {
                    (self.visit)(&device);
                    self.count = self.count.saturating_add(1);
                }
            }
            Term::Name { name, value, size } =>
            {
                if let (Some(c), Some(name)) = (dev.as_deref_mut(), name)
                {
                    record(c, name, buf, value, size);
                }
            }
            Term::Method { name, .. } =>
            {
                if let Some(c) = dev.as_deref_mut()
                    && matches!(name, Some(n) if is_dynamic_name(n))
                {
                    c.dynamic = true;
                }
            }
            Term::Skip { .. } =>
            {}
        }
        term.end()
    }
}

/// Whether a `Method` of this name makes the device's identity dynamic.
fn is_dynamic_name(name: [u8; 4]) -> bool
{
    matches!(&name, b"_HID" | b"_CID" | b"_CRS")
}

/// Record the value of `Name(name, <data at value..value+size>)` into `c`.
pub(crate) fn record<'a>(
    c: &mut Collect<'a>,
    name: [u8; 4],
    buf: &'a [u8],
    value: usize,
    size: usize,
)
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
        let Some(size) = data_object_len(limited, p)
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

    /// Report an I/O port range if its length is non-zero.
    fn port(&mut self, base: u16, count: u8) -> bool
    {
        count == 0
            || self.push(CrsResource::IoPort {
                base,
                count: u16::from(count),
            })
    }

    /// Report a memory range if its size is non-zero.
    fn mem(&mut self, base: u64, size: u64) -> bool
    {
        size == 0 || self.push(CrsResource::Mmio { base, size })
    }
}

/// `IRQ_MODE_*` bits from the level and polarity flags.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`level` and `active_low` are the descriptor's trigger and polarity flags, encoded \
              into the `IRQ_MODE_*` bits"
)]
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
/// descriptor running past the slice, or at the bound; skips a descriptor
/// whose length does not fit its kind. Returns how many it visited.
///
/// Reported: the lines of an IRQ or Extended Interrupt descriptor, an I/O
/// Port or Fixed I/O Port range, a 32-bit Fixed Memory range, a 32-bit
/// Memory range whose minimum and maximum are equal, and a `DWord` or `QWord`
/// memory range the device consumes. A zero-length range, and every other
/// descriptor, is skipped.
pub fn crs_resources(crs: &[u8], visit: impl FnMut(CrsResource)) -> usize
{
    let mut em = Emit { visit, n: 0 };
    for descriptor in resource::descriptors(crs)
    {
        let ok = match descriptor
        {
            Ok(r) => report(&mut em, &r),
            Err(resource::Error::Malformed { .. }) => true,
            Err(resource::Error::Truncated) => false,
        };
        if !ok
        {
            break;
        }
    }
    em.n
}

/// Report the resources of the descriptor `r`; false when the bound is
/// reached.
fn report<F: FnMut(CrsResource)>(em: &mut Emit<F>, r: &Resource<'_>) -> bool
{
    match *r
    {
        Resource::Irq(irq) =>
        {
            let mode = irq_mode(irq.level(), irq.active_low());
            (0..16u32)
                .filter(|bit| irq.mask & (1 << bit) != 0)
                .all(|line| {
                    em.push(CrsResource::Interrupt {
                        line,
                        mode,
                        shared: irq.shared(),
                        isa: true,
                    })
                })
        }
        Resource::ExtendedIrq(irq) =>
        {
            let mode = irq_mode(irq.level(), irq.active_low());
            irq.lines().all(|line| {
                em.push(CrsResource::Interrupt {
                    line,
                    mode,
                    shared: irq.shared(),
                    isa: false,
                })
            })
        }
        Resource::Io { min, len, .. } => em.port(min, len),
        Resource::FixedIo { base, len } => em.port(base, len),
        Resource::FixedMemory32 { base, len, .. } => em.mem(u64::from(base), u64::from(len)),
        Resource::Memory32 { min, max, len, .. } =>
        {
            min != max || em.mem(u64::from(min), u64::from(len))
        }
        Resource::Address(a) =>
        {
            let consumed_memory = a.space == SPACE_MEMORY
                && a.consumer()
                && matches!(a.width, AddressWidth::DWord | AddressWidth::QWord);
            !consumed_memory || em.mem(a.min, a.length)
        }
        Resource::Memory24 { .. } | Resource::GenericRegister { .. } | Resource::Other { .. } =>
        {
            true
        }
    }
}

#[cfg(test)]
mod tests
{
    use ::aml::encoding::{OP_BYTE, OP_DWORD, OP_ONE, OP_STRING, OP_WORD, OP_ZERO};

    use super::*;

    // ── Builders ──────────────────────────────────────────────────────

    /// `PkgLength` of `payload` following bytes, forced to `n` encoded bytes.
    fn pkg_n(payload: usize, n: usize) -> Vec<u8>
    {
        let len = payload + n;
        if n == 1
        {
            assert!(len <= 63);
            return vec![u8::try_from(len).unwrap()];
        }
        let mut out = vec![(u8::try_from(n - 1).unwrap() << 6) | u8::try_from(len & 0xF).unwrap()];
        for i in 0..n - 1
        {
            out.push(u8::try_from((len >> (4 + 8 * i)) & 0xff).unwrap());
        }
        out
    }

    /// `PkgLength` in its shortest form.
    fn pkg(payload: usize) -> Vec<u8>
    {
        let n = if payload < 63
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
        out.extend([OP_BYTE, u8::try_from(list.len()).unwrap()]);
        out.extend_from_slice(list);
        out
    }

    fn package_val(items: &[Vec<u8>]) -> Vec<u8>
    {
        let body: Vec<u8> = items.iter().flatten().copied().collect();
        let mut out = vec![OP_PACKAGE];
        out.extend(pkg(1 + body.len()));
        out.push(u8::try_from(items.len()).unwrap());
        out.extend(body);
        out
    }

    fn table(aml: &[u8]) -> Vec<u8>
    {
        let mut t = b"DSDT".to_vec();
        t.extend(
            u32::try_from(SDT_HDR_LEN + aml.len())
                .unwrap()
                .to_le_bytes(),
        );
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
        d.hid.map_or_default(|i| i.as_bytes().to_vec())
    }

    /// A `DWord` Address Space descriptor of type memory with `flags`.
    fn addr32(flags: u8, min: u32, len: u32) -> Vec<u8>
    {
        let mut d = vec![0x87, 23, 0, 0, flags, 0];
        d.extend([0; 4]);
        d.extend(min.to_le_bytes());
        d.extend([0; 8]);
        d.extend(len.to_le_bytes());
        d
    }

    /// A `QWord` Address Space descriptor of type memory with `flags`.
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

    // ── EISA ──────────────────────────────────────────────────────────

    #[test]
    fn eisa_decode()
    {
        assert_eq!(eisa_id(0x0105_D041).unwrap().as_bytes(), b"PNP0501");
        assert_eq!(eisa_id(0), None);
        assert_eq!(eisa("PNP0501"), vec![OP_DWORD, 0x41, 0xD0, 0x05, 0x01]);
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
        assert_eq!(collect(&t)[0].crs, Some(&[1u8, 2][..]));
    }

    #[test]
    fn short_or_bad_header()
    {
        assert_eq!(devices(&[0; 10], |_| {}), 0);
        let mut t = com1_table();
        t[4..8].copy_from_slice(&20u32.to_le_bytes());
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
        assert_eq!(
            crs_list(&addr32(0, 0x3000_0000, 0x1000)),
            [] as [CrsResource; 0]
        );
        assert_eq!(
            crs_list(&addr64(0, 0x4000_0000, 0x8000)),
            [] as [CrsResource; 0]
        );
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
        assert_eq!(crs_list(&[0x86, 9, 0, 0, 0]), [] as [CrsResource; 0]);
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
        assert_eq!(crs_list(&[]), [] as [CrsResource; 0]);
    }
}

/// The proofs of the walk's steps and of the adapter (docs/testing.md
/// § Bounded verification), on the checks of `crate::property::aml`: the
/// term at any place of a term list, the record of a `Name`'s value, the
/// rule that reports a device, one descriptor of every kind and length
/// through the adapter, and every short template whole. The term lists'
/// loops and their recursion into a `Scope` or `Device` are left to the fuzz
/// target `devmgr-firmware`, the replay of the checked-in inputs and the
/// unit tests.
#[cfg(kani)]
mod proofs
{
    use ::aml::encoding::{
        EXT_BANK_FIELD, EXT_DEVICE, EXT_EVENT, EXT_FIELD, EXT_INDEX_FIELD, EXT_MUTEX,
        EXT_OP_REGION, EXT_POWER_RES, EXT_PROCESSOR, EXT_THERMAL_ZONE, OP_ALIAS, OP_ELSE,
        OP_EXT_PREFIX, OP_EXTERNAL, OP_IF, OP_METHOD, OP_NAME, OP_SCOPE, OP_WHILE,
    };

    use super::{Collect, Id, MAX_CIDS};
    use crate::property::aml as property;

    /// Every term list of `N` bytes whose term at place 1 starts with
    /// `lead` reads that term as the grammar's construct. A construct longer
    /// than the place leaves is one cut short.
    fn term_at_place_one_holds<const N: usize>(lead: &[u8])
    {
        let mut bytes: [u8; N] = kani::any();
        bytes[1..=lead.len()].copy_from_slice(lead);
        let _ = property::term_holds(&bytes, 1);
    }

    /// Every term at place 1 of a term list of 3 bytes, of any lead, reads
    /// as the grammar's construct: a lead the walk does not size reads as
    /// none, and every other is cut short. The loops are the parent prefixes.
    #[kani::proof]
    #[kani::unwind(4)]
    fn every_term_reads_as_its_construct()
    {
        term_at_place_one_holds::<3>(&[]);
    }

    /// Every `Scope` at place 1 of a term list of 11 bytes reads as its
    /// construct: 10 bytes hold it with a one-segment or a dual name and a
    /// body, and every `PkgLength` form. The loops are the parent prefixes
    /// and the name's segments.
    #[kani::proof]
    #[kani::unwind(11)]
    fn every_scope_reads_as_its_construct()
    {
        term_at_place_one_holds::<11>(&[OP_SCOPE]);
    }

    /// Every `Method` at place 1 of a term list of 11 bytes reads as its
    /// construct, as a `Scope` does.
    #[kani::proof]
    #[kani::unwind(11)]
    fn every_method_reads_as_its_construct()
    {
        term_at_place_one_holds::<11>(&[OP_METHOD]);
    }

    /// Every `Device` at place 1 of a term list of 12 bytes reads as its
    /// construct, as a `Scope` does after its two-byte opcode.
    #[kani::proof]
    #[kani::unwind(11)]
    fn every_device_reads_as_its_construct()
    {
        term_at_place_one_holds::<12>(&[OP_EXT_PREFIX, EXT_DEVICE]);
    }

    /// Every `Name` at place 1 of a term list of 11 bytes reads as its
    /// construct: 10 bytes hold a one-segment name with a value of any kind
    /// up to a dword, and a dual name with a byte. The loops are the name's
    /// segments and a string's bytes.
    #[kani::proof]
    #[kani::unwind(11)]
    fn every_name_reads_as_its_construct()
    {
        term_at_place_one_holds::<11>(&[OP_NAME]);
    }

    /// Every `If`, `Else` and `While` at place 1 of a term list of 8 bytes
    /// reads as the construct it skips, every `PkgLength` form among them.
    /// The loop is the `PkgLength` bytes.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_conditional_reads_as_its_skip()
    {
        match kani::any::<u8>() % 3
        {
            0 => term_at_place_one_holds::<8>(&[OP_IF]),
            1 => term_at_place_one_holds::<8>(&[OP_ELSE]),
            _ => term_at_place_one_holds::<8>(&[OP_WHILE]),
        }
    }

    /// Every `External` and `Alias` at place 1 of a term list of 11 bytes
    /// reads as the construct it skips: 10 bytes hold an `External` of a
    /// one-segment or a dual name and an `Alias` of two one-segment names.
    /// The loops are the names' segments.
    #[kani::proof]
    #[kani::unwind(11)]
    fn every_external_and_alias_reads_as_its_skip()
    {
        if kani::any()
        {
            term_at_place_one_holds::<11>(&[OP_EXTERNAL]);
        }
        else
        {
            term_at_place_one_holds::<11>(&[OP_ALIAS]);
        }
    }

    /// Every `0x5B` construct the walk sizes by its `PkgLength`, at place 1
    /// of a term list of 8 bytes, reads as the construct it skips: a
    /// `Field`, `IndexField`, `BankField`, `Processor`, `PowerResource`
    /// and `ThermalZone`, every `PkgLength` form among them. The loop is
    /// the `PkgLength` bytes.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_extended_package_reads_as_its_skip()
    {
        let ext = [
            EXT_FIELD,
            EXT_INDEX_FIELD,
            EXT_BANK_FIELD,
            EXT_PROCESSOR,
            EXT_POWER_RES,
            EXT_THERMAL_ZONE,
        ];
        let which: usize = kani::any();
        if let Some(&code) = ext.get(which)
        {
            term_at_place_one_holds::<8>(&[OP_EXT_PREFIX, code]);
        }
    }

    /// Every `OperationRegion`, `Mutex` and `Event` at place 1 of a term
    /// list of 12 bytes reads as the construct it skips: 12 bytes hold each
    /// with a one-segment name, a region with a byte offset and length, and a
    /// `Mutex` and an `Event` with a dual name. The loops are the name's
    /// segments and an integer's bytes.
    #[kani::proof]
    #[kani::unwind(11)]
    fn every_extended_named_object_reads_as_its_skip()
    {
        match kani::any::<u8>() % 3
        {
            0 => term_at_place_one_holds::<12>(&[OP_EXT_PREFIX, EXT_OP_REGION]),
            1 => term_at_place_one_holds::<12>(&[OP_EXT_PREFIX, EXT_MUTEX]),
            _ => term_at_place_one_holds::<12>(&[OP_EXT_PREFIX, EXT_EVENT]),
        }
    }

    /// Every `Name` called `name` records its value of any kind at place 1
    /// of `N` bytes, a value longer than the place leaves being one cut
    /// short, into a device that holds nothing and one that holds every
    /// field.
    fn name_at_place_one_records<const N: usize>(name: [u8; 4])
    {
        let bytes: [u8; N] = kani::any();
        if let Some(size) = ::aml::encoding::data_object_len(&bytes, 1)
        {
            property::record_holds(&bytes, name, 1, size);
        }
    }

    /// Every `_HID`, `_UID` and `_STA`, and a `_ADR` the walk ignores,
    /// records its value of any kind at place 1 of 9 bytes: 8 bytes hold a
    /// dword EISA ID, a string ID of up to 6 characters, and every integer
    /// form up to a dword. The loops are a string's bytes and an integer's.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_identity_name_records_as_its_value()
    {
        match kani::any::<u8>() % 4
        {
            0 => name_at_place_one_records::<9>(*b"_HID"),
            1 => name_at_place_one_records::<9>(*b"_UID"),
            2 => name_at_place_one_records::<9>(*b"_STA"),
            _ => name_at_place_one_records::<9>(*b"_ADR"),
        }
    }

    /// Every `_CID` records its value of any kind at place 1 of 9 bytes: 8
    /// bytes hold one dword EISA ID or string ID, and a `Package` of two
    /// one-character string IDs or of an ID and an element that is none. The
    /// loops are a package's elements and a string's bytes.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_cid_records_as_its_ids()
    {
        name_at_place_one_records::<9>(*b"_CID");
    }

    /// Every `_CRS` records its value of any kind at place 1 of 9 bytes: 8
    /// bytes hold a `Buffer` with every size-integer form and a byte list
    /// longer and shorter than its size. The loop is an integer's bytes.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_crs_records_as_its_list()
    {
        name_at_place_one_records::<9>(*b"_CRS");
    }

    /// Every collected device is reported by its identity, its `_STA` and its
    /// methods alone, with the fields it holds. The loop is the `_CID` slots.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_device_reports_by_its_identity()
    {
        let id = |present: bool| if present { Id::new(b"PNP0501") } else { None };
        let mut cids = [None; MAX_CIDS];
        for cid in &mut cids
        {
            *cid = id(kani::any());
        }
        let list = [0u8; 2];
        let c = Collect {
            hid: id(kani::any()),
            cids,
            uid: kani::any(),
            crs: if kani::any() { Some(&list[..]) } else { None },
            sta: kani::any(),
            dynamic: kani::any(),
        };
        property::qualify_holds(&c);
    }

    /// Every template that is one large descriptor of kind `key` and a body
    /// of `N` bytes less its 3-byte header reports as its fields.
    fn large_descriptor_holds<const N: usize>(key: u8)
    {
        let mut bytes: [u8; N] = kani::any();
        bytes[0] = key;
        let body = u16::try_from(N - 3).unwrap_or(0);
        bytes[1..3].copy_from_slice(&body.to_le_bytes());
        property::crs_holds(&bytes);
    }

    /// Every large descriptor the adapter reads reports as its fields: a
    /// 32-bit Fixed Memory range, a 32-bit Memory range, a `DWord` and a
    /// `QWord` address space at their least length, and an Extended
    /// Interrupt of up to two lines, its count of any value. The loops are
    /// the Extended Interrupt's lines and the comparison of the 8 resources
    /// the bound holds.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_large_descriptor_reports_as_its_resources()
    {
        match kani::any::<u8>() % 5
        {
            0 => large_descriptor_holds::<12>(0x86),
            1 => large_descriptor_holds::<20>(0x85),
            2 => large_descriptor_holds::<26>(0x87),
            3 => large_descriptor_holds::<46>(0x8A),
            _ => large_descriptor_holds::<13>(0x89),
        }
    }

    /// Every template that is one small descriptor the adapter reads reports
    /// as its fields: an IRQ with and without its flags, an I/O Port and a
    /// Fixed I/O Port. The loops are an IRQ's 16 lines and the comparison of
    /// the 8 resources the bound holds.
    #[kani::proof]
    #[kani::unwind(17)]
    fn every_small_descriptor_reports_as_its_resources()
    {
        match kani::any::<u8>() % 4
        {
            0 => small_descriptor_holds::<3>(0x22),
            1 => small_descriptor_holds::<4>(0x23),
            2 => small_descriptor_holds::<8>(0x47),
            _ => small_descriptor_holds::<4>(0x4B),
        }
    }

    /// Every template that is the small descriptor `tag` of `N` bytes
    /// reports as its fields.
    fn small_descriptor_holds<const N: usize>(tag: u8)
    {
        let mut bytes: [u8; N] = kani::any();
        bytes[0] = tag;
        property::crs_holds(&bytes);
    }

    /// Every template of 4 bytes reports as its descriptors whole: up to 4
    /// descriptors of one byte, the End Tag, an IRQ before and after others,
    /// a large descriptor's header, and a descriptor that runs past the end.
    /// The loops are the descriptors and an IRQ's 16 lines.
    #[kani::proof]
    #[kani::unwind(17)]
    fn every_short_template_reports_as_its_resources()
    {
        let bytes: [u8; 4] = kani::any();
        property::crs_holds(&bytes);
    }
}
