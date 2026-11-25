// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/property/aml.rs

//! The checks of [`crate::aml`]: the static namespace walk of a DSDT or
//! SSDT, [`aml::devices`], read from the AML grammar of ACPI 6.5 § 20, and
//! the resource-template adapter, [`aml::crs_resources`], read from the
//! resource descriptors of ACPI 6.5 § 6.4. The encodings (`PkgLength`,
//! `NameString`, data objects, the EISA ID, the descriptors) are read here
//! afresh, apart from the `aml` crate the decoder is built on.

extern crate alloc;

use alloc::vec::Vec;

use super::{byte, bytes_at, le16, le32, le64, sdt_length};
use crate::aml::{self, Collect, CrsResource, Id, MAX_CIDS, MAX_CRS_RESOURCES, MAX_DEPTH, Term};

/// Check the walk and the adapter on `input`: the input read as a DSDT,
/// each device's `_CRS` template, and the input read as a template.
pub(crate) fn aml_holds(input: &[u8])
{
    for crs in walk_holds(input)
    {
        crs_holds(crs);
        descriptor_steps_hold(crs);
    }
    crs_holds(input);
    descriptor_steps_hold(input);
}

/// Check the adapter's step on each descriptor the walk of the template
/// `crs` reaches, after every count of resources.
fn descriptor_steps_hold(crs: &[u8])
{
    let mut pos = 0usize;
    while let Some(rest) = crs.get(pos..)
    {
        for prior in 0..=MAX_CRS_RESOURCES
        {
            descriptor_holds(rest, prior);
        }
        let Some(next) = template_step(crs, pos, &mut Reported::default())
        else
        {
            break;
        };
        pos = next;
    }
}

// ── Encodings ───────────────────────────────────────────────────────────────

/// The package whose `PkgLength` is at `lead`: its body's first byte and its
/// end, which counts from `lead` and lies inside `bytes`. The lead byte's
/// bits 7:6 count the bytes that follow it; with none, bits 5:0 are the
/// length, else bits 3:0 are its low nibble and each following byte the next
/// 8 bits.
fn package(bytes: &[u8], lead: usize) -> Option<(usize, usize)>
{
    let b0 = byte(bytes, lead)?;
    let follow = usize::from(b0 >> 6);
    let mut length = usize::from(if follow == 0 { b0 & 0x3F } else { b0 & 0x0F });
    for i in 0..follow
    {
        let b = usize::from(byte(bytes, lead.checked_add(1)?.checked_add(i)?)?);
        length |= b << i.checked_mul(8)?.checked_add(4)?;
    }
    let body = lead.checked_add(1)?.checked_add(follow)?;
    let end = lead.checked_add(length)?;
    (body <= end && end <= bytes.len()).then_some((body, end))
}

/// Whether `b` may open a `NameSeg`: `A`-`Z` or `_`.
const fn lead_name_char(b: u8) -> bool
{
    b.is_ascii_uppercase() || b == b'_'
}

/// The `NameString` at `pos`: its size and its last `NameSeg`. A root
/// prefix (`\\`) or a run of parent prefixes (`^`), then `NullName` (0x00),
/// a dual name (0x2E and two segments), a multi name (0x2F, a count, and
/// that many segments) or one segment; a segment is a lead name character and
/// three of `A`-`Z`, `_`, `0`-`9`.
fn name_string(bytes: &[u8], pos: usize) -> Option<(usize, Option<[u8; 4]>)>
{
    let mut p = pos;
    if byte(bytes, p)? == b'\\'
    {
        p = p.checked_add(1)?;
    }
    else
    {
        while byte(bytes, p)? == b'^'
        {
            p = p.checked_add(1)?;
        }
    }
    let (segments, first) = match byte(bytes, p)?
    {
        0x00 => return Some((p.checked_add(1)?.checked_sub(pos)?, None)),
        0x2E => (2, p.checked_add(1)?),
        0x2F => (
            usize::from(byte(bytes, p.checked_add(1)?)?),
            p.checked_add(2)?,
        ),
        _ => (1, p),
    };
    let mut last = None;
    for s in 0..segments
    {
        let seg: [u8; 4] = bytes_at(bytes, s.checked_mul(4)?.checked_add(first)?)?;
        let [lead, b1, b2, b3] = seg;
        if !lead_name_char(lead)
            || ![b1, b2, b3]
                .iter()
                .all(|&b| lead_name_char(b) || b.is_ascii_digit())
        {
            return None;
        }
        last = Some(seg);
    }
    Some((
        segments
            .checked_mul(4)?
            .checked_add(first)?
            .checked_sub(pos)?,
        last,
    ))
}

/// The integer data object at `pos`: `ZeroOp`, `OneOp`, `OnesOp`, or a
/// byte, word, dword or qword after its prefix (0x0A, 0x0B, 0x0C, 0x0E). Its
/// value and size.
fn integer(bytes: &[u8], pos: usize) -> Option<(u64, usize)>
{
    let at = pos.checked_add(1)?;
    match byte(bytes, pos)?
    {
        0x00 => Some((0, 1)),
        0x01 => Some((1, 1)),
        0xFF => Some((u64::MAX, 1)),
        0x0A => Some((u64::from(byte(bytes, at)?), 2)),
        0x0B => Some((u64::from(le16(bytes, at)?), 3)),
        0x0C => Some((u64::from(le32(bytes, at)?), 5)),
        0x0E => Some((le64(bytes, at)?, 9)),
        _ => None,
    }
}

/// The string data object at `pos`: 0x0D, then bytes up to a NUL. Its bytes
/// and its size.
fn string(bytes: &[u8], pos: usize) -> Option<(&[u8], usize)>
{
    if byte(bytes, pos)? != 0x0D
    {
        return None;
    }
    let first = pos.checked_add(1)?;
    let mut nul = first;
    while byte(bytes, nul)? != 0
    {
        nul = nul.checked_add(1)?;
    }
    Some((
        bytes.get(first..nul)?,
        nul.checked_add(1)?.checked_sub(pos)?,
    ))
}

/// The size of the data object at `pos`: an integer, a string, a `Buffer`
/// (0x11), `Package` (0x12) or `VarPackage` (0x13) sized by its
/// `PkgLength`, or `RevisionOp` (0x5B 0x30).
fn data_object_len(bytes: &[u8], pos: usize) -> Option<usize>
{
    if let Some((_, size)) = integer(bytes, pos)
    {
        return Some(size);
    }
    match byte(bytes, pos)?
    {
        0x0D => string(bytes, pos).map(|(_, size)| size),
        0x11..=0x13 => package(bytes, pos.checked_add(1)?)?.1.checked_sub(pos),
        0x5B if byte(bytes, pos.checked_add(1)?)? == 0x30 => Some(2),
        _ => None,
    }
}

/// An identifier as the property reads it: 1 to 16 bytes of `!` to `~`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Ident
{
    bytes: [u8; 16],
    len: usize,
}

impl Ident
{
    /// `text` as an identifier, if it is one.
    fn new(text: &[u8]) -> Option<Self>
    {
        if text.is_empty() || text.len() > 16 || !text.iter().all(|b| (0x21..=0x7E).contains(b))
        {
            return None;
        }
        let mut bytes = [0; 16];
        bytes.get_mut(..text.len())?.copy_from_slice(text);
        Some(Self {
            bytes,
            len: text.len(),
        })
    }

    /// Whether the decoder's `id` is this identifier.
    fn is(&self, id: &Id) -> bool
    {
        self.bytes.get(..self.len) == Some(id.as_bytes())
    }
}

/// The EISA ID that the dword `value` stores, as AML holds it: its first two
/// bytes, big-endian, hold three letters of 5 bits each (1 for `A` to 26 for
/// `Z`) under a clear top bit; its last two, four hexadecimal digits, high
/// nibble first.
fn eisa_id(value: u32) -> Option<Ident>
{
    let [b0, b1, b2, b3] = value.to_le_bytes();
    let mut text = [0u8; 7];
    let letters = [(b0 >> 2) & 0x1F, ((b0 & 0x03) << 3) | (b1 >> 5), b1 & 0x1F];
    for (slot, letter) in text.iter_mut().zip(letters)
    {
        if !(1..=26).contains(&letter)
        {
            return None;
        }
        *slot = b'@'.checked_add(letter)?;
    }
    let digits = [b2 >> 4, b2 & 0x0F, b3 >> 4, b3 & 0x0F];
    for (slot, digit) in text.iter_mut().skip(3).zip(digits)
    {
        *slot = *b"0123456789ABCDEF".get(usize::from(digit))?;
    }
    Ident::new(&text)
}

/// A `_HID` or `_CID` value at `pos`: an integer of at most 32 bits read as an
/// EISA ID, or a string that is an identifier.
fn id_value(bytes: &[u8], pos: usize) -> Option<Ident>
{
    if let Some((value, _)) = integer(bytes, pos)
    {
        return eisa_id(u32::try_from(value).ok()?);
    }
    Ident::new(string(bytes, pos)?.0)
}

// ── Walk ────────────────────────────────────────────────────────────────────

/// The term at `pos` of the term list `bytes` (which ends the list), as
/// the walk reads it: `Scope` (0x10), `Method` (0x14) and `Device` (0x5B 0x82)
/// as a package whose name ends inside it; `Name` (0x08) as its name and data
/// object; `If`, `Else`, `While` (0xA0 to 0xA2) and `Field`, `IndexField`,
/// `BankField`, `Processor`, `PowerResource`, `ThermalZone` (0x5B 0x81, 0x86,
/// 0x87, 0x83 to 0x85) by their package; `External` (0x15) as a name and two
/// bytes; `Alias` (0x06) as two names; `OperationRegion` (0x5B 0x80) as a
/// name, a space byte and two integers; `Mutex` (0x5B 0x01) as a name and a
/// byte; `Event` (0x5B 0x02) as a name. Anything else, or a construct cut
/// short, is none.
fn read_term(bytes: &[u8], pos: usize) -> Option<Term>
{
    let after = |n: usize| pos.checked_add(n);
    let named = |lead: usize| -> Option<(usize, usize, Option<[u8; 4]>)> {
        let (name_at, end) = package(bytes, lead)?;
        let (size, last) = name_string(bytes.get(..end)?, name_at)?;
        Some((name_at.checked_add(size)?, end, last))
    };
    let named_end = |at: usize, extra: usize| -> Option<usize> {
        let end = at
            .checked_add(name_string(bytes, at)?.0)?
            .checked_add(extra)?;
        (end <= bytes.len()).then_some(end)
    };
    let skip = |end| Some(Term::Skip { end });
    match byte(bytes, pos)?
    {
        0x10 =>
        {
            let (body, end, _) = named(after(1)?)?;
            Some(Term::Scope { body, end })
        }
        0x14 =>
        {
            let (_, end, name) = named(after(1)?)?;
            Some(Term::Method { name, end })
        }
        0x08 =>
        {
            let (size, name) = name_string(bytes, after(1)?)?;
            let value = after(1)?.checked_add(size)?;
            Some(Term::Name {
                name,
                value,
                size: data_object_len(bytes, value)?,
            })
        }
        0xA0..=0xA2 => skip(package(bytes, after(1)?)?.1),
        0x15 => skip(named_end(after(1)?, 2)?),
        0x06 => skip(named_end(named_end(after(1)?, 0)?, 0)?),
        0x5B => match byte(bytes, after(1)?)?
        {
            0x82 =>
            {
                let (body, end, _) = named(after(2)?)?;
                Some(Term::Device { body, end })
            }
            0x81 | 0x83..=0x87 => skip(package(bytes, after(2)?)?.1),
            0x80 =>
            {
                let offset = named_end(after(2)?, 1)?;
                let length = offset.checked_add(integer(bytes, offset)?.1)?;
                skip(length.checked_add(integer(bytes, length)?.1)?)
            }
            0x01 => skip(named_end(after(2)?, 1)?),
            0x02 => skip(named_end(after(2)?, 0)?),
            _ => None,
        },
        _ => None,
    }
}

/// [`aml::term_step`] reads the term at `pos` of the term list `bytes` as
/// [`read_term`] does. Returns it.
pub(crate) fn term_holds(bytes: &[u8], pos: usize) -> Option<Term>
{
    let expected = read_term(bytes, pos);
    assert_eq!(
        aml::term_step(bytes, pos),
        expected,
        "an AML term judged against the grammar"
    );
    expected
}

/// A device as the property collects it; `crs` is the range of its `_CRS`
/// byte list in the bytes the walk reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Device
{
    hid: Option<Ident>,
    cids: [Option<Ident>; MAX_CIDS],
    uid: Option<u64>,
    crs: Option<(usize, usize)>,
    sta: Option<u64>,
    dynamic: bool,
}

/// Record `Name(name, value)`, its value the data object at `value` of the
/// `bytes` that end with it, into `d`: a `_HID` that is an ID replaces the
/// last; a `_CID`, one ID or a `Package` (0x12) of them, fills the slots from
/// the first with the IDs among its elements; a `_UID` that is an integer
/// replaces the last; a `_CRS` is the byte list of a `Buffer` (0x11), cut to
/// its size integer, or none; a `_STA` is its integer, or none.
fn record(bytes: &[u8], d: &mut Device, name: [u8; 4], value: usize)
{
    match &name
    {
        b"_HID" =>
        {
            if let Some(id) = id_value(bytes, value)
            {
                d.hid = Some(id);
            }
        }
        b"_CID" => record_cids(bytes, d, value),
        b"_UID" =>
        {
            if let Some((uid, _)) = integer(bytes, value)
            {
                d.uid = Some(uid);
            }
        }
        b"_CRS" => d.crs = crs_list(bytes, value),
        b"_STA" => d.sta = integer(bytes, value).map(|(sta, _)| sta),
        _ =>
        {}
    }
}

/// The `_CID` value at `value`, into `d`'s slots from the first.
fn record_cids(bytes: &[u8], d: &mut Device, value: usize)
{
    let mut slots = d.cids.iter_mut();
    let mut keep = |id: Option<Ident>| {
        if let Some(id) = id
            && let Some(slot) = slots.next()
        {
            *slot = Some(id);
        }
    };
    if byte(bytes, value) != Some(0x12)
    {
        keep(id_value(bytes, value));
        return;
    }
    let Some((count_at, end)) = value.checked_add(1).and_then(|lead| package(bytes, lead))
    else
    {
        return;
    };
    let (Some(count), Some(elements)) = (byte(bytes, count_at), bytes.get(..end))
    else
    {
        return;
    };
    let mut at = count_at.saturating_add(1);
    for _ in 0..count
    {
        let Some(size) = data_object_len(elements, at)
        else
        {
            return;
        };
        keep(id_value(elements, at));
        at = at.saturating_add(size);
    }
}

/// The byte list of the `Buffer` at `value`: after its `PkgLength` and its
/// size integer, to the package's end, cut to that size.
fn crs_list(bytes: &[u8], value: usize) -> Option<(usize, usize)>
{
    if byte(bytes, value)? != 0x11
    {
        return None;
    }
    let (body, end) = package(bytes, value.checked_add(1)?)?;
    let (declared, size) = integer(bytes, body)?;
    let first = body.checked_add(size)?;
    let available = end.checked_sub(first)?;
    let kept = usize::try_from(declared).map_or(available, |d| d.min(available));
    Some((first, first.checked_add(kept)?))
}

/// Whether a device is reported: a `_HID` or a `_CID`, no `_HID`, `_CID` or
/// `_CRS` method, and no `_STA` with its present bit (bit 0) clear.
fn reported(d: &Device) -> bool
{
    let identity = d.hid.is_some() || d.cids.iter().any(Option::is_some);
    let absent = d.sta.is_some_and(|sta| sta & 1 == 0);
    identity && !d.dynamic && !absent
}

/// The decoder's form of the property's device `d`, its `_CRS` a range of
/// `table`.
fn collect_of<'a>(table: &'a [u8], d: &Device) -> Collect<'a>
{
    let id = |i: Option<Ident>| i.and_then(|i| Id::new(i.bytes.get(..i.len)?));
    Collect {
        hid: id(d.hid),
        cids: d.cids.map(id),
        uid: d.uid,
        crs: d.crs.and_then(|(first, end)| table.get(first..end)),
        sta: d.sta,
        dynamic: d.dynamic,
    }
}

/// Whether the decoder's collected device `c` is the property's `d`, its
/// `_CRS` the same range of `bytes`.
fn same(bytes: &[u8], c: &Collect<'_>, d: &Device) -> bool
{
    let ids = |got: Option<Id>, want: Option<Ident>| match (got, want)
    {
        (Some(got), Some(want)) => want.is(&got),
        (None, None) => true,
        _ => false,
    };
    ids(c.hid, d.hid)
        && c.cids.iter().zip(d.cids).all(|(&got, want)| ids(got, want))
        && c.uid == d.uid
        && c.crs.map(|crs| range_of(bytes, crs)) == d.crs
        && c.sta == d.sta
        && c.dynamic == d.dynamic
}

/// The range of `part`, a slice of `bytes`, in `bytes`.
fn range_of(bytes: &[u8], part: &[u8]) -> (usize, usize)
{
    let start = part.as_ptr().addr().wrapping_sub(bytes.as_ptr().addr());
    (start, start.wrapping_add(part.len()))
}

/// The device a `Name` or a `Method` is taken into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Prior
{
    /// One that holds nothing yet.
    Empty,
    /// One whose every field already holds a value.
    Full,
}

/// The decoder's and the property's forms of the device `into`, its `_CRS`
/// an empty range at the start of `bytes`.
fn device_of(bytes: &[u8], into: Prior) -> (Collect<'_>, Device)
{
    if into == Prior::Empty
    {
        return (Collect::default(), Device::default());
    }
    let id = Id::new(b"PRIOR");
    let ident = Ident::new(b"PRIOR");
    (
        Collect {
            hid: id,
            cids: [id; MAX_CIDS],
            uid: Some(7),
            crs: bytes.get(..0),
            sta: Some(1),
            dynamic: false,
        },
        Device {
            hid: ident,
            cids: [ident; MAX_CIDS],
            uid: Some(7),
            crs: Some((0, 0)),
            sta: Some(1),
            dynamic: false,
        },
    )
}

/// [`aml::record`] records `Name(name, value)`, its value the `size` bytes
/// at `value` of `bytes`, into the device `into` as [`record`] does.
pub(crate) fn record_holds(bytes: &[u8], name: [u8; 4], value: usize, size: usize, into: Prior)
{
    let Some(data) = value.checked_add(size).and_then(|end| bytes.get(..end))
    else
    {
        return;
    };
    let (mut c, mut d) = device_of(bytes, into);
    aml::record(&mut c, name, bytes, value, size);
    record(data, &mut d, name, value);
    assert!(same(bytes, &c, &d), "a Name recorded against its value");
}

/// [`aml::method`] takes a `Method` called `name` into the device `into`:
/// one called `_HID`, `_CID` or `_CRS` makes it dynamic, and nothing else
/// changes.
pub(crate) fn method_holds(name: Option<[u8; 4]>, into: Prior)
{
    let (mut c, mut d) = device_of(&[], into);
    aml::method(&mut c, name);
    if matches!(name.as_ref(), Some(b"_HID" | b"_CID" | b"_CRS"))
    {
        d.dynamic = true;
    }
    assert!(same(&[], &c, &d), "a Method taken against its name");
}

/// [`aml::cid_value`] takes the `_CID` value at `value` of `bytes` into the
/// device `into` as [`record_cids`] does before the elements: a value that
/// is not a `Package` (0x12) is one ID, or none, for the first slot; a
/// `Package` takes nothing and yields its element count, the offset after
/// the count, and its end.
pub(crate) fn cid_value_holds(bytes: &[u8], value: usize, into: Prior)
{
    let (mut c, mut d) = device_of(bytes, into);
    let got = aml::cid_value(&mut c, bytes, value);
    let expected = if byte(bytes, value) == Some(0x12)
    {
        value
            .checked_add(1)
            .and_then(|lead| package(bytes, lead))
            .and_then(|(count_at, end)| {
                Some((byte(bytes, count_at)?, count_at.checked_add(1)?, end))
            })
    }
    else
    {
        if let Some(id) = id_value(bytes, value)
            && let Some(slot) = d.cids.first_mut()
        {
            *slot = Some(id);
        }
        None
    };
    assert_eq!(got, expected, "a _CID value's package against its header");
    assert!(same(bytes, &c, &d), "a _CID value taken against its ID");
}

/// [`aml::cid_element`] takes the element at `at` of a `_CID` `Package`'s
/// `elements` into slot `n` of the device `into` as [`record_cids`] does:
/// an element that is an ID fills slot `n` when there is one, and the next
/// free slot follows it; any data object is passed by its size; at no data
/// object, nothing is taken.
pub(crate) fn cid_element_holds(elements: &[u8], at: usize, n: usize, into: Prior)
{
    let (mut c, mut d) = device_of(elements, into);
    let got = aml::cid_element(&mut c, n, elements, at);
    let expected = data_object_len(elements, at).map(|size| {
        let mut next = n;
        if let Some(id) = id_value(elements, at)
            && let Some(slot) = d.cids.get_mut(n)
        {
            *slot = Some(id);
            next = n.saturating_add(1);
        }
        (size, next)
    });
    assert_eq!(
        got, expected,
        "a _CID element's size and slot against its object"
    );
    assert!(
        same(elements, &c, &d),
        "a _CID element taken against its ID"
    );
}

/// Check the steps of the `_CID` value at `value` of `data`: the value, and
/// each element of a `Package` that [`record_cids`] reads, into every
/// slot, of a device that holds nothing and of one that holds every field.
fn cid_steps_hold(data: &[u8], value: usize)
{
    for into in [Prior::Empty, Prior::Full]
    {
        cid_value_holds(data, value, into);
    }
    if byte(data, value) != Some(0x12)
    {
        return;
    }
    let Some((count_at, end)) = value.checked_add(1).and_then(|lead| package(data, lead))
    else
    {
        return;
    };
    let (Some(count), Some(elements)) = (byte(data, count_at), data.get(..end))
    else
    {
        return;
    };
    let mut at = count_at.saturating_add(1);
    for _ in 0..count
    {
        for n in 0..=MAX_CIDS
        {
            for into in [Prior::Empty, Prior::Full]
            {
                cid_element_holds(elements, at, n, into);
            }
        }
        let Some(size) = data_object_len(elements, at)
        else
        {
            return;
        };
        at = at.saturating_add(size);
    }
}

/// [`aml::qualify`] reports the device `c` when [`reported`] does, with its
/// identity, `_UID` and `_CRS`.
pub(crate) fn qualify_holds(c: &Collect<'_>)
{
    let identity = c.hid.is_some() || c.cids.iter().any(Option::is_some);
    let absent = c.sta.is_some_and(|sta| sta & 1 == 0);
    let device = aml::qualify(c);
    assert_eq!(
        device.is_some(),
        identity && !c.dynamic && !absent,
        "a device reported against its identity"
    );
    if let Some(device) = device
    {
        assert!(
            device.hid == c.hid
                && device.cids == c.cids
                && device.uid == c.uid
                && match (device.crs, c.crs)
                {
                    (Some(got), Some(held)) => got == held,
                    (got, held) => got.is_none() && held.is_none(),
                },
            "a device reported with other fields than it holds"
        );
    }
}

/// Walk the term list `start..end` of `table` at `depth`, `dev` the device
/// whose objects it holds, if any, and push each device reported, after its
/// own list. A list deeper than [`MAX_DEPTH`] is not read; the list stops at
/// the first term [`read_term`] reads none of or that does not advance.
fn walk(
    table: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    mut dev: Option<&mut Device>,
    out: &mut Vec<Device>,
)
{
    let Some(bytes) = table.get(..end)
    else
    {
        return;
    };
    if depth > MAX_DEPTH
    {
        return;
    }
    let mut pos = start;
    while pos < end
    {
        let Some(term) = term_holds(bytes, pos)
        else
        {
            return;
        };
        match term
        {
            Term::Scope { body, end } => walk(table, body, end, depth.saturating_add(1), None, out),
            Term::Device { body, end } =>
            {
                let mut d = Device::default();
                walk(table, body, end, depth.saturating_add(1), Some(&mut d), out);
                qualify_holds(&collect_of(table, &d));
                if reported(&d)
                {
                    out.push(d);
                }
            }
            Term::Name {
                name: Some(name),
                value,
                size,
            } =>
            {
                if let (Some(d), Some(data)) = (
                    dev.as_deref_mut(),
                    value.checked_add(size).and_then(|e| bytes.get(..e)),
                )
                {
                    for into in [Prior::Empty, Prior::Full]
                    {
                        record_holds(bytes, name, value, size, into);
                    }
                    if name == *b"_CID"
                    {
                        cid_steps_hold(data, value);
                    }
                    record(data, d, name, value);
                }
            }
            Term::Method { name, .. } =>
            {
                if let Some(d) = dev.as_deref_mut()
                {
                    for into in [Prior::Empty, Prior::Full]
                    {
                        method_holds(name, into);
                    }
                    if matches!(name.as_ref(), Some(b"_HID" | b"_CID" | b"_CRS"))
                    {
                        d.dynamic = true;
                    }
                }
            }
            Term::Name { .. } | Term::Skip { .. } =>
            {}
        }
        match term.end()
        {
            Some(next) if next > pos => pos = next,
            _ => return,
        }
    }
}

/// [`aml::devices`] visits, in order, the devices the property's walk of
/// `input` reports: the term list after the 36-byte header, up to the
/// header's length bounded by the input, for a header of at least 36 bytes.
/// Returns each visited device's `_CRS`.
pub(crate) fn walk_holds(input: &[u8]) -> Vec<&[u8]>
{
    let mut expected = Vec::new();
    if let Some(length) = sdt_length(input)
    {
        walk(input, 36, length.min(input.len()), 0, None, &mut expected);
    }
    let mut visited = Vec::new();
    let count = aml::devices(input, |d| visited.push(*d));
    assert_eq!(count, visited.len(), "a walk's count against its visits");
    assert_eq!(
        visited.len(),
        expected.len(),
        "a walk's devices against the grammar"
    );
    for (got, want) in visited.iter().zip(&expected)
    {
        let c = Collect {
            hid: got.hid,
            cids: got.cids,
            uid: got.uid,
            crs: got.crs,
            sta: want.sta,
            dynamic: want.dynamic,
        };
        assert!(
            same(input, &c, want),
            "a device visited against the grammar"
        );
    }
    visited.iter().filter_map(|d| d.crs).collect()
}

// ── Resource template ───────────────────────────────────────────────────────

/// The resources reported, in order, at most [`MAX_CRS_RESOURCES`].
#[derive(Debug, Default, PartialEq, Eq)]
struct Reported
{
    resources: [Option<CrsResource>; MAX_CRS_RESOURCES],
    count: usize,
}

impl Reported
{
    /// Report `r`; false when the bound is already reached.
    fn push(&mut self, r: CrsResource) -> bool
    {
        let Some(slot) = self.resources.get_mut(self.count)
        else
        {
            return false;
        };
        *slot = Some(r);
        self.count = self.count.saturating_add(1);
        true
    }
}

/// The `IRQ_MODE_*` bits of an interrupt whose `flags`, if any, clear the
/// `edge` bit for a level-triggered one and set the `low` bit for an
/// active-low one.
fn mode(flags: Option<u8>, edge: u8, low: u8) -> u64
{
    let mut mode = 0;
    if flags.is_some_and(|f| f & edge == 0)
    {
        mode |= syscall_abi::IRQ_MODE_LEVEL;
    }
    if flags.is_some_and(|f| f & low != 0)
    {
        mode |= syscall_abi::IRQ_MODE_ACTIVE_LOW;
    }
    mode
}

/// Report the resources of the descriptor whose body is `body`, its kind
/// `key` (a small kind, or a large one with bit 7 set, as its tag holds it);
/// false when the bound is reached. An IRQ (small 0x4, 2 or 3 bytes: a
/// 16-bit mask, then flags: bit 0 edge, bit 3 active-low, bit 4 shared; none
/// means edge, high, exclusive) reports each line of its mask; an I/O Port
/// (small 0x8, 7 bytes: the minimum at 1, the length at 6) and a Fixed I/O
/// Port (small 0x9, 3 bytes: a 10-bit base at 0, the length at 2) their ports;
/// a 32-bit Fixed Memory range (large 0x06, 9 bytes: base at 1, length at 5)
/// its range; a 32-bit Memory range (large 0x05, 17 bytes: minimum at 1,
/// maximum at 5, length at 13) its range when the minimum is the maximum; a
/// `DWord` (large 0x07, at least 23 bytes) or `QWord` (large 0x0A, at least
/// 43 bytes) memory range (type 0) the device consumes (general flag bit 0)
/// its minimum (at 7 or 11) and length (at 19 or 35); an Extended Interrupt
/// (large 0x09, at least 6 bytes: flags, bit 1 edge, bit 2 active-low, bit 3
/// shared; a count; the lines) each line of its count the body holds. A range
/// of length 0 is not reported, nor is any other descriptor or length.
fn descriptor(key: u8, body: &[u8], out: &mut Reported) -> bool
{
    let len = body.len();
    let port = |out: &mut Reported, base: Option<u16>, count: Option<u8>| match (base, count)
    {
        (_, Some(0) | None) | (None, _) => true,
        (Some(base), Some(count)) => out.push(CrsResource::IoPort {
            base,
            count: u16::from(count),
        }),
    };
    let mem = |out: &mut Reported, base: Option<u64>, size: Option<u64>| match (base, size)
    {
        (_, Some(0) | None) | (None, _) => true,
        (Some(base), Some(size)) => out.push(CrsResource::Mmio { base, size }),
    };
    match key
    {
        0x04 if len == 2 || len == 3 =>
        {
            let mask = le16(body, 0).unwrap_or(0);
            let flags = byte(body, 2);
            let shared = flags.is_some_and(|f| f & 0x10 != 0);
            (0..16u32)
                .filter(|line| (mask >> line) & 1 != 0)
                .all(|line| {
                    out.push(CrsResource::Interrupt {
                        line,
                        mode: mode(flags, 0x01, 0x08),
                        shared,
                        isa: true,
                    })
                })
        }
        0x08 if len == 7 => port(out, le16(body, 1), byte(body, 6)),
        0x09 if len == 3 => port(out, le16(body, 0).map(|b| b & 0x3FF), byte(body, 2)),
        0x86 if len == 9 => mem(
            out,
            le32(body, 1).map(u64::from),
            le32(body, 5).map(u64::from),
        ),
        0x85 if len == 17 =>
        {
            le32(body, 1) != le32(body, 5)
                || mem(
                    out,
                    le32(body, 1).map(u64::from),
                    le32(body, 13).map(u64::from),
                )
        }
        0x87 if len >= 23
            && byte(body, 0) == Some(0)
            && byte(body, 1).is_some_and(|f| f & 1 != 0) =>
        {
            mem(
                out,
                le32(body, 7).map(u64::from),
                le32(body, 19).map(u64::from),
            )
        }
        0x8A if len >= 43
            && byte(body, 0) == Some(0)
            && byte(body, 1).is_some_and(|f| f & 1 != 0) =>
        {
            mem(out, le64(body, 11), le64(body, 35))
        }
        0x89 if len >= 6 =>
        {
            let flags = byte(body, 0).unwrap_or(0);
            let count = usize::from(byte(body, 1).unwrap_or(0)).min(len.saturating_sub(2) / 4);
            (0..count).all(|i| {
                let Some(line) = i
                    .checked_mul(4)
                    .and_then(|at| at.checked_add(2))
                    .and_then(|at| le32(body, at))
                else
                {
                    return true;
                };
                out.push(CrsResource::Interrupt {
                    line,
                    mode: mode(Some(flags), 0x02, 0x04),
                    shared: flags & 0x08 != 0,
                    isa: false,
                })
            })
        }
        _ => true,
    }
}

/// The resources of the template `crs`: its descriptors in order, each a
/// small one (tag bit 7 clear: kind in bits 6:3, body length in bits 2:0) or
/// a large one (tag bit 7 set: kind in bits 6:0, a `u16` body length after
/// it), through [`descriptor`]. The template ends at its End Tag (small kind
/// 0xF), at a descriptor that runs past it, at its last byte, or at the bound.
fn template(crs: &[u8]) -> Reported
{
    let mut out = Reported::default();
    let mut pos = 0usize;
    while let Some(next) = template_step(crs, pos, &mut out)
    {
        pos = next;
    }
    out
}

/// Report the descriptor at `pos` of the template `crs` into `out`. Returns
/// the offset after it, or `None` where the template ends: at its end, at a
/// descriptor that runs past it, at the End Tag (small 0xF), or at a
/// descriptor whose resources reach the bound.
fn template_step(crs: &[u8], pos: usize, out: &mut Reported) -> Option<usize>
{
    let tag = byte(crs, pos)?;
    let large = tag & 0x80 != 0;
    let (kind, body, length) = if large
    {
        let length = pos.checked_add(1).and_then(|at| le16(crs, at))?;
        (tag & 0x7F, pos.saturating_add(3), usize::from(length))
    }
    else
    {
        (
            (tag >> 3) & 0x0F,
            pos.saturating_add(1),
            usize::from(tag & 0x07),
        )
    };
    let next = body.checked_add(length).filter(|&next| next <= crs.len())?;
    if !large && kind == 0x0F
    {
        return None;
    }
    descriptor(
        if large { tag } else { kind },
        crs.get(body..next).unwrap_or(&[]),
        out,
    )
    .then_some(next)
}

/// [`aml::crs_step`] reports the first descriptor of the template `crs`,
/// `prior` resources being reported before it, as [`template_step`] does:
/// its resources up to the bound, and whether the walk goes on past it.
pub(crate) fn descriptor_holds(crs: &[u8], prior: usize)
{
    let mut visited = Reported {
        count: prior,
        ..Reported::default()
    };
    let mut past_bound = false;
    let (goes_on, count) = {
        let mut em = aml::Emit {
            visit: |r| past_bound |= !visited.push(r),
            n: prior,
        };
        let goes_on = ::aml::resource::descriptors(crs)
            .next()
            .is_some_and(|d| aml::crs_step(&mut em, d));
        (goes_on, em.n)
    };
    let mut expected = Reported {
        count: prior,
        ..Reported::default()
    };
    let expected_goes_on = template_step(crs, 0, &mut expected).is_some();
    assert!(!past_bound, "a resource visited past the bound");
    assert_eq!(count, visited.count, "a step's count against its visits");
    assert_eq!(
        goes_on, expected_goes_on,
        "a step's stop against the template's"
    );
    assert_eq!(
        visited, expected,
        "a descriptor's resources against its fields"
    );
}

/// [`aml::crs_resources`] visits the resources [`template`] reads from
/// `crs`, in order, and returns their count.
pub(crate) fn crs_holds(crs: &[u8])
{
    let mut visited = Reported::default();
    let mut past_bound = false;
    let count = aml::crs_resources(crs, |r| past_bound |= !visited.push(r));
    assert!(!past_bound, "a resource visited past the bound");
    assert_eq!(
        count, visited.count,
        "a template's count against its visits"
    );
    assert_eq!(
        visited,
        template(crs),
        "a template's resources against its descriptors"
    );
}
