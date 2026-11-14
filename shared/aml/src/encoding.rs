// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/encoding.rs

//! The low-level encodings of the AML grammar (ACPI 6.5 § 20.2): opcodes,
//! `PkgLength`, `NameString`, integer and string data, and the EISA ID
//! encoding. Every read is bounds-checked against the caller's slice and
//! returns `None` on a short or malformed encoding. No allocation.

// ── Opcodes ───────────────────────────────────────────────────────────

/// `ZeroOp`; also `NullName` in a name position.
pub const OP_ZERO: u8 = 0x00;
/// `OneOp`.
pub const OP_ONE: u8 = 0x01;
/// `AliasOp`.
pub const OP_ALIAS: u8 = 0x06;
/// `NameOp`.
pub const OP_NAME: u8 = 0x08;
/// `BytePrefix`.
pub const OP_BYTE: u8 = 0x0A;
/// `WordPrefix`.
pub const OP_WORD: u8 = 0x0B;
/// `DWordPrefix`.
pub const OP_DWORD: u8 = 0x0C;
/// `StringPrefix`.
pub const OP_STRING: u8 = 0x0D;
/// `QWordPrefix`.
pub const OP_QWORD: u8 = 0x0E;
/// `ScopeOp`.
pub const OP_SCOPE: u8 = 0x10;
/// `BufferOp`.
pub const OP_BUFFER: u8 = 0x11;
/// `PackageOp`.
pub const OP_PACKAGE: u8 = 0x12;
/// `VarPackageOp`.
pub const OP_VAR_PACKAGE: u8 = 0x13;
/// `MethodOp`.
pub const OP_METHOD: u8 = 0x14;
/// `ExternalOp`.
pub const OP_EXTERNAL: u8 = 0x15;
/// `DualNamePrefix`.
pub const DUAL_NAME_PREFIX: u8 = 0x2E;
/// `MultiNamePrefix`.
pub const MULTI_NAME_PREFIX: u8 = 0x2F;
/// `ExtOpPrefix`.
pub const OP_EXT_PREFIX: u8 = 0x5B;
/// `RootChar`.
pub const ROOT_CHAR: u8 = 0x5C;
/// `ParentPrefixChar`.
pub const PARENT_PREFIX: u8 = 0x5E;
/// `IfOp`.
pub const OP_IF: u8 = 0xA0;
/// `ElseOp`.
pub const OP_ELSE: u8 = 0xA1;
/// `WhileOp`.
pub const OP_WHILE: u8 = 0xA2;
/// `OnesOp`.
pub const OP_ONES: u8 = 0xFF;

/// `MutexOp` (after `ExtOpPrefix`).
pub const EXT_MUTEX: u8 = 0x01;
/// `EventOp`.
pub const EXT_EVENT: u8 = 0x02;
/// `RevisionOp`.
pub const EXT_REVISION: u8 = 0x30;
/// `OpRegionOp`.
pub const EXT_OP_REGION: u8 = 0x80;
/// `FieldOp`.
pub const EXT_FIELD: u8 = 0x81;
/// `DeviceOp`.
pub const EXT_DEVICE: u8 = 0x82;
/// `ProcessorOp` (deprecated in ACPI 6.4, still accepted).
pub const EXT_PROCESSOR: u8 = 0x83;
/// `PowerResOp`.
pub const EXT_POWER_RES: u8 = 0x84;
/// `ThermalZoneOp`.
pub const EXT_THERMAL_ZONE: u8 = 0x85;
/// `IndexFieldOp`.
pub const EXT_INDEX_FIELD: u8 = 0x86;
/// `BankFieldOp`.
pub const EXT_BANK_FIELD: u8 = 0x87;

// ── PkgLength ─────────────────────────────────────────────────────────

/// The `PkgLength` at `pos`: its value and its encoded size (1 to 4 bytes).
///
/// The value of a package's `PkgLength` counts itself and the package body;
/// a field element's counts bits. [`package`] applies the first meaning.
/// The value has at most 28 bits.
#[must_use]
pub fn pkg_length(buf: &[u8], pos: usize) -> Option<(u32, usize)>
{
    let b0 = *buf.get(pos)?;
    let extra = usize::from(b0 >> 6);
    if extra == 0
    {
        return Some((u32::from(b0 & 0x3F), 1));
    }
    let mut v = u32::from(b0 & 0x0F);
    for i in 0..extra
    {
        let b = *buf.get(pos.checked_add(1)?.checked_add(i)?)?;
        let shift = u32::try_from(i).ok()?.saturating_mul(8).saturating_add(4);
        v |= u32::from(b).checked_shl(shift)?;
    }
    Some((v, extra.checked_add(1)?))
}

/// Bounds of the package whose `PkgLength` lead byte is at `lead`: the offset
/// of the first body byte and the offset one past the package's end. The end
/// must lie within `buf`.
#[must_use]
pub fn package(buf: &[u8], lead: usize) -> Option<(usize, usize)>
{
    let (len, size) = pkg_length(buf, lead)?;
    let len = usize::try_from(len).ok()?;
    if len < size
    {
        return None;
    }
    let end = lead.checked_add(len)?;
    if end > buf.len()
    {
        return None;
    }
    Some((lead.checked_add(size)?, end))
}

// ── NameString ────────────────────────────────────────────────────────

/// Whether `b` may start a `NameSeg` (`LeadNameChar`).
#[must_use]
pub const fn is_lead_name_char(b: u8) -> bool
{
    b.is_ascii_uppercase() || b == b'_'
}

/// Whether `b` may continue a `NameSeg` (`NameChar`).
#[must_use]
pub const fn is_name_char(b: u8) -> bool
{
    is_lead_name_char(b) || b.is_ascii_digit()
}

/// Whether `b` starts a `NameString`: a root or parent prefix, a dual or
/// multi name prefix, or a `LeadNameChar`. `NullName` (0x00) is not
/// included: in most positions that byte is `ZeroOp`.
#[must_use]
pub const fn starts_name(b: u8) -> bool
{
    matches!(
        b,
        ROOT_CHAR | PARENT_PREFIX | DUAL_NAME_PREFIX | MULTI_NAME_PREFIX
    ) || is_lead_name_char(b)
}

/// One `NameSeg`: four name characters.
pub type Seg = [u8; 4];

/// A `NameString` as encoded, borrowed from the AML.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameStr<'a>
{
    /// Whether the name starts at the root (`\`).
    pub root: bool,
    /// The number of parent prefixes (`^`).
    pub up: usize,
    /// The segments, four bytes each, every one validated.
    pub segs: &'a [u8],
}

impl NameStr<'_>
{
    /// The number of segments; zero for `NullName`.
    #[must_use]
    pub const fn len(&self) -> usize
    {
        self.segs.len() / 4
    }

    /// Whether the name has no segment (`NullName`, `\`, or `^`s alone).
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.segs.is_empty()
    }

    /// The segments in order.
    pub fn segments(&self) -> impl Iterator<Item = Seg> + Clone + '_
    {
        self.segs.as_chunks::<4>().0.iter().copied()
    }

    /// The last segment, if any.
    #[must_use]
    pub fn last(&self) -> Option<Seg>
    {
        self.segments().last()
    }

    /// Whether the name is relative, has no parent prefix, and is one
    /// segment: the only form the search rules of ACPI 6.5 § 5.3 apply to.
    #[must_use]
    pub const fn searches(&self) -> bool
    {
        !self.root && self.up == 0 && self.segs.len() == 4
    }
}

/// The `NameString` at `pos` and its encoded size.
#[must_use]
pub fn name_str(buf: &[u8], pos: usize) -> Option<(NameStr<'_>, usize)>
{
    let mut p = pos;
    let mut root = false;
    let mut up = 0usize;
    match *buf.get(p)?
    {
        ROOT_CHAR =>
        {
            root = true;
            p = p.checked_add(1)?;
        }
        PARENT_PREFIX =>
        {
            while buf.get(p) == Some(&PARENT_PREFIX)
            {
                up = up.checked_add(1)?;
                p = p.checked_add(1)?;
            }
        }
        _ =>
        {}
    }
    let (count, skip) = match *buf.get(p)?
    {
        OP_ZERO =>
        {
            let size = p.checked_add(1)?.checked_sub(pos)?;
            return Some((
                NameStr {
                    root,
                    up,
                    segs: &[],
                },
                size,
            ));
        }
        DUAL_NAME_PREFIX => (2, 1),
        MULTI_NAME_PREFIX => (usize::from(*buf.get(p.checked_add(1)?)?), 2),
        _ => (1, 0),
    };
    let first = p.checked_add(skip)?;
    let end = first.checked_add(count.checked_mul(4)?)?;
    let segs = buf.get(first..end)?;
    for seg in segs.as_chunks::<4>().0
    {
        let [lead, rest @ ..] = seg;
        if !is_lead_name_char(*lead) || !rest.iter().all(|b| is_name_char(*b))
        {
            return None;
        }
    }
    Some((NameStr { root, up, segs }, end.checked_sub(pos)?))
}

/// Size and last `NameSeg` of the `NameString` at `pos`. The last segment is
/// `None` for a `NullName` or an empty multi-name.
#[must_use]
pub fn name_string(buf: &[u8], pos: usize) -> Option<(usize, Option<Seg>)>
{
    let (name, size) = name_str(buf, pos)?;
    Some((size, name.last()))
}

// ── Data ──────────────────────────────────────────────────────────────

/// Little-endian integer of `n` bytes (at most 8) at `off`.
#[must_use]
pub fn le(buf: &[u8], off: usize, n: usize) -> Option<u64>
{
    if n > 8
    {
        return None;
    }
    let bytes = buf.get(off..off.checked_add(n)?)?;
    Some(
        bytes
            .iter()
            .rev()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)),
    )
}

/// Integer `DataObject` at `pos` (`ZeroOp`, `OneOp`, `OnesOp`, or a
/// prefixed constant): its value and encoded size.
#[must_use]
pub fn integer(buf: &[u8], pos: usize) -> Option<(u64, usize)>
{
    match *buf.get(pos)?
    {
        OP_ZERO => Some((0, 1)),
        OP_ONE => Some((1, 1)),
        OP_ONES => Some((u64::MAX, 1)),
        OP_BYTE => Some((le(buf, pos.checked_add(1)?, 1)?, 2)),
        OP_WORD => Some((le(buf, pos.checked_add(1)?, 2)?, 3)),
        OP_DWORD => Some((le(buf, pos.checked_add(1)?, 4)?, 5)),
        OP_QWORD => Some((le(buf, pos.checked_add(1)?, 8)?, 9)),
        _ => None,
    }
}

/// The bytes of the `String` at `pos` (after `StringPrefix`, before its
/// NUL) and the string's encoded size.
#[must_use]
pub fn string(buf: &[u8], pos: usize) -> Option<(&[u8], usize)>
{
    if *buf.get(pos)? != OP_STRING
    {
        return None;
    }
    let rest = buf.get(pos.checked_add(1)?..)?;
    let nul = rest.iter().position(|b| *b == 0)?;
    Some((rest.get(..nul)?, nul.checked_add(2)?))
}

/// Encoded size of the `DataRefObject` at `pos`: an integer, a string, a
/// `Buffer`, `Package` or `VarPackage` (sized by its `PkgLength`), or
/// `RevisionOp`.
#[must_use]
pub fn data_object_len(buf: &[u8], pos: usize) -> Option<usize>
{
    if let Some((_, size)) = integer(buf, pos)
    {
        return Some(size);
    }
    match *buf.get(pos)?
    {
        OP_STRING => string(buf, pos).map(|(_, size)| size),
        OP_BUFFER | OP_PACKAGE | OP_VAR_PACKAGE =>
        {
            let (_, end) = package(buf, pos.checked_add(1)?)?;
            end.checked_sub(pos)
        }
        OP_EXT_PREFIX if buf.get(pos.checked_add(1)?) == Some(&EXT_REVISION) => Some(2),
        _ => None,
    }
}

/// Decode a 32-bit EISA ID as AML stores it (`EISAID("PNP0501")` is the
/// `DWord` 0x0105D041) into its seven characters: three letters and four
/// hexadecimal digits. `None` when a letter is outside `A`-`Z`.
#[must_use]
pub fn eisa_id(value: u32) -> Option<[u8; 7]>
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
    Some(text)
}

#[cfg(test)]
mod tests
{
    use super::*;

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

    #[test]
    fn eisa_decode()
    {
        assert_eq!(&eisa_id(0x0105_D041).unwrap(), b"PNP0501");
        assert_eq!(&eisa_id(0x000B_D041).unwrap(), b"PNP0B00");
        assert_eq!(eisa_id(0), None);
        assert_eq!(eisa_id(0x0105_D0FF), None);
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
        // Shorter than its own encoding.
        assert_eq!(package(&[0x00], 0), None);
        assert_eq!(package(&[0x41, 0x00], 0), None);
    }

    #[test]
    fn pkg_length_values()
    {
        assert_eq!(pkg_length(&[0x3F], 0), Some((0x3F, 1)));
        assert_eq!(pkg_length(&[0x4A, 0x12], 0), Some((0x12A, 2)));
        assert_eq!(pkg_length(&[0x81, 0x34, 0x12], 0), Some((0x12341, 3)));
        assert_eq!(
            pkg_length(&[0xC2, 0x01, 0x02, 0x03], 0),
            Some((0x0030_2012, 4))
        );
        assert_eq!(pkg_length(&[0xC2, 0x01, 0x02], 0), None);
        assert_eq!(pkg_length(&[], 0), None);
        // The largest value: 28 bits.
        assert_eq!(
            pkg_length(&[0xCF, 0xFF, 0xFF, 0xFF], 0),
            Some((0x0FFF_FFFF, 4))
        );
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
        assert_eq!(name_string(b"A1b_", 0), None);
    }

    #[test]
    fn name_str_parts()
    {
        let (n, size) = name_str(b"^^AB_CXYZW", 0).unwrap();
        assert_eq!(size, 6);
        assert!(!n.root);
        assert_eq!(n.up, 2);
        assert_eq!(n.segments().collect::<Vec<_>>(), vec![*b"AB_C"]);
        assert!(!n.searches());
        let (n, _) = name_str(b"\\\x00", 0).unwrap();
        assert!(n.root && n.is_empty());
        let (n, _) = name_str(b"ABCD", 0).unwrap();
        assert!(n.searches());
        assert_eq!(n.len(), 1);
        let (n, size) = name_str(&[0x2F, 0], 0).unwrap();
        assert_eq!((n.len(), size), (0, 2));
    }

    #[test]
    fn data_objects()
    {
        assert_eq!(integer(&[0x0C, 1, 2, 3, 4], 0), Some((0x0403_0201, 5)));
        assert_eq!(integer(&[0x0E, 1, 2, 3, 4, 5, 6, 7], 0), None);
        assert_eq!(integer(&[0xFF], 0), Some((u64::MAX, 1)));
        assert_eq!(string(b"\x0dAB\x00", 0), Some((&b"AB"[..], 4)));
        assert_eq!(string(b"\x0dAB", 0), None);
        assert_eq!(data_object_len(&[0x5B, 0x30], 0), Some(2));
        assert_eq!(data_object_len(&[0x11, 3, 0x0A, 0], 0), Some(4));
        assert_eq!(data_object_len(&[0x11, 9, 0x0A, 0], 0), None);
        assert_eq!(data_object_len(&[0x70], 0), None);
        assert_eq!(le(&[1; 9], 0, 9), None);
    }
}
