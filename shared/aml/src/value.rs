// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/value.rs

//! The values AML code computes and named data objects hold, the object
//! references among them, and the data conversions of ACPI 6.5 § 19.3.5.
//!
//! A value owns its data: a package holds its elements and a buffer its
//! bytes. An object reference ([`Ref`]) names where the referenced object
//! lives (a namespace node, a method frame's local or argument, or a
//! temporary it owns) and the index path into it, so a store through it
//! changes the object in place without shared ownership.
//!
//! Every allocation is fallible, and every conversion that builds a buffer
//! or a string is bounded by [`MAX_BUFFER_BYTES`].

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::namespace::NodeId;
use crate::term::Name;
use crate::{FaultKind, MAX_BUFFER_BYTES, MAX_PACKAGE_ELEMENTS};

/// The integer width of the code that computes a value: 32 bits in a table
/// of revision 1, 64 bits from revision 2 (ACPI 6.5 § 19.3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntWidth
{
    /// 32-bit integers.
    Bits32,
    /// 64-bit integers.
    Bits64,
}

impl IntWidth
{
    /// The width of the code of a table of revision `revision`.
    #[must_use]
    pub const fn of_revision(revision: u8) -> Self
    {
        if revision < 2
        {
            Self::Bits32
        }
        else
        {
            Self::Bits64
        }
    }

    /// The mask of an integer's bits, which is also the value of `Ones`.
    #[must_use]
    pub const fn mask(self) -> u64
    {
        match self
        {
            Self::Bits32 => 0xFFFF_FFFF,
            Self::Bits64 => u64::MAX,
        }
    }

    /// The size of an integer in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize
    {
        match self
        {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }

    /// The size of an integer in bits.
    #[must_use]
    pub const fn bits(self) -> u32
    {
        match self
        {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

/// A value: what a named data object, a local, an argument or an
/// expression holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Data
{
    /// No value: a local or argument never stored to, a package element its
    /// list omits.
    #[default]
    Uninitialized,
    /// An integer, already truncated to the width of the code that made it.
    Integer(u64),
    /// A string's characters, without the terminating NUL.
    String(Vec<u8>),
    /// A buffer.
    Buffer(Vec<u8>),
    /// A package.
    Package(Vec<Data>),
    /// A name in a package a table declares, unresolved. The evaluator
    /// resolves it from the scope of the package's `Name` when an element is
    /// read through `Index`, and keeps it a name when nothing of that name
    /// exists.
    Name(Name),
    /// An object reference (`RefOf`, `Index`, `CondRefOf`).
    Ref(Ref),
}

/// An object reference: the place an object lives and the index path into
/// it. Each index selects a package element, or, last, a buffer's byte or a
/// string's character.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ref
{
    /// Where the outermost object lives.
    pub base: Base,
    /// The indices into it, outermost first.
    pub path: Vec<u32>,
}

/// Where the object a [`Ref`] refers to lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Base
{
    /// A namespace node, with its generation when the reference was made:
    /// the reference fails once the node is removed, even if its slot is
    /// reused.
    Node
    {
        /// The node.
        node: NodeId,
        /// [`crate::Namespace::generation`] of the node.
        generation: u32,
    },
    /// A local of the method frame whose serial is `frame`.
    Local
    {
        /// The frame's serial, never reused within an evaluator.
        frame: u64,
        /// `Local0`-`Local7`.
        index: u8,
    },
    /// An argument of the method frame whose serial is `frame`.
    Arg
    {
        /// The frame's serial.
        frame: u64,
        /// `Arg0`-`Arg6`.
        index: u8,
    },
    /// A temporary the reference owns, one value: the result of an
    /// expression that an `Index` refers into.
    Value(Vec<Data>),
}

impl Ref
{
    /// A reference to the whole of node `node` of generation `generation`.
    #[must_use]
    pub const fn node(node: NodeId, generation: u32) -> Self
    {
        Self {
            base: Base::Node { node, generation },
            path: Vec::new(),
        }
    }

    /// A copy of the reference, every allocation fallible.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NoMemory`] when an allocation fails.
    pub fn try_clone(&self) -> Result<Self, FaultKind>
    {
        let base = match &self.base
        {
            Base::Node { node, generation } => Base::Node {
                node: *node,
                generation: *generation,
            },
            Base::Local { frame, index } => Base::Local {
                frame: *frame,
                index: *index,
            },
            Base::Arg { frame, index } => Base::Arg {
                frame: *frame,
                index: *index,
            },
            Base::Value(v) => Base::Value(clone_all(v)?),
        };
        let mut path = vec_with(self.path.len())?;
        path.extend_from_slice(&self.path);
        Ok(Self { base, path })
    }

    fn weight(&self) -> usize
    {
        let temp = match &self.base
        {
            Base::Value(v) => v.iter().map(Data::weight).fold(0, usize::saturating_add),
            Base::Node { .. } | Base::Local { .. } | Base::Arg { .. } => 0,
        };
        temp.saturating_add(self.path.len().saturating_mul(4))
    }

    fn depth(&self) -> usize
    {
        match &self.base
        {
            Base::Value(v) => v.iter().map(Data::depth).max().unwrap_or(0),
            Base::Node { .. } | Base::Local { .. } | Base::Arg { .. } => 0,
        }
    }
}

/// An empty vector with room for `n` items.
///
/// # Errors
///
/// [`FaultKind::NoMemory`] when the allocation fails.
pub fn vec_with<T>(n: usize) -> Result<Vec<T>, FaultKind>
{
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| FaultKind::NoMemory)?;
    Ok(v)
}

/// An owned copy of `bytes`.
///
/// # Errors
///
/// [`FaultKind::NoMemory`] when the allocation fails.
pub fn bytes_of(bytes: &[u8]) -> Result<Vec<u8>, FaultKind>
{
    let mut v = vec_with(bytes.len())?;
    v.extend_from_slice(bytes);
    Ok(v)
}

/// A copy of each value of `values`.
///
/// # Errors
///
/// [`FaultKind::NoMemory`] when an allocation fails.
pub fn clone_all(values: &[Data]) -> Result<Vec<Data>, FaultKind>
{
    let mut out = vec_with(values.len())?;
    for v in values
    {
        out.push(v.try_clone()?);
    }
    Ok(out)
}

/// Check that a buffer or a string of `len` bytes is within
/// [`MAX_BUFFER_BYTES`].
///
/// # Errors
///
/// [`FaultKind::Bound`] when it is not.
pub const fn check_len(len: usize) -> Result<(), FaultKind>
{
    if len > MAX_BUFFER_BYTES
    {
        return Err(FaultKind::Bound);
    }
    Ok(())
}

/// Check that a package of `n` elements is within [`MAX_PACKAGE_ELEMENTS`].
///
/// # Errors
///
/// [`FaultKind::Bound`] when it is not.
pub const fn check_count(n: usize) -> Result<(), FaultKind>
{
    if n > MAX_PACKAGE_ELEMENTS
    {
        return Err(FaultKind::Bound);
    }
    Ok(())
}

impl Data
{
    /// A copy of the value, every allocation fallible.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NoMemory`] when an allocation fails.
    pub fn try_clone(&self) -> Result<Self, FaultKind>
    {
        Ok(match self
        {
            Self::Uninitialized => Self::Uninitialized,
            Self::Integer(v) => Self::Integer(*v),
            Self::String(s) => Self::String(bytes_of(s)?),
            Self::Buffer(b) => Self::Buffer(bytes_of(b)?),
            Self::Package(p) => Self::Package(clone_all(p)?),
            Self::Name(n) =>
            {
                let mut segs = vec_with(n.segs.len())?;
                segs.extend_from_slice(&n.segs);
                Self::Name(Name {
                    root: n.root,
                    up: n.up,
                    segs,
                })
            }
            Self::Ref(r) => Self::Ref(r.try_clone()?),
        })
    }

    /// The bytes the value occupies, its own and its elements', which the
    /// evaluator counts against [`crate::MAX_EVAL_ALLOC`].
    #[must_use]
    pub fn weight(&self) -> usize
    {
        let own = size_of::<Self>();
        match self
        {
            Self::Uninitialized | Self::Integer(_) => own,
            Self::String(b) | Self::Buffer(b) => own.saturating_add(b.len()),
            Self::Package(p) => p.iter().map(Self::weight).fold(own, usize::saturating_add),
            Self::Name(n) => own.saturating_add(n.segs.len().saturating_mul(4)),
            Self::Ref(r) => own.saturating_add(r.weight()),
        }
    }

    /// The nesting depth of packages in the value: 0 for a value that is
    /// not a package, 1 for a package that holds no package.
    #[must_use]
    pub fn depth(&self) -> usize
    {
        match self
        {
            Self::Package(p) => p
                .iter()
                .map(Self::depth)
                .max()
                .unwrap_or(0)
                .saturating_add(1),
            Self::Ref(r) => r.depth(),
            Self::Uninitialized
            | Self::Integer(_)
            | Self::String(_)
            | Self::Buffer(_)
            | Self::Name(_) => 0,
        }
    }

    /// Whether the value is an integer, a string or a buffer: a type the
    /// conversions of ACPI 6.5 § 19.3.5.7 start from.
    #[must_use]
    pub const fn is_computational(&self) -> bool
    {
        matches!(self, Self::Integer(_) | Self::String(_) | Self::Buffer(_))
    }

    /// The `ObjectType` number of the value (ACPI 6.5 § 19.6.97).
    #[must_use]
    pub const fn type_number(&self) -> u64
    {
        match self
        {
            Self::Uninitialized | Self::Name(_) => 0,
            Self::Integer(_) => 1,
            Self::String(_) => 2,
            Self::Buffer(_) => 3,
            Self::Package(_) => 4,
            Self::Ref(_) => 0x14,
        }
    }
}

// ── Implicit conversions (ACPI 6.5 § 19.3.5.7) ───────────────────────────

/// The value of the hexadecimal digit `b`.
fn hex_digit(b: u8) -> Option<u64>
{
    char::from(b).to_digit(16).map(u64::from)
}

/// The integer a buffer's first bytes give, little-endian: a shorter buffer
/// is zero-extended and a longer one truncated to the integer's size.
#[must_use]
pub fn buffer_integer(b: &[u8], w: IntWidth) -> u64
{
    b.iter()
        .take(w.bytes())
        .rev()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

/// Implicit conversion to an integer.
///
/// A string is read as a hexadecimal number from its first character to its
/// first non-hexadecimal one, at most as many digits as the integer holds (8
/// or 16); no `0x` prefix is read, and a string with no digit gives 0. A
/// buffer is [`buffer_integer`].
///
/// # Errors
///
/// [`FaultKind::Type`] for a value that is not an integer, a string or a
/// buffer, and [`FaultKind::Uninitialized`] for no value.
pub fn integer(d: &Data, w: IntWidth) -> Result<u64, FaultKind>
{
    match d
    {
        Data::Integer(v) => Ok(*v & w.mask()),
        Data::String(s) => Ok(s
            .iter()
            .take(w.bytes().saturating_mul(2))
            .map_while(|b| hex_digit(*b))
            .fold(0u64, |acc, digit| (acc << 4) | digit)),
        Data::Buffer(b) => Ok(buffer_integer(b, w)),
        Data::Uninitialized => Err(FaultKind::Uninitialized),
        Data::Package(_) | Data::Name(_) | Data::Ref(_) => Err(FaultKind::Type),
    }
}

/// The bytes of an integer, little-endian, as many as the integer holds.
///
/// # Errors
///
/// [`FaultKind::NoMemory`] when the allocation fails.
pub fn integer_bytes(v: u64, w: IntWidth) -> Result<Vec<u8>, FaultKind>
{
    let bytes = v.to_le_bytes();
    bytes_of(bytes.get(..w.bytes()).unwrap_or(&bytes))
}

/// Implicit conversion to a buffer: an integer's bytes, little-endian; a
/// string's characters and its terminating NUL.
///
/// # Errors
///
/// [`FaultKind::Type`] for a value that is not an integer, a string or a
/// buffer, [`FaultKind::Uninitialized`] for no value, [`FaultKind::Bound`]
/// past [`MAX_BUFFER_BYTES`], and [`FaultKind::NoMemory`].
pub fn buffer(d: &Data, w: IntWidth) -> Result<Vec<u8>, FaultKind>
{
    match d
    {
        Data::Integer(v) => integer_bytes(*v, w),
        Data::String(s) =>
        {
            let len = s.len().saturating_add(1);
            check_len(len)?;
            let mut out = vec_with(len)?;
            out.extend_from_slice(s);
            out.push(0);
            Ok(out)
        }
        Data::Buffer(b) => bytes_of(b),
        Data::Uninitialized => Err(FaultKind::Uninitialized),
        Data::Package(_) | Data::Name(_) | Data::Ref(_) => Err(FaultKind::Type),
    }
}

/// How an integer or a buffer is written as text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Radix
{
    /// Implicit conversion: an integer as all its hexadecimal digits, a
    /// buffer as `0x`-prefixed byte values separated by spaces.
    Implicit,
    /// `ToHexString`: an integer as `0x` and its digits without leading
    /// zeros, a buffer as `0x`-prefixed byte values separated by commas.
    Hex,
    /// `ToDecimalString`: an integer in decimal, a buffer as decimal byte
    /// values separated by commas.
    Decimal,
}

/// Append the digits of `v` in base `base` (10 or 16) to `out`, `min`
/// digits at least.
fn digits(out: &mut Vec<u8>, v: u64, base: u32, min: usize) -> Result<(), FaultKind>
{
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    let mut rest = v;
    let base64 = u64::from(base);
    for slot in &mut tmp
    {
        if rest == 0 && n >= min.max(1)
        {
            break;
        }
        let digit = u32::try_from(rest.checked_rem(base64).unwrap_or(0)).unwrap_or(0);
        let c = char::from_digit(digit, base)
            .unwrap_or('0')
            .to_ascii_uppercase();
        *slot = u8::try_from(c).unwrap_or(b'0');
        rest = rest.checked_div(base64).unwrap_or(0);
        n = n.saturating_add(1);
    }
    out.try_reserve(n).map_err(|_| FaultKind::NoMemory)?;
    out.extend(tmp.iter().take(n).rev());
    Ok(())
}

/// Append `bytes` to `out`.
fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FaultKind>
{
    out.try_reserve(bytes.len())
        .map_err(|_| FaultKind::NoMemory)?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Conversion to a string, implicit or by `ToHexString` or
/// `ToDecimalString` as `radix` says; a string is copied.
///
/// # Errors
///
/// [`FaultKind::Type`] for a value that is not an integer, a string or a
/// buffer, [`FaultKind::Uninitialized`] for no value, [`FaultKind::Bound`]
/// past [`MAX_BUFFER_BYTES`], and [`FaultKind::NoMemory`].
pub fn string(d: &Data, w: IntWidth, radix: Radix) -> Result<Vec<u8>, FaultKind>
{
    let mut out = Vec::new();
    match d
    {
        Data::Integer(v) =>
        {
            let v = *v & w.mask();
            match radix
            {
                Radix::Implicit => digits(&mut out, v, 16, w.bytes().saturating_mul(2))?,
                Radix::Hex =>
                {
                    put(&mut out, b"0x")?;
                    digits(&mut out, v, 16, 1)?;
                }
                Radix::Decimal => digits(&mut out, v, 10, 1)?,
            }
        }
        Data::String(s) => return bytes_of(s),
        Data::Buffer(b) =>
        {
            check_len(b.len().saturating_mul(5))?;
            let sep: &[u8] = if radix == Radix::Implicit { b" " } else { b"," };
            for (i, byte) in b.iter().enumerate()
            {
                if i > 0
                {
                    put(&mut out, sep)?;
                }
                if radix == Radix::Decimal
                {
                    digits(&mut out, u64::from(*byte), 10, 1)?;
                }
                else
                {
                    put(&mut out, b"0x")?;
                    digits(&mut out, u64::from(*byte), 16, 2)?;
                }
            }
        }
        Data::Uninitialized => return Err(FaultKind::Uninitialized),
        Data::Package(_) | Data::Name(_) | Data::Ref(_) => return Err(FaultKind::Type),
    }
    Ok(out)
}

/// Convert `d` implicitly to the type of `like`: an integer, a string or a
/// buffer.
///
/// # Errors
///
/// [`FaultKind::Type`] when `like` is not one of those types, and the
/// faults of the conversion.
pub fn convert_like(d: &Data, like: &Data, w: IntWidth) -> Result<Data, FaultKind>
{
    Ok(match like
    {
        Data::Integer(_) => Data::Integer(integer(d, w)?),
        Data::String(_) => Data::String(string(d, w, Radix::Implicit)?),
        Data::Buffer(_) => Data::Buffer(buffer(d, w)?),
        Data::Uninitialized => return Err(FaultKind::Uninitialized),
        Data::Package(_) | Data::Name(_) | Data::Ref(_) => return Err(FaultKind::Type),
    })
}

// ── Explicit conversions and data operators (ACPI 6.5 § 19.6) ────────────

/// `ToInteger`: an integer as it is; a string as a decimal number, or a
/// hexadecimal one after a `0x` prefix, up to its first character that is
/// not a digit; a buffer as [`buffer_integer`].
///
/// # Errors
///
/// [`FaultKind::Range`] for a string whose number does not fit the integer,
/// and the faults of [`integer`].
pub fn explicit_integer(d: &Data, w: IntWidth) -> Result<u64, FaultKind>
{
    let Data::String(s) = d
    else
    {
        return integer(d, w);
    };
    let (base, body) = match s.as_slice()
    {
        [b'0', b'x' | b'X', rest @ ..] => (16u32, rest),
        _ => (10u32, s.as_slice()),
    };
    let mut acc = 0u64;
    for b in body
    {
        let Some(digit) = char::from(*b).to_digit(base)
        else
        {
            break;
        };
        acc = acc
            .checked_mul(u64::from(base))
            .and_then(|v| v.checked_add(u64::from(digit)))
            .filter(|v| *v <= w.mask())
            .ok_or(FaultKind::Range)?;
    }
    Ok(acc)
}

/// `ToString`: the bytes of `b` up to its first NUL, at most `len`.
///
/// # Errors
///
/// [`FaultKind::NoMemory`] when the allocation fails.
pub fn bytes_to_string(b: &[u8], len: u64) -> Result<Vec<u8>, FaultKind>
{
    let limit = usize::try_from(len).unwrap_or(usize::MAX).min(b.len());
    let head = b.get(..limit).unwrap_or(&[]);
    let end = head.iter().position(|c| *c == 0).unwrap_or(limit);
    bytes_of(head.get(..end).unwrap_or(&[]))
}

/// `Mid`: `len` bytes of a string or buffer from `index`, as many as there
/// are; an empty one when `index` is past the end.
///
/// # Errors
///
/// [`FaultKind::Type`] for a source that is not a string or a buffer, and
/// [`FaultKind::NoMemory`].
pub fn mid(d: &Data, index: u64, len: u64) -> Result<Data, FaultKind>
{
    let slice = |b: &[u8]| {
        let start = usize::try_from(index).unwrap_or(usize::MAX).min(b.len());
        let end = start
            .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
            .min(b.len());
        bytes_of(b.get(start..end).unwrap_or(&[]))
    };
    match d
    {
        Data::String(s) => Ok(Data::String(slice(s)?)),
        Data::Buffer(b) => Ok(Data::Buffer(slice(b)?)),
        Data::Uninitialized => Err(FaultKind::Uninitialized),
        Data::Integer(_) | Data::Package(_) | Data::Name(_) | Data::Ref(_) => Err(FaultKind::Type),
    }
}

/// Append `b` to `a` within [`MAX_BUFFER_BYTES`].
fn join(mut a: Vec<u8>, b: &[u8]) -> Result<Vec<u8>, FaultKind>
{
    check_len(a.len().saturating_add(b.len()))?;
    put(&mut a, b)?;
    Ok(a)
}

/// `Concatenate`: the type of `a` decides. Two integers give a buffer of
/// both, little-endian; a string gives a string, `b` converted to one; a
/// buffer gives a buffer, `b` converted to one.
///
/// # Errors
///
/// [`FaultKind::Type`] when `a` is not an integer, a string or a buffer,
/// [`FaultKind::Bound`] past [`MAX_BUFFER_BYTES`], and the faults of the
/// conversions.
pub fn concat(a: &Data, b: &Data, w: IntWidth) -> Result<Data, FaultKind>
{
    Ok(match a
    {
        Data::Integer(v) =>
        {
            let second = integer_bytes(integer(b, w)?, w)?;
            Data::Buffer(join(integer_bytes(*v, w)?, &second)?)
        }
        Data::String(s) =>
        {
            let second = string(b, w, Radix::Implicit)?;
            Data::String(join(bytes_of(s)?, &second)?)
        }
        Data::Buffer(x) =>
        {
            let second = buffer(b, w)?;
            Data::Buffer(join(bytes_of(x)?, &second)?)
        }
        Data::Uninitialized => return Err(FaultKind::Uninitialized),
        Data::Package(_) | Data::Name(_) | Data::Ref(_) => return Err(FaultKind::Type),
    })
}

/// The length of a resource template up to its end tag, which is not
/// counted. A template with no end tag is malformed.
fn template_body(t: &[u8]) -> Result<usize, FaultKind>
{
    let mut at = 0usize;
    while let Some(&tag) = t.get(at)
    {
        let len = if tag & 0x80 == 0
        {
            if (tag >> 3) & 0xF == 0xF
            {
                return Ok(at);
            }
            usize::from(tag & 7).saturating_add(1)
        }
        else
        {
            let lo = t.get(at.saturating_add(1)).ok_or(FaultKind::Type)?;
            let hi = t.get(at.saturating_add(2)).ok_or(FaultKind::Type)?;
            usize::from(u16::from_le_bytes([*lo, *hi])).saturating_add(3)
        };
        at = at.saturating_add(len);
    }
    Err(FaultKind::Type)
}

/// `ConcatenateResTemplate`: the descriptors of `a`, then those of `b`,
/// then one end tag whose checksum byte is 0. An empty buffer is an empty
/// template.
///
/// # Errors
///
/// [`FaultKind::Type`] for a buffer that is not a resource template,
/// [`FaultKind::Bound`] past [`MAX_BUFFER_BYTES`], and
/// [`FaultKind::NoMemory`].
pub fn concat_templates(a: &[u8], b: &[u8]) -> Result<Vec<u8>, FaultKind>
{
    let body = |t: &[u8]| {
        if t.is_empty()
        {
            Ok(0)
        }
        else
        {
            template_body(t)
        }
    };
    let (la, lb) = (body(a)?, body(b)?);
    let out = bytes_of(a.get(..la).unwrap_or(&[]))?;
    let out = join(out, b.get(..lb).unwrap_or(&[]))?;
    join(out, &[0x79, 0])
}

/// Compare `a` with `b` converted to the type of `a`, as `LEqual`,
/// `LGreater`, `LLess` and `Match` do: integers by value, strings and
/// buffers byte by byte, a prefix of the other first.
///
/// # Errors
///
/// [`FaultKind::Type`] when `a` is not an integer, a string or a buffer,
/// and the faults of the conversion.
pub fn compare(a: &Data, b: &Data, w: IntWidth) -> Result<Ordering, FaultKind>
{
    Ok(match a
    {
        Data::Integer(x) => (*x & w.mask()).cmp(&integer(b, w)?),
        Data::String(x) => x.as_slice().cmp(string(b, w, Radix::Implicit)?.as_slice()),
        Data::Buffer(x) => x.as_slice().cmp(buffer(b, w)?.as_slice()),
        Data::Uninitialized => return Err(FaultKind::Uninitialized),
        Data::Package(_) | Data::Name(_) | Data::Ref(_) => return Err(FaultKind::Type),
    })
}

/// `FromBCD`: the integer whose decimal digits are the nibbles of `v`.
///
/// # Errors
///
/// [`FaultKind::Range`] for a nibble above 9.
pub fn from_bcd(v: u64, w: IntWidth) -> Result<u64, FaultKind>
{
    let mut out = 0u64;
    for i in (0..w.bits().checked_div(4).unwrap_or(0)).rev()
    {
        let nibble = v.checked_shr(i.saturating_mul(4)).unwrap_or(0) & 0xF;
        if nibble > 9
        {
            return Err(FaultKind::Range);
        }
        out = out
            .checked_mul(10)
            .and_then(|o| o.checked_add(nibble))
            .ok_or(FaultKind::Range)?;
    }
    Ok(out & w.mask())
}

/// `ToBCD`: the BCD form of `v`, one decimal digit per nibble.
///
/// # Errors
///
/// [`FaultKind::Range`] when `v` has more digits than the integer has
/// nibbles.
pub fn to_bcd(v: u64, w: IntWidth) -> Result<u64, FaultKind>
{
    let mut out = 0u64;
    let mut rest = v & w.mask();
    let mut shift = 0u32;
    while rest != 0
    {
        if shift >= w.bits()
        {
            return Err(FaultKind::Range);
        }
        out |= rest
            .checked_rem(10)
            .unwrap_or(0)
            .checked_shl(shift)
            .unwrap_or(0);
        rest = rest.checked_div(10).unwrap_or(0);
        shift = shift.saturating_add(4);
    }
    Ok(out)
}
