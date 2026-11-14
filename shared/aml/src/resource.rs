// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/resource.rs

//! The resource-template decoder (ACPI 6.5 § 6.4): the byte list of a
//! `_CRS`, `_PRS` or `ResourceTemplate()` buffer, read as a sequence of small
//! and large resource descriptors up to the End Tag.
//!
//! [`descriptors`] yields one [`Resource`] per descriptor, in template order.
//! A descriptor whose body is shorter than its kind requires (or, for a
//! fixed-size kind, not exactly its size) yields [`Error::Malformed`] and the
//! iteration continues after it; a descriptor that runs past the slice
//! yields [`Error::Truncated`] and ends the iteration. A template without an
//! End Tag ends with the slice. Every read is bounds-checked and each step
//! advances, so any byte string terminates without a panic. No allocation.

use crate::encoding::le;

/// `_CRS` address-space resource type: memory.
pub const SPACE_MEMORY: u8 = 0;
/// Address-space resource type: I/O.
pub const SPACE_IO: u8 = 1;
/// Address-space resource type: bus number range.
pub const SPACE_BUS: u8 = 2;

/// Small descriptor kind of the End Tag.
const SMALL_END: u8 = 0xF;

/// Why a descriptor was not decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error
{
    /// A known descriptor whose body length does not fit its kind; the
    /// iteration continues after it.
    Malformed
    {
        /// Whether it is a large descriptor.
        large: bool,
        /// The descriptor kind (small: bits 6:3 of the tag; large: bits 6:0).
        kind: u8,
    },
    /// A descriptor running past the end of the template; the iteration ends.
    Truncated,
}

/// A small IRQ descriptor (kind 0x4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Irq
{
    /// Bit `n` set: IRQ `n` is described.
    pub mask: u16,
    /// The information byte, absent from the two-byte form (which means
    /// edge-triggered, active-high, exclusive).
    pub info: Option<u8>,
}

impl Irq
{
    /// Whether the interrupt is level-triggered (information bit 0 clear).
    #[must_use]
    pub fn level(&self) -> bool
    {
        self.info.is_some_and(|f| f & 1 == 0)
    }

    /// Whether the interrupt is active-low (information bit 3).
    #[must_use]
    pub fn active_low(&self) -> bool
    {
        self.info.is_some_and(|f| f & (1 << 3) != 0)
    }

    /// Whether the interrupt may be shared (information bit 4).
    #[must_use]
    pub fn shared(&self) -> bool
    {
        self.info.is_some_and(|f| f & (1 << 4) != 0)
    }

    /// Whether the interrupt can wake the system (information bit 5).
    #[must_use]
    pub fn wake(&self) -> bool
    {
        self.info.is_some_and(|f| f & (1 << 5) != 0)
    }
}

/// An Extended Interrupt descriptor (large kind 0x09).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtendedIrq<'a>
{
    /// The interrupt vector flags byte.
    pub flags: u8,
    /// The interrupt numbers, four little-endian bytes each: the count byte's
    /// entries, cut to those the descriptor holds.
    table: &'a [u8],
}

impl ExtendedIrq<'_>
{
    /// Whether the device consumes the interrupt (flag bit 0).
    #[must_use]
    pub const fn consumer(&self) -> bool
    {
        self.flags & 1 != 0
    }

    /// Whether the interrupt is level-triggered (flag bit 1 clear).
    #[must_use]
    pub const fn level(&self) -> bool
    {
        self.flags & (1 << 1) == 0
    }

    /// Whether the interrupt is active-low (flag bit 2).
    #[must_use]
    pub const fn active_low(&self) -> bool
    {
        self.flags & (1 << 2) != 0
    }

    /// Whether the interrupt may be shared (flag bit 3).
    #[must_use]
    pub const fn shared(&self) -> bool
    {
        self.flags & (1 << 3) != 0
    }

    /// Whether the interrupt can wake the system (flag bit 4).
    #[must_use]
    pub const fn wake(&self) -> bool
    {
        self.flags & (1 << 4) != 0
    }

    /// The interrupt numbers (GSIs on x86-64, wired sources on riscv64).
    pub fn lines(&self) -> impl Iterator<Item = u32> + '_
    {
        self.table
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
    }
}

/// Width of an Address Space descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressWidth
{
    /// `WordSpace` (large kind 0x08).
    Word,
    /// `DWordSpace` (large kind 0x07).
    DWord,
    /// `QWordSpace` (large kind 0x0A).
    QWord,
    /// `ExtendedSpace` (large kind 0x0B).
    Extended,
}

/// An Address Space descriptor: a memory, I/O or bus-number window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address
{
    /// The descriptor's encoding.
    pub width: AddressWidth,
    /// The resource type: [`SPACE_MEMORY`], [`SPACE_IO`], [`SPACE_BUS`], or
    /// 192-255 for a vendor-defined space.
    pub space: u8,
    /// General flags: bit 0 consumer (set) or producer (clear), bit 1
    /// subtractive decode, bit 2 minimum fixed, bit 3 maximum fixed.
    pub general_flags: u8,
    /// Type-specific flags.
    pub type_flags: u8,
    /// Address-space granularity.
    pub granularity: u64,
    /// Range minimum.
    pub min: u64,
    /// Range maximum.
    pub max: u64,
    /// Translation offset.
    pub translation: u64,
    /// Range length.
    pub length: u64,
}

impl Address
{
    /// Whether the device consumes the range (general flag bit 0), rather
    /// than produce it as a window for its children.
    #[must_use]
    pub const fn consumer(&self) -> bool
    {
        self.general_flags & 1 != 0
    }
}

/// One descriptor of a resource template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource<'a>
{
    /// IRQ descriptor.
    Irq(Irq),
    /// I/O Port descriptor (small kind 0x8).
    Io
    {
        /// Information byte: bit 0 set for 16-bit decode.
        info: u8,
        /// Range minimum base.
        min: u16,
        /// Range maximum base.
        max: u16,
        /// Base alignment.
        align: u8,
        /// Number of ports.
        len: u8,
    },
    /// Fixed Location I/O Port descriptor (small kind 0x9); the base is the
    /// 10-bit address it decodes.
    FixedIo
    {
        /// First port.
        base: u16,
        /// Number of ports.
        len: u8,
    },
    /// 24-bit Memory Range descriptor (large kind 0x01). Its addresses and
    /// length are stored in units of 256 bytes, and are given here in bytes.
    Memory24
    {
        /// Information byte: bit 0 set when writable.
        info: u8,
        /// Range minimum base.
        min: u32,
        /// Range maximum base.
        max: u32,
        /// Base alignment, in bytes; 0 means `0x1_0000`.
        align: u16,
        /// Range length.
        len: u32,
    },
    /// 32-bit Memory Range descriptor (large kind 0x05).
    Memory32
    {
        /// Information byte: bit 0 set when writable.
        info: u8,
        /// Range minimum base.
        min: u32,
        /// Range maximum base.
        max: u32,
        /// Base alignment.
        align: u32,
        /// Range length.
        len: u32,
    },
    /// 32-bit Fixed Memory Range descriptor (large kind 0x06).
    FixedMemory32
    {
        /// Information byte: bit 0 set when writable.
        info: u8,
        /// Range base.
        base: u32,
        /// Range length.
        len: u32,
    },
    /// `Word`, `DWord`, `QWord` or `Extended` Address Space descriptor.
    Address(Address),
    /// Extended Interrupt descriptor.
    ExtendedIrq(ExtendedIrq<'a>),
    /// Generic Register descriptor (large kind 0x02).
    GenericRegister
    {
        /// Address space ID.
        space: u8,
        /// Register bit width.
        bit_width: u8,
        /// Register bit offset.
        bit_offset: u8,
        /// Access size.
        access_size: u8,
        /// Register address.
        address: u64,
    },
    /// Any other descriptor: DMA, dependent functions, vendor-defined,
    /// GPIO, serial-bus and the rest, with its body.
    Other
    {
        /// Whether it is a large descriptor.
        large: bool,
        /// The descriptor kind.
        kind: u8,
        /// The descriptor's body (after its tag and, for a large one, its
        /// length).
        body: &'a [u8],
    },
}

/// The descriptors of the resource template `buf`, in order.
#[must_use]
pub const fn descriptors(buf: &[u8]) -> Descriptors<'_>
{
    Descriptors {
        buf,
        pos: 0,
        done: false,
    }
}

/// Iterator over the descriptors of a resource template; see [`descriptors`].
#[derive(Clone, Debug)]
pub struct Descriptors<'a>
{
    buf: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Iterator for Descriptors<'a>
{
    type Item = Result<Resource<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item>
    {
        if self.done
        {
            return None;
        }
        let Some(&tag) = self.buf.get(self.pos)
        else
        {
            self.done = true;
            return None;
        };
        let Some((large, kind, body, next)) = self.split(tag)
        else
        {
            self.done = true;
            return Some(Err(Error::Truncated));
        };
        if !large && kind == SMALL_END
        {
            self.done = true;
            return None;
        }
        self.pos = next;
        let decoded = if large
        {
            large_kind(kind, body)
        }
        else
        {
            small_kind(kind, body)
        };
        Some(decoded.ok_or(Error::Malformed { large, kind }))
    }
}

impl<'a> Descriptors<'a>
{
    /// The descriptor whose tag `tag` is at the current position: whether it
    /// is large, its kind, its body, and the offset after it. `None` when it
    /// runs past the slice.
    fn split(&self, tag: u8) -> Option<(bool, u8, &'a [u8], usize)>
    {
        if tag & 0x80 == 0
        {
            let body_at = self.pos.checked_add(1)?;
            let next = body_at.checked_add(usize::from(tag & 7))?;
            Some((false, (tag >> 3) & 0xF, self.buf.get(body_at..next)?, next))
        }
        else
        {
            let len = usize::try_from(le(self.buf, self.pos.checked_add(1)?, 2)?).ok()?;
            let body_at = self.pos.checked_add(3)?;
            let next = body_at.checked_add(len)?;
            Some((true, tag & 0x7F, self.buf.get(body_at..next)?, next))
        }
    }
}

/// Little-endian `u16` at `off` of `body`.
fn u16_at(body: &[u8], off: usize) -> Option<u16>
{
    u16::try_from(le(body, off, 2)?).ok()
}

/// Little-endian `u32` at `off` of `body`.
fn u32_at(body: &[u8], off: usize) -> Option<u32>
{
    u32::try_from(le(body, off, 4)?).ok()
}

/// Decode a small descriptor body of a kind other than the End Tag; `None`
/// when its length does not fit the kind.
fn small_kind(kind: u8, body: &[u8]) -> Option<Resource<'_>>
{
    match kind
    {
        0x4 =>
        {
            if !matches!(body.len(), 2 | 3)
            {
                return None;
            }
            Some(Resource::Irq(Irq {
                mask: u16_at(body, 0)?,
                info: body.get(2).copied(),
            }))
        }
        0x8 =>
        {
            if body.len() != 7
            {
                return None;
            }
            Some(Resource::Io {
                info: *body.first()?,
                min: u16_at(body, 1)?,
                max: u16_at(body, 3)?,
                align: *body.get(5)?,
                len: *body.get(6)?,
            })
        }
        0x9 =>
        {
            if body.len() != 3
            {
                return None;
            }
            Some(Resource::FixedIo {
                base: u16_at(body, 0)? & 0x3FF,
                len: *body.get(2)?,
            })
        }
        _ => Some(Resource::Other {
            large: false,
            kind,
            body,
        }),
    }
}

/// Decode a large descriptor body; `None` when its length does not fit the
/// kind.
fn large_kind(kind: u8, body: &[u8]) -> Option<Resource<'_>>
{
    match kind
    {
        0x01 =>
        {
            if body.len() != 9
            {
                return None;
            }
            let units = |off| u16_at(body, off).map(|v| u32::from(v) << 8);
            Some(Resource::Memory24 {
                info: *body.first()?,
                min: units(1)?,
                max: units(3)?,
                align: u16_at(body, 5)?,
                len: units(7)?,
            })
        }
        0x02 =>
        {
            if body.len() != 12
            {
                return None;
            }
            Some(Resource::GenericRegister {
                space: *body.first()?,
                bit_width: *body.get(1)?,
                bit_offset: *body.get(2)?,
                access_size: *body.get(3)?,
                address: le(body, 4, 8)?,
            })
        }
        0x05 =>
        {
            if body.len() != 17
            {
                return None;
            }
            Some(Resource::Memory32 {
                info: *body.first()?,
                min: u32_at(body, 1)?,
                max: u32_at(body, 5)?,
                align: u32_at(body, 9)?,
                len: u32_at(body, 13)?,
            })
        }
        0x06 =>
        {
            if body.len() != 9
            {
                return None;
            }
            Some(Resource::FixedMemory32 {
                info: *body.first()?,
                base: u32_at(body, 1)?,
                len: u32_at(body, 5)?,
            })
        }
        0x07 => address(AddressWidth::DWord, body),
        0x08 => address(AddressWidth::Word, body),
        0x0A => address(AddressWidth::QWord, body),
        0x0B => address(AddressWidth::Extended, body),
        0x09 =>
        {
            if body.len() < 6
            {
                return None;
            }
            let count = usize::from(*body.get(1)?);
            let avail = body.len().saturating_sub(2) / 4;
            let end = count.min(avail).checked_mul(4)?.checked_add(2)?;
            Some(Resource::ExtendedIrq(ExtendedIrq {
                flags: *body.first()?,
                table: body.get(2..end)?,
            }))
        }
        _ => Some(Resource::Other {
            large: true,
            kind,
            body,
        }),
    }
}

/// Decode an Address Space descriptor body of `width`. The five range values
/// follow the type, flag and (Extended only) revision bytes; a resource
/// source may follow them.
fn address(width: AddressWidth, body: &[u8]) -> Option<Resource<'_>>
{
    let (size, first): (usize, usize) = match width
    {
        AddressWidth::Word => (2, 3),
        AddressWidth::DWord => (4, 3),
        AddressWidth::QWord => (8, 3),
        AddressWidth::Extended => (8, 5),
    };
    let value =
        |i: usize| -> Option<u64> { le(body, first.checked_add(i.checked_mul(size)?)?, size) };
    let minimum = first.checked_add(size.checked_mul(5)?)?;
    let minimum = if width == AddressWidth::Extended
    {
        minimum.checked_add(8)?
    }
    else
    {
        minimum
    };
    if body.len() < minimum
    {
        return None;
    }
    Some(Resource::Address(Address {
        width,
        space: *body.first()?,
        general_flags: *body.get(1)?,
        type_flags: *body.get(2)?,
        granularity: value(0)?,
        min: value(1)?,
        max: value(2)?,
        translation: value(3)?,
        length: value(4)?,
    }))
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn all(buf: &[u8]) -> Vec<Result<Resource<'_>, Error>>
    {
        descriptors(buf).collect()
    }

    /// A `DWord` Address Space descriptor.
    fn addr32(space: u8, flags: u8, min: u32, len: u32) -> Vec<u8>
    {
        let mut d = vec![0x87, 23, 0, space, flags, 0];
        d.extend([0; 4]);
        d.extend(min.to_le_bytes());
        d.extend(min.wrapping_add(len).wrapping_sub(1).to_le_bytes());
        d.extend([0; 4]);
        d.extend(len.to_le_bytes());
        d
    }

    #[test]
    fn small_kinds()
    {
        let t = [
            0x47,
            1,
            0xF8,
            0x03,
            0xF8,
            0x03,
            1,
            8, // IO 0x3F8 count 8
            0x22,
            0x10,
            0x00, // IRQNoFlags {4}
            0x23,
            0x00,
            0x08,
            0b0011_1000, // IRQ level-low shared wake {11}
            0x4B,
            0x60,
            0xFC,
            0x05, // FixedIO 0x60 (upper bits ignored)
            0x2A,
            0x04,
            0x00, // DMA: Other
            0x79,
            0,
            0x47, // End Tag, then junk not read
        ];
        let l = all(&t);
        assert_eq!(l.len(), 5, "{l:?}");
        assert_eq!(
            l[0],
            Ok(Resource::Io {
                info: 1,
                min: 0x3F8,
                max: 0x3F8,
                align: 1,
                len: 8
            })
        );
        let Ok(Resource::Irq(irq)) = l[1]
        else
        {
            panic!("{:?}", l[1]);
        };
        assert_eq!(irq.mask, 1 << 4);
        assert!(!irq.level() && !irq.active_low() && !irq.shared() && !irq.wake());
        let Ok(Resource::Irq(irq)) = l[2]
        else
        {
            panic!("{:?}", l[2]);
        };
        assert_eq!(irq.mask, 1 << 11);
        assert!(irq.level() && irq.active_low() && irq.shared() && irq.wake());
        assert_eq!(l[3], Ok(Resource::FixedIo { base: 0x60, len: 5 }));
        assert!(matches!(
            l[4],
            Ok(Resource::Other {
                large: false,
                kind: 0x5,
                ..
            })
        ));
    }

    #[test]
    fn large_kinds()
    {
        let mut t = vec![
            0x86, 9, 0, 1, 0x00, 0x00, 0xD0, 0xFE, 0x00, 0x04, 0x00, 0x00,
        ];
        t.extend([
            0x85, 17, 0, 0, 0x00, 0x20, 0, 0, 0x00, 0x20, 0, 0, 1, 0, 0, 0, 0x00, 0x04, 0, 0,
        ]);
        t.extend([
            0x81, 9, 0, 1, 0x00, 0x10, 0xFF, 0x10, 0x00, 0x00, 0x01, 0x00,
        ]);
        t.extend([0x82, 12, 0, 1, 8, 0, 1, 0x00, 0x10, 0, 0, 0, 0, 0, 0]);
        t.extend(addr32(SPACE_MEMORY, 0x0C, 0x8000_0000, 0x1000_0000));
        t.extend([0x89, 10, 0, 0x0B, 2, 5, 0, 0, 0, 6, 0, 0, 0]);
        t.extend([0x8C, 2, 0, 0xAA, 0xBB]); // GPIO connection: Other
        t.extend([0x79, 0]);
        let l = all(&t);
        assert_eq!(l.len(), 7, "{l:?}");
        assert_eq!(
            l[0],
            Ok(Resource::FixedMemory32 {
                info: 1,
                base: 0xFED0_0000,
                len: 0x400
            })
        );
        assert_eq!(
            l[1],
            Ok(Resource::Memory32 {
                info: 0,
                min: 0x2000,
                max: 0x2000,
                align: 1,
                len: 0x400
            })
        );
        assert_eq!(
            l[2],
            Ok(Resource::Memory24 {
                info: 1,
                min: 0x10_0000,
                max: 0x10_FF00,
                align: 0,
                len: 0x100
            })
        );
        assert_eq!(
            l[3],
            Ok(Resource::GenericRegister {
                space: 1,
                bit_width: 8,
                bit_offset: 0,
                access_size: 1,
                address: 0x1000
            })
        );
        let Ok(Resource::Address(a)) = l[4]
        else
        {
            panic!("{:?}", l[4]);
        };
        assert_eq!(a.width, AddressWidth::DWord);
        assert_eq!(
            (a.space, a.min, a.max, a.length),
            (SPACE_MEMORY, 0x8000_0000, 0x8FFF_FFFF, 0x1000_0000)
        );
        assert!(!a.consumer());
        let Ok(Resource::ExtendedIrq(x)) = l[5]
        else
        {
            panic!("{:?}", l[5]);
        };
        assert!(x.consumer() && !x.level() && !x.active_low() && x.shared() && !x.wake());
        assert_eq!(x.lines().collect::<Vec<_>>(), vec![5, 6]);
        assert!(matches!(
            l[6],
            Ok(Resource::Other {
                large: true,
                kind: 0x0C,
                body: [0xAA, 0xBB]
            })
        ));
    }

    #[test]
    fn address_widths()
    {
        // Word bus range 0-0xFF, producer.
        let word = [0x88, 13, 0, 2, 0x0C, 0, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0, 1];
        let Some(Ok(Resource::Address(a))) = descriptors(&word).next()
        else
        {
            panic!();
        };
        assert_eq!(
            (a.width, a.space, a.min, a.max, a.length),
            (AddressWidth::Word, SPACE_BUS, 0, 0xFF, 0x100)
        );
        // QWord memory window.
        let mut q = vec![0x8A, 43, 0, 0, 0x0C, 0];
        for v in [0u64, 0x38_0000_0000, 0x38_7FFF_FFFF, 0, 0x8000_0000]
        {
            q.extend(v.to_le_bytes());
        }
        let Some(Ok(Resource::Address(a))) = descriptors(&q).next()
        else
        {
            panic!();
        };
        assert_eq!(
            (a.width, a.min, a.max, a.length),
            (
                AddressWidth::QWord,
                0x38_0000_0000,
                0x38_7FFF_FFFF,
                0x8000_0000
            )
        );
        // Extended: type, flags, type flags, revision, reserved, five values,
        // then the type-specific attribute.
        let mut e = vec![0x8B, 53, 0, 0, 1, 0, 1, 0];
        for v in [0u64, 0x1000, 0x1FFF, 0, 0x1000, 7]
        {
            e.extend(v.to_le_bytes());
        }
        let Some(Ok(Resource::Address(a))) = descriptors(&e).next()
        else
        {
            panic!();
        };
        assert_eq!(
            (a.width, a.min, a.length),
            (AddressWidth::Extended, 0x1000, 0x1000)
        );
        assert!(a.consumer());
    }

    #[test]
    fn malformed_continues_truncated_ends()
    {
        // FixedIO with a 4-byte body, then a good FixedIO.
        let t = [0x4C, 0x60, 0, 5, 0, 0x4B, 0x70, 0, 2, 0x79, 0];
        assert_eq!(
            all(&t),
            vec![
                Err(Error::Malformed {
                    large: false,
                    kind: 0x9
                }),
                Ok(Resource::FixedIo { base: 0x70, len: 2 })
            ]
        );
        // Short DWord address, then a good one.
        let mut t = vec![0x87, 3, 0, 0, 0, 0];
        t.extend(addr32(0, 1, 0x1000, 0x10));
        let l = all(&t);
        assert_eq!(l.len(), 2);
        assert_eq!(
            l[0],
            Err(Error::Malformed {
                large: true,
                kind: 0x07
            })
        );
        assert_eq!(l[1].as_ref().err(), None);
        // Past the end.
        assert_eq!(all(&[0x86, 9, 0, 0, 0]), vec![Err(Error::Truncated)]);
        assert_eq!(all(&[0x86, 9]), vec![Err(Error::Truncated)]);
        assert_eq!(all(&[0x47, 1, 2]), vec![Err(Error::Truncated)]);
        // No End Tag: ends with the slice.
        assert_eq!(all(&[0x4B, 0x60, 0x00, 0x05]).len(), 1);
        assert_eq!(all(&[]), Vec::new());
        // Extended interrupt count past its length: cut to what it holds.
        let l = all(&[0x89, 6, 0, 1, 9, 0x0A, 0, 0, 0]);
        let Ok(Resource::ExtendedIrq(x)) = l[0]
        else
        {
            panic!();
        };
        assert_eq!(x.lines().collect::<Vec<_>>(), vec![10]);
    }

    #[test]
    fn every_byte_string_terminates()
    {
        // Every 3-byte string, and every prefix of a mixed template.
        for a in 0..=255u8
        {
            for b in [0u8, 1, 2, 9, 0x2B, 0xFF]
            {
                for c in [0u8, 3, 0xFF]
                {
                    let t = [a, b, c];
                    assert!(descriptors(&t).count() <= 3);
                }
            }
        }
        let mut t = addr32(0, 1, 0x1000, 0x10);
        t.extend([0x22, 0x10, 0x00, 0x89, 6, 0, 1, 1, 0x0A, 0, 0, 0, 0x79, 0]);
        for k in 0..=t.len()
        {
            let _ = descriptors(&t[..k]).count();
        }
    }
}
