// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/bytes.rs

//! Fixed-width field reads from a firmware table's bytes.
//!
//! A field is read only when it lies wholly inside the buffer; a field that
//! starts or ends past the buffer reads as zero. The table walkers bound every
//! structure against its declared length before reading its fields, so a zero
//! here is the value of a field the walker has already refused, never one it
//! acts on.

/// The `N` bytes at `off`, or `None` when they do not lie wholly inside `buf`.
fn field<const N: usize>(buf: &[u8], off: usize) -> Option<&[u8; N]>
{
    buf.get(off..).and_then(<[u8]>::first_chunk::<N>)
}

/// The byte at `off`, or zero past the end of `buf`.
pub(crate) fn read_u8(buf: &[u8], off: usize) -> u8
{
    buf.get(off).copied().unwrap_or(0)
}

/// The little-endian `u16` at `off`, or zero unless it lies wholly inside `buf`.
pub(crate) fn read_u16(buf: &[u8], off: usize) -> u16
{
    field(buf, off).map_or(0, |b| u16::from_le_bytes(*b))
}

/// The little-endian `u32` at `off`, or zero unless it lies wholly inside `buf`.
pub(crate) fn read_u32(buf: &[u8], off: usize) -> u32
{
    field(buf, off).map_or(0, |b| u32::from_le_bytes(*b))
}

/// The little-endian `u64` at `off`, or zero unless it lies wholly inside `buf`.
pub(crate) fn read_u64(buf: &[u8], off: usize) -> u64
{
    field(buf, off).map_or(0, |b| u64::from_le_bytes(*b))
}

/// The big-endian `u32` at `off`, or zero unless it lies wholly inside `buf`.
pub(crate) fn be_u32(buf: &[u8], off: usize) -> u32
{
    field(buf, off).map_or(0, |b| u32::from_be_bytes(*b))
}

/// The big-endian `u64` at `off`, or zero unless it lies wholly inside `buf`.
pub(crate) fn be_u64(buf: &[u8], off: usize) -> u64
{
    field(buf, off).map_or(0, |b| u64::from_be_bytes(*b))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_field_inside_the_buffer_reads_in_its_byte_order()
    {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        assert_eq!(read_u8(&buf, 8), 0x09);
        assert_eq!(read_u16(&buf, 1), 0x0302);
        assert_eq!(read_u32(&buf, 5), 0x0908_0706);
        assert_eq!(read_u64(&buf, 1), 0x0908_0706_0504_0302);
        assert_eq!(be_u32(&buf, 5), 0x0607_0809);
        assert_eq!(be_u64(&buf, 0), 0x0102_0304_0506_0708);
    }

    #[test]
    fn a_field_that_ends_or_starts_past_the_buffer_reads_as_zero()
    {
        let buf = [0xFF; 7];
        assert_eq!(read_u8(&buf, 7), 0);
        assert_eq!(read_u16(&buf, 6), 0);
        assert_eq!(read_u32(&buf, 4), 0);
        assert_eq!(read_u64(&buf, 0), 0);
        assert_eq!(be_u32(&buf, usize::MAX), 0);
        assert_eq!(be_u64(&buf, 3), 0);
    }
}
