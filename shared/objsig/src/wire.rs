// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/wire.rs

//! Byte-wise little-endian fields over unaligned slices: a reader that fails
//! at the end of its slice and a writer that fails at the end of its buffer,
//! neither of which panics.

use crate::EncodeError;

/// A cursor that reads fields front to back.
pub(crate) struct Reader<'a>
{
    rest: &'a [u8],
}

impl<'a> Reader<'a>
{
    /// A reader at the start of `bytes`.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self
    {
        Self { rest: bytes }
    }

    /// The next `len` bytes; `None` when fewer remain.
    pub(crate) fn take(&mut self, len: usize) -> Option<&'a [u8]>
    {
        let (head, tail) = self.rest.split_at_checked(len)?;
        self.rest = tail;
        Some(head)
    }

    /// The next `N` bytes, borrowed; `None` when fewer remain.
    pub(crate) fn array_ref<const N: usize>(&mut self) -> Option<&'a [u8; N]>
    {
        let (head, tail) = self.rest.split_first_chunk::<N>()?;
        self.rest = tail;
        Some(head)
    }

    /// The next `N` bytes; `None` when fewer remain.
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]>
    {
        let (head, tail) = self.rest.split_first_chunk::<N>()?;
        self.rest = tail;
        Some(*head)
    }

    /// The next byte.
    pub(crate) fn u8(&mut self) -> Option<u8>
    {
        self.array::<1>().map(|[byte]| byte)
    }

    /// The next little-endian `u16`.
    pub(crate) fn u16(&mut self) -> Option<u16>
    {
        self.array().map(u16::from_le_bytes)
    }

    /// The next little-endian `u32`.
    pub(crate) fn u32(&mut self) -> Option<u32>
    {
        self.array().map(u32::from_le_bytes)
    }

    /// The next little-endian `u64`.
    pub(crate) fn u64(&mut self) -> Option<u64>
    {
        self.array().map(u64::from_le_bytes)
    }

    /// The bytes not yet read.
    pub(crate) const fn rest(&self) -> &'a [u8]
    {
        self.rest
    }
}

/// A cursor that writes fields front to back into a caller's buffer.
pub(crate) struct Writer<'a>
{
    out: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a>
{
    /// A writer at the start of `out`.
    pub(crate) const fn new(out: &'a mut [u8]) -> Self
    {
        Self { out, len: 0 }
    }

    /// Append `bytes`.
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<(), EncodeError>
    {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(EncodeError::TooLong)?;
        let slot = self
            .out
            .get_mut(self.len..end)
            .ok_or(EncodeError::BufferTooSmall)?;
        slot.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    /// The number of bytes written.
    pub(crate) const fn len(&self) -> usize
    {
        self.len
    }
}

/// The bytes of `parts`, concatenated into an array of their total length,
/// which the caller states as `N`: a part past it is dropped, and a short
/// total leaves zeros, both of which the callers' layout tests would show.
pub(crate) fn concat<const N: usize>(parts: &[&[u8]]) -> [u8; N]
{
    let mut out = [0u8; N];
    for (slot, byte) in out
        .iter_mut()
        .zip(parts.iter().flat_map(|part| part.iter()))
    {
        *slot = *byte;
    }
    out
}
