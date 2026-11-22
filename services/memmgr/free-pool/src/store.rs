// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/store.rs

//! The stream a compressed chunk's pages are stored as
//! (`services/memmgr/docs/memory-pool.md` § Eviction).
//!
//! For each page the chunk's backed mask names, in page order, the stream
//! holds a two-byte little-endian header and the page's bytes: header
//! [`ZERO_PAGE`] for a page whose bytes are all zero, which takes nothing
//! more; a header from 1 to `PAGE_BYTES - 1`, the length of the page's
//! compressed stream ([`crate::compress`]), which follows; or [`RAW_PAGE`]
//! for a page that does not compress below a page, whose bytes follow as
//! they are. The stream lies in whole store pages from their start, so a
//! chunk whose every backed page is zero is the empty stream and takes none.
//! A page is decoded by reading the stream in the same order, so the stream
//! needs no index and no length.
//!
//! A raw chunk, whose stream gains nothing, is written to a swap slot as its
//! backed pages alone, in page order ([`RawPages`]); a restore reads either
//! through [`PageReader`].

use crate::compress::{self, CodecError, HashTable, PAGE_BYTES};

/// The header of a page whose bytes are all zero.
pub const ZERO_PAGE: u16 = 0;

/// The header of a page stored as it is.
#[expect(clippy::cast_possible_truncation, reason = "PAGE_BYTES is 4096")]
pub const RAW_PAGE: u16 = PAGE_BYTES as u16;

// Hard size budget: the raw header, and every compressed length below it,
// fit the header's two bytes.
const _: () = assert!(PAGE_BYTES <= u16::MAX as usize);

/// Bytes of a page's header.
const HEADER_BYTES: usize = 2;

/// Encode the pages of a chunk whose backed mask is `backed` into the start of
/// `out`, reading page `i` through `page(i)` for each bit `i` set, and using
/// `table` as the compressor's ([`compress::compress`]). Returns the
/// stream's length, 0 when every page is zero (the empty stream, which fits
/// any `out`, an empty one too), or `None` when it does not fit `out`, so a
/// caller that sizes `out` below what the chunk's pages take in RAM learns
/// that storing them gains nothing.
pub fn encode_chunk<'a>(
    backed: u16,
    mut page: impl FnMut(u32) -> &'a [u8; PAGE_BYTES],
    out: &mut [u8],
    table: &mut HashTable,
) -> Option<usize>
{
    let mut len: usize = 0;
    let mut nonzero = false;
    for i in (0..u16::BITS).filter(|&i| backed.checked_shr(i).is_some_and(|b| b & 1 != 0))
    {
        let bytes = page(i);
        let body = len.checked_add(HEADER_BYTES)?;
        let header = if bytes.iter().all(|&b| b == 0)
        {
            ZERO_PAGE
        }
        else
        {
            let room = out.len().saturating_sub(body);
            let window =
                out.get_mut(body..body.checked_add(room.min(PAGE_BYTES.saturating_sub(1)))?)?;
            if let Some(n) = compress::compress(bytes, window, table)
            {
                u16::try_from(n).ok()?
            }
            else
            {
                out.get_mut(body..body.checked_add(PAGE_BYTES)?)?
                    .copy_from_slice(bytes);
                RAW_PAGE
            }
        };
        nonzero |= header != ZERO_PAGE;
        match out.get_mut(len..body)
        {
            Some(slot) => slot.copy_from_slice(&header.to_le_bytes()),
            // While every page so far is zero the stream may still be the
            // empty one, so a header past `out` is no overflow yet: `len`
            // then lies past `out`, and a later non-zero page's write fails.
            None if !nonzero =>
            {}
            None => return None,
        }
        let taken = if header == RAW_PAGE
        {
            PAGE_BYTES
        }
        else
        {
            usize::from(header)
        };
        len = body.checked_add(taken)?;
    }
    Some(if nonzero { len } else { 0 })
}

/// The store pages a stream of `len` bytes takes.
#[must_use]
pub const fn store_pages(len: usize) -> u64
{
    // A `usize` count of pages fits a `u64` on every target.
    len.div_ceil(PAGE_BYTES) as u64
}

/// A source of a chunk's backed pages, read one at a time in page order, as a
/// restore fills them.
pub trait PageReader
{
    /// Write every byte of the next page into `page`.
    ///
    /// # Errors
    /// [`CodecError::Malformed`] when the source cannot give the page whole;
    /// `page` then holds a partial page.
    fn next_page(&mut self, page: &mut [u8; PAGE_BYTES]) -> Result<(), CodecError>;
}

/// A reader over a raw chunk's bytes: its backed pages, whole and in page
/// order, with nothing between them.
pub struct RawPages<'a>
{
    bytes: &'a [u8],
}

impl<'a> RawPages<'a>
{
    /// A reader at the start of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self
    {
        Self { bytes }
    }
}

impl PageReader for RawPages<'_>
{
    /// Copy the next page's bytes into `page`.
    ///
    /// # Errors
    /// [`CodecError::Malformed`] when fewer than a page's bytes are left;
    /// `page` is then unchanged.
    fn next_page(&mut self, page: &mut [u8; PAGE_BYTES]) -> Result<(), CodecError>
    {
        let (next, rest) = self
            .bytes
            .split_first_chunk::<PAGE_BYTES>()
            .ok_or(CodecError::Malformed)?;
        page.copy_from_slice(next);
        self.bytes = rest;
        Ok(())
    }
}

/// A reader over one chunk's stream, which hands out its pages in the order
/// [`encode_chunk`] wrote them.
pub struct Decoder<'a>
{
    stream: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a>
{
    /// A reader at the start of `stream`, which may run on past the chunk's
    /// last page, as a stream does to the end of its last store page. The
    /// empty stream reads as zero pages.
    #[must_use]
    pub const fn new(stream: &'a [u8]) -> Self
    {
        Self { stream, pos: 0 }
    }
}

impl PageReader for Decoder<'_>
{
    /// Write every byte of the next page of the stream into `page`.
    ///
    /// # Errors
    /// [`CodecError::Malformed`] when the stream ends inside the page, its
    /// header is past [`RAW_PAGE`], or its compressed bytes are malformed
    /// ([`compress::decompress`]); `page` then holds a partial page.
    fn next_page(&mut self, page: &mut [u8; PAGE_BYTES]) -> Result<(), CodecError>
    {
        if self.stream.is_empty()
        {
            page.fill(0);
            return Ok(());
        }
        let body = self
            .pos
            .checked_add(HEADER_BYTES)
            .ok_or(CodecError::Malformed)?;
        let header = self
            .stream
            .get(self.pos..body)
            .and_then(|h| h.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or(CodecError::Malformed)?;
        let taken = match header
        {
            ZERO_PAGE =>
            {
                page.fill(0);
                0
            }
            RAW_PAGE =>
            {
                let raw = self
                    .stream
                    .get(body..body.checked_add(PAGE_BYTES).ok_or(CodecError::Malformed)?)
                    .ok_or(CodecError::Malformed)?;
                page.copy_from_slice(raw);
                PAGE_BYTES
            }
            n if n < RAW_PAGE =>
            {
                let n = usize::from(n);
                let packed = self
                    .stream
                    .get(body..body.checked_add(n).ok_or(CodecError::Malformed)?)
                    .ok_or(CodecError::Malformed)?;
                compress::decompress(packed, page)?;
                n
            }
            _ => return Err(CodecError::Malformed),
        };
        self.pos = body.checked_add(taken).ok_or(CodecError::Malformed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::compress::HASH_ENTRIES;

    fn pages() -> Vec<[u8; PAGE_BYTES]>
    {
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut v = vec![[0u8; PAGE_BYTES]; 16];
        // Page 1: random, stored raw.
        for b in &mut v[1]
        {
            *b = next().to_le_bytes()[0];
        }
        // Pages 2 and 3: compressible.
        for (i, b) in v[2].iter_mut().enumerate()
        {
            *b = u8::try_from(i % 11).unwrap();
        }
        v[3][100] = 9;
        // Page 0 and the rest stay zero.
        v
    }

    fn decode(stream: &[u8], backed: u16) -> Vec<(u32, [u8; PAGE_BYTES])>
    {
        let mut d = Decoder::new(stream);
        (0..16)
            .filter(|i| (backed >> i) & 1 != 0)
            .map(|i| {
                let mut p = [0xEEu8; PAGE_BYTES];
                d.next_page(&mut p).unwrap();
                (i, p)
            })
            .collect()
    }

    #[test]
    fn a_chunk_round_trips_with_zero_raw_and_compressed_pages_and_holes()
    {
        let pages = pages();
        let backed: u16 = 0b1000_0000_0000_1111;
        let mut out = vec![0u8; 16 * PAGE_BYTES];
        let mut table = Box::new([0u16; HASH_ENTRIES]);
        let len = encode_chunk(backed, |i| &pages[i as usize], &mut out, &mut table).unwrap();
        // Two zero pages take their headers; the raw page a page; the two
        // compressible pages far less.
        assert!(len > PAGE_BYTES + 10 && len < PAGE_BYTES + 400, "{len}");
        assert_eq!(store_pages(len), 2);
        // The stream reads back the same, with trailing bytes of its last
        // store page ignored.
        for (i, p) in decode(&out[..2 * PAGE_BYTES], backed)
        {
            assert_eq!(p, pages[i as usize], "page {i}");
        }
    }

    #[test]
    fn an_all_zero_chunk_takes_no_store_page()
    {
        let zero = [0u8; PAGE_BYTES];
        let mut out = vec![0u8; 64];
        let mut table = Box::new([0u16; HASH_ENTRIES]);
        let len = encode_chunk(0xFFFF, |_| &zero, &mut out, &mut table).unwrap();
        assert_eq!(len, 0);
        assert_eq!(store_pages(len), 0);
        // The empty stream reads back as zero pages.
        for (_, p) in decode(&[], 0xFFFF)
        {
            assert_eq!(p, zero);
        }
    }

    #[test]
    fn an_all_zero_chunk_is_the_empty_stream_whatever_the_output_length()
    {
        let zero = [0u8; PAGE_BYTES];
        let mut table = Box::new([0u16; HASH_ENTRIES]);
        // One backed page, whose gain limit leaves no output byte at all.
        assert_eq!(encode_chunk(0b1, |_| &zero, &mut [], &mut table), Some(0));
        // A whole chunk, into less than its pages' headers take.
        let mut out = [0u8; 3];
        assert_eq!(
            encode_chunk(0xFFFF, |_| &zero, &mut out, &mut table),
            Some(0)
        );
    }

    #[test]
    fn a_zero_page_header_past_the_output_refuses_a_stream_with_data()
    {
        let pages = pages();
        let mut table = Box::new([0u16; HASH_ENTRIES]);
        // Page 0 is zero and page 3 compressible: the zero page's header fits
        // no empty output, and the stream is not empty.
        assert_eq!(
            encode_chunk(0b1001, |i| &pages[i as usize], &mut [], &mut table),
            None
        );
        // Page 3, then the zero page 4, whose header lands past an output
        // that holds page 3's stream alone.
        let mut out = vec![0u8; PAGE_BYTES];
        let len = encode_chunk(0b1000, |i| &pages[i as usize], &mut out, &mut table).unwrap();
        let mut out = vec![0u8; len];
        assert_eq!(
            encode_chunk(0b1_1000, |i| &pages[i as usize], &mut out, &mut table),
            None
        );
    }

    #[test]
    fn a_stream_that_does_not_fit_is_refused()
    {
        let pages = pages();
        let mut table = Box::new([0u16; HASH_ENTRIES]);
        // The random page alone needs a page and its header.
        let mut out = vec![0u8; PAGE_BYTES];
        assert_eq!(
            encode_chunk(0b10, |i| &pages[i as usize], &mut out, &mut table),
            None
        );
        let mut out = vec![0u8; PAGE_BYTES + 2];
        assert_eq!(
            encode_chunk(0b10, |i| &pages[i as usize], &mut out, &mut table),
            Some(PAGE_BYTES + 2)
        );
    }

    #[test]
    fn a_truncated_or_corrupt_stream_is_refused()
    {
        let mut p = [0u8; PAGE_BYTES];
        assert_eq!(
            Decoder::new(&[0x01, 0x10]).next_page(&mut p),
            Err(CodecError::Malformed)
        );
        assert_eq!(
            Decoder::new(&[0x00, 0x10, 1]).next_page(&mut p),
            Err(CodecError::Malformed)
        );
        assert_eq!(
            Decoder::new(&[3, 0, 0x10, 1, 0]).next_page(&mut p),
            Err(CodecError::Malformed)
        );
    }

    #[test]
    fn raw_pages_hand_out_whole_pages_in_order_and_refuse_a_short_one()
    {
        let src = pages();
        let mut tail: Vec<u8> = src[..3].iter().flatten().copied().collect();
        tail.extend_from_slice(&[7; 10]);
        let mut r = RawPages::new(&tail);
        let mut p = [0u8; PAGE_BYTES];
        for want in &src[..3]
        {
            r.next_page(&mut p).unwrap();
            assert_eq!(&p, want);
        }
        // Ten bytes are left, short of a page: refused, the page unchanged.
        assert_eq!(r.next_page(&mut p), Err(CodecError::Malformed));
        assert_eq!(&p, &src[2]);
        assert_eq!(
            RawPages::new(&[]).next_page(&mut p),
            Err(CodecError::Malformed)
        );
    }
}
