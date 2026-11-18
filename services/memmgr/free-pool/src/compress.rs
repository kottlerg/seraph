// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/compress.rs

//! The page codec of memmgr's compressed store
//! (`services/memmgr/docs/memory-pool.md` § Eviction): an LZ4-class block
//! compressor over one page, and its decompressor.
//!
//! A compressed page is a series of sequences. Each starts with a token byte
//! whose high nibble is its literal count and whose low nibble is its match
//! length less [`MIN_MATCH`]; a nibble of 15 is followed by length bytes that
//! each add their value, the last of them below 255. The literals follow, then,
//! unless they complete the page, the match: a two-byte little-endian offset
//! back from the current position, and the match length's extra bytes. The
//! sequence that completes the page carries no match, and the stream ends
//! with it.
//!
//! The compressor is a greedy single pass over a hash table of the page's
//! 4-byte prefixes, which the caller supplies, so the codec takes no large
//! stack frame and holds no state. The decompressor checks every length and
//! offset against its input and its output, so a stream it was not given by
//! [`compress`] is refused, never read or written past.

use syscall_abi::PAGE_SIZE;

/// Bytes of one page, the unit the codec works on.
#[expect(clippy::cast_possible_truncation, reason = "PAGE_SIZE is 4096")]
pub const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// Log2 of the entries of a [`HashTable`].
const HASH_LOG: u32 = 12;

/// Entries of a [`HashTable`].
pub const HASH_ENTRIES: usize = 1 << HASH_LOG;

/// The compressor's match table: for each hash of a 4-byte prefix, the
/// position after the last place in the page it was seen, or 0 for none. A
/// page's positions fit a `u16`, so the table is 8 KiB.
pub type HashTable = [u16; HASH_ENTRIES];

// Hard size budget: every position after a byte of the page fits an entry.
const _: () = assert!(PAGE_BYTES <= u16::MAX as usize);

/// The shortest match a sequence encodes: a match takes three bytes of the
/// stream, its offset and its token's share, so a shorter one gains nothing.
const MIN_MATCH: usize = 4;

/// A nibble value that says length bytes follow.
const NIBBLE_MORE: usize = 15;

/// The value of a length byte that says another follows.
const LENGTH_MORE: usize = 255;

/// Misses after the last match over which the compressor steps one byte
/// further at a time, so a page with nothing to match costs a fraction of
/// its bytes in table probes. A tuning value that bounds no capacity.
const SKIP_LOG: u32 = 5;

/// Why [`decompress`] refused a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError
{
    /// The stream ends inside a sequence, a length or offset leaves the page,
    /// an offset is zero, or bytes follow the sequence that completes the
    /// page.
    Malformed,
}

/// Compress `page` into the start of `out` using `table`, which this call
/// clears first. Returns the bytes written, or `None` when the stream does
/// not fit `out`; `out` then holds a partial stream.
pub fn compress(page: &[u8; PAGE_BYTES], out: &mut [u8], table: &mut HashTable) -> Option<usize>
{
    table.fill(0);
    let mut w = Writer { out, len: 0 };
    let mut anchor: usize = 0;
    let mut at: usize = 0;
    let mut misses: usize = 0;
    while let Some(word) = read_u32(page, at)
    {
        let slot = table.get_mut(hash(word))?;
        let seen = usize::from(*slot);
        // `at` lies below the page's bytes, so `at + 1` fits a `u16` (the
        // assertion above).
        *slot = u16::try_from(at.saturating_add(1)).ok()?;
        if let Some(earlier) = seen.checked_sub(1)
            && read_u32(page, earlier) == Some(word)
        {
            let len = match_len(
                page,
                earlier.saturating_add(MIN_MATCH),
                at.saturating_add(MIN_MATCH),
            )
            .saturating_add(MIN_MATCH);
            w.sequence(
                page.get(anchor..at)?,
                Some((at.saturating_sub(earlier), len)),
            )?;
            at = at.saturating_add(len);
            anchor = at;
            misses = 0;
            continue;
        }
        misses = misses.saturating_add(1);
        at = at.saturating_add(1usize.saturating_add(misses.checked_shr(SKIP_LOG).unwrap_or(0)));
    }
    if anchor < PAGE_BYTES
    {
        w.sequence(page.get(anchor..)?, None)?;
    }
    Some(w.len)
}

/// Decompress `src`, one stream [`compress`] wrote, into `page`, writing
/// every byte of it.
///
/// # Errors
/// [`CodecError::Malformed`] for a stream [`compress`] did not write;
/// `page` then holds a partial page.
pub fn decompress(src: &[u8], page: &mut [u8; PAGE_BYTES]) -> Result<(), CodecError>
{
    let mut r = Reader { src, pos: 0 };
    let mut out: usize = 0;
    while out < PAGE_BYTES
    {
        let token = r.byte()?;
        let literals = r.length(usize::from(token.checked_shr(4).unwrap_or(0)))?;
        let end = out
            .checked_add(literals)
            .filter(|&e| e <= PAGE_BYTES)
            .ok_or(CodecError::Malformed)?;
        page.get_mut(out..end)
            .ok_or(CodecError::Malformed)?
            .copy_from_slice(r.take(literals)?);
        out = end;
        if out == PAGE_BYTES
        {
            break;
        }
        let offset = usize::from(u16::from_le_bytes([r.byte()?, r.byte()?]));
        let len = r
            .length(usize::from(token & 0x0F))?
            .checked_add(MIN_MATCH)
            .ok_or(CodecError::Malformed)?;
        let from = out
            .checked_sub(offset)
            .filter(|_| offset != 0)
            .ok_or(CodecError::Malformed)?;
        let end = out
            .checked_add(len)
            .filter(|&e| e <= PAGE_BYTES)
            .ok_or(CodecError::Malformed)?;
        // Byte by byte, front to back: a match may overlap its own output,
        // repeating the `offset` bytes before it.
        for (src_at, dst_at) in (from..).zip(out..end)
        {
            let b = *page.get(src_at).ok_or(CodecError::Malformed)?;
            *page.get_mut(dst_at).ok_or(CodecError::Malformed)? = b;
        }
        out = end;
    }
    if r.pos == src.len()
    {
        Ok(())
    }
    else
    {
        Err(CodecError::Malformed)
    }
}

/// The little-endian word at `at`, or `None` when fewer than four bytes
/// remain.
fn read_u32(page: &[u8], at: usize) -> Option<u32>
{
    let bytes = page.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// The table entry of a 4-byte prefix: Knuth's multiplicative hash, its top
/// [`HASH_LOG`] bits.
fn hash(word: u32) -> usize
{
    let h = word
        .wrapping_mul(2_654_435_761)
        .checked_shr(32 - HASH_LOG)
        .unwrap_or(0);
    // At most `HASH_LOG` bits, so it fits a `usize`.
    usize::try_from(h).unwrap_or(0)
}

/// How many bytes from `later` repeat those from `earlier`, up to the end of
/// the page.
fn match_len(page: &[u8], earlier: usize, later: usize) -> usize
{
    let (Some(a), Some(b)) = (page.get(earlier..), page.get(later..))
    else
    {
        return 0;
    };
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// The nibble a length takes in a token: the length itself up to 14, and
/// [`NIBBLE_MORE`] for 15 and above.
fn nibble(len: usize) -> u8
{
    u8::try_from(len.min(NIBBLE_MORE)).unwrap_or(0x0F)
}

/// A bounded output cursor.
struct Writer<'a>
{
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_>
{
    fn byte(&mut self, b: u8) -> Option<()>
    {
        *self.out.get_mut(self.len)? = b;
        self.len = self.len.checked_add(1)?;
        Some(())
    }

    fn bytes(&mut self, src: &[u8]) -> Option<()>
    {
        let end = self.len.checked_add(src.len())?;
        self.out.get_mut(self.len..end)?.copy_from_slice(src);
        self.len = end;
        Some(())
    }

    /// The length bytes of a length whose nibble is [`NIBBLE_MORE`].
    fn extra(&mut self, len: usize) -> Option<()>
    {
        if len < NIBBLE_MORE
        {
            return Some(());
        }
        let mut rest = len.saturating_sub(NIBBLE_MORE);
        while rest >= LENGTH_MORE
        {
            self.byte(0xFF)?;
            rest = rest.saturating_sub(LENGTH_MORE);
        }
        self.byte(u8::try_from(rest).ok()?)
    }

    /// One sequence: `literals`, then the match `(offset, len)` when there is
    /// one.
    fn sequence(&mut self, literals: &[u8], matched: Option<(usize, usize)>) -> Option<()>
    {
        let match_extra = matched.map_or(0, |(_, len)| len.saturating_sub(MIN_MATCH));
        self.byte(nibble(literals.len()).wrapping_shl(4) | nibble(match_extra))?;
        self.extra(literals.len())?;
        self.bytes(literals)?;
        if let Some((offset, _)) = matched
        {
            self.bytes(&u16::try_from(offset).ok()?.to_le_bytes())?;
            self.extra(match_extra)?;
        }
        Some(())
    }
}

/// A bounded input cursor.
struct Reader<'a>
{
    src: &'a [u8],
    pos: usize,
}

impl Reader<'_>
{
    fn byte(&mut self) -> Result<u8, CodecError>
    {
        let b = *self.src.get(self.pos).ok_or(CodecError::Malformed)?;
        self.pos = self.pos.checked_add(1).ok_or(CodecError::Malformed)?;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], CodecError>
    {
        let end = self.pos.checked_add(n).ok_or(CodecError::Malformed)?;
        let bytes = self.src.get(self.pos..end).ok_or(CodecError::Malformed)?;
        self.pos = end;
        Ok(bytes)
    }

    /// A length whose token nibble is `nibble`: the nibble, plus its length
    /// bytes when it is [`NIBBLE_MORE`]. A length past a page is refused as
    /// soon as it passes one, so the bytes read stay bounded.
    fn length(&mut self, nibble: usize) -> Result<usize, CodecError>
    {
        let mut len = nibble;
        if nibble != NIBBLE_MORE
        {
            return Ok(len);
        }
        loop
        {
            let b = usize::from(self.byte()?);
            len = len
                .checked_add(b)
                .filter(|&l| l <= PAGE_BYTES)
                .ok_or(CodecError::Malformed)?;
            if b != LENGTH_MORE
            {
                return Ok(len);
            }
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A deterministic xorshift generator, so a failure reproduces.
    struct Rng(u64);

    impl Rng
    {
        fn next(&mut self) -> u64
        {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn byte(&mut self) -> u8
        {
            self.next().to_le_bytes()[0]
        }

        fn page(&mut self) -> Box<[u8; PAGE_BYTES]>
        {
            let mut p = Box::new([0u8; PAGE_BYTES]);
            for b in &mut *p
            {
                *b = self.byte();
            }
            p
        }
    }

    fn table() -> Box<HashTable>
    {
        Box::new([0; HASH_ENTRIES])
    }

    /// Compress `page` into a buffer of `room` bytes, decompress it again,
    /// and check the round trip; returns the stream's length, or `None` when it
    /// did not fit.
    fn round_trip(page: &[u8; PAGE_BYTES], room: usize) -> Option<usize>
    {
        let mut out = vec![0u8; room];
        let len = compress(page, &mut out, &mut table())?;
        let mut back = Box::new([0xA5u8; PAGE_BYTES]);
        decompress(&out[..len], &mut back).unwrap();
        assert_eq!(&back[..], &page[..]);
        Some(len)
    }

    #[test]
    fn a_zero_page_compresses_to_a_few_bytes_and_back()
    {
        let len = round_trip(&[0u8; PAGE_BYTES], PAGE_BYTES).unwrap();
        assert!(len < 32, "{len}");
    }

    #[test]
    fn a_random_page_does_not_fit_below_a_page_but_round_trips_with_room()
    {
        let mut rng = Rng(0x1234_5678_9ABC_DEF1);
        for _ in 0..16
        {
            let page = rng.page();
            assert_eq!(round_trip(&page, PAGE_BYTES - 1), None);
            // Literals cost a token and length bytes beyond their own.
            assert!(round_trip(&page, 2 * PAGE_BYTES).is_some());
        }
    }

    #[test]
    fn repetitive_and_structured_pages_round_trip_smaller()
    {
        let mut pages: Vec<Box<[u8; PAGE_BYTES]>> = Vec::new();
        // A repeating period shorter than a match: overlapping copies.
        let mut p = Box::new([0u8; PAGE_BYTES]);
        for (i, b) in p.iter_mut().enumerate()
        {
            *b = b"ab"[i % 2];
        }
        pages.push(p);
        // A pattern of 64-bit words, as a heap of counters.
        let mut p = Box::new([0u8; PAGE_BYTES]);
        for (i, w) in p.as_chunks_mut::<8>().0.iter_mut().enumerate()
        {
            *w = (u64::try_from(i).unwrap() * 3).to_le_bytes();
        }
        pages.push(p);
        // Text with a random tail, so the final sequence is literals.
        let mut p = Box::new([0u8; PAGE_BYTES]);
        let text = b"memmgr evicts cold chunks into a compressed store. ";
        for (i, b) in p.iter_mut().enumerate()
        {
            *b = text[i % text.len()];
        }
        let mut rng = Rng(77);
        for b in &mut p[PAGE_BYTES - 7..]
        {
            *b = rng.byte();
        }
        pages.push(p);
        // A page that ends in a match reaching its last byte.
        let mut p = Box::new([7u8; PAGE_BYTES]);
        p[0] = 1;
        pages.push(p);
        for page in &pages
        {
            let len = round_trip(page, PAGE_BYTES - 1).unwrap();
            assert!(len < PAGE_BYTES * 3 / 4, "{len}");
        }
    }

    #[test]
    fn half_random_pages_round_trip_in_every_mix()
    {
        let mut rng = Rng(0xDEAD_BEEF);
        for split in [1, 3, 4, 5, 15, 16, 17, 270, 2048, 4091, 4095]
        {
            let mut p = rng.page();
            for b in &mut p[split..]
            {
                *b = 0x5A;
            }
            round_trip(&p, 2 * PAGE_BYTES).unwrap();
        }
    }

    #[test]
    fn a_stream_that_does_not_fit_its_buffer_is_refused()
    {
        let page = [0u8; PAGE_BYTES];
        assert_eq!(compress(&page, &mut [0u8; 2], &mut table()), None);
    }

    #[test]
    fn malformed_streams_are_refused()
    {
        let mut page = Box::new([0u8; PAGE_BYTES]);
        let cases: &[&[u8]] = &[
            // Empty: no byte of the page.
            &[],
            // One literal, then the stream ends where an offset belongs.
            &[0x10, 1],
            // A match with offset 0.
            &[0x10, 1, 0, 0],
            // A match reaching before the page.
            &[0x10, 1, 2, 0],
            // A literal length past the page.
            &[
                0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF,
            ],
            // A literal run longer than its bytes.
            &[0x50, 1, 2],
        ];
        for case in cases
        {
            assert_eq!(
                decompress(case, &mut page),
                Err(CodecError::Malformed),
                "{case:?}"
            );
        }
        // Bytes after the sequence that completes the page.
        let mut out = vec![0u8; PAGE_BYTES];
        let len = compress(&[3u8; PAGE_BYTES], &mut out, &mut table()).unwrap();
        out[len] = 0;
        assert_eq!(
            decompress(&out[..=len], &mut page),
            Err(CodecError::Malformed)
        );
        // The same stream cut short.
        assert_eq!(
            decompress(&out[..len - 1], &mut page),
            Err(CodecError::Malformed)
        );
    }

    #[test]
    fn random_and_mutated_streams_never_read_or_write_past_their_slices()
    {
        let mut rng = Rng(42);
        let mut page = Box::new([0u8; PAGE_BYTES]);
        for _ in 0..2000
        {
            let len = usize::try_from(rng.next() % 64).unwrap();
            let junk: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            let _ = decompress(&junk, &mut page);
        }
        let mut text = Box::new([0u8; PAGE_BYTES]);
        for (i, b) in text.iter_mut().enumerate()
        {
            *b = u8::try_from(i / 7 % 13).unwrap();
        }
        let mut out = vec![0u8; 2 * PAGE_BYTES];
        let len = compress(&text, &mut out, &mut table()).unwrap();
        for _ in 0..2000
        {
            let mut s = out[..len].to_vec();
            let at = usize::try_from(rng.next()).unwrap() % len;
            s[at] = rng.byte();
            let _ = decompress(&s, &mut page);
        }
    }
}
