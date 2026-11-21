// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/fill.rs

//! The chunks a `FILL_REGION` request names, and the object page each page
//! it backs takes (services/memmgr/docs/ipc-interface.md § Label 36:
//! `FILL_REGION`): each page a chunk's mask names takes the next object page,
//! in chunk and page order, as a snapshot's chunk descriptors lay out the
//! pages they wrote.

use syscall_abi::PAGE_SIZE;

/// The most chunks one request names (`memmgr_labels::FILL_CHUNKS`, which
/// memmgr asserts equal).
pub const FILL_CHUNKS: usize = 4;

/// One chunk of a `FILL_REGION` request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FillChunk
{
    /// The chunk's base.
    pub va: u64,
    /// Its pages to back, bit `j` for page `j`.
    pub mask: u16,
    /// The object page its first named page takes.
    pub first: u64,
}

impl FillChunk
{
    /// The runs of consecutive pages `mask` names, each as its first page,
    /// its end and the object page its first page takes, in page order.
    pub fn runs(&self) -> impl Iterator<Item = (u32, u32, u64)> + '_
    {
        let mut at = 0u32;
        let mut taken = 0u64;
        core::iter::from_fn(move || {
            let rest = u32::from(self.mask).checked_shr(at).unwrap_or(0);
            if rest == 0
            {
                return None;
            }
            let first = at.saturating_add(rest.trailing_zeros());
            let len = rest
                .checked_shr(rest.trailing_zeros())
                .unwrap_or(0)
                .trailing_ones();
            let end = first.saturating_add(len);
            let object = self.first.saturating_add(taken);
            taken = taken.saturating_add(u64::from(len));
            at = end;
            Some((first, end, object))
        })
    }
}

/// The chunks of a request whose first object page is `first` and whose
/// words after the count are `words`, two a chunk (its base and its mask),
/// `n` chunks: each with the object page its first named page takes. `None`
/// for a count of 0 or past [`FILL_CHUNKS`] or the words, a base off a page
/// or not above the one before, a mask past 16 bits, or object pages that
/// overflow; that a base is a chunk's and its mask inside the chunk is the
/// caller's to check against the region. Also returns the object pages the
/// request takes.
#[must_use]
pub fn fill_chunks(first: u64, n: u64, words: &[u64]) -> Option<([FillChunk; FILL_CHUNKS], u64)>
{
    let n = usize::try_from(n)
        .ok()
        .filter(|&n| n != 0 && n <= FILL_CHUNKS)?;
    if words.len() < n.checked_mul(2)?
    {
        return None;
    }
    let mut chunks = [FillChunk::default(); FILL_CHUNKS];
    let mut taken = 0u64;
    let mut floor: Option<u64> = None;
    for (i, chunk) in chunks.iter_mut().enumerate().take(n)
    {
        let va = *words.get(i.checked_mul(2)?)?;
        let mask = u16::try_from(*words.get(i.checked_mul(2)?.checked_add(1)?)?).ok()?;
        if !va.is_multiple_of(PAGE_SIZE) || floor.is_some_and(|f| va <= f)
        {
            return None;
        }
        floor = Some(va);
        *chunk = FillChunk {
            va,
            mask,
            first: first.checked_add(taken)?,
        };
        taken = taken.checked_add(u64::from(mask.count_ones()))?;
    }
    first.checked_add(taken)?;
    Some((chunks, taken))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn each_named_page_takes_the_next_object_page_in_chunk_and_page_order()
    {
        let words = [0x10000, 0b1001, 0x30000, 0xFFFF, 0x50000, 0];
        let (chunks, taken) = fill_chunks(7, 3, &words).unwrap();
        assert_eq!(taken, 18);
        assert_eq!(
            chunks[..3],
            [
                FillChunk {
                    va: 0x10000,
                    mask: 0b1001,
                    first: 7
                },
                FillChunk {
                    va: 0x30000,
                    mask: 0xFFFF,
                    first: 9
                },
                FillChunk {
                    va: 0x50000,
                    mask: 0,
                    first: 25
                },
            ]
        );
        let runs: Vec<_> = chunks[0].runs().collect();
        assert_eq!(runs, [(0, 1, 7), (3, 4, 8)]);
        let runs: Vec<_> = chunks[1].runs().collect();
        assert_eq!(runs, [(0, 16, 9)]);
        assert_eq!(chunks[2].runs().count(), 0);
        let mixed = FillChunk {
            va: 0,
            mask: 0b0111_0000_1100_0010,
            first: 100,
        };
        let runs: Vec<_> = mixed.runs().collect();
        assert_eq!(runs, [(1, 2, 100), (6, 8, 101), (12, 15, 103)]);
    }

    #[test]
    fn a_request_out_of_order_off_a_page_or_past_its_bounds_is_refused()
    {
        assert!(fill_chunks(0, 0, &[]).is_none());
        let five = [0u64; 10];
        assert!(fill_chunks(0, 5, &five).is_none());
        assert!(fill_chunks(0, 2, &[0x10000, 1]).is_none());
        assert!(fill_chunks(0, 2, &[0x20000, 1, 0x10000, 1]).is_none());
        assert!(fill_chunks(0, 2, &[0x10000, 1, 0x10000, 1]).is_none());
        assert!(fill_chunks(0, 1, &[0x10001, 1]).is_none());
        assert!(fill_chunks(0, 1, &[0x10000, 0x1_0000]).is_none());
        assert!(fill_chunks(u64::MAX, 1, &[0x10000, 1]).is_none());
        assert!(fill_chunks(u64::MAX, 1, &[0x10000, 0]).is_some());
    }
}
