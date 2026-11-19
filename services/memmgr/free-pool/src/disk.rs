// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/disk.rs

//! The disk tier of the compressed store (`services/memmgr/docs/memory-pool.md`
//! § Disk tier): the swap slots memmgr hands the swap service, the sealing of a
//! chunk's stream into a slot's bytes, and what a fault on a chunk of each state
//! needs.
//!
//! A swap slot holds one chunk: its stream ([`crate::store`]), encrypted and
//! authenticated with ChaCha20-Poly1305 under memmgr's per-boot key, followed by
//! the tag. The nonce is a per-boot counter memmgr never repeats under the key,
//! recorded on the chunk's disk node, so the bytes of a slot open only as the
//! seal memmgr last made for the chunk that holds it: another chunk's bytes, an
//! older seal of the same chunk, or any change fail the tag.
//!
//! [`SwapSlots`] maps each taken slot to the disk node of its chunk, so a
//! request naming a slot finds the chunk, and keeps the free slots on a list
//! threaded through the same words, so a slot is taken and freed in constant
//! time. Its words grow a page at a time, as far as the highest slot ever taken,
//! so it costs memory in proportion to the slots in use at their peak, not to
//! the partition.

use crypto::chacha20poly1305::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use syscall_abi::PAGE_SIZE;

use crate::CHUNK_BYTES;
use crate::arena::NodeIdx;
use crate::chunk::{ChunkEntry, ChunkState};
use crate::index::WordStore;

/// Bytes of memmgr's per-boot key.
pub const KEY_BYTES: usize = KEY_LEN;

/// Bytes of a slot's tag, after its sealed stream.
pub const TAG_BYTES: usize = TAG_LEN;

/// Bytes of one swap slot: a chunk. A stream is stored only when it takes
/// fewer pages than the chunk, so a stream and its tag always fit.
pub const SLOT_BYTES: u64 = CHUNK_BYTES;

/// Slot-map words per page of storage.
pub const SLOT_WORDS_PER_PAGE: u64 = PAGE_SIZE / 8;

/// The tag of a free slot's word; its low bits name the next free slot.
const FREE: u64 = 1 << 63;

/// The end of the free list.
const END: u64 = FREE - 1;

/// The swap slots: which disk node each taken slot holds, and the free list.
pub struct SwapSlots<W>
{
    words: W,
    /// Words the storage holds.
    capacity: u64,
    /// Slots the swap service registered.
    total: u64,
    /// Slots below this have been taken at least once; their words are valid.
    high: u64,
    /// The first free slot below `high`, or [`END`].
    free_head: u64,
    /// Slots taken.
    used: u64,
}

impl<W: WordStore> SwapSlots<W>
{
    /// No slots, and no storage.
    pub const fn new(words: W) -> Self
    {
        Self {
            words,
            capacity: 0,
            total: 0,
            high: 0,
            free_head: END,
            used: 0,
        }
    }

    /// Slots the swap service registered.
    #[must_use]
    pub const fn total(&self) -> u64
    {
        self.total
    }

    /// Slots taken.
    #[must_use]
    pub const fn used(&self) -> u64
    {
        self.used
    }

    /// Slots free: registered and not taken.
    #[must_use]
    pub const fn free(&self) -> u64
    {
        self.total.saturating_sub(self.used)
    }

    /// Set the registered slot count to `total`. Returns `false`, changing
    /// nothing, when `total` is below a slot ever taken: a slot on the free
    /// list or in use would then lie past the swap service's partition.
    pub fn set_total(&mut self, total: u64) -> bool
    {
        if total < self.high || total > u64::from(u32::MAX)
        {
            return false;
        }
        self.total = total;
        true
    }

    /// Storage pages given so far; the next [`SwapSlots::add_page`] covers
    /// page `pages()`.
    #[must_use]
    pub const fn pages(&self) -> u64
    {
        self.capacity / SLOT_WORDS_PER_PAGE
    }

    /// Whether the next [`SwapSlots::take`] needs another page of storage:
    /// no free slot is listed, a registered slot was never taken, and the
    /// storage ends at it.
    #[must_use]
    pub const fn wants_page(&self) -> bool
    {
        self.free_head == END && self.high < self.total && self.high >= self.capacity
    }

    /// Give the map the next page of storage (words `[capacity, capacity +
    /// SLOT_WORDS_PER_PAGE)`).
    ///
    /// # Safety
    /// The store MUST accept [`WordStore::read`] and [`WordStore::write`] for
    /// every word in that range for the map's life.
    pub unsafe fn add_page(&mut self)
    {
        self.capacity = self.capacity.saturating_add(SLOT_WORDS_PER_PAGE);
    }

    fn word(&self, slot: u64) -> u64
    {
        debug_assert!(slot < self.capacity);
        if slot >= self.capacity
        {
            return FREE | END;
        }
        // SAFETY: `slot < capacity`, which `add_page`'s contract made valid.
        unsafe { self.words.read(slot) }
    }

    fn set_word(&mut self, slot: u64, v: u64)
    {
        debug_assert!(slot < self.capacity);
        if slot < self.capacity
        {
            // SAFETY: as in `word`.
            unsafe { self.words.write(slot, v) };
        }
    }

    /// Take a free slot for the disk node `node`: the most recently freed
    /// one, else the lowest never taken. `None` when every registered slot is
    /// taken, when the storage has no word for the next one
    /// ([`SwapSlots::wants_page`]), or for a node index with the free tag.
    pub fn take(&mut self, node: NodeIdx) -> Option<u32>
    {
        if node & FREE != 0
        {
            return None;
        }
        let slot = if self.free_head == END
        {
            if self.high >= self.total || self.high >= self.capacity
            {
                return None;
            }
            let slot = self.high;
            self.high = self.high.saturating_add(1);
            slot
        }
        else
        {
            let slot = self.free_head;
            self.free_head = self.word(slot) & !FREE;
            slot
        };
        self.set_word(slot, node);
        // At most `total` slots are taken, so the count stays below it.
        self.used = self.used.saturating_add(1);
        u32::try_from(slot).ok()
    }

    /// The disk node slot `slot` holds, or `None` when it is free or was
    /// never taken.
    #[must_use]
    pub fn node(&self, slot: u32) -> Option<NodeIdx>
    {
        let slot = u64::from(slot);
        if slot >= self.high
        {
            return None;
        }
        let w = self.word(slot);
        (w & FREE == 0).then_some(w)
    }

    /// Free slot `slot`. Returns `false`, changing nothing, when it is not
    /// taken.
    pub fn release(&mut self, slot: u32) -> bool
    {
        if self.node(slot).is_none()
        {
            return false;
        }
        let at = u64::from(slot);
        self.set_word(at, FREE | self.free_head);
        self.free_head = at;
        // The slot was taken, so the count is above zero.
        self.used = self.used.saturating_sub(1);
        true
    }

    /// The first taken slot at or past `from`, with its disk node.
    #[must_use]
    pub fn next_taken(&self, from: u32) -> Option<(u32, NodeIdx)>
    {
        (u64::from(from)..self.high).find_map(|slot| {
            let w = self.word(slot);
            if w & FREE == 0
            {
                u32::try_from(slot).ok().map(|s| (s, w))
            }
            else
            {
                None
            }
        })
    }
}

/// The nonce of the seal numbered `counter`: the counter's eight bytes, little
/// endian, then four zero bytes.
#[must_use]
pub fn nonce(counter: u64) -> [u8; NONCE_LEN]
{
    let mut n = [0u8; NONCE_LEN];
    for (dst, src) in n.iter_mut().zip(counter.to_le_bytes())
    {
        *dst = src;
    }
    n
}

/// Why a slot's bytes could not be made or opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError
{
    /// The bytes do not fit the buffer, or a slot, or are shorter than a tag.
    Size,
    /// The tag does not verify: the bytes are not the seal memmgr made of the
    /// chunk under that nonce.
    Tampered,
}

/// Seal the stream in the first `len` bytes of `buf` in place under `key`
/// with the nonce of `counter`, and write its tag right after it. Returns the
/// slot's bytes: `len` and the tag.
///
/// # Errors
/// [`SlotError::Size`] when the stream and its tag do not fit `buf` or a
/// slot; `buf` is then unchanged.
pub fn seal(
    key: &[u8; KEY_BYTES],
    counter: u64,
    buf: &mut [u8],
    len: usize,
) -> Result<usize, SlotError>
{
    let total = len.checked_add(TAG_BYTES).ok_or(SlotError::Size)?;
    if u64::try_from(total).map_or(true, |t| t > SLOT_BYTES) || total > buf.len()
    {
        return Err(SlotError::Size);
    }
    let (stream, rest) = buf.split_at_mut(len);
    let tag =
        chacha20poly1305::seal(key, &nonce(counter), &[], stream).map_err(|_| SlotError::Size)?;
    rest.get_mut(..TAG_BYTES)
        .ok_or(SlotError::Size)?
        .copy_from_slice(&tag);
    Ok(total)
}

/// Open the slot's bytes in the first `total` bytes of `buf` in place: check
/// the tag after the sealed stream under `key` and the nonce of `counter`, and
/// only on a match decrypt the stream. Returns the stream's length.
///
/// # Errors
/// [`SlotError::Size`] when `total` is shorter than a tag or past `buf` or a
/// slot, and [`SlotError::Tampered`] when the tag does not verify; the stream's
/// bytes are then unchanged.
pub fn open(
    key: &[u8; KEY_BYTES],
    counter: u64,
    buf: &mut [u8],
    total: usize,
) -> Result<usize, SlotError>
{
    let len = total.checked_sub(TAG_BYTES).ok_or(SlotError::Size)?;
    if u64::try_from(total).map_or(true, |t| t > SLOT_BYTES)
    {
        return Err(SlotError::Size);
    }
    let bytes = buf.get_mut(..total).ok_or(SlotError::Size)?;
    let (stream, tag) = bytes.split_at_mut(len);
    let tag: [u8; TAG_BYTES] = (&*tag).try_into().map_err(|_| SlotError::Size)?;
    chacha20poly1305::open(key, &nonce(counter), &[], stream, &tag)
        .map_err(|_| SlotError::Tampered)?;
    Ok(len)
}

/// The word a fault redirected to the swap service carries
/// (`FAULT_REDIRECT_WORD`): the slot in its low 32 bits and the slot's byte
/// count above them.
#[must_use]
pub const fn redirect_word(slot: u32, len: u16) -> u64
{
    ((len as u64) << 32) | slot as u64
}

/// What a fault on a chunk of a demand region needs before the page can be
/// backed, by the chunk's state (`services/memmgr/docs/memory-pool.md`
/// § Eviction, § Disk tier).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPath
{
    /// Nothing: the chunk is resident or unbacked, and the page is backed as
    /// any demand fault's.
    Back,
    /// The evicting chunk's runs mapped back.
    CancelEvict,
    /// The chunk restored from the store: compressed, or writing, whose store
    /// runs are kept until its write ends.
    RestoreFromStore,
    /// The fault redirected to the swap service, which reads the slot and
    /// hands memmgr its bytes (`SWAP_RESTORE`).
    Redirect,
    /// Declined: the chunk is on disk and no swap service is registered.
    DeclineUnregistered,
    /// Declined: the chunk's bytes failed authentication, and it is lost.
    DeclineLost,
}

/// The path a fault on a chunk whose entry is `entry` takes, with a swap
/// service registered or not.
#[must_use]
pub const fn fault_path(entry: &ChunkEntry, registered: Registered) -> FaultPath
{
    match entry.state()
    {
        ChunkState::Unbacked | ChunkState::Resident => FaultPath::Back,
        ChunkState::Evicting => FaultPath::CancelEvict,
        ChunkState::Compressed | ChunkState::Writing => FaultPath::RestoreFromStore,
        ChunkState::OnDisk => match registered
        {
            Registered::Yes => FaultPath::Redirect,
            Registered::No => FaultPath::DeclineUnregistered,
        },
        ChunkState::Lost => FaultPath::DeclineLost,
    }
}

/// Whether a swap service is registered to restore the chunks on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registered
{
    Yes,
    No,
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[derive(Default)]
    struct VecWords(Vec<u64>);

    impl WordStore for VecWords
    {
        unsafe fn read(&self, i: u64) -> u64
        {
            self.0[usize::try_from(i).unwrap()]
        }

        unsafe fn write(&mut self, i: u64, v: u64)
        {
            let i = usize::try_from(i).unwrap();
            if self.0.len() <= i
            {
                self.0.resize(i + 1, 0);
            }
            self.0[i] = v;
        }
    }

    fn slots(total: u64) -> SwapSlots<VecWords>
    {
        let mut s = SwapSlots::new(VecWords::default());
        assert!(s.set_total(total));
        s
    }

    const KEY: [u8; KEY_BYTES] = [7; KEY_BYTES];

    fn slot() -> usize
    {
        usize::try_from(SLOT_BYTES).unwrap()
    }

    #[test]
    fn slots_are_taken_from_the_freed_ones_first_then_in_order()
    {
        let mut s = slots(3);
        // No storage yet: the first take needs a page.
        assert!(s.wants_page());
        assert_eq!(s.take(10), None);
        // SAFETY: VecWords grows on write.
        unsafe { s.add_page() };
        assert!(!s.wants_page());
        assert_eq!(
            (s.take(10), s.take(11), s.take(12)),
            (Some(0), Some(1), Some(2))
        );
        assert_eq!((s.used(), s.free()), (3, 0));
        // Every registered slot is taken.
        assert_eq!(s.take(13), None);
        assert!(!s.wants_page());
        assert!(s.release(1));
        assert!(s.release(0));
        assert!(!s.release(0));
        assert_eq!((s.node(0), s.node(1), s.node(2)), (None, None, Some(12)));
        // The most recently freed slot goes first.
        assert_eq!((s.take(20), s.take(21)), (Some(0), Some(1)));
        assert_eq!((s.node(0), s.node(1)), (Some(20), Some(21)));
        assert_eq!(s.node(3), None);
    }

    #[test]
    fn the_slot_map_grows_a_page_at_a_time_as_far_as_the_highest_slot_taken()
    {
        let mut s = slots(SLOT_WORDS_PER_PAGE + 1);
        // SAFETY: VecWords grows on write.
        unsafe { s.add_page() };
        for i in 0..SLOT_WORDS_PER_PAGE
        {
            assert_eq!(s.take(i).map(u64::from), Some(i));
        }
        assert!(s.wants_page());
        assert_eq!(s.take(99), None);
        // A freed slot is taken without more storage.
        assert!(s.release(5));
        assert!(!s.wants_page());
        assert_eq!(s.take(99), Some(5));
        // SAFETY: VecWords grows on write.
        unsafe { s.add_page() };
        assert_eq!((s.take(100), s.pages()), (Some(512), 2));
    }

    #[test]
    fn the_slot_count_cannot_fall_below_a_slot_ever_taken()
    {
        let mut s = slots(4);
        // SAFETY: VecWords grows on write.
        unsafe { s.add_page() };
        s.take(1).unwrap();
        s.take(2).unwrap();
        assert!(s.release(1));
        assert!(!s.set_total(1));
        assert_eq!(s.total(), 4);
        assert!(s.set_total(2));
        assert!(!s.set_total(u64::from(u32::MAX) + 1));
        assert_eq!(s.next_taken(0), Some((0, 1)));
        assert_eq!(s.next_taken(1), None);
    }

    #[test]
    fn a_sealed_slot_opens_to_the_stream_under_its_own_nonce_only()
    {
        let stream: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut buf = vec![0u8; slot()];
        buf[..stream.len()].copy_from_slice(&stream);
        let total = seal(&KEY, 9, &mut buf, stream.len()).unwrap();
        assert_eq!(total, stream.len() + TAG_BYTES);
        assert_ne!(&buf[..stream.len()], &stream[..]);
        let sealed = buf.clone();
        // Another nonce, a flipped byte of the stream or of the tag, or a cut
        // fails the tag and leaves the bytes as they were.
        let mut other = sealed.clone();
        assert_eq!(open(&KEY, 8, &mut other, total), Err(SlotError::Tampered));
        assert_eq!(other, sealed);
        for at in [0, stream.len() - 1, stream.len(), total - 1]
        {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert_eq!(
                open(&KEY, 9, &mut bad, total),
                Err(SlotError::Tampered),
                "{at}"
            );
        }
        let mut cut = sealed.clone();
        assert_eq!(open(&KEY, 9, &mut cut, total - 1), Err(SlotError::Tampered));
        let mut good = sealed.clone();
        assert_eq!(open(&KEY, 9, &mut good, total), Ok(stream.len()));
        assert_eq!(&good[..stream.len()], &stream[..]);
    }

    #[test]
    fn a_slot_that_does_not_fit_is_refused_unchanged()
    {
        let mut buf = vec![1u8; 64];
        assert_eq!(
            seal(&KEY, 1, &mut buf, 64 - TAG_BYTES + 1),
            Err(SlotError::Size)
        );
        assert_eq!(buf, vec![1u8; 64]);
        let mut big = vec![0u8; slot() + 1];
        let len = slot() - TAG_BYTES + 1;
        assert_eq!(seal(&KEY, 1, &mut big, len), Err(SlotError::Size));
        assert_eq!(open(&KEY, 1, &mut buf, TAG_BYTES - 1), Err(SlotError::Size));
        assert_eq!(open(&KEY, 1, &mut buf, 65), Err(SlotError::Size));
        assert_eq!(open(&KEY, 1, &mut big, slot() + 1), Err(SlotError::Size));
        // The largest stream a slot holds, and the empty stream, round-trip.
        let len = slot() - TAG_BYTES;
        let total = seal(&KEY, 2, &mut big, len).unwrap();
        assert_eq!(open(&KEY, 2, &mut big, total), Ok(len));
        assert_eq!(seal(&KEY, 3, &mut buf, 0), Ok(TAG_BYTES));
        assert_eq!(open(&KEY, 3, &mut buf, TAG_BYTES), Ok(0));
    }

    #[test]
    fn a_fault_redirects_an_on_disk_chunk_only_while_a_swap_service_is_registered()
    {
        let resident = ChunkEntry::UNBACKED.back(0, 4, 7).unwrap();
        let evicting = resident.begin_evict(1).unwrap();
        let compressed = evicting.finish_evict(9).unwrap();
        let writing = compressed.begin_write(5).unwrap();
        let on_disk = writing.finish_write().unwrap();
        let lost = on_disk.lose().unwrap();
        for (entry, yes, no) in [
            (ChunkEntry::UNBACKED, FaultPath::Back, FaultPath::Back),
            (resident, FaultPath::Back, FaultPath::Back),
            (evicting, FaultPath::CancelEvict, FaultPath::CancelEvict),
            (
                compressed,
                FaultPath::RestoreFromStore,
                FaultPath::RestoreFromStore,
            ),
            (
                writing,
                FaultPath::RestoreFromStore,
                FaultPath::RestoreFromStore,
            ),
            (on_disk, FaultPath::Redirect, FaultPath::DeclineUnregistered),
            (lost, FaultPath::DeclineLost, FaultPath::DeclineLost),
        ]
        {
            assert_eq!(fault_path(&entry, Registered::Yes), yes, "{entry:?}");
            assert_eq!(fault_path(&entry, Registered::No), no, "{entry:?}");
        }
    }
}
