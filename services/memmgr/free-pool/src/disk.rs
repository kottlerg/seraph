// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/disk.rs

//! The disk tier of the compressed store (`services/memmgr/docs/memory-pool.md`
//! § Disk tier): the swap slots memmgr hands the swap service, the sealing of a
//! chunk's stream into a slot's bytes, and what a fault on a chunk of each state
//! needs.
//!
//! A swap slot holds one chunk, encrypted and authenticated with
//! ChaCha20-Poly1305 under memmgr's per-boot key: a compressed chunk's stream
//! ([`crate::store`]) followed by the tag, or a raw chunk's backed pages in page
//! order, which can fill the slot, so its tag is kept on the chunk's entry
//! ([`seal_detached`]). The nonce is a per-boot counter memmgr never repeats
//! under the key, recorded on the chunk's disk node, so the bytes of a slot open
//! only as the seal memmgr last made for the chunk that holds it: another
//! chunk's bytes, an older seal of the same chunk, or any change fail the tag.
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
use crate::chunk::{ChunkEntry, ChunkState, SealTag};
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
    /// nothing, when `total` is 0, or below a slot ever taken: a slot on the
    /// free list or in use would then lie past the swap service's partition.
    /// A count once registered is never withdrawn, so the commitments promised
    /// past the free pool on its slots keep their committed draws off the
    /// growth floor (`crate::Ledger::overcommits`).
    pub fn set_total(&mut self, total: u64) -> bool
    {
        if total == 0 || total < self.high || total > u64::from(u32::MAX)
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

/// Seal a raw chunk's pages, the first `len` bytes of `buf`, in place under
/// `key` with the nonce of `counter`. The pages can fill a slot, which then
/// has no room for the tag, so the slot's bytes are the `len` sealed bytes
/// alone and the tag is returned, for memmgr to keep on the chunk's entry
/// ([`crate::chunk::ChunkEntry::tag`]).
///
/// # Errors
/// [`SlotError::Size`] when `len` is 0 or past `buf` or a slot; `buf` is
/// then unchanged.
pub fn seal_detached(
    key: &[u8; KEY_BYTES],
    counter: u64,
    buf: &mut [u8],
    len: usize,
) -> Result<SealTag, SlotError>
{
    if len == 0 || u64::try_from(len).map_or(true, |l| l > SLOT_BYTES)
    {
        return Err(SlotError::Size);
    }
    let bytes = buf.get_mut(..len).ok_or(SlotError::Size)?;
    chacha20poly1305::seal(key, &nonce(counter), &[], bytes).map_err(|_| SlotError::Size)
}

/// Open a raw chunk's slot bytes, the first `len` bytes of `buf`, in place:
/// check `tag`, the tag [`seal_detached`] returned, under `key` and the
/// nonce of `counter`, and only on a match decrypt them.
///
/// # Errors
/// [`SlotError::Size`] when `len` is 0 or past `buf` or a slot, and
/// [`SlotError::Tampered`] when the tag does not verify; the bytes are then
/// unchanged.
pub fn open_detached(
    key: &[u8; KEY_BYTES],
    counter: u64,
    buf: &mut [u8],
    len: usize,
    tag: &SealTag,
) -> Result<(), SlotError>
{
    if len == 0 || u64::try_from(len).map_or(true, |l| l > SLOT_BYTES)
    {
        return Err(SlotError::Size);
    }
    let bytes = buf.get_mut(..len).ok_or(SlotError::Size)?;
    chacha20poly1305::open(key, &nonce(counter), &[], bytes, tag).map_err(|_| SlotError::Tampered)
}

/// Bits of a slot word's slot: [`WORD_SLOTS`] slots.
const SLOT_BITS: u32 = 28;

/// Bits of a slot word's length field, which holds the byte count less one
/// ([`len_field`]).
const LEN_BITS: u32 = 16;

/// The length field's mask.
const LEN_MASK: u64 = (1 << LEN_BITS) - 1;

// Hard size budget: the length field names every byte count from 1 to a full
// slot's, the bytes of a raw chunk of every page backed.
const _: () = assert!(1 << LEN_BITS == SLOT_BYTES);

/// Bits of a slot word's generation: the low bits of the nonce counter of the
/// seal the slot holds.
pub const GENERATION_BITS: u32 = 20;

const _: () = assert!(SLOT_BITS + LEN_BITS + GENERATION_BITS == 64);

/// The slots a slot word can name.
pub const WORD_SLOTS: u64 = 1 << SLOT_BITS;

/// The length field of a slot word naming `len` bytes: `len` less one, so the
/// field's 16 bits name every count from 1 byte to a full slot's 65536. A
/// slot's bytes are never none: a compressed chunk's hold at least its tag,
/// and a raw chunk's at least a page. A count of 0, or past a slot, names no
/// slot's bytes, and has no field of its own.
#[must_use]
pub const fn len_field(len: u32) -> u64
{
    (len.saturating_sub(1) as u64) & LEN_MASK
}

/// The byte count the slot word length field `field` names: the field plus
/// one ([`len_field`]).
#[must_use]
pub fn field_len(field: u64) -> u32
{
    // The mask keeps 16 bits, and one more is at most 65536, which a `u32`
    // holds.
    u32::try_from((field & LEN_MASK).saturating_add(1)).unwrap_or(u32::MAX)
}

/// The word naming slot `slot` while it holds the seal numbered `counter`,
/// of `len` bytes, 1 to a slot's: the slot in its low 28 bits, the length
/// field, the byte count less one ([`len_field`]), in the next 16, and the
/// counter's low [`GENERATION_BITS`] bits above them. A fault
/// redirected to the swap service carries it (`FAULT_REDIRECT_WORD`), as
/// `SWAP_TAKE`'s reply does, and `SWAP_RESTORE` names it back, so a request
/// made for one use of a slot is told from one made for a later use: the slot
/// freed, by a restore or a teardown, and taken again since. Two uses of a
/// slot share a word only when `2^GENERATION_BITS` seals, or a multiple,
/// came between them.
#[must_use]
pub const fn slot_word(slot: u32, len: u32, counter: u64) -> u64
{
    (counter << (SLOT_BITS + LEN_BITS))
        | (len_field(len) << SLOT_BITS)
        | (slot as u64 & (WORD_SLOTS - 1))
}

/// The slot a slot word names.
#[must_use]
pub fn word_slot(word: u64) -> u32
{
    // The mask keeps 28 bits, which a `u32` holds.
    u32::try_from(word & (WORD_SLOTS - 1)).unwrap_or(u32::MAX)
}

/// The byte count a slot word names, from its length field ([`field_len`]).
#[must_use]
pub fn word_len(word: u64) -> u32
{
    field_len(word >> SLOT_BITS)
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
    /// The chunk's own runs mapped back: an evicting chunk's, or a raw chunk's
    /// before or while its write.
    Remap,
    /// The chunk restored from the store: compressed, or writing after it was
    /// compressed, whose store runs are kept until its write ends.
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
        ChunkState::Evicting | ChunkState::Raw => FaultPath::Remap,
        ChunkState::Writing if entry.is_raw() => FaultPath::Remap,
        ChunkState::Compressed | ChunkState::Writing => FaultPath::RestoreFromStore,
        ChunkState::OnDisk => match registered
        {
            Registered::Yes => FaultPath::Redirect,
            Registered::No => FaultPath::DeclineUnregistered,
        },
        ChunkState::Lost => FaultPath::DeclineLost,
    }
}

/// What `MAKE_RESIDENT` does with a chunk of the range it walks, by the chunk's
/// state, with a swap service that registered a want Notification or not
/// (`services/memmgr/docs/memory-pool.md` § Eviction, Debugger reads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentPath
{
    /// Nothing: the chunk is resident, or holds no page a fault backed.
    Skip,
    /// Made resident in the request's turn: its runs mapped back, or its pages
    /// restored from the store.
    Restore,
    /// Posted to the swap service's want list: the swap service reads its slot
    /// and restores it ahead of a fault, and the reader asks again.
    Want,
    /// Passed over: a lost chunk, or a chunk on disk with no swap service to
    /// ask; its pages stay not present.
    PassOver,
}

/// The path `MAKE_RESIDENT` takes for a chunk whose entry is `entry`, with
/// `wants` saying whether a registered swap service can be asked for a chunk
/// on disk.
#[must_use]
pub const fn resident_path(entry: &ChunkEntry, wants: Registered) -> ResidentPath
{
    match entry.state()
    {
        ChunkState::Unbacked | ChunkState::Resident => ResidentPath::Skip,
        ChunkState::Evicting | ChunkState::Compressed | ChunkState::Raw | ChunkState::Writing =>
        {
            ResidentPath::Restore
        }
        ChunkState::OnDisk => match wants
        {
            Registered::Yes => ResidentPath::Want,
            Registered::No => ResidentPath::PassOver,
        },
        ChunkState::Lost => ResidentPath::PassOver,
    }
}

/// The address a pending `MAKE_RESIDENT` reply names, from the base of the
/// first chunk the request posted, `first_posted`, and the request's start,
/// `va`: the chunk's base, or `va` when the chunk starts below it, so the
/// reader, which asks from `va` as it gave it, page boundary or not, asks
/// again from there and never sees a reply below its own address.
#[must_use]
pub const fn pending_from(first_posted: u64, va: u64) -> u64
{
    if first_posted > va { first_posted } else { va }
}

/// Words the want list holds at most, and so the most one `SWAP_WANTED` reply
/// carries.
pub const WANT_WORDS: usize = 8;

/// Whether [`WantList::post`] added a word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posted
{
    /// The word was added, the oldest one dropped when the list was full.
    Added,
    /// The word was already on the list, which is unchanged.
    Already,
}

/// The slot words of chunks on disk a debugger's `MAKE_RESIDENT` met, in the
/// order they were posted, which the swap service takes with `SWAP_WANTED`,
/// reads and restores ahead of a fault. Bounded: a full list drops its oldest
/// word for a new one, and the reader whose word was dropped posts it again
/// when it asks again.
pub struct WantList
{
    words: [u64; WANT_WORDS],
    /// Index of the oldest word.
    start: usize,
    /// Words held.
    len: usize,
}

impl WantList
{
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            words: [0; WANT_WORDS],
            start: 0,
            len: 0,
        }
    }

    /// Words held.
    #[must_use]
    pub const fn len(&self) -> usize
    {
        self.len
    }

    /// Whether the list holds no word.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// The word at position `i` from the oldest.
    fn at(&self, i: usize) -> u64
    {
        self.words
            .get(self.start.wrapping_add(i) % WANT_WORDS)
            .copied()
            .unwrap_or(0)
    }

    /// Post `word`, unless the list holds it already.
    pub fn post(&mut self, word: u64) -> Posted
    {
        if (0..self.len).any(|i| self.at(i) == word)
        {
            return Posted::Already;
        }
        let end = self.start.wrapping_add(self.len) % WANT_WORDS;
        if let Some(w) = self.words.get_mut(end)
        {
            *w = word;
        }
        if self.len == WANT_WORDS
        {
            self.start = self.start.wrapping_add(1) % WANT_WORDS;
        }
        else
        {
            self.len = self.len.saturating_add(1);
        }
        Posted::Added
    }

    /// Move every word into `out`, oldest first, and empty the list: the count
    /// moved.
    pub fn take(&mut self, out: &mut [u64; WANT_WORDS]) -> usize
    {
        let n = self.len;
        for (i, slot) in out.iter_mut().enumerate().take(n)
        {
            *slot = self.at(i);
        }
        self.start = 0;
        self.len = 0;
        n
    }
}

impl Default for WantList
{
    fn default() -> Self
    {
        Self::new()
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
        assert!(!s.set_total(0));
        assert_eq!(s.total(), 4);
        // No registration is of no slot, so none withdraws the slots before it.
        let mut fresh = SwapSlots::new(VecWords::default());
        assert!(!fresh.set_total(0));
        assert_eq!(fresh.total(), 0);
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
    fn a_slot_word_names_its_slot_length_and_seal_and_tells_a_later_use_apart()
    {
        let word = slot_word(5, 4112, 9);
        assert_eq!((word_slot(word), word_len(word)), (5, 4112));
        // The last slot and a full slot's count round-trip, as does the
        // shortest count.
        let top = u32::try_from(WORD_SLOTS - 1).unwrap();
        let full = u32::try_from(SLOT_BYTES).unwrap();
        let word_top = slot_word(top, full, u64::MAX);
        assert_eq!((word_slot(word_top), word_len(word_top)), (top, full));
        assert_eq!(word_len(slot_word(0, 1, 0)), 1);
        assert_ne!(slot_word(5, full, 9), slot_word(5, 1, 9));
        // Another seal of the same slot and length is another word, until the
        // generation wraps.
        assert_ne!(slot_word(5, 4112, 10), word);
        assert_ne!(slot_word(5, 4112, 9 + (1 << (GENERATION_BITS - 1))), word);
        assert_eq!(slot_word(5, 4112, 9 + (1 << GENERATION_BITS)), word);
        assert_ne!(slot_word(6, 4112, 9), word);
    }

    // Defect guarded: a field holding the count itself cannot name a full
    // slot's 65536 bytes, a raw chunk's of every page, in 16 bits.
    #[test]
    fn the_length_field_holds_the_count_less_one_from_one_byte_to_a_full_slot()
    {
        let full = u32::try_from(SLOT_BYTES).unwrap();
        assert_eq!((len_field(1), field_len(0)), (0, 1));
        assert_eq!((len_field(full), field_len(LEN_MASK)), (LEN_MASK, full));
        for len in [1, 2, 16, 4096, 4112, full - 1, full]
        {
            assert_eq!(field_len(len_field(len)), len, "{len}");
        }
        // The field keeps to its bits, whatever lies above them in a word.
        assert_eq!(field_len(LEN_MASK + 1), 1);
    }

    #[test]
    fn a_raw_chunks_pages_seal_to_a_full_slot_with_the_tag_apart()
    {
        let pages: Vec<u8> = (0..slot())
            .map(|i| (i.wrapping_mul(7919) >> 3).to_le_bytes()[0])
            .collect();
        let mut buf = pages.clone();
        let tag = seal_detached(&KEY, 4, &mut buf, slot()).unwrap();
        assert_ne!(buf, pages);
        let sealed = buf.clone();
        // Another nonce, another tag, or a flipped byte fails and changes
        // nothing.
        let mut other = sealed.clone();
        assert_eq!(
            open_detached(&KEY, 5, &mut other, slot(), &tag),
            Err(SlotError::Tampered)
        );
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert_eq!(
            open_detached(&KEY, 4, &mut other, slot(), &bad_tag),
            Err(SlotError::Tampered)
        );
        other[slot() - 1] ^= 1;
        assert_eq!(
            open_detached(&KEY, 4, &mut other, slot(), &tag),
            Err(SlotError::Tampered)
        );
        assert_eq!(&other[..slot() - 1], &sealed[..slot() - 1]);
        let mut good = sealed.clone();
        assert_eq!(open_detached(&KEY, 4, &mut good, slot(), &tag), Ok(()));
        assert_eq!(good, pages);
        // No bytes, or more than a slot, is refused unchanged.
        let mut big = vec![1u8; slot() + 1];
        assert_eq!(seal_detached(&KEY, 1, &mut big, 0), Err(SlotError::Size));
        assert_eq!(
            seal_detached(&KEY, 1, &mut big, slot() + 1),
            Err(SlotError::Size)
        );
        assert_eq!(
            seal_detached(&KEY, 1, &mut good, slot() + 1),
            Err(SlotError::Size)
        );
        assert_eq!(big, vec![1u8; slot() + 1]);
        assert_eq!(
            open_detached(&KEY, 4, &mut big, slot() + 1, &tag),
            Err(SlotError::Size)
        );
    }

    #[test]
    fn a_fault_redirects_an_on_disk_chunk_only_while_a_swap_service_is_registered()
    {
        let resident = ChunkEntry::UNBACKED.back(0, 4, 7).unwrap();
        let evicting = resident.begin_evict(1).unwrap();
        let compressed = evicting.finish_evict(9).unwrap();
        let writing = compressed.begin_write(5, None).unwrap();
        let on_disk = writing.finish_write().unwrap();
        let lost = on_disk.lose().unwrap();
        let raw = ChunkEntry::UNBACKED
            .back(0, 4, 8)
            .unwrap()
            .begin_evict(1)
            .unwrap()
            .finish_raw()
            .unwrap();
        let raw_writing = raw.begin_write(6, Some([3; TAG_BYTES])).unwrap();
        let raw_on_disk = raw_writing.finish_write().unwrap();
        for (entry, yes, no) in [
            (ChunkEntry::UNBACKED, FaultPath::Back, FaultPath::Back),
            (resident, FaultPath::Back, FaultPath::Back),
            (evicting, FaultPath::Remap, FaultPath::Remap),
            (raw, FaultPath::Remap, FaultPath::Remap),
            (raw_writing, FaultPath::Remap, FaultPath::Remap),
            (
                raw_on_disk,
                FaultPath::Redirect,
                FaultPath::DeclineUnregistered,
            ),
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
    #[test]
    fn make_resident_restores_from_ram_wants_a_chunk_on_disk_and_passes_a_lost_one_over()
    {
        let resident = ChunkEntry::UNBACKED.back(0, 4, 7).unwrap();
        let evicting = resident.begin_evict(1).unwrap();
        let compressed = evicting.finish_evict(9).unwrap();
        let writing = compressed.begin_write(5, None).unwrap();
        let on_disk = writing.finish_write().unwrap();
        let lost = on_disk.lose().unwrap();
        let raw = ChunkEntry::UNBACKED
            .back(0, 4, 8)
            .unwrap()
            .begin_evict(1)
            .unwrap()
            .finish_raw()
            .unwrap();
        let raw_writing = raw.begin_write(6, Some([3; TAG_BYTES])).unwrap();
        let raw_on_disk = raw_writing.finish_write().unwrap();
        for (entry, yes, no) in [
            (ChunkEntry::UNBACKED, ResidentPath::Skip, ResidentPath::Skip),
            (resident, ResidentPath::Skip, ResidentPath::Skip),
            (evicting, ResidentPath::Restore, ResidentPath::Restore),
            (compressed, ResidentPath::Restore, ResidentPath::Restore),
            (writing, ResidentPath::Restore, ResidentPath::Restore),
            (raw, ResidentPath::Restore, ResidentPath::Restore),
            (raw_writing, ResidentPath::Restore, ResidentPath::Restore),
            (on_disk, ResidentPath::Want, ResidentPath::PassOver),
            (raw_on_disk, ResidentPath::Want, ResidentPath::PassOver),
            (lost, ResidentPath::PassOver, ResidentPath::PassOver),
        ]
        {
            assert_eq!(resident_path(&entry, Registered::Yes), yes, "{entry:?}");
            assert_eq!(resident_path(&entry, Registered::No), no, "{entry:?}");
        }
    }

    #[test]
    fn the_want_list_keeps_each_word_once_in_posting_order_and_empties_when_taken()
    {
        let mut wants = WantList::new();
        assert_eq!(wants.post(3), Posted::Added);
        assert_eq!(wants.post(1), Posted::Added);
        assert_eq!(wants.post(3), Posted::Already);
        let mut out = [0; WANT_WORDS];
        assert_eq!(wants.take(&mut out), 2);
        assert_eq!(out[..2], [3, 1]);
        assert!(wants.is_empty());
        assert_eq!(wants.take(&mut out), 0);
        // A word taken can be posted again.
        assert_eq!(wants.post(3), Posted::Added);
        assert_eq!(wants.len(), 1);
    }

    #[test]
    fn a_full_want_list_drops_its_oldest_word_for_a_new_one()
    {
        let mut wants = WantList::new();
        let words = u64::try_from(WANT_WORDS).unwrap();
        for word in 0..words
        {
            assert_eq!(wants.post(word), Posted::Added);
        }
        // Full: a word already held changes nothing, a new one replaces the
        // oldest, and the rest keep their order.
        assert_eq!(wants.post(words - 1), Posted::Already);
        assert_eq!(wants.post(words), Posted::Added);
        assert_eq!(wants.post(words + 1), Posted::Added);
        assert_eq!(wants.len(), WANT_WORDS);
        let mut out = [0; WANT_WORDS];
        assert_eq!(wants.take(&mut out), WANT_WORDS);
        let expected: Vec<u64> = (2..words + 2).collect();
        assert_eq!(out.to_vec(), expected);
    }

    #[test]
    fn a_pending_reply_never_names_an_address_below_the_request()
    {
        // The request starts inside the posted chunk, off a page boundary.
        assert_eq!(pending_from(0x40_0000, 0x40_1008), 0x40_1008);
        assert_eq!(pending_from(0x40_0000, 0x40_0000), 0x40_0000);
        // The posted chunk lies past the start.
        assert_eq!(pending_from(0x41_0000, 0x40_1008), 0x41_0000);
    }
}
