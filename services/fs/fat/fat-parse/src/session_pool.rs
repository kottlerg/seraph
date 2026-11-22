// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/session_pool.rs

//! The records of `fatfs`'s filesystem sessions, kept in pages each session's
//! client pays for (services/fs/docs/fs-driver-protocol.md § Label 23).
//!
//! **Pages.** A session's pages hold its records and nothing of the driver's
//! own. Each is one [`Page`] of [`SLOTS_PER_PAGE`] slots of [`SLOT_WORDS`]
//! words, which the caller maps and names by a page number; the pool reaches
//! a page only through the caller's [`PageStore`], so this module holds no
//! address and no `unsafe`. Slot 0 of a page is its header: which slots are
//! taken, which of them start an open, the next page of the session, and the
//! caller's two words naming the page's frame. A session's first page holds
//! its session record in slot 1 and is held for the session's life; a later
//! page leaves the session, its frame handed back to the caller for release,
//! when its last record does. A record takes free slots in the lowest page
//! that has them.
//!
//! **Records.** A session record (one slot) holds the session's id, its two
//! capabilities, its counts, and its place in the list of sessions. An open
//! record (two slots, at an even slot) holds the open's id, its node, its
//! release SEND, where its reads stand, and the chain of its held pages. A
//! held-page record (one slot) holds one page the open's client was handed by
//! `FS_READ_MEMORY`.
//!
//! **Ids.** Every session and open takes the next value of one counter of
//! [`ID_BITS`] bits, which never repeats: at its end the pool refuses new
//! sessions and opens ([`PoolError::Exhausted`]). An id therefore names at
//! most one record over the driver's life, so a capability or a message that
//! carries an ended record's id resolves to nothing. The index from id to
//! record is a table of chain heads on the caller's heap, with each chain
//! linked through the records themselves: the table doubles when the records
//! reach twice its heads and halves when they fall below half of them, so it
//! holds at most two 4-byte heads per live session or open, and at least
//! [`MIN_HEADS`].

use alloc::vec::Vec;

use crate::ChainCursor;

/// Words of one record slot (64 bytes).
pub const SLOT_WORDS: usize = 8;

/// Slots in one 4 KiB page; one bit of a page's `u64` occupancy word each.
pub const SLOTS_PER_PAGE: usize = 64;

/// Words of one page.
pub const PAGE_WORDS: usize = SLOT_WORDS * SLOTS_PER_PAGE;

/// [`SLOTS_PER_PAGE`] as a slot number's type.
const SLOTS_U32: u32 = 64;

const _: () = assert!(SLOTS_U32 as usize == SLOTS_PER_PAGE);

/// Most pages a [`PageStore`] can number: a [`Link`] keeps 26 bits of page
/// number beside its 6 bits of slot.
pub const MAX_PAGES: u32 = 1 << 26;

/// Width of the id counter: the 40 id bits of a namespace badge and the 14
/// its kind-flagged caps add (shared/namespace-protocol/README.md § Badge
/// shape).
pub const ID_BITS: u32 = 54;

/// Fewest chain heads the index keeps once it has any.
pub const MIN_HEADS: usize = 64;

/// One page of session records, as the caller maps it.
#[repr(C, align(4096))]
pub struct Page(pub [u64; PAGE_WORDS]);

const _: () = assert!(core::mem::size_of::<Page>() == 4096);

impl Page
{
    /// A page of zero words.
    #[must_use]
    pub const fn zeroed() -> Self
    {
        Self([0; PAGE_WORDS])
    }
}

/// The caller's mapped session pages, by page number (below [`MAX_PAGES`]).
pub trait PageStore
{
    /// The page `no` names, when the caller holds it mapped.
    fn page(&self, no: u32) -> Option<&Page>;
    /// Mutable access to the page `no` names; `None` as [`Self::page`].
    fn page_mut(&mut self, no: u32) -> Option<&mut Page>;
}

/// The place of a record: its page number and its first slot. Its raw value
/// is never 0, since slot 0 of every page is a header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Link(u32);

impl Link
{
    const NONE: u32 = 0;

    /// The link of slot `slot` of page `page`; `None` when either is out of
    /// range or the slot is a header.
    #[must_use]
    pub const fn new(page: u32, slot: u32) -> Option<Self>
    {
        if page >= MAX_PAGES || slot == 0 || slot >= SLOTS_U32
        {
            return None;
        }
        Some(Self(page.wrapping_shl(6) | slot))
    }

    fn from_word(raw: u64) -> Option<Self>
    {
        u32::try_from(raw).ok().filter(|r| r & 63 != 0).map(Self)
    }

    fn word(this: Option<Self>) -> u64
    {
        u64::from(this.map_or(Self::NONE, |l| l.0))
    }

    /// The page number.
    #[must_use]
    pub const fn page(self) -> u32
    {
        self.0 >> 6
    }

    /// The first slot.
    #[must_use]
    pub const fn slot(self) -> u32
    {
        self.0 & 63
    }

    fn word_index(self, word: usize) -> usize
    {
        usize::try_from(self.slot())
            .unwrap_or(0)
            .saturating_mul(SLOT_WORDS)
            .saturating_add(word)
    }
}

// Page header words (slot 0).
const H_USED: usize = 0;
const H_OPENS: usize = 1;
const H_NEXT: usize = 2;
const H_FRAME_A: usize = 3;
const H_FRAME_B: usize = 4;
const NO_PAGE: u64 = u64::MAX;

// Session record words (slot 1 of the first page). The id and the chain
// link sit where an open record keeps its own, so the index reads both kinds
// alike.
const S_ID: usize = 0;
// Word 1 is the id index's chain link, as an open record's O_CHAIN.
const S_CHARGE: usize = 2;
const S_LIVENESS: usize = 3;
const S_OPENS: usize = 4;
const S_PAGES: usize = 5;
const S_PREV: usize = 6;
const S_NEXT: usize = 7;

// Open record words (two slots).
const O_ID: usize = 0;
const O_CHAIN: usize = 1;
const O_NODE: usize = 2;
const O_RELEASE: usize = 3;
const O_NEXT_READ: usize = 4;
const O_CURSOR_EPOCH: usize = 5;
const O_CURSOR_CLUSTERS: usize = 6;
const O_CURSOR_INDEX: usize = 7;
const O_CURSOR_SET: usize = 8;
const O_HELD: usize = 9;
const O_HELD_COUNT: usize = 10;
const O_SESSION: usize = 11;

// Held-page record words (one slot).
const P_COOKIE: usize = 0;
const P_CACHE_SLOT: usize = 1;
const P_ANCESTOR: usize = 2;
const P_NEXT: usize = 3;
const P_QUEUED: usize = 4;

/// The slots the header and the session record take in a first page.
const FIRST_PAGE_FIXED: u64 = 0b11;
/// The slot the header takes in a later page.
const PAGE_FIXED: u64 = 0b1;
/// The even slots: where an open record may start.
const EVEN_SLOTS: u64 = 0x5555_5555_5555_5555;

/// What the caller keeps of an open, read from or written to its record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenFields
{
    /// The node the open was minted on.
    pub node: u64,
    /// The client's release SEND, 0 when the open carried none.
    pub release_cap: u64,
    /// The offset a sequential `FS_READ_MEMORY` asks for next.
    pub next_read: u64,
    /// Where the open's last read stood in the file's cluster chain.
    pub cursor: Option<ChainCursor>,
}

/// One page a client holds through an open, as its held-page record keeps it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeldPage
{
    /// The client's cookie for the page.
    pub cookie: u64,
    /// The cache slot whose reference the page holds.
    pub cache_slot: u64,
    /// The per-page ancestor cap, revoked to take the page back.
    pub ancestor_cap: u64,
    /// Whether the page is queued for eviction.
    pub eviction_queued: bool,
}

/// What a session record keeps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionFields
{
    /// The session's id.
    pub id: u64,
    /// The charge-only handle the pages are charged through.
    pub charge_cap: u64,
    /// The parent of the client's liveness cap.
    pub liveness_cap: u64,
    /// Live opens.
    pub opens: u64,
    /// Pages held, the first included.
    pub pages: u64,
}

/// Why a record could not be placed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PoolError
{
    /// Every page of the session is full: the caller adds a page
    /// ([`SessionPool::add_page`]) and asks again.
    NeedPage,
    /// The session or open named is not live, or the store does not hold the
    /// page named.
    Gone,
    /// The caller's heap could not hold the index's first table.
    Heap,
    /// The open already holds its most pages.
    Full,
    /// The id counter is spent: no session or open is made again.
    Exhausted,
}

/// A session page the pool gave back, for the caller to unmap and release:
/// its page number and the two words naming its frame.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Frame
{
    /// The page's number in the caller's store.
    pub page: u32,
    /// The words the caller gave with the page.
    pub words: [u64; 2],
}

/// Fibonacci hashing of `id` onto a table of `heads` heads, a power of two.
/// Ids are the pool's own counter, which no client chooses.
fn bucket(id: u64, heads: usize) -> usize
{
    let shift = u64::BITS.saturating_sub(heads.trailing_zeros());
    let h = id.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    usize::try_from(h.checked_shr(shift).unwrap_or(0)).unwrap_or(0)
}

/// A filesystem's sessions, their opens and their held pages, in pages a
/// [`PageStore`] maps; see the module docs.
pub struct SessionPool<S>
{
    store: S,
    /// Chain heads of the id index, a power of two of them once any.
    heads: Vec<u32>,
    /// Live sessions and opens.
    live: usize,
    /// The first session of the session list.
    sessions: Option<Link>,
    /// The id the next session or open takes.
    next_id: u64,
    /// The first id past the counter.
    id_end: u64,
    /// The first of the pages a removal gave back and the caller has not
    /// taken yet ([`Self::take_freed`]), chained through their headers'
    /// next-page word: out of every session, still in the store.
    freed: Option<u32>,
}

impl<S: PageStore> SessionPool<S>
{
    /// An empty pool over `store`, with an id counter of [`ID_BITS`].
    /// Allocates nothing.
    pub const fn new(store: S) -> Self
    {
        Self::with_id_bits(store, ID_BITS)
    }

    /// An empty pool whose ids run from 1 below `2^bits`; lets a test spend
    /// the counter.
    pub const fn with_id_bits(store: S, bits: u32) -> Self
    {
        Self {
            store,
            heads: Vec::new(),
            live: 0,
            sessions: None,
            freed: None,
            next_id: 1,
            id_end: match 1u64.checked_shl(bits)
            {
                Some(end) => end,
                None => u64::MAX,
            },
        }
    }

    /// The caller's page store.
    pub const fn store(&self) -> &S
    {
        &self.store
    }

    /// Mutable access to the caller's page store.
    pub const fn store_mut(&mut self) -> &mut S
    {
        &mut self.store
    }

    /// Live sessions and opens.
    #[must_use]
    pub const fn live(&self) -> usize
    {
        self.live
    }

    /// Chain heads the id index keeps on the caller's heap.
    #[must_use]
    pub fn index_heads(&self) -> usize
    {
        self.heads.len()
    }

    fn word(&self, link: Link, word: usize) -> u64
    {
        self.store
            .page(link.page())
            .and_then(|p| p.0.get(link.word_index(word)))
            .copied()
            .unwrap_or(0)
    }

    fn set_word(&mut self, link: Link, word: usize, value: u64)
    {
        if let Some(w) = self
            .store
            .page_mut(link.page())
            .and_then(|p| p.0.get_mut(link.word_index(word)))
        {
            *w = value;
        }
    }

    fn header(&self, page: u32, word: usize) -> u64
    {
        self.store
            .page(page)
            .and_then(|p| p.0.get(word))
            .copied()
            .unwrap_or(0)
    }

    fn set_header(&mut self, page: u32, word: usize, value: u64)
    {
        if let Some(w) = self.store.page_mut(page).and_then(|p| p.0.get_mut(word))
        {
            *w = value;
        }
    }

    /// The frame of page `page`, as its header names it.
    fn frame(&self, page: u32) -> Frame
    {
        Frame {
            page,
            words: [self.header(page, H_FRAME_A), self.header(page, H_FRAME_B)],
        }
    }

    // ── id index ─────────────────────────────────────────────────────────

    /// The next id, or [`PoolError::Exhausted`] once the counter is spent.
    fn take_id(&mut self) -> Result<u64, PoolError>
    {
        let id = self.next_id;
        if id >= self.id_end
        {
            return Err(PoolError::Exhausted);
        }
        self.next_id = id.saturating_add(1);
        Ok(id)
    }

    fn find(&self, id: u64) -> Option<Link>
    {
        let head = *self.heads.get(bucket(id, self.heads.len()))?;
        let mut at = Link::from_word(u64::from(head));
        while let Some(link) = at
        {
            if self.word(link, O_ID) == id
            {
                return Some(link);
            }
            at = Link::from_word(self.word(link, O_CHAIN));
        }
        None
    }

    /// Make the index's first table. `Err` when the heap refuses it.
    fn ensure_heads(&mut self) -> Result<(), PoolError>
    {
        if self.heads.is_empty()
        {
            self.heads
                .try_reserve_exact(MIN_HEADS)
                .map_err(|_| PoolError::Heap)?;
            self.heads.resize(MIN_HEADS, Link::NONE);
        }
        Ok(())
    }

    /// Link `link`, whose record holds `id` in its first word, into the
    /// index, doubling the table first when the records reach twice its
    /// heads; a doubling the heap refuses leaves longer chains. The table
    /// exists ([`Self::ensure_heads`]).
    fn index_insert(&mut self, id: u64, link: Link)
    {
        let len = self.heads.len();
        if self.live >= len.saturating_mul(2)
        {
            self.rehash(len.saturating_mul(2));
        }
        let b = bucket(id, self.heads.len());
        if let Some(head) = self.heads.get_mut(b)
        {
            let old = u64::from(*head);
            *head = link.0;
            self.set_word(link, O_CHAIN, old);
            self.live = self.live.saturating_add(1);
        }
    }

    fn index_remove(&mut self, id: u64, link: Link)
    {
        let b = bucket(id, self.heads.len());
        let next = self.word(link, O_CHAIN);
        let Some(&head) = self.heads.get(b)
        else
        {
            return;
        };
        if head == link.0
        {
            if let Some(h) = self.heads.get_mut(b)
            {
                *h = u32::try_from(next).unwrap_or(Link::NONE);
            }
        }
        else
        {
            let mut at = Link::from_word(u64::from(head));
            while let Some(prev) = at
            {
                let after = Link::from_word(self.word(prev, O_CHAIN));
                if after == Some(link)
                {
                    self.set_word(prev, O_CHAIN, next);
                    break;
                }
                at = after;
            }
        }
        self.live = self.live.saturating_sub(1);
        let len = self.heads.len();
        if len > MIN_HEADS && self.live < len / 2
        {
            self.rehash(len / 2);
        }
    }

    /// Move every chain onto a table of `len` heads; a table the heap
    /// refuses leaves the index as it was.
    fn rehash(&mut self, len: usize)
    {
        let mut heads = Vec::new();
        if heads.try_reserve_exact(len).is_err()
        {
            return;
        }
        heads.resize(len, Link::NONE);
        let old = core::mem::take(&mut self.heads);
        for &head in &old
        {
            let mut at = Link::from_word(u64::from(head));
            while let Some(link) = at
            {
                at = Link::from_word(self.word(link, O_CHAIN));
                if let Some(h) = heads.get_mut(bucket(self.word(link, O_ID), len))
                {
                    let prev = u64::from(*h);
                    *h = link.0;
                    self.set_word(link, O_CHAIN, prev);
                }
            }
        }
        self.heads = heads;
    }

    // ── sessions ─────────────────────────────────────────────────────────

    /// Start a session in the caller's fresh page `page`, whose frame
    /// `frame` names, with the session's two caps. Returns the session's
    /// link; its id is [`Self::id_of`] it.
    ///
    /// # Errors
    ///
    /// [`PoolError::Exhausted`] when the id counter is spent,
    /// [`PoolError::Heap`] when the index's first table cannot be had, and
    /// [`PoolError::Gone`] when the store does not hold `page`; the page is
    /// then left as it was.
    pub fn new_session(
        &mut self,
        page: u32,
        frame: [u64; 2],
        charge_cap: u64,
        liveness_cap: u64,
    ) -> Result<Link, PoolError>
    {
        let link = Link::new(page, 1).ok_or(PoolError::Gone)?;
        if self.store.page(page).is_none()
        {
            return Err(PoolError::Gone);
        }
        self.ensure_heads()?;
        let id = self.take_id()?;
        if let Some(p) = self.store.page_mut(page)
        {
            p.0 = [0; PAGE_WORDS];
        }
        self.set_header(page, H_USED, FIRST_PAGE_FIXED);
        self.set_header(page, H_NEXT, NO_PAGE);
        self.set_header(page, H_FRAME_A, frame[0]);
        self.set_header(page, H_FRAME_B, frame[1]);
        self.set_word(link, S_ID, id);
        self.set_word(link, S_CHARGE, charge_cap);
        self.set_word(link, S_LIVENESS, liveness_cap);
        self.set_word(link, S_PAGES, 1);
        self.set_word(link, S_NEXT, Link::word(self.sessions));
        if let Some(head) = self.sessions
        {
            self.set_word(head, S_PREV, Link::word(Some(link)));
        }
        self.sessions = Some(link);
        self.index_insert(id, link);
        Ok(link)
    }

    /// The live session whose id is `id`.
    #[must_use]
    pub fn session(&self, id: u64) -> Option<Link>
    {
        self.find(id).filter(|l| l.slot() == 1)
    }

    /// The fields of the session `session` names.
    #[must_use]
    pub fn session_fields(&self, session: Link) -> SessionFields
    {
        SessionFields {
            id: self.word(session, S_ID),
            charge_cap: self.word(session, S_CHARGE),
            liveness_cap: self.word(session, S_LIVENESS),
            opens: self.word(session, S_OPENS),
            pages: self.word(session, S_PAGES),
        }
    }

    /// Every live session, the newest first. Stops early when the heap
    /// cannot hold the list.
    #[must_use]
    pub fn sessions(&self) -> Vec<Link>
    {
        let mut out = Vec::new();
        let mut at = self.sessions;
        while let Some(s) = at
        {
            if out.try_reserve(1).is_err()
            {
                break;
            }
            out.push(s);
            at = Link::from_word(self.word(s, S_NEXT));
        }
        out
    }

    /// The page after `page` in its session's list.
    fn next_page(&self, page: u32) -> Option<u32>
    {
        let next = self.header(page, H_NEXT);
        if next == NO_PAGE
        {
            None
        }
        else
        {
            u32::try_from(next).ok()
        }
    }

    /// Add the caller's fresh page `page`, whose frame `frame` names, to the
    /// session `session`, after its first page.
    ///
    /// # Errors
    ///
    /// [`PoolError::Gone`] when the store does not hold `page`.
    pub fn add_page(&mut self, session: Link, page: u32, frame: [u64; 2]) -> Result<(), PoolError>
    {
        let p = self.store.page_mut(page).ok_or(PoolError::Gone)?;
        p.0 = [0; PAGE_WORDS];
        let first = session.page();
        let after = self.header(first, H_NEXT);
        self.set_header(page, H_USED, PAGE_FIXED);
        self.set_header(page, H_NEXT, after);
        self.set_header(page, H_FRAME_A, frame[0]);
        self.set_header(page, H_FRAME_B, frame[1]);
        self.set_header(first, H_NEXT, u64::from(page));
        let pages = self.word(session, S_PAGES).saturating_add(1);
        self.set_word(session, S_PAGES, pages);
        Ok(())
    }

    /// Where `width` (1 or 2) free slots, at an even slot for 2, lie in the
    /// lowest page of `session` that has them.
    fn find_slots(&self, session: Link, width: usize) -> Option<(u32, u32)>
    {
        let mut at = Some(session.page());
        while let Some(page) = at
        {
            let free = !self.header(page, H_USED);
            let fits = if width == 2
            {
                free & (free >> 1) & EVEN_SLOTS
            }
            else
            {
                free
            };
            if fits != 0
            {
                return Some((page, fits.trailing_zeros()));
            }
            at = self.next_page(page);
        }
        None
    }

    /// Whether the session `session` names has room for an open's record
    /// without a page more.
    #[must_use]
    pub fn room_for_open(&self, session: Link) -> bool
    {
        self.find_slots(session, 2).is_some()
    }

    /// Whether the session `session` names has room for a held page's record
    /// without a page more.
    #[must_use]
    pub fn room_for_held(&self, session: Link) -> bool
    {
        self.find_slots(session, 1).is_some()
    }

    /// Take `width` (1 or 2) free slots, at an even slot for 2, from the
    /// lowest page of `session` that has them, zeroed.
    fn take_slots(&mut self, session: Link, width: usize) -> Option<Link>
    {
        let (page, slot) = self.find_slots(session, width)?;
        let link = Link::new(page, slot)?;
        let used = self.header(page, H_USED);
        self.set_header(page, H_USED, used | slot_mask(slot, width));
        for w in 0..SLOT_WORDS.saturating_mul(width)
        {
            self.set_word(link, w, 0);
        }
        Some(link)
    }

    /// Give back the `width` slots at `link`; when that empties a page other
    /// than the session's first, unlink the page and return its frame.
    fn give_slots(&mut self, session: Link, link: Link, width: usize) -> Option<Frame>
    {
        let page = link.page();
        let mask = slot_mask(link.slot(), width);
        let used = self.header(page, H_USED) & !mask;
        self.set_header(page, H_USED, used);
        if used != PAGE_FIXED || page == session.page()
        {
            return None;
        }
        let mut prev = session.page();
        loop
        {
            let next = self.next_page(prev)?;
            if next == page
            {
                let after = self.header(page, H_NEXT);
                self.set_header(prev, H_NEXT, after);
                break;
            }
            prev = next;
        }
        let pages = self.word(session, S_PAGES).saturating_sub(1);
        self.set_word(session, S_PAGES, pages);
        Some(self.frame(page))
    }

    /// Give back the `width` slots at `link` as [`Self::give_slots`] does,
    /// the page it empties joining the freed pages.
    fn give_back(&mut self, session: Link, link: Link, width: usize)
    {
        if let Some(frame) = self.give_slots(session, link, width)
        {
            self.push_freed(frame.page);
        }
    }

    /// Put `page`, out of every session, on the freed pages.
    fn push_freed(&mut self, page: u32)
    {
        let next = self.freed.map_or(NO_PAGE, u64::from);
        self.set_header(page, H_NEXT, next);
        self.freed = Some(page);
    }

    /// Take one of the pages a removal gave back ([`Self::remove_open`],
    /// [`Self::remove_opens_where`], [`Self::end_session`]), for the caller
    /// to unmap and release; `None` once none is left. The caller takes every
    /// one after each removal: a freed page stays in the store, its frame
    /// unreleased, until it is taken.
    pub fn take_freed(&mut self) -> Option<Frame>
    {
        let page = self.freed?;
        self.freed = self.next_page(page);
        Some(self.frame(page))
    }

    // ── opens ────────────────────────────────────────────────────────────

    /// Record a new open in the session `session`. Returns its link; its id
    /// is [`Self::id_of`] it.
    ///
    /// # Errors
    ///
    /// [`PoolError::Gone`] when the session is not live,
    /// [`PoolError::Exhausted`] when the id counter is spent, and
    /// [`PoolError::NeedPage`] when every page of the session is full.
    pub fn new_open(&mut self, session: Link, fields: OpenFields) -> Result<Link, PoolError>
    {
        if self.session(self.word(session, S_ID)) != Some(session)
        {
            return Err(PoolError::Gone);
        }
        if self.next_id >= self.id_end
        {
            return Err(PoolError::Exhausted);
        }
        let link = self.take_slots(session, 2).ok_or(PoolError::NeedPage)?;
        let id = self.take_id()?;
        self.set_word(link, O_ID, id);
        let page = link.page();
        let starts = self.header(page, H_OPENS) | slot_mask(link.slot(), 1);
        self.set_header(page, H_OPENS, starts);
        self.set_word(link, O_SESSION, Link::word(Some(session)));
        self.write_open(link, fields);
        let opens = self.word(session, S_OPENS).saturating_add(1);
        self.set_word(session, S_OPENS, opens);
        self.index_insert(id, link);
        Ok(link)
    }

    /// The live open whose id is `id`.
    #[must_use]
    pub fn open(&self, id: u64) -> Option<Link>
    {
        self.find(id).filter(|l| l.slot() != 1)
    }

    /// The id of the session or open `link` names.
    #[must_use]
    pub fn id_of(&self, link: Link) -> u64
    {
        self.word(link, O_ID)
    }

    /// The fields of the open `open` names.
    #[must_use]
    pub fn open_fields(&self, open: Link) -> OpenFields
    {
        let clusters = self.word(open, O_CURSOR_CLUSTERS);
        let cursor = (self.word(open, O_CURSOR_SET) != 0).then(|| ChainCursor {
            epoch: self.word(open, O_CURSOR_EPOCH),
            first_cluster: low32(clusters),
            cluster_index: self.word(open, O_CURSOR_INDEX),
            cluster: low32(clusters >> 32),
        });
        OpenFields {
            node: self.word(open, O_NODE),
            release_cap: self.word(open, O_RELEASE),
            next_read: self.word(open, O_NEXT_READ),
            cursor,
        }
    }

    /// Write `fields` to the open `open` names.
    pub fn write_open(&mut self, open: Link, fields: OpenFields)
    {
        let c = fields.cursor;
        self.set_word(open, O_NODE, fields.node);
        self.set_word(open, O_RELEASE, fields.release_cap);
        self.set_word(open, O_NEXT_READ, fields.next_read);
        self.set_word(open, O_CURSOR_SET, u64::from(c.is_some()));
        self.set_word(open, O_CURSOR_EPOCH, c.map_or(0, |c| c.epoch));
        self.set_word(
            open,
            O_CURSOR_CLUSTERS,
            c.map_or(0, |c| {
                u64::from(c.first_cluster) | (u64::from(c.cluster) << 32)
            }),
        );
        self.set_word(open, O_CURSOR_INDEX, c.map_or(0, |c| c.cluster_index));
    }

    /// The session the open `open` names belongs to.
    #[must_use]
    pub fn session_of(&self, open: Link) -> Option<Link>
    {
        Link::from_word(self.word(open, O_SESSION))
    }

    /// Every live open of the session `session`. Stops early when the heap
    /// cannot hold the list.
    #[must_use]
    pub fn opens_of(&self, session: Link) -> Vec<Link>
    {
        let mut out = Vec::new();
        let mut at = Some(session.page());
        while let Some(page) = at
        {
            let mut starts = self.header(page, H_OPENS);
            while starts != 0
            {
                let slot = starts.trailing_zeros();
                starts &= starts.wrapping_sub(1);
                if let Some(l) = Link::new(page, slot)
                {
                    if out.try_reserve(1).is_err()
                    {
                        return out;
                    }
                    out.push(l);
                }
            }
            at = self.next_page(page);
        }
        out
    }

    /// Remove the open `open` names: its id stops resolving. Each page it
    /// held goes to `held` as its record goes, and each session page the
    /// removal empties joins the freed pages ([`Self::take_freed`]), so a
    /// removal takes no memory and gives back everything the open had.
    /// Returns the open's fields, whose release SEND the caller deletes;
    /// `None` when it is not a live open.
    pub fn remove_open(&mut self, open: Link, mut held: impl FnMut(HeldPage))
    -> Option<OpenFields>
    {
        let id = self.word(open, O_ID);
        if self.open(id) != Some(open)
        {
            return None;
        }
        let session = self.session_of(open)?;
        let fields = self.open_fields(open);
        while let Some(l) = Link::from_word(self.word(open, O_HELD))
        {
            self.set_word(open, O_HELD, self.word(l, P_NEXT));
            held(self.read_held(l));
            self.give_back(session, l, 1);
        }
        self.set_word(open, O_HELD_COUNT, 0);
        self.index_remove(id, open);
        let page = open.page();
        let starts = self.header(page, H_OPENS) & !slot_mask(open.slot(), 1);
        self.set_header(page, H_OPENS, starts);
        let opens = self.word(session, S_OPENS).saturating_sub(1);
        self.set_word(session, S_OPENS, opens);
        self.give_back(session, open, 2);
        Some(fields)
    }

    /// Remove every open, of every session, whose fields `matches` accepts,
    /// as [`Self::remove_open`] does: each page one held goes to `held`, and
    /// each one's fields to `removed`. Takes no memory.
    pub fn remove_opens_where(
        &mut self,
        matches: impl Fn(&OpenFields) -> bool,
        mut held: impl FnMut(HeldPage),
        mut removed: impl FnMut(OpenFields),
    )
    {
        let mut at = self.sessions;
        while let Some(session) = at
        {
            while let Some(open) = self.first_open_where(session, &matches)
            {
                let Some(fields) = self.remove_open(open, &mut held)
                else
                {
                    break;
                };
                removed(fields);
            }
            at = Link::from_word(self.word(session, S_NEXT));
        }
    }

    /// The first open of the session `session`, page by page, whose fields
    /// `matches` accepts.
    fn first_open_where(&self, session: Link, matches: impl Fn(&OpenFields) -> bool)
    -> Option<Link>
    {
        let mut at = Some(session.page());
        while let Some(page) = at
        {
            let mut starts = self.header(page, H_OPENS);
            while starts != 0
            {
                let slot = starts.trailing_zeros();
                starts &= starts.wrapping_sub(1);
                if let Some(l) = Link::new(page, slot)
                    && matches(&self.open_fields(l))
                {
                    return Some(l);
                }
            }
            at = self.next_page(page);
        }
        None
    }

    // ── held pages ───────────────────────────────────────────────────────

    /// Record `page` as held by the open `open`, which holds at most
    /// `limit` pages.
    ///
    /// # Errors
    ///
    /// [`PoolError::Gone`] when the open is not live, [`PoolError::Full`]
    /// at `limit`, and [`PoolError::NeedPage`] when every page of the
    /// session is full.
    pub fn hold(&mut self, open: Link, page: HeldPage, limit: u64) -> Result<(), PoolError>
    {
        if self.open(self.word(open, O_ID)) != Some(open)
        {
            return Err(PoolError::Gone);
        }
        let session = self.session_of(open).ok_or(PoolError::Gone)?;
        let count = self.word(open, O_HELD_COUNT);
        if count >= limit
        {
            return Err(PoolError::Full);
        }
        let link = self.take_slots(session, 1).ok_or(PoolError::NeedPage)?;
        self.set_word(link, P_COOKIE, page.cookie);
        self.set_word(link, P_CACHE_SLOT, page.cache_slot);
        self.set_word(link, P_ANCESTOR, page.ancestor_cap);
        self.set_word(link, P_QUEUED, u64::from(page.eviction_queued));
        self.set_word(link, P_NEXT, self.word(open, O_HELD));
        self.set_word(open, O_HELD, Link::word(Some(link)));
        self.set_word(open, O_HELD_COUNT, count.saturating_add(1));
        Ok(())
    }

    fn read_held(&self, link: Link) -> HeldPage
    {
        HeldPage {
            cookie: self.word(link, P_COOKIE),
            cache_slot: self.word(link, P_CACHE_SLOT),
            ancestor_cap: self.word(link, P_ANCESTOR),
            eviction_queued: self.word(link, P_QUEUED) != 0,
        }
    }

    /// The pages the open `open` holds, the newest first.
    #[must_use]
    pub fn held(&self, open: Link) -> Vec<HeldPage>
    {
        let mut out = Vec::new();
        let mut at = Link::from_word(self.word(open, O_HELD));
        while let Some(l) = at
        {
            if out.try_reserve(1).is_err()
            {
                break;
            }
            out.push(self.read_held(l));
            at = Link::from_word(self.word(l, P_NEXT));
        }
        out
    }

    /// Mark the newest page of the open `open` not yet queued for eviction
    /// as queued, and return it.
    pub fn queue_for_eviction(&mut self, open: Link) -> Option<HeldPage>
    {
        let mut at = Link::from_word(self.word(open, O_HELD));
        while let Some(l) = at
        {
            if self.word(l, P_QUEUED) == 0
            {
                self.set_word(l, P_QUEUED, 1);
                return Some(self.read_held(l));
            }
            at = Link::from_word(self.word(l, P_NEXT));
        }
        None
    }

    /// The newest page of the open `open` that `matches` accepts.
    pub fn held_where(&self, open: Link, matches: impl Fn(&HeldPage) -> bool) -> Option<HeldPage>
    {
        let mut at = Link::from_word(self.word(open, O_HELD));
        while let Some(l) = at
        {
            let page = self.read_held(l);
            if matches(&page)
            {
                return Some(page);
            }
            at = Link::from_word(self.word(l, P_NEXT));
        }
        None
    }

    /// Take the newest page of the open `open` that `matches` accepts off
    /// it. Returns the page, with the frame of the session page that
    /// emptied, if any.
    pub fn unhold(
        &mut self,
        open: Link,
        matches: impl Fn(&HeldPage) -> bool,
    ) -> Option<(HeldPage, Option<Frame>)>
    {
        if self.open(self.word(open, O_ID)) != Some(open)
        {
            return None;
        }
        let session = self.session_of(open)?;
        let mut prev: Option<Link> = None;
        let mut at = Link::from_word(self.word(open, O_HELD));
        while let Some(l) = at
        {
            let next = self.word(l, P_NEXT);
            let page = self.read_held(l);
            if matches(&page)
            {
                match prev
                {
                    Some(p) => self.set_word(p, P_NEXT, next),
                    None => self.set_word(open, O_HELD, next),
                }
                let count = self.word(open, O_HELD_COUNT).saturating_sub(1);
                self.set_word(open, O_HELD_COUNT, count);
                return Some((page, self.give_slots(session, l, 1)));
            }
            prev = Some(l);
            at = Link::from_word(next);
        }
        None
    }

    // ── session end ──────────────────────────────────────────────────────

    /// End the session `session` names: remove every open of it, as
    /// [`Self::remove_open`] does, each page an open held going to `held`
    /// and each open's fields to `removed`, then the session itself, every
    /// page of it, the first included, joining the freed pages
    /// ([`Self::take_freed`]). Takes no memory. Returns the session's fields
    /// as they stood before, whose caps the caller releases; `None` when it
    /// is not a live session.
    pub fn end_session(
        &mut self,
        session: Link,
        mut held: impl FnMut(HeldPage),
        mut removed: impl FnMut(OpenFields),
    ) -> Option<SessionFields>
    {
        let fields = self.session_fields(session);
        if self.session(fields.id) != Some(session)
        {
            return None;
        }
        while let Some(open) = self.first_open_where(session, |_| true)
        {
            let Some(open_fields) = self.remove_open(open, &mut held)
            else
            {
                break;
            };
            removed(open_fields);
        }
        self.index_remove(fields.id, session);
        let prev = Link::from_word(self.word(session, S_PREV));
        let next = Link::from_word(self.word(session, S_NEXT));
        match prev
        {
            Some(p) => self.set_word(p, S_NEXT, Link::word(next)),
            None => self.sessions = next,
        }
        if let Some(n) = next
        {
            self.set_word(n, S_PREV, Link::word(prev));
        }
        let mut at = Some(session.page());
        while let Some(page) = at
        {
            at = self.next_page(page);
            self.set_header(page, H_USED, 0);
            self.push_freed(page);
        }
        Some(fields)
    }
}

/// The low half of a word two `u32` fields share.
fn low32(word: u64) -> u32
{
    u32::try_from(word & u64::from(u32::MAX)).unwrap_or(0)
}

/// The occupancy bits of `width` slots from `slot` (below 64).
const fn slot_mask(slot: u32, width: usize) -> u64
{
    let bits = if width == 2 { 0b11u64 } else { 1u64 };
    bits.wrapping_shl(slot)
}

#[cfg(test)]
mod tests
{
    use std::collections::BTreeMap;

    use super::*;

    /// Pages by number, as a test maps them.
    #[derive(Default)]
    struct Store(BTreeMap<u32, Box<Page>>);

    impl Store
    {
        fn map(&mut self, no: u32)
        {
            self.0.insert(no, Box::new(Page::zeroed()));
        }
    }

    impl PageStore for Store
    {
        fn page(&self, no: u32) -> Option<&Page>
        {
            self.0.get(&no).map(AsRef::as_ref)
        }

        fn page_mut(&mut self, no: u32) -> Option<&mut Page>
        {
            self.0.get_mut(&no).map(AsMut::as_mut)
        }
    }

    /// A pool over pages 0..`pages`, each mapped.
    fn pool(pages: u32) -> SessionPool<Store>
    {
        let mut store = Store::default();
        for no in 0..pages
        {
            store.map(no);
        }
        SessionPool::new(store)
    }

    fn frame(page: u32) -> [u64; 2]
    {
        [u64::from(page) + 100, u64::from(page) + 200]
    }

    fn freed(page: u32) -> Frame
    {
        Frame {
            page,
            words: frame(page),
        }
    }

    fn fields(node: u64) -> OpenFields
    {
        OpenFields {
            node,
            release_cap: node + 1,
            next_read: 0,
            cursor: None,
        }
    }

    fn held(cookie: u64) -> HeldPage
    {
        HeldPage {
            cookie,
            cache_slot: cookie + 10,
            ancestor_cap: cookie + 20,
            eviction_queued: false,
        }
    }

    /// Opens a page holds beside its header, and beside the session record
    /// in a session's first page.
    const OPENS_PER_PAGE: usize = (SLOTS_PER_PAGE - 2) / 2;

    #[test]
    fn a_session_resolves_by_its_id_with_its_fields()
    {
        let mut p = pool(1);
        let s = p.new_session(0, frame(0), 7, 8).unwrap();
        let id = p.id_of(s);
        assert_eq!(p.session(id), Some(s));
        assert_eq!(p.open(id), None);
        let f = p.session_fields(s);
        assert_eq!(
            (f.id, f.charge_cap, f.liveness_cap, f.opens, f.pages),
            (id, 7, 8, 0, 1)
        );
        assert_eq!(p.sessions(), vec![s]);
    }

    #[test]
    fn a_session_on_an_unmapped_page_is_refused_and_takes_no_id()
    {
        let mut p = pool(1);
        assert_eq!(p.new_session(5, frame(5), 1, 2), Err(PoolError::Gone));
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        assert_eq!(p.id_of(s), 1);
    }

    #[test]
    fn an_open_keeps_its_fields_and_its_cursor()
    {
        let mut p = pool(1);
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        let o = p.new_open(s, fields(40)).unwrap();
        assert_eq!(o.slot() % 2, 0);
        assert_eq!(p.open(p.id_of(o)), Some(o));
        assert_eq!(p.session(p.id_of(o)), None);
        assert_eq!(p.session_of(o), Some(s));
        assert_eq!(p.open_fields(o), fields(40));
        let cursor = ChainCursor {
            epoch: 3,
            first_cluster: u32::MAX,
            cluster_index: 9,
            cluster: 0x8000_0001,
        };
        let moved = OpenFields {
            next_read: 4096,
            cursor: Some(cursor),
            ..fields(40)
        };
        p.write_open(o, moved);
        assert_eq!(p.open_fields(o), moved);
        assert_eq!(p.session_fields(s).opens, 1);
    }

    #[test]
    fn a_full_session_asks_for_a_page_and_a_later_page_returns_when_it_empties()
    {
        let mut p = pool(2);
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        let first: Vec<Link> = (0..OPENS_PER_PAGE)
            .map(|i| p.new_open(s, fields(u64::try_from(i).unwrap())).unwrap())
            .collect();
        assert!(first.iter().all(|o| o.page() == 0));
        let live = p.live();
        assert!(!p.room_for_open(s));
        assert!(!p.room_for_held(s));
        assert_eq!(p.new_open(s, fields(99)), Err(PoolError::NeedPage));
        assert_eq!(p.live(), live);
        p.add_page(s, 1, frame(1)).unwrap();
        assert!(p.room_for_open(s));
        assert_eq!(p.session_fields(s).pages, 2);
        let later = p.new_open(s, fields(99)).unwrap();
        assert_eq!(later.page(), 1);
        // A record freed in the first page is taken before the later page's.
        assert_eq!(p.remove_open(first[3], |_| ()), Some(fields(3)));
        assert_eq!(p.take_freed(), None);
        let again = p.new_open(s, fields(98)).unwrap();
        assert_eq!(again.page(), 0);
        assert_eq!(p.remove_open(later, |_| ()), Some(fields(99)));
        assert_eq!(p.take_freed(), Some(freed(1)));
        assert_eq!(p.take_freed(), None);
        assert_eq!(p.session_fields(s).pages, 1);
    }

    #[test]
    fn the_first_page_is_held_while_its_session_lives()
    {
        let mut p = pool(1);
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        let o = p.new_open(s, fields(1)).unwrap();
        assert!(p.remove_open(o, |_| ()).is_some());
        assert_eq!(p.take_freed(), None);
        assert_eq!(p.session(p.id_of(s)), Some(s));
    }

    #[test]
    fn an_id_never_resolves_again_once_its_record_goes()
    {
        let mut p = pool(1);
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        let o = p.new_open(s, fields(1)).unwrap();
        let id = p.id_of(o);
        p.remove_open(o, |_| ()).unwrap();
        assert_eq!(p.open(id), None);
        assert!(p.remove_open(o, |_| ()).is_none());
        let reused = p.new_open(s, fields(2)).unwrap();
        assert_eq!(reused, o);
        assert_ne!(p.id_of(reused), id);
        assert_eq!(p.open(id), None);
    }

    #[test]
    fn held_pages_are_kept_bounded_and_given_back()
    {
        let mut p = pool(1);
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        let o = p.new_open(s, fields(1)).unwrap();
        p.hold(o, held(1), 2).unwrap();
        p.hold(o, held(2), 2).unwrap();
        assert_eq!(p.hold(o, held(3), 2), Err(PoolError::Full));
        assert_eq!(p.held(o), vec![held(2), held(1)]);
        let queued = p.queue_for_eviction(o).unwrap();
        assert_eq!(queued.cookie, 2);
        assert_eq!(p.queue_for_eviction(o).unwrap().cookie, 1);
        assert!(p.queue_for_eviction(o).is_none());
        let (page, emptied) = p.unhold(o, |h| h.cookie == 2).unwrap();
        assert_eq!(page.cookie, 2);
        assert!(page.eviction_queued);
        assert!(emptied.is_none());
        assert!(p.unhold(o, |h| h.cookie == 2).is_none());
        assert_eq!(
            p.held_where(o, |h| h.cookie == 1).map(|h| h.cache_slot),
            Some(11)
        );
        assert!(p.held_where(o, |h| h.cookie == 2).is_none());
        p.hold(o, held(3), 2).unwrap();
        let mut given = Vec::new();
        p.remove_open(o, |h| given.push(h)).unwrap();
        given.sort_unstable_by_key(|h| h.cookie);
        assert_eq!(
            given.iter().map(|h| h.cookie).collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert!(p.unhold(o, |h| h.cookie == 3).is_none());
    }

    #[test]
    fn a_held_page_in_a_later_page_returns_that_page_when_unheld()
    {
        let mut p = pool(2);
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        let opens: Vec<Link> = (0..OPENS_PER_PAGE)
            .map(|i| p.new_open(s, fields(u64::try_from(i).unwrap())).unwrap())
            .collect();
        assert_eq!(p.hold(opens[0], held(1), 8), Err(PoolError::NeedPage));
        p.add_page(s, 1, frame(1)).unwrap();
        p.hold(opens[0], held(1), 8).unwrap();
        let (_, emptied) = p.unhold(opens[0], |h| h.cookie == 1).unwrap();
        assert_eq!(emptied, Some(freed(1)));
    }

    #[test]
    fn a_session_end_returns_every_record_and_page_and_spares_the_others()
    {
        let mut p = pool(3);
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        let other = p.new_session(2, frame(2), 3, 4).unwrap();
        let kept = p.new_open(other, fields(50)).unwrap();
        let opens: Vec<Link> = (0..=OPENS_PER_PAGE)
            .map(|i| {
                if i == OPENS_PER_PAGE
                {
                    p.add_page(s, 1, frame(1)).unwrap();
                }
                p.new_open(s, fields(u64::try_from(i).unwrap())).unwrap()
            })
            .collect();
        p.hold(opens[0], held(7), 4).unwrap();
        let ids: Vec<u64> = opens.iter().map(|&o| p.id_of(o)).collect();
        let sid = p.id_of(s);
        let mut given = Vec::new();
        let mut gone = Vec::new();
        let ended = p
            .end_session(s, |h| given.push(h), |f| gone.push(f))
            .unwrap();
        assert_eq!(ended.id, sid);
        assert_eq!(gone.len(), opens.len());
        assert_eq!(given, vec![held(7)]);
        let mut frames: Vec<Frame> = core::iter::from_fn(|| p.take_freed()).collect();
        frames.sort_unstable();
        assert_eq!(frames, vec![freed(0), freed(1)]);
        assert_eq!(p.session(sid), None);
        assert!(ids.iter().all(|&id| p.open(id).is_none()));
        assert!(p.end_session(s, |_| (), |_| ()).is_none());
        assert_eq!(p.sessions(), vec![other]);
        assert_eq!(p.open(p.id_of(kept)), Some(kept));
        assert_eq!(p.live(), 2);
        assert_eq!(p.new_open(s, fields(1)), Err(PoolError::Gone));
    }

    #[test]
    fn the_opens_of_a_node_go_from_every_session_with_their_pages()
    {
        let mut p = pool(3);
        let a = p.new_session(0, frame(0), 1, 2).unwrap();
        let b = p.new_session(1, frame(1), 3, 4).unwrap();
        let spared = p.new_open(a, fields(5)).unwrap();
        let in_a = p.new_open(a, fields(9)).unwrap();
        let in_b = p.new_open(b, fields(9)).unwrap();
        let filler: Vec<Link> = (0..OPENS_PER_PAGE - 1)
            .map(|_| p.new_open(b, fields(6)).unwrap())
            .collect();
        p.add_page(b, 2, frame(2)).unwrap();
        p.hold(in_b, held(1), 4).unwrap();
        p.hold(in_a, held(2), 4).unwrap();
        let (ia, ib) = (p.id_of(in_a), p.id_of(in_b));
        let mut given = Vec::new();
        let mut gone = Vec::new();
        p.remove_opens_where(
            |f| f.node == 9,
            |h| given.push(h.cookie),
            |f| gone.push(f.node),
        );
        given.sort_unstable();
        assert_eq!(given, vec![1, 2]);
        assert_eq!(gone, vec![9, 9]);
        assert_eq!((p.open(ia), p.open(ib)), (None, None));
        // The held page's record was alone in session b's later page.
        assert_eq!(p.take_freed(), Some(freed(2)));
        assert_eq!(p.take_freed(), None);
        assert_eq!(p.open(p.id_of(spared)), Some(spared));
        assert!(filler.iter().all(|&o| p.open(p.id_of(o)) == Some(o)));
    }

    #[test]
    fn the_session_list_unlinks_from_its_middle()
    {
        let mut p = pool(3);
        let a = p.new_session(0, frame(0), 1, 2).unwrap();
        let b = p.new_session(1, frame(1), 1, 2).unwrap();
        let c = p.new_session(2, frame(2), 1, 2).unwrap();
        p.end_session(b, |_| (), |_| ()).unwrap();
        assert_eq!(p.sessions(), vec![c, a]);
        p.end_session(c, |_| (), |_| ()).unwrap();
        assert_eq!(p.sessions(), vec![a]);
    }

    #[test]
    fn the_index_grows_with_its_records_and_shrinks_after_them()
    {
        let sessions = 64u32;
        let mut p = pool(sessions);
        let mut opens = Vec::new();
        let all: Vec<Link> = (0..sessions)
            .map(|no| p.new_session(no, frame(no), 1, 2).unwrap())
            .collect();
        for &s in &all
        {
            for i in 0..OPENS_PER_PAGE
            {
                opens.push(p.new_open(s, fields(u64::try_from(i).unwrap())).unwrap());
            }
        }
        let live = p.live();
        assert!(p.index_heads() * 2 >= live && p.index_heads() <= live);
        for &o in &opens
        {
            assert_eq!(p.open(p.id_of(o)), Some(o));
        }
        for &s in all.iter().skip(1)
        {
            p.end_session(s, |_| (), |_| ()).unwrap();
            assert!(p.index_heads() <= (2 * p.live()).max(MIN_HEADS));
        }
        assert_eq!(p.index_heads(), MIN_HEADS);
        for &o in opens.iter().take(OPENS_PER_PAGE)
        {
            assert_eq!(p.open(p.id_of(o)), Some(o));
        }
    }

    #[test]
    fn a_spent_counter_refuses_sessions_and_opens_and_places_nothing()
    {
        let mut store = Store::default();
        store.map(0);
        store.map(1);
        let mut p = SessionPool::with_id_bits(store, 3);
        let s = p.new_session(0, frame(0), 1, 2).unwrap();
        let ids: Vec<u64> = (0..6)
            .map(|i| {
                let o = p.new_open(s, fields(i)).unwrap();
                p.id_of(o)
            })
            .collect();
        assert_eq!(ids, vec![2, 3, 4, 5, 6, 7]);
        assert_eq!(p.new_open(s, fields(9)), Err(PoolError::Exhausted));
        assert_eq!(p.new_session(1, frame(1), 1, 2), Err(PoolError::Exhausted));
        assert_eq!(p.session_fields(s).opens, 6);
        assert_eq!(p.live(), 7);
        // Closing frees a record but no id.
        let first = p.open(2).unwrap();
        p.remove_open(first, |_| ()).unwrap();
        assert_eq!(p.new_open(s, fields(9)), Err(PoolError::Exhausted));
    }

    #[test]
    fn links_refuse_headers_and_out_of_range_places()
    {
        assert!(Link::new(0, 0).is_none());
        assert!(Link::new(0, 64).is_none());
        assert!(Link::new(MAX_PAGES, 1).is_none());
        let l = Link::new(MAX_PAGES - 1, 63).unwrap();
        assert_eq!((l.page(), l.slot()), (MAX_PAGES - 1, 63));
    }
}
