// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/file.rs

//! Open instances of the FAT driver, of both kinds ([`Opens`]).
//!
//! An `FS_OPEN` made in a session (services/fs/docs/fs-driver-protocol.md
//! § Label 23) records the open in the session's pages, which its client pays
//! for (`fat_parse::session_pool`, `crate::session`): the open's id, from a
//! counter that never repeats, is the open cap's badge, and its held pages
//! are records in those pages too. One made without a session, the unpaid
//! path, inserts one [`OpenFile`] into an [`OpenTable`] on fatfs's own heap,
//! whose generation-checked identifier is the open cap's badge
//! (services/fs/docs/fs-driver-protocol.md § Label 18). Either kind is named
//! by a `namespace_protocol::OpenRef`, and [`Opens`] serves both through one
//! interface.
//!
//! Two opens of one file are two opens, so each keeps its own outstanding
//! pages and release SEND, and one open's `FS_CLOSE` touches no other. An
//! unpaid open carries a table of outstanding cache pages handed out via `FS_READ_MEMORY`, grown
//! on demand up to the cache's slot ceiling; each entry holds the cookie the
//! client uses to reference the page, the cache slot the page lives in (so
//! the slot's refcount can be decremented on release), and an ancestor cap
//! interposed between the slot's parent cap and the caller-side child cap so
//! per-cookie revocation is possible. An unpaid open also keeps the parent of
//! its liveness cap, whose sole remaining reference marks an open whose client is
//! gone ([`OpenFile::client_gone`]), and where its memory-cap reads stand: the
//! offset a sequential read takes next and a cursor into the file's cluster
//! chain.

use fat_parse::ChainCursor;
use fat_parse::open_slab::{OpenSlab, SweepSchedule};
use fat_parse::session_pool::{Frame, HeldPage, Link, OpenFields, PoolError, Removed, SessionPool};
use namespace_protocol::{NodeId, OpenRef};

use crate::cache::PageCache;
use crate::eviction::EvictReq;
use crate::session::{self, Grant, SessionPages};

/// The driver's open instances made without a session, keyed by the open id
/// an open cap's badge carries. At most `node_slab::MAX_ENTRIES` (2^24 - 1)
/// live opens, the identifier's index field; no per-client bound applies,
/// since the driver has no client identity and an open cap can be
/// delegated. Opens whose client is gone are swept out on the schedule
/// `open_slab::SweepSchedule` sets.
pub type OpenTable = OpenSlab<OpenFile>;

/// One outstanding page handed to a client via `FS_READ_MEMORY`.
#[derive(Clone, Copy)]
pub struct OutstandingPage
{
    /// Caller-visible identifier for this page; round-trips through
    /// `FS_RELEASE_MEMORY`. Disambiguates which outstanding entry an
    /// inbound client release or worker-driven eviction targets when
    /// multiple pages of the same file are mapped concurrently.
    pub cookie: u64,
    /// Cache slot index whose refcount is held by this entry.
    pub slot_idx: usize,
    /// Per-cookie ancestor cap, derived from the cache slot's parent cap.
    /// Revoking it kills only this caller's child cap; the cache slot's
    /// parent cap stays untouched. Lives in the fs's `CSpace` until the
    /// outstanding entry is dropped.
    pub ancestor_cap: u64,
    /// Set when the page has been queued for the eviction worker, so a
    /// later cache miss picks another page instead of queueing this one
    /// again. It is never cleared: the entry leaves the table when the
    /// page is cleaned up.
    pub eviction_queued: bool,
}

/// One open instance of a file, minted by `FS_OPEN`.
///
/// The file's size and first cluster are not kept here: reads take them
/// from the node table, which every write and truncate updates.
pub struct OpenFile
{
    /// The node the open was minted on. An `FS_REMOVE` or `FS_RENAME` that
    /// frees the node releases every open naming it.
    pub node_id: NodeId,
    /// Outstanding pages; a `None` entry is a free one, reused before the
    /// table grows.
    pub outstanding: Vec<Option<OutstandingPage>>,
    /// SEND cap on the client's release endpoint, from `caps[0]` of the
    /// `FS_OPEN` that minted this open (services/fs/docs/fs-driver-protocol.md
    /// § Label 18); the eviction worker addresses cooperative
    /// `FS_RELEASE_MEMORY` requests for this open's pages to it. Zero when
    /// the open carried none; eviction then skips the cooperative
    /// round-trip and goes straight to the revoke. Deleted from the fs's
    /// `CSpace` when the open is released.
    pub release_endpoint_cap: u64,
    /// The driver's own cap on the open's liveness Notification, the parent
    /// of the zero-rights liveness cap the `FS_OPEN` reply handed the client
    /// (services/fs/docs/fs-driver-protocol.md § Label 18). Revoked, which
    /// kills the client's copy and every copy still in this cap's derivation
    /// subtree, and deleted when the open is released.
    pub liveness_cap: u64,
    /// The file offset an `FS_READ_MEMORY` on a sequential scan asks for
    /// next: the end of the bytes the open's last one returned, 0 before
    /// the first. A read at it that misses the cache fills a run of pages
    /// (services/fs/fat/docs/storage-layout.md, Page cache).
    pub next_read: u64,
    /// Where the open's last `FS_READ_MEMORY` stood in the file's cluster
    /// chain; the next one's walk starts there when it still serves
    /// (`fat_parse::walk_start`). `None` before the first.
    pub cursor: Option<ChainCursor>,
}

/// Whether every copy outside the driver of the liveness cap whose parent
/// is `liveness` is gone: the driver's own cap is the only reference left to
/// the Notification (`CAP_INFO_SOLE_REFERENCE`). Once it answers so it keeps
/// answering so, since only the driver could take a new reference through its
/// cap. A failed inquiry answers `false`, keeping what the cap guards.
fn sole_reference(liveness: u64) -> bool
{
    syscall::cap_info(liveness, syscall::CAP_INFO_SOLE_REFERENCE) == Ok(1)
}

impl OpenFile
{
    pub const fn new(node_id: NodeId, release_endpoint_cap: u64, liveness_cap: u64) -> Self
    {
        Self {
            node_id,
            outstanding: Vec::new(),
            release_endpoint_cap,
            liveness_cap,
            next_read: 0,
            cursor: None,
        }
    }

    /// Whether every copy of the open's liveness cap outside the driver is
    /// gone, so no holder keeps the open alive: the driver's own cap is the
    /// only reference left to the Notification (`CAP_INFO_SOLE_REFERENCE`).
    /// Once it answers so it keeps answering so, since only the driver could
    /// take a new reference through its cap. A failed inquiry answers `false`,
    /// keeping the open.
    pub fn client_gone(&self) -> bool
    {
        sole_reference(self.liveness_cap)
    }

    /// Insert `entry` into a free outstanding slot, growing the table while
    /// it holds fewer than `limit` pages, the cache's slot ceiling: each
    /// outstanding page holds a cache slot, so one open cannot usefully hold
    /// more pages than the cache has slots, and the bound scales with the
    /// cache. The per-call ancestor caps live in the fs's `CSpace` until
    /// released or close; the table grows only with the pages a client
    /// holds. Returns `false` when the open already holds `limit` pages, or
    /// the table cannot grow.
    pub fn track_outstanding(&mut self, entry: OutstandingPage, limit: usize) -> bool
    {
        if let Some(slot) = self.outstanding.iter_mut().find(|s| s.is_none())
        {
            *slot = Some(entry);
            return true;
        }
        if self.outstanding.len() >= limit || self.outstanding.try_reserve(1).is_err()
        {
            return false;
        }
        self.outstanding.push(Some(entry));
        true
    }
}

impl OutstandingPage
{
    /// The page as a session's held-page record keeps it.
    fn held(self) -> HeldPage
    {
        HeldPage {
            cookie: self.cookie,
            cache_slot: u64::try_from(self.slot_idx).unwrap_or(u64::MAX),
            ancestor_cap: self.ancestor_cap,
            eviction_queued: self.eviction_queued,
        }
    }

    /// The page a session's held-page record keeps.
    fn from_held(page: HeldPage) -> Self
    {
        Self {
            cookie: page.cookie,
            slot_idx: usize::try_from(page.cache_slot).unwrap_or(usize::MAX),
            ancestor_cap: page.ancestor_cap,
            eviction_queued: page.eviction_queued,
        }
    }

    /// Whether this is the page `req` was queued for.
    const fn is(&self, req: &EvictReq) -> bool
    {
        self.cookie == req.cookie
            && self.slot_idx == req.slot_idx
            && self.ancestor_cap == req.ancestor_cap
    }

    /// Revoke the client's cap on the page, delete the ancestor, and drop the
    /// cache slot's reference.
    fn release(&self, cache: &PageCache)
    {
        let _ = syscall::cap_revoke_all(self.ancestor_cap);
        let _ = syscall::cap_delete(self.ancestor_cap);
        cache.release_slot(self.slot_idx);
    }
}

/// Why a session could not take a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionRefusal
{
    /// The session is not live.
    Gone,
    /// The session needs another page first; its charge-only handle, which
    /// [`session::request_page`] takes.
    NeedPage(u64),
    /// The driver's ids, heap, or address-space window are spent.
    Spent,
    /// memmgr gave no page; the `fs_errors` code to answer
    /// ([`session::request_page`]).
    Memmgr(u64),
}

/// Every open instance of the driver: those made in a session, in the
/// session's own pages, and those made without one, in an [`OpenTable`].
/// Shared with the eviction worker under one `Mutex`; each method that
/// releases something releases it before it returns, a session page with a
/// memmgr call.
pub struct Opens
{
    /// The opens made without a session.
    pub unpaid: OpenTable,
    /// The sessions, their opens, and the pages their opens hold.
    sessions: SessionPool<SessionPages>,
}

impl Opens
{
    /// No open and no session; session pages map into `pages`, the id
    /// counter as wide as an open or session badge carries
    /// (`namespace_protocol::KIND_ID_BITS`).
    pub const fn new(pages: SessionPages) -> Self
    {
        Self {
            unpaid: OpenTable::new(),
            sessions: SessionPool::with_id_bits(pages, namespace_protocol::KIND_ID_BITS),
        }
    }

    /// The node the open `open` names was minted on; `None` when it is not
    /// live.
    pub fn node(&self, open: OpenRef) -> Option<NodeId>
    {
        match open
        {
            OpenRef::Unpaid(id) => self.unpaid.get(id).map(|f| f.node_id),
            OpenRef::Session(id) => self
                .sessions
                .open(id)
                .map(|l| NodeId::from_raw_truncated(self.sessions.open_fields(l).node)),
        }
    }

    /// Where the open's last memory-cap read stood in its file's cluster
    /// chain.
    pub fn cursor(&self, open: OpenRef) -> Option<ChainCursor>
    {
        match open
        {
            OpenRef::Unpaid(id) => self.unpaid.get(id).and_then(|f| f.cursor),
            OpenRef::Session(id) => self
                .sessions
                .open(id)
                .and_then(|l| self.sessions.open_fields(l).cursor),
        }
    }

    /// Record `cursor` as where the open's read at `offset` stands, and
    /// return whether that read continues a sequential scan (`offset` is
    /// where the open's last read ended); `false` when the open is not live.
    pub fn note_read(&mut self, open: OpenRef, cursor: ChainCursor, offset: u64) -> bool
    {
        match open
        {
            OpenRef::Unpaid(id) => self.unpaid.get_mut(id).is_some_and(|f| {
                f.cursor = Some(cursor);
                f.next_read == offset
            }),
            OpenRef::Session(id) =>
            {
                let Some(l) = self.sessions.open(id)
                else
                {
                    return false;
                };
                let mut fields = self.sessions.open_fields(l);
                fields.cursor = Some(cursor);
                self.sessions.write_open(l, fields);
                fields.next_read == offset
            }
        }
    }

    /// Record `entry` as held by the open, which holds at most `limit`
    /// pages, and `next_read` as where a sequential read of it goes on.
    /// `false` when the open is not live, already holds `limit` pages, or
    /// cannot record the page (an unpaid open's heap, or a session's pages,
    /// full).
    pub fn track(
        &mut self,
        open: OpenRef,
        entry: OutstandingPage,
        limit: usize,
        next_read: u64,
    ) -> bool
    {
        match open
        {
            OpenRef::Unpaid(id) => self.unpaid.get_mut(id).is_some_and(|f| {
                let tracked = f.track_outstanding(entry, limit);
                if tracked
                {
                    f.next_read = next_read;
                }
                tracked
            }),
            OpenRef::Session(id) =>
            {
                let Some(l) = self.sessions.open(id)
                else
                {
                    return false;
                };
                let limit = u64::try_from(limit).unwrap_or(u64::MAX);
                if self.sessions.hold(l, entry.held(), limit).is_err()
                {
                    return false;
                }
                let mut fields = self.sessions.open_fields(l);
                fields.next_read = next_read;
                self.sessions.write_open(l, fields);
                true
            }
        }
    }

    /// Release the page the open holds under `cookie`, if any, as
    /// `FS_RELEASE_MEMORY` does. `false` when the open is not live.
    pub fn release_held(&mut self, open: OpenRef, cookie: u64, cache: &PageCache) -> bool
    {
        match open
        {
            OpenRef::Unpaid(id) =>
            {
                let Some(file) = self.unpaid.get_mut(id)
                else
                {
                    return false;
                };
                if let Some(slot) = file
                    .outstanding
                    .iter_mut()
                    .find(|s| s.is_some_and(|e| e.cookie == cookie))
                    && let Some(entry) = slot.take()
                {
                    entry.release(cache);
                }
                true
            }
            OpenRef::Session(id) =>
            {
                let Some(l) = self.sessions.open(id)
                else
                {
                    return false;
                };
                if let Some((page, emptied)) = self.sessions.unhold(l, |h| h.cookie == cookie)
                {
                    OutstandingPage::from_held(page).release(cache);
                    self.release_frame(emptied);
                }
                true
            }
        }
    }

    /// Mark one held page not yet queued for eviction as queued and return
    /// it, so repeated misses under pressure queue distinct pages. `None`
    /// when every held page is queued already, or none is held.
    pub fn pick_eviction_candidate(&mut self) -> Option<EvictReq>
    {
        for (open_id, file) in self.unpaid.iter_mut()
        {
            if let Some(entry) = file
                .outstanding
                .iter_mut()
                .flatten()
                .find(|e| !e.eviction_queued)
            {
                entry.eviction_queued = true;
                return Some(EvictReq::new(OpenRef::Unpaid(open_id), entry));
            }
        }
        for session in self.sessions.sessions()
        {
            for open in self.sessions.opens_of(session)
            {
                if let Some(page) = self.sessions.queue_for_eviction(open)
                {
                    let id = self.sessions.id_of(open);
                    return Some(EvictReq::new(
                        OpenRef::Session(id),
                        &OutstandingPage::from_held(page),
                    ));
                }
            }
        }
        None
    }

    /// When the page `req` was queued for is still held, the release SEND
    /// of its open: `Some(0)` when the open carried none. `None` when the
    /// page was already released.
    pub fn release_endpoint_if_held(&self, req: &EvictReq) -> Option<u64>
    {
        match req.open
        {
            OpenRef::Unpaid(id) =>
            {
                let file = self.unpaid.get(id)?;
                file.outstanding
                    .iter()
                    .flatten()
                    .any(|e| e.is(req))
                    .then_some(file.release_endpoint_cap)
            }
            OpenRef::Session(id) =>
            {
                let l = self.sessions.open(id)?;
                self.sessions
                    .held_where(l, |h| OutstandingPage::from_held(*h).is(req))?;
                Some(self.sessions.open_fields(l).release_cap)
            }
        }
    }

    /// Take the page `req` was queued for off its open, when it is still
    /// held: the caller then owns its release. A session page the record held
    /// is given back here.
    pub fn take_held(&mut self, req: &EvictReq) -> bool
    {
        match req.open
        {
            OpenRef::Unpaid(id) =>
            {
                let Some(file) = self.unpaid.get_mut(id)
                else
                {
                    return false;
                };
                let Some(slot) = file
                    .outstanding
                    .iter_mut()
                    .find(|s| s.is_some_and(|e| e.is(req)))
                else
                {
                    return false;
                };
                *slot = None;
                true
            }
            OpenRef::Session(id) =>
            {
                let Some(l) = self.sessions.open(id)
                else
                {
                    return false;
                };
                let Some((_, emptied)) = self
                    .sessions
                    .unhold(l, |h| OutstandingPage::from_held(*h).is(req))
                else
                {
                    return false;
                };
                self.release_frame(emptied);
                true
            }
        }
    }

    /// Close the open: release its pages and its release SEND, and for an
    /// unpaid open its liveness cap. `false` when it is not live.
    pub fn close(&mut self, open: OpenRef, cache: &PageCache) -> bool
    {
        match open
        {
            OpenRef::Unpaid(id) => self
                .unpaid
                .remove(id)
                .map(|f| release_open_file(&f, cache))
                .is_some(),
            OpenRef::Session(id) =>
            {
                let Some(l) = self.sessions.open(id)
                else
                {
                    return false;
                };
                if let Some(removed) = self.sessions.remove_open(l)
                {
                    self.release_removed(removed, cache);
                }
                true
            }
        }
    }

    /// Close every open of `node`, of either kind.
    pub fn close_node(&mut self, node: NodeId, cache: &PageCache)
    {
        self.unpaid
            .remove_where(|f| f.node_id == node, |f| release_open_file(&f, cache));
        for session in self.sessions.sessions()
        {
            for open in self.sessions.opens_of(session)
            {
                if self.sessions.open_fields(open).node == node.raw()
                    && let Some(removed) = self.sessions.remove_open(open)
                {
                    self.release_removed(removed, cache);
                }
            }
        }
    }

    /// Release every unpaid open whose client holds no copy of its liveness
    /// cap any more ([`OpenFile::client_gone`]), as `FS_CLOSE` would, and
    /// restart `sweeps` from the unpaid opens left.
    pub fn sweep_unpaid(&mut self, sweeps: &mut SweepSchedule, cache: &PageCache)
    {
        self.unpaid
            .remove_where(OpenFile::client_gone, |f| release_open_file(&f, cache));
        sweeps.swept(self.unpaid.len());
    }

    /// End every session whose client holds no copy of its liveness cap any
    /// more, with every open made in it, and give its pages back. Returns the
    /// sessions left. One `CAP_INFO_SOLE_REFERENCE` per live session.
    pub fn sweep_sessions(&mut self, cache: &PageCache) -> usize
    {
        let mut left = 0usize;
        for session in self.sessions.sessions()
        {
            if sole_reference(self.sessions.session_fields(session).liveness_cap)
            {
                self.end_session(session, cache);
            }
            else
            {
                left = left.saturating_add(1);
            }
        }
        left
    }

    /// Live opens of either kind.
    pub fn live_opens(&self) -> usize
    {
        let sessions = self.sessions.sessions().len();
        self.unpaid
            .len()
            .saturating_add(self.sessions.live().saturating_sub(sessions))
    }

    /// Release every open and end every session.
    pub fn release_all(&mut self, cache: &PageCache)
    {
        self.unpaid
            .remove_where(|_| true, |f| release_open_file(&f, cache));
        for session in self.sessions.sessions()
        {
            self.end_session(session, cache);
        }
    }

    // ── sessions ─────────────────────────────────────────────────────────

    /// Start a session in `grant`, its first page, with its charge-only
    /// handle and the parent of its liveness cap. Returns its id. On
    /// [`SessionRefusal::Spent`] nothing of the session is kept and the
    /// grant, the handle and the liveness cap are the caller's still.
    pub fn start_session(
        &mut self,
        grant: Grant,
        handle: u64,
        liveness: u64,
    ) -> Result<u64, SessionRefusal>
    {
        let page = self
            .sessions
            .store_mut()
            .map(grant.cap)
            .ok_or(SessionRefusal::Spent)?;
        let started = self
            .sessions
            .new_session(page, grant.words(), handle, liveness);
        if let Ok(l) = started
        {
            Ok(self.sessions.id_of(l))
        }
        else
        {
            self.sessions.store_mut().unmap(page);
            Err(SessionRefusal::Spent)
        }
    }

    /// The session `id` names, when live.
    fn session(&self, id: u64) -> Result<Link, SessionRefusal>
    {
        self.sessions.session(id).ok_or(SessionRefusal::Gone)
    }

    /// Whether the session `id` names can take an open's record now:
    /// `Err(NeedPage)` when it needs another page first.
    pub fn room_for_open(&self, id: u64) -> Result<(), SessionRefusal>
    {
        let l = self.session(id)?;
        if self.sessions.room_for_open(l)
        {
            Ok(())
        }
        else
        {
            Err(SessionRefusal::NeedPage(
                self.sessions.session_fields(l).charge_cap,
            ))
        }
    }

    /// Whether the session of the open `open` names can take a held page's
    /// record now: `Err(NeedPage)` when it needs another page first, `Ok`
    /// for an unpaid open and for one that is not live, which the read
    /// refuses later.
    pub fn room_for_held(&self, open: OpenRef) -> Result<(), SessionRefusal>
    {
        let OpenRef::Session(id) = open
        else
        {
            return Ok(());
        };
        let Some(session) = self
            .sessions
            .open(id)
            .and_then(|l| self.sessions.session_of(l))
        else
        {
            return Ok(());
        };
        if self.sessions.room_for_held(session)
        {
            Ok(())
        }
        else
        {
            Err(SessionRefusal::NeedPage(
                self.sessions.session_fields(session).charge_cap,
            ))
        }
    }

    /// The session's id, for the session an open `open` names belongs to;
    /// `None` for an unpaid or ended open.
    pub fn session_of(&self, open: OpenRef) -> Option<u64>
    {
        let OpenRef::Session(id) = open
        else
        {
            return None;
        };
        let session = self
            .sessions
            .open(id)
            .and_then(|l| self.sessions.session_of(l))?;
        Some(self.sessions.id_of(session))
    }

    /// Add `grant` to the session `id` names as another page. On an error
    /// the grant is the caller's still.
    pub fn add_page(&mut self, id: u64, grant: Grant) -> Result<(), SessionRefusal>
    {
        let l = self.session(id)?;
        let page = self
            .sessions
            .store_mut()
            .map(grant.cap)
            .ok_or(SessionRefusal::Spent)?;
        if self.sessions.add_page(l, page, grant.words()).is_err()
        {
            self.sessions.store_mut().unmap(page);
            return Err(SessionRefusal::Spent);
        }
        Ok(())
    }

    /// Record an open of `node` in the session `id` names, with its release
    /// SEND (0 for none). Returns the open's id.
    pub fn open_in_session(
        &mut self,
        id: u64,
        node: NodeId,
        release_cap: u64,
    ) -> Result<u64, SessionRefusal>
    {
        let l = self.session(id)?;
        let fields = OpenFields {
            node: node.raw(),
            release_cap,
            next_read: 0,
            cursor: None,
        };
        match self.sessions.new_open(l, fields)
        {
            Ok(open) => Ok(self.sessions.id_of(open)),
            Err(PoolError::Gone) => Err(SessionRefusal::Gone),
            Err(PoolError::NeedPage) => Err(SessionRefusal::NeedPage(
                self.sessions.session_fields(l).charge_cap,
            )),
            Err(_) => Err(SessionRefusal::Spent),
        }
    }

    /// End the session `id` names, as the loss of its last liveness copy
    /// would; `false` when it is not live.
    pub fn end_session_by_id(&mut self, id: u64, cache: &PageCache) -> bool
    {
        let Ok(l) = self.session(id)
        else
        {
            return false;
        };
        self.end_session(l, cache);
        true
    }

    /// End the session `session` names: release each of its opens, revoke
    /// the copies of its liveness cap, delete its handle, and give back
    /// every page.
    fn end_session(&mut self, session: Link, cache: &PageCache)
    {
        let Some(ended) = self.sessions.end_session(session)
        else
        {
            return;
        };
        for open in ended.opens
        {
            self.release_removed(open, cache);
        }
        let _ = syscall::cap_revoke_all(ended.session.liveness_cap);
        let _ = syscall::cap_delete(ended.session.liveness_cap);
        let _ = syscall::cap_delete(ended.session.charge_cap);
        for frame in ended.frames
        {
            self.release_frame(Some(frame));
        }
    }

    /// Release an open taken out of a session: its held pages, its release
    /// SEND, and the session pages its removal emptied.
    fn release_removed(&mut self, removed: Removed, cache: &PageCache)
    {
        for page in removed.held
        {
            OutstandingPage::from_held(page).release(cache);
        }
        if removed.fields.release_cap != 0
        {
            let _ = syscall::cap_delete(removed.fields.release_cap);
        }
        for frame in removed.frames
        {
            self.release_frame(Some(frame));
        }
    }

    /// Unmap a session page the pool gave back and return it to memmgr. A
    /// page that will not unmap is kept mapped, and stays charged, until
    /// fatfs exits.
    fn release_frame(&mut self, frame: Option<Frame>)
    {
        let Some(frame) = frame
        else
        {
            return;
        };
        if self.sessions.store_mut().unmap(frame.page)
        {
            session::release_page(Grant::from_words(frame.words));
        }
        else
        {
            std::os::seraph::log!(warn: "session: a page would not unmap; kept");
        }
    }
}

/// Release an unpaid open taken out of the table: revoke and drop each
/// outstanding page, delete the recorded release SEND (leaving it in the
/// `CSpace` would accumulate a stale SEND per open across the fs's
/// lifetime), and revoke the copies of the liveness cap before deleting its
/// parent, so the client's copy dies with the open and the Notification's
/// bytes return to fatfs's object slab. A copy derived from another holder's
/// copy is out of the revoke's reach once a `CSpace` holding a copy on its
/// derivation path is torn down, and holds the bytes until its holder
/// deletes it (services/fs/docs/fs-driver-protocol.md § Label 18).
pub fn release_open_file(file: &OpenFile, cache: &PageCache)
{
    let _ = syscall::cap_revoke_all(file.liveness_cap);
    let _ = syscall::cap_delete(file.liveness_cap);
    for entry in file.outstanding.iter().flatten()
    {
        entry.release(cache);
    }
    if file.release_endpoint_cap != 0
    {
        let _ = syscall::cap_delete(file.release_endpoint_cap);
    }
}
