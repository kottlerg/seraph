// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/oomd/src/source.rs

//! oomd's stop sources: the services that list candidates oomd may stop and
//! stop the one it names, all through the shared stop labels
//! (`ipc::stop_labels`; docs/session-supervision.md § Stop Sources).
//!
//! Each walk asks svcmgr, on the stop authority, for the sources that run now
//! (`svcmgr_labels::LIST_STOP_SOURCES`): a page of at most
//! `MSG_CAP_SLOTS_MAX` sources, each with its class, which svcmgr reads from
//! the source's recipe, and a stop-badged SEND on its endpoint. It walks each
//! listed source's candidates in svcmgr's order, then svcmgr's own, the
//! service class, on the stop authority, and offers every candidate to a
//! [`Best`]. A walk keeps the cap of the source of the candidate kept and
//! deletes every other cap it received as soon as it is done with it, so it
//! holds at most one page's caps and that one beside them; the caller
//! releases the kept one after its stop ([`Candidate::release`]).
//!
//! Each call to a source is bounded by [`CALL_TIMEOUT_MS`], and a source that
//! does not answer, or answers out of protocol, is logged and passed over, and
//! the walk of one source's list ends after [`LIST_WALK_MS`], so a wedged
//! source does not stall the ladder.

use core::fmt;
use std::time::{Duration, Instant};

use ipc::stop_labels::{LIST_CANDIDATES, LIST_CANDIDATES_PAGE, STOP_CANDIDATE, unpack_candidate};
use ipc::svcmgr_labels::{LIST_STOP_SOURCES, LIST_STOP_SOURCES_PAGE, NAME_MAX, unpack_stop_source};
use ipc::{IpcMessage, stop_labels};
use policy::{Best, Class, Order};

/// How long one call to a source may take, in milliseconds: the wait for the
/// source to receive it and for its reply.
pub const CALL_TIMEOUT_MS: u32 = 2000;

/// How long a walk reads one list, a source's candidates or svcmgr's
/// sources, in milliseconds: a source whose cursor keeps advancing cannot
/// hold the walk past it. A time bound, so a list of any length a source
/// answers at its usual pace, a page in well under a millisecond, is read
/// whole; bounds no capacity.
const LIST_WALK_MS: u64 = 4000;

/// The most caps a walk holds at once: one page of svcmgr's sources and the
/// kept candidate's source. oomd funds this much `CSpace` headroom at start,
/// so no walk grows its `CSpace`.
pub const WALK_CAPS_MAX: usize = LIST_STOP_SOURCES_PAGE + 1;

/// A stop source: its class, the cap oomd calls it on, whether the walk owns
/// that cap (every source but svcmgr), and its name in oomd's log.
struct Source
{
    class: Class,
    cap: u64,
    owned: bool,
    name: [u8; NAME_MAX],
    len: usize,
}

impl Source
{
    /// The source's name, for the log; `?` for one that is not UTF-8.
    fn name(&self) -> &str
    {
        shown(&self.name, self.len)
    }
}

/// `name`'s first `len` bytes as text; `?` when they are not UTF-8.
fn shown(name: &[u8; NAME_MAX], len: usize) -> &str
{
    name.get(..len)
        .and_then(|name| core::str::from_utf8(name).ok())
        .unwrap_or("?")
}

/// A candidate a source listed: the cap its source is called on, whether the
/// walk owns that cap, its key, and its name.
pub struct Candidate
{
    cap: u64,
    owned: bool,
    key: u64,
    name: [u8; NAME_MAX],
    len: usize,
}

impl Candidate
{
    /// The candidate's name, for the log; `?` for one that is not UTF-8.
    pub fn name(&self) -> &str
    {
        shown(&self.name, self.len)
    }

    /// Delete the cap of the candidate's source when the walk received it.
    pub fn release(self)
    {
        if self.owned
        {
            let _ = syscall::cap_delete(self.cap);
        }
    }
}

/// Why a call to a source gave no answer oomd can use.
pub enum Failure
{
    /// The call failed or timed out (the IPC error).
    NoAnswer(i64),
    /// The source replied with a label other than success.
    Refused(u64),
    /// The reply broke the protocol: an entry that does not decode, a page
    /// longer than its page size, caps that do not match its entries, or a
    /// cursor that does not advance.
    Malformed,
    /// The list was not read whole within [`LIST_WALK_MS`].
    Slow,
}

impl fmt::Display for Failure
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::NoAnswer(e) => write!(f, "no answer (err={e})"),
            Self::Refused(label) => write!(f, "refused ({label:#x})"),
            Self::Malformed => f.write_str("reply out of protocol"),
            Self::Slow => write!(f, "list not read within {LIST_WALK_MS} ms"),
        }
    }
}

/// Delete `cap` unless it is 0.
fn delete(cap: u64)
{
    if cap != 0
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Walk the sources svcmgr lists on the stop authority `stop`, then svcmgr
/// itself, and return the candidate stopped first, with its place in the
/// order; `None` when no source listed one. A source that fails is logged,
/// and what it listed before it failed is kept.
pub fn walk(stop: u64, ipc_buf: *mut u64) -> Option<(Order, Candidate)>
{
    let mut best = Best::default();
    if let Err(why) = walk_sources(stop, &mut best, ipc_buf)
    {
        std::os::seraph::log!(warn: "svcmgr: stop sources not read: {why}");
    }
    let mut name = [0u8; NAME_MAX];
    let svcmgr = b"svcmgr";
    if let Some(dst) = name.get_mut(..svcmgr.len())
    {
        dst.copy_from_slice(svcmgr);
    }
    let svcmgr = Source {
        class: Class::Service,
        cap: stop,
        owned: false,
        name,
        len: svcmgr.len(),
    };
    walk_one(&svcmgr, &mut best, ipc_buf);
    best.take()
}

/// The time left of a list walk that began at `start`, as a call's timeout
/// within it, at least a millisecond (a timeout of 0 would wait without
/// bound) and at most [`CALL_TIMEOUT_MS`]; `None` once it is spent.
fn time_left(start: Instant) -> Option<u32>
{
    let left = Duration::from_millis(LIST_WALK_MS).saturating_sub(start.elapsed());
    if left.is_zero()
    {
        return None;
    }
    Some(
        u32::try_from(left.as_millis())
            .unwrap_or(u32::MAX)
            .clamp(1, CALL_TIMEOUT_MS),
    )
}

/// svcmgr's `LIST_STOP_SOURCES` walk on `stop`, page by page until a short
/// page, walking each source a page lists before the next page is asked.
/// The time a page's sources take is not the list's: its bound covers the
/// calls to svcmgr.
fn walk_sources(stop: u64, best: &mut Best<Candidate>, ipc_buf: *mut u64) -> Result<(), Failure>
{
    let mut spent = Duration::ZERO;
    let mut cursor = 0;
    loop
    {
        let begun = Instant::now();
        let start = begun.checked_sub(spent).unwrap_or(begun);
        let timeout = time_left(start).ok_or(Failure::Slow)?;
        let msg = IpcMessage::builder(LIST_STOP_SOURCES)
            .word(0, cursor)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call_timeout(stop, &msg, ipc_buf, timeout) }
            .map_err(Failure::NoAnswer)?;
        spent = spent.saturating_add(begun.elapsed());
        let caps = reply.caps();
        let count = usize::try_from(reply.word(0)).unwrap_or(usize::MAX);
        if reply.label != ipc::svcmgr_errors::SUCCESS
            || count > LIST_STOP_SOURCES_PAGE
            || caps.len() != count
            || caps.contains(&0)
        {
            for &cap in caps
            {
                delete(cap);
            }
            return Err(
                if reply.label == ipc::svcmgr_errors::SUCCESS
                {
                    Failure::Malformed
                }
                else
                {
                    Failure::Refused(reply.label)
                },
            );
        }
        let mut page = [0u64; LIST_STOP_SOURCES_PAGE];
        for (slot, &cap) in page.iter_mut().zip(caps)
        {
            *slot = cap;
        }
        let words = reply.words();
        for (entry, &cap) in page.iter().enumerate().take(count)
        {
            let Some((code, name, len)) = unpack_stop_source(words, entry)
            else
            {
                delete(cap);
                std::os::seraph::log!(warn: "svcmgr: stop source entry {entry} out of protocol");
                continue;
            };
            let Some(class) = Class::from_code(code)
            else
            {
                delete(cap);
                std::os::seraph::log!(
                    warn: "{}: class {code} unknown; passed over",
                    shown(&name, len)
                );
                continue;
            };
            let source = Source {
                class,
                cap,
                owned: true,
                name,
                len,
            };
            walk_one(&source, best, ipc_buf);
            // The source's cap stays only while the candidate kept is its.
            if best.kept().is_none_or(|(_, kept)| kept.cap != cap)
            {
                delete(cap);
            }
        }
        if count < LIST_STOP_SOURCES_PAGE
        {
            return Ok(());
        }
        let next = reply.word(1);
        if next <= cursor
        {
            return Err(Failure::Malformed);
        }
        cursor = next;
    }
}

/// Offer every candidate `source` lists to `best`, logging a failure.
fn walk_one(source: &Source, best: &mut Best<Candidate>, ipc_buf: *mut u64)
{
    if let Err(why) = list(source, best, ipc_buf)
    {
        std::os::seraph::log!(warn: "{}: candidates not read: {why}", source.name());
    }
}

/// Offer every candidate `source` lists to `best`: its `LIST_CANDIDATES`
/// walk, page by page until a short page, within [`LIST_WALK_MS`]. A
/// candidate the offer displaces releases its source's cap unless that is
/// `source`'s, which the caller holds.
fn list(source: &Source, best: &mut Best<Candidate>, ipc_buf: *mut u64) -> Result<(), Failure>
{
    let start = Instant::now();
    let mut cursor = 0;
    loop
    {
        let timeout = time_left(start).ok_or(Failure::Slow)?;
        let msg = IpcMessage::builder(LIST_CANDIDATES).word(0, cursor).build();
        let reply = call(source.cap, &msg, timeout, ipc_buf)?;
        let count = usize::try_from(reply.word(0)).unwrap_or(usize::MAX);
        if count > LIST_CANDIDATES_PAGE
        {
            return Err(Failure::Malformed);
        }
        for entry in 0..count
        {
            let listed = unpack_candidate(reply.words(), entry).ok_or(Failure::Malformed)?;
            let order = Order {
                class: source.class,
                rank: listed.rank,
                pages: listed.pages,
            };
            let candidate = Candidate {
                cap: source.cap,
                owned: source.owned,
                key: listed.key,
                name: listed.name,
                len: listed.len,
            };
            if let Some(dropped) = best.offer(order, candidate)
                && dropped.cap != source.cap
            {
                dropped.release();
            }
        }
        if count < LIST_CANDIDATES_PAGE
        {
            return Ok(());
        }
        let next = reply.word(1);
        if next <= cursor
        {
            return Err(Failure::Malformed);
        }
        cursor = next;
    }
}

/// Stop `candidate` through its source: `STOP_CANDIDATE` of its key. A call
/// that times out may still have stopped it.
pub fn stop(candidate: &Candidate, ipc_buf: *mut u64) -> Result<(), Failure>
{
    let msg = IpcMessage::builder(STOP_CANDIDATE)
        .word(0, candidate.key)
        .build();
    call(candidate.cap, &msg, CALL_TIMEOUT_MS, ipc_buf).map(|_| ())
}

/// Call the source on `cap` with `msg`, bounded by `timeout_ms`: its reply
/// when it replied success. No stop label's reply carries a cap, so any the
/// source sent is deleted.
fn call(
    cap: u64,
    msg: &IpcMessage,
    timeout_ms: u32,
    ipc_buf: *mut u64,
) -> Result<IpcMessage, Failure>
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call_timeout(cap, msg, ipc_buf, timeout_ms) }
        .map_err(Failure::NoAnswer)?;
    for &sent in reply.caps()
    {
        delete(sent);
    }
    if reply.label != stop_labels::SUCCESS
    {
        return Err(Failure::Refused(reply.label));
    }
    Ok(reply)
}
