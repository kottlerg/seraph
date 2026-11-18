// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/oomd/src/source.rs

//! oomd's stop sources: the services that list candidates oomd may stop and
//! stop the one it names (docs/session-supervision.md § Stop Sources).
//!
//! A walk asks each source in turn for its whole list and offers every entry
//! to a [`Best`], so the candidate kept is the one the order stops first,
//! ties going to the earlier source and then its earlier entry. Each call to
//! a source is bounded by [`CALL_TIMEOUT_MS`], and a source that does not
//! answer, or answers out of protocol, is logged and passed over, and the
//! walk of one source's list ends after [`LIST_WALK_MS`], so a wedged source
//! does not stall the ladder. svcmgr is the one source: its class is
//! the service class, and it serves `LIST_STOPPABLE` and `STOP_SERVICE` on
//! the stop authority (services/svcmgr/docs/ipc-interface.md § Label 5 and
//! § Label 6).

use core::fmt;
use std::time::{Duration, Instant};

use ipc::svcmgr_labels::{
    LIST_STOPPABLE, LIST_STOPPABLE_PAGE, NAME_MAX, STOP_SERVICE, unpack_stoppable_entry,
};
use ipc::{IpcMessage, svcmgr_errors};
use policy::{Best, Class, Order};

/// How long one call to a source may take, in milliseconds: the wait for the
/// source to receive it and for its reply.
pub const CALL_TIMEOUT_MS: u32 = 2000;

/// How long a walk reads one source's list, in milliseconds: a source whose
/// cursor keeps advancing cannot hold the walk past it. A time bound, so a
/// list of any length a source answers at its usual pace, a page in well
/// under a millisecond, is read whole; bounds no capacity.
const LIST_WALK_MS: u64 = 4000;

/// The rank of every service svcmgr lists: the service class has one rank.
const SERVICE_RANK: u8 = 0;

/// A stop source: its class and the cap oomd calls it on.
pub struct Source
{
    class: Class,
    cap: u64,
    /// The source's name in oomd's log.
    what: &'static str,
}

impl Source
{
    /// svcmgr, the service class's source, reached on the stop authority
    /// `cap`.
    pub const fn svcmgr(cap: u64) -> Self
    {
        Self {
            class: Class::Service,
            cap,
            what: "svcmgr",
        }
    }
}

/// A candidate a source listed: its source and its key, the name the source
/// stops it by.
#[derive(Clone, Copy)]
pub struct Candidate
{
    /// The index of its source in the walk's list.
    source: usize,
    name: [u8; NAME_MAX],
    len: usize,
}

impl Candidate
{
    /// The candidate's name, for the log; `?` for one that is not UTF-8.
    pub fn name(&self) -> &str
    {
        self.name
            .get(..self.len)
            .and_then(|name| core::str::from_utf8(name).ok())
            .unwrap_or("?")
    }

    fn key(&self) -> &[u8]
    {
        self.name.get(..self.len).unwrap_or_default()
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
    /// longer than [`LIST_STOPPABLE_PAGE`], or a cursor that does not
    /// advance.
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

/// Walk `sources` in order and return the candidate stopped first, with its
/// place in the order; `None` when no source listed one. A source that
/// fails is logged, and what it listed before it failed is kept.
pub fn walk(sources: &[Source], ipc_buf: *mut u64) -> Option<(Order, Candidate)>
{
    let mut best = Best::default();
    for (index, source) in sources.iter().enumerate()
    {
        if let Err(why) = list(source, index, &mut best, ipc_buf)
        {
            std::os::seraph::log!(warn: "{}: candidates not read: {why}", source.what);
        }
    }
    best.take()
}

/// Offer every candidate `source`, at `index` in the walk, lists to `best`:
/// svcmgr's `LIST_STOPPABLE` walk, page by page until a short page, within
/// [`LIST_WALK_MS`].
fn list(
    source: &Source,
    index: usize,
    best: &mut Best<Candidate>,
    ipc_buf: *mut u64,
) -> Result<(), Failure>
{
    let start = Instant::now();
    let walk = Duration::from_millis(LIST_WALK_MS);
    let mut cursor = 0;
    loop
    {
        let left = walk.saturating_sub(start.elapsed());
        if left.is_zero()
        {
            return Err(Failure::Slow);
        }
        // Each call within the walk's time left, and at least a millisecond:
        // a timeout of 0 would wait without bound.
        let timeout = u32::try_from(left.as_millis())
            .unwrap_or(u32::MAX)
            .clamp(1, CALL_TIMEOUT_MS);
        let msg = IpcMessage::builder(LIST_STOPPABLE).word(0, cursor).build();
        let reply = call(source, &msg, timeout, ipc_buf)?;
        let count = usize::try_from(reply.word(0)).unwrap_or(usize::MAX);
        if count > LIST_STOPPABLE_PAGE
        {
            return Err(Failure::Malformed);
        }
        for entry in 0..count
        {
            let (pages, name, len) =
                unpack_stoppable_entry(reply.words(), entry).ok_or(Failure::Malformed)?;
            let order = Order {
                class: source.class,
                rank: SERVICE_RANK,
                pages,
            };
            best.offer(
                order,
                Candidate {
                    source: index,
                    name,
                    len,
                },
            );
        }
        if count < LIST_STOPPABLE_PAGE
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

/// Stop `candidate` through its source in `sources`: svcmgr's
/// `STOP_SERVICE` of its name. A call that times out may still have
/// stopped it.
pub fn stop(sources: &[Source], candidate: &Candidate, ipc_buf: *mut u64) -> Result<(), Failure>
{
    let source = sources.get(candidate.source).ok_or(Failure::Malformed)?;
    let key = candidate.key();
    let label = STOP_SERVICE | ((key.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, key).build();
    call(source, &msg, CALL_TIMEOUT_MS, ipc_buf).map(|_| ())
}

/// Call `source` with `msg`, bounded by `timeout_ms`: its reply when it
/// replied success.
fn call(
    source: &Source,
    msg: &IpcMessage,
    timeout_ms: u32,
    ipc_buf: *mut u64,
) -> Result<IpcMessage, Failure>
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call_timeout(source.cap, msg, ipc_buf, timeout_ms) }
        .map_err(Failure::NoAnswer)?;
    if reply.label != svcmgr_errors::SUCCESS
    {
        return Err(Failure::Refused(reply.label));
    }
    Ok(reply)
}
