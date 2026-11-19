// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/mem-fill/src/lib.rs

//! Filling memmgr's pool down to its growth floor (the system reserve and,
//! while chunks are swapped, the restore headroom), for the test fixtures that
//! drive the out-of-memory paths: the `memhog` fixture
//! (services/memhog/README.md) and crashme's `oom-fill` mode
//! (programs/crashme/README.md).
//!
//! A [`Fill`] takes what memmgr can still promise a process outside the
//! reserve: it commits that much through the heap, halving an attempt memmgr
//! refuses, then takes what is left a page at a time by `REQUEST_MEMORY_CAPS`
//! grants, whose caps stay in the process's `CSpace` until it dies.
//! [`Fill::to_critical`] does so until nothing is left and the pressure level
//! has read `CRITICAL` for [`SETTLE_MS`]; [`Fill::top_up`] takes back what
//! other processes freed since. Neither allocates beyond the blocks it
//! commits, whose list's room [`Fill::new`] makes.

use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::PAGE_SIZE;

/// How long the level reads `CRITICAL`, with nothing left to take, before
/// [`Fill::to_critical`] returns: a file system gives back its cache when the
/// level rises, and the fill takes that too.
pub const SETTLE_MS: u64 = 500;
/// How long [`Fill::to_critical`] tries to reach `CRITICAL`. A test wait
/// bound.
pub const TIMEOUT_MS: u64 = 30_000;
/// How often a fill takes back what other processes freed.
pub const TICK_MS: u64 = 10;

/// Blocks a fill commits at most: each failure halves the next attempt, and
/// each success commits at least half of what is left.
const MAX_BLOCKS: usize = 256;
/// Attempts of one top-up.
const TOP_UP_ROUNDS: usize = 64;
/// Pages a heap commitment grows by at least (the runtime's heap grows in
/// 16-page steps); less than this is taken by one-page grants.
const COMMIT_MIN_PAGES: u64 = 16;
/// Bytes of the ballast: the size of the heap's floor, an uncommitted demand
/// region whose untouched pages memmgr backs only while it has pages to
/// spare, so every block a fill commits after lies above it.
const BALLAST_BYTES: usize = 2 << 20;

/// Why [`Fill::to_critical`] did not reach `CRITICAL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed
{
    /// memmgr did not answer `QUERY_POOL_STATUS`, or refused it.
    Status,
    /// The level did not read `CRITICAL`, with nothing left to take, for
    /// [`SETTLE_MS`] within [`TIMEOUT_MS`].
    NotCritical,
}

/// What a fill holds: its ballast, the blocks it committed through the heap,
/// and the count of pages it took by commitments and grants.
pub struct Fill
{
    _ballast: Vec<u8>,
    blocks: Vec<Vec<u8>>,
    pages: u64,
}

impl Fill
{
    /// The ballast allocated and the block list's room made, so a fill
    /// allocates only the blocks it commits; `None` when either fails.
    #[must_use]
    pub fn new() -> Option<Self>
    {
        let mut ballast: Vec<u8> = Vec::new();
        ballast.try_reserve_exact(BALLAST_BYTES).ok()?;
        ballast.resize(BALLAST_BYTES, 1);
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(MAX_BLOCKS).ok()?;
        Some(Self {
            _ballast: ballast,
            blocks,
            pages: 0,
        })
    }

    /// The pages taken by commitments and grants.
    #[must_use]
    pub const fn pages(&self) -> u64
    {
        self.pages
    }

    /// Take what memmgr can still promise, every [`TICK_MS`], until nothing
    /// is left and the level has read `CRITICAL` for [`SETTLE_MS`]. What was
    /// taken is kept when it fails.
    ///
    /// # Errors
    /// [`Failed::Status`] when memmgr does not answer its pool status;
    /// [`Failed::NotCritical`] when the level does not settle at `CRITICAL`
    /// within [`TIMEOUT_MS`].
    pub fn to_critical(&mut self) -> Result<(), Failed>
    {
        let start = Instant::now();
        let mut critical_since: Option<Instant> = None;
        loop
        {
            self.top_up();
            let full = available().ok_or(Failed::Status)? == 0
                && std::os::seraph::memory_pressure()
                    == Some(std::os::seraph::MemoryPressure::Critical);
            match (full, critical_since)
            {
                (true, Some(since)) if since.elapsed() >= Duration::from_millis(SETTLE_MS) =>
                {
                    return Ok(());
                }
                (true, None) => critical_since = Some(Instant::now()),
                (false, _) => critical_since = None,
                (true, Some(_)) =>
                {}
            }
            if start.elapsed() > Duration::from_millis(TIMEOUT_MS)
            {
                return Err(Failed::NotCritical);
            }
            std::thread::sleep(Duration::from_millis(TICK_MS));
        }
    }

    /// Take what memmgr can still promise: commit it through the heap,
    /// halving an attempt memmgr refuses, while [`COMMIT_MIN_PAGES`] or more
    /// are left and the block list has room, then take what is left a page at
    /// a time by grants. Returns when nothing is left, a grant is refused, or
    /// memmgr does not answer.
    pub fn top_up(&mut self)
    {
        let mut ask = u64::MAX;
        for _ in 0..TOP_UP_ROUNDS
        {
            let Some(left) = available().filter(|&left| left != 0)
            else
            {
                return;
            };
            ask = ask.min(left);
            if ask >= COMMIT_MIN_PAGES && self.blocks.len() < self.blocks.capacity()
            {
                let bytes = usize::try_from(ask.saturating_mul(PAGE_SIZE)).unwrap_or(usize::MAX);
                let mut block: Vec<u8> = Vec::new();
                if block.try_reserve_exact(bytes).is_ok()
                {
                    self.blocks.push(block);
                    self.pages = self.pages.saturating_add(ask);
                }
                else
                {
                    ask /= 2;
                }
            }
            else if grant_one()
            {
                self.pages = self.pages.saturating_add(1);
            }
            else
            {
                return;
            }
        }
    }
}

/// What memmgr can still promise a process outside the reserve, in pages: its
/// free pages less `promised` and the growth floor (`QUERY_POOL_STATUS`'s
/// `data[3]`, `data[8]` and `data[11]`); `None` when memmgr does not answer or
/// refuses. Allocates nothing.
fn available() -> Option<u64>
{
    let req = IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &req,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .ok()?;
    (reply.label == memmgr_errors::SUCCESS).then(|| {
        (reply.word(3) / PAGE_SIZE)
            .saturating_sub(reply.word(8) / PAGE_SIZE)
            .saturating_sub(reply.word(11) / PAGE_SIZE)
    })
}

/// Take one page by a `REQUEST_MEMORY_CAPS` grant, keeping its cap; `false`
/// when memmgr refuses it.
fn grant_one() -> bool
{
    let grant = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &grant,
            std::os::seraph::current_ipc_buf(),
        )
    };
    reply.is_ok_and(|r| r.label == memmgr_errors::SUCCESS)
}
