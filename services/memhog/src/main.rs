// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memhog/src/main.rs

//! The memory hog test fixture: a supervised service that, on request, takes
//! what memmgr can still promise a process outside the system reserve until
//! the pressure level reads `CRITICAL`, and holds it until it is stopped
//! (services/memhog/README.md).
//!
//! memhog serves `ipc::memhog_labels` on the endpoint of the name its recipe
//! provides, which svcmgr delivers in bootstrap slot 0. Its recipe sets
//! `oom_stop = yes` and no reserve, so it is the service the out-of-memory
//! policy service stops: svctest's `oom` phase has it hog, and reads that it
//! was stopped and restarted idle.

use std::time::{Duration, Instant};

use ipc::{IpcMessage, memhog_labels as hog, memmgr_errors, memmgr_labels};
use syscall_abi::{PAGE_SIZE, SyscallError};

/// Blocks the fixture commits at most: each failure halves the next attempt,
/// and each success commits at least half of what is left.
const MAX_BLOCKS: usize = 256;
/// Attempts of one top-up.
const TOP_UP_ROUNDS: usize = 64;
/// Pages a heap commitment grows by at least (the runtime's heap grows in
/// 16-page steps); less than this is taken by one-page grants.
const COMMIT_MIN_PAGES: u64 = 16;
/// Bytes of the fixture's ballast: the size of the heap's floor, an
/// uncommitted demand region whose untouched pages memmgr backs only while it
/// has pages to spare, so every block the fixture commits after lies above it.
const BALLAST_BYTES: usize = 2 << 20;
/// Bytes of stack the fixture touches at start, below its loop's frame.
const STACK_TOUCH_BYTES: usize = 16 * 1024;

fn main() -> !
{
    std::os::seraph::log::register_name(b"memhog");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let service = unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) }
        .map_or(0, |[cap]| cap);
    let nonce = syscall::random_u64().unwrap_or(0);
    if service == 0 || nonce == 0
    {
        std::os::seraph::log!(error: "no service endpoint or nonce");
        syscall::thread_exit();
    }
    let Some(mut hold) = Hold::new()
    else
    {
        std::os::seraph::log!(error: "ballast not allocated");
        syscall::thread_exit();
    };
    touch_stack();
    std::os::seraph::log!("serving");
    serve(service, nonce, &mut hold, ipc_buf)
}

/// Serve [`hog`]'s labels on `service`, and once hogging, take back what
/// other processes free every [`hog::TICK_MS`] between requests.
fn serve(service: u64, nonce: u64, hold: &mut Hold, ipc_buf: *mut u64) -> !
{
    loop
    {
        // 0 waits without bound.
        let timeout = if hold.hogging { hog::TICK_MS } else { 0 };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv_timeout(service, ipc_buf, timeout) }
        {
            Ok(msg) => msg,
            Err(e) if e == SyscallError::WouldBlock as i64 =>
            {
                hold.top_up();
                continue;
            }
            Err(_) => continue,
        };
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        let reply = match msg.label
        {
            hog::PROBE => IpcMessage::builder(hog::SUCCESS)
                .word(0, nonce)
                .word(1, hold.pages)
                .build(),
            hog::HOG =>
            {
                if hold.fill()
                {
                    std::os::seraph::log!("holding {} pages: memory critical", hold.pages);
                    IpcMessage::builder(hog::SUCCESS)
                        .word(0, hold.pages)
                        .build()
                }
                else
                {
                    std::os::seraph::log!(
                        warn: "memory not critical within {} ms, {} pages held",
                        hog::FILL_TIMEOUT_MS,
                        hold.pages
                    );
                    IpcMessage::new(hog::NOT_CRITICAL)
                }
            }
            _ => IpcMessage::new(hog::UNKNOWN_OPCODE),
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// What the fixture holds: its ballast, the blocks it committed through the
/// heap, and the count of pages it took by commitments and grants. The
/// grants' caps stay in the fixture's `CSpace` until it dies.
struct Hold
{
    _ballast: Vec<u8>,
    blocks: Vec<Vec<u8>>,
    pages: u64,
    /// Whether a [`hog::HOG`] was received.
    hogging: bool,
}

impl Hold
{
    /// The ballast allocated and the block list's room made, so a fill
    /// allocates only the blocks it commits; `None` when either fails.
    fn new() -> Option<Self>
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
            hogging: false,
        })
    }

    /// Take what memmgr can still promise until nothing is left and the
    /// level has read `CRITICAL` for [`hog::SETTLE_MS`]: `false` when that
    /// does not happen within [`hog::FILL_TIMEOUT_MS`].
    fn fill(&mut self) -> bool
    {
        self.hogging = true;
        let settle = Duration::from_millis(hog::SETTLE_MS);
        let start = Instant::now();
        let mut critical_since: Option<Instant> = None;
        loop
        {
            self.top_up();
            let full = available() == Some(0)
                && std::os::seraph::memory_pressure()
                    == Some(std::os::seraph::MemoryPressure::Critical);
            match (full, critical_since)
            {
                (true, Some(since)) if since.elapsed() >= settle => return true,
                (true, None) => critical_since = Some(Instant::now()),
                (false, _) => critical_since = None,
                (true, Some(_)) =>
                {}
            }
            if start.elapsed() > Duration::from_millis(hog::FILL_TIMEOUT_MS)
            {
                return false;
            }
            let _ = syscall::thread_sleep(hog::TICK_MS);
        }
    }

    /// Take what memmgr can still promise: commit it through the heap,
    /// halving an attempt memmgr refuses, while [`COMMIT_MIN_PAGES`] or more
    /// are left and the block list has room, then take what is left a page at
    /// a time by grants.
    fn top_up(&mut self)
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

/// What memmgr can still promise a process outside the reserve, in pages:
/// its free pages less `promised` and the reserve (`QUERY_POOL_STATUS`'s
/// `data[3]`, `data[8]` and `data[6]`); `None` when memmgr does not
/// answer. Allocates nothing.
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
            .saturating_sub(reply.word(6) / PAGE_SIZE)
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

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame, so the fixture
/// faults no new stack page while memory is critical.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the touch: its array is the stack the fixture uses, written once at start"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}
