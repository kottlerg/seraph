// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/swap.rs

//! memmgr's eviction of cold demand-region chunks into its compressed store
//! and their restore (services/memmgr/docs/memory-pool.md), end to end.
//!
//! A `swap-fixture` child of `/tests/svctest` registers an uncommitted demand
//! region of twice memmgr's system reserve, and at least 8 MiB, which it
//! fills with a word of each page's offset, repeated over the page, except for
//! one chunk it never touches, so no fault backs its pages (one of them the
//! hole), and a 256 KiB region registered `REGION_NO_EVICT`, which it fills
//! the same way. Three threads of its own each keep a 64 KiB array on their
//! stack live and call memmgr's `QUERY_MEMORY_USAGE` until told to verify.
//! The phase finds the child with `LIST_PROCESSES`, attaches to it for a
//! thread cap, and reads chunks of its regions with `SYS_THREAD_READ_MEM`,
//! which does not ask the pager and fails with `InvalidAddress` on a page that
//! is not present.
//!
//! The phase then takes grants from memmgr until the pressure level reads
//! `LOW` and keeps it there, taking more whenever the level falls to
//! `NORMAL` and giving a block back at `CRITICAL`, until memmgr holds a quarter
//! more of the child's main region swapped than the reserve. It requires:
//!
//! * a page of the main region that reads `InvalidAddress` reads its pattern
//!   after procmgr's `MAKE_RESIDENT` of its chunk, and the hole stays not
//!   present across the same request on its chunk;
//! * with the phase's grants taking every page memmgr grants, at `CRITICAL`,
//!   growth stops with at least a chunk free above the reserve: the restore
//!   headroom memmgr keeps while pages are swapped;
//! * chunks of the main region restored by `MAKE_RESIDENT` from that headroom
//!   read their pattern, and once the free pages fall short of the reserve and
//!   a chunk, where they admit no restore, another chunk reads its pattern
//!   after `MAKE_RESIDENT` of it: memmgr's direct reclaim made the room;
//! * the no-evict region reads whole, and every page of logd's stack that
//!   read before the hog reads while the hog holds the level (logd's budget
//!   node is in the system reserve);
//! * the child reads every page of both regions, and its threads read their
//!   arrays, while the hog still holds the level;
//! * a snapshot (procmgr's `SNAPSHOT`) taken while chunks of the main region are
//!   evicted is complete and holds every page's pattern but the hole chunk's.
//!   procmgr seals a capture from at most 63 grants, which memmgr serves from
//!   its largest free runs (docs/limits.md), and the runs the hog holds after
//!   eviction and restores can be too small for that, so the phase takes a room
//!   of the region's pages and the capture's other pages before the hog, while
//!   memmgr still serves it from its largest runs, and gives it back right
//!   before the snapshot.
//!
//! After the hog's grants are released and the child has exited, the phase
//! makes every process resident, and requires the store and the swapped total
//! to be empty, the all-RAM-accounted identity to hold, and memmgr's free and
//! deferred pages, with those charged to svctest itself, to total at least
//! what they did at the start: the pages the hog's `CSpace` top-ups take stay
//! svctest's.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::os::seraph::{current_ipc_buf, register_demand_paged, reserve_pages, startup_info};
use std::process::{Child, ChildStdin, Command, Stdio, exit};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ipc::procmgr_snapshot::SNAPSHOT_COMPLETE;
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use syscall_abi::{PAGE_SIZE, SyscallError};

use crate::arch::current::REGS_SIZE;
use crate::bootstrap::Caps;
use crate::phases::snapshot::{Attached, account, snapshot};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_swap",
        run: swap_phase,
    }]
}

/// Child-mode dispatch for the argv tokens this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == FIXTURE_ROLE
    {
        fixture_main();
    }
}

/// The phase's name in its failure messages.
const PHASE: &str = "memmgr_swap";
/// argv[1] of the fixture child that holds the regions and the threads.
const FIXTURE_ROLE: &str = "swap-fixture";
/// The process name `LIST_PROCESSES` lists logd under.
const LOGD_NAME: &[u8] = b"logd";

/// Bytes of a page, as an array length.
const PAGE_LEN: usize = 4096;
const _: () = assert!(PAGE_LEN as u64 == PAGE_SIZE);
/// Words of one page.
const PAGE_WORDS: u64 = PAGE_SIZE / 8;
/// Pages of one memmgr demand chunk, the unit of eviction.
pub(super) const CHUNK_PAGES: u64 = memmgr_labels::DEMAND_CHUNK_BYTES / PAGE_SIZE;
/// Bytes of one chunk.
pub(super) const CHUNK_LEN: u64 = memmgr_labels::DEMAND_CHUNK_BYTES;
/// Pages of the fixture's main region at the least: 8 MiB.
const MAIN_PAGES_MIN: u64 = 2048;
/// The chunk of the main region the fixture never touches: a demand fault
/// backs the unbacked pages of the faulting page's whole chunk, so a page no
/// fault backs lies in a chunk no page of which is touched.
const HOLE_CHUNK: u64 = 1;
/// Index of the page of the main region the phase checks no request backs:
/// the last page of [`HOLE_CHUNK`].
const HOLE_PAGE: u64 = (HOLE_CHUNK + 1) * CHUNK_PAGES - 1;
/// Pages of the fixture's no-evict region: 256 KiB.
const NOEVICT_PAGES: u64 = 64;
/// What each word of the main region is xored with: the word's byte offset
/// in the region gives the word.
pub(super) const MAIN_XOR: u64 = 0x5eed_5eed_0000_0001;
/// What each word of the no-evict region is xored with.
const NOEVICT_XOR: u64 = 0x7a11_0ff0_1234_5678;
/// What a thread's array words are xored with, multiplied by the thread's
/// number plus one.
const THREAD_XOR: u64 = 0x7ead_0000_0000_0003;

/// Threads the fixture starts.
const FIXTURE_THREADS: u32 = 3;
/// Bytes of each fixture thread's stack: 256 KiB.
const THREAD_STACK_BYTES: usize = 256 * 1024;
/// Words of each fixture thread's array: 64 KiB.
const THREAD_ARRAY_WORDS: usize = 8192;
/// How long a fixture thread sleeps between its calls to memmgr.
const THREAD_SLEEP: Duration = Duration::from_millis(20);
/// How long the fixture waits for its threads to fill their arrays. A test
/// wait bound.
const THREADS_READY_BOUND: Duration = Duration::from_secs(30);

/// Exit code of the fixture: the main region's registration failed.
const FIXTURE_REGION_FAILED: i32 = 10;
/// Exit code of the fixture: the no-evict region's reservation or
/// registration failed.
const FIXTURE_NOEVICT_FAILED: i32 = 11;
/// Exit code of the fixture: a thread did not start.
const FIXTURE_THREAD_FAILED: i32 = 12;
/// Exit code of the fixture: its threads did not fill their arrays within
/// [`THREADS_READY_BOUND`].
const FIXTURE_THREADS_NOT_READY: i32 = 13;
/// Exit code of the fixture: argv[2], the main region's pages, is missing, or
/// is not a whole number of chunks past the hole's.
const FIXTURE_BAD_ARGUMENT: i32 = 14;

/// Set by the fixture's main thread when its threads are to verify their
/// arrays and end.
static VERIFY: AtomicBool = AtomicBool::new(false);
/// Fixture threads that have filled their arrays.
static THREADS_READY: AtomicU32 = AtomicU32::new(0);
/// Fixture threads that found their array changed.
static THREADS_BAD: AtomicU32 = AtomicU32::new(0);

/// Pages memmgr is asked for at most in one grant of the hog.
const HOG_BLOCK_PAGES: u64 = 256;
/// Grants the hog's list has room for, made before the phase's baseline so
/// the list never grows while the hog holds memory.
const HOG_MAX_GRANTS: usize = 32_768;
/// The general slots of svctest's `CSpace` the hog holds free before each
/// grant ([`HOG_HEADROOM`]): a grant's reply carries a cap for each run, up
/// to `MSG_CAP_SLOTS_MAX`, and a pool cut into small runs by eviction makes
/// the hog hold a cap for every few pages.
const HOG_CSPACE_LOW_WATER: u64 = 64;
/// The slots each top-up of [`HOG_HEADROOM`] funds.
const HOG_CSPACE_TOPUP_SLOTS: u64 = 1024;
/// The hold of svctest's `CSpace` above [`HOG_CSPACE_LOW_WATER`] general
/// slots (runtime/ruststd/README.md § `CSpace` slot headroom): the hog's caps
/// outgrow the slots procmgr seeded. Its top-ups stay with the `CSpace`, so
/// the pages they take are svctest's own when the phase ends ([`phase_totals`]).
static HOG_HEADROOM: std::os::seraph::CSpaceHeadroom =
    std::os::seraph::CSpaceHeadroom::new(HOG_CSPACE_LOW_WATER, HOG_CSPACE_TOPUP_SLOTS);
/// Caps one grant's reply carries at most: one message's worth, the size of
/// the IPC receive reserve.
const GRANT_CAPS_MAX: u64 = syscall_abi::CSPACE_IPC_RECV_RESERVE;
/// The label [`Hog::take`] records as its refusal when the hold of svctest's
/// `CSpace` was refused and its general headroom, the refusal's first word,
/// cannot hold a grant's caps: a grant then would take the receive reserve the
/// next top-up's reply needs. memmgr replies no such label.
const HOLD_REFUSED: u64 = u64::MAX - 1;
/// Pages the snapshot's room ([`take_room`]) holds beyond the fixture's main
/// region: the capture's other pages (the fixture's heap, stacks and no-evict
/// region) and the snapshot object's layout.
const ROOM_EXTRA_PAGES: u64 = 1024;
/// Grants the snapshot's room may take at most: one seal names at most
/// `SEAL_OBJECT_MAX_GRANTS`, the layout's grant among them.
const ROOM_GRANTS_MAX: u64 = memmgr_labels::SEAL_OBJECT_MAX_GRANTS - 1;
/// Grants the room's list has room for: [`ROOM_GRANTS_MAX`] and the caps of
/// one more reply, so that [`take_room`] records every grant of the reply
/// that takes the room past its bound before it fails the phase.
const ROOM_LIST_GRANTS: u64 = ROOM_GRANTS_MAX + GRANT_CAPS_MAX;
/// Grant region ids one `RELEASE_MEMORY_CAPS` of the hog's release names.
const RELEASE_BATCH: usize = 32;
/// How often the hog looks at the level once it holds it.
pub(super) const HOG_TICK: Duration = Duration::from_millis(10);
/// How long the hog takes to bring the level to `LOW`. A test wait bound.
const FILL_BOUND: Duration = Duration::from_secs(120);
/// How long the phase waits, with the hog holding the level, for memmgr to
/// swap more of the fixture's pages than the reserve. A test wait bound.
const SWAP_BOUND: Duration = Duration::from_secs(90);
/// How often the phase asks the fixture how many of its pages are swapped.
const SWAP_POLL: Duration = Duration::from_millis(50);
/// How long the phase waits for a line of the fixture. A test wait bound.
const LINE_BOUND: Duration = Duration::from_secs(120);
/// How long the phase waits for the fixture to exit. A test wait bound.
const EXIT_BOUND: Duration = Duration::from_secs(30);
/// How long the phase waits, after it made everything resident, for memmgr's
/// store to empty and its totals to return to their baseline. A test wait
/// bound.
const SETTLE_BOUND: Duration = Duration::from_secs(30);
/// How often the final wait looks again.
const SETTLE_POLL: Duration = Duration::from_millis(50);
/// Times the phase asks for a chunk to be made resident and reads its page
/// again: memmgr may evict the chunk anew between the request and the read,
/// its worker with the level held at `LOW`, or another restore's direct
/// reclaim at `CRITICAL`.
const RESIDENT_TRIES: u32 = 8;
/// How long [`make_resident`] asks again after replies pending at chunks on
/// disk before it fails the phase: swapd's restore of a chunk takes a slot's
/// read and memmgr's open, a few milliseconds. A test wait bound.
const PENDING_BOUND: Duration = Duration::from_secs(10);
/// Time the phase holds the level at `CRITICAL` before the restores there and
/// before the one direct reclaim pays for, so memmgr's clock runs a few slices
/// (one each 10 ms) and ages the chunks it may take.
const CRITICAL_SETTLE: Duration = Duration::from_millis(100);
/// Pages of logd's stack, from the one the stack pointer lies in down, whose
/// readability the phase records: 256 KiB.
const LOGD_STACK_PAGES: u64 = 64;

/// `SYS_THREAD_READ_MEM`'s error for a page that is not present.
const INVALID_ADDRESS: i64 = SyscallError::InvalidAddress as i64;

/// What the phase reads of memmgr's `QUERY_POOL_STATUS`, in bytes.
pub(super) struct Pool
{
    /// `data[0]`: installed RAM.
    pub(super) system_ram: u64,
    /// `data[1]`: the kernel's reserve.
    pub(super) kernel_reserved: u64,
    /// `data[2]`: every page memmgr owns.
    pub(super) total: u64,
    /// `data[3]`: free pages.
    pub(super) free: u64,
    /// `data[4]`: deferred pages.
    pub(super) deferred: u64,
    /// `data[6]`: the system reserve.
    pub(super) reserve: u64,
    /// `data[7]`: the pressure level.
    pub(super) level: u64,
    /// `data[8]`: promised pages.
    pub(super) promised: u64,
    /// `data[9]`: pages the compressed store holds.
    pub(super) store: u64,
    /// `data[10]`: pages of evicted chunks.
    pub(super) swapped: u64,
    /// `data[11]`: the growth floor.
    pub(super) floor: u64,
    /// `data[12]`: pages of chunks on disk.
    pub(super) on_disk: u64,
    /// `data[13]`: the swap slots free.
    pub(super) free_slots: u64,
    /// `data[14]`: the evictions memmgr has begun, a count.
    pub(super) evictions: u64,
    /// `data[15]`: the overcommit allowance.
    pub(super) allowance: u64,
    /// `data[17]`: the free pages outside `promised`.
    uncommitted: u64,
    /// `data[18]`: pages of evicted chunks of committed regions.
    committed_swapped: u64,
}

impl Pool
{
    /// Whether the all-RAM-accounted identity holds.
    fn identity(&self) -> bool
    {
        self.system_ram == self.kernel_reserved.saturating_add(self.total)
    }

    /// The pages free outside what the committed regions can still take, the
    /// quantity the pressure level reads.
    fn available_pages(&self) -> u64
    {
        self.uncommitted / PAGE_SIZE
    }

    /// The pages `available_pages` falls below at `LOW`: a sixteenth of the pool.
    fn low_pages(&self) -> u64
    {
        self.total / 16 / PAGE_SIZE
    }

    /// The system reserve's pages, which only a reserve node's charge takes.
    pub(super) fn reserve_pages(&self) -> u64
    {
        self.reserve / PAGE_SIZE
    }

    /// Whether a swap service has registered swap slots
    /// (`free_pool::Ledger::overcommits`): a slot is free or holds a chunk on
    /// disk. A slot whose chunk's write is in flight counts in neither, so
    /// every slot writing at once would read as none; the phase's chunks take
    /// a small share of any swap partition.
    fn overcommits(&self) -> bool
    {
        self.free_slots != 0 || self.on_disk != 0
    }

    /// The pages an uncommitted chunk's restore is admitted against
    /// (`free_pool::Ledger::restore_fits`; services/memmgr/docs/memory-pool.md
    /// § Eviction, States): the free frames while swap slots are registered,
    /// since the pages free outside `promised` can then stand below the
    /// growth floor while the allowance bounds them and a restore leaves them
    /// as they were, and those pages otherwise.
    fn restore_pages(&self) -> u64
    {
        if self.overcommits()
        {
            self.free / PAGE_SIZE
        }
        else
        {
            self.available_pages()
        }
    }

    /// The restore headroom the growth floor holds above the reserve: the
    /// pages of evicted chunks of uncommitted regions, up to the reserve
    /// (services/memmgr/docs/memory-pool.md § Eviction, Restore headroom). A
    /// committed chunk's restore draws from `promised`, so its pages take
    /// none.
    fn headroom_pages(&self) -> u64
    {
        (self.swapped.saturating_sub(self.committed_swapped) / PAGE_SIZE).min(self.reserve_pages())
    }

    /// Whether the pages a restore is admitted against fall short of the
    /// reserve and a chunk ([`Self::restore_pages`]), so no restore of a whole
    /// chunk is admitted without direct reclaim.
    fn short_of_a_chunk(&self) -> bool
    {
        self.restore_pages() < self.reserve_pages().saturating_add(CHUNK_PAGES)
    }
}

/// memmgr's reply to `msg`, panicking with `what` when the call fails.
pub(super) fn memmgr_call(msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{PHASE}: {what}: ipc_call failed ({e})"))
}

/// memmgr's pool status, from one `QUERY_POOL_STATUS`.
pub(super) fn pool() -> Pool
{
    let reply = memmgr_call(
        &IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS),
        "QUERY_POOL_STATUS",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "{PHASE}: QUERY_POOL_STATUS replied {:#x}",
        reply.label
    );
    Pool {
        system_ram: reply.word(0),
        kernel_reserved: reply.word(1),
        total: reply.word(2),
        free: reply.word(3),
        deferred: reply.word(4),
        reserve: reply.word(6),
        level: reply.word(7),
        promised: reply.word(8),
        store: reply.word(9),
        swapped: reply.word(10),
        floor: reply.word(11),
        on_disk: reply.word(12),
        free_slots: reply.word(13),
        evictions: reply.word(14),
        allowance: reply.word(15),
        uncommitted: reply.word(17),
        committed_swapped: reply.word(18),
    }
}

/// The pages charged to the caller's own node and the pages of them memmgr
/// holds swapped (`QUERY_MEMORY_USAGE` `data[0]` and `data[4]`); `None` when
/// the call fails or is refused.
fn own_usage() -> Option<(u64, u64)>
{
    let req = IpcMessage::new(memmgr_labels::QUERY_MEMORY_USAGE);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply =
        unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, &req, current_ipc_buf()) }.ok()?;
    (reply.label == memmgr_errors::SUCCESS).then(|| (reply.word(0), reply.word(4)))
}

/// The pages of the fixture's main region of `main_pages` pages that memmgr
/// holds swapped, at least: the node's swapped pages less every charged page
/// outside the region's backed ones (all but the hole's chunk), which its
/// stacks, heap and no-evict region hold. 0 when the call fails.
fn main_swapped_pages(main_pages: u64) -> u64
{
    let Some((charged, swapped)) = own_usage()
    else
    {
        return 0;
    };
    let backed = main_pages.saturating_sub(CHUNK_PAGES);
    swapped.saturating_sub(charged.saturating_sub(backed))
}

/// The address of page `index` of the region at `base`.
fn page_va(base: u64, index: u64) -> u64
{
    base.saturating_add(index.saturating_mul(PAGE_SIZE))
}

// ── The hog ──────────────────────────────────────────────────────────────────

/// The highest values of memmgr's store, its swapped total and the hog's own
/// size the phase has seen, in pages.
#[derive(Default)]
struct Peaks
{
    store: u64,
    swapped: u64,
    hogged: u64,
}

/// The grants the phase holds to keep memmgr's pressure level at `LOW`.
pub(super) struct Hog
{
    /// Each grant's cap, region id and pages.
    grants: Vec<(u64, u64, u64)>,
    /// Pages held.
    pages: u64,
    peaks: Peaks,
    /// The label and first three words of memmgr's last refusal of a grant,
    /// or [`HOLD_REFUSED`] and svctest's general headroom.
    refusal: (u64, [u64; 3]),
}

impl Hog
{
    /// An empty hog whose list has room for [`HOG_MAX_GRANTS`] grants.
    pub(super) fn new() -> Self
    {
        Self::with_capacity(HOG_MAX_GRANTS)
    }

    /// An empty hog whose list has room for `capacity` grants.
    fn with_capacity(capacity: usize) -> Self
    {
        let mut grants = Vec::new();
        grants
            .try_reserve_exact(capacity)
            .unwrap_or_else(|e| panic!("{PHASE}: the hog's list of {capacity}: {e}"));
        Self {
            grants,
            pages: 0,
            peaks: Peaks::default(),
            refusal: (0, [0; 3]),
        }
    }

    /// Take a grant of `pages` pages, holding svctest's `CSpace` headroom
    /// first ([`HOG_HEADROOM`]); whether memmgr granted it. A refused hold
    /// refuses the grant while the general headroom cannot hold its caps.
    fn take(&mut self, pages: u64) -> bool
    {
        let cspace = startup_info().self_cspace;
        if !HOG_HEADROOM.hold(cspace)
        {
            let headroom = std::os::seraph::cspace_slot_headroom(cspace);
            if headroom < GRANT_CAPS_MAX
            {
                self.refusal = (HOLD_REFUSED, [headroom, 0, 0]);
                return false;
            }
        }
        let req = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
            .word(0, pages)
            .build();
        let reply = memmgr_call(&req, "REQUEST_MEMORY_CAPS");
        assert_ne!(
            reply.label,
            syscall_abi::IPC_REPLY_TRANSFER_FAILED,
            "{PHASE}: a grant's reply could not be received: svctest's CSpace has no slot for \
             its caps, at a general headroom of {}, with {} caps held",
            std::os::seraph::cspace_slot_headroom(cspace),
            self.grants.len()
        );
        if reply.label != memmgr_errors::SUCCESS
        {
            self.refusal = (reply.label, [reply.word(0), reply.word(1), reply.word(2)]);
            return false;
        }
        let (counts, ids) = ipc::memmgr_grant_layout(&reply)
            .unwrap_or_else(|| panic!("{PHASE}: a REQUEST_MEMORY_CAPS reply of no grant layout"));
        assert!(
            self.grants.len().saturating_add(reply.caps().len()) <= self.grants.capacity(),
            "{PHASE}: the hog's list of {} grants is full",
            self.grants.capacity()
        );
        for ((&cap, &count), &id) in reply.caps().iter().zip(counts).zip(ids)
        {
            self.grants.push((cap, id, count));
            self.pages = self.pages.saturating_add(count);
        }
        true
    }

    /// Return the last grant to memmgr: delete its cap, then release its
    /// region.
    fn release_one(&mut self)
    {
        let Some((cap, id, count)) = self.grants.pop()
        else
        {
            return;
        };
        syscall::cap_delete(cap)
            .unwrap_or_else(|e| panic!("{PHASE}: deleting a hog grant's cap failed ({e})"));
        let req = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS)
            .word(0, 1)
            .word(1, id)
            .build();
        let reply = memmgr_call(&req, "RELEASE_MEMORY_CAPS");
        assert_eq!(
            reply.label,
            memmgr_errors::SUCCESS,
            "{PHASE}: RELEASE_MEMORY_CAPS of a hog grant replied {:#x}",
            reply.label
        );
        self.pages = self.pages.saturating_sub(count);
    }

    /// Return every grant: delete the caps, then release the regions in
    /// batches of [`RELEASE_BATCH`].
    pub(super) fn release_all(&mut self)
    {
        for &(cap, _, _) in &self.grants
        {
            syscall::cap_delete(cap)
                .unwrap_or_else(|e| panic!("{PHASE}: deleting a hog grant's cap failed ({e})"));
        }
        // The pool can stand at the floor until the grants are returned, so
        // the batch is built on the stack: a heap allocation could fault a
        // new page memmgr declines there.
        let mut words = [0u64; RELEASE_BATCH + 1];
        for batch in self.grants.chunks(RELEASE_BATCH)
        {
            let fields = core::iter::once(u64::try_from(batch.len()).unwrap_or(0))
                .chain(batch.iter().map(|&(_, id, _)| id));
            for (w, v) in words.iter_mut().zip(fields)
            {
                *w = v;
            }
            let used = words.get(..=batch.len()).unwrap_or(&words);
            let req = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS)
                .words(0, used)
                .build();
            let reply = memmgr_call(&req, "RELEASE_MEMORY_CAPS");
            assert_eq!(
                reply.label,
                memmgr_errors::SUCCESS,
                "{PHASE}: RELEASE_MEMORY_CAPS of the hog's grants replied {:#x}",
                reply.label
            );
        }
        self.grants.clear();
        self.pages = 0;
    }

    /// Act on `status`: at `NORMAL` take a grant of at most
    /// [`HOG_BLOCK_PAGES`] that leaves the level at `LOW` or just above it, at
    /// `CRITICAL` give one grant back, at `LOW` do nothing. Notes the peaks.
    fn step(&mut self, status: &Pool)
    {
        self.note(status);
        match status.level
        {
            memmgr_labels::PRESSURE_CRITICAL => self.release_one(),
            memmgr_labels::PRESSURE_NORMAL =>
            {
                let need = status
                    .available_pages()
                    .saturating_sub(status.low_pages())
                    .saturating_add(1);
                let _ = self.take(need.min(HOG_BLOCK_PAGES));
            }
            _ =>
            {}
        }
    }

    /// Read the pool and act on it ([`step`]); the status read.
    pub(super) fn tick(&mut self) -> Pool
    {
        let status = pool();
        self.step(&status);
        status
    }

    /// Note the peaks `status` shows.
    fn note(&mut self, status: &Pool)
    {
        self.peaks.store = self.peaks.store.max(status.store / PAGE_SIZE);
        self.peaks.swapped = self.peaks.swapped.max(status.swapped / PAGE_SIZE);
        self.peaks.hogged = self.peaks.hogged.max(self.pages);
    }

    /// Take grants, each of at most [`HOG_BLOCK_PAGES`] and halved on a
    /// refusal, until memmgr refuses one of a page with the level at
    /// `CRITICAL` and no more pages available than the floor: growth outside
    /// the system reserve has then stopped at the floor memmgr keeps, the
    /// reserve and, while pages are swapped, the restore headroom. Pages that
    /// come free between the refusal and the status read, such as a chunk's
    /// runs an eviction in flight returns, are taken too. Returns the status
    /// read then.
    pub(super) fn fill_to_floor(&mut self) -> Pool
    {
        let start = Instant::now();
        let mut want = HOG_BLOCK_PAGES;
        loop
        {
            if self.take(want)
            {
                continue;
            }
            if want > 1
            {
                want /= 2;
                continue;
            }
            let status = pool();
            self.note(&status);
            if status.level == memmgr_labels::PRESSURE_CRITICAL
                && status.available_pages() <= status.floor / PAGE_SIZE
            {
                return status;
            }
            assert!(
                start.elapsed() < FILL_BOUND,
                "{PHASE}: a grant of a page refused with the level at {} (0 normal, 1 low, 2 \
                 critical) after {FILL_BOUND:?} of taking grants: {} pages available against a \
                 reserve of {} and a growth floor of {} pages, {} pages held in {} grants; the \
                 refusal's label {:#x} and words {:?} ({HOLD_REFUSED:#x}: the CSpace top-up)",
                status.level,
                status.available_pages(),
                status.reserve_pages(),
                status.floor / PAGE_SIZE,
                self.pages,
                self.grants.len(),
                self.refusal.0,
                self.refusal.1
            );
            // The level is read again at memmgr's next turn, and pages may
            // have come free meanwhile.
            std::thread::sleep(HOG_TICK);
            want = HOG_BLOCK_PAGES;
        }
    }

    /// Give grants back, one by one, until the level reads `LOW` or
    /// `NORMAL`.
    pub(super) fn release_from_critical(&mut self)
    {
        while pool().level == memmgr_labels::PRESSURE_CRITICAL
        {
            assert!(
                !self.grants.is_empty(),
                "{PHASE}: the level reads CRITICAL with every hog grant returned"
            );
            self.release_one();
        }
    }

    /// Take grants until the level reads `LOW`, without a pause between them.
    pub(super) fn fill_to_low(&mut self)
    {
        let start = Instant::now();
        loop
        {
            let status = self.tick();
            if status.level == memmgr_labels::PRESSURE_LOW
            {
                return;
            }
            assert!(
                start.elapsed() < FILL_BOUND,
                "{PHASE}: the level read {} (0 normal, 1 low, 2 critical) after {FILL_BOUND:?} \
                 of taking grants, {} pages held",
                status.level,
                self.pages
            );
        }
    }
}

// ── The fixture, parent side ─────────────────────────────────────────────────

/// What the fixture's `ready` line reports.
pub(super) struct Ready
{
    pub(super) region: u64,
    /// Chunks of the main region.
    pub(super) chunks: u64,
    pub(super) hole: u64,
    noevict: u64,
}

/// The fixture child and the means to talk to it.
pub(super) struct Fixture
{
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    reader: JoinHandle<()>,
}

impl Fixture
{
    /// Spawn the fixture with a main region of `main_pages` pages filled as
    /// `fill` says, piped stdin and stdout, and a thread that passes each
    /// line it prints on.
    fn spawn(main_pages: u64, fill: Fill) -> Self
    {
        let mut child = Command::new("/tests/svctest")
            .arg(FIXTURE_ROLE)
            .arg(main_pages.to_string())
            .arg(fill.token())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{PHASE}: spawning the fixture failed: {e}"));
        let stdin = child.stdin.take().expect("the fixture's stdin is piped");
        let mut stdout =
            BufReader::new(child.stdout.take().expect("the fixture's stdout is piped"));
        let (send, lines) = mpsc::channel();
        let reader = std::thread::Builder::new()
            .name("swap-reader".into())
            .spawn(move || {
                loop
                {
                    let mut line = String::new();
                    match stdout.read_line(&mut line)
                    {
                        Ok(0) | Err(_) => return,
                        Ok(_) =>
                        {
                            if send.send(line).is_err()
                            {
                                return;
                            }
                        }
                    }
                }
            })
            .unwrap_or_else(|e| panic!("{PHASE}: spawning the fixture's reader failed: {e}"));
        Self {
            child,
            stdin,
            lines,
            reader,
        }
    }

    /// Send the command `cmd`.
    pub(super) fn send(&mut self, cmd: &str)
    {
        self.stdin
            .write_all(format!("{cmd}\n").as_bytes())
            .and_then(|()| self.stdin.flush())
            .unwrap_or_else(|e| panic!("{PHASE}: writing {cmd:?} to the fixture failed: {e}"));
    }

    /// The fixture's next line, within [`LINE_BOUND`]; with a `hog`, it takes
    /// a step every [`HOG_TICK`] while it waits.
    pub(super) fn line(&mut self, mut hog: Option<&mut Hog>, what: &str) -> String
    {
        let start = Instant::now();
        loop
        {
            match self.lines.recv_timeout(HOG_TICK)
            {
                Ok(line) => return line,
                Err(mpsc::RecvTimeoutError::Timeout) =>
                {
                    if let Some(hog) = hog.as_mut()
                    {
                        let _ = hog.tick();
                    }
                    assert!(
                        start.elapsed() < LINE_BOUND,
                        "{PHASE}: no {what} line from the fixture in {LINE_BOUND:?}"
                    );
                }
                Err(mpsc::RecvTimeoutError::Disconnected) =>
                {
                    panic!("{PHASE}: the fixture closed its stdout before its {what} line")
                }
            }
        }
    }

    /// The fixture's next line if one arrives within `wait`, else `None`.
    pub(super) fn try_line(&mut self, wait: Duration) -> Option<String>
    {
        match self.lines.recv_timeout(wait)
        {
            Ok(line) => Some(line),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) =>
            {
                panic!("{PHASE}: the fixture closed its stdout while a line was awaited")
            }
        }
    }

    /// Wait for the fixture's exit and its reader's end, and require status 0.
    fn finish(self)
    {
        let status = self.exit_status();
        assert!(status.success(), "{PHASE}: the fixture exited {status:?}");
    }

    /// Close the fixture's stdin, wait for its exit and its reader's end, and
    /// return its status.
    pub(super) fn exit_status(mut self) -> std::process::ExitStatus
    {
        drop(self.stdin);
        let start = Instant::now();
        let status = loop
        {
            if let Some(status) = self.child.try_wait().expect("try_wait of the fixture")
            {
                break status;
            }
            assert!(
                start.elapsed() < EXIT_BOUND,
                "{PHASE}: the fixture did not exit in {EXIT_BOUND:?}"
            );
            std::thread::sleep(HOG_TICK);
        };
        let _ = self.reader.join();
        status
    }
}

/// Parse the fixture's `ready` line.
fn parse_ready(line: &str) -> Ready
{
    let mut words = line.split_ascii_whitespace();
    assert_eq!(
        words.next(),
        Some("ready"),
        "{PHASE}: the fixture printed {line:?}"
    );
    let mut hex = || {
        words
            .next()
            .and_then(|w| u64::from_str_radix(w, 16).ok())
            .unwrap_or_else(|| panic!("{PHASE}: the fixture's ready line is {line:?}"))
    };
    let region = hex();
    let region_len = hex();
    let hole = hex();
    let noevict = hex();
    let _noevict_len = hex();
    Ready {
        region,
        chunks: region_len / CHUNK_LEN,
        hole,
        noevict,
    }
}

/// The pages of its main region the fixture reports swapped, at least, from its
/// `swapped <n> <charged> <node swapped>` line.
fn parse_swapped(line: &str) -> u64
{
    line.trim()
        .strip_prefix("swapped ")
        .and_then(|n| n.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("{PHASE}: the fixture answered swapped with {line:?}"))
}

// ── procmgr's debug authority ────────────────────────────────────────────────

/// procmgr's reply to `msg` on the debug-authority cap `authority`.
fn procmgr_call(authority: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(authority, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{PHASE}: {what}: ipc_call failed ({e})"))
}

/// The name `LIST_PROCESSES` lists a child svctest spawns of itself under: the
/// first string of its argv, which `Command` makes the program path.
pub(super) const SVCTEST_CHILD_NAME: &[u8] = b"/tests/svctest";

/// The badge of the child of svctest's own binary spawned since `before`, a
/// [`listed_badges`] taken before the spawn: the one process
/// `LIST_PROCESSES` lists under [`SVCTEST_CHILD_NAME`] that `before` does
/// not hold. Any other process can be spawned meanwhile (the next instance of
/// a service svcmgr restarts once oomd has stopped it, say), so a new entry under
/// another name is not the child's. `what` names the phase in a panic.
pub(super) fn spawned_badge(authority: u64, before: &[u64], what: &str) -> u64
{
    let new: Vec<u64> = super::crash::badges_named(authority, SVCTEST_CHILD_NAME)
        .into_iter()
        .filter(|badge| !before.contains(badge))
        .collect();
    let [badge] = new[..]
    else
    {
        panic!(
            "{what}: LIST_PROCESSES lists {new:#x?} under {:?} as new since the spawn",
            String::from_utf8_lossy(SVCTEST_CHILD_NAME)
        );
    };
    badge
}

/// The badges `LIST_PROCESSES` lists.
pub(super) fn listed_badges(authority: u64) -> Vec<u64>
{
    let badges = RefCell::new(Vec::new());
    let _ = super::crash::find_listed(authority, |badge, _| {
        badges.borrow_mut().push(badge);
        false
    });
    badges.into_inner()
}

/// Attach to the process `process` without a watch: its thread caps, its main
/// thread's first, which the caller deletes through [`detach`].
pub(super) fn attach(authority: u64, process: u64, what: &str) -> Vec<u64>
{
    let attach = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, process)
        .word(1, 0)
        .build();
    let reply = procmgr_call(authority, &attach, "ATTACH_PROCESS");
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{PHASE}: ATTACH_PROCESS of {what} replied {:#x}",
        reply.label
    );
    let threads = reply.caps().to_vec();
    assert!(
        !threads.is_empty(),
        "{PHASE}: the attach to {what} returned no thread"
    );
    threads
}

/// Delete the thread caps `threads` and detach from `process`.
pub(super) fn detach(authority: u64, process: u64, threads: &[u64], what: &str)
{
    for &cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
    let detach = IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
        .word(0, process)
        .build();
    let reply = procmgr_call(authority, &detach, "DETACH_PROCESS");
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{PHASE}: DETACH_PROCESS of {what} replied {:#x}",
        reply.label
    );
}

/// procmgr's label for `MAKE_RESIDENT` of `[va, va + len)` of `process`,
/// asked again from where each success stopped until it reaches the range's
/// end: memmgr makes a bounded part of a range resident per request. A reply
/// pending at a chunk on disk is asked again after `ipc::PENDING_PAUSE_MS`,
/// once swapd has restored the chunk, for at most [`PENDING_BOUND`] in all:
/// swapd restores every chunk on disk a request posts. A success that stops
/// where it started, or a range still pending past the bound, fails the
/// phase.
pub(super) fn make_resident(authority: u64, process: u64, va: u64, len: u64) -> u64
{
    let end = va.saturating_add(len);
    let mut at = va;
    let start = Instant::now();
    loop
    {
        let req = IpcMessage::builder(procmgr_labels::MAKE_RESIDENT)
            .word(0, process)
            .word(1, at)
            .word(2, end.saturating_sub(at))
            .build();
        let reply = procmgr_call(authority, &req, "MAKE_RESIDENT");
        if reply.label == procmgr_errors::SUCCESS
            && reply.word(1) == memmgr_labels::RESIDENT_PENDING
        {
            assert!(
                start.elapsed() < PENDING_BOUND,
                "{PHASE}: MAKE_RESIDENT from {at:#x} to {end:#x} still pending at {:#x} after \
                 {PENDING_BOUND:?}: swapd did not restore the chunk on disk",
                reply.word(0)
            );
            at = reply.word(0);
            std::thread::sleep(Duration::from_millis(ipc::PENDING_PAUSE_MS));
            continue;
        }
        if reply.label != procmgr_errors::SUCCESS || reply.word(0) >= end
        {
            return reply.label;
        }
        assert!(
            reply.word(0) > at,
            "{PHASE}: MAKE_RESIDENT from {at:#x} to {end:#x} stopped at {:#x}",
            reply.word(0)
        );
        at = reply.word(0);
    }
}

/// Whether the page at `va` of the fixture's main region at `base`, read
/// through `thread`, holds its pattern.
pub(super) fn chunk_reads_pattern(thread: u64, va: u64, base: u64) -> bool
{
    read_pattern(thread, va, base, MAIN_XOR) == Ok(true)
}

/// Whether the page at `va` of `thread`'s process holds the pattern of a region
/// at `base` xored with `xor`; the syscall's error when it cannot be read.
fn read_pattern(thread: u64, va: u64, base: u64, xor: u64) -> Result<bool, i64>
{
    let mut page = [0u8; PAGE_LEN];
    syscall::thread_read_mem(thread, va, &mut page)?;
    let want = pattern(va, base, xor);
    Ok((0..PAGE_WORDS).all(|word| {
        let start = usize::try_from(word.saturating_mul(8)).unwrap_or(usize::MAX);
        let got = page
            .get(start..start.saturating_add(8))
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_ne_bytes);
        got == Some(want)
    }))
}

/// Assert the page at `va` reads its pattern.
fn require_pattern(thread: u64, va: u64, base: u64, xor: u64, what: &str)
{
    match read_pattern(thread, va, base, xor)
    {
        Ok(true) =>
        {}
        Ok(false) => panic!("{PHASE}: {what}: the page at {va:#x} reads other than its pattern"),
        Err(code) => panic!("{PHASE}: {what}: reading the page at {va:#x} failed ({code})"),
    }
}

/// Byte offset of the stack pointer in the register file.
fn sp_offset() -> usize
{
    if REGS_SIZE == syscall_abi::REGS_X86_64_SIZE
    {
        syscall_abi::REGS_X86_64_SP_OFFSET
    }
    else
    {
        syscall_abi::REGS_RISCV64_SP_OFFSET
    }
}

/// Whether the page at `va` of `thread`'s process is present.
pub(super) fn page_present(thread: u64, va: u64) -> bool
{
    let mut probe = [0u8; 8];
    syscall::thread_read_mem(thread, va, &mut probe).is_ok()
}

/// The pages of a process's stack the phase read.
pub(super) struct StackPages
{
    process: u64,
    /// The pages that read.
    readable: Vec<u64>,
}

/// Attach to the process named `name`, read its main thread's stack pointer
/// with the thread stopped, restart it, and record which of the
/// [`LOGD_STACK_PAGES`] pages from the stack pointer's down read. Writes no
/// log line while the thread is stopped. `what` names the process in a
/// failure.
pub(super) fn read_stack(authority: u64, name: &[u8], what: &str) -> StackPages
{
    let process = super::crash::badge_named(authority, name)
        .unwrap_or_else(|| panic!("{PHASE}: LIST_PROCESSES lists no {what}"));
    let threads = attach(authority, process, what);
    let main = *threads.first().expect("the attach returned a thread");
    let stopped = syscall::thread_stop(main);
    let mut regs = [0u8; REGS_SIZE];
    let read = syscall::thread_read_regs(main, &mut regs);
    let started = syscall::thread_start(main);
    stopped.unwrap_or_else(|e| panic!("{PHASE}: stopping {what}'s main thread ({e})"));
    read.unwrap_or_else(|e| panic!("{PHASE}: reading {what}'s registers ({e})"));
    started.unwrap_or_else(|e| panic!("{PHASE}: restarting {what}'s main thread ({e})"));
    let sp = regs
        .get(sp_offset()..sp_offset().saturating_add(8))
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_ne_bytes)
        .expect("the stack pointer lies within the register file");
    let top = sp & !PAGE_SIZE.saturating_sub(1);
    let readable = (0..LOGD_STACK_PAGES)
        .map(|k| top.saturating_sub(k.saturating_mul(PAGE_SIZE)))
        .filter(|&va| page_present(main, va))
        .collect();
    detach(authority, process, &threads, what);
    StackPages { process, readable }
}

/// Require every page of `before`, which the process `what` names, to read
/// now.
pub(super) fn require_stack(authority: u64, before: &StackPages, what: &str)
{
    let threads = attach(authority, before.process, what);
    let main = *threads.first().expect("the attach returned a thread");
    let missing: Vec<u64> = before
        .readable
        .iter()
        .copied()
        .filter(|&va| !page_present(main, va))
        .collect();
    detach(authority, before.process, &threads, what);
    assert!(
        missing.is_empty(),
        "{PHASE}: pages of {what}'s stack read before the hog and not under it: {missing:#x?}"
    );
}

/// SNAPSHOT `process`, the fixture, over `authority` and require the object
/// complete and every page of its main region but the hole's chunk to hold its
/// pattern. `phase` names the caller in a failure.
pub(super) fn require_snapshot(authority: u64, process: u64, ready: &Ready, phase: &str)
{
    let reply = snapshot(authority, process, Some(account()), phase);
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{phase}: SNAPSHOT of the fixture replied {:#x}",
        reply.label
    );
    assert_eq!(
        reply.word(1),
        SNAPSHOT_COMPLETE,
        "{phase}: SNAPSHOT of the fixture replied flags {:#x} with label {:#x}",
        reply.word(1),
        reply.label
    );
    let handle = *reply.caps().first().expect("SNAPSHOT replied no handle");
    let object = Attached::attach(handle, reply.word(0), phase);
    let mut first: Option<String> = None;
    let mut failures: u64 = 0;
    for page in 0..ready.chunks.saturating_mul(CHUNK_PAGES)
    {
        if page / CHUNK_PAGES == HOLE_CHUNK
        {
            continue;
        }
        let va = page_va(ready.region, page);
        let what = match object.page(va)
        {
            None => "missing",
            Some(bytes) if bytes_intact(bytes, va, ready.region, MAIN_XOR, Fill::Page) => continue,
            Some(_) => "wrong",
        };
        failures = failures.saturating_add(1);
        if first.is_none()
        {
            first = Some(format!("{va:#x} {what}"));
        }
    }
    object.release();
    assert!(
        failures == 0,
        "{phase}: {failures} pages of the snapshot of the main region fail; the first is {}",
        first.unwrap_or_default()
    );
}

// ── The phase ────────────────────────────────────────────────────────────────

/// The phase (see the module documentation).
fn swap_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "{PHASE}: no debug authority");

    // The hog's list is made before the baseline, so it is not a change of it,
    // and so is the snapshot's room's.
    let mut hog = Hog::new();
    let mut room = Hog::with_capacity(usize::try_from(ROOM_LIST_GRANTS).unwrap_or(usize::MAX));
    // An earlier phase that took the level to `LOW` may have had memmgr evict
    // chunks of any process: make them resident first, so the store starts
    // empty.
    let _ = settle_resident(authority, None);
    let baseline = baseline_totals();
    let reserve = pool().reserve_pages();
    let (mut fixture, ready, process) = start_fixture(authority, main_pages(reserve), Fill::Page);
    let threads = attach(authority, process, "the fixture");
    let thread = *threads.first().expect("the attach returned a thread");
    read_before_hog(thread, &ready);
    let logd = read_stack(authority, LOGD_NAME, "logd");
    let room_pages = ready
        .chunks
        .saturating_mul(CHUNK_PAGES)
        .saturating_add(ROOM_EXTRA_PAGES);
    take_room(&mut room, room_pages);

    hog.fill_to_low();
    // A restore from the headroom of at most the reserve takes nearly a chunk
    // of free pages (`pattern`), so the restores that use it up and the one
    // direct reclaim admits need a little more than the reserve swapped: a
    // quarter more allows for chunks the clock evicts meanwhile.
    await_swapped(&mut hog, &mut fixture, reserve.saturating_add(reserve / 4));
    debugger_restore(authority, process, thread, &ready);
    let from_headroom = critical_restore(&mut hog, authority, process, thread, &ready);
    hog.fill_to_low();
    require_no_evict(thread, &ready);
    require_stack(authority, &logd, "logd");

    // A snapshot taken while chunks of the main region are evicted holds every
    // page's pattern. The room goes back for its frames.
    let mut from = 0;
    let evicted = next_evicted(thread, &ready, &mut from);
    let room_grants = room.grants.len();
    room.release_all();
    // The snapshot's grants take the level back toward `LOW`, so the clock
    // may evict the fixture's chunks while procmgr holds it: memmgr supplies
    // each chunk wherever it is.
    let evictions = pool().evictions;
    require_snapshot(authority, process, &ready, PHASE);
    let during = pool().evictions.saturating_sub(evictions);
    hog.fill_to_low();
    std::os::seraph::log!(
        "{PHASE}: snapshot complete with the chunk at {evicted:#x} of the main region evicted, \
         {during} evictions begun during it, its frames from a room of {room_pages} pages in \
         {room_grants} grants"
    );

    // The fixture reads everything while the hog holds the level.
    fixture.send("verify");
    let verdict = fixture.line(Some(&mut hog), "verify");
    assert_eq!(
        verdict.trim(),
        "ok",
        "{PHASE}: the fixture's verify answered {verdict:?}"
    );
    detach(authority, process, &threads, "the fixture");

    hog.release_all();
    fixture.send("exit");
    fixture.finish();
    let end = settle_resident(authority, Some(baseline));

    let peaks = &hog.peaks;
    std::os::seraph::log!(
        "memmgr_swap phase passed (store peak {} pages, swapped peak {} pages, hogged {} pages, \
         {from_headroom} chunks restored from the headroom at CRITICAL, free, deferred and \
         svctest's own {} pages above the start)",
        peaks.store,
        peaks.swapped,
        peaks.hogged,
        end.saturating_sub(baseline) / PAGE_SIZE
    );
}

/// Check the phase's baseline: the identity holds and the store and the
/// swapped total are empty. The phase's totals ([`phase_totals`]) once
/// memmgr's deferred list has settled.
pub(super) fn baseline_totals() -> u64
{
    let _ = crate::phases::memmgr::settled_deferred_bytes();
    let base = pool();
    assert!(
        base.identity(),
        "{PHASE}: baseline: system_ram {} != kernel_reserved {} + pool_total {}",
        base.system_ram,
        base.kernel_reserved,
        base.total
    );
    assert!(
        base.store == 0 && base.swapped == 0,
        "{PHASE}: baseline: store {} bytes, swapped {} bytes, both expected 0",
        base.store,
        base.swapped
    );
    phase_totals(&base)
}

/// memmgr's free and deferred bytes with the bytes charged to svctest's own
/// node: what the phase's pages total once they are all back. The pages the
/// hog's `CSpace` top-ups take stay with svctest's `CSpace`
/// ([`HOG_HEADROOM`]) and charged to svctest, so they count as back.
fn phase_totals(status: &Pool) -> u64
{
    let (charged, _) = own_usage()
        .unwrap_or_else(|| panic!("{PHASE}: QUERY_MEMORY_USAGE of svctest's own node failed"));
    status
        .free
        .saturating_add(status.deferred)
        .saturating_add(charged.saturating_mul(PAGE_SIZE))
}

/// The pages of the fixture's main region for a system reserve of `reserve`
/// pages: twice the reserve in whole chunks, so more than the reserve of them
/// can be swapped, and at least [`MAIN_PAGES_MIN`].
pub(super) fn main_pages(reserve: u64) -> u64
{
    reserve
        .saturating_mul(2)
        .next_multiple_of(CHUNK_PAGES)
        .max(MAIN_PAGES_MIN)
}

/// Spawn the fixture with a main region of `main_pages` pages filled as
/// `fill` says, wait for its ready line, and find its process badge
/// ([`spawned_badge`]).
pub(super) fn start_fixture(authority: u64, main_pages: u64, fill: Fill) -> (Fixture, Ready, u64)
{
    let before = listed_badges(authority);
    let mut fixture = Fixture::spawn(main_pages, fill);
    let line = fixture.line(None, "ready");
    let ready = parse_ready(&line);
    let process = spawned_badge(authority, &before, PHASE);
    (fixture, ready, process)
}

/// Take the snapshot's room of `pages` pages into `room`, before the hog.
/// memmgr serves a grant from the smallest free run that covers it, or else
/// from its largest runs first (services/memmgr/docs/memory-pool.md
/// § Allocation), and serves the capture's frames the same way once the room
/// is given back. Taken while the pool is still nearly free, the room holds runs the
/// capture can be sealed from; one in more than [`ROOM_GRANTS_MAX`] grants
/// means the pool's largest runs cannot hold a capture of its size, which
/// fails the phase here rather than at the snapshot.
fn take_room(room: &mut Hog, pages: u64)
{
    while room.pages < pages
    {
        assert!(
            room.take(pages.saturating_sub(room.pages)),
            "{PHASE}: the snapshot's room of {pages} pages refused with {} pages held: label \
             {:#x}, words {:?}",
            room.pages,
            room.refusal.0,
            room.refusal.1
        );
        // Checked after each reply, which adds at most `GRANT_CAPS_MAX`
        // grants, so the list's room for one more reply is never passed.
        let grants = u64::try_from(room.grants.len()).unwrap_or(u64::MAX);
        assert!(
            grants <= ROOM_GRANTS_MAX,
            "{PHASE}: the snapshot's room of {pages} pages took {grants} grants with {} pages \
             held, more than the {ROOM_GRANTS_MAX} a capture can be sealed from beside its layout",
            room.pages
        );
    }
}

/// Read, with no pressure on memmgr, the first page of the first, the third,
/// the middle and the last chunk of the main region, and every page of the
/// no-evict region.
fn read_before_hog(thread: u64, ready: &Ready)
{
    let last = ready.chunks.saturating_sub(1);
    for chunk in [0, 2, ready.chunks / 2, last]
    {
        let va = page_va(ready.region, chunk.saturating_mul(CHUNK_PAGES));
        require_pattern(
            thread,
            va,
            ready.region,
            MAIN_XOR,
            "before the hog, main region",
        );
    }
    for page in 0..NOEVICT_PAGES
    {
        let va = page_va(ready.noevict, page);
        require_pattern(
            thread,
            va,
            ready.noevict,
            NOEVICT_XOR,
            "before the hog, no-evict",
        );
    }
}

/// With the hog holding the level, wait until the fixture reports at least
/// `want` pages of its main region swapped and memmgr's store and swapped
/// total are nonzero. Only the main region's chunks are restored at
/// `CRITICAL` ([`critical_restore`]), and they must outnumber the restore
/// headroom.
pub(super) fn await_swapped(hog: &mut Hog, fixture: &mut Fixture, want: u64)
{
    let start = Instant::now();
    loop
    {
        let polled = Instant::now();
        while polled.elapsed() < SWAP_POLL
        {
            let _ = hog.tick();
            std::thread::sleep(HOG_TICK);
        }
        fixture.send("swapped");
        let line = fixture.line(Some(&mut *hog), "swapped");
        let swapped = parse_swapped(&line);
        let status = pool();
        if swapped >= want && status.swapped > 0 && status.store > 0
        {
            std::os::seraph::log!(
                "{PHASE}: the fixture reports {:?} (its main region's swapped pages, its \
                 node's charged and swapped pages); memmgr holds {} bytes swapped in a store of \
                 {} bytes, reserve {} pages",
                line.trim(),
                status.swapped,
                status.store,
                status.reserve_pages()
            );
            return;
        }
        assert!(
            start.elapsed() < SWAP_BOUND,
            "{PHASE}: after {SWAP_BOUND:?} at level {}, the fixture reports {swapped} pages \
             of its main region swapped of the {want} awaited, memmgr's swapped total {} \
             bytes and store {} bytes",
            status.level,
            status.swapped,
            status.store
        );
    }
}

/// A debugger's view of the swapped fixture: a page of the main region that
/// reads `InvalidAddress` reads its pattern after `MAKE_RESIDENT` of its
/// chunk, and the hole stays not present across the same request on its chunk.
fn debugger_restore(authority: u64, process: u64, thread: u64, ready: &Ready)
{
    let region = ready.region;
    let evicted = next_evicted(thread, ready, &mut 0);
    restore_chunk(authority, process, thread, ready, evicted, "");
    let mut hole_probe = [0u8; 8];
    assert_eq!(
        syscall::thread_read_mem(thread, ready.hole, &mut hole_probe),
        Err(INVALID_ADDRESS),
        "{PHASE}: the hole at {:#x} reads before MAKE_RESIDENT",
        ready.hole
    );
    let label = make_resident(authority, process, page_va(region, CHUNK_PAGES), CHUNK_LEN);
    assert_eq!(
        label,
        procmgr_errors::SUCCESS,
        "{PHASE}: MAKE_RESIDENT of the hole's chunk replied {label:#x}"
    );
    assert_eq!(
        syscall::thread_read_mem(thread, ready.hole, &mut hole_probe),
        Err(INVALID_ADDRESS),
        "{PHASE}: the hole at {:#x} reads after MAKE_RESIDENT, which backs no page",
        ready.hole
    );
}

/// The first page of the first chunk of the main region from chunk `*from`
/// on, the hole's aside, that reads `InvalidAddress`: a page of an evicted
/// chunk. `*from` moves past that chunk.
fn next_evicted(thread: u64, ready: &Ready, from: &mut u64) -> u64
{
    let region = ready.region;
    for chunk in (*from..ready.chunks).filter(|&c| c != HOLE_CHUNK)
    {
        let va = page_va(region, chunk.saturating_mul(CHUNK_PAGES));
        *from = chunk.saturating_add(1);
        match read_pattern(thread, va, region, MAIN_XOR)
        {
            Ok(true) =>
            {}
            Ok(false) =>
            {
                panic!(
                    "{PHASE}: the page at {va:#x} of the main region reads other than its pattern"
                )
            }
            Err(INVALID_ADDRESS) => return va,
            Err(code) => panic!("{PHASE}: reading the page at {va:#x} failed ({code})"),
        }
    }
    panic!(
        "{PHASE}: every first page of the main region's {} chunks from chunk {} on reads while \
         memmgr holds {} bytes swapped",
        ready.chunks,
        *from,
        pool().swapped
    )
}

/// Make the evicted page `evicted` of the main region resident with
/// `MAKE_RESIDENT` of its chunk, which must succeed, and require it to read
/// its pattern; `when` names the moment in a failure. The request is made up
/// to [`RESIDENT_TRIES`] times.
fn restore_chunk(authority: u64, process: u64, thread: u64, ready: &Ready, evicted: u64, when: &str)
{
    let region = ready.region;
    for _ in 0..RESIDENT_TRIES
    {
        let label = make_resident(authority, process, evicted, CHUNK_LEN);
        assert_eq!(
            label,
            procmgr_errors::SUCCESS,
            "{PHASE}: MAKE_RESIDENT of the chunk at {evicted:#x}{when} replied {label:#x}"
        );
        match read_pattern(thread, evicted, region, MAIN_XOR)
        {
            Ok(true) => return,
            Ok(false) =>
            {
                panic!("{PHASE}: the restored page at {evicted:#x} reads other than its pattern")
            }
            Err(INVALID_ADDRESS) =>
            {}
            Err(code) =>
            {
                panic!("{PHASE}: reading the restored page at {evicted:#x} failed ({code})")
            }
        }
    }
    panic!(
        "{PHASE}: the page at {evicted:#x} did not read after {RESIDENT_TRIES} MAKE_RESIDENT of \
         its chunk{when}"
    );
}

/// With the hog taking every page memmgr grants, at `CRITICAL`, growth stops
/// with at least a chunk free above the system reserve: the restore headroom
/// memmgr keeps while pages are swapped (services/memmgr/docs/memory-pool.md
/// § Eviction, Restore headroom). Swapped chunks of the main region are then
/// restored with `MAKE_RESIDENT`, one by one, from that headroom, until the
/// pages a restore is admitted against ([`Pool::restore_pages`]) fall short
/// of the reserve and a chunk; one more is restored there, which they cannot
/// admit, so memmgr's
/// direct reclaim made the room by evicting idle chunks in its turn. Each
/// restored page reads its pattern. The hog then gives grants back until the
/// level leaves `CRITICAL`. Returns the chunks restored from the headroom.
fn critical_restore(hog: &mut Hog, authority: u64, process: u64, thread: u64, ready: &Ready)
-> u64
{
    let status = hog.fill_to_floor();
    let reserve = status.reserve_pages();
    let headroom = status.headroom_pages();
    assert!(
        status.floor / PAGE_SIZE == reserve.saturating_add(headroom)
            && status.available_pages() <= status.floor / PAGE_SIZE,
        "{PHASE}: growth stopped at CRITICAL with {} pages available, against a reported \
         growth floor of {} pages; the reserve of {reserve} pages and {headroom} pages of \
         restore headroom expected",
        status.available_pages(),
        status.floor / PAGE_SIZE
    );
    assert!(
        !status.short_of_a_chunk(),
        "{PHASE}: growth stopped at CRITICAL with {} pages a restore is admitted against and a \
         reserve of {} while {} pages are swapped: no restore headroom",
        status.restore_pages(),
        status.reserve_pages(),
        status.swapped / PAGE_SIZE
    );
    // The clock's slices run at `CRITICAL` too: let a few age the chunks
    // and keep victims, then take what came free meanwhile.
    std::thread::sleep(CRITICAL_SETTLE);
    let _ = hog.fill_to_floor();
    let mut from = 0;
    let mut restored: u64 = 0;
    loop
    {
        if pool().short_of_a_chunk()
        {
            // Let the clock age the chunks restored so far, which direct
            // reclaim may take; pages may come free meanwhile, so look again.
            std::thread::sleep(CRITICAL_SETTLE);
            if pool().short_of_a_chunk()
            {
                break;
            }
        }
        let evicted = next_evicted(thread, ready, &mut from);
        restore_chunk(
            authority,
            process,
            thread,
            ready,
            evicted,
            " from the restore headroom",
        );
        restored = restored.saturating_add(1);
    }
    let evicted = next_evicted(thread, ready, &mut from);
    restore_chunk(
        authority,
        process,
        thread,
        ready,
        evicted,
        " with the pool short of the reserve and a chunk",
    );
    hog.release_from_critical();
    restored
}

/// Require every page of the no-evict region to read its pattern.
fn require_no_evict(thread: u64, ready: &Ready)
{
    for page in 0..NOEVICT_PAGES
    {
        let va = page_va(ready.noevict, page);
        require_pattern(
            thread,
            va,
            ready.noevict,
            NOEVICT_XOR,
            "under the hog, no-evict",
        );
    }
}

/// Make every listed process resident, then wait until memmgr's store and
/// swapped total are empty, the identity holds and, given a `baseline`, the
/// phase's totals ([`phase_totals`]) reach at least it: the phase's pages are
/// all back, while another process may have returned pages of its own
/// meanwhile. Returns the phase's totals then.
pub(super) fn settle_resident(authority: u64, baseline: Option<u64>) -> u64
{
    let top = syscall::user_va_top()
        .unwrap_or_else(|e| panic!("{PHASE}: SystemInfoType::UserVaTop failed ({e})"));
    for badge in listed_badges(authority)
    {
        let label = make_resident(authority, badge, 0, top);
        assert!(
            label == procmgr_errors::SUCCESS || label == procmgr_errors::INVALID_BADGE,
            "{PHASE}: MAKE_RESIDENT of process {badge:#x} replied {label:#x}"
        );
    }
    let start = Instant::now();
    loop
    {
        crate::phases::memmgr::recheck_deferred();
        let status = pool();
        let totals = phase_totals(&status);
        if status.identity()
            && status.store == 0
            && status.swapped == 0
            && baseline.is_none_or(|b| totals >= b)
        {
            return totals;
        }
        assert!(
            start.elapsed() < SETTLE_BOUND,
            "{PHASE}: {SETTLE_BOUND:?} after everything was made resident: identity {} (ram {} \
             reserved {} total {}), store {} bytes, swapped {} bytes, free + deferred + \
             svctest's own {totals} bytes against {baseline:?} at the start",
            status.identity(),
            status.system_ram,
            status.kernel_reserved,
            status.total,
            status.store,
            status.swapped
        );
        std::thread::sleep(SETTLE_POLL);
    }
}

// ── The fixture child ────────────────────────────────────────────────────────

/// How the fixture fills its main region: the token of its `argv[3]`.
#[derive(Clone, Copy)]
pub(super) enum Fill
{
    /// Each page one word repeated ([`pattern`]), which compresses to a few
    /// bytes.
    Page,
    /// Each word its own ([`noise`]), whose compressed stream gains nothing,
    /// so memmgr holds an evicted chunk of it raw.
    Noise,
}

impl Fill
{
    /// The fill's `argv[3]` token.
    const fn token(self) -> &'static str
    {
        match self
        {
            Self::Page => "page",
            Self::Noise => "noise",
        }
    }

    /// The word at `at` of a region at `base` filled so, with `xor`.
    pub(super) const fn word(self, at: u64, base: u64, xor: u64) -> u64
    {
        match self
        {
            Self::Page => pattern(at, base, xor),
            Self::Noise => noise(at.saturating_sub(base) ^ xor),
        }
    }
}

/// Write each word of the page at `va` of the region at `base` as `fill`
/// makes it with `xor`.
fn fill_page(va: u64, base: u64, xor: u64, fill: Fill)
{
    for word in 0..PAGE_WORDS
    {
        let at = va.saturating_add(word.saturating_mul(8));
        // SAFETY: the word is in a region this process registered writable,
        // in a reservation of its own that no Rust object occupies; the
        // write is volatile so that it is made, and faults, here.
        unsafe { std::ptr::write_volatile(at as *mut u64, fill.word(at, base, xor)) };
    }
}

/// The word every word of the page at `va` of the region at `base` holds: the
/// page's offset in the region, XOR `xor`. One word repeated over the page
/// compresses to a few bytes, so a restore of a chunk of it takes nearly a
/// chunk of free pages, the store returning almost none.
const fn pattern(va: u64, base: u64, xor: u64) -> u64
{
    (va & !(PAGE_SIZE - 1)).saturating_sub(base) ^ xor
}

/// `SplitMix64`'s output for `seed`: a word whose bits look random, a different
/// one for each seed, so a page of them leaves a compressor nothing to gain.
const fn noise(seed: u64) -> u64
{
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Whether each word of the page at `va` reads as [`fill_page`] wrote it.
fn page_intact(va: u64, base: u64, xor: u64, fill: Fill) -> bool
{
    let mut bytes = [0u8; PAGE_LEN];
    for (word, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate()
    {
        let at = va.saturating_add((word as u64).saturating_mul(8));
        // SAFETY: as in [`fill_page`]; the read restores the page when memmgr
        // evicted it.
        let got = unsafe { std::ptr::read_volatile(at as *const u64) };
        *chunk = got.to_ne_bytes();
    }
    bytes_intact(&bytes, va, base, xor, fill)
}

/// Whether `bytes`, a copy of the page at `va` of the region at `base`, hold
/// each word as [`fill_page`] wrote it.
pub(super) fn bytes_intact(bytes: &[u8], va: u64, base: u64, xor: u64, fill: Fill) -> bool
{
    bytes.len() == PAGE_LEN
        && bytes
            .as_chunks::<8>()
            .0
            .iter()
            .enumerate()
            .all(|(word, chunk)| {
                let at = va.saturating_add((word as u64).saturating_mul(8));
                u64::from_ne_bytes(*chunk) == fill.word(at, base, xor)
            })
}

/// Fixture thread `index`: fill a 64 KiB array on its own stack, keep it live,
/// call memmgr's `QUERY_MEMORY_USAGE` every [`THREAD_SLEEP`] until [`VERIFY`],
/// then check the array and count itself in [`THREADS_BAD`] if it changed.
#[expect(
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    reason = "the thread keeps a 64 KiB array on its own stack, which is what the phase tests: the \
              pages of a thread stack stay readable while memmgr evicts others"
)]
fn fixture_thread(index: u32)
{
    let seed = THREAD_XOR.wrapping_mul(u64::from(index).wrapping_add(1));
    let mut array = [0u64; THREAD_ARRAY_WORDS];
    for (word, slot) in array.iter_mut().enumerate()
    {
        *slot = u64::try_from(word).unwrap_or(0) ^ seed;
    }
    let _ = std::hint::black_box(&mut array);
    THREADS_READY.fetch_add(1, Ordering::AcqRel);
    while !VERIFY.load(Ordering::Acquire)
    {
        let _ = own_usage();
        std::thread::sleep(THREAD_SLEEP);
    }
    let live = std::hint::black_box(&array);
    let intact = live
        .iter()
        .enumerate()
        .all(|(word, &got)| got == u64::try_from(word).unwrap_or(0) ^ seed);
    if !intact
    {
        THREADS_BAD.fetch_add(1, Ordering::AcqRel);
    }
}

/// Reserve, register and fill the fixture's no-evict region of
/// [`NOEVICT_PAGES`] pages; its base and length in bytes. Exits
/// [`FIXTURE_NOEVICT_FAILED`] when the reservation or the registration fails.
fn fixture_noevict() -> (u64, u64)
{
    let Ok(noevict) = reserve_pages(NOEVICT_PAGES)
    else
    {
        exit(FIXTURE_NOEVICT_FAILED);
    };
    let noevict_base = noevict.va_start();
    let noevict_len = NOEVICT_PAGES.saturating_mul(PAGE_SIZE);
    // Best effort, as the std registration does; the pager funds the pool
    // itself when a fault finds it exhausted.
    let _ = std::os::seraph::fund_aspace_pt_budget(startup_info().self_aspace, NOEVICT_PAGES);
    let register = IpcMessage::builder(memmgr_labels::REGISTER_REGION)
        .word(0, noevict_base)
        .word(1, noevict_len)
        .word(2, syscall::MAP_WRITABLE)
        .word(3, memmgr_labels::REGION_NO_EVICT)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let registered =
        unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, &register, current_ipc_buf()) }
            .is_ok_and(|reply| reply.label == memmgr_errors::SUCCESS);
    if !registered
    {
        exit(FIXTURE_NOEVICT_FAILED);
    }
    for page in 0..NOEVICT_PAGES
    {
        fill_page(
            page_va(noevict_base, page),
            noevict_base,
            NOEVICT_XOR,
            Fill::Page,
        );
    }
    (noevict_base, noevict_len)
}

/// The fixture's main region's pages, `argv[2]`, and its fill, `argv[3]`.
/// Exits [`FIXTURE_BAD_ARGUMENT`] when either is not one the fixture takes.
fn fixture_args() -> (u64, Fill)
{
    let mut args = std::env::args().skip(2);
    let main_pages = args
        .next()
        .and_then(|a| a.parse::<u64>().ok())
        .filter(|&p| p > HOLE_PAGE && p % CHUNK_PAGES == 0);
    let fill = match args.next().as_deref()
    {
        Some("page") => Some(Fill::Page),
        Some("noise") => Some(Fill::Noise),
        _ => None,
    };
    match (main_pages, fill)
    {
        (Some(pages), Some(fill)) => (pages, fill),
        _ => exit(FIXTURE_BAD_ARGUMENT),
    }
}

/// Child role: register the main region, which `argv[3]` fills ([`Fill`]),
/// and the no-evict region and fill them, start [`FIXTURE_THREADS`] threads, print `ready <region> <len> <hole>
/// <noevict> <len>` in hex, and serve `swapped`, `verify` and `exit` lines
/// on stdin until one of `exit` or the end of the input, then exit 0.
fn fixture_main() -> !
{
    let (main_pages, fill) = fixture_args();
    let Ok(region) = register_demand_paged(main_pages)
    else
    {
        exit(FIXTURE_REGION_FAILED);
    };
    let base = region.va_start();
    for page in 0..main_pages
    {
        if page / CHUNK_PAGES != HOLE_CHUNK
        {
            fill_page(page_va(base, page), base, MAIN_XOR, fill);
        }
    }
    let (noevict_base, noevict_len) = fixture_noevict();
    let mut threads = Vec::new();
    for index in 0..FIXTURE_THREADS
    {
        let Ok(handle) = std::thread::Builder::new()
            .name(format!("swap-fixture-{index}"))
            .stack_size(THREAD_STACK_BYTES)
            .spawn(move || fixture_thread(index))
        else
        {
            exit(FIXTURE_THREAD_FAILED);
        };
        threads.push(handle);
    }
    let start = Instant::now();
    while THREADS_READY.load(Ordering::Acquire) < FIXTURE_THREADS
    {
        if start.elapsed() > THREADS_READY_BOUND
        {
            exit(FIXTURE_THREADS_NOT_READY);
        }
        std::thread::sleep(HOG_TICK);
    }
    println!(
        "ready {base:x} {:x} {:x} {noevict_base:x} {noevict_len:x}",
        main_pages.saturating_mul(PAGE_SIZE),
        page_va(base, HOLE_PAGE)
    );
    let _ = std::io::stdout().flush();
    for line in std::io::stdin().lock().lines()
    {
        let Ok(line) = line
        else
        {
            break;
        };
        match line.trim()
        {
            "swapped" =>
            {
                let (charged, swapped) = own_usage().unwrap_or((0, 0));
                println!(
                    "swapped {} {charged} {swapped}",
                    main_swapped_pages(main_pages)
                );
            }
            "verify" =>
            {
                VERIFY.store(true, Ordering::Release);
                let verdict = fixture_verdict(base, main_pages, noevict_base, fill);
                for handle in threads.drain(..)
                {
                    let _ = handle.join();
                }
                let bad = THREADS_BAD.load(Ordering::Acquire);
                match verdict
                {
                    Some(what) => println!("bad {what}"),
                    None if bad != 0 => println!("bad {bad} thread arrays"),
                    None => println!("ok"),
                }
            }
            "exit" => break,
            other =>
            {
                // `touch <hex va>`: read the page at that address of the main
                // region, and say whether it holds its pattern.
                if let Some(va) = other
                    .strip_prefix("touch ")
                    .and_then(|v| u64::from_str_radix(v, 16).ok())
                {
                    let ok = va >= base
                        && va < page_va(base, main_pages)
                        && page_intact(va & !(PAGE_SIZE - 1), base, MAIN_XOR, fill);
                    println!("touched {}", if ok { "ok" } else { "bad" });
                }
            }
        }
        let _ = std::io::stdout().flush();
    }
    exit(0);
}

/// Read every page of both regions, the main one of `main_pages` pages filled
/// as `fill` says, but the hole's chunk; the first that does not read as
/// written, named.
fn fixture_verdict(base: u64, main_pages: u64, noevict_base: u64, fill: Fill) -> Option<String>
{
    for page in 0..main_pages
    {
        if page / CHUNK_PAGES != HOLE_CHUNK
            && !page_intact(page_va(base, page), base, MAIN_XOR, fill)
        {
            return Some(format!("main page {page}"));
        }
    }
    for page in 0..NOEVICT_PAGES
    {
        if !page_intact(
            page_va(noevict_base, page),
            noevict_base,
            NOEVICT_XOR,
            Fill::Page,
        )
        {
            return Some(format!("noevict page {page}"));
        }
    }
    None
}
