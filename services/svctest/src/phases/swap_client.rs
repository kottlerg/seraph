// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/swap_client.rs

//! memmgr's disk tier through its swap interface
//! (services/memmgr/docs/ipc-interface.md § Labels 22 to 26), with svctest
//! acting as a second swap client beside swapd, through the `memmgr.swap`
//! seed, over a RAM slot store. svctest registers nothing and serves no
//! fault: the registration is swapd's, and the fault redirect and the want
//! path through a real slot are swapd's own phase's.
//!
//! The phase reuses `memmgr_swap`'s fixture and hog (`super::swap`), whose
//! failure messages name that phase. It first requires the swap labels to
//! refuse a process badge and the swap authority to refuse another label.
//! The hog then holds the level at `LOW` until memmgr holds chunks of the
//! fixture's main region swapped, and is released; with the level back at
//! `NORMAL`, where memmgr evicts nothing, the phase makes every other range
//! of every process resident until memmgr's swapped total is the fixture's
//! and its count of evictions begun did not move while it did ([`isolate`]),
//! so every chunk `SWAP_TAKE` takes is one of the main region's.
//! It requires:
//!
//! * no page on disk and free slots, swapd's registration having made them;
//! * `SWAP_TAKE` and `SWAP_DONE` of three chunks to disk, and the pool
//!   status's pages on disk and free slots;
//! * a `SWAP_RESTORE` of one of them ahead of any fault, and its slot word
//!   `RESTORE_STALE` after;
//! * the slot it freed taken again for a fourth chunk, written, and the first
//!   chunk's word and bytes `RESTORE_STALE` there, the fourth staying on disk
//!   and then restored with its own word;
//! * a fifth chunk left in flight, the bytes taken looking as ciphertext does
//!   (their byte counts' chi-square over 256 values below
//!   [`CHI_SQUARE_BOUND`]);
//! * a second chunk restored ahead, leaving the third on disk and the fifth
//!   in flight;
//! * `ipc::make_resident` of the fixture's whole main region restoring every
//!   chunk in RAM and cancelling the write in flight, whose `SWAP_DONE` then
//!   frees its slot, and replying pending at the third chunk on disk, whose
//!   slot swapd reads and finds holding no seal of it, so memmgr loses the
//!   chunk and frees its slot, leaving no chunk on disk and every slot free;
//! * the fixture's read of a page of the lost chunk declined by memmgr, and
//!   the fixture killed;
//! * and once the fixture is gone, the end of `memmgr_swap`: the store and
//!   the swapped total empty, the identity holding, and memmgr's free and
//!   deferred pages with svctest's own charged pages at least what they were
//!   at the start, less the pages of the swap slot map, which memmgr keeps as
//!   its metadata once swapd registered every slot.

use std::collections::HashMap;
use std::os::seraph::{current_ipc_buf, startup_info};
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use syscall_abi::{MAP_READ, MAP_WRITABLE, PAGE_SIZE};

use super::swap::{
    CHUNK_LEN, CHUNK_PAGES, Fill, HOG_TICK, Hog, Ready, attach, await_swapped, baseline_totals,
    detach, listed_badges, main_pages, make_resident, page_present, pool, settle_resident,
    start_fixture,
};
use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_swap_client",
        run: swap_client_phase,
    }]
}

/// The phase's name in its failure messages.
const PHASE: &str = "memmgr_swap_client";

/// Chunks of the main region the phase awaits swapped: a, b, t, c and x, and
/// one more for a chunk the clock's last slice did not reach.
const SWAPPED_CHUNKS: u64 = 6;
/// `SWAP_TAKE`s the phase makes for one chunk at most: each walks a bounded
/// part of memmgr's records, and successive ones cover them all.
const TAKE_TRIES: u32 = 256;
/// Pages of a buffer: a chunk, the most a slot's bytes take.
const BUF_PAGES: u64 = CHUNK_PAGES;
/// The chi-square of a slot's byte counts over 256 values that bytes looking
/// as ciphertext stay below: 255 degrees of freedom, whose mean is 255 and
/// standard deviation about 23, so uniform bytes exceed it with a
/// probability below 10^-20, and a compressed stream of the fixture's pattern
/// lies far above it.
const CHI_SQUARE_BOUND: u64 = 512;
/// Bytes of ciphertext the chi-square needs at the least.
const CHI_SQUARE_MIN_BYTES: usize = 8192;
/// How long the phase waits for the level to return to `NORMAL`, and for
/// memmgr's swapped total to be the fixture's alone. A test wait bound.
const SETTLE_BOUND: Duration = Duration::from_secs(30);
/// How long the phase waits for a fault to reach its endpoint and be served.
/// A test wait bound.
const SERVE_BOUND: Duration = Duration::from_secs(30);

/// The RAM slot store: each slot's bytes as the phase took them.
pub(super) type Slots = HashMap<u32, Vec<u8>>;

/// A buffer of [`BUF_PAGES`] pages: a contiguous grant mapped read-write in
/// svctest, and its cap, which a swap label moves to memmgr and back.
pub(super) struct Buffer
{
    cap: u64,
    region_id: u64,
    va: u64,
}

impl Buffer
{
    pub(super) fn new() -> Self
    {
        let pages = u32::try_from(BUF_PAGES).unwrap_or(16);
        let (cap, region_id) = crate::phases::memmgr::try_request_contiguous(pages)
            .unwrap_or_else(|label| panic!("{PHASE}: a buffer's grant replied {label:#x}"));
        let range = std::os::seraph::reserve_pages(BUF_PAGES)
            .unwrap_or_else(|e| panic!("{PHASE}: reserving a buffer's range: {e:?}"));
        let va = range.va_start();
        // SAFETY: `range` is a fresh reservation from the per-process arena,
        // owned here: VA no Rust object or IPC page occupies.
        unsafe {
            std::os::seraph::mem_map_funded(
                cap,
                startup_info().self_aspace,
                va,
                0,
                BUF_PAGES,
                MAP_READ | MAP_WRITABLE,
            )
        }
        .unwrap_or_else(|e| panic!("{PHASE}: mapping a buffer: {e}"));
        Self { cap, region_id, va }
    }

    /// The first `len` bytes, copied out.
    fn read(&self, len: usize) -> Vec<u8>
    {
        let len = len.min(usize::try_from(CHUNK_LEN).unwrap_or(0));
        // SAFETY: `va` maps the buffer's `BUF_PAGES` pages, which only this
        // owner touches while memmgr does not hold its cap.
        unsafe { std::slice::from_raw_parts(self.va as *const u8, len) }.to_vec()
    }

    /// Write `bytes` from the buffer's start.
    fn write(&self, bytes: &[u8])
    {
        let len = bytes.len().min(usize::try_from(CHUNK_LEN).unwrap_or(0));
        // SAFETY: as in `read`; `len` fits the mapping.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.va as *mut u8, len) };
    }

    /// Unmap the buffer and give its grant back.
    pub(super) fn release(self)
    {
        // SAFETY: the range is this buffer's own mapping, which nothing else
        // refers to.
        let _ = unsafe { syscall::mem_unmap(startup_info().self_aspace, self.va, BUF_PAGES) };
        crate::phases::memmgr::release_grant(self.cap, self.region_id);
    }
}

/// memmgr's reply to `msg` on the swap authority `swap`, panicking with
/// `what` when the call fails. A cap the reply moves back is the caller's.
fn swap_call(swap: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(swap, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{PHASE}: {what}: ipc_call failed ({e})"))
}

/// `SWAP_TAKE` into `buf`: the slot and its slot word, the slot's bytes kept
/// in the store. A walk that finds no chunk within memmgr's bound replies
/// `NOTHING_TO_TAKE`, and the next goes on from where it stopped, so it is
/// asked again, at most [`TAKE_TRIES`] times.
pub(super) fn take(swap: u64, buf: &mut Buffer, slots: &mut Slots, what: &str) -> (u32, u64)
{
    let mut tries: u32 = 0;
    let reply = loop
    {
        let msg = IpcMessage::builder(memmgr_labels::SWAP_TAKE)
            .cap(buf.cap)
            .build();
        let reply = swap_call(swap, &msg, what);
        buf.cap = *reply
            .caps()
            .first()
            .unwrap_or_else(|| panic!("{PHASE}: {what}: SWAP_TAKE moved no buffer back"));
        tries = tries.saturating_add(1);
        if reply.label != memmgr_errors::NOTHING_TO_TAKE || tries >= TAKE_TRIES
        {
            break reply;
        }
    };
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "{PHASE}: {what}: SWAP_TAKE replied {:#x}",
        reply.label
    );
    let slot = u32::try_from(reply.word(0))
        .unwrap_or_else(|_| panic!("{PHASE}: {what}: slot {:#x}", reply.word(0)));
    let len = usize::try_from(reply.word(1)).unwrap_or(usize::MAX);
    assert!(
        len > 16 && len <= usize::try_from(CHUNK_LEN).unwrap_or(0),
        "{PHASE}: {what}: slot {slot} of {len} bytes"
    );
    let word = reply.word(2);
    assert_eq!(
        (
            free_pool::disk::word_slot(word),
            usize::try_from(free_pool::disk::word_len(word)).unwrap_or(usize::MAX)
        ),
        (slot, len),
        "{PHASE}: {what}: slot word {word:#x}"
    );
    let bytes = buf.read(len);
    slots.insert(slot, bytes);
    (slot, word)
}

/// The bytes the store holds for `slot`.
pub(super) fn stored(slots: &Slots, slot: u32) -> Vec<u8>
{
    slots.get(&slot).cloned().unwrap_or_default()
}

/// `SWAP_DONE` of `slot` with status `status`: memmgr's reply label.
pub(super) fn done(swap: u64, slot: u32, status: u64, what: &str) -> u64
{
    let msg = IpcMessage::builder(memmgr_labels::SWAP_DONE)
        .word(0, u64::from(slot))
        .word(1, status)
        .build();
    swap_call(swap, &msg, what).label
}

/// `SWAP_RESTORE` of the slot word `word` with `bytes`, written into `buf`:
/// memmgr's reply label and word 0.
pub(super) fn restore(
    swap: u64,
    word: u64,
    bytes: &[u8],
    buf: &mut Buffer,
    what: &str,
) -> (u64, u64)
{
    buf.write(bytes);
    let msg = IpcMessage::builder(memmgr_labels::SWAP_RESTORE)
        .word(0, word)
        .cap(buf.cap)
        .build();
    let reply = swap_call(swap, &msg, what);
    buf.cap = *reply
        .caps()
        .first()
        .unwrap_or_else(|| panic!("{PHASE}: {what}: SWAP_RESTORE moved no buffer back"));
    (reply.label, reply.word(0))
}

/// The pages memmgr holds on disk and the slots free, from its pool status.
pub(super) fn disk_and_free() -> (u64, u64)
{
    let status = pool();
    (status.on_disk / PAGE_SIZE, status.free_slots)
}

/// The swap labels refuse svctest's own memmgr SEND, a process badge, with
/// `UNAUTHORIZED`, and the swap authority refuses `QUERY_POOL_STATUS` so.
fn require_refusals(swap: u64)
{
    for label in [
        memmgr_labels::SWAP_REGISTER,
        memmgr_labels::SWAP_TAKE,
        memmgr_labels::SWAP_DONE,
        memmgr_labels::SWAP_RESTORE,
    ]
    {
        let reply = super::swap::memmgr_call(&IpcMessage::new(label), "a swap label");
        assert_eq!(
            reply.label,
            memmgr_errors::UNAUTHORIZED,
            "{PHASE}: swap label {label} on a process badge replied {:#x}",
            reply.label
        );
    }
    let reply = swap_call(
        swap,
        &IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS),
        "QUERY_POOL_STATUS",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::UNAUTHORIZED,
        "{PHASE}: QUERY_POOL_STATUS on the swap authority replied {:#x}",
        reply.label
    );
}

/// The chi-square of `bytes`' counts over the 256 byte values, rounded
/// down; `u64::MAX` for no bytes. In integers: with `n` bytes, each value
/// expected `n / 256` times, the sum of `(c - n/256)^2 / (n/256)` over the
/// counts `c` is `256 * sum(c^2) / n - n`.
fn chi_square(bytes: &[u8]) -> u64
{
    let mut counts = [0u64; 256];
    for &b in bytes
    {
        if let Some(c) = counts.get_mut(usize::from(b))
        {
            *c = c.saturating_add(1);
        }
    }
    let n = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if n == 0
    {
        return u64::MAX;
    }
    let squares = counts
        .iter()
        .fold(0u64, |sum, &c| sum.saturating_add(c.saturating_mul(c)));
    (squares.saturating_mul(256))
        .checked_div(n)
        .unwrap_or(u64::MAX)
        .saturating_sub(n)
}

/// Wait for the level to read `NORMAL`, where memmgr evicts nothing.
pub(super) fn await_normal()
{
    let start = Instant::now();
    while pool().level != memmgr_labels::PRESSURE_NORMAL
    {
        assert!(
            start.elapsed() < SETTLE_BOUND,
            "{PHASE}: the level did not return to NORMAL in {SETTLE_BOUND:?}"
        );
        std::thread::sleep(HOG_TICK);
    }
}

/// Make every range of every process resident but the fixture's main region,
/// until memmgr's swapped total is the fixture's own and no eviction began
/// while the ranges were made resident. A chunk the round meets evicting, raw
/// or evicted is made resident, an eviction in flight on it cancelled, and a
/// chunk leaves the resident state again only by an eviction begun, which
/// `QUERY_POOL_STATUS` `data[14]` counts: an unchanged count leaves no chunk
/// outside the main region that `SWAP_TAKE` can take, a raw one included,
/// which counts in no swapped total until it is written. Returns the
/// fixture's swapped pages then.
pub(super) fn isolate(
    authority: u64,
    process: u64,
    ready: &Ready,
    fixture: &mut super::swap::Fixture,
) -> u64
{
    let top = syscall::user_va_top()
        .unwrap_or_else(|e| panic!("{PHASE}: SystemInfoType::UserVaTop failed ({e})"));
    let region_end = ready
        .region
        .saturating_add(ready.chunks.saturating_mul(CHUNK_LEN));
    let start = Instant::now();
    loop
    {
        let before = pool().evictions;
        for badge in listed_badges(authority)
        {
            let ranges: &[(u64, u64)] = if badge == process
            {
                &[(0, ready.region), (region_end, top)]
            }
            else
            {
                &[(0, top)]
            };
            for &(va, end) in ranges
            {
                let label = make_resident(authority, badge, va, end.saturating_sub(va));
                assert!(
                    label == procmgr_errors::SUCCESS || label == procmgr_errors::INVALID_BADGE,
                    "{PHASE}: MAKE_RESIDENT of process {badge:#x} replied {label:#x}"
                );
            }
        }
        fixture.send("swapped");
        let line = fixture.line(None, "swapped");
        let node: u64 = line
            .split_whitespace()
            .nth(3)
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("{PHASE}: the fixture answered swapped with {line:?}"));
        let status = pool();
        let total = status.swapped / PAGE_SIZE;
        let moved = status.evictions.wrapping_sub(before);
        if total == node && moved == 0
        {
            return node;
        }
        assert!(
            start.elapsed() < SETTLE_BOUND,
            "{PHASE}: memmgr holds {total} pages swapped, the fixture {node}, and began \
             {moved} evictions in the last round, after {SETTLE_BOUND:?} of making every \
             other range resident"
        );
        std::thread::sleep(HOG_TICK);
    }
}

/// The phase (see the module documentation).
#[expect(
    clippy::too_many_lines,
    reason = "one scenario whose steps each depend on the state the one before left; split, each \
              part would take and return the whole of it"
)]
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s of its calls (568 B each) and their builder \
              temporaries; on svctest's main-thread stack, which every phase shares"
)]
fn swap_client_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    let swap = caps.memmgr_swap;
    assert_ne!(authority, 0, "{PHASE}: no debug authority");
    assert_ne!(swap, 0, "{PHASE}: no memmgr.swap seed");
    require_refusals(swap);

    let mut hog = Hog::new();
    let _ = settle_resident(authority, None);
    let baseline = baseline_totals();
    let reserve = pool().reserve_pages();
    let (mut fixture, ready, process) = start_fixture(authority, main_pages(reserve), Fill::Page);
    let begun = pool().evictions;
    hog.fill_to_low();
    await_swapped(&mut hog, &mut fixture, SWAPPED_CHUNKS * CHUNK_PAGES);
    assert!(
        pool().evictions.wrapping_sub(begun) >= SWAPPED_CHUNKS,
        "{PHASE}: memmgr's count of evictions begun moved by {} while it swapped {} chunks \
         of the fixture's",
        pool().evictions.wrapping_sub(begun),
        SWAPPED_CHUNKS
    );
    hog.release_all();
    await_normal();
    let swapped = isolate(authority, process, &ready, &mut fixture);
    assert!(
        swapped >= (SWAPPED_CHUNKS - 1) * CHUNK_PAGES,
        "{PHASE}: {swapped} pages of the fixture's main region swapped once isolated"
    );

    let (disk0, free0) = disk_and_free();
    assert!(
        disk0 == 0 && free0 > 0,
        "{PHASE}: {disk0} pages on disk and {free0} slots free before any take: swapd's \
         registration is missing"
    );
    let mut slots = Slots::new();

    // Three chunks to disk.
    let mut buf = Buffer::new();
    let (slot_a, word_a) = take(swap, &mut buf, &mut slots, "take a");
    assert_eq!(done(swap, slot_a, 0, "done a"), memmgr_errors::SUCCESS);
    let (slot_b, word_b) = take(swap, &mut buf, &mut slots, "take b");
    assert_eq!(done(swap, slot_b, 0, "done b"), memmgr_errors::SUCCESS);
    let (slot_t, _) = take(swap, &mut buf, &mut slots, "take t");
    assert_eq!(done(swap, slot_t, 0, "done t"), memmgr_errors::SUCCESS);
    assert_eq!(
        disk_and_free(),
        (3 * CHUNK_PAGES, free0.saturating_sub(3)),
        "{PHASE}: three chunks on disk"
    );

    // A restore ahead of any fault, and its word stale after.
    let bytes_a = stored(&slots, slot_a);
    assert_eq!(
        restore(swap, word_a, &bytes_a, &mut buf, "restore a"),
        (memmgr_errors::SUCCESS, 0)
    );
    assert_eq!(
        restore(swap, word_a, &bytes_a, &mut buf, "restore a again").0,
        memmgr_errors::RESTORE_STALE
    );

    // The slot a's restore freed, taken again first, holds another chunk on
    // disk: a's word and bytes there are stale and leave it on disk, and its
    // own word restores it.
    let (slot_c, word_c) = take(swap, &mut buf, &mut slots, "take c");
    assert_eq!(
        slot_c, slot_a,
        "{PHASE}: the take after a's restore did not reuse the slot it freed"
    );
    assert_eq!(done(swap, slot_c, 0, "done c"), memmgr_errors::SUCCESS);
    assert_eq!(
        restore(swap, word_a, &bytes_a, &mut buf, "a's late restore").0,
        memmgr_errors::RESTORE_STALE
    );
    assert_eq!(
        disk_and_free(),
        (3 * CHUNK_PAGES, free0.saturating_sub(3)),
        "{PHASE}: after a's late restore"
    );
    let bytes_c = stored(&slots, slot_c);
    assert_eq!(
        restore(swap, word_c, &bytes_c, &mut buf, "restore c"),
        (memmgr_errors::SUCCESS, 0)
    );

    // A write in flight.
    let (slot_x, _) = take(swap, &mut buf, &mut slots, "take x");
    assert_eq!(
        disk_and_free(),
        (2 * CHUNK_PAGES, free0.saturating_sub(3)),
        "{PHASE}: two chunks on disk and one in flight"
    );
    let sealed: Vec<u8> = slots
        .values()
        .flat_map(|bytes| bytes.iter().take(bytes.len().saturating_sub(16)).copied())
        .collect();
    let chi = chi_square(&sealed);
    assert!(
        sealed.len() >= CHI_SQUARE_MIN_BYTES && chi < CHI_SQUARE_BOUND,
        "{PHASE}: {} bytes taken, chi-square {chi}: not ciphertext",
        sealed.len()
    );

    // A restore of b ahead leaves t on disk and x in flight.
    let bytes_b = stored(&slots, slot_b);
    assert_eq!(
        restore(swap, word_b, &bytes_b, &mut buf, "restore b"),
        (memmgr_errors::SUCCESS, 0)
    );
    assert_eq!(
        disk_and_free(),
        (CHUNK_PAGES, free0.saturating_sub(2)),
        "{PHASE}: t on disk and x in flight"
    );

    // MAKE_RESIDENT of the whole main region restores every chunk in RAM and
    // x's writing chunk, cancelling its write, and replies pending at t's
    // chunk: memmgr posts t's word to swapd, whose want thread reads t's
    // slot, which holds no seal of t's, so memmgr loses t and frees its slot.
    let region_len = ready.chunks.saturating_mul(CHUNK_LEN);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let _ = unsafe {
        ipc::make_resident(
            authority,
            process,
            ready.region,
            region_len,
            current_ipc_buf(),
        )
    };
    assert_eq!(
        done(swap, slot_x, 0, "done x after the cancel"),
        memmgr_errors::SUCCESS
    );
    let start = Instant::now();
    while disk_and_free() != (0, free0)
    {
        assert!(
            start.elapsed() < SERVE_BOUND,
            "{PHASE}: {:?} (pages on disk, free slots) in {SERVE_BOUND:?}, expected (0, {free0}) \
             once t was lost",
            disk_and_free()
        );
        std::thread::sleep(HOG_TICK);
    }

    // The lost chunk is the one main-region chunk not present.
    let threads = attach(authority, process, "the fixture");
    let thread = *threads.first().expect("the attach returned a thread");
    let hole_chunk = ready.hole.saturating_sub(ready.region) / CHUNK_LEN;
    let absent: Vec<u64> = (0..ready.chunks)
        .filter(|&i| i != hole_chunk)
        .map(|i| ready.region.saturating_add(i.saturating_mul(CHUNK_LEN)))
        .filter(|&va| !page_present(thread, va))
        .collect();
    detach(authority, process, &threads, "the fixture");
    let [lost] = absent[..]
    else
    {
        panic!("{PHASE}: chunks of the main region not present: {absent:#x?}, one expected")
    };

    // A fault on it is declined and the fixture killed.
    fixture.send(&format!("touch {lost:x}"));
    let status = fixture.exit_status();
    assert!(
        !status.success(),
        "{PHASE}: the fixture survived its lost chunk ({status:?})"
    );

    buf.release();
    let slot_map_pages = free0.div_ceil(free_pool::disk::SLOT_WORDS_PER_PAGE);
    let floor = baseline.saturating_sub(slot_map_pages.saturating_mul(PAGE_SIZE));
    let end = settle_resident(authority, Some(floor));
    std::os::seraph::log!(
        "memmgr_swap_client phase passed ({} bytes sealed, chi-square {chi}, t lost and its \
         chunk's fault declined, free, deferred and svctest's own {} pages above the start less \
         the {slot_map_pages} slot-map pages)",
        sealed.len(),
        end.saturating_sub(floor) / PAGE_SIZE
    );
}
