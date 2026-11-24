// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/swap_raw.rs

//! memmgr's raw chunks end to end (services/memmgr/docs/memory-pool.md
//! § Disk tier): a chunk whose compressed stream gains nothing, evicted while
//! a swap slot is free, stays on its own frames, unmapped, until a swap
//! client takes it, and a slot holds its pages sealed alone. svctest acts as a
//! second swap client through the `memmgr.swap` seed, as
//! [`super::swap_client`] does, over a RAM slot store, and reuses
//! `memmgr_swap`'s hog (`super::swap`) and its fixture with a main region of
//! noise, each word its own, whose failure messages name that phase.
//!
//! The hog holds the level at `LOW` until at least [`RAW_CHUNKS`] chunks of
//! the fixture's main region are not present, and is released; with the level
//! back at `NORMAL`, the phase makes every other range of every process
//! resident. It requires:
//!
//! * those chunks evicted and none of their pages swapped, in memmgr's total
//!   or the fixture's own: a raw chunk counts as swapped only once written;
//!   no page on disk, and free slots;
//! * `SWAP_TAKE` of one, its slot holding a whole chunk's bytes, none of
//!   them a word of the chunk in the clear, and `SWAP_DONE` putting it on
//!   disk, where its pages count as swapped, in memmgr's total and the
//!   fixture's;
//! * a `SWAP_RESTORE` of it making its chunk, the one that was not present,
//!   read its noise, the swapped totals and the pages on disk back to none,
//!   and its slot word `RESTORE_STALE` after;
//! * a second chunk taken and left in flight, and procmgr's `MAKE_RESIDENT`
//!   of a chunk not present mapping it back, with no page on disk;
//! * the fixture reading every page of its main region, the faults on the
//!   chunks still raw and on the one in flight mapping their frames back, and
//!   the `SWAP_DONE` of the cancelled write freeing its slot;
//! * with the hog holding the level at `LOW` until chunks are raw again and
//!   then at `CRITICAL`, swapd writing at least [`WRITTEN_CHUNKS`] of them to
//!   its partition; once the level is back at `NORMAL` and every other range
//!   is resident, every page swapped one on disk, and the fixture reading every
//!   page of its main region, each chunk on disk faulted, redirected to swapd,
//!   and restored intact, and none left on disk;
//! * and once the fixture is gone, the end of `memmgr_swap`, as
//!   `memmgr_swap_client` requires it.

use std::time::{Duration, Instant};

use ipc::{memmgr_errors, procmgr_errors};
use syscall_abi::PAGE_SIZE;

use super::swap::{
    CHUNK_LEN, CHUNK_PAGES, Fill, Fixture, HOG_TICK, Hog, MAIN_XOR, Ready, attach, baseline_totals,
    detach, main_pages, make_resident, page_present, pool, settle_resident, start_fixture,
};
use super::swap_client::{
    Buffer, Slots, await_normal, disk_and_free, done, isolate, restore, stored, take,
};
use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_swap_raw",
        run: swap_raw_phase,
    }]
}

/// The phase's name in its failure messages.
const PHASE: &str = "memmgr_swap_raw";

/// Chunks of the main region the phase awaits not present under the hog: one
/// written and restored, one left in flight, one made resident, and one more
/// the fixture's read faults back raw.
const RAW_CHUNKS: u64 = 4;
/// How long the phase waits, with the hog holding the level, for memmgr to
/// evict [`RAW_CHUNKS`] chunks of the main region. A test wait bound.
const RAW_BOUND: Duration = Duration::from_secs(90);
/// How often the phase looks at the main region while it waits.
const RAW_POLL: Duration = Duration::from_millis(50);
/// Raw chunks swapd writes at `CRITICAL` that the phase awaits.
const WRITTEN_CHUNKS: u64 = 2;
/// How long the phase waits for swapd to write chunks out at `CRITICAL`, and
/// for a write it began to end. A test wait bound.
const WRITE_BOUND: Duration = Duration::from_secs(60);
/// Bytes of a page, as an array length.
const PAGE_LEN: usize = 4096;
const _: () = assert!(PAGE_LEN as u64 == PAGE_SIZE);

/// The bases of the chunks of the main region, the hole's chunk excluded, that
/// read as not present through `thread`.
fn absent_chunks(thread: u64, ready: &Ready) -> Vec<u64>
{
    let hole_chunk = ready.hole.saturating_sub(ready.region) / CHUNK_LEN;
    (0..ready.chunks)
        .filter(|&i| i != hole_chunk)
        .map(|i| ready.region.saturating_add(i.saturating_mul(CHUNK_LEN)))
        .filter(|&va| !page_present(thread, va))
        .collect()
}

/// The pages of the fixture's node that memmgr counts swapped, from its
/// `swapped` line.
fn node_swapped(fixture: &mut Fixture) -> u64
{
    fixture.send("swapped");
    let line = fixture.line(None, "swapped");
    line.split_whitespace()
        .nth(3)
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("{PHASE}: the fixture answered swapped with {line:?}"))
}

/// The words of `bytes` that equal the word at their offset of the chunk at
/// `va` of the main region in the clear.
fn clear_words(bytes: &[u8], va: u64, ready: &Ready) -> usize
{
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .zip((0..).map(|w: u64| va.saturating_add(w.saturating_mul(8))))
        .filter(|&(word, at)| {
            u64::from_ne_bytes(*word) == Fill::Noise.word(at, ready.region, MAIN_XOR)
        })
        .count()
}

/// Whether the chunk at `va` of the main region, read through `thread`, holds
/// its noise.
fn chunk_reads_noise(thread: u64, va: u64, ready: &Ready) -> bool
{
    let mut page = [0u8; PAGE_LEN];
    (0..CHUNK_PAGES).all(|p| {
        let page_va = va.saturating_add(p.saturating_mul(PAGE_SIZE));
        syscall::thread_read_mem(thread, page_va, &mut page).is_ok()
            && clear_words(&page, page_va, ready) == PAGE_LEN / 8
    })
}

/// With the hog holding the level, wait until at least [`RAW_CHUNKS`] chunks
/// of the main region read as not present through `thread`.
fn await_raw(hog: &mut Hog, thread: u64, ready: &Ready)
{
    let start = Instant::now();
    loop
    {
        let polled = Instant::now();
        while polled.elapsed() < RAW_POLL
        {
            let _ = hog.tick();
            std::thread::sleep(HOG_TICK);
        }
        let absent = u64::try_from(absent_chunks(thread, ready).len()).unwrap_or(u64::MAX);
        if absent >= RAW_CHUNKS
        {
            return;
        }
        let status = pool();
        assert!(
            start.elapsed() < RAW_BOUND,
            "{PHASE}: after {RAW_BOUND:?} at level {}, {absent} chunks of the fixture's main              region not present of the {RAW_CHUNKS} awaited, {} slots free",
            status.level,
            status.free_slots
        );
    }
}

/// Wait until no write is in flight, every slot taken of the `free0` free at
/// the start holding a chunk on disk, within [`WRITE_BOUND`].
fn await_writes_ended(free0: u64)
{
    let start = Instant::now();
    loop
    {
        let status = pool();
        let taken = free0.saturating_sub(status.free_slots);
        if taken.saturating_mul(CHUNK_LEN) == status.on_disk
        {
            return;
        }
        assert!(
            start.elapsed() < WRITE_BOUND,
            "{PHASE}: {taken} slots taken and {} bytes on disk {WRITE_BOUND:?} after the level \
             fell from CRITICAL",
            status.on_disk
        );
        std::thread::sleep(HOG_TICK);
    }
}

/// swapd's write-out of raw chunks and the fault path back (see the module
/// documentation), with `free0` slots free and nothing on disk at its start.
/// Returns the chunks on disk once the level is back at `NORMAL`.
fn written_by_swapd(
    authority: u64,
    hog: &mut Hog,
    fixture: &mut Fixture,
    ready: &Ready,
    process: u64,
    thread: u64,
    free0: u64,
) -> u64
{
    hog.fill_to_low();
    await_raw(hog, thread, ready);
    let _ = hog.fill_to_floor();
    let start = Instant::now();
    while pool().on_disk < WRITTEN_CHUNKS * CHUNK_LEN
    {
        assert!(
            start.elapsed() < WRITE_BOUND,
            "{PHASE}: {} bytes on disk {WRITE_BOUND:?} into CRITICAL, {} awaited",
            pool().on_disk,
            WRITTEN_CHUNKS * CHUNK_LEN
        );
        std::thread::sleep(HOG_TICK);
    }
    hog.release_from_critical();
    hog.release_all();
    await_normal();
    // Every chunk on disk the fixture's: the others are restored. A write
    // swapd began at CRITICAL may end after the level fell: wait for it.
    let _ = isolate(authority, process, ready, fixture);
    await_writes_ended(free0);
    let status = pool();
    assert!(
        status.on_disk >= CHUNK_LEN && status.swapped == status.on_disk && status.store == 0,
        "{PHASE}: {} bytes on disk, {} swapped and {} in the store once isolated: every \
         chunk of noise swapped is one written raw",
        status.on_disk,
        status.swapped,
        status.store
    );
    fixture.send("verify");
    let verdict = fixture.line(None, "verify");
    assert_eq!(
        verdict.trim(),
        "ok",
        "{PHASE}: the fixture's verify after swapd's write-out answered {verdict:?}"
    );
    assert_eq!(
        disk_and_free(),
        (0, free0),
        "{PHASE}: pages on disk and free slots after the fixture read every page"
    );
    status.on_disk / CHUNK_LEN
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
              temporaries, and a page read; on svctest's main-thread stack, which every phase \
              shares"
)]
fn swap_raw_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    let swap = caps.memmgr_swap;
    assert_ne!(authority, 0, "{PHASE}: no debug authority");
    assert_ne!(swap, 0, "{PHASE}: no memmgr.swap seed");

    let mut hog = Hog::new();
    let _ = settle_resident(authority, PHASE, None);
    let baseline = baseline_totals(authority, PHASE);
    let reserve = pool().reserve_pages();
    let (mut fixture, ready, process) = start_fixture(authority, main_pages(reserve), Fill::Noise);
    let threads = attach(authority, process, "the fixture");
    let thread = *threads.first().expect("the attach returned a thread");

    hog.fill_to_low();
    await_raw(&mut hog, thread, &ready);
    hog.release_all();
    await_normal();
    let swapped = isolate(authority, process, &ready, &mut fixture);
    let raw = absent_chunks(thread, &ready);
    let raw_count = u64::try_from(raw.len()).unwrap_or(0);
    let (disk0, free0) = disk_and_free();
    assert!(
        raw_count >= RAW_CHUNKS && swapped == 0 && pool().swapped == 0,
        "{PHASE}: {raw_count} chunks of the fixture's main region not present once isolated, \
         {swapped} pages of the fixture's and {} bytes of memmgr's swapped: a raw chunk counts \
         as swapped only once written",
        pool().swapped
    );
    assert!(
        disk0 == 0 && free0 > 0,
        "{PHASE}: {disk0} pages on disk and {free0} slots free before any take"
    );
    let mut slots = Slots::new();
    let mut buf = Buffer::new();

    // r to disk: a whole chunk's bytes, none of them in the clear, swapped
    // once written.
    let (slot_r, word_r) = take(swap, &mut buf, &mut slots, "take r");
    let bytes_r = stored(&slots, slot_r);
    assert_eq!(
        u64::try_from(bytes_r.len()),
        Ok(CHUNK_LEN),
        "{PHASE}: take r: the bytes of the slot of a raw chunk of noise"
    );
    assert_eq!(done(swap, slot_r, 0, "done r"), memmgr_errors::SUCCESS);
    assert_eq!(
        (disk_and_free(), pool().swapped, node_swapped(&mut fixture)),
        (
            (CHUNK_PAGES, free0.saturating_sub(1)),
            CHUNK_LEN,
            CHUNK_PAGES
        ),
        "{PHASE}: r on disk ((pages on disk, free slots), memmgr's swapped bytes, the \
         fixture's swapped pages)"
    );

    // r restored: its chunk reads its noise, and its word is stale after.
    assert_eq!(
        restore(swap, word_r, &bytes_r, &mut buf, "restore r"),
        (memmgr_errors::SUCCESS, 0)
    );
    let still = absent_chunks(thread, &ready);
    let back: Vec<u64> = raw
        .iter()
        .copied()
        .filter(|va| !still.contains(va))
        .collect();
    let [r_va] = back[..]
    else
    {
        panic!("{PHASE}: chunks present after r's restore that were not before: {back:#x?}")
    };
    assert!(
        chunk_reads_noise(thread, r_va, &ready),
        "{PHASE}: r's chunk at {r_va:#x} does not read its noise after its restore"
    );
    let clear = clear_words(&bytes_r, r_va, &ready);
    assert_eq!(
        clear, 0,
        "{PHASE}: {clear} words of r's slot hold its chunk at {r_va:#x} in the clear"
    );
    assert_eq!(
        (disk_and_free(), pool().swapped, node_swapped(&mut fixture)),
        ((0, free0), 0, 0),
        "{PHASE}: r restored"
    );
    assert_eq!(
        restore(swap, word_r, &bytes_r, &mut buf, "restore r again").0,
        memmgr_errors::RESTORE_STALE
    );

    // w in flight, and a raw chunk made resident without the disk.
    let (slot_w, _) = take(swap, &mut buf, &mut slots, "take w");
    assert_eq!(
        u64::try_from(stored(&slots, slot_w).len()),
        Ok(CHUNK_LEN),
        "{PHASE}: take w: the bytes of the slot of a raw chunk of noise"
    );
    let m_va = *still
        .first()
        .unwrap_or_else(|| panic!("{PHASE}: no chunk not present after r's restore"));
    assert_eq!(
        make_resident(authority, process, m_va, CHUNK_LEN),
        procmgr_errors::SUCCESS,
        "{PHASE}: MAKE_RESIDENT of the raw chunk at {m_va:#x}"
    );
    assert!(
        chunk_reads_noise(thread, m_va, &ready),
        "{PHASE}: the chunk at {m_va:#x} does not read its noise once made resident"
    );
    assert_eq!(
        disk_and_free(),
        (0, free0.saturating_sub(1)),
        "{PHASE}: w in flight"
    );

    // The fixture's read faults every other chunk back, w's in flight with
    // them, and the write ends cancelled.
    fixture.send("verify");
    let verdict = fixture.line(None, "verify");
    assert_eq!(
        verdict.trim(),
        "ok",
        "{PHASE}: the fixture's verify answered {verdict:?}"
    );
    let absent = absent_chunks(thread, &ready);
    assert!(
        absent.is_empty(),
        "{PHASE}: chunks not present after the fixture read every page: {absent:#x?}"
    );
    assert_eq!(done(swap, slot_w, 0, "done w"), memmgr_errors::SUCCESS);
    assert_eq!(
        (disk_and_free(), pool().swapped),
        ((0, free0), 0),
        "{PHASE}: w's write ended cancelled"
    );
    let written = written_by_swapd(
        authority,
        &mut hog,
        &mut fixture,
        &ready,
        process,
        thread,
        free0,
    );
    detach(authority, process, &threads, "the fixture");

    fixture.send("exit");
    let status = fixture.exit_status();
    assert!(status.success(), "{PHASE}: the fixture exited {status:?}");
    buf.release();
    let slot_map_pages = free0.div_ceil(free_pool::disk::SLOT_WORDS_PER_PAGE);
    let floor = baseline.less(slot_map_pages.saturating_mul(PAGE_SIZE));
    let end = settle_resident(authority, PHASE, Some(&floor));
    std::os::seraph::log!(
        "memmgr_swap_raw phase passed ({raw_count} chunks raw, one written and restored, one \
         cancelled in flight, {written} written by swapd and faulted back, free, deferred and svctest's own {} pages above the start less the \
         {slot_map_pages} slot-map pages)",
        end.saturating_sub(floor.totals) / PAGE_SIZE
    );
}
