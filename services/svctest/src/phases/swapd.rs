// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/swapd.rs

//! swapd's disk tier end to end (services/swapd/README.md,
//! services/swapd/docs/operation.md), beside the real swap service, which
//! registered every slot of the swap partition. svctest acts as a second swap
//! client through the `memmgr.swap` seed, as [`super::swap_client`] does, over a
//! RAM slot store, and reuses `memmgr_swap`'s fixture and hog (`super::swap`),
//! whose failure messages name that phase.
//!
//! Each part first holds the level at `LOW` until memmgr holds chunks of the
//! fixture's main region swapped, and makes every other range of every
//! process resident, so every chunk swapped, and later on disk, is the
//! fixture's.
//!
//! Part A stops swapd's three threads and leaves a write and a restore in
//! flight: a chunk taken for writing and left, and a chunk on disk whose slot
//! holds no seal of it, faulted by the fixture, which the kernel redirects to
//! swapd's endpoint, where it waits. It requires:
//!
//! * no page on disk before the phase writes any, and the chunks it takes for
//!   the two cases found in the fixture's main region;
//! * memmgr serving, with both in flight, a demand fault of svctest's own, a
//!   grant, and a `MAKE_RESIDENT` of logd's whole range, each completing, the
//!   fixture's fault still waiting, and the pages on disk and the free slots
//!   those of the two cases in flight;
//! * a restore of the chunk on disk by svctest itself, and the chunk in flight
//!   returned to RAM by a failed write;
//! * swapd, once its threads run again, receiving the held fault, reading the
//!   chunk's slot, handing memmgr bytes under a slot word that is stale, and
//!   resuming the fault, so the fixture's touch succeeds and no page stays on
//!   disk.
//!
//! Part B lets swapd work. It requires:
//!
//! * at `CRITICAL`, with the hog holding the level there, swapd writing at least
//!   three chunks to disk;
//! * every page of the stacks of swapd, devmgr, virtio-blk, and the IOMMU
//!   driver, when one runs, that read before the hog still reading while it
//!   holds the level at `CRITICAL`: the storage path is never evicted;
//! * the want path: a `MAKE_RESIDENT` of the fixture's main region replying
//!   pending at a chunk on disk, which swapd then restores, the chunk reading
//!   its pattern and one chunk fewer on disk;
//! * swapd killed through the debug authority and restarted by svcmgr, the
//!   chunks on disk unchanged across its death;
//! * the fault path through the next instance: the fixture reading every page
//!   of its main region, each chunk on disk faulted, redirected to swapd, and
//!   restored, and none left on disk.
//!
//! Once the fixture is gone, the phase requires the end of `memmgr_swap`: the
//! store and the swapped total empty, the identity holding, and memmgr's free
//! and deferred pages with svctest's own charged pages at least what they were
//! at the start, less the pages of the swap slot map, which memmgr keeps as
//! its metadata once swapd registered every slot. svcmgr's restart of swapd
//! reads its image through fatfs's cache, which keeps it until a pressure
//! episode, so the phase reads the image into that cache before it takes the
//! start's totals.

use std::os::seraph::current_ipc_buf;
use std::time::{Duration, Instant};

use ipc::{memmgr_errors, procmgr_errors};
use syscall_abi::PAGE_SIZE;

use super::process_kill::{IOMMU_NAME, kill};
use super::swap::{
    CHUNK_LEN, CHUNK_PAGES, Fill, HOG_TICK, Hog, Ready, StackPages, attach, await_swapped,
    baseline_totals, chunk_reads_pattern, detach, main_pages, make_resident, page_present, pool,
    read_stack, require_stack, settle_resident, start_fixture,
};
use super::swap_client::{
    Buffer, Slots, await_normal, disk_and_free, done, isolate, restore, stored, take,
};
use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "swapd",
        run: swapd_phase,
    }]
}

/// The phase's name in its failure messages.
const PHASE: &str = "swapd";

/// The slots swapd registers: the swap partition is 64 MiB of 64 KiB slots.
const SWAP_SLOTS: u64 = 1024;
/// swapd's name in `LIST_PROCESSES`, its recipe's `argv`.
const SWAPD_NAME: &[u8] = b"swapd";
/// swapd's image, which svcmgr's restart of it reads.
const SWAPD_IMAGE: &str = "/services/swapd";
/// The processes of the storage path beside swapd, by their names in
/// `LIST_PROCESSES`: devmgr, which init creates from its boot module, and
/// the block driver, which devmgr creates from its install path.
const STORAGE_NAMES: [&str; 2] = ["devmgr", "/services/drivers/virtio-blk"];
/// Chunks of the fixture's main region each part awaits swapped before it
/// takes or writes any.
const SWAPPED_CHUNKS: u64 = 6;
/// Chunks swapd writes at `CRITICAL` that part B awaits.
const WRITTEN_CHUNKS: u64 = 3;
/// Bytes of the demand fault of svctest's own that part A makes while the
/// two cases are in flight.
const OWN_FAULT_BYTES: usize = 256 * 1024;
/// How long part A waits for the fixture's line, to find none: the fault it
/// asked for is held. A test wait bound.
const HELD_QUIET: Duration = Duration::from_millis(200);
/// How long part B waits for swapd to write chunks out at `CRITICAL`. A test
/// wait bound.
const WRITE_BOUND: Duration = Duration::from_secs(60);
/// How long part B waits for swapd's want thread to restore the chunk
/// `MAKE_RESIDENT` posted. A test wait bound.
const WANT_BOUND: Duration = Duration::from_secs(10);
/// How long the phase waits for svcmgr to restart swapd. A test wait bound.
const RESTART_BOUND: Duration = Duration::from_secs(30);

/// The `[start, start + CHUNK_LEN)` chunk bases of the main region, the hole's
/// chunk excluded.
fn main_chunks(ready: &Ready) -> Vec<u64>
{
    let hole_chunk = ready.hole.saturating_sub(ready.region) / CHUNK_LEN;
    (0..ready.chunks)
        .filter(|&i| i != hole_chunk)
        .map(|i| ready.region.saturating_add(i.saturating_mul(CHUNK_LEN)))
        .collect()
}

/// `MAKE_RESIDENT` of each chunk of the main region in turn, from its start,
/// until one replies pending at a chunk on disk: that chunk's base.
fn first_pending_chunk(authority: u64, process: u64, ready: &Ready) -> Option<u64>
{
    for base in main_chunks(ready)
    {
        let end = base.saturating_add(CHUNK_LEN);
        let mut at = base;
        while at < end
        {
            // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
            let step =
                unsafe { ipc::make_resident_step(authority, process, at, end, current_ipc_buf()) }
                    .unwrap_or_else(|| {
                        panic!("{PHASE}: MAKE_RESIDENT of {at:#x} to {end:#x} failed")
                    });
            if step.pending
            {
                return Some(base);
            }
            assert!(
                step.reached > at,
                "{PHASE}: MAKE_RESIDENT from {at:#x} to {end:#x} stopped at {:#x}",
                step.reached
            );
            at = step.reached;
        }
    }
    None
}

/// Wait until no write is in flight, every slot taken holding a chunk on
/// disk, within [`WRITE_BOUND`].
fn await_writes_ended()
{
    let start = Instant::now();
    loop
    {
        let status = pool();
        let taken = SWAP_SLOTS.saturating_sub(status.free_slots);
        if taken.saturating_mul(CHUNK_LEN) == status.on_disk
        {
            return;
        }
        assert!(
            start.elapsed() < WRITE_BOUND,
            "{PHASE}: {taken} slots taken and {} bytes on disk {WRITE_BOUND:?} after the \
             level fell from CRITICAL",
            status.on_disk
        );
        std::thread::sleep(HOG_TICK);
    }
}

/// Part A: memmgr never waits on storage, with a write and a restore in
/// flight (see the module documentation). Returns the free slots at its start.
fn part_a(
    caps: &Caps,
    hog: &mut Hog,
    fixture: &mut super::swap::Fixture,
    ready: &Ready,
    process: u64,
    swapd: u64,
) -> u64
{
    let authority = caps.debug_authority;
    let swap = caps.memmgr_swap;

    hog.fill_to_low();
    await_swapped(hog, fixture, SWAPPED_CHUNKS * CHUNK_PAGES);
    hog.release_all();
    await_normal();
    let swapped = isolate(authority, process, ready, fixture);
    assert!(
        swapped >= 2 * CHUNK_PAGES,
        "{PHASE}: {swapped} pages of the fixture's main region swapped once isolated"
    );

    // swapd's threads stopped: neither a write nor a restore proceeds.
    let swapd_threads = attach(authority, swapd, "swapd");
    for &thread in &swapd_threads
    {
        syscall::thread_stop(thread)
            .unwrap_or_else(|e| panic!("{PHASE}: stopping a thread of swapd ({e})"));
    }
    let (disk0, free0) = disk_and_free();
    assert_eq!(
        disk0, 0,
        "{PHASE}: {disk0} pages on disk before any take: swapd wrote at NORMAL or LOW"
    );

    // x's write in flight. It is taken first: the walk below that finds y's
    // chunk restores every chunk before it, x's among them when it lies
    // there, which cancels the write but leaves its `SWAP_DONE` owed.
    let mut slots = Slots::new();
    let mut buf = Buffer::new();
    let (slot_x, _) = take(swap, &mut buf, &mut slots, "take x");

    // y on disk, its slot holding no seal of y's.
    let (slot_y, word_y) = take(swap, &mut buf, &mut slots, "take y");
    assert_eq!(done(swap, slot_y, 0, "done y"), memmgr_errors::SUCCESS);
    let bytes_y = stored(&slots, slot_y);

    // y's chunk: the first MAKE_RESIDENT replying pending. swapd's want thread
    // is stopped, so the word it posted is not served.
    let y_va = first_pending_chunk(authority, process, ready)
        .unwrap_or_else(|| panic!("{PHASE}: no chunk of the main region replied pending"));

    // The fixture's fault on y is redirected to swapd's endpoint and waits.
    fixture.send(&format!("touch {y_va:x}"));

    // Both in flight, memmgr serves.
    let mut own = vec![0u8; OWN_FAULT_BYTES];
    for offset in (0..OWN_FAULT_BYTES).step_by(usize::try_from(PAGE_SIZE).unwrap_or(4096))
    {
        if let Some(byte) = own.get_mut(offset)
        {
            *byte = 1;
        }
    }
    std::hint::black_box(&mut own);
    drop(own);
    let (grant, region_id) = crate::phases::memmgr::try_request_contiguous(1)
        .unwrap_or_else(|label| panic!("{PHASE}: a grant replied {label:#x} with swap in flight"));
    crate::phases::memmgr::release_grant(grant, region_id);
    let logd = super::crash::badge_named(authority, b"logd")
        .unwrap_or_else(|| panic!("{PHASE}: LIST_PROCESSES lists no logd"));
    let top = syscall::user_va_top()
        .unwrap_or_else(|e| panic!("{PHASE}: SystemInfoType::UserVaTop failed ({e})"));
    assert_eq!(
        make_resident(authority, logd, 0, top),
        procmgr_errors::SUCCESS,
        "{PHASE}: MAKE_RESIDENT of logd's range with swap in flight"
    );
    let early = fixture.try_line(HELD_QUIET);
    assert!(
        early.is_none(),
        "{PHASE}: the fixture printed {early:?} while its fault was held"
    );
    assert_eq!(
        disk_and_free(),
        (CHUNK_PAGES, free0.saturating_sub(2)),
        "{PHASE}: y on disk and x in flight"
    );

    // svctest restores y itself; x's write failed.
    assert_eq!(
        restore(swap, word_y, &bytes_y, &mut buf, "restore y"),
        (memmgr_errors::SUCCESS, 0)
    );
    assert_eq!(done(swap, slot_x, 1, "done x"), memmgr_errors::SUCCESS);
    buf.release();

    // swapd runs again: it receives the held fault, reads y's slot, hands
    // memmgr the bytes under a stale word, and resumes the fault.
    for &thread in &swapd_threads
    {
        syscall::thread_start(thread)
            .unwrap_or_else(|e| panic!("{PHASE}: starting a thread of swapd ({e})"));
    }
    detach(authority, swapd, &swapd_threads, "swapd");
    let line = fixture.line(None, "touch");
    assert_eq!(
        line.trim(),
        "touched ok",
        "{PHASE}: the fixture's touch of {y_va:#x} answered {line:?}"
    );
    assert_eq!(
        disk_and_free(),
        (0, free0),
        "{PHASE}: pages on disk and free slots after the held fault was served"
    );
    free0
}

/// Part B: write-out, the storage path never evicted, the want path, a
/// restart, and the fault path (see the module documentation). Returns the
/// chunks on disk after the write-out.
fn part_b(
    caps: &Caps,
    hog: &mut Hog,
    fixture: &mut super::swap::Fixture,
    ready: &Ready,
    process: u64,
    stacks: &[(String, StackPages)],
) -> u64
{
    let authority = caps.debug_authority;
    hog.fill_to_low();
    await_swapped(hog, fixture, 4 * CHUNK_PAGES);
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
    for (name, stack) in stacks
    {
        require_stack(authority, stack, name);
    }
    hog.release_from_critical();
    hog.release_all();
    await_normal();
    // Every chunk on disk the fixture's: the others are restored. A write
    // swapd began at CRITICAL may end after the level fell: wait for it.
    let _ = isolate(authority, process, ready, fixture);
    await_writes_ended();
    let disk1 = pool().on_disk;
    assert!(
        disk1 >= CHUNK_LEN,
        "{PHASE}: {disk1} bytes of the fixture's main region on disk once isolated"
    );

    // The want path.
    let threads = attach(authority, process, "the fixture");
    let thread = *threads.first().expect("the attach returned a thread");
    let want = first_pending_chunk(authority, process, ready)
        .unwrap_or_else(|| panic!("{PHASE}: no chunk of the main region replied pending"));
    let start = Instant::now();
    while !(page_present(thread, want) && chunk_reads_pattern(thread, want, ready.region))
    {
        assert!(
            start.elapsed() < WANT_BOUND,
            "{PHASE}: the chunk at {want:#x} was not restored in {WANT_BOUND:?}"
        );
        std::thread::sleep(HOG_TICK);
    }
    assert_eq!(
        pool().on_disk,
        disk1.saturating_sub(CHUNK_LEN),
        "{PHASE}: bytes on disk after the want path restored one chunk"
    );
    detach(authority, process, &threads, "the fixture");

    // A restart.
    let on_disk = pool().on_disk;
    let killed = super::crash::badge_named(authority, SWAPD_NAME)
        .unwrap_or_else(|| panic!("{PHASE}: LIST_PROCESSES lists no swapd"));
    kill(authority, killed, "swapd", PHASE);
    let start = Instant::now();
    while super::crash::badge_named(authority, SWAPD_NAME).is_none_or(|badge| badge == killed)
    {
        assert!(
            start.elapsed() < RESTART_BOUND,
            "{PHASE}: no next swapd instance in {RESTART_BOUND:?}"
        );
        std::thread::sleep(HOG_TICK);
    }
    assert_eq!(
        pool().on_disk,
        on_disk,
        "{PHASE}: bytes on disk across swapd's restart"
    );

    // The fault path through the next instance.
    fixture.send("verify");
    let verdict = fixture.line(None, "verify");
    assert_eq!(
        verdict.trim(),
        "ok",
        "{PHASE}: the fixture's verify answered {verdict:?}"
    );
    assert_eq!(
        pool().on_disk,
        0,
        "{PHASE}: bytes on disk after the fixture read every page"
    );
    on_disk / CHUNK_LEN
}

/// The phase (see the module documentation).
fn swapd_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "{PHASE}: no debug authority");
    assert_ne!(caps.memmgr_swap, 0, "{PHASE}: no memmgr.swap seed");

    // swapd's restart reads its image through fatfs's cache, which keeps it
    // until a pressure episode: read it into the cache before the baseline,
    // so the end finds it there as the start did.
    let image = std::fs::read(SWAPD_IMAGE)
        .unwrap_or_else(|e| panic!("{PHASE}: reading {SWAPD_IMAGE} failed: {e}"));
    drop(std::hint::black_box(image));

    let mut hog = Hog::new();
    let _ = settle_resident(authority, None);
    let baseline = baseline_totals();
    let reserve = pool().reserve_pages();
    let (mut fixture, ready, process) = start_fixture(authority, main_pages(reserve), Fill::Page);

    let swapd = super::crash::badge_named(authority, SWAPD_NAME)
        .unwrap_or_else(|| panic!("{PHASE}: LIST_PROCESSES lists no swapd"));
    let mut stacks = vec![(
        "swapd".to_string(),
        read_stack(authority, SWAPD_NAME, "swapd"),
    )];
    for name in STORAGE_NAMES
    {
        stacks.push((
            name.to_string(),
            read_stack(authority, name.as_bytes(), name),
        ));
    }
    if super::crash::badge_named(authority, IOMMU_NAME.as_bytes()).is_some()
    {
        stacks.push((
            IOMMU_NAME.to_string(),
            read_stack(authority, IOMMU_NAME.as_bytes(), IOMMU_NAME),
        ));
    }

    let free0 = part_a(caps, &mut hog, &mut fixture, &ready, process, swapd);
    let written = part_b(caps, &mut hog, &mut fixture, &ready, process, &stacks);

    fixture.send("exit");
    let status = fixture.exit_status();
    assert!(status.success(), "{PHASE}: the fixture exited {status:?}");
    let slot_map_pages = SWAP_SLOTS.div_ceil(free_pool::disk::SLOT_WORDS_PER_PAGE);
    let floor = baseline.saturating_sub(slot_map_pages.saturating_mul(PAGE_SIZE));
    let end = settle_resident(authority, Some(floor));
    std::os::seraph::log!(
        "swapd phase passed ({free0} slots free at the start, {written} chunks on disk before \
         the restart and every one faulted back through the next instance, free, deferred and \
         svctest's own {} pages above the start less the {slot_map_pages} slot-map pages)",
        end.saturating_sub(floor) / PAGE_SIZE
    );
}
