// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/spill.rs

//! memmgr's disk tier through its spill interface
//! (services/memmgr/docs/ipc-interface.md § Labels 22 to 25), with svctest
//! acting as the swap service over a RAM slot store, through the
//! `memmgr.spill` seed.
//!
//! The phase reuses `memmgr_swap`'s fixture and hog (`super::swap`), whose
//! failure messages name that phase. It first requires the spill labels to
//! refuse a process badge and the spill authority to refuse another label.
//! The hog then holds the level at `LOW` until memmgr holds chunks of the
//! fixture's main region swapped, and is released; with the level back at
//! `NORMAL`, where memmgr evicts nothing, the phase makes every other range
//! of every process resident and requires memmgr's swapped total to be the
//! fixture's, so every chunk `SPILL_TAKE` takes is one of the main region's.
//! It requires:
//!
//! * `SPILL_REGISTER` with an endpoint of the phase's own, and the pool
//!   status's free slots then;
//! * `SPILL_TAKE` and `SPILL_DONE` of three chunks to disk and a fourth left
//!   in flight, the bytes taken looking as ciphertext does (their byte counts'
//!   chi-square over 256 values below [`CHI_SQUARE_BOUND`]), and the pool
//!   status's spilled pages and free slots;
//! * a second `SPILL_REGISTER` ending the write in flight, so its
//!   `SPILL_DONE` is refused, and keeping the chunks on disk;
//! * a `SPILL_RESTORE` of one slot ahead of any fault, and its slot refused
//!   after;
//! * a write in flight that procmgr's `MAKE_RESIDENT` cancels, its
//!   `SPILL_DONE` then freeing its slot, while `MAKE_RESIDENT` passes the two
//!   chunks on disk over: they are the main region's only chunks not present
//!   but the hole's;
//! * the fixture's read of a page of one of them redirected to the phase's
//!   endpoint, restored, and reading its pattern;
//! * the fixture's read of a page of the other, whose slot the phase hands
//!   back with a byte changed, refused by memmgr with the code-12 word of
//!   detail 1, forwarded, and the fixture killed;
//! * and once the fixture is gone, no chunk on disk, every slot free, and the
//!   end of `memmgr_swap`: the store and the swapped total empty, the
//!   identity holding, and memmgr's free and deferred pages at least what
//!   they were at the start.

use std::collections::HashMap;
use std::os::seraph::{current_ipc_buf, startup_info};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use syscall_abi::{
    FAULT_LABEL, FAULT_REDIRECT_WORD, FAULT_REPLY_FORWARD, FAULT_REPLY_RESUME, MAP_READ,
    MAP_WRITABLE, PAGE_SIZE, SyscallError,
};

use super::swap::{
    CHUNK_LEN, CHUNK_PAGES, HOG_TICK, Hog, Ready, attach, await_swapped, baseline_totals, detach,
    listed_badges, main_pages, make_resident, page_present, pool, settle_resident, start_fixture,
};
use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_spill",
        run: spill_phase,
    }]
}

/// The phase's name in its failure messages.
const PHASE: &str = "memmgr_spill";

/// Swap slots the phase registers.
const SLOTS: u64 = 64;
/// Chunks of the main region the phase awaits swapped: three to disk, one in
/// flight, and one more for a chunk the clock's last slice did not reach.
const SWAPPED_CHUNKS: u64 = 5;
/// `SPILL_TAKE`s the phase makes for one chunk at most: each walks a bounded
/// part of memmgr's records, and successive ones cover them all.
const TAKE_TRIES: u32 = 256;
/// Pages of a buffer: a chunk, the most a slot's bytes take.
const BUF_PAGES: u64 = CHUNK_PAGES;
/// The chi-square of a slot's byte counts over 256 values that bytes looking
/// as ciphertext stay below: 255 degrees of freedom, whose mean is 255 and
/// standard deviation about 23, so uniform bytes exceed it with a
/// probability below 10^-20, and a compressed stream of the fixture's pattern
/// lies far above it.
const CHI_SQUARE_BOUND: f64 = 512.0;
/// Bytes of ciphertext the chi-square needs at the least.
const CHI_SQUARE_MIN_BYTES: usize = 8192;
/// The decline word memmgr hands back for a slot that fails authentication:
/// code 12, detail 1.
const LOST_WORD: u64 = 0xC | (1 << 32);
/// How long the restore thread waits for a fault before it looks at its stop
/// flag.
const RESTORER_POLL_MS: u64 = 50;
/// How long the phase waits for the level to return to `NORMAL`, and for
/// memmgr's swapped total to be the fixture's alone. A test wait bound.
const SETTLE_BOUND: Duration = Duration::from_secs(30);
/// How long the phase waits for a fault to reach its endpoint and be served.
/// A test wait bound.
const SERVE_BOUND: Duration = Duration::from_secs(30);

/// A fault the restore thread served: the slot its redirect named, the
/// faulting address, and memmgr's reply to the `SPILL_RESTORE`, its label and
/// word 0.
#[derive(Clone, Copy, Debug)]
struct Served
{
    slot: u32,
    va: u64,
    label: u64,
    word: u64,
}

/// The RAM slot store, the slot whose bytes the restore thread changes, and
/// what it served, shared between the phase and its restore thread.
#[derive(Default)]
struct Shared
{
    slots: Mutex<HashMap<u32, Vec<u8>>>,
    tamper: Mutex<Option<u32>>,
    served: Mutex<Vec<Served>>,
    stop: AtomicBool,
}

/// A buffer of [`BUF_PAGES`] pages: a contiguous grant mapped read-write in
/// svctest, and its cap, which a spill label moves to memmgr and back.
struct Buffer
{
    cap: u64,
    region_id: u64,
    va: u64,
}

impl Buffer
{
    fn new() -> Self
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
    fn release(self)
    {
        // SAFETY: the range is this buffer's own mapping, which nothing else
        // refers to.
        let _ = unsafe { syscall::mem_unmap(startup_info().self_aspace, self.va, BUF_PAGES) };
        crate::phases::memmgr::release_grant(self.cap, self.region_id);
    }
}

/// memmgr's reply to `msg` on the spill authority `spill`, panicking with
/// `what` when the call fails. A cap the reply moves back is the caller's.
fn spill_call(spill: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(spill, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{PHASE}: {what}: ipc_call failed ({e})"))
}

/// `SPILL_REGISTER` with a SEND on `endpoint` and [`SLOTS`] slots.
fn register(spill: u64, endpoint: u64, what: &str)
{
    let send = syscall::cap_derive(endpoint, syscall::RIGHTS_EP_SEND)
        .unwrap_or_else(|e| panic!("{PHASE}: {what}: deriving the restore SEND ({e})"));
    let msg = IpcMessage::builder(memmgr_labels::SPILL_REGISTER)
        .word(0, SLOTS)
        .cap(send)
        .build();
    let reply = spill_call(spill, &msg, what);
    assert_eq!(
        (reply.label, reply.word(0)),
        (memmgr_errors::SUCCESS, SLOTS),
        "{PHASE}: {what}: SPILL_REGISTER replied {:#x} with {} slots",
        reply.label,
        reply.word(0)
    );
}

/// `SPILL_TAKE` into `buf`: the slot and its bytes, kept in the store. A walk
/// that finds no chunk within memmgr's bound replies `NOTHING_TO_SPILL`, and
/// the next goes on from where it stopped, so it is asked again, at most
/// [`TAKE_TRIES`] times.
fn take(spill: u64, buf: &mut Buffer, shared: &Shared, what: &str) -> u32
{
    let mut tries: u32 = 0;
    let reply = loop
    {
        let msg = IpcMessage::builder(memmgr_labels::SPILL_TAKE)
            .cap(buf.cap)
            .build();
        let reply = spill_call(spill, &msg, what);
        buf.cap = *reply
            .caps()
            .first()
            .unwrap_or_else(|| panic!("{PHASE}: {what}: SPILL_TAKE moved no buffer back"));
        tries = tries.saturating_add(1);
        if reply.label != memmgr_errors::NOTHING_TO_SPILL || tries >= TAKE_TRIES
        {
            break reply;
        }
    };
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "{PHASE}: {what}: SPILL_TAKE replied {:#x}",
        reply.label
    );
    let slot = u32::try_from(reply.word(0))
        .unwrap_or_else(|_| panic!("{PHASE}: {what}: slot {:#x}", reply.word(0)));
    let len = usize::try_from(reply.word(1)).unwrap_or(usize::MAX);
    assert!(
        len > 16 && len <= usize::try_from(CHUNK_LEN).unwrap_or(0),
        "{PHASE}: {what}: slot {slot} of {len} bytes"
    );
    let bytes = buf.read(len);
    shared
        .slots
        .lock()
        .expect("the slot store's lock")
        .insert(slot, bytes);
    slot
}

/// `SPILL_DONE` of `slot` with status `status`: memmgr's reply label.
fn done(spill: u64, slot: u32, status: u64, what: &str) -> u64
{
    let msg = IpcMessage::builder(memmgr_labels::SPILL_DONE)
        .word(0, u64::from(slot))
        .word(1, status)
        .build();
    spill_call(spill, &msg, what).label
}

/// `SPILL_RESTORE` of `slot` with its stored bytes, written into `buf`:
/// memmgr's reply label and word 0.
fn restore(spill: u64, slot: u32, buf: &mut Buffer, shared: &Shared, what: &str) -> (u64, u64)
{
    let bytes = shared
        .slots
        .lock()
        .expect("the slot store's lock")
        .get(&slot)
        .cloned()
        .unwrap_or_default();
    buf.write(&bytes);
    let msg = IpcMessage::builder(memmgr_labels::SPILL_RESTORE)
        .word(0, u64::from(slot))
        .cap(buf.cap)
        .build();
    let reply = spill_call(spill, &msg, what);
    buf.cap = *reply
        .caps()
        .first()
        .unwrap_or_else(|| panic!("{PHASE}: {what}: SPILL_RESTORE moved no buffer back"));
    (reply.label, reply.word(0))
}

/// The pages memmgr holds on disk and the slots free, from its pool status.
fn disk_and_free() -> (u64, u64)
{
    let status = pool();
    (status.spilled / PAGE_SIZE, status.free_slots)
}

/// The spill labels refuse svctest's own memmgr SEND, a process badge, with
/// `UNAUTHORIZED`, and the spill authority refuses `QUERY_POOL_STATUS` so.
fn require_refusals(spill: u64)
{
    for label in [
        memmgr_labels::SPILL_REGISTER,
        memmgr_labels::SPILL_TAKE,
        memmgr_labels::SPILL_DONE,
        memmgr_labels::SPILL_RESTORE,
    ]
    {
        let reply = super::swap::memmgr_call(&IpcMessage::new(label), "a spill label");
        assert_eq!(
            reply.label,
            memmgr_errors::UNAUTHORIZED,
            "{PHASE}: spill label {label} on a process badge replied {:#x}",
            reply.label
        );
    }
    let reply = spill_call(
        spill,
        &IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS),
        "QUERY_POOL_STATUS",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::UNAUTHORIZED,
        "{PHASE}: QUERY_POOL_STATUS on the spill authority replied {:#x}",
        reply.label
    );
}

/// The chi-square of `bytes`' counts over the 256 byte values.
fn chi_square(bytes: &[u8]) -> f64
{
    let mut counts = [0u64; 256];
    for &b in bytes
    {
        if let Some(c) = counts.get_mut(usize::from(b))
        {
            *c = c.saturating_add(1);
        }
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "a test statistic over at most a few hundred KiB, well inside f64's exact range"
    )]
    let expected = bytes.len() as f64 / 256.0;
    counts
        .iter()
        .map(|&c| {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a count of at most a few hundred thousand, exact in f64"
            )]
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum()
}

/// Wait for the level to read `NORMAL`, where memmgr evicts nothing.
fn await_normal()
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
/// until memmgr's swapped total is the fixture's own. Returns the fixture's
/// swapped pages then.
fn isolate(authority: u64, process: u64, ready: &Ready, fixture: &mut super::swap::Fixture) -> u64
{
    let top = syscall::user_va_top()
        .unwrap_or_else(|e| panic!("{PHASE}: SystemInfoType::UserVaTop failed ({e})"));
    let region_end = ready
        .region
        .saturating_add(ready.chunks.saturating_mul(CHUNK_LEN));
    let start = Instant::now();
    loop
    {
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
        let total = pool().swapped / PAGE_SIZE;
        if total == node
        {
            return node;
        }
        assert!(
            start.elapsed() < SETTLE_BOUND,
            "{PHASE}: memmgr holds {total} pages swapped, the fixture {node}, after \
             {SETTLE_BOUND:?} of making every other range resident"
        );
        std::thread::sleep(HOG_TICK);
    }
}

/// The restore thread: receive each fault redirected to `endpoint`, hand
/// memmgr its slot's stored bytes, with the first byte changed for the slot
/// [`Shared::tamper`] names, through `buf`, then resume the fault on
/// `SUCCESS` or forward it with memmgr's decline word. Returns the buffer once
/// told to stop.
fn restorer(spill: u64, endpoint: u64, mut buf: Buffer, shared: &Shared) -> Buffer
{
    let ipc_buf = current_ipc_buf();
    while !shared.stop.load(Ordering::Acquire)
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv_timeout(endpoint, ipc_buf, RESTORER_POLL_MS) }
        {
            Ok(msg) => msg,
            Err(e) if e == SyscallError::WouldBlock as i64 => continue,
            Err(e) => panic!("{PHASE}: the restore thread's receive failed ({e})"),
        };
        if msg.label != FAULT_LABEL
        {
            // SAFETY: as above.
            let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_FORWARD), ipc_buf) };
            continue;
        }
        let word = msg.word(FAULT_REDIRECT_WORD);
        let slot = u32::try_from(word & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        let va = msg.word(1);
        let tamper = *shared.tamper.lock().expect("the tamper lock") == Some(slot);
        if tamper
            && let Some(bytes) = shared
                .slots
                .lock()
                .expect("the slot store's lock")
                .get_mut(&slot)
            && let Some(b) = bytes.first_mut()
        {
            *b ^= 1;
        }
        let (label, decline) = restore(spill, slot, &mut buf, shared, "a redirected fault");
        let reply = if label == memmgr_errors::SUCCESS
        {
            IpcMessage::new(FAULT_REPLY_RESUME)
        }
        else
        {
            IpcMessage::builder(FAULT_REPLY_FORWARD)
                .word(0, decline)
                .build()
        };
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        shared.served.lock().expect("the served lock").push(Served {
            slot,
            va,
            label,
            word: decline,
        });
    }
    buf
}

/// Wait until the restore thread has served `n` faults; what it served.
fn await_served(shared: &Shared, n: usize) -> Vec<Served>
{
    let start = Instant::now();
    loop
    {
        let served = shared.served.lock().expect("the served lock").clone();
        if served.len() >= n
        {
            return served;
        }
        assert!(
            start.elapsed() < SERVE_BOUND,
            "{PHASE}: {} faults served of the {n} awaited in {SERVE_BOUND:?}",
            served.len()
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
fn spill_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    let spill = caps.memmgr_spill;
    assert_ne!(authority, 0, "{PHASE}: no debug authority");
    assert_ne!(spill, 0, "{PHASE}: no memmgr.spill seed");
    require_refusals(spill);

    let mut hog = Hog::new();
    let _ = settle_resident(authority, None);
    let baseline = baseline_totals();
    let reserve = pool().reserve_pages();
    let (mut fixture, ready, process) = start_fixture(authority, main_pages(reserve));
    hog.fill_to_low();
    await_swapped(&mut hog, &mut fixture, SWAPPED_CHUNKS * CHUNK_PAGES);
    hog.release_all();
    await_normal();
    let swapped = isolate(authority, process, &ready, &mut fixture);
    assert!(
        swapped >= (SWAPPED_CHUNKS - 1) * CHUNK_PAGES,
        "{PHASE}: {swapped} pages of the fixture's main region swapped once isolated"
    );

    // Registration, with an endpoint of the phase's own.
    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or_else(|| panic!("{PHASE}: a restore endpoint"));
    register(spill, endpoint, "the first registration");
    assert_eq!(
        disk_and_free(),
        (0, SLOTS),
        "{PHASE}: after the registration"
    );
    let shared = Arc::new(Shared::default());
    let restorer_buf = Buffer::new();
    let thread_shared = Arc::clone(&shared);
    let restorer = std::thread::Builder::new()
        .name("spill-restorer".into())
        .spawn(move || restorer(spill, endpoint, restorer_buf, &thread_shared))
        .unwrap_or_else(|e| panic!("{PHASE}: spawning the restore thread: {e}"));

    // Three chunks to disk and one in flight.
    let mut buf = Buffer::new();
    let slot_a = take(spill, &mut buf, &shared, "take a");
    assert_eq!(done(spill, slot_a, 0, "done a"), memmgr_errors::SUCCESS);
    let slot_b = take(spill, &mut buf, &shared, "take b");
    assert_eq!(done(spill, slot_b, 0, "done b"), memmgr_errors::SUCCESS);
    let slot_t = take(spill, &mut buf, &shared, "take t");
    assert_eq!(done(spill, slot_t, 0, "done t"), memmgr_errors::SUCCESS);
    let slot_c = take(spill, &mut buf, &shared, "take c");
    assert_eq!(
        disk_and_free(),
        (3 * CHUNK_PAGES, SLOTS - 4),
        "{PHASE}: three chunks on disk and one in flight"
    );
    let sealed: Vec<u8> = shared
        .slots
        .lock()
        .expect("the slot store's lock")
        .values()
        .flat_map(|bytes| bytes.iter().take(bytes.len().saturating_sub(16)).copied())
        .collect();
    let chi = chi_square(&sealed);
    assert!(
        sealed.len() >= CHI_SQUARE_MIN_BYTES && chi < CHI_SQUARE_BOUND,
        "{PHASE}: {} bytes taken, chi-square {chi:.1}: not ciphertext",
        sealed.len()
    );

    // A second registration ends the write in flight and keeps the chunks on
    // disk.
    register(spill, endpoint, "the second registration");
    assert_eq!(
        done(spill, slot_c, 0, "done c after the registration"),
        memmgr_errors::INVALID_ARGUMENT
    );
    assert_eq!(
        disk_and_free(),
        (3 * CHUNK_PAGES, SLOTS - 3),
        "{PHASE}: after the second registration"
    );

    // A write in flight, and a restore ahead of any fault.
    let slot_d = take(spill, &mut buf, &shared, "take d");
    assert_eq!(
        restore(spill, slot_a, &mut buf, &shared, "restore a"),
        (memmgr_errors::SUCCESS, 0)
    );
    assert_eq!(
        restore(spill, slot_a, &mut buf, &shared, "restore a again").0,
        memmgr_errors::INVALID_ARGUMENT
    );

    // MAKE_RESIDENT restores the chunk in flight and passes the two on disk
    // over: they are the main region's only chunks not present but the hole's.
    let len = ready.chunks.saturating_mul(CHUNK_LEN);
    let label = make_resident(authority, process, ready.region, len);
    assert_eq!(
        label,
        procmgr_errors::SUCCESS,
        "{PHASE}: MAKE_RESIDENT of the main region replied {label:#x}"
    );
    assert_eq!(done(spill, slot_d, 0, "done d"), memmgr_errors::SUCCESS);
    assert_eq!(
        disk_and_free(),
        (2 * CHUNK_PAGES, SLOTS - 2),
        "{PHASE}: after the restores"
    );
    let threads = attach(authority, process, "the fixture");
    let thread = *threads.first().expect("the attach returned a thread");
    let hole_chunk = ready.hole.saturating_sub(ready.region) / CHUNK_LEN;
    let absent: Vec<u64> = (0..ready.chunks)
        .filter(|&i| i != hole_chunk)
        .map(|i| ready.region.saturating_add(i.saturating_mul(CHUNK_LEN)))
        .filter(|&va| !page_present(thread, va))
        .collect();
    detach(authority, process, &threads, "the fixture");
    let [first, second] = absent[..]
    else
    {
        panic!("{PHASE}: chunks of the main region not present: {absent:#x?}, two expected")
    };

    // A fault on a chunk on disk, redirected and restored.
    fixture.send(&format!("touch {first:x}"));
    let line = fixture.line(None, "touch");
    assert_eq!(
        line.trim(),
        "touched ok",
        "{PHASE}: the fixture's first touch"
    );
    let served = await_served(&shared, 1);
    let one = *served.first().expect("one fault served");
    assert!(
        (one.slot == slot_b || one.slot == slot_t)
            && one.va >= first
            && one.va < first.saturating_add(CHUNK_LEN)
            && one.label == memmgr_errors::SUCCESS,
        "{PHASE}: the first redirected fault served as {one:x?}"
    );
    assert_eq!(
        disk_and_free(),
        (CHUNK_PAGES, SLOTS - 1),
        "{PHASE}: after the first fault"
    );

    // A fault on the other, its slot's bytes changed: the fixture is killed.
    let other = if one.slot == slot_b { slot_t } else { slot_b };
    *shared.tamper.lock().expect("the tamper lock") = Some(other);
    fixture.send(&format!("touch {second:x}"));
    let served = await_served(&shared, 2);
    let two = *served.get(1).expect("two faults served");
    assert!(
        two.slot == other && two.label == memmgr_errors::RESTORE_DECLINED && two.word == LOST_WORD,
        "{PHASE}: the tampered fault served as {two:x?}"
    );
    let status = fixture.exit_status();
    assert!(
        !status.success(),
        "{PHASE}: the fixture survived its tampered chunk ({status:?})"
    );
    assert_eq!(
        disk_and_free(),
        (0, SLOTS),
        "{PHASE}: after the fixture's death"
    );

    shared.stop.store(true, Ordering::Release);
    let restorer_buf = restorer
        .join()
        .unwrap_or_else(|_| panic!("{PHASE}: the restore thread panicked"));
    restorer_buf.release();
    buf.release();
    let end = settle_resident(authority, Some(baseline));
    std::os::seraph::log!(
        "memmgr_spill phase passed ({} bytes sealed, chi-square {chi:.1}, free and deferred {} \
         pages above the start)",
        sealed.len(),
        end.saturating_sub(baseline) / PAGE_SIZE
    );
}
