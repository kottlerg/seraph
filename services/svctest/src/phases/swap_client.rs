// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/swap_client.rs

//! memmgr's disk tier through its swap interface
//! (services/memmgr/docs/ipc-interface.md § Labels 22 to 26), with svctest
//! acting as the swap service over a RAM slot store, through the
//! `memmgr.swap` seed.
//!
//! The phase reuses `memmgr_swap`'s fixture and hog (`super::swap`), whose
//! failure messages name that phase. It first requires the swap labels to
//! refuse a process badge and the swap authority to refuse another label.
//! The hog then holds the level at `LOW` until memmgr holds chunks of the
//! fixture's main region swapped, and is released; with the level back at
//! `NORMAL`, where memmgr evicts nothing, the phase makes every other range
//! of every process resident and requires memmgr's swapped total to be the
//! fixture's, so every chunk `SWAP_TAKE` takes is one of the main region's.
//! It requires:
//!
//! * `SWAP_REGISTER` with an endpoint of the phase's own, and the pool
//!   status's free slots then;
//! * `SWAP_TAKE` and `SWAP_DONE` of three chunks to disk, and the pool
//!   status's pages on disk and free slots;
//! * a `SWAP_RESTORE` of one of them ahead of any fault, and its slot word
//!   `RESTORE_STALE` after;
//! * the slot it freed taken again for a fourth chunk, written, and the first
//!   chunk's word and bytes `RESTORE_STALE` there, the fourth staying on disk
//!   and then restored with its own word;
//! * a fifth chunk left in flight, the bytes taken looking as ciphertext does
//!   (their byte counts' chi-square over 256 values below
//!   [`CHI_SQUARE_BOUND`]), and a second `SWAP_REGISTER` ending the write,
//!   so its `SWAP_DONE` is refused, and keeping the chunks on disk;
//! * a second registration with a want Notification, and a fifth chunk taken
//!   and written;
//! * a write in flight that procmgr's `MAKE_RESIDENT` cancels, its
//!   `SWAP_DONE` then freeing its slot, while `MAKE_RESIDENT` of each chunk of
//!   the main region replies pending at each of the three chunks on disk, the
//!   Notification fires, and `SWAP_WANTED` hands over that chunk's slot word
//!   alone, once: the three are the main region's only chunks not present but
//!   the hole's;
//! * `ipc::make_resident` of the fifth chunk returning once a thread of the
//!   phase, woken by the Notification, restored it from `SWAP_WANTED`'s word,
//!   and the chunk reading its pattern; and `ipc::make_resident` of another
//!   chunk on disk, whose word that thread leaves alone, giving up after its
//!   tries with the chunk still not present;
//! * the fixture's read of a page of one of them redirected to the phase's
//!   endpoint, restored, and reading its pattern;
//! * the fixture's read of a page of the other, whose slot the phase hands
//!   back with a byte changed, refused by memmgr with the code-12 word of
//!   detail 1, forwarded, and the fixture killed;
//! * and once the fixture is gone, no chunk on disk, every slot free, and the
//!   end of `memmgr_swap`: the store and the swapped total empty, the
//!   identity holding, and memmgr's free and deferred pages at least what
//!   they were at the start, less the pages of the swap slot map, which
//!   memmgr keeps as its metadata once the takes grew it.

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
        name: "memmgr_swap_client",
        run: swap_client_phase,
    }]
}

/// The phase's name in its failure messages.
const PHASE: &str = "memmgr_swap_client";

/// Swap slots the phase registers.
const SLOTS: u64 = 64;
/// Pages of memmgr's swap slot map the phase's takes can leave at the most:
/// the map grows a page at a time as slots are taken, up to the slots
/// registered, and keeps its pages as memmgr's metadata
/// (services/memmgr/docs/memory-pool.md § Disk tier).
const SLOT_MAP_PAGES: u64 = SLOTS.div_ceil(free_pool::disk::SLOT_WORDS_PER_PAGE);
/// Chunks of the main region the phase awaits swapped: five to disk, one in
/// flight, and one more for a chunk the clock's last slice did not reach.
const SWAPPED_CHUNKS: u64 = 7;
/// The bits memmgr sends on the phase's want Notification.
const WANT_BITS: u64 = 1;
/// How long the phase waits for the want Notification after a `MAKE_RESIDENT`
/// replied pending: memmgr sends on it before it replies, so it has fired. A
/// test wait bound.
const WANT_FIRED_MS: u64 = 1000;
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

/// A fault the restore thread served: the slot its redirect's word named,
/// the faulting address, and memmgr's reply to the `SWAP_RESTORE`, its label
/// and word 0.
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
    /// The slot word the want thread restores when `SWAP_WANTED` hands it
    /// over; every other word it takes, it leaves on disk.
    restore_wanted: Mutex<Option<u64>>,
    /// The words the want thread took from `SWAP_WANTED`.
    wanted: Mutex<Vec<u64>>,
    want_stop: AtomicBool,
}

/// A buffer of [`BUF_PAGES`] pages: a contiguous grant mapped read-write in
/// svctest, and its cap, which a swap label moves to memmgr and back.
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

/// memmgr's reply to `msg` on the swap authority `swap`, panicking with
/// `what` when the call fails. A cap the reply moves back is the caller's.
fn swap_call(swap: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(swap, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{PHASE}: {what}: ipc_call failed ({e})"))
}

/// `SWAP_REGISTER` with a SEND on `endpoint` and [`SLOTS`] slots, and, when
/// `want` names one, a Notify derivation of that Notification memmgr sends
/// [`WANT_BITS`] on when `MAKE_RESIDENT` posts a slot word.
fn register(swap: u64, endpoint: u64, want: Option<u64>, what: &str)
{
    let send = syscall::cap_derive(endpoint, syscall::RIGHTS_EP_SEND)
        .unwrap_or_else(|e| panic!("{PHASE}: {what}: deriving the restore SEND ({e})"));
    let mut msg = IpcMessage::builder(memmgr_labels::SWAP_REGISTER)
        .word(0, SLOTS)
        .word(1, WANT_BITS)
        .cap(send);
    if let Some(ntf) = want
    {
        let notify = syscall::cap_derive(ntf, syscall::RIGHTS_NTF_NOTIFY)
            .unwrap_or_else(|e| panic!("{PHASE}: {what}: deriving the want Notify ({e})"));
        msg = msg.cap(notify);
    }
    let msg = msg.build();
    let reply = swap_call(swap, &msg, what);
    assert_eq!(
        (reply.label, reply.word(0)),
        (memmgr_errors::SUCCESS, SLOTS),
        "{PHASE}: {what}: SWAP_REGISTER replied {:#x} with {} slots",
        reply.label,
        reply.word(0)
    );
}

/// `SWAP_TAKE` into `buf`: the slot and its slot word, the slot's bytes kept
/// in the store. A walk that finds no chunk within memmgr's bound replies
/// `NOTHING_TO_TAKE`, and the next goes on from where it stopped, so it is
/// asked again, at most [`TAKE_TRIES`] times.
fn take(swap: u64, buf: &mut Buffer, shared: &Shared, what: &str) -> (u32, u64)
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
            usize::from(free_pool::disk::word_len(word))
        ),
        (slot, len),
        "{PHASE}: {what}: slot word {word:#x}"
    );
    let bytes = buf.read(len);
    shared
        .slots
        .lock()
        .expect("the slot store's lock")
        .insert(slot, bytes);
    (slot, word)
}

/// The bytes the store holds for `slot`.
fn stored(shared: &Shared, slot: u32) -> Vec<u8>
{
    shared
        .slots
        .lock()
        .expect("the slot store's lock")
        .get(&slot)
        .cloned()
        .unwrap_or_default()
}

/// `SWAP_DONE` of `slot` with status `status`: memmgr's reply label.
fn done(swap: u64, slot: u32, status: u64, what: &str) -> u64
{
    let msg = IpcMessage::builder(memmgr_labels::SWAP_DONE)
        .word(0, u64::from(slot))
        .word(1, status)
        .build();
    swap_call(swap, &msg, what).label
}

/// `SWAP_RESTORE` of the slot word `word` with `bytes`, written into `buf`:
/// memmgr's reply label and word 0.
fn restore(swap: u64, word: u64, bytes: &[u8], buf: &mut Buffer, what: &str) -> (u64, u64)
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

/// `SWAP_WANTED`: the slot words memmgr posted since the last request.
fn wanted(swap: u64, what: &str) -> Vec<u64>
{
    let reply = swap_call(swap, &IpcMessage::new(memmgr_labels::SWAP_WANTED), what);
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "{PHASE}: {what}: SWAP_WANTED replied {:#x}",
        reply.label
    );
    let n = usize::try_from(reply.word(0)).unwrap_or(usize::MAX);
    assert!(
        n <= usize::try_from(memmgr_labels::SWAP_WANTED_WORDS).unwrap_or(0),
        "{PHASE}: {what}: SWAP_WANTED replied {n} words"
    );
    (1..=n).map(|i| reply.word(i)).collect()
}

/// One `MAKE_RESIDENT` of `[va, va + len)` of `process`, through procmgr.
fn resident_step(authority: u64, process: u64, va: u64, len: u64) -> ipc::ResidentStep
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe {
        ipc::make_resident_step(
            authority,
            process,
            va,
            va.saturating_add(len),
            current_ipc_buf(),
        )
    }
    .unwrap_or_else(|| panic!("{PHASE}: MAKE_RESIDENT of the chunk at {va:#x} failed"))
}

/// The want thread: wait on the want Notification `ntf`, take the words
/// memmgr posted with `SWAP_WANTED`, and restore the one
/// [`Shared::restore_wanted`] names from the slot store through `buf`, ahead
/// of any fault. Returns the buffer once told to stop.
fn want_server(swap: u64, ntf: u64, mut buf: Buffer, shared: &Shared) -> Buffer
{
    while !shared.want_stop.load(Ordering::Acquire)
    {
        if syscall::notification_wait_timeout(ntf, RESTORER_POLL_MS).is_err()
        {
            continue;
        }
        let words = wanted(swap, "the want thread's take");
        let restore_word = *shared.restore_wanted.lock().expect("the want lock");
        for &word in &words
        {
            if Some(word) == restore_word
            {
                let bytes = stored(shared, free_pool::disk::word_slot(word));
                let (label, _) = restore(swap, word, &bytes, &mut buf, "a wanted restore");
                assert_eq!(
                    label,
                    memmgr_errors::SUCCESS,
                    "{PHASE}: the want thread's SWAP_RESTORE replied {label:#x}"
                );
            }
        }
        shared.wanted.lock().expect("the want lock").extend(words);
    }
    buf
}

/// `MAKE_RESIDENT` of each chunk of the fixture's main region but the hole's,
/// one request each: a chunk in RAM is made resident, and a chunk on disk is
/// replied pending at its own base, memmgr having sent on `want` and posted its
/// slot word, which `SWAP_WANTED` hands over alone and once. The chunks found
/// on disk, each with its slot word.
fn want_each_chunk(
    authority: u64,
    process: u64,
    swap: u64,
    want: u64,
    ready: &Ready,
) -> Vec<(u64, u64)>
{
    let _ = syscall::notification_try_wait(want);
    let hole_chunk = ready.hole.saturating_sub(ready.region) / CHUNK_LEN;
    let mut on_disk = Vec::new();
    for i in (0..ready.chunks).filter(|&i| i != hole_chunk)
    {
        let va = ready.region.saturating_add(i.saturating_mul(CHUNK_LEN));
        let step = resident_step(authority, process, va, CHUNK_LEN);
        if !step.pending
        {
            assert!(
                step.reached >= va.saturating_add(CHUNK_LEN),
                "{PHASE}: MAKE_RESIDENT of the chunk at {va:#x} stopped at {:#x}",
                step.reached
            );
            continue;
        }
        assert_eq!(
            step.reached, va,
            "{PHASE}: MAKE_RESIDENT of the chunk at {va:#x} pending at another address"
        );
        let bits = syscall::notification_wait_timeout(want, WANT_FIRED_MS);
        assert!(
            bits.is_ok_and(|b| b & WANT_BITS != 0),
            "{PHASE}: the want Notification did not fire for the chunk at {va:#x} ({bits:?})"
        );
        let words = wanted(swap, "SWAP_WANTED after a pending MAKE_RESIDENT");
        let [word] = words[..]
        else
        {
            panic!("{PHASE}: SWAP_WANTED for the chunk at {va:#x} handed over {words:#x?}")
        };
        assert!(
            wanted(swap, "a second SWAP_WANTED").is_empty(),
            "{PHASE}: SWAP_WANTED handed the chunk at {va:#x}'s word over twice"
        );
        on_disk.push((va, word));
    }
    on_disk
}

/// The pages memmgr holds on disk and the slots free, from its pool status.
fn disk_and_free() -> (u64, u64)
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
/// memmgr its slot word and its slot's stored bytes, with the first byte
/// changed for the slot [`Shared::tamper`] names, through `buf`, then resume
/// the fault on `SUCCESS` or `RESTORE_STALE` or forward it with memmgr's
/// decline word. Returns the buffer once told to stop.
fn restorer(swap: u64, endpoint: u64, mut buf: Buffer, shared: &Shared) -> Buffer
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
        let slot = free_pool::disk::word_slot(word);
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
        let bytes = stored(shared, slot);
        let (label, decline) = restore(swap, word, &bytes, &mut buf, "a redirected fault");
        let reply = if label == memmgr_errors::SUCCESS || label == memmgr_errors::RESTORE_STALE
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
    register(swap, endpoint, None, "the first registration");
    assert_eq!(
        disk_and_free(),
        (0, SLOTS),
        "{PHASE}: after the registration"
    );
    let shared = Arc::new(Shared::default());
    let restorer_buf = Buffer::new();
    let thread_shared = Arc::clone(&shared);
    let restorer = std::thread::Builder::new()
        .name("swap-restorer".into())
        .spawn(move || restorer(swap, endpoint, restorer_buf, &thread_shared))
        .unwrap_or_else(|e| panic!("{PHASE}: spawning the restore thread: {e}"));

    // Three chunks to disk.
    let mut buf = Buffer::new();
    let (slot_a, word_a) = take(swap, &mut buf, &shared, "take a");
    assert_eq!(done(swap, slot_a, 0, "done a"), memmgr_errors::SUCCESS);
    let (slot_b, word_b) = take(swap, &mut buf, &shared, "take b");
    assert_eq!(done(swap, slot_b, 0, "done b"), memmgr_errors::SUCCESS);
    let (slot_t, word_t) = take(swap, &mut buf, &shared, "take t");
    assert_eq!(done(swap, slot_t, 0, "done t"), memmgr_errors::SUCCESS);
    assert_eq!(
        disk_and_free(),
        (3 * CHUNK_PAGES, SLOTS - 3),
        "{PHASE}: three chunks on disk"
    );

    // A restore ahead of any fault, and its word stale after.
    let bytes_a = stored(&shared, slot_a);
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
    let (slot_c, word_c) = take(swap, &mut buf, &shared, "take c");
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
        (3 * CHUNK_PAGES, SLOTS - 3),
        "{PHASE}: after a's late restore"
    );
    let bytes_c = stored(&shared, slot_c);
    assert_eq!(
        restore(swap, word_c, &bytes_c, &mut buf, "restore c"),
        (memmgr_errors::SUCCESS, 0)
    );

    // A write in flight.
    let (slot_x, _) = take(swap, &mut buf, &shared, "take x");
    assert_eq!(
        disk_and_free(),
        (2 * CHUNK_PAGES, SLOTS - 3),
        "{PHASE}: two chunks on disk and one in flight"
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
        "{PHASE}: {} bytes taken, chi-square {chi}: not ciphertext",
        sealed.len()
    );

    // A second registration, with a want Notification, ends the write in
    // flight and keeps the chunks on disk.
    let want =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
        .unwrap_or_else(|| panic!("{PHASE}: a want Notification"));
    register(swap, endpoint, Some(want), "the second registration");
    assert_eq!(
        done(swap, slot_x, 0, "done x after the registration"),
        memmgr_errors::INVALID_ARGUMENT
    );
    assert_eq!(
        disk_and_free(),
        (2 * CHUNK_PAGES, SLOTS - 2),
        "{PHASE}: after the second registration"
    );
    let (slot_e, word_e) = take(swap, &mut buf, &shared, "take e");
    assert_eq!(done(swap, slot_e, 0, "done e"), memmgr_errors::SUCCESS);

    // A write in flight for MAKE_RESIDENT to cancel.
    let (slot_d, _) = take(swap, &mut buf, &shared, "take d");

    // MAKE_RESIDENT of each chunk restores the chunk in flight and replies
    // pending at each chunk on disk, whose word alone SWAP_WANTED then hands
    // over: they are the main region's only chunks not present but the hole's.
    let on_disk = want_each_chunk(authority, process, swap, want, &ready);
    assert_eq!(done(swap, slot_d, 0, "done d"), memmgr_errors::SUCCESS);
    assert_eq!(
        disk_and_free(),
        (3 * CHUNK_PAGES, SLOTS - 3),
        "{PHASE}: after the restores"
    );
    let mut words: Vec<u64> = on_disk.iter().map(|&(_, word)| word).collect();
    words.sort_unstable();
    let mut expected = vec![word_b, word_t, word_e];
    expected.sort_unstable();
    assert_eq!(
        words, expected,
        "{PHASE}: the words SWAP_WANTED handed over for the chunks MAKE_RESIDENT found on disk"
    );
    let threads = attach(authority, process, "the fixture");
    let thread = *threads.first().expect("the attach returned a thread");
    let hole_chunk = ready.hole.saturating_sub(ready.region) / CHUNK_LEN;
    let absent = |thread: u64| -> Vec<u64> {
        (0..ready.chunks)
            .filter(|&i| i != hole_chunk)
            .map(|i| ready.region.saturating_add(i.saturating_mul(CHUNK_LEN)))
            .filter(|&va| !page_present(thread, va))
            .collect()
    };
    let mut want_vas: Vec<u64> = on_disk.iter().map(|&(va, _)| va).collect();
    want_vas.sort_unstable();
    assert_eq!(
        absent(thread),
        want_vas,
        "{PHASE}: chunks of the main region not present, against those on disk"
    );

    // The want path end to end: ipc::make_resident of e's chunk returns once
    // the want thread restored it, and of b's gives up, b staying on disk.
    let va_of = |word: u64| {
        on_disk
            .iter()
            .find(|&&(_, w)| w == word)
            .map_or(0, |&(va, _)| va)
    };
    *shared.restore_wanted.lock().expect("the want lock") = Some(word_e);
    let want_shared = Arc::clone(&shared);
    let want_buf = Buffer::new();
    let want_thread = std::thread::Builder::new()
        .name("swap-want".into())
        .spawn(move || want_server(swap, want, want_buf, &want_shared))
        .unwrap_or_else(|e| panic!("{PHASE}: spawning the want thread: {e}"));
    let va_e = va_of(word_e);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let made =
        unsafe { ipc::make_resident(authority, process, va_e, CHUNK_LEN, current_ipc_buf()) };
    assert!(
        made,
        "{PHASE}: ipc::make_resident of e's chunk at {va_e:#x} failed"
    );
    let pattern = super::swap::chunk_reads_pattern(thread, va_e, ready.region);
    assert!(
        pattern,
        "{PHASE}: e's chunk at {va_e:#x}, restored ahead, lacks its pattern"
    );
    let va_b = va_of(word_b);
    // SAFETY: as above.
    let made =
        unsafe { ipc::make_resident(authority, process, va_b, CHUNK_LEN, current_ipc_buf()) };
    assert!(
        !made && !page_present(thread, va_b),
        "{PHASE}: ipc::make_resident of b's chunk at {va_b:#x}, never restored, returned {made}"
    );
    shared.want_stop.store(true, Ordering::Release);
    let want_buf = want_thread
        .join()
        .unwrap_or_else(|_| panic!("{PHASE}: the want thread panicked"));
    want_buf.release();
    assert!(
        shared
            .wanted
            .lock()
            .expect("the want lock")
            .iter()
            .all(|&w| w == word_e || w == word_b),
        "{PHASE}: the want thread was handed a word no MAKE_RESIDENT asked for"
    );
    assert_eq!(
        disk_and_free(),
        (2 * CHUNK_PAGES, SLOTS - 2),
        "{PHASE}: after e's restore ahead"
    );
    let remaining = absent(thread);
    detach(authority, process, &threads, "the fixture");
    let [first, second] = remaining[..]
    else
    {
        panic!("{PHASE}: chunks of the main region not present: {remaining:#x?}, two expected")
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
    let floor = baseline.saturating_sub(SLOT_MAP_PAGES.saturating_mul(PAGE_SIZE));
    let end = settle_resident(authority, Some(floor));
    std::os::seraph::log!(
        "memmgr_swap_client phase passed ({} bytes sealed, chi-square {chi}, free and deferred {} \
         pages above the start less the {SLOT_MAP_PAGES} slot-map pages)",
        sealed.len(),
        end.saturating_sub(floor) / PAGE_SIZE
    );
}
