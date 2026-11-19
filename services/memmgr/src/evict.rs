// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/src/evict.rs

//! Eviction into the compressed store and restore from it
//! (services/memmgr/docs/memory-pool.md § Eviction): the clock's slice each
//! reclaiming turn runs, the compression worker and its job slots, the drain
//! of its completions, and the restore a fault or a make-resident request
//! makes.
//!
//! The receive loop owns the ledger alone. The worker is a raw thread of
//! memmgr that touches no ledger state: it reads a victim chunk through its
//! job slot's input window, which the loop mapped, compresses it into the
//! slot's output buffer, and marks the slot done. A slot's state word orders
//! the hand-offs: the loop writes a job's fields, then publishes it with a
//! release store of [`POSTED`]; the worker reads it after an acquire load and
//! publishes its result with a release store of [`DONE`], which the loop
//! reads after an acquire load. Each side touches a slot's buffer only while
//! the state gives the slot to it.
//!
//! A restore that the free pages do not admit evicts victims itself, in its
//! turn, through the synchronous slot: an input window and an output buffer
//! beside the worker's, and a hash table of its own, so it shares nothing
//! with the worker (services/memmgr/docs/memory-pool.md § Eviction, Direct
//! reclaim).

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicUsize, Ordering};

use free_pool::chunk::{ChunkEntry, ChunkState};
use free_pool::compress::{HASH_ENTRIES, HashTable, PAGE_BYTES};
use free_pool::store::{Decoder, encode_chunk, store_pages};
use free_pool::{
    CHUNK_BYTES, COLD_SWEEPS, ClockHand, DEMAND_CHUNK_PAGES, DemandRegion, Fit, FrameDesc, FreeRun,
    NO_REGION_ID, NodeIdx, PressureLevel, Victim, chunk_for, reserve_pages,
};
use syscall_abi::PAGE_SIZE;

use crate::{
    FaultDecline, FaultTarget, MemLedger, SCRUB_VA, SCRUB_WINDOW_PAGES, coalesce, current_pressure,
    ensure_slots, insert_run, map_client_chunk, map_self, pool_total_pages, quiescent,
    recheck_deferred, release_unmapped_chunk, return_taken, select, self_aspace,
};

/// Job slots of the compression worker: evictions in flight at once.
pub(crate) const JOB_SLOTS: usize = 2;

/// The slot of a restore's synchronous eviction ([`evict_now`]): an input
/// window and an output buffer after the worker's, never posted to it.
const SYNC_SLOT: usize = JOB_SLOTS;

/// Input windows and output buffers: one per job slot, and the synchronous
/// slot's.
const SLOTS: usize = JOB_SLOTS + 1;

/// Victims a restore evicts at most in its turn before it is declined
/// ([`admit_restore`]). A tuning value that bounds the turn's work: each
/// victim kept frees at least one page, and a typical one most of a chunk.
const MAX_SYNC_VICTIMS: usize = 4;

/// Victims the clock's slices keep for a restore's direct reclaim.
const VICTIM_CACHE: usize = 8;

/// Sweeps without an access after which direct reclaim may take a chunk: one,
/// with its pages read once more for an access since ([`accessed_since_sweep`]),
/// so a chunk accessed, or restored, since the last sweep is never taken.
const RECLAIM_IDLE_SWEEPS: u8 = 1;

/// A chunk's pages, as a `u64` and as a `usize`.
const CHUNK_PAGES: u64 = DEMAND_CHUNK_PAGES as u64;
const CHUNK_RUNS: usize = DEMAND_CHUNK_PAGES as usize;

/// Base of memmgr's eviction windows (the zone map in main.rs): the input
/// window of each job slot and of the synchronous slot, a chunk each, then
/// the stream window.
pub(crate) const EVICT_ZONE_VA: u64 = 0x0000_0001_0040_0000;

/// The stream window, where the loop maps a chunk's store runs to write its
/// stream into them or read it back for a restore. A chunk: a stream is
/// stored only when it takes fewer pages than the chunk.
const STREAM_VA: u64 = EVICT_ZONE_VA + SLOTS as u64 * CHUNK_BYTES;

/// Exclusive end of the eviction windows.
pub(crate) const EVICT_ZONE_END: u64 = STREAM_VA + CHUNK_BYTES;

/// Bytes of a job slot's output buffer: a page less than a chunk, since a
/// stream that takes the chunk's pages gains nothing and is not stored.
const OUT_BYTES: usize = (CHUNK_RUNS - 1) * PAGE_BYTES;

/// Steps of one slice of the clock ([`free_pool::Ledger::sweep`]): a chunk
/// swept, or a region or record passed. A tuning value that bounds a turn's
/// work and no capacity: successive slices visit every eligible chunk.
const SWEEP_SLICE_STEPS: u64 = 512;

/// Microseconds from one slice of the clock to the next while memmgr
/// reclaims, so a level eviction cannot bring back to `NORMAL` costs the loop
/// a bounded share of its CPU. A tuning value that bounds no capacity.
const SWEEP_INTERVAL_US: u64 = 10_000;

/// Milliseconds the receive loop waits for a message while it reclaims or a
/// job is in flight, so it drains completions and runs slices when no
/// message arrives.
pub(crate) const RECLAIM_WAIT_MS: u64 = 2;

/// Bytes of the worker's stack, in memmgr's image.
const WORKER_STACK_BYTES: usize = 16 * 1024;

/// A job slot holds no job.
const FREE: u8 = 0;
/// The loop posted the slot's job for the worker.
const POSTED: u8 = 1;
/// The worker finished the slot's job.
const DONE: u8 = 2;

/// The result of a job whose stream does not fit fewer pages than the
/// chunk's backed pages, so storing it gains nothing.
const NO_GAIN: usize = usize::MAX;

/// Each job slot's state: [`FREE`], [`POSTED`] or [`DONE`].
static STATE: [AtomicU8; JOB_SLOTS] = [const { AtomicU8::new(FREE) }; JOB_SLOTS];

/// Each posted job's backed mask, which the worker reads.
static BACKED: [AtomicU16; JOB_SLOTS] = [const { AtomicU16::new(0) }; JOB_SLOTS];

/// Each done job's stream length, or [`NO_GAIN`].
static RESULT: [AtomicUsize; JOB_SLOTS] = [const { AtomicUsize::new(NO_GAIN) }; JOB_SLOTS];

/// Each slot's output buffer: a job slot's is the worker's while the slot is
/// posted and the loop's while it is done; the synchronous slot's is the
/// loop's. Each side reaches only the buffer of the slot it holds
/// ([`out_buf`]), never the array whole.
static mut OUT: [[u8; OUT_BYTES]; SLOTS] = [[0; OUT_BYTES]; SLOTS];

/// The compressor's hash table, the worker's alone.
static mut TABLE: HashTable = [0; HASH_ENTRIES];

/// The synchronous slot's hash table, the loop's alone.
static mut SYNC_TABLE: HashTable = [0; HASH_ENTRIES];

/// The worker's stack.
#[repr(C, align(16))]
struct Stack([u8; WORKER_STACK_BYTES]);

static mut WORKER_STACK: Stack = Stack([0; WORKER_STACK_BYTES]);

/// What the loop keeps of a posted job: the chunk it evicts.
#[derive(Clone, Copy)]
struct Job
{
    rec: NodeIdx,
    reg: NodeIdx,
    page_base: u64,
}

/// The loop's state of eviction: each slot's job, the worker's Notification
/// (0 while no worker runs), the clock's hand, when the last slice ran, and
/// the victims kept for direct reclaim. The loop's alone.
struct Evictor
{
    jobs: [Option<Job>; JOB_SLOTS],
    notify: u64,
    hand: ClockHand,
    last_slice_us: u64,
    cache: [Option<Victim>; VICTIM_CACHE],
}

static mut EVICTOR: Evictor = Evictor {
    jobs: [None; JOB_SLOTS],
    notify: 0,
    hand: ClockHand::START,
    last_slice_us: 0,
    cache: [None; VICTIM_CACHE],
};

#[expect(
    static_mut_refs,
    reason = "`EVICTOR` is reached only through this accessor, by the receive loop, the one \
              thread that touches it, and each caller holds one `&mut` at a time"
)]
fn evictor() -> &'static mut Evictor
{
    // SAFETY: the receive loop is the only thread that reaches `EVICTOR`, and
    // no caller holds the reference across another call of this accessor.
    unsafe { &mut EVICTOR }
}

/// The output buffer of slot `slot`, below [`SLOTS`], reached alone.
fn out_buf(slot: usize) -> *mut [u8; OUT_BYTES]
{
    debug_assert!(slot < SLOTS);
    // A pointer to one element of `OUT`, made with no reference to the
    // array, so the worker's buffer and the loop's never alias.
    addr_of_mut!(OUT)
        .cast::<[u8; OUT_BYTES]>()
        .wrapping_add(slot.min(SLOTS - 1))
}

/// The input window of slot `slot`.
const fn input_va(slot: usize) -> u64
{
    // `slot` is below `SLOTS`, so the window lies in the zone.
    EVICT_ZONE_VA.saturating_add((slot as u64).saturating_mul(CHUNK_BYTES))
}

/// The slot index `slot` as the chunk entry's job slot.
const fn job_id(slot: usize) -> u8
{
    // `slot` is below `SLOTS`.
    slot as u8
}

/// Start the compression worker: retype a pool run into its thread and its
/// Notification, at `ipc::sched_policy::MEMMGR_WORKER_PRIORITY` under
/// memmgr's `SchedControl` cap `sched`, on a stack in memmgr's image. The run
/// leaves the pool for good and stays in `pool_total` as memmgr's metadata.
/// Returns `false` when it cannot; memmgr then evicts nothing.
pub(crate) fn start_worker(l: &mut MemLedger, self_cspace: u64, sched: u64) -> bool
{
    let Ok(thread_bytes) =
        syscall::system_info(syscall_abi::SystemInfoType::ThreadRetypeBytes as u64)
    else
    {
        return false;
    };
    // The thread's debit, and a page for the Notification's, which takes far
    // less.
    let Ok(pages) = u32::try_from(thread_bytes.div_ceil(PAGE_SIZE).saturating_add(1))
    else
    {
        return false;
    };
    let Ok(grant) = select(l, pages, Fit::Contiguous)
    else
    {
        return false;
    };
    let (outer, taken, phys) = grant.entries[0];
    let Ok(notify) = syscall::cap_create_notification(outer)
    else
    {
        return_taken(l, outer, taken, phys);
        return false;
    };
    // A failure from here leaves the run memmgr's, out of circulation: the
    // Notification holds a reference on it.
    let Ok(thread) = syscall::cap_create_thread(
        outer,
        self_aspace(),
        self_cspace,
        sched,
        ipc::sched_policy::MEMMGR_WORKER_PRIORITY,
    )
    else
    {
        return false;
    };
    // The end of the stack static, its top.
    let top = addr_of_mut!(WORKER_STACK)
        .cast::<u8>()
        .wrapping_add(WORKER_STACK_BYTES) as u64;
    // SAFETY: `worker_entry` is an `extern "C" fn(u64) -> !` that never returns;
    // `top` tops a stack static dedicated to the worker, which nothing else
    // uses; no TLS block is set, and the worker reads none.
    let configured =
        unsafe { syscall::thread_configure(thread, worker_entry as *const () as u64, top, notify) };
    if configured.is_err() || syscall::thread_start(thread).is_err()
    {
        return false;
    }
    evictor().notify = notify;
    true
}

/// The worker: wait on its Notification, then run every posted job.
extern "C" fn worker_entry(notify: u64) -> !
{
    loop
    {
        // A failed wait, which none is expected to be, only makes the worker
        // look for posted jobs early.
        let _ = syscall::notification_wait(notify);
        for (slot, state) in STATE.iter().enumerate()
        {
            if state.load(Ordering::Acquire) == POSTED
            {
                compress_job(slot);
                state.store(DONE, Ordering::Release);
            }
        }
    }
}

/// Compress the chunk job slot `slot` names, from its input window into its
/// output buffer, and write its stream's length, or [`NO_GAIN`], as its
/// result.
fn compress_job(slot: usize)
{
    let backed = BACKED.get(slot).map_or(0, |b| b.load(Ordering::Relaxed));
    // SAFETY: the slot is posted, so its output buffer is the worker's alone
    // until it marks the slot done.
    let out = unsafe { &mut *out_buf(slot) };
    // SAFETY: the table is the worker's alone.
    let table = unsafe { &mut *addr_of_mut!(TABLE) };
    // SAFETY: the loop mapped each backed page of the chunk at its offset in
    // the slot's input window before it posted the job, and unmaps it only
    // once the job is done; nothing writes the pages meanwhile, since the
    // process's mappings of them are gone.
    let len = unsafe { compress(backed, input_va(slot), out, table) };
    if let Some(r) = RESULT.get(slot)
    {
        r.store(len, Ordering::Relaxed);
    }
}

/// Compress the chunk whose backed pages, as the mask `backed` names, are
/// mapped at their offsets from `input`, into `out` with the hash table
/// `table`. Returns the stream's length, or [`NO_GAIN`] when it does not
/// take fewer pages than the backed pages.
///
/// # Safety
/// Each backed page of the chunk is mapped readable at its offset from
/// `input`, and nothing writes it until this returns.
unsafe fn compress(
    backed: u16,
    input: u64,
    out: &mut [u8; OUT_BYTES],
    table: &mut HashTable,
) -> usize
{
    // A stream gains only when it takes fewer pages than the chunk's backed
    // pages.
    let limit = (backed.count_ones() as usize)
        .saturating_sub(1)
        .saturating_mul(PAGE_BYTES)
        .min(OUT_BYTES);
    let input = input as *const [u8; PAGE_BYTES];
    out.get_mut(..limit)
        .and_then(|buf| {
            encode_chunk(
                backed,
                // SAFETY: the caller's contract: page `i` is mapped at its
                // offset and nothing writes it.
                |i| unsafe { &*input.wrapping_add(i as usize) },
                buf,
                table,
            )
        })
        .unwrap_or(NO_GAIN)
}

/// Whether a job is in flight, so the loop must wake to drain it.
pub(crate) fn in_flight() -> bool
{
    STATE.iter().any(|s| s.load(Ordering::Relaxed) != FREE)
}

/// Whether memmgr reclaims in the background: the worker runs and the
/// pressure level reads `LOW`. At `CRITICAL` the free pages above the
/// growth floor are gone, so a frame background eviction frees goes to the next
/// admission, which a process draining the pool makes first; there only a
/// restore evicts, for itself ([`admit_restore`];
/// services/memmgr/docs/memory-pool.md § Eviction, Selection).
pub(crate) fn reclaiming() -> bool
{
    evictor().notify != 0 && current_pressure() == PressureLevel::Low
}

/// Whether the clock runs: the worker runs and the pressure level reads
/// `LOW` or `CRITICAL`, so a restore at `CRITICAL` finds victims aged
/// since the level fell.
pub(crate) fn clocking() -> bool
{
    evictor().notify != 0 && current_pressure() != PressureLevel::Normal
}

/// One turn's eviction work, after the turn's message, if any: drain the done
/// jobs, then, while the clock runs and the interval since the last slice has
/// passed, run a slice of it. While memmgr reclaims, the slice finds the cold
/// chunks and posts a job for each, as many as there are free slots;
/// otherwise it finds the chunks idle for [`RECLAIM_IDLE_SWEEPS`]. The rest
/// it finds are kept for direct reclaim ([`keep_victims`]).
pub(crate) fn turn(l: &mut MemLedger)
{
    drain(l);
    if !clocking()
    {
        return;
    }
    let now = syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let ev = evictor();
    if now.saturating_sub(ev.last_slice_us) < SWEEP_INTERVAL_US
    {
        return;
    }
    ev.last_slice_us = now;
    let background = reclaiming();
    let idle = if background
    {
        COLD_SWEEPS
    }
    else
    {
        RECLAIM_IDLE_SWEEPS
    };
    let mut victims = [Victim::default(); JOB_SLOTS + VICTIM_CACHE];
    let found = l.sweep(
        &mut ev.hand,
        SWEEP_SLICE_STEPS,
        |aspace, va, pages, bitmap| syscall::aspace_harvest(aspace, va, pages, bitmap).is_ok(),
        &mut victims,
        idle,
    );
    let mut found = victims.get(..found).unwrap_or(&[]);
    while background
        && let Some((v, rest)) = found.split_first()
        && let Some(slot) = STATE.iter().position(|s| s.load(Ordering::Relaxed) == FREE)
    {
        post(l, v, slot);
        found = rest;
    }
    keep_victims(l, found);
}

/// Whether the victim `v` may still be evicted, as a chunk idle for `idle`
/// sweeps of an eligible region of a process memmgr can unmap.
fn still_victim(l: &MemLedger, v: &Victim, idle: u8) -> bool
{
    l.region_for(v.rec, v.page_base)
        .is_some_and(|(reg, _)| reg == v.reg)
        && l.evictable(v.rec, v.reg)
        && l.aspace_cap(v.rec) != 0
        && l.chunk_at(v.reg, v.page_base).is_idle(idle)
}

/// Keep `found` for direct reclaim: drop the kept victims that may no longer
/// be evicted, then add each of `found` not kept already while there is
/// room.
fn keep_victims(l: &MemLedger, found: &[Victim])
{
    let cache = &mut evictor().cache;
    for kept in cache.iter_mut()
    {
        if kept.is_some_and(|v| !still_victim(l, &v, RECLAIM_IDLE_SWEEPS))
        {
            *kept = None;
        }
    }
    for v in found
    {
        if cache.contains(&Some(*v))
        {
            continue;
        }
        let Some(free) = cache.iter_mut().find(|k| k.is_none())
        else
        {
            break;
        };
        *free = Some(*v);
    }
}

/// Take the kept victim of the greatest age that may still be evicted,
/// dropping each that may not. `None` when none is left.
fn take_victim(l: &MemLedger) -> Option<Victim>
{
    let cache = &mut evictor().cache;
    let mut best: Option<(usize, u8)> = None;
    for (i, kept) in cache.iter_mut().enumerate()
    {
        let Some(v) = *kept
        else
        {
            continue;
        };
        if !still_victim(l, &v, RECLAIM_IDLE_SWEEPS)
        {
            *kept = None;
            continue;
        }
        let age = l.chunk_at(v.reg, v.page_base).age();
        if best.is_none_or(|(_, a)| age > a)
        {
            best = Some((i, age));
        }
    }
    best.and_then(|(i, _)| cache.get_mut(i))
        .and_then(Option::take)
}

/// The runs of the resident or evicting chunk holding `page_base` in region
/// `reg`, copied from its run list, and their count: at most one per page.
fn chunk_runs(l: &MemLedger, reg: NodeIdx, page_base: u64) -> ([FrameDesc; CHUNK_RUNS], usize)
{
    let mut runs = [FrameDesc::default(); CHUNK_RUNS];
    let mut n: usize = 0;
    l.for_each_run(l.chunk_at(reg, page_base), |f| {
        if let Some(slot) = runs.get_mut(n)
        {
            *slot = *f;
            n = n.saturating_add(1);
        }
    });
    (runs, n)
}

/// Map each of `runs` into the process's address space at its address with
/// the region's protection, as the fault that first backed it did
/// ([`map_client_chunk`]); `target` charges nothing for the runs. On a
/// failure, unmap every run of `runs` and return the decline.
fn map_runs(
    l: &mut MemLedger,
    target: &FaultTarget,
    runs: &[FrameDesc],
) -> Result<(), (FaultDecline, u64)>
{
    for run in runs
    {
        if let Err(refusal) = map_client_chunk(l, target, run)
        {
            let _ = unmap_runs(target.aspace_cap, runs);
            return Err(refusal.decline());
        }
    }
    Ok(())
}

/// Unmap each of `runs` from the address space `aspace`, leaving its page
/// tables, so a later map of the runs needs no funding. `false` when an
/// unmap failed.
fn unmap_runs(aspace: u64, runs: &[FrameDesc]) -> bool
{
    runs.iter().fold(true, |ok, run| {
        // SAFETY: `aspace` is a client address space procmgr delegated, never
        // memmgr's own, so the unmap changes nothing memmgr runs on.
        let unmapped =
            unsafe { syscall::mem_unmap(aspace, run.va, u64::from(run.page_count)) }.is_ok();
        ok && unmapped
    })
}

/// The target of a map of runs into the chunk at `page_base` of region
/// `region` of `rec`, whose pages are charged already, holding `held` arena
/// slots for the runs' descriptors.
const fn remap_target(
    rec: NodeIdx,
    aspace_cap: u64,
    region: &DemandRegion,
    page_base: u64,
    held: u64,
) -> FaultTarget
{
    FaultTarget {
        rec,
        aspace_cap,
        prot: region.prot,
        span: (page_base, page_base),
        page_base,
        held,
        committed: None,
        charged: true,
    }
}

/// Evict the cold chunk `v` through job slot `slot`: unmap it and map it
/// at the slot's input window ([`begin`]), then post the job.
fn post(l: &mut MemLedger, v: &Victim, slot: usize)
{
    let Some(job) = begin(l, v, slot, COLD_SWEEPS)
    else
    {
        return;
    };
    let backed = l.chunk_at(job.reg, job.page_base).backed();
    if let Some(j) = evictor().jobs.get_mut(slot)
    {
        *j = Some(job);
    }
    if let (Some(b), Some(s)) = (BACKED.get(slot), STATE.get(slot))
    {
        b.store(backed, Ordering::Relaxed);
        s.store(POSTED, Ordering::Release);
    }
    let _ = syscall::notification_send(evictor().notify, 1);
}

/// Evict the victim `v` now, in the loop's turn, through the synchronous
/// slot (services/memmgr/docs/memory-pool.md § Eviction, Direct reclaim):
/// pass it over when its pages were accessed since the sweep that aged it
/// ([`accessed_since_sweep`]), else unmap it and map it at the slot's input
/// window ([`begin`]), compress it
/// into the slot's buffer, unmap the window, and store the stream
/// ([`store`]), which returns the chunk's runs to the pool. A stream that
/// gains nothing, or a step that fails, maps the chunk back.
fn evict_now(l: &mut MemLedger, v: &Victim)
{
    if accessed_since_sweep(l, v)
    {
        return;
    }
    let Some(job) = begin(l, v, SYNC_SLOT, RECLAIM_IDLE_SWEEPS)
    else
    {
        return;
    };
    let backed = l.chunk_at(job.reg, job.page_base).backed();
    // SAFETY: the synchronous slot's buffer is the loop's alone.
    let out = unsafe { &mut *out_buf(SYNC_SLOT) };
    // SAFETY: the synchronous slot's table is the loop's alone.
    let table = unsafe { &mut *addr_of_mut!(SYNC_TABLE) };
    // SAFETY: `begin` mapped each backed page of the chunk at its offset in
    // the slot's input window, and the process's mappings of them are gone,
    // so nothing writes them until the window is unmapped below.
    let len = unsafe { compress(backed, input_va(SYNC_SLOT), out, table) };
    // SAFETY: the window is memmgr's own zone, mapped for this eviction alone.
    let _ = unsafe { syscall::mem_unmap(self_aspace(), input_va(SYNC_SLOT), CHUNK_PAGES) };
    if len == NO_GAIN || !store(l, &job, SYNC_SLOT, len)
    {
        cancel(l, &job);
    }
}

/// Whether the victim `v`'s chunk was accessed since the sweep that aged it:
/// a kept victim's age is the one the clock's last sweep over it recorded,
/// which may be many turns old, so its pages' accessed bits are read now
/// (`SYS_ASPACE_HARVEST`). The read clears them, so an access it finds is
/// recorded on the chunk at once, its age back to 0
/// ([`free_pool::Ledger::record_access`]). A chunk whose bits cannot be read
/// counts as accessed.
fn accessed_since_sweep(l: &mut MemLedger, v: &Victim) -> bool
{
    let Some((reg, region)) = l
        .region_for(v.rec, v.page_base)
        .filter(|(reg, _)| *reg == v.reg)
    else
    {
        return true;
    };
    let aspace = l.aspace_cap(v.rec);
    let (chunk_base, pages) = chunk_for(&region, v.page_base);
    let mut bitmap = [0u8; 2];
    if aspace == 0
        || syscall::aspace_harvest(aspace, chunk_base, u64::from(pages), &mut bitmap).is_err()
    {
        return true;
    }
    l.record_access(reg, chunk_base, u16::from_le_bytes(bitmap))
}

/// Start evicting the victim `v` through slot `slot`: unmap its runs from
/// the process, mark it evicting, and map its runs at the slot's input
/// window. Returns its job. A chunk no longer idle for `idle` sweeps, or a
/// step that fails, leaves the chunk resident and mapped, and returns
/// `None`.
fn begin(l: &mut MemLedger, v: &Victim, slot: usize, idle: u8) -> Option<Job>
{
    let (reg, region) = l
        .region_for(v.rec, v.page_base)
        .filter(|(reg, _)| *reg == v.reg)?;
    let entry = l.chunk_at(reg, v.page_base);
    let aspace = l.aspace_cap(v.rec);
    if !entry.is_idle(idle) || aspace == 0
    {
        return None;
    }
    let (chunk_base, _) = chunk_for(&region, v.page_base);
    let (runs, n) = chunk_runs(l, reg, v.page_base);
    let runs = runs.get(..n).unwrap_or(&[]);
    let target = remap_target(v.rec, aspace, &region, v.page_base, 0);
    if !unmap_runs(aspace, runs)
        || l.begin_evict(v.rec, reg, v.page_base, job_id(slot))
            .is_err()
    {
        let _ = map_runs(l, &target, runs);
        return None;
    }
    let window = input_va(slot);
    for run in runs
    {
        let at = window.saturating_add(run.va.saturating_sub(chunk_base));
        // SAFETY: the slot's input window is memmgr's own zone (the zone map in
        // main.rs), unmapped while the slot is free, and the run lies in the
        // chunk, so its pages lie in the window.
        if unsafe { map_self(l, run.cap_slot, at, 0, u64::from(run.page_count)) }.is_err()
        {
            // SAFETY: as above; the window holds nothing memmgr runs on.
            let _ = unsafe { syscall::mem_unmap(self_aspace(), window, CHUNK_PAGES) };
            if map_runs(l, &target, runs).is_ok()
            {
                let _ = l.cancel_evict(v.rec, reg, v.page_base);
            }
            return None;
        }
    }
    Some(Job {
        rec: v.rec,
        reg,
        page_base: v.page_base,
    })
}

/// Drain every done job: unmap its input window, then store the chunk's
/// stream and swap the chunk, or, for a stream that gains nothing or a step
/// that fails, map the chunk's runs back and mark it resident. A job whose
/// chunk a fault or a teardown took first is stale, and only frees its slot.
fn drain(l: &mut MemLedger)
{
    for (slot, state) in STATE.iter().enumerate()
    {
        if state.load(Ordering::Acquire) != DONE
        {
            continue;
        }
        // SAFETY: the window is memmgr's own zone, mapped for this job alone.
        let _ = unsafe { syscall::mem_unmap(self_aspace(), input_va(slot), CHUNK_PAGES) };
        let job = evictor().jobs.get_mut(slot).and_then(Option::take);
        let len = RESULT
            .get(slot)
            .map_or(NO_GAIN, |r| r.load(Ordering::Relaxed));
        if let Some(job) = job
            && evicting(l, &job, slot)
            && (len == NO_GAIN || !store(l, &job, slot, len))
        {
            cancel(l, &job);
        }
        state.store(FREE, Ordering::Release);
    }
}

/// Whether `job`'s chunk is still evicting under job slot `slot`, in a region
/// of its record.
fn evicting(l: &MemLedger, job: &Job, slot: usize) -> bool
{
    l.region_for(job.rec, job.page_base)
        .is_some_and(|(reg, _)| reg == job.reg)
        && l.chunk_at(job.reg, job.page_base).job() == Some(job_id(slot))
}

/// Map the evicting chunk of `job` back into its process and mark it
/// resident. When the map fails the chunk stays evicting, so a later fault on
/// it maps it again: a resident chunk is always mapped.
fn cancel(l: &mut MemLedger, job: &Job)
{
    let Some((reg, region)) = l.region_for(job.rec, job.page_base)
    else
    {
        return;
    };
    let aspace = l.aspace_cap(job.rec);
    let (runs, n) = chunk_runs(l, reg, job.page_base);
    let target = remap_target(job.rec, aspace, &region, job.page_base, 0);
    if map_runs(l, &target, runs.get(..n).unwrap_or(&[])).is_ok()
    {
        let _ = l.cancel_evict(job.rec, reg, job.page_base);
    }
}

/// Store the stream of `len` bytes slot `slot` holds for `job`'s chunk:
/// take its store pages from the pool, write the stream into them through the
/// stream window, and swap the chunk onto them
/// ([`free_pool::Ledger::finish_evict`]), which returns the chunk's runs to
/// the pool. `false` when a step fails, every store run taken back in the
/// pool.
fn store(l: &mut MemLedger, job: &Job, slot: usize, len: usize) -> bool
{
    let pages = store_pages(len);
    let mut runs = [FreeRun::default(); CHUNK_RUNS];
    let mut n: usize = 0;
    let mut taken: u64 = 0;
    // The slots the store runs take on the chunk's entry, first.
    let mut ok = ensure_slots(l, pages);
    while ok && taken < pages
    {
        // At most a chunk's pages.
        let want = u32::try_from(pages.saturating_sub(taken)).unwrap_or(0);
        let Ok(grant) = select(l, want, Fit::UpTo)
        else
        {
            ok = false;
            break;
        };
        let (cap_slot, got, phys_base) = grant.entries[0];
        let Some(r) = runs.get_mut(n)
        else
        {
            return_taken(l, cap_slot, got, phys_base);
            ok = false;
            break;
        };
        *r = FreeRun {
            cap_slot,
            page_count: u64::from(got),
            phys_base,
        };
        n = n.saturating_add(1);
        taken = taken.saturating_add(u64::from(got));
    }
    let runs = runs.get(..n).unwrap_or(&[]);
    if ok
        && write_stream(l, runs, slot, len)
        && l.finish_evict(
            job.rec,
            job.reg,
            job.page_base,
            job_id(slot),
            runs,
            quiescent,
        )
        .is_ok()
    {
        return true;
    }
    for run in runs
    {
        insert_run(l, *run);
    }
    false
}

/// Write the first `len` bytes of slot `slot`'s output buffer into the
/// store runs `runs`, in order, through the stream window.
fn write_stream(l: &mut MemLedger, runs: &[FreeRun], slot: usize, len: usize) -> bool
{
    let Some(pages) = map_stream(l, runs)
    else
    {
        return false;
    };
    // SAFETY: the slot is done, or is the synchronous slot, so its output
    // buffer is the loop's.
    let out = unsafe { &*out_buf(slot) };
    let room = usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(0);
    let src = out.get(..len).filter(|src| src.len() <= room);
    if let Some(src) = src
    {
        // SAFETY: `map_stream` mapped `pages` pages read-write at the stream
        // window, which nothing else refers to, and `src` fits them.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), STREAM_VA as *mut u8, src.len());
        }
    }
    unmap_stream(pages);
    src.is_some()
}

/// Map `runs` in order at the stream window. Returns their pages, or `None`,
/// nothing left mapped, when they do not fit the window or a map fails.
fn map_stream(l: &mut MemLedger, runs: &[FreeRun]) -> Option<u64>
{
    let mut at: u64 = 0;
    for run in runs
    {
        let end = at.saturating_add(run.page_count);
        let va = STREAM_VA.saturating_add(at.saturating_mul(PAGE_SIZE));
        // SAFETY: the stream window is memmgr's own zone, which every use
        // leaves unmapped, and the check keeps the run inside it.
        if end > CHUNK_PAGES || unsafe { map_self(l, run.cap_slot, va, 0, run.page_count) }.is_err()
        {
            unmap_stream(CHUNK_PAGES);
            return None;
        }
        at = end;
    }
    Some(at)
}

/// Unmap the first `pages` pages of the stream window.
fn unmap_stream(pages: u64)
{
    if pages > 0
    {
        // SAFETY: the stream window is memmgr's own zone.
        let _ = unsafe { syscall::mem_unmap(self_aspace(), STREAM_VA, pages) };
    }
}

/// Make the chunk holding `page_base` in region `reg` of `rec` resident, for a
/// fault on it or a make-resident request: an evicting chunk's runs are
/// mapped back and its job made stale; a compressed or writing chunk is restored
/// from its store runs ([`restore`]), a writing one's write cancelled. A
/// chunk in another state needs nothing here: one on disk or lost is routed by
/// the caller before ([`free_pool::fault_path`]).
///
/// # Errors
/// The [`FaultDecline`] and its detail word.
pub(crate) fn make_resident(
    l: &mut MemLedger,
    rec: NodeIdx,
    reg: NodeIdx,
    region: &DemandRegion,
    page_base: u64,
    aspace: u64,
) -> Result<(), (FaultDecline, u64)>
{
    match l.chunk_at(reg, page_base).state()
    {
        ChunkState::Evicting =>
        {
            let (runs, n) = chunk_runs(l, reg, page_base);
            let target = remap_target(rec, aspace, region, page_base, 0);
            map_runs(l, &target, runs.get(..n).unwrap_or(&[]))?;
            let _ = l.cancel_evict(rec, reg, page_base);
            Ok(())
        }
        ChunkState::Compressed | ChunkState::Writing =>
        {
            restore(l, rec, reg, region, page_base, aspace, None)
        }
        // A chunk on disk or lost is the caller's to route first
        // (`free_pool::fault_path`): memmgr cannot read a swap slot.
        ChunkState::Unbacked | ChunkState::Resident | ChunkState::OnDisk | ChunkState::Lost =>
        {
            Ok(())
        }
    }
}

/// Return each of `runs`, mapped nowhere, to the free pool.
fn give_back(l: &mut MemLedger, runs: &[FrameDesc])
{
    for run in runs
    {
        insert_run(
            l,
            FreeRun {
                cap_slot: run.cap_slot,
                page_count: u64::from(run.page_count),
                phys_base: run.phys_base,
            },
        );
    }
}

/// Restore the compressed, writing or on-disk chunk holding `page_base` in
/// region `reg` of `rec` from its stream: `stream`, the bytes a swap slot
/// held opened, for a chunk on disk (`crate::disk`), else its store runs
/// (services/memmgr/docs/memory-pool.md § Eviction, States): admitted when the
/// free pages outside `promised` cover its backed pages and, for a node outside
/// it, the system reserve, once direct reclaim has made room when needed
/// ([`admit_restore`]); then runs covering exactly its backed pages, each
/// filled whole through the scrub window from the stream, mapped into the
/// process, and the chunk resident on them, its store back in the pool. The
/// chunk's pages are charged already.
///
/// # Errors
/// [`FaultDecline::NoFreePage`] when the restore is not admitted or the pool
/// runs out, [`FaultDecline::NoArenaSlot`] when the arena cannot grow for the
/// runs' descriptors, [`FaultDecline::MapFailed`] when a map fails or the stream
/// is malformed (detail 0), and [`FaultDecline::FrameRecord`] when the ledger
/// refuses the runs. The chunk then stays as it was.
pub(crate) fn restore(
    l: &mut MemLedger,
    rec: NodeIdx,
    reg: NodeIdx,
    region: &DemandRegion,
    page_base: u64,
    aspace: u64,
    stream: Option<&[u8]>,
) -> Result<(), (FaultDecline, u64)>
{
    let backed = l.chunk_at(reg, page_base).backed();
    if !admit_restore(l, rec, u64::from(backed.count_ones()))
    {
        return Err((FaultDecline::NoFreePage, 0));
    }
    // Read after the admission, whose direct reclaim changes the chunk
    // tables: the chunk itself stays compressed, since it is no victim.
    let entry = l.chunk_at(reg, page_base);
    let (chunk_base, _) = chunk_for(region, page_base);
    let mut runs = [FrameDesc::default(); CHUNK_RUNS];
    let n = select_restore_runs(l, backed, chunk_base, &mut runs)?;
    let runs = runs.get(..n).unwrap_or(&[]);
    // The runs' descriptors on the chunk's entry.
    let held = u64::try_from(n).unwrap_or(u64::MAX);
    if !ensure_slots(l, held)
    {
        give_back(l, runs);
        return Err((FaultDecline::NoArenaSlot, 0));
    }
    let filled = match stream
    {
        Some(stream) => decode_runs(l, stream, runs),
        None => fill_runs(l, entry, runs),
    };
    if let Err(e) = filled
    {
        give_back(l, runs);
        return Err(e);
    }
    let target = remap_target(rec, aspace, region, page_base, held);
    if let Err(e) = map_runs(l, &target, runs)
    {
        // A run the failed map left mapped may still be: each goes back
        // through the unmap that keeps it on the record when it fails.
        for run in runs
        {
            release_unmapped_chunk(l, rec, aspace, *run);
        }
        return Err(e);
    }
    if l.restore_chunk(rec, reg, page_base, runs).is_err()
    {
        for run in runs
        {
            release_unmapped_chunk(l, rec, aspace, *run);
        }
        return Err((FaultDecline::FrameRecord, 0));
    }
    Ok(())
}

/// Whether a restore of `pages` pages for `rec` is admitted: the free pages
/// outside `promised` cover them and, for a budget node outside the reserve,
/// the system reserve, but not the restore headroom that growth leaves for
/// restores (`free_pool::growth_floor`). When they do not, after the turn's deferred recheck,
/// memmgr reclaims directly (services/memmgr/docs/memory-pool.md § Eviction,
/// Direct reclaim): it evicts the kept victims of greatest age now, one by
/// one ([`evict_now`]), until the restore is admitted or
/// [`MAX_SYNC_VICTIMS`] have been tried.
fn admit_restore(l: &mut MemLedger, rec: NodeIdx, pages: u64) -> bool
{
    let reserve = if l.budget(rec).is_some_and(|b| b.reserve())
    {
        0
    }
    else
    {
        reserve_pages(pool_total_pages())
    };
    let fits = |l: &MemLedger| l.uncommitted_free() >= pages.saturating_add(reserve);
    if fits(l)
    {
        return true;
    }
    if recheck_deferred(l) != 0
    {
        coalesce(l);
    }
    let mut tried: usize = 0;
    while !fits(l) && tried < MAX_SYNC_VICTIMS
    {
        let Some(v) = take_victim(l)
        else
        {
            return false;
        };
        evict_now(l, &v);
        tried = tried.saturating_add(1);
    }
    fits(l)
}

/// Select runs covering exactly the pages the mask `backed` names of the chunk
/// at `chunk_base`, span by span, none over an unbacked page, into `runs`, each
/// with its address. Returns their count.
///
/// # Errors
/// [`FaultDecline::NoFreePage`] when the pool runs out; every run taken goes
/// back to it.
fn select_restore_runs(
    l: &mut MemLedger,
    backed: u16,
    chunk_base: u64,
    runs: &mut [FrameDesc; CHUNK_RUNS],
) -> Result<usize, (FaultDecline, u64)>
{
    let is_backed = |page: u32| backed.checked_shr(page).is_some_and(|b| b & 1 != 0);
    let mut n: usize = 0;
    let mut page: u32 = 0;
    while page < DEMAND_CHUNK_PAGES
    {
        if !is_backed(page)
        {
            page = page.saturating_add(1);
            continue;
        }
        let mut end = page;
        while end < DEMAND_CHUNK_PAGES && is_backed(end)
        {
            end = end.saturating_add(1);
        }
        while page < end
        {
            let grant = select(l, end.saturating_sub(page), Fit::UpTo);
            let (Ok(grant), Some(slot)) = (grant, runs.get_mut(n))
            else
            {
                give_back(l, runs.get(..n).unwrap_or(&[]));
                return Err((FaultDecline::NoFreePage, 0));
            };
            let (cap_slot, got, phys_base) = grant.entries[0];
            *slot = FrameDesc {
                cap_slot,
                page_count: got,
                phys_base,
                va: chunk_base.saturating_add(u64::from(page).saturating_mul(PAGE_SIZE)),
                region_id: NO_REGION_ID,
            };
            n = n.saturating_add(1);
            page = page.saturating_add(got);
        }
    }
    Ok(n)
}

/// The store runs of the compressed or writing chunk `entry`, in stream order,
/// into `store`. Returns their count.
fn store_runs(l: &MemLedger, entry: ChunkEntry, store: &mut [FreeRun; CHUNK_RUNS]) -> usize
{
    let mut n: usize = 0;
    l.for_each_store_run(entry, |r| {
        if let Some(slot) = store.get_mut(n)
        {
            *slot = *r;
            n = n.saturating_add(1);
        }
    });
    n
}

/// Copy the stream of the compressed chunk `entry`, its store runs' pages whole,
/// into `dst`, through the stream window, for its write (`crate::disk`).
/// Returns the bytes copied, or `None`, nothing copied, when a map fails or
/// they do not fit `dst`.
pub(crate) fn read_store(l: &mut MemLedger, entry: ChunkEntry, dst: &mut [u8]) -> Option<usize>
{
    let mut store = [FreeRun::default(); CHUNK_RUNS];
    let n = store_runs(l, entry, &mut store);
    let pages = map_stream(l, store.get(..n).unwrap_or(&[]))?;
    let bytes = usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(usize::MAX);
    let copied = dst.get_mut(..bytes).map(|dst| {
        // SAFETY: `map_stream` mapped `pages` pages at the stream window, which
        // nothing writes while the stream is read, and `dst` is memmgr's own
        // buffer of that length.
        unsafe {
            core::ptr::copy_nonoverlapping(STREAM_VA as *const u8, dst.as_mut_ptr(), bytes);
        }
        bytes
    });
    unmap_stream(pages);
    copied
}

/// Write every byte of every page of `runs`, in page order, from the stream of
/// the compressed or writing chunk `entry`, its store runs mapped at the stream
/// window meanwhile ([`decode_runs`]).
///
/// # Errors
/// As [`decode_runs`], and [`FaultDecline::MapFailed`] (detail 0) when the
/// store runs cannot be mapped.
fn fill_runs(
    l: &mut MemLedger,
    entry: ChunkEntry,
    runs: &[FrameDesc],
) -> Result<(), (FaultDecline, u64)>
{
    let mut store = [FreeRun::default(); CHUNK_RUNS];
    let n = store_runs(l, entry, &mut store);
    let Some(pages) = map_stream(l, store.get(..n).unwrap_or(&[]))
    else
    {
        return Err((FaultDecline::MapFailed, 0));
    };
    let bytes = usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(0);
    // SAFETY: `map_stream` mapped `pages` pages at the stream window, which
    // nothing writes while the stream is read; the empty stream maps none, and
    // a slice of no bytes reads nothing.
    let stream = unsafe { core::slice::from_raw_parts(STREAM_VA as *const u8, bytes) };
    let result = decode_runs(l, stream, runs);
    unmap_stream(pages);
    result
}

/// Write every byte of every page of `runs`, in page order, from `stream`:
/// each run mapped at the scrub window, its pages decoded there, a zero page
/// zero-filled, and unmapped.
///
/// # Errors
/// [`FaultDecline::MapFailed`]: a map failed (its error's magnitude the
/// detail), or the stream is malformed (detail 0).
fn decode_runs(
    l: &mut MemLedger,
    stream: &[u8],
    runs: &[FrameDesc],
) -> Result<(), (FaultDecline, u64)>
{
    let mut reader = Decoder::new(stream);
    let mut result = Ok(());
    for run in runs
    {
        let count = u64::from(run.page_count);
        // A run covers at most a chunk, which the scrub window holds.
        debug_assert!(count <= SCRUB_WINDOW_PAGES);
        // SAFETY: the scrub window is memmgr's own zone, which every use
        // leaves unmapped.
        if let Err(e) = unsafe { map_self(l, run.cap_slot, SCRUB_VA, 0, count) }
        {
            result = Err((FaultDecline::MapFailed, e.unsigned_abs()));
            break;
        }
        let decoded = (0..count).try_for_each(|p| {
            // SAFETY: page `p` of the run is mapped read-write in the scrub
            // window, and nothing else refers to it.
            let page = unsafe {
                &mut *(SCRUB_VA.saturating_add(p.saturating_mul(PAGE_SIZE))
                    as *mut [u8; PAGE_BYTES])
            };
            reader.next_page(page)
        });
        // SAFETY: the span is the scrub window mapped above. The unmap is
        // inline assembly without `nomem`, so the decoded stores are made before
        // it.
        let _ = unsafe { syscall::mem_unmap(self_aspace(), SCRUB_VA, count) };
        if decoded.is_err()
        {
            result = Err((FaultDecline::MapFailed, 0));
            break;
        }
    }
    result
}
