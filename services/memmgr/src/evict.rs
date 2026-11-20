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
use free_pool::store::{Decoder, PageReader, RawPages, encode_chunk, store_pages};
use free_pool::{
    CHUNK_BYTES, COLD_SWEEPS, ClockHand, DEMAND_CHUNK_PAGES, DemandRegion, Fit, FrameDesc, FreeRun,
    NO_REGION_ID, NodeIdx, PressureLevel, Victim, band, chunk_for, reserve_pages,
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

/// Whether memmgr reclaims in the background: the worker runs, and the
/// pressure level reads `LOW` or memmgr evicts for frames ([`frames_short`]).
/// Otherwise at `CRITICAL` the free pages above the growth floor are gone,
/// so a frame background eviction frees goes to the next admission, which a
/// process draining the pool makes first; there only a restore or a committed
/// draw evicts, for itself ([`admit_restore`], [`draw_room`];
/// services/memmgr/docs/memory-pool.md § Eviction, Selection).
fn reclaiming(l: &MemLedger) -> bool
{
    evictor().notify != 0 && (current_pressure() == PressureLevel::Low || frames_short(l))
}

/// Whether memmgr evicts in the background for free frames
/// ([`free_pool::Ledger::frames_short`]): the free pool does not cover
/// `promised`, and its free frames stand at or below the growth floor and
/// the hysteresis band, or a demand chunk when the band is less, so the
/// eviction opens the draw room (`ipc::memmgr_labels::QUERY_POOL_STATUS`
/// `data[16]`). The frames then go to the committed draws, which
/// `promised` keeps them for, and to the restores, and not to the next
/// admission, so eviction runs at `CRITICAL` too, and any evictable idle
/// chunk is a victim.
fn frames_short(l: &MemLedger) -> bool
{
    let total = pool_total_pages();
    l.frames_short(
        l.growth_floor(total),
        band(total).max(u64::from(DEMAND_CHUNK_PAGES)),
    )
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
/// chunks and posts a job for each whose eviction raises the free pages
/// outside `promised`, or for each while it evicts for frames, as many as
/// there are free slots;
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
    let background = reclaiming(l);
    let frames = background && frames_short(l);
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
    // While memmgr reclaims, each victim whose eviction raises the free pages
    // outside `promised`, or any while it evicts for frames, takes a free job
    // slot; the rest are kept.
    let mut kept = [Victim::default(); JOB_SLOTS + VICTIM_CACHE];
    let mut n: usize = 0;
    for v in victims.get(..found).unwrap_or(&[])
    {
        if background
            && (frames || l.evicting_frees(v.reg))
            && let Some(slot) = STATE.iter().position(|s| s.load(Ordering::Relaxed) == FREE)
        {
            post(l, v, slot);
            continue;
        }
        if let Some(k) = kept.get_mut(n)
        {
            *k = *v;
            n = n.saturating_add(1);
        }
    }
    keep_victims(l, kept.get(..n).unwrap_or(&[]));
}

/// What a victim's eviction is for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need
{
    /// The free pages outside `promised`: background eviction and an
    /// uncommitted restore's direct reclaim, whose victims must raise them.
    Free,
    /// Free pages alone: a committed draw, which takes any evictable victim.
    Frames,
}

/// Whether the victim `v` may still be evicted, as a chunk idle for `idle`
/// sweeps of an eligible region of a process memmgr can unmap, and, unless
/// `need` is [`Need::Frames`], whether evicting it raises the free pages
/// outside `promised` ([`free_pool::Ledger::evicting_frees`]).
fn still_victim(l: &MemLedger, v: &Victim, idle: u8, need: Need) -> bool
{
    l.region_for(v.rec, v.page_base)
        .is_some_and(|(reg, _)| reg == v.reg)
        && l.evictable(v.rec, v.reg)
        && (need == Need::Frames || l.evicting_frees(v.reg))
        && l.aspace_cap(v.rec) != 0
        && l.chunk_at(v.reg, v.page_base).is_idle(idle)
}

/// Keep `found` for direct reclaim: drop the kept victims that may no longer
/// be evicted, then add each of `found` not kept already while there is
/// room. A victim whose eviction raises the free pages outside `promised`
/// ([`Need::Free`]) takes the place of a kept one only a committed draw may
/// take when there is none, so committed victims never crowd out those an
/// uncommitted restore needs.
fn keep_victims(l: &MemLedger, found: &[Victim])
{
    let cache = &mut evictor().cache;
    for kept in cache.iter_mut()
    {
        if kept.is_some_and(|v| !still_victim(l, &v, RECLAIM_IDLE_SWEEPS, Need::Frames))
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
        let frees = l.evicting_frees(v.reg);
        let slot = cache.iter().position(Option::is_none).or_else(|| {
            frees
                .then(|| {
                    cache
                        .iter()
                        .position(|k| k.is_some_and(|k| !l.evicting_frees(k.reg)))
                })
                .flatten()
        });
        if let Some(k) = slot.and_then(|i| cache.get_mut(i))
        {
            *k = Some(*v);
        }
    }
}

/// Take the kept victim of the greatest age that may still be evicted,
/// dropping each that may not, for `need` ([`still_victim`]); one that
/// only a committed draw may take is kept for one. `None` when none is left.
fn take_victim(l: &MemLedger, need: Need, spare: Option<(NodeIdx, u64)>) -> Option<Victim>
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
        if !still_victim(l, &v, RECLAIM_IDLE_SWEEPS, Need::Frames)
        {
            *kept = None;
            continue;
        }
        if !still_victim(l, &v, RECLAIM_IDLE_SWEEPS, need) || spared(l, &v, spare)
        {
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

/// Whether `v` is the chunk at `spare`, a region and the base of a chunk of
/// it: the chunk a committed fault backs, which its own draw must not evict.
fn spared(l: &MemLedger, v: &Victim, spare: Option<(NodeIdx, u64)>) -> bool
{
    spare.is_some_and(|(reg, base)| {
        reg == v.reg
            && l.region_for(v.rec, v.page_base)
                .is_some_and(|(_, region)| chunk_for(&region, v.page_base).0 == base)
    })
}

/// The runs of the resident, evicting or raw chunk holding `page_base` in region
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
/// `reg`, `region`, of `rec`, whose pages are charged already, holding
/// `held` arena slots for the runs' descriptors. A committed region's
/// commitment is named, so a page-table donation the map needs draws from its
/// reservation, and the arena's growth from its metadata bound, as its faults'
/// do (services/memmgr/docs/memory-pool.md § Commit, Faults).
fn remap_target(
    l: &MemLedger,
    rec: NodeIdx,
    aspace_cap: u64,
    (reg, region): (NodeIdx, &DemandRegion),
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
        committed: l.is_committed(reg).then_some(reg),
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
/// gains nothing keeps the chunk raw while the disk tier takes one
/// ([`keep_raw`]); otherwise, or when a step fails, the chunk is mapped back.
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
    if !finish(l, &job, SYNC_SLOT, len)
    {
        cancel(l, &job);
    }
}

/// End the eviction of `job`'s chunk through slot `slot`, whose stream is
/// `len` bytes or [`NO_GAIN`]: store the stream ([`store`]), or keep a chunk
/// whose stream gains nothing raw ([`keep_raw`]). `false` when neither is
/// done, the chunk still evicting for the caller to map back.
fn finish(l: &mut MemLedger, job: &Job, slot: usize, len: usize) -> bool
{
    if len == NO_GAIN
    {
        keep_raw(l, job, slot)
    }
    else
    {
        store(l, job, slot, len)
    }
}

/// Keep `job`'s chunk, whose stream gains nothing, raw for a swap slot
/// (services/memmgr/docs/memory-pool.md § Eviction, States) while the disk
/// tier takes one ([`crate::disk::takes_raw`]): its runs stay on it,
/// unmapped from the process, until the swap service takes and writes it or
/// a fault maps them back ([`free_pool::Ledger::finish_raw`]). `false`
/// when the disk tier takes none.
fn keep_raw(l: &mut MemLedger, job: &Job, slot: usize) -> bool
{
    crate::disk::takes_raw(l)
        && l.finish_raw(job.rec, job.reg, job.page_base, job_id(slot))
            .is_ok()
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
    let target = remap_target(l, v.rec, aspace, (reg, &region), v.page_base, 0);
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
/// stream and swap the chunk, or keep a chunk whose stream gains nothing raw
/// ([`finish`]); when neither is done, map the chunk's runs back and mark it
/// resident. A job whose
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
            && !finish(l, &job, slot, len)
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
    let target = remap_target(l, job.rec, aspace, (reg, &region), job.page_base, 0);
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
/// mapped back and its job made stale; a raw chunk's runs are mapped back,
/// a write of them cancelled ([`free_pool::Ledger::remap_raw`]); a compressed
/// chunk, writing or not, is restored from its store runs ([`restore`]), a
/// write cancelled. A
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
    let entry = l.chunk_at(reg, page_base);
    match entry.state()
    {
        ChunkState::Evicting =>
        {
            let (runs, n) = chunk_runs(l, reg, page_base);
            let target = remap_target(l, rec, aspace, (reg, region), page_base, 0);
            map_runs(l, &target, runs.get(..n).unwrap_or(&[]))?;
            let _ = l.cancel_evict(rec, reg, page_base);
            Ok(())
        }
        ChunkState::Raw => remap_raw(l, rec, reg, region, page_base, aspace),
        ChunkState::Writing if entry.is_raw() => remap_raw(l, rec, reg, region, page_base, aspace),
        ChunkState::Compressed | ChunkState::Writing =>
        {
            restore(l, rec, reg, region, page_base, aspace, Source::Store)
        }
        // A chunk on disk or lost is the caller's to route first
        // (`free_pool::fault_path`): memmgr cannot read a swap slot.
        ChunkState::Unbacked | ChunkState::Resident | ChunkState::OnDisk | ChunkState::Lost =>
        {
            Ok(())
        }
    }
}

/// Map the runs of the raw chunk holding `page_base` in region `reg` of
/// `rec`, raw or writing, back into the process and mark it resident on
/// them, a write cancelled ([`free_pool::Ledger::remap_raw`]). Its pages are
/// charged already and its frames its own, so nothing is drawn.
///
/// # Errors
/// The map's [`FaultDecline`] and its detail word; the chunk stays raw.
fn remap_raw(
    l: &mut MemLedger,
    rec: NodeIdx,
    reg: NodeIdx,
    region: &DemandRegion,
    page_base: u64,
    aspace: u64,
) -> Result<(), (FaultDecline, u64)>
{
    let (runs, n) = chunk_runs(l, reg, page_base);
    let target = remap_target(l, rec, aspace, (reg, region), page_base, 0);
    map_runs(l, &target, runs.get(..n).unwrap_or(&[]))?;
    let _ = l.remap_raw(rec, reg, page_base);
    Ok(())
}

/// Where a restore reads a chunk's pages from ([`restore`]).
#[derive(Clone, Copy)]
pub(crate) enum Source<'a>
{
    /// The chunk's store runs: a compressed chunk, writing or not.
    Store,
    /// A compressed chunk's stream, a swap slot's bytes opened.
    Stream(&'a [u8]),
    /// A raw chunk's backed pages in page order, a swap slot's bytes opened.
    Pages(&'a [u8]),
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
/// region `reg` of `rec` from `source`: the bytes a swap slot held opened,
/// a stream or a raw chunk's pages, for a chunk on disk (`crate::disk`), else
/// its store runs (services/memmgr/docs/memory-pool.md § Eviction, States): admitted when the
/// free pages outside `promised` cover its backed pages and, for a node outside
/// it, the system reserve, once direct reclaim has made room when needed
/// ([`admit_restore`]), or, for a chunk of a committed region, which draws
/// from `promised`, when the draw finds its frames ([`draw_room`]); then runs
/// covering exactly its backed pages, each filled whole through the scrub
/// window from the source, mapped into the process, and the chunk resident on
/// them, its store back in the pool. The chunk's pages are charged already.
///
/// # Errors
/// [`FaultDecline::NoFreePage`] when the restore is not admitted or the pool
/// runs out, [`FaultDecline::CommitOverrun`] when a committed chunk's draw
/// finds too few free pages, [`FaultDecline::NoArenaSlot`] when the arena
/// cannot grow for the runs' descriptors, [`FaultDecline::BudgetLimit`] when a
/// page-table donation the map needs is refused at a max,
/// [`FaultDecline::MapFailed`] when a map fails, the floor refuses that
/// donation, or the source is malformed (detail 0), and
/// [`FaultDecline::FrameRecord`] when the ledger refuses the runs. The chunk then stays as it was.
pub(crate) fn restore(
    l: &mut MemLedger,
    rec: NodeIdx,
    reg: NodeIdx,
    region: &DemandRegion,
    page_base: u64,
    aspace: u64,
    source: Source<'_>,
) -> Result<(), (FaultDecline, u64)>
{
    let backed = l.chunk_at(reg, page_base).backed();
    let pages = u64::from(backed.count_ones());
    let (admitted, short) = if l.is_committed(reg)
    {
        (
            draw_room(l, rec, pages, pages, None) >= pages,
            FaultDecline::CommitOverrun,
        )
    }
    else
    {
        (admit_restore(l, rec, pages), FaultDecline::NoFreePage)
    };
    if !admitted
    {
        return Err((short, 0));
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
    let filled = match source
    {
        Source::Store => fill_runs(l, entry, runs),
        Source::Stream(stream) => decode_runs(l, &mut Decoder::new(stream), runs),
        Source::Pages(pages) => decode_runs(l, &mut RawPages::new(pages), runs),
    };
    if let Err(e) = filled
    {
        give_back(l, runs);
        return Err(e);
    }
    let target = remap_target(l, rec, aspace, (reg, region), page_base, held);
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

/// Whether a restore of `pages` pages of an uncommitted chunk for `rec` is
/// admitted: the free pages outside `promised` cover them and, for a budget
/// node outside the reserve, the system reserve, but not the restore headroom
/// that growth leaves for restores (`free_pool::growth_floor`). When they do
/// not, memmgr reclaims directly ([`reclaim`]).
fn admit_restore(l: &mut MemLedger, rec: NodeIdx, pages: u64) -> bool
{
    let reserve = reserve_of(l, rec);
    reclaim(l, Need::Free, None, |l| {
        l.uncommitted_free() >= pages.saturating_add(reserve)
    })
}

/// The pages, up to `want`, a committed draw for `rec` takes from the free
/// pool (a fault in a committed region, or a restore of a committed chunk,
/// each drawing from `promised`): as many as
/// [`free_pool::Ledger::draw_room`] gives above [`draw_floor`]. When that is
/// short of `least`, after the turn's
/// deferred recheck, memmgr evicts victims in its turn as a restore's direct
/// reclaim does, any evictable chunk among them, until the draw fits or
/// [`MAX_SYNC_VICTIMS`] have been tried (services/memmgr/docs/memory-pool.md
/// § Commit, Overcommit); `spare`, a region and the base of a chunk of it,
/// names the chunk a fault backs, which is never taken. With an allowance of
/// 0 the draw always fits while a page is free. 0: the draw is a commit
/// overrun.
pub(crate) fn draw_room(
    l: &mut MemLedger,
    rec: NodeIdx,
    want: u64,
    least: u64,
    spare: Option<(NodeIdx, u64)>,
) -> u64
{
    let floor = draw_floor(l, rec);
    if !reclaim(l, Need::Frames, spare, |l| l.draw_room(floor) >= least)
    {
        return 0;
    }
    l.draw_room(floor).min(want)
}

/// The free pages a committed draw for `rec` leaves while the free pool does
/// not cover `promised` ([`free_pool::Ledger::draw_room`]): the growth floor,
/// the system reserve and the restore headroom, for a budget node outside the
/// reserve; 0 for a reserve node.
pub(crate) fn draw_floor(l: &MemLedger, rec: NodeIdx) -> u64
{
    if l.budget(rec).is_some_and(|b| b.reserve())
    {
        0
    }
    else
    {
        l.growth_floor(pool_total_pages())
    }
}

/// The system reserve a charge to the budget node of `rec` leaves: 0 for a
/// reserve node.
fn reserve_of(l: &MemLedger, rec: NodeIdx) -> u64
{
    if l.budget(rec).is_some_and(|b| b.reserve())
    {
        0
    }
    else
    {
        reserve_pages(pool_total_pages())
    }
}

/// Whether `fits` holds, after the turn's deferred recheck and memmgr's
/// direct reclaim when it does not (services/memmgr/docs/memory-pool.md
/// § Eviction, Direct reclaim): the kept victims of greatest age evicted now,
/// one by one ([`evict_now`]), each whose eviction raises the free pages
/// outside `promised` or, for a committed draw ([`Need::Frames`]), any but the
/// chunk at `spare` ([`draw_room`]), until `fits` holds or [`MAX_SYNC_VICTIMS`]
/// have been tried.
fn reclaim(
    l: &mut MemLedger,
    need: Need,
    spare: Option<(NodeIdx, u64)>,
    fits: impl Fn(&MemLedger) -> bool,
) -> bool
{
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
        let Some(v) = take_victim(l, need, spare)
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

/// Copy the backed pages of the raw chunk holding `page_base` in region
/// `reg` of `rec`, in page order, into `dst`, for its write
/// (`crate::disk`): its runs mapped at the stream window, each at its offset
/// in the chunk. Returns the bytes copied, or `None`, nothing copied, when
/// the chunk has no region, a map fails, or they do not fit `dst`.
pub(crate) fn read_raw(
    l: &mut MemLedger,
    rec: NodeIdx,
    reg: NodeIdx,
    page_base: u64,
    dst: &mut [u8],
) -> Option<usize>
{
    let (_, region) = l.region_for(rec, page_base).filter(|(r, _)| *r == reg)?;
    let (chunk_base, _) = chunk_for(&region, page_base);
    let backed = l.chunk_at(reg, page_base).backed();
    let (runs, n) = chunk_runs(l, reg, page_base);
    let mut mapped = true;
    for run in runs.get(..n).unwrap_or(&[])
    {
        let first = run.va.saturating_sub(chunk_base) / PAGE_SIZE;
        let end = first.saturating_add(u64::from(run.page_count));
        let va = STREAM_VA.saturating_add(first.saturating_mul(PAGE_SIZE));
        if end > CHUNK_PAGES
        {
            mapped = false;
            break;
        }
        // SAFETY: the stream window is memmgr's own zone, which every use
        // leaves unmapped, and the check above keeps the run inside it.
        if unsafe { map_self(l, run.cap_slot, va, 0, u64::from(run.page_count)) }.is_err()
        {
            mapped = false;
            break;
        }
    }
    let pages = backed.count_ones() as usize;
    let bytes = pages.saturating_mul(PAGE_BYTES);
    let copied = dst.get_mut(..bytes).filter(|_| mapped).map(|dst| {
        let (out, _) = dst.as_chunks_mut::<PAGE_BYTES>();
        let held =
            (0..DEMAND_CHUNK_PAGES).filter(|p| backed.checked_shr(*p).is_some_and(|b| b & 1 != 0));
        for (page, to) in held.zip(out.iter_mut())
        {
            let from = STREAM_VA.saturating_add(u64::from(page).saturating_mul(PAGE_SIZE));
            // SAFETY: each backed page of the chunk lies in one of its runs,
            // mapped above at its offset in the stream window; nothing writes
            // the pages, which no process maps, while they are read.
            to.copy_from_slice(unsafe { &*(from as *const [u8; PAGE_BYTES]) });
        }
        bytes
    });
    unmap_stream(CHUNK_PAGES);
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
    let result = decode_runs(l, &mut Decoder::new(stream), runs);
    unmap_stream(pages);
    result
}

/// Write every byte of every page of `runs`, in page order, from `reader`:
/// each run mapped at the scrub window, its pages read there, and unmapped.
///
/// # Errors
/// [`FaultDecline::MapFailed`]: a map failed (its error's magnitude the
/// detail), or the reader's source is malformed (detail 0).
fn decode_runs(
    l: &mut MemLedger,
    reader: &mut impl PageReader,
    runs: &[FrameDesc],
) -> Result<(), (FaultDecline, u64)>
{
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
