// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// memmgr/src/main.rs

//! Tier-1 userspace service that owns the userspace RAM frame pool.
//!
//! memmgr serves frame allocation, release, and per-process accounting over
//! IPC. See `memmgr/docs/{frame-pool,ipc-interface}.md` for the authoritative
//! contracts. memmgr is `no_std` and uses statically-bounded data structures
//! only — it cannot bootstrap a heap against itself.

#![no_std]
#![no_main]
// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use process_abi::{
    PROCESS_ABI_VERSION, PROCESS_INFO_VADDR, ProcessInfo, StartupInfo, process_info_ref,
};
use syscall_abi::PAGE_SIZE;

// memmgr's bootstrap parser carries page-count buffers on stack and
// pushes deeper through `bootstrap_from_init`; declare a 12-page
// (48 KiB) main-thread stack instead of the default 8 (32 KiB).
process_abi::stack_pages!(12);

// ── Bespoke runtime ─────────────────────────────────────────────────────────
//
// memmgr cannot share `std::sys::seraph::_start`: that path bootstraps a heap
// by calling `REQUEST_FRAMES` against memmgr itself, and memmgr must serve
// that call. The bespoke `_start` here runs on `core` + raw syscalls only.

#[unsafe(no_mangle)]
pub extern "C" fn _start(_info_ptr: u64) -> !
{
    // SAFETY: init's loader maps a valid ProcessInfo page at
    // PROCESS_INFO_VADDR before starting this thread; the page remains
    // mapped for the process's lifetime.
    let info: &ProcessInfo = unsafe { process_info_ref(PROCESS_INFO_VADDR) };

    if info.version != PROCESS_ABI_VERSION
    {
        syscall::thread_exit();
    }

    let startup = StartupInfo {
        ipc_buffer: info.ipc_buffer_vaddr as *mut u8,
        creator_endpoint: info.creator_endpoint_cap,
        self_thread: info.self_thread_cap,
        self_aspace: info.self_aspace_cap,
        self_cspace: info.self_cspace_cap,
        procmgr_endpoint: info.procmgr_endpoint_cap,
        memmgr_endpoint: info.memmgr_endpoint_cap,
        stdin_frame_cap: info.stdin_frame_cap,
        stdout_frame_cap: info.stdout_frame_cap,
        stderr_frame_cap: info.stderr_frame_cap,
        stdin_data_signal_cap: info.stdin_data_signal_cap,
        stdin_space_signal_cap: info.stdin_space_signal_cap,
        stdout_data_signal_cap: info.stdout_data_signal_cap,
        stdout_space_signal_cap: info.stdout_space_signal_cap,
        stderr_data_signal_cap: info.stderr_data_signal_cap,
        stderr_space_signal_cap: info.stderr_space_signal_cap,
        tls_template_vaddr: info.tls_template_vaddr,
        tls_template_filesz: info.tls_template_filesz,
        tls_template_memsz: info.tls_template_memsz,
        tls_template_align: info.tls_template_align,
        args_blob: &[],
        args_count: 0,
        env_blob: &[],
        env_count: 0,
        stack_top_vaddr: info.stack_top_vaddr,
        stack_pages: info.stack_pages,
    };

    main(&startup)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> !
{
    syscall::thread_exit();
}

// ── State ────────────────────────────────────────────────────────────────────

/// Maximum concurrent processes memmgr will track.
const MAX_PROCESSES: usize = 64;
/// Maximum frame records per process.
const MAX_PER_PROC: usize = 512;
/// Maximum free runs in the pool. Each run is one Frame cap covering one
/// or more contiguous pages.
const MAX_FREE_RUNS: usize = 512;

/// One free run: a Frame cap memmgr owns, covering `page_count` pages
/// starting at physical address `phys_base`.
#[derive(Clone, Copy)]
struct FreeRun
{
    cap_slot: u32,
    page_count: u32,
    phys_base: u64,
}

/// One per-process frame record.
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct OwnedFrame
{
    /// Slot index in memmgr's `CSpace` where memmgr retains the outer
    /// derivation (the parent of the cap handed to the caller). Used to
    /// re-add the underlying region to the free pool when the process dies.
    cap_slot: u32,
    page_count: u32,
    phys_base: u64,
}

/// Process accounting record: token plus the list of frames memmgr has
/// issued to that process.
struct ProcessRecord
{
    token: u64,
    used: usize,
    frames: [Option<OwnedFrame>; MAX_PER_PROC],
}

impl ProcessRecord
{
    // large_stack_arrays: ProcessRecord lives inside a `static mut`
    // ProcessTable, so this initializer never lands on a runtime stack
    // frame. const-evaluated at static-init time.
    #[allow(clippy::large_stack_arrays)]
    const fn new(token: u64) -> Self
    {
        Self {
            token,
            used: 0,
            frames: [None; MAX_PER_PROC],
        }
    }

    fn push(&mut self, frame: OwnedFrame) -> Result<(), ()>
    {
        if self.used >= MAX_PER_PROC
        {
            return Err(());
        }
        self.frames[self.used] = Some(frame);
        self.used += 1;
        Ok(())
    }
}

/// Free pool: array of runs. Order is irrelevant; allocation scans linearly.
struct FreePool
{
    runs: [Option<FreeRun>; MAX_FREE_RUNS],
}

impl FreePool
{
    // large_stack_arrays: FreePool lives in a `static mut` so this
    // initializer never lands on a runtime stack frame.
    #[allow(clippy::large_stack_arrays)]
    const fn new() -> Self
    {
        Self {
            runs: [None; MAX_FREE_RUNS],
        }
    }

    fn push(&mut self, run: FreeRun) -> Result<(), ()>
    {
        for slot in &mut self.runs
        {
            if slot.is_none()
            {
                *slot = Some(run);
                return Ok(());
            }
        }
        Err(())
    }

    /// Find the smallest run covering at least `want` pages. Returns the
    /// array index, or `None` if no run is large enough.
    fn smallest_fit(&self, want: u32) -> Option<usize>
    {
        let mut best: Option<usize> = None;
        let mut best_size: u32 = u32::MAX;
        for (i, slot) in self.runs.iter().enumerate()
        {
            if let Some(run) = slot
                && run.page_count >= want
                && run.page_count < best_size
            {
                best = Some(i);
                best_size = run.page_count;
            }
        }
        best
    }

    /// Find the largest run regardless of size. Used by best-effort
    /// allocation to greedily pick the biggest available chunk.
    fn largest(&self) -> Option<usize>
    {
        let mut best: Option<usize> = None;
        let mut best_size: u32 = 0;
        for (i, slot) in self.runs.iter().enumerate()
        {
            if let Some(run) = slot
                && run.page_count > best_size
            {
                best = Some(i);
                best_size = run.page_count;
            }
        }
        best
    }

    /// Coalesce free runs by repeatedly trying `frame_merge` between every
    /// pair. Bounded: each successful merge reduces the run count by one.
    fn coalesce(&mut self)
    {
        loop
        {
            let mut merged_any = false;
            'outer: for i in 0..MAX_FREE_RUNS
            {
                let Some(run_a) = self.runs[i]
                else
                {
                    continue;
                };
                for j in 0..MAX_FREE_RUNS
                {
                    if i == j
                    {
                        continue;
                    }
                    let Some(run_b) = self.runs[j]
                    else
                    {
                        continue;
                    };
                    // Try merging in both orders. Option-D frame_merge
                    // requires physical contiguity (parent first, tail
                    // second) and identical rights/parents; it rejects every
                    // non-adjacent pair, so blind probing is correct (just
                    // O(N²)). On success the parent's slot stays valid and
                    // the tail's slot is freed; the merged run's cap_slot
                    // is therefore the parent (lower-address) cap.
                    if syscall::frame_merge(run_a.cap_slot, run_b.cap_slot).is_ok()
                    {
                        // run_a was parent (lower base); its slot survives
                        // and now covers run_a.size + run_b.size.
                        self.runs[i] = Some(FreeRun {
                            cap_slot: run_a.cap_slot,
                            page_count: run_a.page_count + run_b.page_count,
                            phys_base: run_a.phys_base,
                        });
                        self.runs[j] = None;
                        merged_any = true;
                        break 'outer;
                    }
                    if syscall::frame_merge(run_b.cap_slot, run_a.cap_slot).is_ok()
                    {
                        // run_b was parent; its slot survives.
                        self.runs[i] = Some(FreeRun {
                            cap_slot: run_b.cap_slot,
                            page_count: run_a.page_count + run_b.page_count,
                            phys_base: run_b.phys_base,
                        });
                        self.runs[j] = None;
                        merged_any = true;
                        break 'outer;
                    }
                }
            }
            if !merged_any
            {
                break;
            }
        }
    }
}

/// Process tracking table: dense array of records, indexed by an internal
/// monotonically-incremented token (held externally as the procmgr-minted
/// process identity).
struct ProcessTable
{
    records: [Option<ProcessRecord>; MAX_PROCESSES],
}

impl ProcessTable
{
    // large_stack_arrays: const-evaluated at static-initialization time;
    // never touches a runtime stack frame.
    #[allow(clippy::large_stack_arrays)]
    const fn new() -> Self
    {
        const NONE: Option<ProcessRecord> = None;
        Self {
            records: [NONE; MAX_PROCESSES],
        }
    }

    fn insert(&mut self, token: u64) -> Option<&mut ProcessRecord>
    {
        for slot in &mut self.records
        {
            if slot.is_none()
            {
                *slot = Some(ProcessRecord::new(token));
                return slot.as_mut();
            }
        }
        None
    }

    fn find_mut(&mut self, token: u64) -> Option<&mut ProcessRecord>
    {
        for slot in &mut self.records
        {
            if let Some(rec) = slot
                && rec.token == token
            {
                return slot.as_mut();
            }
        }
        None
    }

    fn take(&mut self, token: u64) -> Option<ProcessRecord>
    {
        for slot in &mut self.records
        {
            if let Some(rec) = slot
                && rec.token == token
            {
                return slot.take();
            }
        }
        None
    }
}

/// Token counter for memmgr-minted process identities. Each
/// `REGISTER_PROCESS` call consumes one.
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

// Per-process tracking and the free pool live in statics so the ~150 KB of
// per-process bookkeeping never lands on a syscall stack frame. memmgr is
// single-threaded — its only thread runs the main dispatch loop and owns
// these tables exclusively, so the `static mut` reads/writes are sound.
//
// Access is gated through `pool_mut()` and `table_mut()` to keep the
// `unsafe` to one place per access.

static mut FREE_POOL: FreePool = FreePool::new();
static mut PROCESS_TABLE: ProcessTable = ProcessTable::new();

#[allow(static_mut_refs)]
fn pool_mut() -> &'static mut FreePool
{
    // SAFETY: single-threaded service; no concurrent access.
    unsafe { &mut FREE_POOL }
}

#[allow(static_mut_refs)]
fn table_mut() -> &'static mut ProcessTable
{
    // SAFETY: single-threaded service; no concurrent access.
    unsafe { &mut PROCESS_TABLE }
}

// ── Bootstrap protocol ───────────────────────────────────────────────────────
//
// Init → memmgr bootstrap (one round on memmgr's creator endpoint):
//   caps[0]: memmgr's service endpoint (full rights; memmgr's RECV side).
//   caps[1]: read-only Frame cap (one page) carrying `[u64; frame_count]`
//            of physical-base addresses, parallel to `page_counts`. memmgr
//            maps it RO at `PHYS_TABLE_TEMP_VA`, copies the values into
//            its `FreeRun` records, then unmaps + cap-deletes.
//   data[0]: frame_base — first slot index of the RAM Frame caps already
//            copied into memmgr's `CSpace`.
//   data[1]: frame_count — number of consecutive RAM frames.
//   data[2]: procmgr_token — the token init burned into procmgr's tokened
//            SEND on memmgr's endpoint. memmgr stores this and gates the
//            procmgr-only labels (REGISTER_PROCESS, PROCESS_DIED) on it.
//   data[3..3+ceil(frame_count/2)]: page_count per frame, packed two per
//            word (low 32 bits = even index, high 32 bits = odd index).
//
// MSG_DATA_WORDS_MAX = 64; this layout supports up to 122 RAM frames per
// bootstrap round (same as before phys_base was plumbed: phys travels via
// the auxiliary frame in caps[1] rather than competing for data-field
// budget).

/// Maximum number of frames init can deliver in one bootstrap round.
/// Mirrors `MEMMGR_BOOTSTRAP_MAX_FRAMES` in init's `bootstrap.rs`:
/// 64-word data field minus 3-word prefix, two `page_counts` packed
/// per word.
const BOOTSTRAP_MAX_FRAMES: usize = 122;

/// Scratch VA in memmgr's address space for mapping the bootstrap
/// phys-table frame. One page; mapped RO during `bootstrap_from_init`,
/// unmapped before the dispatch loop entry.
const PHYS_TABLE_TEMP_VA: u64 = 0x0000_5000_0000_0000;

struct InitBootstrap
{
    service_ep: u32,
    procmgr_token: u64,
    frame_base: u32,
    frame_count: u32,
    page_counts: [u32; BOOTSTRAP_MAX_FRAMES],
    phys_bases: [u64; BOOTSTRAP_MAX_FRAMES],
}

fn bootstrap_from_init(
    creator_ep: u32,
    self_aspace: u32,
    ipc_buf: *mut u64,
) -> Option<InitBootstrap>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: caller passes the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) }.ok()?;
    if round.cap_count < 2 || round.data_words < 3 || !round.done
    {
        return None;
    }
    let frame_count = round.data[1] as u32;
    let packed_words = (frame_count as usize).div_ceil(2);
    if (frame_count as usize) > BOOTSTRAP_MAX_FRAMES || 3 + packed_words > round.data_words
    {
        return None;
    }
    // Unpack 2 page_counts per word: low 32 bits = even index, high 32
    // bits = odd index.
    let mut page_counts = [0u32; BOOTSTRAP_MAX_FRAMES];
    for w in 0..packed_words
    {
        let word = round.data[3 + w];
        let lo = word as u32;
        let hi = (word >> 32) as u32;
        let i0 = w * 2;
        page_counts[i0] = lo;
        if i0 + 1 < frame_count as usize
        {
            page_counts[i0 + 1] = hi;
        }
    }

    // Map the phys-table frame and copy out frame_count u64 entries.
    let phys_table_cap = round.caps[1];
    let mut phys_bases = [0u64; BOOTSTRAP_MAX_FRAMES];
    if syscall::mem_map(phys_table_cap, self_aspace, PHYS_TABLE_TEMP_VA, 0, 1, 0).is_err()
    {
        return None;
    }
    // SAFETY: PHYS_TABLE_TEMP_VA is mapped RO, one page. Init wrote the
    // first `frame_count` u64 entries; the rest is zero. The pointer is
    // page-aligned (4 KiB) so u64 alignment is satisfied.
    #[allow(clippy::cast_ptr_alignment)]
    let phys_ptr = PHYS_TABLE_TEMP_VA as *const u64;
    for (i, slot) in phys_bases.iter_mut().enumerate().take(frame_count as usize)
    {
        // SAFETY: i < frame_count <= BOOTSTRAP_MAX_FRAMES = 122; 122 * 8 =
        // 976 B fits in one 4 KiB page.
        *slot = unsafe { core::ptr::read_volatile(phys_ptr.add(i)) };
    }
    let _ = syscall::mem_unmap(self_aspace, PHYS_TABLE_TEMP_VA, 1);
    let _ = syscall::cap_delete(phys_table_cap);

    Some(InitBootstrap {
        service_ep: round.caps[0],
        procmgr_token: round.data[2],
        frame_base: round.data[0] as u32,
        frame_count,
        page_counts,
        phys_bases,
    })
}

// ── Allocation primitives ────────────────────────────────────────────────────

/// Peel exactly `want` pages off the run at index `idx`. If the run is
/// larger, splits via `frame_split`; the residue is reinserted into the
/// pool. Returns the cap slot (in memmgr's `CSpace`) covering exactly `want`
/// pages plus that slot's physical base address.
fn take_exactly(pool: &mut FreePool, idx: usize, want: u32) -> Option<(u32, u64)>
{
    let run = pool.runs[idx]?;
    if run.page_count == want
    {
        pool.runs[idx] = None;
        return Some((run.cap_slot, run.phys_base));
    }
    if run.page_count < want
    {
        return None;
    }
    let split_offset = u64::from(want) * PAGE_SIZE;
    // Option-D frame_split: `run.cap_slot` shrinks in place to cover the
    // first `split_offset` bytes; the returned slot is the new tail covering
    // the remainder at `phys_base + split_offset`.
    let tail = syscall::frame_split(run.cap_slot, split_offset).ok()?;
    pool.runs[idx] = Some(FreeRun {
        cap_slot: tail,
        page_count: run.page_count - want,
        phys_base: run.phys_base + split_offset,
    });
    Some((run.cap_slot, run.phys_base))
}

/// Derive an inner copy of the outer cap to hand to the caller. The outer
/// cap (`outer_slot`) stays in memmgr's `CSpace` as the per-process tracking
/// anchor; the inner derivation (returned) is what gets transferred via
/// `ipc_reply`.
///
/// `RIGHTS_ALL` is required so the caller can in turn derive RW/RX/R-only
/// variants for distinct page mappings (procmgr's ELF loader covers all
/// three). Restricting to `RIGHTS_MAP_RW` here would silently break
/// executable-segment maps, since `cap_derive` only narrows rights.
fn derive_for_caller(outer_slot: u32) -> Option<u32>
{
    syscall::cap_derive(outer_slot, syscall::RIGHTS_ALL).ok()
}

// ── IPC handlers ─────────────────────────────────────────────────────────────

/// Reply slot count for `REQUEST_FRAMES`. Per-cap page counts pack into
/// `data[1..1+count]`; `data[0]` holds the count itself.
const MAX_REPLY_CAPS: usize = syscall_abi::MSG_CAP_SLOTS_MAX;

/// One peeled selection entry: `(outer_cap_slot, page_count, phys_base)`.
type GrantEntry = (u32, u32, u64);

/// Result of a single `select_frames` call: the array of peeled entries
/// plus the count of valid entries.
type GrantArray = [GrantEntry; MAX_REPLY_CAPS];

/// Pool selection for a single `REQUEST_FRAMES` call. Returns the array of
/// peeled `(outer_cap, page_count, phys_base)` entries plus their count, or
/// an error code on failure. On error the pool is unchanged; on success the
/// caller owns each outer cap and is responsible for either accounting it
/// to a process record or pushing it back via `pool.push`.
fn select_frames(
    pool: &mut FreePool,
    want_pages: u32,
    contiguous: bool,
) -> Result<(GrantArray, usize), u64>
{
    let mut granted: GrantArray = [(0, 0, 0); MAX_REPLY_CAPS];

    if contiguous
    {
        let idx = pool
            .smallest_fit(want_pages)
            .ok_or(memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS)?;
        let (outer, phys) =
            take_exactly(pool, idx, want_pages).ok_or(memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS)?;
        granted[0] = (outer, want_pages, phys);
        return Ok((granted, 1));
    }

    // Best-effort: greedy, largest-first, bounded by reply slots.
    let mut count: usize = 0;
    let mut remaining = want_pages;
    while remaining > 0 && count < MAX_REPLY_CAPS
    {
        let Some(idx) = pool.largest()
        else
        {
            break;
        };
        let avail = pool.runs[idx].map_or(0, |r| r.page_count);
        if avail == 0
        {
            break;
        }
        let take_pages = avail.min(remaining);
        let Some((outer, phys)) = take_exactly(pool, idx, take_pages)
        else
        {
            break;
        };
        granted[count] = (outer, take_pages, phys);
        count += 1;
        remaining -= take_pages;
    }
    if remaining > 0
    {
        for &(outer, pages, phys) in granted.iter().take(count)
        {
            let _ = pool.push(FreeRun {
                cap_slot: outer,
                page_count: pages,
                phys_base: phys,
            });
        }
        return Err(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
    }
    Ok((granted, count))
}

/// Roll back a partial selection: push each outer back onto the pool and
/// delete any inner derivations already minted.
fn rollback_selection(
    pool: &mut FreePool,
    granted: &GrantArray,
    granted_count: usize,
    inner: &[u32; MAX_REPLY_CAPS],
    inner_count: usize,
)
{
    for &(o, p, phys) in granted.iter().take(granted_count)
    {
        let _ = pool.push(FreeRun {
            cap_slot: o,
            page_count: p,
            phys_base: phys,
        });
    }
    for &slot in inner.iter().take(inner_count)
    {
        let _ = syscall::cap_delete(slot);
    }
}

fn handle_request_frames(req: &IpcMessage, ipc_buf: *mut u64)
{
    let token = req.token;
    let arg = req.word(0);
    let want_pages = (arg & 0xFFFF_FFFF) as u32;
    let flags = (arg >> 32) as u32;

    if want_pages == 0 || flags & !memmgr_labels::REQUIRE_CONTIGUOUS != 0
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    }

    let pool = pool_mut();
    let Some(record) = table_mut().find_mut(token)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };

    let contiguous = flags & memmgr_labels::REQUIRE_CONTIGUOUS != 0;
    let (granted, granted_count) = match select_frames(pool, want_pages, contiguous)
    {
        Ok(v) => v,
        Err(code) =>
        {
            reply_label(ipc_buf, code);
            return;
        }
    };

    // Account each peeled outer to the caller's record, then derive the
    // inner copy that ships in the reply. On any failure, roll the entire
    // selection back to the pool.
    let mut inner: [u32; MAX_REPLY_CAPS] = [0; MAX_REPLY_CAPS];
    for (i, &(outer, pages, phys)) in granted.iter().take(granted_count).enumerate()
    {
        if record
            .push(OwnedFrame {
                cap_slot: outer,
                page_count: pages,
                phys_base: phys,
            })
            .is_err()
        {
            rollback_selection(pool, &granted, granted_count, &inner, i);
            reply_label(ipc_buf, memmgr_errors::QUOTA);
            return;
        }
        let Some(d) = derive_for_caller(outer)
        else
        {
            rollback_selection(pool, &granted, granted_count, &inner, i);
            // Drop the just-pushed record entry too.
            record.used -= 1;
            record.frames[record.used] = None;
            reply_label(ipc_buf, memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
            return;
        };
        inner[i] = d;
    }

    // Build the reply:
    //   data[0]                  = cap_count
    //   data[1..1+count]         = page_count_for_cap_i (u32 in low half)
    //   data[1+count..1+2*count] = phys_base_for_cap_i (u64)
    //   caps[0..count]           = Frame caps (MAP|WRITE)
    let mut builder = IpcMessage::builder(memmgr_errors::SUCCESS).word(0, granted_count as u64);
    for (i, &(_, pages, phys)) in granted.iter().take(granted_count).enumerate()
    {
        builder = builder.word(1 + i, u64::from(pages));
        builder = builder.word(1 + granted_count + i, phys);
    }
    for &slot in inner.iter().take(granted_count)
    {
        builder = builder.cap(slot);
    }
    let reply = builder.build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

fn handle_release_frames(req: &IpcMessage, ipc_buf: *mut u64)
{
    // First-cut RELEASE: receive the caller's caps, drop them. Per-process
    // tracking is not updated; the underlying physical region remains
    // pinned by memmgr's outer derivation until PROCESS_DIED reclaims the
    // process. This is correctness-safe (no double-free) and intentionally
    // conservative until userspace has a way to identify outers from
    // received inner caps.
    for &slot in req.caps()
    {
        let _ = syscall::cap_delete(slot);
    }
    reply_label(ipc_buf, memmgr_errors::SUCCESS);
}

fn handle_register_process(req: &IpcMessage, ipc_buf: *mut u64, service_ep: u32, procmgr_token: u64)
{
    if req.token != procmgr_token
    {
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }

    let table = table_mut();
    let new_token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);

    if table.insert(new_token).is_none()
    {
        reply_label(ipc_buf, memmgr_errors::TOO_MANY_PROCESSES);
        return;
    }

    let Ok(send_cap) = syscall::cap_derive_token(service_ep, syscall::RIGHTS_SEND_GRANT, new_token)
    else
    {
        // Roll back the table insertion.
        let _ = table.take(new_token);
        reply_label(ipc_buf, memmgr_errors::TOO_MANY_PROCESSES);
        return;
    };

    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, new_token)
        .cap(send_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

fn handle_process_died(req: &IpcMessage, ipc_buf: *mut u64, procmgr_token: u64)
{
    if req.token != procmgr_token
    {
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }
    // The dead process's tokened SEND cap arrives in `caps[0]` (when the
    // caller transfers it). The kernel does not surface the token of a
    // transferred cap to the receiver — only the token of the
    // receive-side cap — so procmgr also encodes the dead process's
    // token in `data[0]` for memmgr's table lookup.
    let dead_token = req.word(0);

    // Auto-reclaim invariant (documented, not asserted in-line):
    //
    // By the time PROCESS_DIED reaches memmgr, procmgr has revoked +
    // deleted the child's CSpace, which cascades through every derived
    // inner Frame cap *and* every kernel object retyped from those caps.
    // Auto-reclaim (`KernelObjectHeader.ancestor`) credits each retype's
    // bytes back to the source `FrameObject` — which memmgr's outer cap
    // and the child's inner cap share. With the child gone, only the
    // outer cap remains.
    //
    // We do *not* assert `available_bytes == size` here: the per-cap
    // `RetypeAllocator` metadata cost (~64 B per cap, debited on first
    // retype) stays charged for as long as the FrameObject lives, which
    // is until memmgr's outer cap is also released — i.e. forever for
    // pool caps. A correct cross-check would compare against the
    // available value snapshotted at grant time, which is more state
    // than memmgr's record currently carries; the ktest
    // `integration::retype_reclaim` covers the same invariant on a
    // dedicated source cap with no allocator residual.
    let pool = pool_mut();
    if let Some(record) = table_mut().take(dead_token)
    {
        for frame in record.frames.iter().take(record.used).flatten()
        {
            let _ = pool.push(FreeRun {
                cap_slot: frame.cap_slot,
                page_count: frame.page_count,
                phys_base: frame.phys_base,
            });
        }
        // Coalesce reclaimed runs back into larger contiguous chunks via
        // `frame_merge`. Probing is O(N²) over MAX_FREE_RUNS but each
        // probe is a single kernel syscall that returns immediately on
        // non-adjacency, and successful merges decrease the run count —
        // amortised cost per death is tolerable at expected workloads.
        // Without coalescing, fragmentation accumulates monotonically:
        // every spawn-and-die cycle leaves the pool with smaller runs
        // than it started, until `MAX_FREE_RUNS` fills and `pool.push`
        // starts leaking frames.
        pool.coalesce();
    }
    // Idempotent: missing token is not an error.

    // Drop any caps the caller transferred (typically the dead process's
    // tokened SEND cap, no longer useful).
    for &slot in req.caps()
    {
        let _ = syscall::cap_delete(slot);
    }

    reply_label(ipc_buf, memmgr_errors::SUCCESS);
}

// ── Reply helpers ────────────────────────────────────────────────────────────

fn reply_label(ipc_buf: *mut u64, label: u64)
{
    let reply = IpcMessage::new(label);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

// ── Main loop ────────────────────────────────────────────────────────────────

fn ingest_pool(boot: &InitBootstrap)
{
    let pool = pool_mut();
    for i in 0..(boot.frame_count as usize)
    {
        let cap_slot = boot.frame_base + i as u32;
        // Every RAM Frame cap memmgr ingests from init MUST carry
        // `Rights::RETYPE`. The kernel stamps RETYPE on usable RAM at
        // Phase-7 mint (`core/kernel/src/cap/mod.rs`), and init's
        // `finalize_memmgr` forwards caps through `cap_derive(_, RIGHTS_ALL)`
        // which preserves RETYPE. If this ever fires, memmgr cannot retype
        // these frames into kernel objects on its consumers' behalf and the
        // typed-memory contract is broken — fail fast at boot. The check
        // fires for at least the first cap (gating panic on i == 0);
        // subsequent caps would be debit-cheap to also check, but the
        // kernel mints them as a uniform batch so one is sufficient.
        if i == 0
        {
            // `packed` is `(tag << 32) | rights`; low 32 bits are rights, and
            // `RIGHTS_RETYPE` (1 << 21) is a low-bit-position right so the
            // comparison against the full u64 is exact. cap_info(slot,
            // TAG_RIGHTS) cannot fail on a non-null slot — init has just
            // forwarded the cap, so an Err here means the cap-routing graph
            // is broken and the bootstrap invariant fails.
            let Ok(packed) = syscall::cap_info(cap_slot, syscall::CAP_INFO_TAG_RIGHTS)
            else
            {
                panic!("memmgr: cap_info failed on bootstrap Frame cap");
            };
            assert!(
                packed & syscall::RIGHTS_RETYPE != 0,
                "memmgr: ingested RAM Frame cap missing RIGHTS_RETYPE",
            );
        }
        let _ = pool.push(FreeRun {
            cap_slot,
            page_count: boot.page_counts[i],
            phys_base: boot.phys_bases[i],
        });
    }
}

fn dispatch(req: &IpcMessage, ipc_buf: *mut u64, boot: &InitBootstrap)
{
    match req.label & 0xFFFF
    {
        memmgr_labels::REQUEST_FRAMES =>
        {
            handle_request_frames(req, ipc_buf);
        }
        memmgr_labels::RELEASE_FRAMES =>
        {
            handle_release_frames(req, ipc_buf);
        }
        memmgr_labels::REGISTER_PROCESS =>
        {
            handle_register_process(req, ipc_buf, boot.service_ep, boot.procmgr_token);
        }
        memmgr_labels::PROCESS_DIED =>
        {
            handle_process_died(req, ipc_buf, boot.procmgr_token);
        }
        _ =>
        {
            reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        }
    }
}

fn main(startup: &StartupInfo) -> !
{
    if syscall::ipc_buffer_set(startup.ipc_buffer as u64).is_err()
    {
        syscall::thread_exit();
    }

    // IPC buffer is page-aligned and registered.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    let Some(boot) = bootstrap_from_init(startup.creator_endpoint, startup.self_aspace, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    ingest_pool(&boot);

    // Auto-register procmgr's record so `REQUEST_FRAMES` against
    // procmgr's tokened SEND succeeds — procmgr's own std heap-bootstrap
    // is the first IPC memmgr serves after entering the loop. The
    // procmgr_token cap doubles as the auth gate for `REGISTER_PROCESS`
    // and `PROCESS_DIED`; both code paths still check `req.token` against
    // `boot.procmgr_token` independently of the table entry.
    if table_mut().insert(boot.procmgr_token).is_none()
    {
        // Process table full at boot — fatal; refuse to enter dispatch.
        syscall::thread_exit();
    }

    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(req) = (unsafe { ipc::ipc_recv(boot.service_ep, ipc_buf) })
        else
        {
            continue;
        };
        dispatch(&req, ipc_buf, &boot);
    }
}
