// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// memmgr/src/main.rs

//! Tier-1 userspace service that owns the userspace RAM memory-cap pool.
//!
//! memmgr serves memory-cap allocation, release, and per-process accounting over
//! IPC. See `memmgr/docs/{memory-pool,ipc-interface}.md` for the authoritative
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
use syscall_abi::{MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, PAGE_SIZE};

// memmgr's bootstrap parser carries page-count buffers on stack and
// pushes deeper through `bootstrap_from_init`; declare a 12-page
// (48 KiB) main-thread stack instead of the default 8 (32 KiB).
process_abi::stack_pages!(12);

// ── Bespoke runtime ─────────────────────────────────────────────────────────
//
// memmgr cannot share `std::sys::seraph::_start`: that path bootstraps a heap
// by calling `REQUEST_MEMORY_CAPS` against memmgr itself, and memmgr must serve
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
        service_registry_cap: info.service_registry_cap,
        stdin_memory_cap: info.stdin_memory_cap,
        stdout_memory_cap: info.stdout_memory_cap,
        stderr_memory_cap: info.stderr_memory_cap,
        system_root_cap: info.system_root_cap,
        current_dir_cap: info.current_dir_cap,
        stdin_data_notification_cap: info.stdin_data_notification_cap,
        stdin_space_notification_cap: info.stdin_space_notification_cap,
        stdout_data_notification_cap: info.stdout_data_notification_cap,
        stdout_space_notification_cap: info.stdout_space_notification_cap,
        stderr_data_notification_cap: info.stderr_data_notification_cap,
        stderr_space_notification_cap: info.stderr_space_notification_cap,
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
        pager_endpoint_cap: info.pager_endpoint_cap,
        pager_badge: info.pager_badge,
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
/// Maximum memory-cap records per process.
const MAX_PER_PROC: usize = 512;
/// Maximum demand-paged regions tracked per process. Generous for the
/// anonymous-memory consumer; a process needing more registers coarser regions.
const MAX_REGIONS_PER_PROC: usize = 8;
/// Maximum free runs in the pool. Each run is one Memory cap covering one
/// or more contiguous pages.
const MAX_FREE_RUNS: usize = 512;

/// Rights every pool frame MUST carry. A pool frame is general anonymous RAM:
/// memmgr derives an R / RW / RX inner from it on demand (`cap_derive`, which
/// only narrows), so the outer must hold WRITE (`1 << 1`) and EXECUTE
/// (`1 << 2`) — the `cap::slot::Rights` bit positions mirrored by
/// `RIGHTS_MAP_RW` / `RIGHTS_MAP_RX` — plus RETYPE so a consumer can still
/// retype the frame. READ is omitted: the kernel grants read at every map
/// (`sys_mem_map`) and the bulk usable-RAM caps are minted without it. Enforced
/// at both pool entry points (`ingest_pool`, `handle_donate_memory_caps`) so a
/// kernel mint-rights regression fails loudly instead of surfacing as an
/// intermittent consumer fault.
const POOL_FRAME_RIGHTS: u64 = ((syscall::RIGHTS_MAP_RW | syscall::RIGHTS_MAP_RX)
    & !syscall::RIGHTS_MAP_READ)
    | syscall::RIGHTS_RETYPE;

/// One free run: a Memory cap memmgr owns, covering `page_count` pages
/// starting at physical address `phys_base`.
#[derive(Clone, Copy)]
struct FreeRun
{
    cap_slot: u32,
    page_count: u32,
    phys_base: u64,
}

/// One per-process memory-cap record.
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct OwnedMemory
{
    /// Slot index in memmgr's `CSpace` where memmgr retains the outer
    /// derivation (the parent of the cap handed to the caller). Used to
    /// re-add the underlying region to the free pool when the process dies.
    cap_slot: u32,
    page_count: u32,
    phys_base: u64,
}

/// One demand-paged anonymous region a process registered via
/// `REGISTER_REGION`. A page fault inside `[va_base, va_base + len)` is backed
/// on demand with `prot`; a fault outside every region is declined.
#[derive(Clone, Copy)]
struct DemandRegion
{
    va_base: u64,
    len: u64,
    prot: u64,
}

/// Process accounting record: badge plus the list of memory caps memmgr has
/// issued to that process.
struct ProcessRecord
{
    badge: u64,
    used: usize,
    memory_caps: [Option<OwnedMemory>; MAX_PER_PROC],
    /// Demand-paged child `AddressSpace` cap delegated by procmgr, or `0` when
    /// the process is not demand-paged. memmgr maps fault-backing frames into
    /// it.
    aspace_cap: u32,
    /// Registered demand-paged regions and their live count.
    regions: [Option<DemandRegion>; MAX_REGIONS_PER_PROC],
    region_count: usize,
}

impl ProcessRecord
{
    // large_stack_arrays: ProcessRecord lives inside a `static mut`
    // ProcessTable, so this initializer never lands on a runtime stack
    // frame. const-evaluated at static-init time.
    #[allow(clippy::large_stack_arrays)]
    const fn new(badge: u64) -> Self
    {
        Self {
            badge,
            used: 0,
            memory_caps: [None; MAX_PER_PROC],
            aspace_cap: 0,
            regions: [None; MAX_REGIONS_PER_PROC],
            region_count: 0,
        }
    }

    /// Reuse this free slot for `badge`, in place. Resets only the scalar
    /// cursors — stale `memory_caps` / `regions` entries beyond `used` /
    /// `region_count` are never read, so they need no clearing. In-place reset
    /// is load-bearing: constructing a fresh `ProcessRecord` by value (~12 KiB)
    /// would overflow memmgr's VA-capped main-thread stack.
    fn reset(&mut self, badge: u64)
    {
        self.badge = badge;
        self.used = 0;
        self.aspace_cap = 0;
        self.region_count = 0;
    }

    fn push(&mut self, memory_cap: OwnedMemory) -> Result<(), ()>
    {
        if self.used >= MAX_PER_PROC
        {
            return Err(());
        }
        self.memory_caps[self.used] = Some(memory_cap);
        self.used += 1;
        Ok(())
    }

    /// Undo the most recent [`Self::push`]. Used to roll an accounting entry
    /// back when a later step in the same handler fails.
    fn pop(&mut self)
    {
        if self.used > 0
        {
            self.used -= 1;
            self.memory_caps[self.used] = None;
        }
    }

    /// Register a demand-paged region, rejecting overlap and over-quota.
    /// Returns the `memmgr_errors` code to reply with on failure.
    fn add_region(&mut self, region: DemandRegion) -> Result<(), u64>
    {
        if self.region_count >= MAX_REGIONS_PER_PROC
        {
            return Err(memmgr_errors::QUOTA);
        }
        let new_end = region.va_base.saturating_add(region.len);
        for existing in self.regions.iter().take(self.region_count).flatten()
        {
            let end = existing.va_base.saturating_add(existing.len);
            if region.va_base < end && existing.va_base < new_end
            {
                return Err(memmgr_errors::INVALID_ARGUMENT);
            }
        }
        self.regions[self.region_count] = Some(region);
        self.region_count += 1;
        Ok(())
    }

    /// Find the registered region containing `va`, if any.
    fn region_for(&self, va: u64) -> Option<DemandRegion>
    {
        for region in self.regions.iter().take(self.region_count).flatten()
        {
            if va >= region.va_base && va < region.va_base.saturating_add(region.len)
            {
                return Some(*region);
            }
        }
        None
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

    /// Push a run, coalescing once and retrying if the array is full.
    ///
    /// `push` fails only when all `MAX_FREE_RUNS` slots are occupied.
    /// Occupancy is dominated by fragmentation — many small runs `memory_merge`
    /// can fold into fewer, larger ones — so on a full array we `coalesce`
    /// (freeing a slot per successful merge) and retry the push once. `Err`
    /// means the array is still full afterward (every run physically
    /// disjoint). This governs free-pool *residency*, not ownership: a caller
    /// that retains the cap must account for it on ownership regardless of
    /// this result. Eliminating the fixed array (so residency cannot fail
    /// while RAM remains) is tracked as a separate redesign.
    fn push_or_coalesce(&mut self, run: FreeRun) -> Result<(), ()>
    {
        if self.push(run).is_ok()
        {
            return Ok(());
        }
        self.coalesce();
        self.push(run)
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

    /// Coalesce free runs into larger physically-contiguous chunks.
    ///
    /// `memory_merge` only joins runs adjacent in physical memory, so sorting
    /// the populated runs by `phys_base` places every mergeable pair
    /// consecutively. A single linear pass then folds each run into its
    /// lower-addressed neighbour with one `memory_merge` per pair: O(P)
    /// syscalls over P populated runs, versus the O(P²) of blind all-pairs
    /// probing. The distinction is load-bearing once the pool spans the whole
    /// machine and every process death coalesces — a syscall per ordered pair
    /// dominates teardown latency.
    // cast_possible_truncation: slot indices are bounded by MAX_FREE_RUNS
    // (512), so `i as u16` cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    fn coalesce(&mut self)
    {
        // Collect populated slot indices (slot < MAX_FREE_RUNS fits u16).
        let mut order = [0u16; MAX_FREE_RUNS];
        let mut n = 0usize;
        for (i, slot) in self.runs.iter().enumerate()
        {
            if slot.is_some()
            {
                order[n] = i as u16;
                n += 1;
            }
        }
        // Insertion sort by phys_base: P is small in practice and this needs
        // no allocator. None never appears in `order`, so map_or's default is
        // unreachable.
        for a in 1..n
        {
            let key = order[a];
            let key_phys = self.runs[key as usize].map_or(0, |r| r.phys_base);
            let mut b = a;
            while b > 0 && self.runs[order[b - 1] as usize].map_or(0, |r| r.phys_base) > key_phys
            {
                order[b] = order[b - 1];
                b -= 1;
            }
            order[b] = key;
        }
        // Fold each run into the current survivor while `memory_merge` accepts
        // the pair. The survivor is the lower-addressed run, so it is always
        // the merge parent; a rejection (non-adjacent or foreign parent) ends
        // this survivor's run and promotes the rejecting run to survivor.
        let mut s = 0usize;
        while s < n
        {
            let surv = order[s] as usize;
            let mut t = s + 1;
            while t < n
            {
                let (Some(parent), Some(tail)) = (self.runs[surv], self.runs[order[t] as usize])
                else
                {
                    break;
                };
                if syscall::memory_merge(parent.cap_slot, tail.cap_slot).is_err()
                {
                    break;
                }
                self.runs[surv] = Some(FreeRun {
                    cap_slot: parent.cap_slot,
                    page_count: parent.page_count + tail.page_count,
                    phys_base: parent.phys_base,
                });
                self.runs[order[t] as usize] = None;
                t += 1;
            }
            s = t;
        }
    }
}

/// Process tracking table: dense array of records, indexed by an internal
/// monotonically-incremented badge (held externally as the procmgr-minted
/// process identity).
struct ProcessTable
{
    /// Slots are stored inline (not `Option`) so insert/free never move a
    /// ~12 KiB `ProcessRecord` by value onto memmgr's VA-capped stack. A slot
    /// is free iff `badge == 0` (every minted badge is nonzero).
    records: [ProcessRecord; MAX_PROCESSES],
}

impl ProcessTable
{
    // large_stack_arrays: const-evaluated at static-initialization time. The
    // EMPTY record is all-zero, so the static lands in .bss — never a stack
    // frame.
    #[allow(clippy::large_stack_arrays)]
    const fn new() -> Self
    {
        const EMPTY: ProcessRecord = ProcessRecord::new(0);
        Self {
            records: [EMPTY; MAX_PROCESSES],
        }
    }

    /// Claim a free slot for `badge`, resetting it in place. Returns `None`
    /// when the table is full.
    fn insert(&mut self, badge: u64) -> Option<&mut ProcessRecord>
    {
        let slot = self.records.iter_mut().find(|slot| slot.badge == 0)?;
        slot.reset(badge);
        Some(slot)
    }

    fn find_mut(&mut self, badge: u64) -> Option<&mut ProcessRecord>
    {
        self.records.iter_mut().find(|slot| slot.badge == badge)
    }

    /// Mark the slot owned by `badge` free (reusable) in place. The caller has
    /// already reclaimed the record's resources.
    fn free(&mut self, badge: u64)
    {
        if let Some(rec) = self.find_mut(badge)
        {
            rec.badge = 0;
        }
    }
}

/// Badge counter for memmgr-minted process identities. Each
/// `REGISTER_PROCESS` call consumes one.
static NEXT_BADGE: AtomicU64 = AtomicU64::new(1);

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
// The init → memmgr bootstrap payload layout (round caps + data words and the
// auxiliary phys-table page) is defined in `ipc::memmgr_bootstrap`. memmgr
// reads the free-run prefix from the data words and, from the phys-table page,
// the per-cap physical bases plus the in-use bootstrap arenas (memmgr's,
// procmgr's, and init's own backing). The arenas are recorded against per-owner
// process records so `pool_total` spans every page of RAM memmgr owns, not only
// the free runs and reap donations.

/// Maximum free RAM memory caps init delivers in one bootstrap round; see
/// `ipc::memmgr_bootstrap::MAX_MEMORY_CAPS`.
const BOOTSTRAP_MAX_MEMORY_CAPS: usize = ipc::memmgr_bootstrap::MAX_MEMORY_CAPS;

/// Reserved process-table badge for memmgr's own bootstrap-backing record.
/// Out of range of every minted badge (memmgr's `NEXT_BADGE` and init's
/// bootstrap badges both start at 1), so no real caller can match it.
const MEMMGR_SELF_BADGE: u64 = u64::MAX;

/// Reserved process-table badge for init's orphaned bootstrap-backing record.
/// init exits at reap, so no live process owns its arena; its pages stay
/// parked and accounted here. Like `MEMMGR_SELF_BADGE`, far out of minted-badge
/// range, so no real caller can match it.
const INIT_SELF_BADGE: u64 = u64::MAX - 1;

/// Scratch VA in memmgr's address space for mapping the bootstrap
/// phys-table memory cap. One page; mapped RO during `bootstrap_from_init`,
/// unmapped before the dispatch loop entry.
const PHYS_TABLE_TEMP_VA: u64 = 0x0000_5000_0000_0000;

/// One in-use bootstrap arena delivered by init: a Memory cap covering a
/// tier-1 service's whole backing (retype slabs + offset-mapped pages),
/// recorded as an `OwnedMemory` against the owning service's record so its
/// pages count toward `pool_total`.
#[derive(Clone, Copy, Default)]
struct BootInUse
{
    cap_slot: u32,
    page_count: u32,
    phys_base: u64,
    kind: u64,
}

struct InitBootstrap
{
    service_ep: u32,
    procmgr_badge: u64,
    memory_base: u32,
    memory_count: u32,
    page_counts: [u32; BOOTSTRAP_MAX_MEMORY_CAPS],
    phys_bases: [u64; BOOTSTRAP_MAX_MEMORY_CAPS],
    in_use: [BootInUse; ipc::memmgr_bootstrap::MAX_IN_USE],
    in_use_count: usize,
    system_ram_bytes: u64,
    kernel_reserved_bytes: u64,
}

fn bootstrap_from_init(
    creator_ep: u32,
    self_aspace: u32,
    ipc_buf: *mut u64,
) -> Option<InitBootstrap>
{
    use ipc::memmgr_bootstrap as mb;

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
    let memory_count = round.data[1] as u32;
    let packed_words = (memory_count as usize).div_ceil(2);
    if (memory_count as usize) > BOOTSTRAP_MAX_MEMORY_CAPS || 3 + packed_words > round.data_words
    {
        return None;
    }
    // Unpack 2 page_counts per word: low 32 bits = even index, high 32
    // bits = odd index.
    let mut page_counts = [0u32; BOOTSTRAP_MAX_MEMORY_CAPS];
    for w in 0..packed_words
    {
        let word = round.data[3 + w];
        let lo = word as u32;
        let hi = (word >> 32) as u32;
        let i0 = w * 2;
        page_counts[i0] = lo;
        if i0 + 1 < memory_count as usize
        {
            page_counts[i0 + 1] = hi;
        }
    }

    // Map the phys-table memory cap and copy out memory_count u64 entries.
    let phys_table_cap = round.caps[1];
    let mut phys_bases = [0u64; BOOTSTRAP_MAX_MEMORY_CAPS];
    if syscall::mem_map(phys_table_cap, self_aspace, PHYS_TABLE_TEMP_VA, 0, 1, 0).is_err()
    {
        return None;
    }
    // SAFETY: PHYS_TABLE_TEMP_VA is mapped RO, one page. Init wrote the
    // first `memory_count` u64 entries; the rest is zero. The pointer is
    // page-aligned (4 KiB) so u64 alignment is satisfied.
    #[allow(clippy::cast_ptr_alignment)]
    let phys_ptr = PHYS_TABLE_TEMP_VA as *const u64;
    for (i, slot) in phys_bases
        .iter_mut()
        .enumerate()
        .take(memory_count as usize)
    {
        // SAFETY: i < memory_count <= BOOTSTRAP_MAX_MEMORY_CAPS = 122; 122 * 8 =
        // 976 B fits in one 4 KiB page.
        *slot = unsafe { core::ptr::read_volatile(phys_ptr.add(i)) };
    }

    // Read the in-use bootstrap arenas from the phys-table page's in-use
    // section (above the phys-base table and the immutable facts).
    // SAFETY: IN_USE_COUNT_IDX is within the mapped 4 KiB page.
    let in_use_count = (unsafe { core::ptr::read_volatile(phys_ptr.add(mb::IN_USE_COUNT_IDX)) }
        as usize)
        .min(mb::MAX_IN_USE);
    let mut in_use = [BootInUse::default(); mb::MAX_IN_USE];
    for (i, entry) in in_use.iter_mut().enumerate().take(in_use_count)
    {
        let base = mb::IN_USE_BASE_IDX + i * mb::IN_USE_WORDS;
        // SAFETY: base + 2 < IN_USE_BASE_IDX + MAX_IN_USE * IN_USE_WORDS, within the mapped page.
        let (w0, phys_base, kind) = unsafe {
            (
                core::ptr::read_volatile(phys_ptr.add(base)),
                core::ptr::read_volatile(phys_ptr.add(base + 1)),
                core::ptr::read_volatile(phys_ptr.add(base + 2)),
            )
        };
        *entry = BootInUse {
            cap_slot: w0 as u32,
            page_count: (w0 >> 32) as u32,
            phys_base,
            kind,
        };
    }

    // The kernel's immutable RAM-accounting facts, written by init at fixed
    // phys-table indices. They form the left side of the all-RAM-accounted
    // identity (`system_ram == kernel_reserved + pool_total`) surfaced via
    // `QUERY_POOL_STATUS`.
    // SAFETY: both indices are within the mapped 4 KiB page and past the
    // phys-base table.
    let (system_ram_bytes, kernel_reserved_bytes) = unsafe {
        (
            core::ptr::read_volatile(phys_ptr.add(mb::FACTS_SYSTEM_RAM_IDX)),
            core::ptr::read_volatile(phys_ptr.add(mb::FACTS_KERNEL_RESERVED_IDX)),
        )
    };

    let _ = syscall::mem_unmap(self_aspace, PHYS_TABLE_TEMP_VA, 1);
    let _ = syscall::cap_delete(phys_table_cap);

    Some(InitBootstrap {
        service_ep: round.caps[0],
        procmgr_badge: round.data[2],
        memory_base: round.data[0] as u32,
        memory_count,
        page_counts,
        phys_bases,
        in_use,
        in_use_count,
        system_ram_bytes,
        kernel_reserved_bytes,
    })
}

// ── Allocation primitives ────────────────────────────────────────────────────

/// Peel exactly `want` pages off the run at index `idx`. If the run is
/// larger, splits via `memory_split`; the residue is reinserted into the
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
    // Option-D memory_split: `run.cap_slot` shrinks in place to cover the
    // first `split_offset` bytes; the returned slot is the new tail covering
    // the remainder at `phys_base + split_offset`.
    let tail = syscall::memory_split(run.cap_slot, split_offset).ok()?;
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

/// Map a demand-region protection mask to the cap rights to derive for the
/// fault-backing inner cap: least-privilege, exactly the rights `mem_map` will
/// validate against the requested prot bits. `region.prot` is W^X-exclusive
/// (checked at registration), so this never produces a W+X cap.
fn rights_for_prot(prot: u64) -> u64
{
    if prot & MAP_EXECUTABLE != 0
    {
        syscall::RIGHTS_MAP_RX
    }
    else if prot & MAP_WRITABLE != 0
    {
        syscall::RIGHTS_MAP_RW
    }
    else
    {
        syscall::RIGHTS_MAP_READ
    }
}

// ── IPC handlers ─────────────────────────────────────────────────────────────

/// Reply slot count for `REQUEST_MEMORY_CAPS`. Per-cap page counts pack into
/// `data[1..1+count]`; `data[0]` holds the count itself.
const MAX_REPLY_CAPS: usize = syscall_abi::MSG_CAP_SLOTS_MAX;

/// One peeled selection entry: `(outer_cap_slot, page_count, phys_base)`.
type GrantEntry = (u32, u32, u64);

/// Result of a single `select_memory_caps` call: the array of peeled entries
/// plus the count of valid entries.
type GrantArray = [GrantEntry; MAX_REPLY_CAPS];

/// Pool selection for a single `REQUEST_MEMORY_CAPS` call. Returns the array of
/// peeled `(outer_cap, page_count, phys_base)` entries plus their count, or
/// an error code on failure. On error the pool is unchanged; on success the
/// caller owns each outer cap and is responsible for either accounting it
/// to a process record or pushing it back via `pool.push`.
fn select_memory_caps(
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

fn handle_request_memory_caps(req: &IpcMessage, ipc_buf: *mut u64)
{
    let badge = req.badge;
    let arg = req.word(0);
    let want_pages = (arg & 0xFFFF_FFFF) as u32;
    let flags = (arg >> 32) as u32;

    if want_pages == 0 || flags & !memmgr_labels::REQUIRE_CONTIGUOUS != 0
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    }

    let pool = pool_mut();
    let Some(record) = table_mut().find_mut(badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };

    let contiguous = flags & memmgr_labels::REQUIRE_CONTIGUOUS != 0;
    let (granted, granted_count) = match select_memory_caps(pool, want_pages, contiguous)
    {
        Ok(v) => v,
        Err(code) =>
        {
            let mut total_pages: u64 = 0;
            let mut run_count: u32 = 0;
            let mut max_run: u32 = 0;
            for r in pool.runs.iter().flatten()
            {
                total_pages += u64::from(r.page_count);
                run_count += 1;
                if r.page_count > max_run
                {
                    max_run = r.page_count;
                }
            }
            let reply = IpcMessage::builder(code)
                .word(0, total_pages)
                .word(1, u64::from(run_count))
                .word(2, u64::from(max_run))
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
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
            .push(OwnedMemory {
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
            record.memory_caps[record.used] = None;
            reply_label(ipc_buf, memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
            return;
        };
        inner[i] = d;
    }

    // Build the reply:
    //   data[0]                  = cap_count
    //   data[1..1+count]         = page_count_for_cap_i (u32 in low half)
    //   data[1+count..1+2*count] = phys_base_for_cap_i (u64)
    //   caps[0..count]           = Memory caps (MAP|WRITE)
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

fn handle_release_memory_caps(req: &IpcMessage, ipc_buf: *mut u64)
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

fn handle_register_process(req: &IpcMessage, ipc_buf: *mut u64, service_ep: u32, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }

    if req.word(0) != u64::from(ipc::MEMMGR_LABELS_VERSION)
    {
        reply_label(ipc_buf, memmgr_errors::LABEL_VERSION_MISMATCH);
        return;
    }

    let table = table_mut();
    let new_badge = NEXT_BADGE.fetch_add(1, Ordering::Relaxed);

    if table.insert(new_badge).is_none()
    {
        reply_label(ipc_buf, memmgr_errors::TOO_MANY_PROCESSES);
        return;
    }

    let Ok(send_cap) = syscall::cap_derive_badge(service_ep, syscall::RIGHTS_SEND_GRANT, new_badge)
    else
    {
        // Roll back the table insertion.
        table.free(new_badge);
        reply_label(ipc_buf, memmgr_errors::TOO_MANY_PROCESSES);
        return;
    };

    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, new_badge)
        .cap(send_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

fn handle_process_died(req: &IpcMessage, ipc_buf: *mut u64, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }
    // The dead process's badged SEND cap arrives in `caps[0]` (when the
    // caller transfers it). The kernel does not surface the badge of a
    // transferred cap to the receiver — only the badge of the
    // receive-side cap — so procmgr also encodes the dead process's
    // badge in `data[0]` for memmgr's table lookup.
    let dead_badge = req.word(0);

    // Auto-reclaim invariant (documented, not asserted in-line):
    //
    // By the time PROCESS_DIED reaches memmgr, procmgr has revoked +
    // deleted the child's CSpace, which cascades through every derived
    // inner Memory cap *and* every kernel object retyped from those caps.
    // Auto-reclaim (`KernelObjectHeader.ancestor`) credits each retype's
    // bytes back to the source `MemoryObject` — which memmgr's outer cap
    // and the child's inner cap share. With the child gone, only the
    // outer cap remains.
    //
    // We do *not* assert `available_bytes == size` here: the per-cap
    // `RetypeAllocator` metadata at offset 0 of the cap region (debited
    // on first retype) stays charged for as long as the MemoryObject
    // lives, which is until memmgr's outer cap is also released — i.e.
    // forever for pool caps. A correct cross-check would compare against
    // the available value snapshotted at grant time, which is more state
    // than memmgr's record currently carries; the ktest
    // `integration::retype_reclaim` covers the same invariant on a
    // dedicated source cap with no allocator residual.
    let pool = pool_mut();
    if let Some(record) = table_mut().find_mut(dead_badge)
    {
        for memory_cap in record.memory_caps.iter().take(record.used).flatten()
        {
            // Reachability-only: these pages were already counted in
            // pool_total at acquisition, so a failure here cannot break the
            // identity — coalesce-then-retry just shrinks the forgotten-cap
            // window. The trailing batch coalesce below still runs.
            let _ = pool.push_or_coalesce(FreeRun {
                cap_slot: memory_cap.cap_slot,
                page_count: memory_cap.page_count,
                phys_base: memory_cap.phys_base,
            });
        }
        // Restore contiguity across all reclaimed runs in one pass (the
        // per-cap `push_or_coalesce` above only fires `coalesce` under slot
        // pressure). Without coalescing, fragmentation accumulates
        // monotonically: every spawn-and-die cycle leaves the pool with
        // smaller runs than it started, until the array fills and
        // `push_or_coalesce` parks reclaimed memory caps (unreachable for
        // allocation, though still owned and accounted).
        pool.coalesce();

        // Drop memmgr's copy of a demand-paged process's delegated address
        // space, freeing the CSpace slot. The child's own AS is torn down by
        // procmgr; this only releases memmgr's reference.
        if record.aspace_cap != 0
        {
            let _ = syscall::cap_delete(record.aspace_cap);
        }
        // Free the slot in place (mark reusable); no by-value move.
        record.badge = 0;
    }
    // Idempotent: missing badge is not an error.

    // Drop any caps the caller transferred (typically the dead process's
    // badged SEND cap, no longer useful).
    for &slot in req.caps()
    {
        let _ = syscall::cap_delete(slot);
    }

    reply_label(ipc_buf, memmgr_errors::SUCCESS);
}

fn handle_donate_memory_caps(req: &IpcMessage, ipc_buf: *mut u64)
{
    // Caller (init or procmgr) is permanently transferring reclaimed Memory
    // caps (init's ELF segments, InitInfo, stack, boot-module ELF sources,
    // reclaim scratch, AP trampoline) into memmgr's pool. Each donated cap
    // must carry the full pool-frame rights ([`POOL_FRAME_RIGHTS`]) so memmgr
    // can derive the R / RW / RX inner a demand fault or REQUEST_MEMORY_CAPS
    // consumer needs and retype on their behalf.
    //
    // We trust the caller (single-tenant userspace; donation is gated by
    // possessing a memmgr SEND cap, which only init and procmgr hold) but
    // still validate the cap shape via `cap_info` — a malformed or under-rights
    // cap from a buggy loader should reject, not poison the pool.
    let pool = pool_mut();
    let mut accepted_caps: u32 = 0;
    let mut accepted_pages: u64 = 0;
    for &slot in req.caps()
    {
        // Required: Memory tag implied by MEMORY_SIZE selector returning Ok.
        // Required: full pool-frame rights (WRITE|EXECUTE|RETYPE).
        // Required: contiguous run (we read the whole cap as one run).
        let Ok(packed) = syscall::cap_info(slot, syscall::CAP_INFO_TAG_RIGHTS)
        else
        {
            let _ = syscall::cap_delete(slot);
            continue;
        };
        if packed & POOL_FRAME_RIGHTS != POOL_FRAME_RIGHTS
        {
            // Under-rights frame: cannot derive the R/RW/RX inner a demand
            // fault or REQUEST_MEMORY_CAPS consumer needs (cap_derive only
            // narrows). Reject rather than poison the pool — a pool frame that
            // silently lacks WRITE/EXECUTE surfaces later as an intermittent
            // consumer fault when allocation order happens to draw it. The
            // kernel mints every donatable RAM cap full-rights
            // (`core/kernel/src/main.rs`, `core/kernel/src/cap/mod.rs`), so this
            // only fires on a mint-rights regression.
            let _ = syscall::cap_delete(slot);
            continue;
        }
        let Ok(size_bytes) = syscall::cap_info(slot, syscall::CAP_INFO_MEMORY_SIZE)
        else
        {
            let _ = syscall::cap_delete(slot);
            continue;
        };
        let Ok(phys_base) = syscall::cap_info(slot, syscall::CAP_INFO_MEMORY_PHYS_BASE)
        else
        {
            let _ = syscall::cap_delete(slot);
            continue;
        };
        // cast_possible_truncation: page_count fits u32 for any single
        // run we accept (4 GiB max ≈ 1M pages, well under u32::MAX).
        #[allow(clippy::cast_possible_truncation)]
        let page_count = (size_bytes / 4096) as u32;
        // The cap is valid and now permanently owned by memmgr (it is never
        // deleted past this point). Count it on ownership, not on pool-slot
        // residency: pool_total must equal the live owned set whether the run
        // lands in a free slot or is parked because the array is full.
        accepted_caps += 1;
        accepted_pages += u64::from(page_count);
        pool_total_add(u64::from(page_count));
        // Best-effort placement. On failure (array full even after a coalesce
        // retry) the cap stays owned (counted above) but has no free-pool
        // slot, unreachable for allocation until a later coalesce frees one:
        // a reachability leak only, never an identity residual. The structural
        // fix is a non-fixed free pool (tracked separately).
        let _ = pool.push_or_coalesce(FreeRun {
            cap_slot: slot,
            page_count,
            phys_base,
        });
    }
    if accepted_caps > 0
    {
        pool.coalesce();
    }
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, u64::from(accepted_caps))
        .word(1, accepted_pages)
        .word(2, pool_total_pages())
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Reply with the all-RAM-accounted identity terms (all in bytes):
/// `system_ram`, `kernel_reserved`, `pool_total`. Read-only; the caller asserts
/// `system_ram == kernel_reserved + pool_total`. `pool_total` is the page
/// counter scaled to bytes; the facts arrive verbatim from the kernel.
fn handle_query_pool_status(ipc_buf: *mut u64, boot: &InitBootstrap)
{
    let pool_total_bytes = pool_total_pages().saturating_mul(PAGE_SIZE);
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, boot.system_ram_bytes)
        .word(1, boot.kernel_reserved_bytes)
        .word(2, pool_total_bytes)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Register a demand-paged anonymous region for the calling process.
///
/// Attributed by `req.badge` (the caller's per-process badge). The region is
/// validated (page alignment, nonzero length, W^X, known prot bits) and stored
/// against the caller's record; no mapping is installed here — backing happens
/// lazily in [`handle_fault`].
fn handle_register_region(req: &IpcMessage, ipc_buf: *mut u64)
{
    let va_base = req.word(0);
    let len = req.word(1);
    let prot = req.word(2);

    let known_prot = MAP_READ | MAP_WRITABLE | MAP_EXECUTABLE;
    let wx = MAP_WRITABLE | MAP_EXECUTABLE;
    if len == 0
        || !va_base.is_multiple_of(PAGE_SIZE)
        || !len.is_multiple_of(PAGE_SIZE)
        || va_base.checked_add(len).is_none()
        || prot & !known_prot != 0
        || prot & wx == wx
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    }

    let Some(record) = table_mut().find_mut(req.badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    match record.add_region(DemandRegion { va_base, len, prot })
    {
        Ok(()) => reply_label(ipc_buf, memmgr_errors::SUCCESS),
        Err(code) => reply_label(ipc_buf, code),
    }
}

/// Procmgr-only: store a demand-paged child's delegated `AddressSpace` cap so
/// [`handle_fault`] can map backing frames into it. Keyed by the child's
/// memmgr badge in `data[0]`; the cap arrives in `caps[0]`.
fn handle_delegate_aspace(req: &IpcMessage, ipc_buf: *mut u64, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        for &slot in req.caps()
        {
            let _ = syscall::cap_delete(slot);
        }
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }
    let child_badge = req.word(0);
    let Some(&as_cap) = req.caps().first()
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let Some(record) = table_mut().find_mut(child_badge)
    else
    {
        let _ = syscall::cap_delete(as_cap);
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    // Replace any prior delegation, dropping the stale cap.
    if record.aspace_cap != 0
    {
        let _ = syscall::cap_delete(record.aspace_cap);
    }
    record.aspace_cap = as_cap;
    reply_label(ipc_buf, memmgr_errors::SUCCESS);
}

/// Service a kernel-synthesized page fault for a demand-paged process.
///
/// `req.badge` is the faulting process's memmgr badge; words are
/// `[kind, faulting_va, access, ip]`. On a VM fault whose address lies in a
/// registered region of a process with a delegated address space, memmgr
/// allocates one frame, maps it at the faulting page with the region's
/// protection, and replies [`syscall_abi::FAULT_REPLY_RESUME`]. Every other
/// case — non-VM fault, unknown process, address outside every region, no
/// delegated AS, or any allocation/map failure — replies
/// [`syscall_abi::FAULT_REPLY_KILL`], preserving default segfault semantics.
///
/// The frame is accounted to the process record (reclaimed on `PROCESS_DIED`
/// like any other issued cap); `pool_total` is unchanged because the page was
/// already owned — it moves from a free run to the process's record.
fn handle_fault(req: &IpcMessage, ipc_buf: *mut u64)
{
    if req.word(0) != syscall_abi::FAULT_KIND_VM
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }
    let va = req.word(1);
    let page_base = va & !(PAGE_SIZE - 1);

    let pool = pool_mut();
    let Some(record) = table_mut().find_mut(req.badge)
    else
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    };
    let Some(region) = record.region_for(va)
    else
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    };
    if record.aspace_cap == 0
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }

    let Ok((granted, _count)) = select_memory_caps(pool, 1, true)
    else
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    };
    let (outer, pages, phys) = granted[0];

    // Account the frame so it is reclaimed on death; roll back to the pool on
    // any subsequent failure.
    if record
        .push(OwnedMemory {
            cap_slot: outer,
            page_count: pages,
            phys_base: phys,
        })
        .is_err()
    {
        let _ = pool.push(FreeRun {
            cap_slot: outer,
            page_count: pages,
            phys_base: phys,
        });
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }

    // Derive the inner mapping cap with exactly the rights the region's
    // protection needs (R / R+W / R+X), least-privilege. Pool outers are
    // full-rights (every RAM frame, including init's donated segments, carries
    // WRITE), so the narrowing always succeeds; `mem_map` then validates the
    // requested prot bits against these rights. Mirrors procmgr's RW mapping
    // pattern (`cap_derive(_, RIGHTS_MAP_RW)`).
    let Ok(inner) = syscall::cap_derive(outer, rights_for_prot(region.prot))
    else
    {
        record.pop();
        let _ = pool.push(FreeRun {
            cap_slot: outer,
            page_count: pages,
            phys_base: phys,
        });
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    };
    if syscall::mem_map(inner, record.aspace_cap, page_base, 0, 1, region.prot).is_err()
    {
        let _ = syscall::cap_delete(inner);
        record.pop();
        let _ = pool.push(FreeRun {
            cap_slot: outer,
            page_count: pages,
            phys_base: phys,
        });
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }
    // The kernel holds the mapping independently of the inner cap; the outer
    // pins the frame until reclaim.
    let _ = syscall::cap_delete(inner);
    reply_label(ipc_buf, syscall_abi::FAULT_REPLY_RESUME);
}

/// Total pages of RAM memmgr owns: every page it has taken ownership of since
/// boot, across all dispositions — bootstrap free runs, in-use bootstrap
/// arenas, and reap donations. memmgr never returns RAM to the kernel, and
/// `memory_split`/`memory_merge` preserve total page count, so this monotonic
/// counter equals the live owned set exactly.
///
/// Ownership — and therefore the count — is taken when memmgr *retains* a cap
/// (a donation that passes validation and is not deleted), independent of
/// whether the run finds a free-pool slot. A run parked because the slot array
/// is full is still owned and still counted; counting MUST NOT be gated on
/// `push` success, or the identity under-counts owned-but-parked RAM.
///
/// This is the `pool_total` of the all-RAM-accounted identity
/// (`system_ram == kernel_reserved + pool_total`). Surfaced in the
/// `DONATE_MEMORY_CAPS` reply (`word(2)`) so callers can read it without a separate
/// IPC. Single-threaded memmgr — plain static suffices.
static mut POOL_TOTAL_PAGES: u64 = 0;

fn pool_total_pages() -> u64
{
    // SAFETY: memmgr is single-threaded; no concurrent access.
    unsafe { POOL_TOTAL_PAGES }
}

fn pool_total_add(pages: u64)
{
    // SAFETY: memmgr is single-threaded; no concurrent access.
    unsafe {
        POOL_TOTAL_PAGES = POOL_TOTAL_PAGES.saturating_add(pages);
    }
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
    for i in 0..(boot.memory_count as usize)
    {
        let cap_slot = boot.memory_base + i as u32;
        // Every RAM Memory cap memmgr ingests from init MUST carry the full
        // pool-frame rights ([`POOL_FRAME_RIGHTS`]: WRITE | EXECUTE | RETYPE).
        // The kernel stamps these on usable RAM at Phase-7 mint
        // (`core/kernel/src/cap/mod.rs`), and init's `finalize_memmgr` forwards
        // caps through `cap_derive(_, RIGHTS_ALL)` which preserves them. If this
        // ever fires, memmgr cannot derive the writable/executable inner a
        // consumer needs (nor retype on its behalf) and the pool contract is
        // broken — fail fast at boot rather than surface as an intermittent
        // consumer fault. The check fires for at least the first cap (gating
        // panic on i == 0); the kernel mints them as a uniform batch so one is
        // sufficient.
        if i == 0
        {
            // `packed` is `(tag << 32) | rights`; low 32 bits are rights, and
            // every bit in `POOL_FRAME_RIGHTS` is a low-bit-position right so the
            // mask comparison against the full u64 is exact. cap_info(slot,
            // TAG_RIGHTS) cannot fail on a non-null slot — init has just
            // forwarded the cap, so an Err here means the cap-routing graph
            // is broken and the bootstrap invariant fails.
            let Ok(packed) = syscall::cap_info(cap_slot, syscall::CAP_INFO_TAG_RIGHTS)
            else
            {
                panic!("memmgr: cap_info failed on bootstrap Memory cap");
            };
            assert!(
                packed & POOL_FRAME_RIGHTS == POOL_FRAME_RIGHTS,
                "memmgr: ingested RAM Memory cap missing pool-frame rights (WRITE|EXECUTE|RETYPE)",
            );
        }
        // Ownership is taken on ingest — count on ownership, place best-effort
        // (mirrors `handle_donate_memory_caps`). Bootstrap never overflows the pool,
        // but `pool_total` must equal owned RAM uniformly across every ingest
        // site, never gated on free-slot residency.
        pool_total_add(u64::from(boot.page_counts[i]));
        let _ = pool.push_or_coalesce(FreeRun {
            cap_slot,
            page_count: boot.page_counts[i],
            phys_base: boot.phys_bases[i],
        });
    }
}

/// Record each in-use bootstrap arena as an `OwnedMemory` against the owning
/// service's process record so the arena's pages count toward `pool_total`.
/// The arenas are retype-pinned and offset-mapped for the immortal service's
/// life — memmgr never allocates from or frees them; this is pure accounting.
/// Both owner records (procmgr, memmgr-self) must already exist.
fn ingest_in_use(boot: &InitBootstrap)
{
    for entry in boot.in_use.iter().take(boot.in_use_count)
    {
        let badge = match entry.kind
        {
            ipc::memmgr_bootstrap::IN_USE_KIND_MEMMGR => MEMMGR_SELF_BADGE,
            ipc::memmgr_bootstrap::IN_USE_KIND_PROCMGR => boot.procmgr_badge,
            ipc::memmgr_bootstrap::IN_USE_KIND_INIT => INIT_SELF_BADGE,
            _ => continue,
        };
        // Owned on ingest — count on ownership; the per-process record is
        // best-effort tracking (these arenas are immortal, never reclaimed), so
        // a record miss must not under-count `pool_total`.
        pool_total_add(u64::from(entry.page_count));
        if let Some(record) = table_mut().find_mut(badge)
        {
            let _ = record.push(OwnedMemory {
                cap_slot: entry.cap_slot,
                page_count: entry.page_count,
                phys_base: entry.phys_base,
            });
        }
    }
}

fn dispatch(req: &IpcMessage, ipc_buf: *mut u64, boot: &InitBootstrap)
{
    // The kernel-synthesized fault IPC carries the full `FAULT_LABEL` sentinel
    // (`u64::MAX - 1`), which would alias other opcodes under the `& 0xFFFF`
    // mask below; match it on the full label first.
    if req.label == syscall_abi::FAULT_LABEL
    {
        handle_fault(req, ipc_buf);
        return;
    }
    match req.label & 0xFFFF
    {
        memmgr_labels::REQUEST_MEMORY_CAPS =>
        {
            handle_request_memory_caps(req, ipc_buf);
        }
        memmgr_labels::RELEASE_MEMORY_CAPS =>
        {
            handle_release_memory_caps(req, ipc_buf);
        }
        memmgr_labels::REGISTER_PROCESS =>
        {
            handle_register_process(req, ipc_buf, boot.service_ep, boot.procmgr_badge);
        }
        memmgr_labels::PROCESS_DIED =>
        {
            handle_process_died(req, ipc_buf, boot.procmgr_badge);
        }
        memmgr_labels::DONATE_MEMORY_CAPS =>
        {
            handle_donate_memory_caps(req, ipc_buf);
        }
        memmgr_labels::QUERY_POOL_STATUS =>
        {
            handle_query_pool_status(ipc_buf, boot);
        }
        memmgr_labels::REGISTER_REGION =>
        {
            handle_register_region(req, ipc_buf);
        }
        memmgr_labels::DELEGATE_ASPACE =>
        {
            handle_delegate_aspace(req, ipc_buf, boot.procmgr_badge);
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

    // Auto-register procmgr's record so `REQUEST_MEMORY_CAPS` against
    // procmgr's badged SEND succeeds — procmgr's own std heap-bootstrap
    // is the first IPC memmgr serves after entering the loop. The
    // procmgr_badge cap doubles as the auth gate for `REGISTER_PROCESS`
    // and `PROCESS_DIED`; both code paths still check `req.badge` against
    // `boot.procmgr_badge` independently of the table entry.
    //
    // Register memmgr-self and init-self records too: `ingest_in_use` files
    // memmgr's, procmgr's, and init's bootstrap arenas against them so every
    // arena's pages join `pool_total`. procmgr and memmgr never die; init exits
    // at reap but its arena stays parked, so none of these records is ever
    // reclaimed.
    if table_mut().insert(boot.procmgr_badge).is_none()
        || table_mut().insert(MEMMGR_SELF_BADGE).is_none()
        || table_mut().insert(INIT_SELF_BADGE).is_none()
    {
        // Process table full at boot — fatal; refuse to enter dispatch.
        syscall::thread_exit();
    }
    ingest_in_use(&boot);

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
