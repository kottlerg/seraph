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

use free_pool::{DemandRegion, FreePool, FreeRun, chunk_for, region_contains, regions_overlap};
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

// ── Metadata arena ────────────────────────────────────────────────────────────
//
// Per-process region and frame descriptors are not statically arrayed: each is
// a node drawn from a self-hosted arena of pool-backed pages, threaded onto a
// per-process intrusive list. Per-process region and frame capacity is thereby
// bounded by RAM, not by a compile-time constant — the demand-paged thread-stack
// consumer is the first O(threads) region/frame user and would overrun any fixed
// array.
//
// The arena only grows. A page, once carved into nodes, is permanent
// memmgr-owned metadata: it was counted in `pool_total` at ingest and is never
// returned, so the all-RAM-accounted identity is preserved. Growth stops at the
// peak concurrent node count — freed nodes return to the arena's own free list
// and are reused — so spawn/die churn leaks no pages.

/// Sentinel node index: empty list / free-list tail. `u32::MAX` is reserved, so
/// the arena addresses up to `u32::MAX - 1` nodes (far past any RAM-bound need).
const NODE_NULL: u32 = u32::MAX;

/// `va` stamped on a frame node memmgr did **not** map itself
/// (`REQUEST_MEMORY_CAPS` grants and bootstrap arenas): the caller owns the
/// mapping, so `UNREGISTER_REGION` must never unmap it. Demand-fault frames
/// carry their mapped page base instead.
const FRAME_VA_UNMAPPED: u64 = u64::MAX;

/// One arena node: a demand-paged region descriptor, a backing-frame
/// descriptor, or a free slot. Stored in pool-backed arena pages and reached by
/// index via [`slot_ptr`].
#[derive(Clone, Copy)]
enum Node
{
    Free,
    Region
    {
        va_base: u64,
        len: u64,
        prot: u64,
    },
    Frame
    {
        cap_slot: u32,
        page_count: u32,
        phys_base: u64,
        va: u64,
    },
}

/// An arena slot: a [`Node`] payload plus the index of the next slot in the
/// singly-linked list this slot currently belongs to (a per-process region or
/// frame list, or the global free list). `NODE_NULL` terminates the list.
#[derive(Clone, Copy)]
struct Slot
{
    node: Node,
    next: u32,
}

/// Base VA of the metadata arena in memmgr's own address space. Sits in the
/// free scratch band above [`PHYS_TABLE_TEMP_VA`] and below the high-canonical
/// stack / `ProcessInfo` / IPC-buffer region, giving a 16 TiB window.
const META_ARENA_BASE: u64 = 0x0000_6000_0000_0000;

/// Bytes per arena slot.
const NODE_SIZE: usize = core::mem::size_of::<Slot>();

/// Slots per arena page. The page remainder (`PAGE_SIZE % NODE_SIZE`) is unused
/// so no slot straddles a page boundary and index→VA stays a clean
/// (page, slot) split.
const NODES_PER_PAGE: usize = PAGE_SIZE as usize / NODE_SIZE;

// Arena allocator state. Single-threaded service — plain statics suffice; access
// is `unsafe` only because the storage is raw mapped memory, not for concurrency.
static mut ARENA_FREE_HEAD: u32 = NODE_NULL;
static mut ARENA_PAGES: u32 = 0;
static mut ARENA_SELF_ASPACE: u32 = 0;

/// Record memmgr's own `AddressSpace` cap for arena page mapping. Called once at
/// boot, before any node allocation.
fn arena_init(self_aspace: u32)
{
    // SAFETY: single-threaded; called once before the dispatch loop.
    unsafe { ARENA_SELF_ASPACE = self_aspace };
}

/// Raw pointer to slot `idx`. The slot's page is mapped for any index ever
/// returned by [`node_alloc`].
fn slot_ptr(idx: u32) -> *mut Slot
{
    let page = idx as usize / NODES_PER_PAGE;
    let slot = idx as usize % NODES_PER_PAGE;
    (META_ARENA_BASE as usize + page * PAGE_SIZE as usize + slot * NODE_SIZE) as *mut Slot
}

/// Map one pool frame as the next arena page and thread its slots onto the free
/// list. Returns `false` if the pool cannot spare a page (system RAM exhausted)
/// or the self-map fails.
fn arena_grow(pool: &mut FreePool) -> bool
{
    let Ok((granted, _)) = select_memory_caps(pool, 1, true)
    else
    {
        return false;
    };
    let (outer, _pages, phys) = granted[0];
    // SAFETY: single-threaded; set at boot / tracked here.
    let (self_aspace, page_idx) = unsafe { (ARENA_SELF_ASPACE, ARENA_PAGES) };
    let va = META_ARENA_BASE + u64::from(page_idx) * PAGE_SIZE;
    if syscall::mem_map(outer, self_aspace, va, 0, 1, MAP_READ | MAP_WRITABLE).is_err()
    {
        // Return the unusable frame to the pool; it stays owned and counted.
        let _ = pool.push(FreeRun {
            cap_slot: outer,
            page_count: 1,
            phys_base: phys,
        });
        return false;
    }
    // Carve the freshly-mapped page into free slots, prepended to the free list.
    // Every slot is fully initialized here, so later reads never touch
    // uninitialized arena memory.
    let first = page_idx as usize * NODES_PER_PAGE;
    for j in 0..NODES_PER_PAGE
    {
        let idx = (first + j) as u32;
        let next = if j + 1 < NODES_PER_PAGE
        {
            (first + j + 1) as u32
        }
        else
        {
            // SAFETY: single-threaded.
            unsafe { ARENA_FREE_HEAD }
        };
        // SAFETY: idx lies in the page just mapped at `va`; the pointer is in
        // range and 8-aligned. `ptr::write` initializes without reading prior
        // (uninitialized) bytes.
        unsafe {
            core::ptr::write(
                slot_ptr(idx),
                Slot {
                    node: Node::Free,
                    next,
                },
            );
        }
    }
    // SAFETY: single-threaded.
    unsafe {
        ARENA_FREE_HEAD = first as u32;
        ARENA_PAGES = page_idx + 1;
    }
    true
}

/// Pop a free slot, growing the arena if the free list is empty. Returns the
/// slot index for the caller to populate, or `None` on RAM exhaustion.
fn node_alloc(pool: &mut FreePool) -> Option<u32>
{
    // SAFETY: single-threaded.
    let mut head = unsafe { ARENA_FREE_HEAD };
    if head == NODE_NULL
    {
        if !arena_grow(pool)
        {
            return None;
        }
        // SAFETY: arena_grow set a non-null head.
        head = unsafe { ARENA_FREE_HEAD };
    }
    // SAFETY: head is a valid, mapped slot.
    let next = unsafe { (*slot_ptr(head)).next };
    // SAFETY: single-threaded.
    unsafe { ARENA_FREE_HEAD = next };
    Some(head)
}

/// Return slot `idx` to the free list.
fn node_free(idx: u32)
{
    // SAFETY: single-threaded; idx is a valid, mapped slot.
    unsafe {
        core::ptr::write(
            slot_ptr(idx),
            Slot {
                node: Node::Free,
                next: ARENA_FREE_HEAD,
            },
        );
        ARENA_FREE_HEAD = idx;
    }
}

/// Process accounting record: badge plus the heads of this process's intrusive
/// region and backing-frame lists. The list nodes live in the metadata arena.
struct ProcessRecord
{
    badge: u64,
    /// Head of the backing-frame list (`NODE_NULL` = empty).
    frame_head: u32,
    /// Head of the demand-paged region list (`NODE_NULL` = empty).
    region_head: u32,
    /// Demand-paged child `AddressSpace` cap delegated by procmgr, or `0` when
    /// the process is not demand-paged. memmgr maps fault-backing frames into
    /// it.
    aspace_cap: u32,
}

impl ProcessRecord
{
    const fn new(badge: u64) -> Self
    {
        Self {
            badge,
            frame_head: NODE_NULL,
            region_head: NODE_NULL,
            aspace_cap: 0,
        }
    }

    /// Reuse this free slot for `badge`. A slot reaches `badge == 0` either
    /// never-used (lists already empty) or via [`Self::reclaim_all`], which
    /// frees every node before the badge is cleared; the heads are therefore
    /// already `NODE_NULL`. Re-assert defensively.
    fn reset(&mut self, badge: u64)
    {
        self.badge = badge;
        self.frame_head = NODE_NULL;
        self.region_head = NODE_NULL;
        self.aspace_cap = 0;
    }

    /// Record a backing frame against this process. `va` is the page base memmgr
    /// mapped the frame at (demand fault), or [`FRAME_VA_UNMAPPED`] when the
    /// caller owns the mapping. Returns `Err` if the arena cannot grow.
    fn push_frame(
        &mut self,
        cap_slot: u32,
        page_count: u32,
        phys_base: u64,
        va: u64,
        pool: &mut FreePool,
    ) -> Result<(), ()>
    {
        let idx = node_alloc(pool).ok_or(())?;
        // SAFETY: idx is a fresh slot now owned by this record.
        unsafe {
            core::ptr::write(
                slot_ptr(idx),
                Slot {
                    node: Node::Frame {
                        cap_slot,
                        page_count,
                        phys_base,
                        va,
                    },
                    next: self.frame_head,
                },
            );
        }
        self.frame_head = idx;
        Ok(())
    }

    /// Undo the most recent [`Self::push_frame`] (LIFO), returning the node to
    /// the arena. The frame cap itself is the caller's to return to the pool.
    fn pop_frame(&mut self)
    {
        if self.frame_head != NODE_NULL
        {
            let idx = self.frame_head;
            // SAFETY: idx is a live frame node.
            self.frame_head = unsafe { (*slot_ptr(idx)).next };
            node_free(idx);
        }
    }

    /// Register a demand-paged region, rejecting overlap. Returns the
    /// `memmgr_errors` code to reply with on failure.
    fn add_region(&mut self, region: DemandRegion, pool: &mut FreePool) -> Result<(), u64>
    {
        let mut cur = self.region_head;
        while cur != NODE_NULL
        {
            // SAFETY: cur is a live region node.
            let s = unsafe { *slot_ptr(cur) };
            if let Node::Region { va_base, len, .. } = s.node
                && regions_overlap(region.va_base, region.len, va_base, len)
            {
                return Err(memmgr_errors::INVALID_ARGUMENT);
            }
            cur = s.next;
        }
        let idx = node_alloc(pool).ok_or(memmgr_errors::QUOTA)?;
        // SAFETY: idx is a fresh slot now owned by this record.
        unsafe {
            core::ptr::write(
                slot_ptr(idx),
                Slot {
                    node: Node::Region {
                        va_base: region.va_base,
                        len: region.len,
                        prot: region.prot,
                    },
                    next: self.region_head,
                },
            );
        }
        self.region_head = idx;
        Ok(())
    }

    /// Find the registered region containing `va`, if any.
    fn region_for(&self, va: u64) -> Option<DemandRegion>
    {
        let mut cur = self.region_head;
        while cur != NODE_NULL
        {
            // SAFETY: cur is a live region node.
            let s = unsafe { *slot_ptr(cur) };
            if let Node::Region { va_base, len, prot } = s.node
                && region_contains(va_base, len, va)
            {
                return Some(DemandRegion { va_base, len, prot });
            }
            cur = s.next;
        }
        None
    }

    /// True if a memmgr-mapped frame (chunk) already covers `page_base` — the
    /// page is backed, so a (re-)fault on it should resume without allocating.
    /// Guards against a stale-TLB redelivery of a page another fault's chunk
    /// already mapped.
    fn frame_covering(&self, page_base: u64) -> bool
    {
        let mut cur = self.frame_head;
        while cur != NODE_NULL
        {
            // SAFETY: cur is a live frame node.
            let s = unsafe { *slot_ptr(cur) };
            if let Node::Frame { va, page_count, .. } = s.node
                && va != FRAME_VA_UNMAPPED
                && page_base >= va
                && page_base < va + u64::from(page_count) * PAGE_SIZE
            {
                return true;
            }
            cur = s.next;
        }
        false
    }

    /// Remove the region exactly matching `[va_base, va_base + len)`, freeing
    /// its node. Returns the removed descriptor, or `None` if no exact match.
    fn remove_region(&mut self, va_base: u64, len: u64) -> Option<DemandRegion>
    {
        let mut prev = NODE_NULL;
        let mut cur = self.region_head;
        while cur != NODE_NULL
        {
            // SAFETY: cur is a live region node.
            let s = unsafe { *slot_ptr(cur) };
            if let Node::Region {
                va_base: rb,
                len: rl,
                prot,
            } = s.node
                && rb == va_base
                && rl == len
            {
                if prev == NODE_NULL
                {
                    self.region_head = s.next;
                }
                else
                {
                    // SAFETY: prev is a live region node.
                    unsafe { (*slot_ptr(prev)).next = s.next };
                }
                node_free(cur);
                return Some(DemandRegion {
                    va_base: rb,
                    len: rl,
                    prot,
                });
            }
            prev = cur;
            cur = s.next;
        }
        None
    }

    /// Return to the pool every memmgr-mapped frame whose page base lies in
    /// `[base, end)`, freeing its tracking node. Used by `UNREGISTER_REGION`:
    /// the caller has already cleared the span's leaf PTEs and reclaimed the
    /// intermediate page tables via `mem_unmap_reclaim`, so this only re-pools
    /// the backing frames. Frames the caller mapped ([`FRAME_VA_UNMAPPED`]) are
    /// left untouched.
    fn return_frames_in(&mut self, base: u64, end: u64, pool: &mut FreePool)
    {
        let mut prev = NODE_NULL;
        let mut cur = self.frame_head;
        while cur != NODE_NULL
        {
            // SAFETY: cur is a live frame node.
            let s = unsafe { *slot_ptr(cur) };
            let next = s.next;
            if let Node::Frame {
                cap_slot,
                page_count,
                phys_base,
                va,
            } = s.node
                && va != FRAME_VA_UNMAPPED
                && va >= base
                && va < end
            {
                let _ = pool.push_or_coalesce(FreeRun {
                    cap_slot,
                    page_count,
                    phys_base,
                });
                if prev == NODE_NULL
                {
                    self.frame_head = next;
                }
                else
                {
                    // SAFETY: prev is a live frame node.
                    unsafe { (*slot_ptr(prev)).next = next };
                }
                node_free(cur);
                cur = next;
                continue;
            }
            prev = cur;
            cur = next;
        }
    }

    /// Return a single caller-owned grant — identified by `phys` — to the pool
    /// mid-life, freeing its tracking node. Matches the first `Node::Frame`
    /// with `phys_base == phys` and `va == FRAME_VA_UNMAPPED`: only frames
    /// issued via `REQUEST_MEMORY_CAPS` (caller owns the mapping) are
    /// releasable this way; demand-mapped chunks (`va != FRAME_VA_UNMAPPED`)
    /// are reclaimed only via `UNREGISTER_REGION` / `PROCESS_DIED` and are
    /// skipped. Returns whether a grant matched.
    ///
    /// The run may be "dirty": its `MemoryObject` keeps the retype bump pointer
    /// advanced even after the caller's retype was freed. `push_or_coalesce` is
    /// sound regardless — `coalesce`'s `memory_merge` guards every join with
    /// `.is_err()` and the kernel refuses to merge a non-virgin tail
    /// (`sys_memory_merge`) or split past the bump (`sys_memory_split`), so a
    /// dirty run is parked discrete and re-granted whole, reusing the kernel's
    /// retype free-list. A varied-size workload that releases dirty runs may
    /// see mild fragmentation (no sub-splitting until the run goes virgin);
    /// same-size churn (the Thread-retype slab) is unaffected.
    fn release_frame_by_phys(&mut self, phys: u64, pool: &mut FreePool) -> bool
    {
        let mut prev = NODE_NULL;
        let mut cur = self.frame_head;
        while cur != NODE_NULL
        {
            // SAFETY: cur is a live frame node.
            let s = unsafe { *slot_ptr(cur) };
            if let Node::Frame {
                cap_slot,
                page_count,
                phys_base,
                va,
            } = s.node
                && va == FRAME_VA_UNMAPPED
                && phys_base == phys
            {
                let _ = pool.push_or_coalesce(FreeRun {
                    cap_slot,
                    page_count,
                    phys_base,
                });
                if prev == NODE_NULL
                {
                    self.frame_head = s.next;
                }
                else
                {
                    // SAFETY: prev is a live frame node.
                    unsafe { (*slot_ptr(prev)).next = s.next };
                }
                node_free(cur);
                return true;
            }
            prev = cur;
            cur = s.next;
        }
        false
    }

    /// Reclaim every frame and region node on process death: each frame cap
    /// returns to the pool (the kernel's cspace-revoke cascade, run by procmgr
    /// before this point, already tore down the child's mappings, so no unmap
    /// is needed here), and every node returns to the arena.
    fn reclaim_all(&mut self, pool: &mut FreePool)
    {
        let mut cur = self.frame_head;
        while cur != NODE_NULL
        {
            // SAFETY: cur is a live frame node.
            let s = unsafe { *slot_ptr(cur) };
            if let Node::Frame {
                cap_slot,
                page_count,
                phys_base,
                ..
            } = s.node
            {
                let _ = pool.push_or_coalesce(FreeRun {
                    cap_slot,
                    page_count,
                    phys_base,
                });
            }
            node_free(cur);
            cur = s.next;
        }
        self.frame_head = NODE_NULL;

        let mut cur = self.region_head;
        while cur != NODE_NULL
        {
            // SAFETY: cur is a live region node.
            let next = unsafe { (*slot_ptr(cur)).next };
            node_free(cur);
            cur = next;
        }
        self.region_head = NODE_NULL;
    }
}

/// Process tracking table: dense array of records, indexed by an internal
/// monotonically-incremented badge (held externally as the procmgr-minted
/// process identity).
struct ProcessTable
{
    /// Slots are stored inline; a slot is free iff `badge == 0` (every minted
    /// badge is nonzero). Inserts and frees reset in place — the per-process
    /// region and frame lists live in the arena, not in the record.
    records: [ProcessRecord; MAX_PROCESSES],
}

impl ProcessTable
{
    // Const-evaluated at static-initialization time; never a stack frame.
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

// Per-process tracking and the free pool live in statics so the bookkeeping
// never lands on a syscall stack frame. memmgr is single-threaded — its only
// thread runs the main dispatch loop and owns these tables exclusively, so the
// `static mut` reads/writes are sound.
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
/// recorded as a backing frame against the owning service's record so its
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

/// Binds the free pool's platform-injected merge/split operations to the real
/// kernel syscalls. The pure allocator in `free_pool` takes `memory_merge` /
/// `memory_split` as closures so it stays host-testable; this trait re-presents
/// the bound `coalesce` / `push_or_coalesce` so every call site keeps its
/// original shape. `memory_merge`'s `Ok` is the pure-logic "join accepted".
trait PoolExt
{
    fn coalesce(&mut self);
    fn push_or_coalesce(&mut self, run: FreeRun) -> Result<(), ()>;
}

impl PoolExt for FreePool
{
    fn coalesce(&mut self)
    {
        self.coalesce_with(|parent, tail| syscall::memory_merge(parent, tail).is_ok());
    }

    fn push_or_coalesce(&mut self, run: FreeRun) -> Result<(), ()>
    {
        self.push_or_coalesce_with(run, |parent, tail| {
            syscall::memory_merge(parent, tail).is_ok()
        })
    }
}

/// Peel exactly `want` pages off the run at index `idx`, binding the kernel's
/// `memory_split` (Option-D: shrink in place, return the tail cap) to the
/// pool's injected split closure.
fn take_exactly(pool: &mut FreePool, idx: usize, want: u32) -> Option<(u32, u64)>
{
    pool.take_exactly(idx, want, |cap, offset| {
        syscall::memory_split(cap, offset).ok()
    })
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

    // Best-effort: a single best-fit run satisfies the request with the fewest
    // caps and reuses a freed run of the requested size instead of re-splitting
    // a larger one, so churn that frees and re-requests a fixed size cycles the
    // same run (and the same anchor slot) rather than leaking one per request.
    // Fall back to greedy largest-first only when no single run is large enough.
    if let Some(idx) = pool.smallest_fit(want_pages)
        && let Some((outer, phys)) = take_exactly(pool, idx, want_pages)
    {
        granted[0] = (outer, want_pages, phys);
        return Ok((granted, 1));
    }

    // Fallback: greedy, largest-first across multiple runs, bounded by reply slots.
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
            .push_frame(outer, pages, phys, FRAME_VA_UNMAPPED, pool)
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
            // Drop the just-pushed frame node too.
            record.pop_frame();
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
    // Drop any inner caps the caller still holds. The common caller (ruststd
    // releasing a reclaimed Thread-retype slab) already deleted its inner cap
    // after retype, so this is usually empty; it is defensive for callers that
    // hand the cap back too.
    for &slot in req.caps()
    {
        let _ = syscall::cap_delete(slot);
    }

    let pool = pool_mut();
    let Some(record) = table_mut().find_mut(req.badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };

    // Each word names a previously-granted region by physical base (the value
    // memmgr reported in the grant reply). Return every match to the pool;
    // unmatched bases are ignored, so release is idempotent and a racing
    // double-release (a joined thread plus the detached-thread reaper) is
    // harmless. Clamp to the words actually present to stay in bounds.
    let count = (req.word(0) as usize).min(req.word_count().saturating_sub(1));
    for i in 0..count
    {
        let phys = req.word(1 + i);
        let _ = record.release_frame_by_phys(phys, pool);
    }
    // Restore contiguity across the released runs. As in `handle_unregister_region`,
    // `push_or_coalesce` only coalesces under slot pressure, so a release-heavy
    // churn (ruststd returning Thread-retype slabs on join/reap) would otherwise
    // fragment the pool monotonically.
    pool.coalesce();
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
        // Return every backing frame to the pool and free all region and frame
        // nodes to the arena. Reachability-only for the identity: these pages
        // were already counted in pool_total at acquisition, so a parked run
        // here cannot break it. The kernel's cspace-revoke cascade (run by
        // procmgr before this message) already tore down the child's mappings,
        // so no unmap is performed.
        record.reclaim_all(pool);
        // Restore contiguity across all reclaimed runs in one pass (the
        // per-frame `push_or_coalesce` above only fires `coalesce` under slot
        // pressure). Without coalescing, fragmentation accumulates
        // monotonically: every spawn-and-die cycle leaves the pool with
        // smaller runs than it started, until the array fills and
        // `push_or_coalesce` parks reclaimed memory caps (unreachable for
        // allocation, though still owned and accounted).
        pool.coalesce();

        // Do NOT delete memmgr's delegated address-space cap here. It is a
        // `cap_derive` child of the child's AddressSpace cap (procmgr's
        // `DELEGATE_ASPACE` derivation), so procmgr's `cap_revoke` of that
        // AddressSpace during child teardown — which runs before this
        // `PROCESS_DIED` — has already revoked memmgr's copy and freed its
        // CSpace slot. By this point `record.aspace_cap` is a stale slot index
        // that memmgr's allocator may have already reused for an unrelated cap
        // (e.g. a pool-run tail); deleting it would free that unrelated cap and
        // corrupt the free pool. The delegated copy's teardown is owned by
        // procmgr's revocation of the parent aspace.
        record.aspace_cap = 0;
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

/// Reply with the all-RAM-accounted identity terms plus the current free total
/// (all in bytes): `system_ram`, `kernel_reserved`, `pool_total`, `free`.
/// Read-only; the caller asserts `system_ram == kernel_reserved + pool_total`.
/// `pool_total` is the monotonic owned-RAM counter scaled to bytes; `free` is
/// the subset currently parked in free runs (lent to no process), which falls
/// on allocation and rises on reclamation. The identity facts arrive verbatim
/// from the kernel.
fn handle_query_pool_status(ipc_buf: *mut u64, boot: &InitBootstrap)
{
    let pool_total_bytes = pool_total_pages().saturating_mul(PAGE_SIZE);
    let free_bytes = pool_mut().free_pages().saturating_mul(PAGE_SIZE);
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, boot.system_ram_bytes)
        .word(1, boot.kernel_reserved_bytes)
        .word(2, pool_total_bytes)
        .word(3, free_bytes)
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

    let pool = pool_mut();
    let Some(record) = table_mut().find_mut(req.badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    match record.add_region(DemandRegion { va_base, len, prot }, pool)
    {
        Ok(()) => reply_label(ipc_buf, memmgr_errors::SUCCESS),
        Err(code) => reply_label(ipc_buf, code),
    }
}

/// Unregister a demand-paged region for the calling process, reclaiming every
/// frame memmgr mapped inside it.
///
/// Attributed by `req.badge`; words are `[va_base, len_bytes]`. The range must
/// match a previously [`handle_register_region`]'d region exactly. memmgr
/// unmaps each backing frame from the child `AddressSpace`, returns it to the
/// pool, and frees the region. The reverse of registration plus the frames
/// [`handle_fault`] mapped. Reply: [`memmgr_errors::SUCCESS`], or
/// `INVALID_ARGUMENT` (unknown badge or no exact-match region).
fn handle_unregister_region(req: &IpcMessage, ipc_buf: *mut u64)
{
    let va_base = req.word(0);
    let len = req.word(1);

    let pool = pool_mut();
    let Some(record) = table_mut().find_mut(req.badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let Some(region) = record.remove_region(va_base, len)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let end = region.va_base.saturating_add(region.len);
    let aspace_cap = record.aspace_cap;
    // Tear down the whole region span in the child AS in one call: clear every
    // leaf PTE and reclaim the now-empty intermediate page tables to the child's
    // PT growth pool (one coarse shootdown). Done before re-pooling the backing
    // frames so no frame is re-handed to a future fault before its PTE clears.
    let _ = syscall::mem_unmap_reclaim(aspace_cap, region.va_base, region.len / PAGE_SIZE);
    record.return_frames_in(region.va_base, end, pool);
    // Restore contiguity across the reclaimed runs. The per-frame
    // `push_or_coalesce` only fires `coalesce` under slot pressure, so a churn
    // working set that never fills the array would otherwise leave the pool more
    // fragmented after each register/unregister cycle, drifting the run (and
    // tracking-anchor) count up monotonically across a long run.
    pool.coalesce();
    reply_label(ipc_buf, memmgr_errors::SUCCESS);
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
/// registered region of a process with a delegated address space, memmgr backs
/// the [`chunk_for`] chunk containing the faulting page — one contiguous
/// Memory cap mapped across up to `DEMAND_CHUNK_PAGES` pages — and replies
/// [`syscall_abi::FAULT_REPLY_RESUME`]. Backing a chunk rather than a single
/// page bounds cap-slot consumption (one cap per chunk) so a deep demand stack
/// cannot exhaust memmgr's `CSpace`. Every other case — non-VM fault, unknown
/// process, address outside every region, no delegated AS, or any
/// allocation/map failure — replies [`syscall_abi::FAULT_REPLY_KILL`],
/// preserving default segfault semantics.
///
/// The chunk is accounted to the process record (reclaimed on `PROCESS_DIED` /
/// `UNREGISTER_REGION` like any issued cap); `pool_total` is unchanged because
/// the pages were already owned — they move from a free run to the record.
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
    // Already backed by an earlier chunk (stale-TLB redelivery): resume.
    if record.frame_covering(page_base)
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_RESUME);
        return;
    }

    // Back the whole chunk containing the faulting page with one Memory cap.
    let (chunk_base, chunk_pages) = chunk_for(&region, page_base);
    let Ok((granted, _count)) = select_memory_caps(pool, chunk_pages, true)
    else
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    };
    let (outer, pages, phys) = granted[0];

    // Account the chunk so it is reclaimed on death/unregister; roll back to the
    // pool on any subsequent failure. `chunk_base` is the chunk's mapped VA so
    // UNREGISTER_REGION can find and unmap it.
    if record
        .push_frame(outer, pages, phys, chunk_base, pool)
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

    // Map the whole chunk into the child at `chunk_base` with the region's prot.
    // Pool outers are full-rights, so `mem_map` gates the mapping to `region.prot`
    // directly (the kernel grants read at every map, and W^X is enforced); no
    // per-fault inner derivation is needed. The kernel holds the mapping
    // independently of the cap, which stays in memmgr as the reclaim anchor.
    if syscall::mem_map(
        outer,
        record.aspace_cap,
        chunk_base,
        0,
        u64::from(pages),
        region.prot,
    )
    .is_err()
    {
        record.pop_frame();
        let _ = pool.push(FreeRun {
            cap_slot: outer,
            page_count: pages,
            phys_base: phys,
        });
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }
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

/// Record each in-use bootstrap arena as a backing frame against the owning
/// service's process record so the arena's pages count toward `pool_total`.
/// The arenas are retype-pinned and offset-mapped for the immortal service's
/// life — memmgr never allocates from or frees them; this is pure accounting.
/// Both owner records (procmgr, memmgr-self) must already exist. Frames carry
/// [`FRAME_VA_UNMAPPED`]: memmgr did not map them, so no `UNREGISTER_REGION`
/// path ever unmaps them.
fn ingest_in_use(boot: &InitBootstrap)
{
    let pool = pool_mut();
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
            let _ = record.push_frame(
                entry.cap_slot,
                entry.page_count,
                entry.phys_base,
                FRAME_VA_UNMAPPED,
                pool,
            );
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
        memmgr_labels::UNREGISTER_REGION =>
        {
            handle_unregister_region(req, ipc_buf);
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

    // The metadata arena maps its pages into memmgr's own AS; record the cap
    // before any per-process node is allocated (the first is in `ingest_in_use`).
    arena_init(startup.self_aspace);

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

    // memmgr has no log channel; on persistent recv failure its signals are
    // the kernel's rate-limited pre-allocate diagnostic and the loud
    // EXIT_RECV_WEDGE death itself.
    let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let req = match unsafe { ipc::ipc_recv(boot.service_ep, ipc_buf) }
        {
            Ok(req) => req,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        dispatch(&req, ipc_buf, &boot);
    }
}
