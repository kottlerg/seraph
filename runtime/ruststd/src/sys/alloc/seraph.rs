// seraph-overlay: std::sys::alloc::seraph
//
// Seraph PAL allocator: a spinlock-guarded first-fit free list whose
// backing pages are lazily requested from memmgr. All syscall wrappers
// and protocol labels come from the workspace crates `syscall-abi`,
// `syscall`, and `ipc`, pulled into std's dep graph through
// `library/std/Cargo.toml` — mirrors the `hermit-abi` /
// `fortanix-sgx-abi` pattern. The overlay itself holds no inline asm
// and duplicates no protocol numbers. Heap-zone VAs are private
// constants below; the page-reservation allocator (`std::sys::reserve`)
// owns its own arena disjoint from the heap.
//
// Bootstrap is explicit: `std::os::seraph::heap_bootstrap(procmgr_ep,
// self_aspace)` must be called once, after the bootstrap IPC round
// that produces `procmgr_ep`, before the first allocation. An
// allocation before bootstrap returns a null pointer and the alloc
// crate aborts via `handle_alloc_error`.
//
// The IPC buffer pointer used by `grow` is read from the TLS slot
// populated in `_start` / the thread trampoline (see
// `std::os::seraph::current_ipc_buf`). Each thread's allocation-
// triggered grow thus targets the buffer the kernel actually reads
// from for that thread.
//
// `unsafe impl GlobalAlloc for System` below delegates to the static
// heap; services that want this allocator simply omit a custom
// `#[global_allocator]` and use `System` (std's default).

use crate::alloc::{GlobalAlloc, Layout, System};
use crate::cell::UnsafeCell;
use crate::mem::{align_of, size_of};
use crate::os::seraph::current_ipc_buf;
use crate::ptr::{NonNull, null_mut};
use crate::sync::atomic::{AtomicBool, Ordering};

use ipc::memmgr_labels::REQUEST_FRAMES;
use syscall_abi::{MAP_WRITABLE, PAGE_SIZE};

// Heap-zone VAs are private to the std-overlay allocator. They sit
// well below the page-reservation arena (`RESERVE_ARENA_BASE = 0x1_0000_0000`)
// and are ASLR-pending: a one-line change here switches each constant
// to a per-process RNG draw once the kernel RNG lands.

/// Heap base (inclusive).
const HEAP_BASE: u64 = 0x0000_0000_4000_0000;

/// Heap zone upper bound (exclusive). Maximum heap size = `HEAP_MAX -
/// HEAP_BASE` = 1 GiB. Growth beyond this surfaces OOM.
const HEAP_MAX: u64 = 0x0000_0000_8000_0000;

/// Initial heap size at `_start`, in 4 KiB pages. Sized to cover stdio's
/// lazy line-buffer, two worker-thread stacks plus their per-thread IPC
/// buffer pages, and typical collection workloads. Cost is one
/// `REQUEST_FRAMES` round-trip at bootstrap, ≈ 512 KiB of physical RAM.
const HEAP_INITIAL_PAGES: u64 = 128;

/// Minimum grow increment in pages. Allocation-failure retries extend the
/// heap by at least this many 4 KiB pages to amortise the memmgr IPC
/// round-trip over many small follow-up allocations. 16 pages = 64 KiB.
const GROW_MIN_PAGES: u64 = 16;

/// Upper bound on a single `grow` call's page count. memmgr's reply is
/// bounded by `MSG_CAP_SLOTS_MAX = 4` Frame caps per round; with
/// best-effort allocation each cap may cover many pages, so this cap is
/// no longer driven by per-page CSpace consumption (as it was under
/// procmgr's one-cap-per-page ABI). Kept large enough that typical
/// large `Vec` reallocations stay within a single round.
const GROW_MAX_PAGES: u64 = 256;

// ── Spinlock ────────────────────────────────────────────────────────────────

struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    const fn new() -> Self {
        Self { locked: AtomicBool::new(false) }
    }

    fn lock(&self) {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

// ── Free-list node ──────────────────────────────────────────────────────────

#[repr(C)]
struct FreeNode {
    size: usize,
    next: Option<NonNull<FreeNode>>,
}

const NODE_SIZE: usize = size_of::<FreeNode>();
const NODE_ALIGN: usize = align_of::<FreeNode>();
const MIN_BLOCK: usize = NODE_SIZE;

fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

// ── Heap ────────────────────────────────────────────────────────────────────

struct Heap {
    head: Option<NonNull<FreeNode>>,
    /// First VA above the currently mapped heap region. Grows upward toward
    /// `HEAP_MAX` as `grow` maps fresh frames. Zero before bootstrap.
    mapped_end: usize,
    /// Cached memmgr endpoint cap used by `grow` to request additional
    /// frames. Zero before bootstrap; `grow` returns false in that state.
    memmgr_ep: u32,
    /// Cached aspace cap for mapping grow-path frames. Zero before bootstrap.
    self_aspace: u32,
}

impl Heap {
    const fn new() -> Self {
        Self {
            head: None,
            mapped_end: 0,
            memmgr_ep: 0,
            self_aspace: 0,
        }
    }

    /// # Safety
    /// `base..base+size` must be a writable, exclusively-owned region that
    /// stays mapped for the process's lifetime.
    unsafe fn init(&mut self, base: usize, size: usize) {
        if size < NODE_SIZE {
            return;
        }
        let node = base as *mut FreeNode;
        unsafe {
            (*node).size = size;
            (*node).next = None;
        }
        self.head = NonNull::new(node);
    }

    /// # Safety
    /// `ptr..ptr+size` must be a freed allocation previously returned by `alloc`.
    unsafe fn insert(&mut self, ptr: usize, size: usize) {
        let mut cur = self.head;
        let mut prev: Option<NonNull<FreeNode>> = None;
        while let Some(c) = cur {
            if (c.as_ptr() as usize) > ptr {
                break;
            }
            prev = Some(c);
            unsafe { cur = (*c.as_ptr()).next };
        }

        let new_node = ptr as *mut FreeNode;
        unsafe {
            (*new_node).size = size;
            (*new_node).next = cur;
        }

        match prev {
            Some(p) => unsafe { (*p.as_ptr()).next = NonNull::new(new_node) },
            None => self.head = NonNull::new(new_node),
        }

        let inserted = NonNull::new(new_node).unwrap();
        unsafe { Self::try_coalesce(inserted) };
        if let Some(p) = prev {
            unsafe { Self::try_coalesce(p) };
        }
    }

    /// # Safety
    /// `node` must point to a valid free-list node owned by this heap.
    unsafe fn try_coalesce(node: NonNull<FreeNode>) {
        unsafe {
            let n = node.as_ptr();
            let Some(next) = (*n).next else {
                return;
            };
            let next_ptr = next.as_ptr() as usize;
            let n_end = node.as_ptr() as usize + (*n).size;
            if n_end == next_ptr {
                (*n).size += (*next.as_ptr()).size;
                (*n).next = (*next.as_ptr()).next;
            }
        }
    }

    fn alloc(&mut self, layout: Layout) -> *mut u8 {
        // Reserve-size must itself be a multiple of `NODE_ALIGN`, not just
        // the block's starting address. `split-off remainder = start +
        // (padding + want)`, where we then materialise a fresh `FreeNode`
        // — if `want` is unaligned the remainder is too, and the subsequent
        // write into `(*new_node).size` trips `ptr::write`'s alignment
        // precondition under build-std debug.
        let want = align_up(layout.size().max(MIN_BLOCK), NODE_ALIGN);
        let align = layout.align().max(NODE_ALIGN);
        let mut prev: Option<NonNull<FreeNode>> = None;
        let mut cur = self.head;
        while let Some(c) = cur {
            let (node_size, node_next) = unsafe { ((*c.as_ptr()).size, (*c.as_ptr()).next) };
            let start = c.as_ptr() as usize;
            let payload = align_up(start, align);
            let padding = payload - start;
            if node_size >= padding + want {
                let total_used = padding + want;
                let remaining = node_size - total_used;
                if remaining >= MIN_BLOCK {
                    let new_node_addr = start + total_used;
                    let new_node = new_node_addr as *mut FreeNode;
                    unsafe {
                        (*new_node).size = remaining;
                        (*new_node).next = node_next;
                    }
                    let replacement = NonNull::new(new_node);
                    match prev {
                        Some(p) => unsafe { (*p.as_ptr()).next = replacement },
                        None => self.head = replacement,
                    }
                } else {
                    match prev {
                        Some(p) => unsafe { (*p.as_ptr()).next = node_next },
                        None => self.head = node_next,
                    }
                }
                return payload as *mut u8;
            }
            prev = Some(c);
            cur = node_next;
        }
        null_mut()
    }

    /// Extend the heap by requesting fresh frames from procmgr, mapping
    /// them immediately above `mapped_end`, and appending the new region
    /// to the free list.
    ///
    /// Returns `true` if the heap grew by enough pages to cover
    /// `want_bytes`, `false` on any IPC / map failure or when the heap
    /// has reached `HEAP_MAX`. A partial failure (some frames mapped,
    /// then a later batch fails) leaves the successfully-mapped pages
    /// outside the free list — effectively leaked address space until
    /// a future successful grow. This keeps the failure path simple and
    /// avoids a half-formed free-list node.
    ///
    /// # Safety
    /// Caller must hold the heap lock. IPC wrappers and `mem_map` are
    /// themselves non-allocating — the bootstrap IPC buffer is the
    /// pre-registered page, not heap-backed — so `grow` is safe to call
    /// under the allocator lock without re-entrant allocation.
    fn grow(&mut self, want_bytes: usize) -> bool {
        if self.memmgr_ep == 0 || self.self_aspace == 0 {
            return false;
        }
        let start_va = self.mapped_end as u64;
        if start_va >= HEAP_MAX {
            return false;
        }

        let page_size_usize = PAGE_SIZE as usize;
        let pages_needed = want_bytes.div_ceil(page_size_usize) as u64;
        let pages_wanted = core::cmp::max(pages_needed, GROW_MIN_PAGES).min(GROW_MAX_PAGES);

        // Clamp to what fits in the remaining [mapped_end, HEAP_MAX) window.
        let remaining_pages = (HEAP_MAX - start_va) / PAGE_SIZE;
        let pages = pages_wanted.min(remaining_pages);
        if pages == 0 {
            return false;
        }

        self.grow_exact(pages, start_va)
    }

    /// Request and map exactly `pages` frames starting at `start_va`,
    /// then append the new region to the free list. Returns true on
    /// full success.
    ///
    /// memmgr's `REQUEST_FRAMES` reply may carry up to
    /// `MSG_CAP_SLOTS_MAX = 4` Frame caps in best-effort mode, each
    /// covering one or more contiguous pages. The reply layout:
    /// `data[0]` = `returned_cap_count`; `data[1+i]` = `page_count_for_cap_i`;
    /// `caps[0..count]` = Frame caps. We map each returned cap with its
    /// declared `page_count` in a single `mem_map` call, advancing
    /// `start_va` by the same number of pages.
    fn grow_exact(&mut self, pages: u64, start_va: u64) -> bool {
        // Read the calling thread's registered IPC buffer from TLS. The
        // kernel services `ipc_call` by reading the payload from that
        // thread's `tcb.ipc_buffer`; targeting any other VA silently
        // writes to the wrong page.
        let ipc_buf_u64 = current_ipc_buf();
        if ipc_buf_u64.is_null() {
            return false;
        }
        let mut mapped: u64 = 0;
        // memmgr's reply slot count is bounded; if a single best-effort
        // call satisfies fewer pages than requested, loop. Bound the
        // retry count so a misbehaving memmgr cannot wedge the caller.
        const MAX_ROUNDS: u32 = 16;
        let mut rounds: u32 = 0;
        while mapped < pages {
            if rounds >= MAX_ROUNDS {
                return false;
            }
            rounds += 1;

            let want = pages - mapped;
            // data[0] low half = want_pages, high half = flags (best-effort = 0).
            let msg = ipc::IpcMessage::builder(REQUEST_FRAMES).word(0, want).build();
            // SAFETY: ipc_buf_u64 is the current thread's kernel-registered,
            // page-aligned IPC buffer.
            let reply = match unsafe { ipc::ipc_call(self.memmgr_ep, &msg, ipc_buf_u64) } {
                Ok(r) => r,
                Err(_) => return false,
            };
            if reply.label != 0 {
                return false;
            }

            let returned_count = reply.word(0) as usize;
            let cap_slots = reply.caps();
            if cap_slots.len() != returned_count || returned_count == 0 {
                return false;
            }

            for (i, &cap_slot) in cap_slots.iter().take(returned_count).enumerate() {
                let pages_in_cap = reply.word(1 + i);
                if pages_in_cap == 0 {
                    return false;
                }
                let va = start_va + mapped * PAGE_SIZE;
                if !self.mem_map_with_augment_retry(cap_slot, va, pages_in_cap) {
                    return false;
                }
                mapped += pages_in_cap;
            }
        }

        let region_bytes = (mapped * PAGE_SIZE) as usize;
        let region_base = start_va as usize;
        // SAFETY: region just mapped writable, exclusively owned, size is
        // a page multiple (therefore NODE_ALIGN-aligned); base is
        // page-aligned (therefore NODE_ALIGN-aligned). `insert` coalesces
        // with an existing tail free block if adjacent, preserving the
        // free-list invariant.
        unsafe { self.insert(region_base, region_bytes) };
        self.mapped_end = region_base + region_bytes;
        true
    }

    /// `mem_map` wrapper that augments the AS's PT growth budget once on
    /// `OutOfMemory` and retries.
    ///
    /// `mem_map` returns `OutOfMemory` (-8) when the destination AS's PT
    /// growth budget is exhausted (a new intermediate page-table page is
    /// needed but the budget has none). We acquire a fresh Frame cap from
    /// memmgr, augment the AS via `cap_create_aspace(frame, self_aspace,
    /// init_pages=1)`, and retry the map. One augment per failure; if the
    /// retry also fails the caller treats the grow as failed.
    fn mem_map_with_augment_retry(&self, frame_cap: u32, va: u64, pages: u64) -> bool {
        const SYSCALL_OUT_OF_MEMORY: i64 = -8;
        match syscall::mem_map(frame_cap, self.self_aspace, va, 0, pages, MAP_WRITABLE) {
            Ok(()) => return true,
            Err(SYSCALL_OUT_OF_MEMORY) => { /* fall through to augment + retry */ }
            Err(_) => return false,
        }
        // Augment: request 1 page from memmgr, feed to cap_create_aspace
        // in augment mode (target = self_aspace). Single page covers
        // ~511 new PT-entries' worth of mappable VA.
        let Some(aug_frame) = slab_acquire_fresh(PAGE_SIZE, 2) else {
            return false;
        };
        if syscall::cap_create_aspace(aug_frame, self.self_aspace, 1).is_err() {
            // Augment-mode returns 0 on success; treat any error as fatal
            // for this grow. Drop the unused frame.
            let _ = syscall::cap_delete(aug_frame);
            return false;
        }
        // The augment cap is consumed by cap_create_aspace; do not delete.
        syscall::mem_map(frame_cap, self.self_aspace, va, 0, pages, MAP_WRITABLE).is_ok()
    }
}

// ── Global heap ─────────────────────────────────────────────────────────────

struct GlobalHeap {
    inner: UnsafeCell<Heap>,
    lock: SpinLock,
}

// SAFETY: all access to `inner` is serialised by `lock`.
unsafe impl Sync for GlobalHeap {}

static HEAP: GlobalHeap = GlobalHeap {
    inner: UnsafeCell::new(Heap::new()),
    lock: SpinLock::new(),
};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

// ── Bootstrap ───────────────────────────────────────────────────────────────

/// Initialise the heap by requesting frames from memmgr and mapping them
/// at `HEAP_BASE`. Idempotent — only the first call performs real work.
///
/// The IPC buffer used for the bootstrap round is taken from the calling
/// thread's TLS slot ([`crate::os::seraph::current_ipc_buf`]). `_start`
/// populates that slot before calling `heap_bootstrap`, so bootstrap
/// runs on the main thread's registered buffer.
///
/// Returns `true` if the heap is usable after this call.
pub fn heap_bootstrap(memmgr_ep: u32, self_aspace: u32) -> bool {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return true;
    }
    if memmgr_ep == 0 {
        return false;
    }

    let ipc_buf_u64 = current_ipc_buf();
    if ipc_buf_u64.is_null() {
        return false;
    }

    // Bounded retry: memmgr's best-effort reply may cover only a portion
    // of the request when the pool is fragmented; loop until the full
    // initial heap is mapped or memmgr stops making progress.
    const MAX_ROUNDS: u32 = 16;
    let mut mapped: u64 = 0;
    let mut rounds: u32 = 0;
    while mapped < HEAP_INITIAL_PAGES {
        if rounds >= MAX_ROUNDS {
            return false;
        }
        rounds += 1;

        let want = HEAP_INITIAL_PAGES - mapped;
        let msg = ipc::IpcMessage::builder(REQUEST_FRAMES).word(0, want).build();
        // SAFETY: ipc_buf_u64 is the registered, page-aligned buffer.
        let reply = match unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf_u64) } {
            Ok(r) => r,
            Err(_) => return false,
        };
        if reply.label != 0 {
            return false;
        }

        let returned_count = reply.word(0) as usize;
        let cap_slots = reply.caps();
        if cap_slots.len() != returned_count || returned_count == 0 {
            return false;
        }

        for (i, &cap_slot) in cap_slots.iter().take(returned_count).enumerate() {
            let pages_in_cap = reply.word(1 + i);
            if pages_in_cap == 0 {
                return false;
            }
            let va = HEAP_BASE + mapped * PAGE_SIZE;
            if syscall::mem_map(cap_slot, self_aspace, va, 0, pages_in_cap, MAP_WRITABLE).is_err()
            {
                return false;
            }
            mapped += pages_in_cap;
        }
    }

    let base = HEAP_BASE as usize;
    let size = (HEAP_INITIAL_PAGES as usize) * (PAGE_SIZE as usize);
    HEAP.lock.lock();
    // SAFETY: freshly-mapped, exclusively-owned region; lock held.
    unsafe {
        let heap = &mut *HEAP.inner.get();
        heap.init(base, size);
        heap.mapped_end = base + size;
        heap.memmgr_ep = memmgr_ep;
        heap.self_aspace = self_aspace;
    }
    HEAP.lock.unlock();
    true
}

/// Returns `true` once `heap_bootstrap` has completed successfully.
pub fn heap_is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

// ── Object slabs ────────────────────────────────────────────────────────────
//
// Per-process working Frame caps that back kernel-object retypes
// (`SYS_CAP_CREATE_*`). Two cached slabs — one per kernel sub-page bin —
// plus a no-cache path for page-aligned requests. Lazily acquired from
// memmgr on first call; reused across all retypes until exhausted, then a
// fresh slab cap is requested.
//
// Thread-safe via per-pool spinlocks. The cached `local_avail` mirrors the
// kernel's `available_bytes` ledger on the slab cap — debited per acquire
// without crediting on auto-reclaim (the kernel does, against the same cap).
// When `local_avail` underflows our request, a fresh slab is requested
// rather than calling `SYS_CAP_INFO`; this trades a small per-process leak
// of "stuck" bytes on the previous slab for a simpler hot path.
//
// Two pools (one per BIN_128 / BIN_512 size class) prevents a 512-byte
// request from blocking a 128-byte request that could otherwise have been
// served from the same slab without refresh. Page-aligned requests bypass
// the cache entirely — every retype consumes ≥ 1 page so caching offers
// nothing.

struct ObjectSlab {
    cap: crate::sync::atomic::AtomicU32,
    local_avail: crate::sync::atomic::AtomicU64,
    lock: SpinLock,
}

const fn empty_slab() -> ObjectSlab {
    ObjectSlab {
        cap: crate::sync::atomic::AtomicU32::new(0),
        local_avail: crate::sync::atomic::AtomicU64::new(0),
        lock: SpinLock::new(),
    }
}

/// Slab serving sub-page requests `<= 128 B` (Endpoint, Signal).
static SLAB_BIN_128: ObjectSlab = empty_slab();
/// Slab serving sub-page requests `> 128 B && <= 512 B` (WaitSet).
static SLAB_BIN_512: ObjectSlab = empty_slab();

/// memmgr endpoint shared by every slab path. Set once at process start.
static SLAB_MEMMGR_EP: crate::sync::atomic::AtomicU32 = crate::sync::atomic::AtomicU32::new(0);

/// Set the memmgr endpoint backing the object-slab refill path. Called once
/// from `_start` after `heap_bootstrap`. Subsequent calls are ignored.
pub fn object_slab_init(memmgr_ep: u32) {
    SLAB_MEMMGR_EP.store(memmgr_ep, Ordering::Release);
}

/// Round `bytes` up to the same size class the kernel's retype primitive
/// uses (`core::kernel::cap::retype::round_to_class`). Keeps the local
/// ledger in sync with the kernel ledger without a syscall.
fn slab_round_to_class(bytes: u64) -> u64 {
    if bytes == 0 {
        0
    } else if bytes <= 128 {
        128
    } else if bytes <= 512 {
        512
    } else {
        let p = PAGE_SIZE;
        bytes.div_ceil(p) * p
    }
}

/// Request a Frame cap from memmgr covering at least `min_pages` 4-KiB
/// pages. memmgr's best-effort reply may return up to four Frame caps, each
/// covering one or more contiguous pages. We accept the first cap whose
/// declared `page_count` is `>= min_pages`; if none qualifies, we fall back
/// to the first returned cap (any cap unblocks sub-page retypes; a too-small
/// cap simply means the next page-sized retype request triggers a refresh).
///
/// Returns `Some((slot, pages))` on success, `None` on IPC failure or empty
/// reply.
fn slab_request_pages(memmgr_ep: u32, min_pages: u64) -> Option<(u32, u64)> {
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return None;
    }
    let msg = ipc::IpcMessage::builder(REQUEST_FRAMES).word(0, min_pages).build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) }.ok()?;
    if reply.label != 0 {
        return None;
    }
    let returned = reply.word(0) as usize;
    if returned == 0 {
        return None;
    }
    let caps = reply.caps();
    // Prefer the first cap that already covers `min_pages`.
    for i in 0..returned {
        let pages = reply.word(1 + i);
        if pages >= min_pages {
            return Some((caps[i], pages));
        }
    }
    // Fallback: take the first (smaller) cap so sub-page retypes still work.
    Some((caps[0], reply.word(1)))
}

/// Number of pages to request when refilling the object slab.
///
/// The kernel's per-Frame retype allocator carves a small metadata header
/// (≈ 48 B) out of the cap's `available_bytes` on first use. A page-aligned
/// retype therefore cannot fit in a single 4-KiB cap; we always grab two
/// pages so a `PAGE_SIZE`-byte request (e.g. `WaitSet`) succeeds, and a
/// follow-up sub-page request reuses the remaining ~4 KiB on the same cap.
const SLAB_REFILL_PAGES: u64 = 2;

/// Acquire from `pool`, refilling from memmgr if exhausted. `need` is the
/// rounded class size; `pool` is the matching cached slab; `want_pages`
/// is the request size used on refill.
fn slab_acquire_pooled(pool: &ObjectSlab, need: u64, want_pages: u64) -> Option<u32> {
    pool.lock.lock();
    let res = (|| -> Option<u32> {
        // Fast path: existing slab still has room.
        let cur = pool.cap.load(Ordering::Acquire);
        let avail = pool.local_avail.load(Ordering::Relaxed);
        if cur != 0 && avail >= need {
            pool.local_avail.store(avail - need, Ordering::Relaxed);
            return Some(cur);
        }
        // Refill: request a fresh cap from memmgr. One attempt — propagate
        // failure rather than loop on best-effort partial replies.
        let ep = SLAB_MEMMGR_EP.load(Ordering::Acquire);
        if ep == 0 {
            return None;
        }
        let (new_cap, cap_pages) = slab_request_pages(ep, want_pages)?;
        const ALLOCATOR_METADATA_RESERVE: u64 = 64;
        let total = cap_pages.saturating_mul(PAGE_SIZE);
        let usable = total.saturating_sub(ALLOCATOR_METADATA_RESERVE);
        if usable < need {
            // memmgr returned a cap too small for this request. Drop it
            // (the caller will see None and decide what to do); don't
            // install it as the slab — a smaller cap would just block the
            // next bigger request the same way.
            let _ = syscall::cap_delete(new_cap);
            return None;
        }
        pool.cap.store(new_cap, Ordering::Release);
        pool.local_avail.store(usable - need, Ordering::Relaxed);
        Some(new_cap)
    })();
    pool.lock.unlock();
    res
}

/// Acquire a fresh, dedicated Frame cap for a page-aligned retype. No
/// caching — the cap is consumed entirely by the caller's single retype
/// (or by a few retypes against the leftover sub-page tail, which the
/// caller manages). Used by variable-size types (`EventQueue`, `Thread`,
/// `AddressSpace`, `CSpace`) where caching offers no benefit.
fn slab_acquire_fresh(need: u64, want_pages: u64) -> Option<u32> {
    let ep = SLAB_MEMMGR_EP.load(Ordering::Acquire);
    if ep == 0 {
        return None;
    }
    let (new_cap, cap_pages) = slab_request_pages(ep, want_pages)?;
    const ALLOCATOR_METADATA_RESERVE: u64 = 64;
    let total = cap_pages.saturating_mul(PAGE_SIZE);
    if total.saturating_sub(ALLOCATOR_METADATA_RESERVE) < need {
        let _ = syscall::cap_delete(new_cap);
        return None;
    }
    Some(new_cap)
}

/// Return a Frame-cap slot with at least `min_bytes` of `available_bytes`
/// for retype.
///
/// Caller passes the raw byte cost of the upcoming retype (e.g. 88 for
/// `Endpoint`); the function rounds up to the matching size class and
/// dispatches to a per-class cached slab (sub-page) or a fresh dedicated
/// cap (page-aligned). The returned slot index is fed directly to
/// `cap_create_*`.
///
/// Returns `None` if memmgr is unreachable, refuses the request, or
/// returns a cap too small to satisfy the request after refill (memmgr's
/// best-effort policy may shrink the reply when the pool is fragmented).
pub fn object_slab_acquire(min_bytes: u64) -> Option<u32> {
    let need = slab_round_to_class(min_bytes);
    // Pages we need to safely contain `need` plus the kernel's per-cap
    // allocator metadata. One extra page covers metadata for sub-page
    // requests; page-aligned requests need their own pages plus one.
    let want_pages = need.div_ceil(PAGE_SIZE).max(1) + 1;
    if need <= 128 {
        slab_acquire_pooled(&SLAB_BIN_128, need, want_pages)
    } else if need <= 512 {
        slab_acquire_pooled(&SLAB_BIN_512, need, want_pages)
    } else {
        slab_acquire_fresh(need, want_pages)
    }
}

/// Abort the calling thread via `SYS_THREAD_EXIT`. Used as the allocation-
/// failure and panic terminator until P3c wires a proper abort path.
pub fn abort_thread() -> ! {
    syscall::thread_exit()
}

// ── GlobalAlloc for System ──────────────────────────────────────────────────

#[stable(feature = "alloc_system_type", since = "1.28.0")]
unsafe impl GlobalAlloc for System {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HEAP.lock.lock();
        // SAFETY: lock held, single mutator.
        let heap = unsafe { &mut *HEAP.inner.get() };
        let mut ptr = heap.alloc(layout);
        if ptr.is_null() {
            // Grow once, bounded by `GROW_MAX_PAGES`, then retry. A
            // successful grow covers single allocations up to one
            // grow-increment larger than the largest existing free block;
            // anything beyond that returns null to `handle_alloc_error`.
            // Multiple grow rounds are NOT attempted: each grown page
            // consumes one CSpace slot (procmgr's `REQUEST_FRAMES` ABI
            // is one cap per page), and the fixed 256-slot child CSpace
            // saturates after a few hundred pages. Once that cap-transfer
            // fails, the kernel's `ipc_reply` currently leaves the caller
            // blocked rather than returning an error. Bounded grow keeps
            // grow within CSpace headroom. IPC wrappers under the lock
            // are non-allocating (the IPC buffer is the pre-registered
            // page, not heap-backed), so there is no re-entrant
            // allocation here.
            let want = layout.size().saturating_add(layout.align());
            if heap.grow(want) {
                ptr = heap.alloc(layout);
            }
        }
        HEAP.lock.unlock();
        ptr
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegating to alloc; zeroing is done here since the
        // free-list hands back uninitialised pages.
        let ptr = unsafe { <Self as GlobalAlloc>::alloc(self, layout) };
        if !ptr.is_null() {
            // SAFETY: returned block is at least layout.size() bytes of writable memory.
            unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        }
        ptr
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        // Must match `alloc`'s reservation: `want` was
        // `align_up(layout.size().max(MIN_BLOCK), NODE_ALIGN)`. Insert the
        // same amount back so the free-list invariant (every node starts at
        // a `NODE_ALIGN`-aligned address, every block size is a
        // `NODE_ALIGN` multiple) holds.
        let size = align_up(layout.size().max(MIN_BLOCK), NODE_ALIGN);
        HEAP.lock.lock();
        // SAFETY: lock held; caller guarantees ptr/layout match a prior alloc.
        unsafe { (*HEAP.inner.get()).insert(ptr as usize, size) };
        HEAP.lock.unlock();
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
            return null_mut();
        };
        // SAFETY: new_layout is validated above.
        let new_ptr = unsafe { <Self as GlobalAlloc>::alloc(self, new_layout) };
        if new_ptr.is_null() {
            return null_mut();
        }
        let copy_len = old_layout.size().min(new_size);
        // SAFETY: both buffers are non-null and owned; ranges non-overlapping.
        unsafe { core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_len) };
        // SAFETY: caller guarantees (ptr, old_layout) match a prior alloc.
        unsafe { <Self as GlobalAlloc>::dealloc(self, ptr, old_layout) };
        new_ptr
    }
}
