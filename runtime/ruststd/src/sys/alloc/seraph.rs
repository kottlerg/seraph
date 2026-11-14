// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/alloc/seraph.rs

//! Seraph PAL allocator: a spinlock-guarded first-fit free list whose
//! backing pages are lazily requested from memmgr. All syscall wrappers
//! and protocol labels come from the workspace crates `syscall-abi`,
//! `syscall`, and `ipc`, pulled into std's dep graph through
//! `library/std/Cargo.toml` — mirrors the `hermit-abi` /
//! `fortanix-sgx-abi` pattern. The overlay itself holds no inline asm
//! and duplicates no protocol numbers. The heap zone is the one
//! `process_layout::growth_zones` sizes to this process's address
//! space; the page-reservation allocator (`std::sys::reserve`) owns the
//! arena zone disjoint from it.
//!
//! Bootstrap is explicit: `_start` (`std::os::seraph`) calls
//! `heap_bootstrap(memmgr_ep, self_aspace)` with
//! `ProcessInfo.memmgr_endpoint_cap` before `main` whenever that cap is
//! non-zero; a later call does no work and reports whether that first call
//! installed the heap. An allocation before bootstrap returns a null
//! pointer and the alloc crate aborts via `handle_alloc_error`.
//!
//! The IPC buffer pointer used by `grow` is read from the TLS slot
//! populated in `_start` / the thread trampoline (see
//! `std::os::seraph::current_ipc_buf`). Each thread's allocation-
//! triggered grow thus targets the buffer the kernel actually reads
//! from for that thread.
//!
//! The platform functions `alloc`, `alloc_zeroed`, `dealloc`, and `realloc`
//! below delegate to the static heap. They back both std's `System` allocator
//! and std's default global allocator (the `__rdl_*` symbols the `alloc`
//! crate calls when no `#[global_allocator]` is set), so services that want
//! this allocator simply omit a custom `#[global_allocator]`.
//!
//! A request lands where `heap_fit::fit` (the host-tested
//! `ruststd-heap-fit` crate) places it in the first free block that holds
//! it: the block's bytes below and above the request stay on the free list,
//! so `dealloc`, which returns exactly the request's bytes, leaves no byte
//! of the heap outside both the free list and a live block.

use crate::alloc::Layout;
use crate::cell::UnsafeCell;
use crate::marker::PhantomData;
use crate::mem::{align_of, size_of};
use crate::os::seraph::{current_ipc_buf, ipc_call_until_answered};
use crate::ptr::{NonNull, null_mut};
use crate::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use ipc::memmgr_labels::{QUERY_POOL_STATUS, RELEASE_MEMORY_CAPS, REQUEST_MEMORY_CAPS};
use syscall_abi::{MAP_WRITABLE, PAGE_SIZE};

// The heap zone (base window and span) comes from
// `process_layout::growth_zones`, sized to this process's address
// space (`std::os::seraph::user_va_top`); the base is drawn per process at
// bootstrap (ASLR, #39) and the zone lies below the reservation arena's
// (`reserve/seraph.rs`).

/// Heap floor installed at `_start`, in 4 KiB pages (2 MiB). Sized to cover
/// stdio's lazy line buffer, typical collection workloads, and the peak of a
/// piped `Command::spawn` without needing `grow`; a spawned thread's stack and
/// IPC buffer lie in page reservations, not here. In a demand-paged process the
/// floor is a registered demand region (`REGISTER_REGION`), so it costs VA
/// and only the frames of the pages first touched; a process with no pager
/// (pinned, or whose registration failed) maps it eagerly instead.
const HEAP_INITIAL_PAGES: u64 = 512;

/// Minimum grow increment in pages. Allocation-failure retries extend the
/// heap by at least this many 4 KiB pages to amortise the memmgr IPC
/// round-trip over many small follow-up allocations. 16 pages = 64 KiB.
const GROW_MIN_PAGES: u64 = 16;

// ── Spin mutex ──────────────────────────────────────────────────────────────

/// A spinlock that owns the state it serialises: the state is reachable only
/// through the [`SpinGuard`] [`Self::lock`] returns, and the guard releases
/// the lock when it drops, so the type system keeps every access under the
/// lock (docs/coding-standards.md § Concurrency). The byte heap, the object
/// slabs, the page-reservation arena (`sys::reserve`), and the thread
/// reaper's slot table and death queues (`sys::thread`) use it rather than
/// std's `Mutex`, which may park and allocate: the allocator runs beneath
/// both, and the reaper runs inside a spawn.
///
/// A contended [`Self::lock`] does not spin without bound. It spins a
/// bounded number of attempts and then sleeps between attempts, as the
/// `ruststd-spin-wait` policy decides. A strict-priority waiter runs before
/// every fair thread and every lower-level strict-priority thread on its CPU
/// (core/kernel/docs/scheduler.md § Scheduling Classes). Such a waiter that
/// only spun would never let a holder below it, queued on that CPU, run there,
/// and, with no other CPU idle to pull the holder (that document's § Load
/// Balancing), neither thread would progress.
pub(crate) struct SpinMutex<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: `value` is reached only through a `SpinGuard`, and `lock` hands out
// one guard at a time, so threads sharing the mutex take exclusive access in
// turn; `T: Send` lets the value pass between those threads.
unsafe impl<T: Send> Sync for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    /// Wait until the lock is free, then hold it until the guard drops.
    /// Each failed attempt spins or sleeps as [`spin_wait::Backoff`] steps
    /// it. The sleep blocks this thread, so the holder runs even when it is
    /// queued below this thread's level on this thread's CPU.
    pub(crate) fn lock(&self) -> SpinGuard<'_, T> {
        let mut backoff = spin_wait::Backoff::new();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            match backoff.next_step() {
                spin_wait::Step::Spin => core::hint::spin_loop(),
                // An error (`Interrupted` when this thread is stopped or is
                // posted an upcall it does not mask) only ends the sleep
                // early; the next attempt follows either way.
                spin_wait::Step::Sleep(ms) => {
                    let _ = syscall::thread_sleep(ms);
                }
            }
        }
        SpinGuard { mutex: self, _exclusive: PhantomData }
    }

    /// Run `f` on the value under the lock, released when `f` returns.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.lock())
    }
}

/// Exclusive access to a [`SpinMutex`]'s value; dropping it releases the lock.
///
/// The marker gives the guard the auto traits of `&mut T`: it is `Sync` only
/// when `T` is, as std's `MutexGuard` is, so a guard shared by reference
/// never hands two threads a `&T` of a value that is `Send` but not `Sync`.
pub(crate) struct SpinGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
    _exclusive: PhantomData<&'a mut T>,
}

impl<T> crate::ops::Deref for SpinGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this guard holds the lock, so no other reference to the
        // value exists.
        unsafe { self.mutex.value.as_ref_unchecked() }
    }
}

impl<T> crate::ops::DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this guard holds the lock, so no other reference to the
        // value exists.
        unsafe { self.mutex.value.as_mut_unchecked() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
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

/// The bytes `Heap::alloc` takes for `layout`, and `dealloc` returns: the size,
/// at least `MIN_BLOCK`, rounded up to `NODE_ALIGN`.
fn block_size(layout: Layout) -> usize {
    align_up(layout.size().max(MIN_BLOCK), NODE_ALIGN)
}

// ── Heap ────────────────────────────────────────────────────────────────────

struct Heap {
    head: Option<NonNull<FreeNode>>,
    /// First VA above the currently mapped heap region. Grows upward toward
    /// `max` as `grow` maps fresh pages. Zero before bootstrap.
    mapped_end: usize,
    /// Heap zone upper bound (exclusive): the per-process drawn base plus
    /// the heap zone's span. Zero before bootstrap.
    max: usize,
    /// Cached memmgr endpoint cap used by `grow` to request additional
    /// pages. Zero before bootstrap; `grow` returns false in that state.
    memmgr_ep: u64,
    /// Cached aspace cap for mapping grow-path pages. Zero before bootstrap.
    self_aspace: u64,
}

// SAFETY: the free-list pointers address free blocks in the process's own
// heap pages, which no thread owns, and the heap is reached only through
// `HEAP`'s lock, so any thread holding that lock may follow them.
unsafe impl Send for Heap {}

impl Heap {
    const fn new() -> Self {
        Self {
            head: None,
            mapped_end: 0,
            max: 0,
            memmgr_ep: 0,
            self_aspace: 0,
        }
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
        // the block's starting address: the back free node starts at
        // `payload + want`, and an unaligned `want` would leave it unaligned,
        // so its `size` write would trip `ptr::write`'s alignment
        // precondition under build-std debug.
        let want = block_size(layout);
        let align = layout.align().max(NODE_ALIGN);
        let mut prev: Option<NonNull<FreeNode>> = None;
        let mut cur = self.head;
        while let Some(c) = cur {
            let (node_size, node_next) = unsafe { ((*c.as_ptr()).size, (*c.as_ptr()).next) };
            let start = c.as_ptr() as usize;
            // `heap_fit::fit` places the request so that the block's bytes
            // below it (front) and above it (back) each stay a free node or
            // are empty: `dealloc` returns exactly `[payload, payload + want)`,
            // so a byte handed out beyond it, or dropped from the list, would
            // never come back.
            if let Some(fit) = heap_fit::fit(start, node_size, want, align, MIN_BLOCK) {
                let after = if fit.back == 0 {
                    node_next
                } else {
                    let back_node = (fit.payload + want) as *mut FreeNode;
                    // SAFETY: `[payload + want, start + node_size)` is the free
                    // block's own tail, at least MIN_BLOCK bytes at NODE_ALIGN.
                    unsafe {
                        (*back_node).size = fit.back;
                        (*back_node).next = node_next;
                    }
                    NonNull::new(back_node)
                };
                if fit.front == 0 {
                    match prev {
                        Some(p) => unsafe { (*p.as_ptr()).next = after },
                        None => self.head = after,
                    }
                } else {
                    // The block's node stays in place as the front.
                    // SAFETY: `c` is a node of this heap's free list.
                    unsafe {
                        (*c.as_ptr()).size = fit.front;
                        (*c.as_ptr()).next = after;
                    }
                }
                return fit.payload as *mut u8;
            }
            prev = Some(c);
            cur = node_next;
        }
        null_mut()
    }

    /// Free bytes at the top of the mapped heap: the size of the free block
    /// that ends at `mapped_end`, or zero. A grow maps directly above it and
    /// [`Self::insert`] coalesces the two, so a grow need only cover the rest
    /// of a request.
    fn tail_free_bytes(&self) -> usize {
        let mut cur = self.head;
        let mut last: Option<NonNull<FreeNode>> = None;
        while let Some(c) = cur {
            last = Some(c);
            // SAFETY: `c` is a node of this heap's free list.
            cur = unsafe { (*c.as_ptr()).next };
        }
        let Some(l) = last else {
            return 0;
        };
        // SAFETY: `l` is the free list's last (highest) node.
        let size = unsafe { (*l.as_ptr()).size };
        if l.as_ptr() as usize + size == self.mapped_end { size } else { 0 }
    }

    /// Extend the heap by requesting fresh pages from memmgr, mapping
    /// them immediately above `mapped_end`, and appending the new region
    /// to the free list.
    ///
    /// The grow covers `want_bytes` beyond the free block at the heap's top
    /// ([`Self::tail_free_bytes`]), at least `GROW_MIN_PAGES`, with no other
    /// bound: a request the rest of the zone cannot hold fails without
    /// mapping anything. Returns `true` if the grow mapped at least one
    /// page, `false` on any IPC / map failure before the first page or when
    /// the zone cannot hold the request. A grow that mapped some pages and
    /// then failed still adds them to the free list and advances
    /// `mapped_end` past them (see [`Self::grow_exact`]), so the caller's
    /// retry loop makes progress on every `true`.
    ///
    /// Called with the heap lock held. IPC wrappers and `mem_map` are
    /// themselves non-allocating — the bootstrap IPC buffer is the
    /// pre-registered page, not heap-backed — so `grow` runs under the
    /// allocator lock without re-entrant allocation.
    fn grow(&mut self, want_bytes: usize) -> bool {
        if self.memmgr_ep == 0 || self.self_aspace == 0 {
            return false;
        }
        let start_va = self.mapped_end as u64;
        let heap_max = self.max as u64;
        if start_va >= heap_max {
            return false;
        }

        let page_size_usize = PAGE_SIZE as usize;
        let short_bytes = want_bytes.saturating_sub(self.tail_free_bytes());
        let pages_needed = short_bytes.div_ceil(page_size_usize) as u64;
        let remaining_pages = (heap_max - start_va) / PAGE_SIZE;
        if pages_needed > remaining_pages {
            return false;
        }
        // The minimum increment is clamped to what fits in the remaining
        // [mapped_end, max) window; the request itself fits (checked above).
        let pages = pages_needed.max(GROW_MIN_PAGES).min(remaining_pages);
        if pages == 0 {
            return false;
        }

        // SAFETY: `[start_va, start_va + pages * PAGE_SIZE)` lies in the
        // heap's zone at or above `mapped_end` and below `max`, which only
        // this heap maps and where nothing is mapped yet.
        unsafe { self.grow_exact(pages, start_va) };
        self.mapped_end as u64 > start_va
    }

    /// Request and map exactly `pages` pages starting at `start_va`,
    /// then append the new region to the free list. Returns true on
    /// full success.
    ///
    /// memmgr's `REQUEST_MEMORY_CAPS` reply may carry up to
    /// `MSG_CAP_SLOTS_MAX = 4` Memory caps in best-effort mode, each
    /// covering one or more contiguous pages (layout checked by
    /// [`ipc::memmgr_grant_layout`]). We map each returned cap with its
    /// declared `page_count` in a single `mem_map` call, advancing `start_va`
    /// by the same number of pages.
    ///
    /// On failure, every cap of the failing reply that is not mapped is
    /// deleted and its run returned to memmgr ([`release_reply_caps`]). A
    /// failed map can leave some of the cap's pages mapped, so that cap is
    /// unmapped first, and kept, still accounted to this process, if the
    /// unmap fails. The pages mapped before the failure, by this reply or an
    /// earlier round, are still added to the free list with `mapped_end`
    /// advanced past them, so a later grow maps above them rather than over
    /// them.
    ///
    /// # Safety
    /// `[start_va, start_va + pages * PAGE_SIZE)` must lie in this heap's
    /// zone (the zone's span from the drawn base, which nothing else in the
    /// process maps) at or above `mapped_end`, so no live Rust object or IPC
    /// page lies in it.
    unsafe fn grow_exact(&mut self, pages: u64, start_va: u64) -> bool {
        // Read the calling thread's registered IPC buffer from TLS. The
        // kernel services `ipc_call` by reading the payload from that
        // thread's `tcb.ipc_buffer`; targeting any other VA silently
        // writes to the wrong page.
        let ipc_buf = current_ipc_buf();
        if ipc_buf.is_null() {
            return false;
        }
        let mut mapped: u64 = 0;
        // Loop until the request is mapped: a best-effort reply MAY cover
        // fewer pages than asked (a partial grant, when no `MSG_CAP_SLOTS_MAX`
        // runs cover the request although the free pages do), and the next
        // round asks for the rest. Bound the round count so a misbehaving
        // memmgr cannot wedge the caller; a grow that runs out of rounds keeps
        // the pages already mapped.
        const MAX_ROUNDS: u32 = 16;
        let mut rounds: u32 = 0;
        let complete = loop {
            if mapped >= pages {
                break true;
            }
            if rounds >= MAX_ROUNDS {
                break false;
            }
            rounds += 1;

            let want = pages - mapped;
            // data[0] low half = want_pages, high half = flags (best-effort = 0).
            let msg = ipc::IpcMessage::builder(REQUEST_MEMORY_CAPS).word(0, want).build();
            // An interrupted request is made again within the same round: a
            // grant whose reply the cancelled call could not take is rolled
            // back by memmgr, so the repeat is not charged twice.
            // SAFETY: ipc_buf is the current thread's kernel-registered,
            // page-aligned IPC buffer.
            let Ok(reply) = (unsafe { ipc_call_until_answered(self.memmgr_ep, &msg, ipc_buf) })
            else {
                break false;
            };
            let caps = reply.caps();
            let Some((page_counts, region_ids)) = ipc::memmgr_grant_layout(&reply) else {
                release_reply_caps(self.memmgr_ep, ipc_buf, caps, &[], |_| false);
                break false;
            };

            // A cap covering more than the request still needs would map
            // past the window the caller sized, so it fails the round too.
            let mut kept = 0;
            let mut keep_failed = false;
            for (&cap_slot, &pages_in_cap) in caps.iter().zip(page_counts) {
                if pages_in_cap == 0 || pages_in_cap > pages - mapped {
                    break;
                }
                let va = start_va + mapped * PAGE_SIZE;
                // SAFETY: `va` and the cap's pages lie in the unmapped part of
                // the heap zone the caller's contract names (`mapped` never
                // exceeds `pages`), so no live Rust object or IPC page lies in
                // them. The map runs under the heap lock: the top-ups it may
                // make allocate nothing (`mem_map_funded`).
                let map = unsafe {
                    mem_map_funded(cap_slot, self.self_aspace, va, 0, pages_in_cap, MAP_WRITABLE)
                };
                if map.is_err() {
                    // SAFETY: the same span, which nothing but this failed map
                    // touched.
                    keep_failed =
                        unsafe { syscall::mem_unmap(self.self_aspace, va, pages_in_cap) }.is_err();
                    break;
                }
                mapped += pages_in_cap;
                kept += 1;
            }
            if kept < caps.len() {
                let keep = |i| i < kept || (keep_failed && i == kept);
                release_reply_caps(self.memmgr_ep, ipc_buf, caps, region_ids, keep);
                break false;
            }
        };

        if mapped != 0 {
            let region_bytes = (mapped * PAGE_SIZE) as usize;
            let region_base = start_va as usize;
            // SAFETY: region just mapped writable, exclusively owned, size is
            // a page multiple (therefore NODE_ALIGN-aligned); base is
            // page-aligned (therefore NODE_ALIGN-aligned). `insert` coalesces
            // with an existing tail free block if adjacent, preserving the
            // free-list invariant.
            unsafe { self.insert(region_base, region_bytes) };
            self.mapped_end = region_base + region_bytes;
        }
        complete
    }
}

// ── Global heap ─────────────────────────────────────────────────────────────

static HEAP: SpinMutex<Heap> = SpinMutex::new(Heap::new());

/// [`heap_bootstrap`] progress: unclaimed, claimed by the first call and
/// running, or finished with the heap installed or not.
static BOOTSTRAP: AtomicU8 = AtomicU8::new(BOOTSTRAP_UNCLAIMED);
const BOOTSTRAP_UNCLAIMED: u8 = 0;
const BOOTSTRAP_RUNNING: u8 = 1;
const BOOTSTRAP_READY: u8 = 2;
const BOOTSTRAP_FAILED: u8 = 3;

// ── Bootstrap ───────────────────────────────────────────────────────────────

/// Initialise the heap by requesting pages from memmgr and mapping them
/// at a per-process drawn base (ASLR, #39). Only the first call performs
/// real work; every later call returns whether that first call installed
/// the heap, so a failed bootstrap is permanent. A call made while the first
/// is still running returns `false`.
///
/// The IPC buffer used for the bootstrap round is taken from the calling
/// thread's TLS slot ([`crate::os::seraph::current_ipc_buf`]). `_start`
/// populates that slot before calling `heap_bootstrap`, so bootstrap
/// runs on the main thread's registered buffer.
///
/// Returns `true` if the heap is usable after this call.
pub fn heap_bootstrap(memmgr_ep: u64, self_aspace: u64) -> bool {
    if let Err(state) = BOOTSTRAP.compare_exchange(
        BOOTSTRAP_UNCLAIMED,
        BOOTSTRAP_RUNNING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        return state == BOOTSTRAP_READY;
    }
    let ready = memmgr_ep != 0 && heap_install(memmgr_ep, self_aspace);
    BOOTSTRAP.store(if ready { BOOTSTRAP_READY } else { BOOTSTRAP_FAILED }, Ordering::Release);
    ready
}

/// Draw the heap base in the heap zone sized to this process's address space
/// ([`crate::os::seraph::growth_zones`]), record the heap's zone and
/// caps, and install the `HEAP_INITIAL_PAGES` floor: demand-backed
/// ([`register_demand_floor`]) when the process has a pager, else mapped
/// through [`Heap::grow_exact`]. On failure the heap is reset to its
/// unbootstrapped state, so it serves no allocation; pages the failed attempt
/// mapped stay mapped and accounted until the process exits.
fn heap_install(memmgr_ep: u64, self_aspace: u64) -> bool {
    // Both floors fund page tables before the heap exists (a demand floor's
    // top-up, an eager floor's funded map), retyping from the object slab,
    // whose refill path must be wired first. `_start` has already wired it;
    // a second store of the same endpoint is harmless.
    object_slab_init(memmgr_ep);
    // The base draw happens before the allocator exists: the raw getrandom
    // wrapper is a registers-only syscall and must stay non-allocating, like
    // the IPC wrappers `grow_exact` uses. A failed draw degrades to the
    // deterministic window base (no log surface exists this early).
    let zone = crate::os::seraph::growth_zones().heap;
    let mut entropy = [0u8; 8];
    let drawn = match syscall::getrandom(&mut entropy) {
        Ok(n) if n == entropy.len() as u64 => Some(u64::from_le_bytes(entropy)),
        _ => None,
    };
    let heap_base = zone.base(drawn);
    let demand_floor = register_demand_floor(memmgr_ep, self_aspace, heap_base);

    // The heap is unbootstrapped, so no allocation holds a pointer into it.
    let mut heap = HEAP.lock();
    heap.mapped_end = heap_base as usize;
    heap.max = (heap_base + zone.span) as usize;
    heap.memmgr_ep = memmgr_ep;
    heap.self_aspace = self_aspace;
    let floor_end = heap_base + HEAP_INITIAL_PAGES * PAGE_SIZE;
    let ok = if demand_floor {
        heap.mapped_end = floor_end as usize;
        // SAFETY: `[heap_base, floor_end)` is this heap's registered demand
        // floor, which nothing else uses; the node write below faults its
        // first page in.
        unsafe { heap.insert(heap_base as usize, (HEAP_INITIAL_PAGES * PAGE_SIZE) as usize) };
        true
    } else {
        // SAFETY: the heap zone starts at `heap_base`, which nothing in the
        // process has mapped yet (the heap is unbootstrapped), and
        // `HEAP_INITIAL_PAGES` pages fit every zone's span.
        unsafe { heap.grow_exact(HEAP_INITIAL_PAGES, heap_base) }
    };
    if !ok {
        *heap = Heap::new();
    }
    ok
}

/// Register the heap floor `[heap_base, + HEAP_INITIAL_PAGES)` as a demand
/// region with this process's pager, topping up the page tables the pager's
/// maps will need first. Returns `false`, leaving the floor to be mapped
/// eagerly, when the process has no pager (`ProcessInfo.pager_endpoint_cap`
/// zero: pinned, or procmgr's binding failed) or registration fails.
/// Allocates nothing: it runs before the heap exists.
fn register_demand_floor(memmgr_ep: u64, self_aspace: u64, heap_base: u64) -> bool {
    let has_pager =
        crate::os::seraph::try_startup_info().is_some_and(|i| i.pager_endpoint_cap != 0);
    let ipc_buf = current_ipc_buf();
    if !has_pager || ipc_buf.is_null() {
        return false;
    }
    // Best effort, as for every demand region (`register_demand_paged`): the
    // pager funds the pool itself when a fault finds it exhausted, so the
    // top-up only keeps the floor's first faults off that path.
    let _ = fund_aspace_pt_budget(self_aspace, HEAP_INITIAL_PAGES);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe {
        crate::os::seraph::register_rw_region(memmgr_ep, ipc_buf, heap_base, HEAP_INITIAL_PAGES)
    }
}

/// Returns `true` once `heap_bootstrap` has completed successfully.
pub fn heap_is_initialized() -> bool {
    BOOTSTRAP.load(Ordering::Acquire) == BOOTSTRAP_READY
}

// ── Object slabs ────────────────────────────────────────────────────────────
//
// Per-process working Memory caps that back kernel-object retypes
// (`SYS_CAP_CREATE_*`). Two cached pool pages — one per kernel sub-page size
// class — plus a no-cache fresh-grant path for page-aligned requests. Lazily
// acquired from memmgr on first use.
//
// All pool state lives in a per-pool `SpinMutex`, and the retype syscall
// itself runs under that lock (the [`object_slab_retype`] closure contract).
// That discipline is what makes the cap lifecycle below sound: no caller can
// hold an acquired-but-unretyped slot once the lock is released, so the pool
// may resync its ledger from the kernel and delete or release caps it no
// longer serves from, without racing a concurrent cap install into a reused
// slot.
//
// Ledger: `local_avail` mirrors the kernel's `available_bytes` on the
// current pool cap, debited per successful retype without a syscall. The
// kernel credits bytes back to the same cap when retyped objects die
// (auto-reclaim), so the mirror is always <= the kernel ledger; the slow
// path re-reads the kernel ledger (`SYS_CAP_INFO`) before paying for a
// refill, so churn workloads recycle reclaimed bytes instead of consuming
// fresh grants (#364).
//
// Class purity: each pool only ever retypes objects of its own size class,
// so every freed slot in a pool page is reusable for the next request and
// kernel `available_bytes >= class` guarantees the retype succeeds.
//
// Shelf: a refill displaces a current page that still carries live retypes
// (a drained page would have served the request after resync). Displaced
// pages park on a small per-pool shelf, keyed by the grant identity memmgr
// needs for release. The slow path scans the shelf: a fully-drained entry
// (`available_bytes == size`) has its cap deleted and its run returned to
// memmgr (`RELEASE_MEMORY_CAPS`); an entry with room is promoted back to
// current instead of refilling. When the shelf overflows, the oldest entry
// is evicted by cap-delete alone — its run stays accounted to this process
// until process death, the bounded residual strand.
//
// Two pools (one per BIN_128 / BIN_512 size class) prevent a 512-byte
// request from blocking a 128-byte request that could otherwise have been
// served from the same slab without refresh. Page-aligned requests bypass
// the cache entirely — every retype consumes ≥ 1 page so caching offers
// nothing.

/// Retired pool pages a pool can park before evicting (per pool).
const SLAB_SHELF_SIZE: usize = 4;

/// One displaced pool page: the Memory-cap slot, the grant's region id
/// (memmgr's `RELEASE_MEMORY_CAPS` identity), and the cap's total byte size
/// (fully drained ⇔ kernel `available_bytes == size`).
#[derive(Clone, Copy)]
struct ShelfEntry {
    cap: u64,
    region_id: u64,
    size: u64,
}

/// One pool's state: the current page's cap, its ledger mirror, and its
/// grant identity, plus the shelf of displaced pages, oldest first.
struct SlabPool {
    /// The current pool page's Memory cap, or 0 before the first refill.
    cap: u64,
    /// The ledger mirror of `cap`'s `available_bytes`.
    local_avail: u64,
    cur_region_id: u64,
    cur_size: u64,
    shelf: [ShelfEntry; SLAB_SHELF_SIZE],
    shelf_len: usize,
}

/// One size class's pool, under the lock its retypes run under.
type ObjectSlab = SpinMutex<SlabPool>;

const fn empty_slab() -> ObjectSlab {
    SpinMutex::new(SlabPool {
        cap: 0,
        local_avail: 0,
        cur_region_id: 0,
        cur_size: 0,
        shelf: [ShelfEntry { cap: 0, region_id: 0, size: 0 }; SLAB_SHELF_SIZE],
        shelf_len: 0,
    })
}

/// Slab serving sub-page requests `<= 128 B` (Endpoint, Notification).
static SLAB_BIN_128: ObjectSlab = empty_slab();
/// Slab serving sub-page requests `> 128 B && <= 512 B` (WaitSet).
static SLAB_BIN_512: ObjectSlab = empty_slab();

/// memmgr endpoint shared by every slab path. Set once at process start.
static SLAB_MEMMGR_EP: crate::sync::atomic::AtomicU64 = crate::sync::atomic::AtomicU64::new(0);

/// Set the memmgr endpoint backing the object-slab refill path. `_start` sets
/// it before stdio attaches its pipes, since a funded map tops the page-table
/// pool up through the slab, and the heap bootstrap sets it again (to the same
/// endpoint) before installing the floor.
pub fn object_slab_init(memmgr_ep: u64) {
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

/// Request one Memory cap from memmgr covering a single contiguous run of at
/// least `min_pages` 4-KiB pages.
///
/// Every caller retypes from or maps exactly one cap, so the request sets
/// `REQUIRE_CONTIGUOUS`: memmgr replies with one cap covering all `min_pages`
/// or refuses with `OUT_OF_MEMORY_CONTIGUOUS`. The reply is still treated as
/// wire input ([`ipc::memmgr_grant_layout`]): the first returned cap whose
/// declared page count covers `min_pages` is kept, and every other cap the
/// reply carries is deleted and its run returned to memmgr (see
/// [`release_reply_caps`]).
///
/// Returns `Some((slot, pages, region_id))` on success. `region_id` is the
/// kept cap's grant id, which memmgr reports at `data[1 + count + i]`; the
/// caller passes it to [`slab_release_fresh`] to return the run to memmgr's
/// pool mid-life. Also used by the pipe machinery (`sys::pipe`) for ring
/// pages, which need the region id so the grant can be returned when the pipe
/// ends its life.
///
/// Returns `None` on IPC failure, a memmgr error label, a `min_pages` that
/// does not fit the request's 32-bit page-count field, a reply
/// [`ipc::memmgr_grant_layout`] refuses, or a reply none of whose caps covers
/// `min_pages`. A refused reply's caps are deleted the same way as the
/// unchosen caps of an accepted one.
pub fn slab_request_pages(memmgr_ep: u64, min_pages: u64) -> Option<(u64, u64, u64)> {
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return None;
    }
    let want = u32::try_from(min_pages).ok()?;
    // data[0] low half = want_pages, high half = flags.
    let flags = u64::from(ipc::memmgr_labels::REQUIRE_CONTIGUOUS) << 32;
    let msg =
        ipc::IpcMessage::builder(REQUEST_MEMORY_CAPS).word(0, u64::from(want) | flags).build();
    // An interrupted request is made again, as in `Heap::grow_exact`.
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let reply = unsafe { ipc_call_until_answered(memmgr_ep, &msg, ipc_buf) }.ok()?;
    let caps = reply.caps();
    let layout = ipc::memmgr_grant_layout(&reply);
    let keep = layout.and_then(|(page_counts, _)| page_counts.iter().position(|&p| p >= min_pages));
    let region_ids = layout.map_or(&[][..], |(_, ids)| ids);
    release_reply_caps(memmgr_ep, ipc_buf, caps, region_ids, |i| keep == Some(i));
    let (page_counts, region_ids) = layout?;
    let i = keep?;
    Some((caps[i], page_counts[i], region_ids[i]))
}

/// Delete every cap a `REQUEST_MEMORY_CAPS` reply transferred except those
/// `keep` selects by index, and return each deleted cap's run to memmgr's
/// pool with one `RELEASE_MEMORY_CAPS` naming the region id `region_ids`
/// holds at the same index.
///
/// `region_ids` is the reply's region-id words as
/// [`ipc::memmgr_grant_layout`] split them, or empty for a reply it refused.
/// A deleted cap without an id still has its slot freed, and its run stays
/// accounted to this process until it dies.
/// The release is made again for as long as the call is interrupted, which is
/// safe because memmgr ignores an id that matches no outstanding grant. Only a
/// call that memmgr never answers leaves the runs accounted the same way.
fn release_reply_caps(
    memmgr_ep: u64,
    ipc_buf: *mut u64,
    caps: &[u64],
    region_ids: &[u64],
    keep: impl Fn(usize) -> bool,
) {
    let mut released = [0u64; syscall_abi::MSG_CAP_SLOTS_MAX];
    let mut n = 0;
    for (i, &cap) in caps.iter().enumerate() {
        if keep(i) {
            continue;
        }
        let _ = syscall::cap_delete(cap);
        // `n` stays below `caps.len()`, which the kernel bounds by
        // `MSG_CAP_SLOTS_MAX`, so the store is in bounds.
        if let Some(&id) = region_ids.get(i) {
            released[n] = id;
            n += 1;
        }
    }
    if n == 0 {
        return;
    }
    let msg = ipc::IpcMessage::builder(RELEASE_MEMORY_CAPS)
        .word(0, n as u64)
        .words(1, &released[..n])
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let _ = unsafe { ipc_call_until_answered(memmgr_ep, &msg, ipc_buf) };
}

/// Bytes withheld from a fresh grant's local ledger as slack against any
/// kernel-side retype cost the mirror does not model. The kernel debits
/// exactly the class-rounded dispatch cost, so this is conservative; the
/// slow-path resync reads the authoritative ledger anyway. Every pooled and
/// [`object_slab_retype`] request asks memmgr for the pages covering the
/// class plus this reserve ([`slab_want_pages`]); a dedicated grant from
/// [`object_slab_acquire_fresh`] carries one exact retype and withholds
/// nothing.
const ALLOCATOR_METADATA_RESERVE: u64 = 64;

/// Pages a slab request asks memmgr for: the fewest that cover the
/// class-rounded `need` plus [`ALLOCATOR_METADATA_RESERVE`]. A sub-page class
/// asks for one page and a page-aligned class for one page over its own page
/// count. Every request sets `REQUIRE_CONTIGUOUS` ([`slab_request_pages`]),
/// so asking for no more than this keeps a one-page free run able to serve a
/// sub-page class.
fn slab_want_pages(need: u64) -> u64 {
    (need + ALLOCATOR_METADATA_RESERVE).div_ceil(PAGE_SIZE)
}

/// Retype under `pool`'s lock via `retype`. On an exhausted local ledger:
/// resync from the kernel's `available_bytes` (recovers auto-reclaimed
/// bytes), then scan the shelf (release drained retired pages, promote one
/// with room), and only then refill from memmgr. `need` is the rounded class
/// size; `want_pages` is the request size used on refill. The local ledger
/// is debited only when `retype` returns `Some`; see [`object_slab_retype`]
/// for the closure contract.
///
/// One function over the 100-line guideline by design: every step is one
/// state machine over pool state whose invariants hold only while the pool
/// lock is held, and splitting it would spread that lock-held contract
/// across function boundaries.
fn slab_retype_pooled<T>(
    pool: &ObjectSlab,
    need: u64,
    want_pages: u64,
    retype: impl FnOnce(u64) -> Option<T>,
) -> Option<T> {
    let mut guard = pool.lock();
    let pool: &mut SlabPool = &mut guard;
    // Fast path: the local ledger says the current page has room.
    let cur = pool.cap;
    let avail = pool.local_avail;
    if cur != 0 && avail >= need {
        let out = retype(cur)?;
        pool.local_avail = avail - need;
        return Some(out);
    }

    // Resync: the kernel credits auto-reclaimed bytes back to the cap
    // when retyped objects die; the mirror only debits. Re-read the
    // authoritative ledger before paying for a refill. Sound because
    // every debit against a pool cap happens under this lock and
    // concurrent deletions only credit.
    if cur != 0 {
        let avail =
            syscall::cap_info(cur, syscall_abi::CAP_INFO_MEMORY_AVAILABLE).unwrap_or(0);
        pool.local_avail = avail;
        if avail >= need {
            let out = retype(cur)?;
            pool.local_avail = avail - need;
            return Some(out);
        }
    }

    // Shelf scan: release fully-drained retired pages back to memmgr and
    // pick the first entry with room as a promotion candidate (a drained
    // candidate is reused rather than released — strictly cheaper than
    // releasing it and requesting a fresh grant). A failed probe reads
    // as 0: the entry defers (kept, not promoted, never mis-freed).
    let mut avails = [0u64; SLAB_SHELF_SIZE];
    for (i, slot) in avails.iter_mut().enumerate().take(pool.shelf_len) {
        *slot = syscall::cap_info(pool.shelf[i].cap, syscall_abi::CAP_INFO_MEMORY_AVAILABLE)
            .unwrap_or(0);
    }
    let mut promote: Option<(ShelfEntry, u64)> = None;
    let mut keep = 0;
    for i in 0..pool.shelf_len {
        let entry = pool.shelf[i];
        if promote.is_none() && avails[i] >= need {
            promote = Some((entry, avails[i]));
            continue;
        }
        if avails[i] == entry.size {
            // Fully drained: no live retype remains, so the run can go
            // back to memmgr's pool. Delete the cap first per the
            // RELEASE_MEMORY_CAPS contract.
            let _ = syscall::cap_delete(entry.cap);
            slab_release_fresh(entry.region_id);
            continue;
        }
        pool.shelf[keep] = entry;
        keep += 1;
    }
    pool.shelf_len = keep;

    if let Some((entry, entry_avail)) = promote {
        // Swap: park the displaced current page in the slot the
        // candidate vacated (it is pinned by live retypes — a drained
        // current page would have served at resync) and serve from the
        // promoted page.
        if cur != 0 {
            pool.shelf[pool.shelf_len] =
                ShelfEntry { cap: cur, region_id: pool.cur_region_id, size: pool.cur_size };
            pool.shelf_len += 1;
        }
        pool.cap = entry.cap;
        pool.cur_region_id = entry.region_id;
        pool.cur_size = entry.size;
        pool.local_avail = entry_avail;
        let out = retype(entry.cap)?;
        pool.local_avail = entry_avail - need;
        return Some(out);
    }

    // Refill: request a fresh contiguous cap from memmgr. One attempt —
    // propagate failure rather than retry.
    let ep = SLAB_MEMMGR_EP.load(Ordering::Acquire);
    if ep == 0 {
        return None;
    }
    let (new_cap, cap_pages, new_region_id) = slab_request_pages(ep, want_pages)?;
    let total = cap_pages.saturating_mul(PAGE_SIZE);
    let usable = total.saturating_sub(ALLOCATOR_METADATA_RESERVE);
    if usable < need {
        // memmgr returned a cap too small for this request. The grant is
        // virgin — reclaim the slot and return the run rather than
        // stranding it in memmgr's per-process accounting.
        let _ = syscall::cap_delete(new_cap);
        slab_release_fresh(new_region_id);
        return None;
    }
    // Retire the displaced current page. It is pinned by live retypes
    // (see above), so it cannot be released here; the shelf scan frees
    // it once its objects die. On overflow evict the oldest entry by
    // cap-delete alone: its run stays accounted to this process until
    // process death — the bounded residual strand.
    if cur != 0 {
        if pool.shelf_len == SLAB_SHELF_SIZE {
            let evicted = pool.shelf[0];
            let _ = syscall::cap_delete(evicted.cap);
            pool.shelf.copy_within(1.., 0);
            pool.shelf_len -= 1;
        }
        pool.shelf[pool.shelf_len] =
            ShelfEntry { cap: cur, region_id: pool.cur_region_id, size: pool.cur_size };
        pool.shelf_len += 1;
    }
    pool.cap = new_cap;
    pool.cur_region_id = new_region_id;
    pool.cur_size = total;
    pool.local_avail = usable;
    let out = retype(new_cap)?;
    pool.local_avail = usable - need;
    Some(out)
}

/// A freshly-acquired dedicated Memory cap plus the identity memmgr needs to
/// reclaim its backing run mid-life. `region_id` is the id memmgr reported
/// in the grant reply; pass it to [`slab_release_fresh`] once every
/// kernel object retyped from `cap` has been deleted.
#[derive(Clone, Copy)]
pub struct SlabGrant {
    pub cap: u64,
    pub region_id: u64,
}

/// Acquire a fresh, dedicated Memory cap for a page-aligned retype. No
/// caching — the cap is consumed entirely by the caller's single retype
/// (or by a few retypes against the leftover sub-page tail, which the
/// caller manages). Used by variable-size types (`EventQueue`, `Thread`,
/// `AddressSpace`, `CSpace`) where caching offers no benefit. `withheld` is
/// the slack the grant must hold beyond `need`: [`ALLOCATOR_METADATA_RESERVE`]
/// for a ledger-tracked grant, zero for one exact retype.
fn slab_acquire_fresh(need: u64, want_pages: u64, withheld: u64) -> Option<SlabGrant> {
    let ep = SLAB_MEMMGR_EP.load(Ordering::Acquire);
    if ep == 0 {
        return None;
    }
    let (new_cap, cap_pages, region_id) = slab_request_pages(ep, want_pages)?;
    let total = cap_pages.saturating_mul(PAGE_SIZE);
    if total.saturating_sub(withheld) < need {
        // Too small for this request. Delete the inner cap and return the run
        // to memmgr's pool — the slab is virgin (nothing retyped yet), and
        // deleting the inner alone would strand the run in memmgr's
        // per-process accounting until process death.
        let _ = syscall::cap_delete(new_cap);
        slab_release_fresh(region_id);
        return None;
    }
    Some(SlabGrant { cap: new_cap, region_id })
}

/// Return a fresh slab's backing run to memmgr's pool, naming it by the
/// `region_id` recorded in its [`SlabGrant`]. The release is made again for as
/// long as the call is interrupted, which is safe because memmgr ignores an id
/// that matches no outstanding grant. Only a call that memmgr never answers
/// leaves the run accounted to this process until it dies.
///
/// The caller MUST have already deleted its capability to the slab and every
/// kernel object retyped from it; a release while either remains still
/// succeeds, but memmgr holds the run on its deferred list, granted to no
/// one, until both are gone (`services/memmgr/docs/memory-pool.md`
/// § Reclamation).
pub fn slab_release_fresh(region_id: u64) {
    let ep = SLAB_MEMMGR_EP.load(Ordering::Acquire);
    if ep == 0 {
        return;
    }
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return;
    }
    let msg = ipc::IpcMessage::builder(RELEASE_MEMORY_CAPS).word(0, 1).word(1, region_id).build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let _ = unsafe { ipc_call_until_answered(ep, &msg, ipc_buf) };
}

/// Retype one kernel object out of the slab machinery.
///
/// `min_bytes` is the full raw debit the kernel charges for the upcoming
/// retype, the object wrapper plus its state (`syscall_abi::ENDPOINT_RETYPE_BYTES`,
/// `NOTIFICATION_RETYPE_BYTES`, `wait_set_retype_bytes(capacity)`,
/// `event_queue_retype_bytes(capacity, observers)`, or a
/// page-granular object's byte size); it is rounded up to the kernel's size
/// class, so the request covers the debit. `retype` is
/// called at most once with a Memory-cap slot whose `available_bytes` covers
/// the class and must perform exactly one `cap_create_*` syscall against that
/// slot, returning `Some` on success.
///
/// # Closure contract
///
/// Sub-page classes run `retype` under the pool spinlock: exactly one
/// retype syscall and nothing else — no allocation, no blocking, no
/// panicking, no re-entry into the slab APIs — and the slot must not
/// escape the closure.
///
/// Sub-page classes serve from a shared cached pool page, debiting the
/// pool ledger only when `retype` returns `Some`. Page-aligned classes
/// draw a fresh dedicated grant: on success the source cap slot is
/// deleted (the retyped object holds its own ancestor reference on the
/// grant's MemoryObject, `cap_create_aspace` augment mode included); on
/// failure the virgin grant is deleted and its run returned to memmgr's
/// pool.
///
/// Returns `None` if memmgr is unreachable, refuses the request, returns
/// a cap too small for the class, or `retype` itself fails.
pub fn object_slab_retype<T>(min_bytes: u64, retype: impl FnOnce(u64) -> Option<T>) -> Option<T> {
    object_slab_retype_reclaimable(min_bytes, retype).map(|(out, _)| out)
}

/// [`object_slab_retype`], also returning the `region_id` of the dedicated
/// grant a page-aligned class draws, so the caller can return that grant's
/// run to memmgr's pool with [`slab_release_fresh`] once the object is
/// deleted. `None` in its place for a sub-page class, whose pooled page the
/// runtime reclaims itself.
pub fn object_slab_retype_reclaimable<T>(
    min_bytes: u64,
    retype: impl FnOnce(u64) -> Option<T>,
) -> Option<(T, Option<u64>)> {
    let need = slab_round_to_class(min_bytes);
    // Sized so `need` still fits after the ledger withholds
    // `ALLOCATOR_METADATA_RESERVE` from the grant.
    let want_pages = slab_want_pages(need);
    if need <= 128 {
        slab_retype_pooled(&SLAB_BIN_128, need, want_pages, retype).map(|out| (out, None))
    } else if need <= 512 {
        slab_retype_pooled(&SLAB_BIN_512, need, want_pages, retype).map(|out| (out, None))
    } else {
        let grant = slab_acquire_fresh(need, want_pages, ALLOCATOR_METADATA_RESERVE)?;
        match retype(grant.cap) {
            Some(out) => {
                // The retyped object holds its own ancestor ref on the
                // grant's MemoryObject; the source slot is dead weight.
                let _ = syscall::cap_delete(grant.cap);
                Some((out, Some(grant.region_id)))
            }
            None => {
                // Retype failed without consuming the grant — the slab is
                // virgin; reclaim the slot and return the run to memmgr.
                let _ = syscall::cap_delete(grant.cap);
                slab_release_fresh(grant.region_id);
                None
            }
        }
    }
}

/// Acquire a fresh, dedicated Memory cap sized for `min_bytes` and return
/// the [`SlabGrant`] identity, so the caller can manage the retype itself
/// and return the run to memmgr's pool mid-life via [`slab_release_fresh`]
/// once every object retyped from the slab is deleted. For a
/// per-unit-of-work retype (e.g. one Thread slab per spawn) this keeps the
/// process's memmgr-pool footprint bounded instead of leaking a run per
/// iteration until process death. The grant covers exactly the class-rounded
/// `min_bytes`, the kernel's debit for the one retype the caller makes, with
/// no metadata reserve: a Thread slab takes exactly its slot's pages, not one more.
pub fn object_slab_acquire_fresh(min_bytes: u64) -> Option<SlabGrant> {
    let need = slab_round_to_class(min_bytes);
    slab_acquire_fresh(need, need.div_ceil(PAGE_SIZE), 0)
}

/// memmgr's current free-pool size in bytes (`QUERY_POOL_STATUS`, reply
/// `data[3]`). `None` if memmgr is unreachable. A read-only aggregate query,
/// made again for as long as the call is interrupted; used by the threadchurn
/// regression to assert a bounded pool footprint.
pub fn memmgr_query_free_bytes() -> Option<u64> {
    let ep = SLAB_MEMMGR_EP.load(Ordering::Acquire);
    if ep == 0 {
        return None;
    }
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return None;
    }
    let msg = ipc::IpcMessage::builder(QUERY_POOL_STATUS).build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let reply = unsafe { ipc_call_until_answered(ep, &msg, ipc_buf) }.ok()?;
    if reply.label != 0 {
        return None;
    }
    Some(reply.word(3))
}

/// Fund `self_aspace`'s page-table growth budget to cover mapping a
/// `region_pages`-page foreign-frame region (MMIO, DMA) into a
/// retype-backed `AddressSpace`.
///
/// Requests a Memory cap from memmgr (via the object slab) and retypes it
/// onto the AS's PT pool with `cap_create_aspace` in augment mode, so the
/// kernel draws the region's intermediate page tables from this
/// caller-funded, memmgr-accounted budget rather than the fixed kernel PT
/// reserve. The need is `pool_funding::pt_pages_for(region_pages)`, the
/// worst case for a contiguous run, and only the pool's shortfall against
/// it is donated, in at most `pool_funding::FUND_ROUNDS` donations
/// (`pool_funding::top_up`).
///
/// The pool is shared by every mapping of the process, the pager's
/// included, so the top-up is not reserved for the region: another thread's
/// mapping can draw it before the region's map runs. A map into the
/// process's own address space therefore goes through [`mem_map_funded`] or
/// [`mmio_map_funded`], which top up again while the map finds the pool
/// exhausted, and a
/// demand-region registration treats the top-up as best effort, since the
/// pager funds the pool itself when a fault finds it exhausted
/// (services/memmgr/docs/memory-pool.md § Client page-table funding).
///
/// `region_pages == 0` is a no-op success. Returns `false` only when a
/// top-up was needed and could not be had: memmgr is unreachable or refuses
/// the grant, or the kernel refuses the donation. A pool that reads short
/// after donations that were made is no failure, since another thread's
/// mapping drew it.
///
/// Allocates nothing, so the heap's grow can call it under the heap lock.
pub fn fund_aspace_pt_budget(self_aspace: u64, region_pages: u64) -> bool {
    // Funding only the shortfall, and nothing once the pool covers the
    // region, keeps a spawn/join loop from leaking a CSpace slot and PT pages
    // on every spawn: a reused VA range's intermediate page tables persist,
    // so the pool stabilises after the first few spawns.
    let budget_pages = || {
        syscall::cap_info(self_aspace, syscall_abi::CAP_INFO_ASPACE_PT_BUDGET).unwrap_or(0)
            / PAGE_SIZE
    };
    let donate = |pages: u64| {
        object_slab_retype(pages * PAGE_SIZE, |frame| {
            syscall::cap_create_aspace(frame, self_aspace, pages).ok()
        })
        .is_some()
    };
    let need = pool_funding::pt_pages_for(region_pages);
    pool_funding::top_up(|| need.saturating_sub(budget_pages()), donate)
}

/// `syscall::mem_map` of `pages` pages of `memory_cap`, from page `offset`,
/// at `va` in `aspace`, the calling process's own address space, with the
/// page tables it needs funded: a map refused with `OutOfMemory` tops the
/// pool up ([`fund_aspace_pt_budget`]) and is made again, up to
/// `pool_funding::MAP_TOP_UPS` times (`pool_funding::map_with_top_ups`). The
/// first map is made without a top-up, so a pool that already covers the
/// span costs nothing more.
///
/// Every ruststd path that maps Memory into its own address space maps
/// through it, and `std::os::seraph::mem_map_funded` offers it to services.
/// Allocates nothing.
///
/// # Errors
/// The last map's error: `OutOfMemory` when a top-up could not be had or the
/// pool was still exhausted after the last one, else the error of a map
/// refused for another reason (`syscall::mem_map` § Errors).
///
/// # Safety
/// The contract of `syscall::mem_map` for the span `[va, va + pages *
/// PAGE_SIZE)` of the calling program's own address space, which covers the
/// span even when the call fails: a refused map can leave pages before the
/// failing one mapped.
pub unsafe fn mem_map_funded(
    memory_cap: u64,
    aspace: u64,
    va: u64,
    offset: u64,
    pages: u64,
    prot: u64,
) -> Result<(), i64> {
    pool_funding::map_with_top_ups(
        syscall_abi::SyscallError::OutOfMemory as i64,
        // SAFETY: the caller's contract covers the span, for every map made.
        || unsafe { syscall::mem_map(memory_cap, aspace, va, offset, pages, prot) },
        || fund_aspace_pt_budget(aspace, pages),
    )
}

/// `syscall::mmio_map` of the `Mmio` region `mmio_cap`, `pages` pages long,
/// at `va` in `aspace`, the calling process's own address space, with the
/// page tables it needs funded as [`mem_map_funded`] funds them: a map refused
/// with `OutOfMemory` tops the pool up for `pages` pages and is made again, up
/// to `pool_funding::MAP_TOP_UPS` times. A refused `mmio_map` keeps the
/// mapping's record and the pages it mapped, and the next one at the same `va`
/// reuses them.
///
/// `pages` only sizes the top-ups: no `SYS_CAP_INFO` selector reports an
/// `Mmio` region's size, and the map covers the whole region whatever `pages`
/// says. Allocates nothing.
///
/// # Errors
/// The last map's error: `OutOfMemory` when a top-up could not be had or the
/// map still found a pool exhausted after the last one (the page-table pool,
/// or the `CSpace` pool that a mapping past the region's inline records draws
/// on and no page-table top-up refills), else the error of a map refused for
/// another reason (`syscall::mmio_map` § Errors).
///
/// # Safety
/// The contract of `syscall::mmio_map` for the span the region covers at `va`
/// in the calling program's own address space, which covers the span even
/// when the call fails.
pub unsafe fn mmio_map_funded(aspace: u64, mmio_cap: u64, va: u64, pages: u64) -> Result<(), i64> {
    pool_funding::map_with_top_ups(
        syscall_abi::SyscallError::OutOfMemory as i64,
        // SAFETY: the caller's contract covers the span, for every map made.
        // `flags` is reserved and the kernel ignores it.
        || unsafe { syscall::mmio_map(aspace, mmio_cap, va, 0) },
        || fund_aspace_pt_budget(aspace, pages),
    )
}

/// General-allocation headroom of `self_cspace`: free slots the kernel lets a
/// general allocation take, excluding the IPC receive reserve
/// (`CSPACE_IPC_RECV_RESERVE`). Zero when the queries fail.
pub fn cspace_general_headroom(self_cspace: u64) -> u64 {
    let capacity =
        syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_CAPACITY).unwrap_or(0);
    let used =
        syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_USED).unwrap_or(capacity);
    capacity.saturating_sub(used).saturating_sub(syscall_abi::CSPACE_IPC_RECV_RESERVE)
}

/// Fund `self_cspace`'s slot-page pool so at least `slots` general
/// allocations succeed without further growth, with one page of growth budget
/// left beyond them for the `CSpace`'s body arena.
///
/// Reads the `CSpace`'s headroom (`CAP_INFO_CSPACE_CAPACITY` less
/// `CAP_INFO_CSPACE_USED` and the IPC receive reserve) and its growth budget
/// (`CAP_INFO_CSPACE_BUDGET`) and, when either falls short of
/// `syscall_abi::cspace_topup_pages`, requests Memory from memmgr (via the
/// object slab) and donates it to the pool with augment-mode
/// `cap_create_cspace`. After a success, `slots` general allocations succeed,
/// and the body arena can still take one more page: up to 31 further bodies
/// (split children, `Mmio`, `IoPort`, or `Interrupt` copies, spilled mapping
/// records). A burst of `n` splits therefore needs `slots` of at least `n`
/// plus 56 for each 31 bodies past the first page. Call before a known burst
/// of cap acquisitions, or periodically to keep headroom above a low-water
/// mark, so a service never meets the hard `OutOfMemory` of an exhausted
/// `CSpace`.
///
/// The headroom is shared by every capability allocation of the process, so
/// the top-up is not reserved for the caller's burst: another thread's
/// allocations can take the donated slots first, and the caller's own
/// allocation then decides, failing with the refillable `OutOfMemory`. The
/// donations follow `pool_funding::top_up`: the shortfall each round reads,
/// in at most `pool_funding::FUND_ROUNDS` donations.
///
/// `slots == 0` still keeps the arena's page. Returns `false` only when a
/// top-up was needed and could not be had: memmgr is unreachable or refuses
/// the grant, or the kernel refuses the donation (the object slab's own cap
/// needs one free general slot). A headroom that reads short after donations
/// that were made is no failure, since another thread's allocations took it.
pub fn fund_cspace_slot_budget(self_cspace: u64, slots: u64) -> bool {
    let short = || {
        let budget =
            syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_BUDGET).unwrap_or(0);
        syscall_abi::cspace_topup_pages(cspace_general_headroom(self_cspace), budget, slots)
    };
    let donate = |pages: u64| {
        object_slab_retype(pages * PAGE_SIZE, |frame| {
            syscall::cap_create_cspace(frame, self_cspace, pages).ok()
        })
        .is_some()
    };
    pool_funding::top_up(short, donate)
}

/// Abort the calling thread via `SYS_THREAD_EXIT`. Used as the allocation-
/// failure and panic terminator.
pub fn abort_thread() -> ! {
    syscall::thread_exit()
}

// ── Platform allocator functions ───────────────────────────────────────────────

/// Allocate `layout` from the byte heap, growing it through memmgr as needed;
/// null when the heap cannot grow to fit. std's `System` and its default
/// global allocator (the `__rdl_*` symbols) both call it.
///
/// # Safety
/// `layout.size()` is non-zero (the `GlobalAlloc::alloc` contract).
#[inline]
pub unsafe fn alloc(layout: Layout) -> *mut u8 {
    let mut heap = HEAP.lock();
    let mut ptr = heap.alloc(layout);
    // Grow to fit and retry, for as long as each grow maps at least one
    // page: `grow` sizes the free block at the heap's top to
    // `heap_fit::fit_bound`, which places the request wherever that block
    // starts, so one round normally suffices, and a partial grant (memmgr's
    // reply carries at most `MSG_CAP_SLOTS_MAX` runs,
    // services/memmgr/docs/ipc-interface.md § Label 1) takes another.
    // Every iteration that continues advances `mapped_end` toward the
    // zone bound, so the loop ends: on success, on a grow that maps
    // nothing (memmgr out of memory, or the zone cannot hold the
    // request), and null then reaches `handle_alloc_error`. IPC wrappers
    // under the lock are non-allocating (the IPC buffer is the
    // pre-registered page, not heap-backed), so there is no re-entrant
    // allocation here.
    let want = heap_fit::fit_bound(block_size(layout), layout.align().max(NODE_ALIGN), MIN_BLOCK)
        .unwrap_or(usize::MAX);
    while ptr.is_null() && heap.grow(want) {
        ptr = heap.alloc(layout);
    }
    ptr
}

/// [`alloc`], with the block zeroed.
///
/// # Safety
/// As [`alloc`]: `layout.size()` is non-zero.
#[inline]
pub unsafe fn alloc_zeroed(layout: Layout) -> *mut u8 {
    // SAFETY: delegating to alloc under the caller's contract; zeroing is
    // done here since the free-list hands back uninitialised pages.
    let ptr = unsafe { alloc(layout) };
    if !ptr.is_null() {
        // SAFETY: returned block is at least layout.size() bytes of writable memory.
        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
    }
    ptr
}

/// Return the block at `ptr`, allocated with `layout`, to the byte heap.
///
/// # Safety
/// `ptr` is a block [`alloc`] (or [`alloc_zeroed`] or [`realloc`]) returned
/// for exactly `layout` and not yet returned to the heap (the
/// `GlobalAlloc::dealloc` contract).
#[inline]
pub unsafe fn dealloc(ptr: *mut u8, layout: Layout) {
    if ptr.is_null() {
        return;
    }
    // Must match `alloc`'s reservation, `block_size(layout)` bytes at
    // `ptr`: inserting the same amount back keeps the free-list invariant
    // (every node starts at a `NODE_ALIGN`-aligned address, every block
    // size is a `NODE_ALIGN` multiple), and `heap_fit::fit` kept the
    // bytes around the block on the free list.
    let size = block_size(layout);
    let mut heap = HEAP.lock();
    // SAFETY: the caller guarantees ptr/layout match a prior alloc.
    unsafe { heap.insert(ptr as usize, size) };
}

/// Move the block at `ptr`, allocated with `old_layout`, to a new block of
/// `new_size` bytes at the same alignment; null, with the old block kept,
/// when the new one cannot be allocated.
///
/// # Safety
/// `ptr` is a live block of this heap allocated for exactly `old_layout`,
/// and `new_size` is non-zero and, rounded up to `old_layout.align()`, does
/// not exceed `isize::MAX` (the `GlobalAlloc::realloc` contract).
#[inline]
pub unsafe fn realloc(ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
    let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
        return null_mut();
    };
    // SAFETY: new_layout is validated above, and its size is non-zero by the
    // caller's contract.
    let new_ptr = unsafe { alloc(new_layout) };
    if new_ptr.is_null() {
        return null_mut();
    }
    let copy_len = old_layout.size().min(new_size);
    // SAFETY: both buffers are non-null and owned; ranges non-overlapping.
    unsafe { core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_len) };
    // SAFETY: caller guarantees (ptr, old_layout) match a prior alloc.
    unsafe { dealloc(ptr, old_layout) };
    new_ptr
}
