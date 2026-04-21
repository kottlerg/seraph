// seraph-overlay: std::sys::alloc::seraph
//
// Seraph PAL allocator: a spinlock-guarded first-fit free list whose
// backing pages are lazily requested from procmgr. All syscall wrappers,
// protocol labels, and VA constants come from the workspace crates
// `syscall-abi`, `syscall`, `ipc`, and `va_layout`, pulled into std's
// dep graph through `library/std/Cargo.toml` — mirrors the `hermit-abi`
// / `fortanix-sgx-abi` pattern. The overlay itself holds no inline asm
// and duplicates no protocol numbers.
//
// Bootstrap is explicit: `std::os::seraph::heap_bootstrap(procmgr_ep,
// self_aspace, ipc_buffer_vaddr)` must be called once, after the
// bootstrap IPC round that produces `procmgr_ep`, before the first
// allocation. An allocation before bootstrap returns a null pointer and
// the alloc crate aborts via `handle_alloc_error`.
//
// `unsafe impl GlobalAlloc for System` below delegates to the static
// heap; services that want this allocator simply omit a custom
// `#[global_allocator]` and use `System` (std's default).

use crate::alloc::{GlobalAlloc, Layout, System};
use crate::cell::UnsafeCell;
use crate::mem::{align_of, size_of};
use crate::ptr::{NonNull, null_mut};
use crate::sync::atomic::{AtomicBool, Ordering};

use ipc::procmgr_labels::REQUEST_FRAMES;
use syscall_abi::{MAP_WRITABLE, MSG_CAP_SLOTS_MAX};
use va_layout::{FRAMES_PER_REQUEST, HEAP_BASE, HEAP_INITIAL_PAGES, PAGE_SIZE};

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
}

impl Heap {
    const fn new() -> Self {
        Self { head: None }
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

/// Initialise the heap by requesting frames from procmgr and mapping them
/// at `HEAP_BASE`. Idempotent — only the first call performs real work.
///
/// `ipc_buffer_vaddr` must be the VA of the process's pre-mapped IPC
/// buffer (from `ProcessInfo`). The bootstrap registers that buffer with
/// the kernel first, so callers that have already registered it
/// themselves can safely pass the same address.
///
/// Returns `true` if the heap is usable after this call.
pub fn heap_bootstrap(procmgr_ep: u32, self_aspace: u32, ipc_buffer_vaddr: u64) -> bool {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return true;
    }
    if procmgr_ep == 0 || ipc_buffer_vaddr == 0 {
        return false;
    }

    // Registering the IPC buffer twice is a no-op in the kernel.
    let _ = syscall::ipc_buffer_set(ipc_buffer_vaddr);

    let ipc_buf_u64 = ipc_buffer_vaddr as *mut u64;

    let mut mapped: u64 = 0;
    while mapped < HEAP_INITIAL_PAGES {
        let want = (HEAP_INITIAL_PAGES - mapped).min(FRAMES_PER_REQUEST);

        // SAFETY: ipc_buffer_vaddr is the page-aligned IPC buffer registered above.
        unsafe { core::ptr::write_volatile(ipc_buf_u64, want) };

        let Ok((ret_label, _)) = syscall::ipc_call(procmgr_ep, REQUEST_FRAMES, 1, &[]) else {
            return false;
        };
        if ret_label != 0 {
            return false;
        }

        // SAFETY: ipc_buf_u64 is the registered, page-aligned buffer; shared
        // helper reads the cap-transfer metadata using the documented offset
        // `MSG_DATA_WORDS_MAX`.
        let (cap_count, cap_slots) = unsafe { syscall::read_recv_caps(ipc_buf_u64) };
        let got = cap_count.min(MSG_CAP_SLOTS_MAX) as u64;
        if got < want {
            return false;
        }

        for i in 0..want {
            let cap_slot = cap_slots[i as usize];
            let va = HEAP_BASE + (mapped + i) * PAGE_SIZE;
            if syscall::mem_map(cap_slot, self_aspace, va, 0, 1, MAP_WRITABLE).is_err() {
                return false;
            }
        }
        mapped += want;
    }

    let base = HEAP_BASE as usize;
    let size = (HEAP_INITIAL_PAGES as usize) * (PAGE_SIZE as usize);
    HEAP.lock.lock();
    // SAFETY: freshly-mapped, exclusively-owned region; lock held.
    unsafe { (*HEAP.inner.get()).init(base, size) };
    HEAP.lock.unlock();
    true
}

/// Returns `true` once `heap_bootstrap` has completed successfully.
pub fn heap_is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
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
        let ptr = unsafe { (*HEAP.inner.get()).alloc(layout) };
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
