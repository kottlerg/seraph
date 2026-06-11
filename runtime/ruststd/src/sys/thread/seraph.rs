// seraph-overlay: std::sys::thread::seraph
//
// Thread spawning backed by the Seraph kernel's Thread/Notification primitives.
// Stacks and per-thread IPC buffers are allocated from the process heap
// (page-aligned, no guard pages for now — deferred polish). Join
// synchronises on a Notification cap; the child thread signals just before
// calling SYS_THREAD_EXIT, and join then reclaims the child's kernel object,
// caps, and heap/VA resources. A detached handle (dropped without join) hands
// its resources to the in-module `reaper`, which reclaims them once the child's
// kernel death notification lands (see the `reaper` module).
//
// Native ELF TLS is live: `SYS_THREAD_CONFIGURE` accepts `tls_base`, the
// kernel context switch saves/restores `IA32_FS_BASE` (x86-64) / `tp`
// (RISC-V), procmgr pre-populates a main-thread TLS block from `PT_TLS`,
// and `Thread::new` allocates a per-child TLS block here. Target-JSON
// `has-thread-local: true`, so `#[thread_local]` statics and the
// `thread_local!` macro both route through native TLS.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::alloc::{Layout, alloc, dealloc};
use crate::ffi::CStr;
use crate::io;
use crate::num::NonZero;
use crate::thread::ThreadInit;
use crate::time::Duration;

use syscall_abi::{FAULT_CLASS_ALL, PAGE_SIZE};

/// Default minimum stack size. Matches the upstream unsupported-PAL value.
pub const DEFAULT_MIN_STACK_SIZE: usize = 64 * 1024;

const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;

/// Guard pages below a demand-paged thread stack. The guard is reserved but
/// unregistered: a stack overflow faults in this hole, the pager declines the
/// unregistered address, and the thread — and the whole process, via the
/// address-space death-observer — is killed instead of silently corrupting
/// adjacent memory.
const GUARD_PAGES: u64 = 1;

/// Default usable pages for a demand-paged thread stack (2 MiB). Lazily backed
/// — only touched pages cost RAM — so this floor is generous without eager
/// allocation. A larger `Builder::stack_size` raises it.
const DEFAULT_DEMAND_STACK_PAGES: u64 = 512;

/// Per-thread context the entry trampoline pulls off the `arg` slot of
/// `thread_configure`. Owned by the spawning thread until the child takes
/// it over on entry (the child drops it after extracting the pieces).
struct SpawnArgs {
    ipc_buffer_vaddr: u64,
    init: *mut ThreadInit,
    done_notification: u32,
}

/// The reclaimable resources a spawned thread owns. Moved as a unit between the
/// `Thread` handle (joinable), the reaper registry (detached), and the reclaim
/// path. Has no `Drop` glue — every field is a cap slot, a raw heap pointer, a
/// `Copy` `Layout`, a `StackAlloc` (whose variants own no `Drop` resources), or
/// a plain `u64` — so it is freed only via the explicit
/// [`ThreadResources::reclaim`].
struct ThreadResources {
    thread_cap: u32,
    /// Physical base of the Thread-retype slab's backing run, as reported by
    /// memmgr at grant. Returned to memmgr's pool in `reclaim`, after the
    /// Thread cap is deleted, so a thread-churn loop holds a bounded
    /// memmgr-pool footprint (#274).
    slab_phys: u64,
    done_notification: u32,
    stack: StackAlloc,
    ipc_buf_base: *mut u8,
    ipc_buf_layout: Layout,
    tls_block: *mut u8,
    tls_layout: Option<Layout>,
}

impl ThreadResources {
    /// Reclaim every owned resource: delete the Thread cap (drives
    /// `dealloc_object(Thread)` — drain + `retype_free` + ancestor `dec_ref`),
    /// delete the done-notification cap, free the TLS block and IPC buffer, and
    /// release the stack.
    ///
    /// # Safety
    /// The owning thread MUST have left user-mode (joined, or its kernel death
    /// notification observed). Reclaiming a still-running thread's stack/IPC/TLS
    /// is a use-after-free.
    unsafe fn reclaim(self) {
        let _ = syscall::cap_delete(self.done_notification);
        let _ = syscall::cap_delete(self.thread_cap);
        // The Thread cap is now gone, so `dealloc_object(Thread)` has returned
        // the retype slot's bytes to the source MemoryObject. Hand the slab's
        // run back to memmgr's pool so the footprint stays bounded across a
        // thread-churn loop, rather than leaking a run per spawn until process
        // death (#274). Must follow the Thread cap delete above.
        crate::sys::alloc::seraph::slab_release_fresh(self.slab_phys);
        // SAFETY: the thread has left user-mode; these allocations are no longer
        // read or written from user space.
        unsafe {
            if let Some(l) = self.tls_layout {
                dealloc(self.tls_block, l);
            }
            dealloc(self.ipc_buf_base, self.ipc_buf_layout);
        }
        free_stack(self.stack);
    }
}

pub struct Thread {
    res: ThreadResources,
    /// `Some((slot, generation))` when a kernel death observer is bound and a
    /// reaper-registry slot reserves this thread (the common case). `None` is
    /// the fallback when the reaper was unavailable at spawn — then a detached
    /// (un-joined) handle leaks its resources until process death, as before.
    reaper: Option<(usize, u32)>,
}

// SAFETY: every resource is a plain cap slot, an owned pointer to a distinct
// heap allocation, or an owned stack allocation — none shared with any other
// thread; `reaper` is a plain index pair.
unsafe impl Send for Thread {}
// SAFETY: &Thread exposes no interior mutability; `join` consumes by value.
unsafe impl Sync for Thread {}

/// How a spawned thread's stack is backed.
enum StackAlloc {
    /// Eager heap allocation: a non-demand-paged process, or a demand-paged one
    /// whose reservation failed. No guard page.
    Heap { base: *mut u8, layout: Layout },
    /// Guarded demand-paged stack: a large reserved VA window, lazily grown,
    /// with an unregistered guard page below that faults fatally on overflow.
    Demand(crate::os::seraph::GuardedStack),
}

impl StackAlloc {
    /// Initial stack pointer: top of the usable region, 16-byte aligned for the
    /// SysV ABI (the stack grows down).
    fn sp(&self) -> u64 {
        match self {
            StackAlloc::Heap { base, layout } => {
                let top = (*base as usize).saturating_add(layout.size());
                (top & !15) as u64
            }
            StackAlloc::Demand(g) => g.usable_top() & !15,
        }
    }
}

/// Allocate a spawned thread's stack. A demand-paged process gets a guarded
/// demand stack; on any failure — or for a non-demand-paged process, whose
/// guard-page fault would have no pager to make it fatal — it falls back to the
/// eager-heap path, preserving liveness.
fn alloc_stack(
    info: &crate::os::seraph::StartupInfo,
    requested_bytes: usize,
) -> io::Result<StackAlloc> {
    if info.pager_endpoint_cap != 0 {
        let floor = crate::cmp::max(requested_bytes, DEFAULT_MIN_STACK_SIZE);
        let requested_pages = floor.div_ceil(PAGE_SIZE_USIZE) as u64;
        let usable_pages = crate::cmp::max(requested_pages, DEFAULT_DEMAND_STACK_PAGES);
        if let Ok(g) = crate::os::seraph::reserve_guarded_stack(usable_pages, GUARD_PAGES) {
            return Ok(StackAlloc::Demand(g));
        }
    }
    let stack_size = crate::cmp::max(requested_bytes, DEFAULT_MIN_STACK_SIZE);
    let stack_size = (stack_size + PAGE_SIZE_USIZE - 1) & !(PAGE_SIZE_USIZE - 1);
    let layout = Layout::from_size_align(stack_size, PAGE_SIZE_USIZE)
        .map_err(|_| io::Error::other("seraph: stack layout too large"))?;
    // SAFETY: `layout` has a non-zero size and power-of-two alignment.
    let base = unsafe { alloc(layout) };
    if base.is_null() {
        return Err(io::Error::other("seraph: stack allocation failed"));
    }
    Ok(StackAlloc::Heap { base, layout })
}

/// Release a stack allocation: a heap stack is `dealloc`'d; a demand stack is
/// unregistered (memmgr unmaps and reclaims its backing frames) and its VA
/// released. Call only when the thread no longer uses the stack — on the error
/// unwind in [`Thread::new`] (before start) or in [`Thread::join`] (after the
/// thread has left user-mode).
fn free_stack(stack: StackAlloc) {
    match stack {
        // SAFETY: `base` came from `alloc(layout)` in `alloc_stack`.
        StackAlloc::Heap { base, layout } => unsafe { dealloc(base, layout) },
        StackAlloc::Demand(g) => crate::os::seraph::unregister_guarded_stack(g),
    }
}

impl Thread {
    /// # Safety
    /// See `std::thread::Builder::spawn_unchecked` for the caller-side
    /// safety contract.
    pub unsafe fn new(stack_bytes: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
        let info = crate::os::seraph::try_startup_info().ok_or_else(|| {
            io::Error::other("std::os::seraph::_start has not initialised startup state")
        })?;

        // Reap any detached threads that have since died, freeing their CSpace
        // slots and RAM before this spawn reserves its own.
        reaper::sweep();

        let stack = alloc_stack(info, stack_bytes)?;

        let ipc_buf_layout = match Layout::from_size_align(PAGE_SIZE_USIZE, PAGE_SIZE_USIZE) {
            Ok(l) => l,
            Err(_) => {
                free_stack(stack);
                return Err(io::Error::other("seraph: ipc buffer layout invalid"));
            }
        };
        // SAFETY: `ipc_buf_layout` has a non-zero size and power-of-two alignment.
        let ipc_buf_base = unsafe { alloc(ipc_buf_layout) };
        if ipc_buf_base.is_null() {
            free_stack(stack);
            return Err(io::Error::other("seraph: ipc buffer allocation failed"));
        }

        // Allocate + populate the TLS block. Processes without a PT_TLS
        // segment have `tls_template_memsz == 0` and skip allocation —
        // `thread_configure_with_tls` is then called with tls_base=0.
        let (tls_block, tls_layout, tls_base) = match alloc_thread_tls(info) {
            Ok(triple) => triple,
            Err(e) => {
                // SAFETY: ipc_buf_base came from `alloc(ipc_buf_layout)` above.
                unsafe { dealloc(ipc_buf_base, ipc_buf_layout) };
                free_stack(stack);
                return Err(e);
            }
        };

        let done_notification = match crate::sys::alloc::seraph::object_slab_retype(120, |slab| {
            syscall::cap_create_notification(slab).ok()
        }) {
            Some(cap) => cap,
            None => {
                // SAFETY: heap allocations owned by this function.
                unsafe {
                    if let Some(l) = tls_layout {
                        dealloc(tls_block, l);
                    }
                    dealloc(ipc_buf_base, ipc_buf_layout);
                }
                free_stack(stack);
                return Err(io::Error::other("seraph: notification cap alloc failed"));
            }
        };

        let args = Box::into_raw(Box::new(SpawnArgs {
            ipc_buffer_vaddr: ipc_buf_base as u64,
            init: Box::into_raw(init),
            done_notification,
        }));

        // 5-page slab for the Thread retype slot (kstack + wrapper/TCB).
        // Matches `cap::retype::dispatch_for(Thread)` in the kernel.
        const THREAD_RETYPE_BYTES: u64 = 5 * 4096;
        let (thread_slab, thread_slab_phys) =
            match crate::sys::alloc::seraph::object_slab_acquire_fresh(THREAD_RETYPE_BYTES) {
                Some(g) => (g.cap, g.phys),
                None => {
                    // SAFETY: `args` was just leaked via `Box::into_raw`.
                    let args_owned = unsafe { Box::from_raw(args) };
                    // SAFETY: `args_owned.init` was just leaked via `Box::into_raw`.
                    let _init = unsafe { Box::from_raw(args_owned.init) };
                    // SAFETY: heap allocations owned by this function.
                    unsafe {
                        if let Some(l) = tls_layout {
                            dealloc(tls_block, l);
                        }
                        dealloc(ipc_buf_base, ipc_buf_layout);
                    }
                    free_stack(stack);
                    return Err(io::Error::other("seraph: thread retype slab alloc failed"));
                }
            };
        let thread_cap =
            match syscall::cap_create_thread(thread_slab, info.self_aspace, info.self_cspace) {
                Ok(cap) => cap,
                Err(_) => {
                    let _ = syscall::cap_delete(thread_slab);
                    // Retype failed, so the slab is virgin — return its run to
                    // memmgr's pool instead of leaking it until process death.
                    crate::sys::alloc::seraph::slab_release_fresh(thread_slab_phys);
                    // SAFETY: `args` was just leaked via `Box::into_raw`.
                    let args_owned = unsafe { Box::from_raw(args) };
                    // SAFETY: `args_owned.init` was just leaked via `Box::into_raw`.
                    let _init = unsafe { Box::from_raw(args_owned.init) };
                    // SAFETY: heap allocations owned by this function.
                    unsafe {
                        if let Some(l) = tls_layout {
                            dealloc(tls_block, l);
                        }
                        dealloc(ipc_buf_base, ipc_buf_layout);
                    }
                    free_stack(stack);
                    return Err(io::Error::other("seraph: thread cap alloc failed"));
                }
            };

        // The kernel bumped the source MemoryObject's refcount into the Thread
        // (`ancestor.inc_ref()` in `sys_cap_create_thread`), so the Thread keeps
        // the retype slot's backing alive on its own. The `thread_slab` cap slot
        // is now dead weight — delete it to reclaim the slot. The slot is freed
        // immediately; the MemoryObject's bytes are reclaimed when the Thread is.
        let _ = syscall::cap_delete(thread_slab);

        // SP at the top of the usable stack region, 16-byte aligned for SysV
        // ABI; the stack grows down toward the guard page (demand) or heap base.
        let sp = stack.sp();
        let entry_addr = thread_entry as extern "C" fn(u64) -> ! as usize as u64;

        if let Err(_) =
            syscall::thread_configure_with_tls(thread_cap, entry_addr, sp, args as u64, tls_base)
        {
            // The thread was created but never started; deleting its cap drives
            // `dealloc_object(Thread)` (drain gates pass immediately — it never
            // ran) to reclaim the retype slot + ancestor bytes.
            let _ = syscall::cap_delete(thread_cap);
            // Thread destroyed → its retype bytes are back in the MemoryObject;
            // return the slab's run to memmgr's pool.
            crate::sys::alloc::seraph::slab_release_fresh(thread_slab_phys);
            // SAFETY: `args` was just leaked via `Box::into_raw`.
            let args_owned = unsafe { Box::from_raw(args) };
            // SAFETY: `args_owned.init` was just leaked via `Box::into_raw`.
            let _init = unsafe { Box::from_raw(args_owned.init) };
            // SAFETY: heap allocations owned by this function.
            unsafe {
                if let Some(l) = tls_layout {
                    dealloc(tls_block, l);
                }
                dealloc(ipc_buf_base, ipc_buf_layout);
            }
            free_stack(stack);
            return Err(io::Error::other("seraph: thread_configure failed"));
        }

        // Inherit the process's demand-paging pager onto this thread before it
        // starts (the main thread is bound by procmgr at creation). Best-effort
        // and a no-op for non-demand-paged processes (`pager_endpoint_cap == 0`).
        if info.pager_endpoint_cap != 0 {
            let _ = syscall::thread_set_fault_handler(
                thread_cap,
                info.pager_endpoint_cap,
                info.pager_badge,
                FAULT_CLASS_ALL,
            );
        }

        // Bind a kernel death observer so a detached (un-joined) handle's
        // resources can be reclaimed by `reaper::sweep` once this thread leaves
        // user-mode. MUST be done before `thread_start` (binding a running
        // thread races the kernel's lock-free death-post reader). Best-effort:
        // if the reaper is unavailable, fall back to leak-on-detach (`None`).
        let reaper = reaper::register(thread_cap);

        if let Err(_) = syscall::thread_start(thread_cap) {
            if let Some((slot, generation)) = reaper {
                reaper::release(slot, generation);
            }
            // Never started → safe to reclaim the Thread object immediately.
            let _ = syscall::cap_delete(thread_cap);
            // Thread destroyed → return the slab's run to memmgr's pool.
            crate::sys::alloc::seraph::slab_release_fresh(thread_slab_phys);
            // SAFETY: `args` was just leaked via `Box::into_raw`.
            let args_owned = unsafe { Box::from_raw(args) };
            // SAFETY: `args_owned.init` was just leaked via `Box::into_raw`.
            let _init = unsafe { Box::from_raw(args_owned.init) };
            // SAFETY: heap allocations owned by this function.
            unsafe {
                if let Some(l) = tls_layout {
                    dealloc(tls_block, l);
                }
                dealloc(ipc_buf_base, ipc_buf_layout);
            }
            free_stack(stack);
            return Err(io::Error::other("seraph: thread_start failed"));
        }

        Ok(Thread {
            res: ThreadResources {
                thread_cap,
                slab_phys: thread_slab_phys,
                done_notification,
                stack,
                ipc_buf_base,
                ipc_buf_layout,
                tls_block,
                tls_layout,
            },
            reaper,
        })
    }

    pub fn join(self) {
        // Move the resources out and suppress the Drop path; this handle is
        // joined, not detached.
        // SAFETY: `res`/`reaper` are valid initialised fields; `forget(self)`
        // below suppresses the destructor, so these reads are not double-frees.
        let res = unsafe { core::ptr::read(&self.res) };
        let reaper = self.reaper;
        core::mem::forget(self);

        // Wait for the child to signal completion of its rust_start and reach
        // `notification_send`. After this its only remaining action is
        // `thread_exit` (in-kernel), so its stack, IPC buffer, and TLS block are
        // safe to reclaim. `reclaim` then deletes the done-notification cap, the
        // Thread cap (driving `dealloc_object(Thread)` — the drain gates pass
        // without spinning since the child has already exited), and frees the
        // memory. A spurious early wake only makes the cap delete briefly spin
        // in the kernel drain protocol — correct, never a use-after-free.
        let _ = syscall::notification_wait(res.done_notification);
        // SAFETY: the child has left user-mode (it signalled done_notification).
        unsafe { res.reclaim() };

        // Release this thread's reaper slot so its (eventual) death-post is a
        // no-op, then opportunistically reap any detached threads that have died.
        if let Some((slot, generation)) = reaper {
            reaper::release(slot, generation);
        }
        reaper::sweep();
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // Dropping a `Thread` without `join()` is a detach: the child runs on
        // independently and the caller has no synchronisation point to know
        // when it leaves user-mode. Freeing the stack, IPC buffer, or TLS block
        // here would be a use-after-free — the memory would re-enter the heap's
        // free list and the `FreeNode` metadata would clobber the child's live
        // TLS/stack data.
        //
        // Instead, hand ownership to the reaper registry: a kernel death
        // observer (bound in `new`) posts to the process death `EventQueue`
        // when the child exits or faults, and `reaper::sweep` (run on every
        // spawn/join) reclaims the resources then. If the child has already
        // died, `detach` returns the resources to reclaim now.
        //
        // SAFETY: `res` is a valid initialised field; `ThreadResources` has no
        // `Drop` glue, so the field's automatic drop after this returns is a
        // no-op — no double-free of the bytes read out here.
        let res = unsafe { core::ptr::read(&self.res) };
        match self.reaper {
            Some((slot, generation)) => {
                if let Some(res) = reaper::detach(slot, generation, res) {
                    // SAFETY: the child already exited (its death-post was
                    // observed while still Reserved); reclaiming now is safe.
                    unsafe { res.reclaim() };
                }
                reaper::sweep();
            }
            None => {
                // No death observer was bound (the reaper was unavailable at
                // spawn): no signal will tell us when the child leaves
                // user-mode, so reclaiming now would be a use-after-free. Leak
                // the resources until process death (the pre-reaper fallback).
                core::mem::forget(res);
            }
        }
    }
}

/// Detached-thread reaper.
///
/// `std::thread` detach (dropping a `JoinHandle`) leaves a running child the
/// parent can no longer synchronise with. Reclaiming the child's kernel object
/// and heap/VA resources needs a surviving thread to act *after* the child
/// leaves user-mode. The kernel already provides that signal —
/// `SYS_THREAD_BIND_NOTIFICATION` posts a thread's death (exit or fault) to a
/// bound `EventQueue` — so no new syscall is required; this mirrors how
/// `std::process::Child` reaps child processes.
///
/// Every spawned thread binds a death observer (before `thread_start`) to one
/// process-global death `EventQueue`, with a generation-tagged correlator that
/// names a registry slot. A joined thread reclaims its own resources directly
/// and frees its slot; a detached thread leaves its resources in the slot.
/// `sweep` drains the `EventQueue` on every spawn/join and reclaims any detached
/// thread whose death-post has landed. The generation tag makes a stale post
/// for an already-joined or reused slot a no-op.
mod reaper {
    use super::ThreadResources;
    use crate::cell::UnsafeCell;
    use crate::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// Max concurrently-bound spawned threads. A spawn beyond this falls back to
    /// leak-on-detach (join still reclaims directly). 64 covers realistic
    /// thread fan-out; raising it only costs registry static size.
    const REAPER_SLOTS: usize = 64;
    /// Death `EventQueue` capacity. Drained on every spawn/join, so overflow
    /// needs >128 detached threads dying between two thread ops — pathological;
    /// the overflow remainder leaks only until process exit (kernel silently
    /// drops a post to a full queue).
    const EQ_CAPACITY: u32 = 128;
    /// Correlator bit split: low `GEN_BITS` are the generation, the rest the
    /// slot index (6 bits → 64 slots).
    const GEN_BITS: u32 = 26;
    const GEN_MASK: u32 = (1 << GEN_BITS) - 1;

    fn correlator(slot: usize, generation: u32) -> u32 {
        ((slot as u32) << GEN_BITS) | (generation & GEN_MASK)
    }
    fn split(correlator: u32) -> (usize, u32) {
        ((correlator >> GEN_BITS) as usize, correlator & GEN_MASK)
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SlotState {
        /// No occupant.
        Vacant,
        /// Bound, handle still held (joinable). Resources live in the `Thread`.
        Reserved,
        /// Handle dropped (detached). Resources live in `res`, awaiting the
        /// child's death-post.
        Detached,
    }

    struct Slot {
        state: SlotState,
        generation: u32,
        /// Set when a death-post arrives while still `Reserved` (child died
        /// before the handle was joined/detached). `detach` consults it to
        /// reclaim immediately instead of waiting for a post that already fired.
        died: bool,
        res: Option<ThreadResources>,
    }

    const fn vacant_slot() -> Slot {
        Slot { state: SlotState::Vacant, generation: 0, died: false, res: None }
    }

    struct Registry {
        next_gen: u32,
        slots: [Slot; REAPER_SLOTS],
    }

    struct Reaper {
        lock: SpinLock,
        inner: UnsafeCell<Registry>,
    }
    // SAFETY: all access to `inner` is serialised by `lock`; the resources held
    // in slots are owned (not shared) and reclaimed exactly once.
    unsafe impl Sync for Reaper {}

    static REAPER: Reaper = Reaper {
        lock: SpinLock::new(),
        inner: UnsafeCell::new(Registry {
            next_gen: 1,
            slots: [const { vacant_slot() }; REAPER_SLOTS],
        }),
    };

    /// Process death `EventQueue` cap, lazily created on first spawn. `0` = not
    /// yet created or unavailable.
    static DEATH_EQ: AtomicU32 = AtomicU32::new(0);

    /// Minimal spinlock (mirrors the alloc module's; that one is private).
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

    /// Return the process death `EventQueue` cap, creating it on first use.
    /// `0` if the reaper is unavailable (then callers fall back to leak-on-detach).
    fn death_eq() -> u32 {
        let cur = DEATH_EQ.load(Ordering::Acquire);
        if cur != 0 {
            return cur;
        }
        // EventQueue retype size = 80 + (capacity + 1) * 8 bytes; over-request a
        // little so the slab definitely covers it (fresh dedicated cap path).
        let want = (u64::from(EQ_CAPACITY) + 1) * 8 + 256;
        let made = crate::sys::alloc::seraph::object_slab_retype(want, |slab| {
            syscall::event_queue_create(slab, EQ_CAPACITY).ok()
        });
        let Some(eq) = made else {
            return 0;
        };
        match DEATH_EQ.compare_exchange(0, eq, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => eq,
            // Lost the race: another thread installed one. Delete our duplicate.
            Err(existing) => {
                let _ = syscall::cap_delete(eq);
                existing
            }
        }
    }

    /// Reserve a registry slot and bind a kernel death observer on `thread_cap`.
    /// Returns `Some((slot, generation))` on success, `None` if the reaper is
    /// unavailable or full (caller then leaks on detach). Call before
    /// `thread_start`.
    pub(super) fn register(thread_cap: u32) -> Option<(usize, u32)> {
        let eq = death_eq();
        if eq == 0 {
            return None;
        }

        // Reserve a vacant slot.
        REAPER.lock.lock();
        // SAFETY: lock held; single mutator.
        let reg = unsafe { &mut *REAPER.inner.get() };
        let reserved = (|| {
            for (i, slot) in reg.slots.iter_mut().enumerate() {
                if slot.state == SlotState::Vacant {
                    let generation = reg.next_gen & GEN_MASK;
                    reg.next_gen = reg.next_gen.wrapping_add(1);
                    slot.state = SlotState::Reserved;
                    slot.generation = generation;
                    slot.died = false;
                    slot.res = None;
                    return Some((i, generation));
                }
            }
            None
        })();
        REAPER.lock.unlock();

        let (slot, generation) = reserved?;
        // Bind the observer. On failure, release the slot and fall back.
        if syscall::thread_bind_notification(thread_cap, eq, correlator(slot, generation)).is_err()
        {
            release(slot, generation);
            return None;
        }
        Some((slot, generation))
    }

    /// Release a slot on join (resources reclaimed directly by the caller). A
    /// later death-post for this slot is ignored (state `Vacant` / generation
    /// mismatch).
    pub(super) fn release(slot: usize, generation: u32) {
        if slot >= REAPER_SLOTS {
            return;
        }
        REAPER.lock.lock();
        // SAFETY: lock held; single mutator.
        let reg = unsafe { &mut *REAPER.inner.get() };
        let s = &mut reg.slots[slot];
        if s.generation == generation && s.state != SlotState::Vacant {
            *s = vacant_slot();
        }
        REAPER.lock.unlock();
    }

    /// Hand a detached thread's resources to the registry. If the child already
    /// died (its death-post was observed while `Reserved`), returns the
    /// resources for the caller to reclaim immediately; otherwise stores them
    /// for `sweep` and returns `None`.
    pub(super) fn detach(
        slot: usize,
        generation: u32,
        res: ThreadResources,
    ) -> Option<ThreadResources> {
        if slot >= REAPER_SLOTS {
            // Out-of-range slot index can't be reclaimed safely (no death
            // signal we can trust) — leak rather than risk a UAF.
            core::mem::forget(res);
            return None;
        }
        REAPER.lock.lock();
        // SAFETY: lock held; single mutator.
        let reg = unsafe { &mut *REAPER.inner.get() };
        let s = &mut reg.slots[slot];
        let outcome = if s.generation == generation && s.state == SlotState::Reserved {
            if s.died {
                // Child already dead, post already drained — reclaim now.
                *s = vacant_slot();
                Some(res)
            } else {
                s.state = SlotState::Detached;
                s.res = Some(res);
                None
            }
        } else {
            // Unexpected (slot reused/vacated under us). Leak rather than risk a
            // UAF on a possibly-live thread.
            core::mem::forget(res);
            None
        };
        REAPER.lock.unlock();
        outcome
    }

    /// Drain the death `EventQueue` (non-blocking) and reclaim any detached
    /// thread whose death-post has landed. Called on every spawn and join.
    pub(super) fn sweep() {
        let eq = DEATH_EQ.load(Ordering::Acquire);
        if eq == 0 {
            return;
        }
        loop {
            let payload = match syscall::event_try_recv(eq) {
                Ok(p) => p,
                // WouldBlock (empty) or the queue is gone — nothing more to do.
                Err(_) => break,
            };
            let (slot, generation) = split((payload >> 32) as u32);

            REAPER.lock.lock();
            // SAFETY: lock held; single mutator.
            let reg = unsafe { &mut *REAPER.inner.get() };
            let to_reclaim = if slot < REAPER_SLOTS {
                let s = &mut reg.slots[slot];
                if s.generation == generation {
                    match s.state {
                        SlotState::Detached => {
                            let res = s.res.take();
                            *s = vacant_slot();
                            res
                        }
                        SlotState::Reserved => {
                            // Child died but the handle is still held; mark it so
                            // `detach`/`release` reclaims when it runs.
                            s.died = true;
                            None
                        }
                        SlotState::Vacant => None,
                    }
                } else {
                    None // stale post for a reused slot
                }
            } else {
                None
            };
            REAPER.lock.unlock();

            if let Some(res) = to_reclaim {
                // SAFETY: the death-post fired, so the thread has left user-mode;
                // its stack/IPC/TLS and Thread cap are safe to reclaim.
                unsafe { res.reclaim() };
            }
        }
    }
}

/// Allocate a per-thread TLS block according to the architecture's variant,
/// populate it from the PT_TLS template recorded in `StartupInfo`, and
/// return `(block_ptr, layout, tls_base_va)`.
///
/// Returns `(ptr::null_mut(), None, 0)` when the binary has no PT_TLS.
fn alloc_thread_tls(
    info: &crate::os::seraph::StartupInfo,
) -> io::Result<(*mut u8, Option<Layout>, u64)> {
    if info.tls_template_memsz == 0 {
        return Ok((core::ptr::null_mut(), None, 0));
    }

    let (block_size, block_align, tls_base_offset) = process_abi::tls_block_layout(
        info.tls_template_memsz,
        info.tls_template_align,
    );
    if block_size == 0 {
        return Ok((core::ptr::null_mut(), None, 0));
    }

    let layout = Layout::from_size_align(block_size as usize, block_align as usize)
        .map_err(|_| io::Error::other("seraph: tls layout invalid"))?;
    // SAFETY: `layout` has a non-zero size and power-of-two alignment.
    let block = unsafe { alloc(layout) };
    if block.is_null() {
        return Err(io::Error::other("seraph: tls block allocation failed"));
    }

    // SAFETY: `block` owns `block_size` bytes.
    unsafe {
        core::ptr::write_bytes(block, 0, block_size as usize);
        if info.tls_template_filesz != 0 {
            core::ptr::copy_nonoverlapping(
                info.tls_template_vaddr as *const u8,
                block,
                info.tls_template_filesz as usize,
            );
        }
        let tls_base_va = (block as u64) + tls_base_offset;
        process_abi::tls_install_tcb(block, tls_base_offset, tls_base_va);

        Ok((block, Some(layout), tls_base_va))
    }
}

extern "C" fn thread_entry(arg: u64) -> ! {
    // SAFETY: arg was produced via `Box::into_raw(Box::new(SpawnArgs {..}))`
    // in Thread::new; this is the sole consumer.
    let args = unsafe { Box::from_raw(arg as *mut SpawnArgs) };
    let _ = syscall::ipc_buffer_set(args.ipc_buffer_vaddr);
    crate::os::seraph::set_current_ipc_buf(args.ipc_buffer_vaddr as *mut u64);

    // SAFETY: args.init was produced via `Box::into_raw(init)` in
    // Thread::new; consumed exactly once here.
    let init_box = unsafe { Box::from_raw(args.init) };

    // NOTE: we deliberately bypass `ThreadInit::init()` because its
    // internal `set_current(self.handle.clone())` rtaborts on the second
    // caller, and with our `no_threads` thread_local mapping the CURRENT
    // static is shared across threads (so the main thread already set
    // it). Pull `rust_start` out and run it directly; the handle is
    // dropped, which is fine — it is ref-counted and the JoinHandle
    // keeps a clone.
    let rust_start = init_box.rust_start;
    rust_start();

    let _ = syscall::notification_send(args.done_notification, 1);
    syscall::thread_exit();
}

pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    // We don't currently expose CPU topology. Report 1 — callers relying on
    // >1 will degrade to single-threaded scheduling hints, never incorrect.
    Ok(unsafe { NonZero::new_unchecked(1) })
}

pub fn current_os_id() -> Option<u64> {
    None
}

pub fn yield_now() {
    let _ = syscall::thread_yield();
}

pub fn set_name(_name: &CStr) {
    // No kernel-side thread name concept; diagnostic labels are std-side.
}

pub fn sleep(dur: Duration) {
    // Round up sub-ms durations to 1 ms so short sleeps still yield.
    let mut ms = dur.as_millis();
    if ms == 0 && !dur.is_zero() {
        ms = 1;
    }
    let ms = u64::try_from(ms).unwrap_or(u64::MAX);
    let _ = syscall::thread_sleep(ms);
}
