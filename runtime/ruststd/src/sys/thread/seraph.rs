// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/thread/seraph.rs

//! Thread spawning backed by the Seraph kernel's Thread/Notification primitives.
//! A demand-paged process gives each thread a guarded demand-paged stack
//! (`GUARD_PAGES` below at least `os::seraph::DEFAULT_DEMAND_STACK_PAGES`; see
//! `alloc_stack`); a non-demand-paged process, or a failed reservation, falls
//! back to an eager page-aligned heap stack without a guard. Per-thread IPC
//! buffers are page-aligned heap allocations. Join synchronises on a
//! Notification cap; the child thread signals just before calling
//! SYS_THREAD_EXIT, and join then reclaims the child's kernel object, caps, and
//! heap/VA resources. A detached handle (dropped without join), or a join whose
//! wait fails for a reason other than `Interrupted`, hands its resources to the
//! in-module `reaper`, which reclaims them once the child's kernel death
//! notification lands (see the `reaper` module).
//!
//! Native ELF TLS is live: `SYS_THREAD_CONFIGURE` accepts `tls_base`, the
//! kernel context switch saves/restores `IA32_FS_BASE` (x86-64) / `tp`
//! (RISC-V), procmgr pre-populates a main-thread TLS block from `PT_TLS`,
//! and `Thread::new` allocates a per-child TLS block here. Target-JSON
//! `has-thread-local: true`, so `#[thread_local]` statics and the
//! `thread_local!` macro both route through native TLS.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::alloc::{Layout, alloc, dealloc};
use crate::ffi::CStr;
use crate::io;
use crate::num::NonZero;
use crate::thread::ThreadInit;
use crate::time::Duration;

use syscall_abi::{FAULT_CLASS_ALL, PAGE_SIZE, SyscallError, SystemInfoType};

/// The kernel's debit for one Thread retype (`SystemInfoType::ThreadRetypeBytes`),
/// fixed for the boot: the boot CPU's extended-state area sizes it. Queried
/// once and cached; `None` if the query fails.
fn thread_retype_bytes() -> Option<u64> {
    use crate::sync::atomic::{AtomicU64, Ordering};
    static CACHED: AtomicU64 = AtomicU64::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(cached);
    }
    let bytes = syscall::system_info(SystemInfoType::ThreadRetypeBytes as u64).ok()?;
    CACHED.store(bytes, Ordering::Relaxed);
    Some(bytes)
}

/// Default minimum stack size. Matches the upstream unsupported-PAL value.
/// A default only: `Builder::stack_size` sets a thread's size past it.
pub const DEFAULT_MIN_STACK_SIZE: usize = 64 * 1024;

const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;

/// Guard pages below a demand-paged thread stack. The guard is reserved but
/// unregistered: a stack overflow faults in this hole, the pager declines the
/// unregistered address, and the thread — and the whole process, via the
/// address-space death-observer — is killed instead of silently corrupting
/// adjacent memory.
const GUARD_PAGES: u64 = 1;

/// General-allocation headroom of the process's `CSpace` a spawn keeps: a
/// spawn first tops the `CSpace` up when its headroom is below this plus a
/// page's slots (`CSPACE_SLOTS_PER_PAGE`, which
/// `syscall_abi::cspace_topup_pages` holds for the body arena), or its growth
/// budget below a page. One spawn takes a few slots for good (the Thread cap
/// and its done notification) and a few more while it runs (the Thread slab,
/// a pool-page refill, a further death queue and its grant, a heap grow's at
/// most `MSG_CAP_SLOTS_MAX` caps), about ten in all, so the mark leaves room
/// for a whole spawn with margin.
const SPAWN_CSPACE_LOW_WATER: u64 = 32;

/// Headroom a spawn's top-up funds. Past the low-water mark, so the next
/// top-up comes only after a few dozen more live threads, not at every
/// spawn.
const SPAWN_CSPACE_TOPUP_SLOTS: u64 = 128;

/// Keep the process's `CSpace` above [`SPAWN_CSPACE_LOW_WATER`] general
/// slots, with a page of growth budget beyond them for its body arena, so a
/// process's live thread count is bound by the RAM memmgr grants rather than
/// by the `CSpace` its creator seeded. The check is the one memmgr's and
/// procmgr's own low-water top-ups make (`syscall_abi::cspace_topup_pages`).
/// Best-effort: a failed top-up leaves the spawn to fail at its own
/// capability allocation if the headroom is truly spent.
fn hold_cspace_headroom(self_cspace: u64) {
    let budget = syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_BUDGET).unwrap_or(0);
    let headroom = crate::sys::alloc::seraph::cspace_general_headroom(self_cspace);
    if syscall_abi::cspace_topup_pages(headroom, budget, SPAWN_CSPACE_LOW_WATER) != 0 {
        let _ = crate::sys::alloc::seraph::fund_cspace_slot_budget(
            self_cspace,
            SPAWN_CSPACE_TOPUP_SLOTS,
        );
    }
}

/// Per-thread context the entry trampoline pulls off the `arg` slot of
/// `thread_configure`. Owned by the spawning thread until the child takes
/// it over on entry (the child drops it after extracting the pieces).
struct SpawnArgs {
    ipc_buffer_vaddr: u64,
    /// The child's own Thread cap, recorded on entry so a thread it spawns
    /// inherits its fault-handler bindings.
    self_thread_cap: u64,
    init: *mut ThreadInit,
    done_notification: u64,
}

/// The reclaimable resources a spawned thread owns. Moved as a unit between the
/// `Thread` handle (joinable), the reaper registry (detached), and the reclaim
/// path. Has no `Drop` glue — every field is a cap slot, a raw heap pointer, a
/// `Copy` `Layout`, a `StackAlloc` (whose variants own no `Drop` resources), or
/// a plain `u64` — so it is freed only via the explicit
/// [`ThreadResources::reclaim`].
struct ThreadResources {
    thread_cap: u64,
    /// Region id of the Thread-retype slab's backing run, as reported by
    /// memmgr at grant. Returned to memmgr's pool in `reclaim`, after the
    /// Thread cap is deleted, so a thread-churn loop holds a bounded
    /// memmgr-pool footprint (#274).
    slab_region_id: u64,
    done_notification: u64,
    stack: StackAlloc,
    ipc_buf_base: *mut u8,
    ipc_buf_layout: Layout,
    tls_block: *mut u8,
    tls_layout: Option<Layout>,
}

// SAFETY: the raw pointers are owned pointers to distinct heap allocations
// (the IPC buffer, the TLS block) that no other `ThreadResources` names; the
// value is moved whole between the handle, the reaper registry, and the
// reclaim path, so whichever thread holds it is the only one that frees them.
unsafe impl Send for ThreadResources {}

impl ThreadResources {
    /// Reclaim every owned resource: delete the Thread cap (drives
    /// `dealloc_object(Thread)` — drain + `retype_free` + ancestor `dec_ref`),
    /// delete the done-notification cap, free the TLS block and IPC buffer, and
    /// release the stack. A `done_notification` of 0 (the permanently null
    /// slot, set by a join whose wait failed) deletes nothing.
    ///
    /// # Safety
    /// The owning thread MUST have left user-mode (joined, or its kernel death
    /// notification observed). Reclaiming a still-running thread's stack/IPC/TLS
    /// is a use-after-free.
    unsafe fn reclaim(self) {
        let _ = syscall::cap_delete(self.done_notification);
        // Revoke the caps derived from this one first: the copy the thread
        // registered with procmgr (`register_with_procmgr`), and any a
        // debugger holds through it, which would otherwise keep the Thread
        // object, and the slab run below, alive.
        let _ = syscall::cap_revoke_all(self.thread_cap);
        let _ = syscall::cap_delete(self.thread_cap);
        // The Thread cap is now gone, so `dealloc_object(Thread)` has returned
        // the retype slot's bytes to the source MemoryObject. Hand the slab's
        // run back to memmgr's pool so the footprint stays bounded across a
        // thread-churn loop, rather than leaking a run per spawn until process
        // death (#274). Must follow the Thread cap delete above.
        crate::sys::alloc::seraph::slab_release_fresh(self.slab_region_id);
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
    reaper: Option<(u32, u32)>,
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
        let usable_pages =
            crate::cmp::max(requested_pages, crate::os::seraph::DEFAULT_DEMAND_STACK_PAGES);
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

/// Unwind a spawn that failed after its `SpawnArgs` was built and before any
/// thread started with it: delete the done notification, drop the boxed
/// init, free the TLS block and IPC buffer, and release the stack.
///
/// # Safety
/// `args` MUST come from `Box::into_raw` in [`Thread::new`], with no thread
/// started on it; `tls_block`/`tls_layout` and `ipc_buf_base`/`ipc_buf_layout`
/// MUST be that spawn's own allocations, which nothing else references.
unsafe fn unwind_unstarted_spawn(
    args: *mut SpawnArgs,
    tls_block: *mut u8,
    tls_layout: Option<Layout>,
    ipc_buf_base: *mut u8,
    ipc_buf_layout: Layout,
    stack: StackAlloc,
) {
    // SAFETY: the caller's contract makes `args` an unshared `Box::into_raw`.
    let args = unsafe { Box::from_raw(args) };
    // SAFETY: `args.init` came from `Box::into_raw` in `Thread::new`, and no
    // started thread took it over.
    drop(unsafe { Box::from_raw(args.init) });
    let _ = syscall::cap_delete(args.done_notification);
    // SAFETY: the caller's contract makes these this spawn's own allocations.
    unsafe {
        if let Some(l) = tls_layout {
            dealloc(tls_block, l);
        }
        dealloc(ipc_buf_base, ipc_buf_layout);
    }
    free_stack(stack);
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
        hold_cspace_headroom(info.self_cspace);

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
        // The kernel's IPC-buffer copies fail on an unbacked page instead of
        // faulting to the pager, and in a demand-paged process this heap page
        // may not be backed yet: touch it so the pager backs it now
        // (core/kernel/docs/syscalls.md § `SYS_IPC_BUFFER_SET`).
        // SAFETY: `ipc_buf_base` is a fresh, page-aligned, page-sized
        // allocation this function owns; nothing else references it.
        unsafe { core::ptr::write_volatile(ipc_buf_base, 0) };

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

        let bytes = syscall_abi::NOTIFICATION_RETYPE_BYTES;
        let done_notification = match crate::sys::alloc::seraph::object_slab_retype(bytes, |slab| {
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
            self_thread_cap: 0,
            init: Box::into_raw(init),
            done_notification,
        }));

        // Dedicated slab for the Thread retype slot, sized to the kernel's
        // debit (guard page, kstack, wrapper and TCB, extended-state save area).
        let (thread_slab, thread_slab_region_id) =
            match thread_retype_bytes().and_then(crate::sys::alloc::seraph::object_slab_acquire_fresh)
            {
                Some(g) => (g.cap, g.region_id),
                None => {
                    // SAFETY: `args` came from `Box::into_raw` above and no thread started
                    // with it; the TLS block, IPC buffer, and stack are this spawn's own.
                    unsafe {
                        unwind_unstarted_spawn(args, tls_block, tls_layout, ipc_buf_base, ipc_buf_layout, stack)
                    };
                    return Err(io::Error::other("seraph: thread retype slab alloc failed"));
                }
            };
        // Place the new thread at the process's assigned level, or the one a
        // `spawn_at_priority` on this thread asked for, under the process's
        // own baseline band; the kernel refuses a level outside the band. A
        // process with no scheduling authority passes (0, 0) and its workers
        // land at the floor.
        let (spawn_sched_cap, spawn_priority) = if info.sched_control_cap != 0 {
            let requested = crate::os::seraph::thread::requested_spawn_priority();
            let level = if requested != 0 { requested } else { info.initial_priority };
            (info.sched_control_cap, level)
        } else {
            (0, 0)
        };
        let thread_cap =
            match syscall::cap_create_thread(
                thread_slab,
                info.self_aspace,
                info.self_cspace,
                spawn_sched_cap,
                spawn_priority,
            ) {
                Ok(cap) => cap,
                Err(_) => {
                    let _ = syscall::cap_delete(thread_slab);
                    // Retype failed, so the slab is virgin — return its run to
                    // memmgr's pool instead of leaking it until process death.
                    crate::sys::alloc::seraph::slab_release_fresh(thread_slab_region_id);
                    // SAFETY: `args` came from `Box::into_raw` above and no thread started
                    // with it; the TLS block, IPC buffer, and stack are this spawn's own.
                    unsafe {
                        unwind_unstarted_spawn(args, tls_block, tls_layout, ipc_buf_base, ipc_buf_layout, stack)
                    };
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

        // SAFETY: the thread is bound to this process's own address space;
        // `thread_entry` is an `extern "C" fn(u64) -> !` taking `args`; `sp` is
        // the top of `stack`, allocated above for this thread alone and freed
        // only after it exits (the reaper); `tls_base` is 0 or the thread
        // pointer of the TLS block `alloc_thread_tls` built above for it alone.
        if let Err(_) = unsafe {
            syscall::thread_configure_with_tls(thread_cap, entry_addr, sp, args as u64, tls_base)
        } {
            // The thread was created but never started; deleting its cap drives
            // `dealloc_object(Thread)` (drain gates pass immediately — it never
            // ran) to reclaim the retype slot + ancestor bytes.
            let _ = syscall::cap_delete(thread_cap);
            // Thread destroyed → its retype bytes are back in the MemoryObject;
            // return the slab's run to memmgr's pool.
            crate::sys::alloc::seraph::slab_release_fresh(thread_slab_region_id);
            // SAFETY: `args` came from `Box::into_raw` above and no thread started
            // with it; the TLS block, IPC buffer, and stack are this spawn's own.
            unsafe {
                unwind_unstarted_spawn(args, tls_block, tls_layout, ipc_buf_base, ipc_buf_layout, stack)
            };
            return Err(io::Error::other("seraph: thread_configure failed"));
        }

        // Inherit the spawning thread's fault-handler bindings, every class,
        // onto this thread before it starts: the process's demand-paging pager
        // (procmgr binds it on the initial thread at creation, and each spawn
        // passes it on), and any other handler bound there; a copy of no
        // binding for a process with none. A failed copy fails the spawn: a
        // thread started without its pager would die on its first touch of an
        // unbacked demand page (its stack's, when the stack is demand-backed)
        // with a bare unhandled page fault instead of returning this error.
        // SAFETY: `args` was leaked via `Box::into_raw` above and is consumed
        // only by the child, which has not started.
        unsafe { (*args).self_thread_cap = thread_cap };
        if let Err(e) = syscall::thread_inherit_fault_handler(
            thread_cap,
            crate::os::seraph::current_thread_cap(),
            FAULT_CLASS_ALL,
        ) {
            // Never started: deleting its cap reclaims the Thread object, and
            // the slab's run goes back to memmgr's pool.
            let _ = syscall::cap_delete(thread_cap);
            crate::sys::alloc::seraph::slab_release_fresh(thread_slab_region_id);
            // SAFETY: `args` came from `Box::into_raw` above and no thread started
            // with it; the TLS block, IPC buffer, and stack are this spawn's own.
            unsafe {
                unwind_unstarted_spawn(args, tls_block, tls_layout, ipc_buf_base, ipc_buf_layout, stack)
            };
            return Err(io::Error::other(format!(
                "seraph: thread_inherit_fault_handler failed (error {e})"
            )));
        }

        // Bind a kernel death observer so a detached (un-joined) handle's
        // resources can be reclaimed by `reaper::sweep` once this thread leaves
        // user-mode. MUST be done before `thread_start` (binding a running
        // thread races the kernel's lock-free death-post reader). Best-effort:
        // if the reaper is unavailable, fall back to leak-on-detach (`None`).
        let reaper = reaper::register(thread_cap).ok();

        // `Interrupted` means this thread was stopped while the start waited
        // for the child to settle; nothing was started, so the start is
        // retried. Any other error leaves the child never started and is
        // fatal to the spawn.
        let started = loop {
            match syscall::thread_start(thread_cap) {
                Ok(()) => break true,
                Err(e) if e == SyscallError::Interrupted as i64 => {}
                Err(_) => break false,
            }
        };
        if !started {
            if let Some((slot, generation)) = reaper {
                reaper::release(slot, generation);
            }
            // Never started → safe to reclaim the Thread object immediately.
            let _ = syscall::cap_delete(thread_cap);
            // Thread destroyed → return the slab's run to memmgr's pool.
            crate::sys::alloc::seraph::slab_release_fresh(thread_slab_region_id);
            // SAFETY: `args` came from `Box::into_raw` above and no thread started
            // with it; the TLS block, IPC buffer, and stack are this spawn's own.
            unsafe {
                unwind_unstarted_spawn(args, tls_block, tls_layout, ipc_buf_base, ipc_buf_layout, stack)
            };
            return Err(io::Error::other("seraph: thread_start failed"));
        }

        Ok(Thread {
            res: ThreadResources {
                thread_cap,
                slab_region_id: thread_slab_region_id,
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
        // `Interrupted` (this thread was stopped and restarted, or interrupted
        // by an upcall) and a zero-bit return wait again: the child may still
        // be running. Any other error means the private done-notification cap
        // is gone and no wait can succeed; the child is then handed to the
        // reaper as if detached, so its kernel death notification reclaims it,
        // rather than reclaimed under a child that may still be in user mode.
        // Its done-notification index is first set to the permanently null slot
        // 0, so the later `reclaim` deletes nothing there rather than an
        // unrelated cap that has since taken the freed slot. Without a reaper
        // slot its resources are leaked until process death.
        let signalled = loop {
            match syscall::notification_wait(res.done_notification) {
                Ok(0) => {}
                Ok(_) => break true,
                Err(e) if e == SyscallError::Interrupted as i64 => {}
                Err(_) => break false,
            }
        };
        if signalled {
            // SAFETY: the child has left user-mode (it signalled
            // done_notification).
            unsafe { res.reclaim() };
            // Release this thread's reaper slot so its (eventual) death-post
            // is a no-op.
            if let Some((slot, generation)) = reaper {
                reaper::release(slot, generation);
            }
        } else {
            let mut res = res;
            res.done_notification = 0;
            match reaper {
                Some((slot, generation)) => {
                    if let Some(res) = reaper::detach(slot, generation, res) {
                        // SAFETY: the child already exited (its death-post was
                        // observed while still Reserved); reclaiming now is
                        // safe.
                        unsafe { res.reclaim() };
                    }
                }
                None => core::mem::forget(res),
            }
        }
        // Opportunistically reap any detached threads that have died.
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
        // observer (bound in `new`) posts to one of the process's death
        // queues when the child exits or faults, and `reaper::sweep` (run on
        // every spawn, join, and detach) reclaims the resources then. If the
        // child has already died, `detach` returns the resources to reclaim
        // now.
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
/// of the process's death `EventQueue`s, with a generation-tagged correlator
/// that names a registry slot (`death_queues::slots`, the
/// `ruststd-death-queues` crate). The registry grows a slot at a time and the
/// queues a queue at a time, each with twice the last one's nodes
/// (`death_queues::DeathQueues`), so the threads a process can have bound at
/// once are bounded by memory, not by a fixed table. A joined thread reclaims
/// its own resources directly and frees its slot, unless its join wait
/// failed, in which case it is handed to the registry like a detached one; a
/// detached thread leaves its resources in the slot. `sweep` drains every
/// queue on every spawn, join, and detach, and reclaims any thread left in a
/// slot whose death-post has landed. The generation tag makes a stale post
/// for an already-joined or reused slot a no-op.
mod reaper {
    use super::ThreadResources;
    use crate::sys::alloc::seraph::SpinMutex;
    use crate::vec::Vec;
    use death_queues::DeathQueues;
    use death_queues::slots::{Detached, Registry, correlator};
    use syscall_abi::{
        EVENT_QUEUE_MAX_CAPACITY, PAGE_SIZE, SyscallError, WAIT_SET_MAX_MEMBERS,
        event_queue_retype_bytes,
    };

    /// Observer nodes of the process's first death `EventQueue`: the most
    /// whose queue, with one entry more than its nodes ([`create_queue`]),
    /// still fits one 4 KiB retype class (`event_queue_retype_bytes`), since
    /// `object_slab_retype` grants that class for any queue past the
    /// sub-page classes, so a smaller first pool would cost the same two-page
    /// grant. Each further queue has twice the last one's nodes
    /// ([`DeathQueues`]), up to `EVENT_QUEUE_MAX_CAPACITY` less one
    /// ([`create_queue`]).
    const FIRST_POOL_OBSERVERS: u32 = {
        let mut n: u64 = 1;
        while event_queue_retype_bytes(n + 2, n + 1) <= PAGE_SIZE {
            n += 1;
        }
        // `n` is below the page size in nodes, so it fits a u32.
        #[allow(clippy::cast_possible_truncation)]
        let nodes = n as u32;
        nodes
    };
    // The loop above starts at one node without checking it; this pins that
    // the first queue fits the class.
    const _: () = assert!(
        event_queue_retype_bytes(FIRST_POOL_OBSERVERS as u64 + 1, FIRST_POOL_OBSERVERS as u64)
            <= PAGE_SIZE
    );

    // Lock order: `QUEUES` before `SLOTS`. A drain holds `QUEUES` and takes
    // `SLOTS` per post; nothing takes `QUEUES` while holding `SLOTS`. The
    // byte heap's and the object slabs' locks are taken inside either (a
    // `Vec` growth, a queue's slab), and the allocator takes neither.
    // Reclaims, which make memmgr calls, run after both are released, except
    // that a drain whose list cannot grow (the byte heap is exhausted)
    // reclaims that thread in place, under `QUEUES`. A queue is created under
    // `QUEUES`, with the bind that needs it, so two binds racing for a full
    // set cannot both create a queue; that happens only when the set grows,
    // each further queue twice the last.

    /// The reaper's slot registry.
    static SLOTS: SpinMutex<Registry<ThreadResources>> = SpinMutex::new(Registry::new());

    /// The process's death queues. No wait set holds them, so the set is
    /// created as wide as the kernel allows and `DeathQueues::grow` refuses
    /// a further queue past `WAIT_SET_MAX_MEMBERS - 1` queues without asking
    /// for a wider one.
    static QUEUES: SpinMutex<DeathQueues> =
        SpinMutex::new(DeathQueues::new(FIRST_POOL_OBSERVERS, WAIT_SET_MAX_MEMBERS));

    /// Why [`register`] gave no slot.
    #[derive(Debug)]
    pub(super) enum RegisterError {
        /// The registry could not reserve a slot (no memory for the table,
        /// or every index taken).
        Registry,
        /// No death queue took the observer bind.
        Bind,
    }

    /// Create one death queue of `observers` observer nodes, at most
    /// `EVENT_QUEUE_MAX_CAPACITY - 1`, and one entry more than its nodes: a
    /// queue's pending posts can reach its nodes plus one ([`register`]).
    fn create_queue(observers: u32) -> Result<u64, i64> {
        let nodes = observers.min(EVENT_QUEUE_MAX_CAPACITY - 1);
        let entries = nodes + 1;
        let bytes = event_queue_retype_bytes(u64::from(entries), u64::from(nodes));
        crate::sys::alloc::seraph::object_slab_retype(bytes, |slab| {
            syscall::event_queue_create_observed(slab, entries, nodes).ok()
        })
        .ok_or(SyscallError::OutOfMemory as i64)
    }

    /// Take every pending death post off `queues`, handing the resources of
    /// each detached thread whose post it is to `out`, or reclaiming them
    /// here when `out` cannot grow.
    fn drain(queues: &DeathQueues, out: &mut Vec<ThreadResources>) {
        for &queue in queues.queues() {
            // Empty (WouldBlock) or gone: nothing more on this queue.
            while let Ok(death) = syscall::event_try_recv_death(queue) {
                let Some(res) = SLOTS.with(|slots| slots.death(death.correlator)) else {
                    continue;
                };
                if out.try_reserve(1).is_ok() {
                    out.push(res);
                } else {
                    // SAFETY: the death-post fired, so the thread has left
                    // user-mode; its resources are safe to reclaim.
                    unsafe { res.reclaim() };
                }
            }
        }
    }

    /// Reclaim the resources [`drain`] collected.
    fn reclaim_all(out: Vec<ThreadResources>) {
        for res in out {
            // SAFETY: each came from a death post: the thread has left
            // user-mode, so its stack/IPC/TLS and Thread cap are safe to
            // reclaim.
            unsafe { res.reclaim() };
        }
    }

    /// Reserve a registry slot and bind a kernel death observer on `thread_cap`,
    /// on the newest death queue with a free node, a further queue created when
    /// every queue is out of nodes ([`DeathQueues::bind`]). Every queue is
    /// drained first, in the same hold: a node returns when its thread is
    /// destroyed, which may precede the drain of that thread's post, so a bind
    /// on a node freed that way could otherwise stack posts past the queue's
    /// entries. After a queue's drain, its new posts come from the threads
    /// that held its nodes then, at most its nodes, and from the one thread
    /// this hold binds on it, which may take a node returned since the drain;
    /// every later bind drains it again first. Its pending posts therefore
    /// never exceed its nodes plus one, its entries ([`create_queue`]).
    /// Returns the slot and generation. Call before `thread_start`.
    ///
    /// # Errors
    /// [`RegisterError::Registry`] when no slot can be reserved;
    /// [`RegisterError::Bind`] when no queue takes the bind. The caller then
    /// leaks the thread's resources on detach, the fallback without a reaper.
    pub(super) fn register(thread_cap: u64) -> Result<(u32, u32), RegisterError> {
        let (slot, generation) =
            SLOTS.with(Registry::reserve).map_err(|_| RegisterError::Registry)?;
        let tag = correlator(slot, generation);
        let mut drained = Vec::new();
        let bound = QUEUES.with(|queues| {
            drain(queues, &mut drained);
            queues.bind(
                |queue| syscall::thread_bind_notification(thread_cap, queue, tag),
                create_queue,
                // Not reached: the set is created `WAIT_SET_MAX_MEMBERS`
                // wide, and `grow` refuses past that without calling this.
                |_, _| Err(SyscallError::OutOfMemory as i64),
            )
        });
        reclaim_all(drained);
        if bound.is_err() {
            release(slot, generation);
            return Err(RegisterError::Bind);
        }
        Ok((slot, generation))
    }

    /// Release a slot on join (resources reclaimed directly by the caller). A
    /// later death-post for this slot is ignored.
    pub(super) fn release(slot: u32, generation: u32) {
        SLOTS.with(|slots| slots.release(slot, generation));
    }

    /// Hand a detached thread's resources to the registry, or a joined
    /// thread's whose join wait failed (that caller clears `done_notification`
    /// first). If the child already died (its death-post was observed while
    /// `Reserved`), returns the resources for the caller to reclaim
    /// immediately; otherwise stores them for `sweep` and returns `None`.
    pub(super) fn detach(
        slot: u32,
        generation: u32,
        res: ThreadResources,
    ) -> Option<ThreadResources> {
        match SLOTS.with(|slots| slots.detach(slot, generation, res)) {
            Detached::Reclaim(res) => Some(res),
            Detached::Held => None,
            Detached::Leak(res) => {
                // The slot was released or reused under us: no death signal
                // can be trusted for it, so leak rather than risk a UAF on a
                // possibly live thread.
                core::mem::forget(res);
                None
            }
        }
    }

    /// Drain every death queue (non-blocking) and reclaim, once the queues
    /// are released, any detached thread whose death-post has landed. Called
    /// on every spawn, join, and detach.
    pub(super) fn sweep() {
        let mut drained = Vec::new();
        QUEUES.with(|queues| drain(queues, &mut drained));
        reclaim_all(drained);
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

/// Set once procmgr refuses a registration `NOT_ATTACHABLE`: the process
/// declared itself undebuggable, which is one-way, so no later thread of it
/// sends one.
static REGISTRY_REFUSED: crate::sync::atomic::AtomicBool =
    crate::sync::atomic::AtomicBool::new(false);

/// Register the calling thread, a thread this module spawned, with procmgr
/// (`REGISTER_THREAD`, services/procmgr/docs/ipc-interface.md
/// § `REGISTER_THREAD`): hand it a copy of `self_thread_cap` with
/// `RIGHTS_THREAD`, so `ATTACH_PROCESS` lists the thread and procmgr can
/// bind its exception class under a badge of its own. Runs on the new
/// thread before its code, so the spawner never waits on procmgr; a thread
/// that procmgr cannot serve yet waits here alone. Best-effort: a refusal or
/// a failed call leaves the thread unregistered, and it runs as before. A
/// process procmgr did not create (no procmgr endpoint) sends nothing.
fn register_with_procmgr(self_thread_cap: u64, ipc_buf: *mut u64) {
    use crate::sync::atomic::Ordering;
    use ipc::{procmgr_errors, procmgr_labels};

    if REGISTRY_REFUSED.load(Ordering::Relaxed) {
        return;
    }
    let procmgr = crate::os::seraph::try_startup_info().map_or(0, |info| info.procmgr_endpoint);
    if procmgr == 0 {
        return;
    }
    let Ok(cap) = syscall::cap_derive(self_thread_cap, syscall_abi::RIGHTS_THREAD) else {
        return;
    };
    let msg = ipc::IpcMessage::builder(procmgr_labels::REGISTER_THREAD).cap(cap).build();
    // SAFETY: `ipc_buf` is this thread's IPC buffer page, registered by the
    // caller just before; the cap moves to procmgr with the message.
    match unsafe { ipc::ipc_call(procmgr, &msg, ipc_buf) } {
        Ok(reply) => {
            for &extra in reply.caps() {
                let _ = syscall::cap_delete(extra);
            }
            if reply.label == procmgr_errors::NOT_ATTACHABLE {
                REGISTRY_REFUSED.store(true, Ordering::Relaxed);
            }
        }
        // The copy may not have moved: delete it. A slot it moved out of
        // holds a later generation, so the stale handle deletes nothing.
        Err(_) => {
            let _ = syscall::cap_delete(cap);
        }
    }
}

extern "C" fn thread_entry(arg: u64) -> ! {
    // SAFETY: arg was produced via `Box::into_raw(Box::new(SpawnArgs {..}))`
    // in Thread::new; this is the sole consumer.
    let args = unsafe { Box::from_raw(arg as *mut SpawnArgs) };
    crate::os::seraph::set_current_thread_cap(args.self_thread_cap);
    // SAFETY: `ipc_buffer_vaddr` is the page-aligned page Thread::new heap-
    // allocated for this thread alone; no Rust object lives in it, and std
    // reaches it only through the raw `current_ipc_buf` pointer, holding no
    // reference across an IPC syscall.
    if unsafe { syscall::ipc_buffer_set(args.ipc_buffer_vaddr) }.is_ok() {
        // SAFETY: the page was registered for this thread just above; a
        // refused registration leaves the TLS pointer null.
        unsafe { crate::os::seraph::set_current_ipc_buf(args.ipc_buffer_vaddr as *mut u64) };
        register_with_procmgr(args.self_thread_cap, args.ipc_buffer_vaddr as *mut u64);
    }

    // SAFETY: args.init was produced via `Box::into_raw(init)` in
    // Thread::new; consumed exactly once here.
    let init_box = unsafe { Box::from_raw(args.init) };

    // `init` installs this thread's handle as its native-TLS `CURRENT`
    // (so `thread::current()` here is the `JoinHandle`'s thread) before
    // any heap (de)allocation, then frees the `ThreadInit` box and returns
    // the entry point.
    let rust_start = init_box.init();
    let done_notification = args.done_notification;
    drop(args);
    rust_start();

    // `guard::enable` is a no-op on this target, so this thread runs its
    // `thread_local!` destructors and releases its `CURRENT` handle itself,
    // as hermit's `thread_start` does. Both touch the TLS block, which
    // `join` frees once the done signal arrives, so they come first.
    // SAFETY: this is thread exit: the thread's Rust code has returned, so no
    // reference to its TLS variables is live.
    unsafe { crate::sys::thread_local::destructors::run() };
    crate::rt::thread_cleanup();

    // `thread_exit` diverges without unwinding, so every local is dropped
    // above; only the plain cap slot crosses into the tail.
    let _ = syscall::notification_send(done_notification, 1);
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
    // `thread_sleep` can end before `dur` elapses: a stop and restart of this
    // thread, or an upcall to it, returns `Interrupted`, and a park refused by
    // a coalesced wake returns `Ok` without sleeping. `sleep` cannot report
    // either and must never sleep less than `dur`, so every return, `Ok`
    // included, retries for whatever remains; any other error yields first
    // rather than spinning on the syscall. The loop returns only once `dur` has
    // elapsed since the first call.
    let start = crate::time::Instant::now();
    let mut left = dur;
    loop {
        // Round up to whole ms so a sub-ms sleep (or remainder) still sleeps.
        let ms = u64::try_from(left.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX);
        match syscall::thread_sleep(ms) {
            Ok(()) => {}
            Err(e) if e == SyscallError::Interrupted as i64 => {}
            Err(_) => yield_now(),
        }
        match dur.checked_sub(start.elapsed()) {
            Some(rest) if !rest.is_zero() => left = rest,
            _ => return,
        }
    }
}
