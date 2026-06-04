// seraph-overlay: std::sys::thread::seraph
//
// Thread spawning backed by the Seraph kernel's Thread/Notification primitives.
// Stacks and per-thread IPC buffers are allocated from the process heap
// (page-aligned, no guard pages for now — deferred polish). Join
// synchronises on a Notification cap; the child thread signals just before
// calling SYS_THREAD_EXIT.
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
///
/// `tls_base`, `tls_block`, and `tls_layout` are zero/null for threads
/// spawned in a process whose binary has no `PT_TLS` segment.
struct SpawnArgs {
    ipc_buffer_vaddr: u64,
    init: *mut ThreadInit,
    done_notification: u32,
}

pub struct Thread {
    thread_cap: u32,
    done_notification: u32,
    stack: StackAlloc,
    ipc_buf_base: *mut u8,
    ipc_buf_layout: Layout,
    tls_block: *mut u8,
    tls_layout: Option<Layout>,
}

// SAFETY: every field of Thread is either a plain integer (thread_cap,
// done_notification), an owned pointer to a distinct heap allocation, or an
// owned stack allocation — none shared with any other thread.
unsafe impl Send for Thread {}
// SAFETY: &Thread hands out only integer field copies through `join`; no
// interior mutability is exposed.
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

        let done_notification = match crate::sys::alloc::seraph::object_slab_acquire(120)
            .and_then(|slab| syscall::cap_create_notification(slab).ok())
        {
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
        let thread_slab =
            match crate::sys::alloc::seraph::object_slab_acquire(THREAD_RETYPE_BYTES) {
                Some(cap) => cap,
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

        // SP at the top of the usable stack region, 16-byte aligned for SysV
        // ABI; the stack grows down toward the guard page (demand) or heap base.
        let sp = stack.sp();
        let entry_addr = thread_entry as extern "C" fn(u64) -> ! as usize as u64;

        if let Err(_) =
            syscall::thread_configure_with_tls(thread_cap, entry_addr, sp, args as u64, tls_base)
        {
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

        if let Err(_) = syscall::thread_start(thread_cap) {
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
            thread_cap,
            done_notification,
            stack,
            ipc_buf_base,
            ipc_buf_layout,
            tls_block,
            tls_layout,
        })
    }

    pub fn join(self) {
        // Wait for the child to signal completion of its rust_start and
        // reach `notification_send`. After this point the child's next action is
        // `syscall::thread_exit` — its stack, IPC buffer, and TLS block
        // are safe to reclaim because control has left user-mode and will
        // never return. A spurious wake on another bit is fine — we just
        // observed the thread finishing.
        let _ = syscall::notification_wait(self.done_notification);
        let _ = syscall::cap_delete(self.done_notification);
        // SAFETY: child reached notification_send, so its remaining execution is
        // strictly inside the kernel (thread_exit); the allocations we own
        // are no longer read or written from user space.
        unsafe {
            if let Some(l) = self.tls_layout {
                dealloc(self.tls_block, l);
            }
            dealloc(self.ipc_buf_base, self.ipc_buf_layout);
        }
        // Reclaim the stack per its kind: a heap stack is freed; a demand stack
        // is UNREGISTER_REGION'd (memmgr unmaps and returns its frames to the
        // pool) and its VA released.
        // SAFETY: `self.stack` is a valid initialised field; `forget(self)`
        // below suppresses its destructor, so this read is not a double-free.
        let stack = unsafe { core::ptr::read(&self.stack) };
        free_stack(stack);
        // Prevent Drop from running the leak path below; we already
        // reclaimed everything.
        core::mem::forget(self);
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // Dropping a `Thread` without `join()` means the caller detached
        // the child and no longer has a synchronisation point to know
        // when the child has left user-mode. Freeing the stack, IPC
        // buffer, or TLS block now would be a use-after-free from the
        // child's perspective — the memory would re-enter the heap's
        // free list, get split via `Heap::insert`, and the FreeNode
        // metadata (size at [0..8], next ptr at [8..16]) would clobber
        // whatever TLS variable happens to sit at those offsets
        // (`DTORS.borrow` in std::sys::thread_local::destructors::list),
        // breaking all subsequent `RefCell::try_borrow_mut` calls on that
        // thread. The only correct choice for a detached child on seraph
        // is to leak everything this handle owns.
        //
        // `thread_cap` was already leaked by design; the stack, IPC buffer,
        // and TLS block join it here until Seraph has a thread-detach syscall
        // that reclaims memory on thread_exit. The `stack` field drops as a
        // no-op (its variants own no `Drop` resources), so a demand stack's VA
        // reservation and registered region also leak — the same detach
        // semantics as the heap path.
        let _ = self.thread_cap;
        let _ = self.done_notification;
        let _ = &self.stack;
        let _ = self.ipc_buf_base;
        let _ = self.tls_block;
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
