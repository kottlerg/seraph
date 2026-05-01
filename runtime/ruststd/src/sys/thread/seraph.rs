// seraph-overlay: std::sys::thread::seraph
//
// Thread spawning backed by the Seraph kernel's Thread/Signal primitives.
// Stacks and per-thread IPC buffers are allocated from the process heap
// (page-aligned, no guard pages for now — deferred polish). Join
// synchronises on a Signal cap; the child thread signals just before
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

use syscall_abi::PAGE_SIZE;

/// Default minimum stack size. Matches the upstream unsupported-PAL value.
pub const DEFAULT_MIN_STACK_SIZE: usize = 64 * 1024;

const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;

/// Per-thread context the entry trampoline pulls off the `arg` slot of
/// `thread_configure`. Owned by the spawning thread until the child takes
/// it over on entry (the child drops it after extracting the pieces).
///
/// `tls_base`, `tls_block`, and `tls_layout` are zero/null for threads
/// spawned in a process whose binary has no `PT_TLS` segment.
struct SpawnArgs {
    ipc_buffer_vaddr: u64,
    init: *mut ThreadInit,
    done_signal: u32,
}

pub struct Thread {
    thread_cap: u32,
    done_signal: u32,
    stack_base: *mut u8,
    stack_layout: Layout,
    ipc_buf_base: *mut u8,
    ipc_buf_layout: Layout,
    tls_block: *mut u8,
    tls_layout: Option<Layout>,
}

// SAFETY: every field of Thread is either a plain integer (thread_cap,
// done_signal) or an owned pointer to a distinct heap allocation whose
// ownership is not shared with any other thread.
unsafe impl Send for Thread {}
// SAFETY: &Thread hands out only integer field copies through `join`; no
// interior mutability is exposed.
unsafe impl Sync for Thread {}

impl Thread {
    /// # Safety
    /// See `std::thread::Builder::spawn_unchecked` for the caller-side
    /// safety contract.
    pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
        let info = crate::os::seraph::try_startup_info().ok_or_else(|| {
            io::Error::other("std::os::seraph::_start has not initialised startup state")
        })?;

        let stack_size = crate::cmp::max(stack, DEFAULT_MIN_STACK_SIZE);
        let stack_size = (stack_size + PAGE_SIZE_USIZE - 1) & !(PAGE_SIZE_USIZE - 1);
        let stack_layout = Layout::from_size_align(stack_size, PAGE_SIZE_USIZE)
            .map_err(|_| io::Error::other("seraph: stack layout too large"))?;
        // SAFETY: `stack_layout` has a non-zero size and power-of-two alignment.
        let stack_base = unsafe { alloc(stack_layout) };
        if stack_base.is_null() {
            return Err(io::Error::other("seraph: stack allocation failed"));
        }

        let ipc_buf_layout = match Layout::from_size_align(PAGE_SIZE_USIZE, PAGE_SIZE_USIZE) {
            Ok(l) => l,
            Err(_) => {
                // SAFETY: stack_base came from `alloc(stack_layout)` above.
                unsafe { dealloc(stack_base, stack_layout) };
                return Err(io::Error::other("seraph: ipc buffer layout invalid"));
            }
        };
        // SAFETY: `ipc_buf_layout` has a non-zero size and power-of-two alignment.
        let ipc_buf_base = unsafe { alloc(ipc_buf_layout) };
        if ipc_buf_base.is_null() {
            // SAFETY: stack_base came from `alloc(stack_layout)` above.
            unsafe { dealloc(stack_base, stack_layout) };
            return Err(io::Error::other("seraph: ipc buffer allocation failed"));
        }

        // Allocate + populate the TLS block. Processes without a PT_TLS
        // segment have `tls_template_memsz == 0` and skip allocation —
        // `thread_configure_with_tls` is then called with tls_base=0.
        let (tls_block, tls_layout, tls_base) = match alloc_thread_tls(info) {
            Ok(triple) => triple,
            Err(e) => {
                // SAFETY: both pointers came from matching `alloc` calls above.
                unsafe {
                    dealloc(ipc_buf_base, ipc_buf_layout);
                    dealloc(stack_base, stack_layout);
                }
                return Err(e);
            }
        };

        let done_signal = match crate::sys::alloc::seraph::object_slab_acquire(120)
            .and_then(|slab| syscall::cap_create_signal(slab).ok())
        {
            Some(cap) => cap,
            None => {
                // SAFETY: allocations owned by this function.
                unsafe {
                    if let Some(l) = tls_layout {
                        dealloc(tls_block, l);
                    }
                    dealloc(ipc_buf_base, ipc_buf_layout);
                    dealloc(stack_base, stack_layout);
                }
                return Err(io::Error::other("seraph: signal cap alloc failed"));
            }
        };

        let args = Box::into_raw(Box::new(SpawnArgs {
            ipc_buffer_vaddr: ipc_buf_base as u64,
            init: Box::into_raw(init),
            done_signal,
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
                    // SAFETY: allocations owned by this function.
                    unsafe {
                        if let Some(l) = tls_layout {
                            dealloc(tls_block, l);
                        }
                        dealloc(ipc_buf_base, ipc_buf_layout);
                        dealloc(stack_base, stack_layout);
                    }
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
                    // SAFETY: allocations owned by this function.
                    unsafe {
                        if let Some(l) = tls_layout {
                            dealloc(tls_block, l);
                        }
                        dealloc(ipc_buf_base, ipc_buf_layout);
                        dealloc(stack_base, stack_layout);
                    }
                    return Err(io::Error::other("seraph: thread cap alloc failed"));
                }
            };

        // Stack grows down. Point SP at the top, 16-byte aligned for SysV ABI.
        let stack_top = (stack_base as usize).saturating_add(stack_size);
        let sp = (stack_top & !15) as u64;
        let entry_addr = thread_entry as extern "C" fn(u64) -> ! as usize as u64;

        if let Err(_) =
            syscall::thread_configure_with_tls(thread_cap, entry_addr, sp, args as u64, tls_base)
        {
            // SAFETY: `args` was just leaked via `Box::into_raw`.
            let args_owned = unsafe { Box::from_raw(args) };
            // SAFETY: `args_owned.init` was just leaked via `Box::into_raw`.
            let _init = unsafe { Box::from_raw(args_owned.init) };
            // SAFETY: allocations owned by this function.
            unsafe {
                if let Some(l) = tls_layout {
                    dealloc(tls_block, l);
                }
                dealloc(ipc_buf_base, ipc_buf_layout);
                dealloc(stack_base, stack_layout);
            }
            return Err(io::Error::other("seraph: thread_configure failed"));
        }

        if let Err(_) = syscall::thread_start(thread_cap) {
            // SAFETY: `args` was just leaked via `Box::into_raw`.
            let args_owned = unsafe { Box::from_raw(args) };
            // SAFETY: `args_owned.init` was just leaked via `Box::into_raw`.
            let _init = unsafe { Box::from_raw(args_owned.init) };
            // SAFETY: allocations owned by this function.
            unsafe {
                if let Some(l) = tls_layout {
                    dealloc(tls_block, l);
                }
                dealloc(ipc_buf_base, ipc_buf_layout);
                dealloc(stack_base, stack_layout);
            }
            return Err(io::Error::other("seraph: thread_start failed"));
        }

        Ok(Thread {
            thread_cap,
            done_signal,
            stack_base,
            stack_layout,
            ipc_buf_base,
            ipc_buf_layout,
            tls_block,
            tls_layout,
        })
    }

    pub fn join(self) {
        // Wait for the child to signal completion of its rust_start and
        // reach `signal_send`. After this point the child's next action is
        // `syscall::thread_exit` — its stack, IPC buffer, and TLS block
        // are safe to reclaim because control has left user-mode and will
        // never return. A spurious wake on another bit is fine — we just
        // observed the thread finishing.
        let _ = syscall::signal_wait(self.done_signal);
        let _ = syscall::cap_delete(self.done_signal);
        // SAFETY: child reached signal_send, so its remaining execution is
        // strictly inside the kernel (thread_exit); the allocations we own
        // are no longer read or written from user space.
        unsafe {
            if let Some(l) = self.tls_layout {
                dealloc(self.tls_block, l);
            }
            dealloc(self.ipc_buf_base, self.ipc_buf_layout);
            dealloc(self.stack_base, self.stack_layout);
        }
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
        // `thread_cap` was already leaked by design; the other three
        // allocations join it here until Seraph has a thread-detach
        // syscall that reclaims memory on thread_exit.
        let _ = self.thread_cap;
        let _ = self.done_signal;
        let _ = self.stack_base;
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

    let _ = syscall::signal_send(args.done_signal, 1);
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
