// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/os/seraph.rs

//! Seraph-specific public surface. Lives under `std::os::seraph` so service
//! code written against std can reach the platform primitives:
//!
//!   * `_start` — the ELF entry symbol exported for std-built binaries; reads
//!     `ProcessInfo` at the VA delivered in the entry register, registers the
//!     IPC buffer, wires stdio caps, bootstraps the heap, then jumps to the
//!     rustc-synthesised `extern "C" fn main` which calls `std::rt::lang_start`
//!     and in turn the user's idiomatic `fn main`. When `main` returns, exits
//!     the process via `process_exit`, forwarding its code.
//!   * `startup_info()` / `try_startup_info()` — accessors for the
//!     `StartupInfo` stashed by `_start`. Services use these to obtain their
//!     initial caps.
//!   * `heap_bootstrap` / `heap_is_initialized` — allocator bring-up against
//!     memmgr.
//!   * `abort_thread` — placeholder thread terminator.

// std requires every public item to carry a stability attribute. Everything
// in `std::os::seraph` is specific to this target and not promoted through
// libs-api, so tag the module with an internal-only `stable` gate — the
// feature name is a placeholder and has no std-wide meaning.
#![stable(feature = "seraph_ext", since = "1.0.0")]

use crate::cell::{Cell, UnsafeCell};
use crate::mem::MaybeUninit;
use crate::path::PathBuf;
use crate::sync::Mutex;
use crate::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::sys::alloc::seraph as pal_alloc;
use crate::sys::reserve as pal_reserve;
use crate::sys::stdio::seraph as pal_stdio;

use process_abi::{PROCESS_ABI_VERSION, process_info_ref};

/// The `.note.seraph.stack` ELF note a binary's [`stack_pages!`] emits, in
/// the on-disk layout of `process_abi::StackNote`: the note header
/// (`namesz` 7, `descsz` 8, `ntype` `NT_SERAPH_STACK`), the vendor name
/// `b"seraph\0\0"`, and the descriptor (the page count, then a reserved zero
/// word). The loaders read it before mapping the main-thread stack.
///
/// A std-local type rather than a re-export of `process_abi::StackNote`, for
/// the reason the retype-constant block below gives: an item reached through
/// the sysroot-private ABI crate is unstable (`rustc_private`) to std's
/// users. svctest's `stack_note_refused` phase guards this copy's layout
/// (`abi/process-abi/README.md` § Stack-size note).
#[stable(feature = "seraph_ext", since = "1.0.0")]
#[repr(C)]
pub struct StackNote {
    namesz: u32,
    descsz: u32,
    ntype: u32,
    name: [u8; 8],
    pages: u32,
    reserved: u32,
}

impl StackNote {
    /// Build a stack-size note declaring `pages` 4 KiB pages.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    #[rustc_const_stable(feature = "seraph_ext", since = "1.0.0")]
    #[must_use]
    pub const fn new(pages: u32) -> Self {
        Self {
            namesz: 7,
            descsz: 8,
            ntype: process_abi::NT_SERAPH_STACK,
            name: process_abi::SERAPH_NOTE_NAME,
            pages,
            reserved: 0,
        }
    }
}

/// Startup information the kernel+procmgr hand to a process at spawn time,
/// materialised by `_start` from the read-only `ProcessInfo` page and made
/// available through [`startup_info`]. A std-local copy of the shape defined in
/// `process-abi`: users reach it through `std::os::seraph` instead of a
/// direct path dep on the ABI crate, so field access does not cross the
/// sysroot-private-dep boundary that `process-abi` sits behind.
#[stable(feature = "seraph_ext", since = "1.0.0")]
#[derive(Debug, Clone, Copy)]
pub struct StartupInfo {
    /// Virtual address of the main thread's pre-mapped IPC buffer page.
    /// Every other thread registers its own; IPC from any thread goes
    /// through [`current_ipc_buf`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub ipc_buffer: *mut u8,
    /// Cap slot of the SEND endpoint back to the creator, or 0 when absent.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub creator_endpoint: u64,
    /// Cap slot of the caller's own Thread object.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub self_thread: u64,
    /// Cap slot of the caller's own AddressSpace object.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub self_aspace: u64,
    /// Cap slot of the caller's own CSpace object.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub self_cspace: u64,
    /// Cap slot of a baseline `SchedControl` cap, or zero. Pass it as the
    /// `sched_cap` argument to [`crate::os::seraph::syscall`]-level
    /// `thread_set_priority` / `cap_create_thread` to set or assign a
    /// thread's priority within the cap's band (`[1, band_max]`, chosen by
    /// the spawner — see `CommandExt::sched_max`). Zero means no
    /// scheduling authority was delegated.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub sched_control_cap: u64,
    /// Priority level the spawner placed this process's initial thread at.
    /// Always within the band of [`Self::sched_control_cap`] when that cap
    /// is present; `std::thread::spawn` creates further threads at this
    /// level. Zero only for pre-policy bootstrap processes.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub initial_priority: u8,
    /// Cap slot of a badged SEND cap on procmgr. Zero if procmgr is not
    /// reachable (the process is procmgr itself, or runs before procmgr
    /// exists). Used for process-lifecycle queries.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub procmgr_endpoint: u64,
    /// Cap slot of a badged SEND cap on memmgr. Zero if memmgr is not
    /// reachable (memmgr itself, init, or anything earlier in the boot
    /// chain). `_start` consumes this to bootstrap the heap.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub memmgr_endpoint: u64,
    /// Cap slot of a SEND cap on svcmgr's service endpoint, the
    /// system-wide service-discovery handle. Carries only the per-process
    /// badge (no `PUBLISH_AUTHORITY` verb-bit) so it can answer
    /// `svcmgr_labels::QUERY_ENDPOINT` but not `PUBLISH_ENDPOINT`.
    /// `_start` consumes this to install the cap into the
    /// `registry-client` cache, so later `registry_client::lookup(name)`
    /// calls resolve names to service caps. Zero if svcmgr is not
    /// reachable.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub service_registry_cap: u64,
    /// Shmem memory cap backing `std::io::stdin`. Zero when no input
    /// pipe is attached; reads return `Ok(0)` (EOF).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdin_memory_cap: u64,
    /// Shmem memory cap backing `std::io::stdout`. Zero when no sink is
    /// attached; writes silently drop.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdout_memory_cap: u64,
    /// Shmem memory cap backing `std::io::stderr`. Zero when no sink is
    /// attached; writes silently drop.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stderr_memory_cap: u64,
    /// Badged SEND cap on vfsd's namespace endpoint at the synthetic
    /// system root. Installed by the spawner via
    /// `procmgr_labels::CONFIGURE_NAMESPACE` between create and start.
    /// Zero when no spawner-supplied cap was delivered (or vfsd is not
    /// reachable). Reachable application-side via [`root_dir_cap`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub system_root_cap: u64,
    /// Badged SEND cap on a namespace endpoint addressing the initial
    /// current working directory. Anchors relative-path resolution.
    /// Zero means relative paths are unsupported until the process
    /// installs one (e.g. via `std::env::set_current_dir`).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub current_dir_cap: u64,
    /// Wakeup notification caps for the stdio pipes. See `process_abi::ProcessInfo`
    /// for full data-vs-space and writer-vs-reader semantics. Zero when
    /// the corresponding direction is not piped.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdin_data_notification_cap: u64,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdin_space_notification_cap: u64,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdout_data_notification_cap: u64,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdout_space_notification_cap: u64,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stderr_data_notification_cap: u64,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stderr_space_notification_cap: u64,
    /// Badged SEND cap on the system log endpoint, pre-installed by
    /// procmgr at spawn time. Used by [`log!`] directly — no
    /// discovery roundtrip. Zero when no logger is reachable
    /// (init/memmgr/procmgr themselves, or anything earlier in the
    /// boot chain than the log endpoint); the macro silently drops.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub log_send_cap: u64,
    /// Virtual address of the `PT_TLS` template in the loaded image, or 0
    /// when the binary has no TLS segment.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub tls_template_vaddr: u64,
    /// Size of the initialised portion of the TLS template (`.tdata`).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub tls_template_filesz: u64,
    /// Total size of the TLS template (`.tdata` + `.tbss`). Zero means
    /// no TLS.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub tls_template_memsz: u64,
    /// Required alignment of per-thread TLS blocks.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub tls_template_align: u64,
    /// Raw argv blob the spawner delivered, in the read-only argv/env
    /// region after the `ProcessInfo` page. Concatenation of `args_count` NUL-terminated UTF-8
    /// strings; total byte length `args_blob.len()`. Empty slice when no
    /// argv was provided. Application code should not read this
    /// directly — use `std::env::args()`.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub args_blob: &'static [u8],
    /// Number of NUL-terminated entries in [`Self::args_blob`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub args_count: usize,
    /// Raw env blob the spawner delivered, in the read-only argv/env
    /// region after the `ProcessInfo` page. Concatenation of `env_count` NUL-terminated UTF-8 strings
    /// of shape `KEY=VALUE`. Empty slice when no env was provided.
    /// Application code should not read this directly — use
    /// `std::env::{var, vars}`.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub env_blob: &'static [u8],
    /// Number of NUL-terminated `KEY=VALUE` entries in [`Self::env_blob`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub env_count: usize,
    /// Virtual address of the top of the main-thread stack — the value
    /// SP held at `_start`. The loader maps the stack's committed part,
    /// `[stack_top_vaddr - stack_pages * PAGE_SIZE, stack_top_vaddr)`. In a
    /// demand-paged process whose image is `ET_DYN`, `_start` may register
    /// a demand-growth range below it, under the conditions
    /// docs/userspace-memory-model.md § Bootstrap Cross-Boundary VAs states.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stack_top_vaddr: u64,
    /// Number of 4 KiB pages the loader mapped for the main-thread stack, its
    /// committed part.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stack_pages: u32,
    /// `Endpoint` cap on the process's demand-paging pager, or zero when
    /// the process is not demand-paged. procmgr binds it as the main thread's
    /// fault handler at creation, and the runtime copies the spawning thread's
    /// bindings onto every thread it spawns
    /// (`SYS_THREAD_INHERIT_FAULT_HANDLER`), which carries it on; the runtime
    /// reads this field to tell that the process is demand-paged. See
    /// `process_abi::ProcessInfo::pager_endpoint_cap`.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub pager_endpoint_cap: u64,
    /// The derivation badge of [`Self::pager_endpoint_cap`], which the kernel
    /// stamps on this process's fault messages. Zero when not demand-paged.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub pager_badge: u64,
    /// Mapped base virtual address of the main thread's TLS block, or zero when
    /// the process has no TLS. See `process_abi::ProcessInfo::main_tls_vaddr`.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub main_tls_vaddr: u64,
}

// SAFETY: `ipc_buffer` points at a process-global page mapped for the life of
// the process; sharing the pointer is as safe as the static it refers to.
#[stable(feature = "seraph_ext", since = "1.0.0")]
unsafe impl Send for StartupInfo {}
#[stable(feature = "seraph_ext", since = "1.0.0")]
unsafe impl Sync for StartupInfo {}

// ── Per-thread IPC buffer pointer ──────────────────────────────────────────
//
// Each thread registers its own 4 KiB IPC buffer page with the kernel via
// `SYS_IPC_BUFFER_SET`. The kernel writes IPC payload into this page on
// `ipc_recv` / `ipc_call` and reads from it on send; userspace IPC wrappers
// (`ipc::ipc_call`/`ipc_recv`/`ipc_reply`) need the same VA to stage/consume
// payloads. The VA is known only to the code that registered it — `_start`
// for the main thread, the thread trampoline for spawned threads — so we
// stash it in a thread-local slot here and expose it via
// [`current_ipc_buf`].
//
// Every in-tree IPC-issuing subsystem (stdio, heap `grow`, future
// services) reads the buffer pointer from this TLS slot at the call
// site. Caching a buffer VA on behalf of another thread silently
// targets the wrong page from spawned threads, because the kernel
// services IPC from the caller thread's `tcb.ipc_buffer` — not the
// pointer user code passes in.

#[thread_local]
static IPC_BUF_TLS: Cell<*mut u64> = Cell::new(core::ptr::null_mut());

/// Record the current thread's IPC buffer VA. Called by `_start` and by the
/// thread trampoline immediately after `syscall::ipc_buffer_set`.
///
/// # Safety
/// `buf` must be null or the calling thread's IPC buffer page as registered
/// via `syscall::ipc_buffer_set`: std's IPC paths (`log!`, the stdio and
/// panic writers, registry lookups) pass [`current_ipc_buf`] to
/// `ipc::ipc_call`, whose contract requires exactly that.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub unsafe fn set_current_ipc_buf(buf: *mut u64) {
    IPC_BUF_TLS.set(buf);
}

/// Return the current thread's registered IPC buffer VA, or null if the
/// current thread has not registered one. Safe accessor for code that issues
/// IPC from non-main threads (bootstrap workers, user-spawned threads).
///
/// Returns null if called before `_start` has completed on the main thread,
/// or before the thread trampoline has registered a buffer on a spawned
/// thread.
#[must_use]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn current_ipc_buf() -> *mut u64 {
    IPC_BUF_TLS.get()
}

#[thread_local]
static SELF_THREAD_TLS: Cell<u64> = Cell::new(0);

/// Record the current thread's own Thread capability. Called by the thread
/// trampoline of a spawned thread with the cap its spawner created.
pub(crate) fn set_current_thread_cap(cap: u64) {
    SELF_THREAD_TLS.set(cap);
}

/// The current thread's own Thread capability: the one recorded by
/// [`set_current_thread_cap`] for a spawned thread, else the process's
/// initial thread ([`StartupInfo::self_thread`]), or 0 before `_start` has
/// read the startup info.
pub(crate) fn current_thread_cap() -> u64 {
    let cap = SELF_THREAD_TLS.get();
    if cap != 0 { cap } else { try_startup_info().map_or(0, |info| info.self_thread) }
}

/// Register a process-global panic-output sink. When set, std's panic
/// machinery routes panic bytes to `sink` instead of the system log
/// endpoint — covering the default hook AND the non-unwinding
/// `handle_alloc_error` / precondition paths, which share one
/// `panic_output()` chokepoint.
///
/// A process that serves the log endpoint (logd) registers a sink that
/// writes to the serial driver, so its own faults never self-IPC into the
/// endpoint it serves. Processes that leave it unset keep the default
/// log-endpoint path. `sink` must be non-allocating and must not itself
/// panic.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn set_panic_sink(sink: fn(&[u8])) {
    pal_stdio::set_panic_sink(sink);
}

// ── Address-space size ──────────────────────────────────────────────────────

/// Exclusive top of this process's user half, read once by `_start` through
/// `SystemInfoType::UserVaTop` before any heap or reservation zone is placed.
/// Zero before `_start` reads it, or when the kernel did not answer.
static USER_VA_TOP: AtomicU64 = AtomicU64::new(0);

/// Exclusive top of this process's user half: the first virtual address the
/// kernel refuses to map (`SystemInfoType::UserVaTop`), fixed per architecture
/// and boot paging mode. `_start` reads it once; zero before that, or when the
/// kernel did not answer.
#[must_use]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn user_va_top() -> u64 {
    USER_VA_TOP.load(Ordering::Acquire)
}

/// The heap, reservation-arena, and image zones sized to this process's
/// address space ([`user_va_top`]); the zones valid under every paging mode
/// while the size is unknown.
pub(crate) fn growth_zones() -> process_layout::AddressSpaceZones {
    process_layout::growth_zones(user_va_top())
}

// ── Startup storage ─────────────────────────────────────────────────────────

struct StartupCell(UnsafeCell<MaybeUninit<StartupInfo>>);

// SAFETY: the cell is written exactly once by `_start`, which runs before any
// other Rust code in the process; subsequent accesses are reads guarded by
// `STARTUP_READY`.
unsafe impl Sync for StartupCell {}

static STARTUP: StartupCell = StartupCell(UnsafeCell::new(MaybeUninit::uninit()));
static STARTUP_READY: AtomicBool = AtomicBool::new(false);

/// Returns a reference to the captured [`StartupInfo`] for this process.
/// `_start` installs the bundle once before user `main` runs; this accessor
/// reads it.
///
/// Panics if called before `_start` has installed the startup data. Safe to
/// call from anywhere in user `main` and thereafter.
#[must_use]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn startup_info() -> &'static StartupInfo {
    try_startup_info()
        .expect("std::os::seraph::startup_info() called before _start initialised it")
}

/// Returns the captured [`StartupInfo`] if it has been installed, or `None`
/// otherwise. Useful from early panic paths that must not themselves panic.
#[must_use]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn try_startup_info() -> Option<&'static StartupInfo> {
    if STARTUP_READY.load(Ordering::Acquire) {
        // SAFETY: `STARTUP_READY` is only set by `_start` after writing the
        // cell, with Release ordering matched by our Acquire load above.
        Some(unsafe { (*STARTUP.0.get()).assume_init_ref() })
    } else {
        None
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

/// Voluntary exit code reported when `_start` aborts before user `main` runs
/// because the `ProcessInfo` ABI version is unrecognised. In the voluntary
/// range (`< EXIT_FAULT_BASE`) and distinct from plausible application codes, so
/// a supervisor sees a defined startup failure rather than a false success-`0`.
const STARTUP_FAIL_BAD_ABI: u32 = 0x0F01;

/// Voluntary exit code reported when `_start` aborts because the heap bootstrap
/// failed (typically memmgr frame-pool exhaustion). See [`STARTUP_FAIL_BAD_ABI`].
const STARTUP_FAIL_HEAP: u32 = 0x0F02;

/// Process entry point. Exported with the conventional ELF entry symbol name
/// so the linker sets `e_entry` here and procmgr jumps directly in.
///
/// `info_ptr` is the virtual address of the read-only `ProcessInfo` page,
/// delivered by procmgr in the entry register (`rdi`/`a0`). Reads the page,
/// registers the pre-mapped IPC buffer, stashes the derived [`StartupInfo`] in
/// process-global storage, then hands off to the rustc-synthesised
/// `extern "C" fn main` which in turn drives `std::rt::lang_start` and the
/// user's `fn main`. When `main` returns, this function exits the process via
/// `process_exit`, forwarding `main`'s `i32` return (the `ExitCode`/`lang_start`
/// value) so the parent's `ExitStatus` carries it; the process never re-enters
/// kernel entry code.
///
/// # Safety
///
/// Called by the kernel with `info_ptr` pointing at a valid `ProcessInfo` page
/// and a pre-mapped IPC buffer at the VA it records. The function itself is safe
/// to export.
#[unsafe(no_mangle)]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub extern "C" fn _start(info_ptr: u64) -> ! {
    // SAFETY: procmgr maps a valid `ProcessInfo` page and delivers its VA in
    // `info_ptr` before starting the first thread; the page remains mapped for
    // the process's lifetime.
    let info = unsafe { process_info_ref(info_ptr) };

    if info.version != PROCESS_ABI_VERSION {
        syscall::process_exit(STARTUP_FAIL_BAD_ABI);
    }

    // Learn the address space's size before stdio, the heap, or anything else
    // places a heap or reservation zone (`growth_zones`). A kernel that
    // does not answer leaves zero, which selects the zones valid in every
    // paging mode.
    USER_VA_TOP.store(syscall::user_va_top().unwrap_or(0), Ordering::Release);

    // Register the IPC buffer before any IPC-using code runs. Idempotent in
    // the kernel, so services that call `ipc_buffer_set` again are fine.
    // SAFETY: the creator maps `ipc_buffer_vaddr` as the main thread's own IPC
    // page, outside every image, stack, heap and TLS mapping
    // (docs/userspace-memory-model.md); std reaches it only through the raw
    // `current_ipc_buf` pointer, holding no reference across an IPC syscall.
    if unsafe { syscall::ipc_buffer_set(info.ipc_buffer_vaddr) }.is_ok() {
        // SAFETY: the page was registered for this thread just above; a
        // refused registration leaves the TLS pointer null.
        unsafe { set_current_ipc_buf(info.ipc_buffer_vaddr as *mut u64) };
    }

    // Build the argv and env slices from the argv/env region procmgr mapped
    // after the ProcessInfo page. Each offset is a byte offset from the page
    // base; `blob_span` confines the slice to the region's largest extent.
    // Any inconsistency (bogus ABI version, a span outside the region) falls
    // through to an empty slice rather than an out-of-bounds read.
    let region_end = process_abi::ARGV_ENV_REGION_OFFSET + process_abi::ARGV_ENV_MAX_BYTES;
    let blob = |offset: u64, bytes: u64, count: u64| -> &'static [u8] {
        match argv_env::blob_span(
            offset,
            bytes,
            count,
            process_abi::ARGV_ENV_REGION_OFFSET,
            region_end,
        ) {
            Some((offset, len)) => {
                // SAFETY: the creator maps the region's pages read-only for
                // the process's lifetime, covering every byte of each blob
                // it records, and `blob_span` keeps the slice inside the
                // region, clear of every other surface the layout places.
                // Bytes are plain data.
                unsafe { core::slice::from_raw_parts((info_ptr as usize + offset) as *const u8, len) }
            }
            None => &[],
        }
    };
    let args_blob = blob(info.args_offset, info.args_bytes, info.args_count);
    let env_blob = blob(info.env_offset, info.env_bytes, info.env_count);

    let startup = StartupInfo {
        ipc_buffer: info.ipc_buffer_vaddr as *mut u8,
        creator_endpoint: info.creator_endpoint_cap,
        self_thread: info.self_thread_cap,
        self_aspace: info.self_aspace_cap,
        self_cspace: info.self_cspace_cap,
        sched_control_cap: info.sched_control_cap,
        initial_priority: info.initial_priority,
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
        log_send_cap: info.log_send_cap,
        tls_template_vaddr: info.tls_template_vaddr,
        tls_template_filesz: info.tls_template_filesz,
        tls_template_memsz: info.tls_template_memsz,
        tls_template_align: info.tls_template_align,
        args_blob,
        args_count: info.args_count as usize,
        env_blob,
        env_count: info.env_count as usize,
        stack_top_vaddr: info.stack_top_vaddr,
        stack_pages: info.stack_pages,
        pager_endpoint_cap: info.pager_endpoint_cap,
        pager_badge: info.pager_badge,
        main_tls_vaddr: info.main_tls_vaddr,
    };

    // SAFETY: single writer; we are the only code running at this point.
    unsafe { (*STARTUP.0.get()).write(startup) };
    STARTUP_READY.store(true, Ordering::Release);

    // Wire the three stdio pipes before the heap bootstrap. Each
    // direction takes (memory_cap, data_notification_cap, space_notification_cap);
    // zero memory caps are tolerated (writes silently drop / reads
    // return EOF), matching the "no pipe attached" state for processes
    // born without `Stdio::piped()`.
    pal_stdio::stdio_init(
        info.stdin_memory_cap,
        info.stdin_data_notification_cap,
        info.stdin_space_notification_cap,
        info.stdout_memory_cap,
        info.stdout_data_notification_cap,
        info.stdout_space_notification_cap,
        info.stderr_memory_cap,
        info.stderr_data_notification_cap,
        info.stderr_space_notification_cap,
        info.self_aspace_cap,
    );

    // Install the pre-seeded badged log SEND cap procmgr placed in
    // ProcessInfo. `seraph::log!` uses it directly with no discovery
    // roundtrip. Zero is tolerated (the macro silently drops in
    // processes without a logger).
    ::log::install_badged_cap(info.log_send_cap);

    // Install the per-process svcmgr SEND cap into the registry-client
    // cache. Zero is tolerated (processes spawned before svcmgr exists,
    // or whose parent did not derive the cap, see lookups return
    // `None`).
    ::registry_client::install_registry_cap(info.service_registry_cap);

    // Stash the system-root namespace cap so `std::fs` (or any other
    // namespace-walking surface) can reach it. Zero passes through
    // unchanged — `root_dir_cap()` returning 0 means "no system root
    // attached", and the reading side degrades.
    set_root_dir_cap(info.system_root_cap);
    // Same for the cwd cap. Zero means "no cwd attached"; relative
    // paths through `std::fs` return `Unsupported` until set.
    set_current_dir_cap(info.current_dir_cap);

    // Bootstrap the heap so `fn main()` can allocate from its first line
    // (lazy `LineWriter` behind `std::io::stdout`, `String::new`, any `Vec`
    // push, etc.). Zero `memmgr_endpoint_cap` means we are memmgr itself,
    // init, or something earlier in the chain; such processes manage their
    // own storage and do not use std collections.
    //
    // Hard-fail with a visible diagnostic when bootstrap attempts to run
    // but memmgr refuses (frame-pool exhaustion is the common cause). An
    // uninitialised heap surfaces later as a cryptic `handle_alloc_error`
    // deep inside `lang_start`; exiting here puts the failure in context.
    if info.memmgr_endpoint_cap != 0 {
        let ok = pal_alloc::heap_bootstrap(
            info.memmgr_endpoint_cap,
            info.self_aspace_cap,
        );
        if !ok {
            // SAFETY: `_start` registered `info.ipc_buffer_vaddr` and
            // installed it as `current_ipc_buf` above.
            unsafe { ::log::emit(
                current_ipc_buf(),
                format_args!(
                    "std::os::seraph: FATAL: heap_bootstrap failed (memmgr_ep={}); \
                     likely memmgr frame-pool exhaustion — aborting",
                    info.memmgr_endpoint_cap,
                ),
            ) };
            syscall::process_exit(STARTUP_FAIL_HEAP);
        }
        // Wire the object-slab refill path against the same memmgr endpoint.
        // Cap-create syscalls retype memory out of a slab Memory cap acquired
        // lazily on first use.
        pal_alloc::object_slab_init(info.memmgr_endpoint_cap);
    }

    // In a demand-paged process, let the main-thread stack grow on demand below
    // the pages the loader mapped. A failure leaves the stack at its committed
    // size, an overflow of which faults as before; nothing else depends on it.
    if info.pager_endpoint_cap != 0 {
        let _ = register_main_stack_growth(info.stack_top_vaddr, info.stack_pages);
    }

    unsafe extern "C" {
        fn main(argc: isize, argv: *const *const u8) -> i32;
    }

    // SAFETY: `main` is rustc-synthesised for any bin crate that defines
    // `fn main` (i.e., not `#![no_main]`). It invokes `lang_start` and the
    // user's `fn main`, returning the `ExitCode`/`lang_start` value as `i32`.
    let code = unsafe { main(0, core::ptr::null()) };

    // Close every File main left open, so the fs driver drops its opens.
    crate::sys::fs::close_open_files();

    // Close stdio pipes before exit so the close protocol fires
    // (header `closed` flag + notification kick) and any parent blocked on
    // a read/write returns cleanly.
    pal_stdio::close_all();

    // Exit the process carrying `main`'s code; the kernel encodes it into the
    // exit reason so the parent's `ExitStatus` reflects it.
    syscall::process_exit(code as u32);
}

// Force the linker to keep `_start` in the final binary even when the std
// rlib is otherwise dead-code-stripped. Rlibs are archives of object files
// pulled in by undefined-symbol resolution; the linker does resolve `_start`
// as the default ELF entry, but on some link configurations it is possible
// for the object containing `_start` to be dropped before that resolution
// pass. `#[used]` plus an explicit reference from a static bakes the
// reference into `.data` and guarantees retention.
#[used]
#[cfg_attr(target_os = "seraph", unsafe(link_section = ".data.rel.ro"))]
static _START_REF: unsafe extern "C" fn(u64) -> ! = _start;

// ── Public helpers surfaced on std::os::seraph ──────────────────────────────

/// Initialise the process heap against memmgr.
///
/// `_start` calls this before `main`, with `ProcessInfo.memmgr_endpoint_cap`
/// as `memmgr_ep`, whenever that cap is non-zero. Only the first call does
/// work; a later call returns whether that first call installed the heap.
///
/// `self_aspace` is the process's own `AddressSpace` cap slot. The
/// bootstrap IPC round uses the calling thread's registered IPC buffer
/// (read from TLS via [`current_ipc_buf`]); `_start` populates that
/// slot before invoking `heap_bootstrap`.
///
/// Returns `true` if the heap is usable after this call.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn heap_bootstrap(memmgr_ep: u64, self_aspace: u64) -> bool {
    pal_alloc::heap_bootstrap(memmgr_ep, self_aspace)
}

/// Returns `true` once `heap_bootstrap` has completed successfully.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn heap_is_initialized() -> bool {
    pal_alloc::heap_is_initialized()
}

/// Abort the calling thread via `SYS_THREAD_EXIT`.
///
/// Preserved as a convenience for services that want an explicit terminator
/// without going through `std::process::exit`.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn abort_thread() -> ! {
    pal_alloc::abort_thread()
}

// ── System root namespace cap ──────────────────────────────────────────────
//
// Badged SEND on vfsd's namespace endpoint addressing the synthetic
// system root (`NodeId::ROOT`). `_start` reads
// `ProcessInfo.system_root_cap` and installs it here; namespace-walking
// code (`std::fs::File::open` once converted, plus any cap-native
// service code) reads it via [`root_dir_cap`]. Zero means "no system
// root attached" — the reading side degrades.

static ROOT_DIR_CAP: crate::sync::atomic::AtomicU64 =
    crate::sync::atomic::AtomicU64::new(0);

static CURRENT_DIR_CAP: crate::sync::atomic::AtomicU64 =
    crate::sync::atomic::AtomicU64::new(0);

// String-form mirror of the cwd cap. Held under a Mutex so that
// `set_current_dir` updates the cap and the path atomically (readers
// of the pair never see a torn (new cap, old path) intermediate).
//
// `None` is the startup state: `_start` installs `CURRENT_DIR_CAP`
// from `ProcessInfo.current_dir_cap`, but the cap does not carry a
// path string — the spawner has no obligation to label it. Until a
// process calls `set_current_dir`, `current_dir_path()` returns
// `None` and `std::env::current_dir()` reports `Unsupported`.
static CURRENT_DIR_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Install the process-wide root-directory namespace cap. Called by
/// `_start` from `ProcessInfo.system_root_cap`. Demoted to crate-internal
/// visibility because the only legitimate writer is std's own startup
/// path; tier-2 callers must obtain a namespace cap through the spawner
/// (`procmgr_labels::CONFIGURE_NAMESPACE`), not by overwriting this slot.
pub(crate) fn set_root_dir_cap(cap: u64) {
    ROOT_DIR_CAP.store(cap, crate::sync::atomic::Ordering::Release);
}

/// Read the installed root-directory namespace cap, or zero if unset.
/// Used by namespace-walking code to anchor `NS_LOOKUP` walks.
#[must_use]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn root_dir_cap() -> u64 {
    ROOT_DIR_CAP.load(crate::sync::atomic::Ordering::Acquire)
}

/// Install the process-wide current-directory namespace cap. Called by
/// `_start` from `ProcessInfo.current_dir_cap` and by
/// `std::env::set_current_dir`; both writers are inside std. Tier-2
/// callers update cwd via `std::env::set_current_dir` (which performs
/// the namespace walk and stores the result here).
pub(crate) fn set_current_dir_cap(cap: u64) {
    CURRENT_DIR_CAP.store(cap, crate::sync::atomic::Ordering::Release);
}

/// Read the installed current-directory namespace cap, or zero if
/// unset. Used by relative-path resolution in `std::fs`.
#[must_use]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn current_dir_cap() -> u64 {
    CURRENT_DIR_CAP.load(crate::sync::atomic::Ordering::Acquire)
}

/// Snapshot of the cwd path string recorded by the most recent
/// successful `set_current_dir`. Returns `None` until `set_current_dir`
/// has been called in this process — the startup cap installed from
/// `ProcessInfo.current_dir_cap` carries no string label.
///
/// Backs `std::env::current_dir()` on seraph through
/// `crate::sys::env::seraph::getcwd`.
pub(crate) fn current_dir_path() -> Option<PathBuf> {
    CURRENT_DIR_PATH
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

/// Walk `path` from `root_dir_cap()` and install the resolved
/// directory cap as the process-wide current-directory cap. Also
/// records `path` as the string mirror returned by
/// [`current_dir_path`]; the cap and the path are updated under one
/// held lock so concurrent readers never observe a (new cap, old
/// path) intermediate.
///
/// The seraph-native cwd primitive: cwd is a held cap, with a path
/// string kept alongside only for `std::env::current_dir()` to echo.
/// The existing cap (if any) is `cap_delete`'d and replaced.
///
/// `std::env::set_current_dir(impl AsRef<Path>)` delegates to this
/// function on seraph via the env-imp dispatch overlay; this remains
/// the direct entry point for cap-native callers who already hold a
/// `&str` path.
///
/// # Errors
/// - `Unsupported` if `root_dir_cap()` is zero.
/// - Errors from the namespace walk (`NotFound`, `PermissionDenied`,
///   `NotADirectory`).
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn set_current_dir(path: &str) -> crate::io::Result<()> {
    let root = root_dir_cap();
    if root == 0 {
        return Err(crate::io::Error::new(
            crate::io::ErrorKind::Unsupported,
            "seraph: set_current_dir called with no root_dir_cap configured",
        ));
    }
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return Err(crate::io::Error::other(
            "seraph: set_current_dir called before IPC buffer registered",
        ));
    }
    let walked = crate::sys::fs::walk_path_to_dir(root, path, ipc_buf)?;
    let mut guard = CURRENT_DIR_PATH.lock().unwrap_or_else(|p| p.into_inner());
    let prev = CURRENT_DIR_CAP.swap(walked.dir_cap, crate::sync::atomic::Ordering::AcqRel);
    *guard = Some(PathBuf::from(path));
    drop(guard);
    if prev != 0 {
        let _ = syscall::cap_delete(prev);
    }
    Ok(())
}

/// Walk `path` from the supplied namespace cap via `NS_LOOKUP` and return
/// the resolved file's badged SEND cap and its size hint.
///
/// Each non-final path component must resolve to a directory; the final
/// component must resolve to a file. The returned cap is freshly derived
/// — caller takes ownership and must `cap_delete` when done. On any
/// error no cap is returned.
///
/// Used by services that hold an attenuated namespace cap and need to
/// resolve a binary path before issuing `procmgr_labels::CREATE_FROM_FILE`.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn namespace_lookup_file(root_cap: u64, path: &str) -> crate::io::Result<(u64, u64)> {
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return Err(crate::io::Error::other("seraph: IPC buffer not registered"));
    }
    let walked = crate::sys::fs::walk_path_to_file(root_cap, path, ipc_buf)?;
    Ok((walked.file_cap, walked.size))
}

/// Walk `path` from the supplied namespace cap via `NS_LOOKUP`,
/// requesting `requested_rights` per hop, and return the resolved
/// directory's badged SEND cap.
///
/// Every hop (including the final) must resolve to a directory. The
/// returned cap carries at most `requested_rights` intersected with
/// each parent's rights and each entry's `max_rights` — see
/// `shared/namespace-protocol`. Used by spawners that walk-and-
/// attenuate a subtree cap before installing it on a child via
/// `CONFIGURE_NAMESPACE`. Callers wanting the full rights chain pass
/// `0xFFFF`. A path with no components (empty or `/`) names the anchor
/// itself, which no hop narrows: it resolves to a copy of `root_cap` only
/// when `requested_rights` includes every defined namespace right, and to
/// `InvalidInput` otherwise.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn namespace_lookup_dir(
    root_cap: u64,
    path: &str,
    requested_rights: u64,
) -> crate::io::Result<u64> {
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return Err(crate::io::Error::other("seraph: IPC buffer not registered"));
    }
    let walked =
        crate::sys::fs::walk_path_to_dir_with_rights(root_cap, path, requested_rights, ipc_buf)?;
    Ok(walked.dir_cap)
}

// Raw retype debits the kernel charges for one object of each kind, the
// `min_bytes` to pass to `object_slab_retype`. Each constant is defined as the
// ABI crate's item and the function forwards to the ABI crate's, so each
// equals the ABI value by construction; the kernel pins those values to its
// real object sizes, and a size change is an ABI-visible change by design.
// They are defined here rather than re-exported because an item reached
// through the sysroot-private ABI crate is unstable (`rustc_private`) to
// std's users: build-std compiles std's dependencies with
// `-Zforce-unstable-if-unmarked`. The same holds for `ruststd-death-queues`,
// which std uses internally and services take as a path dependency instead.

/// Raw retype debit of one `Endpoint`, in bytes (`syscall_abi`'s
/// `ENDPOINT_RETYPE_BYTES`).
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub const ENDPOINT_RETYPE_BYTES: u64 = syscall_abi::ENDPOINT_RETYPE_BYTES;

/// Raw retype debit of one `Notification`, in bytes (`syscall_abi`'s
/// `NOTIFICATION_RETYPE_BYTES`).
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub const NOTIFICATION_RETYPE_BYTES: u64 = syscall_abi::NOTIFICATION_RETYPE_BYTES;

/// Raw retype debit of one `WaitSet` of `capacity` members, in bytes
/// (`syscall_abi`'s `wait_set_retype_bytes`).
#[stable(feature = "seraph_ext", since = "1.0.0")]
#[must_use]
pub fn wait_set_retype_bytes(capacity: u64) -> u64 {
    syscall_abi::wait_set_retype_bytes(capacity)
}

/// Raw retype debit of one `EventQueue` of `capacity` entries and `observers`
/// death-observer nodes, in bytes (`syscall_abi`'s `event_queue_retype_bytes`).
#[stable(feature = "seraph_ext", since = "1.0.0")]
#[must_use]
pub fn event_queue_retype_bytes(capacity: u64, observers: u64) -> u64 {
    syscall_abi::event_queue_retype_bytes(capacity, observers)
}

/// Retype one kernel object out of the runtime's object-slab machinery.
///
/// `min_bytes` is the full raw debit the kernel charges for the object the
/// caller is about to create, the object wrapper plus its state:
/// [`ENDPOINT_RETYPE_BYTES`], [`NOTIFICATION_RETYPE_BYTES`],
/// [`wait_set_retype_bytes`]`(capacity)`, or
/// [`event_queue_retype_bytes`]`(capacity, observers)`, or
/// the byte size of a page-granular object. The runtime rounds it up to the
/// kernel's size class, so the request covers the kernel's debit. `retype` is
/// called at most once with a Memory-cap slot whose `available_bytes` covers
/// that class and must perform exactly one `cap_create_*` syscall against the
/// slot, returning `Some` on success.
///
/// # Closure contract
///
/// Sub-page classes run `retype` under the slab pool's spinlock: exactly
/// one retype syscall and nothing else — no allocation, no blocking, no
/// panicking, no re-entry into the slab APIs — and the slot must not
/// escape the closure. Page-aligned classes draw a fresh dedicated grant
/// whose cap slot the runtime reclaims afterwards (the retyped object
/// keeps its own ancestor reference on the backing memory).
///
/// Returns `None` if memmgr is unreachable, refuses the request, or
/// `retype` itself fails.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn object_slab_retype<T>(min_bytes: u64, retype: impl FnOnce(u64) -> Option<T>) -> Option<T> {
    pal_alloc::object_slab_retype(min_bytes, retype)
}

/// The dedicated memmgr grant behind one page-granular object retype, as
/// [`object_slab_retype_reclaimable`] returns it: what [`object_slab_release`]
/// needs to return the grant's run to memmgr's pool once the object is
/// deleted.
///
/// Neither `Clone` nor `Copy`: [`object_slab_release`] consumes it, so one
/// grant is released once.
#[stable(feature = "seraph_ext", since = "1.0.0")]
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectGrant {
    region_id: u64,
}

/// [`object_slab_retype`] for an object the caller deletes mid-life: also
/// returns the [`ObjectGrant`] of the dedicated grant a page-granular class
/// draws, so [`object_slab_release`] can return its run to memmgr's pool once
/// the object is deleted. Deleting the object alone leaves that run charged
/// to the process until it dies. `None` in the grant's place for a sub-page
/// class: its pooled page is the runtime's to reclaim.
///
/// `min_bytes` and `retype` are [`object_slab_retype`]'s, under the same
/// closure contract.
///
/// Returns `None` if memmgr is unreachable, refuses the request, or
/// `retype` itself fails.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn object_slab_retype_reclaimable<T>(
    min_bytes: u64,
    retype: impl FnOnce(u64) -> Option<T>,
) -> Option<(T, Option<ObjectGrant>)> {
    pal_alloc::object_slab_retype_reclaimable(min_bytes, retype)
        .map(|(out, region_id)| (out, region_id.map(|region_id| ObjectGrant { region_id })))
}

/// Return `grant`'s run to memmgr's pool. The caller MUST have deleted the
/// object retyped from it first. A release while the object is live still
/// succeeds and takes the run off the process's ledger at once, but memmgr
/// holds it on its deferred list, granted to no one, until the object is
/// deleted (`services/memmgr/docs/memory-pool.md` § Reclamation).
/// Best-effort: a failed call leaves the run charged to the process until it
/// dies.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn object_slab_release(grant: ObjectGrant) {
    pal_alloc::slab_release_fresh(grant.region_id);
}

/// memmgr's current free-pool size in bytes, or `None` if memmgr is
/// unreachable. Thin wrapper over the `QUERY_POOL_STATUS` aggregate query;
/// used by tests asserting that a churn loop holds a bounded memmgr-pool
/// footprint.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn memmgr_pool_free_bytes() -> Option<u64> {
    pal_alloc::memmgr_query_free_bytes()
}

/// Fund `self_aspace`'s page-table growth budget to cover mapping a
/// `region_pages`-page foreign-memory region (MMIO, DMA) into a
/// retype-backed `AddressSpace`.
///
/// Requests Memory backing from memmgr and retypes it onto the AS's PT pool
/// via `cap_create_aspace` augment-mode, so `mmio_map`/`mem_map` of the
/// region draws its intermediate page tables from this caller-funded,
/// memmgr-accounted budget rather than the fixed kernel PT reserve. Call
/// once before mapping a region whose PT cost may exceed the AS's spare
/// budget (every driver mapping discovered MMIO).
///
/// `region_pages == 0` is a no-op success. Returns `false` if memmgr is
/// unreachable, the request/augment fails, or the budget still falls short
/// after the funding rounds (another thread of the process drained it
/// meanwhile); the subsequent map then fails with `OutOfMemory` rather than
/// silently drawing on the reserve.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn fund_aspace_pt_budget(self_aspace: u64, region_pages: u64) -> bool {
    pal_alloc::fund_aspace_pt_budget(self_aspace, region_pages)
}

/// Free slots of `self_cspace` a general capability allocation may still
/// take without growing it: `CAP_INFO_CSPACE_CAPACITY` less
/// `CAP_INFO_CSPACE_USED` and the IPC receive reserve
/// (`CSPACE_IPC_RECV_RESERVE`). Zero when the queries fail. A service that
/// holds headroom above a low-water mark compares this against the mark and
/// calls [`fund_cspace_slot_budget`] when it falls below.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn cspace_slot_headroom(self_cspace: u64) -> u64 {
    pal_alloc::cspace_general_headroom(self_cspace)
}

/// Fund `self_cspace`'s slot-page pool so at least `slots` general
/// capability allocations succeed without further growth, with one page of
/// growth budget left beyond them for the `CSpace`'s body arena.
///
/// A `CSpace` keeps its last `CSPACE_IPC_RECV_RESERVE` free slots for IPC
/// capability transfer, so general allocations (`cap_create_*`, `cap_copy`,
/// `cap_derive`, splits, received grants that a handler then derives from) fail
/// with `OutOfMemory` first. A split, an `Mmio`, `IoPort`, or `Interrupt` copy,
/// and an `Mmio` mapping past its object's inline records also take a body from
/// the `CSpace`'s arena, which draws whole pages from the same growth budget.
/// This helper measures the headroom above the reserve and the budget and, when
/// either is short (`syscall_abi::cspace_topup_pages`), requests Memory from
/// memmgr and donates it to the pool via augment-mode `cap_create_cspace`.
///
/// After a success, `slots` general allocations succeed and the arena can still
/// take one more page, 31 bodies; a burst of `n` splits needs `slots` of at
/// least `n` plus 56 for each 31 bodies past those. Call it before a known
/// burst of cap acquisitions (a cache filling its slots) or periodically to
/// hold headroom above a low-water mark.
///
/// `slots == 0` still keeps the arena's page. Returns `false` if memmgr is
/// unreachable, the request/augment fails, or the headroom still falls
/// short after the funding rounds.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn fund_cspace_slot_budget(self_cspace: u64, slots: u64) -> bool {
    pal_alloc::fund_cspace_slot_budget(self_cspace, slots)
}

// ── Page-reservation allocator ──────────────────────────────────────────────
//
// Re-exports from `crate::sys::reserve`. See that module for the per-process
// arena layout and concurrency model. Used for foreign Memory mappings —
// MMIO from devmgr, DMA buffers from drivers, shmem backings, zero-copy
// file pages from fs drivers, ELF-load scratch in procmgr — i.e. every
// page-granular VA need that is not the byte heap.

#[stable(feature = "seraph_ext", since = "1.0.0")]
pub use pal_reserve::{ReserveError, ReservedRange, reserve_pages, unreserve_pages};

/// Reserve `pages` of unbacked virtual address space and register it as a
/// read-write demand-paged region with the process's pager (memmgr).
///
/// The range maps lazily: the first access to each page faults, the pager
/// backs it read-write, and the access retries transparently. The process
/// must be demand-paged — the system default; not created with
/// `procmgr_labels::CREATE_PINNED` — otherwise the first fault kills the
/// thread.
///
/// On any failure the reservation is released. On success the caller owns the
/// range and must `mem_unmap` any backed pages, then `unreserve_pages`, when
/// done.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn register_demand_paged(pages: u64) -> crate::io::Result<ReservedRange> {
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return Err(crate::io::Error::other("seraph: IPC buffer not registered"));
    }
    let info = startup_info();
    let memmgr_ep = info.memmgr_endpoint;
    if memmgr_ep == 0 {
        return Err(crate::io::Error::other("seraph: no pager (memmgr unreachable)"));
    }
    let range = reserve_pages(pages)
        .map_err(|_| crate::io::Error::other("seraph: VA reservation failed"))?;
    // Fund this address space's page-table growth budget for the region. The
    // pager maps frames into this AS on fault via `map_page_pooled`, which
    // draws intermediate page tables from the AS's own retype-backed pool; the
    // demand region is far from the eager mappings, so without funding the pool
    // is exhausted and the on-fault map fails (the pager then kills the thread).
    if !fund_aspace_pt_budget(info.self_aspace, pages) {
        unreserve_pages(range);
        return Err(crate::io::Error::other("seraph: page-table budget funding failed"));
    }
    // SAFETY: current_ipc_buf returns the registered IPC buffer page.
    if !unsafe { register_rw_region(memmgr_ep, ipc_buf, range.va_start(), pages) } {
        unreserve_pages(range);
        return Err(crate::io::Error::other("seraph: REGISTER_REGION rejected"));
    }
    Ok(range)
}

/// Register `[va, va + pages * PAGE_SIZE)` with memmgr (`REGISTER_REGION`) as
/// a read-write demand-paged region of this process. Returns whether memmgr
/// accepted it. Issues one IPC and allocates nothing, so the heap bootstrap
/// can register its floor before the heap exists.
///
/// # Safety
/// `ipc_buf` is the calling thread's registered IPC buffer page.
pub(crate) unsafe fn register_rw_region(
    memmgr_ep: u64,
    ipc_buf: *mut u64,
    va: u64,
    pages: u64,
) -> bool {
    let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::REGISTER_REGION)
        .word(0, va)
        .word(1, pages.saturating_mul(syscall_abi::PAGE_SIZE))
        .word(2, syscall_abi::MAP_WRITABLE)
        .build();
    // SAFETY: the caller passes the registered IPC buffer page.
    matches!(
        unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) },
        Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS
    )
}

/// Default usable pages of a demand-paged stack (2 MiB), for a spawned thread
/// and for the main thread alike. Lazily backed — only touched pages cost RAM —
/// so this floor is generous without eager allocation. A larger
/// `Builder::stack_size` raises a spawned thread's, and a larger
/// `stack_pages!` note the main thread's.
pub(crate) const DEFAULT_DEMAND_STACK_PAGES: u64 = 512;

// lld synthesises `__ehdr_start` at the image's ELF header, which the
// image's first load segment maps read-only for the process's lifetime.
unsafe extern "C" {
    static __ehdr_start: [u8; 18];
}

/// `e_type` of a position-independent (`ET_DYN`) ELF image.
const ET_DYN: u16 = 3;

/// Whether this process's own image is position-independent (`ET_DYN`), the
/// only kind for which the main-thread stack reservation holds
/// (docs/userspace-memory-model.md § Bootstrap Cross-Boundary VAs).
fn own_image_is_position_independent() -> bool {
    // SAFETY: `__ehdr_start` is this image's ELF header, mapped read-only for
    // the process's lifetime; its first 18 bytes hold `e_ident` and the
    // little-endian `e_type`, both architectures being little-endian.
    let header = unsafe { &*core::ptr::addr_of!(__ehdr_start) };
    u16::from_le_bytes([header[16], header[17]]) == ET_DYN
}

/// Register the main thread's demand-growth range with the pager: the pages of
/// a [`DEFAULT_DEMAND_STACK_PAGES`]-page stack ending at `stack_top` below the
/// `committed_pages` the loader mapped (`process_layout::main_stack_growth`).
/// The page below the range stays unregistered as the guard, inside the
/// reservation the creator's layout leaves below every stack top, so an
/// overflow past it faults on an address the pager declines. On an error the
/// stack keeps only its committed pages, the next page below which the pager
/// declines in the same way.
///
/// For a demand-paged process only: a pinned one has no pager to back the
/// range.
fn register_main_stack_growth(stack_top: u64, committed_pages: u32) -> crate::io::Result<()> {
    use crate::io::{ErrorKind, const_error};
    if !own_image_is_position_independent() {
        return Err(const_error!(ErrorKind::Other, "seraph: ET_EXEC image; no stack reservation"));
    }
    let (base, pages) = process_layout::main_stack_growth(
        stack_top,
        u64::from(committed_pages),
        DEFAULT_DEMAND_STACK_PAGES,
    )
    .ok_or(const_error!(ErrorKind::Other, "seraph: committed stack leaves no growth range"))?;
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return Err(const_error!(ErrorKind::Other, "seraph: IPC buffer not registered"));
    }
    let info = startup_info();
    if info.memmgr_endpoint == 0 {
        return Err(const_error!(ErrorKind::Other, "seraph: no pager (memmgr unreachable)"));
    }
    // The pager maps the range's frames from this address space's page-table
    // pool, which the loader's mappings did not fund for it.
    if !fund_aspace_pt_budget(info.self_aspace, pages) {
        return Err(const_error!(ErrorKind::Other, "seraph: page-table budget funding failed"));
    }
    // SAFETY: current_ipc_buf returns the registered IPC buffer page.
    if !unsafe { register_rw_region(info.memmgr_endpoint, ipc_buf, base, pages) } {
        return Err(const_error!(ErrorKind::Other, "seraph: REGISTER_REGION rejected"));
    }
    Ok(())
}

/// A guarded demand-paged thread stack: a reserved VA window whose upper
/// `usable_pages` are registered RW-demand and whose lowest `guard_pages` are
/// reserved but left unregistered. Because the stack grows down, an overflow
/// past the usable region faults in the guard hole; the pager declines the
/// unregistered address and the kernel kills the thread (and, via the
/// address-space death-observer, the whole process) instead of letting the
/// stack silently grow into adjacent memory.
pub(crate) struct GuardedStack {
    /// The whole reservation (guard + usable), released on teardown.
    range: ReservedRange,
    /// Base of the usable (registered) region — `range.va_start +
    /// guard_pages * PAGE_SIZE`.
    usable_base: u64,
    usable_pages: u64,
}

impl GuardedStack {
    /// Top of the usable region — the initial stack pointer (the stack grows
    /// down from here toward the guard page).
    pub(crate) fn usable_top(&self) -> u64 {
        self.usable_base + self.usable_pages * syscall_abi::PAGE_SIZE
    }
}

/// Reserve a guarded demand-paged stack: `guard_pages` unregistered pages below
/// `usable_pages` of RW demand-paged stack. The process must be demand-paged
/// (the system default; not `CREATE_PINNED`). On any failure the reservation is
/// released.
///
/// Composes [`register_demand_paged`]'s steps but registers only the upper
/// `usable_pages`, leaving the guard hole below to fault fatally. Pairs with
/// [`unregister_guarded_stack`].
pub(crate) fn reserve_guarded_stack(
    usable_pages: u64,
    guard_pages: u64,
) -> crate::io::Result<GuardedStack> {
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return Err(crate::io::Error::other("seraph: IPC buffer not registered"));
    }
    let info = startup_info();
    let memmgr_ep = info.memmgr_endpoint;
    if memmgr_ep == 0 {
        return Err(crate::io::Error::other("seraph: no pager (memmgr unreachable)"));
    }
    let total = guard_pages
        .checked_add(usable_pages)
        .filter(|&t| t != 0 && usable_pages != 0)
        .ok_or_else(|| crate::io::Error::other("seraph: invalid stack geometry"))?;
    let range = reserve_pages(total)
        .map_err(|_| crate::io::Error::other("seraph: VA reservation failed"))?;
    let usable_base = range.va_start() + guard_pages * syscall_abi::PAGE_SIZE;
    // Fund this address space's page-table growth budget for the usable region
    // only — the guard page is never backed.
    if !fund_aspace_pt_budget(info.self_aspace, usable_pages) {
        unreserve_pages(range);
        return Err(crate::io::Error::other("seraph: page-table budget funding failed"));
    }
    // SAFETY: current_ipc_buf returns the registered IPC buffer page.
    if !unsafe { register_rw_region(memmgr_ep, ipc_buf, usable_base, usable_pages) } {
        unreserve_pages(range);
        return Err(crate::io::Error::other("seraph: REGISTER_REGION rejected"));
    }
    Ok(GuardedStack {
        range,
        usable_base,
        usable_pages,
    })
}

/// Tear down a guarded stack: UNREGISTER_REGION the usable region (memmgr unmaps
/// every frame it backed and returns them to the pool), then release the VA.
/// Call only once the thread has left user-mode — its stack is no longer in use.
pub(crate) fn unregister_guarded_stack(stack: GuardedStack) {
    let ipc_buf = current_ipc_buf();
    let memmgr_ep = startup_info().memmgr_endpoint;
    if !ipc_buf.is_null() && memmgr_ep != 0 {
        let usable_len = stack.usable_pages.saturating_mul(syscall_abi::PAGE_SIZE);
        let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::UNREGISTER_REGION)
            .word(0, stack.usable_base)
            .word(1, usable_len)
            .build();
        // SAFETY: current_ipc_buf returns the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) };
    }
    unreserve_pages(stack.range);
}

// ── System log macro surface ────────────────────────────────────────────────
//
// The badged SEND cap procmgr seeds at process create-time (recorded in
// `StartupInfo::log_send_cap` and installed via `::log::install_badged_cap`
// during `_start`) is the destination of every `seraph::log!` call. No
// discovery roundtrip; the cap is live from the first instruction of
// user code.

/// System-log access surface. Re-exports the `shared/log` wire-format
/// helpers wrapped against the calling thread's registered IPC buffer.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub mod log {
    use super::current_ipc_buf;

    /// Return the cached badged SEND cap on the system log endpoint
    /// (pre-installed at `_start` from `ProcessInfo.log_send_cap`).
    /// Returns `0` when no log cap was seeded for this process (init,
    /// memmgr, procmgr themselves, or processes spawned before logd
    /// existed).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn acquire() -> u64 {
        ::log::ensure_badged_cap(current_ipc_buf())
    }

    /// Register a display name for this process's log stream.
    /// Idempotent — re-registration with the same name is a silent
    /// no-op at the receiver. Names longer than the receiver's
    /// per-slot buffer are truncated; collisions with other senders'
    /// names are resolved server-side via `name.2` / `name.3` /
    /// suffixes.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn register_name(name: &[u8]) {
        let buf = current_ipc_buf();
        let cap = ::log::ensure_badged_cap(buf);
        // SAFETY: `current_ipc_buf` is null or this thread's registered IPC
        // buffer page (`_start` and the spawn trampoline set it after
        // registering).
        unsafe { ::log::register_name(cap, buf, name) };
    }

    /// Macro entry point. Resolves the calling thread's IPC buffer and
    /// the process-global badged cap, then formats `args` and emits
    /// one `STREAM_BYTES` message (split across IPC chunks if longer
    /// than 512 bytes). Silently drops when no log cap is acquirable.
    #[doc(hidden)]
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn __emit(args: core::fmt::Arguments<'_>) {
        // SAFETY: `current_ipc_buf` is null or this thread's registered IPC
        // buffer page (`_start` and the spawn trampoline set it after
        // registering).
        unsafe { ::log::emit(current_ipc_buf(), args) };
    }
}

/// Service-registry client surface. Re-exports
/// [`::registry_client::lookup`] against the std-built instance of
/// registry-client — direct dependents would otherwise pull in their
/// own compile of the crate and miss the `REGISTRY_CAP` static that
/// `_start` installed.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub mod registry {
    use super::current_ipc_buf;

    /// Look up `name` in svcmgr's discovery registry. Returns
    /// `Some(cap)` where the cap is a fresh SEND derived by svcmgr;
    /// `None` on any failure.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn lookup(name: &[u8]) -> Option<u64> {
        let buf = current_ipc_buf();
        if buf.is_null() {
            return None;
        }
        // SAFETY: current_ipc_buf returns the registered IPC buffer page.
        unsafe { ::registry_client::lookup(name, buf) }
    }

    /// Return the installed registry cap, or zero if `_start` did not
    /// seed one (e.g. process spawned before svcmgr existed).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn registry_cap() -> u64 {
        ::registry_client::registry_cap()
    }
}

/// System-log macro. Formats and emits one log line on the process's
/// badged SEND cap, lazy-acquired from the discovery cap on first
/// call. The receiver tags each line with the registered display name
/// (default `[?]`); see [`log::register_name`].
///
/// Non-allocating — stages the text in a 512-byte stack buffer that is
/// sent in chunks as it fills, so a message of any length is sent in full;
/// a failed send drops the chunks after it, and the receiver may emit a
/// long message as several lines.
#[macro_export]
#[stable(feature = "seraph_ext", since = "1.0.0")]
macro_rules! __seraph_log {
    ($($arg:tt)*) => {{
        $crate::os::seraph::log::__emit(::core::format_args!($($arg)*))
    }};
}

// Re-export the macro at `std::os::seraph::log!` as well as the
// crate-root `std::__seraph_log!` placement that `#[macro_export]`
// generated. Macros and modules live in separate namespaces, so this
// re-export coexists with the `pub mod log { … }` above.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub use crate::__seraph_log as log;

// ── Stack-size declaration macro ────────────────────────────────────────────
//
// Mirrors `process_abi::stack_pages!` but expands to a static typed via
// `std::os::seraph::StackNote` (std's copy of the `process_abi::StackNote`
// layout), so std-using binaries can declare a custom main-thread stack
// without adding `process-abi` to their Cargo manifest.

/// Declare the main-thread stack size for this binary as `$pages` 4 KiB
/// pages. Expands to a `#[used]` static placed in
/// `.note.seraph.stack`; loaders read it before mapping the child's
/// stack. Binaries that omit the macro inherit
/// `process_abi::DEFAULT_PROCESS_STACK_PAGES`.
#[macro_export]
#[stable(feature = "seraph_ext", since = "1.0.0")]
macro_rules! __seraph_stack_pages {
    ($pages:expr) => {
        #[used]
        #[unsafe(link_section = ".note.seraph.stack")]
        static __SERAPH_STACK_NOTE: $crate::os::seraph::StackNote =
            $crate::os::seraph::StackNote::new($pages);
    };
}

#[stable(feature = "seraph_ext", since = "1.0.0")]
pub use crate::__seraph_stack_pages as stack_pages;

// ── Spawned-thread priority (BuilderExt) ────────────────────────────────────

/// Seraph-specific extensions to `std::thread`.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub mod thread {
    use crate::cell::Cell;
    use crate::io;
    use crate::thread::{Builder, JoinHandle};

    /// The level the next spawn from the current thread places its child at,
    /// set for the length of one [`BuilderExt::spawn_at_priority`] call; 0
    /// when no spawn of this thread asks for one, and the child takes the
    /// process's `initial_priority`. Thread-local, since [`Builder::spawn`]
    /// creates the kernel thread (`sys::thread::Thread::new`) on the spawning
    /// thread before it returns.
    #[thread_local]
    static SPAWN_PRIORITY: Cell<u8> = Cell::new(0);

    /// The level a [`BuilderExt::spawn_at_priority`] in progress on the
    /// current thread asks for, or 0; read by `sys::thread::Thread::new`.
    pub(crate) fn requested_spawn_priority() -> u8 {
        SPAWN_PRIORITY.get()
    }

    /// Seraph-specific extensions to [`Builder`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub trait BuilderExt {
        /// Spawn `f` as [`Builder::spawn`] does, with the new thread placed
        /// at scheduling level `level` instead of the process's
        /// `initial_priority`, within the band of the process's
        /// `SchedControl` cap (`StartupInfo::sched_control_cap`). A server
        /// thread that a higher-level client blocks on is placed at that
        /// client's level this way (`core/kernel/docs/scheduler.md`
        /// § Priority Inversion Mitigation).
        ///
        /// # Errors
        /// `InvalidInput` for a `level` of 0 or a process with no
        /// `SchedControl` cap; otherwise [`Builder::spawn`]'s errors, which
        /// include the kernel's refusal of a level outside the band.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn spawn_at_priority<F, T>(self, level: u8, f: F) -> io::Result<JoinHandle<T>>
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static;
    }

    #[stable(feature = "seraph_ext", since = "1.0.0")]
    impl BuilderExt for Builder {
        fn spawn_at_priority<F, T>(self, level: u8, f: F) -> io::Result<JoinHandle<T>>
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let has_sched =
                super::try_startup_info().is_some_and(|i| i.sched_control_cap != 0);
            if level == 0 || !has_sched {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "seraph: no priority level or no scheduling authority",
                ));
            }
            let previous = SPAWN_PRIORITY.replace(level);
            let spawned = self.spawn(f);
            SPAWN_PRIORITY.set(previous);
            spawned
        }
    }
}

// ── Directory entries (DirEntryExt) ─────────────────────────────────────────

/// Seraph-specific extensions to `std::fs`.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub mod fs {
    use crate::ffi::OsStr;
    use crate::fs::DirEntry;
    use crate::sys::AsInner;

    /// Seraph-specific extensions to [`DirEntry`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub trait DirEntryExt {
        /// The entry's file name, borrowed from the entry. Unlike
        /// [`DirEntry::file_name`] and [`DirEntry::path`], which copy it, this
        /// allocates nothing, so a caller that must handle out-of-memory can
        /// read a directory listing's names.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn file_name_ref(&self) -> &OsStr;
    }

    #[stable(feature = "seraph_ext", since = "1.0.0")]
    impl DirEntryExt for DirEntry {
        fn file_name_ref(&self) -> &OsStr {
            self.as_inner().file_name_ref()
        }
    }
}

// ── Per-spawn namespace caps (CommandExt) ───────────────────────────────────
//
// Sandboxed spawns: caller walks-and-attenuates a namespace cap into a
// reduced-rights sub-cap, then attaches it to the `Command` so the child's
// `ProcessInfo.system_root_cap` / `ProcessInfo.current_dir_cap` carries
// the attenuated cap rather than the parent-inherit default. Wire shape
// lives in `procmgr_labels::CONFIGURE_NAMESPACE`.

/// Seraph-specific extensions to `std::process::Command`.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub mod process {
    use crate::process::{Child, Command};
    use crate::sys::{AsInner, AsInnerMut};

    /// Seraph-specific extensions to [`Command`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub trait CommandExt {
        /// Override the namespace cap delivered to the child via
        /// `ProcessInfo.system_root_cap`. Cap ownership transfers to the
        /// `Command` and is consumed by the next `spawn` (procmgr's
        /// `CONFIGURE_NAMESPACE` handler installs a copy into the child's
        /// `CSpace` at start time, and the source slot is `cap_delete`'d
        /// post-IPC). Without this call, the child inherits the spawner's
        /// `root_dir_cap()` by `cap_copy`. Passing `0` reverts to the
        /// parent-inherit default.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn namespace_cap(&mut self, cap: u64) -> &mut Self;

        /// Override the cwd cap delivered to the child via
        /// `ProcessInfo.current_dir_cap`. Same lifetime contract as
        /// [`Self::namespace_cap`]. Without this call, the child's
        /// cwd cap is computed in `spawn` from (in priority order):
        /// the path stored by `Command::cwd`, or the spawner's own
        /// `current_dir_cap()`, or zero. Passing `0` reverts to that
        /// default chain.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn cwd_dir_cap(&mut self, cap: u64) -> &mut Self;

        /// Create the child *pinned*: eager-mapped, with no system pager.
        /// By default a child is demand-paged — procmgr binds its main thread's
        /// fault handler to the system pager (memmgr) and delegates the child
        /// address space, and the runtime inherits the pager onto threads the
        /// child spawns, so the child can back regions lazily via
        /// [`super::register_demand_paged`]. Set `pinned(true)` only for a
        /// child that cannot depend on the fault path — e.g. one doing DMA.
        /// Defaults to off.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn pinned(&mut self, on: bool) -> &mut Self;

        /// Request the priority level the child's initial thread is created
        /// at (the `CREATE_PRIORITY` label field). `0` (the default)
        /// reverts to procmgr's policy default, clamped to the child's
        /// band. A level above the spawner's own band ceiling — or above
        /// the child's band — makes procmgr reject the spawn with
        /// `InvalidInput`; a level that does not fit the 5-bit label field
        /// (> 31) is rejected by `spawn` itself with `InvalidInput`.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn priority(&mut self, level: u8) -> &mut Self;

        /// Request the upper bound of the `SchedControl` band delegated to
        /// the child (the `CREATE_BAND_MAX` label field; the child's band
        /// is `[1, level]`). `0` (the default) delegates a copy of the
        /// spawner's own band. A bound above the spawner's ceiling makes
        /// procmgr reject the spawn with `InvalidInput`; a bound that does
        /// not fit the 5-bit label field (> 31) is rejected by `spawn`
        /// itself with `InvalidInput`.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn sched_max(&mut self, level: u8) -> &mut Self;
    }

    #[stable(feature = "seraph_ext", since = "1.0.0")]
    impl CommandExt for Command {
        fn namespace_cap(&mut self, cap: u64) -> &mut Command {
            self.as_inner_mut().set_namespace_cap(cap);
            self
        }

        fn cwd_dir_cap(&mut self, cap: u64) -> &mut Command {
            self.as_inner_mut().set_cwd_dir_cap(cap);
            self
        }

        fn pinned(&mut self, on: bool) -> &mut Command {
            self.as_inner_mut().set_pinned(on);
            self
        }

        fn priority(&mut self, level: u8) -> &mut Command {
            self.as_inner_mut().set_priority(level);
            self
        }

        fn sched_max(&mut self, level: u8) -> &mut Command {
            self.as_inner_mut().set_sched_max(level);
            self
        }
    }

    /// Seraph-specific extensions to [`Child`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub trait ChildExt {
        /// The child's procmgr process-handle cap: the full capability handle
        /// (slot index and generation) in this process's `CSpace`, for the
        /// procmgr labels that take one (`QUERY_PROCESS`, a `cap_derive` to
        /// delegate it). [`Child::id`] returns only its slot index, which fits
        /// upstream's `u32` and so cannot carry the generation.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn process_handle(&self) -> u64;
    }

    #[stable(feature = "seraph_ext", since = "1.0.0")]
    impl ChildExt for Child {
        fn process_handle(&self) -> u64 {
            self.as_inner().process_handle()
        }
    }

    /// Pages of the spawner's argv/env run [`ArgvEnvCap::new`] maps at once
    /// while it writes the blobs: one window of this many pages, re-mapped for
    /// every chunk. The window bounds the spawner's page-table cost to the
    /// tables one 256 KiB span needs, whatever the blobs' size; a larger
    /// window only saves map calls.
    const ARGV_ENV_WRITE_WINDOW_PAGES: u64 = 64;

    /// A spawner's argv and env, packed into a Memory cap for a procmgr create
    /// request (`procmgr_labels::CREATE_ARGV_ENV`): one contiguous run of the
    /// pages both blobs fill, granted to this process by memmgr, holding the argv
    /// blob at byte 0 and the env blob directly after it.
    ///
    /// [`Self::cap`] is a map-only derivation the request moves into
    /// procmgr, which deletes its copy before it replies. Dropping the value,
    /// once the create call has returned, deletes the derivation if the call
    /// did not move it, deletes this process's cap on the run, and returns the
    /// run to memmgr (`RELEASE_MEMORY_CAPS`). Two cases withhold the run
    /// instead, so that it stays charged to this process until it exits
    /// rather than going back to memmgr's pool while pages of it may still be
    /// mapped: a [`Self::new`] whose write window it cannot unmap, and a
    /// create procmgr answers `ARGV_ENV_STILL_MAPPED` ([`Self::settle`]).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub struct ArgvEnvCap {
        original: u64,
        transfer: u64,
        region_id: u64,
        header: ipc::procmgr_labels::ArgvEnvHeader,
    }

    impl ArgvEnvCap {
        /// Pack `args` (`args_count` NUL-terminated strings) and `env`
        /// (`env_count` NUL-terminated `KEY=VALUE` strings) into a fresh Memory
        /// cap. `Ok(None)` when both blobs are empty: the request then carries no
        /// argv/env cap.
        ///
        /// # Errors
        /// `ArgumentListTooLong` when the blobs together exceed
        /// `process_abi::ARGV_ENV_MAX_BYTES` or memmgr refuses this process the
        /// contiguous run they fill; `Unsupported` when the process has no memmgr
        /// endpoint or IPC buffer; `Other` when the run cannot be mapped to be
        /// written.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        pub fn new(
            args: &[u8],
            args_count: u64,
            env: &[u8],
            env_count: u64,
        ) -> crate::io::Result<Option<Self>> {
            let total = (args.len() + env.len()) as u64;
            if total == 0 {
                return Ok(None);
            }
            let too_long = |why| crate::io::Error::new(crate::io::ErrorKind::ArgumentListTooLong, why);
            if total > process_abi::ARGV_ENV_MAX_BYTES {
                return Err(too_long("argv and env exceed the process ABI's argv/env region"));
            }
            let (memmgr_ep, aspace) = spawner_memmgr()?;
            let pages = total.div_ceil(syscall_abi::PAGE_SIZE);
            let (original, _, region_id) =
                crate::sys::alloc::seraph::slab_request_pages(memmgr_ep, pages)
                    .ok_or_else(|| too_long("argv and env exceed what the spawner can fund"))?;
            let header = ipc::procmgr_labels::ArgvEnvHeader {
                args_bytes: args.len() as u64,
                args_count,
                env_bytes: env.len() as u64,
                env_count,
            };
            let mut this = Self { original, transfer: 0, region_id, header };
            if let Err(still_mapped) = write_argv_env(aspace, original, pages, args, env) {
                if still_mapped {
                    // A run this process may still have mapped stays charged
                    // to it until it exits, rather than going back to
                    // memmgr's pool.
                    let _ = syscall::cap_delete(this.original);
                    crate::mem::forget(this);
                }
                return Err(crate::io::Error::other("argv/env: mapping the blob pages failed"));
            }
            this.transfer = syscall::cap_derive(original, syscall::RIGHTS_MEM_MAP)
                .map_err(|_| crate::io::Error::other("argv/env: deriving the transfer cap failed"))?;
            Ok(Some(this))
        }

        /// The `ipc::procmgr_labels::ArgvEnvHeader` the request carries, as its
        /// data words in wire order (from word 0 for `CREATE_PROCESS`, from
        /// word 1 for `CREATE_FROM_FILE`).
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        pub fn header_words(&self) -> [u64; ipc::procmgr_labels::ARGV_ENV_HEADER_WORDS] {
            self.header.to_words()
        }

        /// The map-only cap the request transfers to procmgr, the last cap
        /// before a death relay.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        pub fn cap(&self) -> u64 {
            self.transfer
        }

        /// Settle the run after the create call returned `reply_label`:
        /// withhold it when procmgr replied
        /// `procmgr_errors::ARGV_ENV_STILL_MAPPED` (procmgr may still map its
        /// pages, so it stays charged to this process until it exits and
        /// never returns to memmgr's pool), and otherwise drop it, returning
        /// the run to memmgr.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        pub fn settle(self, reply_label: u64) {
            if reply_label == ipc::procmgr_errors::ARGV_ENV_STILL_MAPPED {
                if self.transfer != 0 {
                    let _ = syscall::cap_delete(self.transfer);
                }
                let _ = syscall::cap_delete(self.original);
                crate::mem::forget(self);
            }
        }
    }

    #[stable(feature = "seraph_ext", since = "1.0.0")]
    impl crate::fmt::Debug for ArgvEnvCap {
        fn fmt(&self, f: &mut crate::fmt::Formatter<'_>) -> crate::fmt::Result {
            f.debug_struct("ArgvEnvCap")
                .field("header", &self.header)
                .finish_non_exhaustive()
        }
    }

    #[stable(feature = "seraph_ext", since = "1.0.0")]
    impl Drop for ArgvEnvCap {
        fn drop(&mut self) {
            // A call that moved the derivation left a stale handle here, whose
            // delete the per-slot generation refuses; one that did not, or a
            // value built before the derivation (slot 0), leaves it to delete.
            if self.transfer != 0 {
                let _ = syscall::cap_delete(self.transfer);
            }
            let _ = syscall::cap_delete(self.original);
            crate::sys::alloc::seraph::slab_release_fresh(self.region_id);
        }
    }

    /// The spawning process's memmgr endpoint and address space.
    fn spawner_memmgr() -> crate::io::Result<(u64, u64)> {
        let info = super::try_startup_info().ok_or_else(|| {
            crate::io::Error::new(
                crate::io::ErrorKind::Unsupported,
                "argv/env: startup info not installed",
            )
        })?;
        if info.memmgr_endpoint == 0 || super::current_ipc_buf().is_null() {
            return Err(crate::io::Error::new(
                crate::io::ErrorKind::Unsupported,
                "argv/env: spawning process has no memmgr endpoint or IPC buffer",
            ));
        }
        Ok((info.memmgr_endpoint, info.self_aspace))
    }

    /// Write `args` then `env` from byte 0 of `memory`'s first `pages` pages,
    /// and zero the tail, through one [`ARGV_ENV_WRITE_WINDOW_PAGES`]-page
    /// window of `aspace` re-mapped per chunk (`argv_env::fill_window` fills
    /// each). `Err(still_mapped)` when the reservation, the derivation or a
    /// map fails (`false`), or an unmap does (`true`: a chunk may still be
    /// mapped here, so the caller withholds the run from memmgr).
    fn write_argv_env(
        aspace: u64,
        memory: u64,
        pages: u64,
        args: &[u8],
        env: &[u8],
    ) -> Result<(), bool> {
        use crate::sys::reserve::{reserve_pages, unreserve_pages};

        let rw = syscall::cap_derive(memory, syscall::RIGHTS_MEM_MAP_RW).map_err(|_| false)?;
        let Ok(window) = reserve_pages(ARGV_ENV_WRITE_WINDOW_PAGES) else {
            let _ = syscall::cap_delete(rw);
            return Err(false);
        };
        let va = window.va_start();
        let mut offset = 0;
        let mut result = Ok(());
        while offset < pages {
            let chunk = (pages - offset).min(ARGV_ENV_WRITE_WINDOW_PAGES);
            // SAFETY: `va` is the base of a window reserved just above from the
            // per-process reservation arena (`sys::reserve`), which hands out VA
            // no Rust object or IPC page occupies; this call owns it, and
            // `chunk` is at most its size.
            if unsafe { syscall::mem_map(rw, aspace, va, offset, chunk, syscall::MAP_WRITABLE) }
                .is_err()
            {
                // The kernel maps page by page and stops at the first
                // failure, so pages before it may be mapped: unmap the whole
                // chunk (unmapping a page that was never mapped is harmless).
                // When that unmap fails too, the run is withheld from memmgr
                // (`Err(true)`) and the window stays reserved, rather than
                // returning a run still partly mapped here.
                // SAFETY: the span is this call's own window; nothing
                // references it.
                if unsafe { syscall::mem_unmap(aspace, va, chunk) }.is_err() {
                    let _ = syscall::cap_delete(rw);
                    return Err(true);
                }
                result = Err(false);
                break;
            }
            let base = (offset * syscall_abi::PAGE_SIZE) as usize;
            let len = (chunk * syscall_abi::PAGE_SIZE) as usize;
            // SAFETY: the `chunk` pages at `va` are mapped writable just above,
            // for this process alone (no other mapping of the fresh run exists),
            // and stay mapped until the unmap below, after the slice's last use.
            let dst = unsafe { crate::slice::from_raw_parts_mut(va as *mut u8, len) };
            argv_env::fill_window(dst, base, args, env);
            // SAFETY: the span is this call's own window, mapped above; no slice
            // over it outlives the fill.
            if unsafe { syscall::mem_unmap(aspace, va, chunk) }.is_err() {
                // The window stays reserved, so no later reservation lands on
                // the still-mapped pages.
                let _ = syscall::cap_delete(rw);
                return Err(true);
            }
            offset += chunk;
        }
        let _ = syscall::cap_delete(rw);
        unreserve_pages(window);
        result
    }
}
