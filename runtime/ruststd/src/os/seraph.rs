// seraph-overlay: std::os::seraph
//
// Seraph-specific public surface. Lives under `std::os::seraph` so service
// code written against std can reach the platform primitives:
//
//   * `_start` — the ELF entry symbol exported for std-built binaries; reads
//     `ProcessInfo` at the well-known VA, registers the IPC buffer, wires
//     stdio caps, bootstraps the heap, then jumps to the rustc-synthesised
//     `extern "C" fn main` which calls `std::rt::lang_start` and in turn the
//     user's idiomatic `fn main`. Exits via `thread_exit` if `main` returns.
//   * `startup_info()` / `try_startup_info()` — accessors for the
//     `StartupInfo` stashed by `_start`. Services use these to obtain their
//     initial caps.
//   * `heap_bootstrap` / `heap_is_initialized` — allocator bring-up against
//     procmgr.
//   * `abort_thread` — placeholder thread terminator.

// std requires every public item to carry a stability attribute. Everything
// in `std::os::seraph` is specific to this target and not promoted through
// libs-api, so tag the module with an internal-only `stable` gate — the
// feature name is a placeholder and has no std-wide meaning.
#![stable(feature = "seraph_ext", since = "1.0.0")]

use crate::cell::{Cell, UnsafeCell};
use crate::mem::MaybeUninit;
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sys::alloc::seraph as pal_alloc;
use crate::sys::reserve as pal_reserve;
use crate::sys::stdio::seraph as pal_stdio;

use process_abi::{PROCESS_ABI_VERSION, PROCESS_INFO_VADDR, process_info_ref};

/// Re-export of [`process_abi::StackNote`]. Lets the [`stack_pages!`]
/// macro emit a typed static through `std::os::seraph::StackNote`,
/// keeping std-using binaries free of a direct `process-abi` Cargo
/// dependency.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub use process_abi::StackNote;

/// Startup information the kernel+procmgr hand to a process at spawn time,
/// materialised by `_start` from the read-only `ProcessInfo` page and made
/// available through [`startup_info`]. A std-local copy of the shape defined in
/// `process-abi`: users reach it through `std::os::seraph` instead of a
/// direct path dep on the ABI crate, so field access does not cross the
/// sysroot-private-dep boundary that `process-abi` sits behind.
#[stable(feature = "seraph_ext", since = "1.0.0")]
#[derive(Debug, Clone, Copy)]
pub struct StartupInfo {
    /// Virtual address of the pre-mapped IPC buffer page.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub ipc_buffer: *mut u8,
    /// Cap slot of the SEND endpoint back to the creator, or 0 when absent.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub creator_endpoint: u32,
    /// Cap slot of the caller's own Thread object.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub self_thread: u32,
    /// Cap slot of the caller's own AddressSpace object.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub self_aspace: u32,
    /// Cap slot of the caller's own CSpace object.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub self_cspace: u32,
    /// Cap slot of a tokened SEND cap on procmgr. Zero if procmgr is not
    /// reachable (the process is procmgr itself, or runs before procmgr
    /// exists). Used for process-lifecycle queries.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub procmgr_endpoint: u32,
    /// Cap slot of a tokened SEND cap on memmgr. Zero if memmgr is not
    /// reachable (memmgr itself, init, or anything earlier in the boot
    /// chain). `_start` consumes this to bootstrap the heap.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub memmgr_endpoint: u32,
    /// Shmem frame cap backing `std::io::stdin`. Zero when no input
    /// pipe is attached; reads return `Ok(0)` (EOF).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdin_frame_cap: u32,
    /// Shmem frame cap backing `std::io::stdout`. Zero when no sink is
    /// attached; writes silently drop.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdout_frame_cap: u32,
    /// Shmem frame cap backing `std::io::stderr`. Zero when no sink is
    /// attached; writes silently drop.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stderr_frame_cap: u32,
    /// Tokened SEND cap on vfsd's namespace endpoint at the synthetic
    /// system root. Installed by the spawner via
    /// `procmgr_labels::CONFIGURE_NAMESPACE` between create and start.
    /// Zero when no spawner-supplied cap was delivered (or vfsd is not
    /// reachable). Reachable application-side via [`root_dir_cap`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub system_root_cap: u32,
    /// Tokened SEND cap on a namespace endpoint addressing the initial
    /// current working directory. Anchors relative-path resolution.
    /// Zero means relative paths are unsupported until the process
    /// installs one (e.g. via `std::env::set_current_dir`).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub current_dir_cap: u32,
    /// Wakeup signal caps for the stdio pipes. See `process_abi::ProcessInfo`
    /// for full data-vs-space and writer-vs-reader semantics. Zero when
    /// the corresponding direction is not piped.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdin_data_signal_cap: u32,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdin_space_signal_cap: u32,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdout_data_signal_cap: u32,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdout_space_signal_cap: u32,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stderr_data_signal_cap: u32,
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stderr_space_signal_cap: u32,
    /// Un-tokened SEND cap on the system log endpoint (the "discovery
    /// cap"). Used by [`log!`] to lazy-acquire a tokened SEND cap on
    /// first call via the `GET_LOG_CAP` IPC. Zero when no logger is
    /// reachable; the macro silently drops.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub log_discovery_cap: u32,
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
    /// Raw argv blob written into the read-only `ProcessInfo` page by the
    /// spawner. Concatenation of `args_count` NUL-terminated UTF-8
    /// strings; total byte length `args_blob.len()`. Empty slice when no
    /// argv was provided. Application code should not read this
    /// directly — use `std::env::args()`.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub args_blob: &'static [u8],
    /// Number of NUL-terminated entries in [`Self::args_blob`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub args_count: usize,
    /// Raw env blob written into the read-only `ProcessInfo` page by the
    /// spawner. Concatenation of `env_count` NUL-terminated UTF-8 strings
    /// of shape `KEY=VALUE`. Empty slice when no env was provided.
    /// Application code should not read this directly — use
    /// `std::env::{var, vars}`.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub env_blob: &'static [u8],
    /// Number of NUL-terminated `KEY=VALUE` entries in [`Self::env_blob`].
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub env_count: usize,
    /// Virtual address of the top of the main-thread stack — the value
    /// SP held at `_start`. The live mapping covers
    /// `[stack_top_vaddr - stack_pages * PAGE_SIZE, stack_top_vaddr)`.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stack_top_vaddr: u64,
    /// Number of 4 KiB pages mapped for the main-thread stack.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stack_pages: u32,
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
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn set_current_ipc_buf(buf: *mut u64) {
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

/// Process entry point. Exported with the conventional ELF entry symbol name
/// so the linker sets `e_entry` here and procmgr jumps directly in.
///
/// Reads the read-only `ProcessInfo` page procmgr placed at
/// [`PROCESS_INFO_VADDR`], registers the pre-mapped IPC buffer, stashes the
/// derived [`StartupInfo`] in process-global storage, then hands off to the
/// rustc-synthesised `extern "C" fn main` which in turn drives
/// `std::rt::lang_start` and the user's `fn main`. If `main` returns, this
/// function calls `thread_exit` as a safety net so the process never
/// re-enters kernel entry code with an undefined stack frame.
///
/// # Safety
///
/// Called by the kernel with a valid `ProcessInfo` page mapped at
/// [`PROCESS_INFO_VADDR`] and a pre-mapped IPC buffer at the VA it records.
/// The function itself is safe to export.
#[unsafe(no_mangle)]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub extern "C" fn _start() -> ! {
    // SAFETY: procmgr maps a valid `ProcessInfo` page at `PROCESS_INFO_VADDR`
    // before starting the first thread, and the page remains mapped for the
    // process's lifetime.
    let info = unsafe { process_info_ref(PROCESS_INFO_VADDR) };

    if info.version != PROCESS_ABI_VERSION {
        syscall::thread_exit();
    }

    // Register the IPC buffer before any IPC-using code runs. Idempotent in
    // the kernel, so services that call `ipc_buffer_set` again are fine.
    let _ = syscall::ipc_buffer_set(info.ipc_buffer_vaddr);
    set_current_ipc_buf(info.ipc_buffer_vaddr as *mut u64);

    // Build the argv slice from the ProcessInfo-page region procmgr wrote.
    // `args_offset` is a byte offset within the mapped ProcessInfo page;
    // bounds-check it against the 4 KiB page size. Any inconsistency
    // (bogus ABI version, truncated page) falls through to an empty
    // slice rather than an out-of-bounds read.
    let args_blob: &'static [u8] = if info.args_count > 0
        && info.args_bytes > 0
        && (info.args_offset as u64) < 4096
        && (info.args_offset as u64) + (info.args_bytes as u64) <= 4096
    {
        let base = PROCESS_INFO_VADDR + info.args_offset as u64;
        // SAFETY: the ProcessInfo page is mapped read-only for the
        // process's lifetime and the bounds check above confines the
        // slice to the same page. Bytes are plain data.
        unsafe { core::slice::from_raw_parts(base as *const u8, info.args_bytes as usize) }
    } else {
        &[]
    };

    // Build the env slice the same way as argv. Same page, same bounds
    // check, same empty-slice fallback on any inconsistency.
    let env_blob: &'static [u8] = if info.env_count > 0
        && info.env_bytes > 0
        && (info.env_offset as u64) < 4096
        && (info.env_offset as u64) + (info.env_bytes as u64) <= 4096
    {
        let base = PROCESS_INFO_VADDR + info.env_offset as u64;
        // SAFETY: ProcessInfo page is mapped read-only for the process's
        // lifetime; bounds check above confines the slice to the same page.
        unsafe { core::slice::from_raw_parts(base as *const u8, info.env_bytes as usize) }
    } else {
        &[]
    };

    let startup = StartupInfo {
        ipc_buffer: info.ipc_buffer_vaddr as *mut u8,
        creator_endpoint: info.creator_endpoint_cap,
        self_thread: info.self_thread_cap,
        self_aspace: info.self_aspace_cap,
        self_cspace: info.self_cspace_cap,
        procmgr_endpoint: info.procmgr_endpoint_cap,
        memmgr_endpoint: info.memmgr_endpoint_cap,
        stdin_frame_cap: info.stdin_frame_cap,
        stdout_frame_cap: info.stdout_frame_cap,
        stderr_frame_cap: info.stderr_frame_cap,
        system_root_cap: info.system_root_cap,
        current_dir_cap: info.current_dir_cap,
        stdin_data_signal_cap: info.stdin_data_signal_cap,
        stdin_space_signal_cap: info.stdin_space_signal_cap,
        stdout_data_signal_cap: info.stdout_data_signal_cap,
        stdout_space_signal_cap: info.stdout_space_signal_cap,
        stderr_data_signal_cap: info.stderr_data_signal_cap,
        stderr_space_signal_cap: info.stderr_space_signal_cap,
        log_discovery_cap: info.log_discovery_cap,
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
    };

    // SAFETY: single writer; we are the only code running at this point.
    unsafe { (*STARTUP.0.get()).write(startup) };
    STARTUP_READY.store(true, Ordering::Release);

    // Wire the three stdio pipes before the heap bootstrap. Each
    // direction takes (frame_cap, data_signal_cap, space_signal_cap);
    // zero frame caps are tolerated (writes silently drop / reads
    // return EOF), matching the "no pipe attached" state for processes
    // born without `Stdio::piped()`.
    pal_stdio::stdio_init(
        info.stdin_frame_cap,
        info.stdin_data_signal_cap,
        info.stdin_space_signal_cap,
        info.stdout_frame_cap,
        info.stdout_data_signal_cap,
        info.stdout_space_signal_cap,
        info.stderr_frame_cap,
        info.stderr_data_signal_cap,
        info.stderr_space_signal_cap,
        info.self_aspace_cap,
    );

    // Install the log discovery cap so `seraph::log!` can lazy-acquire
    // a tokened SEND cap on first call. Zero is tolerated (the macro
    // silently drops in processes without a logger).
    ::log::set_discovery_cap(info.log_discovery_cap);

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
            ::log::emit(
                current_ipc_buf(),
                format_args!(
                    "std::os::seraph: FATAL: heap_bootstrap failed (memmgr_ep={}); \
                     likely memmgr frame-pool exhaustion — aborting",
                    info.memmgr_endpoint_cap,
                ),
            );
            syscall::thread_exit();
        }
        // Wire the object-slab refill path against the same memmgr endpoint.
        // Cap-create syscalls retype memory out of a slab Frame cap acquired
        // lazily on first use.
        pal_alloc::object_slab_init(info.memmgr_endpoint_cap);
    }

    unsafe extern "C" {
        fn main(argc: isize, argv: *const *const u8) -> i32;
    }

    // SAFETY: `main` is rustc-synthesised for any bin crate that defines
    // `fn main` (i.e., not `#![no_main]`). It invokes `lang_start` and the
    // user's `fn main`.
    let _ = unsafe { main(0, core::ptr::null()) };

    // Tear down stdio pipes before exit so the close protocol fires
    // (header `closed` flag + signal kick) and any parent blocked on
    // a read/write returns cleanly.
    pal_stdio::close_all();

    syscall::thread_exit();
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
static _START_REF: unsafe extern "C" fn() -> ! = _start;

// ── Public helpers surfaced on std::os::seraph ──────────────────────────────

/// Initialise the process heap against procmgr.
///
/// Must be called once, after the bootstrap IPC round that obtains
/// `procmgr_ep`, before the first allocation through the `System`
/// allocator. Idempotent — subsequent calls are no-ops.
///
/// `self_aspace` is the process's own `AddressSpace` cap slot. The
/// bootstrap IPC round uses the calling thread's registered IPC buffer
/// (read from TLS via [`current_ipc_buf`]); `_start` populates that
/// slot before invoking `heap_bootstrap`.
///
/// Returns `true` if the heap is usable after this call.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn heap_bootstrap(procmgr_ep: u32, self_aspace: u32) -> bool {
    pal_alloc::heap_bootstrap(procmgr_ep, self_aspace)
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
// Tokened SEND on vfsd's namespace endpoint addressing the synthetic
// system root (`NodeId::ROOT`). `_start` reads
// `ProcessInfo.system_root_cap` and installs it here; namespace-walking
// code (`std::fs::File::open` once converted, plus any cap-native
// service code) reads it via [`root_dir_cap`]. Zero means "no system
// root attached" — the reading side degrades.

static ROOT_DIR_CAP: crate::sync::atomic::AtomicU32 =
    crate::sync::atomic::AtomicU32::new(0);

static CURRENT_DIR_CAP: crate::sync::atomic::AtomicU32 =
    crate::sync::atomic::AtomicU32::new(0);

/// Install the process-wide root-directory namespace cap. Called by
/// `_start` from `ProcessInfo.system_root_cap`. Demoted to crate-internal
/// visibility because the only legitimate writer is std's own startup
/// path; tier-2 callers must obtain a namespace cap through the spawner
/// (`procmgr_labels::CONFIGURE_NAMESPACE`), not by overwriting this slot.
pub(crate) fn set_root_dir_cap(cap: u32) {
    ROOT_DIR_CAP.store(cap, crate::sync::atomic::Ordering::Release);
}

/// Read the installed root-directory namespace cap, or zero if unset.
/// Used by namespace-walking code to anchor `NS_LOOKUP` walks.
#[must_use]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn root_dir_cap() -> u32 {
    ROOT_DIR_CAP.load(crate::sync::atomic::Ordering::Acquire)
}

/// Install the process-wide current-directory namespace cap. Called by
/// `_start` from `ProcessInfo.current_dir_cap` and by
/// `std::env::set_current_dir`; both writers are inside std. Tier-2
/// callers update cwd via `std::env::set_current_dir` (which performs
/// the namespace walk and stores the result here).
pub(crate) fn set_current_dir_cap(cap: u32) {
    CURRENT_DIR_CAP.store(cap, crate::sync::atomic::Ordering::Release);
}

/// Read the installed current-directory namespace cap, or zero if
/// unset. Used by relative-path resolution in `std::fs`.
#[must_use]
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn current_dir_cap() -> u32 {
    CURRENT_DIR_CAP.load(crate::sync::atomic::Ordering::Acquire)
}

/// Walk `path` from `root_dir_cap()` and install the resolved
/// directory cap as the process-wide current-directory cap.
///
/// The seraph-native cwd primitive: cwd is a held cap, not a string.
/// The existing cap (if any) is `cap_delete`'d and replaced.
///
/// `std::env::set_current_dir` is `Unsupported` on seraph because the
/// upstream API is path-as-string-only and cannot express the cap
/// model directly; this function is the seraph-specific shape.
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
    let prev = CURRENT_DIR_CAP.swap(walked.dir_cap, crate::sync::atomic::Ordering::AcqRel);
    if prev != 0 {
        let _ = syscall::cap_delete(prev);
    }
    Ok(())
}

/// Walk `path` from the supplied namespace cap via `NS_LOOKUP` and return
/// the resolved file's tokened SEND cap and its size hint.
///
/// Each non-final path component must resolve to a directory; the final
/// component must resolve to a file. The returned cap is freshly derived
/// — caller takes ownership and must `cap_delete` when done. On any
/// error no cap is returned.
///
/// Used by services that hold an attenuated namespace cap and need to
/// resolve a binary path before issuing `procmgr_labels::CREATE_FROM_FILE`.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn namespace_lookup_file(root_cap: u32, path: &str) -> crate::io::Result<(u32, u64)> {
    let ipc_buf = current_ipc_buf();
    if ipc_buf.is_null() {
        return Err(crate::io::Error::other("seraph: IPC buffer not registered"));
    }
    let walked = crate::sys::fs::walk_path_to_file(root_cap, path, ipc_buf)?;
    Ok((walked.file_cap, walked.size))
}

/// Return a Frame-cap slot suitable as the source for a `cap_create_*`
/// retype, with at least `min_bytes` of `available_bytes`.
///
/// `min_bytes` is the raw byte cost of the kernel object the caller is
/// about to create (e.g. 88 for `Endpoint`); the runtime rounds up to the
/// kernel's size-class granularity and debits a per-process local ledger.
/// The returned slot is reused across calls until exhausted, at which
/// point a fresh slab page is fetched from memmgr.
///
/// Returns `None` if memmgr is unreachable or refuses the request.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn object_slab_acquire(min_bytes: u64) -> Option<u32> {
    pal_alloc::object_slab_acquire(min_bytes)
}

// ── Page-reservation allocator ──────────────────────────────────────────────
//
// Re-exports from `crate::sys::reserve`. See that module for the per-process
// arena layout and concurrency model. Used for foreign Frame mappings —
// MMIO from devmgr, DMA buffers from drivers, shmem backings, zero-copy
// file pages from fs drivers, ELF-load scratch in procmgr — i.e. every
// page-granular VA need that is not the byte heap.

#[stable(feature = "seraph_ext", since = "1.0.0")]
pub use pal_reserve::{ReserveError, ReservedRange, reserve_pages, unreserve_pages};

// ── System log macro surface ────────────────────────────────────────────────
//
// The discovery cap installed at process create-time (recorded in
// `StartupInfo::log_discovery_cap` and forwarded to `::log::set_discovery_cap`
// during `_start`) drives a lazy `GET_LOG_CAP` round on first
// `seraph::log!` call; the tokened cap is then cached process-globally for
// the lifetime of the process.

/// System-log access surface. Re-exports the `shared/log` wire-format
/// helpers wrapped against the calling thread's registered IPC buffer.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub mod log {
    use super::current_ipc_buf;

    /// Acquire (or fetch the cached) tokened SEND cap on the system log
    /// endpoint. First call performs one `GET_LOG_CAP` round-trip;
    /// subsequent calls return the same cap from the process-global
    /// cache. Returns `0` when no discovery cap is reachable or the
    /// IPC buffer is not yet registered.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn acquire() -> u32 {
        ::log::ensure_tokened_cap(current_ipc_buf())
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
        let cap = ::log::ensure_tokened_cap(buf);
        ::log::register_name(cap, buf, name);
    }

    /// Macro entry point. Resolves the calling thread's IPC buffer and
    /// the process-global tokened cap, then formats `args` and emits
    /// one `STREAM_BYTES` message (split across IPC chunks if longer
    /// than 512 bytes). Silently drops when no log cap is acquirable.
    #[doc(hidden)]
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub fn __emit(args: core::fmt::Arguments<'_>) {
        ::log::emit(current_ipc_buf(), args);
    }
}

/// System-log macro. Formats and emits one log line on the process's
/// tokened SEND cap, lazy-acquired from the discovery cap on first
/// call. The receiver tags each line with the registered display name
/// (default `[?]`); see [`log::register_name`].
///
/// Non-allocating — uses a 512-byte stack buffer; messages exceeding
/// that are silently truncated.
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
// `std::os::seraph::StackNote` (a re-export of `process_abi::StackNote`),
// so std-using binaries can declare a custom main-thread stack without
// adding `process-abi` to their Cargo manifest.

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
    use crate::process::Command;
    use crate::sys::AsInnerMut;

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
        fn namespace_cap(&mut self, cap: u32) -> &mut Self;

        /// Override the cwd cap delivered to the child via
        /// `ProcessInfo.current_dir_cap`. Same lifetime contract as
        /// [`Self::namespace_cap`]. Without this call, the child's
        /// cwd cap is computed in `spawn` from (in priority order):
        /// the path stored by `Command::cwd`, or the spawner's own
        /// `current_dir_cap()`, or zero. Passing `0` reverts to that
        /// default chain.
        #[stable(feature = "seraph_ext", since = "1.0.0")]
        fn cwd_dir_cap(&mut self, cap: u32) -> &mut Self;
    }

    #[stable(feature = "seraph_ext", since = "1.0.0")]
    impl CommandExt for Command {
        fn namespace_cap(&mut self, cap: u32) -> &mut Command {
            self.as_inner_mut().set_namespace_cap(cap);
            self
        }

        fn cwd_dir_cap(&mut self, cap: u32) -> &mut Command {
            self.as_inner_mut().set_cwd_dir_cap(cap);
            self
        }
    }
}

