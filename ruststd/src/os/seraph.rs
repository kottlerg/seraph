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
use crate::sys::stdio::seraph as pal_stdio;

use process_abi::{PROCESS_ABI_VERSION, PROCESS_INFO_VADDR, process_info_ref};

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
    /// exists). `_start` consumes this to bootstrap the heap.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub procmgr_endpoint: u32,
    /// Cap backing `std::io::stdin`. Zero when no input stream is attached;
    /// reads return `Ok(0)` (EOF).
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdin_cap: u32,
    /// Cap backing `std::io::stdout`. Zero when no sink is attached; writes
    /// silently drop.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stdout_cap: u32,
    /// Cap backing `std::io::stderr`. Zero when no sink is attached; writes
    /// silently drop.
    #[stable(feature = "seraph_ext", since = "1.0.0")]
    pub stderr_cap: u32,
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
        stdin_cap: info.stdin_cap,
        stdout_cap: info.stdout_cap,
        stderr_cap: info.stderr_cap,
        tls_template_vaddr: info.tls_template_vaddr,
        tls_template_filesz: info.tls_template_filesz,
        tls_template_memsz: info.tls_template_memsz,
        tls_template_align: info.tls_template_align,
        args_blob,
        args_count: info.args_count as usize,
        env_blob,
        env_count: info.env_count as usize,
    };

    // SAFETY: single writer; we are the only code running at this point.
    unsafe { (*STARTUP.0.get()).write(startup) };
    STARTUP_READY.store(true, Ordering::Release);

    // Wire the three stdio caps before the heap bootstrap so any diagnostic
    // emitted by bootstrap failure is visible. Zero slots are tolerated
    // (writes silently drop / reads return EOF), matching the "no stream
    // attached yet" state during very-early boot.
    pal_stdio::stdio_init(
        info.stdin_cap,
        info.stdout_cap,
        info.stderr_cap,
    );

    // Bootstrap the heap so `fn main()` can allocate from its first line
    // (lazy `LineWriter` behind `std::io::stdout`, `String::new`, any `Vec`
    // push, etc.). Zero `procmgr_endpoint_cap` means we are procmgr itself
    // or something earlier in the chain; such processes manage their own
    // storage and do not use std collections.
    //
    // Hard-fail with a visible diagnostic when bootstrap attempts to run
    // but procmgr refuses (frame-pool exhaustion is the common cause). An
    // uninitialised heap surfaces later as a cryptic `handle_alloc_error`
    // deep inside `lang_start`; exiting here puts the failure in context.
    if info.procmgr_endpoint_cap != 0 {
        let ok = pal_alloc::heap_bootstrap(
            info.procmgr_endpoint_cap,
            info.self_aspace_cap,
        );
        if !ok {
            diag_writeln_args(format_args!(
                "std::os::seraph: FATAL: heap_bootstrap failed (procmgr_ep={}); \
                 likely procmgr frame-pool exhaustion — aborting",
                info.procmgr_endpoint_cap,
            ));
            syscall::thread_exit();
        }
    }

    unsafe extern "C" {
        fn main(argc: isize, argv: *const *const u8) -> i32;
    }

    // SAFETY: `main` is rustc-synthesised for any bin crate that defines
    // `fn main` (i.e., not `#![no_main]`). It invokes `lang_start` and the
    // user's `fn main`.
    let _ = unsafe { main(0, core::ptr::null()) };

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

/// Write pre-formatted bytes directly to the stderr cap (falling back to
/// stdout if stderr is unset), bypassing `std::io::stdout`'s `LineWriter`.
/// Intended for services that cannot guarantee a live heap when they need
/// to emit diagnostics: the standard `println!` path lazily allocates a
/// 1 KiB line-buffer on first use, which fails for processes that do not
/// bootstrap the heap.
///
/// Silently dropped if `_start` has not yet wired the stdio caps.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn diag_write(bytes: &[u8]) {
    pal_stdio::diag_write_raw(bytes);
}

/// Register a display name for this process's log stream with the system
/// log mediator. Opt-in — services that want their log lines to appear
/// under a specific `[name]` prefix call this once at startup (or again
/// to update the name with runtime context, e.g. a mountpoint).
///
/// Non-logging services should not call this: the mediator only observes
/// senders whose stdout cap points at the log endpoint, and the mediator
/// is the only receiver that interprets `STREAM_REGISTER_NAME`. Sending
/// this message to an unrelated stdout sink (a pipe, a terminal) would
/// appear as arbitrary bytes in that sink.
///
/// Silently dropped if the process has no stdout cap or the IPC buffer
/// is not yet registered.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn register_log_name(name: &[u8]) {
    pal_stdio::register_log_name_raw(name);
}

/// Format `args` into a 512-byte stack buffer and emit through
/// [`diag_write`], appending a trailing newline. Non-allocating — callers
/// without a live heap can use this in place of `eprintln!`. Messages
/// exceeding 511 bytes are truncated.
#[stable(feature = "seraph_ext", since = "1.0.0")]
pub fn diag_writeln_args(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write;

    struct StackBuf {
        data: [u8; 512],
        used: usize,
    }

    impl Write for StackBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let remaining = self.data.len() - self.used;
            let n = remaining.min(s.len());
            self.data[self.used..self.used + n].copy_from_slice(&s.as_bytes()[..n]);
            self.used += n;
            if n < s.len() { Err(core::fmt::Error) } else { Ok(()) }
        }
    }

    let mut buf = StackBuf { data: [0; 512], used: 0 };
    let _ = buf.write_fmt(args);
    // Newline best-effort; if buf is full we drop it to keep the useful prefix.
    if buf.used < buf.data.len() {
        buf.data[buf.used] = b'\n';
        buf.used += 1;
    }
    pal_stdio::diag_write_raw(&buf.data[..buf.used]);
}
