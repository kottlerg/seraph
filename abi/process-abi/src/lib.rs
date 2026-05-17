// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/process-abi/src/lib.rs

//! Userspace process startup ABI: the binary contract between a process creator
//! and the created process.
//!
//! Defines [`ProcessInfo`] (the `#[repr(C)]` handover struct placed at a
//! well-known virtual address before the new process runs) and [`StartupInfo`]
//! (the Rust-native type passed to `main()`).
//!
//! The ABI delivers the kernel-object caps (thread/aspace/cspace), the
//! pre-mapped IPC buffer, the creator endpoint cap, the procmgr service
//! endpoint (used to bootstrap the allocator), and the three standard-stream
//! caps (stdin/stdout/stderr) that back `std::io`. Genuinely service-specific
//! capabilities (registry handles, device caps, block-device endpoints, etc.)
//! are still requested by the child at startup over IPC on the creator
//! endpoint — see `shared/ipc/src/lib.rs::bootstrap`.

// Under `rustc-dep-of-std` (build-std), use the core facade and no_core
// so this crate can sit inside std's dep graph. Mirrors abi/syscall and
// shared/ipc. Normal userspace builds (no feature) retain `#![no_std]`.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

// ── Protocol version ─────────────────────────────────────────────────────────

/// Process ABI version. Incremented on any breaking change to the
/// [`ProcessInfo`] layout or field semantics.
pub const PROCESS_ABI_VERSION: u32 = 15;

// ── Address space constants ──────────────────────────────────────────────────

/// Virtual address where procmgr maps the read-only [`ProcessInfo`] page in
/// every new process's address space.
pub const PROCESS_INFO_VADDR: u64 = 0x0000_7FFF_FFFF_0000;

/// Virtual address of the top of a normal process's user stack.
///
/// `ProcessInfo.stack_pages` pages are mapped immediately below this
/// address. One additional guard page (unmapped) sits below the stack.
pub const PROCESS_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// Default main-thread stack size in 4 KiB pages (32 KiB total).
///
/// Loaders use this when the binary does not declare a custom size via
/// the `.note.seraph.stack` ELF note. Binaries with deeper stack
/// pressure (memmgr's bootstrap parser, future fs-cache workers)
/// declare a larger value through the `elf::stack_pages!` macro.
pub const DEFAULT_PROCESS_STACK_PAGES: u32 = 8;

/// Hard cap on the declared main-thread stack size, in 4 KiB pages.
///
/// Loaders clamp the note value to this bound before allocation;
/// memmgr's existing per-process quota remains the actual policy gate.
/// 256 pages = 1 MiB — far above any realistic in-tree need, sized to
/// catch a corrupt or hostile note rather than to ration memory.
pub const MAX_PROCESS_STACK_PAGES: u32 = 256;

// ── Stack-size ELF note (`.note.seraph.stack`) ──────────────────────────────
//
// Binary-side declaration: every binary may emit one custom ELF note
// declaring its desired main-thread stack size. Loaders (init, procmgr)
// read the note when loading the binary and substitute the declared
// value for [`DEFAULT_PROCESS_STACK_PAGES`].
//
// The format lives in `process-abi` rather than `shared/elf` because
// it is a contract between binary producers and the spawner, in the
// same shape as `ProcessInfo` — binaries opt in via the
// [`stack_pages!`] macro which expands to a `#[link_section]` static of
// type [`StackNote`]. `shared/elf` consumes these constants on the
// loader side via `parse_stack_note` / `parse_stack_note_streaming`.
//
// Standard ELF note layout: a header (`namesz`, `descsz`, `ntype`)
// followed by `name` (padded to 4-byte alignment) and `desc` (likewise).
// For this note: `namesz = 7`, `descsz = 8`, `ntype = NT_SERAPH_STACK`,
// `name = b"seraph\0\0"` (7 bytes + 1 align padding), `desc =
// StackNoteDesc { pages, reserved: 0 }`.

/// Vendor name for Seraph-specific ELF notes. Seven bytes plus the
/// terminating NUL, then one padding byte to 8-byte alignment for the
/// descriptor that follows.
pub const SERAPH_NOTE_NAME: [u8; 8] = *b"seraph\0\0";

/// Note type for the main-thread stack-size declaration.
pub const NT_SERAPH_STACK: u32 = 1;

/// Section name carrying the stack-size note.
pub const SERAPH_STACK_NOTE_SECTION: &str = ".note.seraph.stack";

/// Descriptor bytes for the stack-size note. Eight bytes, naturally
/// 4-byte aligned so no trailing pad is required.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StackNoteDesc
{
    /// Declared main-thread stack size in 4 KiB pages.
    pub pages: u32,
    /// Reserved for future flags. Must be zero on emit; ignored on parse.
    pub reserved: u32,
}

/// Full on-disk repr of the Seraph stack-size note. Place into
/// `.note.seraph.stack` via the [`stack_pages!`] macro; loaders
/// recognise it by section name and the embedded `name`/`ntype` fields.
#[repr(C)]
pub struct StackNote
{
    /// Length of `name` (must be 7 for `b"seraph\0"`).
    pub namesz: u32,
    /// Length of `desc` (must be 8 for `StackNoteDesc`).
    pub descsz: u32,
    /// Note type (`NT_SERAPH_STACK`).
    pub ntype: u32,
    /// Vendor name, NUL-terminated and padded to 4-byte alignment.
    pub name: [u8; 8],
    /// Stack size descriptor.
    pub desc: StackNoteDesc,
}

impl StackNote
{
    /// Build a stack-size note declaring the given page count.
    #[must_use]
    pub const fn new(pages: u32) -> Self
    {
        Self {
            namesz: 7,
            descsz: 8,
            ntype: NT_SERAPH_STACK,
            name: SERAPH_NOTE_NAME,
            desc: StackNoteDesc { pages, reserved: 0 },
        }
    }
}

/// Declare the main-thread stack size for this binary as `$pages` 4 KiB
/// pages. Expands to a `#[used]` static placed in
/// `.note.seraph.stack`; loaders (init, procmgr) read it before mapping
/// the child's stack. Binaries that omit the macro inherit
/// [`DEFAULT_PROCESS_STACK_PAGES`].
///
/// Usable from any crate that depends on `process-abi` (every Seraph
/// userspace component already does, directly or indirectly through
/// std). std re-exports it as `seraph::stack_pages!` for ergonomic use
/// from std-built binaries.
#[macro_export]
macro_rules! stack_pages {
    ($pages:expr) => {
        #[used]
        #[unsafe(link_section = ".note.seraph.stack")]
        static __SERAPH_STACK_NOTE: $crate::StackNote = $crate::StackNote::new($pages);
    };
}

/// Virtual address of the main thread's TLS block in a normal process.
///
/// Procmgr allocates and populates the block at creation time. For processes
/// without a `PT_TLS` segment this region remains unmapped. Placed below
/// [`CHILD_IPC_BUF_VADDR`] so it does not collide with the stack or the
/// `ProcessInfo` page.
pub const PROCESS_MAIN_TLS_VADDR: u64 = 0x0000_7FFF_FFFD_0000;

/// Maximum number of 4 KiB pages reserved for the main thread's TLS block.
///
/// Procmgr rejects binaries whose TLS block exceeds this size. Spawned
/// threads allocate their own blocks from the heap and are unconstrained by
/// this limit.
pub const PROCESS_MAIN_TLS_MAX_PAGES: u64 = 4;

// ── ProcessInfo ──────────────────────────────────────────────────────────────

/// Creator-to-process handover structure.
///
/// Placed at [`PROCESS_INFO_VADDR`] (one 4 KiB page, read-only) before the
/// new process begins execution.
///
/// All slot indices refer to the process's own `CSpace`. Beyond the kernel-
/// object self-caps, the creator endpoint, the procmgr endpoint, and the
/// three standard-stream caps, no further service-specific capabilities are
/// delivered through this page — the child requests them from its creator
/// over IPC at startup (see `ipc::bootstrap`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessInfo
{
    /// Protocol version. Must equal [`PROCESS_ABI_VERSION`].
    pub version: u32,

    /// `CSpace` slot of the process's own Thread capability (Control right).
    pub self_thread_cap: u32,

    /// `CSpace` slot of the process's own `AddressSpace` capability.
    pub self_aspace_cap: u32,

    /// `CSpace` slot of the process's own `CSpace` capability.
    pub self_cspace_cap: u32,

    /// Virtual address of the pre-mapped IPC buffer page.
    ///
    /// Every thread requires a registered IPC buffer for extended message
    /// payloads. The creator maps this page and records it here; the process
    /// calls `SYS_IPC_BUFFER_SET` with this address on startup.
    pub ipc_buffer_vaddr: u64,

    /// `CSpace` slot of a tokened IPC endpoint back to the creating service's
    /// bootstrap handler.
    ///
    /// The child calls `ipc::bootstrap::REQUEST` on this endpoint in a loop to
    /// receive its service-specific capability set. Zero if no creator
    /// endpoint is provided (child operates without bootstrap caps).
    pub creator_endpoint_cap: u32,

    /// `CSpace` slot of a tokened SEND cap on procmgr's service endpoint.
    ///
    /// Used for process-lifecycle queries (`QUERY_PROCESS`,
    /// `DESTROY_PROCESS`, future supervision RPCs) and for any future
    /// procmgr-served operation that is not heap-bootstrap.
    ///
    /// Zero when no procmgr is reachable (procmgr itself, init, anything
    /// before procmgr exists). Consumers must tolerate zero.
    pub procmgr_endpoint_cap: u32,

    /// `CSpace` slot of a tokened SEND cap on memmgr's service endpoint.
    ///
    /// Every std-built process needs this to bootstrap its heap via
    /// `memmgr_labels::REQUEST_FRAMES`. `std::os::seraph::_start` reads
    /// this slot and initialises the allocator before `lang_start` runs,
    /// so idiomatic `fn main()` code can allocate from the very first
    /// statement. The tokened cap identifies the holder to memmgr's
    /// per-process tracking, so allocations are accounted to the correct
    /// process.
    ///
    /// Zero when no memmgr is reachable (memmgr itself, init, anything
    /// before memmgr exists). Consumers must tolerate zero.
    pub memmgr_endpoint_cap: u32,

    /// `CSpace` slot of a SEND cap on svcmgr's service endpoint, used
    /// as the system-wide service-discovery handle. The cap's token
    /// carries only the child's per-process token — without the
    /// `svcmgr_labels::PUBLISH_AUTHORITY` verb-bit — so svcmgr accepts
    /// `QUERY_ENDPOINT` from it but rejects `PUBLISH_ENDPOINT` with
    /// `svcmgr_errors::UNAUTHORIZED`. See `docs/capability-model.md`
    /// "verb-bit authority pattern".
    ///
    /// Every process reads this slot and uses it (via the
    /// `registry-client` crate) to resolve a service name to a SEND cap
    /// on that service's endpoint. The publish-authority caps are held
    /// by init, devmgr, and svcmgr itself — not by callers of this cap.
    ///
    /// This is the **only** service-discovery slot in `ProcessInfo`.
    /// New services do not get their own dedicated slot; they are
    /// resolved by name through this single handle. The deprecated
    /// `log_send_cap` below predates this convention and will be
    /// migrated to the same mechanism in a separate PR.
    ///
    /// Zero when no svcmgr is reachable (svcmgr itself, init, anything
    /// before svcmgr exists). Consumers must tolerate zero.
    pub service_registry_cap: u32,

    /// `CSpace` slot of the shmem frame cap backing `std::io::stdin`.
    ///
    /// One 4 KiB page laid out as `shmem::SpscHeader` followed by a
    /// power-of-two byte ring. The frame is shared with the spawner; the
    /// spawner is the writer (parent → child), the child is the reader.
    /// Wakeup signals live in `stdin_data_signal_cap` (writer-kicks-reader)
    /// and `stdin_space_signal_cap` (reader-kicks-writer); EOF rides on the
    /// header's `closed` flag plus a final signal kick.
    ///
    /// Zero means "no stdin attached"; reads return `Ok(0)` (EOF)
    /// immediately. The standard case for services spawned by init.
    pub stdin_frame_cap: u32,

    /// `CSpace` slot of the shmem frame cap backing `std::io::stdout`.
    ///
    /// Same layout as `stdin_frame_cap` but with the child as the writer
    /// (child → parent) and the spawner as the reader. Wakeup pair is
    /// `stdout_data_signal_cap` / `stdout_space_signal_cap`.
    ///
    /// Zero when no sink is attached; writes are silently dropped.
    pub stdout_frame_cap: u32,

    /// `CSpace` slot of the shmem frame cap backing `std::io::stderr`.
    ///
    /// Same shape as `stdout_frame_cap`; an independent ring so stdout and
    /// stderr stream separately. Wakeup pair is `stderr_data_signal_cap` /
    /// `stderr_space_signal_cap`. Zero means writes are silently dropped.
    pub stderr_frame_cap: u32,

    // ── Thread-local storage template ──────────────────────────────────
    //
    // Set by the creator from the `PT_TLS` program header in the child's
    // ELF image. Every thread (main and spawned) has its own TLS block
    // that is populated by copying `tls_template_filesz` bytes from
    // `tls_template_vaddr`, zero-padding up to `tls_template_memsz`, and
    // aligning the block to `tls_template_align`.
    //
    // For the main thread, the creator allocates and populates the block
    // before `SYS_THREAD_CONFIGURE` and passes the TLS base directly, so
    // startup does not need to re-do this. The template fields are
    // retained here for subsequent `std::thread::spawn` invocations.
    //
    // `tls_template_memsz == 0` means the binary has no `PT_TLS` segment
    // and the process does not use thread-local storage.
    /// Virtual address of the `PT_TLS` template in the loaded image.
    pub tls_template_vaddr: u64,

    /// Size of the initialized portion of the template (`.tdata`).
    pub tls_template_filesz: u64,

    /// Total size of the template (`.tdata` + `.tbss`).
    pub tls_template_memsz: u64,

    /// Required alignment of the per-thread TLS block.
    pub tls_template_align: u64,

    // ── Program arguments (argv) ─────────────────────────────────────
    //
    // Procmgr writes the argv blob into this same `ProcessInfo` page
    // after the struct fields, between `args_offset` and `args_offset +
    // args_bytes`. The blob is a concatenation of `args_count`
    // NUL-terminated UTF-8 strings. `args_offset == 0` OR `args_count ==
    // 0` means "no argv delivered".
    //
    // Argv is bounded by what fits in the remainder of the ProcessInfo
    // page after the fixed struct. Procmgr rejects oversized blobs.
    /// Byte offset from the `ProcessInfo` page base where the argv blob
    /// begins. 0 when no argv was provided.
    pub args_offset: u32,

    /// Total byte length of the argv blob.
    pub args_bytes: u32,

    /// Number of argv entries (NUL-terminated strings) in the blob.
    pub args_count: u32,

    // ── Environment variables (env) ──────────────────────────────────
    //
    // Procmgr writes the env blob into this `ProcessInfo` page after the
    // argv blob, between `env_offset` and `env_offset + env_bytes`. The
    // blob is a concatenation of `env_count` NUL-terminated UTF-8 strings,
    // each of shape `KEY=VALUE`. `env_offset == 0` OR `env_count == 0`
    // means "no env delivered". Same page-remainder bound as argv.
    /// Byte offset from the `ProcessInfo` page base where the env blob
    /// begins. 0 when no env was provided.
    pub env_offset: u32,

    /// Total byte length of the env blob.
    pub env_bytes: u32,

    /// Number of env entries (NUL-terminated `KEY=VALUE` strings) in the blob.
    pub env_count: u32,

    /// `CSpace` slot of a tokened SEND cap on a namespace endpoint
    /// addressing the directory the process should treat as its
    /// system root. Anchors absolute-path resolution.
    ///
    /// Source: the spawner's `procmgr_labels::CONFIGURE_NAMESPACE`
    /// call. Procmgr `cap_copy`s the supplied cap into the child's
    /// `CSpace` at `START_PROCESS` time. Zero when no spawner-
    /// supplied cap was delivered — the child has no namespace
    /// authority and consumers (`std::fs`, namespace-walking code)
    /// must tolerate zero by returning `Unsupported`.
    pub system_root_cap: u32,

    /// `CSpace` slot of a tokened SEND cap on a namespace endpoint
    /// addressing the directory the process should treat as its initial
    /// current working directory. Anchors relative-path resolution.
    ///
    /// Independent of [`Self::system_root_cap`] — typically a derivative
    /// of it (e.g. `NS_LOOKUP("/srv")` against the root cap), but the
    /// kernel imposes no relationship. Zero means "no cwd attached";
    /// std treats relative paths as `Unsupported` until a non-zero cap
    /// is installed (e.g. via `std::env::set_current_dir`).
    pub current_dir_cap: u32,

    /// `CSpace` slot of a tokened SEND cap on the system log endpoint
    /// suitable for direct `STREAM_BYTES` / `STREAM_REGISTER_NAME`
    /// use.
    ///
    /// Procmgr derives this cap per spawn via `cap_derive_token` on
    /// the log endpoint it holds, using the child's procmgr-assigned
    /// token as the cap's token. Logd sees the same token on every
    /// IPC the child makes, keys its per-sender slot map by it, and
    /// matches it directly against the death-notification correlator
    /// procmgr posts on child exit.
    ///
    /// Zero when no logger is reachable (init, memmgr, procmgr
    /// themselves; processes spawned before the log endpoint exists).
    /// `seraph::log!` silently drops in that case.
    pub log_send_cap: u32,

    // ── Stdio pipe wakeup signals ──────────────────────────────────────
    //
    // Each piped direction gets two signal caps:
    //   * `data_signal`  — writer kicks reader after producing bytes;
    //                      reader awaits this when the ring is empty.
    //   * `space_signal` — reader kicks writer after consuming bytes;
    //                      writer awaits this when the ring is full.
    //
    // Both processes hold caps to both signals (kernel signal objects do
    // not distinguish send/wait rights at the cap level). Single-waiter
    // invariant holds because at most one side blocks on each signal at
    // any given moment.
    //
    // Zero in any slot means the corresponding signal is not attached;
    // the AnonPipe peer treats `signal_wait` as a no-op and falls back
    // to spinning on the ring header (used during silent-drop init when
    // a frame cap is also zero).
    /// Data-available signal for the stdin pipe. Writer-kicked.
    pub stdin_data_signal_cap: u32,
    /// Space-available signal for the stdin pipe. Reader-kicked.
    pub stdin_space_signal_cap: u32,
    /// Data-available signal for the stdout pipe. Writer-kicked.
    pub stdout_data_signal_cap: u32,
    /// Space-available signal for the stdout pipe. Reader-kicked.
    pub stdout_space_signal_cap: u32,
    /// Data-available signal for the stderr pipe. Writer-kicked.
    pub stderr_data_signal_cap: u32,
    /// Space-available signal for the stderr pipe. Reader-kicked.
    pub stderr_space_signal_cap: u32,

    // ── Main-thread stack envelope ─────────────────────────────────────
    //
    // Loaders pick the stack size per-binary (see `.note.seraph.stack`)
    // and write the resulting envelope here. Children that want to
    // introspect their own stack range (overflow diagnostics, future
    // crash dumpers) read these fields. `stack_top_vaddr` is the value
    // of the SP register at thread entry; the live mapping covers
    // `[stack_top_vaddr - stack_pages * PAGE_SIZE, stack_top_vaddr)`.
    /// Virtual address of the top of the main-thread stack.
    pub stack_top_vaddr: u64,

    /// Number of 4 KiB pages mapped for the main-thread stack.
    pub stack_pages: u32,
}

// ── StartupInfo ──────────────────────────────────────────────────────────────

/// Rust-native startup information passed to `main()`.
///
/// Constructed by `_start()` from [`ProcessInfo`].
pub struct StartupInfo
{
    /// Virtual address of the IPC buffer page.
    pub ipc_buffer: *mut u8,

    /// `CSpace` slot of the creator endpoint. Zero if none.
    pub creator_endpoint: u32,

    /// `CSpace` slot of own Thread capability.
    pub self_thread: u32,

    /// `CSpace` slot of own `AddressSpace` capability.
    pub self_aspace: u32,

    /// `CSpace` slot of own `CSpace` capability.
    pub self_cspace: u32,

    /// `CSpace` slot of a tokened SEND cap on procmgr's service endpoint.
    /// Zero when unreachable (procmgr itself, or earlier in the boot chain).
    pub procmgr_endpoint: u32,

    /// `CSpace` slot of a tokened SEND cap on memmgr's service endpoint.
    /// Used by `std::os::seraph::_start` to bootstrap the heap allocator.
    /// Zero when unreachable (memmgr itself, init, or earlier in the boot
    /// chain).
    pub memmgr_endpoint: u32,

    /// `CSpace` slot of a SEND cap on svcmgr's service endpoint, the
    /// system-wide service-discovery handle. The cap's token lacks the
    /// `svcmgr_labels::PUBLISH_AUTHORITY` verb-bit, so it answers
    /// `QUERY_ENDPOINT` only. `registry-client::lookup(name)` issues
    /// the QUERY against this cap. Zero when svcmgr is not reachable.
    /// See `ProcessInfo::service_registry_cap` for the long form.
    pub service_registry_cap: u32,

    /// `CSpace` slot of the stdin shmem frame cap. Zero when no input
    /// pipe is attached.
    pub stdin_frame_cap: u32,

    /// `CSpace` slot of the stdout shmem frame cap. Zero when no sink
    /// is attached.
    pub stdout_frame_cap: u32,

    /// `CSpace` slot of the stderr shmem frame cap. Zero when no sink
    /// is attached.
    pub stderr_frame_cap: u32,

    /// Tokened SEND cap on vfsd's namespace endpoint addressing the
    /// synthetic system root. Zero when vfsd is not reachable. See
    /// `ProcessInfo::system_root_cap`.
    pub system_root_cap: u32,

    /// Tokened SEND cap on a namespace endpoint addressing the initial
    /// current working directory. Zero means relative-path resolution
    /// is unsupported until the process sets one. See
    /// `ProcessInfo::current_dir_cap`.
    pub current_dir_cap: u32,

    /// Wakeup signal caps for the three stdio pipes. Zero when the
    /// corresponding direction is not piped. See `ProcessInfo` for the
    /// full data-vs-space and writer-vs-reader semantics.
    pub stdin_data_signal_cap: u32,
    pub stdin_space_signal_cap: u32,
    pub stdout_data_signal_cap: u32,
    pub stdout_space_signal_cap: u32,
    pub stderr_data_signal_cap: u32,
    pub stderr_space_signal_cap: u32,

    /// Virtual address of the `PT_TLS` template in the loaded image.
    /// `tls_template_memsz == 0` signals that the process has no TLS.
    pub tls_template_vaddr: u64,

    /// Size of the initialized portion of the template (`.tdata`).
    pub tls_template_filesz: u64,

    /// Total size of the template (`.tdata` + `.tbss`).
    pub tls_template_memsz: u64,

    /// Required alignment of the per-thread TLS block.
    pub tls_template_align: u64,

    /// Raw argv blob — a concatenation of `args_count` NUL-terminated
    /// UTF-8 strings, total length `args_bytes`. Empty slice when no
    /// argv was provided.
    pub args_blob: &'static [u8],

    /// Number of argv entries in [`Self::args_blob`].
    pub args_count: usize,

    /// Raw env blob — a concatenation of `env_count` NUL-terminated
    /// UTF-8 strings of shape `KEY=VALUE`. Empty slice when no env was
    /// provided.
    pub env_blob: &'static [u8],

    /// Number of env entries in [`Self::env_blob`].
    pub env_count: usize,

    /// Virtual address of the top of the main-thread stack — the value
    /// of SP at thread entry. Live mapping covers
    /// `[stack_top_vaddr - stack_pages * PAGE_SIZE, stack_top_vaddr)`.
    pub stack_top_vaddr: u64,

    /// Number of 4 KiB pages mapped for the main-thread stack.
    pub stack_pages: u32,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Cast a page-aligned virtual address to a `ProcessInfo` reference.
///
/// Encapsulates the `u64 → *const ProcessInfo` cast with alignment validation,
/// eliminating per-site `#[allow(clippy::cast_ptr_alignment)]` annotations.
///
/// # Safety
///
/// `va` must point to a valid, mapped [`ProcessInfo`] page. The page must
/// remain mapped for the lifetime of the returned reference.
#[must_use]
pub unsafe fn process_info_ref(va: u64) -> &'static ProcessInfo
{
    debug_assert!(va.is_multiple_of(4096), "ProcessInfo VA not page-aligned");
    // SAFETY: caller guarantees va points to a valid, mapped ProcessInfo page.
    // cast_ptr_alignment: va is page-aligned (4096-byte), exceeding
    // ProcessInfo's alignment requirement.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        &*(va as *const ProcessInfo)
    }
}

/// Cast a page-aligned virtual address to a mutable `ProcessInfo` reference.
///
/// # Safety
///
/// `va` must point to a writable, page-aligned mapping of a [`ProcessInfo`]
/// page. The page must remain mapped for the lifetime of the returned
/// reference.
#[must_use]
pub unsafe fn process_info_mut(va: u64) -> &'static mut ProcessInfo
{
    debug_assert!(va.is_multiple_of(4096), "ProcessInfo VA not page-aligned");
    // SAFETY: caller guarantees va points to a writable, mapped ProcessInfo
    // page. cast_ptr_alignment: va is page-aligned (4096-byte).
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        &mut *(va as *mut ProcessInfo)
    }
}

// ── TLS block layout ────────────────────────────────────────────────────────
//
// Shared by procmgr (main thread) and the std thread-spawn path (children of
// the main thread). Encapsulates the two TLS-layout variants Seraph supports:
//
//   * x86-64 Variant II — [tdata|tbss|TCB]; thread pointer points at TCB;
//     a self-pointer lives at `*tp`; variables live at negative offsets
//     from `tp`.
//   * RISC-V Variant I — [tdata|tbss]; thread pointer points at the start
//     of the block; no TCB header.
//
// The helper returns the total block size, required alignment of the
// allocation, and the byte offset from the block start at which the thread
// pointer (`IA32_FS_BASE` on x86-64, `tp` on RISC-V) should point.

/// Describe the TLS block layout for the running target architecture.
///
/// `memsz` is the `PT_TLS` `p_memsz` field (sum of `.tdata` + `.tbss`);
/// `align` is `p_align` (minimum 1). Returns `(block_size, block_align,
/// tls_base_offset)` — the caller allocates `block_size` bytes aligned to
/// `block_align`, copies `p_filesz` bytes of template data starting at
/// `block + 0`, zeros the remaining bytes up to `block + memsz`, and treats
/// `tls_base = block_ptr + tls_base_offset` as the value passed to
/// `SYS_THREAD_CONFIGURE`'s fifth argument.
#[must_use]
pub fn tls_block_layout(memsz: u64, align: u64) -> (u64, u64, u64)
{
    let align = if align == 0 { 1 } else { align };

    #[cfg(target_arch = "x86_64")]
    {
        // Variant II: [tdata|tbss|TCB]; thread pointer (fs_base) points at
        // the TCB; variables at negative TPOFF offsets. LLD computes each
        // TLS symbol's TPOFF as `sym_offset - align_up(memsz, p_align)`, so
        // `tls_base_offset` here MUST equal `align_up(memsz, p_align)` for
        // `%fs:TPOFF` accesses to resolve to the right byte. Forcing a
        // larger alignment (e.g. 16) shifts the TCB relative to the block
        // but leaves the linker's TPOFFs unchanged, producing an off-by-
        // alignment skew that corrupts TLS reads whenever memsz is not a
        // multiple of the larger alignment. The block allocation itself is
        // u64-aligned (8 bytes) so the TCB self-pointer is a valid aligned
        // 8-byte slot.
        let tdata_aligned = (memsz + align - 1) & !(align - 1);
        let tcb_size: u64 = 16;
        let block_align = align.max(8);
        (tdata_aligned + tcb_size, block_align, tdata_aligned)
    }
    #[cfg(target_arch = "riscv64")]
    {
        // Variant I: tp = block start. No TCB header.
        let tls_align = if align < 8 { 8 } else { align };
        let block = (memsz + tls_align - 1) & !(tls_align - 1);
        (block, tls_align, 0)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    {
        let _ = (memsz, align);
        (0, 1, 0)
    }
}

/// Install the architecture-specific TCB metadata in a freshly populated
/// TLS block. On x86-64, writes the self-pointer at `block_ptr +
/// tls_base_offset`. No-op on RISC-V.
///
/// # Safety
/// `block_ptr` must point to a writable block of at least `tls_base_offset +
/// 8` bytes.
// cast_ptr_alignment: `tcb` is produced by offsetting a caller-allocated
// block. `tls_block_layout` guarantees the block is at least 8-byte
// aligned and `tls_base_offset = align_up(memsz, p_align)` preserves
// that alignment (p_align is at least 1; practical Rust TLS templates
// use p_align >= 8). `write_unaligned` is used defensively regardless.
// cast_possible_truncation: Seraph is 64-bit only; u64 → usize is lossless.
#[allow(clippy::cast_ptr_alignment, clippy::cast_possible_truncation)]
pub unsafe fn tls_install_tcb(block_ptr: *mut u8, tls_base_offset: u64, tls_base_va: u64)
{
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: caller guarantees block has capacity for a u64 at
        // tls_base_offset. write_unaligned tolerates any address alignment.
        unsafe {
            let tcb = block_ptr.add(tls_base_offset as usize).cast::<u64>();
            tcb.write_unaligned(tls_base_va);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (block_ptr, tls_base_offset, tls_base_va);
    }
}
