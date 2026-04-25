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
pub const PROCESS_ABI_VERSION: u32 = 8;

// ── Address space constants ──────────────────────────────────────────────────

/// Virtual address where procmgr maps the read-only [`ProcessInfo`] page in
/// every new process's address space.
pub const PROCESS_INFO_VADDR: u64 = 0x0000_7FFF_FFFF_0000;

/// Virtual address of the top of a normal process's user stack.
///
/// `PROCESS_STACK_PAGES` pages are mapped immediately below this address.
/// One additional guard page (unmapped) sits below the stack.
pub const PROCESS_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// Number of 4 KiB pages in a normal process's user stack (16 KiB total).
pub const PROCESS_STACK_PAGES: usize = 4;

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
    /// Every std-built process needs this to bootstrap its heap via
    /// `REQUEST_FRAMES`. `std::os::seraph::_start` reads this slot and
    /// initialises the allocator before `lang_start` runs, so idiomatic
    /// `fn main()` code can allocate from the very first statement.
    ///
    /// Zero when no procmgr is reachable (procmgr itself, init, anything
    /// before procmgr exists). Consumers must tolerate zero.
    pub procmgr_endpoint_cap: u32,

    /// `CSpace` slot of the cap backing `std::io::stdin`.
    ///
    /// Receive-side of a byte-stream endpoint. `std::io::stdin().read(buf)`
    /// performs `ipc_recv` on this cap to obtain the next chunk written by
    /// the spawner (or its delegate). Zero means "no input attached"; reads
    /// return `Ok(0)` (EOF) immediately. The standard case for services
    /// spawned by init.
    pub stdin_cap: u32,

    /// `CSpace` slot of the cap backing `std::io::stdout`.
    ///
    /// SEND side of a byte-stream endpoint. `std::io::stdout().write(buf)`
    /// performs `ipc_call` on this cap with `STREAM_BYTES` label and the
    /// bytes packed into IPC data words. The receiver decides what to do
    /// with the bytes — current spawners (init/svcmgr) point this at the
    /// log endpoint with a per-service token, so a log daemon can attribute
    /// output without on-wire self-identification.
    ///
    /// Zero when no sink is attached (very early boot); writes are silently
    /// dropped, matching `unsupported` stdio semantics.
    pub stdout_cap: u32,

    /// `CSpace` slot of the cap backing `std::io::stderr`.
    ///
    /// Same shape as `stdout_cap`. Spawners may point it at the same
    /// endpoint as `stdout_cap` (current default) or at a different sink for
    /// stream-separated diagnostics. Zero means writes are silently dropped.
    pub stderr_cap: u32,

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

    /// `CSpace` slot of an un-tokened SEND cap on the system log endpoint
    /// (the *discovery* cap).
    ///
    /// Used by the `seraph::log!` macro path to lazy-acquire a tokened
    /// SEND cap on first call, via the `log_labels::GET_LOG_CAP` IPC. The
    /// discovery cap by itself grants no identity and no observability —
    /// it merely lets the holder request a freshly-minted tokened cap.
    /// Distributing it widely is therefore harmless.
    ///
    /// Zero when no logger is reachable (very early boot, processes
    /// created before the log infrastructure is wired). Logger-using
    /// callers must tolerate zero (writes silently drop).
    pub log_discovery_cap: u32,
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

    /// `CSpace` slot of the stdin cap. Zero when no input stream is attached.
    pub stdin_cap: u32,

    /// `CSpace` slot of the stdout cap. Zero when no sink is attached.
    pub stdout_cap: u32,

    /// `CSpace` slot of the stderr cap. Zero when no sink is attached.
    pub stderr_cap: u32,

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
