// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/lib.rs

//! Shared IPC helpers for Seraph userspace services.
//!
//! Provides common patterns used across multiple services: the bootstrap
//! protocol (children receive their initial cap set via IPC from their
//! creator), the [`IpcBuf`] accessor, typed error-code constants, label
//! modules, and the path codec used across VFS/FS interfaces.

// When built as a std dep via `rustc-dep-of-std`, we switch to `no_core`
// and rebind `core` to the `rustc_std_workspace_core` facade — same dance
// as abi/syscall and shared/syscall.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]
// cast_possible_truncation: userspace targets 64-bit only; u64/usize conversions
// are lossless. u32 casts on capability slot indices are bounded by CSpace capacity.
#![allow(clippy::cast_possible_truncation)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use syscall_abi::MSG_DATA_WORDS_MAX;

// ── IPC label constants ─────────────────────────────────────────────────────
//
// Per-service IPC operation labels. Namespaced by service because label
// numbers are only meaningful relative to a specific endpoint.

/// IPC labels for the process manager (`procmgr`).
pub mod procmgr_labels
{
    /// Create a new process from a boot module frame.
    pub const CREATE_PROCESS: u64 = 1;
    /// Start a previously created (suspended) process.
    pub const START_PROCESS: u64 = 2;
    /// Request physical memory frames from procmgr's pool.
    pub const REQUEST_FRAMES: u64 = 5;
    /// Create a new process from a VFS path (ELF binary). Wire format
    /// carries `stdio_token`, the path, and optional argv + env blobs;
    /// see procmgr's `handle_create_from_vfs` for the full label and data
    /// layout.
    pub const CREATE_FROM_VFS: u64 = 6;
    /// Provide procmgr with the vfsd endpoint for VFS-based loading.
    pub const SET_VFSD_EP: u64 = 7;
    /// Destroy a process: `cap_delete` its kernel objects (thread, aspace,
    /// cspace, `ProcessInfo` frame), dec-refing any frames the child still
    /// holds so they recycle back into the kernel buddy allocator. The
    /// caller identifies the process via the tokened `process_handle`
    /// received from `CREATE_PROCESS` / `CREATE_FROM_VFS`; the token is
    /// delivered by `ipc_recv` and looked up in procmgr's table. Idempotent
    /// on already-destroyed tokens.
    pub const DESTROY_PROCESS: u64 = 8;
    /// Query a process's state. Caller identifies the target via the tokened
    /// `process_handle` (delivered by `ipc_recv` on procmgr's side). Reply
    /// carries one data word encoding the state (see
    /// [`procmgr_process_state`]) and a second word carrying the exit reason
    /// if known (zero for still-alive processes). Intended for monitoring
    /// tools and `std::process::Child::try_wait`-style probes that want to
    /// peek without blocking on a death event.
    pub const QUERY_PROCESS: u64 = 9;
}

/// Process-state codes returned by `procmgr_labels::QUERY_PROCESS`.
///
/// Populated in data word 0 of the reply. Word 1 carries an accompanying
/// exit reason (kernel death-notification encoding: 0 = clean, `0x1000+vec`
/// = fault, `0x2000` = killed); it is zero for states in which the exit
/// reason is not meaningful (ALIVE, CREATED, UNKNOWN).
pub mod procmgr_process_state
{
    /// Entry exists and the process has been started. Running or blocked.
    pub const ALIVE: u64 = 0;
    /// Entry exists but the process has not yet been started (still in the
    /// suspended post-CREATE state). Rare for external queriers to see.
    pub const CREATED: u64 = 1;
    /// No entry for this token — already reaped, or the token was never
    /// valid. Equivalent to `ESRCH`.
    pub const UNKNOWN: u64 = 2;
}

/// IPC labels for the service manager (`svcmgr`).
pub mod svcmgr_labels
{
    /// Register a service for health monitoring.
    pub const REGISTER_SERVICE: u64 = 1;
    /// Signal that init handover is complete.
    pub const HANDOVER_COMPLETE: u64 = 2;
    /// Publish a named endpoint into the discovery registry.
    ///
    /// Data words: `[name_len, name_words...]`. One cap attached = the
    /// endpoint the name resolves to.
    pub const PUBLISH_ENDPOINT: u64 = 3;
    /// Look up a named endpoint; reply transfers the cap if known.
    ///
    /// Label's high 16 bits carry `name_len` (see `shared/ipc` `read_path`
    /// pattern); data words carry the name. Reply attaches the cap on
    /// success, or returns `svcmgr_errors::UNKNOWN_NAME` on miss.
    pub const QUERY_ENDPOINT: u64 = 4;
}

/// IPC labels for the VFS daemon (`vfsd`).
pub mod vfsd_labels
{
    /// Open a file by path.
    pub const OPEN: u64 = 1;
    /// Read from an open file.
    pub const READ: u64 = 2;
    /// Close an open file.
    pub const CLOSE: u64 = 3;
    /// Stat an open file (get size/attributes).
    pub const STAT: u64 = 4;
    /// Read a directory entry.
    pub const READDIR: u64 = 5;
    /// Mount a filesystem at a path.
    pub const MOUNT: u64 = 10;
}

/// IPC labels for filesystem drivers (FAT, ext4, etc.).
pub mod fs_labels
{
    /// Open a file by path (driver-side).
    pub const FS_OPEN: u64 = 1;
    /// Read from an open file (driver-side).
    pub const FS_READ: u64 = 2;
    /// Close an open file (driver-side).
    pub const FS_CLOSE: u64 = 3;
    /// Stat an open file (driver-side).
    pub const FS_STAT: u64 = 4;
    /// Read a directory entry (driver-side).
    pub const FS_READDIR: u64 = 5;
    /// End-of-directory marker in readdir replies.
    pub const END_OF_DIR: u64 = 6;
    /// Mount notification from vfsd.
    pub const FS_MOUNT: u64 = 10;
}

/// IPC labels for the device manager (`devmgr`).
pub mod devmgr_labels
{
    /// Query for a block device endpoint.
    pub const QUERY_BLOCK_DEVICE: u64 = 1;
    /// Query device configuration (`VirtIO` cap locations, etc.).
    /// The caller's token identifies the device.
    pub const QUERY_DEVICE_INFO: u64 = 2;
}

/// IPC labels for block device drivers.
pub mod blk_labels
{
    /// Read a single sector (512 bytes).
    pub const READ_BLOCK: u64 = 1;
    /// Register a partition range for a tokened endpoint.
    ///
    /// Data words: `[token, base_lba, length_lba]`. Callable only over the
    /// un-tokened (whole-disk) endpoint; tokened callers are rejected.
    pub const REGISTER_PARTITION: u64 = 2;
}

/// IPC labels for byte-stream endpoints (stdin/stdout/stderr backing).
///
/// One label, one direction, bytes inline. The producer issues
/// `ipc_call(cap, label=STREAM_BYTES | (byte_len << 16), …)` per write
/// (chunked at `MSG_DATA_WORDS_MAX * 8` per call). The receiver reads
/// `byte_len.div_ceil(8)` data words from its IPC buffer and unpacks
/// `byte_len` bytes. The receiver replies empty to unblock the writer.
///
/// No multi-chunk reassembly framing on the wire — line buffering
/// (e.g. logd's `[name]` per-newline prefix) lives in the receiver.
///
/// # Label encoding
/// - Bits 0-15: label ID ([`STREAM_BYTES`])
/// - Bits 16-31: byte length of the payload in this call (0..=512).
pub mod stream_labels
{
    /// Base label ID for stream-bytes messages (bits 0-15).
    pub const STREAM_BYTES: u64 = 10;
}

// ── Bootstrap protocol ──────────────────────────────────────────────────────
//
// Children receive their initial cap set via IPC on their `creator_endpoint`
// cap (the only cap installed at process creation beyond the self-caps). The
// child issues `BOOTSTRAP_REQUEST` in a loop; the creator replies with up to
// `MSG_CAP_SLOTS_MAX = 4` caps plus arbitrary payload words per round. The
// reply label's low byte indicates whether more rounds are expected (`MORE`)
// or the bootstrap is complete (`DONE`).
//
// The payload format (which data words mean what, which cap slot goes where)
// is defined per (creator, child-type) pair in each child's crate. No shared
// cap-role enum; no per-service sentinels.

pub mod bootstrap;

/// Bootstrap-protocol error reply codes (creator → child).
pub mod bootstrap_errors
{
    /// Creator has no bootstrap plan for the sending child's token.
    pub const NO_CHILD: u64 = 2;
    /// Creator's bootstrap plan for this child is already drained.
    pub const EXHAUSTED: u64 = 3;
    /// Protocol misuse (unexpected label, malformed request).
    pub const INVALID: u64 = 4;
}

// ── Typed error codes per service ───────────────────────────────────────────
//
// Named constants replace bare numeric reply labels at every `ipc_reply` site.
// `SUCCESS == 0` is an invariant across all services; callers still read
// `label != 0` as a coarse success/failure check.

/// Error replies from procmgr.
pub mod procmgr_errors
{
    pub const SUCCESS: u64 = 0;
    /// ELF image validation failed.
    pub const INVALID_ELF: u64 = 1;
    /// Out of memory during process creation.
    pub const OUT_OF_MEMORY: u64 = 2;
    /// Process handle token not found in process table.
    pub const INVALID_TOKEN: u64 = 4;
    /// Attempt to start a process that was already started.
    pub const ALREADY_STARTED: u64 = 5;
    /// Out of memory while fulfilling a frame request.
    pub const REQUEST_FRAMES_OOM: u64 = 6;
    /// Invalid argument to an IPC request.
    pub const INVALID_ARGUMENT: u64 = 7;
    /// `CREATE_FROM_VFS` without a registered vfsd endpoint.
    pub const NO_VFSD_ENDPOINT: u64 = 8;
    /// File not found via vfsd.
    pub const FILE_NOT_FOUND: u64 = 9;
    /// I/O error reading file from vfsd (during `CREATE_FROM_VFS`).
    pub const IO_ERROR: u64 = 10;
    /// Unknown opcode on procmgr endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFFFF;
}

/// Error replies from vfsd.
pub mod vfsd_errors
{
    pub const SUCCESS: u64 = 0;
    /// File / path not found, or mount-path invalid.
    pub const NOT_FOUND: u64 = 1;
    /// No mount covers the requested path / partition not found.
    pub const NO_MOUNT: u64 = 2;
    /// Filesystem driver module capability unavailable.
    pub const NO_FS_MODULE: u64 = 3;
    /// Failed to spawn filesystem driver.
    pub const SPAWN_FAILED: u64 = 4;
    /// I/O error or mount failed at the driver.
    pub const IO_ERROR: u64 = 5;
    /// Mount table full.
    pub const TABLE_FULL: u64 = 6;
    /// Unknown opcode on vfsd endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

/// Error replies from filesystem drivers (FAT, …).
pub mod fs_errors
{
    pub const SUCCESS: u64 = 0;
    /// File not found, or filesystem failed to validate on mount.
    pub const NOT_FOUND: u64 = 1;
    /// I/O error, or out of memory.
    pub const IO_ERROR: u64 = 2;
    /// Out of file-handle slots.
    pub const TOO_MANY_OPEN: u64 = 3;
    /// File token is invalid or expired.
    pub const INVALID_TOKEN: u64 = 4;
    /// Unknown opcode on fs-driver endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

/// Error replies from devmgr.
pub mod devmgr_errors
{
    pub const SUCCESS: u64 = 0;
    /// Cap derivation failed, or invalid device index.
    pub const INVALID_REQUEST: u64 = 1;
    /// Unknown opcode on devmgr endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

/// Error replies from svcmgr.
pub mod svcmgr_errors
{
    pub const SUCCESS: u64 = 0;
    /// Service table is full.
    pub const TABLE_FULL: u64 = 1;
    /// Invalid service name (too long / malformed).
    pub const INVALID_NAME: u64 = 2;
    /// Registration reply missing required caps.
    pub const INSUFFICIENT_CAPS: u64 = 3;
    /// `EventQueue` binding failed for death notification.
    pub const EVENT_QUEUE_FAILED: u64 = 4;
    /// Discovery registry lookup: name is not published.
    pub const UNKNOWN_NAME: u64 = 5;
    /// Discovery registry publish: table full or duplicate name.
    pub const REGISTER_REJECTED: u64 = 6;
    /// Unknown opcode on svcmgr endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFFFF;
}

/// Error replies from block device drivers.
pub mod blk_errors
{
    pub const SUCCESS: u64 = 0;
    /// Device returned an error status byte (value is the `VirtIO` status byte).
    /// Values 1 (IOERR), 2 (UNSUPP) per `VirtIO` 1.2 §5.2.6.
    pub const DEVICE_STATUS_IOERR: u64 = 1;
    pub const DEVICE_STATUS_UNSUPP: u64 = 2;
    /// Read LBA is outside the bounds registered for the caller's token.
    pub const OUT_OF_BOUNDS: u64 = 3;
    /// Partition registration rejected (no authority, table full, or bad args).
    pub const REGISTER_REJECTED: u64 = 4;
    /// Unknown opcode on block endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

// ── IpcBuf ──────────────────────────────────────────────────────────────────

/// Typed wrapper around a registered IPC buffer page.
///
/// Page-aligned (4 KiB), u64-aligned, mapped for the holding thread's
/// lifetime. Encapsulates the volatile read/write invariants required for
/// kernel-shared memory: the kernel may read or write the IPC buffer at any
/// IPC syscall boundary, so all accesses are volatile.
///
/// `Copy` and bit-identical to `*mut u64`; passing by value is zero-overhead.
/// Bounds on data-word accesses are enforced in debug builds.
#[derive(Clone, Copy)]
pub struct IpcBuf(*mut u64);

impl IpcBuf
{
    /// Wrap a raw pointer to the registered IPC buffer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a 4 KiB-aligned, registered IPC buffer page
    /// mapped into the calling thread's address space. The page must
    /// remain mapped for the lifetime of every access through the
    /// returned `IpcBuf`.
    #[must_use]
    pub const unsafe fn from_raw(ptr: *mut u64) -> Self
    {
        Self(ptr)
    }

    /// Wrap a `*mut u8` pointing at the IPC buffer (common case in
    /// startup code where `StartupInfo::ipc_buffer` is a `*mut u8`).
    ///
    /// # Safety
    ///
    /// Same requirements as [`Self::from_raw`]. Additionally, `ptr` must be
    /// 8-byte aligned — guaranteed when it is page-aligned.
    #[must_use]
    pub unsafe fn from_bytes(ptr: *mut u8) -> Self
    {
        // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB), satisfying u64 alignment.
        #[allow(clippy::cast_ptr_alignment)]
        Self(ptr.cast::<u64>())
    }

    /// Read data word `idx`.
    #[must_use]
    pub fn read_word(self, idx: usize) -> u64
    {
        debug_assert!(idx < MSG_DATA_WORDS_MAX);
        // SAFETY: IPC buffer is page-aligned (u64-aligned), mapped for the
        // holding thread's lifetime (invariant of `from_raw`). `idx` is bounded
        // by `MSG_DATA_WORDS_MAX` in debug; volatile required for kernel-shared memory.
        unsafe { core::ptr::read_volatile(self.0.add(idx)) }
    }

    /// Write data word `idx`.
    pub fn write_word(self, idx: usize, val: u64)
    {
        debug_assert!(idx < MSG_DATA_WORDS_MAX);
        // SAFETY: same invariants as `read_word`.
        unsafe { core::ptr::write_volatile(self.0.add(idx), val) };
    }

    /// Read a contiguous range of data words into `dst`.
    ///
    /// Reads `dst.len()` words starting at `start`. Panics (in debug) if the
    /// range would exceed `MSG_DATA_WORDS_MAX`.
    pub fn read_words(self, start: usize, dst: &mut [u64])
    {
        debug_assert!(start + dst.len() <= MSG_DATA_WORDS_MAX);
        for (i, slot) in dst.iter_mut().enumerate()
        {
            *slot = self.read_word(start + i);
        }
    }

    /// Write a contiguous range of data words from `src`.
    ///
    /// Writes `src.len()` words starting at `start`. Panics (in debug) if the
    /// range would exceed `MSG_DATA_WORDS_MAX`.
    pub fn write_words(self, start: usize, src: &[u64])
    {
        debug_assert!(start + src.len() <= MSG_DATA_WORDS_MAX);
        for (i, &val) in src.iter().enumerate()
        {
            self.write_word(start + i, val);
        }
    }

    /// Escape hatch for syscall wrappers that accept raw pointers.
    #[must_use]
    pub fn as_ptr(self) -> *mut u64
    {
        self.0
    }
}

// ── Path codec ──────────────────────────────────────────────────────────────

/// Maximum path length in bytes (6 IPC data words = 48 bytes).
pub const MAX_PATH_LEN: usize = 48;

/// Maximum data words used for a path (6 words of 8 bytes each).
const MAX_PATH_WORDS: usize = 6;

/// Maximum argv blob size in bytes across an IPC. Constrained by
/// `MSG_DATA_WORDS_MAX * 8 = 512` (full data area) minus room for any
/// path that coexists in the same message (6 words / 48 bytes). 256
/// comfortably fits typical service-argv cases and leaves slack for the
/// path field in `CREATE_FROM_VFS`. The `ProcessInfo` page can hold more,
/// but expanding this also requires extending the label encoding
/// (currently 16 bits).
pub const ARGS_BLOB_MAX: usize = 256;

/// Read path bytes from IPC buffer data words.
///
/// Unpacks `path_len` bytes from little-endian u64 words in `ipc`.
/// Writes into `buf`; returns the number of bytes written (capped at `buf.len()`
/// and `path_len`). Callers typically discard the return value when `path_len`
/// is known in advance.
pub fn read_path_from_ipc(ipc: IpcBuf, path_len: usize, buf: &mut [u8]) -> usize
{
    let effective_len = path_len.min(buf.len()).min(MAX_PATH_LEN);
    let word_count = effective_len.div_ceil(8).min(MAX_PATH_WORDS);
    for i in 0..word_count
    {
        let word = ipc.read_word(i);
        let base = i * 8;
        for j in 0..8
        {
            if base + j < effective_len
            {
                buf[base + j] = (word >> (j * 8)) as u8;
            }
        }
    }
    effective_len
}

/// Write path bytes into IPC buffer data words.
///
/// Packs `path` bytes into little-endian u64 words in `ipc`. Returns the
/// number of words written (callers use this for the `data_count` argument
/// to `ipc_call`; some callers compute it from path length directly and may
/// discard the return).
#[must_use]
pub fn write_path_to_ipc(ipc: IpcBuf, path: &[u8]) -> usize
{
    let effective_len = path.len().min(MAX_PATH_LEN);
    let word_count = effective_len.div_ceil(8).min(MAX_PATH_WORDS);
    for i in 0..word_count
    {
        let mut word: u64 = 0;
        let base = i * 8;
        for j in 0..8
        {
            if base + j < effective_len
            {
                word |= u64::from(path[base + j]) << (j * 8);
            }
        }
        ipc.write_word(i, word);
    }
    word_count
}

/// Read `len` bytes from IPC buffer data words starting at word
/// `word_offset`, unpacking little-endian u64s into `buf`.
///
/// Returns the number of bytes actually written (capped at
/// `buf.len()` and `len`).
pub fn read_blob_from_ipc(ipc: IpcBuf, word_offset: usize, len: usize, buf: &mut [u8]) -> usize
{
    let effective_len = len.min(buf.len());
    let word_count = effective_len.div_ceil(8);
    for i in 0..word_count
    {
        let word = ipc.read_word(word_offset + i);
        let base = i * 8;
        for j in 0..8
        {
            if base + j < effective_len
            {
                buf[base + j] = (word >> (j * 8)) as u8;
            }
        }
    }
    effective_len
}

/// Pack `blob` bytes into IPC buffer data words, starting at word
/// `word_offset`. Returns the number of words written.
#[must_use]
pub fn write_blob_to_ipc(ipc: IpcBuf, word_offset: usize, blob: &[u8]) -> usize
{
    let word_count = blob.len().div_ceil(8);
    for i in 0..word_count
    {
        let mut word: u64 = 0;
        let base = i * 8;
        for j in 0..8
        {
            if base + j < blob.len()
            {
                word |= u64::from(blob[base + j]) << (j * 8);
            }
        }
        ipc.write_word(word_offset + i, word);
    }
    word_count
}
