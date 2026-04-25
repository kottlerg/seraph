// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/lib.rs

//! Shared IPC helpers for Seraph userspace services.
//!
//! Provides the stack-owned [`IpcMessage`] snapshot type plus thin
//! `ipc_call` / `ipc_recv` / `ipc_reply` wrappers that keep the kernel's
//! per-thread IPC buffer as scratch at the syscall boundary (nested IPC
//! cannot clobber a received/reply message). Also hosts the bootstrap
//! protocol (children receive their initial cap set via IPC from their
//! creator), typed error-code constants, and label modules.

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

use syscall_abi::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

// ── IPC label constants ─────────────────────────────────────────────────────
//
// Per-service IPC operation labels. Namespaced by service because label
// numbers are only meaningful relative to a specific endpoint.

/// IPC labels for the process manager (`procmgr`).
pub mod procmgr_labels
{
    /// Create a new process from a boot module frame. Caps: `[module,
    /// creator_endpoint?]`. Stdio pipes (stdin/stdout/stderr) are
    /// configured through one or more [`CONFIGURE_PIPE`] calls against
    /// the returned tokened `process_handle` — procmgr's CREATE path
    /// carries no stdio caps so stdout and stderr can be piped
    /// independently and so the core process-creation primitive stays
    /// stdio-agnostic.
    pub const CREATE_PROCESS: u64 = 1;
    /// Start a previously created (suspended) process.
    pub const START_PROCESS: u64 = 2;
    /// Request physical memory frames from procmgr's pool.
    pub const REQUEST_FRAMES: u64 = 5;
    /// Create a new process from a VFS path (ELF binary). Wire format
    /// carries the path plus optional argv + env blobs; see procmgr's
    /// `handle_create_from_vfs` for the full label and data layout. Caps:
    /// `[creator_endpoint?]`. Stdio pipes via [`CONFIGURE_PIPE`] as for
    /// `CREATE_PROCESS`.
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
    /// Install one direction's shmem-backed stdio pipe on a child
    /// created via [`CREATE_PROCESS`] / [`CREATE_FROM_VFS`] but not yet
    /// started.
    ///
    /// Request: caller invokes on the tokened `process_handle` returned
    /// by the creation call; procmgr uses `recv.token` to find the entry.
    /// Wire format:
    /// * `data[0]` — direction selector ([`PIPE_DIR_STDIN`] /
    ///   [`PIPE_DIR_STDOUT`] / [`PIPE_DIR_STDERR`]).
    /// * `data[1]` — ring byte capacity (power of two, ≤ ring page bytes
    ///   minus header). v1 uses 2048.
    /// * `caps[0]` — frame cap (one shmem page; spawner has already
    ///   initialised the [`SpscHeader`] via `init`).
    /// * `caps[1]` — data-available signal cap.
    /// * `caps[2]` — space-available signal cap.
    ///
    /// procmgr `cap_copy`s each cap into the child's `CSpace` and writes
    /// the resulting slot indices into the matching `<dir>_frame_cap`,
    /// `<dir>_data_signal_cap`, and `<dir>_space_signal_cap` slots of
    /// the child's `ProcessInfo`. All three caps are required; missing
    /// cap slots reply `INVALID_ARGUMENT`.
    ///
    /// Ordering: valid only between `CREATE_PROCESS` and `START_PROCESS`.
    /// Replies `ALREADY_STARTED` if the target is running.
    /// `INVALID_TOKEN` if the `process_handle` is unknown. Idempotent
    /// per direction before start; later calls overwrite the previous
    /// triple for that direction.
    ///
    /// Spawners call this 0–3 times depending on which directions are
    /// piped. The 3 caps × 3 directions = 9 caps total exceeds
    /// `MSG_CAP_SLOTS_MAX = 4`, so per-direction is the minimal-call
    /// shape — non-piped directions cost zero IPC round trips.
    pub const CONFIGURE_PIPE: u64 = 11;

    /// Direction selector for [`CONFIGURE_PIPE`] — child stdin (parent
    /// is the writer, child is the reader).
    pub const PIPE_DIR_STDIN: u64 = 0;
    /// Direction selector for [`CONFIGURE_PIPE`] — child stdout (child
    /// is the writer, parent is the reader).
    pub const PIPE_DIR_STDOUT: u64 = 1;
    /// Direction selector for [`CONFIGURE_PIPE`] — child stderr (child
    /// is the writer, parent is the reader).
    pub const PIPE_DIR_STDERR: u64 = 2;
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
    /// Entry has been auto-reaped by procmgr but the token is still in the
    /// recent-exits ring. Reply word 1 carries the kernel-encoded
    /// `exit_reason`. Recent-exit retention is best-effort; once the ring
    /// rotates, queries on the same token return `UNKNOWN`.
    pub const EXITED: u64 = 3;
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
    /// Register (or update) the display name for the sender's log stream.
    ///
    /// Payload: name bytes via `.bytes(0, name)` with byte length in bits
    /// 16-31 of the label, same encoding as `STREAM_BYTES`. The mediator
    /// looks up the slot for the sender's token (delivered by the kernel
    /// from the tokened SEND cap) and stores the bytes as that slot's
    /// display name. Names that would collide with another token's name
    /// are stored with a `.2` / `.3` / … suffix; re-registration by the
    /// same token with its own current name is a silent no-op. Names
    /// longer than the mediator's per-slot buffer are truncated.
    pub const STREAM_REGISTER_NAME: u64 = 11;
}

/// IPC labels for the system log endpoint's discovery interface.
///
/// Distinct from [`stream_labels`]: the latter carry payload (bytes,
/// names) on tokened SEND caps that have already been minted; these
/// labels are spoken on an un-tokened SEND cap (the "discovery cap"
/// installed in every process at create time) and are how a process
/// acquires its tokened cap in the first place.
pub mod log_labels
{
    /// Request a freshly-minted tokened SEND cap on the log endpoint.
    ///
    /// Request: empty (label only). Reply: one cap — a SEND cap on the
    /// log endpoint whose token uniquely identifies this caller's log
    /// stream — plus a single data word carrying a status code (zero on
    /// success). Callers cache the returned cap process-globally and
    /// reuse it for every subsequent `STREAM_BYTES` /
    /// `STREAM_REGISTER_NAME` message.
    ///
    /// The receiver mints the token (callers cannot pick their own).
    /// Tokens are unforgeable and serve as the immutable identity of a
    /// log sender; display names registered later via
    /// `STREAM_REGISTER_NAME` are mutable labels bound to that identity.
    pub const GET_LOG_CAP: u64 = 12;
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

// ── Protocol constants ─────────────────────────────────────────────────────

/// Maximum path length in bytes (6 IPC data words = 48 bytes).
pub const MAX_PATH_LEN: usize = 48;

/// Maximum argv blob size in bytes across an IPC. Constrained by
/// `MSG_DATA_WORDS_MAX * 8 = 512` (full data area) minus room for any
/// path that coexists in the same message (6 words / 48 bytes). 256
/// comfortably fits typical service-argv cases and leaves slack for the
/// path field in `CREATE_FROM_VFS`. The `ProcessInfo` page can hold more,
/// but expanding this also requires extending the label encoding
/// (currently 16 bits).
pub const ARGS_BLOB_MAX: usize = 256;

// ── IpcMessage ──────────────────────────────────────────────────────────────

/// Stack-owned snapshot of an IPC message — label, token, data words, and
/// received cap-slot indices, carried by value across the IPC wrapper
/// boundary.
///
/// `ipc_recv` and the reply path of `ipc_call` return an `IpcMessage`;
/// `ipc_call` and `ipc_reply` consume one built via [`IpcMessageBuilder`].
/// Received data is copied out of the per-thread IPC buffer before the
/// wrapper returns, which leaves the buffer as pure scratch at the syscall
/// boundary — nested IPC (stdio, logging, any IPC-using helper) is safe by
/// construction.
///
/// Fixed-size inline payload (`MSG_DATA_WORDS_MAX` = 64 data words, 512 B)
/// plus `MSG_CAP_SLOTS_MAX` cap indices. No allocation; `no_std`-clean;
/// cheap to return by value.
#[derive(Clone, Copy)]
pub struct IpcMessage
{
    /// Protocol label (opcode / reply code / bit-packed header).
    pub label: u64,
    /// Endpoint-badge token delivered by `ipc_recv`; zero on send paths
    /// and for untokened endpoints.
    pub token: u64,
    data: [u64; MSG_DATA_WORDS_MAX],
    /// Number of valid `u64` words in `data`. `<= MSG_DATA_WORDS_MAX`.
    data_len: u8,
    /// Number of valid slots in `cap_slots`. `<= MSG_CAP_SLOTS_MAX`.
    cap_count: u8,
    cap_slots: [u32; MSG_CAP_SLOTS_MAX],
}

impl IpcMessage
{
    /// Zero-length message carrying only a label (no data, no caps, no
    /// token).
    #[must_use]
    pub const fn new(label: u64) -> Self
    {
        Self {
            label,
            token: 0,
            data: [0; MSG_DATA_WORDS_MAX],
            data_len: 0,
            cap_count: 0,
            cap_slots: [0; MSG_CAP_SLOTS_MAX],
        }
    }

    /// Start a builder. Equivalent to [`IpcMessageBuilder::new`].
    #[must_use]
    pub const fn builder(label: u64) -> IpcMessageBuilder
    {
        IpcMessageBuilder::new(label)
    }

    /// Read data word `idx`. Debug-panics only on the outer array bound
    /// (`idx >= MSG_DATA_WORDS_MAX`). Reading past the sender's declared
    /// `word_count()` returns zero — the unused array slots are zero-init
    /// and the kernel does not write them past the declared range. This
    /// matches the old `IpcBuf::read_word` contract so protocols that
    /// carry optional trailing words at fixed offsets keep working.
    #[must_use]
    pub fn word(&self, idx: usize) -> u64
    {
        debug_assert!(idx < MSG_DATA_WORDS_MAX);
        self.data[idx]
    }

    /// Slice view of the populated data words: `&data[..word_count()]`.
    #[must_use]
    pub fn words(&self) -> &[u64]
    {
        &self.data[..self.data_len as usize]
    }

    /// Number of populated data words.
    #[must_use]
    pub fn word_count(&self) -> usize
    {
        self.data_len as usize
    }

    /// Byte-slice view of the populated data words (little-endian).
    ///
    /// Length is `word_count() * 8`. Byte-level protocols (path, blob)
    /// typically carry their byte length separately in the label or a
    /// data word; callers slice this view accordingly.
    #[must_use]
    pub fn data_bytes(&self) -> &[u8]
    {
        // SAFETY: `data` is `[u64; MSG_DATA_WORDS_MAX]` — contiguous and
        // u64-aligned, which is stricter than u8 alignment. Length
        // `word_count * 8` stays inside the array (`word_count <=
        // MSG_DATA_WORDS_MAX` by invariant).
        unsafe {
            core::slice::from_raw_parts(
                self.data.as_ptr().cast::<u8>(),
                self.data_len as usize * core::mem::size_of::<u64>(),
            )
        }
    }

    /// Slice view of the received / replied cap-slot indices.
    #[must_use]
    pub fn caps(&self) -> &[u32]
    {
        &self.cap_slots[..self.cap_count as usize]
    }

    /// Snapshot the IPC buffer into an owned `IpcMessage`.
    ///
    /// Reads `word_count` data words plus cap metadata from the registered
    /// IPC buffer page. Used by the `ipc_recv` / `ipc_call` wrappers after
    /// the kernel returns.
    ///
    /// # Safety
    /// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC
    /// buffer page as registered via `ipc_buffer_set`. `word_count` must
    /// be `<= MSG_DATA_WORDS_MAX`.
    #[must_use]
    pub unsafe fn from_ipc_buf(
        ipc_buf: *const u64,
        label: u64,
        token: u64,
        word_count: usize,
    ) -> Self
    {
        debug_assert!(word_count <= MSG_DATA_WORDS_MAX);
        let mut data = [0u64; MSG_DATA_WORDS_MAX];
        for (i, slot) in data.iter_mut().take(word_count).enumerate()
        {
            // SAFETY: caller guarantees `ipc_buf` is valid, page-aligned,
            // and mapped. `i < word_count <= MSG_DATA_WORDS_MAX`, so
            // offset is in-bounds of the 4 KiB buffer. Volatile required
            // for kernel-shared memory.
            *slot = unsafe { core::ptr::read_volatile(ipc_buf.add(i)) };
        }
        // Cap metadata: cap_count at word[MSG_DATA_WORDS_MAX], slot
        // indices at word[MSG_DATA_WORDS_MAX + 1 ..].
        // SAFETY: same invariants; MSG_DATA_WORDS_MAX + 1 + MSG_CAP_SLOTS_MAX
        // = 64 + 1 + 4 = 69 < 512 (4 KiB / 8 B).
        let cap_count_raw = unsafe { core::ptr::read_volatile(ipc_buf.add(MSG_DATA_WORDS_MAX)) };
        let cap_count = (cap_count_raw as usize).min(MSG_CAP_SLOTS_MAX);
        let mut cap_slots = [0u32; MSG_CAP_SLOTS_MAX];
        for (i, slot) in cap_slots.iter_mut().take(cap_count).enumerate()
        {
            // SAFETY: offset bounded as above.
            *slot =
                unsafe { core::ptr::read_volatile(ipc_buf.add(MSG_DATA_WORDS_MAX + 1 + i)) } as u32;
        }
        Self {
            label,
            token,
            data,
            data_len: word_count as u8,
            cap_count: cap_count as u8,
            cap_slots,
        }
    }

    /// Write the populated data words into the IPC buffer.
    ///
    /// Used by the `ipc_call` / `ipc_reply` wrappers before issuing the
    /// syscall. Cap slots are passed as syscall arguments; the sender
    /// does not write cap metadata into the buffer (the kernel installs
    /// caps in the receiver and writes the receiver-side slot indices
    /// into the receiver's buffer).
    ///
    /// # Safety
    /// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC
    /// buffer page as registered via `ipc_buffer_set`.
    pub unsafe fn write_to_ipc_buf(&self, ipc_buf: *mut u64)
    {
        for (i, &val) in self.words().iter().enumerate()
        {
            // SAFETY: `data_len <= MSG_DATA_WORDS_MAX` invariant, so
            // `i < MSG_DATA_WORDS_MAX` and the offset is within the
            // 4 KiB buffer. Caller guarantees pointer validity.
            unsafe { core::ptr::write_volatile(ipc_buf.add(i), val) };
        }
    }
}

// ── IpcMessageBuilder ──────────────────────────────────────────────────────

/// Chainable builder that assembles an [`IpcMessage`] on the caller's
/// stack, without touching the per-thread IPC buffer.
///
/// Typical use at a send site:
/// ```ignore
/// ipc_call(
///     ep,
///     &IpcMessage::builder(label).word(0, value).cap(slot).build(),
///     ipc_buf,
/// )
/// ```
#[derive(Clone, Copy)]
pub struct IpcMessageBuilder
{
    msg: IpcMessage,
}

impl IpcMessageBuilder
{
    /// New builder with the given label and nothing else set.
    #[must_use]
    pub const fn new(label: u64) -> Self
    {
        Self {
            msg: IpcMessage::new(label),
        }
    }

    /// Set data word `idx`; grow `word_count` to cover it if needed.
    #[must_use]
    pub fn word(mut self, idx: usize, val: u64) -> Self
    {
        debug_assert!(idx < MSG_DATA_WORDS_MAX);
        self.msg.data[idx] = val;
        let needed = (idx as u8) + 1;
        if self.msg.data_len < needed
        {
            self.msg.data_len = needed;
        }
        self
    }

    /// Write `src` words contiguously starting at word `start`; grow
    /// `word_count` to cover the range.
    #[must_use]
    pub fn words(mut self, start: usize, src: &[u64]) -> Self
    {
        debug_assert!(start + src.len() <= MSG_DATA_WORDS_MAX);
        for (i, &val) in src.iter().enumerate()
        {
            self.msg.data[start + i] = val;
        }
        let needed = (start + src.len()) as u8;
        if self.msg.data_len < needed
        {
            self.msg.data_len = needed;
        }
        self
    }

    /// Pack `src` bytes into data words (little-endian u64), starting at
    /// word `start_word`. Grows `word_count` to cover the packed bytes.
    #[must_use]
    pub fn bytes(mut self, start_word: usize, src: &[u8]) -> Self
    {
        let word_count = src.len().div_ceil(8);
        debug_assert!(start_word + word_count <= MSG_DATA_WORDS_MAX);
        for i in 0..word_count
        {
            let base = i * 8;
            let mut w: u64 = 0;
            for j in 0..8
            {
                if base + j < src.len()
                {
                    w |= u64::from(src[base + j]) << (j * 8);
                }
            }
            self.msg.data[start_word + i] = w;
        }
        let needed = (start_word + word_count) as u8;
        if self.msg.data_len < needed
        {
            self.msg.data_len = needed;
        }
        self
    }

    /// Append one cap slot. Debug-panics if the slot array is full.
    #[must_use]
    pub fn cap(mut self, slot: u32) -> Self
    {
        debug_assert!((self.msg.cap_count as usize) < MSG_CAP_SLOTS_MAX);
        let i = self.msg.cap_count as usize;
        self.msg.cap_slots[i] = slot;
        self.msg.cap_count += 1;
        self
    }

    /// Replace the label set at construction.
    #[must_use]
    pub fn label(mut self, label: u64) -> Self
    {
        self.msg.label = label;
        self
    }

    /// Explicitly set `word_count`. Useful when a protocol wants padding
    /// words counted (`words`/`word`/`bytes` auto-grow only to the
    /// highest touched word).
    #[must_use]
    pub fn word_count(mut self, len: usize) -> Self
    {
        debug_assert!(len <= MSG_DATA_WORDS_MAX);
        self.msg.data_len = len as u8;
        self
    }

    /// Finalize the message.
    #[must_use]
    pub const fn build(self) -> IpcMessage
    {
        self.msg
    }
}

// ── IPC wrappers (IpcMessage-snapshot) ──────────────────────────────────────

/// Synchronous IPC call on an endpoint, returning a stack-owned reply snapshot.
///
/// Writes `msg`'s payload into the registered IPC buffer, issues
/// `SYS_IPC_CALL`, then copies the reply (label + data words + cap metadata)
/// back out of the buffer into a fresh [`IpcMessage`]. After return the IPC
/// buffer is scratch — nested IPC (stdio, logging, any IPC-using helper)
/// cannot clobber the returned message.
///
/// The endpoint cap must have `Rights::GRANT` when `msg.caps()` is non-empty.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code if the endpoint cap is invalid, the
/// caller has insufficient rights, or the call is interrupted.
#[inline]
pub unsafe fn ipc_call(ep: u32, msg: &IpcMessage, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe {
        msg.write_to_ipc_buf(ipc_buf);
    }
    let caps = msg.caps();
    let cap_packed = syscall::pack_cap_slots(caps);
    let (reply_label, reply_word_count) =
        syscall::raw_ipc_call(ep, msg.label, msg.word_count(), caps.len(), cap_packed)?;
    // SAFETY: `ipc_buf` is the registered IPC buffer; kernel wrote the
    // reply (data + cap metadata) into it before return. `reply_word_count`
    // is already clamped to MSG_DATA_WORDS_MAX by `raw_ipc_call`.
    Ok(unsafe { IpcMessage::from_ipc_buf(ipc_buf, reply_label, 0, reply_word_count) })
}

/// Receive on an endpoint cap, returning a stack-owned message snapshot.
///
/// Blocks until a caller sends. Copies the message (label, token, data
/// words, cap metadata) from the registered IPC buffer into a fresh
/// [`IpcMessage`] before returning. After return the IPC buffer is scratch
/// — nested IPC between `ipc_recv` and reading the message is safe.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code if the endpoint cap is invalid or
/// the receive is interrupted.
#[inline]
pub unsafe fn ipc_recv(ep: u32, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    let (label, token, word_count) = syscall::raw_ipc_recv(ep)?;
    // SAFETY: `ipc_buf` is the registered IPC buffer; kernel wrote data +
    // cap metadata there before return. `word_count` is already clamped to
    // MSG_DATA_WORDS_MAX by `raw_ipc_recv`.
    Ok(unsafe { IpcMessage::from_ipc_buf(ipc_buf, label, token, word_count) })
}

/// Reply to the current thread's pending caller with `msg`.
///
/// Writes `msg`'s data words into the registered IPC buffer, then issues
/// `SYS_IPC_REPLY` with `msg.word_count()` words and `msg.caps()` cap slots.
/// Cap slots are moved from the server's `CSpace` to the caller's `CSpace`
/// atomically with the reply.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code if there is no pending reply target
/// or the reply is otherwise invalid.
#[inline]
pub unsafe fn ipc_reply(msg: &IpcMessage, ipc_buf: *mut u64) -> Result<(), i64>
{
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe {
        msg.write_to_ipc_buf(ipc_buf);
    }
    let caps = msg.caps();
    let cap_packed = syscall::pack_cap_slots(caps);
    syscall::raw_ipc_reply(msg.label, msg.word_count(), caps.len(), cap_packed)
}
