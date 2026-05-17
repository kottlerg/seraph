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
//
// Each `*_LABELS_VERSION` constant declares the wire-protocol version of
// its namespace. Bumped on any breaking change (label added, removed, or
// repurposed; payload shape change). Three consumer-wiring categories:
//
//   Handshake-checked at first contact — producer prepends its compiled
//   `*_LABELS_VERSION` as the first u32 of the handshake payload; receiver
//   compares to its own and rejects on mismatch. Mismatched binaries are
//   stopped before any per-IO traffic.
//     FS_LABELS_VERSION     — fs_labels::FS_MOUNT             (vfsd ↔ fatfs)
//     VFSD_LABELS_VERSION   — vfsd_labels::GET_SYSTEM_ROOT_CAP (init ↔ vfsd)
//     BLK_LABELS_VERSION    — blk_labels::REGISTER_PARTITION   (vfsd ↔ virtio-blk)
//     DEVMGR_LABELS_VERSION — devmgr_labels::QUERY_BLOCK_DEVICE (vfsd ↔ devmgr)
//     MEMMGR_LABELS_VERSION — memmgr_labels::REGISTER_PROCESS   (procmgr ↔ memmgr)
//     SVCMGR_LABELS_VERSION — svcmgr_labels::REGISTER_SERVICE   (init ↔ svcmgr)
//     LOG_LABELS_VERSION    — log_labels::GET_LOG_CAP            (std process ↔ logd)
//
//   Implicitly covered by parent-channel handshake — the channel was opened
//   against a cap-token first minted by a handshake-checked namespace; the
//   token's presence is the version stamp, zero per-message cost.
//     NS_LABELS_VERSION     — caps from vfsd_labels / fs_labels handshakes
//     STREAM_LABELS_VERSION — caps from log_labels handshake
//
//   Marker-only — no clean parent-channel handshake exists; per-message
//   inlining would conflict with existing label-bit usage or cost wire bytes
//   on every call. The constant exists for the bump discipline and for
//   future tooling (CI label-stability scans, distributed-binary
//   compatibility queries). PROCESS_ABI_VERSION at process startup
//   provides coarse-grained coverage in lockstep with workspace-inherited
//   versioning.
//     PROCMGR_LABELS_VERSION
//     PWRMGR_LABELS_VERSION
//     RTC_LABELS_VERSION
//     TIMED_LABELS_VERSION

pub const PROCMGR_LABELS_VERSION: u32 = 1;
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
    /// Create a new process from a caller-supplied file cap (ELF binary).
    ///
    /// The caller already walked its own namespace cap to the binary node
    /// and attaches the resulting tokened file cap. Procmgr issues
    /// `FS_READ` / `FS_READ_FRAME` against that cap to stream the ELF —
    /// it never holds a namespace cap of its own.
    ///
    /// Label layout:
    /// * bits `[0..16]` — opcode (`CREATE_FROM_FILE`)
    /// * bits `[16..32]` — reserved (zero)
    /// * bits `[32..48]` — `args_bytes` (total byte length of the argv blob; u16)
    /// * bits `[48..56]` — `args_count` (number of NUL-terminated argv strings; u8)
    /// * bits `[56..64]` — `env_count` (number of NUL-terminated `KEY=VALUE` strings; u8)
    ///
    /// IPC data words:
    /// * `word 0` — `file_size` (u64), as reported by the caller's `NS_LOOKUP` size hint
    /// * `word 1..1+argv_words` — argv blob, `args_bytes.div_ceil(8)` words
    /// * `word 1+argv_words` — `env_bytes` (low 16 bits; only when `env_count > 0`)
    /// * words after the env header — env blob, `env_bytes.div_ceil(8)` words
    ///
    /// Caps: `[file_cap, creator_endpoint?]`. `file_cap` ownership transfers
    /// to procmgr; procmgr `FS_CLOSE`s and `cap_delete`s it after the load
    /// completes (success or failure). Stdio pipes are installed via
    /// separate [`CONFIGURE_PIPE`] calls between create and start.
    pub const CREATE_FROM_FILE: u64 = 13;
    /// Destroy a process: `cap_delete` its kernel objects (thread, aspace,
    /// cspace, `ProcessInfo` frame), dec-refing any frames the child still
    /// holds so they recycle back into the kernel buddy allocator. The
    /// caller identifies the process via the tokened `process_handle`
    /// received from `CREATE_PROCESS` / `CREATE_FROM_FILE`; the token is
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
    /// created via [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`] but not yet
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

    /// Install the namespace caps delivered to a suspended child via
    /// `ProcessInfo.system_root_cap` and `ProcessInfo.current_dir_cap`.
    ///
    /// Procmgr holds no namespace cap of its own. Without this call,
    /// both child slots stay zero — `std::os::seraph::root_dir_cap()`
    /// reads zero, `std::fs` absolute paths return `Unsupported`,
    /// `current_dir_cap()` reads zero, and relative paths return
    /// `Unsupported`. The spawner is the cap-distribution authority;
    /// this IPC is the only path that installs namespace caps on the
    /// child.
    ///
    /// Request: caller invokes on the tokened `process_handle` returned
    /// by [`CREATE_PROCESS`] or [`CREATE_FROM_FILE`]; procmgr uses
    /// `recv.token` to find the entry. Wire format:
    /// * `caps[0]` — root cap to deliver to the child (mandatory).
    /// * `caps[1]` — cwd cap to deliver to the child (optional). When
    ///   absent the child's `current_dir_cap` slot stays zero.
    ///
    /// Spawners obtain these caps by `cap_copy` of their own
    /// `root_dir_cap()` / `current_dir_cap()` (parent-inherit default)
    /// or by walk-and-attenuate against a sub-tree. procmgr does not
    /// validate cap shape — any tokened SEND on a namespace endpoint
    /// is accepted.
    ///
    /// procmgr stores the IPC-delivered copies in per-process state
    /// and `cap_copy`s each into the child's `CSpace` at
    /// `START_PROCESS` time. The caller's source slots are independent
    /// of this transfer (kernel `cap_derive` semantics); callers that
    /// wanted to relinquish authority over a cap MUST `cap_delete` the
    /// source slot themselves after the call.
    ///
    /// Ordering: valid only between create and `START_PROCESS`.
    /// Replies `ALREADY_STARTED` if the target is running.
    /// `INVALID_TOKEN` if the `process_handle` is unknown.
    /// `INVALID_ARGUMENT` if no cap was provided in `caps[0]`.
    /// Idempotent before start; later calls overwrite the previous
    /// caps (the prior caps are `cap_delete`'d procmgr-side).
    pub const CONFIGURE_NAMESPACE: u64 = 12;

    /// Register a death-notification `EventQueue` cap with procmgr.
    ///
    /// Wire format:
    /// * `caps[0]` = `EventQueue` cap (POST right) on which procmgr
    ///   posts `(process_token as u32) << 32 | exit_reason` for every
    ///   tracked process when it exits or faults.
    ///
    /// Procmgr stores the cap and, for every process already in its
    /// table, calls `sys_thread_bind_notification` on the child's
    /// main thread with this EQ as a second observer. From the
    /// registration moment onward, every newly spawned child also
    /// receives the binding inside `finalize_creation`. Single
    /// observer slot — re-registration replaces the previous cap.
    ///
    /// Real-logd uses this to learn about sender deaths so it can
    /// evict the corresponding slot in its hash-keyed token table.
    /// Reply is `procmgr_errors::SUCCESS` on bind, `INVALID_ARGUMENT`
    /// if the cap is missing or wrong type, `UNAUTHORIZED` if called
    /// over a non-privileged path (gated by tokened SEND cap).
    pub const REGISTER_DEATH_EQ: u64 = 14;

    /// Token bit on procmgr service caps that authorises
    /// `REGISTER_DEATH_EQ`. Init derives this tokened SEND cap and
    /// hands it to real-logd at bootstrap; the un-tokened or
    /// differently-tokened twins are rejected.
    pub const DEATH_EQ_AUTHORITY: u64 = 1u64 << 62;

    /// Hand init's kernel-object caps + reclaimable Frame caps to procmgr
    /// for post-death reap. Init calls this in the post-Phase-3 exit
    /// path, then `sys_thread_exit`s.
    ///
    /// First round (`is_first = data[0] != 0`):
    ///   `caps[0]` = init's `AddressSpace` cap (MOVED out of init's `CSpace`).
    ///   `caps[1]` = init's `CSpace` cap (MOVED).
    ///   `caps[2]` = init's main `Thread` cap (MOVED).
    ///   `caps[3]` = init-logd `Thread` cap (MOVED; may be the same slot
    ///               as a previously-exited thread — its TCB is reclaimed
    ///               on `cap_delete` regardless of state).
    /// Subsequent rounds (`data[0] == 0`):
    ///   `caps[0..N]` = reclaimable Frame caps (segments + stack +
    ///                  `InitInfo` + IPC buffer + any other init-owned
    ///                  donatable Frame). MOVED out of init's `CSpace`
    ///                  via IPC cap-transfer; procmgr accumulates them
    ///                  for the eventual `memmgr.DONATE_FRAMES` chunk.
    ///
    /// Procmgr binds the death-EQ on init's main thread with correlator
    /// `INIT_REAP_CORRELATOR` as part of the first round. Each round
    /// replies `procmgr_errors::SUCCESS`.
    pub const REGISTER_INIT_TEARDOWN: u64 = 15;

    /// Signal end of init's reap-handoff cap stream. After this call
    /// init has no caps left to transfer; procmgr's state machine
    /// transitions to "armed", awaiting the death-EQ event. Init
    /// calls `sys_thread_exit` immediately after this IPC replies.
    pub const INIT_TEARDOWN_DONE: u64 = 16;

    /// Reserved death-notification correlator used by `REGISTER_INIT_TEARDOWN`.
    /// Per-child correlators are `process_token as u32` starting at
    /// `log_tokens::LOG_TOKEN_FIRST_CHILD = 16`; reserving the top of
    /// the u32 range avoids collision.
    pub const INIT_REAP_CORRELATOR: u32 = u32::MAX;
}

pub const MEMMGR_LABELS_VERSION: u32 = 1;
/// IPC labels for the memory manager (`memmgr`).
///
/// memmgr owns the userspace RAM frame pool. All std-built processes
/// bootstrap their heap by calling `REQUEST_FRAMES` on a tokened SEND
/// cap installed in `ProcessInfo.memmgr_endpoint_cap`. Procmgr is the
/// privileged caller that registers and retires process tokens.
///
/// See `services/memmgr/docs/ipc-interface.md` for the authoritative wire
/// shape.
pub mod memmgr_labels
{
    /// Allocate one or more Frame caps covering at least `want_pages` pages.
    ///
    /// Universal label — callable from any tokened cap on memmgr's
    /// endpoint. Wire format:
    ///
    /// * `data[0]` low 32 bits — `want_pages: u32`.
    /// * `data[0]` high 32 bits — `flags: u32` (see flag constants below).
    ///
    /// Reply (success): `data[0]` = `returned_cap_count: u32`;
    /// `data[1+i]` = `page_count_for_cap_i: u32`; `caps[0..count]` = Frame
    /// capabilities (MAP|WRITE rights). `sum(page_count_for_cap_i) ==
    /// want_pages` for both contiguous and best-effort replies. Each reply
    /// cap MUST additionally carry `Rights::RETYPE` so the caller can
    /// retype the frame into kernel objects via the `SYS_CAP_CREATE_*`
    /// syscalls; memmgr derives reply caps with `RIGHTS_ALL`, which
    /// preserves the RETYPE bit stamped at boot by the kernel.
    pub const REQUEST_FRAMES: u64 = 1;
    /// Voluntarily return Frame caps to the pool. Callable from any
    /// tokened cap. Wire format: `data[0]` = `cap_count`; `data[1+i]` =
    /// `page_count_for_cap_i`; `caps[0..cap_count]` = Frame caps to release.
    /// memmgr verifies each cap was previously issued to the caller's token.
    pub const RELEASE_FRAMES: u64 = 2;
    /// Procmgr-only: register a new process. memmgr allocates a per-process
    /// tracking entry and replies with a tokened SEND cap on its endpoint
    /// identifying the new process. Procmgr installs the returned cap in
    /// the new process's `ProcessInfo.memmgr_endpoint_cap`.
    pub const REGISTER_PROCESS: u64 = 3;
    /// Procmgr-only: signal process death. The transferred cap (`caps[0]`)
    /// carries the dead process's token; memmgr reclaims every Frame cap
    /// it had issued to that token, runs coalescing, and clears the
    /// per-process record. Idempotent on unknown tokens.
    pub const PROCESS_DIED: u64 = 4;
    /// Permanently transfer a Frame cap into memmgr's pool.
    ///
    /// Used by init and procmgr to return boot-module Frame caps after the
    /// loader has copied the ELF contents into the target process's
    /// `AddressSpace`. The transferred cap (`caps[0]`) becomes part of
    /// memmgr's free pool; subsequent `REQUEST_FRAMES` callers may receive
    /// pages derived from it.
    ///
    /// Wire format:
    /// * `caps[0]` — the Frame cap to transfer (must carry `Rights::RETYPE`).
    ///
    /// memmgr derives `phys_base` and `size` from the cap itself via
    /// `cap_info`, so no caller-side bookkeeping is required. Reply is
    /// `memmgr_errors::SUCCESS` on ingestion, `INVALID_ARGUMENT` if the
    /// cap is missing RETYPE or the pool is full (cap is dropped on
    /// reject).
    pub const DONATE_FRAMES: u64 = 5;

    /// `REQUEST_FRAMES` flag: reply MUST contain exactly one Frame cap
    /// covering all `want_pages`, or fail with
    /// `memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS`. Bit position 0 within
    /// the flags half of `data[0]`.
    pub const REQUIRE_CONTIGUOUS: u32 = 1 << 0;
}

/// Error replies from memmgr.
///
/// memmgr never panics on allocation failure; the caller decides whether
/// to retry, fall back, or propagate the OOM upstream.
pub mod memmgr_errors
{
    pub const SUCCESS: u64 = 0;
    /// `REQUIRE_CONTIGUOUS` was set and no free run satisfies `want_pages`.
    /// Caller may retry without the flag, or fail.
    pub const OUT_OF_MEMORY_CONTIGUOUS: u64 = 1;
    /// Pool cannot cover `want_pages` even fragmented. System-wide RAM
    /// exhaustion.
    pub const OUT_OF_MEMORY_BEST_EFFORT: u64 = 2;
    /// Per-process frame-record list at static cap. The caller is
    /// consuming an unreasonable number of frames.
    pub const QUOTA: u64 = 3;
    /// `want_pages == 0`, reserved flag bits set, page-count mismatch on
    /// `RELEASE_FRAMES`, or token unknown.
    pub const INVALID_ARGUMENT: u64 = 4;
    /// Procmgr-only label called over a non-procmgr token.
    pub const UNAUTHORIZED: u64 = 5;
    /// `REGISTER_PROCESS` failed because the per-process tracking table
    /// is at static cap. Procmgr handles this as a process-creation
    /// failure.
    pub const TOO_MANY_PROCESSES: u64 = 6;
    /// Caller's compiled `MEMMGR_LABELS_VERSION` does not match the receiver's.
    /// `REGISTER_PROCESS` is the handshake entry point and carries the
    /// caller's version as `data[0]`; mismatch here means the caller was
    /// built against a different revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 7;
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

pub const SVCMGR_LABELS_VERSION: u32 = 1;
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

    /// Verb-bit carried by the caller's token to authorise
    /// [`PUBLISH_ENDPOINT`]. Init mints SEND caps on svcmgr's service
    /// endpoint whose token is exactly `PUBLISH_AUTHORITY` (no
    /// per-publisher identity in the low bits today — server-side
    /// auth is binary: have the bit, or don't). Holders trusted to
    /// add names: init itself, devmgr for driver registrations,
    /// svcmgr's own future post-init service launcher.
    ///
    /// The SEND distributed to every process via
    /// `ProcessInfo.service_registry_cap` carries the child's
    /// per-process token (no `PUBLISH_AUTHORITY` bit), so it is
    /// accepted for `QUERY_ENDPOINT` only; svcmgr rejects publish
    /// attempts whose token lacks the bit with
    /// [`svcmgr_errors::UNAUTHORIZED`]. See
    /// `docs/capability-model.md` "verb-bit authority pattern" for
    /// the rationale and parallel use in
    /// `pwrmgr_labels::SHUTDOWN_AUTHORITY`.
    ///
    /// Per-publisher attenuation (e.g. name-prefix restrictions in
    /// the low token bits, so a session daemon can publish only
    /// `user.*`) is the future-work shape and the token namespace
    /// reserves it — see GitHub issue #76.
    pub const PUBLISH_AUTHORITY: u64 = 1u64 << 63;
}

pub const RTC_LABELS_VERSION: u32 = 1;
/// IPC labels for RTC chip drivers (`services/drivers/cmos`,
/// `services/drivers/virtio/rtc`, and future per-board chip drivers).
///
/// Every RTC driver implements exactly one operation: return the current
/// wall-clock time, as `u64` microseconds since the Unix epoch. The
/// `timed` service queries the driver registered under
/// `rtc.primary` in svcmgr once at startup, computes
/// `offset = rtc_us - kernel_monotonic_us`, and serves
/// [`timed_labels::GET_WALL_TIME`] thereafter without further driver IPC.
///
/// Adding a new RTC chip is a matter of writing a driver crate that
/// answers this single label and registering it as `rtc.primary` from
/// devmgr's per-board discovery path. `timed` itself never sees the
/// chip-specific details.
pub mod rtc_labels
{
    /// Request the current wall-clock time.
    ///
    /// Wire format: empty body (no data words, no caps). Reply:
    /// `data[0]` is `u64` microseconds since the Unix epoch. Reply
    /// label carries a status code in the lower 16 bits.
    pub const RTC_GET_EPOCH_TIME: u64 = 1;
}

/// Error replies from RTC chip drivers.
pub mod rtc_errors
{
    pub const SUCCESS: u64 = 0;
    /// Driver could not read the underlying hardware (transient or
    /// permanent device failure). Caller may retry; `timed` treats this
    /// as "wall-clock unavailable" until a subsequent query succeeds.
    pub const READ_FAILED: u64 = 1;
    /// Driver received a label it does not implement.
    pub const UNKNOWN_OPCODE: u64 = 2;
    /// Reserved for a future per-message version handshake. Unused
    /// today — `RTC_LABELS_VERSION` is marker-only and covered by
    /// `PROCESS_ABI_VERSION` at process startup.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
}

pub const TIMED_LABELS_VERSION: u32 = 1;
/// IPC labels for the wall-clock service (`services/timed`).
///
/// `timed` is RTC-source-agnostic: it looks up `rtc.primary` once at
/// startup, queries the driver via [`rtc_labels::RTC_GET_EPOCH_TIME`],
/// computes a stable offset against the kernel's monotonic clock, and
/// serves wall-clock queries from `offset + system_info(ElapsedUs)`. New
/// RTC chip support never changes timed; only the `rtc.primary` driver
/// changes per platform.
pub mod timed_labels
{
    /// Request the current wall-clock time.
    ///
    /// Wire format: empty body. Reply: `data[0]` is `u64` microseconds
    /// since the Unix epoch. Reply label carries a status code in the
    /// lower 16 bits.
    pub const GET_WALL_TIME: u64 = 1;
}

/// Error replies from the wall-clock service.
pub mod timed_errors
{
    pub const SUCCESS: u64 = 0;
    /// No RTC driver was registered under `rtc.primary` at timed's
    /// startup; the offset was never computed. Boards without an RTC
    /// (some real RISC-V hardware) reach this state until an operator
    /// or NTP path seeds the offset out-of-band. Out of scope for this
    /// PR; documented to make the no-RTC path explicit at the wire
    /// level rather than panicking.
    pub const WALL_CLOCK_UNAVAILABLE: u64 = 1;
    pub const UNKNOWN_OPCODE: u64 = 2;
    /// Reserved for a future per-message version handshake. Unused
    /// today — `TIMED_LABELS_VERSION` is marker-only and covered by
    /// `PROCESS_ABI_VERSION` at process startup.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
}

pub const PWRMGR_LABELS_VERSION: u32 = 1;
/// IPC labels for the power manager (`pwrmgr`).
///
/// pwrmgr owns the platform shutdown surface: ACPI S5 on x86-64 (via
/// `AcpiReclaimable` Frame caps plus the `IoPortRange` cap) and SBI SRST
/// on RISC-V (via the `SbiControl` cap). Init transfers those raw caps to
/// pwrmgr during Phase 3 bootstrap; callers that may invoke shutdown
/// receive a tokened SEND on pwrmgr's service endpoint with the
/// [`pwrmgr_labels::SHUTDOWN_AUTHORITY`] verb bit set.
///
/// See `services/pwrmgr/README.md` for the authoritative description.
pub mod pwrmgr_labels
{
    /// Power off the platform.
    ///
    /// Wire format: empty body. The handler verifies the caller's token
    /// carries [`SHUTDOWN_AUTHORITY`] and replies
    /// [`pwrmgr_errors::UNAUTHORIZED`] otherwise. On the success path the
    /// platform powers off and no reply is delivered (QEMU exits the
    /// process). A reply only ever arrives on a rejection or hardware
    /// failure path.
    pub const SHUTDOWN: u64 = 1;
    /// Cold reboot the platform.
    ///
    /// Same authorization gate as [`SHUTDOWN`]. On the success path the
    /// machine cold-boots back through the bootloader.
    pub const REBOOT: u64 = 2;

    /// Authority bit in the pwrmgr-service-endpoint token's high u64
    /// bit. Set on caps minted for consumers permitted to call
    /// [`SHUTDOWN`] and [`REBOOT`]. Without it the handler replies
    /// [`pwrmgr_errors::UNAUTHORIZED`].
    pub const SHUTDOWN_AUTHORITY: u64 = 1u64 << 63;
}

/// Error replies from pwrmgr.
pub mod pwrmgr_errors
{
    pub const SUCCESS: u64 = 0;
    /// Caller's token lacks the verb bit required by the handler
    /// ([`pwrmgr_labels::SHUTDOWN_AUTHORITY`] for SHUTDOWN / REBOOT).
    pub const UNAUTHORIZED: u64 = 1;
    /// Malformed request (unknown opcode, label-version mismatch on a
    /// future handshake, or platform handler failed in a way that
    /// returned to userspace rather than powering off).
    pub const INVALID_REQUEST: u64 = 2;
    /// Reserved for a future per-message version handshake. Unused in
    /// v0.1.0 — the bootstrap-round handshake gates the cap itself.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
    /// Unknown opcode on pwrmgr endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

pub const VFSD_LABELS_VERSION: u32 = 1;
/// IPC labels for the VFS daemon (`vfsd`).
pub mod vfsd_labels
{
    /// Mount a filesystem at a path.
    pub const MOUNT: u64 = 10;
    /// Trigger vfsd to read `/config/mounts.conf` from the
    /// freshly-mounted root filesystem and issue the additional
    /// MOUNTs it describes.
    ///
    /// Empty body. Reply: `SUCCESS` on success (including missing or
    /// empty config — both are legitimate system states);
    /// `PARTIAL_INGEST` with `data[0]` carrying the failed-line count
    /// when one or more mount entries failed; `CONFIG_INGEST_ERROR`
    /// when vfsd's own NS walk or read against the root mount failed.
    /// `UNAUTHORIZED` when the caller's token lacks
    /// [`INGEST_AUTHORITY`]. Synchronous — vfsd does not reply until
    /// every described mount has been attempted.
    pub const INGEST_CONFIG_MOUNTS: u64 = 12;
    /// Mint a fresh tokened SEND on vfsd's namespace endpoint addressing
    /// the synthetic system root at full namespace rights and return it
    /// to the caller.
    ///
    /// Empty request body. Reply: `SUCCESS` with `caps[0]` = the
    /// system-root cap; `UNAUTHORIZED` when the caller's token lacks
    /// [`SEED_AUTHORITY`]. Init calls this once during bootstrap
    /// (after the cmdline-driven root mount completes) to obtain the
    /// seed cap from which all later namespace-cap distribution flows.
    pub const GET_SYSTEM_ROOT_CAP: u64 = 13;

    /// Authority bit in the vfsd-service-endpoint token's high u64
    /// bit. Set on caps minted for consumers permitted to call
    /// [`INGEST_CONFIG_MOUNTS`]. Without it, the handler replies
    /// `UNAUTHORIZED`. Distinct from [`SEED_AUTHORITY`]: a consumer
    /// may hold either, both, or neither.
    pub const INGEST_AUTHORITY: u64 = 1u64 << 63;
    /// Authority bit in the vfsd-service-endpoint token. Set on caps
    /// minted for consumers permitted to call
    /// [`GET_SYSTEM_ROOT_CAP`]. Without it the handler replies
    /// `UNAUTHORIZED`. Holding this cap is equivalent to holding the
    /// system-root cap (the handler is a seed source), so it is only
    /// distributed to init (and svcmgr's restart path, via init's
    /// future per-service policy).
    pub const SEED_AUTHORITY: u64 = 1u64 << 62;
}

pub const NS_LABELS_VERSION: u32 = 1;
/// IPC labels for the namespace protocol (cap-as-namespace surface).
///
/// Numbered in a reserved range above the surviving [`fs_labels`] codes
/// (`FS_READ`, `FS_CLOSE`, `FS_READ_FRAME`, `FS_RELEASE_FRAME`,
/// `FS_RELEASE_ACK`, `FS_MOUNT`, `END_OF_DIR`) so node-cap and per-file
/// requests share one fs-driver endpoint with no opcode collisions.
/// [`fs_labels::END_OF_DIR`] is reused unchanged as the readdir
/// terminator.
///
/// Protocol semantics, including caller-rights checks, name validation,
/// per-entry visibility, and child-cap minting, are owned by the
/// `namespace-protocol` crate's `dispatch_request` function; backends
/// implement the `NamespaceBackend` trait, run their own receive loop,
/// and route each `NS_*` message through `dispatch_request` for reply.
pub mod ns_labels
{
    /// Walk one path component within a directory cap.
    ///
    /// Request label encodes name length in bits 16..32. Request data:
    /// `data[0]` = caller-requested namespace rights (low 24 bits;
    /// `0xFFFF` is interpreted as "everything I'm allowed"); subsequent
    /// data words carry the name bytes packed little-endian, length
    /// taken from the label. No request caps. Reply on success: label =
    /// 0, `data[0]` = entry kind (0 = File, 1 = Dir), `data[1]` =
    /// cached size hint, `caps[0]` = derived child node cap. On error
    /// the label is the matching `NsError` wire code with no caps.
    pub const NS_LOOKUP: u64 = 20;
    /// Attribute snapshot for the node addressed by the caller's token.
    ///
    /// Request: empty body. Reply on success: label = 0, `data[0]` =
    /// size, `data[1]` = `mtime_us` (best-effort; zero on backends that
    /// do not track it), `data[2]` = kind. Error replies match
    /// [`NS_LOOKUP`].
    pub const NS_STAT: u64 = 21;
    /// One-entry-per-call enumeration of the directory addressed by the
    /// caller's token.
    ///
    /// Request: `data[0]` = zero-based entry index. Reply on success:
    /// label = 0, `data[0]` = kind, `data[1]` = name length in bytes,
    /// subsequent data words carry the name bytes packed
    /// little-endian. Reply label is [`fs_labels::END_OF_DIR`] (6) when
    /// `index` is past the last entry. Error replies match
    /// [`NS_LOOKUP`]. No caps in either direction — clients follow up
    /// with [`NS_LOOKUP`] when they want a node cap for a returned
    /// name.
    pub const NS_READDIR: u64 = 22;
}

pub const FS_LABELS_VERSION: u32 = 2;
/// IPC labels for filesystem drivers (FAT, ext4, etc.).
pub mod fs_labels
{
    /// Read from a node cap (driver-side). Inline reply: `data[0]` =
    /// bytes read, payload follows starting at word 1. Drivers cap
    /// per-call payload at the IPC inline ceiling; callers iterate.
    pub const FS_READ: u64 = 2;
    /// Close a node cap, releasing any lazily-allocated driver-side
    /// bookkeeping bound to the file (outstanding `FS_READ_FRAME`
    /// pages, open-file slot, etc.). The caller still cap-deletes the
    /// node cap to drop the kernel-side reference.
    pub const FS_CLOSE: u64 = 3;
    /// Inline write to a file node cap.
    ///
    /// Request: `label = FS_WRITE | (byte_len << 16)` (bits 0-15 = label
    /// ID, bits 16-31 = payload byte length, ≤ 504), `data[0]` = file
    /// byte offset, payload bytes packed from word 1 onward via
    /// `IpcMessageBuilder::bytes(1, &payload)`. Token must carry the
    /// `WRITE` namespace right (see `namespace-protocol::rights`).
    ///
    /// Reply (success label `fs_errors::SUCCESS`): `data[0]` =
    /// `bytes_written` (may be short on `NO_SPACE` or on
    /// partial-cluster failure; callers iterate). Error labels per
    /// [`fs_errors`].
    pub const FS_WRITE: u64 = 4;
    /// End-of-directory marker in `NS_READDIR` replies.
    pub const END_OF_DIR: u64 = 6;
    /// Read file content into a cached Frame cap returned in the reply.
    ///
    /// Request: token identifies the file (per-file cap), `data[0]` =
    /// byte offset (no alignment requirement), `data[1]` = client-chosen
    /// release cookie (must be non-zero). `caps[0]` = optional per-process
    /// release-endpoint SEND, transferred only on the first
    /// `FS_READ_FRAME` for a given (client, file) pair; the driver
    /// records it on the lazy `OpenFile` slot allocated at that point
    /// so its eviction worker can route cooperative `FS_RELEASE_FRAME`
    /// back to the client. Subsequent `FS_READ_FRAME`s for the same
    /// pair carry no caps. Clients that opt out of cooperative release
    /// omit the cap on every call; eviction falls back to hard-revoke.
    /// Reply: `data[0]` = bytes valid in the returned frame starting at
    /// the indicated frame offset, `data[1]` = the same release cookie
    /// echoed back, `data[2]` = byte offset within the returned frame
    /// where the file's content for the requested `offset` begins,
    /// `caps[0]` = single-page Frame cap with `MAP|READ` rights
    /// covering the cached file page.
    ///
    /// `bytes_valid` is bounded by file end, the current cluster
    /// boundary on the underlying filesystem, and the page tail
    /// (`PAGE_SIZE - frame_data_offset`); callers iterate forward from
    /// `offset + bytes_valid` to read past those boundaries.
    pub const FS_READ_FRAME: u64 = 7;
    /// Filesystem-driver request to a client to release a previously-returned
    /// Frame. Sent on the per-file release endpoint cap. Token identifies the
    /// file; `data[0]` = the release cookie naming the Frame to unmap.
    pub const FS_RELEASE_FRAME: u64 = 8;
    /// Client acknowledgement of [`FS_RELEASE_FRAME`]: synchronous reply,
    /// empty body.
    pub const FS_RELEASE_ACK: u64 = 9;
    /// Mount notification from vfsd.
    pub const FS_MOUNT: u64 = 10;
    /// Write file content from a caller-supplied source Frame cap.
    ///
    /// Mirror of [`FS_READ_FRAME`] for the write direction. Caller maps,
    /// fills, then transfers a Frame holding the bytes to write.
    ///
    /// Request: token identifies the file (per-file cap),
    /// `data[0]` = file byte offset (no alignment requirement),
    /// `data[1]` = bytes to write from the frame (`≤ PAGE_SIZE -
    /// frame_data_offset`), `data[2]` = byte offset within the source
    /// frame where the data begins. `caps[0]` = source Frame cap with
    /// at least `MAP|READ` rights, sized one page. Token must carry the
    /// `WRITE` namespace right.
    ///
    /// Reply (label `fs_errors::SUCCESS`): `data[0]` = `bytes_written`
    /// (short on `NO_SPACE` or cluster-boundary truncation; callers
    /// iterate). `caps[0]` = the source Frame cap moved back to the
    /// caller. Errors per [`fs_errors`].
    pub const FS_WRITE_FRAME: u64 = 12;
    /// Create a new file in a directory.
    ///
    /// Request: token = parent-directory cap (must carry `MUTATE_DIR`),
    /// `label = FS_CREATE | (name_len << 16)`, name bytes packed from
    /// word 0 via `IpcMessageBuilder::bytes(0, name)`. Name validated
    /// per `namespace-protocol::validate_name`.
    ///
    /// Reply (label `fs_errors::SUCCESS`): `data[0]` = entry kind (per
    /// `namespace_protocol::NodeKind`), `caps[0]` = node cap for the
    /// newly-created file. Errors include `EXISTS`, `NO_SPACE`,
    /// `PERMISSION_DENIED`.
    pub const FS_CREATE: u64 = 13;
    /// Remove a file or empty directory from a directory.
    ///
    /// Request: token = parent-directory cap (must carry `MUTATE_DIR`),
    /// `label = FS_REMOVE | (name_len << 16)`, name bytes from word 0.
    ///
    /// Reply (label `fs_errors::SUCCESS`): empty body. Errors:
    /// `NOT_FOUND`, `NOT_EMPTY` (directory has entries), `IO_ERROR`.
    pub const FS_REMOVE: u64 = 14;
    /// Create a new (empty) directory in a directory.
    ///
    /// Request: identical shape to [`FS_CREATE`]. Token must carry
    /// `MUTATE_DIR`. Allocates one cluster zero-filled with `.` and
    /// `..` entries.
    ///
    /// Reply: identical shape to [`FS_CREATE`], `data[0]` = kind (Dir).
    pub const FS_MKDIR: u64 = 15;
    /// Rename a directory entry, optionally across directories.
    ///
    /// Request: token = source-directory cap (must carry `MUTATE_DIR`),
    /// `data[0]` = source name length, `data[1]` = destination name
    /// length, name bytes packed contiguously from word 2 via
    /// `IpcMessageBuilder::bytes(2, &concat(src, dst))` — source bytes
    /// first, destination bytes immediately after with no padding.
    /// `caps[0]` = destination-directory cap (must also carry
    /// `MUTATE_DIR`). Source and destination may be the same cap.
    ///
    /// Not atomic: an interrupted rename can leave both names present
    /// or neither. See `services/fs/fat/docs/crash-safety.md`.
    ///
    /// Reply (label `fs_errors::SUCCESS`): empty body. Errors:
    /// `NOT_FOUND` (source missing), `EXISTS` (destination occupied),
    /// `NO_SPACE`, `IO_ERROR`.
    pub const FS_RENAME: u64 = 16;
}

pub const DEVMGR_LABELS_VERSION: u32 = 1;
/// IPC labels for the device manager (`devmgr`).
pub mod devmgr_labels
{
    /// Query for a block device endpoint.
    ///
    /// Mints a `MOUNT_AUTHORITY`-tokened `SEND_GRANT` cap on
    /// `blk_ep` to the caller. Caller's token must have
    /// [`REGISTRY_QUERY_AUTHORITY`] set; the handler replies
    /// `UNAUTHORIZED` otherwise.
    pub const QUERY_BLOCK_DEVICE: u64 = 1;
    /// Query device configuration (`VirtIO` cap locations, etc.).
    /// The caller's token identifies the device.
    pub const QUERY_DEVICE_INFO: u64 = 2;

    /// Authority bit in the devmgr-registry-endpoint token's high
    /// u64 bit. Set on caps minted for consumers permitted to call
    /// [`QUERY_BLOCK_DEVICE`] (today: vfsd). Without it the handler
    /// replies `UNAUTHORIZED`. Gating `QUERY_BLOCK_DEVICE` upstream of
    /// virtio-blk closes the minter-side surface: `MOUNT_AUTHORITY`
    /// caps are never issued to consumers devmgr did not authorise.
    pub const REGISTRY_QUERY_AUTHORITY: u64 = 1u64 << 63;
}

pub const BLK_LABELS_VERSION: u32 = 2;
/// IPC labels for block device drivers.
pub mod blk_labels
{
    /// Authority bit in the block-service-endpoint token's high u64
    /// bit. Set on caps minted for consumers that may invoke
    /// [`REGISTER_PARTITION`] and may issue whole-disk sector reads
    /// via [`BLK_READ_INTO_FRAME`]. The bit is a verb — "may invoke
    /// these labels" — not an identity: multiple consumers may hold
    /// it, and the bit alone does not encode "is vfsd."
    ///
    /// Disjoint from partition-identity tokens. The driver allocates
    /// partition tokens from a monotonic counter in the low bits of
    /// the u64 (top bit clear); the partition table is keyed by the
    /// full token value so collision is impossible.
    pub const MOUNT_AUTHORITY: u64 = 1u64 << 63;

    /// Register a partition range, receiving back a tokened SEND cap
    /// scoped to that partition.
    ///
    /// Caller's token must have [`MOUNT_AUTHORITY`] set; un-tokened
    /// or partition-tokened callers are rejected. Data words:
    /// `[base_lba, length_lba]`. The driver allocates a fresh
    /// partition-identity token, inserts the bound, and replies with
    /// the partition cap in `caps[0]` — server-side derivation is
    /// required because [`MOUNT_AUTHORITY`] caps are tokened and the
    /// kernel rejects re-tokening of a tokened source.
    pub const REGISTER_PARTITION: u64 = 2;
    /// Read one or more contiguous sectors into a caller-supplied Frame cap.
    ///
    /// Request: `data[0]` = starting LBA, `data[1]` = sector count
    /// (`>= 1`; defaults to `1` if `data[1]` is absent). Caps: `caps[0]` =
    /// target Frame (`MAP|WRITE`; the driver writes `count * 512` bytes
    /// starting at offset 0 of the frame, packed contiguously). The frame
    /// must be at least `count * 512` bytes; the driver rejects with
    /// `INVALID_FRAME_CAP` otherwise. `caps[1]` is reserved for a future
    /// per-request release handle and is null today. `caps[2]` is a
    /// reserved IPC-shape slot for a future userspace IOMMU-grant cap;
    /// the kernel transports nothing for this slot and has no awareness
    /// of IOMMU semantics — IOMMU enforcement is permanently userspace.
    /// Reply: empty body, label is the success or error code; the target
    /// Frame is moved back to the caller in `caps[0]` of the reply.
    pub const BLK_READ_INTO_FRAME: u64 = 3;
    /// Write one or more contiguous sectors from a caller-supplied Frame cap.
    ///
    /// Mirror of [`BLK_READ_INTO_FRAME`] for the write direction. The
    /// caller fills the source frame, then issues the request; the
    /// driver reads `count * 512` bytes starting at offset 0 and writes
    /// them to disk.
    ///
    /// Request: `data[0]` = starting LBA, `data[1]` = sector count
    /// (`>= 1`; defaults to `1` if `data[1]` is absent). Caps: `caps[0]` =
    /// source Frame (`MAP|READ`; the driver reads `count * 512` bytes
    /// starting at offset 0 of the frame, packed contiguously). The frame
    /// must be at least `count * 512` bytes; the driver rejects with
    /// `INVALID_FRAME_CAP` otherwise. `caps[1]` is reserved for a future
    /// per-request release handle and is null today. `caps[2]` is a
    /// reserved IPC-shape slot for a future userspace IOMMU-grant cap;
    /// see [`BLK_READ_INTO_FRAME`] for the userspace-IOMMU framing.
    /// Reply: empty body, label is the success or error code; the source
    /// Frame is moved back to the caller in `caps[0]` of the reply (same
    /// discipline as the read path).
    pub const BLK_WRITE_FROM_FRAME: u64 = 4;
}

pub const STREAM_LABELS_VERSION: u32 = 1;
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

/// Reserved log-endpoint tokens.
///
/// Every tokened SEND cap on the log endpoint carries a `u64` token
/// (kernel-attached at `cap_derive_token` time, immutable thereafter).
/// The cap's holder is identified to the receiver by that token. For
/// procmgr-spawned children the token equals the child's procmgr-
/// assigned process token; the kernel-side identity, the receiver's
/// per-sender slot key, and procmgr's death-notification correlator
/// thus all share one u64. To leave room for system-special senders
/// whose identity is not a procmgr process token, procmgr's per-child
/// token counter starts at [`LOG_TOKEN_FIRST_CHILD`].
pub mod log_tokens
{
    /// init's self-identity. Init derives `cap_derive_token(log_ep,
    /// SEND, LOG_TOKEN_INIT)` at boot and uses the cap for its own
    /// `seraph::log!` writes.
    pub const LOG_TOKEN_INIT: u64 = 1;
    /// procmgr's self-identity. Init derives a tokened SEND cap with
    /// this token at procmgr-bootstrap time and seeds it into
    /// `ProcessInfo.log_send_cap` so procmgr's std `_start` can
    /// install it. Procmgr's `seraph::log!` writes ride this cap.
    pub const LOG_TOKEN_PROCMGR: u64 = 2;
    /// First token value procmgr's per-child counter
    /// (`NEXT_PROCESS_TOKEN`) hands out. Lower values are reserved
    /// for the system specials above; raising this leaves room to
    /// reserve more.
    pub const LOG_TOKEN_FIRST_CHILD: u64 = 16;
}

pub const LOG_LABELS_VERSION: u32 = 1;
/// IPC labels for the system log endpoint's legacy discovery interface
/// and the one-shot init-logd → real-logd handover.
///
/// Distinct from [`stream_labels`]: the latter carry payload (bytes,
/// names) on tokened SEND caps that have already been minted; these
/// labels are spoken on caps that mediate cap acquisition or state
/// transfer.
///
/// New std-built spawns post-pivot receive a pre-installed tokened
/// SEND cap in `ProcessInfo.log_send_cap` and never call
/// [`GET_LOG_CAP`]. The label remains for pre-pivot live writers that
/// acquired their tokened caps under it; the receive handler stays in
/// init-logd and real-logd until those callers are migrated.
pub mod log_labels
{
    /// Legacy discovery: request a freshly-minted tokened SEND cap on
    /// the log endpoint.
    ///
    /// Wire format: `word(0) = LOG_LABELS_VERSION` (mismatch → reply
    /// code 3). Reply: one cap (a tokened SEND on the log endpoint
    /// whose token uniquely identifies this caller) plus
    /// `word(0) = status` (zero on success). Callers cache the
    /// returned cap process-globally.
    ///
    /// The receiver mints the token (counter-allocated by init-logd
    /// or real-logd). Tokens are unforgeable identities; display
    /// names registered later via `STREAM_REGISTER_NAME` are mutable
    /// labels bound to that identity.
    pub const GET_LOG_CAP: u64 = 12;

    /// One-shot handover: real-logd pulls init-logd's captured state.
    ///
    /// Sent by real-logd on a dedicated handover endpoint that init
    /// hands it during bootstrap. Init-logd, on receipt, drains any
    /// pending sends from the log endpoint's queue, then replies with
    /// one or more chunks carrying:
    ///
    /// * The token table — for every active sender token init-logd
    ///   has seen, the `(token, display_name)` pair.
    /// * The captured-history ring — all complete lines init-logd has
    ///   buffered since boot, attributed by token and timestamped at
    ///   the original receipt instant.
    /// * The next-token counter (init-logd's
    ///   `INIT_DISCOVERY_NEXT_TOKEN` value at the moment of handover)
    ///   so real-logd's `GET_LOG_CAP` handler can continue the same
    ///   sequence for any further legacy callers.
    ///
    /// Wire encoding is documented in
    /// `services/logd/docs/handover-protocol.md`. After the final
    /// chunk is replied, init-logd breaks its receive loop and calls
    /// `sys_thread_exit`.
    pub const HANDOVER_PULL: u64 = 13;
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
    /// Invalid argument to an IPC request.
    pub const INVALID_ARGUMENT: u64 = 7;
    /// File not found while walking a namespace cap on the spawner side.
    /// Reserved for callers that want a structured error before issuing
    /// `CREATE_FROM_FILE`.
    pub const FILE_NOT_FOUND: u64 = 9;
    /// I/O error reading file via the supplied file cap during
    /// `CREATE_FROM_FILE`.
    pub const IO_ERROR: u64 = 10;
    /// `mem_map` or scratch mapping failed during ELF page load.
    pub const MAP_FAILED: u64 = 11;
    /// Cap rights derivation failed (e.g. `derive_frame_for_prot`)
    /// during ELF page load.
    pub const INSUFFICIENT_RIGHTS: u64 = 12;
    /// Caller's cap lacks the required authority token for a gated
    /// label (e.g. `REGISTER_DEATH_EQ` requires `DEATH_EQ_AUTHORITY`).
    pub const UNAUTHORIZED: u64 = 13;
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
    /// `INGEST_CONFIG_MOUNTS` walked the namespace successfully but
    /// reading `/config/mounts.conf` itself failed (lookup error other
    /// than `NotFound`, or `FS_READ` failure). Distinguishes "config
    /// not present (legitimate)" from "config present but unreadable
    /// (operator-relevant)" at the wire.
    pub const CONFIG_INGEST_ERROR: u64 = 7;
    /// `INGEST_CONFIG_MOUNTS` parsed the config but one or more
    /// described mounts failed (invalid UUID, partition not found,
    /// fatfs spawn failure, etc.). `data[0]` carries the failed-line
    /// count. Distinct from `CONFIG_INGEST_ERROR` (the config itself
    /// could not be read) and `SUCCESS` (every described mount
    /// landed).
    pub const PARTIAL_INGEST: u64 = 8;
    /// Caller's token lacks the verb bit required by the handler
    /// (e.g. `INGEST_AUTHORITY` for `INGEST_CONFIG_MOUNTS`,
    /// `SEED_AUTHORITY` for `GET_SYSTEM_ROOT_CAP`).
    pub const UNAUTHORIZED: u64 = 9;
    /// Caller's compiled `VFSD_LABELS_VERSION` does not match the receiver's.
    /// The handshake-checked entry point (`GET_SYSTEM_ROOT_CAP`) carries
    /// the caller's version as `data[0]`; mismatch here means the caller
    /// was built against a different revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 10;
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
    /// Cooperative-release watchdog fired; the driver revoked the parent
    /// Frame cap and any derived caps the client still held are now dead.
    pub const RELEASE_TIMEOUT: u64 = 5;
    /// `FS_READ_FRAME` cookie is invalid (zero — collides with the
    /// `OutstandingPage::None` sentinel in fs driver tracking).
    pub const BAD_FRAME_OFFSET: u64 = 6;
    /// Caller's node-cap token lacks a rights bit required by the
    /// requested operation (see `namespace-protocol::rights`).
    pub const PERMISSION_DENIED: u64 = 7;
    /// Caller's compiled `FS_LABELS_VERSION` does not match the receiver's.
    /// `FS_MOUNT` is the handshake entry point and carries the caller's
    /// version as `data[0]`; mismatch here means the caller was built
    /// against a different revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 8;
    /// Mutation refused: the target name already exists in the parent
    /// directory (`FS_CREATE`, `FS_MKDIR`, `FS_RENAME` destination).
    pub const EXISTS: u64 = 9;
    /// Mutation refused: the volume has no free cluster, or the parent
    /// directory has no room for a new entry (FAT16 fixed root full;
    /// FAT32 cluster-chain extension failed).
    pub const NO_SPACE: u64 = 10;
    /// `FS_REMOVE` refused: the target directory is non-empty.
    pub const NOT_EMPTY: u64 = 11;
    /// Operation refused because the target is a directory (e.g.
    /// `FS_WRITE` on a directory cap) or because the operation is
    /// permitted only on files.
    pub const IS_A_DIRECTORY: u64 = 12;
    /// Unknown opcode on fs-driver endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

/// Error replies from devmgr.
pub mod devmgr_errors
{
    pub const SUCCESS: u64 = 0;
    /// Cap derivation failed, or invalid device index.
    pub const INVALID_REQUEST: u64 = 1;
    /// Caller's token lacks the verb bit required by the handler
    /// (e.g. `REGISTRY_QUERY_AUTHORITY` for `QUERY_BLOCK_DEVICE`).
    pub const UNAUTHORIZED: u64 = 2;
    /// Caller's compiled `DEVMGR_LABELS_VERSION` does not match the receiver's.
    /// `QUERY_BLOCK_DEVICE` is the handshake entry point and carries the
    /// caller's version as `data[0]`; mismatch here means the caller was
    /// built against a different revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
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
    /// Caller's compiled `SVCMGR_LABELS_VERSION` does not match the receiver's.
    /// `REGISTER_SERVICE` is the handshake entry point and carries the
    /// caller's version as `data[0]` (with all other words shifted by +1);
    /// mismatch here means the caller was built against a different
    /// revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 7;
    /// Caller's token lacks [`svcmgr_labels::PUBLISH_AUTHORITY`] on a
    /// `PUBLISH_ENDPOINT` request.
    pub const UNAUTHORIZED: u64 = 8;
    /// Client-side: the underlying `ipc_call` returned `Err` (no reply
    /// from svcmgr, transport-level failure). Never emitted by svcmgr
    /// itself — synthesised by `registry-client` to give callers a
    /// uniform status surface.
    pub const IPC_FAILED: u64 = 9;
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
    /// Frame cap rejected: `BLK_READ_INTO_FRAME` target missing
    /// `MAP|WRITE` rights, `BLK_WRITE_FROM_FRAME` source missing
    /// `MAP|READ` rights, sized other than one page, or absent.
    pub const INVALID_FRAME_CAP: u64 = 5;
    /// Caller's compiled `BLK_LABELS_VERSION` does not match the receiver's.
    /// `REGISTER_PARTITION` is the handshake entry point and carries the
    /// caller's version as `data[0]` (with `base_lba` shifted to `data[1]`
    /// and `length_lba` to `data[2]`); mismatch here means the caller was
    /// built against a different revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 6;
    /// Unknown opcode on block endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

// ── Protocol constants ─────────────────────────────────────────────────────

/// Maximum path length in bytes (6 IPC data words = 48 bytes).
pub const MAX_PATH_LEN: usize = 48;

/// Maximum argv blob size in bytes across an IPC. Constrained by
/// `MSG_DATA_WORDS_MAX * 8 = 512` (full data area). 256 comfortably fits
/// typical service-argv cases and leaves slack for any other words a
/// message body may carry. The `ProcessInfo` page can hold more, but
/// expanding this also requires extending the label encoding
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
