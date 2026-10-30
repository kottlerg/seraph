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
//! creator), typed error-code constants, label modules, and the shared
//! policy and code tables listed in `shared/ipc/README.md`.

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
// its namespace. When it is bumped, and what each of the four categories
// below means, is specified in shared/ipc/README.md § Wire Stability; this
// block keeps the per-namespace assignment, with the handshake each check
// rides on.
//
//   Handshake-checked at first contact (`data[0]` unless noted):
//     FS_LABELS_VERSION     — fs_labels::FS_MOUNT             (vfsd ↔ fatfs)
//     VFSD_LABELS_VERSION   — vfsd_labels::GET_SYSTEM_ROOT_CAP (init ↔ vfsd)
//     BLK_LABELS_VERSION    — blk_labels::REGISTER_PARTITION   (vfsd ↔ virtio-blk)
//     MEMMGR_LABELS_VERSION — memmgr_labels::REGISTER_PROCESS   (procmgr ↔ memmgr)
//     SVCMGR_LABELS_VERSION — every svcmgr handover endowment `CAPS` round,
//                             in `data[1]` after the round kind (init ↔ svcmgr)
//
//   Checked on every request (`data[0]`):
//     DEVMGR_LABELS_VERSION — every devmgr_labels request
//
//   Implicitly covered by a parent-channel handshake:
//     NS_LABELS_VERSION     — caps from vfsd_labels / fs_labels handshakes
//
//   Marker-only (no clean parent-channel handshake exists, and per-message
//   inlining would conflict with existing label-bit usage or cost wire bytes
//   on every call; PROCESS_ABI_VERSION at process startup gives
//   coarse-grained coverage in lockstep with workspace-inherited versioning):
//     PROCMGR_LABELS_VERSION
//     PWRMGR_LABELS_VERSION
//     RTC_LABELS_VERSION
//     TIMED_LABELS_VERSION
//     SERIAL_LABELS_VERSION
//     FB_LABELS_VERSION
//     INPUT_LABELS_VERSION
//     LOG_LABELS_VERSION    — log_labels::GET_LOG_CAP carries it, but no
//                             caller issues that handshake
//     STREAM_LABELS_VERSION — stream caps arrive pre-installed in
//                             ProcessInfo.log_send_cap (init derives its
//                             own), not via a handshake

/// Wire-protocol version of [`procmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const PROCMGR_LABELS_VERSION: u32 = 3;
/// IPC labels for the process manager (`procmgr`).
pub mod procmgr_labels
{
    /// Create a new process from a boot module Memory cap. Caps: `[module,
    /// creator_endpoint?]`. Stdio pipes (stdin/stdout/stderr) are
    /// configured through one or more [`CONFIGURE_PIPE`] calls against
    /// the returned badged `process_handle` — procmgr's CREATE path
    /// carries no stdio caps so stdout and stderr can be piped
    /// independently and so the core process-creation primitive stays
    /// stdio-agnostic.
    pub const CREATE_PROCESS: u64 = 1;
    /// Start a previously created (suspended) process.
    pub const START_PROCESS: u64 = 2;
    /// Create a new process from a caller-supplied file cap (ELF binary).
    ///
    /// The caller already walked its own namespace cap to the binary node
    /// and attaches the resulting badged file cap. Procmgr issues
    /// `FS_READ` / `FS_READ_MEMORY` against that cap to stream the ELF —
    /// it never holds a namespace cap of its own.
    ///
    /// Label layout:
    /// * bits `[0..16]` — opcode (`CREATE_FROM_FILE`)
    /// * bits `[16..18]` — flags ([`CREATE_PINNED`], [`CREATE_DEATH_RELAY`])
    /// * bits `[18..23]` — `CREATE_PRIORITY` (see [`CREATE_PRIORITY_SHIFT`])
    /// * bits `[23..28]` — `CREATE_BAND_MAX` (see [`CREATE_BAND_MAX_SHIFT`])
    /// * bits `[28..32]` — reserved (zero; see [`CREATE_RESERVED_MASK`])
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
    /// Caps: `[file_cap, creator_endpoint?, death_relay?]`. `file_cap`
    /// ownership transfers to procmgr; procmgr `FS_CLOSE`s and
    /// `cap_delete`s it after the load completes (success or failure). The
    /// optional `death_relay` POST-only `EventQueue` cap is present iff
    /// [`CREATE_DEATH_RELAY`] is set in the label; when present it is the
    /// LAST cap in the message (procmgr peels it off the tail, so the
    /// `creator_endpoint` slot stays positionally fixed regardless of
    /// relay presence), and it is a cap of its own: a relay request whose
    /// only cap is `file_cap` is refused with `INVALID_ARGUMENT`. Stdio
    /// pipes are installed via separate [`CONFIGURE_PIPE`] calls between
    /// create and start.
    pub const CREATE_FROM_FILE: u64 = 13;
    /// Label flag (bit 16) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]:
    /// create the new process *pinned* — eager-mapped, with no system pager.
    /// Demand paging is the default: when this flag is clear, procmgr binds
    /// the child's main thread fault handler to memmgr (the system pager),
    /// delegates the child `AddressSpace` cap to memmgr via
    /// `memmgr_labels::DELEGATE_ASPACE`, and advertises the pager in
    /// `ProcessInfo` (`pager_endpoint_cap` / `pager_badge`) so the runtime
    /// inherits it onto spawned threads. Set this flag only for a process
    /// that cannot depend on the fault path — a driver doing DMA, whose
    /// memory a device may write before a demand fault could back it.
    /// Occupies bit 16 of the reserved `[16..32]` label window. init,
    /// memmgr, and procmgr are pre-pager and never routed through this
    /// binding path, so they are pinned by construction regardless.
    pub const CREATE_PINNED: u64 = 1 << 16;
    /// Label flag (bit 17) for [`CREATE_FROM_FILE`]: the message carries a
    /// trailing death-relay POST-only `EventQueue` cap (the LAST cap in the
    /// message, which then carries at least two caps). Once the child is
    /// recorded, procmgr binds it as an `AddressSpace` death observer
    /// (correlator 0) on the child so that a terminal fault in any
    /// of the child's threads posts the fault class straight to the
    /// spawner's own death queue, letting `Child::wait()` return. procmgr
    /// `cap_delete`s its copy after the bind (the kernel captured the
    /// `EventQueue` state at bind time). Occupies bit 17 of the reserved
    /// `[16..32]` label window.
    pub const CREATE_DEATH_RELAY: u64 = 1 << 17;
    /// Bit offset of the `CREATE_PRIORITY` field (bits `[18..23]`) in a
    /// [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`] label: the priority level
    /// the child's initial thread is created at. `0` = unspecified —
    /// procmgr places the child at
    /// [`crate::sched_policy::DEFAULT_SPAWN_PRIORITY`] clamped to the
    /// child's band. A nonzero value must satisfy
    /// `1 <= priority <= band_max <= creator's band ceiling`; violations
    /// reply `INVALID_ARGUMENT`. Occupies bits 18–22 of the reserved
    /// `[16..32]` label window.
    pub const CREATE_PRIORITY_SHIFT: u32 = 18;
    /// Bit offset of the `CREATE_BAND_MAX` field (bits `[23..28]`): the
    /// upper bound of the baseline `SchedControl` band procmgr mints into
    /// the child (`[1, band_max]`, delivered via
    /// `ProcessInfo.sched_control_cap`). `0` = unspecified — the child
    /// receives a copy of its creator's band. A nonzero value must not
    /// exceed the creator's band ceiling. Occupies bits 23–27 of the
    /// reserved `[16..32]` label window.
    pub const CREATE_BAND_MAX_SHIFT: u32 = 23;
    /// Width mask of each 5-bit scheduling field in the create label.
    pub const CREATE_SCHED_FIELD_MASK: u64 = 0x1F;
    /// Still-reserved bits `[28..32]` of the create-label window. Procmgr
    /// rejects labels with any of these set (`INVALID_ARGUMENT`), so a
    /// future field addition is provably additive: existing senders are
    /// known to send zeros.
    pub const CREATE_RESERVED_MASK: u64 = 0xF << 28;

    /// Pack the scheduling fields of a [`CREATE_PROCESS`] /
    /// [`CREATE_FROM_FILE`] label. `0` in either field means
    /// "unspecified" (procmgr applies its defaults; see
    /// [`CREATE_PRIORITY_SHIFT`] / [`CREATE_BAND_MAX_SHIFT`]).
    #[must_use]
    pub const fn create_sched_bits(priority: u8, band_max: u8) -> u64
    {
        ((priority as u64) & CREATE_SCHED_FIELD_MASK) << CREATE_PRIORITY_SHIFT
            | ((band_max as u64) & CREATE_SCHED_FIELD_MASK) << CREATE_BAND_MAX_SHIFT
    }

    /// Destroy a process, sent on its badged `process_handle`; procmgr
    /// deletes its kernel objects and sends memmgr `PROCESS_DIED` for it.
    /// Specified in `services/procmgr/docs/ipc-interface.md` § Label 8:
    /// `DESTROY_PROCESS`.
    pub const DESTROY_PROCESS: u64 = 8;
    /// Query a process's state. Caller identifies the target via the badged
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
    /// Called on the badged `process_handle`, with the direction in
    /// `data[0]` ([`PIPE_DIR_STDIN`] / [`PIPE_DIR_STDOUT`] /
    /// [`PIPE_DIR_STDERR`]). Specified, with its caps, ordering, and replies,
    /// in `services/procmgr/docs/ipc-interface.md` § Label 11:
    /// `CONFIGURE_PIPE`.
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
    /// Request: caller invokes on the badged `process_handle` returned
    /// by [`CREATE_PROCESS`] or [`CREATE_FROM_FILE`]; procmgr uses
    /// `recv.badge` to find the entry. Wire format:
    /// * `caps[0]` — root cap to deliver to the child (mandatory).
    /// * `caps[1]` — cwd cap to deliver to the child (optional). When
    ///   absent the child's `current_dir_cap` slot stays zero.
    ///
    /// Spawners obtain these caps by `cap_copy` of their own
    /// `root_dir_cap()` / `current_dir_cap()` (parent-inherit default)
    /// or by walk-and-attenuate against a sub-tree. procmgr does not
    /// validate cap shape — any badged SEND on a namespace endpoint
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
    /// `INVALID_BADGE` if the `process_handle` is unknown.
    /// `INVALID_ARGUMENT` if no cap was provided in `caps[0]`.
    /// Idempotent before start; later calls overwrite the previous
    /// caps (the prior caps are `cap_delete`'d procmgr-side).
    pub const CONFIGURE_NAMESPACE: u64 = 12;

    /// Register a death-notification `EventQueue` cap (`caps[0]`, POST
    /// right) with procmgr, which binds it as a second death observer on
    /// the main thread of every supervised process (threads a process
    /// creates itself carry no binding), so the kernel posts each
    /// process's main-thread death to it.
    /// Real-logd uses it to evict the slot of a dead sender. Specified,
    /// with its replies, in `services/procmgr/docs/ipc-interface.md`
    /// § `REGISTER_DEATH_EQ` — install logd's death observer.
    pub const REGISTER_DEATH_EQ: u64 = 14;

    /// Badge bit on procmgr service caps that authorises
    /// `REGISTER_DEATH_EQ`; un-badged or differently-badged callers are
    /// rejected. Who holds it is in `services/procmgr/docs/ipc-interface.md`
    /// § `REGISTER_DEATH_EQ` — install logd's death observer.
    pub const DEATH_EQ_AUTHORITY: u64 = 1u64 << 62;

    /// Hand init's kernel-object caps and reclaimable Memory caps to
    /// procmgr for the reap after init exits; init calls it on its exit
    /// path, then `sys_thread_exit`s. The rounds, the death-EQ binding on
    /// both init threads (correlator [`INIT_REAP_CORRELATOR`]), and the
    /// replies are specified in `services/procmgr/docs/ipc-interface.md`
    /// § `REGISTER_INIT_TEARDOWN` — init reap handoff.
    pub const REGISTER_INIT_TEARDOWN: u64 = 15;

    /// Notification end of init's reap-handoff cap stream. After this call
    /// init has no caps left to transfer; procmgr's state machine
    /// transitions to "armed". Init calls `sys_thread_exit` immediately
    /// after this IPC replies. Replies `UNAUTHORIZED` from a badged sender,
    /// and `INVALID_ARGUMENT` when no handoff is open or the state machine
    /// is already armed.
    pub const INIT_TEARDOWN_DONE: u64 = 16;

    /// Reserved death-notification correlator used by `REGISTER_INIT_TEARDOWN`.
    /// Per-child correlators are `process_badge as u32`; procmgr redraws a
    /// random badge whose low 32 bits are below
    /// `log_badges::LOG_BADGE_FIRST_CHILD` or equal this value, so the two
    /// never collide.
    pub const INIT_REAP_CORRELATOR: u32 = u32::MAX;
}

/// System-wide scheduling-policy constants: the per-service priority level
/// map. Pure userspace policy — the kernel defines only the level space
/// (`[PRIORITY_MIN, PRIORITY_MAX]`, level 31 reserved) and the
/// `SchedControl` band mechanism; every number here is a placement choice
/// and can change without touching the kernel.
///
/// Level map (30 = init, kernel-assigned; 31 reserved):
///
/// | Level | Occupant |
/// |---|---|
/// | 30 | init (kernel-assigned `INIT_PRIORITY`) |
/// | 28 | memmgr |
/// | 27 | procmgr |
/// | 26 | init-logd, serial, virtio-blk |
/// | 25 | framebuffer, rtc, virtio-input |
/// | 24 | devmgr |
/// | 23 | vfsd, fs drivers (fatfs) |
/// | 21 | svcmgr |
/// | ≤21 | svcmgr-launched services, per `.svc` recipe (logd 18, timed/pwrmgr 16, terminal/svctest/usertest 10, crasher 5), and what they spawn (the shell, at 5 from terminal) |
///
/// Levels for svcmgr-launched services live in their `.svc` recipes
/// (`priority = ...` / `sched_max = ...`), not here — this module carries
/// only the levels assigned by init, procmgr, devmgr, and vfsd directly.
pub mod sched_policy
{
    /// Upper bound of the baseline `SchedControl` band init delegates to
    /// the spawn chain: init splits its root `[1, 30]` cap at
    /// `BASELINE_PRIORITY_MAX + 1`, keeps the elevated remainder
    /// (`[29, 30]`, which stays alive but unreachable in init's pinned
    /// `CSpace` after its reap; releasing it there is design intent, not
    /// yet implemented, per `docs/process-lifecycle.md` § Init reap and
    /// #540), and hands the baseline `[1, 28]` to memmgr and procmgr.
    /// Every band procmgr mints for a child is a (possibly narrowed)
    /// descendant of this baseline, so no spawned process can ever reach
    /// `[29, 30]`.
    pub const BASELINE_PRIORITY_MAX: u8 = 28;

    /// Priority procmgr assigns when a `CREATE_PROCESS` /
    /// `CREATE_FROM_FILE` label carries no `CREATE_PRIORITY` field,
    /// clamped to the child's band.
    pub const DEFAULT_SPAWN_PRIORITY: u8 = 10;

    /// memmgr — the system pager and frame-pool owner. Everything below
    /// it can fault into it, so it outranks all of them.
    pub const MEMMGR_PRIORITY: u8 = 28;

    /// procmgr — process lifecycle authority.
    pub const PROCMGR_PRIORITY: u8 = 27;

    /// init's log-mediator thread (init-logd). Above every log producer
    /// it serves during bootstrap; matches the boot-critical drivers.
    pub const INIT_LOGD_PRIORITY: u8 = 26;

    /// Boot-critical device drivers: serial (console path) and
    /// virtio-blk (root-disk path).
    pub const BOOT_DRIVER_PRIORITY: u8 = 26;

    /// Non-boot-critical device drivers: framebuffer, RTC, virtio-input.
    pub const AUX_DRIVER_PRIORITY: u8 = 25;

    /// devmgr — device enumeration and driver supervision.
    pub const DEVMGR_PRIORITY: u8 = 24;

    /// devmgr's band ceiling. Deliberately above its own level so it can
    /// place the drivers it spawns at [`BOOT_DRIVER_PRIORITY`] /
    /// [`AUX_DRIVER_PRIORITY`].
    pub const DEVMGR_BAND_MAX: u8 = 26;

    /// vfsd — the namespace/VFS authority.
    pub const VFSD_PRIORITY: u8 = 23;

    /// Filesystem drivers (fatfs), spawned by vfsd at its own level: an
    /// fs driver is the blocking dependency of every vfsd read.
    pub const FS_DRIVER_PRIORITY: u8 = 23;

    /// svcmgr — service supervisor and discovery registry. Above every
    /// service it launches (recipes are validated against its band).
    pub const SVCMGR_PRIORITY: u8 = 21;
}

/// Wire-protocol version of [`memmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const MEMMGR_LABELS_VERSION: u32 = 5;
/// IPC labels for the memory manager (`memmgr`).
///
/// memmgr owns the userspace RAM frame pool. All std-built processes
/// bootstrap their heap by calling `REQUEST_MEMORY_CAPS` on a badged SEND
/// cap installed in `ProcessInfo.memmgr_endpoint_cap`. Procmgr is the
/// privileged caller that registers and retires process badges.
///
/// See `services/memmgr/docs/ipc-interface.md` for the authoritative wire
/// shape.
pub mod memmgr_labels
{
    /// Allocate one or more Memory caps covering at least `want_pages` pages,
    /// from any badged cap; [`super::memmgr_grant_layout`] checks the reply
    /// shape. Specified in `services/memmgr/docs/ipc-interface.md` § Label 1:
    /// `REQUEST_MEMORY_CAPS`.
    pub const REQUEST_MEMORY_CAPS: u64 = 1;
    /// Return previously granted regions to the pool mid-life, named by the
    /// `phys_base` the grant reply reported, from any badged cap. Specified in
    /// `services/memmgr/docs/ipc-interface.md` § Label 2:
    /// `RELEASE_MEMORY_CAPS`.
    pub const RELEASE_MEMORY_CAPS: u64 = 2;
    /// Procmgr-only: register a new process and receive the badged SEND cap
    /// procmgr installs in the new process's `ProcessInfo.memmgr_endpoint_cap`.
    /// Specified in `services/memmgr/docs/ipc-interface.md` § Label 3:
    /// `REGISTER_PROCESS`.
    pub const REGISTER_PROCESS: u64 = 3;
    /// Procmgr-only: notify process death. `data[0]` carries the dead process's
    /// memmgr badge (no cap is required); memmgr reclaims every Memory cap
    /// it had issued to that badge, runs coalescing, and clears the
    /// per-process record. Idempotent on unknown badges.
    pub const PROCESS_DIED: u64 = 4;
    /// Procmgr-only: permanently transfer a batch of Memory caps into
    /// memmgr's pool; the caller is procmgr's init reap (donated set:
    /// `docs/process-lifecycle.md` § Init reap). Specified in
    /// `services/memmgr/docs/ipc-interface.md` § Label 5:
    /// `DONATE_MEMORY_CAPS`.
    pub const DONATE_MEMORY_CAPS: u64 = 5;
    /// Read-only query of the all-RAM-accounted identity. Callable from any
    /// badged cap; returns aggregate counts only — no caps, no state change.
    ///
    /// Wire format: request carries no words. Reply (`SUCCESS`):
    ///
    /// * `data[0]` — `system_ram_bytes`: total installed RAM the kernel
    ///   computed at boot (delivered to memmgr via the bootstrap facts).
    /// * `data[1]` — `kernel_reserved_bytes`: the fixed kernel reserve
    ///   (`system_ram_bytes` minus every `owns_memory` page minted to init).
    /// * `data[2]` — `pool_total_bytes`: every page memmgr owns, across free
    ///   runs, in-use bootstrap arenas, and reap donations.
    /// * `data[3]` — `free_bytes`: the subset of `pool_total_bytes` currently
    ///   parked in free runs (owned by memmgr, lent to no process). Unlike
    ///   `pool_total` it falls on allocation and rises on reclamation
    ///   (`PROCESS_DIED`, `RELEASE_MEMORY_CAPS`, `UNREGISTER_REGION`), so a
    ///   caller polls it to confirm a dead process's pages were reclaimed.
    ///
    /// The all-RAM-accounted identity is `data[0] == data[1] + data[2]`: every
    /// page of RAM is either fixed kernel reserve or in memmgr's pool, with no
    /// invisible residue. A nonzero `data[0] - data[1] - data[2]` is leaked
    /// "dark" memory. `data[3]` is an appended field — readers needing only the
    /// identity may ignore it.
    pub const QUERY_POOL_STATUS: u64 = 6;
    /// Register a demand-paged anonymous region for the calling process.
    ///
    /// Universal label — attributed to the caller by `recv.badge` (the
    /// per-process badge minted at [`REGISTER_PROCESS`], carried by the
    /// badged SEND cap installed in `ProcessInfo.memmgr_endpoint_cap`).
    /// memmgr records the region against that badge's tracking entry; a
    /// later page fault inside a registered region is backed on demand by
    /// the fault-handler arm, while a fault outside every registered region
    /// is declined (the faulting thread is killed), preserving segfault
    /// semantics.
    ///
    /// Wire format:
    /// * `data[0]` — `va_base` (page-aligned virtual address).
    /// * `data[1]` — `len_bytes` (region length; page-multiple, nonzero).
    /// * `data[2]` — `prot` (MAP_* protection bits; W^X enforced).
    ///
    /// Reply: `memmgr_errors::SUCCESS`; `INVALID_ARGUMENT` (bad alignment,
    /// zero length, W^X violation, unknown prot bit, unknown badge, or
    /// overlap); or `QUOTA`
    /// (metadata arena could not grow — system RAM exhausted). No mapping is
    /// installed here — backing happens lazily on fault, and only once procmgr
    /// has delegated the process `AddressSpace` cap via [`DELEGATE_ASPACE`].
    /// Reverse with [`UNREGISTER_REGION`].
    pub const REGISTER_REGION: u64 = 7;
    /// Procmgr-only: delegate a demand-paged child's `AddressSpace` cap to
    /// memmgr so the pager can map frames into it on fault.
    ///
    /// Sent at process finalize for demand-paged processes — the default;
    /// not those created with the
    /// [`CREATE_PINNED`](super::procmgr_labels::CREATE_PINNED) flag — after the child
    /// address space exists (so it cannot ride on the earlier
    /// [`REGISTER_PROCESS`] handshake).
    /// memmgr stores the transferred cap against the child's tracking
    /// entry, keyed by the badge minted at [`REGISTER_PROCESS`].
    ///
    /// Wire format:
    /// * `data[0]` — `child_memmgr_badge` (from the child's
    ///   `REGISTER_PROCESS` reply).
    /// * `caps[0]` — the child `AddressSpace` cap (MAP rights); ownership
    ///   transfers to memmgr.
    ///
    /// Reply: `memmgr_errors::SUCCESS`; `UNAUTHORIZED` (caller is not
    /// procmgr); or `INVALID_ARGUMENT` (unknown badge or missing cap — a
    /// stray transferred cap is dropped).
    pub const DELEGATE_ASPACE: u64 = 8;

    /// Unregister a demand-paged region previously [`REGISTER_REGION`]'d,
    /// reclaiming every frame memmgr mapped inside it.
    ///
    /// Universal label — attributed to the caller by `recv.badge`. memmgr
    /// finds the exact-match region, unmaps each backing frame from the
    /// caller's `AddressSpace`, returns the frame to the pool, and frees the
    /// region. The reverse of [`REGISTER_REGION`] plus the on-fault backing;
    /// used when a demand-paged stack (or other anonymous region) is torn down
    /// mid-life — e.g. ruststd freeing a joined thread's guarded stack.
    ///
    /// Wire format:
    /// * `data[0]` — `va_base` (must equal the registered base).
    /// * `data[1]` — `len_bytes` (must equal the registered length).
    ///
    /// Reply: `memmgr_errors::SUCCESS`; `INVALID_ARGUMENT` (unknown badge or no
    /// region matches `[va_base, len)` exactly).
    pub const UNREGISTER_REGION: u64 = 9;

    /// `REQUEST_MEMORY_CAPS` flag: reply MUST contain exactly one Memory cap
    /// covering all `want_pages`, or fail with
    /// `memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS`. Bit position 0 within
    /// the flags half of `data[0]`.
    pub const REQUIRE_CONTIGUOUS: u32 = 1 << 0;
}

/// Split a `memmgr_labels::REQUEST_MEMORY_CAPS` success reply into its page
/// counts and phys bases, one of each per transferred cap: `data[1 + i]` and
/// `data[1 + count + i]` for `i` below the declared `count` in `data[0]`
/// (services/memmgr/docs/ipc-interface.md § Label 1).
///
/// The reply is wire input, so nothing is indexed until it passes these
/// checks. Returns `None` for an error label, a reply with no data words, a
/// declared count of zero or other than the number of caps transferred, or
/// data words too few to cover the declared count; the phys words of such a
/// reply sit at an offset its count does not establish, so no base is read.
#[must_use]
pub fn memmgr_grant_layout(reply: &IpcMessage) -> Option<(&[u64], &[u64])>
{
    let words = reply.words();
    let count = reply.caps().len();
    let declared = *words.first()?;
    // `count` is bounded by `MSG_CAP_SLOTS_MAX`, so `1 + 2 * count` cannot
    // overflow.
    if reply.label != memmgr_errors::SUCCESS
        || count == 0
        || declared != count as u64
        || words.len() < 1 + 2 * count
    {
        return None;
    }
    Some((&words[1..=count], &words[(1 + count)..=(2 * count)]))
}

/// Error replies from memmgr.
///
/// memmgr never panics on allocation failure; the caller decides whether
/// to retry, fall back, or propagate the OOM upstream.
pub mod memmgr_errors
{
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// `REQUIRE_CONTIGUOUS` was set and no free run satisfies `want_pages`.
    /// Caller may retry without the flag, or fail.
    pub const OUT_OF_MEMORY_CONTIGUOUS: u64 = 1;
    /// Pool cannot cover `want_pages` even fragmented. System-wide RAM
    /// exhaustion.
    pub const OUT_OF_MEMORY_BEST_EFFORT: u64 = 2;
    /// memmgr could not allocate per-process tracking metadata for a frame or
    /// region: the self-hosted node arena could not grow because system RAM is
    /// exhausted. Per-process region and frame counts are otherwise RAM-bound,
    /// not capped by a constant.
    pub const QUOTA: u64 = 3;
    /// A malformed request: the per-label cases are listed in
    /// `services/memmgr/docs/ipc-interface.md` (for example `want_pages == 0`
    /// or reserved flag bits on `REQUEST_MEMORY_CAPS`, an unregistered badge,
    /// or a bad region on `REGISTER_REGION`).
    pub const INVALID_ARGUMENT: u64 = 4;
    /// Procmgr-only label called over a non-procmgr badge.
    pub const UNAUTHORIZED: u64 = 5;
    /// `REGISTER_PROCESS` could not complete: the tracking table could not
    /// take a new entry, the badge draw failed, or the reply cap could not
    /// be derived. Procmgr handles this as a process-creation failure.
    pub const TOO_MANY_PROCESSES: u64 = 6;
    /// Caller's compiled `MEMMGR_LABELS_VERSION` does not match the receiver's.
    /// `REGISTER_PROCESS` is the handshake entry point and carries the
    /// caller's version as `data[0]`; mismatch here means the caller was
    /// built against a different revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 7;
}

/// Init → memmgr bootstrap payload layout.
///
/// memmgr is created directly by init (no procmgr exists yet), so its startup
/// pool bounds arrive over a single bootstrap round on memmgr's creator
/// endpoint plus one auxiliary read-only Memory cap (`caps[1]` of that round) —
/// the "phys-table" page. This module is the single source of truth for the
/// payload layout; init writes it and memmgr reads it.
///
/// Round (`ipc::bootstrap` caps + data words):
/// * `caps[0]` — memmgr's own service endpoint (full rights; its RECV side).
/// * `caps[1]` — read-only Memory cap covering the phys-table page (below).
/// * `data[0]` — `frame_base`: first `CSpace` slot of the free RAM Memory caps
///   init copied into memmgr's `CSpace`.
/// * `data[1]` — `frame_count`: number of consecutive free RAM frames.
/// * `data[2]` — `procmgr_badge`: badge init burned into procmgr's badged
///   SEND on memmgr's endpoint; gates the procmgr-only labels.
/// * `data[3..3 + frame_count.div_ceil(2)]` — `page_count` per free frame,
///   packed two per word (low 32 bits = even index, high 32 = odd index).
///
/// Phys-table page (`u64`-indexed; one 4 KiB page = 512 slots):
/// * `[0, frame_count)` — `phys_base` per free frame, parallel to the
///   `page_count` words above.
/// * `FACTS_*` — the kernel's immutable RAM-accounting facts.
/// * `IN_USE_*` — the in-use bootstrap arenas (memmgr's, procmgr's, and init's
///   own backing), forwarded so memmgr's `pool_total` spans every page of RAM
///   it owns, not only the free runs and reap donations.
pub mod memmgr_bootstrap
{
    use syscall_abi::MSG_DATA_WORDS_MAX;

    /// Maximum free RAM frames init delivers in the round's data words:
    /// `MSG_DATA_WORDS_MAX` minus the 3-word prefix, two `page_count`s per
    /// remaining word.
    pub const MAX_MEMORY_CAPS: usize = (MSG_DATA_WORDS_MAX - 3) * 2;

    /// Phys-table `u64` index of the first immutable fact
    /// (`system_ram_bytes`). Sits past the `MAX_MEMORY_CAPS`-entry `phys_base`
    /// table (`MAX_MEMORY_CAPS * 8 = 976 B`) so the two regions never overlap.
    pub const FACTS_SYSTEM_RAM_IDX: usize = 128;
    /// Phys-table `u64` index of `kernel_reserved_bytes`.
    pub const FACTS_KERNEL_RESERVED_IDX: usize = 129;

    /// Phys-table `u64` index of the in-use arena count.
    pub const IN_USE_COUNT_IDX: usize = 130;
    /// Phys-table `u64` index of the first in-use arena descriptor.
    pub const IN_USE_BASE_IDX: usize = 131;
    /// `u64` words per in-use arena descriptor:
    /// * word 0 — `cap_slot` (low 32 bits) | `page_count` (high 32 bits).
    /// * word 1 — `phys_base`.
    /// * word 2 — `kind` (see `IN_USE_KIND_*`).
    pub const IN_USE_WORDS: usize = 3;
    /// Maximum in-use arenas init forwards (memmgr-self, procmgr, init, slack).
    /// `IN_USE_BASE_IDX + MAX_IN_USE * IN_USE_WORDS` must stay within the
    /// 512-slot page.
    pub const MAX_IN_USE: usize = 4;

    /// In-use arena owner kind: memmgr's own bootstrap backing.
    pub const IN_USE_KIND_MEMMGR: u64 = 0;
    /// In-use arena owner kind: procmgr's bootstrap backing.
    pub const IN_USE_KIND_PROCMGR: u64 = 1;
    /// In-use arena owner kind: init's own bootstrap backing (endpoint and
    /// log-thread retype slabs plus the offset-mapped IPC buffer and
    /// log-thread stack/IPC). init exits at reap; the arena's pages stay
    /// parked and are accounted against a dedicated memmgr-side record.
    pub const IN_USE_KIND_INIT: u64 = 2;
}

/// Process-state codes returned by `procmgr_labels::QUERY_PROCESS`.
///
/// Populated in data word 0 of the reply. Word 1 carries an accompanying
/// exit reason (encoded as `docs/process-lifecycle.md` § Exit reason
/// defines); it is zero for states in which the exit reason is not
/// meaningful (ALIVE, CREATED, UNKNOWN).
pub mod procmgr_process_state
{
    /// Entry exists and the process has been started. Running or blocked.
    pub const ALIVE: u64 = 0;
    /// Entry exists but the process has not yet been started (still in the
    /// suspended post-CREATE state). Rare for external queriers to see.
    pub const CREATED: u64 = 1;
    /// No entry for this badge — already reaped, or the badge was never
    /// valid. Equivalent to `ESRCH`.
    pub const UNKNOWN: u64 = 2;
    /// The process has exited: its main thread is already `Exited` (before
    /// procmgr's death-event drain reaps it), or procmgr reaped it and the
    /// badge is still in the recent-exits ring. Reply word 1 carries the
    /// kernel-encoded `exit_reason`. Recent-exit retention is best-effort;
    /// once the ring rotates, queries on the same badge return `UNKNOWN`.
    pub const EXITED: u64 = 3;
}

/// Wire-protocol version of [`svcmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const SVCMGR_LABELS_VERSION: u32 = 9;
/// IPC labels for the service manager (`svcmgr`).
pub mod svcmgr_labels
{
    // The services init started before svcmgr existed (memmgr, procmgr,
    // devmgr, vfsd) are handed to svcmgr over init's bootstrap-round
    // endowment, not a dedicated label (svcmgr launches logd itself, from
    // its recipe). The `CAPS` rounds carry svcmgr's own endpoints plus the source
    // caps it needs for its publish role (`rootfs.root` SEND,
    // devmgr-registry `SEND|GRANT` source, `vfsd.mount` and `vfsd.deny`
    // SENDs) and `SVCMGR_LABELS_VERSION` in
    // `data[1]`; each `SUBSTRATE` round carries one `(name, thread_cap)`
    // pair svcmgr parks in its pending-registration table; a final
    // `LOGD_SOURCES` round carries the master-log and procmgr death-auth
    // sources svcmgr launches logd with. On `HANDOVER_COMPLETE` svcmgr
    // reconciles every parked name against `/config/svcmgr/services/`:
    // a parked name with a definition is bound and supervised using the
    // on-disk recipe; a defined name not parked is launched by svcmgr
    // itself; a parked name with no definition is a hard error (svcmgr
    // has no recipe to restart it). The round kinds and the encoding of
    // the endowment are the `svcmgr-endowment` crate
    // (`services/svcmgr/endowment`); see
    // `services/svcmgr/docs/ipc-interface.md` and
    // `services/svcmgr/docs/service-definitions.md` for the spec. The
    // bootstrap rounds svcmgr serves each child it launches (the `seed` and
    // `log_sink` rounds) split its positional slots into windows of
    // `MSG_CAP_SLOTS_MAX`, one round each, carrying only the present caps
    // and a presence word in `data[0]` (`bootstrap::slot_rounds` /
    // `bootstrap::request_slots`); the endowment's `CAPS` slot list spans
    // rounds the same way. That layout is part of this version.

    /// Internal namespace-policy descriptor stored on `ServiceEntry`
    /// (one of the values below). Parsed by svcmgr from each
    /// service's `namespace = ...` line in `/config/svcmgr/services/<name>.svc`.
    ///
    /// Namespace-policy descriptor: hand the child a `cap_copy` of
    /// svcmgr's own root cap at full rights. Reserved for the services
    /// that need genuine root authority; today the `terminal`, `svctest`,
    /// and `usertest` recipes select it.
    pub const NS_POLICY_UNIVERSAL: u8 = 0;
    /// Namespace-policy descriptor: do not deliver any namespace
    /// cap. The child's `ProcessInfo.system_root_cap` stays zero
    /// (`Unsupported` on absolute-path fs ops in std). Default for
    /// services that own only hardware / IPC authority and never
    /// touch the filesystem.
    pub const NS_POLICY_NONE: u8 = 1;
    /// Namespace-policy descriptor: walk svcmgr's root for a
    /// per-service path with a per-service rights mask, and hand
    /// the resulting directory cap as the child's namespace root.
    /// Path and rights come from the `namespace = subtree:<path>:<rights>`
    /// line in `/config/svcmgr/services/<name>.svc` so attenuation survives a
    /// crash-restart cycle.
    pub const NS_POLICY_SUBTREE: u8 = 2;
    /// Notification that init handover is complete. Honoured once, and
    /// only from a caller whose badge carries [`HANDOVER_AUTHORITY`];
    /// svcmgr replies [`svcmgr_errors::UNAUTHORIZED`] to any other caller
    /// and to a repeat.
    pub const HANDOVER_COMPLETE: u64 = 2;
    /// Verb-bit authorising [`HANDOVER_COMPLETE`]. init alone mints it, on
    /// a SEND it derives for the handover call and deletes after. Only
    /// svcmgr and its trusted minters hold an unbadged SEND on svcmgr's
    /// endpoint (init, and procmgr's per-child source), which is what keeps
    /// the bit theirs: every other SEND on the endpoint is already badged (a
    /// badge is set once) without it — devmgr's with [`PUBLISH_AUTHORITY`],
    /// the published `svcmgr` name's with [`PUBLISHED_SEND_BADGE`], and each
    /// per-process `service_registry_cap` with a process badge, which
    /// [`VERB_BIT_MASK`](crate::VERB_BIT_MASK) keeps clear of verb bits.
    pub const HANDOVER_AUTHORITY: u64 = 1u64 << 62;
    /// Badge on the SEND svcmgr publishes on its own endpoint under the
    /// `svcmgr` name: a fixed value with no verb bit, so a consumer can
    /// `QUERY_ENDPOINT` through it but cannot re-badge it to mint
    /// [`HANDOVER_AUTHORITY`] or [`PUBLISH_AUTHORITY`].
    pub const PUBLISHED_SEND_BADGE: u64 = 1;
    const _: () = core::assert!(PUBLISHED_SEND_BADGE & crate::VERB_BIT_MASK == 0);
    /// Publish a named endpoint into the discovery registry.
    ///
    /// Label bits 16..31 carry `name_len`; data words from 0 carry the name
    /// bytes packed little-endian. `caps[0]` is the endpoint the name
    /// resolves to.
    pub const PUBLISH_ENDPOINT: u64 = 3;
    /// Look up a named public endpoint; on success the reply carries a
    /// freshly derived SEND cap.
    ///
    /// Label bits 16..31 carry `name_len`; data words from 0 carry the name
    /// bytes packed little-endian, as for [`PUBLISH_ENDPOINT`]
    /// (`registry-client`'s `pack_name` is the reference encoder). Reply
    /// attaches a freshly derived SEND cap on success. On failure it carries
    /// no cap and returns `svcmgr_errors::INVALID_NAME` if `name_len` is 0
    /// or exceeds `registry::NAME_MAX`; `svcmgr_errors::UNKNOWN_NAME` on
    /// miss and for a seed-only name (one whose cap carries authority, which
    /// reaches only the recipes seeding it; see [`crate::published_names`]);
    /// or `svcmgr_errors::INSUFFICIENT_CAPS` if svcmgr cannot derive a SEND
    /// from the published endpoint, in which case it drops the entry, so a
    /// later query of the name gets `UNKNOWN_NAME`.
    pub const QUERY_ENDPOINT: u64 = 4;

    /// Verb-bit carried by the caller's badge to authorise
    /// [`PUBLISH_ENDPOINT`] by an *external* publisher (no per-publisher
    /// identity in the low bits today — server-side auth is binary: have
    /// the bit, or don't). svcmgr publishes the well-known names it owns
    /// (`rootfs.root`, `svcmgr`, the three `devmgr.*` names, the two
    /// `vfsd.*` names, and each provider's `provides` names) directly into
    /// its own registry, so those
    /// need no badge. The gate exists for a future external publisher — devmgr
    /// holds a `PUBLISH_AUTHORITY`-badged SEND from its bootstrap bundle,
    /// reserved for driver registrations.
    ///
    /// The SEND distributed to every process via
    /// `ProcessInfo.service_registry_cap` carries the child's
    /// per-process badge (no `PUBLISH_AUTHORITY` bit), so it is
    /// accepted for `QUERY_ENDPOINT` only; svcmgr rejects publish
    /// attempts whose badge lacks the bit with
    /// [`svcmgr_errors::UNAUTHORIZED`]. See
    /// `docs/capability-model.md` "verb-bit authority pattern" for
    /// the rationale and parallel use in
    /// `pwrmgr_labels::SHUTDOWN_AUTHORITY`.
    ///
    /// Per-publisher attenuation (e.g. name-prefix restrictions in
    /// the low badge bits, so a session daemon can publish only
    /// `user.*`) is the future-work shape and the badge namespace
    /// reserves it — see GitHub issue #76.
    pub const PUBLISH_AUTHORITY: u64 = 1u64 << 63;
}

/// Well-known names published into svcmgr's discovery registry.
///
/// Centralised so the publisher (`svcmgr`, post-handover — from source
/// caps init endows it in the handover endowment, plus each provider's
/// `provides` names) and consumers (`svcmgr` resolving each `.svc`'s
/// `seed = ...` list during launch, and any process via
/// `QUERY_ENDPOINT`) share the exact spelling. A typo on either side
/// leaks out as `svcmgr_errors::UNKNOWN_NAME` rather than
/// `INSUFFICIENT_CAPS`.
///
/// Names are FS-driver- and platform-agnostic by design: swapping the
/// root filesystem from fatfs to e.g. ext4, or replacing pwrmgr's
/// platform shutdown source, changes only the publisher's local
/// derivation, not the published name nor any consumer.
///
/// A name whose cap carries authority is seed-only: `rootfs.root`, the
/// three `devmgr.*` names, [`published_names::VFSD_MOUNT`], and each provider
/// name whose badge carries a verb bit ([`crate::VERB_BIT_MASK`]; today
/// `pwrmgr.shutdown`) resolve only through a recipe's `seed = ...` line, and
/// `QUERY_ENDPOINT` answers them `UNKNOWN_NAME`.
/// [`published_names::VFSD_DENY`] carries no authority but is seed-only
/// too, as svctest's test twin. `svcmgr`, `pwrmgr.deny`, `timed`, and any
/// name published through [`svcmgr_labels::PUBLISH_ENDPOINT`] are public
/// (services/svcmgr/docs/ipc-interface.md § Label 4).
pub mod published_names
{
    /// Badged SEND on the root filesystem's namespace endpoint at
    /// its root directory. The driver behind it (fatfs today, any
    /// FS driver tomorrow) is opaque to consumers.
    pub const ROOTFS_ROOT: &[u8] = b"rootfs.root";

    /// `pwrmgr_labels::SHUTDOWN_AUTHORITY`-badged SEND on pwrmgr's
    /// service endpoint. Seed-only: consumers needing power-off authority
    /// seed this name and call [`pwrmgr_labels::SHUTDOWN`] /
    /// [`pwrmgr_labels::REBOOT`] through the returned cap.
    pub const PWRMGR_SHUTDOWN: &[u8] = b"pwrmgr.shutdown";

    /// No-authority SEND on pwrmgr's service endpoint, badgeised
    /// with a non-`SHUTDOWN_AUTHORITY` sentinel. Used by negative
    /// tests (e.g. svctest's `pwrmgr_cap_deny`) that need a cap
    /// pointing at pwrmgr without the shutdown bit to verify the
    /// authority gate rejects it.
    pub const PWRMGR_DENY: &[u8] = b"pwrmgr.deny";

    /// SEND on svcmgr's own service endpoint. Consumers resolve this
    /// when they need to call into svcmgr beyond the per-process
    /// `service_registry_cap` (today: crasher's `seed = svcmgr`).
    pub const SVCMGR: &[u8] = b"svcmgr";

    /// `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's registry
    /// endpoint. Consumers needing to resolve a device driver
    /// themselves seed this name: today `programs/terminal` (frame buffer,
    /// input, and serial queries), `timed` (`QUERY_RTC_DEVICE`), and
    /// `svctest`; logd instead receives a SEND svcmgr mints for it at
    /// launch. svcmgr publishes it
    /// post-handover from the devmgr-registry source cap init endows it
    /// with; the `REGISTRY_QUERY_AUTHORITY` badge bit is preserved
    /// through svcmgr's plain `cap_derive` in `registry_lookup_derived`.
    pub const DEVMGR_REGISTRY: &[u8] = b"devmgr.registry";

    /// SEND on devmgr's registry endpoint badged
    /// `REGISTRY_QUERY_AUTHORITY | SHUTDOWN_DEVICE_AUTHORITY`: the
    /// `devmgr.registry` surface plus `QUERY_SHUTDOWN_DEVICE`. Seed-only and
    /// seeded only by pwrmgr, which acquires the platform shutdown actuators
    /// through it.
    pub const DEVMGR_SHUTDOWN: &[u8] = b"devmgr.shutdown";

    /// TODO(#165): remove with devmgr's test labels. SEND on devmgr's
    /// registry endpoint badged
    /// `REGISTRY_QUERY_AUTHORITY | TEST_LABEL_AUTHORITY`: the
    /// `devmgr.registry` surface plus devmgr's test labels: the
    /// `TEST_SPAWN_ORPHAN` / `TEST_ORPHAN_RESULT` fault-injection shim and
    /// `TEST_QUERY_DENY_DEVICE`. Seed-only and seeded only by svctest.
    pub const DEVMGR_TEST: &[u8] = b"devmgr.test";

    /// SEND on vfsd's service endpoint badged
    /// `vfsd_labels::MOUNT_AUTHORITY` alone: the `MOUNT` surface, without
    /// `GET_SYSTEM_ROOT_CAP`. Seed-only and seeded only by svctest, whose
    /// vfsd phases drive `MOUNT`'s rejection paths.
    pub const VFSD_MOUNT: &[u8] = b"vfsd.mount";

    /// SEND on vfsd's service endpoint badged `vfsd_labels::DENY_BADGE`,
    /// which carries no verb bit: the negative-test twin of [`VFSD_MOUNT`].
    /// Seed-only and seeded only by svctest.
    pub const VFSD_DENY: &[u8] = b"vfsd.deny";
}

/// Wire-protocol version of [`rtc_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const RTC_LABELS_VERSION: u32 = 1;
/// IPC labels for RTC chip drivers (`services/drivers/cmos`,
/// `services/drivers/goldfish-rtc`, and future per-board chip drivers).
///
/// Every RTC driver implements exactly one operation: return the current
/// wall-clock time, as `u64` microseconds since the Unix epoch. devmgr
/// owns the per-board RTC and hands clients a
/// [`READ_AUTHORITY`](rtc_labels::READ_AUTHORITY)-badged SEND via
/// [`devmgr_labels::QUERY_RTC_DEVICE`]. `timed` is the sole client
/// today: it resolves the SEND once at startup, computes
/// `offset = rtc_us - kernel_monotonic_us`, and serves
/// [`timed_labels::GET_WALL_TIME`] thereafter without further driver IPC.
///
/// **Acquisition path**: the RTC driver binary lives on the rootfs disk
/// at `/services/drivers/<chip>` and is loaded by devmgr from there.
/// svcmgr walks its system root to `/services/drivers/` and hands devmgr a
/// `LOOKUP | READ`-attenuated subtree cap via
/// [`devmgr_labels::SET_DRIVERS_DIR`]. Devmgr replies SUCCESS to that
/// handshake *before* doing any spawn work (so svcmgr never blocks on
/// driver bring-up); it then walks the per-arch driver name
/// (`cmos-rtc` on x86-64, `goldfish-rtc` on RISC-V) from the subtree
/// cap, calls [`procmgr_labels::CREATE_FROM_FILE`], and delivers the
/// per-arch hardware authority cap (ISA `IoPort` for CMOS; MMIO
/// aperture for goldfish-rtc) through the bootstrap protocol — all
/// between the `SET_DRIVERS_DIR` handler's `ipc_reply` and the next
/// `ipc_recv`. See [`devmgr_labels::SET_DRIVERS_DIR`] for the nested-IPC
/// constraint that forces this ordering. Spawn is at-most-once per
/// boot; failure is sticky and clients see
/// [`devmgr_errors::NO_DEVICE`] permanently. RTC drivers are
/// **not** carried in the boot bundle.
///
/// Adding a new RTC chip is a matter of writing a driver crate that
/// answers this single label and binding it through devmgr's per-board
/// discovery path; clients reach it via the same `QUERY_RTC_DEVICE`
/// name. `timed` itself never sees the chip-specific details.
pub mod rtc_labels
{
    /// Request the current wall-clock time.
    ///
    /// Wire format: empty body (no data words, no caps). Reply:
    /// `data[0]` is `u64` microseconds since the Unix epoch. Reply
    /// label carries a status code in the lower 16 bits. Caller's
    /// badge must carry [`READ_AUTHORITY`] (devmgr stamps it on every
    /// SEND it mints from `QUERY_RTC_DEVICE`); the driver replies
    /// [`rtc_errors::UNAUTHORIZED`] otherwise.
    pub const RTC_GET_EPOCH_TIME: u64 = 1;

    /// Authority bit in the RTC-service-endpoint badge's high u64 bit.
    /// Set on caps devmgr mints in response to
    /// [`devmgr_labels::QUERY_RTC_DEVICE`]; gates [`RTC_GET_EPOCH_TIME`].
    /// A verb ("may read"), not an identity. Shares the same `1 << 63`
    /// bit position as [`serial_labels::WRITE_AUTHORITY`] and
    /// [`fb_labels::WRITE_AUTHORITY`]. The cmos / goldfish-rtc drivers
    /// enforce the bit at the service loop, as the serial driver enforces
    /// its bits (defence-in-depth alongside the upstream
    /// [`REGISTRY_QUERY_AUTHORITY`](devmgr_labels::REGISTRY_QUERY_AUTHORITY)
    /// gate at devmgr's `QUERY_RTC_DEVICE` handler).
    pub const READ_AUTHORITY: u64 = 1u64 << 63;
}

/// Error replies from RTC chip drivers.
pub mod rtc_errors
{
    /// Request handled.
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
    /// Caller's badge lacked [`rtc_labels::READ_AUTHORITY`]. Backstops
    /// the upstream gate at [`devmgr_labels::QUERY_RTC_DEVICE`]: a
    /// well-behaved client only ever sees this if a SEND cap leaked
    /// without the verb bit (or a future verb-set partition refuses
    /// reads with a more restrictive badge).
    pub const UNAUTHORIZED: u64 = 4;
}

/// Wire-protocol version of [`timed_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const TIMED_LABELS_VERSION: u32 = 1;
/// IPC labels for the wall-clock service (`services/timed`).
///
/// `timed` is RTC-source-agnostic: it resolves the RTC SEND once at
/// startup via [`devmgr_labels::QUERY_RTC_DEVICE`], queries the driver
/// via [`rtc_labels::RTC_GET_EPOCH_TIME`], computes a stable offset
/// against the kernel's monotonic clock, and serves wall-clock queries
/// from `offset + system_info(ElapsedUs)`. New RTC chip support never
/// changes timed; only the chip driver behind devmgr's lookup changes
/// per platform.
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
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// No RTC was reachable through devmgr's [`devmgr_labels::QUERY_RTC_DEVICE`]
    /// at timed's startup; the offset was never computed. Boards without
    /// an RTC (some real RISC-V hardware) stay in this state: seeding the
    /// offset out of band (an operator or NTP path) is design intent; not
    /// yet implemented.
    pub const WALL_CLOCK_UNAVAILABLE: u64 = 1;
    /// Unknown opcode on timed's endpoint.
    pub const UNKNOWN_OPCODE: u64 = 2;
    /// Reserved for a future per-message version handshake. Unused
    /// today — `TIMED_LABELS_VERSION` is marker-only and covered by
    /// `PROCESS_ABI_VERSION` at process startup.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
}

/// Wire-protocol version of [`pwrmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const PWRMGR_LABELS_VERSION: u32 = 1;
/// IPC labels for the power manager (`pwrmgr`).
///
/// pwrmgr owns the platform shutdown surface: ACPI S5 on x86-64 (the
/// `PM1a` `IoPort` carved from the FADT/DSDT it interprets) and SBI
/// SRST on RISC-V (the `SbiControl` cap). It acquires those caps from
/// devmgr — the hardware/ACPI authority — at startup via
/// [`devmgr_labels::QUERY_ACPI_TABLE`] and
/// [`devmgr_labels::QUERY_SHUTDOWN_DEVICE`], not from init. Callers that
/// may invoke shutdown receive a badged SEND on pwrmgr's service
/// endpoint with the [`pwrmgr_labels::SHUTDOWN_AUTHORITY`] verb bit set.
///
/// See `services/pwrmgr/README.md` for the authoritative description.
pub mod pwrmgr_labels
{
    /// Power off the platform.
    ///
    /// Wire format: empty body. The handler verifies the caller's badge
    /// carries [`SHUTDOWN_AUTHORITY`] and replies
    /// [`pwrmgr_errors::UNAUTHORIZED`] otherwise. On the success path the
    /// platform powers off and no reply is delivered (QEMU exits the
    /// process). A reply arrives only on a rejection, when pwrmgr has no
    /// actuator, or when the platform call fails (see
    /// [`pwrmgr_errors::INVALID_REQUEST`]).
    pub const SHUTDOWN: u64 = 1;
    /// Cold reboot the platform.
    ///
    /// Same authorization gate as [`SHUTDOWN`]. On the success path the
    /// machine cold-boots back through the bootloader.
    pub const REBOOT: u64 = 2;

    /// Authority bit in the pwrmgr-service-endpoint badge's high u64
    /// bit. Set on caps minted for consumers permitted to call
    /// [`SHUTDOWN`] and [`REBOOT`]. Without it the handler replies
    /// [`pwrmgr_errors::UNAUTHORIZED`].
    pub const SHUTDOWN_AUTHORITY: u64 = 1u64 << 63;
}

/// Error replies from pwrmgr.
pub mod pwrmgr_errors
{
    /// Request handled (never observed for SHUTDOWN / REBOOT, whose
    /// success path does not return).
    pub const SUCCESS: u64 = 0;
    /// Caller's badge lacks the verb bit required by the handler
    /// ([`pwrmgr_labels::SHUTDOWN_AUTHORITY`] for SHUTDOWN / REBOOT).
    pub const UNAUTHORIZED: u64 = 1;
    /// An authorised SHUTDOWN / REBOOT could not be carried out: pwrmgr has
    /// no platform actuator (its startup acquisition from devmgr failed), or
    /// the platform call returned without powering off or resetting
    /// (`services/pwrmgr/README.md`).
    pub const INVALID_REQUEST: u64 = 2;
    /// Reserved for a future per-message version handshake; not emitted.
    /// `PWRMGR_LABELS_VERSION` is marker-only.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
    /// Unknown opcode on pwrmgr endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

/// Wire-protocol version of [`vfsd_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const VFSD_LABELS_VERSION: u32 = 2;
/// IPC labels for the VFS daemon (`vfsd`).
pub mod vfsd_labels
{
    /// Mount a filesystem at a path. The request body carries a
    /// `MountRole` byte (see `services/vfsd/docs/vfs-ipc-interface.md`)
    /// selecting which GPT type-GUID role to mount; vfsd looks the
    /// partition up itself. The caller's badge MUST carry
    /// [`MOUNT_AUTHORITY`]; vfsd replies `UNAUTHORIZED` otherwise, before it
    /// reads the request.
    pub const MOUNT: u64 = 10;
    // Label 12 is reserved and MUST NOT be reused for an unrelated request
    // (services/vfsd/docs/vfs-ipc-interface.md).
    /// Mint a fresh badged SEND on vfsd's namespace endpoint addressing
    /// the synthetic system root at full namespace rights and return it
    /// to the caller.
    ///
    /// Request: `data[0]` = caller's compiled [`super::VFSD_LABELS_VERSION`].
    /// Reply: `SUCCESS` with `caps[0]` = the system-root cap;
    /// `UNAUTHORIZED` when the caller's badge lacks [`SEED_AUTHORITY`];
    /// `LABEL_VERSION_MISMATCH` when `data[0]` differs; `NO_MOUNT` before
    /// vfsd's own root mount completes; `IO_ERROR` when the derivation
    /// fails. Init calls this once during bootstrap to obtain the seed cap
    /// from which all later namespace-cap distribution flows.
    pub const GET_SYSTEM_ROOT_CAP: u64 = 13;

    /// Authority bit in the vfsd-service-endpoint badge. Set on caps
    /// minted for consumers permitted to call
    /// [`GET_SYSTEM_ROOT_CAP`]. Without it the handler replies
    /// `UNAUTHORIZED`. Holding this cap is equivalent to holding the
    /// system-root cap (the handler is a seed source), so it is only
    /// distributed to init. Distributing it to svcmgr's restart path is
    /// design intent; not yet implemented.
    pub const SEED_AUTHORITY: u64 = 1u64 << 62;

    /// Authority bit in the vfsd-service-endpoint badge gating [`MOUNT`].
    /// init mints it, alone, onto the SEND it endows svcmgr with; svcmgr
    /// publishes that SEND seed-only as
    /// [`crate::published_names::VFSD_MOUNT`], which svctest alone seeds.
    /// The cap is badged, so its holder cannot add [`SEED_AUTHORITY`].
    /// Disjoint position from [`SEED_AUTHORITY`].
    pub const MOUNT_AUTHORITY: u64 = 1u64 << 63;

    /// The badge init stamps on the no-authority SEND on vfsd's service
    /// endpoint that svcmgr publishes seed-only as
    /// [`crate::published_names::VFSD_DENY`]: no verb bit, so [`MOUNT`]
    /// and [`GET_SYSTEM_ROOT_CAP`] refuse it, and non-zero, since a holder
    /// may badge an un-badged SEND itself
    /// (docs/capability-model.md § Verb-bit authority pattern). svctest
    /// asserts the `MOUNT` refusal through it.
    pub const DENY_BADGE: u64 = 1;
}

/// Wire-protocol version of [`ns_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const NS_LABELS_VERSION: u32 = 1;
/// IPC labels for the namespace protocol (cap-as-namespace surface).
///
/// Numbered in a reserved range above the [`fs_labels`] codes (2 through
/// 17) so node-cap and per-file requests share one fs-driver endpoint with
/// no opcode collisions.
/// [`fs_labels::END_OF_DIR`] is reused unchanged as the readdir
/// terminator.
///
/// Protocol semantics, including caller-rights checks, name validation,
/// per-entry visibility (at `NS_LOOKUP` and `NS_READDIR`), and child-cap
/// minting, are owned by the `namespace-protocol` crate's
/// `dispatch_request` function; backends implement the
/// `NamespaceBackend` trait, run their own receive loop, and route each
/// `NS_*` message through `dispatch_request` for reply.
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
    /// Attribute snapshot for the node addressed by the caller's badge.
    ///
    /// Request: empty body. Reply on success: label = 0, `data[0]` =
    /// size, `data[1]` = `mtime_us` (best-effort; zero on backends that
    /// do not track it), `data[2]` = kind. Error replies match
    /// [`NS_LOOKUP`].
    pub const NS_STAT: u64 = 21;
    /// One-entry-per-call enumeration of the directory addressed by the
    /// caller's badge.
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

/// Wire-protocol version of [`fs_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const FS_LABELS_VERSION: u32 = 3;
/// IPC labels for filesystem drivers (FAT, ext4, etc.).
pub mod fs_labels
{
    /// Read from a node cap (driver-side). Inline reply: `data[0]` =
    /// bytes read, payload follows starting at word 1. Drivers cap
    /// per-call payload at the IPC inline ceiling; callers iterate.
    pub const FS_READ: u64 = 2;
    /// Close a node cap, releasing any lazily-allocated driver-side
    /// bookkeeping bound to the file (outstanding `FS_READ_MEMORY`
    /// pages, open-file slot, etc.). The caller still cap-deletes the
    /// node cap to drop the kernel-side reference.
    pub const FS_CLOSE: u64 = 3;
    /// Inline write to a file node cap.
    ///
    /// Request: `label = FS_WRITE | (byte_len << 16)` (bits 0-15 = label
    /// ID, bits 16-31 = payload byte length, ≤ 504), `data[0]` = file
    /// byte offset, payload bytes packed from word 1 onward via
    /// `IpcMessageBuilder::bytes(1, &payload)`. Badge must carry the
    /// `WRITE` namespace right (see `namespace-protocol::rights`).
    ///
    /// Reply (success label `fs_errors::SUCCESS`): `data[0]` =
    /// `bytes_written` (may be short on `NO_SPACE` or on
    /// partial-cluster failure; callers iterate). Error labels per
    /// [`fs_errors`].
    pub const FS_WRITE: u64 = 4;
    /// End-of-directory marker in `NS_READDIR` replies.
    pub const END_OF_DIR: u64 = 6;
    /// Read file content into a cached Memory cap returned in the reply.
    ///
    /// Request: badge identifies the file (per-file cap), `data[0]` =
    /// byte offset (no alignment requirement), `data[1]` = client-chosen
    /// release cookie (must be non-zero). `caps[0]` = optional per-process
    /// release-endpoint SEND for cooperative `FS_RELEASE_MEMORY`; which
    /// request carries it, and which carried SEND the driver records, are
    /// specified in services/fs/docs/fs-driver-protocol.md § Label 7
    /// (the record is per node, not per client).
    /// Reply: `data[0]` = bytes valid in the returned page starting at
    /// the indicated page offset, `data[1]` = the same release cookie
    /// echoed back, `data[2]` = byte offset within the returned page
    /// where the file's content for the requested `offset` begins,
    /// `caps[0]` = single-page Memory cap with `MAP` rights (read-only
    /// mapping authority) covering the cached file page.
    ///
    /// `bytes_valid` is bounded by file end, the current cluster
    /// boundary on the underlying filesystem, and the page tail
    /// (`PAGE_SIZE - memory_data_offset`); callers iterate forward from
    /// `offset + bytes_valid` to read past those boundaries.
    pub const FS_READ_MEMORY: u64 = 7;
    /// Release of a previously-returned page, in either direction.
    ///
    /// Driver-to-client (cooperative eviction): sent on the release endpoint
    /// cap recorded in the node's open-file slot, the first one an
    /// [`FS_READ_MEMORY`] reaching that slot carried (shared per node, not per
    /// client; tracked in #530); `data[0]` = the release cookie naming
    /// the Memory cap to unmap. The client unmaps it and replies
    /// [`FS_RELEASE_ACK`], first letting a local copy from the page finish
    /// within the watchdog window; any other reply label is no ack (the std
    /// client sends `fs_errors::IO_ERROR`). After the reply, or the window
    /// with none, the driver revokes the page's parent Memory cap.
    ///
    /// Client-to-driver (synchronous release after a read): sent on the
    /// per-node badged cap the page was read through; `data[0]` = the
    /// release cookie from the [`FS_READ_MEMORY`] reply. The driver revokes
    /// the page's derived caps and frees its cache slot. Reply: empty body
    /// on success (an unmatched cookie is a no-op success);
    /// `fs_errors::PERMISSION_DENIED` when the badge carries no namespace
    /// rights.
    ///
    /// See `services/fs/docs/fs-driver-protocol.md` "Label 8:
    /// `FS_RELEASE_MEMORY`" for the authoritative contract.
    pub const FS_RELEASE_MEMORY: u64 = 8;
    /// Client acknowledgement of [`FS_RELEASE_MEMORY`]: synchronous reply,
    /// empty body.
    pub const FS_RELEASE_ACK: u64 = 9;
    /// Mount-time probe from vfsd. Specified in
    /// `services/fs/docs/fs-driver-protocol.md` § Label 10: `FS_MOUNT`.
    pub const FS_MOUNT: u64 = 10;
    /// Write file content from a caller-supplied source Memory cap.
    ///
    /// Mirror of [`FS_READ_MEMORY`] for the write direction. Caller maps,
    /// fills, then transfers a Memory cap holding the bytes to write.
    ///
    /// Request: badge identifies the file (per-file cap),
    /// `data[0]` = file byte offset (no alignment requirement),
    /// `data[1]` = bytes to write from the page (`≤ PAGE_SIZE -
    /// memory_data_offset`), `data[2]` = byte offset within the source
    /// page where the data begins. `caps[0]` = source Memory cap with
    /// at least `MAP` rights, sized one page. Badge must carry the
    /// `WRITE` namespace right.
    ///
    /// Reply (label `fs_errors::SUCCESS`): `data[0]` = `bytes_written`
    /// (short on `NO_SPACE` or cluster-boundary truncation; callers
    /// iterate). `caps[0]` = the source Memory cap moved back to the
    /// caller. Errors per [`fs_errors`].
    pub const FS_WRITE_MEMORY: u64 = 12;
    /// Create a new file in a directory.
    ///
    /// Request: badge = parent-directory cap (must carry `MUTATE_DIR`),
    /// `label = FS_CREATE | (name_len << 16)`, name bytes packed from
    /// word 0 via `IpcMessageBuilder::bytes(0, name)`. Name validated
    /// per `namespace-protocol::validate_name`.
    ///
    /// Reply (label `fs_errors::SUCCESS`): `data[0]` = entry kind (per
    /// `namespace_protocol::NodeKind`), `caps[0]` = node cap for the
    /// newly-created file. Errors: as `services/fs/docs/fs-driver-protocol.md`
    /// § Label 13: `FS_CREATE` lists them.
    pub const FS_CREATE: u64 = 13;
    /// Remove a file or empty directory from a directory.
    ///
    /// Request: badge = parent-directory cap (must carry `MUTATE_DIR`),
    /// `label = FS_REMOVE | (name_len << 16)`, name bytes from word 0.
    ///
    /// Reply (label `fs_errors::SUCCESS`): empty body. Errors: as
    /// `services/fs/docs/fs-driver-protocol.md` § Label 14: `FS_REMOVE`
    /// lists them.
    pub const FS_REMOVE: u64 = 14;
    /// Create a new (empty) directory in a directory.
    ///
    /// Request: identical shape to [`FS_CREATE`]. Badge must carry
    /// `MUTATE_DIR`. Allocates one cluster zero-filled with `.` and
    /// `..` entries.
    ///
    /// Reply: identical shape to [`FS_CREATE`], `data[0]` = kind (Dir).
    pub const FS_MKDIR: u64 = 15;
    /// Rename a directory entry within a single directory.
    ///
    /// Request: badge = directory cap (must carry `MUTATE_DIR`),
    /// `data[0]` = source name length, `data[1]` = destination name
    /// length, name bytes packed contiguously from word 2 via
    /// `IpcMessageBuilder::bytes(2, &concat(src, dst))` — source bytes
    /// first, destination bytes immediately after with no padding.
    ///
    /// Cross-directory rename is deferred to Issue #89: the
    /// caller cannot supply a second directory cap because servers
    /// cannot introspect the badge packed inside a cap they receive
    /// (`cap_info` does not expose badge bits), so a cross-directory
    /// destination cannot be resolved to a `NodeId` server-side.
    ///
    /// Not atomic: an interrupted rename can leave only the source, both
    /// names, or only the destination present. See
    /// `services/fs/fat/docs/crash-safety.md`.
    ///
    /// Reply (label `fs_errors::SUCCESS`): empty body. Errors: as
    /// `services/fs/docs/fs-driver-protocol.md` § Label 16: `FS_RENAME`
    /// lists them.
    pub const FS_RENAME: u64 = 16;
    /// Truncate a file to a new length.
    ///
    /// Request: badge = file-node cap (must carry `WRITE`),
    /// `label = FS_TRUNCATE`, `data[0]` = new length in bytes; only zero
    /// is supported. Specified, with its errors, in
    /// `services/fs/docs/fs-driver-protocol.md` § Label 17: `FS_TRUNCATE`.
    pub const FS_TRUNCATE: u64 = 17;
}

/// Wire-protocol version of [`devmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const DEVMGR_LABELS_VERSION: u32 = 10;
/// IPC labels for the device manager (`devmgr`).
///
/// Every request carries the caller's compiled [`DEVMGR_LABELS_VERSION`] in
/// `data[0]`; after any badge check the label makes, devmgr replies
/// [`devmgr_errors::LABEL_VERSION_MISMATCH`] when it differs.
pub mod devmgr_labels
{
    /// Query for a block device endpoint.
    ///
    /// Mints a `MOUNT_AUTHORITY`-badged whole-disk `SEND_GRANT` cap on
    /// `blk_ep` to the caller. Caller's badge must have
    /// [`BLOCK_DEVICE_AUTHORITY`] set; the handler replies
    /// `UNAUTHORIZED` otherwise, and `INVALID_REQUEST` when no block driver
    /// is running or the derivation fails.
    pub const QUERY_BLOCK_DEVICE: u64 = 1;
    /// Query a device's startup-info payload from devmgr's catalog.
    ///
    /// The caller's badge identifies the device by indexing devmgr's
    /// `DeviceCatalog` (badge == entry index + 1); a badge that indexes no
    /// entry gets `INVALID_REQUEST`. No authority bit is checked. Devmgr
    /// stores the
    /// payload bytes opaquely; the per-class shape lives in the driver
    /// crate. Reply schema (generic for every kind):
    /// - `word[0]` = `kind` discriminant ([`super::device_info_kind`])
    /// - `word[1]` = `version` (per-kind payload schema version)
    /// - `word[2]` = `byte_len` (valid bytes in the payload)
    /// - `word[3..3 + byte_len.div_ceil(8)]` = payload bytes packed as
    ///   `u64` words (`repr(C)` of the kind's struct).
    ///
    /// The driver verifies `kind` and `version` before deserialising
    /// the payload. Devmgr does not interpret payload bytes.
    pub const QUERY_DEVICE_INFO: u64 = 2;
    /// Query for the serial (UART) device endpoint.
    ///
    /// Mints a `serial_labels::WRITE_AUTHORITY |
    /// serial_labels::READ_AUTHORITY`-badged `SEND_GRANT` cap on the
    /// serial driver's service endpoint to the caller.
    /// Caller's badge must have [`REGISTRY_QUERY_AUTHORITY`] set; the
    /// handler replies `UNAUTHORIZED` otherwise, and `INVALID_REQUEST`
    /// when the driver is not running or the derivation fails. Mirrors
    /// [`QUERY_BLOCK_DEVICE`]'s reply shape.
    pub const QUERY_SERIAL_DEVICE: u64 = 3;
    /// Query for the framebuffer device endpoint.
    ///
    /// Mints a `fb_labels::WRITE_AUTHORITY`-badged `SEND_GRANT` cap
    /// on the framebuffer driver's service endpoint to the caller.
    /// Caller's badge must have [`REGISTRY_QUERY_AUTHORITY`] set; the
    /// handler replies `UNAUTHORIZED` otherwise. Mirrors
    /// [`QUERY_SERIAL_DEVICE`], including its `INVALID_REQUEST` cases.
    pub const QUERY_FRAMEBUFFER_DEVICE: u64 = 4;
    /// Query for the platform real-time-clock device endpoint.
    ///
    /// Mints a `rtc_labels::READ_AUTHORITY`-badged `SEND_GRANT` cap
    /// on the RTC driver's service endpoint to the caller. Caller's
    /// badge must have [`REGISTRY_QUERY_AUTHORITY`] set; the handler
    /// replies `UNAUTHORIZED` otherwise. Replies `NO_DEVICE` until the
    /// driver is spawned (see [`SET_DRIVERS_DIR`]), and for the rest of the
    /// boot if that spawn failed; `INVALID_REQUEST` when the derivation
    /// fails. Today's sole consumer is `timed`, which seeds its wall-clock
    /// offset from one `RTC_GET_EPOCH_TIME` round-trip and serves
    /// `GET_WALL_TIME` thereafter.
    pub const QUERY_RTC_DEVICE: u64 = 5;
    /// svcmgr-only handshake: install the
    /// `LOOKUP | READ`-attenuated `/services/drivers/` namespace cap from
    /// which devmgr walks its on-disk driver binaries.
    ///
    /// Request: `data[0]` = caller's compiled
    /// [`super::DEVMGR_LABELS_VERSION`]; `caps[0]` = badged SEND on the
    /// `/services/drivers/` directory node, which svcmgr walks from its
    /// system root via `namespace_lookup_dir(root_dir_cap, …, LOOKUP |
    /// READ)` (so the node is served by the root filesystem).
    /// Caller's badge MUST carry [`DRIVERS_DIR_AUTHORITY`]; the handler
    /// replies [`super::devmgr_errors::UNAUTHORIZED`] otherwise and
    /// [`super::devmgr_errors::INVALID_REQUEST`] when `caps[0]` is
    /// absent. A repeated request keeps the first cap and replies
    /// `SUCCESS`.
    ///
    /// Devmgr stashes the cap and replies
    /// [`super::devmgr_errors::SUCCESS`] **before** doing any spawn
    /// work, so svcmgr never blocks on driver bring-up. The actual walk,
    /// the [`super::procmgr_labels::CREATE_FROM_FILE`] call, and the
    /// bootstrap-round delivery for the on-disk drivers (the per-arch RTC
    /// and virtio-input; #165 will generalize) run after the reply but
    /// before devmgr returns to its next `ipc_recv`. The nested IPC
    /// chain the spawn requires (procmgr → vfsd → block driver) cannot
    /// run inside a request-handler frame without clobbering the
    /// implicit reply context, so it must happen between `ipc_reply`
    /// and the next `ipc_recv`. Clients querying `QUERY_RTC_DEVICE`
    /// before the spawn completes block in the kernel's send queue
    /// until devmgr returns to `ipc_recv`; once devmgr returns, those
    /// queries see `rtc_ep != 0` (or the sticky-failure state) and
    /// reply normally.
    ///
    /// Each spawn is attempted at most once per boot. On failure
    /// (missing binary, ELF corrupt, carve failure, OOM, etc.),
    /// devmgr marks the driver permanently unavailable for this boot
    /// and replies [`super::devmgr_errors::NO_DEVICE`] to subsequent
    /// [`QUERY_RTC_DEVICE`] / [`QUERY_INPUT_DEVICE`] queries; clients MUST
    /// NOT retry-loop.
    pub const SET_DRIVERS_DIR: u64 = 6;

    /// Locate an ACPI table and serve a read-only view of it.
    ///
    /// devmgr is the sole owner of ACPI data and the only service that
    /// navigates the table tree (RSDP → XSDT). Callers that need a table
    /// (today: `pwrmgr`, for the FADT + DSDT it interprets for S5
    /// shutdown) request it here rather than holding ACPI Memory caps of
    /// their own.
    ///
    /// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
    /// `data[1]` = 4-byte table signature packed little-endian (e.g.
    /// `FACP`), or `0` to look up by physical address; `data[2]` =
    /// table physical address (used when `data[1] == 0`, e.g. the DSDT,
    /// whose address the caller reads from the FADT). Caller's badge MUST
    /// carry [`REGISTRY_QUERY_AUTHORITY`]; the handler replies
    /// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
    ///
    /// Reply ([`super::devmgr_errors::SUCCESS`]): `caps[0]` = a derived
    /// **read-only-intended** Memory cap on the ACPI region containing the
    /// table (the caller maps it read-only); `data[0]` = region
    /// physical base, `data[1]` = region size in bytes, `data[2]` = the
    /// table's physical address. The caller maps the region and reads the
    /// table at `table_phys - region_base`. devmgr reads only the
    /// directory (RSDP/XSDT) and table headers (signatures) to locate the
    /// table — never a table body. Replies
    /// [`super::devmgr_errors::NO_DEVICE`] when the table is not found,
    /// both `data[1]` and `data[2]` are zero, or `data[1]` has bits above
    /// its low 32, [`super::devmgr_errors::INVALID_REQUEST`] when deriving
    /// the reply's Memory cap from the region fails, and
    /// [`super::devmgr_errors::LABEL_VERSION_MISMATCH`] when `data[0]` is
    /// not `DEVMGR_LABELS_VERSION`.
    pub const QUERY_ACPI_TABLE: u64 = 7;

    /// Carve and serve the platform shutdown-actuator hardware caps.
    ///
    /// devmgr is the hardware authority; it carves the ports the power
    /// manager needs and performs no shutdown logic. The caller (`pwrmgr`)
    /// has already parsed the ACPI tables (served via [`QUERY_ACPI_TABLE`])
    /// and computed the `PM1a` control port it needs; devmgr serves that
    /// port only when it is the FADT's `PM1a_CNT_BLK`.
    ///
    /// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
    /// `data[1]` = the `PM1a` control port (x86-64; ignored on RISC-V).
    /// Caller's badge MUST carry [`SHUTDOWN_DEVICE_AUTHORITY`]; the handler
    /// replies [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
    ///
    /// Reply ([`super::devmgr_errors::SUCCESS`]):
    /// - x86-64: `caps[0]` = a narrow `IoPort` over `[pm1a, pm1a+2)`
    ///   carved from devmgr's full-rights `IoPort`; `caps[1]` = a narrow
    ///   `IoPort` over `[0x64, 0x65)` (8042 KBC reset, for reboot).
    ///   Both are re-derived from it on every call, so a pwrmgr
    ///   restart re-acquires them cleanly.
    /// - RISC-V: `caps[0]` = a Reset-only derivation of devmgr's
    ///   `SbiControl` cap (SBI SRST authority).
    ///
    /// Replies [`super::devmgr_errors::NO_DEVICE`] when the carve fails,
    /// the FADT or its `PM1a_CNT_BLK` cannot be read (x86-64), or the
    /// platform authority cap is absent,
    /// [`super::devmgr_errors::INVALID_REQUEST`] when `data[1]` is not the
    /// FADT's `PM1a_CNT_BLK` (x86-64) or the RISC-V Reset-only derivation
    /// fails, and [`super::devmgr_errors::LABEL_VERSION_MISMATCH`] when
    /// `data[0]` is not `DEVMGR_LABELS_VERSION`.
    pub const QUERY_SHUTDOWN_DEVICE: u64 = 8;

    /// Query for the keyboard/input device endpoint.
    ///
    /// Mints an `input_labels::READ_AUTHORITY`-badged `SEND_GRANT` cap on
    /// the input driver's service endpoint to the caller. Caller's badge
    /// must have [`REGISTRY_QUERY_AUTHORITY`] set; the handler replies
    /// `UNAUTHORIZED` otherwise. Like [`QUERY_RTC_DEVICE`], it replies
    /// `NO_DEVICE` until the on-disk driver is spawned, and for the rest of
    /// the boot if no input device was enumerated or the spawn failed;
    /// `INVALID_REQUEST` when the derivation fails. The verb
    /// is transport-agnostic: any keyboard backend (virtio-input today,
    /// USB HID / PS-2 later) registers this one slot, so consumers never
    /// learn the transport. Value 11 — 9 and 10 are the TODO(#165) test
    /// labels below.
    pub const QUERY_INPUT_DEVICE: u64 = 11;

    /// TODO(#165): remove with the devmgr enumeration redesign. Test-only
    /// label: trigger devmgr's spawn-orphan fault-injection shim (#176). The
    /// handler replies `SUCCESS` immediately (the forced-failure spawn does
    /// nested `ipc_call`s that would clobber the reply context), then forces a
    /// round-2 bootstrap failure and stashes the outcome for
    /// [`TEST_ORPHAN_RESULT`]. Request: `data[0]` = caller's compiled
    /// [`super::DEVMGR_LABELS_VERSION`]. Caller's badge MUST carry
    /// [`TEST_LABEL_AUTHORITY`]; the handler replies
    /// [`super::devmgr_errors::UNAUTHORIZED`] otherwise and
    /// [`super::devmgr_errors::LABEL_VERSION_MISMATCH`] on a version
    /// mismatch, without spawning.
    pub const TEST_SPAWN_ORPHAN: u64 = 9;
    /// TODO(#165): remove with the devmgr enumeration redesign. Test-only
    /// label: report the last [`TEST_SPAWN_ORPHAN`] outcome in reply `data[0]`
    /// — `0` not run, `1` spawn failed as expected (unwind fired), `2`
    /// unexpected success, `3` shim setup error. Request and gate as
    /// [`TEST_SPAWN_ORPHAN`].
    pub const TEST_ORPHAN_RESULT: u64 = 10;
    /// TODO(#165): remove with the devmgr enumeration redesign. Test-only
    /// label: mint a SEND on one driver's service endpoint badged
    /// [`TEST_DENY_BADGE`], which carries none of the driver's verb bits, so
    /// a harness can assert the driver's `UNAUTHORIZED` reply. No other
    /// path mints a SEND on these endpoints without the bit, and a holder
    /// cannot strip a bit from a badged cap. Request: `data[0]` = caller's
    /// compiled [`super::DEVMGR_LABELS_VERSION`]; `data[1]` = the query label
    /// naming the driver ([`QUERY_SERIAL_DEVICE`], [`QUERY_INPUT_DEVICE`], or
    /// [`QUERY_FRAMEBUFFER_DEVICE`]). Gate as [`TEST_SPAWN_ORPHAN`]. Reply:
    /// `SUCCESS` with the SEND in `caps[0]`; `NO_DEVICE` when that driver is
    /// not running; `INVALID_REQUEST` for any other `data[1]` or a failed
    /// derive.
    pub const TEST_QUERY_DENY_DEVICE: u64 = 12;
    /// TODO(#165): remove with [`TEST_QUERY_DENY_DEVICE`]. The badge devmgr
    /// stamps on a [`TEST_QUERY_DENY_DEVICE`] SEND: no verb bit of the
    /// serial, input, or framebuffer driver, and non-zero, since a holder
    /// may badge an un-badged SEND itself
    /// (docs/capability-model.md § Verb-bit authority pattern).
    pub const TEST_DENY_BADGE: u64 = 1;

    /// Authority bit in the devmgr-registry-endpoint badge's high
    /// u64 bit, gating the device-endpoint queries ([`QUERY_SERIAL_DEVICE`],
    /// [`QUERY_FRAMEBUFFER_DEVICE`], [`QUERY_RTC_DEVICE`],
    /// [`QUERY_INPUT_DEVICE`]) and [`QUERY_ACPI_TABLE`]. Set on every
    /// consumer query cap: svcmgr's `devmgr.*` publications, the SEND
    /// svcmgr mints for logd at launch, and the SEND init hands vfsd (the
    /// per-device SENDs drivers hold for [`QUERY_DEVICE_INFO`] lack it).
    /// Without it those handlers reply `UNAUTHORIZED`. It does not admit
    /// [`QUERY_BLOCK_DEVICE`], which [`BLOCK_DEVICE_AUTHORITY`] gates.
    pub const REGISTRY_QUERY_AUTHORITY: u64 = 1u64 << 63;
    /// Authority bit gating [`SET_DRIVERS_DIR`]. svcmgr mints a SEND
    /// cap carrying this bit from the devmgr-registry source cap init
    /// endows it with at handover; the `REGISTRY_QUERY_AUTHORITY`-only
    /// copy svcmgr publishes seed-only as `devmgr.registry` (which recipes
    /// seed) lacks this bit, so no seeding consumer can call
    /// `SET_DRIVERS_DIR`. Disjoint position from
    /// [`REGISTRY_QUERY_AUTHORITY`].
    pub const DRIVERS_DIR_AUTHORITY: u64 = 1u64 << 62;
    /// Authority bit gating [`QUERY_SHUTDOWN_DEVICE`]. svcmgr mints it,
    /// beside [`REGISTRY_QUERY_AUTHORITY`], only onto the SEND it publishes
    /// seed-only as [`crate::published_names::DEVMGR_SHUTDOWN`], which
    /// pwrmgr alone seeds and `QUERY_ENDPOINT` refuses, so no other process
    /// holds the bit. Disjoint position from the other authority bits.
    pub const SHUTDOWN_DEVICE_AUTHORITY: u64 = 1u64 << 61;
    /// TODO(#165): remove with the test labels. Authority bit gating
    /// [`TEST_SPAWN_ORPHAN`], [`TEST_ORPHAN_RESULT`], and
    /// [`TEST_QUERY_DENY_DEVICE`]. svcmgr mints it,
    /// beside [`REGISTRY_QUERY_AUTHORITY`], only onto the SEND it publishes
    /// seed-only as [`crate::published_names::DEVMGR_TEST`], which svctest
    /// alone seeds. Disjoint position from the other authority bits.
    pub const TEST_LABEL_AUTHORITY: u64 = 1u64 << 60;
    /// Authority bit gating [`QUERY_BLOCK_DEVICE`], whose reply is a
    /// `MOUNT_AUTHORITY`-badged whole-disk cap. init mints it, beside
    /// [`REGISTRY_QUERY_AUTHORITY`], only onto the registry SEND it hands
    /// vfsd; svcmgr mints it onto none of its `devmgr.*` publications, so
    /// no other process holds the bit. Gating upstream of virtio-blk keeps
    /// `MOUNT_AUTHORITY` caps with the one consumer devmgr authorises.
    /// Disjoint position from the other authority bits.
    pub const BLOCK_DEVICE_AUTHORITY: u64 = 1u64 << 59;
}

/// Device-info kind discriminants for [`devmgr_labels::QUERY_DEVICE_INFO`]
/// replies. Each driver class owns a fixed value; devmgr stores payload
/// bytes against this discriminant in its `DeviceCatalog` and replies
/// with the discriminant as `word[0]` so callers can verify the type
/// before deserialising.
pub mod device_info_kind
{
    /// `VirtIO` PCI device startup info
    /// (`virtio_core::VirtioPciStartupInfo`).
    pub const VIRTIO_PCI: u32 = 1;
    /// Linear framebuffer geometry (`boot_protocol::FramebufferInfo`).
    pub const FRAMEBUFFER: u32 = 2;
}

/// Wire-protocol version of [`blk_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const BLK_LABELS_VERSION: u32 = 2;
/// IPC labels for block device drivers.
pub mod blk_labels
{
    /// Authority bit in the block-service-endpoint badge's high u64
    /// bit. Set on caps minted for consumers that may invoke
    /// [`REGISTER_PARTITION`] and may issue whole-disk sector reads
    /// via [`BLK_READ_INTO_MEMORY`]. The bit is a verb — "may invoke
    /// these labels" — not an identity: multiple consumers may hold
    /// it, and the bit alone does not encode "is vfsd."
    ///
    /// Disjoint from partition-identity badges. The driver allocates
    /// partition badges from a monotonic counter in the low bits of
    /// the u64 (top bit clear); the partition table is keyed by the
    /// full badge value so collision is impossible.
    pub const MOUNT_AUTHORITY: u64 = 1u64 << 63;

    /// Register a partition range, receiving back a badged SEND cap
    /// scoped to that partition.
    ///
    /// Caller's badge must have [`MOUNT_AUTHORITY`] set. The driver derives
    /// the partition cap itself because [`MOUNT_AUTHORITY`] caps are
    /// badged and the kernel rejects re-badging of a badged source.
    /// Specified, with its replies, in
    /// `services/drivers/virtio/blk/README.md` § Label 2:
    /// `REGISTER_PARTITION`.
    pub const REGISTER_PARTITION: u64 = 2;
    /// Read one or more contiguous sectors into a caller-supplied Memory cap,
    /// which the reply moves back. Specified, with its caps and replies, in
    /// `services/drivers/virtio/blk/README.md` § Label 3:
    /// `BLK_READ_INTO_MEMORY`.
    pub const BLK_READ_INTO_MEMORY: u64 = 3;
    /// Write one or more contiguous sectors from a caller-supplied Memory cap.
    ///
    /// Mirror of [`BLK_READ_INTO_MEMORY`] for the write direction. The
    /// caller fills the source page, then issues the request; the
    /// driver reads `count * 512` bytes starting at offset 0 and writes
    /// them to disk.
    ///
    /// Request: `data[0]` = starting LBA, `data[1]` = sector count
    /// (`>= 1`; defaults to `1` if `data[1]` is absent). Caps: `caps[0]` =
    /// source Memory cap (`MAP` rights; the driver reads `count * 512` bytes
    /// starting at offset 0 of the page, packed contiguously). The page
    /// must be at least `count * 512` bytes; the driver rejects with
    /// `INVALID_MEMORY_CAP` otherwise. `caps[1]` is reserved for a future
    /// per-request release handle and is null today. `caps[2]` is a
    /// reserved IPC-shape slot for a future userspace IOMMU-grant cap;
    /// see [`BLK_READ_INTO_MEMORY`] for the userspace-IOMMU framing.
    /// Reply: empty body, label is the success or error code; the source
    /// Memory cap is moved back to the caller in `caps[0]` of the reply (same
    /// discipline as the read path).
    pub const BLK_WRITE_FROM_MEMORY: u64 = 4;
}

/// Wire-protocol version of [`serial_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const SERIAL_LABELS_VERSION: u32 = 2;
/// IPC labels for the serial (UART) device driver (`services/drivers/serial`).
///
/// The driver answers byte write, byte read, and RX-notify registration. It
/// owns the platform UART hardware authority (an `IoPort` for COM1 on x86-64,
/// an `Mmio` for the QEMU `virt` NS16550 at its platform-static address on
/// RISC-V) and is the sole
/// driver-mediated path for userspace serial bytes in both directions. devmgr
/// spawns it and hands clients a cap badged with
/// [`serial_labels::WRITE_AUTHORITY`] | [`serial_labels::READ_AUTHORITY`] via
/// [`devmgr_labels::QUERY_SERIAL_DEVICE`]. Line-control and flow-control
/// surfaces are planned but unimplemented (see the driver `README.md`); they
/// are not on the wire.
pub mod serial_labels
{
    /// Write bytes to the UART.
    ///
    /// Wire format mirrors [`stream_labels::STREAM_BYTES`]: the payload byte
    /// length rides bits 16-31 of the label, the bytes are packed via
    /// `.bytes(0, …)` into the data words, and the receiver reads
    /// `byte_len.div_ceil(8)` words. The caller's badge must carry
    /// [`WRITE_AUTHORITY`]. Reply: empty body, status code in the reply label.
    ///
    /// # Label encoding
    /// - Bits 0-15: label ID (`SERIAL_WRITE_BYTES`)
    /// - Bits 16-31: byte length of the payload in this call (0..=512).
    pub const SERIAL_WRITE_BYTES: u64 = 1;

    /// Read the bytes currently available in the UART receive FIFO.
    ///
    /// Non-blocking: the driver drains whatever is ready and replies at once,
    /// possibly with zero bytes. Callers that want to sleep until input arrives
    /// register a notification via [`SERIAL_REGISTER_RX_NOTIFY`] and wait on it
    /// between reads. Request: empty body; the caller's badge must carry
    /// [`READ_AUTHORITY`].
    ///
    /// Reply ([`super::serial_errors::SUCCESS`]): the byte count rides bits
    /// 16-31 of the reply label (0..=512), the bytes are packed via
    /// `.bytes(0, …)` into the data words (the same wire shape as
    /// [`SERIAL_WRITE_BYTES`], in the reply direction).
    pub const SERIAL_READ_BYTES: u64 = 2;

    /// Register a notification kicked when receive data becomes ready.
    ///
    /// Request: the client's notification cap in cap slot 0; the caller's badge
    /// must carry [`READ_AUTHORITY`]. The driver binds the UART interrupt to
    /// that notification and arms it. The IRQ is masked on each fire and
    /// re-armed by the next [`SERIAL_READ_BYTES`], so a client loops: drain
    /// with `SERIAL_READ_BYTES`, then wait on its notification (with a bounded
    /// timeout — the x86 IOAPIC is edge-triggered, so a byte racing the re-arm
    /// is recovered by the timeout-driven re-drain). Reply: empty body, status
    /// in the reply label ([`super::serial_errors::REGISTER_FAILED`] if the
    /// driver holds no IRQ cap or the binding fails).
    pub const SERIAL_REGISTER_RX_NOTIFY: u64 = 3;

    /// Authority bit in the serial-service-endpoint badge's high u64 bit.
    /// Set on caps devmgr mints in response to
    /// [`devmgr_labels::QUERY_SERIAL_DEVICE`]; gates [`SERIAL_WRITE_BYTES`].
    /// A verb ("may write"), not an identity.
    pub const WRITE_AUTHORITY: u64 = 1u64 << 63;

    /// Authority bit gating [`SERIAL_READ_BYTES`] and
    /// [`SERIAL_REGISTER_RX_NOTIFY`]. Set alongside [`WRITE_AUTHORITY`] on caps
    /// devmgr mints for [`devmgr_labels::QUERY_SERIAL_DEVICE`]. A verb ("may
    /// read"), not an identity.
    pub const READ_AUTHORITY: u64 = 1u64 << 62;
}

/// Error replies from the serial device driver.
pub mod serial_errors
{
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// Driver received a label it does not implement.
    pub const UNKNOWN_OPCODE: u64 = 2;
    /// Reserved for a future per-message version handshake. Unused today —
    /// `SERIAL_LABELS_VERSION` is marker-only and covered by
    /// `PROCESS_ABI_VERSION` at process startup.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
    /// `SERIAL_REGISTER_RX_NOTIFY` could not bind the UART interrupt: the
    /// driver holds no IRQ cap, or no notification cap was supplied.
    pub const REGISTER_FAILED: u64 = 4;
    /// Caller's badge lacks the verb bit gating the requested label
    /// ([`super::serial_labels::WRITE_AUTHORITY`] for writes,
    /// [`super::serial_labels::READ_AUTHORITY`] for reads and RX-notify).
    pub const UNAUTHORIZED: u64 = 5;
}

/// Wire-protocol version of [`fb_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const FB_LABELS_VERSION: u32 = 2;
/// IPC labels for the framebuffer device driver
/// (`services/drivers/framebuffer`).
///
/// The driver answers a byte-write ([`fb_labels::FB_WRITE_BYTES`]) and a
/// colour-attribute set ([`fb_labels::FB_SET_ATTRS`]). It owns the
/// bootloader-handed GOP linear-framebuffer MMIO end-to-end and is the
/// sole driver-mediated sink for userspace framebuffer bytes. devmgr
/// spawns it and hands clients a [`fb_labels::WRITE_AUTHORITY`]-badged
/// SEND via [`devmgr_labels::QUERY_FRAMEBUFFER_DEVICE`]. Graphical
/// primitives, cursor control, mode set, and multi-head dispatch are
/// planned but unimplemented (see the driver `README.md`); they are not
/// on the wire.
pub mod fb_labels
{
    /// Write bytes to the framebuffer (text rendered through the
    /// embedded 9×20 bitmap font).
    ///
    /// Wire format mirrors [`serial_labels::SERIAL_WRITE_BYTES`] and
    /// [`stream_labels::STREAM_BYTES`]: the payload byte length rides
    /// bits 16-31 of the label, the bytes are packed via
    /// `.bytes(0, …)` into the data words, and the receiver reads
    /// `byte_len.div_ceil(8)` words. Reply: empty body, status code in
    /// the reply label.
    ///
    /// # Label encoding
    /// - Bits 0-15: label ID (`FB_WRITE_BYTES`)
    /// - Bits 16-31: byte length of the payload in this call (0..=512).
    pub const FB_WRITE_BYTES: u64 = 1;

    /// Set the foreground/background colour for subsequent
    /// [`FB_WRITE_BYTES`] glyph rendering.
    ///
    /// The driver holds the pair as sticky state: an `FB_SET_ATTRS`
    /// applies to every following `FB_WRITE_BYTES` until the next
    /// `FB_SET_ATTRS`. The colours are 24-bit truecolour, packed as a
    /// six-byte payload `[fg_r, fg_g, fg_b, bg_r, bg_g, bg_b]` via
    /// `.bytes(0, …)`; the byte length rides bits 16-31 of the label,
    /// mirroring [`FB_WRITE_BYTES`]. The driver renders the bytes it is
    /// given and holds no palette — mapping the 16 ANSI SGR colours to
    /// RGB is the terminal's job (`shared/ansi`). Reply: empty body,
    /// status code in the reply label.
    ///
    /// The default (never set) is full-white-on-black, matching the
    /// pre-colour monochrome output, so callers that never send
    /// `FB_SET_ATTRS` (logd's framebuffer mirror, pre-terminal callers)
    /// render unchanged.
    ///
    /// # Label encoding
    /// - Bits 0-15: label ID (`FB_SET_ATTRS`)
    /// - Bits 16-31: payload byte length (`6`).
    pub const FB_SET_ATTRS: u64 = 2;

    /// Authority bit in the framebuffer-service-endpoint badge's high
    /// u64 bit. Set on caps devmgr mints in response to
    /// [`devmgr_labels::QUERY_FRAMEBUFFER_DEVICE`]. It gates
    /// [`FB_WRITE_BYTES`] and [`FB_SET_ATTRS`]: the driver answers either
    /// label with [`super::fb_errors::UNAUTHORIZED`] when the caller's
    /// badge lacks it. A verb ("may write"), not an identity.
    pub const WRITE_AUTHORITY: u64 = 1u64 << 63;
}

/// Error replies from the framebuffer device driver.
pub mod fb_errors
{
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// Driver received a label it does not implement.
    pub const UNKNOWN_OPCODE: u64 = 2;
    /// Reserved for a future per-message version handshake. Unused
    /// today — `FB_LABELS_VERSION` is marker-only and covered by
    /// `PROCESS_ABI_VERSION` at process startup.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
    /// Caller's badge lacks [`super::fb_labels::WRITE_AUTHORITY`], which
    /// gates [`super::fb_labels::FB_WRITE_BYTES`] and
    /// [`super::fb_labels::FB_SET_ATTRS`].
    pub const UNAUTHORIZED: u64 = 4;
}

/// Wire-protocol version of [`input_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const INPUT_LABELS_VERSION: u32 = 1;
/// IPC labels for the keyboard/input device driver
/// (`services/drivers/virtio/input` today; future USB / PS-2 backends reuse
/// this same protocol).
///
/// The driver decodes hardware key events into a **keysym stream** and
/// answers a single read operation. It owns its transport device end-to-end
/// (virtio-input PCI today) and is the sole driver-mediated source of
/// keyboard input. devmgr spawns it and hands clients an
/// [`input_labels::READ_AUTHORITY`]-badged SEND via
/// [`devmgr_labels::QUERY_INPUT_DEVICE`]. Key-repeat configuration, layout
/// switching, pointer/mouse events, and multi-device fan-out are out of
/// scope (see the driver `README.md`); they are not on the wire.
pub mod input_labels
{
    /// Read a batch of pending keyboard events (blocking).
    ///
    /// Request: empty body; the caller's badge must carry
    /// [`READ_AUTHORITY`], else the driver replies
    /// [`super::input_errors::UNAUTHORIZED`] as soon as it reaches the request,
    /// without waiting for input; the request still waits behind any authorized
    /// read already blocked.
    /// The driver blocks until at least one event is available, then replies
    /// with up to [`super::keysym::INPUT_MAX_EVENTS_PER_READ`] events.
    ///
    /// Reply ([`super::input_errors::SUCCESS`]): `word[0]` = event count `n`
    /// (`1..=INPUT_MAX_EVENTS_PER_READ`); `word[1 + i]` = event `i` packed via
    /// [`super::keysym::pack_event`] (keysym in bits 0-31, modifier mask in
    /// bits 32-62, press/release in bit 63). Consumers decode with
    /// [`super::keysym::unpack_event`].
    pub const INPUT_READ_EVENTS: u64 = 1;

    /// Authority bit in the input-service-endpoint badge's high u64 bit. Set
    /// on caps devmgr mints in response to
    /// [`devmgr_labels::QUERY_INPUT_DEVICE`]. It gates [`INPUT_READ_EVENTS`]:
    /// the driver answers the label with [`super::input_errors::UNAUTHORIZED`]
    /// when the caller's badge lacks it. A verb ("may read"), not an identity.
    pub const READ_AUTHORITY: u64 = 1u64 << 63;
}

/// Error replies from the input device driver.
pub mod input_errors
{
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// Driver received a label it does not implement.
    pub const UNKNOWN_OPCODE: u64 = 2;
    /// Reserved for a future per-message version handshake. Unused today —
    /// `INPUT_LABELS_VERSION` is marker-only and covered by
    /// `PROCESS_ABI_VERSION` at process startup.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
    /// Caller's badge lacks [`super::input_labels::READ_AUTHORITY`], which
    /// gates [`super::input_labels::INPUT_READ_EVENTS`].
    pub const UNAUTHORIZED: u64 = 4;
}

/// Keysym numbering, modifier mask bits, and the
/// [`input_labels::INPUT_READ_EVENTS`] event wire encoding — the
/// transport-agnostic contract shared by every keyboard driver and every
/// input consumer.
///
/// Keysyms follow X11 numbering: a printable Latin-1 keysym *is* its Unicode
/// codepoint (`a` = 0x61, `A` = 0x41, `1` = 0x31), and named keys use the
/// `0xFF00`+ function range. The driver resolves Shift/Caps into the keysym
/// (`A` vs `a`) and reports the full modifier mask so consumers can form
/// Ctrl/Alt combinations without the driver encoding terminal policy. The mask
/// reflects state *after* the event is applied, so a modifier key's own press
/// event carries its bit (a Shift press reports `MOD_SHIFT` next to keysym
/// `SHIFT_L`); its release clears it.
pub mod keysym
{
    // Named keys (X11 function-key range). Printable keys are not enumerated;
    // their keysym equals their Unicode codepoint.
    /// Keysym of the Backspace key.
    pub const BACKSPACE: u32 = 0xFF08;
    /// Keysym of the Tab key.
    pub const TAB: u32 = 0xFF09;
    /// Keysym of the Return key.
    pub const RETURN: u32 = 0xFF0D;
    /// Keysym of the Escape key.
    pub const ESCAPE: u32 = 0xFF1B;
    /// Keysym of the Home key.
    pub const HOME: u32 = 0xFF50;
    /// Keysym of the Left arrow key.
    pub const LEFT: u32 = 0xFF51;
    /// Keysym of the Up arrow key.
    pub const UP: u32 = 0xFF52;
    /// Keysym of the Right arrow key.
    pub const RIGHT: u32 = 0xFF53;
    /// Keysym of the Down arrow key.
    pub const DOWN: u32 = 0xFF54;
    /// Keysym of the End key.
    pub const END: u32 = 0xFF57;
    /// Keysym of the Delete key.
    pub const DELETE: u32 = 0xFFFF;

    // Modifier keys are delivered as their own press/release events too, so
    // consumers can observe modifier state changes directly.
    /// Keysym of the Left Shift key.
    pub const SHIFT_L: u32 = 0xFFE1;
    /// Keysym of the Right Shift key.
    pub const SHIFT_R: u32 = 0xFFE2;
    /// Keysym of the Left Control key.
    pub const CONTROL_L: u32 = 0xFFE3;
    /// Keysym of the Right Control key.
    pub const CONTROL_R: u32 = 0xFFE4;
    /// Keysym of the Caps Lock key.
    pub const CAPS_LOCK: u32 = 0xFFE5;
    /// Keysym of the Left Alt key.
    pub const ALT_L: u32 = 0xFFE9;
    /// Keysym of the Right Alt key.
    pub const ALT_R: u32 = 0xFFEA;

    // Modifier mask bits (X11 state-mask values: Shift=1, Lock=2, Control=4,
    // Mod1=8). Reported in bits 32-62 of a packed event.
    /// Modifier-mask bit: Shift held.
    pub const MOD_SHIFT: u32 = 1 << 0;
    /// Modifier-mask bit: Caps Lock active.
    pub const MOD_CAPS: u32 = 1 << 1;
    /// Modifier-mask bit: Control held.
    pub const MOD_CTRL: u32 = 1 << 2;
    /// Modifier-mask bit: Alt held.
    pub const MOD_ALT: u32 = 1 << 3;

    /// Maximum events returned by one
    /// [`super::input_labels::INPUT_READ_EVENTS`] reply. Bounded so `word[0]`
    /// (count) plus `n` event words fit the 64-word IPC data area with
    /// headroom.
    pub const INPUT_MAX_EVENTS_PER_READ: usize = 32;

    /// Pack a key event into one IPC data word: keysym in bits 0-31, the
    /// modifier mask in bits 32-62, and `pressed` (true = down) in bit 63.
    #[must_use]
    pub const fn pack_event(keysym: u32, modifiers: u32, pressed: bool) -> u64
    {
        // `as` (not `u64::from`) because `From` is not const-callable; the
        // crate-level allow covers the (non-)truncating int casts.
        (keysym as u64) | (((modifiers & 0x7FFF_FFFF) as u64) << 32) | ((pressed as u64) << 63)
    }

    /// Inverse of [`pack_event`]: returns `(keysym, modifiers, pressed)`.
    #[must_use]
    pub const fn unpack_event(word: u64) -> (u32, u32, bool)
    {
        let keysym = (word & 0xFFFF_FFFF) as u32;
        let modifiers = ((word >> 32) & 0x7FFF_FFFF) as u32;
        let pressed = (word >> 63) & 1 != 0;
        (keysym, modifiers, pressed)
    }
}

/// Wire-protocol version of [`stream_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
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
    /// looks up the slot for the sender's badge (delivered by the kernel
    /// from the badged SEND cap) and stores the bytes as that slot's
    /// display name, truncated to the mediator's per-slot buffer.
    /// Collision handling is the mediator's: init's bootstrap log thread
    /// stores a colliding name with a `.2` / `.3` / … suffix, while logd
    /// stores names as given (`services/logd/docs/ipc-interface.md`
    /// § `stream_labels::STREAM_REGISTER_NAME`).
    pub const STREAM_REGISTER_NAME: u64 = 11;
}

/// Badge bits that endpoints gating a label on a verb-bit use for it: each
/// `*_AUTHORITY` constant in this crate is one of these bits. A minter whose
/// badges carry other information onto such an endpoint keeps them clear —
/// procmgr's random per-process badge, stamped on the child's svcmgr-registry
/// and procmgr SENDs — so only a server's trusted minters set a verb bit
/// (docs/capability-model.md § Verb-bit authority pattern). Endpoints with no
/// verb gate (bootstrap endpoints, memmgr, namespace node caps) do not
/// reserve them.
pub const VERB_BIT_MASK: u64 =
    (1u64 << 63) | (1u64 << 62) | (1u64 << 61) | (1u64 << 60) | (1u64 << 59);
const _: () = core::assert!(
    devmgr_labels::SHUTDOWN_DEVICE_AUTHORITY & VERB_BIT_MASK != 0
        && devmgr_labels::TEST_LABEL_AUTHORITY & VERB_BIT_MASK != 0
        && devmgr_labels::BLOCK_DEVICE_AUTHORITY & VERB_BIT_MASK != 0
        && vfsd_labels::MOUNT_AUTHORITY & VERB_BIT_MASK != 0
        && vfsd_labels::SEED_AUTHORITY & VERB_BIT_MASK != 0
        && vfsd_labels::DENY_BADGE & VERB_BIT_MASK == 0
);

/// Reserved log-endpoint badges.
///
/// Every badged SEND cap on the log endpoint carries a `u64` badge
/// (kernel-attached at `cap_derive_badge` time, immutable thereafter).
/// The cap's holder is identified to the receiver by that badge. For
/// procmgr-spawned children the badge equals the child's procmgr-
/// assigned process badge; the kernel-side identity, the receiver's
/// per-sender slot key, and procmgr's death-notification correlator
/// thus all share one u64. To leave room for system-special senders
/// whose identity is not a procmgr process badge, procmgr's per-child
/// badge counter starts at [`LOG_BADGE_FIRST_CHILD`].
pub mod log_badges
{
    /// init's self-identity. Init derives `cap_derive_badge(log_ep,
    /// SEND, LOG_BADGE_INIT)` at boot and uses the cap for its own
    /// log writes (`services/init/src/logging.rs`).
    pub const LOG_BADGE_INIT: u64 = 1;
    /// procmgr's self-identity. Init derives a badged SEND cap with
    /// this badge at procmgr-bootstrap time and seeds it into
    /// `ProcessInfo.log_send_cap` so procmgr's std `_start` can
    /// install it. Procmgr's `seraph::log!` writes ride this cap.
    pub const LOG_BADGE_PROCMGR: u64 = 2;
    /// Floor of the low 32 bits of every per-child badge: procmgr draws
    /// child badges at random and redraws any whose low 32 bits fall below
    /// it. Lower values are reserved for the system specials above;
    /// raising this leaves room to reserve more.
    pub const LOG_BADGE_FIRST_CHILD: u64 = 16;
}

/// Wire-protocol version of [`log_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const LOG_LABELS_VERSION: u32 = 2;
/// IPC labels for the system log endpoint's legacy discovery interface
/// and the one-shot init-logd → real-logd handover.
///
/// Distinct from [`stream_labels`]: the latter carry payload (bytes,
/// names) on badged SEND caps that have already been minted; these
/// labels are spoken on caps that mediate cap acquisition or state
/// transfer.
///
/// Every process receives a pre-installed badged SEND cap in
/// `ProcessInfo.log_send_cap` (init derives its own) and never calls
/// [`GET_LOG_CAP`]; the label is reserved, not served.
pub mod log_labels
{
    /// Legacy discovery label, reserved and not served.
    ///
    /// Formerly requested a freshly minted badged SEND cap on the log
    /// endpoint (`word(0) = LOG_LABELS_VERSION`). No caller issues it:
    /// every process's badged cap arrives pre-installed in
    /// `ProcessInfo.log_send_cap`. Init-logd and real-logd answer it
    /// with an empty reply carrying no cap, so an out-of-tree caller
    /// fails closed (see `services/logd/docs/ipc-interface.md`).
    pub const GET_LOG_CAP: u64 = 12;

    /// Handover drain: real-logd pulls init-logd's captured state.
    ///
    /// Sent by real-logd, one chunk per call, on the single-use SEND cap
    /// on the master log endpoint that svcmgr mints it for its first
    /// launch (bootstrap `cap[1]`); init-logd still holds the endpoint's
    /// RECV and serves every other sender between pulls. The replies
    /// carry, in order:
    ///
    /// * A header — the total history-line count and the active slot
    ///   count.
    /// * The badge table — for every active sender badge init-logd
    ///   has seen, the `(badge, display_name)` pair, and again for each
    ///   slot whose name changed after the table was sent.
    /// * The captured-history ring — the complete lines init-logd still
    ///   holds, oldest first, attributed by badge and timestamped at the
    ///   original receipt instant.
    ///
    /// Wire encoding is documented in
    /// `services/logd/docs/handover-protocol.md` and defined in
    /// `logd-codec` (`services/logd/codec`). The data drain (`MORE`/`DONE`
    /// chunks) only transfers state; init-logd's thread terminates on an
    /// acknowledged [`HANDOVER_RELEASE`], not on the `DONE` chunk.
    pub const HANDOVER_PULL: u64 = 13;

    /// Terminal release: real-logd tells init-logd to exit.
    ///
    /// Sent by real-logd on the same single-use SEND cap after its
    /// [`HANDOVER_PULL`] drain settles (whether the drain ran to `DONE`,
    /// aborted on an IPC error, or hit its iteration cap); a call that
    /// fails is retried a bounded number of times until one is delivered
    /// (see `services/logd/docs/handover-protocol.md` § Termination).
    /// Init-logd replies with a status in the label:
    ///
    /// * `RELEASE_ACK` (0) — it sets its handover-complete flag and
    ///   `sys_thread_exit`s on its next loop iteration.
    /// * `RELEASE_PENDING` (1) — a display name changed after its slot was
    ///   sent; init-logd keeps serving, and real-logd drains again with
    ///   [`HANDOVER_PULL`] before it repeats the release. Init-logd defers
    ///   a bounded number of times (`MAX_RELEASE_DEFERRALS`) and then
    ///   acknowledges.
    ///
    /// See `services/logd/docs/handover-protocol.md` § Name changes during
    /// the drain.
    ///
    /// Decoupling termination from the multi-chunk data drain keeps a
    /// dropped data chunk (a kernel IPC rendezvous race on the shared,
    /// multi-sender log endpoint) from wedging init-logd — which would
    /// otherwise block procmgr's reap of init's Memory caps indefinitely.
    pub const HANDOVER_RELEASE: u64 = 14;
}

// ── Bootstrap protocol ──────────────────────────────────────────────────────
//
// Children receive the startup caps their `ProcessInfo` does not carry via IPC
// on their `creator_endpoint` cap. The child issues `bootstrap::REQUEST` in a
// loop; the creator replies with up to
// `MSG_CAP_SLOTS_MAX = 4` caps plus arbitrary payload words per round. The
// reply label's low byte indicates whether more rounds are expected (`MORE`)
// or the bootstrap is complete (`DONE`).
//
// The payload format (which data words mean what, which cap slot goes where)
// is defined per (creator, child-type) pair in each child's crate. No shared
// cap-role enum; no per-service sentinels.

pub mod bootstrap;

pub mod recv_guard;

/// Bootstrap-protocol error reply codes (creator → child).
pub mod bootstrap_errors
{
    /// Creator has no bootstrap plan for the sending child's badge.
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
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// ELF image validation failed.
    pub const INVALID_ELF: u64 = 1;
    /// Out of memory during process creation.
    pub const OUT_OF_MEMORY: u64 = 2;
    /// `START_PROCESS`: configuring the child's main thread
    /// (`thread_configure_with_tls`) failed.
    pub const THREAD_CONFIGURE_FAILED: u64 = 3;
    /// Process handle badge not found in process table.
    pub const INVALID_BADGE: u64 = 4;
    /// Attempt to start a process that was already started.
    pub const ALREADY_STARTED: u64 = 5;
    /// `START_PROCESS`: starting the child's main thread (`thread_start`)
    /// failed with an error other than `Interrupted`, which procmgr retries.
    pub const THREAD_START_FAILED: u64 = 6;
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
    /// Cap rights derivation failed (e.g. `derive_memory_for_prot`)
    /// during ELF page load.
    pub const INSUFFICIENT_RIGHTS: u64 = 12;
    /// Caller's cap lacks the required authority badge for a gated
    /// label (e.g. `REGISTER_DEATH_EQ` requires `DEATH_EQ_AUTHORITY`).
    pub const UNAUTHORIZED: u64 = 13;
    /// Unknown opcode on procmgr endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFFFF;
}

/// Error replies from vfsd.
pub mod vfsd_errors
{
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// File / path not found, or mount-path invalid.
    pub const NOT_FOUND: u64 = 1;
    /// No mount covers the requested path / partition not found.
    pub const NO_MOUNT: u64 = 2;
    /// Reserved; not emitted by the current vfsd.
    pub const NO_FS_MODULE: u64 = 3;
    /// Failed to spawn filesystem driver.
    pub const SPAWN_FAILED: u64 = 4;
    /// I/O error or mount failed at the driver.
    pub const IO_ERROR: u64 = 5;
    /// Mount table full.
    pub const TABLE_FULL: u64 = 6;
    /// Caller's badge lacks the verb bit required by the handler
    /// (e.g. `SEED_AUTHORITY` for `GET_SYSTEM_ROOT_CAP`).
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
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// File not found, or filesystem failed to validate on mount.
    pub const NOT_FOUND: u64 = 1;
    /// I/O error, or out of memory.
    pub const IO_ERROR: u64 = 2;
    /// Out of file-handle slots.
    pub const TOO_MANY_OPEN: u64 = 3;
    /// File badge is invalid or expired.
    pub const INVALID_BADGE: u64 = 4;
    /// Reserved; not emitted by the current fs driver (the fat driver's
    /// cooperative-release watchdog revokes without replying this code).
    pub const RELEASE_TIMEOUT: u64 = 5;
    /// `FS_READ_MEMORY` cookie is invalid (zero — collides with the
    /// `OutstandingPage::None` sentinel in fs driver tracking), or an
    /// `FS_WRITE_MEMORY` byte range does not fit its source page (zero
    /// count, or offset plus count past the page).
    pub const BAD_MEMORY_OFFSET: u64 = 6;
    /// Caller's node-cap badge lacks a rights bit required by the
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
    /// Mutation refused: the volume has no free cluster, the parent
    /// directory has no room for a new entry (FAT16 fixed root full;
    /// FAT32 cluster-chain extension failed), or a write would end past
    /// the largest file size the filesystem records.
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
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// The request cannot be served: a reply-cap derivation failed, the
    /// requested driver is not running (`QUERY_BLOCK_DEVICE`,
    /// `QUERY_SERIAL_DEVICE`, `QUERY_FRAMEBUFFER_DEVICE`), the badge indexes
    /// no catalog entry (`QUERY_DEVICE_INFO`), `SET_DRIVERS_DIR` carried no
    /// cap, or a label-specific argument was rejected (see
    /// `QUERY_ACPI_TABLE` and `QUERY_SHUTDOWN_DEVICE`).
    pub const INVALID_REQUEST: u64 = 1;
    /// Caller's badge lacks the verb bit required by the handler
    /// (e.g. `BLOCK_DEVICE_AUTHORITY` for `QUERY_BLOCK_DEVICE`).
    pub const UNAUTHORIZED: u64 = 2;
    /// Caller's compiled `DEVMGR_LABELS_VERSION`, carried in `data[0]` of
    /// every devmgr request, does not match the receiver's: the caller was
    /// built against a different revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 3;
    /// Requested device or table is unavailable. Returned by
    /// `QUERY_RTC_DEVICE` and `QUERY_INPUT_DEVICE` when devmgr either (a)
    /// has not yet spawned the on-disk driver (no
    /// [`super::devmgr_labels::SET_DRIVERS_DIR`] yet), or (b) attempted the
    /// lazy disk-walked spawn and failed (missing binary, ELF corrupt,
    /// hardware carve failed, OOM, etc.); case (b) is sticky for the boot,
    /// since a single attempt is made. Clients (timed) MUST treat it as
    /// terminal and fall through to their no-device path; they MUST NOT
    /// retry-loop. Also returned by `QUERY_ACPI_TABLE` (table not found)
    /// and `QUERY_SHUTDOWN_DEVICE` (actuator caps unavailable).
    pub const NO_DEVICE: u64 = 4;
    /// Unknown opcode on devmgr endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFF;
}

/// Error replies from svcmgr.
pub mod svcmgr_errors
{
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// Reserved; not emitted by the current svcmgr.
    pub const TABLE_FULL: u64 = 1;
    /// Invalid service name (too long / malformed).
    pub const INVALID_NAME: u64 = 2;
    /// A required cap is missing: `PUBLISH_ENDPOINT` carried no `caps[0]`,
    /// or `QUERY_ENDPOINT` could not derive from the stored cap (its
    /// publisher is gone; the entry is evicted).
    pub const INSUFFICIENT_CAPS: u64 = 3;
    /// Reserved; not emitted by the current svcmgr.
    pub const EVENT_QUEUE_FAILED: u64 = 4;
    /// Discovery registry lookup: name is not published.
    pub const UNKNOWN_NAME: u64 = 5;
    /// Discovery registry publish: table full or duplicate name.
    pub const REGISTER_REJECTED: u64 = 6;
    /// Reserved; not emitted by the current svcmgr. Each handover-endowment
    /// `CAPS` round carries the caller's `SVCMGR_LABELS_VERSION` in `data[1]`
    /// (after the `svcmgr_endowment::kind::CAPS` round kind in `data[0]`); on
    /// a mismatch svcmgr's bootstrap fails without replying this code.
    pub const LABEL_VERSION_MISMATCH: u64 = 7;
    /// Caller's badge lacks [`svcmgr_labels::PUBLISH_AUTHORITY`] on a
    /// `PUBLISH_ENDPOINT` request or [`svcmgr_labels::HANDOVER_AUTHORITY`] on
    /// a `HANDOVER_COMPLETE`, or the handover has already run.
    pub const UNAUTHORIZED: u64 = 8;
    /// Client-side: the underlying `ipc_call` returned `Err` (no reply
    /// from svcmgr, transport-level failure), for a client that reports it
    /// in the svcmgr status space. Never emitted by svcmgr itself; no
    /// in-tree client synthesises it.
    pub const IPC_FAILED: u64 = 9;
    /// Unknown opcode on svcmgr endpoint.
    pub const UNKNOWN_OPCODE: u64 = 0xFFFF;
}

/// Error replies from block device drivers.
pub mod blk_errors
{
    /// Request handled.
    pub const SUCCESS: u64 = 0;
    /// Device returned an error status byte (value is the `VirtIO` status byte).
    /// Values 1 (IOERR), 2 (UNSUPP) per `VirtIO` 1.2 §5.2.6.
    pub const DEVICE_STATUS_IOERR: u64 = 1;
    /// Device returned the `VirtIO` UNSUPP status byte (2): it does not
    /// support the request type.
    pub const DEVICE_STATUS_UNSUPP: u64 = 2;
    /// Read LBA is outside the bounds registered for the caller's badge.
    pub const OUT_OF_BOUNDS: u64 = 3;
    /// Partition registration rejected (no authority, table full, or bad args).
    pub const REGISTER_REJECTED: u64 = 4;
    /// Memory cap rejected: `BLK_READ_INTO_MEMORY` target missing
    /// `MAP|WRITE` rights, `BLK_WRITE_FROM_MEMORY` source missing
    /// `MAP` rights, smaller than `count * 512` bytes, or absent;
    /// also returned when `count` is 0 or `count * 512` exceeds `u32::MAX`
    /// (an overflowing multiply included).
    pub const INVALID_MEMORY_CAP: u64 = 5;
    /// Caller's compiled `BLK_LABELS_VERSION` does not match the receiver's.
    /// `REGISTER_PARTITION` is the handshake entry point and carries the
    /// caller's version as `data[0]` (with `base_lba` shifted to `data[1]`
    /// and `length_lba` to `data[2]`); mismatch here means the caller was
    /// built against a different revision of `shared/ipc`.
    pub const LABEL_VERSION_MISMATCH: u64 = 6;
    /// The request got no usable completion: the device did not complete it
    /// within the driver's timeout, published a malformed completion, wrote a
    /// status byte outside `VirtIO`'s set, or the chain could not be queued.
    /// After a lost request the driver resets the device, so the reply's
    /// Memory cap is free of device DMA, and answers every later
    /// `BLK_READ_INTO_MEMORY` / `BLK_WRITE_FROM_MEMORY` with this code
    /// (fail-stop).
    pub const DEVICE_FAULT: u64 = 7;
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

/// Stack-owned snapshot of an IPC message — label, badge, data words, and
/// received capability handles, carried by value across the IPC wrapper
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
/// plus `MSG_CAP_SLOTS_MAX` cap handles. No allocation; `no_std`-clean;
/// cheap to return by value.
#[derive(Clone, Copy)]
pub struct IpcMessage
{
    /// Protocol label (opcode / reply code / bit-packed header).
    pub label: u64,
    /// Endpoint badge delivered by `ipc_recv`; zero on send paths
    /// and for unbadged endpoints.
    pub badge: u64,
    data: [u64; MSG_DATA_WORDS_MAX],
    /// Number of valid `u64` words in `data`. `<= MSG_DATA_WORDS_MAX`: every
    /// [`IpcMessageBuilder`] setter panics past the bound in every build (an
    /// empty source at an out-of-range start included), and
    /// [`IpcMessage::from_ipc_buf`] requires it of its caller.
    data_len: u8,
    /// Number of valid slots in `cap_slots`. `<= MSG_CAP_SLOTS_MAX`.
    cap_count: u8,
    cap_slots: [u32; MSG_CAP_SLOTS_MAX],
}

impl IpcMessage
{
    /// Zero-length message carrying only a label (no data, no caps, no
    /// badge).
    #[must_use]
    pub const fn new(label: u64) -> Self
    {
        Self {
            label,
            badge: 0,
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

    /// Read data word `idx`. Reading past the sender's declared
    /// `word_count()` returns zero — the unused array slots are zero-init
    /// and the kernel does not write them past the declared range. This
    /// is a deliberate contract so protocols that carry optional trailing
    /// words at fixed offsets keep working.
    ///
    /// # Panics
    /// Panics in every build if `idx >= MSG_DATA_WORDS_MAX` (the array
    /// bounds check); the index is a protocol constant, so an overrun is a
    /// programmer error.
    #[must_use]
    pub fn word(&self, idx: usize) -> u64
    {
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
        let words = self.words();
        // SAFETY: `words` is a bounds-checked sub-slice of `data`, so a byte
        // view of `words.len() * 8` bytes from its start covers only
        // initialised memory of that array; u64 alignment is stricter than
        // u8 alignment, and the shared borrow of `self` keeps the array
        // alive and unmodified for the returned slice's lifetime.
        unsafe {
            core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), core::mem::size_of_val(words))
        }
    }

    /// Slice view of the message's cap handles: on a received message, the
    /// delivered destination handles; on a message being built, the full
    /// handles to transfer (see [`IpcMessageBuilder::cap`]).
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
        badge: u64,
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
        // Cap metadata: cap_count at word[MSG_DATA_WORDS_MAX], delivered
        // cap handles at word[MSG_DATA_WORDS_MAX + 1 ..].
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
            badge,
            data,
            data_len: word_count as u8,
            cap_count: cap_count as u8,
            cap_slots,
        }
    }

    /// Write the populated data words into the IPC buffer.
    ///
    /// Used by the `ipc_call` / `ipc_reply` wrappers before issuing the
    /// syscall. Cap handles are passed as syscall arguments; the sender
    /// does not write cap metadata into the buffer (the kernel installs
    /// caps in the receiver and writes the receiver-side handles into
    /// the receiver's buffer).
    ///
    /// # Safety
    /// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC
    /// buffer page as registered via `ipc_buffer_set`.
    pub unsafe fn write_to_ipc_buf(&self, ipc_buf: *mut u64)
    {
        for (i, &val) in self.words().iter().enumerate()
        {
            // SAFETY: `words()` is a bounds-checked sub-slice of the
            // `MSG_DATA_WORDS_MAX`-word `data` array, so
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
    ///
    /// # Panics
    /// Panics in every build if `idx >= MSG_DATA_WORDS_MAX` (the array
    /// bounds check on the `MSG_DATA_WORDS_MAX`-word data array, which
    /// fires before `word_count` can grow past the bound); see
    /// [`IpcMessageBuilder::word_count`] for why an overrun is treated as
    /// a programmer error.
    #[must_use]
    pub fn word(mut self, idx: usize, val: u64) -> Self
    {
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
    ///
    /// # Panics
    /// Panics in every build if `start + src.len() > MSG_DATA_WORDS_MAX`,
    /// an empty `src` at an out-of-range `start` included, so `word_count`
    /// can never be set past the bound; see
    /// [`IpcMessageBuilder::word_count`] for why the bound is asserted.
    #[must_use]
    pub fn words(mut self, start: usize, src: &[u64]) -> Self
    {
        assert!(
            start + src.len() <= MSG_DATA_WORDS_MAX,
            "IpcMessageBuilder::words: range exceeds MSG_DATA_WORDS_MAX"
        );
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
    ///
    /// # Panics
    /// Panics in every build if the packed range
    /// `start_word + src.len().div_ceil(8)` exceeds `MSG_DATA_WORDS_MAX`, an
    /// empty `src` at an out-of-range `start_word` included, so `word_count`
    /// can never be set past the bound; see
    /// [`IpcMessageBuilder::word_count`] for why the bound is asserted.
    #[must_use]
    pub fn bytes(mut self, start_word: usize, src: &[u8]) -> Self
    {
        let word_count = src.len().div_ceil(8);
        assert!(
            start_word + word_count <= MSG_DATA_WORDS_MAX,
            "IpcMessageBuilder::bytes: range exceeds MSG_DATA_WORDS_MAX"
        );
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

    /// Append one capability to transfer. `handle` must be the full cap
    /// handle as returned by the cap syscalls (index + per-slot generation)
    /// — the kernel generation-validates it and rejects a stale handle with
    /// `InvalidCapability`.
    ///
    /// # Panics
    /// Panics in every build if `MSG_CAP_SLOTS_MAX` caps are already
    /// appended (the slot array bounds check); a message's cap count is a
    /// protocol constant, so an overrun is a programmer error.
    #[must_use]
    pub fn cap(mut self, handle: u32) -> Self
    {
        let i = self.msg.cap_count as usize;
        self.msg.cap_slots[i] = handle;
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
    ///
    /// # Panics
    /// Panics in every build if `len > MSG_DATA_WORDS_MAX`. The count is a
    /// protocol constant, so an overrun is a programmer error — the same
    /// one `word`/`words`/`bytes` panic on for an out-of-range index — and
    /// it must not reach the `data_len <= MSG_DATA_WORDS_MAX` invariant the
    /// message's views rely on.
    #[must_use]
    pub fn word_count(mut self, len: usize) -> Self
    {
        assert!(
            len <= MSG_DATA_WORDS_MAX,
            "IpcMessageBuilder::word_count: len exceeds MSG_DATA_WORDS_MAX"
        );
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
/// The endpoint cap must have `EpRights::GRANT` when `msg.caps()` is non-empty.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code if the endpoint cap is invalid, the
/// caller has insufficient rights (`GRANT` missing on a cap-bearing call),
/// a cap slot is stale or Null (`InvalidCapability`), a cap slot is
/// repeated in the message (`InvalidArgument`), a cap slot is pinned by an
/// in-flight `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer
/// (`InvalidState`), or the call is interrupted. Cap-slot problems are
/// rejected before blocking; a refusal arising only afterwards delivers the
/// message with zero caps (the caller keeps its capabilities).
#[inline]
pub unsafe fn ipc_call(ep: u32, msg: &IpcMessage, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe {
        msg.write_to_ipc_buf(ipc_buf);
    }
    let caps = msg.caps();
    let (cap_lo, cap_hi) = syscall::pack_cap_handles(caps);
    let (reply_label, reply_word_count) =
        syscall::raw_ipc_call(ep, msg.label, msg.word_count(), caps.len(), cap_lo, cap_hi)?;
    // SAFETY: `ipc_buf` is the registered IPC buffer; kernel wrote the
    // reply (data + cap metadata) into it before return. `reply_word_count`
    // is already clamped to MSG_DATA_WORDS_MAX by `raw_ipc_call`.
    Ok(unsafe { IpcMessage::from_ipc_buf(ipc_buf, reply_label, 0, reply_word_count) })
}

/// Receive on an endpoint cap, returning a stack-owned message snapshot.
///
/// Blocks until a caller sends. Copies the message (label, badge, data
/// words, cap metadata) from the registered IPC buffer into a fresh
/// [`IpcMessage`] before returning. After return the IPC buffer is scratch
/// — nested IPC between `ipc_recv` and reading the message is safe.
///
/// A reply still pending from an earlier receive is released once the
/// receive passes its capability check and cap-slot pre-allocation: that
/// caller's `ipc_call` returns `Interrupted`, and a fault-blocked caller is
/// killed. A receive refused before then keeps the pending binding (see
/// `docs/ipc-design.md` § The Call/Reply Model).
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code:
/// - `InvalidCapability` — `ep` is not a live Endpoint cap.
/// - `InsufficientRights` — `ep` lacks Receive rights.
/// - `QuotaExceeded` — the cap-slot pre-allocation for incoming caps was
///   refused because this thread's `CSpace` directory is structurally full.
/// - `OutOfMemory` — the cap-slot pre-allocation was refused because the
///   `CSpace`'s slot-page pool is exhausted.
/// - `Interrupted` — this thread was stopped, or the endpoint was destroyed,
///   while the receive was blocked.
///
/// The first four refuse the receive before any pending reply is released,
/// so a pending caller stays bound.
#[inline]
pub unsafe fn ipc_recv(ep: u32, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    let (label, badge, word_count) = syscall::raw_ipc_recv(ep)?;
    // SAFETY: `ipc_buf` is the registered IPC buffer; kernel wrote data +
    // cap metadata there before return. `word_count` is already clamped to
    // MSG_DATA_WORDS_MAX by `raw_ipc_recv`.
    Ok(unsafe { IpcMessage::from_ipc_buf(ipc_buf, label, badge, word_count) })
}

/// Reply to the current thread's pending caller with `msg`.
///
/// Writes `msg`'s data words into the registered IPC buffer, then issues
/// `SYS_IPC_REPLY` with `msg.word_count()` words and `msg.caps()` cap slots.
/// Cap slots move from the server's `CSpace` to the caller's `CSpace`
/// all-or-nothing with the reply. An `Err` return consumes the pending
/// reply either way: when a caller was claimed it has already been woken
/// with the synthetic `IPC_REPLY_TRANSFER_FAILED` label (a reply cap slot
/// stale, repeated, pinned by an in-flight revoke, move, or IPC capability
/// transfer, or unacceptable to its `CSpace`), and when none was pending
/// there is nothing to wake — in both cases the reply must not be retried.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` (no pending
/// reply target, or a reply cap slot is stale or Null), `InvalidArgument`
/// (a cap slot repeated in the reply), `InvalidState` (a reply cap slot is
/// pinned by an in-flight `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability
/// transfer), or `QuotaExceeded` / `OutOfMemory` (the caller's `CSpace`
/// cannot accept the reply caps). The reply never blocks, so it never returns
/// `Interrupted`; the message's counts are within the kernel's maxima by
/// construction (the kernel clamps larger ones rather than rejecting them).
#[inline]
pub unsafe fn ipc_reply(msg: &IpcMessage, ipc_buf: *mut u64) -> Result<(), i64>
{
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe {
        msg.write_to_ipc_buf(ipc_buf);
    }
    let caps = msg.caps();
    let (cap_lo, cap_hi) = syscall::pack_cap_handles(caps);
    syscall::raw_ipc_reply(msg.label, msg.word_count(), caps.len(), cap_lo, cap_hi)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A `REQUEST_MEMORY_CAPS` reply with `label`, data `words`, and one
    /// transferred cap per entry of `caps`.
    fn grant_reply(label: u64, words: &[u64], caps: &[u32]) -> IpcMessage
    {
        let mut b = IpcMessage::builder(label).words(0, words);
        for &c in caps
        {
            b = b.cap(c);
        }
        b.build()
    }

    #[test]
    fn grant_layout_splits_page_counts_and_bases_per_cap()
    {
        let reply = grant_reply(0, &[2, 3, 5, 0x1000, 0x8000], &[11, 12]);
        let (pages, bases) = memmgr_grant_layout(&reply).expect("well-formed reply");
        assert_eq!(pages, &[3, 5]);
        assert_eq!(bases, &[0x1000, 0x8000]);
    }

    #[test]
    fn grant_layout_refuses_an_error_label()
    {
        let reply = grant_reply(
            memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS,
            &[1, 1, 0x1000],
            &[11],
        );
        assert_eq!(memmgr_grant_layout(&reply), None);
    }

    #[test]
    fn grant_layout_refuses_a_reply_without_data_words()
    {
        assert_eq!(memmgr_grant_layout(&grant_reply(0, &[], &[11])), None);
    }

    #[test]
    fn grant_layout_refuses_a_zero_count()
    {
        assert_eq!(memmgr_grant_layout(&grant_reply(0, &[0], &[])), None);
    }

    #[test]
    fn grant_layout_refuses_a_count_other_than_the_caps_transferred()
    {
        // Declaring more caps than arrived would put the phys words at an
        // offset the transferred count does not establish.
        let reply = grant_reply(0, &[2, 1, 1, 0x1000, 0x2000], &[11]);
        assert_eq!(memmgr_grant_layout(&reply), None);
    }

    #[test]
    fn grant_layout_refuses_words_too_few_for_the_count()
    {
        let reply = grant_reply(0, &[2, 1, 1, 0x1000], &[11, 12]);
        assert_eq!(memmgr_grant_layout(&reply), None);
    }

    #[test]
    fn packed_bytes_round_trip_through_data_bytes_with_zero_padding()
    {
        // 13 bytes straddle a word boundary: the tail word must carry the
        // 5 live bytes little-endian and zero padding above them.
        let payload: [u8; 13] = *b"seraph-ipc:13";
        let msg = IpcMessage::builder(7).bytes(1, &payload).build();
        assert_eq!(msg.word_count(), 3);
        let bytes = msg.data_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[..8], &[0u8; 8]);
        assert_eq!(&bytes[8..21], &payload);
        assert_eq!(&bytes[21..], &[0u8; 3]);
    }

    #[test]
    fn setters_accept_ranges_ending_exactly_at_the_data_bound()
    {
        let msg = IpcMessage::builder(1)
            .words(MSG_DATA_WORDS_MAX - 2, &[1, 2])
            .bytes(MSG_DATA_WORDS_MAX - 1, &[0xAA; 8])
            .word_count(MSG_DATA_WORDS_MAX)
            .build();
        assert_eq!(msg.word_count(), MSG_DATA_WORDS_MAX);
        assert_eq!(msg.word(MSG_DATA_WORDS_MAX - 2), 1);
        assert_eq!(msg.word(MSG_DATA_WORDS_MAX - 1), 0xAAAA_AAAA_AAAA_AAAA);
    }

    #[test]
    fn reading_past_the_declared_count_yields_zero()
    {
        let msg = IpcMessage::builder(1).word(2, 9).build();
        assert_eq!(msg.word_count(), 3);
        assert_eq!(msg.word(MSG_DATA_WORDS_MAX - 1), 0);
    }

    #[test]
    #[should_panic(expected = "word_count: len exceeds MSG_DATA_WORDS_MAX")]
    fn word_count_past_the_data_bound_panics()
    {
        let _ = IpcMessage::builder(1).word_count(MSG_DATA_WORDS_MAX + 1);
    }

    #[test]
    #[should_panic(expected = "words: range exceeds MSG_DATA_WORDS_MAX")]
    fn empty_words_at_an_out_of_range_start_panics()
    {
        let _ = IpcMessage::builder(1).words(MSG_DATA_WORDS_MAX + 1, &[]);
    }

    #[test]
    #[should_panic(expected = "bytes: range exceeds MSG_DATA_WORDS_MAX")]
    fn empty_bytes_at_an_out_of_range_start_panics()
    {
        let _ = IpcMessage::builder(1).bytes(MSG_DATA_WORDS_MAX + 1, &[]);
    }
}
