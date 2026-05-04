// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Syscall ABI definitions — single source of truth.
//!
//! This crate defines the binary interface between userspace and the kernel.
//! See `kernel/docs/syscalls.md` for the full specification.
//!
//! # Register conventions
//!
//! **x86-64** (`SYSCALL`/`SYSRET`):
//! - `rax` — syscall number (in); return value (out; negative = error)
//! - `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` — arguments 0–5
//! - `rcx` clobbered by `SYSCALL` (holds return address); not an arg register
//! - `r11` clobbered by `SYSCALL` (holds saved rflags); not an arg register
//! - `rdx` — secondary return value (e.g. word count from `ipc_recv`)
//!
//! **RISC-V** (`ECALL`):
//! - `a7` — syscall number
//! - `a0`–`a5` — arguments 0–5
//! - `a0` — primary return value (negative = error)
//! - `a1` — secondary return value
//!
//! # Rules
//! - No std; builds in `no_std`.
//! - No inline assembly.
//! - All cross-boundary types are `#[repr(C)]` with stable layout.
//! - No dependencies outside `core`.

// When pulled into std's dep graph via build-std (feature
// `rustc-dep-of-std` on), `core` isn't yet a conventional crate — we
// import the `rustc-std-workspace-core` facade and alias it so
// `use core::…` continues to resolve. Mirror of the libc / hermit-abi
// pattern. The normal userspace build path keeps plain `#![no_std]`.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

// `no_core` disables the automatic prelude; bring it in by hand so
// `#[derive(…)]`, Copy/Clone, the operator traits, etc. resolve.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

// ── Architectural constants ───────────────────────────────────────────────────

/// Userspace page size in bytes. The kernel maps and unmaps memory at this
/// granularity; `mem_map`'s `offset_pages` and `page_count` arguments are
/// scaled by this constant. Both supported architectures (x86-64 and RISC-V
/// RV64GC under Sv48) use 4 KiB base pages.
pub const PAGE_SIZE: u64 = 0x1000;

// ── Syscall numbers ───────────────────────────────────────────────────────────

/// IPC: synchronous call (send + block waiting for reply).
pub const SYS_IPC_CALL: u64 = 0;
/// IPC: reply to a pending call.
pub const SYS_IPC_REPLY: u64 = 1;
/// IPC: receive a call on an endpoint.
pub const SYS_IPC_RECV: u64 = 2;
/// Signal: send (OR bits into signal object).
pub const SYS_SIGNAL_SEND: u64 = 3;
/// Signal: wait (read-and-clear; blocks if zero).
///
/// arg0 = signal cap index (WAIT right). arg1 = `timeout_ms`: `0` means
/// block indefinitely (the only behaviour before the timeout extension);
/// `> 0` means block until bits are delivered *or* `timeout_ms`
/// milliseconds have elapsed, whichever comes first. On timeout the
/// syscall returns `0` (unambiguous — `signal_send` rejects zero-bit
/// sends, so a legitimate wake always carries non-zero bits).
pub const SYS_SIGNAL_WAIT: u64 = 4;
/// `EventQueue`: post an entry.
pub const SYS_EVENT_POST: u64 = 5;
/// `EventQueue`: receive an entry.
///
/// arg0 = event queue cap index (RECV right). arg1 = `timeout_ms`:
/// - `0` blocks indefinitely until a post arrives.
/// - `u64::MAX` is non-blocking try-once: returns `WouldBlock` immediately
///   if the queue is empty.
/// - `1 ..= u64::MAX-1` blocks until a post arrives or the timeout
///   elapses, whichever comes first. On timeout returns `WouldBlock`
///   (same code as the try-once-empty case — both mean "no payload
///   available"; the caller already knows which mode it asked for).
///
/// On success returns `0` plus the payload in the secondary return
/// register. Sentinel layout matches `SYS_SIGNAL_WAIT` (`0` = forever),
/// but event-queue payloads may be any `u64` including 0, so the kernel
/// uses an out-of-band `tcb.timed_out` marker instead of an in-band
/// sentinel on the payload register.
pub const SYS_EVENT_RECV: u64 = 6;
/// Capability: create an `Endpoint` object.
pub const SYS_CAP_CREATE_ENDPOINT: u64 = 7;
/// Capability: create a `Signal` object.
pub const SYS_CAP_CREATE_SIGNAL: u64 = 8;
/// Capability: create an `EventQueue` object.
pub const SYS_CAP_CREATE_EVENT_Q: u64 = 9;
/// Capability: create a `Thread` object.
pub const SYS_CAP_CREATE_THREAD: u64 = 10;
/// Capability: create an `AddressSpace` object.
pub const SYS_CAP_CREATE_ASPACE: u64 = 11;
/// Capability: create a `CSpace` object.
pub const SYS_CAP_CREATE_CSPACE: u64 = 12;
/// Capability: create a `WaitSet` object.
pub const SYS_CAP_CREATE_WAIT_SET: u64 = 13;
/// Capability: derive (attenuate rights).
pub const SYS_CAP_DERIVE: u64 = 14;
/// Capability: revoke a capability and all descendants.
pub const SYS_CAP_REVOKE: u64 = 15;
/// Memory: map a Frame into an address space.
pub const SYS_MEM_MAP: u64 = 16;
/// Memory: unmap a region from an address space.
pub const SYS_MEM_UNMAP: u64 = 17;
/// Memory: change protections on a mapped region.
pub const SYS_MEM_PROTECT: u64 = 18;
/// Thread: start execution.
pub const SYS_THREAD_START: u64 = 19;
/// Thread: stop execution.
pub const SYS_THREAD_STOP: u64 = 20;
/// Thread: yield the CPU.
pub const SYS_THREAD_YIELD: u64 = 21;
/// Thread: exit and free TCB.
pub const SYS_THREAD_EXIT: u64 = 22;
/// Thread: configure (set entry, stack, arg).
pub const SYS_THREAD_CONFIGURE: u64 = 23;
/// Capability: copy a slot.
pub const SYS_CAP_COPY: u64 = 24;
/// Capability: move a slot (destroying the source).
pub const SYS_CAP_MOVE: u64 = 25;
/// `WaitSet`: add a member.
pub const SYS_WAIT_SET_ADD: u64 = 26;
/// `WaitSet`: remove a member.
pub const SYS_WAIT_SET_REMOVE: u64 = 27;
/// `WaitSet`: wait for any member to become ready.
pub const SYS_WAIT_SET_WAIT: u64 = 28;
/// IRQ: acknowledge a delivered interrupt.
pub const SYS_IRQ_ACK: u64 = 29;
/// IRQ: register a signal to receive interrupt notifications.
pub const SYS_IRQ_REGISTER: u64 = 30;
/// Capability: delete a slot.
pub const SYS_CAP_DELETE: u64 = 31;
/// Capability: insert an object into a specific slot.
pub const SYS_CAP_INSERT: u64 = 32;
/// Frame: split a large frame into smaller ones.
pub const SYS_FRAME_SPLIT: u64 = 33;
/// Memory: map an MMIO region.
pub const SYS_MMIO_MAP: u64 = 34;
/// I/O: bind an `IoPortRange` to the calling thread.
pub const SYS_IOPORT_BIND: u64 = 35;
/// Capability: read-only inspection of a cap's runtime state.
///
/// Returns a discriminated union keyed by `CapTag`:
/// - `Frame` → `(size_bytes, available_bytes, has_retype_right)`
/// - `AddressSpace` → `(pt_growth_budget_bytes)`
/// - `CSpace` → `(slot_capacity, slots_used, growth_budget_bytes)`
/// - all other tags → `(tag, rights)` only
///
/// Cannot fail except on null/invalid slot. Slot 36 was vacated by the
/// `SYS_DMA_GRANT` removal (commit `704c1b4`).
///
/// arg0 = slot index in the caller's `CSpace`.
/// arg1 = field selector — one of the [`CAP_INFO_*`](CAP_INFO_TAG_RIGHTS)
///        constants below. The value returned in the primary register
///        depends on the selector. Field selectors that are tag-specific
///        (every constant other than [`CAP_INFO_TAG_RIGHTS`]) require the
///        slot's `CapTag` to match the field's owning tag; calls with a
///        mismatched slot return [`SyscallError::InvalidArgument`].
///        Selectors not listed below also return
///        [`SyscallError::InvalidArgument`].
pub const SYS_CAP_INFO: u64 = 36;

// ── SYS_CAP_INFO field selectors ──────────────────────────────────────────────
//
// Pass one of these constants as `arg1` to `SYS_CAP_INFO`. Each call returns a
// single `u64`. Userspace assembles a full picture by issuing repeated calls.
// The pattern mirrors `SYS_SYSTEM_INFO` (single-register return + discriminant
// argument) so the wrapper shape stays uniform.

/// Universal field — valid for any non-null capability slot.
///
/// Returns the packed value `((tag as u8 as u64) << 32) | (rights as u32 as u64)`.
/// Userspace recovers the components with:
/// ```text
/// tag    = (value >> 32) as u8;       // matches CapTag discriminant
/// rights =  value        as u32;      // matches Rights bitmask
/// ```
pub const CAP_INFO_TAG_RIGHTS: u64 = 0;

/// `Frame` only — total byte size of the frame region.
///
/// Returns `FrameObject::size`. Calling on a non-Frame slot returns
/// [`SyscallError::InvalidArgument`].
pub const CAP_INFO_FRAME_SIZE: u64 = 1;

/// `Frame` only — bytes still available to retype or map from this frame.
///
/// Returns the current value of `FrameObject::available_bytes`. Calling on
/// a non-Frame slot returns [`SyscallError::InvalidArgument`].
pub const CAP_INFO_FRAME_AVAILABLE: u64 = 2;

/// `Frame` only — `1` if the cap holds the `RETYPE` right, otherwise `0`.
///
/// Returns `1` or `0`. Calling on a non-Frame slot returns
/// [`SyscallError::InvalidArgument`].
pub const CAP_INFO_FRAME_HAS_RETYPE: u64 = 3;

/// `AddressSpace` only — bytes available to back new intermediate page-table pages.
///
/// Returns the current value of `AddressSpaceObject::pt_growth_budget_bytes`.
/// Calling on a non-`AddressSpace` slot returns [`SyscallError::InvalidArgument`].
pub const CAP_INFO_ASPACE_PT_BUDGET: u64 = 4;

/// `CSpace` only — total slot capacity (`max_slots`).
///
/// Returns the `CSpace`'s `max_slots` value. Calling on a non-`CSpace` slot
/// returns [`SyscallError::InvalidArgument`].
pub const CAP_INFO_CSPACE_CAPACITY: u64 = 5;

/// `CSpace` only — number of currently populated (non-null) slots.
///
/// Returns the `CSpace`'s `populated_count()`. Calling on a non-`CSpace` slot
/// returns [`SyscallError::InvalidArgument`].
pub const CAP_INFO_CSPACE_USED: u64 = 6;

/// `CSpace` only — bytes available to back new slot pages.
///
/// Returns the current value of `CSpaceKernelObject::cspace_growth_budget_bytes`.
/// Calling on a non-`CSpace` slot returns [`SyscallError::InvalidArgument`].
pub const CAP_INFO_CSPACE_BUDGET: u64 = 7;

/// `Frame` only — physical base address of the frame region.
///
/// Returns `FrameObject::base`. Calling on a non-Frame slot returns
/// [`SyscallError::InvalidArgument`]. Used by memmgr to track contiguity
/// when ingesting Frame caps it did not itself mint (e.g., boot-module
/// caps donated through `memmgr_labels::DONATE_FRAMES`).
pub const CAP_INFO_FRAME_PHYS_BASE: u64 = 8;

// ── CapTag discriminants ─────────────────────────────────────────────────────
//
// Userspace constants matching the kernel `CapTag` enum, for callers that
// extract the tag from a [`CAP_INFO_TAG_RIGHTS`] result. Only the variants
// userspace currently needs to identify are exposed.

/// `CapTag::Frame` discriminant.
pub const CAP_TAG_FRAME: u8 = 1;
/// Thread: set scheduling priority.
pub const SYS_THREAD_SET_PRIORITY: u64 = 37;
/// Thread: set CPU affinity.
pub const SYS_THREAD_SET_AFFINITY: u64 = 38;
/// Thread: read register state (debug / ptrace).
pub const SYS_THREAD_READ_REGS: u64 = 39;
/// Thread: write register state (debug / ptrace).
pub const SYS_THREAD_WRITE_REGS: u64 = 40;
/// `AddressSpace`: query mapping information.
pub const SYS_ASPACE_QUERY: u64 = 41;
/// IPC: set the IPC buffer address for the calling thread.
pub const SYS_IPC_BUFFER_SET: u64 = 42;
/// System: query kernel capabilities / version.
pub const SYS_SYSTEM_INFO: u64 = 43;
/// SBI: forward an SBI call to M-mode firmware (RISC-V only).
pub const SYS_SBI_CALL: u64 = 44;
/// Split an `MmioRegion` cap into two non-overlapping children.
pub const SYS_MMIO_SPLIT: u64 = 45;
/// Sleep the calling thread for a specified number of milliseconds.
pub const SYS_THREAD_SLEEP: u64 = 46;
/// Bind a death notification `EventQueue` to a thread.
pub const SYS_THREAD_BIND_NOTIFICATION: u64 = 47;
/// Capability: derive with an attached token value.
pub const SYS_CAP_DERIVE_TOKEN: u64 = 48;
/// Split an `Interrupt` range cap into two non-overlapping children.
pub const SYS_IRQ_SPLIT: u64 = 49;
/// Merge two adjacent sibling Frame caps into one covering both ranges.
pub const SYS_FRAME_MERGE: u64 = 50;

// ── Error codes ───────────────────────────────────────────────────────────────

/// Syscall error codes returned in `rax` / `a0` as negative `i64` values.
///
/// On success the return value is `>= 0`. On error it is one of these
/// negative values. Userspace wrappers check `rax < 0` to detect errors.
#[repr(i64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallError
{
    /// Syscall number is not valid.
    UnknownSyscall = -1,
    /// Capability slot index is out of range or slot is null.
    InvalidCapability = -2,
    /// Caller does not hold sufficient rights for this operation.
    InsufficientRights = -3,
    /// A pointer argument does not satisfy alignment or range requirements.
    InvalidAddress = -4,
    /// An integer argument is out of the valid range for this call.
    InvalidArgument = -5,
    /// The operation would block but the caller requested non-blocking mode.
    WouldBlock = -6,
    /// The target thread or object has already exited / been destroyed.
    ObjectGone = -7,
    /// No memory available to satisfy the request.
    OutOfMemory = -8,
    /// The operation is not supported on this object type.
    NotSupported = -9,
    /// The capability rights bitmask violates the W^X constraint.
    WxViolation = -10,
    /// The message is too large for the destination.
    MsgTooLarge = -11,
    /// Deadlock would occur (IPC cycle detected).
    Deadlock = -12,
    /// Event queue is full; post would be lost.
    QueueFull = -13,
    /// The target object is not in the required state for this operation
    /// (e.g. thread not `Stopped` for `read_regs`/`write_regs`).
    InvalidState = -15,
    /// A blocking operation was cancelled because the thread was stopped.
    /// The stopped thread sees this as the return value of its blocked syscall.
    Interrupted = -16,
}

// ── Scheduling constants ──────────────────────────────────────────────────────

/// Default scheduling priority for newly created threads.
pub const PRIORITY_DEFAULT: u8 = 10;
/// First priority level requiring a `SchedControl` capability with `Elevate` rights.
pub const SCHED_ELEVATED_MIN: u8 = 21;
/// Maximum priority available to userspace threads.
pub const PRIORITY_MAX: u8 = 30;

// ── Event Queue constants ─────────────────────────────────────────────────────

/// Maximum capacity (entry count) for an event queue created via
/// `SYS_CAP_CREATE_EVENT_Q`. Must be in the range `1..=EVENT_QUEUE_MAX_CAPACITY`.
pub const EVENT_QUEUE_MAX_CAPACITY: u32 = 4096;

// ── Message constants ─────────────────────────────────────────────────────────

/// Maximum number of data words in an IPC message.
///
/// Supports transferring a full 512-byte disk sector (64 words) inline.
/// Data is read from / written to the sender/receiver's IPC buffer page.
/// Cap metadata starts at word `MSG_DATA_WORDS_MAX` in the IPC buffer.
pub const MSG_DATA_WORDS_MAX: usize = 64;

/// Maximum number of capability slots transferable in a single IPC message.
pub const MSG_CAP_SLOTS_MAX: usize = 4;

/// Maximum number of registers used for inline message data (x86-64: rdi–r9).
/// Words beyond this limit require an IPC buffer in shared memory.
pub const MSG_REGS_DATA_MAX: usize = 6;

/// Synthetic reply label written to the caller's IPC message by the kernel
/// when `SYS_IPC_REPLY` rejects the server's reply before delivery
/// (caller's `CSpace` cannot accept reply caps, server cap-slot lookup
/// failed, malformed IPC buffer, etc.). The caller un-parks with this
/// label so it can surface a graceful failure instead of dead-locking.
/// Reserved by the kernel; servers must not produce this label themselves.
pub const IPC_REPLY_TRANSFER_FAILED: u64 = u64::MAX;

// ── Mapping protection bits ──────────────────────────────────────────────────

/// Mapping protection: writable. Bit 1, matching the kernel `Rights::WRITE` layout.
pub const MAP_WRITABLE: u64 = 0x2;

/// Mapping protection: executable. Bit 2, matching the kernel `Rights::EXECUTE` layout.
pub const MAP_EXECUTABLE: u64 = 0x4;

/// Mapping protection: read-only (no WRITE, no EXECUTE).
///
/// Passed as `prot_bits` to `SYS_MEM_MAP`; equivalent to 0 but more explicit.
pub const MAP_READONLY: u64 = 0;

// ── Capability rights masks ─────────────────────────────────────────────────
//
// `u64` masks for `cap_derive` / `cap_copy` / `cap_insert` rights parameters.
// Bit positions match the kernel `Rights` type (`kernel/src/cap/slot.rs`).

/// All rights — pass through whatever the source cap has. Equivalent to `!0u64`.
pub const RIGHTS_ALL: u64 = !0u64;

/// Send-only IPC endpoint: may call but not receive or grant caps.
pub const RIGHTS_SEND: u64 = 1 << 4;

/// Receive-only IPC endpoint: may accept calls but not call out or grant caps.
pub const RIGHTS_RECEIVE: u64 = 1 << 5;

/// Send + grant: may call and include capabilities in messages.
pub const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);

/// Frame: map read-only.
pub const RIGHTS_MAP_READ: u64 = 1 << 0;

/// Frame: map read-write.
pub const RIGHTS_MAP_RW: u64 = (1 << 0) | (1 << 1);

/// Frame: map read-execute.
pub const RIGHTS_MAP_RX: u64 = (1 << 0) | (1 << 2);

/// Thread: full control (start, stop, configure, observe).
pub const RIGHTS_THREAD: u64 = (1 << 11) | (1 << 12);

/// `CSpace`: full management (insert, delete, derive, revoke).
pub const RIGHTS_CSPACE: u64 = (1 << 13) | (1 << 14) | (1 << 15) | (1 << 16);

/// Frame: authority to retype memory into kernel objects.
///
/// Held by RAM Frame caps minted from buddy at boot; never held by firmware-
/// table / boot-module / init-segment Frame caps. Required by every retype-
/// consuming syscall.
pub const RIGHTS_RETYPE: u64 = 1 << 21;

// ── Exit reason constants ─────────────────────────────────────────────────────
//
// Values passed via death notification when a thread exits or faults.

/// Clean voluntary exit via `SYS_THREAD_EXIT`.
pub const EXIT_VOLUNTARY: u64 = 0;

/// Base value for fault-induced exits. The kernel adds the architecture-specific
/// fault vector/cause to this base: `EXIT_FAULT_BASE + vector` (x86-64) or
/// `EXIT_FAULT_BASE + cause` (RISC-V).
pub const EXIT_FAULT_BASE: u64 = 0x1000;

// ── System info ───────────────────────────────────────────────────────────────

/// Kernel version packed as a single `u64`.
///
/// Layout: `(major as u64) << 32 | (minor as u64) << 16 | (patch as u64)`
///
/// Versioning semantics (semver-style):
/// - **major** — incremented on breaking syscall ABI changes (syscall removed,
///   argument layout changed, error code semantics changed). Once the kernel
///   ABI stabilises this will be `>= 1`; while major is `0` the ABI is
///   explicitly unstable and may change freely between any releases.
/// - **minor** — incremented when new syscalls are added without breaking
///   existing ones.
/// - **patch** — incremented for bug fixes that do not affect the ABI.
///
/// Userspace extracts components with:
/// ```text
/// major = version >> 32
/// minor = (version >> 16) & 0xFFFF
/// patch = version & 0xFFFF
/// ```
///
/// The version is `0.0.1` during initial kernel development. Major will remain
/// `0` until the kernel reaches a meaningful level of completeness; during this
/// phase all ABI changes are considered fully fluid regardless of minor/patch.
// Encode as (major << 32) | (minor << 16) | patch. The zero shifts are retained
// to preserve the positional structure; they will carry non-zero values when
// the ABI stabilises.
#[allow(clippy::identity_op, clippy::eq_op)]
pub const KERNEL_VERSION: u64 = (0u64 << 32) | (0u64 << 16) | 1u64; // 0.0.1

/// Discriminant for `SYS_SYSTEM_INFO` queries.
///
/// Each variant returns a single `u64` in the primary return register.
/// No buffer is required.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemInfoType
{
    /// Kernel version packed as `(major << 32) | (minor << 16) | patch`.
    /// See [`KERNEL_VERSION`] for the current value and encoding details.
    KernelVersion = 0,
    /// Number of logical CPUs initialised at boot.
    CpuCount = 1,
    /// Number of free 4 KiB physical frames at the time of the call.
    FreeFrames = 2,
    /// Total number of 4 KiB physical frames detected at boot.
    /// `FreeFrames / TotalFrames` gives current memory pressure.
    TotalFrames = 3,
    /// Size of a physical page in bytes (always 4096 on supported platforms).
    PageSize = 4,
    /// Boot protocol version used by the bootloader.
    /// Userspace can use this to interpret fields in the boot info struct.
    BootProtocolVersion = 5,
    /// Microseconds elapsed since kernel timer initialisation.
    /// Returns 0 if the timer has not been initialised yet.
    ElapsedUs = 6,
}
