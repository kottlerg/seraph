// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/syscall/src/lib.rs

//! Syscall ABI definitions — single source of truth.
//!
//! This crate defines the binary interface between userspace and the kernel.
//! See `core/kernel/docs/syscalls.md` for the full specification; register
//! conventions are in its § Calling Convention.
//!
//! # Rules
//! - No std; builds in `no_std`.
//! - No inline assembly.
//! - Each cross-boundary type carries an explicit stable repr (`#[repr(C)]`
//!   structs, fixed-width integer-repr enums).
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
/// scaled by this constant. Both supported architectures use 4 KiB base pages
/// in every paging mode.
pub const PAGE_SIZE: u64 = 0x1000;

// ── Capability handle encoding ────────────────────────────────────────────────

/// Number of low bits in a capability handle that hold the `CSpace` slot index.
///
/// The remaining high bits hold a per-slot generation counter (see
/// [`cap_handle_gen`]). 24 index bits cover the maximum `CSpace` capacity with
/// generous headroom; the kernel static-asserts that its slot capacity fits.
pub const CAP_INDEX_BITS: u32 = 24;

/// Mask selecting the slot-index bits of a capability handle.
pub const CAP_INDEX_MASK: u32 = (1u32 << CAP_INDEX_BITS) - 1;

// Generation (8 bits) plus index (`CAP_INDEX_BITS`) must fit in the u32 handle.
// The handle is returned to userspace in a u64 register and reinterpreted as
// i64 by the dispatcher; a u32 zero-extends with bit 63 clear, so a single-cap
// return is never misread as a negative error code.
const _: () = assert!(CAP_INDEX_BITS + 8 <= 32);

/// Build a capability handle from a slot `index` and per-slot `generation`.
///
/// The handle userspace receives and passes back is
/// `(generation << CAP_INDEX_BITS) | index`. A `generation` of `0` makes the
/// handle numerically equal to the bare index, so a long-lived cap minted once
/// and never recycled keeps its historical handle value under this encoding
/// (the backward-compatibility hinge).
#[inline]
#[must_use]
// `u32::from` is not const-stable; the `u8 -> u32` widening cast is exact.
#[allow(clippy::cast_lossless)]
pub const fn cap_handle_encode(index: u32, generation: u8) -> u32
{
    ((generation as u32) << CAP_INDEX_BITS) | (index & CAP_INDEX_MASK)
}

/// Extract the slot index from a capability handle.
#[inline]
#[must_use]
pub const fn cap_handle_index(handle: u32) -> u32
{
    handle & CAP_INDEX_MASK
}

/// Extract the per-slot generation from a capability handle.
#[inline]
#[must_use]
// `>> CAP_INDEX_BITS` leaves at most 8 significant bits, so the `as u8` is exact.
#[allow(clippy::cast_possible_truncation)]
pub const fn cap_handle_gen(handle: u32) -> u8
{
    (handle >> CAP_INDEX_BITS) as u8
}

/// Pack up to [`MSG_CAP_SLOTS_MAX`] cap handles into the two IPC transfer
/// words: two 32-bit **full** handles per word (handles 0/1 in the low
/// word, 2/3 in the high word). Carrying the whole handle — index plus
/// per-slot generation — lets the kernel generation-validate the sender's
/// named slots and fail a stale, recycled handle closed. The inverse of
/// [`unpack_cap_handles`]; both ends of the wire use this one encoding.
/// Handles beyond [`MSG_CAP_SLOTS_MAX`] are silently ignored.
#[must_use]
pub fn pack_cap_handles(handles: &[u32]) -> (u64, u64)
{
    let mut lo: u64 = 0;
    let mut hi: u64 = 0;
    for (i, &handle) in handles.iter().take(MSG_CAP_SLOTS_MAX).enumerate()
    {
        let word = if i < 2 { &mut lo } else { &mut hi };
        *word |= u64::from(handle) << ((i % 2) * 32);
    }
    (lo, hi)
}

/// Unpack `count` cap handles from the two IPC transfer words packed by
/// [`pack_cap_handles`].
#[must_use]
pub fn unpack_cap_handles(lo: u64, hi: u64, count: usize) -> [u32; MSG_CAP_SLOTS_MAX]
{
    let mut out = [0u32; MSG_CAP_SLOTS_MAX];
    for (i, item) in out
        .iter_mut()
        .enumerate()
        .take(count.min(MSG_CAP_SLOTS_MAX))
    {
        let word = if i < 2 { lo } else { hi };
        let shift = (i % 2) * 32;
        // cast_possible_truncation: deliberate — each 32-bit field is one handle.
        #[allow(clippy::cast_possible_truncation)]
        {
            *item = (word >> shift) as u32;
        }
    }
    out
}

// ── Retype costs ──────────────────────────────────────────────────────────────

// The raw bytes the kernel debits from a Memory cap's retype budget for one
// sub-page kernel object: the 24-byte object wrapper plus the object's state
// (`cap::retype::dispatch_for` in core/kernel/src/cap/retype.rs, which uses
// these constants and pins them to the real sizes with const assertions). A
// userspace slab allocator sizes its request from them; the kernel rounds the
// debit up to its size class. They are the kernel's current retype cost for
// each object kind, so a change to an object's size changes them, and that is
// an ABI-visible change by design.

/// Raw retype debit of one `Endpoint`, in bytes.
pub const ENDPOINT_RETYPE_BYTES: u64 = 80;

/// Raw retype debit of one `Notification`, in bytes.
pub const NOTIFICATION_RETYPE_BYTES: u64 = 64;

/// Raw retype debit of one `WaitSet`, in bytes: the 24-byte wrapper plus the
/// kernel's declared 440-byte budget for the wait-set state, which the
/// state's real size never exceeds.
pub const WAIT_SET_RETYPE_BYTES: u64 = 464;

/// Raw retype debit of one `EventQueue` of user-visible `capacity` entries, in
/// bytes: the 24-byte wrapper, the 56-byte queue state, and `capacity + 1`
/// eight-byte ring slots, all inline in the retype slot. `capacity` is one the
/// kernel accepts, `1..=EVENT_QUEUE_MAX_CAPACITY`; a larger value can overflow.
#[must_use]
pub const fn event_queue_retype_bytes(capacity: u64) -> u64
{
    24 + 56 + (capacity + 1) * 8
}

// ── Syscall numbers ───────────────────────────────────────────────────────────

/// IPC: synchronous call (send + block waiting for reply).
pub const SYS_IPC_CALL: u64 = 0;
/// IPC: reply to a pending call.
pub const SYS_IPC_REPLY: u64 = 1;
/// IPC: receive a call on an endpoint.
pub const SYS_IPC_RECV: u64 = 2;
/// Notification: send (OR bits into notification object).
pub const SYS_NOTIFICATION_SEND: u64 = 3;
/// Notification: wait (read-and-clear; blocks if zero, with an optional
/// timeout). See `core/kernel/docs/syscalls.md` § `SYS_NOTIFICATION_WAIT` (4).
pub const SYS_NOTIFICATION_WAIT: u64 = 4;
/// `EventQueue`: post an entry.
pub const SYS_EVENT_POST: u64 = 5;
/// `EventQueue`: receive an entry (blocking, try-once, or with a timeout).
/// See `core/kernel/docs/syscalls.md` § `SYS_EVENT_RECV` (6).
pub const SYS_EVENT_RECV: u64 = 6;
/// Capability: create an `Endpoint` object.
pub const SYS_CAP_CREATE_ENDPOINT: u64 = 7;
/// Capability: create a `Notification` object.
pub const SYS_CAP_CREATE_NOTIFICATION: u64 = 8;
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
/// Memory: map a Memory cap into an address space.
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
/// Thread: exit the calling thread.
pub const SYS_THREAD_EXIT: u64 = 22;
/// Thread: configure (set entry, stack, arg, TLS base).
pub const SYS_THREAD_CONFIGURE: u64 = 23;
/// Capability: copy a slot into another `CSpace`, at a chosen slot or one the
/// kernel allocates. See `core/kernel/docs/syscalls.md` § `SYS_CAP_COPY` (24).
pub const SYS_CAP_COPY: u64 = 24;
/// Capability: move a slot (destroying the source).
pub const SYS_CAP_MOVE: u64 = 25;
/// `WaitSet`: add a member.
pub const SYS_WAIT_SET_ADD: u64 = 26;
/// `WaitSet`: remove a member.
pub const SYS_WAIT_SET_REMOVE: u64 = 27;
/// `WaitSet`: wait for any member to become ready. A wait set takes one
/// waiting thread: a wait while another thread waits returns `InvalidState`.
pub const SYS_WAIT_SET_WAIT: u64 = 28;
/// IRQ: acknowledge a delivered interrupt.
pub const SYS_IRQ_ACK: u64 = 29;
/// IRQ: register a notification to receive interrupt notifications.
pub const SYS_IRQ_REGISTER: u64 = 30;
/// Capability: delete a slot.
pub const SYS_CAP_DELETE: u64 = 31;
/// Thread: bind (or clear) the per-thread fault-handler endpoint. See
/// `core/kernel/docs/syscalls.md` § `SYS_THREAD_SET_FAULT_HANDLER` (32) and
/// [Fault Handling](../../../docs/fault-handling.md) for the protocol.
pub const SYS_THREAD_SET_FAULT_HANDLER: u64 = 32;
/// Memory: split a large Memory cap into smaller ones.
pub const SYS_MEMORY_SPLIT: u64 = 33;
/// Memory: map an MMIO region.
pub const SYS_MMIO_MAP: u64 = 34;
/// I/O: bind an `IoPort` cap to a thread (x86-64 only).
pub const SYS_IOPORT_BIND: u64 = 35;
/// Capability: read-only inspection of a cap's runtime state, one field per
/// call, chosen by one of the [`CAP_INFO_*`](CAP_INFO_TAG_RIGHTS) selectors
/// below. See `core/kernel/docs/syscalls.md` § `SYS_CAP_INFO` (36).
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

/// `Memory` only — total byte size of the memory region.
///
/// Returns `MemoryObject::size`. Calling on a non-Memory slot returns
/// [`SyscallError::InvalidArgument`].
pub const CAP_INFO_MEMORY_SIZE: u64 = 1;

/// `Memory` only — bytes still available to retype or map from this cap.
///
/// Returns the current value of `MemoryObject::available_bytes`. Calling on
/// a non-Memory slot returns [`SyscallError::InvalidArgument`].
pub const CAP_INFO_MEMORY_AVAILABLE: u64 = 2;

/// `Memory` only — `1` if the cap holds the `RETYPE` right, otherwise `0`.
///
/// Returns `1` or `0`. Calling on a non-Memory slot returns
/// [`SyscallError::InvalidArgument`].
pub const CAP_INFO_MEMORY_HAS_RETYPE: u64 = 3;

/// `AddressSpace` only — bytes available to back new intermediate page-table pages.
///
/// Returns the current value of `AddressSpaceObject::pt_growth_budget_bytes`.
/// Calling on a non-`AddressSpace` slot returns [`SyscallError::InvalidArgument`].
pub const CAP_INFO_ASPACE_PT_BUDGET: u64 = 4;

/// `CSpace` only — currently-backed slot capacity.
///
/// Returns the slots already threaded onto allocated pages plus the slots
/// the remaining growth-budget pages would back, clamped to the highest
/// reachable count (the directory's structural ceiling minus the
/// permanently reserved slot 0). Grows with augment-mode
/// `cap_create_cspace` donations. A mild over-estimate: the first page's
/// reserved slot 0 is counted before that page exists, and deep growth
/// spends an occasional budget page on a directory page that backs no
/// slots. Subtracting [`CAP_INFO_CSPACE_USED`] yields headroom, which
/// tolerates both. Calling on a non-`CSpace` slot returns
/// [`SyscallError::InvalidArgument`].
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

/// `Memory` only — physical base address of the memory region.
///
/// Returns `MemoryObject::base`. Calling on a non-Memory slot returns
/// [`SyscallError::InvalidArgument`]. Used by memmgr to track contiguity
/// when ingesting Memory caps it did not itself mint (e.g., boot-module
/// caps donated through `memmgr_labels::DONATE_MEMORY_CAPS`).
pub const CAP_INFO_MEMORY_PHYS_BASE: u64 = 8;

/// `Thread` only — kernel-authoritative lifecycle snapshot.
///
/// Returns the packed value
/// `(state_code << 32) | (exit_reason & 0xFFFF_FFFF)` where `state_code` is
/// one of the [`THREAD_STATE_*`](THREAD_STATE_CREATED) constants and
/// `exit_reason` is the kernel-recorded exit reason (meaningful only for
/// [`THREAD_STATE_EXITED`]; zero for other states). Calling on a non-Thread
/// slot returns [`SyscallError::InvalidArgument`].
///
/// Procmgr's `QUERY_PROCESS` handler consumes this so it can answer
/// "exited" or "alive" without racing the userspace death-event drain.
pub const CAP_INFO_THREAD_STATE: u64 = 9;

/// State code for `CAP_INFO_THREAD_STATE`: thread allocated, never started.
pub const THREAD_STATE_CREATED: u32 = 0;
/// State code for `CAP_INFO_THREAD_STATE`: thread is started and not exited
/// (Ready, Running, Blocked, or Stopped — distinctions are scheduler
/// implementation details, irrelevant to external observers).
pub const THREAD_STATE_ALIVE: u32 = 1;
/// State code for `CAP_INFO_THREAD_STATE`: thread has exited or faulted.
pub const THREAD_STATE_EXITED: u32 = 2;

/// `cap_info` selector: total context-switch activations across all CPUs that
/// loaded a tagged address space **without** flushing (the tagged-TLB
/// optimization firing). System-wide diagnostic; the slot argument is ignored
/// beyond requiring a live capability. Zero when tagging is disabled.
pub const CAP_INFO_TLB_ELIDED: u64 = 10;

/// `cap_info` selector: total context-switch activations across all CPUs that
/// performed a TLB flush (tag reissue, switched-away unmap catch-up, or
/// pool-exhaustion fallback). Pairs with [`CAP_INFO_TLB_ELIDED`].
pub const CAP_INFO_TLB_PERFORMED: u64 = 11;

/// `Memory` only — how many user leaf mappings, across every address space,
/// name a frame of the memory region.
///
/// Returns the sum, over the region's frames, of each frame's count of user
/// page-table leaves that name it (or that a CPU may still hold in its TLB).
/// A frame's count falls only once every CPU has dropped the leaf, so a value
/// equal to the mappings the caller itself holds means no other address space
/// can reach the region. A region larger than
/// [`CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES`] pages, or a non-Memory slot, returns
/// [`SyscallError::InvalidArgument`]. Used by a server that hands a page to a
/// client and must know the client's mapping is gone before reusing the page.
pub const CAP_INFO_MEMORY_MAPPINGS: u64 = 12;

/// Largest Memory region, in pages, [`CAP_INFO_MEMORY_MAPPINGS`] answers for:
/// the query reads one count per page, so the bound keeps the syscall short.
pub const CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES: u64 = 512;

// ── CapTag discriminants ─────────────────────────────────────────────────────
//
// Userspace constants matching the kernel `CapTag` enum, for callers that
// extract the tag from a [`CAP_INFO_TAG_RIGHTS`] result. Only the variants
// userspace currently needs to identify are exposed.

/// `CapTag::Memory` discriminant.
pub const CAP_TAG_MEMORY: u8 = 1;

// ── Syscall numbers (continued) ──────────────────────────────────────────────
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
/// Split an `Mmio` cap into two non-overlapping children.
pub const SYS_MMIO_SPLIT: u64 = 45;
/// Sleep the calling thread for a specified number of milliseconds.
pub const SYS_THREAD_SLEEP: u64 = 46;
/// Bind a death notification `EventQueue` to a thread.
pub const SYS_THREAD_BIND_NOTIFICATION: u64 = 47;
/// Capability: derive with an attached badge value.
pub const SYS_CAP_DERIVE_BADGE: u64 = 48;
/// Split an `Interrupt` range cap into two non-overlapping children.
pub const SYS_IRQ_SPLIT: u64 = 49;
/// Merge two adjacent sibling Memory caps into one covering both ranges.
pub const SYS_MEMORY_MERGE: u64 = 50;
/// Split an `IoPort` cap into two non-overlapping children (`x86_64` only).
pub const SYS_IOPORT_SPLIT: u64 = 51;
/// Split a `SchedControl` cap into two children covering disjoint priority bands.
pub const SYS_SCHED_SPLIT: u64 = 52;
/// Bind a death notification `EventQueue` to an address space (terminal fault).
pub const SYS_ASPACE_BIND_NOTIFICATION: u64 = 53;
/// Exit the whole process with a caller-chosen exit code.
pub const SYS_PROCESS_EXIT: u64 = 54;
/// Fill a user buffer with CSPRNG-quality bytes from the kernel entropy pool
/// (ambient; no capability). See `core/kernel/docs/syscalls.md` § `SYS_GETRANDOM` (55) and
/// `core/kernel/docs/entropy.md`.
pub const SYS_GETRANDOM: u64 = 55;

// ── getrandom constants ───────────────────────────────────────────────────────

/// Maximum bytes a single `SYS_GETRANDOM` call may request.
///
/// Bounds the interrupt-off window of the per-call kernel draw (the handler
/// draws under disabled interrupts); userspace loops for larger buffers. The
/// value mirrors the BSD `getentropy(2)` cap.
pub const MAX_GETRANDOM_LEN: usize = 256;

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
    /// Capability slot index is out of range, the slot is null, or the
    /// handle's generation is stale.
    InvalidCapability = -2,
    /// Caller does not hold sufficient rights for this operation.
    InsufficientRights = -3,
    /// A pointer argument does not satisfy alignment or range requirements.
    InvalidAddress = -4,
    /// An integer argument is out of the valid range for this call.
    InvalidArgument = -5,
    /// The operation would block but the caller requested non-blocking mode.
    WouldBlock = -6,
    /// Reserved; not returned by the current kernel.
    ObjectGone = -7,
    /// No memory available to satisfy the request.
    OutOfMemory = -8,
    /// The operation is not supported on this object type.
    NotSupported = -9,
    /// The capability rights bitmask violates the W^X constraint.
    WxViolation = -10,
    /// Reserved; not returned by the current kernel.
    MsgTooLarge = -11,
    /// Reserved; not returned by the current kernel.
    Deadlock = -12,
    /// Event queue is full; post would be lost.
    QueueFull = -13,
    // -14 retired (`DmaUnsafe`, removed with `SYS_DMA_GRANT`); never reuse.
    /// The target object is not in the required state for this operation
    /// (e.g. thread not `Stopped` for `read_regs`/`write_regs`, or a wait set
    /// another thread already waits on).
    InvalidState = -15,
    /// A blocking operation was cancelled: the thread was stopped, the object
    /// it was blocked on was destroyed, or, for a call, the server received
    /// again, or was destroyed, before replying. The thread sees this as the
    /// return value of its blocked syscall. `SYS_THREAD_START` also returns it
    /// when its caller is stopped while the start waits for the target to
    /// settle (nothing is started). Batched capability operations (revoke,
    /// delete, move, a range split) also return it at their liveness backstop;
    /// each syscall's entry in core/kernel/docs/syscalls.md gives the state the
    /// backstop leaves.
    Interrupted = -16,
    /// A structural per-object ceiling was reached (e.g. a `CSpace`'s
    /// directory is full, or the object a new capability or a retype would
    /// reference already holds 2^31 references). Unlike `OutOfMemory`,
    /// donating memory (augment mode) cannot satisfy the request.
    QuotaExceeded = -17,
}

// ── Scheduling constants ──────────────────────────────────────────────────────

/// Lowest priority a userspace thread may be assigned (0 is the idle band).
///
/// A `SchedControl` cap spanning `[PRIORITY_MIN, PRIORITY_MAX]` is the full
/// userspace priority authority; the kernel mints init's cap with this span.
pub const PRIORITY_MIN: u8 = 1;
/// Maximum priority available to userspace threads.
///
/// The span is an ABI width: the kernel's run-queue bitmask is a `u32`
/// (`NUM_PRIORITY_LEVELS` = 32), whose level 0 is the idle band and whose
/// level 31 is reserved above this one.
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
///
/// The value is an ABI width: the cap count and the handles follow it at fixed
/// word offsets, and all of them fit the one IPC buffer page. It bounds only
/// the inline payload of one message; bulk data travels as a Memory cap.
pub const MSG_DATA_WORDS_MAX: usize = 64;

/// Maximum number of capability slots transferable in a single IPC message.
///
/// Four is an encoding artefact: the handles travel two `u32`s per transfer
/// register (`pack_cap_handles`). It bounds caps per message, not per
/// transfer: every protocol that moves more caps iterates over rounds, as the
/// `shared/ipc` bootstrap rounds and procmgr's `DONATE_MEMORY_CAPS` rounds do.
pub const MSG_CAP_SLOTS_MAX: usize = 4;

// The two-word transfer layout (`pack_cap_handles` / `unpack_cap_handles`)
// holds exactly four 32-bit fields; raising MSG_CAP_SLOTS_MAX past 4 would
// silently alias fields. Trip at compile time instead.
const _: () = assert!(MSG_CAP_SLOTS_MAX <= 4);

/// Synthetic reply label written to the caller's IPC message by the kernel
/// when `SYS_IPC_REPLY` cannot deliver the server's reply intact: rejected
/// before delivery (caller's `CSpace` cannot accept reply caps, server
/// cap-slot lookup failed, malformed IPC buffer), or the reply-cap transfer
/// refused after the caller was claimed (a reply cap slot went stale, was
/// repeated, or is pinned by an in-flight `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`,
/// or IPC capability transfer) — in the latter case this label replaces the
/// already-staged reply. The caller un-parks with this label so it can
/// surface a graceful failure instead of dead-locking. Reserved by the
/// kernel; servers must not produce this label themselves.
pub const IPC_REPLY_TRANSFER_FAILED: u64 = u64::MAX;

// ── Mapping protection bits ──────────────────────────────────────────────────

/// Mapping protection: writable. Bit 1, matching the Memory rights layout
/// (`RIGHTS_MEM_WRITE`).
pub const MAP_WRITABLE: u64 = 0x2;

/// Mapping protection: executable. Bit 2, matching the Memory rights layout
/// (`RIGHTS_MEM_EXECUTE`).
pub const MAP_EXECUTABLE: u64 = 0x4;

/// `SYS_MEM_MAP` protection value `0`: derive the mapping's permissions from
/// the Memory cap's rights (`core/kernel/docs/syscalls.md` § `SYS_MEM_MAP` (16)).
///
/// A cap with WRITE maps read-write and one with EXECUTE maps executable, and
/// a cap carrying both fails with `WxViolation`; a cap narrowed to Map alone
/// maps read-only. To request read-only whatever the cap's rights, pass
/// [`MAP_READ`].
pub const MAP_FROM_CAP: u64 = 0;

/// Mapping protection: explicit read-only. Bit 0.
///
/// Unlike [`MAP_FROM_CAP`] (= 0, which derives permissions from the Memory
/// cap's rights), this nonzero value forces a read-only `SYS_MEM_MAP`
/// mapping regardless of the cap's WRITE/EXECUTE rights, so a full-rights cap
/// can be mapped read-only without first deriving a narrowed child cap. W^X
/// holds trivially (neither WRITE nor EXECUTE set). `SYS_MEM_PROTECT` reads
/// only the WRITE and EXECUTE bits, so this value reprotects read-only there
/// too.
pub const MAP_READ: u64 = 0x1;

// ── Unmap flags ──────────────────────────────────────────────────────────────

/// `SYS_MEM_UNMAP` flags (arg3): reclaim intermediate page tables.
///
/// After clearing the leaf PTEs across the requested span, reclaim each
/// intermediate page table that the cleared span leaves empty back to the
/// address space's page-table growth pool, crediting `pt_growth_budget_bytes`
/// (observable via `cap_info(CAP_INFO_ASPACE_PT_BUDGET)`). A single coarse
/// TLB and paging-structure-cache shootdown closes the teardown, plus one span
/// invalidation each time the cleared frames overflow the kernel's frame-map
/// release batch. memmgr sets this at `UNREGISTER_REGION` to release a demand
/// region's page tables mid-life rather than holding them until address-space
/// death.
///
/// Without this bit `SYS_MEM_UNMAP` clears only leaf PTEs and issues a per-page
/// shootdown; intermediate tables persist until the address space is destroyed.
pub const MEM_UNMAP_RECLAIM_PTS: u64 = 0x1;

// ── Capability rights masks ─────────────────────────────────────────────────
//
// `u64` masks for `cap_derive` / `cap_copy` / `cap_insert` rights parameters
// and the rights half of `CAP_INFO_TAG_RIGHTS`. Rights are scoped per
// capability type: the kernel stores one 32-bit rights word per slot and
// interprets it through the slot's type tag, so every type numbers its bits
// from 0 in its own full-width space. These constants are the single source
// of truth; the kernel's typed rights constants are derived from them.
//
// A mask is only meaningful for the capability type it is named for. Applying
// another type's mask to a derive/copy attenuates whatever bits of the target
// type happen to share those positions — always pick the constant named for
// the cap being attenuated.
//
// Assigned bit values are ABI: they cross the user boundary via the
// CAP_INFO_TAG_RIGHTS rights half and the derive/copy masks. Existing bits
// MUST NOT be renumbered; a new right takes a fresh bit in its own type's
// space.

/// All rights — pass through whatever the source cap has. Equivalent to
/// `!0u64`; valid for every capability type.
pub const RIGHTS_ALL: u64 = !0u64;

// Memory ──

/// Memory: may map this memory into an address space.
pub const RIGHTS_MEM_MAP: u64 = 1 << 0;

/// Memory: authority to create writable mappings from this memory.
pub const RIGHTS_MEM_WRITE: u64 = 1 << 1;

/// Memory: authority to create executable mappings from this memory.
pub const RIGHTS_MEM_EXECUTE: u64 = 1 << 2;

/// Memory: authority to retype this region into kernel objects.
///
/// Held by RAM, boot-module, and init-segment Memory caps (the latter two
/// donate into memmgr's pool as general RAM at init's reap); never held by
/// firmware-table Memory caps (ACPI/RSDP/DTB). Required by every retype-
/// consuming syscall.
pub const RIGHTS_MEM_RETYPE: u64 = 1 << 3;

/// Memory: map read-write.
pub const RIGHTS_MEM_MAP_RW: u64 = RIGHTS_MEM_MAP | RIGHTS_MEM_WRITE;

/// Memory: map read-execute.
pub const RIGHTS_MEM_MAP_RX: u64 = RIGHTS_MEM_MAP | RIGHTS_MEM_EXECUTE;

// AddressSpace ──

/// `AddressSpace`: may map into this address space.
pub const RIGHTS_AS_MAP: u64 = 1 << 0;

/// `AddressSpace`: may read/inspect mappings (`SYS_ASPACE_QUERY`).
pub const RIGHTS_AS_READ: u64 = 1 << 1;

/// `AddressSpace`: control authority — permits registering terminal-fault
/// death observers (`aspace_bind_notification`). Held by the object's
/// creator; mask it out of derived copies handed to components that only
/// need to map within the space.
pub const RIGHTS_AS_CONTROL: u64 = 1 << 2;

// Endpoint ──

/// Endpoint: send-only — may call but not receive or grant caps.
pub const RIGHTS_EP_SEND: u64 = 1 << 0;

/// Endpoint: receive-only — may accept calls but not call out or grant caps.
pub const RIGHTS_EP_RECEIVE: u64 = 1 << 1;

/// Endpoint: may include capabilities in IPC messages.
pub const RIGHTS_EP_GRANT: u64 = 1 << 2;

/// Endpoint: send + grant — may call and include capabilities in messages.
pub const RIGHTS_EP_SEND_GRANT: u64 = RIGHTS_EP_SEND | RIGHTS_EP_GRANT;

// Notification ──

/// Notification: may signal the notification object.
pub const RIGHTS_NTF_NOTIFY: u64 = 1 << 0;

/// Notification: may wait on the notification object.
pub const RIGHTS_NTF_WAIT: u64 = 1 << 1;

// EventQueue ──

/// `EventQueue`: post-only. Permits `event_post` and binding as a
/// notification observer (`thread_bind_notification` /
/// `aspace_bind_notification`), but not draining (`RECV`). Derive a copy
/// narrowed to this right to hand a queue to another component as a
/// write-only sink while retaining `RECV` on the original.
pub const RIGHTS_EQ_POST: u64 = 1 << 0;

/// `EventQueue`: may receive (drain) entries from the queue.
pub const RIGHTS_EQ_RECV: u64 = 1 << 1;

// Interrupt ──

/// Interrupt: may register/acknowledge the line and receive its
/// notifications.
pub const RIGHTS_IRQ_NOTIFY: u64 = 1 << 0;

// Mmio ──

/// Mmio: may map the MMIO region into an address space.
pub const RIGHTS_MMIO_MAP: u64 = 1 << 0;

/// Mmio: may map the MMIO region writable.
pub const RIGHTS_MMIO_WRITE: u64 = 1 << 1;

// Thread ──

/// Thread: may start, stop, and configure the thread.
pub const RIGHTS_THREAD_CONTROL: u64 = 1 << 0;

/// Thread: may read thread register state.
pub const RIGHTS_THREAD_OBSERVE: u64 = 1 << 1;

/// Thread: full control (start, stop, configure, observe).
pub const RIGHTS_THREAD: u64 = RIGHTS_THREAD_CONTROL | RIGHTS_THREAD_OBSERVE;

// CSpace ──

/// `CSpace`: may insert a capability into a slot.
pub const RIGHTS_CS_INSERT: u64 = 1 << 0;

/// `CSpace`: may clear a slot.
pub const RIGHTS_CS_DELETE: u64 = 1 << 1;

/// `CSpace`: may derive a new capability from an existing slot.
pub const RIGHTS_CS_DERIVE: u64 = 1 << 2;

/// `CSpace`: may revoke a capability and all its descendants.
pub const RIGHTS_CS_REVOKE: u64 = 1 << 3;

/// `CSpace`: full management (insert, delete, derive, revoke).
pub const RIGHTS_CS_ALL: u64 =
    RIGHTS_CS_INSERT | RIGHTS_CS_DELETE | RIGHTS_CS_DERIVE | RIGHTS_CS_REVOKE;

// WaitSet ──

/// Wait set: may add or remove members.
pub const RIGHTS_WS_MODIFY: u64 = 1 << 0;

/// Wait set: may poll/wait on the set.
pub const RIGHTS_WS_WAIT: u64 = 1 << 1;

// IoPort ──

/// `IoPort`: may bind the port range to a thread for in/out access.
pub const RIGHTS_IOPORT_USE: u64 = 1 << 0;

// SbiControl (SchedControl carries no rights bits: presence + band is the
// authority) ──

/// `SbiControl`: may forward the SBI System Reset (SRST) extension (RISC-V only).
pub const RIGHTS_SBI_RESET: u64 = 1 << 0;

/// `SbiControl`: may forward the SBI System Suspend (SUSP) extension (RISC-V only).
pub const RIGHTS_SBI_SUSPEND: u64 = 1 << 1;

/// `SbiControl`: may forward the SBI CPPC perf-control extension (RISC-V only).
pub const RIGHTS_SBI_CPPC: u64 = 1 << 2;

/// `SbiControl`: may forward the read-only SBI Base extension (RISC-V only).
pub const RIGHTS_SBI_BASE: u64 = 1 << 3;

/// `SbiControl`: may forward the SBI Debug Console (DBCN) extension (RISC-V only).
pub const RIGHTS_SBI_DBCN: u64 = 1 << 4;

/// `SbiControl`: may forward the SBI Performance Monitoring Unit (PMU) extension
/// (RISC-V only).
pub const RIGHTS_SBI_PMU: u64 = 1 << 5;

// ABI promise: the MAP_WRITABLE / MAP_EXECUTABLE rustdoc above states that
// prot bits coincide with the Memory rights bit positions. Nothing decodes
// positionally any more, but the stated identity is public ABI surface;
// pinned so neither table can drift from the promise silently.
const _: () = assert!(MAP_WRITABLE == RIGHTS_MEM_WRITE);
const _: () = assert!(MAP_EXECUTABLE == RIGHTS_MEM_EXECUTE);

// ── Exit reason constants ─────────────────────────────────────────────────────
//
// The exit reason is the value a death notification delivers (low 32 bits) when
// a thread or process dies. It is a single flat space partitioned into disjoint
// ranges, kernel-owned so userspace can never forge a fault or kill reason:
//
//   | Reason            | Class               | Meaning                            |
//   |-------------------|---------------------|------------------------------------|
//   | `0`               | Voluntary, clean    | success (`SYS_THREAD_EXIT`, or     |
//   |                   |                     | `SYS_PROCESS_EXIT(0)`)             |
//   | `1 ..= 0x0FFF`    | Voluntary, code     | `SYS_PROCESS_EXIT(code)`, where    |
//   |                   |                     | reason == `encode_exit_code(code)` |
//   | `0x1000 ..0x2000` | Fault               | `EXIT_FAULT_BASE + vector/cause`   |
//   | `0x2000`          | Killed              | `EXIT_KILLED`: recorded by         |
//   |                   |                     | object teardown (not posted by     |
//   |                   |                     | it); posted by a userspace kill    |
//
// This is a Seraph-native encoding, not POSIX: exit codes are not 8-bit
// `WEXITSTATUS`-truncated, and faults are native fault classes, not signals.

/// Clean voluntary exit (success): `SYS_THREAD_EXIT`, or `SYS_PROCESS_EXIT(0)`.
pub const EXIT_VOLUNTARY: u64 = 0;

/// Base value for fault-induced exits. The kernel adds the architecture-specific
/// fault vector/cause to this base: `EXIT_FAULT_BASE + vector` (x86-64) or
/// `EXIT_FAULT_BASE + cause` (RISC-V). Voluntary exit codes occupy the disjoint
/// range `[1, EXIT_FAULT_BASE)` below it, so a fault and an exit code can never
/// alias.
pub const EXIT_FAULT_BASE: u64 = 0x1000;

/// Exit reason of a thread killed rather than exited or faulted. The kernel
/// records it as the retained reason of every thread it stops when the last
/// capability to the thread's `CSpace` or `AddressSpace` goes (readable via
/// `CAP_INFO_THREAD_STATE`). That stop posts no death event: an observer
/// bound before it hears nothing from the kernel, while one bound afterwards
/// receives the retained reason through the bind. A thread stopped while
/// already inside its own exit or fault path still posts that path's reason;
/// `EXIT_KILLED` is then at most the retained value. Userspace posts the same
/// value (e.g. `std::process::Child::kill`) so a waiter observes a defined
/// status. Sits just above the fault range so consumers tell a kill from a
/// hardware fault.
pub const EXIT_KILLED: u64 = 0x2000;

/// Encode a voluntary process exit `code` into the flat exit-reason space.
///
/// - `0` → [`EXIT_VOLUNTARY`] (success).
/// - `1 ..= 0x0FFF` → the code verbatim (the gap below [`EXIT_FAULT_BASE`]).
/// - `>= 0x1000` → saturates to `EXIT_FAULT_BASE - 1` (`0x0FFF`).
///
/// Saturating (never masking) guarantees a non-zero code can never alias to
/// `0`/success — unlike POSIX 8-bit truncation, where `exit(256)` becomes `0`.
/// The 12-bit ceiling is deliberate: it slots codes below the established fault
/// range, and test-harness verdicts are binary while shell codes are `0..=255`, both
/// well inside the range.
#[must_use]
pub const fn encode_exit_code(code: u32) -> u64
{
    if code == 0
    {
        EXIT_VOLUNTARY
    }
    else if (code as u64) < EXIT_FAULT_BASE
    {
        code as u64
    }
    else
    {
        EXIT_FAULT_BASE - 1
    }
}

// ── Fault-handler protocol ─────────────────────────────────────────────────────
//
// Stable cross-boundary contract for the kernel → userspace fault redirection
// delivered to a thread's bound fault-handler endpoint (see
// `SYS_THREAD_SET_FAULT_HANDLER` and `docs/fault-handling.md`). The message the
// kernel synthesizes on the faulting thread's behalf carries `FAULT_LABEL`, the
// badge of the bound endpoint cap, and four data words: `[kind, d1, d2, ip]`.

/// Reserved IPC label marking a kernel-originated fault message. Distinct so a
/// handler can recognise a fault message. The label proves kernel origin only
/// on an endpoint whose handler hands out no SEND. The badge of a fault message
/// is the derivation badge of the Endpoint cap bound by
/// `SYS_THREAD_SET_FAULT_HANDLER`, so it is as derivation-locked as the badge
/// of an ordinary send through that cap; a binder cannot choose it (see
/// `docs/fault-handling.md` § Security). Reserved by the kernel; servers must
/// not produce this label themselves. Chosen adjacent to [`IPC_REPLY_TRANSFER_FAILED`] (`u64::MAX`)
/// in the reserved high range.
pub const FAULT_LABEL: u64 = u64::MAX - 1;

/// Fault kind (data word 0): a virtual-memory (page) fault. Data words 1–3 are
/// `[faulting_va, access_flags, faulting_ip]`, where `access_flags` is a mask of
/// the `FAULT_ACCESS_*` bits.
pub const FAULT_KIND_VM: u64 = 0;

/// Fault kind (data word 0): a CPU exception with no kernel resolution (illegal
/// instruction, alignment, breakpoint, …). Data words 1–3 are
/// `[normalized_code, arch_aux_code, faulting_ip]`:
/// - `normalized_code` is an architecture-neutral [`FAULT_EXC_UNKNOWN`]-family
///   class so a handler can dispatch without architecture knowledge.
/// - `arch_aux_code` is the architecture's auxiliary datum for the trap:
///   x86-64 the hardware error code (`0` when the vector has none); RISC-V
///   `stval` (the faulting address for misaligned/access faults, the faulting
///   instruction bits for an illegal instruction).
pub const FAULT_KIND_EXCEPTION: u64 = 1;

/// `FAULT_KIND_VM` access flag: the access was a read.
pub const FAULT_ACCESS_READ: u64 = 1 << 0;
/// `FAULT_KIND_VM` access flag: the access was a write.
pub const FAULT_ACCESS_WRITE: u64 = 1 << 1;
/// `FAULT_KIND_VM` access flag: the access was an instruction fetch.
pub const FAULT_ACCESS_EXEC: u64 = 1 << 2;
/// `FAULT_KIND_VM` access flag: the page was present (protection violation)
/// rather than not-present. Set only on x86-64, and only for a user-half
/// faulting address (a kernel-half one reports it clear); on RISC-V it is always clear
/// because `scause` does not encode presence, so a handler there must not read
/// a clear bit as not-present (it inspects its own mappings instead).
pub const FAULT_ACCESS_PRESENT: u64 = 1 << 3;

// ── Normalized exception codes (FAULT_KIND_EXCEPTION data word 1) ───────────────
//
// Architecture-neutral classification of a CPU exception, so a handler dispatches
// on the class without architecture knowledge. The raw architectural code/value
// is carried separately in `arch_aux_code` (data word 2). Values not listed are
// reserved; a handler MUST treat an unrecognized code as [`FAULT_EXC_UNKNOWN`].

/// Normalized exception: unclassified — the architecture raised a U-mode
/// exception that maps to no class below. Consult `arch_aux_code` for detail.
pub const FAULT_EXC_UNKNOWN: u64 = 0;
/// Normalized exception: illegal / undefined instruction (x86-64 `#UD`; RISC-V
/// illegal instruction).
pub const FAULT_EXC_ILLEGAL_INSTRUCTION: u64 = 1;
/// Normalized exception: software breakpoint (x86-64 `#BP`; RISC-V `ebreak`).
pub const FAULT_EXC_BREAKPOINT: u64 = 2;
/// Normalized exception: debug trap — single-step or hardware breakpoint
/// (x86-64 `#DB`). No RISC-V mapping (debug is an external-debugger facility).
pub const FAULT_EXC_DEBUG: u64 = 3;
/// Normalized exception: integer divide error (x86-64 `#DE`). RISC-V has no
/// hardware divide trap.
pub const FAULT_EXC_DIVIDE: u64 = 4;
/// Normalized exception: arithmetic overflow trap (x86-64 `#OF` / `INTO`).
pub const FAULT_EXC_OVERFLOW: u64 = 5;
/// Normalized exception: bound-range exceeded (x86-64 `#BR`).
pub const FAULT_EXC_BOUND_RANGE: u64 = 6;
/// Normalized exception: misaligned access (x86-64 `#AC`; RISC-V instruction /
/// load / store address-misaligned).
pub const FAULT_EXC_ALIGNMENT: u64 = 7;
/// Normalized exception: physical access fault — the access reached memory the
/// hardware forbids (RISC-V instruction / load / store access fault).
pub const FAULT_EXC_ACCESS: u64 = 8;
/// Normalized exception: protection / segmentation violation (x86-64 `#GP`,
/// `#SS`, `#NP`, `#TS`).
pub const FAULT_EXC_PROTECTION: u64 = 9;
/// Normalized exception: floating-point / SIMD error (x86-64 `#MF` / `#XM`).
pub const FAULT_EXC_FP: u64 = 10;

/// Fault reply label: resume the faulting thread (re-execute the faulting
/// instruction, or continue from a handler-modified instruction pointer). The
/// default disposition; the kernel ignores reply data words and caps.
pub const FAULT_REPLY_RESUME: u64 = 0;

/// Fault reply label: the handler declines; the kernel kills the faulting
/// thread as an unhandled fault.
pub const FAULT_REPLY_KILL: u64 = 1;

/// `fault_class_mask` value covering all fault classes — the only value v1 of
/// `SYS_THREAD_SET_FAULT_HANDLER` accepts. Reserves the encoding for future
/// per-class handlers.
pub const FAULT_CLASS_ALL: u64 = !0u64;

// ── Register file (SYS_THREAD_READ_REGS / SYS_THREAD_WRITE_REGS) ──────────────
//
// The buffer `SYS_THREAD_READ_REGS` fills and `SYS_THREAD_WRITE_REGS` reads is
// the architecture's user register file: an array of `u64` fields in native
// byte order. Its size and the offsets userspace edits are fixed here per
// architecture (both are named on every target, so a consumer selects by its
// own target); the kernel asserts its `TrapFrame` against them at compile time.

/// x86-64 register-file size in bytes.
pub const REGS_X86_64_SIZE: usize = 168;
/// Byte offset of the instruction pointer (`rip`) in the x86-64 register file.
pub const REGS_X86_64_IP_OFFSET: usize = 120;
/// Byte offset of the stack pointer (`rsp`) in the x86-64 register file.
pub const REGS_X86_64_SP_OFFSET: usize = 136;

/// riscv64 register-file size in bytes.
pub const REGS_RISCV64_SIZE: usize = 280;
/// Byte offset of the instruction pointer (`sepc`) in the riscv64 register file.
pub const REGS_RISCV64_IP_OFFSET: usize = 248;
/// Byte offset of the stack pointer (`sp`, `x2`) in the riscv64 register file.
pub const REGS_RISCV64_SP_OFFSET: usize = 8;

// ── System info ───────────────────────────────────────────────────────────────

/// Pack a dotted `X.Y.Z` version string into the [`KERNEL_VERSION`] layout.
///
/// Reads the three leading numeric components, stopping at the first byte that
/// is neither a digit nor a `.`, so any semver pre-release/build suffix is
/// ignored. `const` so the value is fixed at compile time.
const fn pack_project_version(s: &str) -> u64
{
    let b = s.as_bytes();
    let mut parts = [0u64; 3]; // major, minor, patch
    let mut i = 0;
    let mut part = 0;
    while i < b.len() && part < 3
    {
        match b[i]
        {
            d @ b'0'..=b'9' => parts[part] = parts[part] * 10 + (d - b'0') as u64,
            b'.' => part += 1,
            _ => break,
        }
        i += 1;
    }
    (parts[0] << 32) | (parts[1] << 16) | parts[2]
}

/// Kernel version packed as a single `u64`.
///
/// Layout: `(major as u64) << 32 | (minor as u64) << 16 | (patch as u64)`.
/// Userspace extracts components with:
/// ```text
/// major = version >> 32
/// minor = (version >> 16) & 0xFFFF
/// patch = version & 0xFFFF
/// ```
///
/// The value is the Seraph project version, parsed from `CARGO_PKG_VERSION`
/// (the workspace `version`) at compile time: kernel version and project
/// version are one number, governed by the project-version semantics in
/// `docs/conventions.md`. Syscall-ABI compatibility is not expressed here; it
/// is tracked per protocol by the dedicated `*_VERSION` constants in the
/// `abi/` crates. The 32/16/16 field widths are an encoding artefact of
/// fitting one return register and bound no capacity: version components stay
/// far below 2^16.
pub const KERNEL_VERSION: u64 = pack_project_version(env!("CARGO_PKG_VERSION"));

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
    // Discriminants 2 and 3 are reserved and MUST NOT be reused; these values
    // are a stable wire contract.
    /// Size of a physical page in bytes (always 4096 on supported platforms).
    PageSize = 4,
    /// Boot protocol version used by the bootloader.
    /// Userspace can use this to interpret fields in the boot info struct.
    BootProtocolVersion = 5,
    /// Microseconds elapsed since kernel timer initialisation.
    /// Returns 0 if the timer has not been initialised yet.
    ElapsedUs = 6,
    /// Index of the CPU on which the calling thread is currently executing.
    /// Useful for diagnostics and for verifying affinity / migration
    /// behaviour from userspace.
    CurrentCpu = 7,
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn cap_handle_pack_round_trips_all_four_fields()
    {
        // Populated handles with distinct generations, including indices in
        // both the low and high packed words — the lo/hi boundary is where
        // the two ends of the wire could disagree.
        let handles = [
            cap_handle_encode(1, 0),
            cap_handle_encode(0xFFFF, 3),
            cap_handle_encode(70_000, 255),
            cap_handle_encode(CAP_INDEX_MASK, 7),
        ];
        let (lo, hi) = pack_cap_handles(&handles);
        assert_eq!(unpack_cap_handles(lo, hi, 4), handles);

        // Partial counts leave the untransmitted tail zeroed.
        let (lo, hi) = pack_cap_handles(&handles[..2]);
        assert_eq!(hi, 0);
        let out = unpack_cap_handles(lo, hi, 2);
        assert_eq!(&out[..2], &handles[..2]);
        assert_eq!(&out[2..], &[0, 0]);
    }

    // Defects guarded: a per-bit rights constant that overlaps another bit of
    // the same capability type (attenuating one right would silently attenuate
    // the other), and a bit at position >= 32 (silently truncated by the
    // kernel's u64 -> u32 rights decode).
    #[test]
    fn per_type_rights_bits_are_single_disjoint_and_fit_u32()
    {
        let spaces: &[&[u64]] = &[
            // Memory
            &[
                RIGHTS_MEM_MAP,
                RIGHTS_MEM_WRITE,
                RIGHTS_MEM_EXECUTE,
                RIGHTS_MEM_RETYPE,
            ],
            // AddressSpace
            &[RIGHTS_AS_MAP, RIGHTS_AS_READ, RIGHTS_AS_CONTROL],
            // Endpoint
            &[RIGHTS_EP_SEND, RIGHTS_EP_RECEIVE, RIGHTS_EP_GRANT],
            // Notification
            &[RIGHTS_NTF_NOTIFY, RIGHTS_NTF_WAIT],
            // EventQueue
            &[RIGHTS_EQ_POST, RIGHTS_EQ_RECV],
            // Interrupt
            &[RIGHTS_IRQ_NOTIFY],
            // Mmio
            &[RIGHTS_MMIO_MAP, RIGHTS_MMIO_WRITE],
            // Thread
            &[RIGHTS_THREAD_CONTROL, RIGHTS_THREAD_OBSERVE],
            // CSpace
            &[
                RIGHTS_CS_INSERT,
                RIGHTS_CS_DELETE,
                RIGHTS_CS_DERIVE,
                RIGHTS_CS_REVOKE,
            ],
            // WaitSet
            &[RIGHTS_WS_MODIFY, RIGHTS_WS_WAIT],
            // IoPort
            &[RIGHTS_IOPORT_USE],
            // SbiControl
            &[
                RIGHTS_SBI_RESET,
                RIGHTS_SBI_SUSPEND,
                RIGHTS_SBI_CPPC,
                RIGHTS_SBI_BASE,
                RIGHTS_SBI_DBCN,
                RIGHTS_SBI_PMU,
            ],
        ];

        for bits in spaces
        {
            let mut seen: u64 = 0;
            for &bit in *bits
            {
                assert!(
                    bit.is_power_of_two(),
                    "rights bit {bit:#x} is not a single bit"
                );
                assert!(
                    bit < (1u64 << 32),
                    "rights bit {bit:#x} exceeds the 32-bit slot word"
                );
                assert_eq!(
                    seen & bit,
                    0,
                    "rights bit {bit:#x} overlaps another of its type"
                );
                seen |= bit;
            }
        }
    }
}
