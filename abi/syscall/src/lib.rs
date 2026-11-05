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
/// A handle is a `u64`: the slot index in bits `0..CAP_INDEX_BITS` and the
/// per-slot generation (see [`cap_handle_gen`]) in the bits above it. The
/// index field is wider than any `CSpace` the kernel can build; the kernel
/// static-asserts that its structural slot ceiling fits it, so the ceiling is
/// set by the kernel's directory, not by the handle.
pub const CAP_INDEX_BITS: u32 = 32;

/// Mask selecting the slot-index bits of a capability handle.
pub const CAP_INDEX_MASK: u64 = (1u64 << CAP_INDEX_BITS) - 1;

/// Number of significant generation bits in a capability handle.
///
/// The generation occupies bits `CAP_INDEX_BITS..CAP_INDEX_BITS +
/// CAP_GEN_BITS`, and the kernel wraps a slot's generation at
/// `1 << CAP_GEN_BITS`. Bit 63 of a handle is therefore always clear: a
/// handle is returned in the primary syscall return register, which the
/// wrappers read as `i64` and treat as an error when negative.
pub const CAP_GEN_BITS: u32 = 31;

/// Mask selecting the significant bits of a per-slot generation (the value the
/// kernel wraps a slot's generation into).
pub const CAP_GEN_MASK: u32 = (1u32 << CAP_GEN_BITS) - 1;

// The index and the generation fill the handle up to, not including, the sign
// bit of the primary return register.
const _: () = assert!(CAP_INDEX_BITS + CAP_GEN_BITS == 63);

/// Build a capability handle from a slot `index` and per-slot `generation`.
///
/// The handle userspace receives and passes back is
/// `(generation << CAP_INDEX_BITS) | index`, with `generation` taken modulo
/// `1 << CAP_GEN_BITS`. A `generation` of `0` makes the handle numerically
/// equal to the bare index, so a cap minted once and never recycled has the
/// handle value of its index, and handle `0` names the permanently null slot.
#[inline]
#[must_use]
pub const fn cap_handle_encode(index: u32, generation: u32) -> u64
{
    // `u64::from` is not const-stable; both `u32 -> u64` widening casts are exact.
    #[allow(clippy::cast_lossless)]
    let handle = (((generation & CAP_GEN_MASK) as u64) << CAP_INDEX_BITS) | index as u64;
    handle
}

/// Extract the slot index from a capability handle.
#[inline]
#[must_use]
pub const fn cap_handle_index(handle: u64) -> u32
{
    // `& CAP_INDEX_MASK` leaves at most 32 significant bits, so the cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let index = (handle & CAP_INDEX_MASK) as u32;
    index
}

/// Extract the per-slot generation from a capability handle.
///
/// Returns every bit above the index field, so a handle with bit 63 set (one
/// no kernel-issued handle has) yields a value above [`CAP_GEN_MASK`], which
/// matches no slot's generation.
#[inline]
#[must_use]
pub const fn cap_handle_gen(handle: u64) -> u32
{
    // `>> CAP_INDEX_BITS` leaves at most 32 significant bits, so the cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let generation = (handle >> CAP_INDEX_BITS) as u32;
    generation
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

/// Largest member capacity of a `WaitSet` (`SYS_CAP_CREATE_WAIT_SET` arg1 is
/// in `1..=WAIT_SET_MAX_MEMBERS`).
///
/// The set is caller-funded ([`wait_set_retype_bytes`]), so the ceiling
/// protects no shared pool. It bounds the level-readiness walk a wait makes
/// over every member with interrupts off; a server with more sources splits
/// them across sets and waiting threads, so the bound only splits work.
pub const WAIT_SET_MAX_MEMBERS: u32 = 1024;

/// Raw retype debit of one `WaitSet` of `capacity` members, in bytes: the
/// 24-byte wrapper, the 40-byte wait-set state, one 24-byte member slot per
/// member, and the ready ring of `capacity + 1` two-byte member indices
/// rounded up to eight bytes, all inline in the retype slot. `capacity` is
/// one the kernel accepts, `1..=WAIT_SET_MAX_MEMBERS`.
#[must_use]
pub const fn wait_set_retype_bytes(capacity: u64) -> u64
{
    24 + 40 + capacity * 24 + ((capacity + 1) * 2).div_ceil(8) * 8
}

/// Raw retype debit of one `EventQueue` of user-visible `capacity` entries and
/// `observers` death-observer nodes, in bytes: the 24-byte wrapper, the 64-byte
/// queue state, `capacity + 1` sixteen-byte ring slots (one two-word entry
/// each), and one 24-byte node per observer, all inline in the retype slot.
/// Both counts are ones the kernel accepts (`capacity` in
/// `1..=EVENT_QUEUE_MAX_CAPACITY`, `observers` in
/// `0..=EVENT_QUEUE_MAX_CAPACITY`); larger values can overflow.
#[must_use]
pub const fn event_queue_retype_bytes(capacity: u64, observers: u64) -> u64
{
    24 + 64 + (capacity + 1) * 16 + observers * 24
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
/// `cap_create_cspace` donations. Pages the `CSpace`'s body arena or a thread's
/// port-binding table takes spend the same budget ([`CAP_INFO_CSPACE_BUDGET`]),
/// so the capacity falls by a page's slots for each. A mild over-estimate: the first page's
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

/// `CSpace` only — bytes available to back new slot pages, the pages of the
/// `CSpace`'s body arena (the objects a split, an `Mmio`, `IoPort`, or
/// `Interrupt` copy, or a spilled `Mmio` mapping record funded by this `CSpace`
/// needs; see
/// [`cspace_topup_pages`]), and the three pages of the port-binding table of a
/// thread bound to it, taken at the thread's first `ioport_bind`.
///
/// Returns the current value of `CSpaceKernelObject::cspace_growth_budget_bytes`.
/// Calling on a non-`CSpace` slot returns [`SyscallError::InvalidArgument`].
pub const CAP_INFO_CSPACE_BUDGET: u64 = 7;

/// `Memory` only — physical base address of the memory region.
///
/// Returns `MemoryObject::base` to a holder of [`RIGHTS_MEM_PHYS`]: the
/// queried cap carries it, or the third argument names a Memory cap in the
/// caller's `CSpace` that does (the credential; `0` names none). Calling on
/// a non-Memory slot returns [`SyscallError::InvalidArgument`]; a queried cap
/// without the right and no credential returns
/// [`SyscallError::InsufficientRights`], as does a credential without it; a
/// credential that is not a live Memory cap returns
/// [`SyscallError::InvalidCapability`]. init reads it for its arena, memmgr
/// to track contiguity, devmgr and the IOMMU driver to program devices with
/// physical addresses.
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
/// can reach the region. The query covers a window of the region: argument 2
/// is its first page and argument 3 its page count, `1..=`
/// [`CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES`]. A window that is empty, too long,
/// or runs past the region, or a non-Memory slot, returns
/// [`SyscallError::InvalidArgument`]; a larger region is read window by
/// window. Used by a server that hands a page to a client and must know the
/// client's mapping is gone before reusing the page.
pub const CAP_INFO_MEMORY_MAPPINGS: u64 = 12;

/// Longest window, in pages, one [`CAP_INFO_MEMORY_MAPPINGS`] query reads:
/// the query reads one count per page, so the bound keeps the syscall short.
/// A batch size: a larger region is read in more queries.
pub const CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES: u64 = 512;

/// Universal field — `1` if the queried slot is the only reference to the
/// object it names, otherwise `0`.
///
/// "Only reference" counts every capability slot naming the object, in every
/// `CSpace`, and every kernel-internal reference to it (a retype lease of an
/// object retyped from a Memory object, a page-pool donation, a wait-set
/// membership, a fault-handler or death-observer binding, a syscall in flight
/// on it). The inquiry's own pin on the object is not counted. Derivations of
/// a Memory capability name one object, so a Memory cap with a live
/// derivation, a live retyped object, or a donation is never sole; a split
/// child or a range-capability copy is an object of its own.
///
/// Once `1`, the answer stays `1` until the caller itself takes a further
/// reference through the slot (a derivation, copy, retype, page-pool
/// donation, binding, wait-set add, or a syscall of its own in flight): no
/// other process holds a capability through which to add one. The count is
/// read with the slot re-checked under its `CSpace` lock, so a concurrent
/// delete or revoke of the queried slot answers `InvalidCapability`, never a
/// false `1`. A user mapping is not a reference; read it with
/// [`CAP_INFO_MEMORY_MAPPINGS`]. Used by memmgr before it returns a reclaimed
/// frame to its pool (services/memmgr/docs/memory-pool.md § Reclamation).
pub const CAP_INFO_SOLE_REFERENCE: u64 = 13;

/// `AddressSpace` only — the retained terminal-fault reason, or `0`.
///
/// Returns `0` while no thread of the address space has taken a terminal
/// fault, and otherwise the reason of the first one
/// ([`EXIT_FAULT_BASE`] + vector or cause; never `0`), which later faults do
/// not overwrite. It is the reason an `SYS_ASPACE_BIND_NOTIFICATION` observer
/// receives, so a holder that missed the event post reads it back here.
/// Calling on a non-`AddressSpace` slot returns
/// [`SyscallError::InvalidArgument`].
pub const CAP_INFO_ASPACE_TERMINAL_FAULT: u64 = 14;

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

/// One past the highest syscall number. Every number below it is assigned,
/// and the kernel bounds its dispatch table by it, so a syscall numbered at or
/// above it raises it.
pub const SYSCALL_NR_BOUND: u64 = SYS_GETRANDOM + 1;

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
    /// The operation is not supported: on this object type, on this
    /// architecture, or (for a diagnostic query) in this boot; or the firmware
    /// returned an error (`SYS_SBI_CALL`).
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

/// Maximum capacity (entry count), and maximum death-observer node count, for
/// an event queue created via `SYS_CAP_CREATE_EVENT_Q`: capacity in
/// `1..=EVENT_QUEUE_MAX_CAPACITY`, observers in `0..=EVENT_QUEUE_MAX_CAPACITY`.
///
/// The ring and the node pool are caller-funded per queue, so the ceiling
/// protects no shared pool. It bounds the work one create does in the kernel
/// before returning, which zeroes the ring and links every node: at 2^20 that
/// is at most 16 MiB of ring and 24 MiB of nodes. A supervisor that needs more
/// splits its observers across queues, so the bound only splits work.
pub const EVENT_QUEUE_MAX_CAPACITY: u32 = 1 << 20;

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
/// A protocol width, not a capacity: it fixes the cap block of the IPC buffer
/// page (the sender's handles at [`MSG_CAP_HANDLES_WORD`], the receiver's
/// result block at word `MSG_DATA_WORDS_MAX`) and the IPC receive reserve
/// ([`CSPACE_IPC_RECV_RESERVE`]). It bounds caps per message, not per
/// transfer: every protocol that moves more caps iterates over rounds, as the
/// `shared/ipc` bootstrap rounds and procmgr's `DONATE_MEMORY_CAPS` rounds do.
pub const MSG_CAP_SLOTS_MAX: usize = 4;

/// IPC buffer word at which a sender places the capability handles a
/// `SYS_IPC_CALL` or `SYS_IPC_REPLY` transfers: handle `i` (of the call's
/// `cap_count`) at word `MSG_CAP_HANDLES_WORD + i`, one full 64-bit handle per
/// word. The kernel reads them from the sending thread's IPC buffer page when
/// `cap_count` is non-zero. The receive side's result block shares the layout:
/// the delivered count at word `MSG_DATA_WORDS_MAX`, the delivered handles from
/// this word on.
pub const MSG_CAP_HANDLES_WORD: usize = MSG_DATA_WORDS_MAX + 1;

/// Free slots every `CSpace` keeps back from general allocations for IPC
/// capability transfer: one message's worth ([`MSG_CAP_SLOTS_MAX`]). A
/// general allocation (a `cap_create_*`, `cap_copy`, `cap_derive`, a
/// split, a `cap_move`) fails with `OutOfMemory` (or `QuotaExceeded` at the
/// structural ceiling) while only this many slots are free and the slot-page
/// pool cannot grow; the slots stay free for the caps a received message or
/// reply carries, so `SYS_IPC_RECV` still succeeds. Headroom a process
/// funds for its own general allocations is therefore
/// `CAP_INFO_CSPACE_CAPACITY - CAP_INFO_CSPACE_USED - CSPACE_IPC_RECV_RESERVE`.
pub const CSPACE_IPC_RECV_RESERVE: u64 = MSG_CAP_SLOTS_MAX as u64;

/// Capability slots one `CSpace` slot-page backs: each page an augment-mode
/// `cap_create_cspace` donates adds this many slots to
/// [`CAP_INFO_CSPACE_CAPACITY`] (less an occasional page spent on a
/// directory page past the direct region).
pub const CSPACE_SLOTS_PER_PAGE: u64 = 56;

/// Pages to donate to a `CSpace` (augment-mode `cap_create_cspace`) so that it
/// holds `slots` general slots of headroom and, beyond them, one page of growth
/// budget for its body arena; zero when it already does.
///
/// `headroom` is the `CSpace`'s general headroom
/// (`CAP_INFO_CSPACE_CAPACITY - CAP_INFO_CSPACE_USED - CSPACE_IPC_RECV_RESERVE`)
/// and `budget_bytes` its [`CAP_INFO_CSPACE_BUDGET`]. The body arena takes
/// whole pages from the same budget as slot pages, for the objects a split, an
/// `Mmio`, `IoPort`, or `Interrupt` copy, or a spilled `Mmio` mapping record
/// needs: headroom
/// of one page beyond `slots` keeps a page for it after `slots` allocations
/// drawn from the budget, and a budget of a page keeps one when the slots come
/// from pages already in use. A thread's first `ioport_bind` takes three more
/// pages from its `CSpace`'s budget, which this floor does not cover. The
/// result counts one more page for a donation record or a directory page the
/// donation may spend.
#[must_use]
pub const fn cspace_topup_pages(headroom: u64, budget_bytes: u64, slots: u64) -> u64
{
    let slot_short = (slots + CSPACE_SLOTS_PER_PAGE).saturating_sub(headroom);
    let budget_short = budget_bytes < PAGE_SIZE;
    if slot_short == 0 && !budget_short
    {
        return 0;
    }
    let pages = slot_short.div_ceil(CSPACE_SLOTS_PER_PAGE);
    let pages = if pages == 0 { 1 } else { pages };
    pages + 1
}

// The cap block (count word plus the handles) must stay inside the one IPC
// buffer page the kernel reads and writes.
const _: () = assert!(((MSG_CAP_HANDLES_WORD + MSG_CAP_SLOTS_MAX) * 8) as u64 <= PAGE_SIZE);

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

// ── Interrupt line modes ─────────────────────────────────────────────────────

/// `SYS_IRQ_REGISTER` mode (arg2): the line is level-triggered. Clear, it is
/// edge-triggered.
///
/// Every binding on a line passes the same mode: the line's first binding
/// records it, and a binding with another mode is refused with
/// `InvalidArgument` until the line's last binding goes. x86-64 programs the
/// line's I/O APIC redirection entry from it; riscv64 validates it and ignores
/// it (the PLIC gateway is level-sensitive). See
/// `core/kernel/docs/syscalls.md` § `SYS_IRQ_REGISTER`.
pub const IRQ_MODE_LEVEL: u64 = 1 << 0;

/// `SYS_IRQ_REGISTER` mode (arg2): the line asserts low. Clear, it asserts
/// high. See [`IRQ_MODE_LEVEL`].
pub const IRQ_MODE_ACTIVE_LOW: u64 = 1 << 1;

/// Every bit a `SYS_IRQ_REGISTER` mode may set; a mode with any other bit is
/// refused with `InvalidArgument`. Mode 0 is edge-triggered, active-high.
pub const IRQ_MODE_MASK: u64 = IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW;

// ── Capability rights masks ─────────────────────────────────────────────────
//
// `u64` masks for `cap_derive` / `cap_copy` / `cap_insert` rights parameters
// and the rights half of `CAP_INFO_TAG_RIGHTS`. Rights are scoped per
// capability type: the kernel stores one 16-bit rights word per slot and
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

/// Memory: authority to read this region's physical base
/// (`CAP_INFO_MEMORY_PHYS_BASE`).
///
/// Held by every boot-minted RAM, boot-module, init-segment, `InitInfo`,
/// init-stack, and reclaimed boot-scratch Memory cap, and so by memmgr's pool;
/// never by firmware-table Memory caps, whose physical bases `InitInfo`'s
/// descriptors already carry. memmgr strips it from every grant except to the
/// processes docs/capability-model.md § Memory names.
pub const RIGHTS_MEM_PHYS: u64 = 1 << 4;

/// Memory: map read-write.
pub const RIGHTS_MEM_MAP_RW: u64 = RIGHTS_MEM_MAP | RIGHTS_MEM_WRITE;

/// Memory: map read-execute.
pub const RIGHTS_MEM_MAP_RX: u64 = RIGHTS_MEM_MAP | RIGHTS_MEM_EXECUTE;

// AddressSpace ──

/// `AddressSpace`: may map into this address space.
pub const RIGHTS_AS_MAP: u64 = 1 << 0;

/// `AddressSpace`: may read/inspect mappings (`SYS_ASPACE_QUERY`, which
/// returns physical addresses). `SYS_CAP_CREATE_ASPACE` mints it only from a
/// source Memory cap carrying [`RIGHTS_MEM_PHYS`].
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
// The exit reason is the value a death notification delivers (the payload word
// of its two-word entry) when a thread or process dies. It is a single flat
// space partitioned into disjoint ranges, kernel-owned so userspace can never
// forge a fault or kill reason:
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
    /// Exclusive top of the user half of the caller's address space: the
    /// first virtual address a mapping syscall refuses. A fixed value per
    /// architecture and boot paging mode (`(1 << 47) - 4096` or
    /// `(1 << 56) - 4096` on x86-64 at 4- or 5-level paging, whose top user
    /// page is unmappable; `1 << 38`, `1 << 47`, or `1 << 56` under riscv64
    /// Sv39, Sv48, or Sv57), so a process sizes the zones it places itself to
    /// its address space.
    UserVaTop = 8,
    /// Deepest use, in bytes, of the kernel stack class named in arg1
    /// (`STACK_CLASS_IDLE`, `STACK_CLASS_THREAD`, or `STACK_CLASS_HANDOFF`),
    /// measured from the paint the stack was filled with at allocation. A
    /// diagnostic: the handoff class returns `NotSupported` when the kernel
    /// could not locate the stack, and an unknown class returns
    /// `InvalidArgument`. The classes and what each counts are in
    /// core/kernel/docs/syscalls.md § `SYS_SYSTEM_INFO`.
    StackHighWater = 9,
    /// Raw retype debit of one `Thread`, in bytes: one guard page, the kernel
    /// stack, one page holding the object wrapper and the thread control
    /// block, and the extended-state (FPU, SIMD, vector) save area, all
    /// page-granular. The guard page is the caller's memory and unusable
    /// while the thread exists: the kernel unmaps it below the stack so an
    /// overflow faults. The save area's size is the boot CPU's (on x86-64 the
    /// XSAVE size of the enabled components, on riscv64 `304 + 32 * vlenb`,
    /// each rounded up to whole pages), so it is fixed for a boot but not
    /// across machines. A process sizes the Memory cap it retypes a thread
    /// from with it.
    ThreadRetypeBytes = 10,
    /// Number of `CSpace` ids in use system-wide: the kernel's `CSpace`
    /// registry ids allocated and not yet returned by a `CSpace` teardown, the
    /// root `CSpace`'s included. A diagnostic count, readable by any process
    /// with no capability; ktest reads it to check that a teardown returns its
    /// id (core/kernel/docs/syscalls.md § `SYS_SYSTEM_INFO`).
    LiveCSpaceCount = 11,
}

/// `SystemInfoType::StackHighWater` class: the per-CPU idle stacks.
pub const STACK_CLASS_IDLE: u64 = 0;
/// `SystemInfoType::StackHighWater` class: thread kernel stacks.
pub const STACK_CLASS_THREAD: u64 = 1;
/// `SystemInfoType::StackHighWater` class: the bootloader's handoff stack.
pub const STACK_CLASS_HANDOFF: u64 = 2;

#[cfg(test)]
mod tests
{
    use super::*;

    // The defect caught: a top-up that leaves the body arena no page after
    // the slots it funds (a split then fails while slot headroom looked
    // ample), or one that donates when nothing is short.
    #[test]
    fn a_cspace_top_up_keeps_a_page_for_the_arena_beyond_the_slots()
    {
        let p = PAGE_SIZE;
        let s = CSPACE_SLOTS_PER_PAGE;
        assert_eq!(cspace_topup_pages(256 + s, p, 256), 0, "nothing short");
        assert_eq!(
            cspace_topup_pages(1000, 0, 256),
            2,
            "slots on pages, no budget"
        );
        assert_eq!(
            cspace_topup_pages(256, p, 256),
            2,
            "no page beyond the slots"
        );
        assert_eq!(
            cspace_topup_pages(0, 0, 256),
            7,
            "ceil((256 + 56) / 56) + 1"
        );
        assert_eq!(cspace_topup_pages(256 + s - 1, p, 256), 2);
    }

    // Defects guarded: an encode or decode that drops index or generation bits
    // (a 32-bit truncation anywhere names the gen-0 handle of the index), a
    // generation that reaches bit 63 (a kernel-issued handle then reads as an
    // error code), and a gen-0 handle that differs from its bare index.
    #[test]
    fn cap_handle_round_trips_full_index_and_generation_ranges()
    {
        for &index in &[0u32, 1, 255, 70_000, 3_677_183, u32::MAX]
        {
            for &generation in &[0u32, 1, 255, 256, 1 << 24, CAP_GEN_MASK]
            {
                let h = cap_handle_encode(index, generation);
                assert_eq!(cap_handle_index(h), index);
                assert_eq!(cap_handle_gen(h), generation);
                assert_eq!(h >> 63, 0, "bit 63 set in {h:#x}");
            }
        }
        assert_eq!(cap_handle_encode(7, 0), 7);
        // The generation wraps at 1 << CAP_GEN_BITS.
        assert_eq!(cap_handle_encode(7, CAP_GEN_MASK + 1), 7);
        // A handle with bit 63 set decodes to a generation no slot carries.
        assert!(cap_handle_gen(1u64 << 63) > CAP_GEN_MASK);
    }

    // Defects guarded: a per-bit rights constant that overlaps another bit of
    // the same capability type (attenuating one right would silently attenuate
    // the other), and a bit at position >= 16 (dropped by the kernel's 16-bit
    // slot rights word).
    #[test]
    fn per_type_rights_bits_are_single_disjoint_and_fit_u16()
    {
        let spaces: &[&[u64]] = &[
            // Memory
            &[
                RIGHTS_MEM_MAP,
                RIGHTS_MEM_WRITE,
                RIGHTS_MEM_EXECUTE,
                RIGHTS_MEM_RETYPE,
                RIGHTS_MEM_PHYS,
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
                    bit < (1u64 << 16),
                    "rights bit {bit:#x} exceeds the 16-bit slot word"
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
