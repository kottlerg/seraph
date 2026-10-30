// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/syscall/src/lib.rs

//! Raw syscall wrappers for Seraph userspace.
//!
//! Thin `no_std`-compatible functions that issue the architecture-specific
//! syscall instruction (`SYSCALL` on x86-64, `ECALL` on RISC-V) and return
//! the kernel result.
//!
//! IPC calls that transfer data words require the caller to have registered an
//! IPC buffer page via [`ipc_buffer_set`] first.
//!
//! # ABI
//! Register assignment follows `core/kernel/docs/syscalls.md` § Calling
//! Convention; `arch::current` implements it per architecture. A wrapper's
//! argument widths (`u32` cap handles, narrower `u16` and `u8` fields) are
//! the syscall ABI's, not limits of this crate.

// When pulled into std's dep graph via build-std (feature
// `rustc-dep-of-std` on), `core` isn't yet a conventional crate — we
// import the `rustc-std-workspace-core` facade and alias it so
// `core::arch::asm!` and `core::sync::atomic` resolve. Mirror of the
// libc / hermit-abi pattern. Normal userspace build path is unchanged.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

// `no_core` disables the automatic prelude; bring it in by hand so
// operator traits, Copy/Clone, etc. resolve for the asm wrappers and
// result types in this crate.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use syscall_abi::{
    MEM_UNMAP_RECLAIM_PTS, MSG_DATA_WORDS_MAX, SYS_ASPACE_BIND_NOTIFICATION, SYS_ASPACE_QUERY,
    SYS_CAP_COPY, SYS_CAP_CREATE_ASPACE, SYS_CAP_CREATE_CSPACE, SYS_CAP_CREATE_ENDPOINT,
    SYS_CAP_CREATE_EVENT_Q, SYS_CAP_CREATE_NOTIFICATION, SYS_CAP_CREATE_THREAD,
    SYS_CAP_CREATE_WAIT_SET, SYS_CAP_DELETE, SYS_CAP_DERIVE, SYS_CAP_DERIVE_BADGE, SYS_CAP_INFO,
    SYS_CAP_MOVE, SYS_CAP_REVOKE, SYS_EVENT_POST, SYS_EVENT_RECV, SYS_GETRANDOM, SYS_IOPORT_BIND,
    SYS_IOPORT_SPLIT, SYS_IPC_BUFFER_SET, SYS_IPC_CALL, SYS_IPC_RECV, SYS_IPC_REPLY, SYS_IRQ_ACK,
    SYS_IRQ_REGISTER, SYS_IRQ_SPLIT, SYS_MEM_MAP, SYS_MEM_PROTECT, SYS_MEM_UNMAP, SYS_MEMORY_MERGE,
    SYS_MEMORY_SPLIT, SYS_MMIO_MAP, SYS_MMIO_SPLIT, SYS_NOTIFICATION_SEND, SYS_NOTIFICATION_WAIT,
    SYS_PROCESS_EXIT, SYS_SBI_CALL, SYS_SCHED_SPLIT, SYS_SYSTEM_INFO, SYS_THREAD_BIND_NOTIFICATION,
    SYS_THREAD_CONFIGURE, SYS_THREAD_EXIT, SYS_THREAD_READ_REGS, SYS_THREAD_SET_AFFINITY,
    SYS_THREAD_SET_FAULT_HANDLER, SYS_THREAD_SET_PRIORITY, SYS_THREAD_SLEEP, SYS_THREAD_START,
    SYS_THREAD_STOP, SYS_THREAD_WRITE_REGS, SYS_THREAD_YIELD, SYS_WAIT_SET_ADD,
    SYS_WAIT_SET_REMOVE, SYS_WAIT_SET_WAIT, SyscallError,
};

pub use syscall_abi::{
    CAP_INFO_ASPACE_PT_BUDGET, CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_CAPACITY,
    CAP_INFO_CSPACE_USED, CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_HAS_RETYPE,
    CAP_INFO_MEMORY_MAPPINGS, CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES, CAP_INFO_MEMORY_PHYS_BASE,
    CAP_INFO_MEMORY_SIZE, CAP_INFO_TAG_RIGHTS, CAP_TAG_MEMORY, EXIT_FAULT_BASE, EXIT_KILLED,
    EXIT_VOLUNTARY, IPC_REPLY_TRANSFER_FAILED, MAP_EXECUTABLE, MAP_FROM_CAP, MAP_READ,
    MAP_WRITABLE, MAX_GETRANDOM_LEN, RIGHTS_ALL, RIGHTS_AS_CONTROL, RIGHTS_AS_MAP, RIGHTS_AS_READ,
    RIGHTS_CS_ALL, RIGHTS_CS_DELETE, RIGHTS_CS_DERIVE, RIGHTS_CS_INSERT, RIGHTS_CS_REVOKE,
    RIGHTS_EP_GRANT, RIGHTS_EP_RECEIVE, RIGHTS_EP_SEND, RIGHTS_EP_SEND_GRANT, RIGHTS_EQ_POST,
    RIGHTS_EQ_RECV, RIGHTS_IOPORT_USE, RIGHTS_IRQ_NOTIFY, RIGHTS_MEM_EXECUTE, RIGHTS_MEM_MAP,
    RIGHTS_MEM_MAP_RW, RIGHTS_MEM_MAP_RX, RIGHTS_MEM_RETYPE, RIGHTS_MEM_WRITE, RIGHTS_MMIO_MAP,
    RIGHTS_MMIO_WRITE, RIGHTS_NTF_NOTIFY, RIGHTS_NTF_WAIT, RIGHTS_SBI_BASE, RIGHTS_SBI_CPPC,
    RIGHTS_SBI_DBCN, RIGHTS_SBI_PMU, RIGHTS_SBI_RESET, RIGHTS_SBI_SUSPEND, RIGHTS_THREAD,
    RIGHTS_THREAD_CONTROL, RIGHTS_THREAD_OBSERVE, RIGHTS_WS_MODIFY, RIGHTS_WS_WAIT,
};

// ── Raw syscall entry ─────────────────────────────────────────────────────────

mod arch;

use arch::current::{
    syscall1_ret4, syscall2, syscall3, syscall4, syscall4_any, syscall5, syscall5_ret2, syscall6,
    syscall6_ret3,
};

/// Issue syscall `nr` with three argument registers exactly as given, bypassing
/// the typed wrappers' argument types; returns the primary return register
/// (negative = error code). Any secondary return values are discarded.
///
/// For harness tests of the kernel's own argument validation, which must hand
/// it register values no typed wrapper can express (a priority above 255, a
/// CPU id above `u32::MAX`). Everything else uses the typed wrappers. No
/// register the kernel can write on return is assumed preserved, including the
/// argument register that carries `SYS_SCHED_SPLIT`'s second handle.
///
/// # Safety
/// The call must leave untouched everything the calling program runs on. Each
/// of these must hold for `nr` and its arguments:
/// - it takes no user-pointer argument and uses no IPC buffer;
/// - it changes none of the caller's mappings;
/// - it changes no thread of the caller's address space that has started,
///   other than the calling thread's registers that `syscall4_any` declares
///   clobbered (its return registers and, on x86-64, the `rcx` / `r11` that
///   `SYSCALL` overwrites);
/// - it changes the caller's `CSpace` only at the slots its capability
///   arguments name and in fresh slots the kernel fills.
///
/// The calls the kernel's validation tests make meet all four:
/// `SYS_THREAD_SET_PRIORITY` and `SYS_THREAD_SET_AFFINITY` on a thread never
/// started, and `SYS_SCHED_SPLIT` on a capability copy (it consumes the copy's
/// slot and fills two fresh ones). Every argument is then a value the kernel
/// validates, so any value is admissible. `nr` need not be a defined syscall:
/// an undefined number returns `UnknownSyscall` in the primary return register
/// and changes nothing else.
#[inline]
#[must_use]
pub unsafe fn raw_syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    // SAFETY: the caller contract is raw_syscall4's, with a fourth argument of 0.
    unsafe { raw_syscall4(nr, a0, a1, a2, 0) }
}

/// [`raw_syscall3`] with a fourth argument register, for validation tests of
/// a syscall whose fourth argument the typed wrapper fixes (the reserved
/// `badge` word of `SYS_THREAD_SET_FAULT_HANDLER`, which the wrapper passes as
/// 0, beside its class mask). The fourth argument travels in the register
/// `core/kernel/docs/syscalls.md` § Syscall Entry and Exit assigns it.
///
/// # Safety
/// The `# Safety` contract of [`raw_syscall3`].
#[inline]
#[must_use]
pub unsafe fn raw_syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64
{
    // SAFETY: the caller contract keeps the call's effects off everything this
    // program runs on; `syscall4_any` accepts any `nr` and arguments under this
    // same contract (its `# Safety`) and declares every register the kernel can
    // write on return as clobbered.
    unsafe { syscall4_any(nr, a0, a1, a2, a3) }
}

// ── IPC capability handle helpers ─────────────────────────────────────────────

pub use syscall_abi::pack_cap_handles;

// ── Public syscall wrappers ───────────────────────────────────────────────────

/// Voluntarily yield the CPU to the next runnable thread.
///
/// # Errors
/// None: the kernel never fails this call, so the result is always `Ok`.
#[inline]
pub fn thread_yield() -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments; yield is always safe.
    let ret = unsafe { syscall2(SYS_THREAD_YIELD, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Exit the current thread. Never returns.
#[inline]
pub fn thread_exit() -> !
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments; never returns.
    unsafe { syscall2(SYS_THREAD_EXIT, 0, 0) };
    // The syscall never returns; loop to satisfy the diverging type.
    loop
    {
        core::hint::spin_loop();
    }
}

/// Exit the whole process with the voluntary exit `code`. Never returns.
///
/// The kernel records `syscall_abi::encode_exit_code(code)` as the exit reason
/// and posts it to the calling thread's death observers, so a waiting parent's
/// `ExitStatus` carries the code. Like [`thread_exit`] this stops only the
/// calling thread — it does not post to the address-space death surface, which
/// is reserved for terminal faults. Whole-process teardown (reaping any sibling
/// threads) is procmgr-driven via cap revocation once it observes the death.
#[inline]
pub fn process_exit(code: u32) -> !
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments; never returns.
    unsafe { syscall2(SYS_PROCESS_EXIT, u64::from(code), 0) };
    // The syscall never returns; loop to satisfy the diverging type.
    loop
    {
        core::hint::spin_loop();
    }
}

/// Register (or clear) the calling thread's IPC buffer page.
///
/// `virt` must be 4 KiB-aligned (or 0 to deregister). The kernel checks only
/// the alignment and that `virt` lies in the user half; it does not check that
/// the page is mapped (`core/kernel/docs/syscalls.md` § `SYS_IPC_BUFFER_SET`).
/// Once registered, the kernel reads the page for every data-carrying
/// `SYS_IPC_CALL` request and `SYS_IPC_REPLY`, and writes it on every
/// `SYS_IPC_RECV` delivery and `SYS_IPC_CALL` reply, until the thread registers
/// another page or 0.
///
/// # Safety
/// A call that registers a page (a non-zero, page-aligned, user-half `virt`;
/// any other value registers nothing) dedicates that page to the kernel's IPC
/// access for as long as it stays registered:
/// - the page holds no Rust object other than the IPC buffer itself, which is
///   accessed only through raw pointers;
/// - no Rust reference into the page is live across any IPC syscall the
///   calling thread makes;
/// - no other thread registers the same page while this one holds it.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidAddress` (non-zero `virt` not
/// page-aligned, or outside the user half), or `InvalidCapability` (no current
/// thread).
#[inline]
pub unsafe fn ipc_buffer_set(virt: u64) -> Result<(), i64>
{
    // SAFETY: syscall2 issues the raw syscall; `virt` is a scalar the kernel
    // validates for alignment and the user half. The caller's contract
    // dedicates the page it registers, which is what the raw-wrapper contract's
    // IPC-buffer clause requires of every later IPC syscall on this thread.
    let ret = unsafe { syscall2(SYS_IPC_BUFFER_SET, virt, 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Raw `SYS_IPC_CALL` issuing `syscall6_ret3`. Intended for `shared/ipc`'s
/// `IpcMessage`-snapshot wrapper; other callers should use that higher-level
/// entry point.
///
/// Returns `(reply_label, reply_word_count)` on success.
///
/// # Errors
/// Returns a negative `i64` error code, per `SYS_IPC_CALL` in
/// `core/kernel/docs/syscalls.md`: `InvalidCapability` (`ep` is not a live
/// Endpoint cap, or a cap slot is stale or Null), `InsufficientRights` (`ep`
/// lacks Send, or Grant on a cap-bearing call), `InvalidArgument` (a cap
/// slot repeated in one message, or `data_count > 0` with no IPC buffer page
/// registered), `InvalidAddress` (the registered IPC buffer page is
/// unmapped), `InvalidState` (a cap slot is pinned by an in-flight
/// `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer), or
/// `Interrupted` (the call was cancelled while blocked, including by the
/// receiver receiving again before it replied). A `data_count` above
/// `MSG_DATA_WORDS_MAX` or a `cap_count` above `MSG_CAP_SLOTS_MAX` is clamped
/// to the maximum, not rejected.
/// Cap-slot problems are rejected before the caller blocks; a refusal
/// arising only afterwards delivers the message with zero caps.
#[doc(hidden)]
#[inline]
pub fn raw_ipc_call(
    ep: u32,
    label: u64,
    data_count: usize,
    cap_count: usize,
    cap_packed_lo: u64,
    cap_packed_hi: u64,
) -> Result<(u64, usize), i64>
{
    // cast_possible_truncation: word count fits in 16 bits by invariant.
    #[allow(clippy::cast_possible_truncation)]
    let data_count_u64 = data_count as u64;
    #[allow(clippy::cast_possible_truncation)]
    let cap_count_u64 = cap_count as u64;
    // SAFETY: syscall6_ret3 issues the raw syscall; every argument is a scalar
    // the kernel validates. The kernel reads the request words from, and writes
    // the reply into, this thread's registered IPC buffer page; registering it
    // required `ipc_buffer_set`'s contract, under which no Rust reference into
    // the page is live across this call, which is the raw-wrapper contract's
    // IPC-buffer clause.
    let (ret, reply_label, reply_word_count) = unsafe {
        syscall6_ret3(
            SYS_IPC_CALL,
            u64::from(ep),
            label,
            data_count_u64,
            cap_count_u64,
            cap_packed_lo,
            cap_packed_hi,
        )
    };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        // cast_possible_truncation: Seraph targets 64-bit only (usize == u64);
        // kernel clamps reply_word_count to MSG_DATA_WORDS_MAX = 64 before write.
        #[allow(clippy::cast_possible_truncation)]
        let word_count = (reply_word_count as usize).min(MSG_DATA_WORDS_MAX);
        Ok((reply_label, word_count))
    }
}

/// Raw `SYS_IPC_RECV` issuing syscall1_ret4. Intended for `shared/ipc`'s
/// `IpcMessage`-snapshot wrapper; other callers should use that higher-level
/// entry point.
///
/// Returns `(label, badge, word_count)` on success.
///
/// # Errors
/// Returns a negative `i64` error code, per `SYS_IPC_RECV` in
/// `core/kernel/docs/syscalls.md`: `InvalidCapability` (`ep` is not a live
/// Endpoint cap), `InsufficientRights` (`ep` lacks Receive), `QuotaExceeded`
/// (this thread's `CSpace` directory is structurally full for an incoming
/// cap transfer), `OutOfMemory` (the `CSpace` slot-page pool is exhausted),
/// or `Interrupted` (this thread was stopped, or the endpoint destroyed,
/// while the receive was blocked). The first four refuse the receive before
/// any pending reply is released.
#[doc(hidden)]
#[inline]
pub fn raw_ipc_recv(ep: u32) -> Result<(u64, u64, usize), i64>
{
    // SAFETY: syscall1_ret4 issues the raw syscall; `ep` is a scalar the kernel
    // validates. The kernel writes the delivered message into this thread's
    // registered IPC buffer page; registering it required `ipc_buffer_set`'s
    // contract, under which no Rust reference into the page is live across this
    // call, which is the raw-wrapper contract's IPC-buffer clause.
    let (ret, label, badge, word_count) = unsafe { syscall1_ret4(SYS_IPC_RECV, u64::from(ep)) };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        // cast_possible_truncation: Seraph targets 64-bit only (usize == u64);
        // kernel clamps word_count to MSG_DATA_WORDS_MAX = 64 before write.
        #[allow(clippy::cast_possible_truncation)]
        let word_count = (word_count as usize).min(MSG_DATA_WORDS_MAX);
        Ok((label, badge, word_count))
    }
}

/// Raw `SYS_IPC_REPLY`. Intended for `shared/ipc`'s `IpcMessage`-snapshot
/// wrapper; other callers should use that higher-level entry point.
///
/// # Errors
/// Returns a negative `i64` error code, per `SYS_IPC_REPLY` in
/// `core/kernel/docs/syscalls.md`: `InvalidCapability` (no pending reply, or
/// a reply cap slot is stale or Null), `InvalidArgument` (a cap slot
/// repeated in the reply, or `data_count > 0` with no IPC buffer page
/// registered), `InvalidAddress` (the registered IPC buffer page is
/// unmapped), `InvalidState` (a reply cap slot is pinned by an in-flight
/// `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer), or
/// `QuotaExceeded` / `OutOfMemory` (the caller's `CSpace` cannot accept the
/// reply caps). The reply never blocks, so it never returns `Interrupted`. A
/// `data_count` above `MSG_DATA_WORDS_MAX` or a `cap_count` above
/// `MSG_CAP_SLOTS_MAX` is clamped to the maximum, not rejected. An error
/// consumes the pending reply: a caller that was pending has already been
/// woken with the `IPC_REPLY_TRANSFER_FAILED` label, so the reply must not be
/// retried.
#[doc(hidden)]
#[inline]
pub fn raw_ipc_reply(
    label: u64,
    data_count: usize,
    cap_count: usize,
    cap_packed_lo: u64,
    cap_packed_hi: u64,
) -> Result<(), i64>
{
    // cast_possible_truncation: Seraph targets 64-bit only (usize == u64).
    #[allow(clippy::cast_possible_truncation)]
    let data_count_u64 = data_count as u64;
    #[allow(clippy::cast_possible_truncation)]
    let cap_count_u64 = cap_count as u64;
    // SAFETY: syscall5 issues the raw syscall; every argument is a scalar the
    // kernel validates. The kernel reads the reply words from this thread's
    // registered IPC buffer page; registering it required `ipc_buffer_set`'s
    // contract, under which no Rust reference into the page is live across this
    // call, which is the raw-wrapper contract's IPC-buffer clause.
    let ret = unsafe {
        syscall5(
            SYS_IPC_REPLY,
            label,
            data_count_u64,
            cap_count_u64,
            cap_packed_lo,
            cap_packed_hi,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Send `bits` to a notification cap. `bits` must be non-zero.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` (bad cap),
/// `InsufficientRights` (cap lacks Notify), or `InvalidArgument` (`bits` is
/// zero).
#[inline]
pub fn notification_send(sig: u32, bits: u64) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; sig is cap index as u64, bits is bitmask;
    // kernel validates cap and updates notification state.
    let ret = unsafe { syscall2(SYS_NOTIFICATION_SEND, u64::from(sig), bits) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Block until any bits are set on a notification cap. Returns the acquired bitmask.
///
/// The primary return register holds status (`0` on success, negative
/// `SyscallError` on failure); the bitmask is delivered in the secondary
/// register (rdx / a1). Mirrors `event_recv`; the split avoids aliasing
/// bit-63-set bitmasks with the dispatcher's negative-Err encoding.
///
/// # Errors
/// Returns a negative `i64` error code if the notification cap is invalid or
/// lacks Wait rights; `-16` (`Interrupted`) if the caller is stopped while
/// waiting or the notification is destroyed under it.
#[inline]
pub fn notification_wait(sig: u32) -> Result<u64, i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; sig is cap
    // index as u64, arg1 = 0 selects indefinite blocking; kernel validates
    // cap and writes the bitmask into the secondary return register.
    let (ret, bits) = unsafe { syscall5_ret2(SYS_NOTIFICATION_WAIT, u64::from(sig), 0, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(bits) }
}

/// Block until any bits are set on a notification cap, or until `timeout_ms`
/// elapses. Returns the acquired bitmask (non-zero) on wake, or `Ok(0)`
/// on timeout.
///
/// `timeout_ms == 0` is equivalent to [`notification_wait`] — block indefinitely.
/// If the kernel's sleep list is full when the wait parks, it returns `Ok(0)`
/// at once, as a timeout.
///
/// Same register layout as [`notification_wait`]: status in the primary register,
/// bitmask in the secondary. Timeout is notified in-band as `bits == 0`
/// (legitimate because `notification_send` rejects zero-bit sends).
///
/// # Errors
/// Returns a negative `i64` error code if the notification cap is invalid or
/// lacks Wait rights; `-16` (`Interrupted`) if the caller is stopped while
/// waiting or the notification is destroyed under it.
#[inline]
pub fn notification_wait_timeout(sig: u32, timeout_ms: u64) -> Result<u64, i64>
{
    // SAFETY: same as `notification_wait`; arg1 carries the timeout sentinel
    // (0 = infinite, matching the single-arg behaviour).
    let (ret, bits) =
        unsafe { syscall5_ret2(SYS_NOTIFICATION_WAIT, u64::from(sig), timeout_ms, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(bits) }
}

/// Retype a Memory cap into a new Endpoint. Returns the new capability handle
/// (slot index plus generation).
///
/// `memory_cap` is the source Memory-cap slot; it MUST carry `RIGHTS_MEM_RETYPE`
/// and have at least 128 B of `available_bytes` (the `BIN_128` size class the
/// Endpoint wrapper plus state is debited as). Bytes are debited from the
/// Memory cap and credited back when the Endpoint is destroyed.
///
/// # Errors
/// Returns a negative `i64` error code if `memory_cap` is invalid, lacks
/// `RIGHTS_MEM_RETYPE`, has insufficient `available_bytes`, or the caller's
/// `CSpace`'s slot pool cannot back a fresh slot (`OutOfMemory`; `QuotaExceeded` at the
/// structural ceiling). `QuotaExceeded` also means the Memory object's reference
/// count is at its 2^31 ceiling.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_endpoint(memory_cap: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments;
    // kernel retypes the Memory-cap region and returns the new capability handle (slot index
    // plus generation).
    let ret = unsafe { syscall2(SYS_CAP_CREATE_ENDPOINT, u64::from(memory_cap), 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Retype a Memory cap into a new Notification. Returns the new capability
/// handle (slot index plus generation).
///
/// `memory_cap` MUST carry `RIGHTS_MEM_RETYPE` and have at least 128 B of
/// `available_bytes` (the `BIN_128` size class debited). Bytes are debited
/// from the Memory cap and credited back when the Notification is destroyed.
///
/// # Errors
/// Returns a negative `i64` error code if `memory_cap` is invalid, lacks
/// `RIGHTS_MEM_RETYPE`, has insufficient `available_bytes`, or the caller's
/// `CSpace`'s slot pool cannot back a fresh slot (`OutOfMemory`; `QuotaExceeded` at the
/// structural ceiling). `QuotaExceeded` also means the Memory object's reference
/// count is at its 2^31 ceiling.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_notification(memory_cap: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments;
    // kernel retypes the Memory-cap region and returns the new capability handle (slot index
    // plus generation).
    let ret = unsafe { syscall2(SYS_CAP_CREATE_NOTIFICATION, u64::from(memory_cap), 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Retype a Memory cap into a new `AddressSpace`, or augment an existing
/// one's PT growth budget.
///
/// `memory_cap`, a generation-checked capability handle, must carry
/// `MemRights::RETYPE` and have at least `init_pages * PAGE_SIZE` of
/// `available_bytes`. In create mode page 0 of the slab is the kernel wrapper
/// page, page 1 the root PT, and pages `2..init_pages` seed the PT growth
/// pool; `init_pages` must be `>= 2`.
///
/// `augment_target` selects the mode:
/// - `0` → create a new `AddressSpace`; returns the new capability handle
///   (slot index plus generation).
/// - non-zero `AddressSpace` capability handle (generation-checked, with Map
///   rights) → augment that AS's PT growth pool with the `init_pages` carved
///   pages (`init_pages >= 1`); returns `0`. Once per record page of the
///   kernel's donation bookkeeping, a donation keeps its first page for that
///   bookkeeping and seeds `init_pages - 1`, so a one-page donation can leave
///   the budget unchanged; read the budget back with
///   `CAP_INFO_ASPACE_PT_BUDGET` rather than assuming the count.
///
/// # Errors
/// Returns a negative `i64` error code, per `SYS_CAP_CREATE_ASPACE` in
/// `core/kernel/docs/syscalls.md`: `InvalidArgument` if `init_pages` is 0,
/// `init_pages * PAGE_SIZE` overflows, or create mode has `init_pages < 2`;
/// `InvalidCapability` if either handle is invalid, stale, or names the wrong
/// object type; `InsufficientRights` if `memory_cap` lacks Retype or the
/// augment target lacks Map; `OutOfMemory` if `memory_cap`'s region or the
/// caller's `CSpace` slot-page pool is exhausted; `QuotaExceeded` if the
/// caller's `CSpace` directory is structurally full or `memory_cap`'s object has
/// its reference count at its 2^31 ceiling.
// cast_possible_truncation, cast_sign_loss: ret is 0 (augment mode) or a
// non-negative cap handle — a 24-bit slot index plus an 8-bit generation
// (`CAP_INDEX_BITS + 8 <= 32`) — so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_aspace(memory_cap: u32, augment_target: u32, init_pages: u64)
-> Result<u32, i64>
{
    // SAFETY: syscall3 issues a raw syscall; arguments are scalar.
    let ret = unsafe {
        syscall3(
            SYS_CAP_CREATE_ASPACE,
            u64::from(memory_cap),
            u64::from(augment_target),
            init_pages,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Retype a Memory cap into a new `CSpace`, or augment an existing one's
/// slot-page growth budget.
///
/// `memory_cap`, a generation-checked capability handle, must carry
/// `MemRights::RETYPE` and have at least `init_pages * PAGE_SIZE` of
/// `available_bytes`. In create mode the slab's page 0 is the kernel wrapper
/// page; pages `1..init_pages` seed the slot-page pool (each backs 56 slots).
/// `init_pages` must be `>= 1`.
///
/// `augment_target`:
/// - `0` → create new; returns the new capability handle (slot index plus
///   generation).
/// - non-zero `CSpace` capability handle (generation-checked, with Insert
///   rights) → augment that `CSpace`'s growth pool with the `init_pages`
///   carved pages; returns `0`. As for `cap_create_aspace`, once per record
///   page of the kernel's donation bookkeeping a donation seeds
///   `init_pages - 1`; read the budget back with `CAP_INFO_CSPACE_BUDGET`.
///
/// A `CSpace` has no slot quota: its capacity is whatever its slot-page
/// pool backs (query via `CAP_INFO_CSPACE_CAPACITY`), bounded only by the
/// directory's structural ceiling.
///
/// # Errors
/// Returns a negative `i64` error code, per `SYS_CAP_CREATE_CSPACE` in
/// `core/kernel/docs/syscalls.md`: `InvalidArgument` if `init_pages` is 0 or
/// `init_pages * PAGE_SIZE` overflows; `InvalidCapability` if either handle
/// is invalid, stale, or names the wrong object type; `InsufficientRights` if
/// `memory_cap` lacks Retype or the augment target lacks Insert;
/// `OutOfMemory` if `memory_cap`'s region or the caller's `CSpace` slot-page
/// pool is exhausted, or, in create mode, every id of the kernel's `CSpace`
/// registry is live (the registry holds one id per DRAM page);
/// `QuotaExceeded` if the caller's `CSpace` directory is
/// structurally full or `memory_cap`'s object has its reference count at its
/// 2^31 ceiling. A later cap insert into the new `CSpace` fails with
/// `OutOfMemory` (-8) when the seeded pool is exhausted (refill via augment
/// mode) and `QuotaExceeded` (-17) at the structural ceiling.
// cast_possible_truncation, cast_sign_loss: ret is 0 (augment mode) or a
// non-negative cap handle — a 24-bit slot index plus an 8-bit generation
// (`CAP_INDEX_BITS + 8 <= 32`) — so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_cspace(memory_cap: u32, augment_target: u32, init_pages: u64)
-> Result<u32, i64>
{
    // arg3 is reserved (the removed `max_slots` quota) and must be 0.
    let ret = raw_cap_create_cspace(memory_cap, augment_target, init_pages, 0);
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Raw `SYS_CAP_CREATE_CSPACE` with a caller-controlled reserved arg 3.
/// Intended for test harnesses probing the kernel's reserved-argument
/// rejection; other callers should use [`cap_create_cspace`], which
/// always passes `0`.
///
/// Returns the kernel's raw `i64`: the new capability handle (slot index plus
/// generation) in create-mode, or `0` in augment-mode, on success; a negative
/// `SyscallError` code on failure.
#[doc(hidden)]
#[must_use]
#[inline]
pub fn raw_cap_create_cspace(
    memory_cap: u32,
    augment_target: u32,
    init_pages: u64,
    reserved: u64,
) -> i64
{
    // SAFETY: syscall4 issues a raw syscall; arguments are scalar.
    unsafe {
        syscall4(
            SYS_CAP_CREATE_CSPACE,
            u64::from(memory_cap),
            u64::from(augment_target),
            init_pages,
            reserved,
        )
    }
}

/// Retype a Memory cap into a new Thread bound to `aspace_cap` and
/// `cspace_cap`. Returns the new Thread capability handle (slot index plus
/// generation).
///
/// `memory_cap` must carry `MemRights::RETYPE` and have at least 6 pages of
/// `available_bytes` (4 kstack pages, 1 page for the wrapper and TCB,
/// 1 FPU/SIMD save-area page; see `cap::retype::dispatch_for(Thread)`).
///
/// Creation priority: with `sched_cap == 0`, `priority` must also be 0 and
/// the thread is created at `PRIORITY_MIN` (floor-only creation needs no
/// scheduling authority). With a `SchedControl` cap, `priority == 0` selects
/// the cap's band floor; a nonzero `priority` must lie within the cap's
/// `[min, max]` band.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` (a cap is
/// invalid), `InsufficientRights` (a source cap lacks Retype/Map/Insert, or
/// `priority` is outside the `SchedControl` band), `InvalidArgument` (nonzero
/// `priority` without a `SchedControl` cap, or `priority` above
/// `PRIORITY_MAX`), `OutOfMemory` (the Memory cap's `available_bytes` or the
/// caller's `CSpace` slot pool is exhausted), or `QuotaExceeded` (the `CSpace`
/// directory is structurally full, or the Memory object's reference count is at
/// its 2^31 ceiling).
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_thread(
    memory_cap: u32,
    aspace_cap: u32,
    cspace_cap: u32,
    sched_cap: u32,
    priority: u8,
) -> Result<u32, i64>
{
    // SAFETY: syscall5 issues a raw syscall instruction; all arguments are
    // scalar cap indices / a priority level; the kernel validates them.
    let ret = unsafe {
        syscall5(
            SYS_CAP_CREATE_THREAD,
            u64::from(memory_cap),
            u64::from(aspace_cap),
            u64::from(cspace_cap),
            u64::from(sched_cap),
            u64::from(priority),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Map `page_count` pages of a Memory cap into an address space.
///
/// - `memory_cap`: capability handle (slot index plus generation) of the source Memory cap.
/// - `aspace_cap`: capability handle (slot index plus generation) of the target `AddressSpace`.
/// - `virt`: virtual address to map at (page-aligned and below the kernel's
///   `user_va_top`; see `core/kernel/docs/arch-interface.md` § `paging`, `user_va_top`).
/// - `offset_pages`: first page within the memory region to map.
/// - `page_count`: number of pages to map.
/// - `prot_bits`: explicit permission bits (bit 0 = READ, bit 1 = WRITE,
///   bit 2 = EXECUTE; bit 0 grants nothing of its own but makes a read-only
///   request non-zero). Must be a subset of the Memory cap's rights. If zero,
///   permissions are derived from the Memory cap's rights directly.
///
/// W^X is enforced: WRITE and EXECUTE may not both be set. A page already
/// mapped in the span is remapped to the new frame. The range may not reach
/// bytes the Memory cap has retyped into kernel objects: it must start at or
/// above the cap's page-rounded retype cursor (`core/kernel/docs/syscalls.md`
/// § `SYS_MEM_MAP`).
///
/// # Safety
/// When `aspace_cap` names the calling program's own address space, no page
/// of the span `[virt, virt + page_count * 4096)` may hold a live Rust object
/// or the registered IPC buffer page of any of its threads: the call replaces
/// whatever the span maps, changing those bytes outside the compiler's
/// knowledge. A call on another address space changes nothing the calling
/// program runs on, and neither does a refusal other than `OutOfMemory`: the
/// kernel checks every argument before it maps a page, but maps page by page
/// and returns `OutOfMemory` with the pages before the failing one already
/// mapped, so the contract covers the whole span even for a call that fails.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidAddress` (`virt` unaligned,
/// non-canonical, or the range leaves the user half), `InvalidArgument`
/// (zero page count, overflow, the range runs past the memory region, or
/// `offset_pages` lies below the retype cursor),
/// `InvalidCapability` (also when `memory_cap` is revoked or deleted while
/// the call runs), `InsufficientRights` (requested permissions exceed the
/// cap's rights), `WxViolation`, or `OutOfMemory` (page-table
/// allocation, or a frame already named by `u32::MAX` user mappings).
#[inline]
pub unsafe fn mem_map(
    memory_cap: u32,
    aspace_cap: u32,
    virt: u64,
    offset_pages: u64,
    page_count: u64,
    prot_bits: u64,
) -> Result<(), i64>
{
    // SAFETY: syscall6 issues the raw syscall; every argument is a scalar the
    // kernel validates (cap indices, virtual address, page offset, count, prot
    // bits). The caller's contract keeps the span off live Rust objects and the
    // registered IPC page, which is the raw-wrapper contract's mapping clause.
    let ret = unsafe {
        syscall6(
            SYS_MEM_MAP,
            u64::from(memory_cap),
            u64::from(aspace_cap),
            virt,
            offset_pages,
            page_count,
            prot_bits,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Remove `page_count` mappings starting at `virt` from `aspace_cap`.
///
/// Clears leaf PTEs only; intermediate page tables persist until the address
/// space is destroyed. To also reclaim now-empty intermediate tables to the
/// page-table growth pool, use [`mem_unmap_reclaim`].
///
/// Unmapping a page that is not mapped is a no-op (not an error).
/// `virt` must be page-aligned and in the user address range.
///
/// # Safety
/// When `aspace_cap` names the calling program's own address space, no page
/// of the span `[virt, virt + page_count * 4096)` may hold a live Rust object
/// or the registered IPC buffer page of any of its threads: an access to an
/// unmapped page faults where the compiler assumes the object valid.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidAddress` (`virt` unaligned,
/// or the range leaves the user half), `InvalidArgument` (zero page count or
/// overflow), `InvalidCapability`, or `InsufficientRights` (cap lacks Map).
#[inline]
pub unsafe fn mem_unmap(aspace_cap: u32, virt: u64, page_count: u64) -> Result<(), i64>
{
    // SAFETY: syscall4 issues the raw syscall; every argument is a scalar the
    // kernel validates (cap index, virtual address, page count, flags = 0;
    // arg3 is passed explicitly so it is never an uninitialised register, as
    // the flag path keys on it). The caller's contract keeps the span off live
    // Rust objects and the registered IPC page, the raw-wrapper mapping clause.
    let ret = unsafe { syscall4(SYS_MEM_UNMAP, u64::from(aspace_cap), virt, page_count, 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Like [`mem_unmap`], but additionally reclaims every intermediate page table
/// the cleared span leaves empty back to `aspace_cap`'s page-table growth pool
/// (crediting `pt_growth_budget_bytes`), with a single coarse TLB and
/// paging-structure-cache shootdown closing the teardown, plus one span
/// invalidation each time the cleared frames overflow the kernel's frame-map
/// release batch.
///
/// Intended for region teardown (memmgr `UNREGISTER_REGION`): pass the whole
/// region span in one call so a wholly-covered intermediate table is reclaimed.
///
/// # Safety
/// The contract of [`mem_unmap`].
///
/// # Errors
/// The same codes as [`mem_unmap`].
#[inline]
pub unsafe fn mem_unmap_reclaim(aspace_cap: u32, virt: u64, page_count: u64) -> Result<(), i64>
{
    // SAFETY: syscall4 issues the raw syscall; every argument is a scalar the
    // kernel validates (cap index, virtual address, page count, reclaim flag).
    // The caller's contract (`mem_unmap`'s) keeps the span off live Rust
    // objects and the registered IPC page, the raw-wrapper mapping clause.
    let ret = unsafe {
        syscall4(
            SYS_MEM_UNMAP,
            u64::from(aspace_cap),
            virt,
            page_count,
            MEM_UNMAP_RECLAIM_PTS,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Change permission flags on `page_count` existing mappings in `aspace_cap`.
///
/// `memory_cap` authorises the requested permissions: they must be a subset of
/// the Memory cap's rights. `prot` encoding: bit 1 = WRITE, bit 2 = EXECUTE.
/// W^X is enforced. Returns an error if any page is not currently mapped.
///
/// # Safety
/// When `aspace_cap` names the calling program's own address space, no page
/// of the span `[virt, virt + page_count * 4096)` may hold a live Rust object
/// or the registered IPC buffer page of any of its threads whose accesses the
/// new permissions would refuse: an access the compiler assumes valid would
/// fault.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidAddress` (`virt` unaligned,
/// the range leaves the user half, or a page in it is not mapped),
/// `InvalidArgument` (zero page count, overflow, or no free frame during the
/// page-table walk), `WxViolation`, `InvalidCapability`, or
/// `InsufficientRights` (requested permissions exceed the cap's rights).
#[inline]
pub unsafe fn mem_protect(
    memory_cap: u32,
    aspace_cap: u32,
    virt: u64,
    page_count: u64,
    prot: u64,
) -> Result<(), i64>
{
    // SAFETY: syscall5 issues the raw syscall; every argument is a scalar the
    // kernel validates (cap indices, virtual address, page count, protection
    // flags). The caller's contract keeps the span off live Rust objects and the
    // registered IPC page, the raw-wrapper mapping clause.
    let ret = unsafe {
        syscall5(
            SYS_MEM_PROTECT,
            u64::from(memory_cap),
            u64::from(aspace_cap),
            virt,
            page_count,
            prot,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Carve a virgin tail off `memory_cap`.
///
/// `split_offset` is in bytes and must be page-aligned, > 0, < the memory
/// region size, and at or above the next page boundary above the cap's highest
/// live retype offset (a cap that has never been retyped has bump = 0,
/// so any in-range page-aligned offset is acceptable).
///
/// The parent (`memory_cap`) stays in its slot; its `size` shrinks to
/// `split_offset` and, when it carries `RETYPE`, its `available_bytes`
/// debits by the carved length. A new
/// child cap covering `[base + split_offset, base + orig_size)` is
/// inserted in the caller's `CSpace` as a derivation sibling of the
/// parent. Returns the tail's capability handle (slot index plus generation).
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidArgument` (`split_offset`
/// not page-aligned, out of range, inside the cap's bump region, or the
/// parent has derivation children), `InvalidCapability` (also a parent a
/// concurrent delete freed before the tail was linked), `InvalidState` (a
/// `cap_revoke`, `cap_move`, or IPC capability transfer is in flight on the
/// parent), `InsufficientRights` (cap lacks Map), `OutOfMemory` (tail
/// allocation or `CSpace` slot pool exhausted), or `QuotaExceeded` (`CSpace`
/// directory structurally full).
// cast_sign_loss: proven non-negative in Ok branch.
// cast_possible_truncation: returned value is a cap handle — a 24-bit slot index plus an
// 8-bit generation — so it fits u32.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn memory_split(memory_cap: u32, split_offset: u64) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; memory_cap is cap index as u64, split_offset
    // is byte offset; kernel validates cap and offset, returns the tail's cap handle.
    let ret = unsafe { syscall3(SYS_MEMORY_SPLIT, u64::from(memory_cap), split_offset, 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Absorb a virgin tail Memory cap back into its parent.
///
/// Inverse of [`memory_split`]. `parent_cap` covers the
/// physically-lower half and `tail_cap` the upper;
/// `parent.base + parent.size == tail.base` is required. Both caps must
/// share the same rights, `owns_memory` state, derivation parent, and
/// have no derivation children. The tail must be virgin (no live
/// retypes against it).
///
/// `parent_cap`'s slot stays valid; its `size` and `available_bytes`
/// grow to cover the absorbed tail. `tail_cap`'s slot is freed; the tail
/// `MemoryObject` is dec-ref'd without buddy-freeing the underlying
/// physical region (parent now covers it).
///
/// Used by memmgr to coalesce free-pool runs after `RELEASE_MEMORY_CAPS` and
/// `PROCESS_DIED` reclamation.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidArgument` (same slot or
/// object, rights or ownership-flag mismatch, not contiguous, tail not
/// virgin, not siblings, or either has children), `InvalidCapability` (also a
/// cap a concurrent delete freed before the merge took the derivation lock),
/// `InvalidState` (a `cap_revoke`, `cap_move`, or IPC capability transfer is
/// in flight on either cap), or `InsufficientRights` (either cap lacks Map).
#[inline]
pub fn memory_merge(parent_cap: u32, tail_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; both caps are u32 cap indices;
    // kernel validates contiguity, rights, and derivation invariants.
    let ret = unsafe {
        syscall3(
            SYS_MEMORY_MERGE,
            u64::from(parent_cap),
            u64::from(tail_cap),
            0,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Split `mmio_cap` into two non-overlapping child `Mmio` caps.
///
/// `split_offset` is in bytes and must be page-aligned, > 0, and < the region
/// size. The original cap is consumed. Returns `(lower_handle, upper_handle)`,
/// two capability handles: the lower covers `[base, base+split_offset)` and
/// the upper `[base+split_offset, end)`.
///
/// Consuming the original frees its object, which unmaps every [`mmio_map`]
/// mapping made through it, with TLB shootdown, before the call returns
/// (or, when a concurrent syscall still pins the object, when that syscall
/// releases it); a caller that needs the region mapped maps it again through
/// a child (`core/kernel/docs/syscalls.md` § `SYS_MMIO_SPLIT`). The
/// withdrawal reaches no Rust object, because [`mmio_map`]'s `# Safety`
/// contract keeps Rust references out of every MMIO mapping, so this wrapper
/// is safe.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid
/// (`InvalidCapability`) or lacks Map (`InsufficientRights`), or
/// `split_offset` is not page-aligned or out of range for the region
/// (`InvalidArgument`).
///
/// The split consumes the original under the derivation lock. `InvalidState`
/// if a concurrent delete removed the original or a `SYS_CAP_REVOKE`,
/// `SYS_CAP_MOVE`, or IPC capability transfer on it is in flight;
/// `Interrupted` if a concurrent deriver extended its child list faster than
/// the batched reparent could move it (retry); `OutOfMemory` if the caller's
/// `CSpace` cannot back two more slots (`QuotaExceeded` at the structural
/// ceiling).
// cast_sign_loss: proven non-negative in Ok branch.
// cast_possible_truncation: each returned handle is 32 bits (a 24-bit slot index
// plus an 8-bit generation).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn mmio_split(mmio_cap: u32, split_offset: u64) -> Result<(u32, u32), i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; mmio_cap is cap index as
    // u64, split_offset is byte offset; kernel validates cap and offset and returns
    // the first child handle in the primary register, the second in the secondary.
    let (ret, handle2) =
        unsafe { syscall5_ret2(SYS_MMIO_SPLIT, u64::from(mmio_cap), split_offset, 0, 0, 0) };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        Ok((ret as u32, handle2 as u32))
    }
}

/// Split an `Interrupt` range cap into two non-overlapping children.
///
/// `split_at` is the first IRQ id of the upper child (and the exclusive
/// upper bound of the lower child); it must satisfy
/// `start < split_at < start + count` on the cap being split. The
/// original cap is consumed on success; both children inherit the parent's
/// rights. Returns `(lower_handle, upper_handle)`, two capability handles.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid
/// (`InvalidCapability`) or lacks Notify (`InsufficientRights`), or
/// `split_at` falls outside the cap's range (`InvalidArgument`).
///
/// The split consumes the original under the derivation lock. `InvalidState`
/// if a concurrent delete removed the original or a `SYS_CAP_REVOKE`,
/// `SYS_CAP_MOVE`, or IPC capability transfer on it is in flight;
/// `Interrupted` if a concurrent deriver extended its child list faster than
/// the batched reparent could move it (retry); `OutOfMemory` if the caller's
/// `CSpace` cannot back two more slots (`QuotaExceeded` at the structural
/// ceiling).
// cast_sign_loss / cast_possible_truncation: identical to `mmio_split`.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn irq_split(irq_cap: u32, split_at: u32) -> Result<(u32, u32), i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; kernel validates cap and
    // split point, returning the two child handles in the primary/secondary registers.
    let (ret, handle2) = unsafe {
        syscall5_ret2(
            SYS_IRQ_SPLIT,
            u64::from(irq_cap),
            u64::from(split_at),
            0,
            0,
            0,
        )
    };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        Ok((ret as u32, handle2 as u32))
    }
}

/// Split an `IoPort` cap into two non-overlapping children.
///
/// `split_at` is the first port of the upper child (and the exclusive upper
/// bound of the lower child); it must satisfy `base < split_at < base + size`
/// on the cap being split, with `size == 0` interpreted as the full 64K
/// range. Additionally `split_at` must be non-zero (a zero split would
/// yield an empty lower half) and lie in `1..=0xFFFF`; the kernel rejects
/// values outside that range with `InvalidArgument` before loading the cap.
/// The original cap is consumed on success; both children inherit the
/// parent's rights. Returns `(lower_handle, upper_handle)`, two capability
/// handles. Consuming the original withdraws every [`ioport_bind`] binding
/// made through it, from every bound thread on every CPU (the caller
/// included); bind a child to keep the port access
/// (`core/kernel/docs/syscalls.md` § `SYS_IOPORT_SPLIT`).
///
/// On RISC-V: always returns `NotSupported`.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid
/// (`InvalidCapability`) or lacks Use (`InsufficientRights`), `split_at`
/// falls outside the cap's range (`InvalidArgument`), or the syscall is not
/// supported on this architecture (`NotSupported`).
///
/// The split consumes the original under the derivation lock. `InvalidState`
/// if a concurrent delete removed the original or a `SYS_CAP_REVOKE`,
/// `SYS_CAP_MOVE`, or IPC capability transfer on it is in flight;
/// `Interrupted` if a concurrent deriver extended its child list faster than
/// the batched reparent could move it (retry); `OutOfMemory` if the caller's
/// `CSpace` cannot back two more slots (`QuotaExceeded` at the structural
/// ceiling).
// cast_sign_loss / cast_possible_truncation: identical to `mmio_split`.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn ioport_split(ioport_cap: u32, split_at: u16) -> Result<(u32, u32), i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; kernel validates cap and
    // split point, returning the two child handles in the primary/secondary registers.
    let (ret, handle2) = unsafe {
        syscall5_ret2(
            SYS_IOPORT_SPLIT,
            u64::from(ioport_cap),
            u64::from(split_at),
            0,
            0,
            0,
        )
    };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        Ok((ret as u32, handle2 as u32))
    }
}

/// Split a `SchedControl` cap into two children covering disjoint priority bands.
///
/// `split_at` is the lowest priority level of the upper child (and one past the
/// top of the lower child); it must satisfy `min < split_at <= max` on the cap
/// being split. The lower child covers `[min, split_at - 1]`, the upper child
/// `[split_at, max]`. The original cap is consumed on success. Returns
/// `(lower_handle, upper_handle)`, two capability handles. `cap_derive` cannot
/// narrow a band, so this is the only way to hand out a sub-band.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid or `split_at`
/// falls outside the cap's band.
///
/// The split consumes the original under the derivation lock. `InvalidState`
/// if a concurrent delete removed the original or a `SYS_CAP_REVOKE`,
/// `SYS_CAP_MOVE`, or IPC capability transfer on it is in flight;
/// `Interrupted` if a concurrent deriver extended its child list faster than
/// the batched reparent could move it (retry); `OutOfMemory` if the caller's
/// `CSpace` cannot back two more slots (`QuotaExceeded` at the structural
/// ceiling).
// cast_sign_loss / cast_possible_truncation: identical to `mmio_split`.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn sched_split(sched_cap: u32, split_at: u8) -> Result<(u32, u32), i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; kernel validates cap and
    // split point, returning the two child handles in the primary/secondary registers.
    let (ret, handle2) = unsafe {
        syscall5_ret2(
            SYS_SCHED_SPLIT,
            u64::from(sched_cap),
            u64::from(split_at),
            0,
            0,
            0,
        )
    };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        Ok((ret as u32, handle2 as u32))
    }
}

/// Set the entry point, stack, and initial argument for a thread cap.
///
/// The thread must be in `Created` state (not yet started). Call
/// [`thread_start`] afterwards to make it runnable. The thread starts with
/// `tls_base == 0` (no TLS); use [`thread_configure_with_tls`] when the
/// thread needs a preset thread-local-storage pointer.
///
/// # Safety
/// The contract of [`thread_configure_with_tls`], with `tls_base` 0.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` if the thread cap
/// is invalid, `InsufficientRights` if it lacks Control rights, or
/// `InvalidArgument` if the thread is not in `Created` state, `entry` is at or
/// above the user VA top, or `stack_ptr`, as passed or after rounding to the
/// entry ABI's stack alignment, is above it (`core/kernel/docs/arch-interface.md`
/// § `context` gives each architecture's `align_initial_stack`).
#[inline]
pub unsafe fn thread_configure(
    thread_cap: u32,
    entry: u64,
    stack_ptr: u64,
    arg: u64,
) -> Result<(), i64>
{
    // SAFETY: the caller's contract is `thread_configure_with_tls`'s with
    // `tls_base` 0, which names no TLS block.
    unsafe { thread_configure_with_tls(thread_cap, entry, stack_ptr, arg, 0) }
}

/// Same as [`thread_configure`] but also sets the initial `tls_base`.
///
/// `tls_base` is loaded into `IA32_FS_BASE` (x86-64) or `tp` (RISC-V) when
/// the thread first runs. Pass `0` for a thread that does not use TLS.
///
/// # Safety
/// When the thread is bound to the calling program's own address space, the
/// thread, once started, runs on what these arguments name, so:
/// - `entry` must be the address of a function with the entry ABI the kernel
///   starts a thread on (`extern "C" fn(u64) -> !`, taking `arg`), which does
///   not return;
/// - `stack_ptr` must be the top of a stack dedicated to this thread from its
///   start until it exits: no live Rust object and no other thread's stack
///   lies in the part the thread uses;
/// - `tls_base` must be 0 or the thread pointer of a TLS block dedicated to
///   this thread in the same way, laid out as the program's TLS model
///   requires.
///
/// A thread bound to another address space touches none of the calling
/// program's memory, and a call the kernel refuses configures nothing.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` if the thread cap
/// is invalid, `InsufficientRights` if it lacks Control rights, or
/// `InvalidArgument` if the thread is not in `Created` state, `entry` or
/// `tls_base` is at or above the user VA top, or `stack_ptr`, as passed or
/// after rounding to the entry ABI's stack alignment, is above it (see
/// [`thread_configure`]).
#[inline]
pub unsafe fn thread_configure_with_tls(
    thread_cap: u32,
    entry: u64,
    stack_ptr: u64,
    arg: u64,
    tls_base: u64,
) -> Result<(), i64>
{
    // SAFETY: syscall5 issues the raw syscall; every argument is a scalar the
    // kernel validates (cap index, entry point, stack pointer, initial arg, tls
    // base). The caller's contract dedicates the entry, stack, and TLS block,
    // the raw-wrapper contract's thread-entry clause.
    let ret = unsafe {
        syscall5(
            SYS_THREAD_CONFIGURE,
            u64::from(thread_cap),
            entry,
            stack_ptr,
            arg,
            tls_base,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Move a configured `Created` thread, or a `Stopped` one (resume), to
/// `Ready` (enqueue it).
///
/// The thread must have been configured via [`thread_configure`] first.
///
/// A `Stopped` thread whose fault episode a stop cancelled before any reply
/// claimed it, or whose handler's claiming reply was `FAULT_REPLY_KILL`, is
/// not resumed: starting it kills it as an unhandled fault, which posts its
/// death and address-space observers (docs/fault-handling.md § Delivery,
/// Resume, and Kill).
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid
/// (`InvalidCapability`) or lacks Control rights (`InsufficientRights`); if
/// the thread has not been configured yet, is the calling thread itself, or
/// is not `Created`/`Stopped` under the locked commit — including one a
/// concurrent start already resumed, or one that exited or was killed by an
/// object teardown after the first check (`InvalidArgument`); or `-16`
/// (`Interrupted`) if the calling thread is stopped while the start waits for
/// the target to leave its CPU or for an owed wake: the caller is descheduled
/// in place and sees `Interrupted` once restarted; nothing was started and a
/// retry is safe.
#[inline]
pub fn thread_start(thread_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; thread_cap is cap index as u64;
    // kernel validates cap and enqueues thread.
    let ret = unsafe { syscall2(SYS_THREAD_START, u64::from(thread_cap), 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Copy a capability slot from the calling thread's `CSpace` into another `CSpace`.
///
/// - `src_slot`: capability handle (slot index plus generation) of the source
///   in the caller's `CSpace`.
/// - `dest_cspace_cap`: capability handle of the destination `CSpace`.
/// - `rights_mask`: bitmask of rights to grant. The effective rights are the
///   intersection of this mask and the source cap's rights — pass `RIGHTS_ALL`
///   to copy with the same rights as the source.
///
/// Returns the new capability's handle in the destination `CSpace` (slot
/// index and generation, per docs/capability-model.md § Capability Handle
/// Format). The copy of an `Mmio` or `IoPort` capability references a fresh
/// object over the same range, so mappings and port bindings made through it
/// are withdrawn when it goes (docs/capability-model.md § Mmio).
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, the caller
/// lacks sufficient rights, or the destination `CSpace`'s slot pool cannot
/// back a fresh slot (`OutOfMemory`; refill it with `cap_create_cspace` in
/// augment mode; `QuotaExceeded` at the structural ceiling). For an `Mmio` or
/// `IoPort` source, `QuotaExceeded` also means its range already has 64 live
/// copies, and `OutOfMemory` that the kernel's SEED reserve cannot back the
/// fresh object; for any other source, `QuotaExceeded` also means the object's
/// reference count is at its 2^31 ceiling. `InvalidCapability`
/// also covers a source a concurrent delete, move, or revoke freed before the
/// copy was linked; `InvalidState` means a `cap_revoke`, `cap_move`, or IPC
/// capability transfer is in flight on the source.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_copy(src_slot: u32, dest_cspace_cap: u32, rights_mask: u64) -> Result<u32, i64>
{
    // SAFETY: syscall4 issues raw syscall instruction; all arguments are scalar u64 values
    // (source handle, dest CSpace cap, dest slot, rights mask); a dest slot of 0 asks the
    // kernel to allocate a free slot, whose handle it returns.
    let ret = unsafe {
        syscall4(
            SYS_CAP_COPY,
            u64::from(src_slot),
            u64::from(dest_cspace_cap),
            0,
            rights_mask,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Attenuate a capability within the caller's own `CSpace` (`SYS_CAP_DERIVE`).
///
/// Creates a new slot in the caller's `CSpace` with `rights_mask & src_rights`.
/// The new slot is a derivation child of the source; for an `Mmio` or `IoPort`
/// source it references a fresh object over the same range, as for
/// [`cap_copy`].
///
/// Returns the new capability handle (slot index plus generation).
///
/// # Errors
/// Returns a negative `i64` error code if the source cap is invalid or the
/// `CSpace`'s slot pool cannot back a fresh slot (`OutOfMemory`; `QuotaExceeded` at the
/// structural ceiling), or, as for [`cap_copy`], `QuotaExceeded` past 64 live
/// copies of an `Mmio` or `IoPort` source's range or at any other source
/// object's 2^31 reference-count ceiling, and `OutOfMemory` when SEED cannot
/// back an `Mmio` or `IoPort` object. `InvalidCapability` also covers a source a concurrent
/// delete, move, or revoke freed before the new slot was linked;
/// `InvalidState` means a `cap_revoke`, `cap_move`, or IPC capability
/// transfer is in flight on the source.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn cap_derive(src_slot: u32, rights_mask: u64) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; src_slot is cap index as u64, rights_mask
    // is bitmask; kernel validates cap, creates attenuated derivative, returns its cap handle.
    let ret = unsafe { syscall2(SYS_CAP_DERIVE, u64::from(src_slot), rights_mask) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Derive a capability with a badge attached (`SYS_CAP_DERIVE_BADGE`).
///
/// Creates a new slot in the caller's `CSpace` with attenuated rights and the
/// specified `badge` value. The badge is delivered to the receiver on `ipc_recv`
/// when the capability is used for IPC.
///
/// `badge` must be non-zero. The source capability must have `badge == 0`
/// (no re-badging).
///
/// # Errors
/// Returns a negative `i64` error code if the source cap is invalid, the badge
/// is zero, the source already has a badge, or the `CSpace`'s slot pool cannot
/// back a fresh slot (`OutOfMemory`; `QuotaExceeded` at the structural ceiling),
/// or as for [`cap_copy`] (the `Mmio` and `IoPort` copy limits, and any other
/// source object's 2^31 reference-count ceiling).
/// `InvalidCapability` also covers a source a concurrent delete, move, or
/// revoke freed before the new slot was linked; `InvalidState` means a
/// `cap_revoke`, `cap_move`, or IPC capability transfer is in flight on the
/// source.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn cap_derive_badge(src_slot: u32, rights_mask: u64, badge: u64) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; src_slot is cap index, rights_mask
    // is bitmask, badge is the badge value; kernel validates and creates badged derivative.
    let ret = unsafe {
        syscall3(
            SYS_CAP_DERIVE_BADGE,
            u64::from(src_slot),
            rights_mask,
            badge,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Delete a capability slot in the caller's `CSpace` (`SYS_CAP_DELETE`).
///
/// Reparents child derivations to the deleted slot's parent (in batches, the
/// derivation lock released between them), unlinks from the derivation tree,
/// and dec-refs the kernel object. Idempotent on Null slots.
///
/// Deleting the last capability to the caller's own `CSpace` or
/// `AddressSpace` (directly, or through the teardown cascade) stops the
/// caller: the call never returns (or, when another thread's syscall still
/// pins the object, returns, and the stop follows when that syscall
/// releases it; likewise when an `Mmio` capability's object records a mapping
/// into that `AddressSpace`, the stop following when that object is freed).
/// Deleting an `Mmio` or `IoPort` capability unmaps the mappings and withdraws
/// the port bindings made through it. Deleting the caller's own Thread
/// capability is refused instead. A teardown of a Thread left `current` on a
/// CPU that `fatal` halted, or of a `CSpace` or `AddressSpace` with such a
/// thread bound, never completes, so the call does not return
/// (`core/kernel/docs/syscalls.md` § `SYS_CAP_DELETE`).
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` if the handle
/// is out of range or carries a stale generation (deleting a Null slot
/// succeeds); `InvalidState` if the slot names the caller's own thread or a
/// `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer on it is in
/// flight; `Interrupted` if a concurrent deriver extended the slot's child
/// list faster than the batched reparent could move it (retry).
pub fn cap_delete(slot: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; slot is cap index as u64;
    // kernel validates slot, unlinks from derivation tree, dec-refs object.
    let ret = unsafe { syscall2(SYS_CAP_DELETE, u64::from(slot), 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Revoke all capabilities derived from a slot (`SYS_CAP_REVOKE`).
///
/// Clears the entire descendant subtree; the root slot is preserved. A
/// revoked capability that was an object's last reference tears the object
/// down as [`cap_delete`] describes, including the cases in which the call
/// never returns.
///
/// # Errors
/// - `InvalidCapability` (-2) — the handle names no live slot, or its
///   generation is stale.
/// - `InvalidState` (-15) — another revoke, a move, or an IPC capability
///   transfer is already in flight on this slot, or the kernel found a
///   corrupted derivation link (the revoke is incomplete).
/// - `Interrupted` (-16) — the kernel's liveness backstop tripped: the
///   subtree was larger than one call covers (about 1.3 × 10^8 nodes), or
///   concurrent derivation kept extending it; everything revoked so far stays
///   revoked, and a retry continues (see [`cap_revoke_all`]).
pub fn cap_revoke(slot: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; slot is cap index as u64;
    // kernel validates slot and revokes entire descendant subtree.
    let ret = unsafe { syscall2(SYS_CAP_REVOKE, u64::from(slot), 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// [`cap_revoke`], retried while the kernel reports `Interrupted` (the
/// multi-batch liveness backstop) — each retry continues clearing the
/// surviving subtree, so the loop finishes on a fixed subtree, however large,
/// and once concurrent derivation stops. The call sites that must fully clear
/// a subtree before releasing its root (teardown/reclaim paths) use this form.
///
/// Retries are bounded: each `Interrupted` round already represents ~10^8
/// kernel-side edits, so 4096 rounds cover a fixed subtree of about 5 × 10^11
/// nodes (some 36 TB of 72-byte slots), and exhausting the bound means an
/// adversarial deriver is outpacing revocation — the caller gets the
/// final `Interrupted` back rather than this wrapper spinning forever.
///
/// # Errors
/// As for [`cap_revoke`]; `Interrupted` only after the retry bound.
pub fn cap_revoke_all(slot: u32) -> Result<(), i64>
{
    const MAX_RETRIES: u32 = 4096;
    let mut last = Ok(());
    for _ in 0..MAX_RETRIES
    {
        last = cap_revoke(slot);
        match last
        {
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {}
            other => return other,
        }
    }
    last
}

/// Move a capability to another `CSpace` (`SYS_CAP_MOVE`).
///
/// `src_cap` is a capability handle (generation-checked). `dest_index` = 0
/// auto-allocates a slot; non-zero inserts at that index. The source slot
/// is cleared and every capability derived from it follows the move; the
/// object refcount is unchanged.
///
/// Returns the destination capability handle.
///
/// With a non-zero `dest_index`, if every other reference to the destination
/// `CSpace` goes while the call is backing the leaves up to it, the call
/// reclaims that `CSpace` and returns `InvalidCapability`; when the caller
/// itself is bound to it, the caller is stopped and the call never returns.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` if either cap is
/// invalid or stale, or an ancestor's revoke freed the capability while the
/// move was in flight; `InsufficientRights` if the destination `CSpace` cap
/// lacks Insert; `InvalidArgument` if `dest_index` is occupied or out of
/// range (including above `CAP_INDEX_MASK`); `OutOfMemory` if the
/// destination's slot pool cannot back the slot (for a non-zero
/// `dest_index`, every leaf up to that index must be backed;
/// `QuotaExceeded` at the structural ceiling, or when the object's reference
/// count is at its 2^31 ceiling, since the destination takes its reference
/// before the source releases its own);
/// `InvalidState` if a revoke, another move, or an IPC capability transfer
/// is in flight on the source, or the destination slot was freed mid-move
/// (the source keeps the capability);
/// `Interrupted` if a concurrent deriver kept extending the child list past
/// the kernel's batch backstop — the capability then lives in both slots,
/// the destination a derived child of the source, and a `cap_revoke` on the
/// source reclaims it.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn cap_move(src_cap: u32, dest_cspace_cap: u32, dest_index: u32) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; all arguments are scalar u64 values
    // (source handle, dest CSpace cap, dest index); kernel validates and moves cap, returns
    // the destination cap handle.
    let ret = unsafe {
        syscall3(
            SYS_CAP_MOVE,
            u64::from(src_cap),
            u64::from(dest_cspace_cap),
            u64::from(dest_index),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Insert a capability at a specific slot index in another `CSpace`.
///
/// Like `cap_copy` but the destination slot index is caller-chosen — a
/// shorthand over `SYS_CAP_COPY` with a non-zero destination slot.
///
/// If every other reference to the destination `CSpace` goes while the call
/// is backing the leaves up to `dest_index`, the call reclaims it and
/// returns `InvalidCapability`; when the caller itself is bound to that
/// `CSpace`, the caller is stopped and the call never returns.
///
/// Returns the new capability's handle in the destination `CSpace`: its slot
/// index is `dest_index` and its generation is the slot's current one, which
/// advances each time the slot is recycled, so the handle, not the bare
/// index, addresses the capability (docs/capability-model.md § Capability
/// Handle Format).
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, the caller
/// lacks sufficient rights, `dest_index` is 0, already occupied, or out of
/// range, including above `CAP_INDEX_MASK` (`InvalidArgument`; the wrapper
/// returns it for 0 without a syscall), or the destination
/// `CSpace`'s slot pool cannot back every leaf up to `dest_index`
/// (`OutOfMemory`; `QuotaExceeded` at the structural ceiling), or as for
/// [`cap_copy`] (`QuotaExceeded` at the copy limits and the 2^31
/// reference-count ceiling). `InvalidCapability` also covers a source a
/// concurrent delete, move, or revoke freed before the copy was linked; `InvalidState` means a
/// `cap_revoke`, `cap_move`, or IPC capability transfer is in flight on the
/// source.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn cap_insert(
    src_slot: u32,
    dest_cspace_cap: u32,
    dest_index: u32,
    rights_mask: u64,
) -> Result<u32, i64>
{
    // The kernel reads a destination of 0 as "allocate a slot", which would
    // place the copy elsewhere.
    if dest_index == 0
    {
        return Err(SyscallError::InvalidArgument as i64);
    }
    // SAFETY: syscall4 issues raw syscall instruction; all arguments are scalar u64 values
    // (source slot, dest CSpace cap, dest slot, rights mask); kernel validates and inserts cap
    // at the caller-chosen slot and returns its handle.
    let ret = unsafe {
        syscall4(
            SYS_CAP_COPY,
            u64::from(src_slot),
            u64::from(dest_cspace_cap),
            u64::from(dest_index),
            rights_mask,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Query system information by `SystemInfoType` discriminant.
///
/// `kind` is the `u64` value of the desired [`syscall_abi::SystemInfoType`]
/// variant. Returns the queried value as a `u64` on success.
///
/// # Example
/// ```no_run
/// use syscall::system_info;
/// // KernelVersion = 0; packed (major << 32) | (minor << 16) | patch
/// let ver = system_info(0).unwrap();
/// let major = ver >> 32;
/// let minor = (ver >> 16) & 0xFFFF;
/// let patch = ver & 0xFFFF;
/// ```
///
/// # Errors
/// Returns a negative `i64` error code if `kind` is an unknown variant.
// cast_sign_loss: ret is proven non-negative in the Ok branch.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn system_info(kind: u64) -> Result<u64, i64>
{
    // Unused second arg is required because no syscall1 raw variant exists.
    // SAFETY: syscall2 issues raw syscall instruction; kind is SystemInfoType discriminant as u64;
    // kernel validates kind and returns queried value.
    let ret = unsafe { syscall2(SYS_SYSTEM_INFO, kind, 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

/// Inspect a capability slot's runtime state.
///
/// `slot` — capability handle (slot index plus generation) in the caller's
/// `CSpace`; generation-checked.
/// `field` — field selector (one of the `CAP_INFO_*` constants in
/// `syscall_abi`). Each call returns a single `u64`. Userspace assembles
/// a full picture by issuing repeated calls. The pattern mirrors
/// [`system_info`].
///
/// # Field semantics
/// - `CAP_INFO_TAG_RIGHTS` is valid for any non-null slot and returns
///   `((tag as u8 as u64) << 32) | (rights as u32 as u64)`.
/// - `CAP_INFO_TLB_ELIDED` and `CAP_INFO_TLB_PERFORMED` are system-wide
///   counters: they accept any live slot, whatever its tag.
/// - All other selectors are tag-specific:
///   - `CAP_INFO_MEMORY_*` require `CapTag::Memory`.
///   - `CAP_INFO_ASPACE_*` require `CapTag::AddressSpace`.
///   - `CAP_INFO_CSPACE_*` require `CapTag::CSpace`.
///   - `CAP_INFO_THREAD_STATE` requires `CapTag::Thread`.
///
/// Calling a tag-specific field on a slot whose tag does not match
/// returns `SyscallError::InvalidArgument` (-5). Unknown selectors return
/// the same error.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` if the handle is
/// null, out of range, or stale, the slot is empty, or the object the slot
/// references is gone; `InvalidArgument` if the selector is unknown or
/// requires a different capability tag.
// cast_sign_loss: ret is proven non-negative in the Ok branch.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn cap_info(slot: u32, field: u64) -> Result<u64, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; slot is a cap handle as u64,
    // field is one of the CAP_INFO_* selectors. The kernel performs all validation
    // (slot bounds and generation, tag match for tag-specific fields, selector
    // recognition) and returns the requested field value.
    let ret = unsafe { syscall2(SYS_CAP_INFO, u64::from(slot), field) };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

/// Translate a virtual address in an address space to its mapped physical address.
///
/// `aspace_cap` — capability handle (slot index plus generation) of the
/// `AddressSpace` (must have READ right).
/// `virt` — page-aligned virtual address in the user half.
///
/// Returns the physical address on success, or a negative `SyscallError`
/// code if the address is not mapped or the cap is invalid.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidAddress` (`virt` unaligned,
/// outside the user half, or not currently mapped), `InvalidCapability`, or
/// `InsufficientRights` (cap lacks READ).
// cast_sign_loss: ret is proven non-negative in the Ok branch.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn aspace_query(aspace_cap: u32, virt: u64) -> Result<u64, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; aspace_cap is cap index as u64, virt is
    // virtual address; kernel validates cap and mapping, returns physical address.
    let ret = unsafe { syscall2(SYS_ASPACE_QUERY, u64::from(aspace_cap), virt) };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

// ── Event Queue wrappers ──────────────────────────────────────────────────────

/// Retype a Memory cap into a new `EventQueue` with the given capacity (1..=4096).
///
/// `memory_cap` MUST carry `RIGHTS_MEM_RETYPE`; the wrapper, state, and ring
/// buffer all live inline in the same retype slot. Sub-page in-place when
/// the total fits in `BIN_512` (capacity ≤ 53), page-aligned split for
/// larger rings.
///
/// # Errors
/// Returns a negative `i64` error code if `memory_cap` is invalid, lacks
/// `RIGHTS_MEM_RETYPE`, has insufficient `available_bytes`, `capacity` is out
/// of range, or the `CSpace`'s slot pool cannot back a fresh slot
/// (`OutOfMemory`; `QuotaExceeded` at the structural ceiling). `QuotaExceeded`
/// also means the Memory object's reference count is at its 2^31 ceiling.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn event_queue_create(memory_cap: u32, capacity: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; arg0 = source Memory
    // cap slot, arg1 = capacity. Kernel retypes the region.
    let ret = unsafe {
        syscall2(
            SYS_CAP_CREATE_EVENT_Q,
            u64::from(memory_cap),
            u64::from(capacity),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Append `payload` to an event queue (non-blocking).
///
/// Returns `SyscallError::QueueFull` (-13) if the queue is at capacity.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability`,
/// `InsufficientRights` (cap lacks Post), or `QueueFull`.
#[inline]
pub fn event_post(queue_cap: u32, payload: u64) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; queue_cap is cap index as u64, payload
    // is opaque data; kernel validates cap and enqueues payload (non-blocking).
    let ret = unsafe { syscall2(SYS_EVENT_POST, u64::from(queue_cap), payload) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Dequeue the next entry from an event queue, blocking until a post arrives.
///
/// Returns the payload word. The primary return register holds 0 on success;
/// the payload is in the secondary return register (rdx / a1).
///
/// # Errors
/// Returns a negative `i64` error code if the queue cap is invalid or lacks
/// Recv rights; `-16` (`Interrupted`) if the caller is stopped while waiting
/// or the queue is destroyed under it.
#[inline]
pub fn event_recv(queue_cap: u32) -> Result<u64, i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; arg1 = 0 is the
    // "block forever" sentinel for `SYS_EVENT_RECV` (matches `SYS_NOTIFICATION_WAIT`).
    let (ret, payload) = unsafe { syscall5_ret2(SYS_EVENT_RECV, u64::from(queue_cap), 0, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(payload) }
}

/// Non-blocking dequeue. Returns `Err(-6)` (`WouldBlock`) when the queue is
/// empty; otherwise returns the payload.
///
/// # Errors
/// Returns `-6` (`WouldBlock`) if the queue is empty, or `InvalidCapability`
/// or `InsufficientRights` (cap lacks Recv).
#[inline]
pub fn event_try_recv(queue_cap: u32) -> Result<u64, i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; arg1 = u64::MAX
    // is the "non-blocking try-once" sentinel for `SYS_EVENT_RECV`.
    let (ret, payload) =
        unsafe { syscall5_ret2(SYS_EVENT_RECV, u64::from(queue_cap), u64::MAX, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(payload) }
}

/// Dequeue with a timeout. `timeout_ms == 0` blocks indefinitely (same as
/// [`event_recv`]); `timeout_ms == u64::MAX` is a non-blocking poll (same as
/// [`event_try_recv`]); any other value blocks for up to `timeout_ms`
/// milliseconds, then returns `Err(-6)` (`WouldBlock`) if no post arrived
/// (at once if the kernel's sleep list is full when the wait parks).
///
/// # Errors
/// Returns `-6` (`WouldBlock`) on timeout or empty try-once; `-16`
/// (`Interrupted`) if the caller is stopped while waiting or the queue is
/// destroyed under it; or another negative `i64` error code if the queue cap
/// is invalid or lacks Recv rights.
#[inline]
pub fn event_recv_timeout(queue_cap: u32, timeout_ms: u64) -> Result<u64, i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; arg1 carries the
    // timeout sentinel directly to the kernel.
    let (ret, payload) =
        unsafe { syscall5_ret2(SYS_EVENT_RECV, u64::from(queue_cap), timeout_ms, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(payload) }
}

// ── Wait Set wrappers ─────────────────────────────────────────────────────────

/// Retype a Memory cap into a new `WaitSet` with `MODIFY | WAIT` rights.
///
/// `memory_cap` MUST carry `RIGHTS_MEM_RETYPE` and have ≥ 512 bytes of
/// `available_bytes` (the `BIN_512` size class debited from the ledger).
///
/// # Errors
/// Returns a negative `i64` error code if `memory_cap` is invalid, lacks
/// `RIGHTS_MEM_RETYPE`, or the `CSpace`'s slot pool cannot back a fresh slot
/// (`OutOfMemory`; `QuotaExceeded` at the structural ceiling). `QuotaExceeded`
/// also means the Memory object's reference count is at its 2^31 ceiling.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative cap handle —
// a 24-bit slot index plus an 8-bit generation (`CAP_INDEX_BITS + 8 <= 32`),
// so it fits u32.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn wait_set_create(memory_cap: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; arg0 = source Memory
    // cap slot. Kernel retypes the region.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_WAIT_SET, u64::from(memory_cap), 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Register `source_cap` (Endpoint/Notification/EventQueue) in `ws_cap` with a
/// caller-chosen opaque `badge`. The badge is returned by `wait_set_wait`
/// when this source fires.
///
/// Returns `SyscallError::InvalidArgument` (-5) if the wait set is full
/// or the source is already in a wait set.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability`,
/// `InsufficientRights` (wait set lacks Modify, or the source lacks its
/// receive right), or `InvalidArgument` (the wait set is full, or the source
/// is already in a wait set).
#[inline]
pub fn wait_set_add(ws_cap: u32, source_cap: u32, badge: u64) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; all arguments are scalar u64 values
    // (wait set cap, source cap, opaque badge); kernel validates caps and registers source.
    let ret = unsafe {
        syscall3(
            SYS_WAIT_SET_ADD,
            u64::from(ws_cap),
            u64::from(source_cap),
            badge,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Remove `source_cap` from `ws_cap`.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid or
/// `source_cap` is not in the wait set.
#[inline]
pub fn wait_set_remove(ws_cap: u32, source_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; ws_cap and source_cap are cap indices as u64;
    // kernel validates caps and unregisters source from wait set.
    let ret = unsafe {
        syscall2(
            SYS_WAIT_SET_REMOVE,
            u64::from(ws_cap),
            u64::from(source_cap),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Block until any registered source in `ws_cap` becomes ready.
///
/// Returns the opaque badge chosen at `wait_set_add` time for the source that
/// fired. The badge is delivered in the secondary return register (rdx / a1).
/// If multiple sources are ready, each call returns one badge without re-blocking.
///
/// # Errors
/// Returns a negative `i64` error code if the wait set cap is invalid or lacks
/// Wait rights; `-15` (`InvalidState`) if another thread already waits on the
/// set (a wait set takes one waiter); `-16` (`Interrupted`) if the caller is
/// stopped while waiting or the wait set is destroyed under it.
#[inline]
pub fn wait_set_wait(ws_cap: u32) -> Result<u64, i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; ws_cap is cap index as u64;
    // kernel validates cap, blocks until source ready, returns badge in secondary register.
    let (ret, badge) = unsafe { syscall5_ret2(SYS_WAIT_SET_WAIT, u64::from(ws_cap), 0, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(badge) }
}

// ── Hardware access wrappers ──────────────────────────────────────────────────

/// Bind `notification_cap` to receive notifications when `irq_cap`'s interrupt fires.
///
/// After registration the IRQ is masked until the first `irq_ack`. The driver
/// must call `irq_ack` after servicing each interrupt to re-enable delivery.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid or lacks
/// Notify rights, or (`InvalidArgument`) if `irq_cap` covers more than one line
/// or names an id the kernel cannot route (outside GSIs 0–22 on x86-64, PLIC
/// sources 1–127 on RISC-V). A second registration of a line replaces the first.
#[inline]
pub fn irq_register(irq_cap: u32, notification_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; irq_cap and notification_cap are cap indices as u64;
    // kernel validates caps and binds IRQ to a notification for interrupt delivery.
    let ret = unsafe {
        syscall2(
            SYS_IRQ_REGISTER,
            u64::from(irq_cap),
            u64::from(notification_cap),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Re-enable interrupt delivery for `irq_cap` after handling the interrupt.
///
/// Must be called once the interrupt source in the device has been cleared,
/// otherwise the interrupt will fire again immediately on unmask.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability`,
/// `InsufficientRights` (cap lacks Notify), or `InvalidArgument` (the cap
/// covers more than one line).
#[inline]
pub fn irq_ack(irq_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; irq_cap is cap index as u64;
    // kernel validates cap and unmasks IRQ to re-enable delivery.
    let ret = unsafe { syscall2(SYS_IRQ_ACK, u64::from(irq_cap), 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Map `mmio_cap` into `aspace_cap` at virtual address `virt`.
///
/// - `virt` must be page-aligned and in the user address range.
/// - `flags` is reserved and ignored; the mapping is writable iff `mmio_cap`
///   carries the Write right, and never executable.
/// - All pages are mapped uncacheable (PCD|PWT on `x86_64`, Svpbmt
///   PBMT=IO on `riscv64`).
/// - The mapping lasts while `mmio_cap` does: deleting it, consuming it with a
///   split, or revoking an ancestor of it unmaps the mapping
///   (`core/kernel/docs/syscalls.md` § `SYS_MMIO_MAP`).
///
/// # Safety
/// The contract of [`mem_map`], for the span the MMIO region covers at
/// `virt`. Besides, the mapping can be withdrawn at any time: by this
/// program deleting or splitting the capability or revoking an ancestor of
/// it, or by any holder of an ancestor capability, in any process, revoking
/// it. When `aspace_cap` names the calling program's own address space, the
/// program therefore reaches the span only through raw-pointer accesses,
/// never through a Rust reference, and puts the span's virtual addresses to no
/// other use while such an access can still run. A withdrawn mapping then
/// reaches no Rust object, which is why [`cap_delete`], [`cap_revoke`], and
/// [`mmio_split`] stay safe functions.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidAddress` (`virt` unaligned or
/// non-canonical, or the range leaves the user half), `InvalidCapability`,
/// `InsufficientRights` (a cap lacks Map), `InvalidArgument` (MMIO region
/// size zero, unaligned, or overflowing), `QuotaExceeded` (the cap's object
/// already records 4 other mappings), or `OutOfMemory` (page-table growth
/// pool exhausted; refill with [`cap_create_aspace`] in augment mode). An
/// `OutOfMemory` failure keeps the mapping's record and the pages already
/// mapped; a retry at the same `virt` reuses the record.
#[inline]
pub unsafe fn mmio_map(aspace_cap: u32, mmio_cap: u32, virt: u64, flags: u64) -> Result<(), i64>
{
    // SAFETY: syscall4 issues the raw syscall; every argument is a scalar the
    // kernel validates (cap indices, virtual address, flags). The caller's
    // contract (`mem_map`'s) keeps the span off live Rust objects and the
    // registered IPC page, the raw-wrapper mapping clause.
    let ret = unsafe {
        syscall4(
            SYS_MMIO_MAP,
            u64::from(aspace_cap),
            u64::from(mmio_cap),
            virt,
            flags,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Bind `ioport_cap` to `thread_cap`, granting it in/out access to the port range.
///
/// On RISC-V this always returns an error (`NotSupported`).
///
/// The binding lasts while `ioport_cap` does: deleting it, consuming it with a
/// split, or revoking an ancestor of it withdraws the binding
/// (`core/kernel/docs/syscalls.md` § `SYS_IOPORT_BIND`).
///
/// # Errors
/// Returns a negative `i64` error code: `NotSupported` (RISC-V),
/// `InvalidCapability`, `InsufficientRights` (a cap lacks Control/Use),
/// `QuotaExceeded` (the thread already records 16 bindings through other
/// caps), or `OutOfMemory` (binding-table allocation).
#[inline]
pub fn ioport_bind(thread_cap: u32, ioport_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; thread_cap and ioport_cap are cap indices as u64;
    // kernel validates caps and grants I/O port access (x86-64 only; returns NotSupported on RISC-V).
    let ret = unsafe {
        syscall2(
            SYS_IOPORT_BIND,
            u64::from(thread_cap),
            u64::from(ioport_cap),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Stop a running, ready, or blocked thread. The thread transitions to `Stopped`.
///
/// If the thread was blocked (on IPC or in [`thread_sleep`]), or blocks while
/// the stop is in progress, the blocking syscall returns `Interrupted` once
/// the thread is restarted, unless its wake was claimed first, or a timed
/// wait or sleep that found the kernel's sleep list full withdrew itself
/// first (it then returns its timeout or `OutOfMemory`); the full contract is
/// in `core/kernel/docs/syscalls.md` § `SYS_THREAD_STOP`. A thread may stop
/// itself (pass its own thread cap).
///
/// If the thread is blocked on a fault, its fault episode is cancelled with a
/// kill outcome, unless the handler's reply claimed it first, in which case
/// that reply's outcome is kept; no syscall returns on the target, and the
/// outcome takes effect at the next [`thread_start`], which kills the thread
/// on a kill outcome and resumes its faulting instruction on
/// `FAULT_REPLY_RESUME` (docs/fault-handling.md § Delivery, Resume, and
/// Kill).
///
/// If the thread is running on another CPU, the call returns once that CPU
/// has descheduled it and published its register save, or once an object
/// teardown, or the target's own exit, has made it `Exited` (a stop landing
/// inside the target's exit returns `Ok`, and the exit commits `Exited` over
/// it, so a later [`thread_start`] returns `InvalidArgument`). A caller that is
/// itself stopped while it
/// waits returns at once when restarted if `thread_cap` no longer names the
/// target with Control rights, even while the target still runs, and
/// otherwise keeps waiting as above; [`thread_read_regs`] and
/// [`thread_write_regs`] refuse such a target with `InvalidState` until it
/// has left its CPU (`core/kernel/docs/syscalls.md`
/// § `SYS_THREAD_STOP`).
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid or lacks
/// Control rights, or `-15` (`InvalidState`) if the thread is not yet
/// started, already stopped, or exited.
#[inline]
pub fn thread_stop(thread_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; thread_cap is cap index as u64;
    // kernel validates cap and transitions thread to Stopped state.
    let ret = unsafe { syscall2(SYS_THREAD_STOP, u64::from(thread_cap), 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Change a thread's scheduling priority.
///
/// `priority` must be in `[1, PRIORITY_MAX]`. `sched_cap` must be a
/// `SchedControl` cap whose `[min, max]` band covers `priority`; it is always
/// required. There is no ambient priority authority — holding no `SchedControl`
/// (or one whose band excludes `priority`) cannot set any priority. Narrow a
/// band with [`sched_split`].
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid,
/// `priority` is out of range, `sched_cap` is not a `SchedControl`, or its band
/// does not cover `priority`.
#[inline]
pub fn thread_set_priority(thread_cap: u32, priority: u8, sched_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; all arguments are scalar u64 values
    // (thread cap, priority level, sched cap); kernel validates caps and priority range.
    let ret = unsafe {
        syscall3(
            SYS_THREAD_SET_PRIORITY,
            u64::from(thread_cap),
            u64::from(priority),
            u64::from(sched_cap),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Set a thread's CPU affinity.
///
/// `cpu_id` must be a valid CPU ID or `u32::MAX` (clear affinity / any CPU).
/// `thread_cap` must carry Control rights. Takes effect immediately: a Ready
/// thread queued on another CPU is migrated to the target CPU's run queue; a
/// Running thread on another CPU is sent a reschedule IPI and moves at its
/// next `schedule()` entry (worst case one time slice later); a blocked,
/// stopped, or not-yet-started thread observes the new affinity on its next
/// enqueue (a wake, or `SYS_THREAD_START` on start or resume).
///
/// See `core/kernel/docs/syscalls.md` § `SYS_THREAD_SET_AFFINITY` for the
/// call's full contract.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` if the thread cap
/// is invalid, `InsufficientRights` if it lacks Control rights, or
/// `InvalidArgument` if `cpu_id` names an offline or out-of-range CPU.
#[inline]
pub fn thread_set_affinity(thread_cap: u32, cpu_id: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; thread_cap and cpu_id are scalar u64 values;
    // kernel validates cap and CPU ID, sets thread affinity.
    let ret = unsafe {
        syscall2(
            SYS_THREAD_SET_AFFINITY,
            u64::from(thread_cap),
            u64::from(cpu_id),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Bind (or clear) a thread's per-thread fault-handler endpoint.
///
/// `endpoint_cap` is the `Endpoint` whose receiver services this thread's
/// kernel-unresolvable faults, or `0` to unbind. The fault message badge is
/// the derivation badge of `endpoint_cap`, so a handler attributes a fault by
/// which of its badged caps the binder bound (see [`syscall_abi::FAULT_LABEL`]
/// and `docs/fault-handling.md` § Security). `fault_class_mask` selects the
/// covered fault classes; pass [`syscall_abi::FAULT_CLASS_ALL`].
///
/// Requires `CONTROL` on `thread_cap`. See `docs/fault-handling.md`.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` (bad thread cap,
/// or `endpoint_cap` non-zero but not an `Endpoint`), `InsufficientRights`
/// (the thread cap lacks `CONTROL`), or `InvalidArgument` (`fault_class_mask`
/// other than `FAULT_CLASS_ALL`).
#[inline]
pub fn thread_set_fault_handler(
    thread_cap: u32,
    endpoint_cap: u32,
    fault_class_mask: u64,
) -> Result<(), i64>
{
    // SAFETY: syscall4 issues a raw syscall; all arguments are scalar values.
    // The kernel validates the caps and rebinds (or clears) the handler. arg2
    // is reserved and must be 0.
    let ret = unsafe {
        syscall4(
            SYS_THREAD_SET_FAULT_HANDLER,
            u64::from(thread_cap),
            u64::from(endpoint_cap),
            0,
            fault_class_mask,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Copy the register state of a stopped or fault-blocked thread into `buf`.
///
/// The thread must be `Stopped` and descheduled (off every CPU, its register
/// save published), or fault-blocked awaiting a fault-handler reply; a
/// `Stopped` thread still on a CPU is refused with `InvalidState`
/// (`core/kernel/docs/syscalls.md` § `SYS_THREAD_READ_REGS`). `buf` must be at
/// least `size_of::<TrapFrame>()` bytes (architecture-defined). Returns the
/// number of bytes written on success.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` (the thread cap
/// is invalid), `InsufficientRights` (it lacks Observe), `InvalidState` (the
/// thread is neither fault-blocked nor `Stopped` and descheduled),
/// `InvalidArgument` (`buf` is shorter than the frame, or the thread has no
/// register frame), or `InvalidAddress` (`buf` is not wholly in the user half
/// or not mapped writable).
// cast_sign_loss: ret is proven non-negative in the Ok branch; it is a byte count.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn thread_read_regs(thread_cap: u32, buf: &mut [u8]) -> Result<u64, i64>
{
    // SAFETY: syscall3 issues the raw syscall; `buf` is a live, exclusively
    // borrowed slice, so the kernel's writes of at most `buf.len()` bytes land
    // in memory no other Rust reference names, and any byte value is a valid
    // `u8`; the call changes no mapping, IPC page, or thread entry state.
    let ret = unsafe {
        syscall3(
            SYS_THREAD_READ_REGS,
            u64::from(thread_cap),
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

/// Write register state from `buf` into a stopped or fault-blocked thread.
///
/// The thread must be `Stopped` and descheduled, or fault-blocked awaiting a
/// fault-handler reply; a `Stopped` thread still on a CPU is refused with
/// `InvalidState` (`core/kernel/docs/syscalls.md` § `SYS_THREAD_WRITE_REGS`).
/// `buf` must contain a complete `TrapFrame`
/// (`buf.len() >= size_of::<TrapFrame>()`). The kernel sanitizes the frame per
/// architecture before applying it (`core/kernel/docs/arch-interface.md`
/// § `trap_frame` — `arch::current::trap_frame`): on x86-64 it requires a
/// canonical user instruction and stack pointer, forces the ring-3 segment
/// selectors, and clears the privilege bits of `rflags`; on RISC-V it requires
/// a user `sepc`, clears the trap-cause fields, and replaces the supplied
/// `sstatus` with the user-resume value.
///
/// # Safety
/// When the thread is bound to the calling program's own address space, the
/// frame resumes it where the frame says, so its instruction pointer must be
/// code the thread may run at that point and its stack pointer must lie in
/// the stack dedicated to that thread (the thread-entry clause of
/// [`thread_configure_with_tls`]'s contract, for a resume): a frame read with
/// [`thread_read_regs`] and changed only in registers the resumed code
/// expects to be changed meets this. A thread bound to another address space
/// touches none of the calling program's memory, and a call the kernel
/// refuses changes nothing.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` (the thread cap
/// is invalid), `InsufficientRights` (it lacks Control), `InvalidState` (the
/// thread is neither fault-blocked nor `Stopped` and descheduled),
/// `InvalidArgument` (`buf` is shorter than the frame, the thread has no
/// register frame, or the instruction pointer, on x86-64 also the stack
/// pointer, is not a user address), or `InvalidAddress` (`buf` is not wholly
/// in the user half or not mapped readable).
#[inline]
pub unsafe fn thread_write_regs(thread_cap: u32, buf: &[u8]) -> Result<(), i64>
{
    // SAFETY: syscall3 issues the raw syscall; `buf` is a live slice the
    // kernel only reads, for at most `buf.len()` bytes. The caller's contract
    // keeps the installed frame on code and a stack dedicated to the thread,
    // the raw-wrapper contract's thread-entry clause.
    let ret = unsafe {
        syscall3(
            SYS_THREAD_WRITE_REGS,
            u64::from(thread_cap),
            buf.as_ptr() as u64,
            buf.len() as u64,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

// ── Randomness ─────────────────────────────────────────────────────────────────

/// Fill `buf` with cryptographically-secure random bytes from the kernel
/// entropy pool (`SYS_GETRANDOM`).
///
/// `buf.len()` must be `<= MAX_GETRANDOM_LEN`; callers fill larger buffers by
/// looping. On success the whole buffer is written — the kernel never blocks
/// for entropy (the pool is seeded before any userspace process runs) — and
/// the byte count is returned. Each call draws fresh from the kernel's
/// per-CPU CSPRNG; userspace holds no generator state. An empty `buf` is a
/// no-op returning 0.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidArgument` if `buf.len() >
/// MAX_GETRANDOM_LEN`, or `WouldBlock` if the pool is not yet seeded
/// (unreachable in practice). `InvalidAddress` is unreachable: a live
/// writable slice lies in the user half and is mapped writable.
#[inline]
pub fn getrandom(buf: &mut [u8]) -> Result<u64, i64>
{
    // SAFETY: `buf` is a live, exclusively borrowed slice, valid for
    // `buf.len()` bytes of writes, and any byte value is a valid `u8`.
    unsafe { getrandom_raw(buf.as_mut_ptr(), buf.len()) }
}

/// Raw `SYS_GETRANDOM`: the kernel writes `len` random bytes through `buf`.
///
/// For harness tests of the kernel's own buffer validation, which must hand
/// it a pointer no slice can name (an unmapped, read-only, or kernel-half
/// address). Everything else uses [`getrandom`].
///
/// # Safety
/// The span `[buf, buf + len)` must be valid for `len` bytes of writes and
/// name no memory a live Rust reference covers, or the kernel must refuse the
/// call (a `len` above `MAX_GETRANDOM_LEN`, or a span not wholly in the user
/// half, unmapped, or read-only, is refused with nothing written).
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidArgument` if `len >
/// MAX_GETRANDOM_LEN`, `InvalidAddress` if `buf` is null or the span is not
/// wholly in the user half, unmapped, or read-only, or `WouldBlock` if the
/// pool is not yet seeded (unreachable in practice).
// cast_sign_loss: ret is proven non-negative in the Ok branch; it is a byte count.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub unsafe fn getrandom_raw(buf: *mut u8, len: usize) -> Result<u64, i64>
{
    // SAFETY: syscall2 issues the raw syscall; the caller's contract makes the
    // span valid for the kernel's writes or one the kernel refuses; the call
    // changes no mapping, IPC page, or thread entry state.
    let ret = unsafe { syscall2(SYS_GETRANDOM, buf as u64, len as u64) };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

/// Draw a single cryptographically-secure random `u64` from the kernel
/// entropy pool.
///
/// Convenience over [`getrandom`] for the common "I need one random integer"
/// case (badge/correlator minting): fills a fixed 8-byte buffer and assembles
/// it native-endian. The value is raw — callers apply their own non-zero or
/// reserved-value filters.
///
/// # Errors
/// Returns the same negative `i64` codes as [`getrandom`]. For this fixed
/// 8-byte in-bounds draw the only reachable failure is a kernel-contract
/// violation (the pool is seeded before any userspace runs and the length is
/// well under `MAX_GETRANDOM_LEN`); it is surfaced as `Err` rather than
/// panicking so callers handle it on their own fallible path.
#[inline]
pub fn random_u64() -> Result<u64, i64>
{
    let mut b = [0u8; 8];
    let n = getrandom(&mut b)?;
    if n == b.len() as u64
    {
        Ok(u64::from_ne_bytes(b))
    }
    else
    {
        // Unreachable: the kernel fills a valid in-bounds buffer completely or
        // errors (it never returns a short count). Surface the contract
        // violation as `Err` rather than panic.
        Err(SyscallError::InvalidState as i64)
    }
}

// ── SBI ──────────────────────────────────────────────────────────────────────

/// Forward an SBI call to M-mode firmware (RISC-V only).
///
/// - `sbi_cap`: `SbiControl` capability handle (slot index plus generation)
/// - `extension`: SBI extension ID
/// - `function`: SBI function ID
/// - `a0`–`a2`: SBI arguments
///
/// Returns the SBI return value on success.
///
/// # Errors
/// Returns a negative `i64` error code if the kernel rejects the call:
/// `InvalidArgument` if `extension` is not a sanctioned extension,
/// `InsufficientRights` if `sbi_cap` lacks that extension's right (e.g.
/// `RIGHTS_SBI_RESET` for SRST), `InvalidCapability` for a bad handle, or
/// `NotSupported` on x86-64 or if SBI firmware itself returns an error.
#[inline]
pub fn sbi_call(
    sbi_cap: u32,
    extension: u64,
    function: u64,
    a0: u64,
    a1: u64,
    a2: u64,
) -> Result<u64, i64>
{
    // SAFETY: syscall6 issues raw syscall instruction; all arguments are plain u64 values.
    let ret = unsafe {
        syscall6(
            SYS_SBI_CALL,
            u64::from(sbi_cap),
            extension,
            function,
            a0,
            a1,
            a2,
        )
    };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        Ok(ret.cast_unsigned())
    }
}

/// Sleep the calling thread for `ms` milliseconds.
///
/// The thread is blocked and woken by the kernel's timer tick handler when
/// the deadline expires. A wake that coalesced before the sleep refuses the
/// park, and the call returns `Ok` at once without sleeping, so a caller that
/// needs the full duration re-checks elapsed time (core/kernel/docs/syscalls.md
/// § `SYS_THREAD_SLEEP`).
///
/// # Errors
/// Returns `-16` (`Interrupted`) if the thread is stopped before or during
/// the sleep (and restarted), unless the timer had already claimed the
/// elapsed deadline (the sleep returns `Ok`), `-8` (`OutOfMemory`) if the
/// kernel's sleep list is full (even when a stop then lands, if the sleep
/// withdrew first), or another negative `i64` error code on failure.
#[inline]
pub fn thread_sleep(ms: u64) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; ms is a plain u64.
    let ret = unsafe { syscall2(SYS_THREAD_SLEEP, ms, 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Register a death-notification observer on a thread.
///
/// When the target thread exits (clean or fault), the kernel posts
/// `(correlator as u64) << 32 | (exit_reason & 0xFFFF_FFFF)` to
/// `event_queue_cap`. Passing `correlator = 0` keeps the payload equal to
/// the bare exit reason (low 32 bits). If the thread has already exited, the
/// kernel posts the retained reason to `event_queue_cap` at once and the call
/// still succeeds.
///
/// Multiple observers can be registered on the same thread — up to the
/// kernel's per-TCB cap. Returns `SyscallError::OutOfMemory` (-8) if the
/// target thread's observer array is full.
///
/// `correlator` is opaque to the kernel. Its meaning is scoped to one
/// `(event queue, binder)` pair — not a system-wide identifier, not a
/// process id. Typical use: the binder stashes an internal routing tag
/// (e.g. procmgr's `ProcessTable` badge) so it can dispatch the death
/// event to the right bookkeeping without a secondary lookup.
///
/// Requires `CONTROL` on `thread_cap` and `POST` on `event_queue_cap`.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability`,
/// `InsufficientRights` (the thread lacks Control or the event queue lacks
/// Post), or `OutOfMemory` (the target's observer array is full).
#[inline]
pub fn thread_bind_notification(
    thread_cap: u32,
    event_queue_cap: u32,
    correlator: u32,
) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; cap indices and
    // correlator are plain scalar values.
    let ret = unsafe {
        syscall3(
            SYS_THREAD_BIND_NOTIFICATION,
            u64::from(thread_cap),
            u64::from(event_queue_cap),
            u64::from(correlator),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Register a terminal-fault death-notification observer on an address space.
///
/// When a thread in the target address space takes a *terminal* fault, the
/// kernel posts `(correlator as u64) << 32 | (exit_reason & 0xFFFF_FFFF)` to
/// `event_queue_cap`, where `exit_reason` is the fault class
/// (`EXIT_FAULT_BASE + vector` on x86-64, `EXIT_FAULT_BASE + cause` on
/// riscv64). A terminal fault is any kill outcome of the fault protocol:
///
/// - no fault handler bound;
/// - a `KILL` reply;
/// - a fault episode cancelled by destruction of the handler thread;
/// - a fault episode cancelled by destruction of the handler endpoint while
///   the fault is still queued on it;
/// - a fault episode cancelled by a later receive on the handler thread that
///   passes its capability and headroom checks while the fault reply is
///   pending.
///
/// A stop of the faulting thread defers the terminal fault: it cancels the
/// episode before any reply claims it, or keeps a claimed `KILL`, and the
/// fault takes effect, and is posted, only if the thread is started again
/// (docs/fault-handling.md § Delivery, Resume, and Kill).
///
/// Normal `thread_exit` does NOT post to these observers. Passing
/// `correlator = 0` keeps the payload equal to the bare fault class (low 32
/// bits). If the address space has already faulted terminally, the kernel
/// posts the retained reason to `event_queue_cap` at once and the call still
/// succeeds.
///
/// `aspace_cap` requires the `CONTROL` right; `event_queue_cap` requires the
/// `POST` right. Multiple observers can be registered — up to the kernel's
/// per-address-space cap. The kernel only notifies; it never enumerates or
/// terminates threads.
///
/// `correlator` is opaque to the kernel. Its meaning is scoped to one
/// `(event queue, binder)` pair — not a system-wide identifier, not a
/// process id. Typical use: procmgr stashes its `ProcessTable` badge so the
/// terminal-fault event routes into its teardown bookkeeping.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability`,
/// `InsufficientRights` (the address space lacks Control or the event queue
/// lacks Post), or `OutOfMemory` (the address space's observer array is
/// full).
#[inline]
pub fn aspace_bind_notification(
    aspace_cap: u32,
    event_queue_cap: u32,
    correlator: u32,
) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; cap indices and
    // correlator are plain scalar values.
    let ret = unsafe {
        syscall3(
            SYS_ASPACE_BIND_NOTIFICATION,
            u64::from(aspace_cap),
            u64::from(event_queue_cap),
            u64::from(correlator),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

// Names `MSG_DATA_WORDS_MAX` at module level; the IPC wrappers above use it
// directly as well.
const _: usize = MSG_DATA_WORDS_MAX;
