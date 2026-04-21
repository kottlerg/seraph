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
//! - x86-64: syscall number in `rax`; args in `rdi/rsi/rdx/r10/r8/r9`;
//!   return in `rax` (primary), `rdx` (secondary label for `ipc_call`/`ipc_recv`).
//! - RISC-V: syscall number in `a7`; args in `a0–a5`;
//!   return in `a0` (primary), `a1` (secondary label).

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
    MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX, SYS_ASPACE_QUERY, SYS_CAP_COPY, SYS_CAP_CREATE_ASPACE,
    SYS_CAP_CREATE_CSPACE, SYS_CAP_CREATE_ENDPOINT, SYS_CAP_CREATE_EVENT_Q, SYS_CAP_CREATE_SIGNAL,
    SYS_CAP_CREATE_THREAD, SYS_CAP_CREATE_WAIT_SET, SYS_CAP_DELETE, SYS_CAP_DERIVE,
    SYS_CAP_DERIVE_TOKEN, SYS_CAP_INSERT, SYS_CAP_MOVE, SYS_CAP_REVOKE, SYS_DMA_GRANT,
    SYS_EVENT_POST, SYS_EVENT_RECV, SYS_FRAME_SPLIT, SYS_IOPORT_BIND, SYS_IPC_BUFFER_SET,
    SYS_IPC_CALL, SYS_IPC_RECV, SYS_IPC_REPLY, SYS_IRQ_ACK, SYS_IRQ_REGISTER, SYS_MEM_MAP,
    SYS_MEM_PROTECT, SYS_MEM_UNMAP, SYS_MMIO_MAP, SYS_MMIO_SPLIT, SYS_SBI_CALL, SYS_SIGNAL_SEND,
    SYS_SIGNAL_WAIT, SYS_SYSTEM_INFO, SYS_THREAD_BIND_NOTIFICATION, SYS_THREAD_CONFIGURE,
    SYS_THREAD_EXIT, SYS_THREAD_READ_REGS, SYS_THREAD_SET_AFFINITY, SYS_THREAD_SET_PRIORITY,
    SYS_THREAD_SLEEP, SYS_THREAD_START, SYS_THREAD_STOP, SYS_THREAD_WRITE_REGS, SYS_THREAD_YIELD,
    SYS_WAIT_SET_ADD, SYS_WAIT_SET_REMOVE, SYS_WAIT_SET_WAIT,
};

pub use syscall_abi::{
    MAP_EXECUTABLE, MAP_READONLY, MAP_WRITABLE, RIGHTS_ALL, RIGHTS_CSPACE, RIGHTS_MAP_READ,
    RIGHTS_MAP_RW, RIGHTS_MAP_RX, RIGHTS_RECEIVE, RIGHTS_SEND, RIGHTS_SEND_GRANT, RIGHTS_THREAD,
};

// ── Raw syscall entry ─────────────────────────────────────────────────────────

/// Issue a syscall with up to 2 arguments. Returns the primary return value.
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi; clobbers rcx/r11 as documented; no memory side effects (nostack).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            // syscall clobbers rcx and r11.
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0/a1; no caller-saved registers clobbered beyond return; no memory side effects.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            in("a1") a1,
            in("a7") nr,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with up to 4 arguments.
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10; clobbers rcx/r11 as documented; no memory side effects (nostack).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a3; no caller-saved registers clobbered beyond return; no memory side effects.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a7") nr,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with up to 5 arguments. Returns the primary return value.
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10/r8; clobbers rcx/r11 as documented; no memory side effects (nostack).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8")  a4,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a4; no caller-saved registers clobbered beyond return; no memory side effects.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a7") nr,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with up to 3 arguments.
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx; clobbers rcx/r11 as documented; no memory side effects (nostack).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a2; no caller-saved registers clobbered beyond return; no memory side effects.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a7") nr,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with up to 5 arguments. Returns (primary, secondary).
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall5_ret2(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (i64, u64)
{
    let ret: i64;
    let secondary: u64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10/r8; clobbers rcx/r11; reads secondary return from rdx (lateout).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8")  a4,
            out("rcx") _,
            out("r11") _,
            lateout("rdx") secondary,
            options(nostack),
        );
    }
    (ret, secondary)
}

#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall5_ret2(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (i64, u64)
{
    let ret: i64;
    let secondary: u64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a4; reads secondary return from a1 (inout); no memory side effects.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => secondary,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a7") nr,
            options(nostack),
        );
    }
    (ret, secondary)
}

/// Issue a syscall with 1 argument. Returns (primary, secondary, tertiary).
///
/// Used by `ipc_recv` to retrieve the token alongside label.
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall1_ret3(nr: u64, a0: u64) -> (i64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // arg in rdi; clobbers rcx/r11; reads secondary return from rdx (lateout),
    // tertiary return from rsi (lateout). rsi is not used as input (only 1 arg).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            out("rcx") _,
            out("r11") _,
            lateout("rdx") secondary,
            lateout("rsi") tertiary,
            options(nostack),
        );
    }
    (ret, secondary, tertiary)
}

/// Issue a syscall with 1 argument. Returns (primary, secondary, tertiary).
#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall1_ret3(nr: u64, a0: u64) -> (i64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // arg in a0; reads secondary from a1 (lateout), tertiary from a2 (lateout).
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            lateout("a1") secondary,
            lateout("a2") tertiary,
            in("a7") nr,
            options(nostack),
        );
    }
    (ret, secondary, tertiary)
}

/// Issue a syscall with 6 arguments. Returns the primary return value.
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10/r8/r9; clobbers rcx/r11 as documented; no memory side effects.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8")  a4,
            in("r9")  a5,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a5; no memory side effects.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            in("a7") nr,
            options(nostack),
        );
    }
    ret
}

// ── IPC capability slot helpers ───────────────────────────────────────────────

/// Pack up to `MSG_CAP_SLOTS_MAX` `CSpace` slot indices into a single `u64`.
///
/// Each index occupies 16 bits (sufficient for max `CSpace` size of 16384 slots).
/// Indices beyond `MSG_CAP_SLOTS_MAX` are silently ignored.
///
/// Pass the result as arg4 of `SYS_IPC_CALL` or arg3 of `SYS_IPC_REPLY`.
#[must_use]
pub fn pack_cap_slots(slots: &[u32]) -> u64
{
    let mut packed: u64 = 0;
    for (i, &idx) in slots.iter().take(MSG_CAP_SLOTS_MAX).enumerate()
    {
        packed |= (u64::from(idx) & 0xFFFF) << (i * 16);
    }
    packed
}

/// Unpack `count` `CSpace` slot indices from a `u64` packed by [`pack_cap_slots`].
#[must_use]
pub fn unpack_cap_slots(packed: u64, count: usize) -> [u32; MSG_CAP_SLOTS_MAX]
{
    let mut out = [0u32; MSG_CAP_SLOTS_MAX];
    // cast_possible_truncation: each field is masked to 0xFFFF (16 bits), fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    for (i, slot) in out
        .iter_mut()
        .take(count.min(MSG_CAP_SLOTS_MAX))
        .enumerate()
    {
        *slot = ((packed >> (i * 16)) & 0xFFFF) as u32;
    }
    out
}

/// Read cap transfer results from the IPC buffer after a receive or call.
///
/// The kernel writes the following layout starting at word index `MSG_DATA_WORDS_MAX`:
/// ```text
/// word[MSG_DATA_WORDS_MAX + 0] = cap_count as u64
/// word[MSG_DATA_WORDS_MAX + 1] = idx[0] as u64
/// word[MSG_DATA_WORDS_MAX + 2] = idx[1] as u64
/// ...
/// ```
///
/// Returns `(cap_count, [idx0, idx1, idx2, idx3])`.
///
/// # Safety
/// `ipc_buf` must point to the registered IPC buffer page (4 KiB, aligned).
#[must_use]
pub unsafe fn read_recv_caps(ipc_buf: *const u64) -> (usize, [u32; MSG_CAP_SLOTS_MAX])
{
    // cast_possible_truncation: Seraph targets 64-bit only (x86_64, riscv64);
    // usize == u64 on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: caller guarantees ipc_buf points to registered IPC buffer (4 KiB aligned);
    // offset MSG_DATA_WORDS_MAX is within buffer bounds; volatile read required for kernel-written data.
    let cap_count = (unsafe { core::ptr::read_volatile(ipc_buf.add(MSG_DATA_WORDS_MAX)) } as usize)
        .min(MSG_CAP_SLOTS_MAX);
    let mut indices = [0u32; MSG_CAP_SLOTS_MAX];
    // cast_possible_truncation: cap slot indices are at most 16-bit values; fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    for (i, slot) in indices.iter_mut().take(cap_count).enumerate()
    {
        // SAFETY: caller guarantees ipc_buf points to registered IPC buffer; offset is bounded
        // by cap_count <= MSG_CAP_SLOTS_MAX; volatile read required for kernel-written cap indices.
        *slot = unsafe { core::ptr::read_volatile(ipc_buf.add(MSG_DATA_WORDS_MAX + 1 + i)) } as u32;
    }
    (cap_count, indices)
}

// ── Public syscall wrappers ───────────────────────────────────────────────────

/// Voluntarily yield the CPU to the next runnable thread.
///
/// # Errors
/// Returns a negative `i64` error code if the kernel rejects the call.
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

/// Register (or clear) the per-thread IPC buffer page.
///
/// `virt` must be 4 KiB-aligned (or 0 to deregister).
///
/// # Errors
/// Returns a negative `i64` error code if the kernel rejects the call
/// (e.g., address is not page-aligned).
#[inline]
pub fn ipc_buffer_set(virt: u64) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; virt is virtual address passed as u64;
    // kernel validates alignment and mapping before registering buffer.
    let ret = unsafe { syscall2(SYS_IPC_BUFFER_SET, virt, 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Synchronous IPC call on an endpoint cap.
///
/// Sends `label`, up to `MSG_DATA_WORDS_MAX` data words (written to the IPC
/// buffer before the call), and up to `MSG_CAP_SLOTS_MAX` capability slots.
/// Blocks until a server replies.
///
/// Returns `(reply_label, reply_data_count)`. After return, call
/// [`read_recv_caps`] on the IPC buffer to retrieve any caps the server
/// sent in its reply.
///
/// Requires endpoint cap to have `Rights::GRANT` when `cap_slots` is non-empty.
///
/// # Note
/// The caller must have registered an IPC buffer via [`ipc_buffer_set`].
///
/// # Errors
/// Returns a negative `i64` error code if the endpoint cap is invalid, the
/// caller has insufficient rights, or the call is interrupted.
#[inline]
pub fn ipc_call(
    ep: u32,
    label: u64,
    data_count: usize,
    cap_slots: &[u32],
) -> Result<(u64, usize), i64>
{
    let cap_count = cap_slots.len().min(MSG_CAP_SLOTS_MAX);
    let cap_packed = pack_cap_slots(cap_slots);
    // SAFETY: syscall5_ret2 issues raw syscall instruction; all arguments are scalar u64 values
    // (cap indices and packed slot array); kernel validates caps and reads IPC buffer.
    let (ret, secondary) = unsafe {
        syscall5_ret2(
            SYS_IPC_CALL,
            u64::from(ep),
            label,
            data_count as u64,
            cap_count as u64,
            cap_packed,
        )
    };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        Ok((secondary, 0))
    }
}

/// Receive a call on an endpoint cap.
///
/// Blocks until a caller sends. Returns `(label, token)`.
/// Data words are written to the registered IPC buffer.
/// The `token` is the value attached to the sender's endpoint capability
/// via `cap_derive_token`. Zero if the sender used an untokened cap.
///
/// # Errors
/// Returns a negative `i64` error code if the endpoint cap is invalid or
/// the receive is interrupted.
#[inline]
pub fn ipc_recv(ep: u32) -> Result<(u64, u64), i64>
{
    // SAFETY: syscall1_ret3 issues raw syscall instruction; ep is endpoint cap index as u64;
    // kernel validates cap and writes to IPC buffer; returns label in secondary register,
    // token in tertiary register.
    let (ret, secondary, tertiary) = unsafe { syscall1_ret3(SYS_IPC_RECV, u64::from(ep)) };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        Ok((secondary, tertiary))
    }
}

/// Reply to the thread that called us.
///
/// Sends `label`, `data_count` words from the IPC buffer, and up to
/// `MSG_CAP_SLOTS_MAX` capability slots from the current `CSpace`.
///
/// After the reply, `cap_slots` entries are moved to the caller's `CSpace`.
/// The caller can read the resulting slot indices via [`read_recv_caps`].
///
/// # Errors
/// Returns a negative `i64` error code if there is no pending reply target
/// or the call is otherwise invalid.
#[inline]
pub fn ipc_reply(label: u64, data_count: usize, cap_slots: &[u32]) -> Result<(), i64>
{
    let cap_count = cap_slots.len().min(MSG_CAP_SLOTS_MAX);
    let cap_packed = pack_cap_slots(cap_slots);
    // SAFETY: syscall4 issues raw syscall instruction; all arguments are scalar u64 values
    // (label, counts, packed cap slots); kernel reads IPC buffer and validates caps.
    let ret = unsafe {
        syscall4(
            SYS_IPC_REPLY,
            label,
            data_count as u64,
            cap_count as u64,
            cap_packed,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Send `bits` to a signal cap. `bits` must be non-zero.
///
/// # Errors
/// Returns a negative `i64` error code if the signal cap is invalid or `bits` is zero.
#[inline]
pub fn signal_send(sig: u32, bits: u64) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; sig is cap index as u64, bits is bitmask;
    // kernel validates cap and updates signal state.
    let ret = unsafe { syscall2(SYS_SIGNAL_SEND, u64::from(sig), bits) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Block until any bits are set on a signal cap. Returns the acquired bitmask.
///
/// # Errors
/// Returns a negative `i64` error code if the signal cap is invalid or the
/// wait is interrupted.
// cast_sign_loss: ret is proven non-negative in the Ok branch; reinterpreting
// as u64 preserves the bitmask bit-for-bit.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn signal_wait(sig: u32) -> Result<u64, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; sig is cap index as u64;
    // kernel validates cap, blocks until signal bits available, returns bitmask.
    let ret = unsafe { syscall2(SYS_SIGNAL_WAIT, u64::from(sig), 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

/// Block until any bits are set on a signal cap, or until `timeout_ms`
/// elapses. Returns the acquired bitmask (non-zero) on wake, or `Ok(0)`
/// on timeout.
///
/// `timeout_ms == 0` is equivalent to [`signal_wait`] — block indefinitely.
/// Callers that want a non-blocking poll should use `timeout_ms = 1`.
///
/// # Errors
/// Returns a negative `i64` error code if the signal cap is invalid or
/// the wait is interrupted.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn signal_wait_timeout(sig: u32, timeout_ms: u64) -> Result<u64, i64>
{
    // SAFETY: same as `signal_wait`; arg1 carries the timeout (0 =
    // infinite, matching the original single-arg behaviour).
    let ret = unsafe { syscall2(SYS_SIGNAL_WAIT, u64::from(sig), timeout_ms) };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

/// Create a new Endpoint object. Returns the `CSpace` slot index.
///
/// # Errors
/// Returns a negative `i64` error code if the kernel cannot allocate
/// the endpoint or the `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_endpoint() -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments;
    // kernel allocates endpoint and returns slot index.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_ENDPOINT, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Create a new Signal object. Returns the `CSpace` slot index.
///
/// # Errors
/// Returns a negative `i64` error code if the kernel cannot allocate
/// the signal or the `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_signal() -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments;
    // kernel allocates signal and returns slot index.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_SIGNAL, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Create a new `AddressSpace` object. Returns the `CSpace` slot index.
///
/// # Errors
/// Returns a negative `i64` error code if the kernel cannot allocate
/// the address space or the `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_aspace() -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments;
    // kernel allocates address space and returns slot index.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_ASPACE, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Create a new `CSpace` object. `max_slots` is clamped to `[16, 16384]` by the kernel.
/// Returns the `CSpace` slot index.
///
/// # Errors
/// Returns a negative `i64` error code if the kernel cannot allocate
/// the `CSpace` or the caller's `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_cspace(max_slots: u64) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; max_slots is scalar capacity argument;
    // kernel allocates CSpace and returns slot index.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_CSPACE, max_slots, 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Create a new Thread object bound to `aspace_cap` and `cspace_cap`.
/// Returns the `CSpace` slot index of the new Thread capability.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid or the
/// `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_thread(aspace_cap: u32, cspace_cap: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; aspace_cap and cspace_cap are cap indices as u64;
    // kernel validates caps, allocates thread, returns slot index.
    let ret = unsafe {
        syscall2(
            SYS_CAP_CREATE_THREAD,
            u64::from(aspace_cap),
            u64::from(cspace_cap),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Map `page_count` pages of a Frame cap into an address space.
///
/// - `frame_cap`: cap index of the source Frame.
/// - `aspace_cap`: cap index of the target `AddressSpace`.
/// - `virt`: virtual address to map at (page-aligned, < `0x0000_8000_0000_0000`).
/// - `offset_pages`: first page within the frame to map.
/// - `page_count`: number of pages to map.
/// - `prot_bits`: explicit permission bits (bit 1 = WRITE, bit 2 = EXECUTE).
///   Must be a subset of the Frame cap's rights. If zero, permissions are
///   derived from the Frame cap's rights directly.
///
/// W^X is enforced: WRITE and EXECUTE may not both be set.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, `virt` is
/// not page-aligned or out of range, the frame is too small, or W^X is violated.
#[inline]
pub fn mem_map(
    frame_cap: u32,
    aspace_cap: u32,
    virt: u64,
    offset_pages: u64,
    page_count: u64,
    prot_bits: u64,
) -> Result<(), i64>
{
    // SAFETY: syscall6 issues raw syscall instruction; all arguments are scalar u64 values
    // (cap indices, virtual address, page offset, count, prot bits); kernel validates
    // caps, mappings, and permissions.
    let ret = unsafe {
        syscall6(
            SYS_MEM_MAP,
            u64::from(frame_cap),
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
/// Unmapping a page that is not mapped is a no-op (not an error).
/// `virt` must be page-aligned and in the user address range.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid or `virt` is
/// not page-aligned.
#[inline]
pub fn mem_unmap(aspace_cap: u32, virt: u64, page_count: u64) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; all arguments are scalar u64 values
    // (cap index, virtual address, page count); kernel validates cap and unmaps pages.
    let ret = unsafe { syscall3(SYS_MEM_UNMAP, u64::from(aspace_cap), virt, page_count) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Change permission flags on `page_count` existing mappings in `aspace_cap`.
///
/// `frame_cap` authorises the requested permissions: they must be a subset of
/// the Frame cap's rights. `prot` encoding: bit 1 = WRITE, bit 2 = EXECUTE.
/// W^X is enforced. Returns an error if any page is not currently mapped.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, the
/// requested permissions exceed the cap's rights, or any target page is
/// not currently mapped.
#[inline]
pub fn mem_protect(
    frame_cap: u32,
    aspace_cap: u32,
    virt: u64,
    page_count: u64,
    prot: u64,
) -> Result<(), i64>
{
    // SAFETY: syscall5 issues raw syscall instruction; all arguments are scalar u64 values
    // (cap indices, virtual address, page count, protection flags); kernel validates caps and rights.
    let ret = unsafe {
        syscall5(
            SYS_MEM_PROTECT,
            u64::from(frame_cap),
            u64::from(aspace_cap),
            virt,
            page_count,
            prot,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Split `frame_cap` into two non-overlapping child Frame caps.
///
/// `split_offset` is in bytes and must be page-aligned, > 0, and < the frame
/// size. The original cap is consumed. Returns `(slot1, slot2)` where slot1
/// covers `[base, base+split_offset)` and slot2 covers `[base+split_offset, end)`.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid, `split_offset`
/// is not page-aligned, or is out of range for the frame.
// cast_sign_loss: proven non-negative in Ok branch.
// cast_possible_truncation: each half of the packed return is a 32-bit slot index.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn frame_split(frame_cap: u32, split_offset: u64) -> Result<(u32, u32), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; frame_cap is cap index as u64, split_offset
    // is byte offset; kernel validates cap and offset, returns packed slot indices.
    let ret = unsafe { syscall3(SYS_FRAME_SPLIT, u64::from(frame_cap), split_offset, 0) };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        let v = ret as u64;
        Ok(((v & 0xFFFF_FFFF) as u32, (v >> 32) as u32))
    }
}

/// Split `mmio_cap` into two non-overlapping child `MmioRegion` caps.
///
/// `split_offset` is in bytes and must be page-aligned, > 0, and < the region
/// size. The original cap is consumed. Returns `(slot1, slot2)` where slot1
/// covers `[base, base+split_offset)` and slot2 covers `[base+split_offset, end)`.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid, `split_offset`
/// is not page-aligned, or is out of range for the region.
// cast_sign_loss: proven non-negative in Ok branch.
// cast_possible_truncation: each half of the packed return is a 32-bit slot index.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn mmio_split(mmio_cap: u32, split_offset: u64) -> Result<(u32, u32), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; mmio_cap is cap index as u64, split_offset
    // is byte offset; kernel validates cap and offset, returns packed slot indices.
    let ret = unsafe { syscall3(SYS_MMIO_SPLIT, u64::from(mmio_cap), split_offset, 0) };
    if ret < 0
    {
        Err(ret)
    }
    else
    {
        let v = ret as u64;
        Ok(((v & 0xFFFF_FFFF) as u32, (v >> 32) as u32))
    }
}

/// Set the entry point, stack, and initial argument for a thread cap.
///
/// The thread must be in `Created` state (not yet started). Call
/// [`thread_start`] afterwards to make it runnable. The thread starts with
/// `tls_base == 0` (no TLS); use [`thread_configure_with_tls`] when the
/// thread needs a preset thread-local-storage pointer.
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid or the
/// thread is not in `Created` state.
#[inline]
pub fn thread_configure(thread_cap: u32, entry: u64, stack_ptr: u64, arg: u64) -> Result<(), i64>
{
    thread_configure_with_tls(thread_cap, entry, stack_ptr, arg, 0)
}

/// Same as [`thread_configure`] but also sets the initial `tls_base`.
///
/// `tls_base` is loaded into `IA32_FS_BASE` (x86-64) or `tp` (RISC-V) when
/// the thread first runs. Pass `0` for a thread that does not use TLS.
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid or the
/// thread is not in `Created` state.
#[inline]
pub fn thread_configure_with_tls(
    thread_cap: u32,
    entry: u64,
    stack_ptr: u64,
    arg: u64,
    tls_base: u64,
) -> Result<(), i64>
{
    // SAFETY: syscall5 issues raw syscall instruction; all arguments are scalar u64 values
    // (cap index, entry point, stack pointer, initial arg, tls base); kernel validates cap
    // and addresses.
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

/// Move a configured thread from `Created` to `Ready` (enqueue it).
///
/// The thread must have been configured via [`thread_configure`] first.
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid or the
/// thread has not been configured yet.
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
/// - `src_slot`: slot index in the caller's `CSpace`.
/// - `dest_cspace_cap`: cap index of the destination `CSpace`.
/// - `rights_mask`: bitmask of rights to grant. The effective rights are the
///   intersection of this mask and the source cap's rights — pass `RIGHTS_ALL`
///   to copy with the same rights as the source.
///
/// Returns the slot index in the destination `CSpace`.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, the caller
/// lacks sufficient rights, or the destination `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_copy(src_slot: u32, dest_cspace_cap: u32, rights_mask: u64) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; all arguments are scalar u64 values
    // (source slot, dest CSpace cap, rights mask); kernel validates caps and returns new slot.
    let ret = unsafe {
        syscall3(
            SYS_CAP_COPY,
            u64::from(src_slot),
            u64::from(dest_cspace_cap),
            rights_mask,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Attenuate a capability within the caller's own `CSpace` (`SYS_CAP_DERIVE`).
///
/// Creates a new slot in the caller's `CSpace` with `rights_mask & src_rights`.
/// The new slot is a derivation child of the source.
///
/// Returns the new slot index.
///
/// # Errors
/// Returns a negative `i64` error code if the source cap is invalid or the
/// `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn cap_derive(src_slot: u32, rights_mask: u64) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; src_slot is cap index as u64, rights_mask
    // is bitmask; kernel validates cap, creates attenuated derivative, returns new slot.
    let ret = unsafe { syscall2(SYS_CAP_DERIVE, u64::from(src_slot), rights_mask) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Derive a capability with a token attached (`SYS_CAP_DERIVE_TOKEN`).
///
/// Creates a new slot in the caller's `CSpace` with attenuated rights and the
/// specified `token` value. The token is delivered to the receiver on `ipc_recv`
/// when the capability is used for IPC.
///
/// `token` must be non-zero. The source capability must have `token == 0`
/// (no re-tokening).
///
/// # Errors
/// Returns a negative `i64` error code if the source cap is invalid, the token
/// is zero, the source already has a token, or the `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn cap_derive_token(src_slot: u32, rights_mask: u64, token: u64) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; src_slot is cap index, rights_mask
    // is bitmask, token is the token value; kernel validates and creates tokened derivative.
    let ret = unsafe {
        syscall3(
            SYS_CAP_DERIVE_TOKEN,
            u64::from(src_slot),
            rights_mask,
            token,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Delete a capability slot in the caller's `CSpace` (`SYS_CAP_DELETE`).
///
/// Reparents child derivations to the deleted slot's parent, unlinks from the
/// derivation tree, and dec-refs the kernel object. Idempotent on Null slots.
///
/// # Errors
/// Returns a negative `i64` error code if the slot index is out of range.
pub fn cap_delete(slot: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; slot is cap index as u64;
    // kernel validates slot, unlinks from derivation tree, dec-refs object.
    let ret = unsafe { syscall2(SYS_CAP_DELETE, u64::from(slot), 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Revoke all capabilities derived from a slot (`SYS_CAP_REVOKE`).
///
/// Clears the entire descendant subtree; the root slot is preserved.
///
/// # Errors
/// Returns a negative `i64` error code if the slot index is out of range.
pub fn cap_revoke(slot: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; slot is cap index as u64;
    // kernel validates slot and revokes entire descendant subtree.
    let ret = unsafe { syscall2(SYS_CAP_REVOKE, u64::from(slot), 0) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Move a capability to another `CSpace` (`SYS_CAP_MOVE`).
///
/// `dest_index` = 0 auto-allocates a slot; non-zero inserts at that index.
/// The source slot is cleared; object refcount is unchanged.
///
/// Returns the destination slot index.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, the
/// destination `CSpace` is full, or `dest_index` is already occupied.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn cap_move(src_slot: u32, dest_cspace_cap: u32, dest_index: u32) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; all arguments are scalar u64 values
    // (source slot, dest CSpace cap, dest index); kernel validates and moves cap, returns slot.
    let ret = unsafe {
        syscall3(
            SYS_CAP_MOVE,
            u64::from(src_slot),
            u64::from(dest_cspace_cap),
            u64::from(dest_index),
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Insert a capability at a specific slot index in another `CSpace` (`SYS_CAP_INSERT`).
///
/// Like `cap_copy` but the destination slot index is caller-chosen.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, the caller
/// lacks sufficient rights, or `dest_index` is already occupied.
pub fn cap_insert(
    src_slot: u32,
    dest_cspace_cap: u32,
    dest_index: u32,
    rights_mask: u64,
) -> Result<(), i64>
{
    // SAFETY: syscall4 issues raw syscall instruction; all arguments are scalar u64 values
    // (source slot, dest CSpace cap, dest index, rights mask); kernel validates and inserts cap.
    let ret = unsafe {
        syscall4(
            SYS_CAP_INSERT,
            u64::from(src_slot),
            u64::from(dest_cspace_cap),
            u64::from(dest_index),
            rights_mask,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
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

/// Translate a virtual address in an address space to its mapped physical address.
///
/// `aspace_cap` — cap slot of the `AddressSpace` (must have READ right).
/// `virt` — page-aligned virtual address in the user half.
///
/// Returns the physical address on success, or a negative `SyscallError`
/// code if the address is not mapped or the cap is invalid.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid or the address
/// is not currently mapped.
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

/// Create a new `EventQueue` with the given capacity (1..=4096).
///
/// Returns the `CSpace` slot index with POST | RECV rights, or a negative
/// `SyscallError` code on failure.
///
/// # Errors
/// Returns a negative `i64` error code if `capacity` is out of range or
/// the `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn event_queue_create(capacity: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; capacity is scalar queue size as u64;
    // kernel validates capacity (1..=4096), allocates event queue, returns slot index.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_EVENT_Q, u64::from(capacity), 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Append `payload` to an event queue (non-blocking).
///
/// Returns `SyscallError::QueueFull` (-13) if the queue is at capacity.
///
/// # Errors
/// Returns a negative `i64` error code if the queue cap is invalid or the
/// queue is full.
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
/// Returns a negative `i64` error code if the queue cap is invalid or the
/// wait is interrupted.
#[inline]
pub fn event_recv(queue_cap: u32) -> Result<u64, i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; arg1 = 0 selects
    // the blocking path in the kernel.
    let (ret, payload) = unsafe { syscall5_ret2(SYS_EVENT_RECV, u64::from(queue_cap), 0, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(payload) }
}

/// Non-blocking dequeue. Returns `Err(-6)` (`WouldBlock`) when the queue is
/// empty; otherwise returns the payload.
///
/// # Errors
/// Returns `-6` (`WouldBlock`) if the queue is empty, or another negative
/// `i64` error code on invalid cap.
#[inline]
pub fn event_try_recv(queue_cap: u32) -> Result<u64, i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; arg1 = 1 selects
    // the non-blocking / try-once path in the kernel.
    let (ret, payload) = unsafe { syscall5_ret2(SYS_EVENT_RECV, u64::from(queue_cap), 1, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(payload) }
}

// ── Wait Set wrappers ─────────────────────────────────────────────────────────

/// Create a new `WaitSet`. Returns the `CSpace` slot index with MODIFY | WAIT rights.
///
/// # Errors
/// Returns a negative `i64` error code if the kernel cannot allocate the
/// `WaitSet` or the `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn wait_set_create() -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments;
    // kernel allocates wait set and returns slot index.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_WAIT_SET, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Register `source_cap` (Endpoint/Signal/EventQueue) in `ws_cap` with a
/// caller-chosen opaque `token`. The token is returned by `wait_set_wait`
/// when this source fires.
///
/// Returns `SyscallError::InvalidArgument` (-5) if the wait set is full
/// or the source is already in a wait set.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, the source
/// is already in a wait set, or the wait set is full.
#[inline]
pub fn wait_set_add(ws_cap: u32, source_cap: u32, token: u64) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; all arguments are scalar u64 values
    // (wait set cap, source cap, opaque token); kernel validates caps and registers source.
    let ret = unsafe {
        syscall3(
            SYS_WAIT_SET_ADD,
            u64::from(ws_cap),
            u64::from(source_cap),
            token,
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
/// Returns the opaque token chosen at `wait_set_add` time for the source that
/// fired. The token is delivered in the secondary return register (rdx / a1).
/// If multiple sources are ready, each call returns one token without re-blocking.
///
/// # Errors
/// Returns a negative `i64` error code if the wait set cap is invalid or
/// the wait is interrupted.
#[inline]
pub fn wait_set_wait(ws_cap: u32) -> Result<u64, i64>
{
    // SAFETY: syscall5_ret2 issues raw syscall instruction; ws_cap is cap index as u64;
    // kernel validates cap, blocks until source ready, returns token in secondary register.
    let (ret, token) = unsafe { syscall5_ret2(SYS_WAIT_SET_WAIT, u64::from(ws_cap), 0, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(token) }
}

// ── Hardware access wrappers (W6) ─────────────────────────────────────────────

/// Bind `signal_cap` to receive notifications when `irq_cap`'s interrupt fires.
///
/// After registration the IRQ is masked until the first `irq_ack`. The driver
/// must call `irq_ack` after servicing each interrupt to re-enable delivery.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid or the IRQ
/// is already bound.
#[inline]
pub fn irq_register(irq_cap: u32, signal_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; irq_cap and signal_cap are cap indices as u64;
    // kernel validates caps and binds IRQ to signal for interrupt delivery.
    let ret = unsafe { syscall2(SYS_IRQ_REGISTER, u64::from(irq_cap), u64::from(signal_cap)) };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Re-enable interrupt delivery for `irq_cap` after handling the interrupt.
///
/// Must be called once the interrupt source in the device has been cleared,
/// otherwise the interrupt will fire again immediately on unmask.
///
/// # Errors
/// Returns a negative `i64` error code if the IRQ cap is invalid.
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
/// - `flags` bit 1 (`0x2`) makes the mapping writable; executable is always denied.
/// - All pages are mapped uncacheable (PCD|PWT on `x86_64`).
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid, `virt` is
/// not page-aligned, or the virtual address is out of range.
#[inline]
pub fn mmio_map(aspace_cap: u32, mmio_cap: u32, virt: u64, flags: u64) -> Result<(), i64>
{
    // SAFETY: syscall4 issues raw syscall instruction; all arguments are scalar u64 values
    // (cap indices, virtual address, flags); kernel validates caps and creates uncacheable mapping.
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
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid or the
/// architecture does not support I/O ports.
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

/// Return the physical address of `frame_cap` for use as a DMA buffer.
///
/// `flags` must include [`syscall_abi::FLAG_DMA_UNSAFE`] to acknowledge that
/// the DMA transfer is not IOMMU-isolated. Without the flag `DmaUnsafe` (-14)
/// is returned. `device_id` is reserved; pass 0.
///
/// Returns the physical base address of the frame on success.
///
/// # Errors
/// Returns a negative `i64` error code if the frame cap is invalid or
/// `FLAG_DMA_UNSAFE` is not set in `flags`.
// cast_sign_loss: ret is proven non-negative in the Ok branch; it is a physical address.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn dma_grant(frame_cap: u32, device_id: u64, flags: u64) -> Result<u64, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; all arguments are scalar u64 values
    // (cap index, device ID, flags); kernel validates cap and FLAG_DMA_UNSAFE, returns physical address.
    let ret = unsafe { syscall3(SYS_DMA_GRANT, u64::from(frame_cap), device_id, flags) };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

/// Stop a running, ready, or blocked thread. The thread transitions to `Stopped`.
///
/// If the thread was blocked on IPC, the blocking syscall returns `Interrupted`.
/// A thread may stop itself (pass its own thread cap).
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid.
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
/// `priority` must be in `[1, PRIORITY_MAX]`. Priorities `>= SCHED_ELEVATED_MIN`
/// require a valid `sched_cap` with Elevate rights. Pass `sched_cap = 0` for
/// normal-range changes.
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid,
/// `priority` is out of range, or `sched_cap` is invalid when required.
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
/// On single-CPU systems this is recorded but not yet enforced until WSMP.
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid or
/// `cpu_id` is not a valid CPU index.
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

/// Copy the register state of a stopped thread into `buf`.
///
/// The thread must be in `Stopped` state. `buf` must be at least
/// `size_of::<TrapFrame>()` bytes (architecture-defined). Returns the number
/// of bytes written on success.
///
/// # Safety
/// `buf` must be valid for `buf_size` bytes of writes.
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid, the
/// thread is not stopped, or `buf_size` is too small.
// cast_sign_loss: ret is proven non-negative in the Ok branch; it is a byte count.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn thread_read_regs(thread_cap: u32, buf: *mut u8, buf_size: usize) -> Result<u64, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; buf pointer cast to u64 for syscall ABI;
    // kernel validates thread cap, checks buf_size, writes TrapFrame only if thread stopped.
    let ret = unsafe {
        syscall3(
            SYS_THREAD_READ_REGS,
            u64::from(thread_cap),
            buf as u64,
            buf_size as u64,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u64) }
}

/// Write register state from `buf` into a stopped thread.
///
/// The thread must be in `Stopped` state. `buf` must contain a complete
/// `TrapFrame` (`buf_size >= size_of::<TrapFrame>()`). The kernel validates
/// that no privilege bits are set before applying the registers.
///
/// # Safety
/// `buf` must be valid for `buf_size` bytes of reads.
///
/// # Errors
/// Returns a negative `i64` error code if the thread cap is invalid, the
/// thread is not stopped, `buf_size` is too small, or privilege bits are set.
#[inline]
pub fn thread_write_regs(thread_cap: u32, buf: *const u8, buf_size: usize) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; buf pointer cast to u64 for syscall ABI;
    // kernel validates thread cap, checks buf_size, reads TrapFrame only if thread stopped and privileges cleared.
    let ret = unsafe {
        syscall3(
            SYS_THREAD_WRITE_REGS,
            u64::from(thread_cap),
            buf as u64,
            buf_size as u64,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
}

// ── SBI ──────────────────────────────────────────────────────────────────────

/// Forward an SBI call to M-mode firmware (RISC-V only).
///
/// - `sbi_cap`: `SbiControl` capability slot index
/// - `extension`: SBI extension ID
/// - `function`: SBI function ID
/// - `a0`–`a2`: SBI arguments
///
/// Returns the SBI return value on success.
///
/// # Errors
/// Returns a negative `i64` error code if the kernel rejects the call
/// (e.g., invalid cap, or SBI firmware returns an error).
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
/// the deadline expires.
///
/// # Errors
/// Returns a negative `i64` error code on failure.
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
/// the bare exit reason (low 32 bits): the pre-multi-bind behaviour.
///
/// Multiple observers can be registered on the same thread — up to the
/// kernel's per-TCB cap. Returns `SyscallError::OutOfMemory` (-3) if the
/// target thread's observer array is full.
///
/// `correlator` is opaque to the kernel. Its meaning is scoped to one
/// `(event queue, binder)` pair — not a system-wide identifier, not a
/// process id. Typical use: the binder stashes an internal routing tag
/// (e.g. procmgr's `ProcessTable` token) so it can dispatch the death
/// event to the right bookkeeping without a secondary lookup.
///
/// # Errors
/// Returns a negative `i64` error code if either cap is invalid or the
/// target's observer array is full.
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

// Silence "unused import" if user only uses some functions.
const _: usize = MSG_DATA_WORDS_MAX;
