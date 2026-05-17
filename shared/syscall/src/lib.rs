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
    SYS_CAP_DERIVE_TOKEN, SYS_CAP_INFO, SYS_CAP_INSERT, SYS_CAP_MOVE, SYS_CAP_REVOKE,
    SYS_EVENT_POST, SYS_EVENT_RECV, SYS_FRAME_MERGE, SYS_FRAME_SPLIT, SYS_IOPORT_BIND,
    SYS_IOPORT_SPLIT, SYS_IPC_BUFFER_SET, SYS_IPC_CALL, SYS_IPC_RECV, SYS_IPC_REPLY, SYS_IRQ_ACK,
    SYS_IRQ_REGISTER, SYS_IRQ_SPLIT, SYS_MEM_MAP, SYS_MEM_PROTECT, SYS_MEM_UNMAP, SYS_MMIO_MAP,
    SYS_MMIO_SPLIT, SYS_SBI_CALL, SYS_SIGNAL_SEND, SYS_SIGNAL_WAIT, SYS_SYSTEM_INFO,
    SYS_THREAD_BIND_NOTIFICATION, SYS_THREAD_CONFIGURE, SYS_THREAD_EXIT, SYS_THREAD_READ_REGS,
    SYS_THREAD_SET_AFFINITY, SYS_THREAD_SET_PRIORITY, SYS_THREAD_SLEEP, SYS_THREAD_START,
    SYS_THREAD_STOP, SYS_THREAD_WRITE_REGS, SYS_THREAD_YIELD, SYS_WAIT_SET_ADD,
    SYS_WAIT_SET_REMOVE, SYS_WAIT_SET_WAIT,
};

pub use syscall_abi::{
    CAP_INFO_ASPACE_PT_BUDGET, CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_CAPACITY,
    CAP_INFO_CSPACE_USED, CAP_INFO_FRAME_AVAILABLE, CAP_INFO_FRAME_HAS_RETYPE,
    CAP_INFO_FRAME_PHYS_BASE, CAP_INFO_FRAME_SIZE, CAP_INFO_TAG_RIGHTS, CAP_TAG_FRAME,
    MAP_EXECUTABLE, MAP_READONLY, MAP_WRITABLE, RIGHTS_ALL, RIGHTS_CSPACE, RIGHTS_MAP_READ,
    RIGHTS_MAP_RW, RIGHTS_MAP_RX, RIGHTS_RECEIVE, RIGHTS_RETYPE, RIGHTS_SEND, RIGHTS_SEND_GRANT,
    RIGHTS_THREAD,
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
///
/// r9 is marked clobbered because `SYS_IPC_CALL`'s kernel handler writes
/// `reply_word_count` into r9 via `set_ipc_call_return`; even though this
/// wrapper does not read r9, LLVM must not assume r9 is preserved.
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
    // args in rdi/rsi/rdx/r10/r8; clobbers rcx/r11/r9; reads secondary return from rdx (lateout).
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
            out("r9")  _,
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
    // args in a0-a4; reads secondary return from a1 (inout). a2 is inout-to-discard
    // because `SYS_IPC_CALL` writes `reply_word_count` into a2 via
    // `set_ipc_call_return`; this wrapper does not consume it, but LLVM must not
    // assume a2 is preserved.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => secondary,
            inout("a2") a2 => _,
            in("a3") a3,
            in("a4") a4,
            in("a7") nr,
            options(nostack),
        );
    }
    (ret, secondary)
}

/// Issue a syscall with 1 argument. Returns (primary, secondary, tertiary, quaternary).
///
/// Used by `ipc_recv` to retrieve `(ret, label, token, word_count)`.
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall1_ret4(nr: u64, a0: u64) -> (i64, u64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let quaternary: u64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // arg in rdi; clobbers rcx/r11; reads secondary from rdx, tertiary from rsi, quaternary
    // from r8 (all lateout, caller-saved; kernel writes them in the trap frame before SYSRET).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            out("rcx") _,
            out("r11") _,
            lateout("rdx") secondary,
            lateout("rsi") tertiary,
            lateout("r8")  quaternary,
            options(nostack),
        );
    }
    (ret, secondary, tertiary, quaternary)
}

#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall1_ret4(nr: u64, a0: u64) -> (i64, u64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let quaternary: u64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // arg in a0 (inout); reads secondary from a1, tertiary from a2, quaternary from a3.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            lateout("a1") secondary,
            lateout("a2") tertiary,
            lateout("a3") quaternary,
            in("a7") nr,
            options(nostack),
        );
    }
    (ret, secondary, tertiary, quaternary)
}

/// Issue a syscall with up to 5 arguments. Returns (primary, secondary, tertiary).
///
/// Used by `ipc_call` to retrieve `(ret, reply_label, reply_word_count)`.
#[cfg(target_arch = "x86_64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall5_ret3(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (i64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10/r8; clobbers rcx/r11; reads secondary from rdx (lateout),
    // tertiary from r9 (lateout — r9 is unused as input since we have 5 args, not 6).
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
            lateout("r9")  tertiary,
            options(nostack),
        );
    }
    (ret, secondary, tertiary)
}

#[cfg(target_arch = "riscv64")]
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
unsafe fn syscall5_ret3(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (i64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a4; reads secondary from a1 (inout), tertiary from a2 (inout).
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => secondary,
            inout("a2") a2 => tertiary,
            in("a3") a3,
            in("a4") a4,
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

/// Raw `SYS_IPC_CALL` issuing syscall5_ret3. Intended for `shared/ipc`'s
/// `IpcMessage`-snapshot wrapper; other callers should use that higher-level
/// entry point.
///
/// Returns `(reply_label, reply_word_count)` on success.
#[doc(hidden)]
#[inline]
pub fn raw_ipc_call(
    ep: u32,
    label: u64,
    data_count: usize,
    cap_count: usize,
    cap_packed: u64,
) -> Result<(u64, usize), i64>
{
    // cast_possible_truncation: word count fits in 16 bits by invariant.
    #[allow(clippy::cast_possible_truncation)]
    let data_count_u64 = data_count as u64;
    #[allow(clippy::cast_possible_truncation)]
    let cap_count_u64 = cap_count as u64;
    // SAFETY: syscall5_ret3 issues raw syscall; args are scalar u64; kernel
    // validates caps and reads/writes the per-thread IPC buffer.
    let (ret, reply_label, reply_word_count) = unsafe {
        syscall5_ret3(
            SYS_IPC_CALL,
            u64::from(ep),
            label,
            data_count_u64,
            cap_count_u64,
            cap_packed,
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
/// Returns `(label, token, word_count)` on success.
#[doc(hidden)]
#[inline]
pub fn raw_ipc_recv(ep: u32) -> Result<(u64, u64, usize), i64>
{
    // SAFETY: syscall1_ret4 issues raw syscall; kernel writes into the
    // per-thread IPC buffer and returns four values in return registers.
    let (ret, label, token, word_count) = unsafe { syscall1_ret4(SYS_IPC_RECV, u64::from(ep)) };
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
        Ok((label, token, word_count))
    }
}

/// Raw `SYS_IPC_REPLY`. Intended for `shared/ipc`'s `IpcMessage`-snapshot
/// wrapper; other callers should use that higher-level entry point.
#[doc(hidden)]
#[inline]
pub fn raw_ipc_reply(
    label: u64,
    data_count: usize,
    cap_count: usize,
    cap_packed: u64,
) -> Result<(), i64>
{
    // cast_possible_truncation: Seraph targets 64-bit only (usize == u64).
    #[allow(clippy::cast_possible_truncation)]
    let data_count_u64 = data_count as u64;
    #[allow(clippy::cast_possible_truncation)]
    let cap_count_u64 = cap_count as u64;
    // SAFETY: syscall4 issues raw syscall; all args scalar; kernel reads IPC
    // buffer and validates caps.
    let ret = unsafe {
        syscall4(
            SYS_IPC_REPLY,
            label,
            data_count_u64,
            cap_count_u64,
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

/// Retype a Frame cap into a new Endpoint. Returns the `CSpace` slot index.
///
/// `frame_cap` is the source Frame-cap slot; it MUST carry `RIGHTS_RETYPE`
/// and have at least 88 B of `available_bytes` (the Endpoint wrapper plus
/// state). Bytes are debited from the Frame cap and credited back when the
/// Endpoint is destroyed.
///
/// # Errors
/// Returns a negative `i64` error code if `frame_cap` is invalid, lacks
/// `RIGHTS_RETYPE`, has insufficient `available_bytes`, or the caller's
/// `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_endpoint(frame_cap: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments;
    // kernel retypes the Frame-cap region and returns the new slot index.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_ENDPOINT, u64::from(frame_cap), 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Retype a Frame cap into a new Signal. Returns the `CSpace` slot index.
///
/// `frame_cap` MUST carry `RIGHTS_RETYPE` and have at least 120 B of
/// `available_bytes`. Bytes are debited from the Frame cap and credited back
/// when the Signal is destroyed.
///
/// # Errors
/// Returns a negative `i64` error code if `frame_cap` is invalid, lacks
/// `RIGHTS_RETYPE`, has insufficient `available_bytes`, or the caller's
/// `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_signal(frame_cap: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; no pointer arguments;
    // kernel retypes the Frame-cap region and returns the new slot index.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_SIGNAL, u64::from(frame_cap), 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Create a new `AddressSpace` object. Returns the `CSpace` slot index.
///
/// Retype a Frame cap into a new `AddressSpace`, or augment an existing
/// one's PT growth budget.
///
/// `frame_cap` must carry `Rights::RETYPE` and have at least
/// `init_pages * PAGE_SIZE` of `available_bytes`. Page 0 of the slab
/// becomes the root PT; pages 1..`init_pages` form the initial PT growth
/// pool. `init_pages` must be `>= 1`.
///
/// `augment_target` selects the mode:
/// - `0` → create a new `AddressSpace`; returns the new cap slot index.
/// - non-zero `AddressSpace` cap slot → augment that AS's PT growth pool;
///   returns `0`.
///
/// # Errors
/// Returns a negative `i64` error code on insufficient frame budget,
/// invalid cap, or a full `CSpace`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_aspace(frame_cap: u32, augment_target: u32, init_pages: u64) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues a raw syscall; arguments are scalar.
    let ret = unsafe {
        syscall3(
            SYS_CAP_CREATE_ASPACE,
            u64::from(frame_cap),
            u64::from(augment_target),
            init_pages,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Retype a Frame cap into a new `CSpace`, or augment an existing one's
/// slot-page growth budget.
///
/// `frame_cap` must carry `Rights::RETYPE` and have at least
/// `init_pages * PAGE_SIZE` of `available_bytes`. All `init_pages`
/// become the initial slot-page pool (the first `CSpace::grow` consumes
/// one). `init_pages` must be `>= 1`.
///
/// `augment_target`:
/// - `0` → create new with `max_slots` (clamped to `[1, 16384]`); returns
///   the new cap slot index.
/// - non-zero → augment that `CSpace`'s growth pool; returns `0`. The
///   `max_slots` argument is ignored in augment mode.
///
/// # Errors
/// Returns a negative `i64` error code on insufficient frame budget,
/// invalid cap, or a full `CSpace`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_cspace(
    frame_cap: u32,
    augment_target: u32,
    init_pages: u64,
    max_slots: u64,
) -> Result<u32, i64>
{
    // SAFETY: syscall4 issues a raw syscall; arguments are scalar.
    let ret = unsafe {
        syscall4(
            SYS_CAP_CREATE_CSPACE,
            u64::from(frame_cap),
            u64::from(augment_target),
            init_pages,
            max_slots,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Retype a Frame cap into a new Thread bound to `aspace_cap` and
/// `cspace_cap`. Returns the `CSpace` slot index of the new Thread cap.
///
/// `frame_cap` must carry `Rights::RETYPE` and have at least 5 pages of
/// `available_bytes` (4 kstack pages plus 1 page for the wrapper and
/// TCB; see `cap::retype::dispatch_for(Thread)`).
///
/// # Errors
/// Returns a negative `i64` error code if any cap is invalid, the Frame
/// cap lacks `RETYPE` or sufficient `available_bytes`, or the caller's
/// `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn cap_create_thread(frame_cap: u32, aspace_cap: u32, cspace_cap: u32) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; frame_cap, aspace_cap, and
    // cspace_cap are cap indices passed as u64; kernel validates caps, retypes,
    // returns slot index.
    let ret = unsafe {
        syscall3(
            SYS_CAP_CREATE_THREAD,
            u64::from(frame_cap),
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

/// Carve a virgin tail off `frame_cap`.
///
/// `split_offset` is in bytes and must be page-aligned, > 0, < the frame
/// size, and at or above the next page boundary above the cap's highest
/// live retype offset (a cap that has never been retyped has bump = 0,
/// so any in-range page-aligned offset is acceptable).
///
/// The parent (`frame_cap`) stays in its slot; its `size` shrinks to
/// `split_offset` and its `available_bytes` debits accordingly. A new
/// child cap covering `[base + split_offset, base + orig_size)` is
/// inserted in the caller's `CSpace` as a derivation sibling of the
/// parent. Returns the new tail slot index.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid,
/// `split_offset` is not page-aligned, is out of range, lands inside
/// the cap's bump region, or the parent has derivation children.
// cast_sign_loss: proven non-negative in Ok branch.
// cast_possible_truncation: returned value is a 32-bit slot index.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn frame_split(frame_cap: u32, split_offset: u64) -> Result<u32, i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; frame_cap is cap index as u64, split_offset
    // is byte offset; kernel validates cap and offset, returns the new tail slot.
    let ret = unsafe { syscall3(SYS_FRAME_SPLIT, u64::from(frame_cap), split_offset, 0) };
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}

/// Absorb a virgin tail Frame cap back into its parent.
///
/// Inverse of [`frame_split`] under Option D. `parent_cap` covers the
/// physically-lower half and `tail_cap` the upper;
/// `parent.base + parent.size == tail.base` is required. Both caps must
/// share the same rights, `owns_memory` state, derivation parent, and
/// have no derivation children. The tail must be virgin (no live
/// retypes against it).
///
/// `parent_cap`'s slot stays valid; its `size` and `available_bytes`
/// grow to cover the absorbed tail. `tail_cap`'s slot is freed; the tail
/// `FrameObject` is dec-ref'd without buddy-freeing the underlying
/// physical region (parent now covers it).
///
/// Used by memmgr to coalesce free-pool runs after `RELEASE_FRAMES` and
/// `PROCESS_DIED` reclamation.
///
/// # Errors
/// Returns a negative `i64` error code if the caps fail validation.
#[inline]
pub fn frame_merge(parent_cap: u32, tail_cap: u32) -> Result<(), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; both caps are u32 cap indices;
    // kernel validates contiguity, rights, and derivation invariants.
    let ret = unsafe {
        syscall3(
            SYS_FRAME_MERGE,
            u64::from(parent_cap),
            u64::from(tail_cap),
            0,
        )
    };
    if ret < 0 { Err(ret) } else { Ok(()) }
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

/// Split an `Interrupt` range cap into two non-overlapping children.
///
/// `split_at` is the first IRQ id of the upper child (and the exclusive
/// upper bound of the lower child); it must satisfy
/// `start < split_at < start + count` on the cap being split. The
/// original cap is revoked on success; both children inherit the parent's
/// rights. Returns packed `(lower_slot, upper_slot)`.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid or `split_at`
/// falls outside the cap's range.
// cast_sign_loss / cast_possible_truncation: identical to `mmio_split`.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn irq_split(irq_cap: u32, split_at: u32) -> Result<(u32, u32), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; kernel validates cap and split point.
    let ret = unsafe { syscall3(SYS_IRQ_SPLIT, u64::from(irq_cap), u64::from(split_at), 0) };
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

/// Split an `IoPortRange` cap into two non-overlapping children.
///
/// `split_at` is the first port of the upper child (and the exclusive upper
/// bound of the lower child); it must satisfy `base < split_at < base + size`
/// on the cap being split, with `size == 0` interpreted as the full 64K
/// range. Additionally `split_at` must be non-zero (a zero split would
/// yield an empty lower half) and lie in `1..=0xFFFF`; the kernel rejects
/// values outside that range with `InvalidArgument` before loading the cap.
/// The original cap is revoked on success; both children inherit the
/// parent's rights. Returns packed `(lower_slot, upper_slot)`.
///
/// On RISC-V: always returns `NotSupported`.
///
/// # Errors
/// Returns a negative `i64` error code if the cap is invalid, `split_at`
/// falls outside the cap's range, or the syscall is not supported on this
/// architecture.
// cast_sign_loss / cast_possible_truncation: identical to `mmio_split`.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
#[inline]
pub fn ioport_split(ioport_cap: u32, split_at: u16) -> Result<(u32, u32), i64>
{
    // SAFETY: syscall3 issues raw syscall instruction; kernel validates cap and split point.
    let ret = unsafe {
        syscall3(
            SYS_IOPORT_SPLIT,
            u64::from(ioport_cap),
            u64::from(split_at),
            0,
        )
    };
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

/// Inspect a capability slot's runtime state.
///
/// `slot` — capability slot index in the caller's `CSpace`.
/// `field` — field selector (one of the `CAP_INFO_*` constants in
/// `syscall_abi`). Each call returns a single `u64`. Userspace assembles
/// a full picture by issuing repeated calls. The pattern mirrors
/// [`system_info`].
///
/// # Field semantics
/// - `CAP_INFO_TAG_RIGHTS` is valid for any non-null slot and returns
///   `((tag as u8 as u64) << 32) | (rights as u32 as u64)`.
/// - All other selectors are tag-specific:
///   - `CAP_INFO_FRAME_*` require `CapTag::Frame`.
///   - `CAP_INFO_ASPACE_*` require `CapTag::AddressSpace`.
///   - `CAP_INFO_CSPACE_*` require `CapTag::CSpace`.
///
/// Calling a tag-specific field on a slot whose tag does not match
/// returns `SyscallError::InvalidArgument` (-5). Unknown selectors return
/// the same error.
///
/// # Errors
/// Returns a negative `i64` error code if the slot is null/invalid
/// (`InvalidCapability`) or the selector is unknown / mismatched
/// (`InvalidArgument`).
// cast_sign_loss: ret is proven non-negative in the Ok branch.
#[allow(clippy::cast_sign_loss)]
#[inline]
pub fn cap_info(slot: u32, field: u64) -> Result<u64, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; slot is cap index as u64,
    // field is one of the CAP_INFO_* selectors. The kernel performs all validation
    // (slot bounds, tag match for tag-specific fields, selector recognition) and
    // returns the requested field value.
    let ret = unsafe { syscall2(SYS_CAP_INFO, u64::from(slot), field) };
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

/// Retype a Frame cap into a new `EventQueue` with the given capacity (1..=4096).
///
/// `frame_cap` MUST carry `RIGHTS_RETYPE`; the wrapper, state, and ring
/// buffer all live inline in the same retype slot. Sub-page in-place when
/// the total fits in `BIN_512` (≈ capacity ≤ 54), page-aligned split for
/// larger rings.
///
/// # Errors
/// Returns a negative `i64` error code if `frame_cap` is invalid, lacks
/// `RIGHTS_RETYPE`, has insufficient `available_bytes`, `capacity` is out
/// of range, or the `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn event_queue_create(frame_cap: u32, capacity: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; arg0 = source Frame
    // cap slot, arg1 = capacity. Kernel retypes the region.
    let ret = unsafe {
        syscall2(
            SYS_CAP_CREATE_EVENT_Q,
            u64::from(frame_cap),
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
    // SAFETY: syscall5_ret2 issues raw syscall instruction; arg1 = 0 is the
    // "block forever" sentinel for `SYS_EVENT_RECV` (matches `SYS_SIGNAL_WAIT`).
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
    // SAFETY: syscall5_ret2 issues raw syscall instruction; arg1 = u64::MAX
    // is the "non-blocking try-once" sentinel for `SYS_EVENT_RECV`.
    let (ret, payload) =
        unsafe { syscall5_ret2(SYS_EVENT_RECV, u64::from(queue_cap), u64::MAX, 0, 0, 0) };
    if ret < 0 { Err(ret) } else { Ok(payload) }
}

/// Dequeue with a timeout. `timeout_ms == 0` blocks indefinitely (same as
/// [`event_recv`]); `timeout_ms == u64::MAX` is a non-blocking poll (same as
/// [`event_try_recv`]); any other value blocks for up to `timeout_ms`
/// milliseconds, then returns `Err(-6)` (`WouldBlock`) if no post arrived.
///
/// # Errors
/// Returns `-6` (`WouldBlock`) on timeout or empty try-once, or another
/// negative `i64` error code on invalid cap.
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

/// Retype a Frame cap into a new `WaitSet` with `MODIFY | WAIT` rights.
///
/// `frame_cap` MUST carry `RIGHTS_RETYPE` and have ≥ 512 bytes of
/// `available_bytes` (the `BIN_512` size class debited from the ledger).
///
/// # Errors
/// Returns a negative `i64` error code if `frame_cap` is invalid, lacks
/// `RIGHTS_RETYPE`, or the `CSpace` is full.
// cast_possible_truncation, cast_sign_loss: ret is a non-negative CSpace slot index
// guaranteed to fit in u32 (max CSpace size is 16384).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
pub fn wait_set_create(frame_cap: u32) -> Result<u32, i64>
{
    // SAFETY: syscall2 issues raw syscall instruction; arg0 = source Frame
    // cap slot. Kernel retypes the region.
    let ret = unsafe { syscall2(SYS_CAP_CREATE_WAIT_SET, u64::from(frame_cap), 0) };
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

// ── Hardware access wrappers ──────────────────────────────────────────────────

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
/// Takes effect on the thread's next enqueue. A thread already running
/// on or queued on another CPU is not actively migrated.
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
