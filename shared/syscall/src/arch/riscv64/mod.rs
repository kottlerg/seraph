// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/syscall/src/arch/riscv64/mod.rs

//! RISC-V raw syscall entry: the `ECALL` instruction wrappers.

// `no_core` (feature `rustc-dep-of-std`) disables the automatic prelude in
// every module, not only the crate root; bring it in here as lib.rs does.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

/// Issue a syscall with up to 2 arguments. Returns the primary return value.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0/a1; no caller-saved registers clobbered beyond return.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a3; no caller-saved registers clobbered beyond return.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a4; no caller-saved registers clobbered beyond return.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a2; no caller-saved registers clobbered beyond return.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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

/// Issue any syscall with 3 argument registers and every register the kernel
/// can write on return declared clobbered. Returns the primary return value.
///
/// Unlike [`syscall3`], which declares `a1`/`a2` input-only and so serves only
/// syscalls that return in `a0` alone, this declares every argument register
/// (`a1` to `a5`) as discarded on output, so a syscall whose return also writes
/// them (`SYS_SCHED_SPLIT`'s second handle in `a1`) leaves no register the
/// compiler assumes preserved. `a3` to `a5` carry 0.
///
/// # Safety
///
/// The contract of `crate::raw_syscall3`, its only caller, in place of the
/// raw-wrapper contract in [`crate::arch`] § Safety: the call's effects must be
/// confined to kernel objects the capability arguments name (no user-pointer
/// argument, no IPC buffer, no change to the caller's mappings or to the
/// register state or execution of a thread in its address space). Any argument
/// value is then admissible, and `nr` need not be a defined syscall (the kernel
/// returns `UnknownSyscall` in the primary register and changes nothing else).
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall3_any(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a2 (a3-a5 zero); every argument register is declared inout-to-discard
    // because the kernel may write return values into any of them. `nomem` is omitted as
    // in `syscall3`; `nostack` holds because the asm itself does not use the Rust stack.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => _,
            inout("a2") a2 => _,
            inout("a3") 0u64 => _,
            inout("a4") 0u64 => _,
            inout("a5") 0u64 => _,
            in("a7") nr,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with up to 5 arguments. Returns (primary, secondary).
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall5_ret2(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (i64, u64)
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
/// Used by `ipc_recv` to retrieve `(ret, label, badge, word_count)`.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall1_ret4(nr: u64, a0: u64) -> (i64, u64, u64, u64)
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

/// Issue a syscall with 6 arguments; read back 3 return values.
///
/// Used by `raw_ipc_call` to retrieve `(ret, reply_label, reply_word_count)`.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall6_ret3(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> (i64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a5; reads secondary from a1 (inout), tertiary from a2 (inout).
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => secondary,
            inout("a2") a2 => tertiary,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            in("a7") nr,
            options(nostack),
        );
    }
    (ret, secondary, tertiary)
}

/// Issue a syscall with 6 arguments. Returns the primary return value.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 arg reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a5; no caller-saved registers clobbered beyond return.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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
