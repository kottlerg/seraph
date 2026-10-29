// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/syscall/src/arch/x86_64/mod.rs

//! x86-64 raw syscall entry: the `SYSCALL` instruction wrappers.

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
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi; clobbers rcx/r11 as documented.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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

/// Issue a syscall with up to 4 arguments.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10; clobbers rcx/r11 as documented.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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

/// Issue a syscall with up to 5 arguments. Returns the primary return value.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10/r8; clobbers rcx/r11 as documented.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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

/// Issue a syscall with up to 3 arguments.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx; clobbers rcx/r11 as documented.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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

/// Issue any syscall with 3 argument registers and every register the kernel
/// can write on return declared clobbered. Returns the primary return value.
///
/// Unlike [`syscall3`], which declares `rdi`/`rsi`/`rdx` input-only and so
/// serves only syscalls that return in `rax` alone, this declares every
/// argument register (`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`) as discarded on
/// output, so it is sound for a syscall whose return also writes them (the IPC
/// and split calls' `set_ipc_*` returns). `r10`/`r8`/`r9` carry 0.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety, except that the
/// arguments need not match `nr`'s typed contract (pointer arguments must still
/// be valid for the access the kernel makes through them).
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall3_any(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx (r10/r8/r9 zero); every argument register is declared
    // inout-to-discard because the kernel may write return values into any of them, and
    // rcx/r11 are clobbered by SYSCALL. `nomem` is omitted as in `syscall3`; `nostack`
    // holds because the asm itself does not use the Rust stack.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            inout("rdi") a0 => _,
            inout("rsi") a1 => _,
            inout("rdx") a2 => _,
            inout("r10") 0u64 => _,
            inout("r8") 0u64 => _,
            inout("r9") 0u64 => _,
            out("rcx") _,
            out("r11") _,
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
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall5_ret2(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (i64, u64)
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

/// Issue a syscall with 1 argument. Returns (primary, secondary, tertiary, quaternary).
///
/// Used by `ipc_recv` to retrieve `(ret, label, badge, word_count)`.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall1_ret4(nr: u64, a0: u64) -> (i64, u64, u64, u64)
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

/// Issue a syscall with 6 arguments; read back 3 return values.
///
/// Used by `raw_ipc_call` to retrieve `(ret, reply_label, reply_word_count)`.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
// inline_always: syscall wrapper contains inline asm; must inline to call site.
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
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
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10/r8/r9; clobbers rcx/r11. rdx and r9 are inout: third and
    // sixth arguments in, secondary and tertiary returns out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            inout("rdx") a2 => secondary,
            in("r10") a3,
            in("r8")  a4,
            inout("r9") a5 => tertiary,
            out("rcx") _,
            out("r11") _,
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
// cast_possible_wrap: u64 syscall number reinterpreted as i64 register value; bit pattern preserved.
#[allow(clippy::inline_always, clippy::cast_possible_wrap)]
#[inline(always)]
pub unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10/r8/r9; clobbers rcx/r11 as documented.
    // The kernel may read or write user memory that pointer arguments or the registered
    // IPC buffer name, and may change the caller's mappings, so `nomem`/`readonly` are
    // deliberately omitted; `nostack` holds because the asm itself does not use the Rust
    // stack.
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
