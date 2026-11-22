// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/syscall/src/arch/riscv64/mod.rs

//! RISC-V raw syscall entry: the `ECALL` instruction wrappers.

/// Issue a syscall with up to 2 arguments. Returns the primary return value.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
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
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
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
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
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
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
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

/// Issue any syscall with 4 argument registers and every register the kernel
/// can write on return declared clobbered. Returns the primary return value.
///
/// Unlike [`syscall3`], which declares `a1`/`a2` input-only and so serves only
/// syscalls that return in `a0` alone, this declares every argument register
/// (`a1` to `a5`) as discarded on output, and the message registers `a6`,
/// `t0`, `t1`, `t2` with them, so a syscall whose return also writes them
/// (`SYS_SCHED_SPLIT`'s second handle in `a1`, an IPC delivery's message
/// registers) leaves no register the compiler assumes preserved. `a4` and `a5`
/// carry 0.
///
/// # Safety
///
/// The `# Safety` contract of `crate::raw_syscall4`, its only caller, which
/// replaces the raw-wrapper contract in [`crate::arch`] § Safety. The call must
/// leave untouched everything the calling program runs on (see that contract's
/// four conditions). Under it any argument value is admissible, and `nr` need
/// not be a defined syscall.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
#[inline(always)]
pub unsafe fn syscall4_any(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64
{
    let ret: i64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a3 (a4-a5 zero); every argument register and the message registers
    // a6/t0-t2 are declared clobbered because the kernel may write return values into any
    // of them. `nomem` is omitted as
    // in `syscall3`; `nostack` holds because the asm itself does not use the Rust stack.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => _,
            inout("a2") a2 => _,
            inout("a3") a3 => _,
            inout("a4") 0u64 => _,
            inout("a5") 0u64 => _,
            out("a6") _,
            out("t0") _,
            out("t1") _,
            out("t2") _,
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
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
#[inline(always)]
pub unsafe fn syscall5_ret2(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (i64, u64)
{
    let ret: i64;
    let secondary: u64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a4; reads secondary return from a1 (inout). a2 is inout-to-discard
    // defensively: the kernel's IPC return path writes it (`SYS_IPC_CALL` itself
    // goes through `syscall_ipc_call`), and LLVM must not assume it preserved.
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

/// Issue a syscall with 2 arguments. Returns (primary, secondary, tertiary).
///
/// Used by the event-queue receive wrappers to retrieve `(ret, payload, tag)`
/// from a0, a1 and a2.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
#[inline(always)]
pub unsafe fn syscall2_ret3(nr: u64, a0: u64, a1: u64) -> (i64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a1; reads secondary return from a1 (inout) and tertiary from a2; a3 is
    // discarded defensively (an IPC return register).
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => secondary,
            lateout("a2") tertiary,
            lateout("a3") _,
            in("a7") nr,
            options(nostack),
        );
    }
    (ret, secondary, tertiary)
}

/// Issue `SYS_IPC_CALL`: `a0` to `a3` in `a0` to `a3`, and the message
/// registers MR0..MR5 (`a4`, `a5`, `a6`, `t0`, `t1`, `t2`) from `mr`. Returns
/// `(primary, reply label from a1, delivered count word from a2, the message
/// registers on return)`.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
#[inline(always)]
pub unsafe fn syscall_ipc_call(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    mr: [u64; 6],
) -> (i64, u64, u64, [u64; 6])
{
    let ret: i64;
    let label: u64;
    let counts: u64;
    let [mut m0, mut m1, mut m2, mut m3, mut m4, mut m5] = mr;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a3; reads the reply label from a1 (inout) and the count word from a2
    // (inout). The message registers are inout: the request's words in, the reply's out
    // (the kernel writes only the delivered words and leaves the rest as they were).
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => label,
            inout("a2") a2 => counts,
            in("a3") a3,
            inout("a4") m0,
            inout("a5") m1,
            inout("a6") m2,
            inout("t0") m3,
            inout("t1") m4,
            inout("t2") m5,
            in("a7") nr,
            options(nostack),
        );
    }
    (ret, label, counts, [m0, m1, m2, m3, m4, m5])
}

/// Issue `SYS_IPC_RECV`: `a0` and `a1` in `a0` and `a1`. Returns `(primary,
/// label from a1, badge from a2, delivered count word from a3, the message
/// registers MR0..MR5 (`a4`, `a5`, `a6`, `t0`, `t1`, `t2`) on return)`.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
#[inline(always)]
pub unsafe fn syscall_ipc_recv(nr: u64, a0: u64, a1: u64) -> (i64, u64, u64, u64, [u64; 6])
{
    let ret: i64;
    let label: u64;
    let badge: u64;
    let counts: u64;
    let (m0, m1, m2, m3, m4, m5): (u64, u64, u64, u64, u64, u64);
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0 and a1 (inout); reads the label from a1, the badge from a2, the count
    // word from a3 and the message registers.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            inout("a1") a1 => label,
            lateout("a2") badge,
            lateout("a3") counts,
            lateout("a4") m0,
            lateout("a5") m1,
            lateout("a6") m2,
            lateout("t0") m3,
            lateout("t1") m4,
            lateout("t2") m5,
            in("a7") nr,
            options(nostack),
        );
    }
    (ret, label, badge, counts, [m0, m1, m2, m3, m4, m5])
}

/// Issue `SYS_IPC_REPLY`: `a0` to `a2` in `a0` to `a2`, and the message
/// registers MR0..MR5 (`a4`, `a5`, `a6`, `t0`, `t1`, `t2`) from `mr`.
/// Returns the primary return value.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
#[inline(always)]
pub unsafe fn syscall_ipc_reply(nr: u64, a0: u64, a1: u64, a2: u64, mr: [u64; 6]) -> i64
{
    let ret: i64;
    let [m0, m1, m2, m3, m4, m5] = mr;
    let a0 = a0 as i64;
    // SAFETY: inline asm issues ecall instruction per RISC-V ABI; syscall number in a7,
    // args in a0-a2 and the message registers. The reply returns in a0 alone.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a4") m0,
            in("a5") m1,
            in("a6") m2,
            in("t0") m3,
            in("t1") m4,
            in("t2") m5,
            in("a7") nr,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with 6 arguments. Returns the primary return value.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 arg \
              is reinterpreted as an i64 register value with its bit pattern preserved"
)]
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
