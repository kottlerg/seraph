// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/syscall/src/arch/x86_64/mod.rs

//! x86-64 raw syscall entry: the `SYSCALL` instruction wrappers.

/// Issue a syscall with up to 2 arguments. Returns the primary return value.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
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
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
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
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
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
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
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

/// Issue any syscall with 4 argument registers and every register the kernel
/// can write on return declared clobbered. Returns the primary return value.
///
/// Unlike [`syscall3`], which declares `rdi`/`rsi`/`rdx` input-only and so
/// serves only syscalls that return in `rax` alone, this declares every
/// argument register (`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`) as discarded on
/// output, and the message registers `r12` to `r15` with them, so a syscall
/// whose return also writes them (`SYS_SCHED_SPLIT`'s second handle in `rdx`,
/// an IPC delivery's message registers) leaves no register the compiler
/// assumes preserved. `r8`/`r9` carry 0.
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
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
#[inline(always)]
pub unsafe fn syscall4_any(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64
{
    let ret: i64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10 (r8/r9 zero); every argument register and the message
    // registers r12-r15 are declared clobbered because the kernel may write return values
    // into any of them, and rcx/r11 are clobbered by SYSCALL. `nomem` is omitted as in `syscall3`; `nostack`
    // holds because the asm itself does not use the Rust stack.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            inout("rdi") a0 => _,
            inout("rsi") a1 => _,
            inout("rdx") a2 => _,
            inout("r10") a3 => _,
            inout("r8") 0u64 => _,
            inout("r9") 0u64 => _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with up to 5 arguments. Returns (primary, secondary).
///
/// r9 is marked clobbered defensively: it is an IPC message register (MR1),
/// which the kernel writes only on an IPC delivery (`SYS_IPC_CALL` itself goes
/// through `syscall_ipc_call`).
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
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

/// Issue a syscall with 2 arguments. Returns (primary, secondary, tertiary).
///
/// Used by the event-queue receive wrappers to retrieve `(ret, payload, tag)`:
/// the kernel writes the secondary return to rdx and the tertiary to rsi, the
/// register that carried argument 1 in.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
#[inline(always)]
pub unsafe fn syscall2_ret3(nr: u64, a0: u64, a1: u64) -> (i64, u64, u64)
{
    let ret: i64;
    let secondary: u64;
    let tertiary: u64;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi; clobbers rcx/r11, and r8/r9 defensively (IPC message registers);
    // reads secondary return from rdx and tertiary from rsi (inout).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            inout("rsi") a1 => tertiary,
            lateout("rdx") secondary,
            out("rcx") _,
            out("r11") _,
            out("r8")  _,
            out("r9")  _,
            options(nostack),
        );
    }
    (ret, secondary, tertiary)
}

/// Issue `SYS_IPC_CALL`: `a0` to `a3` in `rdi`, `rsi`, `rdx`, `r10`, and the
/// message registers MR0..MR5 (`r8`, `r9`, `r12` to `r15`) from `mr`. Returns
/// `(primary, reply label from rdx, delivered count word from r10, the message
/// registers on return)`.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
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
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx/r10; clobbers rcx/r11. rdx and r10 are inout: third and fourth
    // arguments in, reply label and count word out. The message registers are inout: the
    // request's words in, the reply's out (the kernel writes only the delivered words and
    // leaves the rest as they were).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            inout("rdx") a2 => label,
            inout("r10") a3 => counts,
            inout("r8") m0,
            inout("r9") m1,
            inout("r12") m2,
            inout("r13") m3,
            inout("r14") m4,
            inout("r15") m5,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    (ret, label, counts, [m0, m1, m2, m3, m4, m5])
}

/// Issue `SYS_IPC_RECV`: `a0` and `a1` in `rdi` and `rsi`. Returns `(primary,
/// label from rdx, badge from rsi, delivered count word from r10, the message
/// registers MR0..MR5 (`r8`, `r9`, `r12` to `r15`) on return)`.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
#[inline(always)]
pub unsafe fn syscall_ipc_recv(nr: u64, a0: u64, a1: u64) -> (i64, u64, u64, u64, [u64; 6])
{
    let ret: i64;
    let label: u64;
    let badge: u64;
    let counts: u64;
    let (m0, m1, m2, m3, m4, m5): (u64, u64, u64, u64, u64, u64);
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi and rsi; clobbers rcx/r11; reads the label from rdx, the badge from rsi
    // (inout: it carries a1 in), the count word from r10 and the message registers
    // (lateout, caller-visible; the kernel writes them in the trap frame before SYSRET).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            inout("rsi") a1 => badge,
            lateout("rdx") label,
            lateout("r10") counts,
            lateout("r8") m0,
            lateout("r9") m1,
            lateout("r12") m2,
            lateout("r13") m3,
            lateout("r14") m4,
            lateout("r15") m5,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    (ret, label, badge, counts, [m0, m1, m2, m3, m4, m5])
}

/// Issue `SYS_IPC_REPLY`: `a0` to `a2` in `rdi`, `rsi`, `rdx`, and the message
/// registers MR0..MR5 (`r8`, `r9`, `r12` to `r15`) from `mr`. Returns the
/// primary return value.
///
/// # Safety
///
/// The raw-wrapper contract in [`crate::arch`] § Safety.
#[expect(
    clippy::inline_always,
    clippy::cast_possible_wrap,
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
#[inline(always)]
pub unsafe fn syscall_ipc_reply(nr: u64, a0: u64, a1: u64, a2: u64, mr: [u64; 6]) -> i64
{
    let ret: i64;
    let [m0, m1, m2, m3, m4, m5] = mr;
    let nr = nr as i64;
    // SAFETY: inline asm issues syscall instruction per x86-64 ABI; syscall number in rax,
    // args in rdi/rsi/rdx and the message registers; clobbers rcx/r11. The reply returns in
    // rax alone.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r8") m0,
            in("r9") m1,
            in("r12") m2,
            in("r13") m3,
            in("r14") m4,
            in("r15") m5,
            out("rcx") _,
            out("r11") _,
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
    reason = "syscall wrapper contains inline asm and must inline to the call site; the u64 \
              syscall number is reinterpreted as an i64 register value with its bit pattern \
              preserved"
)]
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
