// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/syscall_rflags_hardening.rs

//! Integration (x86-64): user-controlled RFLAGS bits and the user GS base do not
//! reach the kernel across a SYSCALL.
//!
//! The SYSCALL entry contract (`core/kernel/src/arch/x86_64/syscall.rs`
//! § Entry contract) clears TF, DF and AC on entry and swaps to the kernel GS
//! base. Three phases exercise it from ring 3:
//!
//!   1. **DF**: with DF set, `SYS_GETRANDOM` fills a buffer that sits between
//!      guard bytes. The kernel's user copy must run forward, so the guard bytes
//!      below the buffer stay intact.
//!   2. **TF**: a child sets TF and issues a syscall. The kernel must take no
//!      single-step trap of its own; the trap belongs to ring 3 after the return,
//!      and with no fault handler bound the child dies with
//!      `EXIT_FAULT_BASE + 1` (`#DB`).
//!   3. **GS**: a child loads the flat user data selector into GS (which reloads
//!      the user GS base from the descriptor) and issues a syscall. The kernel
//!      must keep using its own per-CPU base; the child then exits normally.

use syscall::{cap_delete, cap_info, thread_sleep};
use syscall_abi::{
    CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, SYS_GETRANDOM, SYS_THREAD_YIELD, THREAD_STATE_EXITED,
};

use crate::{ChildStack, TestContext, TestResult};

/// Poll bound: ~2 s at ~1 ms per `thread_sleep(1)` before declaring failure.
const MAX_POLLS: u32 = 2000;

/// Guard bytes on each side of the `SYS_GETRANDOM` destination.
const GUARD: usize = 64;
/// Bytes requested from `SYS_GETRANDOM`.
const DRAW: usize = 32;
const GUARD_BYTE: u8 = 0xA5;

/// Flat ring-3 data selector (`gdt.rs` `USER_DS`).
const USER_DS: u16 = 0x1B;

static mut TF_STACK: ChildStack = ChildStack::ZERO;
static mut GS_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    df_is_clear_in_kernel()?;

    let tf_reason = run_child(ctx, tf_child, core::ptr::addr_of!(TF_STACK))?;
    if tf_reason != EXIT_FAULT_BASE + 1
    {
        return Err("syscall_rflags_hardening: TF child did not die on its own #DB");
    }

    let gs_reason = run_child(ctx, gs_child, core::ptr::addr_of!(GS_STACK))?;
    if gs_reason >= EXIT_FAULT_BASE
    {
        return Err("syscall_rflags_hardening: GS child faulted");
    }
    Ok(())
}

/// Phase 1: `SYS_GETRANDOM` with DF set leaves the guard bytes below the
/// destination untouched.
fn df_is_clear_in_kernel() -> TestResult
{
    let mut buf = [GUARD_BYTE; GUARD + DRAW + GUARD];
    let dst = buf[GUARD..].as_mut_ptr();
    let ret: i64;
    // SAFETY: `dst` names `DRAW` writable bytes of `buf`. DF is set for the
    // syscall only and cleared again before the block ends, as the Rust ABI
    // requires; the syscall clobbers rcx and r11.
    unsafe {
        core::arch::asm!(
            "std",
            "syscall",
            "cld",
            inlateout("rax") SYS_GETRANDOM.cast_signed() => ret,
            in("rdi") dst as u64,
            in("rsi") DRAW as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if ret < 0
    {
        return Err("syscall_rflags_hardening: SYS_GETRANDOM failed");
    }
    if buf[..GUARD]
        .iter()
        .chain(&buf[GUARD + DRAW..])
        .any(|&b| b != GUARD_BYTE)
    {
        return Err("syscall_rflags_hardening: user copy ran with DF set");
    }
    Ok(())
}

/// Start `entry` on a fresh child thread and return its exit reason once the
/// kernel reports it `Exited`.
fn run_child(
    ctx: &TestContext,
    entry: fn(u64) -> !,
    stack: *const ChildStack,
) -> Result<u64, &'static str>
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "syscall_rflags_hardening: spawn::new_child failed")?;
    crate::spawn::configure_and_start(&child, entry, ChildStack::top(stack), 0)
        .map_err(|_| "syscall_rflags_hardening: configure_and_start failed")?;

    let mut polls = 0;
    let reason = loop
    {
        let packed = cap_info(child.th, CAP_INFO_THREAD_STATE)
            .map_err(|_| "syscall_rflags_hardening: cap_info(THREAD_STATE) failed")?;
        // cast_possible_truncation: the state code is the packed high word.
        #[allow(clippy::cast_possible_truncation)]
        let state = (packed >> 32) as u32;
        if state == THREAD_STATE_EXITED
        {
            break packed & 0xFFFF_FFFF;
        }
        polls += 1;
        if polls >= MAX_POLLS
        {
            return Err("syscall_rflags_hardening: child never exited");
        }
        thread_sleep(1).ok();
    };

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    Ok(reason)
}

/// Phase 2 child: set TF, then yield. The single-step trap fires in ring 3 after
/// `sysretq` restores TF, and with no handler bound the kernel kills the thread.
fn tf_child(_arg: u64) -> !
{
    // SAFETY: TF is set deliberately; the trap it raises terminates this thread
    // (no fault handler is bound) before control can leave the block.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "or qword ptr [rsp], 0x100",
            "popfq",
            "syscall",
            inlateout("rax") SYS_THREAD_YIELD => _,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    loop
    {
        core::hint::spin_loop();
    }
}

/// Phase 3 child: reload GS from the flat user data selector, yield, then exit
/// normally.
fn gs_child(_arg: u64) -> !
{
    // SAFETY: loading a ring-3 data selector into GS only changes the user GS
    // base (to the descriptor's base, 0); this code makes no GS-relative access.
    unsafe {
        core::arch::asm!(
            "mov gs, {sel:x}",
            "syscall",
            sel = in(reg) USER_DS,
            inlateout("rax") SYS_THREAD_YIELD => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    syscall::thread_exit()
}
