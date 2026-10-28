// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/syscall_rflags_hardening.rs

//! Integration (x86-64): user-controlled RFLAGS bits and the user GS base do not
//! reach the kernel across a SYSCALL.
//!
//! The SYSCALL entry contract (`core/kernel/src/arch/x86_64/syscall.rs`
//! § Entry contract) clears TF, DF and AC on entry and swaps to the kernel GS
//! base. Three phases exercise it from ring 3:
//!
//!   1. **DF**: with DF set, `SYS_GETRANDOM` fills a buffer that sits between
//!      guard bytes. The kernel's user copy must run forward, so the guard bytes
//!      stay intact.
//!   2. **TF**: a child sets TF and issues a syscall. The kernel must take no
//!      single-step trap of its own; the trap belongs to ring 3 after the return,
//!      and with no fault handler bound the child dies with
//!      `EXIT_FAULT_BASE + DEBUG_VECTOR`.
//!   3. **GS**: a child loads the flat user data selector into GS (which reloads
//!      the user GS base from the descriptor) and issues a syscall. The kernel
//!      must keep using its own per-CPU base; the child then exits normally.

use syscall::cap_delete;
use syscall_abi::{EXIT_FAULT_BASE, SYS_GETRANDOM, SYS_THREAD_YIELD};

use crate::{ChildStack, TestContext, TestResult};

/// `#DB`, the vector a single-step trap is delivered on.
const DEBUG_VECTOR: u64 = 1;

/// Poll bound: ~2 s at ~1 ms per poll before declaring failure.
const MAX_POLLS: u32 = 2000;

/// Guard bytes on each side of the `SYS_GETRANDOM` destination.
const GUARD: usize = 64;
/// Bytes requested from `SYS_GETRANDOM`.
const DRAW: usize = 32;
const GUARD_BYTE: u8 = 0xA5;

/// Flat ring-3 data selector (`core/kernel/src/arch/x86_64/gdt.rs` `USER_DS`).
const USER_DS: u16 = 0x1B;

static mut TF_STACK: ChildStack = ChildStack::ZERO;
static mut GS_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    df_is_clear_in_kernel()?;

    let tf_reason = run_child(ctx, tf_child, core::ptr::addr_of!(TF_STACK))?;
    if tf_reason != EXIT_FAULT_BASE + DEBUG_VECTOR
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

/// Phase 1: `SYS_GETRANDOM` with DF set leaves the guard bytes untouched.
fn df_is_clear_in_kernel() -> TestResult
{
    let mut buf = [GUARD_BYTE; GUARD + DRAW + GUARD];
    let ret = getrandom_with_df_set(&mut buf[GUARD..GUARD + DRAW]);
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

/// Issue `SYS_GETRANDOM` into `dst` with RFLAGS.DF set for the syscall only.
fn getrandom_with_df_set(dst: &mut [u8]) -> i64
{
    let ret: i64;
    // SAFETY: `dst` is a live, writable buffer of `dst.len()` bytes. DF is set
    // for the syscall only and cleared before the block ends, as the Rust ABI
    // requires. Registers: rax carries the syscall number in and the result out;
    // rdi and rsi carry the arguments; SYSCALL clobbers rcx and r11.
    unsafe {
        core::arch::asm!(
            "std",
            "syscall",
            "cld",
            inlateout("rax") SYS_GETRANDOM.cast_signed() => ret,
            in("rdi") dst.as_mut_ptr() as u64,
            in("rsi") dst.len() as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Start `entry` on a fresh child thread and return its exit reason once the
/// kernel reports it `Exited`. The child's caps are deleted on every path.
fn run_child(
    ctx: &TestContext,
    entry: extern "C" fn(u64) -> !,
    stack: *const ChildStack,
) -> Result<u64, &'static str>
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "syscall_rflags_hardening: spawn::new_child failed")?;
    let reason = crate::spawn::configure_and_start(&child, entry, ChildStack::top(stack), 0)
        .map_err(|_| "syscall_rflags_hardening: configure_and_start failed")
        .and_then(|()| crate::spawn::wait_until_exited(child.th, MAX_POLLS));
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    reason
}

/// Phase 2 child: set TF, then yield. The single-step trap fires in ring 3 after
/// `sysretq` restores TF, and with no handler bound the kernel kills the thread.
extern "C" fn tf_child(_arg: u64) -> !
{
    yield_with_tf_set();
    loop
    {
        core::hint::spin_loop();
    }
}

/// Set RFLAGS.TF and issue `SYS_THREAD_YIELD`.
fn yield_with_tf_set()
{
    // SAFETY: TF is set deliberately; the trap it raises terminates this thread
    // (no fault handler is bound) before control leaves the block. Registers: rax
    // carries the syscall number in and the result out; SYSCALL clobbers rcx and
    // r11; pushfq/popfq use the stack.
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
}

/// Phase 3 child: reload GS from the flat user data selector, yield, then exit
/// normally.
extern "C" fn gs_child(_arg: u64) -> !
{
    yield_with_user_gs_reloaded();
    syscall::thread_exit()
}

/// Load [`USER_DS`] into GS and issue `SYS_THREAD_YIELD`.
fn yield_with_user_gs_reloaded()
{
    // SAFETY: loading a ring-3 data selector into GS only changes the user GS
    // base (to the descriptor's base, 0); this code makes no GS-relative access.
    // Registers: the selector is an input in any register; rax carries the
    // syscall number in and the result out; SYSCALL clobbers rcx and r11; GS is
    // changed and not restored (nothing in this thread uses it).
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
}
