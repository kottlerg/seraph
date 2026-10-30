// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/syscall_rflags_hardening.rs

//! Integration (x86-64): user-controlled RFLAGS bits and the user GS base do not
//! reach the kernel across a SYSCALL.
//!
//! The SYSCALL entry contract (`core/kernel/src/arch/x86_64/syscall.rs`
//! § Entry contract) clears TF, DF and AC on entry and swaps to the kernel GS
//! base. Four phases exercise it from ring 3:
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
//!   4. **AC**: with AC set, `SYS_GETRANDOM` fills a buffer through the kernel's
//!      SMAP-windowed user copy, and AC is still set when the syscall returns
//!      (`sysretq` restores the user's RFLAGS). A kernel that mishandled a
//!      user-set AC on entry, or dropped it from the user's RFLAGS, fails here.
//!      Whether AC is clear while the kernel runs has no ring-3-visible effect
//!      (it only lifts SMAP for kernel accesses outside the user-copy window,
//!      which the kernel makes none of), so the kernel observes it itself: in
//!      debug builds `syscall::dispatch` asserts AC, DF and TF clear
//!      (`arch::current::cpu::debug_assert_kernel_entry_flags`), and this
//!      phase's syscall trips that assertion if SYSCALL entry left AC set.

use syscall::cap_delete;
use syscall_abi::{EXIT_FAULT_BASE, SYS_GETRANDOM, SYS_THREAD_YIELD};

use crate::{ChildStack, TestContext, TestResult};

/// `#DB`, the vector a single-step trap is delivered on.
const DEBUG_VECTOR: u64 = 1;

/// Poll bound: ~2 s at ~1 ms per poll before declaring failure.
/// Applied through [`crate::scaled_polls`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs, where the child's CPU waits for a host core.
const MAX_POLLS: u32 = 2000;

/// Guard bytes on each side of the `SYS_GETRANDOM` destination.
const GUARD: usize = 64;
/// Bytes requested from `SYS_GETRANDOM`.
const DRAW: usize = 32;
const GUARD_BYTE: u8 = 0xA5;

/// RFLAGS.AC (bit 18), the alignment-check / SMAP-override flag.
const RFLAGS_AC: u64 = 1 << 18;

/// The low RFLAGS doubleword's AC bit, and its complement, as the 32-bit
/// immediates that set and clear it in the stack image of RFLAGS.
const AC_SET_IMM: i32 = 1 << 18;
const AC_CLEAR_IMM: i32 = !AC_SET_IMM;

/// Flat ring-3 data selector (`core/kernel/src/arch/x86_64/gdt.rs` `USER_DS`).
const USER_DS: u16 = 0x1B;

static mut TF_STACK: ChildStack = ChildStack::ZERO;
static mut GS_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    df_is_clear_in_kernel()?;

    // SAFETY: TF_STACK is this test's own `ChildStack`, used by this child
    // alone (`ChildStack`'s rule).
    let tf_reason = unsafe { run_child(ctx, tf_child, core::ptr::addr_of!(TF_STACK)) }?;
    if tf_reason != EXIT_FAULT_BASE + DEBUG_VECTOR
    {
        return Err("syscall_rflags_hardening: TF child did not die on its own #DB");
    }

    // SAFETY: GS_STACK is this test's own `ChildStack`, used by this child
    // alone (`ChildStack`'s rule).
    let gs_reason = unsafe { run_child(ctx, gs_child, core::ptr::addr_of!(GS_STACK)) }?;
    if gs_reason >= EXIT_FAULT_BASE
    {
        return Err("syscall_rflags_hardening: GS child faulted");
    }

    ac_survives_syscall()
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

/// Phase 4: `SYS_GETRANDOM` with AC set fills its buffer and returns with AC
/// still set.
fn ac_survives_syscall() -> TestResult
{
    let mut buf = [GUARD_BYTE; DRAW];
    let (ret, rflags) = getrandom_with_ac_set(&mut buf);
    if ret < 0
    {
        return Err("syscall_rflags_hardening: SYS_GETRANDOM with AC set failed");
    }
    if buf.iter().all(|&b| b == GUARD_BYTE)
    {
        return Err("syscall_rflags_hardening: SYS_GETRANDOM with AC set wrote nothing");
    }
    if rflags & RFLAGS_AC == 0
    {
        return Err("syscall_rflags_hardening: user AC lost across the syscall");
    }
    Ok(())
}

/// Issue `SYS_GETRANDOM` into `dst` with RFLAGS.AC set for the syscall only;
/// returns the syscall result and RFLAGS as read right after it returned.
fn getrandom_with_ac_set(dst: &mut [u8]) -> (i64, u64)
{
    let ret: i64;
    let rflags: u64;
    // SAFETY: `dst` is a live, writable buffer of `dst.len()` bytes. AC is set
    // through the stack image of RFLAGS (`stac` is ring-0 only) and cleared the
    // same way before the block ends; while it is set only the syscall and
    // four aligned stack accesses run (the `pushfq`, the `mov` that reads
    // RFLAGS back, the dword `and` that clears AC in the stack image, and the
    // `popfq` load), so no user access can take an alignment check.
    // Registers: rax carries the syscall number in and the result out; rdi and
    // rsi carry the arguments; SYSCALL clobbers rcx and r11; `flags` receives
    // RFLAGS after the syscall. pushfq/popfq use the stack.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "or dword ptr [rsp], {ac}",
            "popfq",
            "syscall",
            "pushfq",
            "mov {flags}, qword ptr [rsp]",
            "and dword ptr [rsp], {not_ac}",
            "popfq",
            ac = const AC_SET_IMM,
            not_ac = const AC_CLEAR_IMM,
            flags = out(reg) rflags,
            inlateout("rax") SYS_GETRANDOM.cast_signed() => ret,
            in("rdi") dst.as_mut_ptr() as u64,
            in("rsi") dst.len() as u64,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    (ret, rflags)
}

/// Start `entry` on a fresh child thread and return its exit reason once the
/// kernel reports it `Exited`. The child's caps are deleted on every path.
///
/// # Safety
/// `stack` must point at a `ChildStack` no other live thread runs on (the
/// contract of `spawn::configure_and_start`).
unsafe fn run_child(
    ctx: &TestContext,
    entry: extern "C" fn(u64) -> !,
    stack: *const ChildStack,
) -> Result<u64, &'static str>
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "syscall_rflags_hardening: spawn::new_child failed")?;
    // SAFETY: the caller's contract dedicates `stack` to this child.
    let reason =
        unsafe { crate::spawn::configure_and_start(&child, entry, ChildStack::top(stack), 0) }
            .map_err(|_| "syscall_rflags_hardening: configure_and_start failed")
            .and_then(|()| {
                crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))
            });
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
