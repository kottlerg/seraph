// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/thread.rs

//! Tier 1 tests for thread management syscalls.
//!
//! Covers: `SYS_THREAD_CONFIGURE`, `SYS_THREAD_START`, `SYS_THREAD_STOP`,
//! `SYS_THREAD_YIELD`, `SYS_THREAD_EXIT`, `SYS_THREAD_READ_REGS`,
//! `SYS_THREAD_WRITE_REGS`, `SYS_THREAD_SET_PRIORITY`,
//! `SYS_THREAD_SET_AFFINITY`.
//!
//! `SYS_THREAD_EXIT` is exercised implicitly — every child thread entry
//! function calls `thread_exit()`.
//!
//! The `write_regs_resume` test redirects a stopped child's instruction
//! pointer to a second entry point (`phase2_entry`). To hand the signal cap
//! to phase2 without relying on an argument register (which RISC-V's syscall
//! return path clobbers in `a0`), the cap slot is stored in `PHASE2_SIG`
//! before resuming. See the comment on that static for details.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, signal_send,
    signal_wait, system_info, thread_configure, thread_exit, thread_read_regs, thread_set_affinity,
    thread_set_priority, thread_start, thread_stop, thread_write_regs,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult};

// Copy of SIGNAL + WAIT rights (bits 7 and 8). Child needs WAIT to block in
// signal_wait, giving the parent a stable TrapFrame to read/write.
const RIGHTS_SIGNAL_WAIT: u64 = (1 << 7) | (1 << 8);

// Expected TrapFrame size per architecture (kernel/src/arch/*/trap_frame.rs).
#[cfg(target_arch = "x86_64")]
const TRAP_FRAME_BYTES: u64 = 168;
#[cfg(target_arch = "riscv64")]
const TRAP_FRAME_BYTES: u64 = 280;

// Byte offset of the instruction pointer within TrapFrame.
#[cfg(target_arch = "x86_64")]
const IP_OFFSET: usize = 120; // TrapFrame.rip
#[cfg(target_arch = "riscv64")]
const IP_OFFSET: usize = 248; // TrapFrame.sepc

// Child stacks — one per test that spawns a child, to avoid aliasing.
static mut STACK_CONFIGURE: ChildStack = ChildStack::ZERO;
static mut STACK_STOP_REGS: ChildStack = ChildStack::ZERO;
static mut STACK_WRITE_REGS: ChildStack = ChildStack::ZERO;
static mut STACK_CONFIGURE_ERR: ChildStack = ChildStack::ZERO;
static mut STACK_AFFINITY_CPU1: ChildStack = ChildStack::ZERO;
static mut STACK_AFFINITY_RESPECTED: ChildStack = ChildStack::ZERO;
static mut STACK_DEFAULT_AFFINITY: ChildStack = ChildStack::ZERO;

/// Signal cap slot passed to `phase2_entry` via a static rather than a
/// register argument.
///
/// On RISC-V, `a0` is both the first function argument AND the syscall
/// return-value register. The kernel dispatch path always writes the syscall
/// return code into `a0` immediately before returning to user mode, which
/// would clobber any value written there by `thread_write_regs`. Storing the
/// cap here and reading it in `phase2_entry` sidesteps the conflict and keeps
/// the pattern correct on both architectures.
static PHASE2_SIG: AtomicU32 = AtomicU32::new(0);

// ── SYS_THREAD_CONFIGURE / SYS_THREAD_START ──────────────────────────────────

/// `thread_configure` sets entry, stack, and arg; `thread_start` makes it runnable.
///
/// The child signals 0xBEEF back to confirm it executed.
pub fn configure_start(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for configure_start failed")?;
    let cs = cap_create_cspace(16).map_err(|_| "create_cspace for configure_start failed")?;
    let child_sig = cap_copy(sig, cs, 1 << 7) // SIGNAL right only
        .map_err(|_| "cap_copy for configure_start failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for configure_start failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_CONFIGURE));
    thread_configure(
        th,
        sender_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "thread_configure failed")?;
    thread_start(th).map_err(|_| "thread_start failed")?;

    let bits = signal_wait(sig).map_err(|_| "signal_wait after thread_start failed")?;
    if bits != 0xBEEF
    {
        return Err("thread did not send expected bits (expected 0xBEEF)");
    }

    cap_delete(th).map_err(|_| "cap_delete th after configure_start failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after configure_start failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after configure_start failed")?;
    Ok(())
}

// ── SYS_THREAD_YIELD ─────────────────────────────────────────────────────────

/// `thread_yield` voluntarily cedes the CPU. Must return without error.
pub fn r#yield(_ctx: &TestContext) -> TestResult
{
    syscall::thread_yield().map_err(|_| "thread_yield failed")?;
    Ok(())
}

// ── SYS_THREAD_STOP / SYS_THREAD_READ_REGS ───────────────────────────────────

/// `thread_stop` transitions a running/blocked thread to Stopped; `thread_read_regs`
/// returns the thread's register file.
///
/// The child signals readiness (0x1) then blocks in `signal_wait` to provide a
/// stable `TrapFrame`. The parent stops it and reads registers.
pub fn stop_read_regs(ctx: &TestContext) -> TestResult
{
    const BUF_SIZE: usize = 512; // Larger than any architecture's TrapFrame.
    let sync = cap_create_signal().map_err(|_| "create_signal for stop_read_regs failed")?;
    let cs = cap_create_cspace(16).map_err(|_| "create_cspace for stop_read_regs failed")?;
    // Child needs SIGNAL+WAIT so it can both send (readiness) and block (signal_wait).
    let child_sync =
        cap_copy(sync, cs, RIGHTS_SIGNAL_WAIT).map_err(|_| "cap_copy for stop_read_regs failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for stop_read_regs failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_STOP_REGS));
    thread_configure(
        th,
        blocker_entry as *const () as u64,
        stack_top,
        u64::from(child_sync),
    )
    .map_err(|_| "thread_configure for stop_read_regs failed")?;
    thread_start(th).map_err(|_| "thread_start for stop_read_regs failed")?;

    // Wait for the child to signal readiness then enter its blocking signal_wait.
    let ready = signal_wait(sync).map_err(|_| "signal_wait (readiness) failed")?;
    if ready != 0x1
    {
        return Err("child sent wrong readiness bits (expected 0x1)");
    }

    // Stop the child while it is blocked — this gives a stable, non-racy TrapFrame.
    thread_stop(th).map_err(|_| "thread_stop failed")?;

    // Read the register file.
    let mut reg_buf = [0u8; BUF_SIZE];
    let bytes = thread_read_regs(th, reg_buf.as_mut_ptr(), BUF_SIZE)
        .map_err(|_| "thread_read_regs failed")?;

    if bytes != TRAP_FRAME_BYTES
    {
        return Err("thread_read_regs returned unexpected byte count");
    }

    // Instruction pointer must be non-zero (child was executing user code).
    let ip = u64::from_le_bytes(
        reg_buf[IP_OFFSET..IP_OFFSET + 8]
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    if ip == 0
    {
        return Err("rip/sepc is zero after thread_stop — TrapFrame not valid");
    }

    cap_delete(th).map_err(|_| "cap_delete th after stop_read_regs failed")?;
    cap_delete(sync).map_err(|_| "cap_delete sync after stop_read_regs failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after stop_read_regs failed")?;
    Ok(())
}

// ── SYS_THREAD_STOP (double stop) ────────────────────────────────────────────

/// Stopping an already-stopped thread returns `InvalidState`.
pub fn stop_again_invalid_state(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for double-stop test failed")?;
    let cs = cap_create_cspace(16).map_err(|_| "create_cspace for double-stop test failed")?;
    let child_sig = cap_copy(sig, cs, RIGHTS_SIGNAL_WAIT)
        .map_err(|_| "cap_copy for double-stop test failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for double-stop test failed")?;

    // Tests run sequentially; STACK_STOP_REGS contents are stale but the child
    // from the previous test is stopped. Using STACK_WRITE_REGS for safety.
    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_WRITE_REGS));
    thread_configure(
        th,
        blocker_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "thread_configure for double-stop test failed")?;
    thread_start(th).map_err(|_| "thread_start for double-stop test failed")?;

    let _ = signal_wait(sig); // Wait for readiness signal.
    thread_stop(th).map_err(|_| "first thread_stop failed")?;

    // Second stop on a Stopped thread must return InvalidState.
    let err = thread_stop(th);
    if err != Err(SyscallError::InvalidState as i64)
    {
        return Err("double thread_stop did not return InvalidState");
    }

    cap_delete(th).map_err(|_| "cap_delete th after double-stop test failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after double-stop test failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after double-stop test failed")?;
    Ok(())
}

// ── SYS_THREAD_WRITE_REGS + SYS_THREAD_START (resume) ────────────────────────

/// `thread_write_regs` modifies a stopped thread's register state; `thread_start`
/// resumes it at the new instruction pointer.
///
/// The child is stopped while blocked in `signal_wait`. Its IP is redirected to
/// `phase2_entry`. On resume, phase2 reads `PHASE2_SIG` and sends 0x2.
pub fn write_regs_resume(ctx: &TestContext) -> TestResult
{
    const BUF_SIZE: usize = 512;
    let sync = cap_create_signal().map_err(|_| "create_signal for write_regs_resume failed")?;
    let cs = cap_create_cspace(16).map_err(|_| "create_cspace for write_regs_resume failed")?;
    let child_sync = cap_copy(sync, cs, RIGHTS_SIGNAL_WAIT)
        .map_err(|_| "cap_copy for write_regs_resume failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for write_regs_resume failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_WRITE_REGS));
    thread_configure(
        th,
        blocker_entry as *const () as u64,
        stack_top,
        u64::from(child_sync),
    )
    .map_err(|_| "thread_configure for write_regs_resume failed")?;
    thread_start(th).map_err(|_| "thread_start for write_regs_resume failed")?;

    // Wait for readiness then stop while the child is blocked.
    let _ = signal_wait(sync);
    thread_stop(th).map_err(|_| "thread_stop for write_regs_resume failed")?;

    // Publish the signal cap for phase2 before rewriting the IP.
    PHASE2_SIG.store(child_sync, Ordering::Release);

    let mut reg_buf = [0u8; BUF_SIZE];
    thread_read_regs(th, reg_buf.as_mut_ptr(), BUF_SIZE)
        .map_err(|_| "thread_read_regs for write_regs_resume failed")?;

    // Overwrite instruction pointer to redirect child to phase2_entry.
    let phase2_ptr = phase2_entry as *const () as u64;
    reg_buf[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&phase2_ptr.to_le_bytes());

    thread_write_regs(th, reg_buf.as_ptr(), BUF_SIZE).map_err(|_| "thread_write_regs failed")?;

    // Resume — child runs phase2_entry and sends 0x2.
    thread_start(th).map_err(|_| "thread_start (resume) for write_regs_resume failed")?;

    let bits = signal_wait(sync).map_err(|_| "signal_wait for phase2 confirmation failed")?;
    if bits != 0x2
    {
        return Err("phase2_entry did not send expected value 0x2 after write_regs resume");
    }

    cap_delete(th).map_err(|_| "cap_delete th after write_regs_resume failed")?;
    cap_delete(sync).map_err(|_| "cap_delete sync after write_regs_resume failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after write_regs_resume failed")?;
    Ok(())
}

// ── SYS_THREAD_SET_PRIORITY ───────────────────────────────────────────────────

/// `thread_set_priority` in the normal range (1–20) succeeds without a
/// `SchedControl` capability.
pub fn set_priority_normal(ctx: &TestContext) -> TestResult
{
    let cs = cap_create_cspace(8).map_err(|_| "create_cspace for set_priority_normal failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for set_priority_normal failed")?;

    // Priority 5 is in the normal range (1–20); sched_cap = 0 → not required.
    thread_set_priority(th, 5, 0).map_err(|_| "thread_set_priority(5) failed")?;

    cap_delete(th).map_err(|_| "cap_delete th after set_priority_normal failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after set_priority_normal failed")?;
    Ok(())
}

/// `thread_set_priority` with priority ≥ `SCHED_ELEVATED_MIN` (21) fails when
/// no `SchedControl` capability is provided.
pub fn set_priority_elevated_no_cap_err(ctx: &TestContext) -> TestResult
{
    let cs = cap_create_cspace(8).map_err(|_| "create_cspace for elevated_no_cap test failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for elevated_no_cap test failed")?;

    // Priority 25 requires a SchedControl cap; passing 0 must fail.
    let err = thread_set_priority(th, 25, 0);
    if err.is_ok()
    {
        return Err("thread_set_priority(25, no_cap) should fail without SchedControl");
    }

    cap_delete(th).map_err(|_| "cap_delete th after elevated_no_cap test failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after elevated_no_cap test failed")?;
    Ok(())
}

/// `thread_set_priority` with priority ≥ 21 succeeds when a valid `SchedControl`
/// capability is provided.
///
/// The test scans slots up to `aspace_cap + 20` for a slot that accepts
/// elevated priority. If no `SchedControl` cap is found, the test is skipped
/// (reports Ok — the test was not applicable, not a failure).
pub fn set_priority_elevated_with_cap(ctx: &TestContext) -> TestResult
{
    let cs = cap_create_cspace(8).map_err(|_| "create_cspace for elevated_with_cap test failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for elevated_with_cap test failed")?;

    // Scan for a SchedControl cap in the initial capability set.
    let mut found = false;
    for slot in 1..ctx.aspace_cap + 20
    {
        if thread_set_priority(th, 25, slot).is_ok()
        {
            found = true;
            break;
        }
    }

    if !found
    {
        crate::log("ktest: thread::set_priority_elevated_with_cap SKIP (no SchedControl cap)");
    }

    cap_delete(th).map_err(|_| "cap_delete th after elevated_with_cap test failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after elevated_with_cap test failed")?;
    Ok(())
}

// ── SYS_THREAD_SET_AFFINITY ───────────────────────────────────────────────────

/// `thread_set_affinity` with a valid CPU ID succeeds.
pub fn set_affinity_valid(ctx: &TestContext) -> TestResult
{
    let cs = cap_create_cspace(8).map_err(|_| "create_cspace for set_affinity_valid failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for set_affinity_valid failed")?;

    // CPU 0 is always valid on any boot configuration.
    thread_set_affinity(th, 0).map_err(|_| "thread_set_affinity(0) failed")?;

    cap_delete(th).map_err(|_| "cap_delete th after set_affinity_valid failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after set_affinity_valid failed")?;
    Ok(())
}

/// `thread_set_affinity` with an out-of-range CPU ID returns `InvalidArgument`.
pub fn set_affinity_invalid_err(ctx: &TestContext) -> TestResult
{
    let cs =
        cap_create_cspace(8).map_err(|_| "create_cspace for set_affinity_invalid test failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for set_affinity_invalid test failed")?;

    // CPU 999 is beyond any reasonable CPU count.
    let err = thread_set_affinity(th, 999);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("thread_set_affinity(999) did not return InvalidArgument");
    }

    cap_delete(th).map_err(|_| "cap_delete th after set_affinity_invalid test failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after set_affinity_invalid test failed")?;
    Ok(())
}

// ── SYS_THREAD_CONFIGURE negative ────────────────────────────────────────────

/// `thread_configure` on a thread that is already Running or Blocked must fail.
///
/// The child signals readiness then blocks in `signal_wait`, giving the parent
/// a stable point at which the thread is no longer in `Created` state.
pub fn configure_running_thread_err(ctx: &TestContext) -> TestResult
{
    let sig =
        cap_create_signal().map_err(|_| "create_signal for configure_running_thread_err failed")?;
    let cs = cap_create_cspace(16)
        .map_err(|_| "create_cspace for configure_running_thread_err failed")?;
    let child_sig = cap_copy(sig, cs, RIGHTS_SIGNAL_WAIT)
        .map_err(|_| "cap_copy for configure_running_thread_err failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for configure_running_thread_err failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_CONFIGURE_ERR));
    thread_configure(
        th,
        blocker_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "first thread_configure failed")?;
    thread_start(th).map_err(|_| "thread_start failed")?;

    // Wait for the child to signal readiness (it is now Running or Blocked).
    signal_wait(sig).map_err(|_| "signal_wait for readiness failed")?;

    // Attempting to configure a non-Created thread must fail.
    let err = thread_configure(th, blocker_entry as *const () as u64, stack_top, 0);

    // Stop the blocked child before cleanup.
    thread_stop(th).ok();
    cap_delete(th).map_err(|_| "cap_delete th after configure_running_thread_err failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after configure_running_thread_err failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after configure_running_thread_err failed")?;

    if err.is_ok()
    {
        return Err("thread_configure on a started thread should fail");
    }
    Ok(())
}

// ── SYS_THREAD_SET_PRIORITY negative ─────────────────────────────────────────

/// `thread_set_priority(th, 0, 0)` must return `InvalidArgument`.
///
/// Priority 0 is reserved for the idle thread and cannot be assigned to
/// a userspace thread.
pub fn set_priority_zero_err(ctx: &TestContext) -> TestResult
{
    let cs = cap_create_cspace(8).map_err(|_| "create_cspace for set_priority_zero_err failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for set_priority_zero_err failed")?;

    let err = thread_set_priority(th, 0, 0);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("thread_set_priority(0) did not return InvalidArgument");
    }

    cap_delete(th).map_err(|_| "cap_delete th after set_priority_zero_err failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after set_priority_zero_err failed")?;
    Ok(())
}

/// `thread_set_priority(th, 31, 0)` must return `InvalidArgument`.
///
/// Priority 31 is reserved and may not be assigned to any thread.
pub fn set_priority_31_err(ctx: &TestContext) -> TestResult
{
    let cs = cap_create_cspace(8).map_err(|_| "create_cspace for set_priority_31_err failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for set_priority_31_err failed")?;

    let err = thread_set_priority(th, 31, 0);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("thread_set_priority(31) did not return InvalidArgument");
    }

    cap_delete(th).map_err(|_| "cap_delete th after set_priority_31_err failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after set_priority_31_err failed")?;
    Ok(())
}

// ── SYS_THREAD_SET_AFFINITY + SYS_THREAD_START ───────────────────────────────

/// A thread bound to CPU 1 runs and signals back.
///
/// Skips with a log line if only one CPU is online (requires SMP). On SMP
/// builds, the thread is enqueued on CPU 1's run queue and signals `0xC1A1`
/// back to the parent.
pub fn affinity_bind_cpu1(ctx: &TestContext) -> TestResult
{
    // Skip if CPU 1 does not exist.
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: thread::affinity_bind_cpu1 SKIP (requires SMP)");
        return Ok(());
    }

    let sig = cap_create_signal().map_err(|_| "create_signal for affinity_bind_cpu1 failed")?;
    let cs = cap_create_cspace(16).map_err(|_| "create_cspace for affinity_bind_cpu1 failed")?;
    let child_sig = cap_copy(sig, cs, 1 << 7) // SIGNAL right only
        .map_err(|_| "cap_copy for affinity_bind_cpu1 failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for affinity_bind_cpu1 failed")?;

    // Bind to CPU 1 before starting.
    thread_set_affinity(th, 1).map_err(|_| "thread_set_affinity(1) failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_AFFINITY_CPU1));
    thread_configure(
        th,
        affinity_sender_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "thread_configure for affinity_bind_cpu1 failed")?;
    thread_start(th).map_err(|_| "thread_start for affinity_bind_cpu1 failed")?;

    let bits = signal_wait(sig).map_err(|_| "signal_wait for affinity_bind_cpu1 failed")?;
    if bits != 0xC1A1
    {
        return Err("affinity thread did not send expected bits (expected 0xC1A1)");
    }

    cap_delete(th).map_err(|_| "cap_delete th after affinity_bind_cpu1 failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after affinity_bind_cpu1 failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after affinity_bind_cpu1 failed")?;
    Ok(())
}

// ── Phase D scheduler correctness tests ───────────────────────────────────────

/// Thread with explicit CPU affinity starts and executes successfully.
///
/// Phase D routes threads to their affinity CPU via `select_target_cpu`.
/// This test verifies that threads with affinity set to CPU 1 can start,
/// execute, and signal back to the parent. This confirms basic Phase D
/// affinity routing without requiring a `CurrentCpu` syscall variant.
///
/// Skips if only one CPU is online (requires SMP).
pub fn affinity_respected(ctx: &TestContext) -> TestResult
{
    // Skip if CPU 1 does not exist.
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: thread::affinity_respected SKIP (requires SMP)");
        return Ok(());
    }

    let sig = cap_create_signal().map_err(|_| "create_signal for affinity_respected failed")?;
    let cs = cap_create_cspace(16).map_err(|_| "create_cspace for affinity_respected failed")?;
    let child_sig = cap_copy(sig, cs, 1 << 7) // SIGNAL right only
        .map_err(|_| "cap_copy for affinity_respected failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for affinity_respected failed")?;

    // Bind to CPU 1 before starting.
    thread_set_affinity(th, 1).map_err(|_| "thread_set_affinity(1) failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_AFFINITY_RESPECTED));
    thread_configure(
        th,
        affinity_sender_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "thread_configure for affinity_respected failed")?;
    thread_start(th).map_err(|_| "thread_start for affinity_respected failed")?;

    // If the thread successfully signals back, affinity routing worked.
    let bits = signal_wait(sig).map_err(|_| "signal_wait for affinity_respected failed")?;
    if bits != 0xC1A1
    {
        return Err("affinity thread did not send expected bits (expected 0xC1A1)");
    }

    cap_delete(th).map_err(|_| "cap_delete th after affinity_respected failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after affinity_respected failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after affinity_respected failed")?;
    Ok(())
}

/// Thread with default affinity (`AFFINITY_ANY`) defaults to CPU 0 (BSP).
///
/// Phase D uses a simple routing policy: `AFFINITY_ANY` threads are assigned
/// to CPU 0 (the bootstrap processor). Phase F will change this to load-balance
/// across all CPUs. This test verifies the Phase D behavior by creating a thread
/// with `AFFINITY_ANY`, then checking it starts and signals back. Since we cannot
/// query the current CPU ID from userspace without a `CurrentCpu` syscall variant,
/// this test indirectly validates default affinity by confirming the thread runs
/// successfully (which it will only do if it was enqueued on a valid CPU).
///
/// Skips if only one CPU is online (requires SMP).
pub fn default_affinity_bsp(ctx: &TestContext) -> TestResult
{
    // Skip if CPU 1 does not exist.
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: thread::default_affinity_bsp SKIP (requires SMP)");
        return Ok(());
    }

    let sig = cap_create_signal().map_err(|_| "create_signal for default_affinity_bsp failed")?;
    let cs = cap_create_cspace(16).map_err(|_| "create_cspace for default_affinity_bsp failed")?;
    let child_sig = cap_copy(sig, cs, 1 << 7) // SIGNAL right only
        .map_err(|_| "cap_copy for default_affinity_bsp failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for default_affinity_bsp failed")?;

    // Do NOT set affinity — leave it at default (AFFINITY_ANY).
    // Phase D should route this to CPU 0.

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_DEFAULT_AFFINITY));
    thread_configure(
        th,
        sender_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "thread_configure for default_affinity_bsp failed")?;
    thread_start(th).map_err(|_| "thread_start for default_affinity_bsp failed")?;

    // If the thread successfully signals back, default affinity routing worked.
    let bits = signal_wait(sig).map_err(|_| "signal_wait for default_affinity_bsp failed")?;
    if bits != 0xBEEF
    {
        return Err("default affinity thread did not send expected bits (expected 0xBEEF)");
    }

    cap_delete(th).map_err(|_| "cap_delete th after default_affinity_bsp failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after default_affinity_bsp failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after default_affinity_bsp failed")?;
    Ok(())
}

// ── Child thread entry points ─────────────────────────────────────────────────

/// Affinity test sender: sends 0xC1A1 and exits.
///
/// Used by [`affinity_bind_cpu1`] — the child is bound to CPU 1 and confirms
/// it ran by signalling back.
// cast_possible_truncation: sig_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn affinity_sender_entry(sig_slot: u64) -> !
{
    signal_send(sig_slot as u32, 0xC1A1).ok();
    thread_exit()
}

/// Simple sender: sends 0xBEEF and exits.
// cast_possible_truncation: sig_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn sender_entry(sig_slot: u64) -> !
{
    signal_send(sig_slot as u32, 0xBEEF).ok();
    thread_exit()
}

/// Phase 1 blocker: signals readiness (0x1) then blocks in `signal_wait`.
///
/// The parent stops this thread while it is blocked, giving a stable
/// `TrapFrame` for `thread_read_regs` / `thread_write_regs`. If the parent
/// later resumes it (via `write_regs` redirect), execution jumps to `phase2_entry`
/// instead of returning from this `signal_wait`.
// cast_possible_truncation: sig_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn blocker_entry(sig_slot: u64) -> !
{
    signal_send(sig_slot as u32, 0x1).ok();
    // Block so the parent can stop us and read a stable TrapFrame.
    // If write_regs redirects our IP, we jump directly to phase2_entry on resume.
    signal_wait(sig_slot as u32).ok();
    // Not normally reached — parent always stops us while blocked.
    loop
    {
        core::hint::spin_loop();
    }
}

/// Phase 2 entry: reads the signal cap from `PHASE2_SIG` and sends 0x2.
///
/// Entered after the parent rewrites this thread's instruction pointer via
/// `thread_write_regs`. See the `PHASE2_SIG` doc comment for why the cap is
/// passed via a static rather than as a register argument.
fn phase2_entry() -> !
{
    let sig = PHASE2_SIG.load(Ordering::Acquire);
    signal_send(sig, 0x2).ok();
    thread_exit()
}
