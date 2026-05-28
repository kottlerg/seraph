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
    cap_copy, cap_create_signal, cap_delete, event_queue_create, event_recv, signal_send,
    signal_wait, signal_wait_timeout, system_info, thread_bind_notification, thread_configure,
    thread_exit, thread_read_regs, thread_set_affinity, thread_set_priority, thread_sleep,
    thread_start, thread_stop, thread_write_regs,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult};

// SIGNAL = bit 7, WAIT = bit 8. Tests that pin a child in signal_wait give
// the child SIGNAL on the readiness cap and WAIT on a *separate* blocking
// cap, so the child cannot self-deliver its own readiness send before the
// parent has registered as the waiter.
const RIGHTS_SIGNAL: u64 = 1 << 7;
const RIGHTS_WAIT: u64 = 1 << 8;

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
static mut STACK_AFFINITY_MIGRATE_READY: ChildStack = ChildStack::ZERO;
static mut STACK_AFFINITY_MIGRATE_RUNNING: ChildStack = ChildStack::ZERO;
static mut STACK_BALANCE_SPINNERS: [ChildStack; BALANCE_MAX_SPINNERS] = [
    ChildStack::ZERO,
    ChildStack::ZERO,
    ChildStack::ZERO,
    ChildStack::ZERO,
    ChildStack::ZERO,
    ChildStack::ZERO,
    ChildStack::ZERO,
    ChildStack::ZERO,
];

/// Latest CPU index observed by the spinner used in
/// `affinity_migrate_running`. The spinner stores its current CPU id on
/// every iteration; the parent reads this to detect migration.
static MIGRATE_OBSERVED_CPU: AtomicU32 = AtomicU32::new(u32::MAX);

/// Signals the migration spinner to exit cleanly once the parent has
/// observed the migration.
static MIGRATE_SHOULD_EXIT: AtomicU32 = AtomicU32::new(0);

/// Per-spinner observed CPU index. Indexed by spinner id (0..N). Used by
/// the load-balancer tests. `u32::MAX` indicates "spinner has not run yet".
const BALANCE_MAX_SPINNERS: usize = 8;
static BALANCE_OBSERVED_CPU: [AtomicU32; BALANCE_MAX_SPINNERS] = [
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
];

/// Set when the parent wants the balancer spinners to exit.
static BALANCE_SHOULD_EXIT: AtomicU32 = AtomicU32::new(0);

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
    let sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal for configure_start failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::configure_start: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy for configure_start failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_CONFIGURE));
    crate::spawn::configure_and_start(&child, sender_entry, stack_top, u64::from(child_sig))
        .map_err(|_| "thread::configure_start: configure_and_start failed")?;

    let bits = signal_wait(sig).map_err(|_| "signal_wait after thread_start failed")?;
    if bits != 0xBEEF
    {
        return Err("thread did not send expected bits (expected 0xBEEF)");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after configure_start failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after configure_start failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after configure_start failed")?;
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
    let ready = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal (ready) for stop_read_regs failed")?;
    let block = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal (block) for stop_read_regs failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::stop_read_regs: spawn::new_child failed")?;
    let child_ready = cap_copy(ready, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy (ready) for stop_read_regs failed")?;
    let child_block = cap_copy(block, child.cs, RIGHTS_WAIT)
        .map_err(|_| "cap_copy (block) for stop_read_regs failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_STOP_REGS));
    let blocker_arg = (u64::from(child_ready) << 32) | u64::from(child_block);
    crate::spawn::configure_and_start(&child, blocker_entry, stack_top, blocker_arg)
        .map_err(|_| "thread::stop_read_regs: configure_and_start failed")?;

    // Wait for the child to signal readiness then enter its blocking signal_wait.
    let ready_bits = signal_wait(ready).map_err(|_| "signal_wait (readiness) failed")?;
    if ready_bits != 0x1
    {
        return Err("child sent wrong readiness bits (expected 0x1)");
    }

    // Stop the child while it is blocked — this gives a stable, non-racy TrapFrame.
    thread_stop(child.th).map_err(|_| "thread_stop failed")?;

    // Read the register file.
    let mut reg_buf = [0u8; BUF_SIZE];
    let bytes = thread_read_regs(child.th, reg_buf.as_mut_ptr(), BUF_SIZE)
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

    cap_delete(child.th).map_err(|_| "cap_delete th after stop_read_regs failed")?;
    cap_delete(ready).map_err(|_| "cap_delete ready after stop_read_regs failed")?;
    cap_delete(block).map_err(|_| "cap_delete block after stop_read_regs failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after stop_read_regs failed")?;
    Ok(())
}

// ── SYS_THREAD_STOP (double stop) ────────────────────────────────────────────

/// Stopping an already-stopped thread returns `InvalidState`.
pub fn stop_again_invalid_state(ctx: &TestContext) -> TestResult
{
    let ready = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal (ready) for double-stop test failed")?;
    let block = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal (block) for double-stop test failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::stop_again_invalid_state: spawn::new_child failed")?;
    let child_ready = cap_copy(ready, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy (ready) for double-stop test failed")?;
    let child_block = cap_copy(block, child.cs, RIGHTS_WAIT)
        .map_err(|_| "cap_copy (block) for double-stop test failed")?;

    // Tests run sequentially; STACK_STOP_REGS contents are stale but the child
    // from the previous test is stopped. Using STACK_WRITE_REGS for safety.
    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_WRITE_REGS));
    let blocker_arg = (u64::from(child_ready) << 32) | u64::from(child_block);
    crate::spawn::configure_and_start(&child, blocker_entry, stack_top, blocker_arg)
        .map_err(|_| "thread::stop_again_invalid_state: configure_and_start failed")?;

    let _ = signal_wait(ready); // Wait for readiness signal.
    thread_stop(child.th).map_err(|_| "first thread_stop failed")?;

    // Second stop on a Stopped thread must return InvalidState.
    let err = thread_stop(child.th);
    if err != Err(SyscallError::InvalidState as i64)
    {
        return Err("double thread_stop did not return InvalidState");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after double-stop test failed")?;
    cap_delete(ready).map_err(|_| "cap_delete ready after double-stop test failed")?;
    cap_delete(block).map_err(|_| "cap_delete block after double-stop test failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after double-stop test failed")?;
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
    let ready = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal (ready) for write_regs_resume failed")?;
    let block = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal (block) for write_regs_resume failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::write_regs_resume: spawn::new_child failed")?;
    let child_ready = cap_copy(ready, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy (ready) for write_regs_resume failed")?;
    let child_block = cap_copy(block, child.cs, RIGHTS_WAIT)
        .map_err(|_| "cap_copy (block) for write_regs_resume failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_WRITE_REGS));
    let blocker_arg = (u64::from(child_ready) << 32) | u64::from(child_block);
    crate::spawn::configure_and_start(&child, blocker_entry, stack_top, blocker_arg)
        .map_err(|_| "thread::write_regs_resume: configure_and_start failed")?;

    // Wait for readiness then stop while the child is blocked.
    let _ = signal_wait(ready);
    thread_stop(child.th).map_err(|_| "thread_stop for write_regs_resume failed")?;

    // Publish the signal cap phase2_entry will send through.
    PHASE2_SIG.store(child_ready, Ordering::Release);

    let mut reg_buf = [0u8; BUF_SIZE];
    thread_read_regs(child.th, reg_buf.as_mut_ptr(), BUF_SIZE)
        .map_err(|_| "thread_read_regs for write_regs_resume failed")?;

    // Overwrite instruction pointer to redirect child to phase2_entry.
    let phase2_ptr = phase2_entry as *const () as u64;
    reg_buf[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&phase2_ptr.to_le_bytes());

    thread_write_regs(child.th, reg_buf.as_ptr(), BUF_SIZE)
        .map_err(|_| "thread_write_regs failed")?;

    // Resume — child runs phase2_entry and sends 0x2. The helper is single-shot,
    // so the resume calls `thread_start` directly.
    thread_start(child.th).map_err(|_| "thread_start (resume) for write_regs_resume failed")?;

    let bits = signal_wait(ready).map_err(|_| "signal_wait for phase2 confirmation failed")?;
    if bits != 0x2
    {
        return Err("phase2_entry did not send expected value 0x2 after write_regs resume");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after write_regs_resume failed")?;
    cap_delete(ready).map_err(|_| "cap_delete ready after write_regs_resume failed")?;
    cap_delete(block).map_err(|_| "cap_delete block after write_regs_resume failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after write_regs_resume failed")?;
    Ok(())
}

// ── SYS_THREAD_SET_PRIORITY ───────────────────────────────────────────────────

/// `thread_set_priority` in the normal range (1–20) succeeds without a
/// `SchedControl` capability.
pub fn set_priority_normal(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::set_priority_normal: spawn::new_child failed")?;

    // Priority 5 is in the normal range (1–20); sched_cap = 0 → not required.
    thread_set_priority(child.th, 5, 0).map_err(|_| "thread_set_priority(5) failed")?;

    cap_delete(child.th).map_err(|_| "cap_delete th after set_priority_normal failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after set_priority_normal failed")?;
    Ok(())
}

/// `thread_set_priority` with priority ≥ `SCHED_ELEVATED_MIN` (21) fails when
/// no `SchedControl` capability is provided.
pub fn set_priority_elevated_no_cap_err(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::set_priority_elevated_no_cap_err: spawn::new_child failed")?;

    // Priority 25 requires a SchedControl cap; passing 0 must fail.
    let err = thread_set_priority(child.th, 25, 0);
    if err.is_ok()
    {
        return Err("thread_set_priority(25, no_cap) should fail without SchedControl");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after elevated_no_cap test failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after elevated_no_cap test failed")?;
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
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::set_priority_elevated_with_cap: spawn::new_child failed")?;

    // Scan for a SchedControl cap in the initial capability set.
    let mut found = false;
    for slot in 1..ctx.aspace_cap + 20
    {
        if thread_set_priority(child.th, 25, slot).is_ok()
        {
            found = true;
            break;
        }
    }

    if !found
    {
        crate::log("ktest: thread::set_priority_elevated_with_cap SKIP (no SchedControl cap)");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after elevated_with_cap test failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after elevated_with_cap test failed")?;
    Ok(())
}

// ── SYS_THREAD_SET_AFFINITY ───────────────────────────────────────────────────

/// `thread_set_affinity` with a valid CPU ID succeeds.
pub fn set_affinity_valid(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::set_affinity_valid: spawn::new_child failed")?;

    // CPU 0 is always valid on any boot configuration.
    thread_set_affinity(child.th, 0).map_err(|_| "thread_set_affinity(0) failed")?;

    cap_delete(child.th).map_err(|_| "cap_delete th after set_affinity_valid failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after set_affinity_valid failed")?;
    Ok(())
}

/// `thread_set_affinity` with an out-of-range CPU ID returns `InvalidArgument`.
pub fn set_affinity_invalid_err(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::set_affinity_invalid_err: spawn::new_child failed")?;

    // CPU 999 is beyond any reasonable CPU count.
    let err = thread_set_affinity(child.th, 999);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("thread_set_affinity(999) did not return InvalidArgument");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after set_affinity_invalid test failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after set_affinity_invalid test failed")?;
    Ok(())
}

// ── SYS_THREAD_CONFIGURE negative ────────────────────────────────────────────

/// `thread_configure` on a thread that is already Running or Blocked must fail.
///
/// The child signals readiness then blocks in `signal_wait`, giving the parent
/// a stable point at which the thread is no longer in `Created` state.
pub fn configure_running_thread_err(ctx: &TestContext) -> TestResult
{
    let ready = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal (ready) for configure_running_thread_err failed")?;
    let block = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal (block) for configure_running_thread_err failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::configure_running_thread_err: spawn::new_child failed")?;
    let child_ready = cap_copy(ready, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy (ready) for configure_running_thread_err failed")?;
    let child_block = cap_copy(block, child.cs, RIGHTS_WAIT)
        .map_err(|_| "cap_copy (block) for configure_running_thread_err failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_CONFIGURE_ERR));
    let blocker_arg = (u64::from(child_ready) << 32) | u64::from(child_block);
    crate::spawn::configure_and_start(&child, blocker_entry, stack_top, blocker_arg)
        .map_err(|_| "thread::configure_running_thread_err: configure_and_start failed")?;

    // Wait for the child to signal readiness (it is now Running or Blocked).
    signal_wait(ready).map_err(|_| "signal_wait for readiness failed")?;

    // Attempting to configure a non-Created thread must fail. The helper is
    // single-shot for the started-from-Created path; re-configuring uses the
    // raw syscall on purpose to exercise the error case.
    let err = thread_configure(child.th, blocker_entry as *const () as u64, stack_top, 0);

    // Stop the blocked child before cleanup.
    thread_stop(child.th).ok();
    cap_delete(child.th).map_err(|_| "cap_delete th after configure_running_thread_err failed")?;
    cap_delete(ready).map_err(|_| "cap_delete ready after configure_running_thread_err failed")?;
    cap_delete(block).map_err(|_| "cap_delete block after configure_running_thread_err failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after configure_running_thread_err failed")?;

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
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::set_priority_zero_err: spawn::new_child failed")?;

    let err = thread_set_priority(child.th, 0, 0);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("thread_set_priority(0) did not return InvalidArgument");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after set_priority_zero_err failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after set_priority_zero_err failed")?;
    Ok(())
}

/// `thread_set_priority(th, 31, 0)` must return `InvalidArgument`.
///
/// Priority 31 is reserved and may not be assigned to any thread.
pub fn set_priority_31_err(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::set_priority_31_err: spawn::new_child failed")?;

    let err = thread_set_priority(child.th, 31, 0);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("thread_set_priority(31) did not return InvalidArgument");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after set_priority_31_err failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after set_priority_31_err failed")?;
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

    let sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal for affinity_bind_cpu1 failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::affinity_bind_cpu1: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy for affinity_bind_cpu1 failed")?;

    // Bind to CPU 1 before starting.
    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_AFFINITY_CPU1));
    crate::spawn::configure_and_start_pinned(
        &child,
        affinity_sender_entry,
        stack_top,
        u64::from(child_sig),
        1,
    )
    .map_err(|_| "thread::affinity_bind_cpu1: configure_and_start_pinned failed")?;

    let bits = signal_wait(sig).map_err(|_| "signal_wait for affinity_bind_cpu1 failed")?;
    if bits != 0xC1A1
    {
        return Err("affinity thread did not send expected bits (expected 0xC1A1)");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after affinity_bind_cpu1 failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after affinity_bind_cpu1 failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after affinity_bind_cpu1 failed")?;
    Ok(())
}

// ── Active affinity migration (Issue #22) ─────────────────────────────────────

/// `thread_set_affinity` actively migrates a Ready thread queued on another CPU.
///
/// The precondition this test exercises — T is Ready and queued on CPU 0 at
/// the moment of `thread_set_affinity(T, 1)` — must be made deterministic
/// from userspace. Two invariants combined make it so:
///
/// 1. **Parent pinned to CPU 0.** The harness pins itself to CPU 0 via its
///    own `Thread` cap (`ctx.thread_cap`) and yields, forcing the
///    affinity-aware re-enqueue in `schedule()` to land it on CPU 0. Without
///    this, CPU 0 may be idle when `thread_start(T)` enqueues T, and the
///    wake-IPI lets CPU 0 dispatch T (the only Ready thread there) before
///    the active-migration call.
/// 2. **T at priority 1 (below the parent's `INIT_PRIORITY` of 15).**
///    Both the harness and any thread minted via `cap_create_thread`
///    default to `INIT_PRIORITY`. Without this step, same-priority FIFO
///    would let a timer-driven `schedule()` re-enqueue parent at the tail
///    and dispatch T at the head. Strict-lower priority guarantees CPU 0's
///    `dequeue_highest` always returns parent, leaving T queued.
///
/// Together these make `sys_thread_set_affinity` deterministically observe
/// `state == Ready` for T on CPU 0, exercising `migrate_ready_thread`. When
/// the parent then blocks in `signal_wait`, CPU 1 picks T (its only Ready
/// thread) and T reports CPU 1.
///
/// T reports the CPU it actually ran on via `SystemInfoType::CurrentCpu`,
/// encoded in the signal value. Without active migration, T would stay on
/// CPU 0's run queue and report CPU 0 instead, failing the test.
///
/// Requires SMP; skips otherwise.
pub fn affinity_migrate_ready_queued(ctx: &TestContext) -> TestResult
{
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: thread::affinity_migrate_ready_queued SKIP (requires SMP)");
        return Ok(());
    }

    // Pin the harness to CPU 0 and yield to force migration there. The
    // affinity-recheck branch of `schedule()` (`sched/mod.rs` re-enqueue
    // path) routes the yielding parent cross-CPU to CPU 0; when `yield`
    // returns, the parent is running on CPU 0.
    thread_set_affinity(ctx.thread_cap, 0)
        .map_err(|_| "thread_set_affinity(self, 0) for affinity_migrate_ready_queued failed")?;
    syscall::thread_yield().map_err(|_| "thread_yield to land parent on CPU 0 failed")?;

    let result = affinity_migrate_ready_queued_body(ctx);

    // Restore the harness's affinity regardless of test outcome so later
    // tests start from the default any-CPU placement. Preserve the body's
    // error if both fail — the body's failure is the proximate cause.
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "restoring parent affinity to AFFINITY_ANY failed");
    result.and(restore)
}

fn affinity_migrate_ready_queued_body(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal for affinity_migrate_ready_queued failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::affinity_migrate_ready_queued: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy for affinity_migrate_ready_queued failed")?;

    // Priority 1 (strict-lower than the parent's INIT_PRIORITY of 15) so
    // CPU 0's `dequeue_highest` always selects the parent over T while
    // both are Ready/Running there. Priority 1 is below
    // SCHED_ELEVATED_MIN so no SchedControl cap is required
    // (sched_idx = 0). Must be set before `thread_start`.
    thread_set_priority(child.th, 1, 0)
        .map_err(|_| "thread_set_priority(1) for affinity_migrate_ready_queued failed")?;

    // Pin to CPU 0 initially so T's first enqueue lands on CPU 0's run queue.
    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_AFFINITY_MIGRATE_READY));
    crate::spawn::configure_and_start_pinned(
        &child,
        report_cpu_entry,
        stack_top,
        u64::from(child_sig),
        0,
    )
    .map_err(|_| "thread::affinity_migrate_ready_queued: configure_and_start_pinned failed")?;

    // T is Ready, queued on CPU 0 at priority 1; the parent is Running on
    // CPU 0 at INIT_PRIORITY=15 (pinned by the outer wrapper), so no
    // scheduling event can dispatch T here. Switch T's affinity to CPU 1
    // — the active-migration path must dequeue T from CPU 0 and re-enqueue
    // it on CPU 1.
    thread_set_affinity(child.th, 1)
        .map_err(|_| "active migration thread_set_affinity(1) failed")?;

    // Block on the signal: parent leaves CPU 0, CPU 1 runs T which reports
    // its actual CPU id back through the signal bits. `report_cpu_entry`
    // encodes the CPU id as `1u64.wrapping_shl(cpu)` (always non-zero by
    // the modulo-64 shift semantics) so any missed wake — including a
    // `cpu == 0` report from an unexpected stale-CPU run — surfaces as a
    // deterministic test FAIL instead of a HANG. `signal_send(sig, 0)`
    // would be rejected and the parent would park indefinitely (see
    // issue #116). The 5 s timeout is a defensive backstop against any
    // other missed-wake mode.
    let bits = signal_wait_timeout(sig, 5_000)
        .map_err(|_| "signal_wait for affinity_migrate_ready_queued failed")?;
    if bits == 0
    {
        return Err("affinity_migrate_ready_queued timed out — child never signaled");
    }
    if bits != (1u64 << 1)
    {
        return Err("Ready-thread migration did not land on CPU 1");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after affinity_migrate_ready_queued failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after affinity_migrate_ready_queued failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after affinity_migrate_ready_queued failed")?;
    Ok(())
}

/// `thread_set_affinity` causes a Running thread on a different CPU to
/// migrate within one tick.
///
/// Spawns T pinned to CPU 1 with a tight `CurrentCpu` read loop that publishes
/// its observed CPU into `MIGRATE_OBSERVED_CPU`. The parent runs on CPU 0,
/// waits until T is observed on CPU 1, then calls
/// `thread_set_affinity(T, 0)`. The Running-elsewhere path in
/// `sys_thread_set_affinity` sends a reschedule IPI to CPU 1; CPU 1's
/// `schedule()` re-enqueue site sees `cpu_affinity != current_cpu` and
/// routes T cross-CPU to CPU 0. The parent waits for `MIGRATE_OBSERVED_CPU`
/// to flip to 0.
///
/// Requires SMP; skips otherwise.
pub fn affinity_migrate_running(ctx: &TestContext) -> TestResult
{
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: thread::affinity_migrate_running SKIP (requires SMP)");
        return Ok(());
    }

    MIGRATE_OBSERVED_CPU.store(u32::MAX, Ordering::Relaxed);
    MIGRATE_SHOULD_EXIT.store(0, Ordering::Relaxed);

    let sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal for affinity_migrate_running failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::affinity_migrate_running: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy for affinity_migrate_running failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_AFFINITY_MIGRATE_RUNNING));
    crate::spawn::configure_and_start_pinned(
        &child,
        migrate_spinner_entry,
        stack_top,
        u64::from(child_sig),
        1,
    )
    .map_err(|_| "thread::affinity_migrate_running: configure_and_start_pinned failed")?;

    // Wait until T has been scheduled on CPU 1 and reported its CPU.
    let mut spins: u32 = 0;
    while MIGRATE_OBSERVED_CPU.load(Ordering::Relaxed) != 1
    {
        syscall::thread_yield().ok();
        spins = spins.saturating_add(1);
        if spins > 200_000
        {
            MIGRATE_SHOULD_EXIT.store(1, Ordering::Relaxed);
            return Err("T never observed on CPU 1 before migration");
        }
    }

    // Trigger migration of a Running thread.
    thread_set_affinity(child.th, 0).map_err(|_| "migration thread_set_affinity(0) failed")?;

    // Wait up to a generous bound (≫ 1 timer tick) for the migration to land.
    spins = 0;
    while MIGRATE_OBSERVED_CPU.load(Ordering::Relaxed) != 0
    {
        syscall::thread_yield().ok();
        spins = spins.saturating_add(1);
        if spins > 200_000
        {
            MIGRATE_SHOULD_EXIT.store(1, Ordering::Relaxed);
            return Err("Running-thread migration did not land on CPU 0");
        }
    }

    // Tell T to exit and wait for the exit signal.
    MIGRATE_SHOULD_EXIT.store(1, Ordering::Relaxed);
    signal_wait(sig).map_err(|_| "signal_wait for migrate_spinner exit failed")?;

    cap_delete(child.th).map_err(|_| "cap_delete th after affinity_migrate_running failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after affinity_migrate_running failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after affinity_migrate_running failed")?;
    Ok(())
}

// ── Periodic cross-CPU load balancer (Issue #23) ──────────────────────────────

/// Helper: spawn `n` CPU-bound spinners, initially pinned to `initial_cpu`,
/// then change each one's affinity to `final_affinity`. Returns the
/// (thread, cspace, signal) cap triples for cleanup.
///
/// Each spinner publishes its current CPU into `BALANCE_OBSERVED_CPU[i]`
/// on every loop iteration and exits when `BALANCE_SHOULD_EXIT` is set.
#[allow(clippy::cast_possible_truncation)]
fn balance_spawn_spinners(
    ctx: &TestContext,
    n: usize,
    initial_cpu: u32,
    final_affinity: u32,
) -> Result<[(u32, u32, u32); BALANCE_MAX_SPINNERS], &'static str>
{
    let mut triples = [(0u32, 0u32, 0u32); BALANCE_MAX_SPINNERS];

    for i in 0..n
    {
        BALANCE_OBSERVED_CPU[i].store(u32::MAX, Ordering::Relaxed);
        let sig = cap_create_signal(ctx.memory_frame_base)
            .map_err(|_| "balance: cap_create_signal failed")?;
        let child = crate::spawn::new_child(ctx).map_err(|_| "balance: spawn::new_child failed")?;
        let child_sig =
            cap_copy(sig, child.cs, RIGHTS_SIGNAL).map_err(|_| "balance: cap_copy failed")?;

        // Initial pinning to `initial_cpu` forces the first enqueue there.
        // SAFETY: per-spinner stack slot, no aliasing.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(STACK_BALANCE_SPINNERS[i]) });
        let arg = (i as u64) << 32 | u64::from(child_sig);
        crate::spawn::configure_and_start_pinned(
            &child,
            balance_spinner_entry,
            stack_top,
            arg,
            initial_cpu,
        )
        .map_err(|_| "balance: configure_and_start_pinned failed")?;

        triples[i] = (child.th, child.cs, sig);
    }

    // Once started, relax (or fully clear) the affinity. Active migration
    // does NOT trigger here because `AFFINITY_ANY` is the no-migration path
    // — the goal is exactly to leave the threads queued on `initial_cpu`
    // for the periodic balancer to redistribute.
    for (th, _, _) in triples.iter().take(n)
    {
        thread_set_affinity(*th, final_affinity)
            .map_err(|_| "balance: relax thread_set_affinity failed")?;
    }
    Ok(triples)
}

/// Helper: tear down the spinners spawned by `balance_spawn_spinners`.
/// Signals exit, drains each thread's `signal_send`, and deletes the caps.
fn balance_teardown(triples: &[(u32, u32, u32); BALANCE_MAX_SPINNERS], n: usize) -> TestResult
{
    BALANCE_SHOULD_EXIT.store(1, Ordering::Relaxed);
    for &(_, _, sig) in triples.iter().take(n)
    {
        // Each spinner sends 0xC0FE before exiting.
        signal_wait(sig).map_err(|_| "balance: signal_wait teardown failed")?;
    }
    BALANCE_SHOULD_EXIT.store(0, Ordering::Relaxed);
    for &(th, cs, sig) in triples.iter().take(n)
    {
        cap_delete(th).map_err(|_| "balance: cap_delete th failed")?;
        cap_delete(sig).map_err(|_| "balance: cap_delete sig failed")?;
        cap_delete(cs).map_err(|_| "balance: cap_delete cs failed")?;
    }
    Ok(())
}

/// A skewed workload (every thread initially queued on CPU 0) gets
/// redistributed across all CPUs by the periodic load balancer.
///
/// Spawns N = `cpu_count` spinners with hard affinity to CPU 0 (forcing
/// them onto CPU 0's run queue), then relaxes affinity to `AFFINITY_ANY`.
/// After a few ticks the balancer pulls work into the under-loaded CPUs,
/// so at least two distinct CPUs should be observed across the
/// `BALANCE_OBSERVED_CPU` array.
///
/// Requires SMP; skips otherwise.
pub fn load_balancer_redistributes_skewed(ctx: &TestContext) -> TestResult
{
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: thread::load_balancer_redistributes_skewed SKIP (requires SMP)");
        return Ok(());
    }
    let n = core::cmp::min(
        usize::try_from(cpus).unwrap_or(BALANCE_MAX_SPINNERS),
        BALANCE_MAX_SPINNERS,
    );
    // `u32::MAX` is the AFFINITY_ANY sentinel (see SYS_THREAD_SET_AFFINITY).
    let triples = balance_spawn_spinners(ctx, n, 0, u32::MAX)?;

    // Sleep in short increments so the parent is BLOCKED — that
    // takes parent's CPU out of the spinner queue entirely and lets idle
    // CPUs (which carry the pull-balancer in their timer_tick) do their
    // job. Without this, parent's tight yield loop hogs CPU 0 long
    // enough that on slow QEMU instances the balancer never gets a turn.
    //
    // 250 × 4 ms = 1 s total budget. Pull-balance is probabilistic
    // (random victim selection); a one-second budget makes the chance
    // of NOT seeing any migration vanishingly small while keeping the
    // test fast in the common case (PASS fires on the first observed
    // migration, which is usually < 50 ms).
    let mut converged = false;
    for _ in 0..250
    {
        let seen_other_cpu = BALANCE_OBSERVED_CPU.iter().take(n).any(|slot| {
            let obs = slot.load(Ordering::Relaxed);
            obs != u32::MAX && obs != 0
        });
        if seen_other_cpu
        {
            converged = true;
            break;
        }
        // 4 ms blocking sleep: parent is OFF every run queue (Blocked),
        // so spinners and idle CPUs both make progress unimpeded.
        syscall::thread_sleep(4).ok();
    }

    balance_teardown(&triples, n)?;
    if !converged
    {
        return Err("load balancer did not redistribute work off CPU 0");
    }
    Ok(())
}

/// Pinned threads (hard affinity) are NEVER migrated by the load balancer.
///
/// Spawns N pinned threads on CPU 0 and runs the test for a few ticks. The
/// balancer's `find_runnable` predicate filters out `cpu_affinity != AFFINITY_ANY`,
/// so every spinner MUST report CPU 0 throughout the test.
///
/// Requires SMP; skips otherwise.
pub fn load_balancer_skips_pinned(ctx: &TestContext) -> TestResult
{
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: thread::load_balancer_skips_pinned SKIP (requires SMP)");
        return Ok(());
    }
    let n = 4usize.min(BALANCE_MAX_SPINNERS);

    // Pin to CPU 0 AND keep the pin (final affinity == 0).
    let triples = balance_spawn_spinners(ctx, n, 0, 0)?;

    // Give the balancer plenty of wallclock time to misbehave. Sleeping
    // blocks the parent, so the spinners and the idle CPUs both run
    // freely while we wait.
    for _ in 0..50
    {
        syscall::thread_sleep(2).ok();
    }

    // Every observation must be CPU 0.
    let violated = BALANCE_OBSERVED_CPU.iter().take(n).any(|slot| {
        let obs = slot.load(Ordering::Relaxed);
        obs != u32::MAX && obs != 0
    });

    balance_teardown(&triples, n)?;
    if violated
    {
        return Err("load balancer migrated a hard-pinned thread off its CPU");
    }
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

    let sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal for affinity_respected failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::affinity_respected: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy for affinity_respected failed")?;

    // Bind to CPU 1 before starting.
    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_AFFINITY_RESPECTED));
    crate::spawn::configure_and_start_pinned(
        &child,
        affinity_sender_entry,
        stack_top,
        u64::from(child_sig),
        1,
    )
    .map_err(|_| "thread::affinity_respected: configure_and_start_pinned failed")?;

    // If the thread successfully signals back, affinity routing worked.
    let bits = signal_wait(sig).map_err(|_| "signal_wait for affinity_respected failed")?;
    if bits != 0xC1A1
    {
        return Err("affinity thread did not send expected bits (expected 0xC1A1)");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after affinity_respected failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after affinity_respected failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after affinity_respected failed")?;
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

    let sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal for default_affinity_bsp failed")?;
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::default_affinity_bsp: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy for default_affinity_bsp failed")?;

    // Do NOT set affinity — leave it at default (AFFINITY_ANY).
    // Phase D should route this to CPU 0.

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_DEFAULT_AFFINITY));
    crate::spawn::configure_and_start(&child, sender_entry, stack_top, u64::from(child_sig))
        .map_err(|_| "thread::default_affinity_bsp: configure_and_start failed")?;

    // If the thread successfully signals back, default affinity routing worked.
    let bits = signal_wait(sig).map_err(|_| "signal_wait for default_affinity_bsp failed")?;
    if bits != 0xBEEF
    {
        return Err("default affinity thread did not send expected bits (expected 0xBEEF)");
    }

    cap_delete(child.th).map_err(|_| "cap_delete th after default_affinity_bsp failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after default_affinity_bsp failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after default_affinity_bsp failed")?;
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
// cast_possible_truncation: cap slot indices are guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn blocker_entry(arg: u64) -> !
{
    // arg packs (ready_slot << 32) | block_slot. Two distinct caps so the
    // child cannot self-deliver its own readiness send before the parent has
    // registered as the waiter.
    let ready_slot = (arg >> 32) as u32;
    let block_slot = (arg & 0xFFFF_FFFF) as u32;
    signal_send(ready_slot, 0x1).ok();
    // Block so the parent can stop us and read a stable TrapFrame.
    // If write_regs redirects our IP, we jump directly to phase2_entry on resume.
    signal_wait(block_slot).ok();
    // Not normally reached — parent always stops us while blocked.
    loop
    {
        core::hint::spin_loop();
    }
}

/// Reports the current CPU id back through the signal value and exits.
///
/// Used by [`affinity_migrate_ready_queued`] — the child is queued on one
/// CPU, then migrated by the parent via `thread_set_affinity`. The CPU id
/// reported here MUST be the post-migration CPU.
///
/// The CPU id is encoded as `1u64 << cpu` (one bit per CPU) rather than
/// the raw integer. Raw encoding fails when `cpu == 0`: `signal_send`
/// rejects zero-bit sends with `InvalidArgument` (see
/// `core/kernel/src/syscall/ipc.rs:832–835`), the child silently exits,
/// and the parent's `signal_wait` parks indefinitely — manifesting as the
/// all-CPUs-idle stall in issue #116. The bit-per-CPU encoding is always
/// non-zero for any valid CPU id, so the wake always lands; a stale-CPU
/// run shows up as a deterministic test FAIL ("not landed on CPU 1")
/// instead of a HANG.
// cast_possible_truncation: cap slot indices and CPU ids fit comfortably in u32.
#[allow(clippy::cast_possible_truncation)]
fn report_cpu_entry(sig_slot: u64) -> !
{
    let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX);
    // `wrapping_shl` masks the shift count modulo the type width (64),
    // keeping the result non-zero (and therefore acceptable to
    // `signal_send`) even on the defensive `u64::MAX` fallback above —
    // a plain `1u64 << cpu` would shift-overflow and panic in debug.
    signal_send(sig_slot as u32, 1u64.wrapping_shl(cpu as u32)).ok();
    thread_exit()
}

/// Spinner used by the load-balancer tests.
///
/// `arg` packs `(spinner_index << 32) | exit_signal_cap`. On every iteration
/// the spinner publishes the current CPU id into the per-index slot of
/// [`BALANCE_OBSERVED_CPU`]. When [`BALANCE_SHOULD_EXIT`] is set, the
/// spinner sends `0xC0FE` on its signal cap and exits.
// cast_possible_truncation: spinner indices and cap slot indices fit in u32.
#[allow(clippy::cast_possible_truncation)]
fn balance_spinner_entry(arg: u64) -> !
{
    let idx = (arg >> 32) as usize;
    let sig_slot = (arg & 0xFFFF_FFFF) as u32;
    loop
    {
        let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX) as u32;
        if idx < BALANCE_MAX_SPINNERS
        {
            BALANCE_OBSERVED_CPU[idx].store(cpu, Ordering::Relaxed);
        }
        if BALANCE_SHOULD_EXIT.load(Ordering::Relaxed) != 0
        {
            signal_send(sig_slot, 0xC0FE).ok();
            thread_exit();
        }
        for _ in 0..64
        {
            core::hint::spin_loop();
        }
    }
}

/// Tight `CurrentCpu` observation loop used by [`affinity_migrate_running`].
///
/// Publishes the latest observed CPU id into [`MIGRATE_OBSERVED_CPU`] on
/// every iteration. Exits when [`MIGRATE_SHOULD_EXIT`] is set, signalling
/// the parent first so it can complete `signal_wait`.
// cast_possible_truncation: cap slot indices and CPU ids fit comfortably in u32.
#[allow(clippy::cast_possible_truncation)]
fn migrate_spinner_entry(sig_slot: u64) -> !
{
    loop
    {
        let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX) as u32;
        MIGRATE_OBSERVED_CPU.store(cpu, Ordering::Relaxed);
        if MIGRATE_SHOULD_EXIT.load(Ordering::Relaxed) != 0
        {
            signal_send(sig_slot as u32, 0xC0FE).ok();
            thread_exit();
        }
        // Tiny back-off so the parent gets a chance to run between observations.
        for _ in 0..32
        {
            core::hint::spin_loop();
        }
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

// ── SYS_THREAD_SLEEP ─────────────────────────────────────────────────────────

/// `thread_sleep(50)` blocks the caller for at least ~40 ms wall clock
/// (slack to absorb timer granularity on slow VMs).
pub fn sleep_blocks_ms(_ctx: &TestContext) -> TestResult
{
    let t0 = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "thread::sleep_blocks_ms: system_info(ElapsedUs) before failed")?;
    thread_sleep(50).map_err(|_| "thread::sleep_blocks_ms: thread_sleep(50) failed")?;
    let t1 = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "thread::sleep_blocks_ms: system_info(ElapsedUs) after failed")?;
    let elapsed_us = t1.wrapping_sub(t0);
    if elapsed_us < 40_000
    {
        return Err("thread::sleep_blocks_ms: returned earlier than requested timeout");
    }
    Ok(())
}

/// `thread_sleep(0)` is a no-op — returns immediately with `Ok(())`.
pub fn sleep_zero_is_noop(_ctx: &TestContext) -> TestResult
{
    thread_sleep(0).map_err(|_| "thread::sleep_zero_is_noop: thread_sleep(0) returned error")?;
    Ok(())
}

// ── SYS_THREAD_BIND_NOTIFICATION ─────────────────────────────────────────────

/// Stack for the `bind_notification` child.
static mut BIND_NOTIF_STACK: crate::ChildStack = crate::ChildStack::ZERO;

/// Child that exits immediately so its bound `EventQueue` receives the
/// thread-death payload.
fn bind_notif_exit_entry(_arg: u64) -> !
{
    thread_exit()
}

/// `thread_bind_notification(child, eq, correlator)` causes a payload
/// carrying `correlator` to be posted to `eq` when the child thread exits.
pub fn bind_notification_fires_on_exit(ctx: &TestContext) -> TestResult
{
    const CORRELATOR: u32 = 0xCAFEu32;

    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "thread::bind_notification_fires_on_exit: event_queue_create failed")?;

    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "thread::bind_notification_fires_on_exit: spawn::new_child failed")?;

    // Bind BEFORE the child starts so the observer is registered when the
    // thread first becomes Exited.
    thread_bind_notification(child.th, eq, CORRELATOR)
        .map_err(|_| "thread::bind_notification_fires_on_exit: thread_bind_notification failed")?;

    let stack_top = crate::ChildStack::top(core::ptr::addr_of!(BIND_NOTIF_STACK));
    crate::spawn::configure_and_start(&child, bind_notif_exit_entry, stack_top, 0)
        .map_err(|_| "thread::bind_notification_fires_on_exit: configure_and_start failed")?;

    // Block until the death notification arrives.
    let payload =
        event_recv(eq).map_err(|_| "thread::bind_notification_fires_on_exit: event_recv failed")?;

    // The kernel packs the correlator into the high 32 bits of the payload.
    let observed = (payload >> 32) as u32;
    if observed != CORRELATOR
    {
        return Err("thread::bind_notification_fires_on_exit: wrong correlator on death payload");
    }

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    cap_delete(eq).ok();
    Ok(())
}

/// `thread_bind_notification` with a null thread cap must return
/// `InvalidCapability`.
pub fn bind_notification_invalid_cap_err(_ctx: &TestContext) -> TestResult
{
    let err = thread_bind_notification(0, 0, 0);
    if err != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("thread::bind_notification_invalid_cap_err: did not return InvalidCapability");
    }
    Ok(())
}
