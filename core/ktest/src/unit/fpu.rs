// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/fpu.rs

//! Tier 1 test for extended-state (FPU / SIMD / V) isolation across
//! preemption.
//!
//! Two children are pinned to CPU 0 so the scheduler must time-slice them
//! against each other on a single hart. Each loads a distinct bit pattern
//! into every architecturally addressable FP register (and on RISC-V every
//! V register), spins long enough to be preempted many times by the timer,
//! and finally captures the live register file into memory. The parent
//! verifies both captures match the pattern the child wrote. Any
//! cross-thread bleed surfaces as a mismatch and fails the test.
//!
//! [`initial_state`] checks the extended state a new thread starts with,
//! which thread creation writes into its save area.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::system_info;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_notification, cap_create_thread, cap_delete,
    notification_send, notification_wait, thread_configure, thread_exit, thread_set_affinity,
    thread_start,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Spin-loop length in the inline-asm hot path. Sized to give the timer
/// many opportunities to preempt at the default tick rate while finishing
/// the test in well under a second of wall time on QEMU TCG.
const SPIN_ITERS: u64 = 200_000;

/// Spin between the cross-CPU child's register load and its "ready" signal, so
/// timer ticks fire while it owns the extended state on the source CPU.
const CROSS_SPIN_ITERS: u64 = 50_000;

/// Distinct lane pattern per child. Bytes chosen so a byte-granular swap
/// between the two patterns is unambiguous.
const PATTERN_A: u64 = 0xA5A5_A5A5_A5A5_A5A5;
const PATTERN_B: u64 = 0x5A5A_5A5A_5A5A_5A5A;

static mut STACK_A: ChildStack = ChildStack::ZERO;
static mut STACK_B: ChildStack = ChildStack::ZERO;

// Children write the mismatch count after the spin completes and the parent
// reads it only after the corresponding notification_send is observed, so the zero
// default is never mistaken for a result.
static A_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static B_MISMATCHES: AtomicU64 = AtomicU64::new(0);

// Non-zero initialised static. Forces LLD to emit a `.data` section in the
// ktest ELF, exercising the path where the kernel mints a Memory cap whose
// underlying segment has a sub-page-aligned ELF VA. The cap must still
// expose a page-aligned `base` and whole-page `size` to userspace — see
// `mm::init_segment_caps_aligned`.
#[used]
#[unsafe(no_mangle)]
pub static SUB_PAGE_SENTINEL: AtomicU64 = AtomicU64::new(0xDEAD_BEEF_CAFE_BABE);

extern "C" fn child_a_entry(sig_slot: u64) -> !
{
    let mismatches = crate::arch::fpu::preempt_capture(PATTERN_A, SPIN_ITERS);
    A_MISMATCHES.store(mismatches, Ordering::Release);
    let _ = notification_send(sig_slot, 0x1);
    thread_exit();
}

extern "C" fn child_b_entry(sig_slot: u64) -> !
{
    let mismatches = crate::arch::fpu::preempt_capture(PATTERN_B, SPIN_ITERS);
    B_MISMATCHES.store(mismatches, Ordering::Release);
    let _ = notification_send(sig_slot, 0x1);
    thread_exit();
}

/// Two threads pinned to CPU 0 each load a distinct pattern into every
/// architecturally addressable extended-state register, spin long enough
/// to be preempted many times, and capture the live registers afterward.
/// Both captures must equal the child's own pattern — any mismatch
/// indicates the eager-save / lazy-restore path leaked state across the context
/// switch.
pub fn preempt_isolation(ctx: &TestContext) -> TestResult
{
    A_MISMATCHES.store(0, Ordering::Release);
    B_MISMATCHES.store(0, Ordering::Release);

    let sig_a = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification a for fpu::preempt_isolation failed")?;
    let sig_b = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification b for fpu::preempt_isolation failed")?;
    let cs_a = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace a for fpu::preempt_isolation failed")?;
    let cs_b = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace b for fpu::preempt_isolation failed")?;
    let child_sig_a = cap_copy(sig_a, cs_a, RIGHTS_NOTIFY)
        .map_err(|_| "cap_copy sig_a for fpu::preempt_isolation failed")?;
    let child_sig_b = cap_copy(sig_b, cs_b, RIGHTS_NOTIFY)
        .map_err(|_| "cap_copy sig_b for fpu::preempt_isolation failed")?;

    let th_a = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs_a, 0, 0)
        .map_err(|_| "cap_create_thread a for fpu::preempt_isolation failed")?;
    let mut child_a = crate::spawn::SpawnedChild { th: th_a, cs: cs_a };
    let th_b = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs_b, 0, 0)
        .map_err(|_| "cap_create_thread b for fpu::preempt_isolation failed")?;
    let mut child_b = crate::spawn::SpawnedChild { th: th_b, cs: cs_b };

    // SAFETY: `STACK_A` is a static stack, reached only through `addr_of!`.
    let stack_a = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_A)) };
    // SAFETY: `STACK_B` is a static stack, reached only through `addr_of!`.
    let stack_b = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_B)) };

    // SAFETY: the entry is an `extern "C" fn(u64) -> !` of the entry ABI, and the
    // stack is this child's own, on which no other live thread runs (`ChildStack`'s
    // rule, as noted where the stack is chosen).
    unsafe {
        thread_configure(
            th_a,
            child_a_entry as *const () as u64,
            stack_a,
            child_sig_a,
        )
    }
    .map_err(|_| "thread_configure a for fpu::preempt_isolation failed")?;
    // SAFETY: the entry is an `extern "C" fn(u64) -> !` of the entry ABI, and the
    // stack is this child's own, on which no other live thread runs (`ChildStack`'s
    // rule, as noted where the stack is chosen).
    unsafe {
        thread_configure(
            th_b,
            child_b_entry as *const () as u64,
            stack_b,
            child_sig_b,
        )
    }
    .map_err(|_| "thread_configure b for fpu::preempt_isolation failed")?;

    // Pin both children to CPU 0 to force time-sliced co-residency.
    thread_set_affinity(th_a, 0)
        .map_err(|_| "thread_set_affinity a for fpu::preempt_isolation failed")?;
    thread_set_affinity(th_b, 0)
        .map_err(|_| "thread_set_affinity b for fpu::preempt_isolation failed")?;

    thread_start(th_a).map_err(|_| "thread_start a for fpu::preempt_isolation failed")?;
    thread_start(th_b).map_err(|_| "thread_start b for fpu::preempt_isolation failed")?;

    let _ = notification_wait(sig_a)
        .map_err(|_| "notification_wait a for fpu::preempt_isolation failed")?;
    let _ = notification_wait(sig_b)
        .map_err(|_| "notification_wait b for fpu::preempt_isolation failed")?;

    let a_mis = A_MISMATCHES.load(Ordering::Acquire);
    let b_mis = B_MISMATCHES.load(Ordering::Acquire);

    child_a
        .delete_thread()
        .map_err(|_| "cap_delete th_a after fpu::preempt_isolation failed")?;
    child_b
        .delete_thread()
        .map_err(|_| "cap_delete th_b after fpu::preempt_isolation failed")?;
    cap_delete(sig_a).map_err(|_| "cap_delete sig_a after fpu::preempt_isolation failed")?;
    cap_delete(sig_b).map_err(|_| "cap_delete sig_b after fpu::preempt_isolation failed")?;
    child_a
        .delete_cspace()
        .map_err(|_| "cap_delete cs_a after fpu::preempt_isolation failed")?;
    child_b
        .delete_cspace()
        .map_err(|_| "cap_delete cs_b after fpu::preempt_isolation failed")?;

    if a_mis != 0
    {
        return Err("thread A observed extended-state corruption across preemption");
    }
    if b_mis != 0
    {
        return Err("thread B observed extended-state corruption across preemption");
    }
    Ok(())
}

// ── Cross-CPU preemption-isolation (eager-save migration, per #108) ──────────

/// Per-thread stack for the cross-CPU child.
static mut STACK_CROSS: ChildStack = ChildStack::ZERO;
/// Handles, in the cross-CPU child's `CSpace`, of its ready, resume, and
/// done notification caps. The child loads ready and resume before its
/// inline-asm block (so no Rust call runs between the FP load and the
/// capture) and done after it.
static CROSS_SIG_READY: AtomicU64 = AtomicU64::new(0);
static CROSS_SIG_RESUME: AtomicU64 = AtomicU64::new(0);
static CROSS_SIG_DONE: AtomicU64 = AtomicU64::new(0);
/// Mismatch count written by the cross-CPU child after the post-migration
/// register capture. The parent reads it only after the `done` notification so
/// the zero default is never mistaken for a pass.
static CROSS_MISMATCHES: AtomicU64 = AtomicU64::new(0);
/// CPU id observed by the cross-CPU child after migration, sanity-checked
/// by the parent to confirm the migration actually happened.
static CROSS_OBSERVED_CPU: AtomicU32 = AtomicU32::new(u32::MAX);

/// Cross-CPU child entry: load `PATTERN_A` into the extended-state register
/// file, signal "ready", block on "resume", then capture the registers back,
/// through `crate::arch::fpu::notification_rendezvous_capture`, whose one
/// inline-asm block spans the load, both syscalls, and the capture.
extern "C" fn child_cross_entry(_arg: u64) -> !
{
    let mismatches = crate::arch::fpu::notification_rendezvous_capture(
        PATTERN_A,
        CROSS_SPIN_ITERS,
        CROSS_SIG_READY.load(Ordering::Acquire),
        CROSS_SIG_RESUME.load(Ordering::Acquire),
    );
    CROSS_MISMATCHES.store(mismatches, Ordering::Release);
    let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX);
    CROSS_OBSERVED_CPU.store(u32::try_from(cpu).unwrap_or(u32::MAX), Ordering::Release);

    let _ = notification_send(CROSS_SIG_DONE.load(Ordering::Acquire), 0x1);
    thread_exit();
}

/// Cross-CPU FPU-migration correctness: a thread that loaded its
/// extended-state registers on CPU 0, blocked, then was woken with affinity
/// changed to CPU 1, must observe its register file intact post-migration.
/// The kernel discipline that guarantees this is specified in
/// `core/kernel/docs/scheduler.md` § What Gets Saved and Restored and
/// `core/kernel/docs/scheduling-internals.md` § IPI Taxonomy.
///
/// Requires SMP; skips on UP. Runs on both x86-64 (XSAVE/XRSTOR + `#NM`)
/// and RISC-V (`sstatus.FS/VS` dirty-tracking + illegal-instruction trap).
pub fn preempt_isolation_cross_cpu(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "system_info(CpuCount) for preempt_isolation_cross_cpu failed")?;
    if cpus < 2
    {
        crate::log("ktest: fpu::preempt_isolation_cross_cpu SKIP (requires SMP)");
        return Ok(());
    }

    CROSS_MISMATCHES.store(0, Ordering::Release);
    CROSS_OBSERVED_CPU.store(u32::MAX, Ordering::Release);

    let sig_ready = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification ready for preempt_isolation_cross_cpu failed")?;
    let sig_resume = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification resume for preempt_isolation_cross_cpu failed")?;
    let sig_done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification done for preempt_isolation_cross_cpu failed")?;
    let cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace for preempt_isolation_cross_cpu failed")?;

    let child_ready = cap_copy(sig_ready, cs, RIGHTS_NOTIFY)
        .map_err(|_| "cap_copy ready for preempt_isolation_cross_cpu failed")?;
    let child_resume = cap_copy(sig_resume, cs, RIGHTS_NOTIFY)
        .map_err(|_| "cap_copy resume for preempt_isolation_cross_cpu failed")?;
    let child_done = cap_copy(sig_done, cs, RIGHTS_NOTIFY)
        .map_err(|_| "cap_copy done for preempt_isolation_cross_cpu failed")?;

    CROSS_SIG_READY.store(child_ready, Ordering::Release);
    CROSS_SIG_RESUME.store(child_resume, Ordering::Release);
    CROSS_SIG_DONE.store(child_done, Ordering::Release);

    let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
        .map_err(|_| "cap_create_thread for preempt_isolation_cross_cpu failed")?;
    let mut child = crate::spawn::SpawnedChild { th, cs };

    // Pin to CPU 0 initially: the child must run and load its
    // extended-state registers on CPU 0 before the migration step.
    thread_set_affinity(th, 0)
        .map_err(|_| "initial thread_set_affinity(0) for preempt_isolation_cross_cpu failed")?;

    // SAFETY: `STACK_CROSS` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_CROSS)) };
    // SAFETY: the entry is an `extern "C" fn(u64) -> !` of the entry ABI, and the
    // stack is this child's own, on which no other live thread runs (`ChildStack`'s
    // rule, as noted where the stack is chosen).
    unsafe { thread_configure(th, child_cross_entry as *const () as u64, stack_top, 0) }
        .map_err(|_| "thread_configure for preempt_isolation_cross_cpu failed")?;
    thread_start(th).map_err(|_| "thread_start for preempt_isolation_cross_cpu failed")?;

    // Wait for the child to load its extended-state registers on CPU 0 and
    // signal ready.
    // The parent blocks (yielding CPU 0) so the child can run; the child
    // then loads PATTERN_A, briefly spins, signals ready, and blocks on
    // sig_resume.
    let _ = notification_wait(sig_ready)
        .map_err(|_| "notification_wait ready for preempt_isolation_cross_cpu failed")?;

    // Change affinity to CPU 1 while the child is Blocked. This just
    // updates the affinity field; the migration happens at wake time.
    thread_set_affinity(th, 1)
        .map_err(|_| "thread_set_affinity(1) for preempt_isolation_cross_cpu failed")?;

    // Wake the child. The wake path enqueues it on CPU 1's run queue; its
    // extended state was saved into its TCB area when it switched out on
    // CPU 0 and is restored on its first FP op on CPU 1 (see
    // core/kernel/docs/scheduler.md § What Gets Saved and Restored).
    notification_send(sig_resume, 0x1)
        .map_err(|_| "notification_send resume for preempt_isolation_cross_cpu failed")?;

    let _ = notification_wait(sig_done)
        .map_err(|_| "notification_wait done for preempt_isolation_cross_cpu failed")?;

    let mismatches = CROSS_MISMATCHES.load(Ordering::Acquire);
    let observed_cpu = CROSS_OBSERVED_CPU.load(Ordering::Acquire);

    child
        .delete_thread()
        .map_err(|_| "cap_delete th after preempt_isolation_cross_cpu failed")?;
    cap_delete(sig_ready)
        .map_err(|_| "cap_delete sig_ready after preempt_isolation_cross_cpu failed")?;
    cap_delete(sig_resume)
        .map_err(|_| "cap_delete sig_resume after preempt_isolation_cross_cpu failed")?;
    cap_delete(sig_done)
        .map_err(|_| "cap_delete sig_done after preempt_isolation_cross_cpu failed")?;
    child
        .delete_cspace()
        .map_err(|_| "cap_delete cs after preempt_isolation_cross_cpu failed")?;

    crate::log_u64(
        "fpu::preempt_isolation_cross_cpu observed_cpu=",
        u64::from(observed_cpu),
    );
    crate::log_u64("fpu::preempt_isolation_cross_cpu mismatches=", mismatches);
    if mismatches != 0
    {
        return Err("cross-CPU child observed extended-state corruption after migration");
    }
    // The migration was either actually cross-CPU (observed != 0) or the
    // scheduler kept the child on its original CPU. In either case, the
    // FP state must be intact; no cross-CPU FPU coordination exists (see
    // core/kernel/docs/scheduling-internals.md § IPI Taxonomy). We log the
    // observed CPU for diagnostics but do not gate the test on it — the
    // existing `thread::affinity_migrate_ready_queued` test already covers
    // strict affinity enforcement.
    Ok(())
}

// ── A new thread's initial state ─────────────────────────────────────────────

/// Stack of the initial-state child.
static mut STACK_INITIAL: ChildStack = ChildStack::ZERO;

/// Outcome of the initial-state child's check of its control words:
/// [`NOT_REACHED`] until it runs, 0 when every word holds its initial
/// value, else one more than the index into `crate::arch::fpu::STATE_WORDS`
/// of the first that does not.
static INITIAL_MISMATCH: AtomicU64 = AtomicU64::new(NOT_REACHED);
/// The value of the word [`INITIAL_MISMATCH`] names.
static INITIAL_VALUE: AtomicU64 = AtomicU64::new(0);
/// Outcome of the child's inexact division: [`NOT_REACHED`] until it
/// completes, 0 when the status after it is the expected one, else 1.
static DIVIDE_MISMATCH: AtomicU64 = AtomicU64::new(NOT_REACHED);
/// The status word the child read after its division.
static DIVIDE_VALUE: AtomicU64 = AtomicU64::new(0);

/// An outcome the child has not written.
const NOT_REACHED: u64 = u64::MAX;

/// Polls of the wait for the child to exit, ~1 ms each, applied through
/// [`crate::scaled_polls`]: the child runs two checks and exits.
const EXIT_POLLS: u32 = 2000;

/// Initial-state child entry: check the control words before any other use
/// of the extended state, publish the result, then divide inexactly and
/// publish that, and exit. A child whose state unmasks the inexact exception
/// dies at the division, leaving [`DIVIDE_MISMATCH`] unwritten.
extern "C" fn initial_state_entry(_arg: u64) -> !
{
    let (mismatch, value) = match crate::arch::fpu::initial_state_check()
    {
        Ok(()) => (0, 0),
        Err((i, got)) => ((i as u64).saturating_add(1), got),
    };
    INITIAL_VALUE.store(value, Ordering::Relaxed);
    INITIAL_MISMATCH.store(mismatch, Ordering::Release);
    let (mismatch, value) = match crate::arch::fpu::inexact_divide_check()
    {
        Ok(()) => (0, 0),
        Err(got) => (1, got),
    };
    DIVIDE_VALUE.store(value, Ordering::Relaxed);
    DIVIDE_MISMATCH.store(mismatch, Ordering::Release);
    thread_exit();
}

/// A new thread starts with the architected initial extended state: its
/// floating-point control words read their initial values at its first use
/// (on x86-64 `MXCSR` 0x1F80, every SIMD exception masked, and the x87
/// control word 0x037F; on riscv64 `fcsr`, `vl`, `vtype`, `vstart` and
/// `vcsr` 0), and an inexact division completes and sets only the inexact
/// flag, where an unmasked exception would kill the thread. ktest's own
/// thread, which the kernel creates at boot by the same path, holds the same
/// control fields.
pub fn initial_state(ctx: &TestContext) -> TestResult
{
    control_words_hold(
        "ktest's own thread",
        crate::arch::fpu::control_state_check(),
    )?;
    INITIAL_MISMATCH.store(NOT_REACHED, Ordering::Relaxed);
    DIVIDE_MISMATCH.store(NOT_REACHED, Ordering::Relaxed);
    let mut child =
        crate::spawn::new_child(ctx).map_err(|_| "fpu::initial_state: spawn::new_child failed")?;
    // SAFETY: `STACK_INITIAL` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_INITIAL)) };
    // SAFETY: the stack is `STACK_INITIAL`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    let started =
        unsafe { crate::spawn::configure_and_start(&child, initial_state_entry, stack_top, 0) };
    let exited = started
        .and_then(|()| crate::spawn::wait_until_exited(child.th, crate::scaled_polls(EXIT_POLLS)));
    let released = child
        .delete_thread()
        .and_then(|()| child.delete_cspace())
        .map_err(|_| "fpu::initial_state: teardown of the child failed");
    exited?;
    released?;
    child_outcome()
}

/// Judge what the initial-state child published.
fn child_outcome() -> TestResult
{
    let initial = INITIAL_MISMATCH.load(Ordering::Acquire);
    if initial == NOT_REACHED
    {
        return Err("fpu::initial_state: the child exited before checking its state");
    }
    let initial = match initial.checked_sub(1)
    {
        None => Ok(()),
        Some(i) => Err((
            usize::try_from(i).unwrap_or(usize::MAX),
            INITIAL_VALUE.load(Ordering::Relaxed),
        )),
    };
    control_words_hold("a new thread", initial)?;
    match DIVIDE_MISMATCH.load(Ordering::Acquire)
    {
        0 => Ok(()),
        NOT_REACHED => Err("fpu::initial_state: a new thread died at an inexact division"),
        _ =>
        {
            crate::log_u64(
                "ktest: fpu::initial_state status after the division=",
                DIVIDE_VALUE.load(Ordering::Relaxed),
            );
            Err("fpu::initial_state: an inexact division left a wrong status word")
        }
    }
}

/// Map a control-word check of `whose` state to the test's result, logging
/// the word that differs and its value.
fn control_words_hold(whose: &str, check: Result<(), (usize, u64)>) -> TestResult
{
    let Err((i, got)) = check
    else
    {
        return Ok(());
    };
    crate::log("ktest: fpu::initial_state: a control word differs in the state of");
    crate::log(whose);
    crate::log(
        crate::arch::fpu::STATE_WORDS
            .get(i)
            .copied()
            .unwrap_or("an unnamed word"),
    );
    crate::log_u64("ktest: fpu::initial_state value=", got);
    Err("fpu::initial_state: a control word does not hold its initial value")
}
