// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/return_work.rs

//! Integration: the work a thread owes at a return to user mode is done
//! before the thread is back in user mode, whether the producer of the work
//! runs on the thread's CPU (local) or on another CPU (remote). The cases
//! observe behaviour through syscalls only.
//!
//! CPU A is the CPU of the case's own thread (CPU 0) and CPU B the CPU of the
//! remote child (CPU 1).
//!
//!   1. **`upcall_syscall_remote`.** A child on CPU B loops on a syscall; a
//!      syscall-point upcall posted from CPU A is delivered.
//!   2. **`upcall_any_remote`.** A child on CPU B spins with no syscall; an
//!      `UPCALL_ANY_INSTRUCTION` upcall posted from CPU A is delivered at the
//!      interrupt point.
//!   3. **`upcall_syscall_local`.** A child on CPU A, not running at the post,
//!      takes a syscall-point upcall once the poster blocks.
//!   4. **`upcall_any_local`.** As 3, for the any-instruction upcall of a
//!      spinning child.
//!   5. **`exit_remote_syscall_loop`.** A delete of the only Thread capability
//!      of a child looping on a syscall on CPU B stops its progress: the child
//!      never returns to user mode after the delete returns.
//!   6. **`exit_remote_spin`.** As 5, for a child spinning in user mode.
//!   7. **`sole_ref_remote_busy`.** A sole-reference post for a capability whose
//!      other copy a child on CPU B deletes arrives although CPU B never
//!      idles.
//!   8. **`reclaim_busy_cpu`.** The `CSpace` objects that threads tearing
//!      themselves down queue on a CPU that never idles are reclaimed by that
//!      CPU's busy thread's next return.
//!
//!   9. **`exit_local_self_teardown`.** A child on CPU B that deletes the last
//!      capability to its own `CSpace` is torn down by that syscall and never
//!      returns to user mode from it.
//!
//! Cases 5 and 6 check the outcome of a remote teardown, which the kernel's
//! drain gate guarantees whatever the return path does; the return path's
//! share there is latency, which no case measures.
//!
//! Cases that need a second CPU skip on a one-CPU boot.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_info,
    event_queue_create_observed, event_recv_entry, system_info, thread_post_upcall,
    thread_set_affinity, thread_sleep, thread_yield,
};
use syscall_abi::{
    CAP_INFO_MEMORY_AVAILABLE, FAULT_CLASS_UPCALL, FAULT_KIND_UPCALL, FAULT_LABEL,
    FAULT_REPLY_RESUME, RIGHTS_ALL, SyscallError, SystemInfoType, UPCALL_ANY_INSTRUCTION,
    UPCALL_POINT_INTERRUPT, UPCALL_POINT_SYSCALL,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// CPU A: the case's own thread, and the local children.
const CPU_A: u32 = 0;

/// CPU B: the remote children.
const CPU_B: u32 = 1;

/// Badge bound with the upcall class.
const BADGE_UP: u64 = 0x0B5E_CA21;

/// Bound, in milliseconds, on a wait for an upcall or a post, applied through
/// [`crate::scaled_bound`].
const WAIT_MS: u64 = 2000;

/// Bound, in 1 ms polls, on a wait for a child's progress or exit, applied
/// through [`crate::scaled_polls`].
const PROGRESS_POLLS: u32 = 2000;

/// Interval, in milliseconds, that a stopped child's counter must stay still
/// across (several timer ticks).
const STILL_MS: u64 = 10;

/// Deadline, in microseconds, on the wait for a spinning child's counter to
/// stop after its delete, applied through [`crate::scaled_bound`].
const STOP_DEADLINE_US: u64 = 1_000_000;

/// Threads that exit in [`reclaim_busy_cpu`].
const CHURN_THREADS: u32 = 64;

/// `event_recv_entry`'s non-blocking poll.
const TRY_ONCE: u64 = u64::MAX;

/// Correlator of the sole-reference binding.
const CORRELATOR: u64 = 0x5013_0000_0000_0707;

/// Stack slots: one per case, then the exiting threads' of case 8.
const STACK_SOLE: usize = 6;
const STACK_BUSY: usize = 7;
const STACK_CHURN: usize = 8;

const STACK_SELF: usize = 9;

/// First stack slot of case 7's spinners, one per CPU other than CPUs A and B,
/// and how many slots there are: CPUs past that many are left unspun, so on a
/// boot wider than eight CPUs an idle CPU can drain the post and the case
/// checks only that it arrives. CI's ktest boots run at four CPUs.
const SPINNER_BASE: usize = 10;
const SPINNER_SLOTS: usize = 6;

static mut STACKS: [ChildStack; SPINNER_BASE + SPINNER_SLOTS] =
    [const { ChildStack::ZERO }; SPINNER_BASE + SPINNER_SLOTS];

/// Flags of case 9's child: set before, and after, its delete of its own
/// `CSpace`.
static SELF_BEFORE: AtomicU64 = AtomicU64::new(0);
static SELF_AFTER: AtomicU64 = AtomicU64::new(0);

/// The progress counter of the running child.
static COUNT: AtomicU64 = AtomicU64::new(0);

/// The child of an upcall case: one looping on a syscall, counting, or one
/// spinning in user mode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChildKind
{
    SyscallLoop,
    Spin,
}

impl ChildKind
{
    /// The child's entry.
    fn entry(self) -> extern "C" fn(u64) -> !
    {
        match self
        {
            Self::SyscallLoop => syscall_loop_entry,
            Self::Spin => spin_entry,
        }
    }
}

/// The messages of one upcall case.
struct Msgs
{
    setup: &'static str,
    post: &'static str,
    unseen: &'static str,
    wrong: &'static str,
    resume: &'static str,
    teardown: &'static str,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("return_work: starting");
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "integration::return_work: system_info(CpuCount) failed")?;
    thread_set_affinity(ctx.thread_cap, CPU_A)
        .map_err(|_| "integration::return_work: pinning the case thread failed")?;
    let result = reach_cpu_a().and_then(|()| cases(ctx, cpus));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "integration::return_work: restoring affinity failed");
    result.and(restore)
}

/// Run the cases in order.
fn cases(ctx: &TestContext, cpus: u64) -> TestResult
{
    let remote = cpus >= 2;
    if remote
    {
        upcall_syscall_remote(ctx)?;
        upcall_any_remote(ctx)?;
    }
    else
    {
        crate::log(
            "ktest: return_work upcall_syscall_remote, upcall_any_remote SKIP (needs 2 CPUs)",
        );
    }
    upcall_syscall_local(ctx)?;
    upcall_any_local(ctx)?;
    if remote
    {
        exit_remote_syscall_loop(ctx)?;
        exit_remote_spin(ctx)?;
        exit_local_self_teardown(ctx)?;
        sole_ref_remote_busy(ctx, cpus)?;
        reclaim_busy_cpu(ctx)
    }
    else
    {
        crate::log(
            "ktest: return_work exit_remote_*, exit_local_self_teardown, sole_ref_remote_busy, reclaim_busy_cpu SKIP \
             (needs 2 CPUs)",
        );
        Ok(())
    }
}

/// Yield until the case's thread runs on [`CPU_A`].
fn reach_cpu_a() -> TestResult
{
    let on_cpu = || system_info(SystemInfoType::CurrentCpu as u64) == Ok(u64::from(CPU_A));
    for _ in 0..1000
    {
        if on_cpu()
        {
            return Ok(());
        }
        let _ = thread_yield();
    }
    if on_cpu()
    {
        Ok(())
    }
    else
    {
        Err("integration::return_work: the case thread did not move to CPU A")
    }
}

/// Child entry: yield in a loop, counting.
extern "C" fn syscall_loop_entry(_arg: u64) -> !
{
    loop
    {
        COUNT.fetch_add(1, Ordering::Release);
        // A syscall that never reschedules, so only the return path's own work
        // runs at each return (a yield would reschedule on its own).
        let _ = system_info(SystemInfoType::CurrentCpu as u64);
    }
}

/// Child entry: spin with no syscall.
extern "C" fn spin_entry(_arg: u64) -> !
{
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: count in a loop with no syscall.
extern "C" fn count_spin_entry(_arg: u64) -> !
{
    loop
    {
        COUNT.fetch_add(1, Ordering::Release);
    }
}

/// Child entry: delete the capability in slot `handle`, then loop on a syscall
/// that never reschedules, forever.
extern "C" fn delete_then_busy_entry(handle: u64) -> !
{
    let _ = cap_delete(handle);
    loop
    {
        let _ = system_info(SystemInfoType::CurrentCpu as u64);
    }
}

/// Child entry: delete the capability in slot `handle`, the last one to its own
/// `CSpace`, flagging before and after; the delete must not return.
extern "C" fn self_teardown_entry(handle: u64) -> !
{
    SELF_BEFORE.store(1, Ordering::Release);
    let _ = cap_delete(handle);
    SELF_AFTER.store(1, Ordering::Release);
    loop
    {
        core::hint::spin_loop();
    }
}

/// Configure `child` at `entry(arg)` on stack slot `slot`, pin it to `cpu`, and start it.
fn start(
    child: &spawn::SpawnedChild,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    arg: u64,
    cpu: u32,
    err: &'static str,
) -> TestResult
{
    // SAFETY: `STACKS` is a static array of stacks, reached only through `addr_of!`.
    let top = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), slot) }.map_err(|_| err)?;
    // SAFETY: the stack is `STACKS[slot]`, this test's own, and each slot's previous
    // child has been deleted or has exited before the slot is used again.
    unsafe { spawn::configure_and_start_pinned(child, entry, top, arg, cpu) }.map_err(|_| err)
}

/// Delete `child`'s caps; whether both deletes succeeded.
fn reap(child: &mut spawn::SpawnedChild) -> bool
{
    let thread = child.delete_thread().is_ok();
    let cspace = child.delete_cspace().is_ok();
    thread && cspace
}

/// Wait, bounded, until [`COUNT`] exceeds `above`.
fn wait_count_above(above: u64) -> bool
{
    for _ in 0..crate::scaled_polls(PROGRESS_POLLS)
    {
        if COUNT.load(Ordering::Acquire) > above
        {
            return true;
        }
        let _ = thread_sleep(1);
    }
    COUNT.load(Ordering::Acquire) > above
}

/// Microseconds since boot.
fn elapsed_us(err: &'static str) -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64).map_err(|_| err)
}

/// One upcall case: a child at `entry` pinned to `cpu` takes a post with `flags`; the
/// handler (this thread, receiving on the bound endpoint) must see it within
/// the bound, at `point` when one is given, and the reply resumes the child; with
/// a counting child its [`COUNT`] must advance after it.
fn upcall_case(
    ctx: &TestContext,
    slot: usize,
    cpu: u32,
    child_kind: ChildKind,
    flags: u64,
    point: Option<u64>,
    m: &Msgs,
) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base).map_err(|_| m.setup)?;
    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        let _ = cap_delete(ep);
        return Err(m.setup);
    };
    let result = upcall_body(ctx, &child, ep, slot, cpu, child_kind, flags, point, m);
    let reaped = reap(&mut child);
    let freed = cap_delete(ep).is_ok();
    result?;
    if reaped && freed
    {
        Ok(())
    }
    else
    {
        Err(m.teardown)
    }
}

/// Body of [`upcall_case`].
#[expect(
    clippy::too_many_arguments,
    reason = "the arguments of upcall_case, passed through"
)]
fn upcall_body(
    ctx: &TestContext,
    child: &spawn::SpawnedChild,
    ep: u64,
    slot: usize,
    cpu: u32,
    child_kind: ChildKind,
    flags: u64,
    point: Option<u64>,
    m: &Msgs,
) -> TestResult
{
    COUNT.store(0, Ordering::Release);
    crate::bind_fault_handler_classes(child.th, ep, BADGE_UP, FAULT_CLASS_UPCALL)
        .map_err(|_| m.setup)?;
    start(child, slot, child_kind.entry(), 0, cpu, m.setup)?;
    let cookie = 0x5150_0100 | u64::from(cpu);
    thread_post_upcall(child.th, cookie, flags).map_err(|_| m.post)?;
    receive_upcall(ctx, ep, cookie, point, m)?;
    let before = COUNT.load(Ordering::Acquire);
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| m.resume)?;
    if child_kind == ChildKind::SyscallLoop && !wait_count_above(before)
    {
        return Err(m.resume);
    }
    Ok(())
}

/// Receive the upcall message on `ep` and check it carries `cookie`, and
/// `point` when one is given.
///
/// `#[inline(never)]` keeps the received message's frame apart from the reply's
/// in [`upcall_body`], each a 576-byte message with its `Result` temporary.
#[inline(never)]
fn receive_upcall(
    ctx: &TestContext,
    ep: u64,
    cookie: u64,
    point: Option<u64>,
    m: &Msgs,
) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv_timeout(ep, ctx.ipc_buf, crate::scaled_bound(WAIT_MS)) }
        .map_err(|_| m.unseen)?;
    if msg.label != FAULT_LABEL
        || msg.badge != BADGE_UP
        || msg.word(0) != FAULT_KIND_UPCALL
        || msg.word(1) != cookie
        || point.is_some_and(|p| msg.word(2) != p)
    {
        return Err(m.wrong);
    }
    Ok(())
}

/// Case 1: a syscall-point upcall posted from CPU A reaches a child looping on
/// a syscall on CPU B.
fn upcall_syscall_remote(ctx: &TestContext) -> TestResult
{
    upcall_case(
        ctx,
        0,
        CPU_B,
        ChildKind::SyscallLoop,
        0,
        Some(UPCALL_POINT_SYSCALL),
        &Msgs {
            setup: "integration::return_work: upcall_syscall_remote: setup failed",
            post: "integration::return_work: upcall_syscall_remote: post was refused",
            unseen: "integration::return_work: upcall_syscall_remote: the upcall was not delivered \
                     to a child looping on a syscall on another CPU",
            wrong: "integration::return_work: upcall_syscall_remote: the upcall message or its \
                    point was wrong",
            resume: "integration::return_work: upcall_syscall_remote: the child did not run on \
                     after the handler's reply",
            teardown: "integration::return_work: upcall_syscall_remote: teardown failed",
        },
    )
}

/// Case 2: an any-instruction upcall posted from CPU A reaches a child
/// spinning in user mode on CPU B, at the interrupt point.
fn upcall_any_remote(ctx: &TestContext) -> TestResult
{
    upcall_case(
        ctx,
        1,
        CPU_B,
        ChildKind::Spin,
        UPCALL_ANY_INSTRUCTION,
        Some(UPCALL_POINT_INTERRUPT),
        &Msgs {
            setup: "integration::return_work: upcall_any_remote: setup failed",
            post: "integration::return_work: upcall_any_remote: post was refused",
            unseen: "integration::return_work: upcall_any_remote: the upcall was not delivered to \
                     a child spinning in user mode on another CPU",
            wrong: "integration::return_work: upcall_any_remote: the upcall message was wrong or \
                    not at the interrupt point",
            resume: "integration::return_work: upcall_any_remote: the handler's reply failed",
            teardown: "integration::return_work: upcall_any_remote: teardown failed",
        },
    )
}

/// Case 3: a syscall-point upcall posted to a child on CPU A that is not
/// running is delivered once the poster blocks.
fn upcall_syscall_local(ctx: &TestContext) -> TestResult
{
    upcall_case(
        ctx,
        2,
        CPU_A,
        ChildKind::SyscallLoop,
        0,
        Some(UPCALL_POINT_SYSCALL),
        &Msgs {
            setup: "integration::return_work: upcall_syscall_local: setup failed",
            post: "integration::return_work: upcall_syscall_local: post was refused",
            unseen: "integration::return_work: upcall_syscall_local: the upcall was not delivered \
                     once the poster blocked on the child's CPU",
            wrong: "integration::return_work: upcall_syscall_local: the upcall message or its \
                    point was wrong",
            resume: "integration::return_work: upcall_syscall_local: the child did not run on \
                     after the handler's reply",
            teardown: "integration::return_work: upcall_syscall_local: teardown failed",
        },
    )
}

/// Case 4: an any-instruction upcall posted to a spinning child on CPU A that
/// is not running is delivered once the poster blocks.
fn upcall_any_local(ctx: &TestContext) -> TestResult
{
    upcall_case(
        ctx,
        3,
        CPU_A,
        ChildKind::Spin,
        UPCALL_ANY_INSTRUCTION,
        None,
        &Msgs {
            setup: "integration::return_work: upcall_any_local: setup failed",
            post: "integration::return_work: upcall_any_local: post was refused",
            unseen: "integration::return_work: upcall_any_local: the upcall was not delivered \
                     once the poster blocked on the child's CPU",
            wrong: "integration::return_work: upcall_any_local: the upcall message was wrong",
            resume: "integration::return_work: upcall_any_local: the handler's reply failed",
            teardown: "integration::return_work: upcall_any_local: teardown failed",
        },
    )
}

/// Start a counting child on CPU B at `entry`, wait for it to count, delete its
/// only Thread capability, and check the capability is gone. Returns the
/// child's guard (its `CSpace` still held) after the delete.
fn start_and_delete(
    ctx: &TestContext,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    case: &'static str,
    msgs: [&'static str; 3],
) -> Result<spawn::SpawnedChild, &'static str>
{
    let [setup, never_ran, still_there] = msgs;
    let _ = case;
    COUNT.store(0, Ordering::Release);
    let mut child = spawn::new_child(ctx).map_err(|_| setup)?;
    let result = (|| {
        start(&child, slot, entry, 0, CPU_B, setup)?;
        if !wait_count_above(0)
        {
            return Err(never_ran);
        }
        let th = child.th;
        child.delete_thread().map_err(|_| setup)?;
        if spawn::is_exited(th).is_ok()
        {
            return Err(still_there);
        }
        Ok(())
    })();
    match result
    {
        Ok(()) => Ok(child),
        Err(e) =>
        {
            let _ = reap(&mut child);
            Err(e)
        }
    }
}

/// Case 5: after the delete of the only Thread capability of a child looping
/// on a syscall on CPU B returns, the child's counter never moves.
fn exit_remote_syscall_loop(ctx: &TestContext) -> TestResult
{
    let mut child = start_and_delete(
        ctx,
        4,
        syscall_loop_entry,
        "exit_remote_syscall_loop",
        [
            "integration::return_work: exit_remote_syscall_loop: setup failed",
            "integration::return_work: exit_remote_syscall_loop: the child never counted",
            "integration::return_work: exit_remote_syscall_loop: the thread capability was still \
             live after its delete",
        ],
    )?;
    let first = COUNT.load(Ordering::Acquire);
    let _ = thread_sleep(STILL_MS);
    let second = COUNT.load(Ordering::Acquire);
    let reaped = reap(&mut child);
    if first != second
    {
        return Err(
            "integration::return_work: exit_remote_syscall_loop: the child counted after \
                    its thread was deleted",
        );
    }
    if reaped
    {
        Ok(())
    }
    else
    {
        Err("integration::return_work: exit_remote_syscall_loop: teardown failed")
    }
}

/// Case 6: after the delete of the only Thread capability of a child spinning
/// in user mode on CPU B, its counter stops within a bounded interval.
fn exit_remote_spin(ctx: &TestContext) -> TestResult
{
    let mut child = start_and_delete(
        ctx,
        5,
        count_spin_entry,
        "exit_remote_spin",
        [
            "integration::return_work: exit_remote_spin: setup failed",
            "integration::return_work: exit_remote_spin: the child never counted",
            "integration::return_work: exit_remote_spin: the thread capability was still live \
             after its delete",
        ],
    )?;
    let outcome = (|| {
        let clock = "integration::return_work: exit_remote_spin: system_info(ElapsedUs) failed";
        let start = elapsed_us(clock)?;
        loop
        {
            let first = COUNT.load(Ordering::Acquire);
            let _ = thread_sleep(STILL_MS / 2);
            if COUNT.load(Ordering::Acquire) == first
            {
                return Ok(());
            }
            if elapsed_us(clock)?.saturating_sub(start) > crate::scaled_bound(STOP_DEADLINE_US)
            {
                return Err(
                    "integration::return_work: exit_remote_spin: the child still counted \
                            a second after its thread was deleted",
                );
            }
        }
    })();
    let reaped = reap(&mut child);
    outcome?;
    if reaped
    {
        Ok(())
    }
    else
    {
        Err("integration::return_work: exit_remote_spin: teardown failed")
    }
}

/// Case 9: a child on CPU B that deletes the last capability to its own
/// `CSpace` is stopped by the delete: its thread reads gone, and the code after
/// the delete never runs.
fn exit_local_self_teardown(ctx: &TestContext) -> TestResult
{
    let setup = "integration::return_work: exit_local_self_teardown: setup failed";
    SELF_BEFORE.store(0, Ordering::Release);
    SELF_AFTER.store(0, Ordering::Release);
    let mut child = spawn::new_child(ctx).map_err(|_| setup)?;
    let outcome = (|| {
        // The child's copy of its own CSpace becomes the CSpace's last
        // reference once the parent's capability is deleted.
        let own = cap_copy(child.cs, child.cs, RIGHTS_ALL).map_err(|_| setup)?;
        child.delete_cspace().map_err(|_| setup)?;
        start(&child, STACK_SELF, self_teardown_entry, own, CPU_B, setup)?;
        let mut seen = false;
        for _ in 0..crate::scaled_polls(PROGRESS_POLLS)
        {
            if SELF_BEFORE.load(Ordering::Acquire) != 0
            {
                seen = true;
                break;
            }
            let _ = thread_sleep(1);
        }
        if !seen
        {
            return Err(
                "integration::return_work: exit_local_self_teardown: the child never \
                        reached its delete",
            );
        }
        spawn::wait_until_exited(child.th, crate::scaled_polls(PROGRESS_POLLS)).map_err(|_| {
            "integration::return_work: exit_local_self_teardown: the thread was not torn down \
             by its delete of its own CSpace"
        })?;
        let _ = thread_sleep(STILL_MS);
        if SELF_AFTER.load(Ordering::Acquire) != 0
        {
            return Err(
                "integration::return_work: exit_local_self_teardown: the child returned \
                        to user mode from the delete that tore it down",
            );
        }
        Ok(())
    })();
    let reaped = reap(&mut child);
    outcome?;
    if reaped
    {
        Ok(())
    }
    else
    {
        Err("integration::return_work: exit_local_self_teardown: teardown failed")
    }
}

/// Case 7: the sole-reference post for an object whose other copy a child on
/// CPU B deletes arrives within the bound while CPU B never idles.
///
/// CPU B's own return path must be the only drain of the post: the case
/// thread polls the queue without blocking, so CPU A never idles, and one
/// spinner runs on every other CPU, so none idles; no idle CPU can pick the
/// work up.
fn sole_ref_remote_busy(ctx: &TestContext, cpus: u64) -> TestResult
{
    let eq = event_queue_create_observed(ctx.memory_base, 4, 1)
        .map_err(|_| "integration::return_work: sole_ref_remote_busy: queue creation failed")?;
    let mut spinners = [const { spawn::SpawnedChild::EMPTY }; SPINNER_SLOTS];
    let result = start_spinners(ctx, cpus, &mut spinners).and_then(|()| sole_ref_on(ctx, eq));
    let mut reaped = true;
    for spinner in &mut spinners
    {
        reaped &= reap(spinner);
    }
    let freed = cap_delete(eq).is_ok();
    result?;
    if freed && reaped
    {
        Ok(())
    }
    else
    {
        Err("integration::return_work: sole_ref_remote_busy: teardown failed")
    }
}

/// Start a spinner on each CPU other than CPUs A and B, up to
/// [`SPINNER_SLOTS`] of them, recording each in `spinners`.
fn start_spinners(
    ctx: &TestContext,
    cpus: u64,
    spinners: &mut [spawn::SpawnedChild; SPINNER_SLOTS],
) -> TestResult
{
    let setup = "integration::return_work: sole_ref_remote_busy: spinner setup failed";
    let others = (0..cpus)
        .filter_map(|c| u32::try_from(c).ok())
        .filter(|&c| c != CPU_A && c != CPU_B);
    for ((cpu, spinner), slot) in others.zip(spinners.iter_mut()).zip(SPINNER_BASE..)
    {
        *spinner = spawn::new_child(ctx).map_err(|_| setup)?;
        start(spinner, slot, spin_entry, 0, cpu, setup)?;
    }
    Ok(())
}

/// Body of [`sole_ref_remote_busy`] on the queue `eq`.
fn sole_ref_on(ctx: &TestContext, eq: u64) -> TestResult
{
    let setup = "integration::return_work: sole_ref_remote_busy: setup failed";
    let object = cap_create_notification(ctx.memory_base).map_err(|_| setup)?;
    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        let _ = cap_delete(object);
        return Err(setup);
    };
    let outcome = (|| {
        let copy = cap_copy(object, child.cs, RIGHTS_ALL).map_err(|_| setup)?;
        syscall::cap_bind_sole_reference(object, eq, CORRELATOR).map_err(|_| setup)?;
        start(
            &child,
            STACK_SOLE,
            delete_then_busy_entry,
            copy,
            CPU_B,
            setup,
        )?;
        let entry = poll_post(eq)?;
        if entry.payload != 0 || entry.tag != CORRELATOR
        {
            return Err("integration::return_work: sole_ref_remote_busy: the post was wrong");
        }
        Ok(())
    })();
    let reaped = reap(&mut child);
    let freed = cap_delete(object).is_ok();
    outcome?;
    if reaped && freed
    {
        Ok(())
    }
    else
    {
        Err("integration::return_work: sole_ref_remote_busy: teardown failed")
    }
}

/// Poll `eq` without blocking until an entry arrives, for at most the bound.
fn poll_post(eq: u64) -> Result<syscall::EventEntry, &'static str>
{
    let missing = "integration::return_work: sole_ref_remote_busy: no post arrived for the deleted \
                   copy while the remote CPU stayed busy";
    let clock = "integration::return_work: sole_ref_remote_busy: system_info(ElapsedUs) failed";
    let start = elapsed_us(clock)?;
    loop
    {
        match event_recv_entry(eq, TRY_ONCE)
        {
            Ok(entry) => return Ok(entry),
            Err(e) if e == SyscallError::WouldBlock as i64 =>
            {}
            Err(_) => return Err(missing),
        }
        if elapsed_us(clock)?.saturating_sub(start)
            > crate::scaled_bound(WAIT_MS).saturating_mul(1000)
        {
            return Err(missing);
        }
    }
}

/// Case 8: the `CSpace` objects that threads tearing themselves down queue on a
/// CPU that never idles are reclaimed, and memory returns to the baseline.
///
/// Each churn thread deletes the last capability to its own `CSpace` on CPU
/// B, which queues the `CSpace` on CPU B's deferred-reclaim stack; the
/// thread's own return schedules it away without draining, so the reclaim
/// falls to the next return of CPU B's busy thread, which loops on a syscall
/// and never lets CPU B idle.
fn reclaim_busy_cpu(ctx: &TestContext) -> TestResult
{
    let setup = "integration::return_work: reclaim_busy_cpu: setup failed";
    let mut busy = spawn::new_child(ctx).map_err(|_| setup)?;
    let outcome = reclaim_body(ctx, &busy);
    let reaped = reap(&mut busy);
    outcome?;
    if reaped
    {
        Ok(())
    }
    else
    {
        Err("integration::return_work: reclaim_busy_cpu: teardown failed")
    }
}

/// Start `child` on CPU B at [`self_teardown_entry`] with the last capability
/// to its own `CSpace`, and wait until it has exited.
fn churn_self_teardown(
    child: &mut spawn::SpawnedChild,
    setup: &'static str,
    exits: &'static str,
) -> TestResult
{
    let own = cap_copy(child.cs, child.cs, RIGHTS_ALL).map_err(|_| setup)?;
    child.delete_cspace().map_err(|_| setup)?;
    start(child, STACK_CHURN, self_teardown_entry, own, CPU_B, setup)?;
    spawn::wait_until_exited(child.th, crate::scaled_polls(PROGRESS_POLLS))
        .map(|_| ())
        .map_err(|_| exits)
}

/// Body of [`reclaim_busy_cpu`] with the busy child `busy`.
fn reclaim_body(ctx: &TestContext, busy: &spawn::SpawnedChild) -> TestResult
{
    let setup = "integration::return_work: reclaim_busy_cpu: setup failed";
    let exits = "integration::return_work: reclaim_busy_cpu: an exiting thread never exited";
    start(busy, STACK_BUSY, syscall_loop_entry, 0, CPU_B, setup)?;
    // The busy child's own objects are in the baseline.
    let baseline = cap_info(ctx.memory_base, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "integration::return_work: reclaim_busy_cpu: reading the baseline failed")?;
    for _ in 0..CHURN_THREADS
    {
        let mut child = spawn::new_child(ctx).map_err(|_| setup)?;
        let outcome = churn_self_teardown(&mut child, setup, exits);
        let reaped = reap(&mut child);
        outcome?;
        if !reaped
        {
            return Err("integration::return_work: reclaim_busy_cpu: teardown failed");
        }
    }
    spawn::wait_memory_baseline(
        ctx.memory_base,
        baseline,
        crate::scaled_polls(PROGRESS_POLLS),
    )
    .map_err(|_| {
        "integration::return_work: reclaim_busy_cpu: memory did not return to its baseline while \
         the CPU stayed busy"
    })
}
