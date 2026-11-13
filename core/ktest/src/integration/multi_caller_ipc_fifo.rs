// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/multi_caller_ipc_fifo.rs

//! Integration: endpoint send-queue FIFO ordering with three concurrent callers.
//!
//! Verifies that `ipc_recv` dequeues blocked callers in the order they arrived
//! on the send queue (FIFO), not priority order or any other order
//! (core/kernel/docs/ipc-internals.md, the endpoint's send queue).
//!
//! ## Approach
//!
//! The kernel orders the send queue by arrival, and it promises nothing about
//! when a started thread reaches its first syscall: a thread at a fair level
//! can be preempted at any tick before its `ipc_call` and requeued behind a
//! thread started after it (core/kernel/docs/scheduler.md § Time Slice
//! Policy). So the arrival order is fixed by strict priority, not by time.
//! Callers A (label 1), B (label 2) and C (label 3) are started in that order
//! at the strictly decreasing RT levels of [`CALLER_LEVELS`], all pinned to
//! [`CALLER_CPU`], and a barrier thread is started last below them on the same
//! CPU; its entry only exits. Each assertion rests on a kernel promise:
//!
//! - The arrival order is A, B, C: a CPU dispatches the highest non-empty run
//!   queue, and a slice expiry with no peer at the thread's level or above
//!   reselects the same thread (core/kernel/docs/scheduler.md § Scheduling
//!   Classes and § Timer-Driven Preemption). B, started after A at a lower
//!   level on A's CPU, runs only once A is not ready there, which is once A has
//!   blocked in `ipc_call`; C likewise after B.
//! - All three are on the send queue when the server first receives: the
//!   barrier, below all three, runs and exits only once none of them is ready
//!   on that CPU, and a caller that exits instead of calling is caught by its
//!   thread state (`CAP_INFO_THREAD_STATE`). The server waits for the
//!   barrier's exit under a `crate::scaled_polls` bound.
//! - The receive order is the arrival order, whatever the callers' levels: the
//!   server first moves the queued callers to the increasing levels of
//!   [`RECV_LEVELS`] (`SYS_THREAD_SET_PRIORITY`, core/kernel/docs/syscalls.md),
//!   so a queue ordered by priority would return C first, and a
//!   last-in-first-out one would too. The labels must come back 1, 2, 3.
//!
//! Each caller ORs a distinct bit into the shared `done` notification after receiving
//! its reply; the server waits for all three bits before returning.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait, thread_exit, thread_set_priority,
};
use syscall_abi::RIGHTS_EP_SEND_GRANT;

use crate::spawn::SpawnedChild;
use crate::{ChildStack, TestContext, TestResult, spawn};

/// CPU every caller and the barrier are pinned to, so strict priority on one
/// run queue orders their arrivals.
const CALLER_CPU: u32 = 0;

/// RT levels callers A, B, C are created at: strictly decreasing in start
/// order, so each runs only once the callers started before it have blocked.
/// All are below the harness thread's level (`PRIORITY_MAX`).
const CALLER_LEVELS: [u8; 3] = [24, 23, 22];

/// Level of the barrier thread: the lowest RT level, below every caller.
const BARRIER_LEVEL: u8 = 21;

/// Levels callers A, B, C are moved to once all three are queued: increasing,
/// the reverse of their arrival order.
const RECV_LEVELS: [u8; 3] = [22, 23, 24];

/// 1 ms polls the server waits, at most, for the barrier to exit (stretched
/// by `crate::scaled_polls`); a bound so a lost caller fails the test rather
/// than hanging it.
const BARRIER_POLLS: u32 = 10_000;

// One stack per child to avoid aliasing; entries 0, 1, 2 are callers A, B, C.
static mut CALLER_STACKS: [ChildStack; 3] = [ChildStack::ZERO, ChildStack::ZERO, ChildStack::ZERO];
static mut BARRIER_STACK: ChildStack = ChildStack::ZERO;

/// Per-caller arguments (slots in the caller's own `CSpace`), handed to
/// `caller_entry` by address; entries 0, 1, 2 are callers A, B, C.
#[derive(Clone, Copy)]
struct CallerArgs
{
    ep: u64,
    done: u64,
    label: u64,
}

static CALLER_ARGS: spawn::ArgBlock<CallerArgs, 3> = spawn::ArgBlock::new(CallerArgs {
    ep: 0,
    done: 0,
    label: 0,
});

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("multi_caller_ipc_fifo: starting");

    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "multi_caller_ipc_fifo: cap_create_endpoint failed")?;
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        return Err("multi_caller_ipc_fifo: cap_create_notification failed");
    };

    // The guards delete every child on every path, the callers first.
    let mut callers = [
        SpawnedChild::EMPTY,
        SpawnedChild::EMPTY,
        SpawnedChild::EMPTY,
    ];
    let mut barrier = SpawnedChild::EMPTY;
    let result = drive(ctx, ep, done, &mut callers, &mut barrier);
    drop(callers);
    drop(barrier);
    cap_delete(ep).ok();
    cap_delete(done).ok();
    result?;

    crate::log("multi_caller_ipc_fifo: PASS");
    Ok(())
}

/// Start the callers and the barrier into the guards, wait until all three
/// callers are queued, and check the receive order.
fn drive(
    ctx: &TestContext,
    ep: u64,
    done: u64,
    callers: &mut [SpawnedChild; 3],
    barrier: &mut SpawnedChild,
) -> TestResult
{
    for (index, caller) in callers.iter_mut().enumerate()
    {
        *caller = start_caller(ctx, index, ep, done)?;
    }
    *barrier = start_barrier(ctx)?;

    spawn::wait_until_exited(barrier.th, crate::scaled_polls(BARRIER_POLLS))
        .map_err(|_| "multi_caller_ipc_fifo: the barrier never ran below the callers")?;
    for caller in callers.iter()
    {
        if spawn::is_exited(caller.th)?
        {
            return Err("multi_caller_ipc_fifo: a caller exited before calling");
        }
    }
    for (caller, &level) in callers.iter().zip(&RECV_LEVELS)
    {
        thread_set_priority(caller.th, level, ctx.sched_control_cap)
            .map_err(|_| "multi_caller_ipc_fifo: re-level a queued caller failed")?;
    }

    let labels = receive_three(ctx, ep)?;
    if labels != [1, 2, 3]
    {
        return Err("FIFO violated: labels not received in arrival order 1, 2, 3");
    }

    // Wait for all three callers to confirm they received their reply.
    //
    // notification_wait returns as soon as ANY bits are set, not necessarily all three.
    // Accumulate via repeated waits until all three bits (0x7) arrive.
    let mut all_done = 0u64;
    while all_done != 0x7
    {
        let bits = notification_wait(done)
            .map_err(|_| "multi_caller_ipc_fifo: notification_wait done failed")?;
        all_done |= bits;
    }
    Ok(())
}

/// Receive and reply three times, logging and returning each label in the
/// order received.
fn receive_three(ctx: &TestContext, ep: u64) -> Result<[u64; 3], &'static str>
{
    let reply = IpcMessage::new(0);
    let mut labels = [0u64; 3];
    for label in &mut labels
    {
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
            .map_err(|_| "multi_caller_ipc_fifo: ipc_recv failed")?;
        *label = msg.label;
        crate::log_u64("multi_caller_ipc_fifo: received label=", msg.label);
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }
            .map_err(|_| "multi_caller_ipc_fifo: ipc_reply failed")?;
    }
    Ok(labels)
}

/// Create caller `index` (0, 1, 2 for A, B, C) at its `CALLER_LEVELS` level
/// with copies of `ep` and `done`, and start it pinned to `CALLER_CPU`.
fn start_caller(
    ctx: &TestContext,
    index: usize,
    ep: u64,
    done: u64,
) -> Result<SpawnedChild, &'static str>
{
    let level = *CALLER_LEVELS
        .get(index)
        .ok_or("multi_caller_ipc_fifo: caller index out of range")?;
    let child = spawn::new_child_at(ctx, ctx.sched_control_cap, level)
        .map_err(|_| "multi_caller_ipc_fifo: new_child_at caller failed")?;
    let ep_child = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "multi_caller_ipc_fifo: copy the endpoint failed")?;
    let done_child = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "multi_caller_ipc_fifo: copy the done notification failed")?;
    // Labels 1, 2, 3 for callers A, B, C.
    let label = (index as u64)
        .checked_add(1)
        .ok_or("multi_caller_ipc_fifo: caller index out of range")?;
    // SAFETY: entry `index` is this caller's alone, and it has not started.
    let arg = unsafe {
        CALLER_ARGS.publish(
            index,
            CallerArgs {
                ep: ep_child,
                done: done_child,
                label,
            },
        )
    };
    // SAFETY: `CALLER_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(CALLER_STACKS), index) }?;
    // SAFETY: the stack is this caller's own `ChildStack`, on which no other
    // live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(&child, caller_entry, stack, arg, CALLER_CPU) }
        .map_err(|_| "multi_caller_ipc_fifo: start a caller failed")?;
    Ok(child)
}

/// Create the barrier at `BARRIER_LEVEL` and start it pinned to `CALLER_CPU`.
fn start_barrier(ctx: &TestContext) -> Result<SpawnedChild, &'static str>
{
    let child = spawn::new_child_at(ctx, ctx.sched_control_cap, BARRIER_LEVEL)
        .map_err(|_| "multi_caller_ipc_fifo: new_child_at barrier failed")?;
    // SAFETY: `BARRIER_STACK` is a static stack, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top(core::ptr::addr_of!(BARRIER_STACK)) };
    // SAFETY: the stack is `BARRIER_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(&child, barrier_entry, stack, 0, CALLER_CPU) }
        .map_err(|_| "multi_caller_ipc_fifo: start the barrier failed")?;
    Ok(child)
}

// ── Child thread entries ──────────────────────────────────────────────────────

/// Barrier entry: exit at once. Its exit is the evidence that it ran, which
/// strict priority allows only once no caller is ready on its CPU.
extern "C" fn barrier_entry(_arg: u64) -> !
{
    thread_exit()
}

/// IPC pages of the three [`caller_entry`] children, one per caller label.
static mut CALLER_IPC_PAGES: [crate::IpcPage; 3] = [crate::IpcPage::ZERO; 3];

/// Caller entry: calls the endpoint immediately with its label, then ORs its
/// bit into the `done` notification when the reply arrives.
///
/// `arg`: address of the caller's [`CallerArgs`].
extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this caller.
    let CallerArgs {
        ep: ep_slot,
        done: done_slot,
        label,
    } = unsafe { spawn::child_args(arg) };

    let Some(bit_index) = label.checked_sub(1)
    else
    {
        thread_exit()
    };
    #[expect(clippy::cast_possible_truncation, reason = "`label` is 1, 2, or 3")]
    let page = bit_index as usize;
    let Ok(buf_addr) = crate::IpcPage::addr_at(core::ptr::addr_of_mut!(CALLER_IPC_PAGES), page)
    else
    {
        thread_exit()
    };
    // SAFETY: `CALLER_IPC_PAGES[page]` is this caller's own IPC page, used by one
    // thread at a time (`IpcPage`'s rule); no Rust object lives in it, and the
    // child reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        thread_exit()
    }

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    if unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(label), buf_addr as *mut u64) }.is_ok()
    {
        // OR the bit for this caller's label (label 1→bit0, 2→bit1, 3→bit2).
        let bit = 1u64 << bit_index;
        notification_send(done_slot, bit).ok();
    }
    /* else: no bit set — server detects the missing bit */
    thread_exit()
}
