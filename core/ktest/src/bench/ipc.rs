// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/ipc.rs

//! Synchronous IPC round-trip benchmarks.
//!
//! Each case spawns one child caller that loops `ipc_call`; the parent loops
//! `ipc_recv` / `ipc_reply`, the request and the reply carrying the case's
//! number of data words. Per-iteration bracketing on the parent side so
//! min/max/mean are meaningful. The cases are an empty message, the largest
//! message the message registers carry, and one word more, which travels in
//! the IPC buffer page (docs/ipc-design.md § Message Format).

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait, thread_exit,
};

use super::{cycles_now, log_bench_header};
use crate::{ChildStack, spawn};

/// The cases: the log name and the data words of the request and the reply.
const CASES: [(&str, usize); 3] = [
    ("ipc_round_trip", 0),
    ("ipc_round_trip_6w", REG_WORDS),
    ("ipc_round_trip_7w", REG_WORDS + 1),
];

/// The largest message the message registers carry.
const REG_WORDS: usize = 6;

/// One caller child's stack per case, so a case's child never shares a stack
/// with the previous case's, which may still be on its way to exit.
static mut BENCH_IPC_STACKS: [ChildStack; CASES.len()] = [ChildStack::ZERO; CASES.len()];

/// The caller child's arguments, handed to `ipc_caller_entry` by address.
#[derive(Clone, Copy)]
struct CallerArgs
{
    ep: u64,
    done: u64,
    n: u64,
    /// The case's index: its entry in `CALLER_ARGS` and its IPC page.
    case: usize,
    /// Data words of each request.
    words: usize,
}

static CALLER_ARGS: spawn::ArgBlock<CallerArgs, { CASES.len() }> =
    spawn::ArgBlock::new(CallerArgs {
        ep: 0,
        done: 0,
        n: 0,
        case: 0,
        words: 0,
    });

/// IPC pages of the [`ipc_caller_entry`] children, one per case.
static mut IPC_CALLER_IPC_PAGES: [crate::IpcPage; CASES.len()] =
    [crate::IpcPage::ZERO; CASES.len()];

/// The data words a request or reply of `words` words carries.
fn payload(label: u64, words: usize) -> IpcMessage
{
    let mut builder = IpcMessage::builder(label);
    for i in 0..words
    {
        builder = builder.word(i, 0x5EED_0000 | i as u64);
    }
    builder.build()
}

extern "C" fn ipc_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this child.
    let CallerArgs {
        ep: ep_slot,
        done: done_slot,
        n,
        case,
        words,
    } = unsafe { spawn::child_args(arg) };

    let Ok(buf_addr) = crate::IpcPage::addr_at(core::ptr::addr_of_mut!(IPC_CALLER_IPC_PAGES), case)
    else
    {
        notification_send(done_slot, 1).ok();
        thread_exit()
    };
    // SAFETY: entry `case` of `IPC_CALLER_IPC_PAGES` is this child's own IPC page, used by one
    // thread at a time (`IpcPage`'s rule); no Rust object lives in it, and the child reaches it
    // only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 1).ok();
        thread_exit()
    }
    let ipc_buf = buf_addr as *mut u64;
    let msg = payload(0, words);

    for _ in 0..n
    {
        // SAFETY: buf_addr was registered as this thread's IPC buffer above.
        if unsafe { ipc::ipc_call(ep_slot, &msg, ipc_buf) }.is_err()
        {
            break;
        }
    }
    notification_send(done_slot, 1).ok();
    thread_exit()
}

pub(super) fn bench_ipc_round_trip(ctx: &crate::TestContext, iters: u32)
{
    for (case, &(name, words)) in CASES.iter().enumerate()
    {
        if !bench_case(ctx, iters, case, name, words)
        {
            break;
        }
    }
}

/// Run one case of [`CASES`]. Returns whether every round trip completed,
/// which leaves its child on its way to exit, never parked in `ipc_call`.
fn bench_case(ctx: &crate::TestContext, iters: u32, case: usize, name: &str, words: usize) -> bool
{
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        return false;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        return false;
    };
    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        cap_delete(done).ok();
        cap_delete(ep).ok();
        return false;
    };

    let completed = run_round_trips(ctx, ep, done, &child, iters, case, name, words);

    // One cleanup path for every exit: deleting the child's Thread cap also
    // ends a child still parked in `ipc_call` after an early break.
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(done).ok();
    cap_delete(ep).ok();
    completed
}

/// Start case `case`'s caller child on `ep`, serve `iters` round trips of
/// `words` data words each way, and log the statistics under `name`.
/// Returns whether every round trip completed; returns `false` early,
/// leaving cleanup to the caller, when the child cannot be set up.
#[expect(
    clippy::too_many_arguments,
    reason = "one case's endpoint, notification, child, and its three case fields; a struct \
              for one private call site adds only names"
)]
fn run_round_trips(
    ctx: &crate::TestContext,
    ep: u64,
    done: u64,
    child: &spawn::SpawnedChild,
    iters: u32,
    case: usize,
    name: &str,
    words: usize,
) -> bool
{
    use syscall_abi::RIGHTS_EP_SEND_GRANT;
    let n = u64::from(iters);

    let Ok(child_ep) = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
    else
    {
        return false;
    };
    let Ok(child_done) = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
    else
    {
        return false;
    };

    // SAFETY: entry `case` belongs to this case's child alone, which has not
    // been started yet.
    let arg = unsafe {
        CALLER_ARGS.publish(
            case,
            CallerArgs {
                ep: child_ep,
                done: child_done,
                n,
                case,
                words,
            },
        )
    };
    // SAFETY: `BENCH_IPC_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let Ok(stack_top) =
        (unsafe { ChildStack::top_at(core::ptr::addr_of!(BENCH_IPC_STACKS), case) })
    else
    {
        return false;
    };

    // SAFETY: the stack is entry `case` of `BENCH_IPC_STACKS`, this case's own
    // `ChildStack`, on which no other live thread runs (`ChildStack`'s rule).
    if unsafe { spawn::configure_and_start(child, ipc_caller_entry, stack_top, arg) }.is_err()
    {
        return false;
    }

    let reply = payload(0, words);
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;
    let mut completed: u64 = 0;
    for _ in 0..n
    {
        let t0 = cycles_now();
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }.is_err()
        {
            break;
        }
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }.is_err()
        {
            break;
        }
        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
        completed = completed.saturating_add(1);
    }

    // After every round trip the child's last call has returned and it is on
    // its way to `done`; after an early break it may be parked in `ipc_call`
    // for good, so the caller's Thread-cap delete ends it instead of a wait.
    if completed == n
    {
        notification_wait(done).ok();
    }

    log_bench_header(name, iters);
    if let Some(mean) = total.checked_div(completed)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
    completed == n
}
