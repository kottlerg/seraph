// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/ipc.rs

//! Synchronous IPC round-trip benchmark, in three message sizes and one case
//! that uses the vector registers.
//!
//! Each case spawns one child caller that loops `ipc_call`; the parent loops
//! `ipc_recv` / `ipc_reply`, the request and the reply carrying the case's
//! number of data words. Per-iteration bracketing on the parent side. The
//! cases, the variant `words=` of the `ipc_round_trip` line, are an empty
//! message, the largest message the message registers carry, and one word
//! more, which travels in the IPC buffer page (docs/ipc-design.md § Message
//! Format). ktest is soft-float, so none of these touches the FPU. The fourth
//! case, `words=0 fpu=both`, is the empty message with each side writing and
//! reading one vector register per round trip, as every std-built thread does
//! through its SIMD copies: the line without `fpu=` minus this one is the cost
//! of the FPU and vector state on the IPC path.

use bench::Value;
use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait, thread_exit,
};

use super::Harness;
use crate::{ChildStack, spawn};

/// The benchmark's name; each case's line carries its `words=`, and the case
/// that uses the vector registers its `fpu=both`.
const NAME: &str = "ipc_round_trip";

/// Whether the two sides of a case touch a vector register each round trip.
#[derive(Clone, Copy)]
enum Fpu
{
    /// Neither side does; the line carries no `fpu=`.
    None,
    /// Both sides do, once per round trip; the line carries `fpu=both`.
    Both,
}

/// One case: the data words of the request and the reply, and the FPU use.
#[derive(Clone, Copy)]
struct Case
{
    words: usize,
    fpu: Fpu,
}

/// The cases.
const CASES: [Case; 4] = [
    Case {
        words: 0,
        fpu: Fpu::None,
    },
    Case {
        words: REG_WORDS,
        fpu: Fpu::None,
    },
    Case {
        words: REG_WORDS + 1,
        fpu: Fpu::None,
    },
    Case {
        words: 0,
        fpu: Fpu::Both,
    },
];

/// The largest message the message registers carry. A literal, so the bench
/// builds unchanged at a head before `MSG_REGS_DATA_MAX` existed, for a
/// before-and-after comparison; the assertion keeps the two equal.
const REG_WORDS: usize = 6;
const _: () = assert!(REG_WORDS == syscall_abi::MSG_REGS_DATA_MAX);

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
    /// Whether the child touches a vector register before each call.
    fpu: Fpu,
}

static CALLER_ARGS: spawn::ArgBlock<CallerArgs, { CASES.len() }> =
    spawn::ArgBlock::new(CallerArgs {
        ep: 0,
        done: 0,
        n: 0,
        case: 0,
        words: 0,
        fpu: Fpu::None,
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
        fpu,
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

    for i in 0..n
    {
        touch_fpu(fpu, i);
        // SAFETY: buf_addr was registered as this thread's IPC buffer above.
        if unsafe { ipc::ipc_call(ep_slot, &msg, ipc_buf) }.is_err()
        {
            break;
        }
    }
    notification_send(done_slot, 1).ok();
    thread_exit()
}

/// Touch a vector register when the case asks for it.
fn touch_fpu(fpu: Fpu, value: u64)
{
    match fpu
    {
        Fpu::None =>
        {}
        Fpu::Both => crate::arch::fpu::touch_vector_register(value),
    }
}

/// A case's variant parameters as its line writes them, for a SKIP line.
struct Label(Case);

impl core::fmt::Display for Label
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self.0.fpu
        {
            Fpu::None => write!(f, "words={}", self.0.words),
            Fpu::Both => write!(f, "words={} fpu=both", self.0.words),
        }
    }
}

/// Run every case of [`CASES`] in turn. A case that does not complete every
/// round trip ends the benchmark: each later case logs a SKIP line.
pub(super) fn bench_ipc_round_trip(ctx: &crate::TestContext, h: &mut Harness)
{
    let mut failed = false;
    for (case, &c) in CASES.iter().enumerate()
    {
        if failed
        {
            h.skip(
                NAME,
                format_args!("{}: an earlier case did not complete", Label(c)),
            );
            continue;
        }
        failed = !bench_case(ctx, h, case, c);
    }
}

/// Run case `case` of [`CASES`], `c`. Returns whether every round trip
/// completed, which leaves its child on its way to exit, never parked in
/// `ipc_call`.
fn bench_case(ctx: &crate::TestContext, h: &mut Harness, case: usize, c: Case) -> bool
{
    let label = Label(c);
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        h.skip(NAME, format_args!("{label}: cap_create_endpoint failed"));
        return false;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        h.skip(
            NAME,
            format_args!("{label}: cap_create_notification failed"),
        );
        return false;
    };
    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        cap_delete(done).ok();
        cap_delete(ep).ok();
        h.skip(NAME, format_args!("{label}: new_child failed"));
        return false;
    };

    let completed = run_round_trips(ctx, ep, done, &child, h, case, c);

    // One cleanup path for every exit: deleting the child's Thread cap also
    // ends a child still parked in `ipc_call` after an early break.
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(done).ok();
    cap_delete(ep).ok();
    completed
}

/// Start case `case`'s caller child on `ep`, serve [`Harness::iters`] round
/// trips of `c.words` data words each way, touching a vector register before
/// each reply when `c.fpu` asks for it, and report the result. Returns
/// whether every round trip completed; returns `false` early, leaving cleanup
/// to the caller, when the child cannot be set up.
fn run_round_trips(
    ctx: &crate::TestContext,
    ep: u64,
    done: u64,
    child: &spawn::SpawnedChild,
    h: &mut Harness,
    case: usize,
    c: Case,
) -> bool
{
    use syscall_abi::RIGHTS_EP_SEND_GRANT;
    let label = Label(c);
    let n = u64::from(h.iters());

    let Ok(child_ep) = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
    else
    {
        h.skip(NAME, format_args!("{label}: cap_copy of endpoint failed"));
        return false;
    };
    let Ok(child_done) = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
    else
    {
        h.skip(
            NAME,
            format_args!("{label}: cap_copy of notification failed"),
        );
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
                words: c.words,
                fpu: c.fpu,
            },
        )
    };
    // SAFETY: `BENCH_IPC_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let Ok(stack_top) =
        (unsafe { ChildStack::top_at(core::ptr::addr_of!(BENCH_IPC_STACKS), case) })
    else
    {
        h.skip(NAME, format_args!("{label}: no child stack"));
        return false;
    };

    // SAFETY: the stack is entry `case` of `BENCH_IPC_STACKS`, this case's own
    // `ChildStack`, on which no other live thread runs (`ChildStack`'s rule).
    if unsafe { spawn::configure_and_start(child, ipc_caller_entry, stack_top, arg) }.is_err()
    {
        h.skip(NAME, format_args!("{label}: child start failed"));
        return false;
    }

    let reply = payload(0, c.words);
    let start = super::Placement::read(ctx.thread_cap, child.th);
    let (mut samples, counters) = h.recorder();
    let mut completed: u64 = 0;
    for i in 0..n
    {
        let t0 = counters.read();
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }.is_err()
        {
            break;
        }
        touch_fpu(c.fpu, i);
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }.is_err()
        {
            break;
        }
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
        completed = completed.saturating_add(1);
    }
    let summary = samples.summary();
    let end = super::Placement::read(ctx.thread_cap, child.th);

    // After every round trip the child's last call has returned and it is on
    // its way to `done`; after an early break it may be parked in `ipc_call`
    // for good, so the caller's Thread-cap delete ends it instead of a wait.
    if completed == n
    {
        notification_wait(done).ok();
    }

    let extras = super::placement_extras(start.as_ref(), end.as_ref());
    let extras = extras.as_ref().map_or(&[][..], |e| &e[..]);
    let words = ("words", Value::Num(c.words as u64));
    match c.fpu
    {
        Fpu::None => h.report(NAME, &[words], summary, extras),
        Fpu::Both => h.report(
            NAME,
            &[words, ("fpu", Value::Word("both"))],
            summary,
            extras,
        ),
    }
    completed == n
}
