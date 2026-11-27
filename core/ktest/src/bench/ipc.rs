// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/ipc.rs

//! Synchronous IPC round-trip benchmark, in six message sizes and one case
//! that uses the vector registers.
//!
//! Each case spawns one child caller that loops `ipc_call`; the parent loops
//! `ipc_recv` / `ipc_reply`, the request and the reply carrying the case's
//! number of data words. Per-iteration bracketing on the parent side. The
//! cases, the variant `words=` of the `ipc_round_trip` line, are an empty
//! message, one word, the largest message the message registers carry, one
//! word more, which travels in the IPC buffer page (docs/ipc-design.md
//! § Message Format), 16 words, and the largest message, `MSG_DATA_WORDS_MAX`
//! words. ktest is soft-float, so none of these touches the FPU. The next
//! case, `words=0 fpu=both`, is the empty message with each side writing and
//! reading one vector register per round trip, as every std-built thread does
//! through its SIMD copies: the line without `fpu=` minus this one is the cost
//! of the FPU and vector state on the IPC path.
//!
//! The last case, `words=0 server=reply_recv`, is the empty message served by
//! `ipc_reply_recv`: each sample is one reply-and-receive, the reply to one call
//! and the receive of the next (core/kernel/docs/syscalls.md
//! § `SYS_IPC_REPLY_RECV`); the line without `server=` minus this one is what
//! the one syscall saves.
//!
//! Four more cases, variant `words=0 placement=`, measure where the kernel
//! runs a call's recipient (core/kernel/docs/scheduler.md § Thread
//! Assignment): the harness thread on CPU 0 calls a child server pinned to
//! CPU 0 (`same`), pinned to CPU 1 (`apart`), or started on CPU 1 and then
//! unpinned (`unpinned`), timing each call on its own side; and three callers
//! pinned to CPUs 1 to 3 call one unpinned server at once, each timing its own
//! calls on its own CPU (`fan_in`). They need two CPUs, `fan_in` four, and
//! log a SKIP line below that. Their servers loop `ipc_recv` and
//! `ipc_reply`; `unpinned` and `fan_in` run again with a server that loops
//! `ipc_reply_recv`, variant `server=reply_recv`, whose reply wake waits for
//! its receive's outcome (core/kernel/docs/scheduler.md § Thread Assignment).
//!
//! Two cases, variant `words=0 aspace=`, isolate the address-space switch:
//! the harness serves empty calls, timed as the `words=0` case times them,
//! from a caller pinned to CPU 0 beside it that runs the machine-code stub
//! `code_stub::syscall_repeat` in ktest's own address space (`same`) or in
//! one of its own (`cross`), so each round trip of `cross` switches address
//! space twice and the two lines differ by those switches alone. ktest's text
//! is not mapped in the caller's space, hence the stub.
//!
//! The case `words=0 iopb=none` (x86-64; it logs a SKIP line on riscv64)
//! runs the empty message between two children pinned to CPU 0, the caller
//! timing its own calls while the harness waits: no thread of a round trip
//! holds an I/O port binding, where the harness thread of every other case
//! holds ktest's, so the `words=0 placement=same` line minus this one is what
//! the I/O permission bitmap adds to a round trip
//! (core/kernel/docs/capability-internals.md § `IoPort` Bindings).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bench::Value;
use ipc::IpcMessage;
use syscall::{
    MAP_WRITABLE, cap_copy, cap_create_aspace, cap_create_cspace, cap_create_endpoint,
    cap_create_notification, cap_create_thread, cap_delete, mem_map, mem_unmap, notification_send,
    notification_wait, thread_exit,
};
use syscall_abi::{SYS_IPC_CALL, SYS_NOTIFICATION_SEND, SYS_THREAD_EXIT, ipc_call_count_arg};

use super::{CHILD_SAMPLES, Harness, MAX_SAMPLES};
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

/// How a server serves its calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Serve
{
    /// `ipc_recv`, then `ipc_reply`, per call; the line carries no `server=`.
    RecvReply,
    /// One `ipc_recv` first, then one `ipc_reply_recv` per call; the line
    /// carries `server=reply_recv`.
    ReplyRecv,
}

impl Serve
{
    /// The line's `server=` parameter, none for [`Serve::RecvReply`].
    const fn param(self) -> Option<(&'static str, Value<'static>)>
    {
        match self
        {
            Self::RecvReply => None,
            Self::ReplyRecv => Some(("server", Value::Word("reply_recv"))),
        }
    }

    /// The first slot of this way's placement children in [`PLACE_STACKS`],
    /// [`PLACE_IPC_PAGES`] and [`SERVER_ARGS`].
    const fn place_base(self) -> usize
    {
        match self
        {
            Self::RecvReply => 0,
            Self::ReplyRecv => PLACE_SET,
        }
    }

    /// The first entry of this way's `fan_in` callers in [`FAN_IN_ARGS`].
    const fn fan_in_base(self) -> usize
    {
        match self
        {
            Self::RecvReply => 0,
            Self::ReplyRecv => FAN_IN_CALLERS,
        }
    }
}

/// The SKIP-line suffix of a placement case served the way `serve` says.
const fn server_suffix(serve: Serve) -> &'static str
{
    match serve
    {
        Serve::RecvReply => "",
        Serve::ReplyRecv => " server=reply_recv",
    }
}

/// Serve calls on `ep` through the registered IPC buffer `ipc_buf` with an
/// empty reply, the way `serve` says, until a receive or a reply fails.
fn serve_calls(ep: u64, ipc_buf: *mut u64, serve: Serve)
{
    let reply = payload(0, 0);
    match serve
    {
        Serve::RecvReply => loop
        {
            // SAFETY: ipc_buf is this thread's registered IPC buffer.
            if unsafe { ipc::ipc_recv(ep, ipc_buf) }.is_err()
            {
                break;
            }
            // SAFETY: as for the receive.
            if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
            {
                break;
            }
        },
        Serve::ReplyRecv =>
        {
            // SAFETY: ipc_buf is this thread's registered IPC buffer.
            if unsafe { ipc::ipc_recv(ep, ipc_buf) }.is_err()
            {
                return;
            }
            // SAFETY: as for the receive.
            while unsafe { ipc::ipc_reply_recv(ep, &reply, ipc_buf, 0) }.is_ok()
            {}
        }
    }
}

/// One case: the data words of the request and the reply, the FPU use, and
/// how the harness serves.
#[derive(Clone, Copy)]
struct Case
{
    words: usize,
    fpu: Fpu,
    serve: Serve,
}

/// The cases.
const CASES: [Case; 8] = [
    EMPTY,
    Case {
        words: 1,
        fpu: Fpu::None,
        serve: Serve::RecvReply,
    },
    Case {
        words: REG_WORDS,
        fpu: Fpu::None,
        serve: Serve::RecvReply,
    },
    Case {
        words: REG_WORDS + 1,
        fpu: Fpu::None,
        serve: Serve::RecvReply,
    },
    Case {
        words: 16,
        fpu: Fpu::None,
        serve: Serve::RecvReply,
    },
    Case {
        words: syscall_abi::MSG_DATA_WORDS_MAX,
        fpu: Fpu::None,
        serve: Serve::RecvReply,
    },
    Case {
        words: 0,
        fpu: Fpu::Both,
        serve: Serve::RecvReply,
    },
    Case {
        words: 0,
        fpu: Fpu::None,
        serve: Serve::ReplyRecv,
    },
];

/// The largest message the message registers carry.
const REG_WORDS: usize = syscall_abi::MSG_REGS_DATA_MAX;

/// The empty message served by `ipc_recv` and `ipc_reply`: the first of
/// [`CASES`], and the timed loop of the `aspace=` cases.
const EMPTY: Case = Case {
    words: 0,
    fpu: Fpu::None,
    serve: Serve::RecvReply,
};

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
        write!(f, "words={}", self.0.words)?;
        if let Fpu::Both = self.0.fpu
        {
            write!(f, " fpu=both")?;
        }
        if let Serve::ReplyRecv = self.0.serve
        {
            write!(f, " server=reply_recv")?;
        }
        Ok(())
    }
}

/// Run every case of [`CASES`] in turn, then the placement cases. A case of
/// [`CASES`] that does not complete every round trip ends those cases: each
/// later one logs a SKIP line. Each placement case runs on its own endpoint
/// and children, so one that fails logs its own SKIP line and the next runs.
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
    for layout in [Layout::Same, Layout::Apart, Layout::Unpinned]
    {
        bench_placement(ctx, h, layout, Serve::RecvReply);
    }
    bench_fan_in(ctx, h, Serve::RecvReply);
    bench_placement(ctx, h, Layout::Unpinned, Serve::ReplyRecv);
    bench_fan_in(ctx, h, Serve::ReplyRecv);
    bench_aspace(ctx, h, Aspace::Same);
    bench_aspace(ctx, h, Aspace::Cross);
    bench_iopb_none(ctx, h);
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
/// each reply when `c.fpu` asks for it, and report the result. A
/// [`Serve::ReplyRecv`] case takes one untimed call first, then times each
/// reply-and-receive, and answers the last call untimed. Returns
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
    // The calls the child makes: one more for a reply-and-receive case, whose
    // first call is received untimed.
    let calls = match c.serve
    {
        Serve::RecvReply => n,
        Serve::ReplyRecv => n.saturating_add(1),
    };

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
                n: calls,
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

    let start = super::Placement::read(ctx.thread_cap, child.th);
    let (summary, completed) = match c.serve
    {
        Serve::RecvReply => serve_recv_reply(ctx, h, ep, c, n),
        Serve::ReplyRecv => serve_reply_recv(ctx, h, ep, c, n),
    };
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
    match (c.fpu, c.serve.param())
    {
        (Fpu::None, None) => h.report(NAME, &[words], summary, extras),
        (Fpu::None, Some(server)) => h.report(NAME, &[words, server], summary, extras),
        (Fpu::Both, None) => h.report(
            NAME,
            &[words, ("fpu", Value::Word("both"))],
            summary,
            extras,
        ),
        (Fpu::Both, Some(server)) => h.report(
            NAME,
            &[words, ("fpu", Value::Word("both")), server],
            summary,
            extras,
        ),
    }
    completed == n
}

/// The timed loop of a [`Serve::RecvReply`] case `c`: `n` round trips on
/// `ep`, each an `ipc_recv` and an `ipc_reply`, touching a vector register
/// between them when `c.fpu` asks for it. Returns their measurement and how
/// many completed.
#[inline(never)]
fn serve_recv_reply(
    ctx: &crate::TestContext,
    h: &mut Harness,
    ep: u64,
    c: Case,
    n: u64,
) -> (super::Measured, u64)
{
    let reply = payload(0, c.words);
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
    (samples.summary(), completed)
}

/// The timed loop of a [`Serve::ReplyRecv`] case `c`: an untimed
/// `ipc_recv` of the first call on `ep`, then `n` reply-and-receives, each
/// the reply to one call and the receive of the next, then an untimed
/// `ipc_reply` to the last. Returns their measurement and how many completed;
/// none when the last reply fails.
#[inline(never)]
fn serve_reply_recv(
    ctx: &crate::TestContext,
    h: &mut Harness,
    ep: u64,
    c: Case,
    n: u64,
) -> (super::Measured, u64)
{
    let reply = payload(0, c.words);
    let (mut samples, counters) = h.recorder();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    if unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }.is_err()
    {
        return (samples.summary(), 0);
    }
    let mut completed: u64 = 0;
    for _ in 0..n
    {
        let t0 = counters.read();
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_reply_recv(ep, &reply, ctx.ipc_buf, 0) }.is_err()
        {
            break;
        }
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
        completed = completed.saturating_add(1);
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    if completed == n && unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }.is_err()
    {
        completed = 0;
    }
    (samples.summary(), completed)
}

// ── Placement cases ───────────────────────────────────────────────────────────

/// Where a 1:1 placement case's server child runs; its `placement=` word.
#[derive(Clone, Copy)]
enum Layout
{
    /// Pinned to CPU 0, the harness's CPU: `same`.
    Same,
    /// Pinned to CPU 1: `apart`.
    Apart,
    /// Started on CPU 1 and unpinned after its first round trip, so the
    /// kernel's wake placement decides where it runs: `unpinned`.
    Unpinned,
}

impl Layout
{
    /// The `placement=` word.
    const fn word(self) -> &'static str
    {
        match self
        {
            Self::Same => "same",
            Self::Apart => "apart",
            Self::Unpinned => "unpinned",
        }
    }

    /// The CPU the server starts pinned to.
    const fn start_cpu(self) -> u32
    {
        match self
        {
            Self::Same => 0,
            Self::Apart | Self::Unpinned => 1,
        }
    }

    /// The child's slot in [`PLACE_STACKS`], [`PLACE_IPC_PAGES`] and
    /// [`SERVER_ARGS`], after its way of serving's [`Serve::place_base`].
    const fn slot(self) -> usize
    {
        match self
        {
            Self::Same => 0,
            Self::Apart => 1,
            Self::Unpinned => 2,
        }
    }
}

/// The `fan_in` case's callers, pinned to CPUs 1 to `FAN_IN_CALLERS`.
const FAN_IN_CALLERS: usize = 3;

/// The `fan_in` server's slot; its callers take the slots after it.
const FAN_IN_SERVER: usize = 3;

/// The placement children of one way of serving: a server per 1:1 case, then
/// the `fan_in` server and its callers.
const PLACE_SET: usize = FAN_IN_SERVER + 1 + FAN_IN_CALLERS;

/// The slot of the `iopb=none` case's server.
const IOPB_SERVER: usize = 2 * PLACE_SET;

/// The slot of the `iopb=none` case's caller.
const IOPB_CALLER: usize = IOPB_SERVER + 1;

/// The placement cases' children, one set per way of serving, and the
/// `iopb=none` case's two.
const PLACE_CHILDREN: usize = IOPB_SERVER + 2;

/// The `SYS_THREAD_SET_AFFINITY` argument that clears a thread's hard
/// affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// One stack per placement child, so no case's child shares a stack with an
/// earlier case's, which may still be on its way to exit.
static mut PLACE_STACKS: [ChildStack; PLACE_CHILDREN] = [ChildStack::ZERO; PLACE_CHILDREN];

/// IPC pages of the placement children, one per child.
static mut PLACE_IPC_PAGES: [crate::IpcPage; PLACE_CHILDREN] =
    [crate::IpcPage::ZERO; PLACE_CHILDREN];

/// A server child's arguments, handed to `ipc_server_entry` by address.
#[derive(Clone, Copy)]
struct ServerArgs
{
    ep: u64,
    /// The child's slot: its IPC page.
    slot: usize,
    serve: Serve,
}

static SERVER_ARGS: spawn::ArgBlock<ServerArgs, PLACE_CHILDREN> =
    spawn::ArgBlock::new(ServerArgs {
        ep: 0,
        slot: 0,
        serve: Serve::RecvReply,
    });

/// The IPC buffer of placement child `slot`, registered for the calling
/// thread; `None` when it cannot be.
fn register_place_page(slot: usize) -> Option<*mut u64>
{
    let buf_addr = crate::IpcPage::addr_at(core::ptr::addr_of_mut!(PLACE_IPC_PAGES), slot).ok()?;
    // SAFETY: entry `slot` of `PLACE_IPC_PAGES` is this child's own IPC page, used by one thread
    // at a time (`IpcPage`'s rule); no Rust object lives in it, and the child reaches it only
    // through the raw pointer returned.
    unsafe { syscall::ipc_buffer_set(buf_addr) }.ok()?;
    Some(buf_addr as *mut u64)
}

/// A server child: serve calls with an empty reply the way its arguments say
/// until a receive or a reply fails. Its case deletes it, parked in its
/// receive.
extern "C" fn ipc_server_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this child.
    let ServerArgs { ep, slot, serve } = unsafe { spawn::child_args(arg) };
    if let Some(ipc_buf) = register_place_page(slot)
    {
        serve_calls(ep, ipc_buf, serve);
    }
    thread_exit()
}

/// Start a server child on `ep` in `slot` that serves the way `serve` says,
/// pinned to `cpu` when it is `Some`; the error names the step that failed.
fn start_server(
    ctx: &crate::TestContext,
    ep: u64,
    (slot, serve): (usize, Serve),
    cpu: Option<u32>,
) -> Result<spawn::SpawnedChild, &'static str>
{
    let child = spawn::new_child(ctx).map_err(|_| "new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, syscall_abi::RIGHTS_EP_RECEIVE)
        .map_err(|_| "cap_copy of endpoint failed")?;
    // SAFETY: entry `slot` belongs to this child alone, which has not been started yet.
    let arg = unsafe {
        SERVER_ARGS.publish(
            slot,
            ServerArgs {
                ep: child_ep,
                slot,
                serve,
            },
        )
    };
    // SAFETY: `PLACE_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top_at(core::ptr::addr_of!(PLACE_STACKS), slot) }
        .map_err(|_| "no child stack")?;
    let started = if let Some(cpu) = cpu
    {
        // SAFETY: the stack is entry `slot` of `PLACE_STACKS`, this child's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start_pinned(&child, ipc_server_entry, stack_top, arg, cpu) }
    }
    else
    {
        // SAFETY: as for the pinned start.
        unsafe { spawn::configure_and_start(&child, ipc_server_entry, stack_top, arg) }
    };
    started.map_err(|_| "child start failed")?;
    Ok(child)
}

/// Run the 1:1 placement case `layout` with a server that serves the way
/// `serve` says: the harness thread, on CPU 0, calls a server child
/// [`Harness::iters`] times with an empty message, timing each call, after
/// one untimed call that the server takes on its start CPU.
fn bench_placement(ctx: &crate::TestContext, h: &mut Harness, layout: Layout, serve: Serve)
{
    let word = layout.word();
    let server_word = server_suffix(serve);
    if h.cpus < 2
    {
        h.skip(
            NAME,
            format_args!("words=0 placement={word}{server_word}: one CPU"),
        );
        return;
    }
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        h.skip(
            NAME,
            format_args!("words=0 placement={word}{server_word}: cap_create_endpoint failed"),
        );
        return;
    };
    let slot = serve.place_base().saturating_add(layout.slot());
    match start_server(ctx, ep, (slot, serve), Some(layout.start_cpu()))
    {
        Ok(mut server) =>
        {
            if let Err(e) = time_calls(ctx, h, ep, &server, (layout, serve))
            {
                h.skip(
                    NAME,
                    format_args!("words=0 placement={word}{server_word}: {e}"),
                );
            }
            // The server is parked in its receive; deleting its Thread cap ends it.
            server.delete_thread().ok();
            server.delete_cspace().ok();
        }
        Err(e) => h.skip(
            NAME,
            format_args!("words=0 placement={word}{server_word}: {e}"),
        ),
    }
    cap_delete(ep).ok();
}

/// The measured part of [`bench_placement`]: the untimed call, the unpin of
/// an `unpinned` server, the timed calls and the report.
fn time_calls(
    ctx: &crate::TestContext,
    h: &mut Harness,
    ep: u64,
    server: &spawn::SpawnedChild,
    (layout, serve): (Layout, Serve),
) -> Result<(), &'static str>
{
    warm_up(ctx, ep, server, layout)?;
    let msg = payload(0, 0);
    let n = h.iters();
    let start = super::Placement::read(ctx.thread_cap, server.th);
    let (mut samples, counters) = h.recorder();
    for _ in 0..n
    {
        let t0 = counters.read();
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_call(ep, &msg, ctx.ipc_buf) }.is_err()
        {
            return Err("a call failed");
        }
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
    }
    let summary = samples.summary();
    let end = super::Placement::read(ctx.thread_cap, server.th);
    let extras = super::placement_extras(start.as_ref(), end.as_ref());
    let extras = extras.as_ref().map_or(&[][..], |e| &e[..]);
    let words = ("words", Value::Num(0));
    let placement = ("placement", Value::Word(layout.word()));
    match serve.param()
    {
        None => h.report(NAME, &[words, placement], summary, extras),
        Some(server) => h.report(NAME, &[words, placement, server], summary, extras),
    }
    Ok(())
}

/// The untimed first call of a 1:1 placement case, which its server takes on
/// its start CPU, then the unpin of an `unpinned` server.
#[inline(never)]
fn warm_up(
    ctx: &crate::TestContext,
    ep: u64,
    server: &spawn::SpawnedChild,
    layout: Layout,
) -> Result<(), &'static str>
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_call(ep, &payload(0, 0), ctx.ipc_buf) }.map_err(|_| "first call failed")?;
    if matches!(layout, Layout::Unpinned)
    {
        syscall::thread_set_affinity(server.th, AFFINITY_ANY).map_err(|_| "unpin failed")?;
    }
    Ok(())
}

/// A `fan_in` caller's arguments, handed to `fan_in_caller_entry` by
/// address.
#[derive(Clone, Copy)]
struct FanInArgs
{
    ep: u64,
    ready: u64,
    done: u64,
    /// The caller's index: its notification bit and its count in
    /// [`FAN_IN_COMPLETED`].
    index: usize,
    /// The caller's slot in [`PLACE_STACKS`] and [`PLACE_IPC_PAGES`].
    slot: usize,
    /// Calls this caller makes, and the length of its sample stripe.
    iters: usize,
}

/// The callers' arguments, one set per way of serving.
static FAN_IN_ARGS: spawn::ArgBlock<FanInArgs, { 2 * FAN_IN_CALLERS }> =
    spawn::ArgBlock::new(FanInArgs {
        ep: 0,
        ready: 0,
        done: 0,
        index: 0,
        slot: 0,
        iters: 0,
    });

/// Release barrier: the callers wait here after their ready bit, so their
/// calls overlap.
static FAN_IN_GO: AtomicBool = AtomicBool::new(false);

/// Calls each caller completed, its sample stored in its stripe of
/// [`CHILD_SAMPLES`], caller `i`'s from `i * iters`.
///
/// Relaxed is sufficient for the samples and this count: the harness reads
/// them only for a caller whose `done` bit arrived, and the
/// `notification_send`/`notification_wait` pair orders them before the read.
static FAN_IN_COMPLETED: [AtomicU64; FAN_IN_CALLERS] =
    [const { AtomicU64::new(0) }; FAN_IN_CALLERS];

/// A `fan_in` caller: pinned to its CPU from its start, so its counters are
/// that CPU's; signals ready, waits for [`FAN_IN_GO`], times each of its
/// calls into its stripe, and signals done.
extern "C" fn fan_in_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this caller.
    let FanInArgs {
        ep,
        ready,
        done,
        index,
        slot,
        iters,
    } = unsafe { spawn::child_args(arg) };
    let bit = 1u64 << index;
    let counters = ::bench::Counters::open();
    let Some(ipc_buf) = register_place_page(slot)
    else
    {
        notification_send(ready, bit).ok();
        notification_send(done, bit).ok();
        thread_exit()
    };
    notification_send(ready, bit).ok();
    while !FAN_IN_GO.load(Ordering::Acquire)
    {
        let _ = syscall::thread_yield();
    }
    let msg = payload(0, 0);
    let stripe = index.saturating_mul(iters);
    for j in 0..iters
    {
        let t0 = counters.read();
        // SAFETY: ipc_buf was registered as this thread's IPC buffer above.
        if unsafe { ipc::ipc_call(ep, &msg, ipc_buf) }.is_err()
        {
            break;
        }
        let t1 = counters.read();
        if let (Some(sample), Some(completed)) = (
            CHILD_SAMPLES.get(stripe.saturating_add(j)),
            FAN_IN_COMPLETED.get(index),
        )
        {
            sample.store(t1.since(&t0).cycles, Ordering::Relaxed);
            completed.store(j.saturating_add(1) as u64, Ordering::Relaxed);
        }
    }
    notification_send(done, bit).ok();
    thread_exit()
}

/// Run the `fan_in` case: [`FAN_IN_CALLERS`] callers pinned to CPUs 1 and up
/// call one unpinned server child, which serves the way `serve` says, at
/// once, sharing [`Harness::iters`] calls.
fn bench_fan_in(ctx: &crate::TestContext, h: &mut Harness, serve: Serve)
{
    let suffix = server_suffix(serve);
    if (h.cpus as usize) <= FAN_IN_CALLERS
    {
        h.skip(
            NAME,
            format_args!("words=0 placement=fan_in{suffix}: needs 4 CPUs"),
        );
        return;
    }
    FAN_IN_GO.store(false, Ordering::Relaxed);
    for completed in &FAN_IN_COMPLETED
    {
        completed.store(0, Ordering::Relaxed);
    }
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        h.skip(
            NAME,
            format_args!("words=0 placement=fan_in{suffix}: cap_create_endpoint failed"),
        );
        return;
    };
    let Ok(ready) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        h.skip(
            NAME,
            format_args!("words=0 placement=fan_in{suffix}: cap_create_notification failed"),
        );
        return;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ready).ok();
        cap_delete(ep).ok();
        h.skip(
            NAME,
            format_args!("words=0 placement=fan_in{suffix}: cap_create_notification failed"),
        );
        return;
    };
    let mut callers = [const { spawn::SpawnedChild::EMPTY }; FAN_IN_CALLERS];
    let server_slot = serve.place_base().saturating_add(FAN_IN_SERVER);
    match start_server(ctx, ep, (server_slot, serve), None)
    {
        Ok(mut server) =>
        {
            if let Err(e) = fan_in_rounds(ctx, h, (ep, serve), [ready, done], &server, &mut callers)
            {
                h.skip(NAME, format_args!("words=0 placement=fan_in{suffix}: {e}"));
            }
            server.delete_thread().ok();
            server.delete_cspace().ok();
        }
        Err(e) => h.skip(NAME, format_args!("words=0 placement=fan_in{suffix}: {e}")),
    }
    for caller in &mut callers
    {
        caller.delete_thread().ok();
        caller.delete_cspace().ok();
    }
    cap_delete(done).ok();
    cap_delete(ready).ok();
    cap_delete(ep).ok();
}

/// Start the `fan_in` callers into `callers`, release them together, wait
/// for each to finish, and report their samples with the server's CPU at the
/// end and the number of callers.
fn fan_in_rounds(
    ctx: &crate::TestContext,
    h: &mut Harness,
    (ep, serve): (u64, Serve),
    [ready, done]: [u64; 2],
    server: &spawn::SpawnedChild,
    callers: &mut [spawn::SpawnedChild; FAN_IN_CALLERS],
) -> Result<(), &'static str>
{
    let per_caller = (h.iters() as usize)
        .div_ceil(FAN_IN_CALLERS)
        .min(MAX_SAMPLES / FAN_IN_CALLERS);
    for (index, slot) in callers.iter_mut().enumerate()
    {
        *slot = start_fan_in_caller(ctx, (ep, serve), [ready, done], index, per_caller)?;
    }
    let all = (1u64 << FAN_IN_CALLERS) - 1;
    let mut arrived = 0u64;
    crate::tally::await_all(ready, &mut arrived, all, "a caller never reported ready")?;
    FAN_IN_GO.store(true, Ordering::Release);
    let mut reported = 0u64;
    crate::tally::await_all(done, &mut reported, all, "a caller never reported done")?;
    let server_cpu =
        syscall::cap_info_thread_placement(server.th, syscall_abi::THREAD_PLACEMENT_CPU)
            .map_err(|_| "server placement read failed")?;

    let mut recorder = ::bench::Samples::new(h.buffer());
    for (index, completed) in FAN_IN_COMPLETED.iter().enumerate()
    {
        let count = usize::try_from(completed.load(Ordering::Relaxed))
            .unwrap_or(0)
            .min(per_caller);
        let stripe = CHILD_SAMPLES
            .iter()
            .skip(index.saturating_mul(per_caller))
            .take(count);
        for sample in stripe
        {
            recorder.record(sample.load(Ordering::Relaxed));
        }
    }
    let measured = super::Measured::of_other_cpus(recorder.summary());
    let words = ("words", Value::Num(0));
    let placement = ("placement", Value::Word("fan_in"));
    let extras = [
        ("callers", FAN_IN_CALLERS as u64),
        ("server_cpu", server_cpu),
    ];
    match serve.param()
    {
        None => h.report(NAME, &[words, placement], measured, &extras),
        Some(server) => h.report(NAME, &[words, placement, server], measured, &extras),
    }
    Ok(())
}

/// Start `fan_in` caller `index` of the case served the way `serve` says,
/// pinned to CPU `index + 1`, to make `iters` calls on `ep`.
fn start_fan_in_caller(
    ctx: &crate::TestContext,
    (ep, serve): (u64, Serve),
    [ready, done]: [u64; 2],
    index: usize,
    iters: usize,
) -> Result<spawn::SpawnedChild, &'static str>
{
    let child = spawn::new_child(ctx).map_err(|_| "new_child failed")?;
    let child_ep =
        cap_copy(ep, child.cs, syscall_abi::RIGHTS_EP_SEND).map_err(|_| "cap_copy failed")?;
    let child_ready =
        cap_copy(ready, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY).map_err(|_| "cap_copy failed")?;
    let child_done =
        cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY).map_err(|_| "cap_copy failed")?;
    let slot = serve
        .place_base()
        .saturating_add(FAN_IN_SERVER)
        .saturating_add(1)
        .saturating_add(index);
    let cpu = u32::try_from(index.saturating_add(1)).map_err(|_| "caller CPU past u32")?;
    // SAFETY: entry `fan_in_base() + index` belongs to this caller alone, which
    // has not been started yet.
    let arg = unsafe {
        FAN_IN_ARGS.publish(
            serve.fan_in_base().saturating_add(index),
            FanInArgs {
                ep: child_ep,
                ready: child_ready,
                done: child_done,
                index,
                slot,
                iters,
            },
        )
    };
    // SAFETY: `PLACE_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top_at(core::ptr::addr_of!(PLACE_STACKS), slot) }
        .map_err(|_| "no child stack")?;
    // SAFETY: the stack is entry `slot` of `PLACE_STACKS`, this caller's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(&child, fan_in_caller_entry, stack_top, arg, cpu) }
        .map_err(|_| "child start failed")?;
    Ok(child)
}

// ── Address-space cases ───────────────────────────────────────────────────────

/// Where an `aspace=` case's caller runs; its `aspace=` word.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Aspace
{
    /// ktest's own address space: `same`.
    Same,
    /// An address space of its own: `cross`.
    Cross,
}

impl Aspace
{
    /// The `aspace=` word.
    const fn word(self) -> &'static str
    {
        match self
        {
            Self::Same => "same",
            Self::Cross => "cross",
        }
    }
}

/// VA of the call-loop stub: a scratch VA of ktest's own space for `same`
/// (crate docs § Scratch VAs), and the same VA in the caller's space for
/// `cross`.
const STUB_VA: u64 = 0x3E_5800_0000;
/// VA of the caller's program, a scratch VA of ktest's own space, mapped at the
/// same VA in the caller's space for `cross`.
const PROGRAM_VA: u64 = 0x3E_5810_0000;
/// The stub caller's stack pointer; the stub touches no stack.
const STUB_STACK: u64 = STUB_VA + 0x800;

/// Words of one record of the caller's program (`code_stub::syscall_repeat`):
/// the number, six arguments, and the repeat count.
const RECORD_WORDS: usize = 8;
/// The word of a record that holds its repeat count, and after the run the
/// calls not completed.
const REPEAT_WORD: usize = 7;

/// The stub caller of an `aspace=` case and the pages it runs on. Drop
/// deletes every cap and returns each frame to the pool once no mapping of it
/// is left; a zero cap or frame holds none.
#[derive(Default)]
struct StubCaller
{
    /// ktest's own space, from which drop removes the scratch mappings.
    host: u64,
    /// Whether the stub is mapped in ktest's own space (`same`).
    same: bool,
    /// The caller's own space for `cross`; 0 for `same`.
    aspace: u64,
    cspace: u64,
    thread: u64,
    /// The stub's frame.
    stub: u64,
    /// The program's frame, and whether it is mapped in ktest's own space.
    program: u64,
    program_in_host: bool,
}

impl StubCaller
{
    /// Create the caller's thread, not configured, in `space`, with the stub
    /// mapped executable at [`STUB_VA`] and the program's frame writable at
    /// [`PROGRAM_VA`], in ktest's own space and, for `cross`, in the
    /// caller's.
    fn new(ctx: &crate::TestContext, space: Aspace) -> Result<Self, &'static str>
    {
        let mut c = Self {
            host: ctx.aspace_cap,
            same: space == Aspace::Same,
            ..Self::default()
        };
        if space == Aspace::Cross
        {
            c.aspace =
                cap_create_aspace(ctx.memory_base, 0, 8).map_err(|_| "cap_create_aspace failed")?;
        }
        let target = if c.same { ctx.aspace_cap } else { c.aspace };
        c.cspace =
            cap_create_cspace(ctx.memory_base, 0, 4).map_err(|_| "cap_create_cspace failed")?;
        c.stub = spawn::install_stub(
            ctx,
            target,
            STUB_VA,
            &crate::arch::code_stub::syscall_repeat(),
        )?;
        let frame = crate::frame_pool::alloc().ok_or("frame_pool::alloc returned None")?;
        // SAFETY: `PROGRAM_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe { mem_map(frame, ctx.aspace_cap, PROGRAM_VA, 0, 1, MAP_WRITABLE) }.is_err()
        {
            // SAFETY: `frame` came from `alloc` and the failed map left it
            // mapped nowhere.
            unsafe { crate::frame_pool::free(frame) };
            return Err("program mem_map failed");
        }
        c.program = frame;
        c.program_in_host = true;
        if !c.same
        {
            // SAFETY: `c.aspace` is a space this case created, not ktest's own,
            // so the mapping changes nothing ktest runs on.
            unsafe { mem_map(frame, c.aspace, PROGRAM_VA, 0, 1, MAP_WRITABLE) }
                .map_err(|_| "caller's program mem_map failed")?;
        }
        c.thread = cap_create_thread(ctx.memory_base, target, c.cspace, 0, 0)
            .map_err(|_| "cap_create_thread failed")?;
        Ok(c)
    }

    /// The word `word` of record `record` of the program.
    fn word(record: usize, word: usize) -> *mut u64
    {
        (PROGRAM_VA as *mut u64)
            .wrapping_add(record.saturating_mul(RECORD_WORDS).saturating_add(word))
    }

    /// Write the program: `calls` empty calls on `ep`, then a signal of
    /// `done`, the thread's exit, and the terminator; each handle is the
    /// caller's.
    fn write_program(ep: u64, done: u64, calls: u64)
    {
        let records: [[u64; RECORD_WORDS]; 4] = [
            [
                SYS_IPC_CALL,
                ep,
                0,
                ipc_call_count_arg(0, 0),
                0,
                0,
                0,
                calls,
            ],
            [SYS_NOTIFICATION_SEND, done, 1, 0, 0, 0, 0, 1],
            [SYS_THREAD_EXIT, 0, 0, 0, 0, 0, 0, 1],
            [u64::MAX, 0, 0, 0, 0, 0, 0, 0],
        ];
        for (r, record) in records.iter().enumerate()
        {
            for (w, &value) in record.iter().enumerate()
            {
                // SAFETY: the four records are 256 bytes of the page mapped
                // writable at `PROGRAM_VA` in ktest's own space (`new`), which
                // no Rust reference reaches; the caller has not started.
                unsafe { Self::word(r, w).write_volatile(value) };
            }
        }
    }

    /// The calls of the program's first record not completed.
    fn calls_left() -> u64
    {
        // SAFETY: as for `write_program`; the caller has signalled `done`,
        // after its last store to the record.
        unsafe { Self::word(0, REPEAT_WORD).read_volatile() }
    }

    /// Start the caller pinned to CPU 0, the stub entered with the
    /// program's VA.
    fn start(&self) -> Result<(), &'static str>
    {
        // SAFETY: the thread runs the stub, which touches no stack and no
        // memory but its program's page: for `cross` in a space this case
        // created; for `same` at scratch VAs of ktest's own space, where no
        // Rust object lives and no other thread runs.
        unsafe { syscall::thread_configure(self.thread, STUB_VA, STUB_STACK, PROGRAM_VA) }
            .map_err(|_| "thread_configure failed")?;
        syscall::thread_set_affinity(self.thread, 0).map_err(|_| "thread_set_affinity failed")?;
        syscall::thread_start(self.thread).map_err(|_| "thread_start failed")
    }
}

impl Drop for StubCaller
{
    fn drop(&mut self)
    {
        for cap in [self.thread, self.cspace]
        {
            if cap != 0
            {
                cap_delete(cap).ok();
            }
        }
        let space_gone = self.aspace == 0 || cap_delete(self.aspace).is_ok();
        let unmap_host = |va: u64| {
            // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the
            // span holds no Rust object or IPC page of ktest.
            unsafe { mem_unmap(self.host, va, 1) }.is_ok()
        };
        let stub_free = !self.same || unmap_host(STUB_VA);
        let program_free = !self.program_in_host || unmap_host(PROGRAM_VA);
        // A frame still mapped somewhere stays out of the pool, which takes
        // only unmapped frames.
        for (frame, free) in [(self.stub, stub_free), (self.program, program_free)]
        {
            if space_gone && free && frame != 0
            {
                // SAFETY: `frame` came from the pool and every mapping of it
                // is gone.
                unsafe { crate::frame_pool::free(frame) };
            }
        }
    }
}

/// Run the `aspace=` case `space`: the harness serves [`Harness::iters`]
/// empty calls, timed as the `words=0` case times them, from a stub caller
/// pinned to CPU 0 in ktest's own address space or in one of its own.
fn bench_aspace(ctx: &crate::TestContext, h: &mut Harness, space: Aspace)
{
    let word = space.word();
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        h.skip(
            NAME,
            format_args!("words=0 aspace={word}: cap_create_endpoint failed"),
        );
        return;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        h.skip(
            NAME,
            format_args!("words=0 aspace={word}: cap_create_notification failed"),
        );
        return;
    };
    let outcome = StubCaller::new(ctx, space)
        .and_then(|caller| stub_round_trips(ctx, h, (ep, done), &caller, space));
    if let Err(e) = outcome
    {
        h.skip(NAME, format_args!("words=0 aspace={word}: {e}"));
    }
    cap_delete(done).ok();
    cap_delete(ep).ok();
}

/// The measured part of [`bench_aspace`]: the program, the caller's start,
/// the timed round trips and the report. A caller parked in a call after an
/// early break is ended by the drop of `caller`.
fn stub_round_trips(
    ctx: &crate::TestContext,
    h: &mut Harness,
    (ep, done): (u64, u64),
    caller: &StubCaller,
    space: Aspace,
) -> Result<(), &'static str>
{
    let n = u64::from(h.iters());
    let child_ep = cap_copy(ep, caller.cspace, syscall_abi::RIGHTS_EP_SEND)
        .map_err(|_| "cap_copy of endpoint failed")?;
    let child_done = cap_copy(done, caller.cspace, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy of notification failed")?;
    StubCaller::write_program(child_ep, child_done, n);
    caller.start()?;
    let start = super::Placement::read(ctx.thread_cap, caller.thread);
    let (summary, completed) = serve_recv_reply(ctx, h, ep, EMPTY, n);
    let end = super::Placement::read(ctx.thread_cap, caller.thread);
    if completed != n
    {
        return Err("a round trip failed");
    }
    let mut signalled = 0u64;
    crate::tally::await_all(done, &mut signalled, 1, "the caller never signalled")?;
    if StubCaller::calls_left() != 0
    {
        return Err("a call of the caller failed");
    }
    let extras = super::placement_extras(start.as_ref(), end.as_ref());
    let extras = extras.as_ref().map_or(&[][..], |e| &e[..]);
    h.report(
        NAME,
        &[
            ("words", Value::Num(0)),
            ("aspace", Value::Word(space.word())),
        ],
        summary,
        extras,
    );
    Ok(())
}

// ── Port-binding case ─────────────────────────────────────────────────────────

/// The `iopb=none` caller's arguments, handed to `timed_caller_entry` by
/// address.
#[derive(Clone, Copy)]
struct TimedArgs
{
    ep: u64,
    done: u64,
    /// Calls the caller makes and times.
    iters: usize,
}

static TIMED_ARGS: spawn::ArgBlock<TimedArgs, 1> = spawn::ArgBlock::new(TimedArgs {
    ep: 0,
    done: 0,
    iters: 0,
});

/// The `iopb=none` caller: times each of its empty calls on its own CPU into
/// [`CHILD_SAMPLES`], counts them in [`super::CHILD_COMPLETED`], and
/// signals `done`.
extern "C" fn timed_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this caller.
    let TimedArgs { ep, done, iters } = unsafe { spawn::child_args(arg) };
    let counters = ::bench::Counters::open();
    if let Some(ipc_buf) = register_place_page(IOPB_CALLER)
    {
        let msg = payload(0, 0);
        for (j, sample) in CHILD_SAMPLES.iter().take(iters).enumerate()
        {
            let t0 = counters.read();
            // SAFETY: ipc_buf was registered as this thread's IPC buffer above.
            if unsafe { ipc::ipc_call(ep, &msg, ipc_buf) }.is_err()
            {
                break;
            }
            let t1 = counters.read();
            sample.store(t1.since(&t0).cycles, Ordering::Relaxed);
            super::CHILD_COMPLETED.store(j.saturating_add(1) as u64, Ordering::Relaxed);
        }
    }
    notification_send(done, 1).ok();
    thread_exit()
}

/// Run the `iopb=none` case (x86-64): a server child and a caller child,
/// neither holding an I/O port binding, pinned to CPU 0, the caller timing
/// [`Harness::iters`] empty calls while the harness waits for it.
fn bench_iopb_none(ctx: &crate::TestContext, h: &mut Harness)
{
    if !crate::arch::HAS_IO_PORTS
    {
        h.skip(NAME, "words=0 iopb=none: no I/O ports");
        return;
    }
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        h.skip(NAME, "words=0 iopb=none: cap_create_endpoint failed");
        return;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        h.skip(NAME, "words=0 iopb=none: cap_create_notification failed");
        return;
    };
    let mut caller = spawn::SpawnedChild::EMPTY;
    let outcome =
        start_server(ctx, ep, (IOPB_SERVER, Serve::RecvReply), Some(0)).and_then(|mut server| {
            let outcome = timed_children(ctx, h, (ep, done), &mut caller);
            // The server is parked in its receive; deleting its Thread cap
            // ends it.
            server.delete_thread().ok();
            server.delete_cspace().ok();
            outcome
        });
    caller.delete_thread().ok();
    caller.delete_cspace().ok();
    match outcome
    {
        Ok(measured) => h.report(
            NAME,
            &[("words", Value::Num(0)), ("iopb", Value::Word("none"))],
            measured,
            &[],
        ),
        Err(e) => h.skip(NAME, format_args!("words=0 iopb=none: {e}")),
    }
    cap_delete(done).ok();
    cap_delete(ep).ok();
}

/// Start the `iopb=none` caller into `caller`, pinned to CPU 0, wait for
/// it, and return its samples' measurement, with CPU 0's idle halts from its
/// start to its signal.
fn timed_children(
    ctx: &crate::TestContext,
    h: &mut Harness,
    (ep, done): (u64, u64),
    caller: &mut spawn::SpawnedChild,
) -> Result<super::Measured, &'static str>
{
    let iters = h.iters() as usize;
    super::CHILD_COMPLETED.store(0, Ordering::Relaxed);
    *caller = spawn::new_child(ctx).map_err(|_| "new_child failed")?;
    let child_ep =
        cap_copy(ep, caller.cs, syscall_abi::RIGHTS_EP_SEND).map_err(|_| "cap_copy failed")?;
    let child_done =
        cap_copy(done, caller.cs, syscall_abi::RIGHTS_NTF_NOTIFY).map_err(|_| "cap_copy failed")?;
    // SAFETY: entry 0 belongs to this caller alone, which has not been started
    // yet.
    let arg = unsafe {
        TIMED_ARGS.publish(
            0,
            TimedArgs {
                ep: child_ep,
                done: child_done,
                iters,
            },
        )
    };
    // SAFETY: `PLACE_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top_at(core::ptr::addr_of!(PLACE_STACKS), IOPB_CALLER) }
        .map_err(|_| "no child stack")?;
    let (mut samples, _) = h.recorder();
    // SAFETY: the stack is entry `IOPB_CALLER` of `PLACE_STACKS`, this
    // caller's own `ChildStack`, on which no other live thread runs
    // (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(caller, timed_caller_entry, stack_top, arg, 0) }
        .map_err(|_| "child start failed")?;
    let mut signalled = 0u64;
    crate::tally::await_all(done, &mut signalled, 1, "the caller never signalled")?;
    samples.record_children();
    Ok(samples.summary())
}
