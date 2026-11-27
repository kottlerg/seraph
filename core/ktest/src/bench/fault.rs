// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/fault.rs

//! Fault round-trip benchmark: a page fault delivered to a userspace handler
//! and resumed (docs/fault-handling.md § Mechanism Overview), with the
//! handler's work cut to one `mem_map`.
//!
//! A child thread in ktest's address space, bound to an endpoint the harness
//! thread receives on as its `FAULT_CLASS_VM` handler, stores once to each of
//! [`FAULT_PAGES`] scratch pages, none mapped, in turn. The harness maps one
//! pool frame at the faulting page and answers with `ipc_reply_recv`
//! (`FAULT_REPLY_RESUME`), so it is parked in its receive when the next fault
//! arrives, as a pager loop is. No thread receives its own faults
//! (docs/fault-handling.md § Recursion and Escalation). Each fault is a page's
//! first touch, so no unmap sits in the loop: the range's leaf tables are made
//! before the loop, by a map and unmap of one page per table, and the range is
//! unmapped after it.
//!
//! Four counter reads bound each round trip: `t0` on the child before its
//! store, `t1` on the harness when its receive returns the fault, `t2` on the
//! harness after its map, before the reply, and `t3` on the child once the
//! store has run again. The child hands `t0` and `t3` to the harness through
//! [`CHILD_T0`] and [`CHILD_T3`]. Variant `placement=same` pins the child to
//! CPU 0 with the harness, so all four reads are CPU 0's, and reports four
//! lines, variant `leg=`: `delivery` (`t1 - t0`), `handler` (`t2 - t1`),
//! `resume` (`t3 - t2`) and `total` (`t3 - t0`). Variant `placement=apart`
//! pins the child to CPU 1, where both of its reads are taken, and reports
//! `leg=total` alone, since no two harts' counters are kept in step on
//! riscv64; it needs two CPUs and logs a SKIP line below that.

use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};

use ::bench::{Counters, Value};
use ipc::IpcMessage;
use syscall::{cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, thread_exit};
use syscall_abi::{FAULT_LABEL, FAULT_REPLY_RESUME, MAP_WRITABLE, PAGE_SIZE};

use super::{Harness, Legs, MAX_SAMPLES, Measured};
use crate::{ChildStack, spawn};

/// The benchmark's name; each line carries its `placement=` and `leg=`.
const NAME: &str = "fault_round_trip";

/// The legs of one round trip, in the order of their parts of the sample
/// buffer and of their lines.
const LEGS: [&str; 4] = ["delivery", "handler", "resume", "total"];

/// The part of the sample buffer [`LEGS`]' `total` records into.
const TOTAL: usize = 3;

/// Pages the child faults on, one round trip each: the samples one leg's part
/// of the buffer holds, so the benchmark runs at most this many iterations.
const FAULT_PAGES: usize = MAX_SAMPLES / LEGS.len();

/// Scratch VA (crate docs § Scratch VAs) of the first page the child faults
/// on; the pages run up from it, and it is aligned to a leaf table's span.
const FAULT_VA: u64 = 0x1_A800_0000;

/// Pages one leaf table maps, on both architectures.
const LEAF_TABLE_PAGES: usize = 512;

/// Badge of the endpoint cap bound as the child's handler.
const FAULT_BADGE: u64 = 0xFA17_0001;

/// The child's `t0` of the fault it is in, and its `t3` of the round trip
/// before it.
///
/// Relaxed is sufficient: the child stores `t0` before its faulting store and
/// `t3` before its next one or its `done` signal, and the harness loads them
/// only once the fault message or the signal that follows has reached it,
/// which the kernel's IPC and notification paths order after the stores.
static CHILD_T0: AtomicU64 = AtomicU64::new(0);
/// See [`CHILD_T0`].
static CHILD_T3: AtomicU64 = AtomicU64::new(0);

/// Where the child runs, and so which CPU its reads are taken on.
#[derive(Clone, Copy)]
enum Side
{
    /// Pinned to CPU 0, the harness's CPU: `placement=same`.
    Same,
    /// Pinned to CPU 1: `placement=apart`.
    Apart,
}

impl Side
{
    /// The `placement=` word.
    const fn word(self) -> &'static str
    {
        match self
        {
            Self::Same => "same",
            Self::Apart => "apart",
        }
    }

    /// The CPU the child is pinned to, and its slot in [`FAULT_STACKS`] and
    /// [`FAULT_ARGS`].
    const fn cpu(self) -> u32
    {
        match self
        {
            Self::Same => 0,
            Self::Apart => 1,
        }
    }
}

/// One stack per variant, so no variant's child shares a stack with the
/// previous one's, which may still be on its way to exit.
static mut FAULT_STACKS: [ChildStack; 2] = [ChildStack::ZERO; 2];

/// The child's arguments, handed to [`fault_child_entry`] by address.
#[derive(Clone, Copy)]
struct FaultArgs
{
    /// Notification the child signals once its last store has run.
    done: u64,
    /// Pages to store to, from [`FAULT_VA`] up.
    pages: usize,
}

static FAULT_ARGS: spawn::ArgBlock<FaultArgs, 2> =
    spawn::ArgBlock::new(FaultArgs { done: 0, pages: 0 });

/// The address of fault page `i`; `i` is below [`FAULT_PAGES`], so the sum
/// stays in the low scratch band.
fn fault_page(i: usize) -> u64
{
    (i as u64).wrapping_mul(PAGE_SIZE).wrapping_add(FAULT_VA)
}

/// The child: store once to each of its pages, each store faulting, with a
/// counter read before the store and after it, then signal `done`. A child
/// whose harness stops answering stays parked in a fault until its Thread cap
/// is deleted.
extern "C" fn fault_child_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this child.
    let FaultArgs { done, pages } = unsafe { spawn::child_args(arg) };
    let counters = Counters::open();
    for i in 0..pages
    {
        let t0 = counters.read();
        CHILD_T0.store(t0.cycles, Ordering::Relaxed);
        // Keep the store of `t0` before the faulting store, which hands the
        // CPU to the kernel.
        compiler_fence(Ordering::SeqCst);
        let page = fault_page(i) as *mut u64;
        // SAFETY: the page is a scratch VA (crate docs § Scratch VAs) the
        // benchmark leaves unmapped for this store; the harness, bound as
        // this thread's fault handler, maps a frame there and resumes it, so
        // the store runs again against the page. No Rust object lives there.
        unsafe { page.write_volatile(i as u64) };
        let t3 = counters.read();
        CHILD_T3.store(t3.cycles, Ordering::Relaxed);
    }
    syscall::notification_send(done, 1).ok();
    thread_exit()
}

/// Run the `placement=same` variant, then the `placement=apart` one.
pub(super) fn bench_fault_round_trip(ctx: &crate::TestContext, h: &mut Harness)
{
    bench_side(ctx, h, Side::Same);
    if h.cpus < 2
    {
        return h.skip(NAME, "placement=apart: one CPU");
    }
    bench_side(ctx, h, Side::Apart);
}

/// Run variant `side`: set up its endpoint, its `done` notification, the
/// pool frame the harness maps and the child, time the round trips, and
/// clean up whatever was set up.
fn bench_side(ctx: &crate::TestContext, h: &mut Harness, side: Side)
{
    let word = side.word();
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        return h.skip(
            NAME,
            format_args!("placement={word}: cap_create_endpoint failed"),
        );
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        return h.skip(
            NAME,
            format_args!("placement={word}: cap_create_notification failed"),
        );
    };
    let Some(frame) = crate::frame_pool::alloc()
    else
    {
        cap_delete(done).ok();
        cap_delete(ep).ok();
        return h.skip(
            NAME,
            format_args!("placement={word}: frame_pool alloc failed"),
        );
    };
    let pages = (h.iters() as usize).min(FAULT_PAGES);
    let unmapped = match make_leaf_tables(ctx, frame, pages)
    {
        Ok(()) => match spawn::new_child(ctx)
        {
            Ok(mut child) =>
            {
                if let Err(e) = run_side(ctx, h, (ep, done, frame), &child, (side, pages))
                {
                    h.skip(NAME, format_args!("placement={word}: {e}"));
                }
                // Deleting the child's Thread cap also ends a child parked in
                // a fault after an early stop.
                child.delete_thread().ok();
                child.delete_cspace().ok();
                // SAFETY: the range is the scratch pages this benchmark maps,
                // which hold no Rust object, and the child that stored to them
                // is gone.
                unsafe { syscall::mem_unmap_reclaim(ctx.aspace_cap, FAULT_VA, pages as u64) }
                    .is_ok()
            }
            Err(e) =>
            {
                h.skip(NAME, format_args!("placement={word}: {e}"));
                true
            }
        },
        Err(e) =>
        {
            h.skip(NAME, format_args!("placement={word}: {e}"));
            true
        }
    };
    // A frame an unmap left mapped stays out of the pool rather than alias the
    // next test's mapping.
    if unmapped
    {
        // SAFETY: `frame` is from the pool, and no page maps it any more.
        unsafe { crate::frame_pool::free(frame) };
    }
    cap_delete(done).ok();
    cap_delete(ep).ok();
}

/// Make the leaf tables of the first `pages` fault pages by mapping `frame`
/// at one page of each table and unmapping it, so no sample includes a table's
/// allocation. A plain unmap leaves the tables in place.
fn make_leaf_tables(ctx: &crate::TestContext, frame: u64, pages: usize)
-> Result<(), &'static str>
{
    for i in (0..pages).step_by(LEAF_TABLE_PAGES)
    {
        // SAFETY: the page is a scratch VA (crate docs § Scratch VAs), so it
        // holds no Rust object or IPC page of ktest.
        unsafe { syscall::mem_map(frame, ctx.aspace_cap, fault_page(i), 0, 1, MAP_WRITABLE) }
            .map_err(|_| "mem_map of a leaf table's page failed")?;
        // SAFETY: as for the map.
        unsafe { syscall::mem_unmap(ctx.aspace_cap, fault_page(i), 1) }
            .map_err(|_| "mem_unmap of a leaf table's page failed")?;
    }
    Ok(())
}

/// Bind the child's `FAULT_CLASS_VM` handler to `ep`, start it pinned to
/// `side`'s CPU to fault on `pages` pages, serve its faults with `frame`, and
/// report variant `side`'s lines.
fn run_side(
    ctx: &crate::TestContext,
    h: &mut Harness,
    (ep, done, frame): (u64, u64, u64),
    child: &spawn::SpawnedChild,
    (side, pages): (Side, usize),
) -> Result<(), &'static str>
{
    crate::bind_fault_handler_classes(child.th, ep, FAULT_BADGE, syscall_abi::FAULT_CLASS_VM)
        .map_err(|_| "thread_set_fault_handler failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy of notification failed")?;
    let cpu = side.cpu();
    // SAFETY: entry `cpu` belongs to this variant's child alone, which has not
    // been started yet.
    let arg = unsafe {
        FAULT_ARGS.publish(
            cpu as usize,
            FaultArgs {
                done: child_done,
                pages,
            },
        )
    };
    // SAFETY: `FAULT_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top_at(core::ptr::addr_of!(FAULT_STACKS), cpu as usize) }
        .map_err(|_| "no child stack")?;
    // SAFETY: the stack is entry `cpu` of `FAULT_STACKS`, this variant's own
    // `ChildStack`, on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(child, fault_child_entry, stack_top, arg, cpu) }
        .map_err(|_| "child start failed")?;

    let start = super::Placement::read(ctx.thread_cap, child.th);
    let legs = serve_faults(ctx, h, (ep, done, frame), pages)?;
    let end = super::Placement::read(ctx.thread_cap, child.th);
    let extras = super::placement_extras(start.as_ref(), end.as_ref());
    let extras = extras.as_ref().map_or(&[][..], |e| &e[..]);
    report_side(h, side, &legs, extras);
    Ok(())
}

/// Report variant `side`'s lines: every leg's for `placement=same`, the
/// total's alone for `placement=apart`.
fn report_side(h: &Harness, side: Side, legs: &[Measured; LEGS.len()], extras: &[(&str, u64)])
{
    let placement = ("placement", Value::Word(side.word()));
    match side
    {
        Side::Same =>
        {
            for (leg, &measured) in LEGS.iter().zip(legs)
            {
                h.report(
                    NAME,
                    &[placement, ("leg", Value::Word(leg))],
                    measured,
                    extras,
                );
            }
        }
        // The samples were taken on CPU 1, of whose windows CPU 0's halts say
        // nothing.
        Side::Apart => h.report(
            NAME,
            &[placement, ("leg", Value::Word("total"))],
            Measured::of_other_cpus(legs.get(TOTAL).and_then(|total| total.summary)),
            extras,
        ),
    }
}

/// The harness's half of the round trips: serve `pages` faults on `ep`, each
/// by a map of `frame` at the faulting page, and record each round trip's
/// legs; then the wait for the child's `done`, after the last store.
#[inline(never)]
fn serve_faults(
    ctx: &crate::TestContext,
    h: &mut Harness,
    (ep, done, frame): (u64, u64, u64),
    pages: usize,
) -> Result<[Measured; LEGS.len()], &'static str>
{
    let (mut legs, counters) = h.legs::<{ LEGS.len() }>();
    let mut fault = recv_fault(ep, ctx.ipc_buf).map_err(|_| "ipc_recv failed")?;
    // The previous round trip's `t0` and `t2`, whose `t3` the next fault's
    // arrival, or `done`, makes readable.
    let mut previous: Option<(u64, u64)> = None;
    for i in 0..pages
    {
        let t1 = counters.read().cycles;
        let t0 = CHILD_T0.load(Ordering::Relaxed);
        if let Some(earlier) = previous
        {
            record_resume(&mut legs, earlier, CHILD_T3.load(Ordering::Relaxed));
        }
        if fault != (FAULT_LABEL, fault_page(i))
        {
            return Err("an unexpected fault message");
        }
        // SAFETY: the page is a scratch VA (crate docs § Scratch VAs), so it
        // holds no Rust object or IPC page of ktest.
        unsafe { syscall::mem_map(frame, ctx.aspace_cap, fault_page(i), 0, 1, MAP_WRITABLE) }
            .map_err(|_| "mem_map failed")?;
        let t2 = counters.read().cycles;
        legs.record(0, t1.wrapping_sub(t0));
        legs.record(1, t2.wrapping_sub(t1));
        previous = Some((t0, t2));
        if i.saturating_add(1) < pages
        {
            fault = resume_and_recv(ep, ctx.ipc_buf).map_err(|_| "ipc_reply_recv failed")?;
        }
        else
        {
            resume(ctx.ipc_buf).map_err(|_| "ipc_reply failed")?;
        }
    }
    syscall::notification_wait(done).map_err(|_| "notification_wait failed")?;
    if let Some(last) = previous
    {
        record_resume(&mut legs, last, CHILD_T3.load(Ordering::Relaxed));
    }
    Ok(legs.summaries())
}

/// The label and the faulting address (word 1) of a fault message.
fn fault_of(msg: &IpcMessage) -> (u64, u64)
{
    (msg.label, msg.word(1))
}

/// Receive the first fault on `ep` through the registered IPC buffer
/// `ipc_buf`; its [`fault_of`]. Out of line, so the message's frame is not
/// [`serve_faults`]'s.
#[inline(never)]
fn recv_fault(ep: u64, ipc_buf: *mut u64) -> Result<(u64, u64), i64>
{
    // SAFETY: ipc_buf is the caller's registered per-thread IPC buffer.
    unsafe { ipc::ipc_recv(ep, ipc_buf) }.map(|msg| fault_of(&msg))
}

/// Resume the faulted thread and receive the next fault on `ep`, in one
/// `ipc_reply_recv`; the next fault's [`fault_of`].
#[inline(never)]
fn resume_and_recv(ep: u64, ipc_buf: *mut u64) -> Result<(u64, u64), i64>
{
    let reply = IpcMessage::builder(FAULT_REPLY_RESUME).build();
    // SAFETY: ipc_buf is the caller's registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply_recv(ep, &reply, ipc_buf, 0) }.map(|msg| fault_of(&msg))
}

/// Resume the faulted thread, receiving nothing after.
#[inline(never)]
fn resume(ipc_buf: *mut u64) -> Result<(), i64>
{
    let reply = IpcMessage::builder(FAULT_REPLY_RESUME).build();
    // SAFETY: ipc_buf is the caller's registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&reply, ipc_buf) }
}

/// Record the `resume` and `total` legs of the round trip whose `t0` and `t2`
/// were `(t0, t2)` and whose `t3` the child stored.
fn record_resume(legs: &mut Legs<'_, { LEGS.len() }>, (t0, t2): (u64, u64), t3: u64)
{
    legs.record(2, t3.wrapping_sub(t2));
    legs.record(TOTAL, t3.wrapping_sub(t0));
}
