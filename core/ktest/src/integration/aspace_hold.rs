// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/aspace_hold.rs

//! Integration: `SYS_ASPACE_HOLD` and `SYS_ASPACE_RELEASE` stop, defer and
//! resume the threads of a fresh address space (spec: core/kernel/src/sched/
//! hold.rs; core/kernel/docs/syscalls.md § `SYS_ASPACE_HOLD`).
//!
//! The child threads run `crate::arch::code_stub::syscall_program` from a stub
//! page, each on a record array in a data frame that ktest maps in its own
//! space as well: the program makes each record's syscall in turn, stores its
//! primary return in the record's result word, and then counts up in the
//! terminator record. A running thread is told from a stopped one by that
//! counter, since `CAP_INFO_THREAD_STATE` reads a stopped thread as alive. Each
//! result word starts as a sentinel, so a call that has not returned reads so.
//!
//! - Containment (A): after the hold the counter stands still, and after the
//!   release it advances. A kernel that returns before every thread is off its
//!   CPU, or that never restarts them, fails.
//! - Stops survive (B): a start of a thread the hold stopped is refused with
//!   `InvalidArgument`; a `thread_stop` during the hold, and one before it,
//!   leaves the thread stopped by the release, until its own start. A release
//!   that starts every thread fails.
//! - Deferred start (C): a thread created, configured and started during the
//!   hold does not run until the release.
//! - Reply during the hold (D): a call parked on its reply, answered while the
//!   hold stands, delivers the reply and the result only after the release.
//! - Fault resumed during the hold (E): a fault-blocked thread, resumed while
//!   the hold stands, does not run until the release; the handler maps the
//!   code page into the held space.
//! - Deadline during the hold (F): a call whose timeout expires during the
//!   hold reports it only after the release.
//! - Own space (H): a thread's hold of its own space, through a capability
//!   with Control, is refused with `InvalidArgument` and leaves the space
//!   free; a kernel that let it through would wait for its own caller.
//! - Teardown (G): deleting the last cap of a held space kills its thread.

use ipc::IpcMessage;
use syscall::{
    aspace_hold, aspace_release, cap_copy, cap_create_aspace, cap_create_cspace,
    cap_create_endpoint, cap_create_thread, cap_delete, mem_map, mem_unmap, thread_configure,
    thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{
    EXIT_KILLED, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_RESUME, MAP_WRITABLE, RIGHTS_ALL,
    SYS_ASPACE_HOLD, SYS_IPC_BUFFER_SET, SYS_IPC_CALL, SyscallError, ipc_call_count_arg,
};

use crate::{TestContext, TestResult};

/// VA of the stub page in each space. Canonical in every paging mode (below
/// the 2^38 Sv39 user half) and distinct from other tests' VAs.
const STUB_VA: u64 = 0x3E_2A00_0000;
/// VA of the data frame (the record arrays) in the child's space.
const CHILD_DATA_VA: u64 = 0x3E_2A10_0000;
/// VA of the IPC buffer frame in the child's space.
const CHILD_IBUF_VA: u64 = 0x3E_2A20_0000;
/// Unmapped entry PC of the faulting thread; the handler maps the stub here.
const FAULT_VA: u64 = 0x3E_2A30_0000;
/// VAs of the data and IPC buffer frames in ktest's own space, scratch VAs
/// (crate docs § Scratch VAs).
const HOST_DATA_VA: u64 = 0x3E_2B00_0000;
const HOST_IBUF_VA: u64 = 0x3E_2B10_0000;
/// Stack pointer of every thread; the program touches no stack.
const STACK: u64 = STUB_VA + 0x800;

/// Bytes of one record (eight words: number, six arguments, result) and of
/// one thread's record array (four records, the terminator among them).
const RECORD_BYTES: u64 = 64;
const SLOT_BYTES: u64 = 0x100;
/// Most calls a program holds besides its terminator.
const MAX_CALLS: usize = 3;
/// Most threads of one space.
const MAX_THREADS: usize = 2;

/// Result word of a record whose call has not returned.
const SENTINEL: u64 = 0x5EED_5EED_5EED_5EED;
/// Number of the terminator record.
const TERMINATOR: u64 = u64::MAX;

/// Label of the calls, the request and reply words, and the fault badge.
const CALL_LABEL: u64 = 0x4801;
const REQUEST_WORD: u64 = 0xCA11_0000_0000_0001;
const REPLY_WORD: u64 = 0x4E91_0000_0000_0002;
const FAULT_BADGE: u64 = 0xA5E7_0000_0000_0010;

/// Milliseconds a "stays unchanged" check sleeps before it compares.
const SETTLE_MS: u64 = 10;
/// Poll bound for an "advances" check: about 2 s at 1 ms per poll, applied
/// through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

const INVALID_ARGUMENT: Result<(), i64> = Err(SyscallError::InvalidArgument as i64);

/// One call of a program: the syscall number and its first four arguments.
type Call = [u64; 5];

pub fn run(ctx: &TestContext) -> TestResult
{
    containment(ctx)?;
    stops_survive(ctx)?;
    deferred_start(ctx)?;
    reply_during_hold(ctx)?;
    fault_resumed_during_hold(ctx)?;
    deadline_during_hold(ctx)?;
    own_space_refused(ctx)?;
    teardown_of_held_space(ctx)
}

/// One fresh space with its stub page, data frame and IPC
/// buffer frame, and the threads made in it; every cap and frame is released
/// on drop. A zero cap or frame holds none.
#[derive(Default)]
struct Space
{
    /// ktest's own space, whose scratch mappings of the frames drop removes.
    host_aspace: u64,
    threads: [u64; MAX_THREADS],
    cspace: u64,
    aspace: u64,
    ep: u64,
    /// The stub page's frame and the second stub of the fault case.
    stubs: [u64; 2],
    data: u64,
    ibuf: u64,
    data_in_host: bool,
    ibuf_in_host: bool,
}

impl Space
{
    /// Create the space, map its stub, and its data frame in the space
    /// and in ktest's own.
    fn new(ctx: &TestContext) -> Result<Space, &'static str>
    {
        let mut sp = Space {
            host_aspace: ctx.aspace_cap,
            ..Space::default()
        };
        sp.aspace = cap_create_aspace(ctx.memory_base, 0, 8)
            .map_err(|_| "aspace_hold: cap_create_aspace failed")?;
        sp.cspace = cap_create_cspace(ctx.memory_base, 0, 4)
            .map_err(|_| "aspace_hold: cap_create_cspace failed")?;
        sp.stubs[0] = crate::spawn::install_stub(
            ctx,
            sp.aspace,
            STUB_VA,
            &crate::arch::code_stub::syscall_program(),
        )?;
        sp.data = sp.map_frame(HOST_DATA_VA, CHILD_DATA_VA)?;
        sp.data_in_host = true;
        Ok(sp)
    }

    /// Map the IPC buffer frame in the space and in ktest's own.
    fn add_ibuf(&mut self) -> TestResult
    {
        self.ibuf = self.map_frame(HOST_IBUF_VA, CHILD_IBUF_VA)?;
        self.ibuf_in_host = true;
        Ok(())
    }

    /// A pool frame mapped writable at `host_va` in ktest's space and at
    /// `child_va` in this space, returned as the caller's to release.
    fn map_frame(&self, host_va: u64, child_va: u64) -> Result<u64, &'static str>
    {
        let frame =
            crate::frame_pool::alloc().ok_or("aspace_hold: frame_pool::alloc returned None")?;
        // SAFETY: `host_va` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe { mem_map(frame, self.host_aspace, host_va, 0, 1, MAP_WRITABLE) }.is_err()
        {
            // SAFETY: `frame` came from `alloc` and the failed map left it
            // mapped nowhere.
            unsafe { crate::frame_pool::free(frame) };
            return Err("aspace_hold: host mem_map failed");
        }
        // SAFETY: `self.aspace` is a space this test created, not ktest's
        // own, so the call changes nothing ktest runs on.
        if unsafe { mem_map(frame, self.aspace, child_va, 0, 1, MAP_WRITABLE) }.is_err()
        {
            // SAFETY: `host_va` is the scratch VA mapped just above.
            unsafe { mem_unmap(self.host_aspace, host_va, 1) }.ok();
            // SAFETY: `frame` came from `alloc` and is unmapped just above.
            unsafe { crate::frame_pool::free(frame) };
            return Err("aspace_hold: child mem_map failed");
        }
        Ok(frame)
    }

    /// Create the endpoint ktest keeps.
    fn endpoint(&mut self, ctx: &TestContext) -> TestResult
    {
        self.ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "aspace_hold: cap_create_endpoint failed")?;
        Ok(())
    }

    /// Copy the endpoint into the child's `CSpace`; the handle there.
    fn give_endpoint(&self) -> Result<u64, &'static str>
    {
        cap_copy(self.ep, self.cspace, RIGHTS_ALL).map_err(|_| "aspace_hold: cap_copy failed")
    }

    /// Make thread `t`, configured to enter at `entry` with its record
    /// array's VA as its argument; not started.
    fn add_thread(&mut self, ctx: &TestContext, t: usize, entry: u64) -> TestResult
    {
        let thread = cap_create_thread(ctx.memory_base, self.aspace, self.cspace, 0, 0)
            .map_err(|_| "aspace_hold: cap_create_thread failed")?;
        *self
            .threads
            .get_mut(t)
            .ok_or("aspace_hold: thread index out of range")? = thread;
        // SAFETY: the thread is bound to the dedicated address space created
        // above, not ktest's own, so its entry state touches nothing ktest
        // runs on.
        unsafe {
            thread_configure(
                thread,
                entry,
                STACK,
                CHILD_DATA_VA.wrapping_add((t as u64).wrapping_mul(SLOT_BYTES)),
            )
        }
        .map_err(|_| "aspace_hold: thread_configure failed")
    }

    /// Thread `t`'s cap.
    fn thread(&self, t: usize) -> u64
    {
        self.threads.get(t).copied().unwrap_or_default()
    }

    /// Start thread `t`.
    fn start(&self, t: usize) -> TestResult
    {
        thread_start(self.thread(t)).map_err(|_| "aspace_hold: thread_start failed")
    }

    /// Hold the space.
    fn hold(&self) -> TestResult
    {
        aspace_hold(self.aspace).map_err(|_| "aspace_hold: aspace_hold failed")
    }

    /// Release the space.
    fn release(&self) -> TestResult
    {
        aspace_release(self.aspace).map_err(|_| "aspace_hold: aspace_release failed")
    }
}

impl Drop for Space
{
    fn drop(&mut self)
    {
        for thread in self.threads
        {
            if thread != 0
            {
                cap_delete(thread).ok();
            }
        }
        if self.cspace != 0
        {
            cap_delete(self.cspace).ok();
        }
        let unmapped = self.aspace == 0 || cap_delete(self.aspace).is_ok();
        if self.ep != 0
        {
            cap_delete(self.ep).ok();
        }
        let data_free = self.data_in_host && unmap_host(self.host_aspace, HOST_DATA_VA);
        let ibuf_free = self.ibuf_in_host && unmap_host(self.host_aspace, HOST_IBUF_VA);
        // A frame still mapped somewhere stays out of the pool, which takes
        // only unmapped frames.
        if unmapped
        {
            for frame in self.stubs
            {
                free_frame(frame);
            }
            if data_free
            {
                free_frame(self.data);
            }
            if ibuf_free
            {
                free_frame(self.ibuf);
            }
        }
    }
}

/// Remove ktest's scratch mapping at `va`; whether it is gone.
fn unmap_host(aspace: u64, va: u64) -> bool
{
    // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the span
    // holds no Rust object or IPC page of ktest.
    unsafe { mem_unmap(aspace, va, 1) }.is_ok()
}

/// Return `frame` to the pool; 0 holds none.
fn free_frame(frame: u64)
{
    if frame != 0
    {
        // SAFETY: the caller's frame came from the pool and every mapping of
        // it is gone.
        unsafe { crate::frame_pool::free(frame) };
    }
}

/// Write thread `t`'s record array: `calls` in order, each result word the
/// sentinel, then the terminator with its counter at 0.
fn set_program(t: usize, calls: &[Call]) -> TestResult
{
    if calls.len() > MAX_CALLS
    {
        return Err("aspace_hold: a program has too many calls");
    }
    for (k, call) in calls.iter().enumerate()
    {
        for (w, word) in call.iter().enumerate()
        {
            write_word(rec_va(t, k, w), *word);
        }
        write_word(rec_va(t, k, 5), 0);
        write_word(rec_va(t, k, 6), 0);
        write_word(rec_va(t, k, 7), SENTINEL);
    }
    let end = calls.len();
    write_word(rec_va(t, end, 0), TERMINATOR);
    for w in 1..8
    {
        write_word(rec_va(t, end, w), 0);
    }
    Ok(())
}

/// Word 1 of thread `t`'s record `k`, the counter when `k` is the terminator.
fn counter(t: usize, k: usize) -> u64
{
    read_word(rec_va(t, k, 1))
}

/// Word 7 of thread `t`'s record `k`, the call's result.
fn result(t: usize, k: usize) -> u64
{
    read_word(rec_va(t, k, 7))
}

/// Word `i` of the IPC buffer frame.
fn ibuf_word(i: u64) -> u64
{
    read_word(HOST_IBUF_VA.wrapping_add(i.wrapping_mul(8)))
}

/// ktest's VA of word `w` of thread `t`'s record `k`.
fn rec_va(t: usize, k: usize, w: usize) -> u64
{
    // Every index is at most a few, so no step wraps.
    HOST_DATA_VA
        .wrapping_add((t as u64).wrapping_mul(SLOT_BYTES))
        .wrapping_add((k as u64).wrapping_mul(RECORD_BYTES))
        .wrapping_add((w as u64).wrapping_mul(8))
}

fn read_word(va: u64) -> u64
{
    // SAFETY: `va` lies in a frame the live `Space` maps in ktest's own
    // space at a scratch VA, 8-aligned; a child writes it concurrently, so
    // the read is volatile.
    unsafe { (va as *const u64).read_volatile() }
}

fn write_word(va: u64, value: u64)
{
    // SAFETY: as `read_word`; the write is volatile for the same reason.
    unsafe { (va as *mut u64).write_volatile(value) };
}

/// Sleep, then require thread `t`'s terminator counter to still read `value`.
fn expect_stands_still(t: usize, k: usize, value: u64, why: &'static str) -> TestResult
{
    thread_sleep(SETTLE_MS).ok();
    if counter(t, k) != value
    {
        return Err(why);
    }
    Ok(())
}

/// Poll until thread `t`'s counter exceeds `past`.
fn wait_past(t: usize, k: usize, past: u64, why: &'static str) -> TestResult
{
    for _ in 0..crate::scaled_polls(MAX_POLLS)
    {
        if counter(t, k) > past
        {
            return Ok(());
        }
        thread_sleep(1).ok();
    }
    Err(why)
}

/// A: the hold stops the thread, the release runs it again.
fn containment(ctx: &TestContext) -> TestResult
{
    let mut sp = Space::new(ctx)?;
    set_program(0, &[])?;
    sp.add_thread(ctx, 0, STUB_VA)?;
    sp.start(0)?;
    wait_past(0, 0, 0, "aspace_hold: the thread never ran")?;
    sp.hold()?;
    let held = counter(0, 0);
    expect_stands_still(0, 0, held, "aspace_hold: a thread ran during the hold")?;
    sp.release()?;
    wait_past(
        0,
        0,
        held,
        "aspace_hold: the thread did not run after the release",
    )
}

/// B: a thread a hold or a `thread_stop` stopped stays stopped by the release.
fn stops_survive(ctx: &TestContext) -> TestResult
{
    let mut sp = Space::new(ctx)?;
    for t in 0..2
    {
        set_program(t, &[])?;
        sp.add_thread(ctx, t, STUB_VA)?;
    }

    // Thread 0: stopped during the hold, which started it running.
    sp.start(0)?;
    wait_past(0, 0, 0, "aspace_hold: thread 0 never ran")?;
    sp.hold()?;
    if thread_start(sp.thread(0)) != INVALID_ARGUMENT
    {
        return Err("aspace_hold: start of a hold-stopped thread was not InvalidArgument");
    }
    thread_stop(sp.thread(0)).map_err(|_| "aspace_hold: thread_stop of a held thread failed")?;
    let stopped = counter(0, 0);
    sp.release()?;
    expect_stands_still(
        0,
        0,
        stopped,
        "aspace_hold: the release started a thread stopped during the hold",
    )?;
    sp.start(0)?;
    wait_past(
        0,
        0,
        stopped,
        "aspace_hold: thread 0 did not run after its start",
    )?;

    // Thread 1: stopped before the hold.
    sp.start(1)?;
    wait_past(1, 0, 0, "aspace_hold: thread 1 never ran")?;
    thread_stop(sp.thread(1)).map_err(|_| "aspace_hold: thread_stop failed")?;
    thread_sleep(SETTLE_MS).ok();
    let stopped = counter(1, 0);
    sp.hold()?;
    sp.release()?;
    expect_stands_still(
        1,
        0,
        stopped,
        "aspace_hold: the release started a thread stopped before the hold",
    )?;
    sp.start(1)?;
    wait_past(
        1,
        0,
        stopped,
        "aspace_hold: thread 1 did not run after its start",
    )
}

/// C: a thread started during the hold runs at the release.
fn deferred_start(ctx: &TestContext) -> TestResult
{
    let mut sp = Space::new(ctx)?;
    set_program(0, &[])?;
    set_program(1, &[])?;
    sp.add_thread(ctx, 0, STUB_VA)?;
    sp.start(0)?;
    wait_past(0, 0, 0, "aspace_hold: thread 0 never ran")?;
    sp.hold()?;
    sp.add_thread(ctx, 1, STUB_VA)?;
    sp.start(1)?;
    expect_stands_still(1, 0, 0, "aspace_hold: a thread started during the hold ran")?;
    sp.release()?;
    wait_past(
        1,
        0,
        0,
        "aspace_hold: the deferred thread did not run at the release",
    )
}

/// D: a reply made during the hold reaches the caller only after the release.
fn reply_during_hold(ctx: &TestContext) -> TestResult
{
    let mut sp = Space::new(ctx)?;
    sp.add_ibuf()?;
    sp.endpoint(ctx)?;
    let handle = sp.give_endpoint()?;
    set_program(
        0,
        &[
            [SYS_IPC_BUFFER_SET, CHILD_IBUF_VA, 0, 0, 0],
            [
                SYS_IPC_CALL,
                handle,
                CALL_LABEL,
                ipc_call_count_arg(1, 0),
                0,
            ],
        ],
    )?;
    write_word(HOST_IBUF_VA, REQUEST_WORD);
    sp.add_thread(ctx, 0, STUB_VA)?;
    sp.start(0)?;
    receive_request(ctx, sp.ep)?;
    sp.hold()?;
    send_reply(ctx, REPLY_WORD)?;
    thread_sleep(SETTLE_MS).ok();
    if ibuf_word(0) != REQUEST_WORD
    {
        return Err("aspace_hold: the reply reached the held caller's buffer");
    }
    if result(0, 1) != SENTINEL || counter(0, 2) != 0
    {
        return Err("aspace_hold: the held caller returned from its call");
    }
    sp.release()?;
    wait_past(
        0,
        2,
        0,
        "aspace_hold: the caller did not return after the release",
    )?;
    if result(0, 1) != 0
    {
        return Err("aspace_hold: the call did not return success");
    }
    if ibuf_word(0) != REPLY_WORD
    {
        return Err("aspace_hold: the reply did not reach the caller's buffer");
    }
    Ok(())
}

/// Receive the child's call and check its request.
fn receive_request(ctx: &TestContext, ep: u64) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg =
        unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }.map_err(|_| "aspace_hold: ipc_recv failed")?;
    if msg.label != CALL_LABEL || msg.word_count() != 1 || msg.word(0) != REQUEST_WORD
    {
        return Err("aspace_hold: the received call is not the child's request");
    }
    Ok(())
}

/// Reply to the call received last, with `word` as its one data word.
fn send_reply(ctx: &TestContext, word: u64) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::builder(0).word(0, word).build(), ctx.ipc_buf) }
        .map_err(|_| "aspace_hold: ipc_reply failed")
}

/// E: a fault resumed during the hold leaves the thread stopped until the
/// release.
fn fault_resumed_during_hold(ctx: &TestContext) -> TestResult
{
    let mut sp = Space::new(ctx)?;
    sp.endpoint(ctx)?;
    set_program(0, &[])?;
    sp.add_thread(ctx, 0, FAULT_VA)?;
    crate::bind_fault_handler(sp.thread(0), sp.ep, FAULT_BADGE)
        .map_err(|_| "aspace_hold: bind_fault_handler failed")?;
    sp.start(0)?;
    receive_fault(ctx, sp.ep)?;
    sp.hold()?;
    sp.stubs[1] = crate::spawn::install_stub(
        ctx,
        sp.aspace,
        FAULT_VA,
        &crate::arch::code_stub::syscall_program(),
    )?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe {
        ipc::ipc_reply(
            &IpcMessage::builder(FAULT_REPLY_RESUME).build(),
            ctx.ipc_buf,
        )
    }
    .map_err(|_| "aspace_hold: ipc_reply(RESUME) failed")?;
    thread_sleep(SETTLE_MS).ok();
    if crate::spawn::is_exited(sp.thread(0))?
    {
        return Err("aspace_hold: the resumed thread exited");
    }
    if counter(0, 0) != 0
    {
        return Err("aspace_hold: a thread resumed during the hold ran");
    }
    sp.release()?;
    wait_past(
        0,
        0,
        0,
        "aspace_hold: the resumed thread did not run after the release",
    )
}

/// Receive the child's instruction-fetch fault and check its shape.
fn receive_fault(ctx: &TestContext, ep: u64) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "aspace_hold: ipc_recv(fault) failed")?;
    if msg.label != FAULT_LABEL
        || msg.badge != FAULT_BADGE
        || msg.word(0) != FAULT_KIND_VM
        || msg.word(1) != FAULT_VA
    {
        return Err("aspace_hold: the received message is not the child's fetch fault");
    }
    Ok(())
}

/// F: a call timeout that expires during the hold is reported after the
/// release.
fn deadline_during_hold(ctx: &TestContext) -> TestResult
{
    let mut sp = Space::new(ctx)?;
    sp.endpoint(ctx)?;
    let handle = sp.give_endpoint()?;
    set_program(
        0,
        &[[
            SYS_IPC_CALL,
            handle,
            CALL_LABEL,
            ipc_call_count_arg(0, 20),
            0,
        ]],
    )?;
    sp.add_thread(ctx, 0, STUB_VA)?;
    sp.start(0)?;
    thread_sleep(5).ok();
    sp.hold()?;
    thread_sleep(60).ok();
    if result(0, 0) != SENTINEL || counter(0, 1) != 0
    {
        return Err("aspace_hold: the held caller returned from its timed call");
    }
    sp.release()?;
    wait_past(
        0,
        1,
        0,
        "aspace_hold: the caller did not return after the release",
    )?;
    if result(0, 0) != (SyscallError::WouldBlock as i64).cast_unsigned()
    {
        return Err("aspace_hold: the timed call did not report WouldBlock");
    }
    Ok(())
}

/// H: a thread's hold of its own space is refused, and leaves it free.
fn own_space_refused(ctx: &TestContext) -> TestResult
{
    let mut sp = Space::new(ctx)?;
    let handle = cap_copy(sp.aspace, sp.cspace, RIGHTS_ALL)
        .map_err(|_| "aspace_hold: cap_copy(aspace) failed")?;
    set_program(0, &[[SYS_ASPACE_HOLD, handle, 0, 0, 0]])?;
    sp.add_thread(ctx, 0, STUB_VA)?;
    sp.start(0)?;
    wait_past(
        0,
        1,
        0,
        "aspace_hold: the hold of the caller's own space did not return",
    )?;
    if result(0, 0) != (SyscallError::InvalidArgument as i64).cast_unsigned()
    {
        return Err("aspace_hold: hold of the caller's own space was not InvalidArgument");
    }
    sp.hold()?;
    sp.release()
}

/// G: deleting the last cap of a held space kills its thread.
fn teardown_of_held_space(ctx: &TestContext) -> TestResult
{
    let mut sp = Space::new(ctx)?;
    set_program(0, &[])?;
    sp.add_thread(ctx, 0, STUB_VA)?;
    sp.start(0)?;
    wait_past(0, 0, 0, "aspace_hold: the thread never ran")?;
    sp.hold()?;
    cap_delete(sp.aspace).map_err(|_| "aspace_hold: cap_delete of the held space failed")?;
    sp.aspace = 0;
    let reason = crate::spawn::wait_until_exited(sp.thread(0), crate::scaled_polls(MAX_POLLS))?;
    if reason != EXIT_KILLED
    {
        return Err("aspace_hold: the held space's thread did not exit EXIT_KILLED");
    }
    Ok(())
}
