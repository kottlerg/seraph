// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_syscall_buffer.rs

//! Integration: a kernel copy into or out of an unbacked syscall buffer faults
//! to the caller's fault handler, and the syscall re-executes when the handler
//! resumes it (docs/fault-handling.md § Kernel Copies).
//!
//!   1. **Resume, copy to the buffer.** A child bound to the harness's endpoint
//!      calls `SYS_GETRANDOM` on an unmapped scratch page. The harness receives
//!      a `FAULT_KIND_VM` naming the buffer with write access, maps a frame
//!      there, and replies `FAULT_REPLY_RESUME`; the re-executed call returns
//!      the whole length, and the bytes landed.
//!   2. **Decline.** The same call on another unmapped page, which the harness
//!      declines with `FAULT_REPLY_KILL`: the call fails with `InvalidAddress`,
//!      the outcome with no handler bound, and the child lives to report it.
//!   3. **Resume, copy from the buffer.** The child calls
//!      `SYS_THREAD_WRITE_REGS` on a stopped helper from an unmapped page. The
//!      harness receives the fault with read access, maps the page, fills it
//!      with the helper's own registers, and resumes; the re-executed call
//!      succeeds.
//!
//! The harness waits on a wait set holding both the endpoint and the child's
//! report notification, so a kernel that fails the copy instead of delivering
//! the fault (the child reports first) fails the case rather than hanging it.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, mem_map, mem_unmap,
    notification_send, notification_wait, notification_wait_timeout, thread_exit, thread_read_regs,
    thread_stop, wait_set_add, wait_set_create, wait_set_wait,
};
use syscall_abi::{
    FAULT_ACCESS_READ, FAULT_ACCESS_WRITE, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL,
    FAULT_REPLY_RESUME, MAP_WRITABLE, RIGHTS_ALL, SyscallError,
};

use crate::{ChildStack, TestContext, TestResult};

/// Unmapped scratch pages (crate docs § Scratch VAs) the cases' buffers lie
/// on, one per case, distinct from other tests' VAs.
const GETRANDOM_VA: u64 = 0x3E_4800_0000;
const DECLINE_VA: u64 = 0x3E_4801_0000;
const WRITE_REGS_VA: u64 = 0x3E_4802_0000;

/// Badge bound with the handler and delivered in the fault message.
const FAULT_BADGE: u64 = 0xC0FF_EE05;

/// Bytes the `SYS_GETRANDOM` cases ask for.
const RANDOM_LEN: usize = 32;

/// Bytes of a register frame, the `SYS_THREAD_WRITE_REGS` buffer's length.
// cast_possible_truncation: the frame is a few hundred bytes.
#[allow(clippy::cast_possible_truncation)]
const FRAME_BYTES: usize = crate::arch::TRAP_FRAME_BYTES as usize;

/// Wait-set badges of the endpoint and the report notification.
const WS_FAULT: u64 = 1;
const WS_REPORT: u64 = 2;

/// The child's report bits: its call returned what the case expects, or
/// anything else.
const BIT_OK: u64 = 1 << 0;
const BIT_BAD: u64 = 1 << 1;

/// Bound on the child's report after the reply. Applied through
/// [`crate::scaled_bound`], which stretches it past [`crate::UNSCALED_CPUS`]
/// CPUs, where the child's CPU waits for a host core.
const REPORT_MS: u64 = 1000;

/// What the child calls, and what it expects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op
{
    /// `SYS_GETRANDOM` on `GETRANDOM_VA`, resumed: the whole length.
    Getrandom,
    /// `SYS_GETRANDOM` on `DECLINE_VA`, declined: `InvalidAddress`.
    Declined,
    /// `SYS_THREAD_WRITE_REGS` on the helper from `WRITE_REGS_VA`, resumed:
    /// success.
    WriteRegs,
}

/// The child's arguments, by address: its operation, its report notification,
/// and (for [`Op::WriteRegs`]) the helper's Thread cap.
#[derive(Clone, Copy)]
struct CallerArgs
{
    op: Op,
    done: u64,
    helper: u64,
}

static CALLER_ARGS: crate::spawn::ArgBlock<CallerArgs, 1> =
    crate::spawn::ArgBlock::new(CallerArgs {
        op: Op::Getrandom,
        done: 0,
        helper: 0,
    });

// The child of each case, and case 3's helper; each case deletes both before
// the next starts.
static mut CALLER_STACK: ChildStack = ChildStack::ZERO;
static mut HELPER_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    run_case(ctx, Op::Getrandom, GETRANDOM_VA)?;
    run_case(ctx, Op::Declined, DECLINE_VA)?;
    run_case(ctx, Op::WriteRegs, WRITE_REGS_VA)
}

/// The caps and children one case creates, deleted on drop.
#[derive(Default)]
struct Case
{
    ep: Option<u64>,
    done: Option<u64>,
    ws: Option<u64>,
    caller: Option<crate::spawn::SpawnedChild>,
    helper: Option<crate::spawn::SpawnedChild>,
}

impl Drop for Case
{
    fn drop(&mut self)
    {
        // The children go first: a caller's Thread teardown releases its fault
        // binding's reference on the endpoint.
        drop(self.caller.take());
        drop(self.helper.take());
        for cap in [self.ws, self.done, self.ep].into_iter().flatten()
        {
            cap_delete(cap).ok();
        }
    }
}

/// Run one case: start the child bound to the harness as its fault handler,
/// take the fault of its call's copy, answer it as `op` requires, and check
/// the child's report.
fn run_case(ctx: &TestContext, op: Op, va: u64) -> TestResult
{
    let mut case = Case::default();
    let ep = *case.ep.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "fault_syscall_buffer: cap_create_endpoint failed")?,
    );
    let done = *case.done.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "fault_syscall_buffer: cap_create_notification failed")?,
    );
    let ws = *case.ws.insert(
        wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
            .map_err(|_| "fault_syscall_buffer: wait_set_create failed")?,
    );
    wait_set_add(ws, ep, WS_FAULT)
        .and_then(|()| wait_set_add(ws, done, WS_REPORT))
        .map_err(|_| "fault_syscall_buffer: wait_set_add failed")?;

    let helper = if op == Op::WriteRegs
    {
        let helper = case.helper.insert(start_helper(ctx)?);
        thread_stop(helper.th).map_err(|_| "fault_syscall_buffer: stop the helper failed")?;
        Some(helper.th)
    }
    else
    {
        None
    };

    let caller = case.caller.insert(
        crate::spawn::new_child(ctx).map_err(|_| "fault_syscall_buffer: new_child failed")?,
    );
    let c_done = cap_copy(done, caller.cs, RIGHTS_ALL)
        .map_err(|_| "fault_syscall_buffer: cap_copy(done) failed")?;
    let c_helper = match helper
    {
        Some(th) => cap_copy(th, caller.cs, RIGHTS_ALL)
            .map_err(|_| "fault_syscall_buffer: cap_copy(helper) failed")?,
        None => 0,
    };
    crate::bind_fault_handler(caller.th, ep, FAULT_BADGE)
        .map_err(|_| "fault_syscall_buffer: thread_set_fault_handler failed")?;
    // SAFETY: no caller is live: each case deletes its caller before the next
    // publishes.
    let arg = unsafe {
        CALLER_ARGS.publish(
            0,
            CallerArgs {
                op,
                done: c_done,
                helper: c_helper,
            },
        )
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(CALLER_STACK));
    // SAFETY: the stack is `CALLER_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(caller, caller_entry, stack_top, arg) }
        .map_err(|_| "fault_syscall_buffer: configure_and_start failed")?;

    let fired = wait_set_wait(ws).map_err(|_| "fault_syscall_buffer: wait_set_wait failed")?;
    if fired != WS_FAULT
    {
        return Err(
            "fault_syscall_buffer: the call returned without its copy's fault reaching \
                    the handler",
        );
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "fault_syscall_buffer: ipc_recv failed")?;
    check_fault(&msg, op, va)?;
    let backing = answer_fault(ctx, op, va, helper)?;

    let bits = notification_wait_timeout(done, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "fault_syscall_buffer: waiting for the report failed");
    // Delete the children before the page goes, so nothing reaches it.
    drop(case);
    if let Some(mem) = backing
    {
        release_backing(ctx, va, mem);
    }
    match bits?
    {
        0 => Err("fault_syscall_buffer: the child did not report after the reply"),
        BIT_OK => Ok(()),
        _ => Err(match op
        {
            Op::Getrandom =>
            {
                "fault_syscall_buffer: the resumed SYS_GETRANDOM did not fill the buffer"
            }
            Op::Declined =>
            {
                "fault_syscall_buffer: a declined copy fault did not fail the call \
                             with InvalidAddress"
            }
            Op::WriteRegs => "fault_syscall_buffer: the resumed SYS_THREAD_WRITE_REGS failed",
        }),
    }
}

/// Check that `msg` is the kernel's fault message for the copy of `op` at
/// `va`.
fn check_fault(msg: &IpcMessage, op: Op, va: u64) -> TestResult
{
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE
    {
        return Err("fault_syscall_buffer: the message is not the child's fault");
    }
    if msg.word(0) != FAULT_KIND_VM || msg.word(1) != va
    {
        return Err("fault_syscall_buffer: the fault does not name the buffer's first byte");
    }
    let access = if op == Op::WriteRegs
    {
        FAULT_ACCESS_READ
    }
    else
    {
        FAULT_ACCESS_WRITE
    };
    if msg.word(2) & (FAULT_ACCESS_READ | FAULT_ACCESS_WRITE) != access
    {
        return Err("fault_syscall_buffer: the fault's access is not the copy's direction");
    }
    if msg.word(3) == 0
    {
        return Err("fault_syscall_buffer: the fault carries no instruction pointer");
    }
    Ok(())
}

/// Answer the fault of `op`: decline it, or back `va` (for
/// [`Op::WriteRegs`], with the stopped helper's own registers) and resume.
/// Returns the pool frame now backing `va`, if any, for the caller to release
/// once the case's children are gone.
fn answer_fault(
    ctx: &TestContext,
    op: Op,
    va: u64,
    helper: Option<u64>,
) -> Result<Option<u64>, &'static str>
{
    if op == Op::Declined
    {
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        return unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_KILL), ctx.ipc_buf) }
            .map(|()| None)
            .map_err(|_| "fault_syscall_buffer: ipc_reply(KILL) failed");
    }
    let mem = crate::frame_pool::alloc().ok_or("fault_syscall_buffer: frame_pool::alloc failed")?;
    // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the page
    // holds no Rust object or IPC page of ktest.
    if unsafe { mem_map(mem, ctx.aspace_cap, va, 0, 1, MAP_WRITABLE) }.is_err()
    {
        // SAFETY: mem is from the pool and was never mapped.
        unsafe { crate::frame_pool::free(mem) };
        return Err("fault_syscall_buffer: mem_map failed");
    }
    let filled = match helper
    {
        Some(th) =>
        {
            // SAFETY: the page at `va` is mapped writable above and holds no
            // Rust object; this slice is the only reference to it and ends
            // with the statement, before the child's re-executed call reads
            // the page.
            let page = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, FRAME_BYTES) };
            thread_read_regs(th, page)
                .map(|_| ())
                .map_err(|_| "fault_syscall_buffer: read the helper failed")
        }
        None => Ok(()),
    };
    let replied = filled.and_then(|()| {
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
            .map_err(|_| "fault_syscall_buffer: ipc_reply(RESUME) failed")
    });
    match replied
    {
        Ok(()) => Ok(Some(mem)),
        Err(e) =>
        {
            release_backing(ctx, va, mem);
            Err(e)
        }
    }
}

/// Unmap `va` and return its backing frame `mem` to the pool, once no thread
/// of the case is left to reach the page.
fn release_backing(ctx: &TestContext, va: u64, mem: u64)
{
    // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs) this case mapped,
    // and no thread of the case reaches it any more.
    unsafe { mem_unmap(ctx.aspace_cap, va, 1) }.ok();
    // SAFETY: mem is from the pool and no longer mapped.
    unsafe { crate::frame_pool::free(mem) };
}

/// Start the helper, a thread of ktest's address space that parks on a
/// notification nothing signals, for case 3 to stop and write.
fn start_helper(ctx: &TestContext) -> Result<crate::spawn::SpawnedChild, &'static str>
{
    let helper =
        crate::spawn::new_child(ctx).map_err(|_| "fault_syscall_buffer: new_child failed")?;
    let park = cap_create_notification(ctx.memory_base)
        .map_err(|_| "fault_syscall_buffer: cap_create_notification (park) failed")?;
    let c_park = cap_copy(park, helper.cs, RIGHTS_ALL);
    cap_delete(park).ok();
    let c_park = c_park.map_err(|_| "fault_syscall_buffer: cap_copy(park) failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(HELPER_STACK));
    // SAFETY: the stack is `HELPER_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&helper, helper_entry, stack_top, c_park) }
        .map_err(|_| "fault_syscall_buffer: start the helper failed")?;
    Ok(helper)
}

/// The helper: park on `park` until the case deletes the thread.
extern "C" fn helper_entry(park: u64) -> !
{
    loop
    {
        notification_wait(park).ok();
    }
}

/// The child: make the call its case names on an unmapped buffer and report
/// whether it returned what the case expects.
extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the `CALLER_ARGS` entry `run_case` published.
    let CallerArgs { op, done, helper } = unsafe { crate::spawn::child_args(arg) };
    let ok = match op
    {
        Op::Getrandom =>
        {
            // SAFETY: the span is a scratch page no Rust object occupies; the
            // kernel writes it once the bound handler backs it.
            let filled = unsafe { syscall::getrandom_raw(GETRANDOM_VA as *mut u8, RANDOM_LEN) };
            filled == Ok(RANDOM_LEN as u64) && landed(GETRANDOM_VA)
        }
        Op::Declined =>
        {
            // SAFETY: as above; the handler declines, so nothing is written.
            let refused = unsafe { syscall::getrandom_raw(DECLINE_VA as *mut u8, RANDOM_LEN) };
            refused == Err(SyscallError::InvalidAddress as i64)
        }
        Op::WriteRegs =>
        {
            // SAFETY: the span is a scratch page no Rust object occupies, which
            // the handler fills with the stopped helper's own frame before
            // resuming, so the helper is written back where it stopped.
            let written = unsafe {
                syscall::thread_write_regs_raw(helper, WRITE_REGS_VA as *const u8, FRAME_BYTES)
            };
            written.is_ok()
        }
    };
    notification_send(done, if ok { BIT_OK } else { BIT_BAD }).ok();
    thread_exit()
}

/// Whether the `RANDOM_LEN` bytes at `va` hold something other than the zeroes
/// a fresh frame starts with (all zero has probability 2^-256).
fn landed(va: u64) -> bool
{
    (0..RANDOM_LEN).any(|i| {
        // SAFETY: the page at `va` is mapped (the call that wrote it returned),
        // and the read is volatile through a raw pointer.
        unsafe { ((va as *const u8).add(i)).read_volatile() != 0 }
    })
}
