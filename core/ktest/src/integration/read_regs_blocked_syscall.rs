// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/read_regs_blocked_syscall.rs

//! Integration: the registers of a thread blocked in a syscall read, and a
//! write of them is refused (core/kernel/docs/syscalls.md
//! § `SYS_THREAD_READ_REGS`, § `SYS_THREAD_READ_EXT_REGS` and
//! § `SYS_THREAD_WRITE_REGS`).
//!
//! Two children block: a client in an `ipc_call` that a server receives and
//! never answers (`BlockedOnReply`), and a receiver in an `ipc_recv` no one
//! calls (`BlockedOnReceive`). For each, the controller reads the register
//! file until the read is admitted (a read of the thread before it blocks is
//! refused `InvalidState`, at most the scaled [`READ_POLLS`] 1 ms polls) and
//! requires:
//!
//! - the read reports the whole frame and the hold `THREAD_REGS_SYSCALL`;
//! - the syscall-number register (`rax` on x86-64, which the dispatcher
//!   overwrites only on exit; `a7` on riscv64) names the blocking syscall, and
//!   the stack pointer lies in the child's own stack, so the file is the
//!   frame the thread entered the syscall with;
//! - a second read returns the same file, the thread still blocked;
//! - `SYS_THREAD_READ_EXT_REGS` reads the thread's extended state;
//! - `SYS_THREAD_WRITE_REGS` of the file is refused `InvalidState`, since the
//!   syscall's return still writes the frame, and a read after it returns the
//!   file unchanged.
//!
//! The hold of a stopped thread is checked by `unit::thread`, that of a
//! fault-blocked one by `integration::fault_debug`.
//!
//! Needs no SMP: the children are unpinned, and on a single CPU they run as
//! timer-preempted peers.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, thread_exit, thread_read_ext_regs, thread_read_regs,
    thread_sleep, thread_write_regs,
};
use syscall_abi::{
    RIGHTS_EP_RECEIVE, RIGHTS_EP_SEND_GRANT, RIGHTS_NTF_NOTIFY, RIGHTS_NTF_WAIT, SYS_IPC_CALL,
    SYS_IPC_RECV, SyscallError, THREAD_REGS_SYSCALL,
};

use crate::arch::{SP_OFFSET, SYSCALL_NR_OFFSET, TRAP_FRAME_BYTES};
use crate::spawn::{SpawnedChild, reg_word};
use crate::tally::await_report;
use crate::{ChildStack, TestContext, TestResult, spawn};

/// The server has received the client's call, which now awaits its reply.
const BIT_ARMED: u64 = 1 << 0;
/// The receiver is about to block in its receive.
const BIT_RECEIVING: u64 = 1 << 1;
/// A blocking syscall of a child returned, which nothing in this cell
/// causes before the children are deleted.
const BIT_RETURNED: u64 = 1 << 2;

/// Bound on the reads of a child before it blocks, in 1 ms polls. Applied
/// through [`crate::scaled_polls`].
const READ_POLLS: u32 = 2000;

/// Register-file buffer size; holds the arch `TrapFrame`.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= TRAP_FRAME_BYTES);

/// A page-aligned 4 KiB IPC buffer page per child.
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);

// Each used only by its one child.
static mut CLIENT_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);
static mut SERVER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);
static mut RECEIVER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

static mut CLIENT_STACK: ChildStack = ChildStack::ZERO;
static mut SERVER_STACK: ChildStack = ChildStack::ZERO;
static mut RECEIVER_STACK: ChildStack = ChildStack::ZERO;

/// A child's arguments, handed to its entry by address: the endpoint it
/// calls or receives on, the report notification, and, for the server, the
/// notification it parks on once it holds the call.
#[derive(Clone, Copy)]
struct ChildArgs
{
    ep: u64,
    done: u64,
    block: u64,
}

/// Slots of [`ARGS`].
const CLIENT: usize = 0;
const SERVER: usize = 1;
const RECEIVER: usize = 2;

static ARGS: spawn::ArgBlock<ChildArgs, 3> = spawn::ArgBlock::new(ChildArgs {
    ep: 0,
    done: 0,
    block: 0,
});

/// The caps `run` creates, deleted on every path.
struct Caps
{
    call_ep: u64,
    recv_ep: u64,
    done: u64,
    block: u64,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut caps = Caps {
        call_ep: 0,
        recv_ep: 0,
        done: 0,
        block: 0,
    };
    let mut children = [
        SpawnedChild::EMPTY,
        SpawnedChild::EMPTY,
        SpawnedChild::EMPTY,
    ];
    let result = scenario(ctx, &mut caps, &mut children);
    // Deleting a blocked child's thread reaps it; the server's delete ends
    // the client's call, whose return then finds the client deleted too.
    let mut reaped: TestResult = Ok(());
    for child in &mut children
    {
        if child.delete_thread().and(child.delete_cspace()).is_err()
        {
            reaped = Err("integration::read_regs_blocked_syscall: reap of a child failed");
        }
    }
    for cap in [caps.call_ep, caps.recv_ep, caps.done, caps.block]
    {
        if cap != 0 && cap_delete(cap).is_err()
        {
            reaped = Err("integration::read_regs_blocked_syscall: cap_delete failed");
        }
    }
    result?;
    reaped
}

/// Block the three children, then read the client and the receiver.
fn scenario(ctx: &TestContext, caps: &mut Caps, children: &mut [SpawnedChild; 3]) -> TestResult
{
    let err = |_| "integration::read_regs_blocked_syscall: cap creation failed";
    caps.call_ep = cap_create_endpoint(ctx.memory_base).map_err(err)?;
    caps.recv_ep = cap_create_endpoint(ctx.memory_base).map_err(err)?;
    caps.done = cap_create_notification(ctx.memory_base).map_err(err)?;
    caps.block = cap_create_notification(ctx.memory_base).map_err(err)?;

    // SAFETY: `SERVER_STACK` is a static stack, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top(core::ptr::addr_of!(SERVER_STACK)) };
    children[SERVER] = start(
        ctx,
        caps,
        SERVER,
        server_entry,
        stack,
        (caps.call_ep, RIGHTS_EP_RECEIVE),
    )?;
    // SAFETY: `CLIENT_STACK` is a static stack, reached only through `addr_of!`.
    let client_stack = unsafe { ChildStack::top(core::ptr::addr_of!(CLIENT_STACK)) };
    children[CLIENT] = start(
        ctx,
        caps,
        CLIENT,
        client_entry,
        client_stack,
        (caps.call_ep, RIGHTS_EP_SEND_GRANT),
    )?;
    // SAFETY: `RECEIVER_STACK` is a static stack, reached only through `addr_of!`.
    let receiver_stack = unsafe { ChildStack::top(core::ptr::addr_of!(RECEIVER_STACK)) };
    children[RECEIVER] = start(
        ctx,
        caps,
        RECEIVER,
        receiver_entry,
        receiver_stack,
        (caps.recv_ep, RIGHTS_EP_RECEIVE),
    )?;

    let mut acc = 0u64;
    await_report(
        caps.done,
        &mut acc,
        BIT_ARMED,
        "integration::read_regs_blocked_syscall: the server never received the call",
    )?;
    await_report(
        caps.done,
        &mut acc,
        BIT_RECEIVING,
        "integration::read_regs_blocked_syscall: the receiver never reported receiving",
    )?;
    read_blocked(children[CLIENT].th, SYS_IPC_CALL, client_stack)?;
    read_blocked(children[RECEIVER].th, SYS_IPC_RECV, receiver_stack)?;
    if acc & BIT_RETURNED != 0
    {
        return Err("integration::read_regs_blocked_syscall: a blocking syscall returned");
    }
    Ok(())
}

/// Create a child, give it its endpoint (with `ep_rights`) and its report
/// and park notifications, publish its arguments in slot `slot`, and start
/// it at `entry` on the stack topped by `stack_top`.
fn start(
    ctx: &TestContext,
    caps: &Caps,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    stack_top: u64,
    (ep, ep_rights): (u64, u64),
) -> Result<SpawnedChild, &'static str>
{
    let child = spawn::new_child(ctx)
        .map_err(|_| "integration::read_regs_blocked_syscall: spawn::new_child failed")?;
    let copy = |cap, rights| {
        cap_copy(cap, child.cs, rights)
            .map_err(|_| "integration::read_regs_blocked_syscall: cap_copy failed")
    };
    let args = ChildArgs {
        ep: copy(ep, ep_rights)?,
        done: copy(caps.done, RIGHTS_NTF_NOTIFY)?,
        block: copy(caps.block, RIGHTS_NTF_WAIT)?,
    };
    // SAFETY: slot `slot` is this child's alone, and the child has not
    // started.
    let arg = unsafe { ARGS.publish(slot, args) };
    // SAFETY: `stack_top` tops the child's own `ChildStack` (`CLIENT_STACK`,
    // `SERVER_STACK` or `RECEIVER_STACK`), on which no other live thread runs.
    unsafe { spawn::configure_and_start(&child, entry, stack_top, arg) }
        .map_err(|_| "integration::read_regs_blocked_syscall: start of a child failed")?;
    Ok(child)
}

/// Read the registers of `th`, blocked (or about to block) in syscall
/// `nr` on the stack topped by `stack_top`, and check them as the module
/// says.
fn read_blocked(th: u64, nr: u64, stack_top: u64) -> TestResult
{
    let regs = read_once_blocked(th)?;
    if reg_word(&regs, SYSCALL_NR_OFFSET)? != nr
    {
        crate::log_u64(
            "ktest: integration::read_regs_blocked_syscall syscall number=",
            reg_word(&regs, SYSCALL_NR_OFFSET)?,
        );
        return Err(
            "integration::read_regs_blocked_syscall: the frame read does not name the blocking \
             syscall",
        );
    }
    let sp = reg_word(&regs, SP_OFFSET)?;
    let base = stack_top.saturating_sub(ChildStack::BYTES as u64);
    if sp <= base || sp > stack_top
    {
        return Err(
            "integration::read_regs_blocked_syscall: the frame's stack pointer is outside the \
             child's stack",
        );
    }
    unchanged(
        th,
        &regs,
        "integration::read_regs_blocked_syscall: a second read changed the frame",
    )?;
    let mut word = [0u8; 8];
    match thread_read_ext_regs(th, 0, &mut word)
    {
        Ok((8, size)) if size >= 8 =>
        {}
        _ =>
        {
            return Err(
                "integration::read_regs_blocked_syscall: the extended state of a blocked thread \
                 did not read",
            );
        }
    }
    // SAFETY: the kernel refuses the write (the check below), so the thread's
    // frame is not changed; were it written, the file is the thread's own
    // frame, read back unchanged.
    let wrote = unsafe { thread_write_regs(th, &regs[..BUF]) };
    if wrote != Err(SyscallError::InvalidState as i64)
    {
        return Err(
            "integration::read_regs_blocked_syscall: a write of a blocked thread's registers \
             was not refused with InvalidState",
        );
    }
    unchanged(
        th,
        &regs,
        "integration::read_regs_blocked_syscall: the refused write changed the frame",
    )
}

/// Read `th`'s registers again ([`read_again`]) and require `regs`;
/// `err` when they differ.
fn unchanged(th: u64, regs: &[u8; BUF], err: &'static str) -> TestResult
{
    if read_again(th)? == *regs
    {
        Ok(())
    }
    else
    {
        Err(err)
    }
}

/// Read `th`'s registers until the read is admitted, at most the scaled
/// [`READ_POLLS`] 1 ms polls ([`read_held`]).
fn read_once_blocked(th: u64) -> Result<[u8; BUF], &'static str>
{
    for _ in 0..crate::scaled_polls(READ_POLLS)
    {
        match read_held(th)
        {
            Ok(regs) => return Ok(regs),
            Err(None) =>
            {}
            Err(Some(failure)) => return Err(failure),
        }
        let _ = thread_sleep(1);
    }
    Err("integration::read_regs_blocked_syscall: the child's registers never read")
}

/// Read `th`'s registers, requiring the whole frame and the hold of a
/// thread blocked in a syscall: `Err(None)` when the kernel refuses the read
/// with `InvalidState`, the failure otherwise.
fn read_held(th: u64) -> Result<[u8; BUF], Option<&'static str>>
{
    let mut regs = [0u8; BUF];
    let (bytes, held) = match thread_read_regs(th, &mut regs[..BUF])
    {
        Ok(read) => read,
        Err(e) if e == SyscallError::InvalidState as i64 => return Err(None),
        Err(e) =>
        {
            crate::tally::log_error("ktest: integration::read_regs_blocked_syscall error=", e);
            return Err(Some(
                "integration::read_regs_blocked_syscall: thread_read_regs failed",
            ));
        }
    };
    if bytes != TRAP_FRAME_BYTES
    {
        return Err(Some(
            "integration::read_regs_blocked_syscall: the read did not cover the frame",
        ));
    }
    if held != THREAD_REGS_SYSCALL
    {
        crate::log_u64("ktest: integration::read_regs_blocked_syscall hold=", held);
        return Err(Some(
            "integration::read_regs_blocked_syscall: the read did not report a thread blocked in \
             a syscall",
        ));
    }
    Ok(regs)
}

/// Read `th`'s registers once more, the thread already found blocked.
fn read_again(th: u64) -> Result<[u8; BUF], &'static str>
{
    read_held(th).map_err(|failure| {
        failure.unwrap_or(
            "integration::read_regs_blocked_syscall: a read of a thread found blocked was refused",
        )
    })
}

/// This child's IPC buffer page, registered; exits the thread when the
/// kernel refuses it.
fn register(page: *mut IpcBufPage) -> *mut u64
{
    let buf = page.cast::<u64>();
    // SAFETY: `buf` is this thread's own page-aligned IPC page (a static of
    // this cell used by one child), registered by one thread; no Rust object
    // lives in it, and the thread reaches it only through the raw `buf`.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        thread_exit()
    }
    buf
}

/// Client: call the endpoint, which the server receives and never answers.
extern "C" fn client_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start` published for this child.
    let ChildArgs { ep, done, .. } = unsafe { spawn::child_args(arg) };
    let buf = register(core::ptr::addr_of_mut!(CLIENT_IPC_BUF));
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let _ = unsafe { ipc::ipc_call(ep, &IpcMessage::new(0), buf) };
    notification_send(done, BIT_RETURNED).ok();
    thread_exit()
}

/// Server: receive the client's call, report it, and park without replying
/// until the controller deletes it.
extern "C" fn server_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start` published for this child.
    let ChildArgs { ep, done, block } = unsafe { spawn::child_args(arg) };
    let buf = register(core::ptr::addr_of_mut!(SERVER_IPC_BUF));
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    if unsafe { ipc::ipc_recv(ep, buf) }.is_ok()
    {
        notification_send(done, BIT_ARMED).ok();
    }
    loop
    {
        notification_wait(block).ok();
    }
}

/// Receiver: report, then receive on an endpoint no one calls.
extern "C" fn receiver_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start` published for this child.
    let ChildArgs { ep, done, .. } = unsafe { spawn::child_args(arg) };
    let buf = register(core::ptr::addr_of_mut!(RECEIVER_IPC_BUF));
    notification_send(done, BIT_RECEIVING).ok();
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let _ = unsafe { ipc::ipc_recv(ep, buf) };
    notification_send(done, BIT_RETURNED).ok();
    thread_exit()
}
