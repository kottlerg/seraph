// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/write_regs_blocked_syscall.rs

//! Integration: a thread stopped while blocked inside a syscall has its
//! register frame edited from another CPU, and the edit survives the blocked
//! syscall's own return.
//!
//! A thread blocked in a syscall leaves the frame it entered with published
//! as its `trap_frame`. While it is `Stopped`, `SYS_THREAD_READ_REGS` and
//! `SYS_THREAD_WRITE_REGS` on another CPU read and rewrite that frame; on
//! restart the blocked syscall returns `Interrupted`, writing its return
//! value into the same frame, and the thread resumes from it. The syscall
//! dispatcher and the trap entries therefore hold the frame only as a raw
//! pointer, deriving a reference for each access that cannot block, so their
//! accesses never overlap the foreign ones (`syscall::UserFrame` in
//! core/kernel/src/syscall/mod.rs; riscv64 `trap_dispatch` and
//! `redirect_user_fault`; core/kernel/docs/arch-interface.md § `trap_frame`,
//! the aliasing model). Before that model the handlers held a `&mut
//! TrapFrame` across the block, and riscv64's `trap_dispatch` held one for
//! the whole trap (#514).
//!
//! The aliasing violation itself has no run-time signature: the compiled
//! code may happen to behave either way, and no assertion can see a borrow.
//! What this cell pins is the behaviour the frame model must preserve, which
//! a compiler exploiting a live `&mut` across the block is free to break: a
//! foreign edit of the frame of a thread blocked in a syscall takes effect
//! on its resume. The edit changes the instruction pointer (the syscall
//! returns into [`redirected_entry`] instead of its call site; on riscv64 the
//! trap re-reads `sepc` after the dispatch instead of advancing a copy past
//! the `ecall`) and the second C-argument register, which no failed syscall
//! return writes (`rsi` on x86-64; `a1` on riscv64, the secondary return
//! register written only on success). The syscall's return-value write must
//! leave both edits in place, so [`redirected_entry`] receives the edited
//! argument.
//!
//! A child pinned to CPU 1 loops: it reports that it is about to block, then
//! blocks in one of three syscalls, rotating by round: an untimed
//! `notification_wait`, an `ipc_recv` no one calls, and a long
//! `thread_sleep`. The controller, pinned to CPU 0, runs [`ROUNDS`] rounds:
//! it waits (bounded) for the report, stops the child, and reads its frame.
//! The syscall-number register (`rax` on x86-64, which the dispatcher
//! overwrites only on exit; `a7` on riscv64) must name the round's blocking
//! syscall, which places the stop inside that syscall or at its entry
//! instruction; a stop that landed earlier restarts the child unchanged and
//! retries after 1 ms, bounded. The controller then points the instruction
//! pointer at [`redirected_entry`], writes the round's token into the
//! argument register, publishes the round and the next round's syscall,
//! writes the frame back, and restarts the child. It waits (bounded) for the
//! child to record the round and the token, which it can learn only by
//! entering [`redirected_entry`] afresh with the edited frame. Required:
//! every round's stop lands in its syscall within the bound, every redirect
//! records its round and its token, and no blocking call ever returns to its
//! call site (each is cancelled by the stop and resumed elsewhere).
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, system_info, thread_read_regs, thread_set_affinity,
    thread_sleep, thread_start, thread_stop, thread_write_regs, thread_yield,
};
use syscall_abi::{
    RIGHTS_EP_RECEIVE, SYS_IPC_RECV, SYS_NOTIFICATION_WAIT, SYS_THREAD_SLEEP, SyscallError,
    SystemInfoType,
};

use crate::arch::{ARG1_OFFSET, IP_OFFSET, SYSCALL_NR_OFFSET};
use crate::spawn::SpawnedChild;
use crate::tally::{BadTally, await_report, log_error};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "integration::write_regs_blocked_syscall";

/// Rounds of block, stop, edit, and restart, rotating over the three
/// blocking syscalls.
const ROUNDS: u32 = 30;

/// CPUs needed: one for the controller and one for the child.
const MIN_CPUS: u64 = 2;

/// The participants' CPUs.
const CONTROLLER_CPU: u32 = 0;
const CHILD_CPU: u32 = 1;

/// The blocking syscalls, rotating by round.
const KIND_NOTIFICATION: u32 = 0;
const KIND_RECV: u32 = 1;
const KIND_SLEEP: u32 = 2;
const KINDS: u32 = 3;

/// The sleep kind's duration: far past any round, so only the stop ends it.
const LONG_SLEEP_MS: u64 = 60_000;

/// The child is about to block.
const BIT_BLOCKING: u64 = 1 << 0;

/// Bound on the retries of a stop that landed before the round's syscall,
/// in 1 ms steps. Applied through [`crate::scaled_polls`].
const PROBE_TRIES: u32 = 1000;

/// Bound on the wait for a redirected child to record its round, in 1 ms
/// polls. Applied through [`crate::scaled_polls`].
const REDIRECT_POLLS: u32 = 2000;

/// Register-file buffer size; holds the arch `TrapFrame`
/// (`crate::arch::TRAP_FRAME_BYTES`) on every architecture, as the guard
/// below checks.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// The round's token written into the argument register: a fixed tag with
/// the round in the low bits.
const TOKEN_TAG: u64 = 0x5140_0000_0000_0000;

/// The child's capability handles, in its own `CSpace`, published before
/// its start.
static CHILD_SIG: AtomicU32 = AtomicU32::new(0);
static CHILD_EP: AtomicU32 = AtomicU32::new(0);
static CHILD_DONE: AtomicU32 = AtomicU32::new(0);
/// The blocking syscall the child enters next ([`KIND_NOTIFICATION`],
/// [`KIND_RECV`], or [`KIND_SLEEP`]).
static KIND: AtomicU32 = AtomicU32::new(KIND_NOTIFICATION);
/// The round the controller publishes before restarting an edited child.
static ROUND: AtomicU32 = AtomicU32::new(0);
/// The round, and the token, the child last read on entering
/// [`redirected_entry`]; rounds count from 1, so 0 is no redirect yet.
static REDIRECTED: AtomicU32 = AtomicU32::new(0);
static TOKEN_SEEN: AtomicU64 = AtomicU64::new(0);
/// Blocking calls that returned to their call site (with their result).
static RETURNED: BadTally = BadTally::new();

/// The child's IPC buffer page (its `ipc_recv` needs one registered).
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);
// SAFETY: used only by this cell's single child.
static mut CHILD_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "integration::write_regs_blocked_syscall: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: integration::write_regs_blocked_syscall SKIP (need 2+ CPUs)");
        return Ok(());
    }
    RETURNED.reset();
    for counter in [&ROUND, &REDIRECTED]
    {
        counter.store(0, Ordering::Release);
    }
    TOKEN_SEEN.store(0, Ordering::Release);
    KIND.store(kind_of(1), Ordering::Release);
    // The yield moves the controller onto its CPU now, so every stop comes
    // from another CPU than the child's.
    let result = thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "integration::write_regs_blocked_syscall: pin controller failed")
        .and_then(|()| {
            thread_yield().map_err(|_| "integration::write_regs_blocked_syscall: yield failed")
        })
        .and_then(|()| scenario(ctx));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "integration::write_regs_blocked_syscall: restore controller affinity failed");
    result?;
    restore?;
    RETURNED.check(
        CELL,
        "integration::write_regs_blocked_syscall: a stopped blocking call returned to its call \
         site instead of the edited instruction pointer",
    )
}

/// The blocking syscall of `round` (rounds count from 1).
fn kind_of(round: u32) -> u32
{
    (round - 1) % KINDS
}

/// The syscall number the child's frame carries while it blocks in `kind`.
fn syscall_nr_of(kind: u32) -> u64
{
    match kind
    {
        KIND_NOTIFICATION => SYS_NOTIFICATION_WAIT,
        KIND_RECV => SYS_IPC_RECV,
        _ => SYS_THREAD_SLEEP,
    }
}

/// The objects the child blocks on and reports through.
struct Parts
{
    sig: u32,
    ep: u32,
    done: u32,
}

/// Create the objects, spawn the child, run the rounds, and release
/// everything whatever the outcome.
fn scenario(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::write_regs_blocked_syscall: create sig failed")?;
    let ep = cap_create_endpoint(ctx.memory_base);
    let done = cap_create_notification(ctx.memory_base);
    let (Ok(ep), Ok(done)) = (ep, done)
    else
    {
        // Best-effort cleanup of whichever objects exist.
        let _ = cap_delete(sig);
        if let Ok(ep) = ep
        {
            let _ = cap_delete(ep);
        }
        if let Ok(done) = done
        {
            let _ = cap_delete(done);
        }
        return Err("integration::write_regs_blocked_syscall: create objects failed");
    };
    let parts = Parts { sig, ep, done };
    let ran = with_child(ctx, &parts);
    let deleted = [cap_delete(sig), cap_delete(ep), cap_delete(done)]
        .into_iter()
        .collect::<Result<(), i64>>();
    ran?;
    deleted.map_err(|_| "integration::write_regs_blocked_syscall: delete objects failed")
}

/// Spawn the child with its handles published, run the rounds, and release
/// the child.
fn with_child(ctx: &TestContext, parts: &Parts) -> TestResult
{
    let child = spawn::new_child(ctx)
        .map_err(|_| "integration::write_regs_blocked_syscall: spawn::new_child failed")?;
    let ran = publish_handles(&child, parts)
        .and_then(|()| {
            let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
            // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`,
            // on which no other live thread runs (`ChildStack`'s rule).
            unsafe {
                spawn::configure_and_start_pinned(&child, child_entry, stack_top, 0, CHILD_CPU)
            }
        })
        .and_then(|()| rounds(&child, parts.done));
    let released = release(&child);
    ran?;
    released
}

/// Copy the objects into the child's `CSpace` and publish its handles.
fn publish_handles(child: &SpawnedChild, parts: &Parts) -> TestResult
{
    let sig = cap_copy(parts.sig, child.cs, syscall_abi::RIGHTS_NTF_WAIT)
        .map_err(|_| "integration::write_regs_blocked_syscall: cap_copy sig failed")?;
    let ep = cap_copy(parts.ep, child.cs, RIGHTS_EP_RECEIVE)
        .map_err(|_| "integration::write_regs_blocked_syscall: cap_copy ep failed")?;
    let done = cap_copy(parts.done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::write_regs_blocked_syscall: cap_copy done failed")?;
    CHILD_SIG.store(sig, Ordering::Release);
    CHILD_EP.store(ep, Ordering::Release);
    CHILD_DONE.store(done, Ordering::Release);
    Ok(())
}

/// Run [`ROUNDS`] rounds, stopping at the first that fails.
fn rounds(child: &SpawnedChild, done: u32) -> TestResult
{
    for round in 1..=ROUNDS
    {
        let mut acc = 0u64;
        await_report(
            done,
            &mut acc,
            BIT_BLOCKING,
            "integration::write_regs_blocked_syscall: the child never reported blocking",
        )?;
        let mut regs = stop_in_syscall(child, kind_of(round))?;
        edit_and_restart(child, round, &mut regs)?;
        await_redirect(child, round)?;
    }
    Ok(())
}

/// Stop the child and read its frame until the frame shows it inside (or at
/// the entry of) the syscall of `kind`; a stop that landed earlier restarts
/// the child unchanged and retries after 1 ms, at most the scaled
/// [`PROBE_TRIES`] times. Returns the frame, the child left stopped.
fn stop_in_syscall(child: &SpawnedChild, kind: u32) -> Result<[u8; BUF], &'static str>
{
    let want = syscall_nr_of(kind);
    for _ in 0..crate::scaled_polls(PROBE_TRIES)
    {
        thread_stop(child.th).map_err(|e| {
            log_error(
                "ktest: integration::write_regs_blocked_syscall thread_stop error=",
                e,
            );
            "integration::write_regs_blocked_syscall: thread_stop of the child failed"
        })?;
        let mut regs = [0u8; BUF];
        thread_read_regs(child.th, &mut regs[..BUF]).map_err(|e| {
            log_error(
                "ktest: integration::write_regs_blocked_syscall thread_read_regs error=",
                e,
            );
            "integration::write_regs_blocked_syscall: thread_read_regs refused the stopped child"
        })?;
        if read_word(&regs, SYSCALL_NR_OFFSET) == want
        {
            return Ok(regs);
        }
        thread_start(child.th)
            .map_err(|_| "integration::write_regs_blocked_syscall: restart after probe failed")?;
        let _ = thread_sleep(1);
    }
    Err("integration::write_regs_blocked_syscall: no stop landed in the blocking syscall")
}

/// Point the stopped child's instruction pointer at [`redirected_entry`],
/// write `round`'s token into the argument register, publish the round and
/// the next round's syscall, write the frame back, and restart the child.
fn edit_and_restart(child: &SpawnedChild, round: u32, regs: &mut [u8; BUF]) -> TestResult
{
    ROUND.store(round, Ordering::Release);
    KIND.store(kind_of(round + 1), Ordering::Release);
    let target = redirected_entry as *const () as u64;
    regs[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&target.to_le_bytes());
    let token = TOKEN_TAG | u64::from(round);
    regs[ARG1_OFFSET..ARG1_OFFSET + 8].copy_from_slice(&token.to_le_bytes());
    // SAFETY: the frame was read from this stopped child, so its stack pointer
    // stays on the child's own `ChildStack`; its IP is set to `redirected_entry`,
    // an `extern "C"` entry that never returns and needs nothing of the
    // abandoned frame, so the child resumes on code and a stack it owns.
    unsafe { thread_write_regs(child.th, &regs[..BUF]) }.map_err(|e| {
        log_error(
            "ktest: integration::write_regs_blocked_syscall thread_write_regs error=",
            e,
        );
        "integration::write_regs_blocked_syscall: thread_write_regs refused the stopped child"
    })?;
    thread_start(child.th)
        .map_err(|_| "integration::write_regs_blocked_syscall: restart of the edited child failed")
}

/// Wait (at most the scaled [`REDIRECT_POLLS`] 1 ms polls) for the child to
/// record `round` and its token in [`redirected_entry`].
fn await_redirect(child: &SpawnedChild, round: u32) -> TestResult
{
    for _ in 0..crate::scaled_polls(REDIRECT_POLLS)
    {
        if REDIRECTED.load(Ordering::Acquire) == round
        {
            if TOKEN_SEEN.load(Ordering::Acquire) != TOKEN_TAG | u64::from(round)
            {
                crate::log_u64(
                    "ktest: integration::write_regs_blocked_syscall token seen=",
                    TOKEN_SEEN.load(Ordering::Acquire),
                );
                return Err(
                    "integration::write_regs_blocked_syscall: the edited argument register did \
                     not survive the blocked syscall's return",
                );
            }
            return Ok(());
        }
        let _ = thread_sleep(1);
    }
    if spawn::is_exited(child.th)?
    {
        return Err("integration::write_regs_blocked_syscall: the child died");
    }
    Err("integration::write_regs_blocked_syscall: the edited instruction pointer never took effect")
}

/// Read the little-endian word at `offset` of a register file.
fn read_word(regs: &[u8; BUF], offset: usize) -> u64
{
    u64::from_le_bytes(regs[offset..offset + 8].try_into().unwrap_or([0u8; 8]))
}

/// Stop the child, so its deletion tears down a thread off its CPU, then
/// delete its Thread and `CSpace` caps. A stop refused with `InvalidState`
/// finds the child already stopped (a failed round) or dead.
fn release(child: &SpawnedChild) -> TestResult
{
    let stopped = match thread_stop(child.th)
    {
        Ok(()) => true,
        Err(e) => e == SyscallError::InvalidState as i64,
    };
    let thread_deleted = cap_delete(child.th).is_ok();
    let cspace_deleted = cap_delete(child.cs).is_ok();
    if stopped && thread_deleted && cspace_deleted
    {
        Ok(())
    }
    else
    {
        Err("integration::write_regs_blocked_syscall: teardown failed")
    }
}

/// Child entry: register the IPC buffer, then block in a loop.
extern "C" fn child_entry(_arg: u64) -> !
{
    let buf = core::ptr::addr_of_mut!(CHILD_IPC_BUF).cast::<u64>();
    // SAFETY: `buf` is this thread's own page-aligned IPC page (the static above),
    // registered by one thread at a time; no Rust object lives in it, and the
    // thread reaches it only through the raw `buf` pointer.
    if let Err(e) = unsafe { ipc_buffer_set(buf as u64) }
    {
        RETURNED.record_error(e);
    }
    block_loop()
}

/// Redirect target, entered on resume from a stopped blocking call with the
/// edited frame: `token` arrives in the second argument register the
/// controller wrote (the first carries whatever the frame held: the failed
/// syscall's return value on riscv64). Records the round the controller
/// published and the token, then blocks again. Each redirect enters this on
/// the stack the child was stopped on, which grows by a few frames a round,
/// far inside a `ChildStack` across [`ROUNDS`] rounds.
extern "C" fn redirected_entry(_arg0: u64, token: u64) -> !
{
    TOKEN_SEEN.store(token, Ordering::Release);
    REDIRECTED.store(ROUND.load(Ordering::Acquire), Ordering::Release);
    block_loop()
}

/// Report blocking, then block in the published syscall. Every block is
/// ended by the controller's stop and resumed in [`redirected_entry`], so a
/// call that returns here is recorded as a failure; the loop then reports
/// and blocks again.
fn block_loop() -> !
{
    loop
    {
        // A failed send fails the controller's bounded wait for the bit.
        notification_send(CHILD_DONE.load(Ordering::Acquire), BIT_BLOCKING).ok();
        let result = match KIND.load(Ordering::Acquire)
        {
            KIND_RECV =>
            {
                let buf = core::ptr::addr_of_mut!(CHILD_IPC_BUF).cast::<u64>();
                // SAFETY: buf is this thread's registered IPC buffer.
                unsafe { ipc::ipc_recv(CHILD_EP.load(Ordering::Acquire), buf) }.map(|m| m.label)
            }
            KIND_SLEEP => thread_sleep(LONG_SLEEP_MS).map(|()| 0),
            _ => notification_wait(CHILD_SIG.load(Ordering::Acquire)),
        };
        match result
        {
            Ok(value) => RETURNED.record(value),
            Err(e) => RETURNED.record_error(e),
        }
    }
}
