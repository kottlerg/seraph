// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/user_mode_controls.rs

//! Integration: on every checked CPU, user mode reads the counter the kernel
//! grants and traps on each user-mode control the kernel denies, whatever the
//! firmware left (docs/capability-model.md § Microarchitectural Isolation for
//! the counters).
//!
//! The kernel grants the cycle counter (`RDTSC` on x86-64, `csrr cycle` on
//! riscv64, as `bench::Counters` reads it) and denies the other
//! counters and the other user-mode controls an architecture half lists: the
//! boot CPU starts from the firmware's controls and each AP from its own reset
//! or firmware state, so a control the kernel leaves alone can differ between
//! CPUs. On each CPU of the [`crate::cpu_sample`] sample, one child per denied
//! instruction (`crate::arch::user_controls::DENIED`), pinned there with this
//! thread as its fault handler, reads the granted counter, records the address
//! of the denied instruction in [`EXEC_IP`], executes it, and then an illegal
//! instruction. Before it, the child runs the architecture's checks of the
//! controls' state (`crate::arch::user_controls::STATE_CHECKS`: on x86-64 the
//! processor identifier `RDTSCP` and `RDPID` read, ring-3 `CPUID`, alignment
//! checking, and the user shadow stack), and the handler fails the case on the
//! first that did not hold. The fault the handler receives must be the denied
//! instruction's: of its class (and its error code where the architecture
//! fixes one) at the recorded address. A trap of the granted read arrives with
//! [`EXEC_IP`] still zero, and a denied instruction that completes leaves the
//! child to its illegal instruction, whose fault names another address; either
//! fails the case, naming the instruction.
//!
//! **No fault dump.** As in `umip_descriptor_reads_fault`, the handler resumes
//! each faulted child at [`exit_entry`], so it exits voluntarily and the kernel
//! prints no kill dump.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{cap_create_endpoint, cap_delete, thread_read_regs, thread_write_regs};
use syscall_abi::{
    EXIT_VOLUNTARY, FAULT_KIND_EXCEPTION, FAULT_LABEL, FAULT_REPLY_RESUME, SystemInfoType,
};

use crate::arch::user_controls::{DENIED, STATE_CHECKS};
use crate::{ChildStack, TestContext, TestResult};

/// An instruction user mode is denied, as an architecture's half of the case
/// lists it.
pub struct DeniedInstruction
{
    /// Store the address of the instruction into the slot, then execute it;
    /// returns only when it does not trap.
    pub exec: fn(&AtomicU64),
    /// The fault class (`syscall_abi::FAULT_EXC_*`) it raises.
    pub fault: u64,
    /// The error code of that fault, where the architecture fixes one.
    pub fault_code: Option<u64>,
    /// The failure line when it completes instead of trapping.
    pub not_denied: &'static str,
}

/// The state of a user-mode control the kernel sets, as an architecture's half
/// of the case lists it, which the child checks on its CPU before the denied
/// instruction.
pub struct StateCheck
{
    /// Whether the state holds; it may trap only where the control does not
    /// hold the kernel's value, which fails the case as a trap.
    pub holds: fn() -> bool,
    /// The failure line when it does not.
    pub wrong: &'static str,
}

/// Badge bound with the handler and delivered in each fault message.
const FAULT_BADGE: u64 = 0x0C47_0001;

/// Register-file buffer size; holds the arch `TrapFrame`
/// (`crate::arch::TRAP_FRAME_BYTES`) on every architecture, as the guard
/// below checks.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// Poll bound for each child's exit: ~2 s at ~1 ms per poll, through
/// [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Address of the denied instruction the child is about to execute, written
/// by the child before it and compared with the fault message's IP by the
/// handler; zero until then.
static EXEC_IP: AtomicU64 = AtomicU64::new(0);

/// One plus the index in [`STATE_CHECKS`] of the first check that did not hold on
/// the child's CPU, written by the child before the denied instruction; zero
/// when every check held.
static STATE_WRONG: AtomicU64 = AtomicU64::new(0);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("integration::user_mode_controls: system_info(CpuCount) failed")?;
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::user_mode_controls: cap_create_endpoint failed")?;
    let result = (0..crate::cpu_sample::count(cpus)).try_for_each(|k| {
        let cpu = crate::cpu_sample::checked_cpu(k, cpus)?;
        DENIED
            .iter()
            .enumerate()
            .try_for_each(|(which, denied)| expect_denied(ctx, ep, which, denied, cpu))
    });
    cap_delete(ep).ok();
    result
}

/// Run one child, pinned to `cpu` with this thread as its fault handler on
/// `ep`, that reads the granted counter and then executes `denied` (entry
/// `DENIED[which]`); check the fault is `denied`'s, then resume the
/// child at [`exit_entry`] and check it exits voluntarily. The child's caps
/// are deleted on every path (the `SpawnedChild` guard).
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each), the `Result` temporaries \
              of its `ipc_recv(..)?` (about 576 B each) and the `regs` buffer (512 B); on init's \
              16 KiB stack"
)]
fn expect_denied(
    ctx: &TestContext,
    ep: u64,
    which: usize,
    denied: &DeniedInstruction,
    cpu: u32,
) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "integration::user_mode_controls: spawn::new_child failed")?;
    crate::bind_fault_handler(child.th, ep, FAULT_BADGE)
        .map_err(|_| "integration::user_mode_controls: thread_set_fault_handler failed")?;
    // SAFETY: `CHILD_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(CHILD_STACK)) };
    // The previous child's address and checks must not stand in for this one's.
    EXEC_IP.store(0, Ordering::Release);
    STATE_WRONG.store(0, Ordering::Release);
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on which
    // no other live thread runs (`ChildStack`'s rule): the previous child has
    // exited and its Thread cap has been deleted before the next starts.
    unsafe {
        crate::spawn::configure_and_start_pinned(&child, reader, stack_top, which as u64, cpu)
    }
    .map_err(|_| "integration::user_mode_controls: configure_and_start_pinned failed")?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::user_mode_controls: ipc_recv failed")?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE || msg.word(0) != FAULT_KIND_EXCEPTION
    {
        return Err("integration::user_mode_controls: unexpected fault message");
    }
    let exec_ip = EXEC_IP.load(Ordering::Acquire);
    if exec_ip == 0
    {
        return Err(
            "integration::user_mode_controls: the granted cycle-counter read or a state check \
             trapped",
        );
    }
    if let Some(check) = usize::try_from(STATE_WRONG.load(Ordering::Acquire))
        .ok()
        .and_then(|wrong| wrong.checked_sub(1))
        .and_then(|i| STATE_CHECKS.get(i))
    {
        return Err(check.wrong);
    }
    if msg.word(3) != exec_ip
    {
        return Err(denied.not_denied);
    }
    if msg.word(1) != denied.fault || denied.fault_code.is_some_and(|code| msg.word(2) != code)
    {
        return Err(
            "integration::user_mode_controls: a denied instruction raised another exception",
        );
    }

    let mut regs = [0u8; BUF];
    thread_read_regs(child.th, &mut regs[..])
        .map_err(|_| "integration::user_mode_controls: thread_read_regs failed")?;
    crate::spawn::redirect_to_entry(&mut regs[..], exit_entry as *const () as u64)?;
    // SAFETY: the frame was read from this fault-blocked child, so its stack
    // pointer lies on the child's own `ChildStack`; `redirect_to_entry` pointed it
    // at `exit_entry`, an `extern "C"` entry that never returns and needs nothing
    // of the abandoned frame, with the stack pointer moved down to the entry
    // ABI's alignment on that same stack.
    unsafe { thread_write_regs(child.th, &regs[..]) }
        .map_err(|_| "integration::user_mode_controls: thread_write_regs failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::user_mode_controls: ipc_reply(RESUME) failed")?;

    let reason = crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    if reason != EXIT_VOLUNTARY
    {
        return Err("integration::user_mode_controls: resumed child did not exit voluntarily");
    }
    Ok(())
}

/// Child entry: read the granted counter and run the [`STATE_CHECKS`],
/// recording the first that fails in [`STATE_WRONG`], then execute the
/// denied instruction `DENIED[which]`, then an illegal instruction. The denied
/// instruction faults first and the handler resumes this thread at
/// [`exit_entry`]; one that completes leaves the illegal instruction's fault
/// to the handler.
extern "C" fn reader(which: u64) -> !
{
    core::hint::black_box(::bench::Counters::open().read());
    if let Some(wrong) = STATE_CHECKS.iter().position(|check| !(check.holds)())
    {
        STATE_WRONG.store(
            u64::try_from(wrong).map_or(u64::MAX, |i| i.saturating_add(1)),
            Ordering::Release,
        );
    }
    if let Some(denied) = usize::try_from(which).ok().and_then(|i| DENIED.get(i))
    {
        (denied.exec)(&EXEC_IP);
    }
    crate::arch::illegal_instruction()
}

/// Recovery entry the handler resumes a faulted child at: exit voluntarily.
extern "C" fn exit_entry(_arg: u64) -> !
{
    syscall::thread_exit()
}
