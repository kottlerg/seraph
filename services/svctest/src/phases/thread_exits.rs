// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/thread_exits.rs

//! Ending two threads of another process in an order the phase chooses, each
//! with an end the phase chooses, through the debug authority svctest holds:
//! the order in which a main thread's own end and its process's end reach a
//! supervisor (`docs/process-lifecycle.md` § Exit reason).
//!
//! svctest attaches to the process (`ATTACH_PROCESS`), which gives it each
//! listed thread's cap with `CONTROL`, `OBSERVE` and `UPCALL`, binds the
//! main thread's and another thread's upcall class to an endpoint of its own
//! under the debugger tag, and posts each an upcall
//! (`docs/fault-handling.md` § Asynchronous Upcalls). A thread blocked in a
//! syscall returns from it, `Interrupted`, and is delivered the upcall there,
//! fault-blocked with the syscall's result already in its registers. svctest
//! stops it, which drops the upcall and leaves the thread to resume at its
//! registers when next started, and points it at a syscall instruction with
//! the syscall number and first argument of the end it is to make:
//! `SYS_THREAD_EXIT`, or `SYS_ASPACE_EXIT` with a code. A thread stopped while
//! blocked, without the upcall, would have its syscall's `Interrupted` written
//! over those registers when started. The instruction is a `syscall` or
//! `ecall` found in the text page the thread was blocked in, other than the
//! one it was blocked at: the riscv64 kernel steps past the `ecall` a
//! syscall-point delivery names unless the handler wrote another `pc`.
//! svctest then starts the first thread, and the second once the first reads
//! `Exited`.
//!
//! The second end lands before procmgr's teardown of the process unless
//! procmgr reaps the first in the moment between the two starts; the
//! teardown then stops the second thread, which ends with no post. A check
//! built on the order therefore never fails for that, and catches a defect
//! whenever the second end lands first.

use std::time::{Duration, Instant};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use syscall_abi::{
    CAP_INFO_THREAD_STATE, FAULT_CLASS_UPCALL, FAULT_KIND_UPCALL, FAULT_LABEL, MAX_THREAD_MEM_COPY,
    PAGE_SIZE, RIGHTS_THREAD_OBSERVE, SYS_ASPACE_EXIT, SYS_THREAD_EXIT, THREAD_STATE_EXITED,
    UPCALL_ANY_INSTRUCTION,
};

use crate::arch::current::{
    IP_OFFSET, REGS_SIZE, SYSCALL_ARG0_OFFSET, SYSCALL_INSN, SYSCALL_INSN_ALIGN,
    SYSCALL_INSN_BEFORE_IP, SYSCALL_NR_OFFSET,
};

/// How long the phase waits, at most, for an upcall's delivery, and for the
/// first thread to read `Exited`.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The badge svctest's upcall bindings carry: procmgr's debugger tag, as
/// procmgr requires of a debugger's binding.
const DEBUGGER_BADGE: u64 = procmgr_labels::DEBUGGER_BADGE_TAG | 2;

/// The end a thread is made to take.
#[derive(Clone, Copy, Debug)]
pub(crate) enum End
{
    /// `SYS_THREAD_EXIT`: the thread's own end, which ends no address space.
    Thread,
    /// `SYS_ASPACE_EXIT` with the code: the process's end, unless another
    /// thread's end came first.
    Process(u32),
}

impl End
{
    /// The syscall number and first argument of the end.
    fn syscall(self) -> (u64, u64)
    {
        match self
        {
            Self::Thread => (SYS_THREAD_EXIT, 0),
            Self::Process(code) => (SYS_ASPACE_EXIT, u64::from(code)),
        }
    }
}

/// Which of the two threads ends first.
#[derive(Clone, Copy, Debug)]
pub(crate) enum First
{
    /// The main thread, then another thread of the process.
    Main,
    /// Another thread of the process, then the main thread.
    Other,
}

/// End the main thread of `process` with `main` and the first other thread
/// it lists with `other`, in the order `first` names, as the module
/// documentation describes. `authority` is the debug authority; `what`
/// names the phase and the process in a failure.
pub(crate) fn end_two(authority: u64, process: u64, main: End, other: End, first: First, what: &str)
{
    let threads = attach(authority, process, what);
    let (&main_cap, &other_cap) = threads.first().zip(threads.get(1)).unwrap_or_else(|| {
        panic!(
            "{what}: the attach listed {} threads, not two",
            threads.len()
        )
    });
    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or_else(|| panic!("{what}: an upcall endpoint"));
    let send = syscall::cap_derive_badge(endpoint, syscall::RIGHTS_EP_SEND, DEBUGGER_BADGE)
        .unwrap_or_else(|e| panic!("{what}: an upcall SEND ({e})"));
    hold(main_cap, endpoint, send, main, what);
    hold(other_cap, endpoint, send, other, what);
    let (one, two) = match first
    {
        First::Main => (main_cap, other_cap),
        First::Other => (other_cap, main_cap),
    };
    syscall::thread_start(one).unwrap_or_else(|e| panic!("{what}: starting the first ({e})"));
    let start = Instant::now();
    while syscall::cap_info(one, CAP_INFO_THREAD_STATE)
        .is_ok_and(|packed| (packed >> 32) as u32 != THREAD_STATE_EXITED)
    {
        assert!(
            start.elapsed() < TIMEOUT,
            "{what}: the first thread did not exit within {TIMEOUT:?}"
        );
        let _ = syscall::thread_yield();
    }
    // The teardown of a process procmgr reaped already refuses the start,
    // which leaves the second thread stopped, with no end of its own.
    let _ = syscall::thread_start(two);
    for cap in threads.into_iter().chain([send, endpoint])
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Attach to `process`, with svctest's own thread as the watch: the caps of
/// its first listed threads, its main thread's first.
fn attach(authority: u64, process: u64, what: &str) -> Vec<u64>
{
    let watch = syscall::cap_derive(
        std::os::seraph::thread::current_thread_cap(),
        RIGHTS_THREAD_OBSERVE,
    )
    .unwrap_or_else(|e| panic!("{what}: a watch cap ({e})"));
    let msg = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, process)
        .word(1, 0)
        .cap(watch)
        .build();
    // SAFETY: the IPC buffer is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &msg, std::os::seraph::current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{what}: ATTACH_PROCESS ipc_call failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{what}: ATTACH_PROCESS refused ({:#x})",
        reply.label
    );
    reply.caps().to_vec()
}

/// Take `thread` out of the syscall it is blocked in through an upcall to
/// `endpoint`, bound through `send`, stop it there, and point it at a
/// syscall instruction with the syscall number and argument of `end`.
fn hold(thread: u64, endpoint: u64, send: u64, end: End, what: &str)
{
    syscall::thread_set_fault_handler(thread, send, FAULT_CLASS_UPCALL)
        .unwrap_or_else(|e| panic!("{what}: binding a thread's upcall class ({e})"));
    syscall::thread_post_upcall(thread, 0, UPCALL_ANY_INSTRUCTION)
        .unwrap_or_else(|e| panic!("{what}: posting a thread an upcall ({e})"));
    let timeout = u64::try_from(TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    // SAFETY: the IPC buffer is this thread's registered IPC buffer page.
    let msg =
        unsafe { ipc::ipc_recv_timeout(endpoint, std::os::seraph::current_ipc_buf(), timeout) }
            .unwrap_or_else(|e| panic!("{what}: no upcall delivered within {TIMEOUT:?} ({e})"));
    assert!(
        msg.label == FAULT_LABEL && msg.word(0) == FAULT_KIND_UPCALL,
        "{what}: a message other than the upcall ({:#x}, kind {})",
        msg.label,
        msg.word(0)
    );
    // The stop cancels the delivery and drops the upcall: the thread resumes
    // at the registers written below when next started.
    syscall::thread_stop(thread).unwrap_or_else(|e| panic!("{what}: stopping a thread ({e})"));
    let mut regs = [0u8; REGS_SIZE];
    syscall::thread_read_regs(thread, &mut regs)
        .unwrap_or_else(|e| panic!("{what}: reading a stopped thread's registers ({e})"));
    let own = word(&regs, IP_OFFSET).wrapping_sub(SYSCALL_INSN_BEFORE_IP);
    let site = syscall_site(thread, own)
        .unwrap_or_else(|| panic!("{what}: no other syscall instruction in the page of {own:#x}"));
    let (nr, arg0) = end.syscall();
    for (offset, value) in [
        (IP_OFFSET, site),
        (SYSCALL_NR_OFFSET, nr),
        (SYSCALL_ARG0_OFFSET, arg0),
    ]
    {
        regs.get_mut(offset..offset.saturating_add(8))
            .unwrap_or_else(|| panic!("{what}: offset {offset} within the register file"))
            .copy_from_slice(&value.to_ne_bytes());
    }
    // SAFETY: the thread is the attached process's, bound to its address
    // space, so the frame it resumes on touches none of svctest's memory; it
    // resumes at a syscall instruction of its own text and ends there.
    unsafe { syscall::thread_write_regs(thread, &regs) }
        .unwrap_or_else(|e| panic!("{what}: writing a stopped thread's registers ({e})"));
}

/// The address of a syscall instruction in the text page of `own`, the one
/// `thread` was blocked at, other than `own`; `None` when the page holds
/// no other or does not read.
fn syscall_site(thread: u64, own: u64) -> Option<u64>
{
    let page = own & !(PAGE_SIZE - 1);
    let page_bytes = usize::try_from(PAGE_SIZE).ok()?;
    let chunk = MAX_THREAD_MEM_COPY.min(page_bytes);
    let mut text = vec![0u8; page_bytes];
    for (at, piece) in text.chunks_mut(chunk).enumerate()
    {
        let offset = u64::try_from(at.checked_mul(chunk)?).ok()?;
        syscall::thread_read_mem(thread, page.checked_add(offset)?, piece).ok()?;
    }
    text.windows(SYSCALL_INSN.len())
        .enumerate()
        .step_by(SYSCALL_INSN_ALIGN)
        .filter(|(_, bytes)| *bytes == SYSCALL_INSN)
        .filter_map(|(at, _)| page.checked_add(u64::try_from(at).ok()?))
        .find(|&site| site != own)
}

/// The register-file word at `offset`.
fn word(regs: &[u8; REGS_SIZE], offset: usize) -> u64
{
    regs.get(offset..offset.saturating_add(8))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_ne_bytes)
}
