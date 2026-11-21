// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/thread_exits.rs

//! Ending a process from a thread other than its main thread, and then its
//! main thread, each by `SYS_ASPACE_EXIT` with a code of its own, through
//! the debug authority svctest holds: the process's reason is the other
//! thread's, and the main thread's own end, which posts to its thread's
//! observers, carries the other code (`docs/process-lifecycle.md` § Exit
//! reason).
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
//! the syscall number and first argument of its end, `SYS_ASPACE_EXIT` with
//! its code. A thread stopped while
//! blocked, without the upcall, would have its syscall's `Interrupted` written
//! over those registers when started. The instruction is a `syscall` or
//! `ecall` in an executable page of the process, other than the one the
//! thread was blocked at: the riscv64 kernel steps past the `ecall` a
//! syscall-point delivery names unless the handler wrote another `pc`.
//! svctest looks first in the page the thread was blocked in, and then in the
//! process's other executable pages (`SYS_THREAD_LIST_PAGES`), since where a
//! build places its syscall instructions decides whether that page holds
//! another.
//! svctest then starts the other thread, and the main thread once the other
//! reads `Exited`.
//!
//! The other thread's end is the address space's first terminal end, which
//! the kernel retains before the main thread starts, so every reader of the
//! process's reason gets the other thread's code whatever the order of its
//! reads. The main thread's end lands, and posts, unless procmgr's teardown
//! of the process stops it first; a check that the main thread's code is not
//! taken for the process's therefore never fails for that order, and catches
//! a defect whenever the main thread's end lands.

use std::time::{Duration, Instant};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use syscall_abi::{
    CAP_INFO_THREAD_STATE, FAULT_CLASS_UPCALL, FAULT_KIND_UPCALL, FAULT_LABEL, MAX_PAGE_RUNS,
    MAX_THREAD_MEM_COPY, PAGE_RUN_EXECUTE, PAGE_RUN_NO_COPY, PAGE_SIZE, PageRun,
    RIGHTS_THREAD_OBSERVE, SYS_ASPACE_EXIT, THREAD_STATE_EXITED, UPCALL_ANY_INSTRUCTION,
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

/// End `process` from the first thread other than its main thread it lists,
/// with `SYS_ASPACE_EXIT` of `other_code`, and then end its main thread with
/// `SYS_ASPACE_EXIT` of `main_code`, as the module documentation
/// describes. `authority` is the debug authority; `what` names the phase
/// and the process in a failure.
pub(crate) fn end_two(authority: u64, process: u64, main_code: u32, other_code: u32, what: &str)
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
    hold(main_cap, endpoint, send, main_code, what);
    hold(other_cap, endpoint, send, other_code, what);
    let (one, two) = (other_cap, main_cap);
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
/// syscall instruction with the syscall number of `SYS_ASPACE_EXIT` and
/// `code` as its argument.
fn hold(thread: u64, endpoint: u64, send: u64, code: u32, what: &str)
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
    let site = syscall_site(thread, own).unwrap_or_else(|| {
        panic!("{what}: no executable page holds a syscall instruction but {own:#x}")
    });
    let (nr, arg0) = (SYS_ASPACE_EXIT, u64::from(code));
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
    // resumes at a syscall instruction of its own executable pages and ends
    // there.
    unsafe { syscall::thread_write_regs(thread, &regs) }
        .unwrap_or_else(|e| panic!("{what}: writing a stopped thread's registers ({e})"));
}

/// The address of a syscall instruction in an executable page of `thread`'s
/// address space, other than `own`, the one `thread` was blocked at: the
/// first in the page of `own`, else the first in the lowest other
/// executable page that holds one. `None` when no page holds one, or the
/// pages do not list. Every byte of an executable page executes, so the
/// instruction need not be one the compiler emitted there.
fn syscall_site(thread: u64, own: u64) -> Option<u64>
{
    let own_page = own & !(PAGE_SIZE - 1);
    if let Some(site) = site_in_page(thread, own_page, own)
    {
        return Some(site);
    }
    let mut runs = vec![PageRun::default(); usize::try_from(MAX_PAGE_RUNS).ok()?];
    let mut start = 0;
    loop
    {
        let (count, resume) = syscall::thread_list_pages(thread, start, &mut runs).ok()?;
        for run in runs.get(..count)?
        {
            if run.prot & (PAGE_RUN_EXECUTE | PAGE_RUN_NO_COPY) != PAGE_RUN_EXECUTE
            {
                continue;
            }
            for index in 0..run.pages
            {
                let page = run.va.checked_add(index.checked_mul(PAGE_SIZE)?)?;
                if page == own_page
                {
                    continue;
                }
                if let Some(site) = site_in_page(thread, page, own)
                {
                    return Some(site);
                }
            }
        }
        // Only a call at the top of the user half lists no run and returns
        // its own start.
        if count == 0 && resume == start
        {
            return None;
        }
        start = resume;
    }
}

/// The address of the first syscall instruction in `page` of `thread`'s
/// address space other than `own`; `None` when the page holds no other or
/// does not read.
fn site_in_page(thread: u64, page: u64, own: u64) -> Option<u64>
{
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
