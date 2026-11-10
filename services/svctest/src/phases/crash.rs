// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/crash.rs

//! procmgr's crash endpoint end to end, with svctest as the crash service
//! (`services/procmgr/docs/ipc-interface.md` § Crash Endpoint and Debug
//! Authority): svctest's recipe sets `debug_authority = yes`, and the
//! svctest boot stages no crashd, so the endpoint is free to take.
//!
//! The phase registers with a helper thread's cap, is refused a second
//! registration, receives the forwarded page fault of a `crashme vm` child,
//! attaches to it and finds its main thread stopped at the fault's
//! instruction pointer, and declines it. It then ends the helper, after which
//! procmgr takes the endpoint back: a `crashme exception` child it spawns
//! dies of its fault though svctest receives nothing. A second registration
//! then succeeds, and is given back the same way. With crashd staged (a
//! manual boot) the endpoint is taken and the phase checks only the refusal.

use std::os::seraph::process::ChildExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use syscall_abi::{
    EXIT_FAULT_BASE, EXIT_KILLED, FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL,
    FAULT_REPLY_KILL, REGS_RISCV64_SIZE, REGS_X86_64_SIZE, RIGHTS_THREAD_OBSERVE,
};

use crate::bootstrap::Caps;

/// Faults the phase receives, at most, while it waits for its child's:
/// crasher, co-staged, faults on every spawn, and its faults reach the
/// endpoint too.
const MAX_FAULTS: usize = 32;

/// A helper thread whose cap registers svctest as the crash service, and
/// whose exit gives the endpoint back.
struct Registrant
{
    thread: u64,
    release: mpsc::Sender<()>,
    handle: std::thread::JoinHandle<()>,
}

impl Registrant
{
    fn spawn() -> Self
    {
        let (cap_tx, cap_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            cap_tx
                .send(std::os::seraph::thread::current_thread_cap())
                .expect("crash_endpoint: publishing the helper's cap");
            let _ = release_rx.recv();
        });
        let own = cap_rx.recv().expect("crash_endpoint: the helper's cap");
        let thread = syscall::cap_derive(own, RIGHTS_THREAD_OBSERVE)
            .expect("crash_endpoint: deriving the helper's cap");
        Self {
            thread,
            release,
            handle,
        }
    }

    /// End the helper; procmgr takes the endpoint back on its next pass.
    fn end(self)
    {
        let _ = self.release.send(());
        self.handle
            .join()
            .expect("crash_endpoint: joining the helper");
    }
}

/// Call `cap` with `msg` and return the reply.
fn call(cap: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(cap, msg, std::os::seraph::current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("crash_endpoint: {what}: ipc_call failed ({e})"))
}

/// `REGISTER_CRASH_SERVICE` with `thread`; the reply.
fn register(authority: u64, thread: u64) -> IpcMessage
{
    call(
        authority,
        &IpcMessage::builder(procmgr_labels::REGISTER_CRASH_SERVICE)
            .cap(thread)
            .build(),
        "REGISTER_CRASH_SERVICE",
    )
}

/// Bytes of a register file on either architecture.
const REGS_BYTES: usize = if REGS_X86_64_SIZE > REGS_RISCV64_SIZE
{
    REGS_X86_64_SIZE
}
else
{
    REGS_RISCV64_SIZE
};

/// The register file of a stopped or fault-blocked thread, or `None` when
/// it cannot be read (the thread runs, or waits elsewhere).
fn stopped_regs(thread: u64) -> Option<[u8; REGS_BYTES]>
{
    let mut file = [0u8; REGS_BYTES];
    syscall::thread_read_regs(thread, &mut file).ok()?;
    Some(file)
}

/// Spawn `/programs/crashme <mode>`.
fn crashme(mode: &str) -> std::process::Child
{
    Command::new("/programs/crashme")
        .arg(mode)
        .stdout(Stdio::null())
        .spawn()
        .expect("crash_endpoint: spawning crashme")
}

/// Check that `child` died of a fault.
// cast_sign_loss: exit reasons are non-negative; the cast preserves them.
#[allow(clippy::cast_sign_loss)]
fn expect_fault_death(mut child: std::process::Child, what: &str)
{
    let status = child.wait().expect("crash_endpoint: waiting for crashme");
    let reason = status.code().map(|c| c as u64);
    assert!(
        reason.is_some_and(|r| (EXIT_FAULT_BASE..EXIT_KILLED).contains(&r)),
        "crash_endpoint: {what}: crashme exited {status}, not of a fault"
    );
}

/// Receive faults on `endpoint`, declining each, until the one of `child`'s
/// main thread: a forwarded page fault. Each fault's process is attached to
/// (`ATTACH_PROCESS`), and its fault is the child's when the attached main
/// thread and the child's, both stopped, hold the same registers.
fn take_child_fault(endpoint: u64, authority: u64, child: &std::process::Child)
{
    let child_thread = child.main_thread_cap();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    for _ in 0..MAX_FAULTS
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let msg = unsafe { ipc::ipc_recv(endpoint, ipc_buf) }
            .expect("crash_endpoint: ipc_recv on the crash endpoint");
        assert_eq!(
            msg.label, FAULT_LABEL,
            "crash_endpoint: not a fault message"
        );
        let reply = call(
            authority,
            &IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
                .word(0, msg.badge)
                .word(1, 0)
                .build(),
            "ATTACH_PROCESS",
        );
        let attached = (reply.label == procmgr_errors::SUCCESS)
            .then(|| reply.caps().first().copied())
            .flatten();
        let ours = attached.is_some_and(|thread| {
            let regs = stopped_regs(thread);
            regs.is_some() && regs == stopped_regs(child_thread)
        });
        for &cap in reply.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        if ours
        {
            assert_eq!(reply.word(0), 1, "crash_endpoint: attached thread count");
            assert_eq!(msg.word(0), FAULT_KIND_VM, "crash_endpoint: fault kind");
            assert!(
                msg.word_count() > FAULT_FORWARD_REASON_WORD,
                "crash_endpoint: the page fault did not come forwarded by the pager"
            );
        }
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_KILL), ipc_buf) }
            .expect("crash_endpoint: declining a fault");
        if ours
        {
            return;
        }
    }
    panic!("crash_endpoint: the child's fault never arrived");
}

pub fn crash_endpoint_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "crash_endpoint: no debug authority delivered");

    let first = Registrant::spawn();
    let reply = register(authority, first.thread);
    if reply.label == procmgr_errors::CRASH_SERVICE_PRESENT
    {
        first.end();
        std::os::seraph::log!("crash_endpoint: a crash service is registered; refusal checked");
        return;
    }
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "crash_endpoint: registration"
    );
    let endpoint = *reply
        .caps()
        .first()
        .expect("crash_endpoint: registration returned no RECV cap");

    let second = Registrant::spawn();
    assert_eq!(
        register(authority, second.thread).label,
        procmgr_errors::CRASH_SERVICE_PRESENT,
        "crash_endpoint: a second registration while the first lives"
    );
    second.end();

    let child = crashme("vm");
    take_child_fault(endpoint, authority, &child);
    expect_fault_death(child, "while registered");

    // The helper's exit gives the endpoint back: the next procmgr request,
    // this spawn, finds it gone, and procmgr's decliner declines the fault.
    first.end();
    expect_fault_death(crashme("exception"), "after the take-back");

    let again = Registrant::spawn();
    let reply = register(authority, again.thread);
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "crash_endpoint: registration after the take-back"
    );
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    again.end();
    // A request for procmgr's next pass, which takes the endpoint back.
    let reply = call(
        authority,
        &IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
            .word(0, 0)
            .word(1, 0)
            .build(),
        "ATTACH_PROCESS of no process",
    );
    assert_eq!(
        reply.label,
        procmgr_errors::INVALID_BADGE,
        "crash_endpoint: attach to a badge no process carries"
    );
    let _ = syscall::cap_delete(endpoint);
    std::os::seraph::log!("crash_endpoint phase passed");
}
