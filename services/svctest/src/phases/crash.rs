// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/crash.rs

//! procmgr's crash endpoint end to end, with svctest as the crash service
//! (`services/procmgr/docs/ipc-interface.md` § Crash Endpoint and Debug
//! Authority): svctest's recipe sets `debug_authority = yes`, and the
//! svctest boot stages no crashd, so the endpoint is free to take.
//!
//! The phase registers with a helper thread's cap, is refused a second
//! registration, and receives faults on the endpoint until the forwarded
//! page fault of a `crashme vm` child: it attaches to each fault's process
//! and knows the child's when the attached main thread's register file
//! equals the child's own, both stopped at the fault. It declines every
//! fault. Two more children check the registry procmgr keeps of the threads
//! the runtime spawns (`REGISTER_THREAD`): `crashme registry-main`, whose
//! main-thread fault's attach lists its two parked threads and not the one
//! that exited, and on which the phase then acts as a debugger
//! ([`debugger_session`]: `LIST_PROCESSES` names it, and `DETACH_PROCESS`,
//! then the death of an attach's watch thread, restore a parked thread's
//! crash binding), and `crashme registry-worker`, whose spawned thread faults
//! under a crash badge of its own, which names its process and the thread,
//! its joined sibling no longer listed. `crashme debugger-tag` then checks,
//! with svctest as its debugger ([`debugger_tag_check`]), that a thread that
//! registers with a gone debugger's binding is bound back to the crash
//! endpoint, and that a declaration unbinds an attached debugger and leaves
//! no watch to bind the process back. procmgr then refuses a registration
//! from svctest, which declared itself undebuggable. It then ends the
//! helper, after which procmgr takes the endpoint back: a
//! `crashme exception` child it spawns dies of its fault though
//! svctest receives nothing. A second registration then succeeds, and is
//! given back the same way. With crashd staged (a manual boot, or burn-in's
//! svctest cell, which keeps the default crashd staging) the endpoint is
//! taken and the phase checks only the refusal.

use std::os::seraph::process::ChildExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use syscall_abi::{
    CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, EXIT_KILLED, FAULT_CLASS_EXCEPTION, FAULT_CLASS_UPCALL,
    FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL, REGS_RISCV64_SIZE,
    REGS_X86_64_SIZE, RIGHTS_THREAD, RIGHTS_THREAD_OBSERVE, THREAD_STATE_EXITED,
};

use crate::bootstrap::Caps;

/// Faults the phase receives, at most, while it waits for its child's:
/// crasher, co-staged, faults on every spawn, and its faults reach the
/// endpoint too.
const MAX_FAULTS: usize = 32;

/// How long the phase waits for a released helper to exit.
const HELPER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// A helper thread whose cap registers svctest as the crash service, and
/// whose exit gives the endpoint back.
struct Registrant
{
    thread: u64,
    /// A second observe cap on the helper, kept to see it exit.
    watch: u64,
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
        let watch = syscall::cap_derive(own, RIGHTS_THREAD_OBSERVE)
            .expect("crash_endpoint: deriving the helper's watch cap");
        Self {
            thread,
            watch,
            release,
            handle,
        }
    }

    /// End the helper and wait until its watch cap shows it gone, exited or
    /// the cap revoked, so procmgr's next pass, which any following request
    /// wakes, finds it gone and takes the endpoint back. The join's reclaim
    /// revokes every cap derived from the helper's, the watch cap and the
    /// one procmgr keeps among them (runtime/ruststd/README.md § Thread
    /// capability).
    fn end(self)
    {
        let _ = self.release.send(());
        self.handle
            .join()
            .expect("crash_endpoint: joining the helper");
        let start = Instant::now();
        loop
        {
            match syscall::cap_info(self.watch, CAP_INFO_THREAD_STATE)
            {
                Ok(packed) if (packed >> 32) as u32 != THREAD_STATE_EXITED =>
                {}
                _ => break,
            }
            assert!(
                start.elapsed() < HELPER_EXIT_TIMEOUT,
                "crash_endpoint: the helper did not exit"
            );
            let _ = syscall::thread_yield();
        }
        let _ = syscall::cap_delete(self.watch);
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

/// The fault of a `crashme` child the phase takes, and what it checks of
/// the attach that reaches it.
#[derive(Clone, Copy)]
enum ChildFault
{
    /// `crashme vm`: its main thread's forwarded page fault; the child holds
    /// its main thread alone.
    MainVm,
    /// `crashme registry-main`: its main thread's fault, with two parked
    /// threads registered and a detached one exited, which is not listed.
    RegistryMain,
    /// `crashme registry-worker`: a spawned thread's fault after its sibling
    /// was joined, which is not listed; the fault's badge is the thread's
    /// crash badge, which names its process and it.
    RegistryWorker,
}

impl ChildFault
{
    /// Whether the fault `msg`, whose attach replied `reply`, is the
    /// child's: the attached main thread and the child's hold the same
    /// registers, both stopped. A spawned thread faults while the child's
    /// main thread runs, so for its fault the main thread is stopped first,
    /// and started again when the fault is another process's, so the child
    /// goes on to release its faulting thread.
    fn is_childs(self, msg: &IpcMessage, reply: &IpcMessage, child_thread: u64) -> bool
    {
        if reply.label != procmgr_errors::SUCCESS
        {
            return false;
        }
        let mut stopped = false;
        if let ChildFault::RegistryWorker = self
        {
            if msg.badge == reply.word(procmgr_labels::ATTACH_WORD_PROCESS_BADGE)
            {
                return false;
            }
            stopped = syscall::thread_stop(child_thread).is_ok();
        }
        let same = reply.caps().first().is_some_and(|&thread| {
            let regs = stopped_regs(thread);
            regs.is_some() && regs == stopped_regs(child_thread)
        });
        if stopped && !same
        {
            syscall::thread_start(child_thread)
                .expect("crash_endpoint: restarting the child's main thread");
        }
        same
    }

    /// Check the attach `reply` to the child's fault `msg`.
    fn check(self, msg: &IpcMessage, reply: &IpcMessage)
    {
        let named = reply.word(procmgr_labels::ATTACH_WORD_NAMED_THREAD);
        let process = reply.word(procmgr_labels::ATTACH_WORD_PROCESS_BADGE);
        match self
        {
            ChildFault::MainVm =>
            {
                assert_eq!(reply.word(0), 1, "crash_endpoint: attached thread count");
                assert_eq!(msg.word(0), FAULT_KIND_VM, "crash_endpoint: fault kind");
                assert!(
                    msg.word_count() > FAULT_FORWARD_REASON_WORD,
                    "crash_endpoint: the page fault did not come forwarded by the pager"
                );
            }
            ChildFault::RegistryMain =>
            {
                assert_eq!(
                    reply.word(0),
                    3,
                    "crash_endpoint: the main thread and two parked ones, not the exited one"
                );
                assert_eq!(
                    named, 0,
                    "crash_endpoint: a process badge names the main thread"
                );
                assert_eq!(process, msg.badge, "crash_endpoint: the process badge");
                for &thread in reply.caps()
                {
                    let packed = syscall::cap_info(thread, CAP_INFO_THREAD_STATE)
                        .expect("crash_endpoint: a listed thread's state");
                    assert_ne!(
                        (packed >> 32) as u32,
                        THREAD_STATE_EXITED,
                        "crash_endpoint: an exited thread is listed"
                    );
                }
            }
            ChildFault::RegistryWorker =>
            {
                assert_eq!(
                    reply.word(0),
                    2,
                    "crash_endpoint: the main thread and the faulting one, not the joined one"
                );
                assert_eq!(
                    named, 1,
                    "crash_endpoint: the crash badge names the spawned thread"
                );
                // svctest stopped only the main thread: the named thread's
                // registers read because it is the one blocked on the fault.
                assert!(
                    reply
                        .caps()
                        .get(1)
                        .copied()
                        .and_then(stopped_regs)
                        .is_some(),
                    "crash_endpoint: the named thread is not fault-blocked"
                );
            }
        }
    }
}

/// Receive faults on `endpoint`, declining each, until `child`'s `fault`.
/// Each fault's process is attached to (`ATTACH_PROCESS`, by the fault's
/// badge), and [`ChildFault::is_childs`] tells the child's apart from those
/// of other processes (crasher, co-staged, faults on every spawn).
fn take_child_fault(endpoint: u64, authority: u64, child: &std::process::Child, fault: ChildFault)
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
        let ours = fault.is_childs(&msg, &reply, child_thread);
        if ours
        {
            fault.check(&msg, &reply);
            if let ChildFault::RegistryMain = fault
            {
                debugger_session(
                    authority,
                    reply.word(procmgr_labels::ATTACH_WORD_PROCESS_BADGE),
                    reply.caps(),
                );
            }
        }
        for &cap in reply.caps()
        {
            let _ = syscall::cap_delete(cap);
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

/// The badge a debugger's binding carries in [`debugger_session`]: procmgr's
/// debugger tag, as procmgr requires of a debugger.
const DEBUGGER_BADGE: u64 = procmgr_labels::DEBUGGER_BADGE_TAG | 1;

/// The badge `thread`'s exception class is bound under.
fn exception_badge(thread: u64, what: &str) -> Option<u64>
{
    class_badge(thread, FAULT_CLASS_EXCEPTION, what)
}

/// The badge `thread`'s `class` is bound under.
fn class_badge(thread: u64, class: u64, what: &str) -> Option<u64>
{
    syscall::thread_get_fault_handler(thread, class)
        .unwrap_or_else(|e| panic!("crash_endpoint: {what}: reading the binding ({e})"))
}

/// Walk `LIST_PROCESSES` for `process`; its name.
fn listed_name(authority: u64, process: u64) -> Option<Vec<u8>>
{
    find_listed(authority, |badge, _| badge == process).map(|(_, name)| name)
}

/// Walk `LIST_PROCESSES` for the first live process named `name`; its badge.
fn badge_named(authority: u64, name: &[u8]) -> Option<u64>
{
    find_listed(authority, |_, listed| listed == name).map(|(badge, _)| badge)
}

/// Walk `LIST_PROCESSES` for the first entry `matches` accepts; its badge
/// and name.
fn find_listed(authority: u64, matches: impl Fn(u64, &[u8]) -> bool) -> Option<(u64, Vec<u8>)>
{
    let mut cursor = None;
    loop
    {
        let reply = call(
            authority,
            &IpcMessage::builder(procmgr_labels::LIST_PROCESSES)
                .word(0, u64::from(cursor.is_some()))
                .word(1, cursor.unwrap_or(0))
                .build(),
            "LIST_PROCESSES",
        );
        assert_eq!(
            reply.label,
            procmgr_errors::SUCCESS,
            "crash_endpoint: LIST_PROCESSES with the authority"
        );
        let words = reply.words();
        let count = usize::try_from(words.first().copied().unwrap_or(0)).unwrap_or(0);
        let mut name = [0u8; ipc::svcmgr_labels::NAME_MAX];
        for i in 0..count
        {
            let (badge, len) = procmgr_labels::unpack_list_entry(words, i, &mut name)
                .expect("crash_endpoint: a LIST_PROCESSES entry");
            if matches(badge, &name[..len])
            {
                return Some((badge, name[..len].to_vec()));
            }
            cursor = Some(badge);
        }
        if count < procmgr_labels::LIST_PROCESSES_PAGE
        {
            return None;
        }
    }
}

/// What a debugger does to `crashme registry-main`, its main thread held at
/// its fault and `threads` the caps its attach returned: it finds the
/// process by name (`LIST_PROCESSES`), binds a parked thread's exception and
/// upcall classes to an endpoint of its own, and hands the thread back
/// (`DETACH_PROCESS`), which restores the crash binding and unbinds the
/// upcall class; then it attaches with a watch, binds the thread again, and
/// dies, its watch thread exiting, after which procmgr's next pass does the
/// same unasked. procmgr leaves the main thread, whose binding is already
/// its own, so the fault stays svctest's to decline.
fn debugger_session(authority: u64, process: u64, threads: &[u64])
{
    assert_eq!(
        listed_name(authority, process).as_deref(),
        Some(&b"/programs/crashme"[..]),
        "crash_endpoint: LIST_PROCESSES names the child by its argv[0]"
    );
    let parked = *threads
        .get(1)
        .expect("crash_endpoint: a parked thread's cap");
    let crash_badge = exception_badge(parked, "a parked thread")
        .expect("crash_endpoint: a registered thread bound to the crash endpoint");
    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .expect("crash_endpoint: a debugger endpoint");
    let send = syscall::cap_derive_badge(endpoint, syscall::RIGHTS_EP_SEND, DEBUGGER_BADGE)
        .expect("crash_endpoint: a debugger SEND");
    let bind = || {
        syscall::thread_set_fault_handler(parked, send, FAULT_CLASS_EXCEPTION | FAULT_CLASS_UPCALL)
            .expect("crash_endpoint: binding the parked thread");
        assert_eq!(
            exception_badge(parked, "the debugger's bind"),
            Some(DEBUGGER_BADGE)
        );
    };
    let upcall_unbound = |what: &str| {
        assert_eq!(
            class_badge(parked, FAULT_CLASS_UPCALL, what),
            None,
            "crash_endpoint: {what} leaves the debugger's upcall binding"
        );
    };

    bind();
    let reply = call(
        authority,
        &IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
            .word(0, process)
            .build(),
        "DETACH_PROCESS",
    );
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "crash_endpoint: DETACH_PROCESS with the authority"
    );
    assert_eq!(
        exception_badge(parked, "after DETACH_PROCESS"),
        Some(crash_badge),
        "crash_endpoint: DETACH_PROCESS restores the crash badge"
    );
    upcall_unbound("DETACH_PROCESS");

    let debugger = Registrant::spawn();
    let reply = call(
        authority,
        &IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
            .word(0, process)
            .word(1, 0)
            .cap(debugger.thread)
            .build(),
        "ATTACH_PROCESS with a watch",
    );
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "crash_endpoint: an attach with a watch"
    );
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    bind();
    debugger.end();
    // The request wakes procmgr's loop, whose pass finds the watch gone
    // before it serves the request.
    let _ = listed_name(authority, process);
    assert_eq!(
        exception_badge(parked, "after the watch's exit"),
        Some(crash_badge),
        "crash_endpoint: the debugger's death restores the crash badge"
    );
    upcall_unbound("the debugger's death");
    let _ = syscall::cap_delete(send);
    let _ = syscall::cap_delete(endpoint);
}

/// How long the phase waits, at most, for a child to act on a step.
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Drive `crashme debugger-tag`, as a debugger that binds its main thread
/// under the debugger tag (`procmgr_labels::DEBUGGER_BADGE_TAG`): first with
/// no debugger watched, so the thread the child then spawns, which copies
/// that binding, is bound back to the crash endpoint at its registration;
/// then attached with a watch, after which the child declares itself
/// undebuggable, which unbinds the debugger's bindings, and the watch's end
/// binds nothing back. The child checks its side and exits 0 when it holds.
fn debugger_tag_check(authority: u64)
{
    use std::io::{BufRead, BufReader, Write};

    let mut child = Command::new("/programs/crashme")
        .arg("debugger-tag")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("crash_endpoint: spawning crashme debugger-tag");
    let main = child.main_thread_cap();
    let mut steps = child
        .stdin
        .take()
        .expect("crash_endpoint: the child's stdin");
    let mut report = BufReader::new(
        child
            .stdout
            .take()
            .expect("crash_endpoint: the child's stdout"),
    );
    let mut line = String::new();
    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .expect("crash_endpoint: a debugger endpoint");
    let send = syscall::cap_derive_badge(endpoint, syscall::RIGHTS_EP_SEND, DEBUGGER_BADGE)
        .expect("crash_endpoint: a debugger SEND");
    let bind = || {
        syscall::thread_set_fault_handler(main, send, FAULT_CLASS_EXCEPTION | FAULT_CLASS_UPCALL)
            .expect("crash_endpoint: binding the child's main thread");
    };

    // No debugger is watched for the child: its next thread registers with
    // a gone debugger's binding.
    bind();
    writeln!(steps).expect("crash_endpoint: the first step");
    // The child's report of the first step: its thread has registered, before
    // the attach below watches a debugger.
    report
        .read_line(&mut line)
        .expect("crash_endpoint: the child's first report");
    assert!(
        line.contains("took the binding back: true"),
        "crash_endpoint: a registration with a gone debugger's binding: {line}"
    );

    let process = badge_named(authority, b"/programs/crashme")
        .expect("crash_endpoint: LIST_PROCESSES lists crashme debugger-tag");
    let debugger = Registrant::spawn();
    let reply = call(
        authority,
        &IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
            .word(0, process)
            .word(1, 0)
            .cap(debugger.thread)
            .build(),
        "ATTACH_PROCESS of crashme debugger-tag",
    );
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "crash_endpoint: an attach with a watch to crashme debugger-tag"
    );
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    bind();
    writeln!(steps).expect("crash_endpoint: the second step");
    let start = Instant::now();
    while exception_badge(main, "the declaring child").is_some()
    {
        assert!(
            start.elapsed() < STEP_TIMEOUT,
            "crash_endpoint: the declaration left the debugger's binding"
        );
        let _ = syscall::thread_yield();
    }
    debugger.end();
    // The request wakes procmgr's loop, whose pass finds the watch gone,
    // had the declaration left it, before it serves the request.
    let _ = listed_name(authority, process);
    assert_eq!(
        exception_badge(main, "after the watch's end"),
        None,
        "crash_endpoint: a declared process was bound back when its debugger's watch ended"
    );
    drop(steps);
    line.clear();
    let _ = report.read_line(&mut line);
    assert!(
        line.contains("unbound the debugger: true"),
        "crash_endpoint: the declaration while a debugger is attached: {line}"
    );
    let status = child
        .wait()
        .expect("crash_endpoint: waiting for crashme debugger-tag");
    assert!(
        status.success(),
        "crash_endpoint: crashme debugger-tag exited {status}"
    );
    let _ = syscall::cap_delete(send);
    let _ = syscall::cap_delete(endpoint);
}

/// svctest declared itself undebuggable, so procmgr refuses to register a
/// thread of it (`REGISTER_THREAD`, `NOT_ATTACHABLE`), as its runtime's
/// first registration found, and first unbinds the thread as the declaration
/// unbinds a declared process's threads: a helper thread bound under the
/// debugger tag comes back unbound.
fn expect_registration_refused()
{
    let (cap_tx, cap_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let helper = std::thread::spawn(move || {
        cap_tx
            .send(std::os::seraph::thread::current_thread_cap())
            .expect("crash_endpoint: publishing the helper's cap");
        let _ = release_rx.recv();
    });
    let own = cap_rx.recv().expect("crash_endpoint: the helper's cap");
    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .expect("crash_endpoint: a debugger endpoint");
    let send = syscall::cap_derive_badge(endpoint, syscall::RIGHTS_EP_SEND, DEBUGGER_BADGE)
        .expect("crash_endpoint: a debugger SEND");
    syscall::thread_set_fault_handler(own, send, FAULT_CLASS_EXCEPTION | FAULT_CLASS_UPCALL)
        .expect("crash_endpoint: binding the helper under the debugger tag");
    let thread = syscall::cap_derive(own, RIGHTS_THREAD)
        .expect("crash_endpoint: deriving a thread cap to register");
    let procmgr = std::os::seraph::startup_info().procmgr_endpoint;
    let reply = call(
        procmgr,
        &IpcMessage::builder(procmgr_labels::REGISTER_THREAD)
            .cap(thread)
            .build(),
        "REGISTER_THREAD",
    );
    assert_eq!(
        reply.label,
        procmgr_errors::NOT_ATTACHABLE,
        "crash_endpoint: a registration from a process that declared no-debug"
    );
    assert_eq!(
        (
            exception_badge(own, "the refused helper"),
            class_badge(own, FAULT_CLASS_UPCALL, "the refused helper")
        ),
        (None, None),
        "crash_endpoint: a refused registration of a declared process left a debugger's binding"
    );
    let _ = release.send(());
    helper.join().expect("crash_endpoint: joining the helper");
    let _ = syscall::cap_delete(send);
    let _ = syscall::cap_delete(endpoint);
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
    take_child_fault(endpoint, authority, &child, ChildFault::MainVm);
    expect_fault_death(child, "while registered");
    let child = crashme("registry-main");
    take_child_fault(endpoint, authority, &child, ChildFault::RegistryMain);
    expect_fault_death(child, "registry-main");
    let child = crashme("registry-worker");
    take_child_fault(endpoint, authority, &child, ChildFault::RegistryWorker);
    expect_fault_death(child, "registry-worker");
    debugger_tag_check(authority);
    expect_registration_refused();

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
