// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/crashme/src/main.rs

//! Test fixture that dies on a fault on purpose, for the crash report its
//! death leaves in the system log.
//!
//! `crashme vm` writes to the null page, a page fault memmgr cannot back;
//! `crashme exception` executes an illegal instruction. `crashme worker`
//! dies of the illegal instruction on a spawned thread while a sibling is
//! held fault-blocked at the same instruction, so the report must tell the
//! two apart. `crashme registry-main` and `crashme registry-worker` fault on
//! the main thread and on a spawned one with threads registered, parked,
//! exited, and joined around them, for svctest's attach checks. Each first
//! logs under the log name `crashme`, so logd's reclaim line at its death
//! names it, and reaches the fault two calls deep, so the report's stack walk
//! has frames to find. `crashme registry-declare` does not fault: it checks
//! that declaring itself undebuggable unbinds a registered thread's crash
//! binding as well as the main thread's, and exits 0 when it does. See
//! programs/crashme/README.md.

mod arch;

use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use syscall_abi::{
    CAP_INFO_THREAD_STATE, FAULT_CLASS_EXCEPTION, RIGHTS_THREAD_OBSERVE, THREAD_STATE_EXITED,
};

/// The fault the fixture dies of.
#[derive(Clone, Copy)]
enum Mode
{
    /// A write to the null page.
    Vm,
    /// An illegal instruction.
    Exception,
}

/// Parked threads `worker` spawns before its faulting thread, so the
/// faulting thread's index in procmgr's attach list lies past the first
/// page of `ipc::procmgr_labels::ATTACH_THREADS_PAGE` caps.
const WORKER_PARKED: usize = ipc::procmgr_labels::ATTACH_THREADS_PAGE;

/// How long the fixture waits, at most, for a thread it let exit to finish
/// exiting.
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

fn main()
{
    std::os::seraph::log::register_name(b"crashme");
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str()
    {
        "vm" => fault_here(&arg, Mode::Vm),
        "exception" => fault_here(&arg, Mode::Exception),
        "worker" => worker(&arg),
        "registry-main" => registry_main(&arg),
        "registry-worker" => registry_worker(&arg),
        "registry-declare" => registry_declare(),
        _ =>
        {
            println!(
                "usage: crashme vm|exception|worker|registry-main|registry-worker|registry-declare"
            );
            std::process::exit(2);
        }
    }
}

/// Announce the fault on the log and stdout, then take it as `mode` says.
fn fault_here(arg: &str, mode: Mode) -> !
{
    std::os::seraph::log!("faulting ({arg})");
    println!("faulting ({arg})");
    outer(mode);
}

/// A thread parked until its sender drops or sends.
fn park() -> (mpsc::Sender<()>, JoinHandle<()>)
{
    let (tx, rx) = mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let _ = rx.recv();
    });
    (tx, handle)
}

/// Fault on a spawned thread while another is fault-blocked at the same
/// instruction: a holder thread receives the first worker's fault on an
/// endpoint the main thread bound its exception class to, and keeps it
/// unanswered; the second worker's fault, past `WORKER_PARKED` parked
/// threads, reaches the crash service.
fn worker(arg: &str)
{
    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |s| {
            syscall::cap_create_endpoint(s).ok()
        })
        .unwrap_or_else(|| fail("worker: no endpoint"));
    let (held_tx, held_rx) = mpsc::channel::<()>();
    let _holder = std::thread::spawn(move || hold_one_fault(endpoint, &held_tx));

    let (cap_tx, cap_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let _first = std::thread::spawn(move || {
        let _ = cap_tx.send(std::os::seraph::thread::current_thread_cap());
        let _ = go_rx.recv();
        outer(Mode::Exception);
    });
    let first = cap_rx
        .recv()
        .unwrap_or_else(|_| fail("worker: no thread cap"));
    if syscall::thread_set_fault_handler(first, endpoint, FAULT_CLASS_EXCEPTION).is_err()
    {
        fail("worker: binding the first worker's exception class");
    }
    let _ = go_tx.send(());
    held_rx
        .recv()
        .unwrap_or_else(|_| fail("worker: the first worker's fault was not held"));

    let parked: Vec<_> = (0..WORKER_PARKED).map(|_| park()).collect();
    std::os::seraph::log!("faulting ({arg})");
    println!("faulting ({arg})");
    let second = std::thread::spawn(|| {
        outer(Mode::Exception);
    });
    let _ = second.join();
    drop(parked);
}

/// Receive one fault on `endpoint`, tell the main thread, and never answer
/// it, so its thread stays fault-blocked until the process dies. The thread
/// receives nothing more, which would cancel the held fault.
fn hold_one_fault(endpoint: u64, held: &mpsc::Sender<()>) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    if unsafe { ipc::ipc_recv(endpoint, ipc_buf) }.is_ok()
    {
        let _ = held.send(());
    }
    loop
    {
        std::thread::park();
    }
}

/// Fault on the main thread with two parked threads registered and a
/// detached one exited, which the attach must not list.
fn registry_main(arg: &str)
{
    let parked = [park(), park()];
    let (watch_tx, watch_rx) = mpsc::channel();
    drop(std::thread::spawn(move || {
        let own = std::os::seraph::thread::current_thread_cap();
        let _ = watch_tx.send(syscall::cap_derive(own, RIGHTS_THREAD_OBSERVE).ok());
    }));
    let watch = watch_rx
        .recv()
        .ok()
        .flatten()
        .unwrap_or_else(|| fail("registry-main: no watch cap on the detached thread"));
    wait_gone(watch);
    let _keep = parked;
    fault_here(arg, Mode::Exception);
}

/// Wait until the thread `watch` observes has exited, or the cap is gone
/// (the reaper's reclaim revokes it), at most [`EXIT_TIMEOUT`].
fn wait_gone(watch: u64)
{
    let start = Instant::now();
    while syscall::cap_info(watch, CAP_INFO_THREAD_STATE)
        .is_ok_and(|packed| (packed >> 32) as u32 != THREAD_STATE_EXITED)
    {
        if start.elapsed() > EXIT_TIMEOUT
        {
            fail("a detached thread did not exit");
        }
        let _ = syscall::thread_yield();
    }
}

/// Check that `DECLARE_NO_DEBUG` unbinds a registered thread's crash
/// binding, which procmgr made under a badge of the thread's own, with the
/// main thread's. Exits 0 when it does, 1 when it does not.
fn registry_declare()
{
    let (cap_tx, cap_rx) = mpsc::channel();
    let (stop, parked) = mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        let _ = cap_tx.send(std::os::seraph::thread::current_thread_cap());
        let _ = parked.recv();
    });
    let thread = cap_rx
        .recv()
        .unwrap_or_else(|_| fail("registry-declare: no thread cap"));
    let main = std::os::seraph::thread::current_thread_cap();
    let binding = |cap| {
        syscall::thread_get_fault_handler(cap, FAULT_CLASS_EXCEPTION)
            .ok()
            .flatten()
    };
    let (main_before, thread_before) = (binding(main), binding(thread));
    let procmgr = std::os::seraph::startup_info().procmgr_endpoint;
    // SAFETY: the main thread's registered IPC buffer page.
    let declared = unsafe {
        ipc::ipc_call(
            procmgr,
            &IpcMessage::new(procmgr_labels::DECLARE_NO_DEBUG),
            std::os::seraph::current_ipc_buf(),
        )
    }
    .is_ok_and(|r| r.label == procmgr_errors::SUCCESS);
    let (main_after, thread_after) = (binding(main), binding(thread));
    let _ = stop.send(());
    let _ = worker.join();
    let pass = declared
        && main_before.is_some()
        && thread_before.is_some()
        && thread_before != main_before
        && main_after.is_none()
        && thread_after.is_none();
    println!(
        "registry-declare: {} (main {main_before:x?} -> {main_after:x?}, thread {thread_before:x?} \
         -> {thread_after:x?}, declared {declared})",
        if pass { "PASS" } else { "FAIL" }
    );
    std::process::exit(i32::from(!pass));
}

/// Fault on a spawned thread after joining its sibling, which the attach
/// must not list.
fn registry_worker(arg: &str)
{
    let (gone_tx, gone) = park();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let faulting = std::thread::spawn(move || {
        let _ = go_rx.recv();
        outer(Mode::Exception);
    });
    drop(gone_tx);
    let _ = gone.join();
    std::os::seraph::log!("faulting ({arg})");
    println!("faulting ({arg})");
    let _ = go_tx.send(());
    let _ = faulting.join();
}

/// Report a setup failure and exit with a code that is not a fault's.
fn fail(what: &str) -> !
{
    println!("crashme: {what}");
    std::process::exit(3);
}

/// The first of the two calls the fault happens under.
#[inline(never)]
fn outer(mode: Mode) -> !
{
    inner(std::hint::black_box(mode))
}

/// Fault as `mode` says.
#[inline(never)]
fn inner(mode: Mode) -> !
{
    if let Mode::Vm = mode
    {
        // SAFETY: deliberately invalid: the write faults, memmgr cannot back
        // the null page, and the thread dies before the write returns.
        unsafe {
            core::ptr::write_volatile(core::ptr::null_mut::<u64>(), 0x0BAD_C0DE);
        }
    }
    arch::current::illegal_instruction()
}
