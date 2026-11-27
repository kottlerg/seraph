// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/program-modes/src/deadline.rs

//! Deadline-cancel fixture: a supervisor bounds a worker's computation with
//! an asynchronous upcall (docs/fault-handling.md § Asynchronous Upcalls).
//!
//! The worker spins in a computation that makes no syscall and never ends.
//! The supervisor (the main thread) binds the worker's upcall class to an
//! endpoint of its own, lets the worker run past a deadline, and posts it an
//! upcall with `UPCALL_ANY_INSTRUCTION`, which reaches the spinning worker at
//! an interrupt's return. The supervisor receives the upcall, redirects the
//! worker's instruction pointer into a cancellation routine, and resumes it;
//! the routine marks the computation cancelled and ends the worker.
//!
//! The main thread then bounds blocking calls by a call deadline
//! (`std::os::seraph::with_call_deadline`): a runtime call and a call of the
//! fixture's own, each on an endpoint nobody receives on, end `TimedOut` and
//! `WouldBlock` at the deadline, a later deadline nested inside does not
//! extend it, and a call under a deadline already passed is not sent. A
//! spawn whose child is given bootstrap caps it never asks for
//! (`CommandExt::bootstrap_caps`) ends `TimedOut` at the deadline and
//! releases the caps, and the fixture, spawned with none, holds no creator
//! endpoint. The fixture prints `PASS` once both parts hold.
//!
//! Driven by `services/svctest`'s `deadline` phase.

#![expect(
    clippy::expect_used,
    reason = "a test fixture, where unwrap and expect are permitted (docs/coding-standards.md § \
              Error Handling): a failed step must abort the fixture, and the panic's non-zero exit \
              is its FAIL verdict for the phase"
)]

use std::io::ErrorKind;
use std::os::seraph::process::CommandExt;
use std::os::seraph::{call_time_left, startup_info, with_call_deadline};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ipc::IpcMessage;
use syscall_abi::{
    FAULT_CLASS_UPCALL, FAULT_KIND_UPCALL, FAULT_LABEL, FAULT_REPLY_RESUME, SyscallError,
    UPCALL_ANY_INSTRUCTION, UPCALL_POINT_INTERRUPT,
};

/// How long the worker computes before the supervisor cancels it.
const DEADLINE: Duration = Duration::from_millis(50);

/// The call deadline's bound, from just before the bounded call.
const CALL_BOUND: Duration = Duration::from_millis(100);

/// The least a bounded call waits: half its bound, which leaves the kernel's
/// timer a tick of slack and still tells a call that waited from one that
/// failed at once.
const CALL_WAIT_MIN: Duration = Duration::from_millis(50);

/// The most a bounded call may take: past it the deadline did not end the
/// call, which would otherwise wait for good.
const CALL_WAIT_MAX: Duration = Duration::from_secs(5);

/// The call deadline of a spawn whose child never asks for its bootstrap
/// caps: long enough for the create and start calls before the serve, so the
/// serve is what the deadline ends.
const SPAWN_BOUND: Duration = Duration::from_secs(2);

/// The least such a spawn waits: half [`SPAWN_BOUND`], as [`CALL_WAIT_MIN`]
/// is of [`CALL_BOUND`].
const SPAWN_WAIT_MIN: Duration = Duration::from_secs(1);

/// The cookie the supervisor posts, read back from the upcall message.
const COOKIE: u64 = 0xDEAD_11E0;

/// Register-file buffer, large enough for either architecture's.
const REGS_BYTES: usize = 512;

/// The worker's own Thread cap, published once it runs.
static WORKER: AtomicU64 = AtomicU64::new(0);

/// The worker's computation progress.
static SPINS: AtomicU64 = AtomicU64::new(0);

/// Set by the cancellation routine.
static CANCELLED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
mod arch
{
    pub const IP: usize = syscall_abi::REGS_X86_64_IP_OFFSET;
    pub const SP: usize = syscall_abi::REGS_X86_64_SP_OFFSET;

    /// The stack pointer at a function's entry, as if called: 16-byte aligned
    /// before the return address the call would push.
    pub fn entry_sp(sp: u64) -> u64
    {
        (sp & !0xF)
            .checked_sub(8)
            .expect("the worker's stack pointer leaves room for a return address")
    }
}

#[cfg(target_arch = "riscv64")]
mod arch
{
    pub const IP: usize = syscall_abi::REGS_RISCV64_IP_OFFSET;
    pub const SP: usize = syscall_abi::REGS_RISCV64_SP_OFFSET;

    /// The stack pointer at a function's entry: 16-byte aligned.
    pub fn entry_sp(sp: u64) -> u64
    {
        sp & !0xF
    }
}

/// The mode of this fixture in its binary (`crate::PATH`), the first argument
/// of the idle child it spawns.
const MODE: &str = "deadline";

/// The argument that runs the fixture as the idle child [`call_deadline`]
/// kills.
const IDLE_ARG: &str = "idle";

pub fn main()
{
    if std::env::args().nth(2).as_deref() == Some(IDLE_ARG)
    {
        idle();
    }
    // Defect guarded: a child spawned without bootstrap caps handed a creator
    // endpoint all the same.
    assert_eq!(
        startup_info().creator_endpoint,
        0,
        "the fixture, spawned with no bootstrap caps, holds a creator endpoint"
    );
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let ep = std::os::seraph::create_endpoint().expect("create the upcall endpoint");

    let _worker = std::thread::spawn(|| {
        WORKER.store(
            std::os::seraph::thread::current_thread_cap(),
            Ordering::Release,
        );
        #[expect(
            clippy::infinite_loop,
            reason = "the worker spins until the process exits, and a `thread::spawn` closure \
                      returns a value type, not `!`"
        )]
        loop
        {
            SPINS.fetch_add(1, Ordering::Relaxed);
            core::hint::spin_loop();
        }
    });
    while WORKER.load(Ordering::Acquire) == 0 || SPINS.load(Ordering::Relaxed) == 0
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    let worker = WORKER.load(Ordering::Acquire);
    syscall::thread_set_fault_handler(worker, ep, FAULT_CLASS_UPCALL)
        .expect("bind the worker's upcall class");

    std::thread::sleep(DEADLINE);
    syscall::thread_post_upcall(worker, COOKIE, UPCALL_ANY_INSTRUCTION)
        .expect("post the deadline upcall");

    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("receive the upcall");
    assert!(
        msg.label == FAULT_LABEL
            && msg.word(0) == FAULT_KIND_UPCALL
            && msg.word(1) == COOKIE
            && msg.word(2) == UPCALL_POINT_INTERRUPT,
        "unexpected upcall message"
    );

    let mut regs = [0u8; REGS_BYTES];
    syscall::thread_read_regs(worker, &mut regs).expect("read the worker's registers");
    let mut word = [0u8; 8];
    word.copy_from_slice(&regs[arch::SP..arch::SP + 8]);
    let sp = arch::entry_sp(u64::from_le_bytes(word));
    regs[arch::SP..arch::SP + 8].copy_from_slice(&sp.to_le_bytes());
    let entry = cancelled as *const () as u64;
    regs[arch::IP..arch::IP + 8].copy_from_slice(&entry.to_le_bytes());
    // SAFETY: the frame was read from the worker, upcall-blocked, so its stack
    // pointer lies on the worker's own stack, moved down to the entry ABI's
    // alignment; `cancelled` is an `extern "C"` entry that never returns.
    unsafe { syscall::thread_write_regs(worker, &regs) }.expect("redirect the worker");
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ipc_buf) }
        .expect("resume the worker");

    while !CANCELLED.load(Ordering::Acquire)
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    let at_cancel = SPINS.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        SPINS.load(Ordering::Relaxed),
        at_cancel,
        "the worker kept computing after its cancellation"
    );
    println!("deadline: worker cancelled after {at_cancel} spins");

    call_deadline(ipc_buf);
    println!("PASS");
}

/// The idle child: wait to be killed.
fn idle() -> !
{
    loop
    {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The instant `after` from `start`.
fn at(start: Instant, after: Duration) -> Instant
{
    start
        .checked_add(after)
        .expect("the deadline fits an Instant")
}

/// Bound calls on an endpoint nobody receives on, which never answers, by a
/// call deadline: a runtime call fails `TimedOut` and the fixture's own call
/// `WouldBlock`, each after waiting about [`CALL_BOUND`]; a later deadline
/// nested inside does not extend the scope; a call under a deadline already
/// passed is not sent, `Child::kill` among them; and no deadline is left
/// once the scope ends.
fn call_deadline(ipc_buf: *mut u64)
{
    let ep = std::os::seraph::create_endpoint().expect("create the endpoint nobody receives on");

    let start = Instant::now();
    let looked_up = with_call_deadline(at(start, CALL_BOUND), || {
        with_call_deadline(at(start, CALL_WAIT_MAX), || {
            std::os::seraph::namespace_lookup_file(ep, "x")
        })
    });
    let waited = start.elapsed();
    let err = looked_up.expect_err("a lookup on an endpoint nobody receives on was answered");
    assert_eq!(
        err.kind(),
        ErrorKind::TimedOut,
        "the bounded runtime call failed {err}"
    );
    assert!(
        (CALL_WAIT_MIN..CALL_WAIT_MAX).contains(&waited),
        "the bounded runtime call ended after {waited:?}, not at its deadline"
    );
    assert!(
        call_time_left().is_none(),
        "a call deadline outlived its scope"
    );

    let own_start = Instant::now();
    let called = with_call_deadline(at(own_start, CALL_BOUND), || {
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        unsafe { ipc::ipc_call_within(ep, &IpcMessage::new(0), ipc_buf, call_time_left()) }
    });
    let own_waited = own_start.elapsed();
    assert!(
        matches!(called, Err(e) if e == SyscallError::WouldBlock as i64),
        "the bounded call did not end WouldBlock"
    );
    assert!(
        (CALL_WAIT_MIN..CALL_WAIT_MAX).contains(&own_waited),
        "the bounded call ended after {own_waited:?}, not at its deadline"
    );

    let passed_start = Instant::now();
    let refused = with_call_deadline(passed_start, || {
        std::os::seraph::namespace_lookup_file(ep, "x")
    });
    let passed_waited = passed_start.elapsed();
    let mut child = std::process::Command::new(crate::PATH)
        .args([MODE, IDLE_ARG])
        .spawn()
        .expect("spawn the idle child");
    let kill_err = with_call_deadline(Instant::now(), || child.kill())
        .expect_err("a kill under a passed deadline was sent");
    assert_eq!(
        kill_err.kind(),
        ErrorKind::TimedOut,
        "the kill under a passed deadline failed {kill_err}"
    );
    child.kill().expect("kill the idle child");
    child.wait().expect("wait for the idle child");
    let spawn_waited = bootstrap_deadline(ep);
    let err = refused.expect_err("a lookup under a passed deadline was answered");
    assert_eq!(
        err.kind(),
        ErrorKind::TimedOut,
        "the call under a passed deadline failed {err}"
    );
    assert!(
        passed_waited < CALL_WAIT_MIN,
        "a call under a passed deadline waited {passed_waited:?}"
    );
    println!(
        "deadline: a call deadline ended a runtime call after {} ms, a call of the \
         fixture's after {} ms, and a bootstrap serve after {} ms",
        waited.as_millis(),
        own_waited.as_millis(),
        spawn_waited.as_millis()
    );
}

/// Spawn the idle child, which never asks for its bootstrap caps, with a copy
/// of `ep` as its one cap, under a call deadline [`SPAWN_BOUND`] ahead: the
/// spawn fails `TimedOut` at the deadline, having torn the child down, and
/// the copy it did not deliver is deleted. Returns how long the spawn took.
fn bootstrap_deadline(ep: u64) -> Duration
{
    let cap = syscall::cap_copy(ep, startup_info().self_cspace, syscall::RIGHTS_EP_SEND)
        .expect("copy the endpoint to hand the idle child");
    let start = Instant::now();
    let spawned = with_call_deadline(at(start, SPAWN_BOUND), || {
        std::process::Command::new(crate::PATH)
            .args([MODE, IDLE_ARG])
            .bootstrap_caps(&[cap])
            .spawn()
    });
    let waited = start.elapsed();
    let err = spawned.expect_err("a child that never asked for its bootstrap caps was spawned");
    assert_eq!(
        err.kind(),
        ErrorKind::TimedOut,
        "the spawn whose child never asked failed {err}"
    );
    assert!(
        (SPAWN_WAIT_MIN..CALL_WAIT_MAX).contains(&waited),
        "the spawn whose child never asked ended after {waited:?}, not at its deadline"
    );
    assert!(
        syscall::cap_info(cap, syscall_abi::CAP_INFO_TAG_RIGHTS).is_err(),
        "the bootstrap cap the spawn did not deliver was not deleted"
    );
    waited
}

/// The cancellation routine the supervisor redirects the worker into: mark the
/// computation cancelled and end the worker thread.
extern "C" fn cancelled() -> !
{
    CANCELLED.store(true, Ordering::Release);
    syscall::thread_exit()
}
