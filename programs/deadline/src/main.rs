// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/deadline/src/main.rs

//! Deadline-cancel fixture: a supervisor bounds a worker's computation with
//! an asynchronous upcall (docs/fault-handling.md § Asynchronous Upcalls).
//!
//! The worker spins in a computation that makes no syscall and never ends.
//! The supervisor (the main thread) binds the worker's upcall class to an
//! endpoint of its own, lets the worker run past a deadline, and posts it an
//! upcall with `UPCALL_ANY_INSTRUCTION`, which reaches the spinning worker at
//! an interrupt's return. The supervisor receives the upcall, redirects the
//! worker's instruction pointer into a cancellation routine, and resumes it;
//! the routine marks the computation cancelled and ends the worker. The
//! supervisor prints `PASS` once the worker is cancelled and has stopped
//! computing.
//!
//! Driven by its per-program tester (`tester/`), which `usertest` runs.

// Staged roll-out of these two lints: docs/coding-standards.md § Clippy.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// A test fixture, where unwrap and expect are permitted
// (docs/coding-standards.md § Error Handling): a failed step must abort the
// fixture, and the panic's non-zero exit is its FAIL verdict for the tester.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ipc::IpcMessage;
use syscall_abi::{
    FAULT_CLASS_UPCALL, FAULT_KIND_UPCALL, FAULT_LABEL, FAULT_REPLY_RESUME, UPCALL_ANY_INSTRUCTION,
    UPCALL_POINT_INTERRUPT,
};

/// How long the worker computes before the supervisor cancels it.
const DEADLINE: Duration = Duration::from_millis(50);

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

fn main()
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let ep = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .expect("create the upcall endpoint");

    let _worker = std::thread::spawn(|| {
        WORKER.store(
            std::os::seraph::thread::current_thread_cap(),
            Ordering::Release,
        );
        // infinite_loop: the worker spins until the process exits, and a
        // `thread::spawn` closure returns a value type, not `!`.
        #[expect(clippy::infinite_loop)]
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
    println!("PASS");
}

/// The cancellation routine the supervisor redirects the worker into: mark the
/// computation cancelled and end the worker thread.
extern "C" fn cancelled() -> !
{
    CANCELLED.store(true, Ordering::Release);
    syscall::thread_exit()
}
