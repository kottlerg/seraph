// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/crash.rs

//! The crash endpoint: the exception-class handler endpoint of every process
//! procmgr creates, until the process declares itself undebuggable
//! (`DECLARE_NO_DEBUG`), and who receives on it.
//!
//! procmgr creates the endpoint at startup and binds each such process's
//! main thread to it at creation, badged with the process badge; the runtime
//! copies the binding onto every thread the process spawns. While no crash
//! service is registered, procmgr's decliner thread receives on it and
//! declines every fault, so a fault takes the outcome it has with no handler.
//! A crash service that registers (`REGISTER_CRASH_SERVICE`) receives a
//! `RECV` cap on it, and the decliner parks; when that service dies, the
//! decliner receives again, faults already queued included
//! (`services/procmgr/docs/ipc-interface.md` § `REGISTER_CRASH_SERVICE`).
//!
//! The decliner is a thread of its own so that a receive on the endpoint
//! never waits behind procmgr's request loop. It shares nothing with that
//! loop but the atomics below, and makes no request of procmgr.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall_abi::{FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL};

/// The crash endpoint (procmgr's full cap on it); 0 when it could not be
/// created, and no process is then bound to it.
static ENDPOINT: AtomicU64 = AtomicU64::new(0);

/// The decliner thread's Thread cap; 0 until it publishes it.
static DECLINER: AtomicU64 = AtomicU64::new(0);

/// The notification the parked decliner waits on.
static WAKE: AtomicU64 = AtomicU64::new(0);

/// Whether a crash service holds the receive side.
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Where the decliner is in its loop, which the handover reads after
/// stopping it.
static PHASE: AtomicU8 = AtomicU8::new(PHASE_IDLE);

/// Between iterations, holding no fault.
const PHASE_IDLE: u8 = 0;
/// About to receive, or blocked receiving: holding no fault.
const PHASE_RECEIVING: u8 = 1;
/// Holding a received fault until its reply.
const PHASE_HOLDING: u8 = 2;
/// Waiting on [`WAKE`] while a crash service is registered.
const PHASE_PARKED: u8 = 3;

/// The crash endpoint, 0 when there is none.
pub fn endpoint() -> u64
{
    ENDPOINT.load(Ordering::Acquire)
}

/// Create the crash endpoint and start the decliner on it. A failure leaves
/// no endpoint, and processes are then created with their exception class
/// unbound, as before the endpoint existed; it is logged.
pub fn start()
{
    let Some(ep) =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |s| {
            syscall::cap_create_endpoint(s).ok()
        })
    else
    {
        std::os::seraph::log!("crash endpoint not created; exceptions stay unbound");
        return;
    };
    let Some(wake) =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |s| {
            syscall::cap_create_notification(s).ok()
        })
    else
    {
        let _ = syscall::cap_delete(ep);
        std::os::seraph::log!("crash wake notification not created; exceptions stay unbound");
        return;
    };
    WAKE.store(wake, Ordering::Release);
    if std::thread::Builder::new()
        .name("crash-decliner".into())
        .spawn(move || decline_loop(ep))
        .is_err()
    {
        let _ = syscall::cap_delete(ep);
        std::os::seraph::log!("crash decliner not started; exceptions stay unbound");
        return;
    }
    // Published only once a receiver exists, so no process is bound to an
    // endpoint nobody serves.
    ENDPOINT.store(ep, Ordering::Release);
}

/// The decliner: receive each fault on the crash endpoint and decline it,
/// while no crash service is registered; park while one is.
fn decline_loop(ep: u64) -> !
{
    DECLINER.store(
        std::os::seraph::thread::current_thread_cap(),
        Ordering::Release,
    );
    let ipc_buf = std::os::seraph::current_ipc_buf();
    loop
    {
        PHASE.store(PHASE_IDLE, Ordering::Release);
        if REGISTERED.load(Ordering::Acquire)
        {
            PHASE.store(PHASE_PARKED, Ordering::Release);
            let _ = syscall::notification_wait(WAKE.load(Ordering::Acquire));
            continue;
        }
        PHASE.store(PHASE_RECEIVING, Ordering::Release);
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(ep, ipc_buf) })
        else
        {
            // A stop of this thread cancels the receive (`Interrupted`).
            continue;
        };
        PHASE.store(PHASE_HOLDING, Ordering::Release);
        if msg.label == FAULT_LABEL
        {
            decline(&msg, ipc_buf);
        }
    }
}

/// Decline the fault `msg`, as if no handler were bound: a forwarded
/// virtual-memory fault with the pager's reason, which the kernel prints as
/// it did when the pager declined it, and an exception with no reason.
fn decline(msg: &IpcMessage, ipc_buf: *mut u64)
{
    let forwarded = msg.word(0) == FAULT_KIND_VM && msg.word_count() > FAULT_FORWARD_REASON_WORD;
    let reply = if forwarded
    {
        IpcMessage::builder(FAULT_REPLY_KILL)
            .word(0, msg.word(FAULT_FORWARD_REASON_WORD))
            .build()
    }
    else
    {
        IpcMessage::new(FAULT_REPLY_KILL)
    };
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// The registered crash service's Thread cap, in procmgr's `CSpace`; 0 while
/// none is registered. Written only by procmgr's request loop.
static REGISTRANT: AtomicU64 = AtomicU64::new(0);

/// Why [`register`] refuses a crash service.
pub enum RegisterRefusal
{
    /// No crash endpoint exists, or no thread cap came with the request.
    NoEndpointOrThread,
    /// A registered crash service still lives.
    Present,
    /// The `RECV` cap for the service could not be derived.
    OutOfSlots,
}

/// Register the crash service whose main thread `thread_cap` names (moved
/// into procmgr's `CSpace` by the request): returns the `RECV` cap on the
/// crash endpoint to reply with, after the receive side is handed over.
/// `thread_cap` is kept to tell when the service is gone
/// ([`check_registrant`]); on a refusal it is deleted.
///
/// # Errors
/// The [`RegisterRefusal`] that refuses it.
pub fn register(thread_cap: u64) -> Result<u64, RegisterRefusal>
{
    let ep = endpoint();
    if ep == 0 || thread_cap == 0
    {
        delete_nonzero(thread_cap);
        return Err(RegisterRefusal::NoEndpointOrThread);
    }
    check_registrant();
    if registered()
    {
        delete_nonzero(thread_cap);
        return Err(RegisterRefusal::Present);
    }
    let Ok(recv) = syscall::cap_derive(ep, syscall_abi::RIGHTS_EP_RECEIVE)
    else
    {
        delete_nonzero(thread_cap);
        return Err(RegisterRefusal::OutOfSlots);
    };
    REGISTRANT.store(thread_cap, Ordering::Release);
    hand_over();
    Ok(recv)
}

/// Take the receive side back when the registered crash service is gone:
/// its thread cap revoked (procmgr's teardown of the service revokes every
/// cap derived from its main thread) or its thread exited. procmgr's loop
/// calls it after every death drain, which the service's death wakes.
pub fn check_registrant()
{
    let thread = REGISTRANT.load(Ordering::Acquire);
    if thread == 0
    {
        return;
    }
    let gone = match syscall::cap_info(thread, syscall_abi::CAP_INFO_THREAD_STATE)
    {
        Ok(packed) => (packed >> 32) as u32 == syscall_abi::THREAD_STATE_EXITED,
        Err(_) => true,
    };
    if gone
    {
        REGISTRANT.store(0, Ordering::Release);
        let _ = syscall::cap_delete(thread);
        take_back();
        std::os::seraph::log!("crash service gone; declining faults again");
    }
}

fn delete_nonzero(cap: u64)
{
    if cap != 0
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Whether a registered crash service holds the receive side.
pub fn registered() -> bool
{
    REGISTERED.load(Ordering::Acquire)
}

/// Hand the receive side to a crash service: mark it registered and stop
/// the decliner where it holds no fault. A decliner found holding one is
/// started again to decline it, and stopped again after; a parked one is
/// started again to park. Returns once the decliner neither receives nor
/// holds a fault.
fn hand_over()
{
    REGISTERED.store(true, Ordering::Release);
    let decliner = DECLINER.load(Ordering::Acquire);
    if decliner == 0
    {
        return;
    }
    loop
    {
        // The stop returns once the decliner has left its CPU, so the phase
        // read after it is the one it stopped in; a receive it was blocked in
        // is cancelled and has taken no fault.
        let _ = syscall::thread_stop(decliner);
        match PHASE.load(Ordering::Acquire)
        {
            // Stopped before or inside its receive: it stays stopped,
            // holding nothing, until [`take_back`] starts it.
            PHASE_RECEIVING => return,
            // Parked, or between iterations: run on, to park.
            PHASE_PARKED =>
            {
                let _ = syscall::thread_start(decliner);
                return;
            }
            // Holding a fault, or between its reply and its flag check: let
            // it decline the fault and reach its park.
            _ =>
            {
                let _ = syscall::thread_start(decliner);
                std::thread::yield_now();
            }
        }
    }
}

/// Take the receive side back from a crash service that died: the decliner
/// receives again, and declines the faults queued for the dead service.
fn take_back()
{
    REGISTERED.store(false, Ordering::Release);
    let _ = syscall::notification_send(WAKE.load(Ordering::Acquire), 1);
    let decliner = DECLINER.load(Ordering::Acquire);
    if decliner != 0
    {
        // A decliner stopped in its receive resumes it; a running one
        // refuses the start, harmlessly.
        let _ = syscall::thread_start(decliner);
    }
}
