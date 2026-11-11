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
//! `RECV` cap on it, and the decliner parks; when that service is gone, the
//! decliner receives again, faults already queued included
//! (`services/procmgr/docs/ipc-interface.md` § `REGISTER_CRASH_SERVICE`).
//!
//! The decliner is a thread of its own so that a receive on the endpoint
//! never waits behind procmgr's request workers. The handover is a message on
//! the endpoint itself: the worker serving the registration calls the
//! endpoint with [`PARK_LABEL`], which the decliner receives only after every
//! fault queued ahead of it, so it parks holding none. No stop is involved,
//! and no fault is ever left with a receiver that does not run.
//!
//! A registration, its undoing, and the check that takes the endpoint back
//! run on procmgr's request workers and on its reaper thread, so each holds
//! [`REGISTRATION`] throughout: two registrations cannot both find no
//! registrant, and a check cannot take back a registration whose park call
//! is still in flight.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use ipc::IpcMessage;
use syscall_abi::{FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL};

/// The label of the handover message a procmgr request worker sends the
/// decliner on the crash endpoint, un-badged. Every fault the kernel delivers
/// carries `FAULT_LABEL` and the badge of a process's binding, never zero, and
/// only procmgr holds a `SEND` on the endpoint, so nothing else carries it.
const PARK_LABEL: u64 = 0;

/// The crash endpoint (procmgr's full cap on it); 0 when it could not be
/// created, and no process is then bound to it.
static ENDPOINT: AtomicU64 = AtomicU64::new(0);

/// The notification the parked decliner waits on.
static WAKE: AtomicU64 = AtomicU64::new(0);

/// The registered crash service's Thread cap, in procmgr's `CSpace`; 0 while
/// none is registered. Written only under [`REGISTRATION`].
static REGISTRANT: AtomicU64 = AtomicU64::new(0);

/// Held by [`register`], [`unregister`] and [`check_registrant`] for their
/// whole run. [`register`] holds it across its park call to the decliner,
/// a lock held across an IPC call: the decliner, procmgr's own thread,
/// answers that call without taking any lock, so the call cannot wait on
/// the lock's holder.
static REGISTRATION: Mutex<()> = Mutex::new(());

fn lock_registration() -> MutexGuard<'static, ()>
{
    REGISTRATION.lock().unwrap_or_else(PoisonError::into_inner)
}

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
    if std::thread::Builder::new()
        .name("crash-decliner".into())
        .spawn(move || decline_loop(ep, wake))
        .is_err()
    {
        let _ = syscall::cap_delete(ep);
        let _ = syscall::cap_delete(wake);
        std::os::seraph::log!("crash decliner not started; exceptions stay unbound");
        return;
    }
    WAKE.store(wake, Ordering::Release);
    // Published only once a receiver exists, so no process is bound to an
    // endpoint nobody serves.
    ENDPOINT.store(ep, Ordering::Release);
}

/// The decliner: receive each fault on the crash endpoint and decline it;
/// on the handover message, answer it and park on `wake` until procmgr takes
/// the endpoint back.
fn decline_loop(ep: u64, wake: u64) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(ep, ipc_buf) })
        else
        {
            continue;
        };
        if msg.label == FAULT_LABEL
        {
            decline(&msg, ipc_buf);
            continue;
        }
        // The handover: answer it, then wait for the endpoint back. A wait
        // the kernel cancels is waited again; only `take_back`'s signal
        // ends it.
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(0), ipc_buf) };
        while !matches!(syscall::notification_wait(wake), Ok(bits) if bits != 0)
        {}
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

/// Why [`register`] refuses a crash service.
pub enum RegisterRefusal
{
    /// No crash endpoint exists, or no thread cap came with the request.
    NoEndpointOrThread,
    /// A registered crash service still lives.
    Present,
    /// The `RECV` cap for the service could not be derived, or the decliner
    /// could not be parked.
    OutOfSlots,
}

/// Register the crash service whose main thread `thread_cap` names (moved
/// into procmgr's `CSpace` by the request): park the decliner, then return
/// the `RECV` cap on the crash endpoint to reply with. `thread_cap` is kept
/// to tell when the service is gone ([`check_registrant`]); on a refusal it
/// is deleted. `ipc_buf` is the serving worker's IPC buffer: the handover is
/// a call on the endpoint, made while the request's own reply is pending,
/// which a downstream call leaves bound.
///
/// # Errors
/// The [`RegisterRefusal`] that refuses it.
pub fn register(thread_cap: u64, ipc_buf: *mut u64) -> Result<u64, RegisterRefusal>
{
    let ep = endpoint();
    if ep == 0 || thread_cap == 0
    {
        delete_nonzero(thread_cap);
        return Err(RegisterRefusal::NoEndpointOrThread);
    }
    let _registration = lock_registration();
    take_back_if_gone();
    if REGISTRANT.load(Ordering::Acquire) != 0
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
    // The decliner answers once it has declined every fault queued ahead of
    // the call, and then receives no more.
    // SAFETY: ipc_buf is the serving worker's registered IPC buffer page.
    if unsafe { ipc::ipc_call(ep, &IpcMessage::new(PARK_LABEL), ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(recv);
        delete_nonzero(thread_cap);
        return Err(RegisterRefusal::OutOfSlots);
    }
    REGISTRANT.store(thread_cap, Ordering::Release);
    Ok(recv)
}

/// Take the receive side back when the registered crash service is gone:
/// its thread cap revoked (procmgr's teardown of the service revokes every
/// cap derived from its main thread) or its thread exited. procmgr's reaper
/// calls it on every pass, which the service's death wakes, and the worker
/// that destroys a process calls it after the teardown.
pub fn check_registrant()
{
    let _registration = lock_registration();
    take_back_if_gone();
}

/// [`check_registrant`]'s check, under [`REGISTRATION`], which the caller
/// holds.
fn take_back_if_gone()
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
        take_back(thread);
        std::os::seraph::log!("crash service gone; declining faults again");
    }
}

/// Undo a registration whose `RECV` cap never reached the service (the
/// reply carrying it failed): forget the registrant and give the endpoint
/// back to the decliner, so no fault waits on a receiver that holds nothing.
pub fn unregister()
{
    let _registration = lock_registration();
    let thread = REGISTRANT.load(Ordering::Acquire);
    if thread != 0
    {
        take_back(thread);
    }
}

/// Forget the registrant `thread`, delete its cap, and wake the parked
/// decliner, which receives again, the faults queued for the service first.
/// The caller holds [`REGISTRATION`].
fn take_back(thread: u64)
{
    REGISTRANT.store(0, Ordering::Release);
    let _ = syscall::cap_delete(thread);
    let _ = syscall::notification_send(WAKE.load(Ordering::Acquire), 1);
}

fn delete_nonzero(cap: u64)
{
    if cap != 0
    {
        let _ = syscall::cap_delete(cap);
    }
}
