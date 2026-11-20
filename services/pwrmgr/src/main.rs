// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/main.rs

//! Seraph power manager — userspace authority for platform shutdown and
//! reboot.
//!
//! pwrmgr is a svcmgr-launched provider. It owns the shutdown policy: on
//! x86-64 it reaches the ACPI sleep and reset registers through acpid, which
//! runs the AML and holds the FADT's register blocks, and holds one port
//! block of its own, for the core-death power-off below; on RISC-V it drives
//! SBI SRST through a `SbiControl` derivation it acquires from devmgr at
//! startup. svcmgr
//! publishes a `SHUTDOWN_AUTHORITY`-badged SEND (`pwrmgr.shutdown`) and its
//! no-auth twin (`pwrmgr.deny`) on pwrmgr's service endpoint; the recipes
//! that seed `pwrmgr.shutdown` hold the authority, and svcmgr calls it as
//! the shutdown actuator. On x86-64 a second thread waits on acpid for the
//! power button and powers the platform off when it is pressed.
//!
//! As the shutdown actuator pwrmgr also owns the death of the core set
//! (docs/supervision.md § Core Set and System Death): svcmgr serves it a
//! receive-only derivation of the core-death queue, which the death observers
//! of svcmgr's, memmgr's and procmgr's main threads and address spaces post
//! to, and pwrmgr waits on that queue beside its service endpoint. An entry
//! is a core death, and pwrmgr powers the platform off at once: svcmgr
//! creates it pinned, so it takes no page fault, and the power-off allocates
//! nothing ([`pwrmgr::guard`]), logs nothing and calls no service, so it
//! holds no matter which member died.
//!
//! See `services/pwrmgr/README.md` for the design and future-scope
//! sketch.

mod arch;
mod caps;

use ipc::{IpcMessage, pwrmgr_errors, pwrmgr_labels};
use pwrmgr::guard::AllocGuard;
use std::alloc::System;
use std::os::seraph::startup_info;
use std::time::Duration;

/// pwrmgr's allocator, guarded so the core-death power-off can check that it
/// allocates nothing ([`core_died`]).
#[global_allocator]
static ALLOCATOR: AllocGuard<System> = AllocGuard::new(System, thread_identity);

/// The calling thread's identity for [`ALLOCATOR`]: the address of its IPC
/// buffer, which each thread registers before it runs code of pwrmgr's and
/// which no two live threads share. Read from thread-local storage, so it
/// allocates nothing.
fn thread_identity() -> usize
{
    std::os::seraph::current_ipc_buf().addr()
}

/// How long pwrmgr waits after a power-off or reset request returns before
/// treating it as failed. A platform that acts on the request stops
/// executing well within this (QEMU at once); the wait keeps the error
/// reply from racing a reset that lands shortly after the request returns.
const RESET_GRACE: Duration = Duration::from_secs(1);

fn main() -> !
{
    std::os::seraph::log::register_name(b"pwrmgr");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is page-aligned (4 KiB) by the boot protocol, satisfying u64 alignment"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(bootstrap) = caps::request_bootstrap(info, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "bootstrap failed, exiting");
        syscall::thread_exit();
    };

    if bootstrap.service_ep == 0
    {
        std::os::seraph::log!(error: "no service endpoint, exiting");
        syscall::thread_exit();
    }

    // Resolve the actuation state. `None` means the platform authority
    // could not be resolved; pwrmgr still serves so callers get a clean
    // error rather than a hung ipc_call.
    let actuator = arch::current::resolve(&bootstrap, ipc_buf);
    if let Some(act) = &actuator
    {
        arch::current::watch_events(*act);
        std::os::seraph::log!("ready");
    }
    else
    {
        std::os::seraph::log!(warn: "ready (degraded: no shutdown actuator)");
    }

    let (wait_set, power_off) = arm_core_death(
        bootstrap.service_ep,
        bootstrap.core_death,
        actuator.as_ref(),
        ipc_buf,
    );

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        if wait_set != 0
        {
            match syscall::wait_set_wait(wait_set)
            {
                Ok(WAKE_CORE_DEATH) =>
                {
                    core_died(
                        bootstrap.core_death,
                        power_off.as_ref(),
                        actuator.as_ref(),
                        ipc_buf,
                    );
                    continue;
                }
                Ok(_) =>
                {}
                Err(e) =>
                {
                    guard.on_failure(e);
                    continue;
                }
            }
        }
        let msg = match receive(bootstrap.service_ep, wait_set, ipc_buf)
        {
            Ok(Some(msg)) => msg,
            Ok(None) => continue,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        serve(&msg, actuator.as_ref(), ipc_buf);
    }
}

/// Serve one request, `msg`: `SHUTDOWN` or `REBOOT` through `actuator` for a
/// caller whose badge carries `SHUTDOWN_AUTHORITY`. Returns, replying, only
/// when the request is refused or the platform keeps running.
fn serve(msg: &IpcMessage, actuator: Option<&arch::current::Actuator>, ipc_buf: *mut u64)
{
    let authorized = msg.badge & pwrmgr_labels::SHUTDOWN_AUTHORITY != 0;
    match msg.label
    {
        pwrmgr_labels::SHUTDOWN | pwrmgr_labels::REBOOT if !authorized =>
        {
            reject(pwrmgr_errors::UNAUTHORIZED, ipc_buf);
        }
        pwrmgr_labels::SHUTDOWN =>
        {
            std::os::seraph::log!("SHUTDOWN requested");
            if let Some(act) = actuator
            {
                arch::current::shutdown(act, ipc_buf);
            }
            // Reached here → no actuator or shutdown failed. Reply so
            // the caller does not hang on its ipc_call.
            reject(pwrmgr_errors::INVALID_REQUEST, ipc_buf);
        }
        pwrmgr_labels::REBOOT =>
        {
            std::os::seraph::log!("REBOOT requested");
            if let Some(act) = actuator
            {
                arch::current::reboot(act, ipc_buf);
            }
            reject(pwrmgr_errors::INVALID_REQUEST, ipc_buf);
        }
        _ => reject(pwrmgr_errors::UNKNOWN_OPCODE, ipc_buf),
    }
}

/// Receive a request on `service_ep`. With a wait set pwrmgr has been woken
/// for the endpoint, and a wake is readiness that can lapse before the
/// receive (its caller stopped or destroyed in between): the receive does not
/// block, and `Ok(None)` is nothing to take, so the wait, where a core death
/// is seen, stays pwrmgr's one blocking point.
fn receive(service_ep: u64, wait_set: u64, ipc_buf: *mut u64) -> Result<Option<IpcMessage>, i64>
{
    if wait_set == 0
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        return unsafe { ipc::ipc_recv(service_ep, ipc_buf) }.map(Some);
    }
    // SAFETY: ipc_buf is the registered IPC buffer.
    match unsafe { ipc::ipc_try_recv(service_ep, ipc_buf) }
    {
        Ok(msg) => Ok(Some(msg)),
        Err(e) if e == syscall_abi::SyscallError::WouldBlock as i64 => Ok(None),
        Err(e) => Err(e),
    }
}

/// Wait-set badge of pwrmgr's service endpoint.
const WAKE_REQUEST: u64 = 0;
/// Wait-set badge of the core-death queue.
const WAKE_CORE_DEATH: u64 = 1;
/// Members of the wait set: the service endpoint and the core-death queue.
const WAIT_SET_MEMBERS: u32 = 2;

/// Make the wait set over pwrmgr's service endpoint and `core_death`, the
/// receive-only derivation of the core-death queue. `0`, logged, when the
/// queue is absent or the set cannot be made: pwrmgr then receives on its
/// endpoint alone, and a core death goes unobserved.
fn observe_core(service_ep: u64, core_death: u64) -> u64
{
    if core_death == 0
    {
        std::os::seraph::log!(error: "no core-death queue; a core death is unobserved");
        return 0;
    }
    let wait_set = std::os::seraph::object_slab_retype(
        std::os::seraph::wait_set_retype_bytes(u64::from(WAIT_SET_MEMBERS)),
        |slab| syscall::wait_set_create(slab, WAIT_SET_MEMBERS).ok(),
    )
    .unwrap_or(0);
    let joined = wait_set != 0
        && syscall::wait_set_add(wait_set, service_ep, WAKE_REQUEST).is_ok()
        && syscall::wait_set_add(wait_set, core_death, WAKE_CORE_DEATH).is_ok();
    if !joined
    {
        if wait_set != 0
        {
            // Deleting the set removes the members it took.
            let _ = syscall::cap_delete(wait_set);
        }
        std::os::seraph::log!(error: "core-death wait set not made; a core death is unobserved");
        return 0;
    }
    wait_set
}

/// Arm the core-death power-off: observe the core-death queue
/// ([`observe_core`]), resolve the architecture's immediate power-off
/// through `actuator`, and log whether it is armed: the queue is observed,
/// the power-off is held, and pwrmgr has no pager, so it takes no page fault
/// on memmgr. `cargo xtask test-core-death` waits for the armed line before
/// it kills memmgr or procmgr. When the power-off is held but pwrmgr is
/// demand-paged it still runs on a core death; when it is not held a core
/// death takes the ordinary shutdown. Returns the wait set (`0` when the
/// queue is not observed) and the power-off.
fn arm_core_death(
    service_ep: u64,
    core_death: u64,
    actuator: Option<&arch::current::Actuator>,
    ipc_buf: *mut u64,
) -> (u64, Option<arch::current::PowerOff>)
{
    let wait_set = observe_core(service_ep, core_death);
    if wait_set == 0
    {
        // `observe_core` logged it.
        return (0, None);
    }
    let power_off = arch::current::resolve_power_off(actuator, ipc_buf);
    let pinned = startup_info().pager_endpoint_cap == 0;
    match (power_off.is_some(), pinned)
    {
        (true, true) => std::os::seraph::log!("core-death power-off armed"),
        (true, false) => std::os::seraph::log!(
            error: "core-death power-off not armed: pwrmgr is demand-paged, so a core death can \
             fault it on memmgr"
        ),
        (false, _) => std::os::seraph::log!(
            error: "core-death power-off not armed: no immediate power-off; a core death takes \
             the ordinary shutdown"
        ),
    }
    (wait_set, power_off)
}

/// A core member has died: drain the entries its observers posted to
/// `core_death` and power the platform off through `power_off`, the
/// architecture's immediate power-off, with [`ALLOCATOR`] armed against this
/// thread. Nothing between the wake and the power-off allocates, frees, logs
/// or calls a service, so it needs neither memmgr, a dead member's pages, nor
/// any service that waits on them. Only when the platform keeps running, or
/// no immediate power-off is held, does pwrmgr disarm, log the death, and
/// take the ordinary shutdown through `actuator` (acpid's `SLEEP(5)` on
/// x86-64, which runs `\_PTS`), as a `SHUTDOWN` request does; when that too
/// fails it logs it and serves on.
fn core_died(
    core_death: u64,
    power_off: Option<&arch::current::PowerOff>,
    actuator: Option<&arch::current::Actuator>,
    ipc_buf: *mut u64,
)
{
    ALLOCATOR.arm();
    let death = pwrmgr::core_death::first(|| {
        syscall::event_try_recv_death(core_death)
            .ok()
            .map(|d| (d.correlator, d.exit_reason))
    });
    if let Some(power_off) = power_off
    {
        arch::current::power_off_now(power_off);
    }
    ALLOCATOR.disarm();

    let member = death
        .and_then(|d| d.member)
        .map_or("a core member", pwrmgr::core_death::CoreMember::name);
    match death
    {
        Some(d) => std::os::seraph::log!(
            error: "{member} died (exit reason {:#x}); powering off",
            d.exit_reason
        ),
        None => std::os::seraph::log!(error: "{member} died; powering off"),
    }
    if power_off.is_some()
    {
        std::os::seraph::log!(error: "core-death power-off did not take effect");
    }
    match actuator
    {
        Some(act) => arch::current::shutdown(act, ipc_buf),
        None => std::os::seraph::log!(error: "{member} died; no shutdown actuator to power off"),
    }
}

/// Wait out [`RESET_GRACE`] after a power-off or reset request (`op`) that
/// returned, then log that it did not take effect. The arch routine then
/// returns, and `main` replies `pwrmgr_errors::INVALID_REQUEST`, so the
/// caller is answered whenever the platform keeps running. Blocks in
/// `thread_sleep`, which is legal in user mode on every architecture.
pub(crate) fn await_reset(op: &str)
{
    std::thread::sleep(RESET_GRACE);
    std::os::seraph::log!(error: "{op} did not take effect");
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

fn reject(code: u64, ipc_buf: *mut u64)
{
    let reply = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}
