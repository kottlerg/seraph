// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/arch/x86_64/mod.rs

//! x86-64 platform shutdown and reboot, through acpid.
//!
//! The ACPI sleep and reset sequences run in acpid, which holds the FADT's
//! fixed register blocks and runs the AML (`services/acpid/README.md`
//! § Power requests): pwrmgr calls [`acpid_labels::SLEEP`] with
//! [`acpid_labels::STATE_S5`] to power off and [`acpid_labels::RESET`] to
//! reboot, through the `acpid.power` seed. It reads no table.
//!
//! For the death of a core service it holds one port block of its own:
//! at startup it asks acpid for `PM1a_CNT` and the S5 `SLP_TYPa`
//! ([`acpid_labels::QUERY_SLEEP`]), binds the block to its main thread, and
//! on a core death writes the S5 sleep type itself ([`power_off_now`]),
//! with no call on acpid, which may be stuck on the dead member, and without
//! the `\_PTS` and the event quiescing that acpid's `SLEEP` runs first.
//!
//! Each call is bounded by [`ACPID_CALL_TIMEOUT_MS`], so an acpid that is
//! down, or blocked, fails the request instead of holding pwrmgr and its
//! caller, svcmgr's graceful shutdown among them. On any failure, including
//! a request acpid carried out without the platform acting within
//! [`crate::await_reset`]'s grace, a routine logs and returns, and the
//! caller (`main`) replies `pwrmgr_errors::INVALID_REQUEST`. acpid
//! answers a `SLEEP` only 10 s after its writes (its `SLEEP_GRACE`), so a
//! power-off the platform does not act on fails about 11 s after it was
//! issued, a reboot about one second after.
//!
//! The power button reaches pwrmgr through acpid too: a thread of its own
//! ([`watch_events`]) waits in [`acpid_labels::WAIT_EVENT`] and powers
//! off on a press, as `SHUTDOWN` does.

use std::time::Duration;

use crate::caps::{Bootstrap, drop_unused};
use ipc::{IpcMessage, acpid_errors, acpid_labels};

/// The bound on one acpid call, from the send to the reply, in
/// milliseconds. A time bound that bounds no capacity: far above acpid's
/// start-up, which a request sent during it waits behind, and its `\_PTS`
/// evaluation, so a live acpid answers within it; an acpid that is down or
/// blocked (on a dead devmgr, say) fails the request after it.
const ACPID_CALL_TIMEOUT_MS: u32 = 30_000;

/// How long the event thread waits before it calls `WAIT_EVENT` again
/// after a call that failed in transit: acpid died holding it, and svcmgr
/// restarts acpid on the same endpoint.
const WAIT_EVENT_RETRY: Duration = Duration::from_secs(1);

/// Resolved actuation state: the `acpid.power` SEND.
#[derive(Clone, Copy)]
pub struct Actuator
{
    acpid: u64,
}

/// Keep the `acpid.power` seed and delete the `devmgr.shutdown` one, which
/// serves nothing on x86-64. `None`, logged, when the seed is absent.
pub fn resolve(bootstrap: &Bootstrap, _ipc_buf: *mut u64) -> Option<Actuator>
{
    drop_unused(bootstrap.devmgr_shutdown);
    if bootstrap.acpid_power == 0
    {
        // Loud: a boot whose final shutdown cannot run still passes on its
        // harness marker, so this line is what shows the missing seed.
        std::os::seraph::log!(error: "no acpid.power seed: SHUTDOWN and REBOOT cannot run");
        return None;
    }
    Some(Actuator {
        acpid: bootstrap.acpid_power,
    })
}

/// Power off: acpid's `SLEEP(5)`. Does not return when the platform powers
/// off; logs and returns otherwise.
pub fn shutdown(act: &Actuator, ipc_buf: *mut u64)
{
    call(
        act,
        acpid_labels::SLEEP,
        acpid_labels::STATE_S5,
        "shutdown",
        ipc_buf,
    );
}

/// Reboot: acpid's `RESET`, the FADT reset register. Does not return when
/// the platform resets; logs and returns otherwise.
pub fn reboot(act: &Actuator, ipc_buf: *mut u64)
{
    call(act, acpid_labels::RESET, 0, "reboot", ipc_buf);
}

/// The core-death power-off: `PM1a_CNT`, bound to pwrmgr's main thread,
/// and the S5 `SLP_TYPa`, both from acpid's [`acpid_labels::QUERY_SLEEP`].
pub struct PowerOff
{
    /// The block's first port, `PM1a_CNT`.
    port: u16,
    /// The S5 sleep type, at most `acpid_labels::SLP_TYP_MAX`.
    slp_typ: u16,
}

/// The core-death power-off: acpid's [`acpid_labels::QUERY_SLEEP`] of S5,
/// bounded by [`ACPID_CALL_TIMEOUT_MS`], through `actuator`, with the
/// block it serves bound to the calling thread, pwrmgr's main thread, which
/// runs [`power_off_now`]. `None`, logged, without an actuator, when acpid
/// refuses (no `PM1a_CNT`, as on a hardware-reduced platform, or no usable
/// `\_S5_`) or does not answer, or when the block cannot be bound.
pub fn resolve_power_off(actuator: Option<&Actuator>, ipc_buf: *mut u64) -> Option<PowerOff>
{
    let act = actuator?;
    let msg = IpcMessage::builder(acpid_labels::QUERY_SLEEP)
        .word(0, u64::from(ipc::ACPID_LABELS_VERSION))
        .word(1, acpid_labels::STATE_S5)
        .build();
    // SAFETY: `ipc_buf` is the kernel-registered per-thread IPC buffer.
    let reply =
        match unsafe { ipc::ipc_call_timeout(act.acpid, &msg, ipc_buf, ACPID_CALL_TIMEOUT_MS) }
        {
            Ok(reply) => reply,
            Err(e) =>
            {
                std::os::seraph::log!(error: "QUERY_SLEEP failed (acpid call err={e})");
                return None;
            }
        };
    let cap = reply.caps().first().copied();
    if reply.label != acpid_errors::SUCCESS
    {
        std::os::seraph::log!(error: "QUERY_SLEEP refused (acpid replied {:#x})", reply.label);
        return None;
    }
    let (Some(cap), Ok(port), Ok(slp_typ)) = (
        cap,
        u16::try_from(reply.word(0)),
        u16::try_from(reply.word(1)),
    )
    else
    {
        if let Some(cap) = cap
        {
            let _ = syscall::cap_delete(cap);
        }
        std::os::seraph::log!(error: "QUERY_SLEEP answer malformed");
        return None;
    };
    if u64::from(slp_typ) > acpid_labels::SLP_TYP_MAX || !bind_ports(cap)
    {
        let _ = syscall::cap_delete(cap);
        std::os::seraph::log!(error: "PM1a control block {port:#x} not usable");
        return None;
    }
    Some(PowerOff { port, slp_typ })
}

/// Power off at once: write the S5 sleep type to `PM1a_CNT`, then with
/// `SLP_EN`, keeping the register's other bits
/// ([`acpid_labels::pm1_control_writes`]). Port I/O alone: allocates, logs
/// and calls nothing. Runs on pwrmgr's main thread, to which
/// [`resolve_power_off`] bound the block; returns only when the platform
/// keeps running.
pub fn power_off_now(power_off: &PowerOff)
{
    // SAFETY: `power_off.port` is `PM1a_CNT`, the first port of the block
    // acpid served for it and `resolve_power_off` bound to this thread; a
    // read of it has no side effect.
    let current = unsafe { inw(power_off.port) };
    let [typed, enter] = acpid_labels::pm1_control_writes(current, power_off.slp_typ);
    // SAFETY: as the read; writing `SLP_TYP` with `SLP_EN` clear is the
    // first step of the ACPI sleep sequence.
    unsafe { outw(power_off.port, typed) };
    // SAFETY: as the read; writing `SLP_TYP | SLP_EN` enters the state.
    unsafe { outw(power_off.port, enter) };
}

/// Bind the `IoPort` `cap` to pwrmgr's main thread. Its first bind takes the
/// thread's port-binding table from pwrmgr's `CSpace` budget
/// (`syscall_abi::IOPORT_BINDING_TABLE_PAGES` pages), so a bind refused with
/// `OutOfMemory` is made again once after [`fund_binding_table`]. Whether
/// the block is bound.
fn bind_ports(cap: u64) -> bool
{
    // pwrmgr's main thread, which calls this and runs `power_off_now`.
    let thread = std::os::seraph::startup_info().self_thread;
    match syscall::ioport_bind(thread, cap)
    {
        Err(e) if e == syscall_abi::SyscallError::OutOfMemory as i64 && fund_binding_table() =>
        {
            syscall::ioport_bind(thread, cap).is_ok()
        }
        result => result.is_ok(),
    }
}

/// Donate one port-binding table's pages, and one more, to pwrmgr's own
/// `CSpace` (augment-mode `cap_create_cspace`), from memmgr through the
/// object slab; the page beyond the table covers the bookkeeping a donation
/// keeps in its own pages. Whether the donation was made.
fn fund_binding_table() -> bool
{
    let cspace = std::os::seraph::startup_info().self_cspace;
    let pages = syscall_abi::IOPORT_BINDING_TABLE_PAGES + 1;
    std::os::seraph::object_slab_retype(pages * syscall_abi::PAGE_SIZE, |frame| {
        syscall::cap_create_cspace(frame, cspace, pages).ok()
    })
    .is_some()
}

/// `in ax, dx`.
///
/// # Safety
///
/// `port` lies in an `IoPort` block bound to the calling thread, and
/// reading it has no effect the caller does not intend.
unsafe fn inw(port: u16) -> u16
{
    let value: u16;
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("in ax, dx", in("dx") port, out("ax") value, options(nomem, nostack));
    };
    value
}

/// `out dx, ax`.
///
/// # Safety
///
/// `port` lies in an `IoPort` block bound to the calling thread, and
/// writing `value` to it has the effect the caller intends.
unsafe fn outw(port: u16, value: u16)
{
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack));
    };
}

/// Watch the power button: spawn the event thread, which waits in acpid's
/// `WAIT_EVENT` for pwrmgr's lifetime and powers off on a press. A thread
/// that cannot be spawned is logged, and pwrmgr serves without it.
pub fn watch_events(act: Actuator)
{
    let spawned = std::thread::Builder::new()
        .name("pwrmgr-events".into())
        .spawn(move || events(&act));
    if let Err(e) = spawned
    {
        std::os::seraph::log!(error: "power-button thread not spawned: {e}");
    }
}

/// The event thread: call `WAIT_EVENT` with no bound, and on the power
/// button power off as `SHUTDOWN` does. A call that fails in transit is
/// made again after [`WAIT_EVENT_RETRY`], and a superseded one at once; any
/// other reply (acpid has no event to wait for, or refuses the call) ends
/// the thread, logged.
fn events(act: &Actuator)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    std::os::seraph::log!("watching the power button");
    let msg = IpcMessage::builder(acpid_labels::WAIT_EVENT)
        .word(0, u64::from(ipc::ACPID_LABELS_VERSION))
        .build();
    loop
    {
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
        match unsafe { ipc::ipc_call(act.acpid, &msg, ipc_buf) }
        {
            Ok(reply) if reply.label == acpid_errors::SUCCESS =>
            {
                if reply.word(0) & acpid_labels::EVENT_POWER_BUTTON != 0
                {
                    std::os::seraph::log!("power button: shutting down");
                    shutdown(act, ipc_buf);
                }
            }
            Ok(reply) if reply.label == acpid_errors::SUPERSEDED =>
            {}
            Ok(reply) =>
            {
                std::os::seraph::log!(
                    "not watching the power button (acpid replied {:#x})",
                    reply.label
                );
                return;
            }
            Err(e) =>
            {
                std::os::seraph::log!(warn: "WAIT_EVENT failed (err={e}); calling again");
                std::thread::sleep(WAIT_EVENT_RETRY);
            }
        }
    }
}

/// Call acpid's `label` with `arg` in `data[1]`, bounded by
/// [`ACPID_CALL_TIMEOUT_MS`]. A `SUCCESS` reply means acpid wrote the
/// register and the platform still runs, so pwrmgr waits out
/// [`crate::await_reset`]'s grace; any other reply, a failed call, or no
/// answer within the bound is logged.
fn call(act: &Actuator, label: u64, arg: u64, op: &str, ipc_buf: *mut u64)
{
    let msg = IpcMessage::builder(label)
        .word(0, u64::from(ipc::ACPID_LABELS_VERSION))
        .word(1, arg)
        .build();
    // SAFETY: `ipc_buf` is the kernel-registered per-thread IPC buffer.
    match unsafe { ipc::ipc_call_timeout(act.acpid, &msg, ipc_buf, ACPID_CALL_TIMEOUT_MS) }
    {
        Ok(reply) if reply.label == acpid_errors::SUCCESS => crate::await_reset(op),
        Ok(reply) =>
        {
            std::os::seraph::log!(error: "{op} failed (acpid replied {:#x})", reply.label);
        }
        Err(e) if e == syscall_abi::SyscallError::WouldBlock as i64 =>
        {
            std::os::seraph::log!(
                error: "{op} failed (acpid did not answer within {ACPID_CALL_TIMEOUT_MS} ms)"
            );
        }
        Err(e) => std::os::seraph::log!(error: "{op} failed (acpid call err={e})"),
    }
}
