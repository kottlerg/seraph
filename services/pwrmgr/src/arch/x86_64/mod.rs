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
//! For the death of a core service it holds one register of its own: at
//! startup it asks acpid for the register acpid's `SLEEP` writes and the S5
//! `SLP_TYPa` ([`acpid_labels::QUERY_SLEEP`]), `PM1a_CNT` or, on a
//! hardware-reduced platform, `SLEEP_CONTROL_REG`; it binds a port to its
//! main thread or maps a memory register's page, and on a core death writes
//! the S5 sleep type itself ([`power_off_now`]), with no call on acpid,
//! which may be stuck on the dead member, and without the `\_PTS`, the
//! event quiescing and the clearing of `WAK_STS` that acpid's `SLEEP` runs
//! first.
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
use pwrmgr::power_off::{Target, page_and_offset};

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

/// The core-death power-off: the register acpid's
/// [`acpid_labels::QUERY_SLEEP`] served, ready to write, and what is written.
pub enum PowerOff
{
    /// `PM1a_CNT`, the first port of the block bound to pwrmgr's main
    /// thread, and the S5 sleep type, at most `acpid_labels::SLP_TYP_MAX`.
    Pm1aCnt
    {
        port: u16, slp_typ: u16
    },
    /// `SLEEP_CONTROL_REG`'s port, bound to pwrmgr's main thread, and the
    /// value that enters S5.
    ControlPort
    {
        port: u16, value: u8
    },
    /// `SLEEP_CONTROL_REG`'s address in pwrmgr's address space, where the
    /// page that holds it is mapped for pwrmgr's lifetime, and the value that
    /// enters S5.
    ControlMemory
    {
        va: u64, value: u8
    },
}

/// The core-death power-off: acpid's [`acpid_labels::QUERY_SLEEP`] of S5,
/// bounded by [`ACPID_CALL_TIMEOUT_MS`], through `actuator`, with the
/// register it serves made ready for the calling thread, pwrmgr's main
/// thread, which runs [`power_off_now`]: a port bound to it, or a page
/// mapped. `None`, logged, without an actuator, when acpid refuses (no
/// sleep register, or no usable `\_S5_`) or does not answer, when its
/// answer is malformed, or when the port cannot be bound or the page mapped.
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
    let target = Target::from_answer(reply.word(2), reply.word(0), reply.word(1));
    let (Some(cap), Some(target)) = (cap, target)
    else
    {
        if let Some(cap) = cap
        {
            let _ = syscall::cap_delete(cap);
        }
        std::os::seraph::log!(error: "QUERY_SLEEP answer malformed");
        return None;
    };
    let power_off = match target
    {
        Target::Pm1aCnt { port, slp_typ } if bind_ports(cap) =>
        {
            Some(PowerOff::Pm1aCnt { port, slp_typ })
        }
        Target::ControlPort { port, value } if bind_ports(cap) =>
        {
            Some(PowerOff::ControlPort { port, value })
        }
        Target::ControlMemory { address, value } =>
        {
            map_page(cap, address).map(|va| PowerOff::ControlMemory { va, value })
        }
        Target::Pm1aCnt { .. } | Target::ControlPort { .. } =>
        {
            let _ = syscall::cap_delete(cap);
            None
        }
    };
    if power_off.is_none()
    {
        std::os::seraph::log!(error: "sleep register {target:?} not usable");
    }
    power_off
}

/// Map the `Mmio` capability `cap` over the page that holds the register at
/// physical `address` into pwrmgr's address space, for pwrmgr's lifetime;
/// the register's address there. `None` when no VA is left, the capability
/// then deleted, or the map is refused, the VA and the capability then kept.
/// Runs at startup: the map takes its page-table pages from memmgr through
/// the object slab, and the power-off that writes the register later maps
/// nothing.
fn map_page(cap: u64, address: u64) -> Option<u64>
{
    let (_, offset) = page_and_offset(address);
    let Ok(range) = std::os::seraph::reserve_pages(1)
    else
    {
        let _ = syscall::cap_delete(cap);
        return None;
    };
    let va = range.va_start();
    let aspace = std::os::seraph::startup_info().self_aspace;
    // SAFETY: `range` is a fresh one-page reservation from the per-process
    // arena: VA no Rust object or IPC page occupies. The register is held for
    // pwrmgr's lifetime, so the range is never returned and nothing else is
    // placed there.
    if unsafe { std::os::seraph::mmio_map_funded(aspace, cap, va, 1) }.is_err()
    {
        // A refused map can leave the page mapped, so the range stays
        // reserved and the capability is kept with it.
        return None;
    }
    // `va` is page-aligned and `offset` below the page size, so the OR adds
    // them.
    Some(va | offset)
}

/// Power off at once: on `PM1a_CNT`, write the S5 sleep type, then with
/// `SLP_EN`, keeping the register's other bits
/// ([`acpid_labels::pm1_control_writes`]); on `SLEEP_CONTROL_REG`, write the
/// one value that enters S5 (`acpid_labels::sleep_control_value`). Port I/O
/// or one store to a page mapped at startup alone: allocates, maps, logs and
/// calls nothing. Runs on pwrmgr's main thread, to which
/// [`resolve_power_off`] bound the port; returns only when the platform
/// keeps running.
pub fn power_off_now(power_off: &PowerOff)
{
    match *power_off
    {
        PowerOff::Pm1aCnt { port, slp_typ } =>
        {
            // SAFETY: `port` is `PM1a_CNT`, the first port of the block acpid
            // served for it and `resolve_power_off` bound to this thread; a
            // read of it has no side effect.
            let current = unsafe { inw(port) };
            let [typed, enter] = acpid_labels::pm1_control_writes(current, slp_typ);
            // SAFETY: as the read; writing `SLP_TYP` with `SLP_EN` clear is
            // the first step of the ACPI sleep sequence.
            unsafe { outw(port, typed) };
            // SAFETY: as the read; writing `SLP_TYP | SLP_EN` enters the
            // state.
            unsafe { outw(port, enter) };
        }
        PowerOff::ControlPort { port, value } =>
        {
            // SAFETY: `port` is `SLEEP_CONTROL_REG`, the port acpid served
            // for it and `resolve_power_off` bound to this thread; writing
            // `SLP_TYPx | SLP_EN` to it enters the state (ACPI 6.5
            // § 4.8.3.7).
            unsafe { outb(port, value) };
        }
        PowerOff::ControlMemory { va, value } =>
        {
            // SAFETY: `va` is `SLEEP_CONTROL_REG` in the page acpid served for
            // it, which `resolve_power_off` mapped for pwrmgr's lifetime, so
            // the store reaches that byte of device memory and takes no fault;
            // writing `SLP_TYPx | SLP_EN` to it enters the state (ACPI 6.5
            // § 4.8.3.7).
            unsafe { (va as *mut u8).write_volatile(value) };
        }
    }
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

/// `out dx, al`.
///
/// # Safety
///
/// `port` lies in an `IoPort` block bound to the calling thread, and
/// writing `value` to it has the effect the caller intends.
unsafe fn outb(port: u16, value: u8)
{
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    };
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
/// button power off as `SHUTDOWN` does, the log flushed first. A call that fails in transit is
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
                    crate::drain_log(crate::FLUSH_BOUND_MS);
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
