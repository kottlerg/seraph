// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/caps.rs

//! Bootstrap for pwrmgr.
//!
//! pwrmgr is a svcmgr-launched provider. Its bootstrap round (served by
//! svcmgr's provider path) delivers:
//!
//! * `caps[0]` = pwrmgr's own service endpoint (RECV; the SHUTDOWN/REBOOT
//!   receive end). svcmgr holds the persistent source and publishes
//!   `pwrmgr.shutdown` / `pwrmgr.deny` SENDs against it.
//! * `caps[1]` = `REGISTRY_QUERY_AUTHORITY | SHUTDOWN_DEVICE_AUTHORITY`-badged
//!   SEND on devmgr's registry endpoint (the `devmgr.shutdown` seed), through
//!   which the RISC-V arch module acquires the SBI shutdown authority.
//! * `caps[2]` = `POWER_AUTHORITY`-badged SEND on acpid's service endpoint
//!   (the `acpid.power` seed), through which the x86-64 arch module reaches
//!   the ACPI sleep and reset registers and waits for the power button.
//! * `caps[3]` = a receive-only derivation of the event queue svcmgr's own
//!   death posts to, which svcmgr serves the shutdown actuator after its
//!   seeds; an entry on it is svcmgr's death (docs/supervision.md § Observing
//!   svcmgr).
//!
//! pwrmgr owns no hardware caps directly. The target's arch module
//! ([`crate::arch::current`]) keeps the cap it uses and deletes the other.

use std::os::seraph::StartupInfo;

/// Caps delivered to pwrmgr by svcmgr's provider bootstrap round.
pub struct Bootstrap
{
    /// pwrmgr's service endpoint (RECV). Zero if the round was empty.
    pub service_ep: u64,
    /// The `devmgr.shutdown` seed. Zero if absent.
    pub devmgr_shutdown: u64,
    /// The `acpid.power` seed. Zero if absent.
    pub acpid_power: u64,
    /// The receive-only derivation of svcmgr's own death queue. Zero if
    /// absent.
    pub svcmgr_death: u64,
}

/// Drain the provider bootstrap rounds from `creator_endpoint`.
pub fn request_bootstrap(info: &StartupInfo, ipc_buf: *mut u64) -> Option<Bootstrap>
{
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }
    // SAFETY: `ipc_buf` is the kernel-registered per-thread IPC buffer.
    // Only the present caps ride, named by each round's presence word; an
    // absent slot decodes as `0`.
    let [service_ep, devmgr_shutdown, acpid_power, svcmgr_death] =
        unsafe { ipc::bootstrap::request_slots::<4>(creator, ipc_buf) }.ok()?;
    Some(Bootstrap {
        service_ep,
        devmgr_shutdown,
        acpid_power,
        svcmgr_death,
    })
}

/// Delete `cap` when it is a slot (non-zero): a seed the arch module does
/// not use.
pub fn drop_unused(cap: u64)
{
    if cap != 0
    {
        let _ = syscall::cap_delete(cap);
    }
}
