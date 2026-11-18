// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/acpi.rs

//! acpid's evaluation, read from devmgr, and the `ACPI_AUTHORITY` gate.
//!
//! The host-bridge phase reads, with `QUERY_HOST_BRIDGE` on
//! `devmgr.registry`, what devmgr holds from acpid's pushes for each PCI host
//! bridge (services/acpid/README.md § Checks), waiting for acpid to finish
//! its start-up. It asserts that each bridge's `_OSC` was evaluated and
//! granted control 0x1E, every PCI Express feature but native hotplug, which
//! QEMU's tables keep while ACPI PCI hotplug is on, as it is on every boot
//! cell of q35 and `virt`; that devmgr holds the bridge's interrupt routes,
//! having checked them against each boot function's line (on x86-64 the
//! `_PRT` read in the PIC model against the Interrupt Line register the
//! firmware programmed, on RISC-V against the `virt` swizzle); and that it
//! holds the bridge's `_CRS` windows, having checked each boot function's
//! bus, memory BARs and I/O BARs against them. Each check must have covered
//! at least one boot function.
//!
//! The deny phase sends each label gated by `ACPI_AUTHORITY` on
//! `devmgr.registry`, whose badge lacks it, and asserts `UNAUTHORIZED`: no
//! holder of the registry cap can take an operation region, reach a PCI
//! function's configuration space, or replace what acpid pushed.
//!
//! The power deny phase resolves the public `acpid.deny`, a SEND on acpid's
//! endpoint without `POWER_AUTHORITY`, and asserts that `SLEEP(5)`, `RESET`
//! and `WAIT_EVENT` reply `UNAUTHORIZED`: no process but the holder of the
//! seed-only `acpid.power` (pwrmgr) can power the platform off, reset it,
//! or take its power-button events.

use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// How long the host-bridge phase waits for devmgr to hold acpid's pushes:
/// acpid evaluates the tables under TCG after svcmgr starts it.
const ACPID_WAIT_MS: u64 = 30_000;

/// The `_OSC` control dword QEMU's q35 and `virt` tables grant while ACPI
/// PCI hotplug is on: SHPC hotplug, PME, AER and the PCI Express
/// capability, without native hotplug (bit 0).
const OSC_CONTROL: u64 = 0x1E;

/// `_OSC` status bits 1 to 3: `_OSC` failure, unrecognized UUID,
/// unrecognized revision.
const OSC_ERRORS: u64 = 0x0E;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "acpi_host_bridges",
            run: host_bridges_phase,
        },
        Phase {
            name: "acpi_authority_deny",
            run: authority_deny_phase,
        },
        Phase {
            name: "acpid_power_deny",
            run: power_deny_phase,
        },
    ]
}

/// What devmgr holds for one host bridge (`QUERY_HOST_BRIDGE`'s reply).
#[derive(Debug)]
struct Bridge
{
    segment: u64,
    bus: u64,
    osc_evaluated: bool,
    osc_status: u64,
    osc_control: u64,
    routes_held: bool,
    routes_covered: u64,
    windows_held: bool,
    windows_covered: u64,
}

impl Bridge
{
    /// Whether devmgr holds every push acpid makes for the bridge.
    fn complete(&self) -> bool
    {
        self.osc_evaluated && self.routes_held && self.windows_held
    }
}

/// `QUERY_HOST_BRIDGE(ordinal)` on `devmgr`: the bridge, or devmgr's
/// status.
fn query_bridge(devmgr: u64, ordinal: u64) -> Result<Bridge, u64>
{
    let req = ipc::IpcMessage::builder(ipc::devmgr_labels::QUERY_HOST_BRIDGE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .word(1, ordinal)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(devmgr, &req, ipc_buf) }
        .unwrap_or_else(|_| panic!("QUERY_HOST_BRIDGE({ordinal}) ipc_call failed"));
    if reply.label != ipc::devmgr_errors::SUCCESS
    {
        return Err(reply.label);
    }
    let w = |i| reply.word(i);
    Ok(Bridge {
        segment: w(0),
        bus: w(1),
        osc_evaluated: w(2) == 1,
        osc_status: w(3),
        osc_control: w(4),
        routes_held: w(5) == 1,
        routes_covered: w(6),
        windows_held: w(7) == 1,
        windows_covered: w(8),
    })
}

/// Every bridge devmgr holds a push for, in ordinal order.
fn bridges(devmgr: u64) -> Vec<Bridge>
{
    let mut out = Vec::new();
    for ordinal in 0..
    {
        match query_bridge(devmgr, ordinal)
        {
            Ok(b) => out.push(b),
            Err(l) if l == ipc::devmgr_errors::NO_DEVICE => break,
            Err(l) => panic!("QUERY_HOST_BRIDGE({ordinal}) replied {l:#x}"),
        }
    }
    out
}

fn host_bridges_phase(caps: &Caps)
{
    let devmgr = caps.devmgr_registry;
    assert!(
        devmgr != 0,
        "acpi host bridges: no devmgr.registry cap seeded"
    );

    // acpid pushes each bridge's _OSC, windows and routes in turn; wait
    // until devmgr holds all of them for every bridge it knows.
    let start = Instant::now();
    let found = loop
    {
        let found = bridges(devmgr);
        if (!found.is_empty() && found.iter().all(Bridge::complete))
            || start.elapsed() >= Duration::from_millis(ACPID_WAIT_MS)
        {
            break found;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        !found.is_empty(),
        "acpi host bridges: devmgr holds no push for any host bridge {ACPID_WAIT_MS} ms in"
    );
    for b in &found
    {
        let at = format!("bridge {}:{}", b.segment, b.bus);
        assert!(b.osc_evaluated, "{at}: _OSC not evaluated ({b:?})");
        assert_eq!(
            b.osc_status & OSC_ERRORS,
            0,
            "{at}: _OSC status reports an error ({b:?})"
        );
        assert_eq!(b.osc_control, OSC_CONTROL, "{at}: _OSC control ({b:?})");
        assert!(b.routes_held, "{at}: devmgr holds no _PRT routes ({b:?})");
        assert!(
            b.routes_covered > 0,
            "{at}: the _PRT check covered no boot function ({b:?})"
        );
        assert!(b.windows_held, "{at}: devmgr holds no _CRS windows ({b:?})");
        assert!(
            b.windows_covered > 0,
            "{at}: the _CRS check covered no boot function ({b:?})"
        );
    }
    std::os::seraph::log!("acpi host bridges: {found:?}");
}

fn authority_deny_phase(caps: &Caps)
{
    let devmgr = caps.devmgr_registry;
    assert!(devmgr != 0, "acpi deny: no devmgr.registry cap seeded");
    let ipc_buf = std::os::seraph::current_ipc_buf();
    for (label, name) in [
        (
            ipc::devmgr_labels::QUERY_ACPI_RESOURCES,
            "QUERY_ACPI_RESOURCES",
        ),
        (ipc::devmgr_labels::ACPI_REGION_GRANT, "ACPI_REGION_GRANT"),
        (ipc::devmgr_labels::ACPI_PCI_CONFIG, "ACPI_PCI_CONFIG"),
        (ipc::devmgr_labels::OSC_RESULT, "OSC_RESULT"),
        (ipc::devmgr_labels::BRIDGE_WINDOWS, "BRIDGE_WINDOWS"),
        (ipc::devmgr_labels::PRT_TABLE, "PRT_TABLE"),
        (ipc::devmgr_labels::ACPI_HOTPLUG, "ACPI_HOTPLUG"),
    ]
    {
        let req = ipc::IpcMessage::builder(label)
            .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
            .build();
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(devmgr, &req, ipc_buf) }
            .unwrap_or_else(|_| panic!("{name} ipc_call failed"));
        assert_eq!(
            reply.label,
            ipc::devmgr_errors::UNAUTHORIZED,
            "{name} without ACPI_AUTHORITY must reply UNAUTHORIZED"
        );
        assert!(reply.caps().is_empty(), "{name} deny must carry no cap");
    }
}

/// `SLEEP(5)`, `RESET` and `WAIT_EVENT` through the public `acpid.deny`
/// reply `UNAUTHORIZED`. acpid serves its endpoint once its start-up is
/// done, which the host-bridge phase before this one waits for; on x86-64
/// pwrmgr's `WAIT_EVENT` holds one of acpid's two receivers meanwhile, so
/// these replies come from the other.
fn power_deny_phase(_caps: &Caps)
{
    let deny = std::os::seraph::registry::lookup(ipc::published_names::ACPID_DENY)
        .expect("acpid power deny: acpid.deny must resolve");
    let ipc_buf = std::os::seraph::current_ipc_buf();
    for (label, arg, name) in [
        (
            ipc::acpid_labels::SLEEP,
            ipc::acpid_labels::STATE_S5,
            "SLEEP(5)",
        ),
        (ipc::acpid_labels::RESET, 0, "RESET"),
        (ipc::acpid_labels::WAIT_EVENT, 0, "WAIT_EVENT"),
    ]
    {
        let req = ipc::IpcMessage::builder(label)
            .word(0, u64::from(ipc::ACPID_LABELS_VERSION))
            .word(1, arg)
            .build();
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(deny, &req, ipc_buf) }
            .unwrap_or_else(|_| panic!("acpid {name} ipc_call failed"));
        assert_eq!(
            reply.label,
            ipc::acpid_errors::UNAUTHORIZED,
            "acpid {name} through acpid.deny must reply UNAUTHORIZED (got {:#x})",
            reply.label
        );
    }
    let _ = syscall::cap_delete(deny);
    std::os::seraph::log!("acpid power-deny phase passed (UNAUTHORIZED replies)");
}
