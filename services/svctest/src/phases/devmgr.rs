// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/devmgr.rs

//! devmgr surface — the class, `QUERY_SHUTDOWN_DEVICE`, and `BIND_DRIVERS`
//! authority gates, the instance ordinal of `QUERY_DEVICE`, the on-demand
//! bind with its settle, mid-bootstrap teardown (#176), and withdrawal, DMA
//! confinement, and MSI delivery, forgery, churn, and release.
//!
//! The deny phases send the gated labels on `devmgr.registry`, a cap
//! carrying `REGISTRY_QUERY_AUTHORITY` but none of `CLASS_AUTHORITY`,
//! `SHUTDOWN_DEVICE_AUTHORITY`, and `BIND_AUTHORITY` and no class slot, and
//! assert `UNAUTHORIZED`: such a holder cannot reach any class's drivers
//! (the whole-disk block cap and the debug port among them), mint a class
//! SEND, acquire the platform shutdown actuators, or have devmgr bind
//! drivers. The class gates are also checked on `devmgr.bind`, whose badge
//! carries `BIND_AUTHORITY` and no class slot. They are checked before any
//! device lookup, so they hold on a boot with no driver of a class too.
//!
//! The ordinal phase asks the `input` class (`devmgr.class.input`) for the
//! input driver at ordinal 0, absent and explicit, and past the one keyboard
//! every boot's device set carries, and asserts a cap for the first and
//! `NO_DEVICE` for the second.
//!
//! The on-demand bind phase sends `BIND_DRIVERS` on `devmgr.bind` with a cap
//! on `/tests/drivers/`, which holds the `test-fault` fixture, whose
//! declaration matches the four `pci-testdev` functions a test launch
//! attaches (`cargo xtask run --test-devices`): two the fixture serves, one
//! on which it never reports ready, and one on which it refuses its
//! bootstrap. It asserts that the registry serves another class while the
//! bind's settle runs, that the settle ends no earlier than its bound with
//! the two serving fixtures at ordinals 0 and 1 and no other, that a served
//! fixture's death withdraws it (a call queued on it returns, its ordinal
//! replies `WITHDRAWN`) while ordinal 1 keeps its fixture, that memmgr's
//! free pool recovers the memory the never-ready and refusing fixtures held,
//! which only their destruction returns, and that a second `BIND_DRIVERS`
//! over the same directory binds nothing and settles at once.
//!
//! The DMA confinement phase asks the `test-dma` class
//! (`devmgr.class.test-dma`) for the `test-dma` fixture, which devmgr binds
//! to QEMU's `edu` device (attached by a test launch, on both architectures)
//! by its declaration when svcmgr hands it the drivers directory, and asks
//! the fixture to probe: a copy through a page its driver mapped (`DMA_MAP`)
//! must arrive, and, where an IOMMU confines the device, a copy to the same
//! device address after its `DMA_UNMAP` must not reach the page, and devmgr
//! must have taken an IOMMU fault for the device at that address, which the
//! fixture reads from devmgr (`DMA_FAULTS`). Without an IOMMU the phase
//! checks the mapped copies only.
//!
//! The MSI delivery phase asks the same fixture to have the `edu` device
//! raise its interrupt (`INTERRUPT_PROBE`) and asserts that the fixture
//! holds the device's MSI vector, not its wired line, and that the message
//! reached the fixture's notification: devmgr programmed the device's MSI
//! capability with the message of a vector it minted and, where the IOMMU
//! translates the device's message writes (RISC-V), made the target's
//! interrupt file reachable through the device's domain (`MAP_MSI`).
//!
//! The forged-message phase (`MSI_FORGE`) has the confined device's DMA
//! engine write its own message, which must be delivered, and a forged one,
//! which must not be: on riscv64 the interrupt file page beside its target's,
//! which the IOMMU must block and devmgr count as the device's fault; on
//! `x86_64` a remappable message naming a handle no remapping entry holds,
//! after asserting the fixture's own message is remappable.
//!
//! The MSI churn phase asks the fixture to delete, while the device raises
//! its MSI in a loop, the `Interrupt` cap bound to it, and then the bound
//! notification's last cap and the binding's cap, and asserts that after each
//! the next binding the fixture makes receives the device's interrupt. The
//! MSI release phase has the fixture exit with its interrupt raised, waits
//! for devmgr to withdraw it, and asserts `system_ram == kernel_reserved +
//! pool_total`; devmgr then releases the device and frees the
//! message-signaled target, and the later `ram_accounted_identity` phase
//! asserts the identity again. It runs last of the phases that use the
//! fixture.

use std::os::seraph::startup_info;
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::phases::drivers::INPUT_ATTEMPTS;
use crate::runner::Phase;

/// What a phase that needs the test-only devices or class files says when
/// they are missing.
pub(crate) const TEST_DEVICES_HINT: &str = "stage the test class files of \
     /config/devmgr/tests/ with the svctest recipe and boot with \
     `cargo xtask run --test-devices` (docs/testing.md § Gating)";

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "devmgr_class_deny",
            run: class_deny_phase,
        },
        Phase {
            name: "devmgr_shutdown_device_deny",
            run: shutdown_device_deny_phase,
        },
        Phase {
            name: "devmgr_bind_deny",
            run: bind_deny_phase,
        },
        Phase {
            name: "devmgr_input_instance_ordinal",
            run: input_instance_ordinal_phase,
        },
        Phase {
            name: "devmgr_on_demand_bind",
            run: on_demand_bind_phase,
        },
        Phase {
            name: "devmgr_dma_confinement",
            run: dma_confinement_phase,
        },
        Phase {
            name: "devmgr_msi_delivery",
            run: msi_delivery_phase,
        },
        Phase {
            name: "devmgr_msi_forge",
            run: msi_forge_phase,
        },
        Phase {
            name: "devmgr_msi_churn",
            run: msi_churn_phase,
        },
        Phase {
            name: "devmgr_msi_release",
            run: msi_release_phase,
        },
    ]
}

/// A version-current request with the right label.
fn versioned(label: u64) -> ipc::IpcMessage
{
    ipc::IpcMessage::builder(label)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build()
}

/// `label` sent on `devmgr.registry`, whose badge lacks the label's
/// authority bit (`bit_name`), replies `UNAUTHORIZED` and carries no cap.
fn assert_registry_denies(caps: &Caps, label: u64, label_name: &str, bit_name: &str)
{
    let devmgr = caps.devmgr_registry;
    assert!(
        devmgr != 0,
        "{label_name} deny: no devmgr.registry cap seeded"
    );
    assert_denies(devmgr, label, label_name, bit_name);
}

/// `label` sent on `devmgr`, a SEND on devmgr's registry endpoint whose
/// badge lacks what the label needs (`bit_name`), replies `UNAUTHORIZED` and
/// carries no cap.
fn assert_denies(devmgr: u64, label: u64, label_name: &str, bit_name: &str)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();

    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(devmgr, &versioned(label), ipc_buf) }
        .unwrap_or_else(|_| panic!("{label_name} ipc_call failed"));
    assert_eq!(
        reply.label,
        ipc::devmgr_errors::UNAUTHORIZED,
        "{label_name} without {bit_name} must reply UNAUTHORIZED"
    );
    assert!(
        reply.caps().is_empty(),
        "{label_name} deny must carry no cap"
    );
}

/// `QUERY_DEVICE` and `MINT_CLASS_SEND` on `devmgr.registry` and on
/// `devmgr.bind`, neither of whose badges carries a class slot or
/// `CLASS_AUTHORITY`, reply `UNAUTHORIZED`.
fn class_deny_phase(caps: &Caps)
{
    for (cap, shown) in [
        (caps.devmgr_registry, "devmgr.registry"),
        (caps.devmgr_bind, "devmgr.bind"),
    ]
    {
        assert!(cap != 0, "class deny: no {shown} cap seeded");
        assert_denies(
            cap,
            ipc::devmgr_labels::QUERY_DEVICE,
            "QUERY_DEVICE",
            "a class slot",
        );
        assert_denies(
            cap,
            ipc::devmgr_labels::MINT_CLASS_SEND,
            "MINT_CLASS_SEND",
            "CLASS_AUTHORITY",
        );
    }
}

fn shutdown_device_deny_phase(caps: &Caps)
{
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::QUERY_SHUTDOWN_DEVICE,
        "QUERY_SHUTDOWN_DEVICE",
        "SHUTDOWN_DEVICE_AUTHORITY",
    );
}

/// `QUERY_DEVICE` on the `input` class SEND selecting `ordinal` in
/// `data[1]`, or sending no `data[1]` for `None`.
fn query_input(input_class: u64, ordinal: Option<u64>) -> ipc::IpcMessage
{
    let mut req = ipc::IpcMessage::builder(ipc::devmgr_labels::QUERY_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION));
    if let Some(o) = ordinal
    {
        req = req.word(1, o);
    }
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    unsafe { ipc::ipc_call(input_class, &req.build(), ipc_buf) }
        .unwrap_or_else(|_| panic!("input QUERY_DEVICE ordinal {ordinal:?} ipc_call failed"))
}

/// `reply` is a `SUCCESS` carrying one cap, which is released.
fn assert_granted(reply: &ipc::IpcMessage, what: &str)
{
    assert_eq!(reply.label, ipc::devmgr_errors::SUCCESS, "{what} status");
    let cap = reply.caps().first().copied().unwrap_or(0);
    assert!(cap != 0, "{what} carried no cap");
    let _ = syscall::cap_delete(cap);
}

fn input_instance_ordinal_phase(caps: &Caps)
{
    let devmgr = caps.input_class;
    assert!(
        devmgr != 0,
        "input ordinal: no devmgr.class.input cap seeded"
    );

    let mut first = query_input(devmgr, None);
    for _ in 1..INPUT_ATTEMPTS
    {
        if first.label != ipc::devmgr_errors::NO_DEVICE
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        first = query_input(devmgr, None);
    }
    assert_granted(&first, "input QUERY_DEVICE without an ordinal");
    assert_granted(
        &query_input(devmgr, Some(0)),
        "input QUERY_DEVICE ordinal 0",
    );
    for ordinal in [1, u64::MAX]
    {
        let reply = query_input(devmgr, Some(ordinal));
        assert_eq!(
            reply.label,
            ipc::devmgr_errors::NO_DEVICE,
            "input QUERY_DEVICE ordinal {ordinal} past the one keyboard must reply NO_DEVICE"
        );
        assert!(
            reply.caps().is_empty(),
            "ordinal {ordinal} reply must carry no cap"
        );
    }
}

/// Read memmgr's current free-pool total (`QUERY_POOL_STATUS` `data[3]`).
fn free_bytes(memmgr_ep: u64, ipc_buf: *mut u64) -> u64
{
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }
        .expect("memmgr QUERY_POOL_STATUS ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "QUERY_POOL_STATUS status"
    );
    reply.word(3)
}

/// `BIND_DRIVERS` on `devmgr.registry` (no `BIND_AUTHORITY`) replies
/// `UNAUTHORIZED`.
fn bind_deny_phase(caps: &Caps)
{
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::BIND_DRIVERS,
        "BIND_DRIVERS",
        "BIND_AUTHORITY",
    );
}

/// `QUERY_DEVICE` on the class SEND `class` at `ordinal`: the driver SEND, or
/// devmgr's refusal label.
fn query_class(class: u64, ordinal: u64, what: &str) -> Result<u64, u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    match unsafe { ipc::query_device(class, ordinal, ipc_buf) }
    {
        Ok(cap) => Ok(cap),
        Err(ipc::ClassCallError::Refused(label)) => Err(label),
        Err(e) => panic!("{what} QUERY_DEVICE ordinal {ordinal} failed: {e:?}"),
    }
}

/// Call a fault fixture with `label` and no data.
fn call_fixture(cap: u64, label: u64) -> Result<ipc::IpcMessage, i64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    unsafe { ipc::ipc_call(cap, &ipc::IpcMessage::new(label), ipc_buf) }
}

/// Send `BIND_DRIVERS` on `devmgr.bind` with a cap on `/tests/drivers/`;
/// asserts devmgr accepts it.
fn bind_test_drivers(devmgr_bind: u64)
{
    let rights = u64::from(
        namespace_protocol::rights::LOOKUP
            | namespace_protocol::rights::READ
            | namespace_protocol::rights::READDIR,
    );
    let root = std::os::seraph::root_dir_cap();
    assert!(root != 0, "devmgr_on_demand_bind: no root directory cap");
    let dir = std::os::seraph::namespace_lookup_dir(root, "/tests/drivers", rights)
        .unwrap_or_else(|e| panic!("devmgr_on_demand_bind: walk /tests/drivers failed: {e}"));
    let msg = ipc::IpcMessage::builder(ipc::devmgr_labels::BIND_DRIVERS)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .cap(dir)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(devmgr_bind, &msg, ipc_buf) })
    else
    {
        // The call failed before the kernel moved the cap.
        let _ = syscall::cap_delete(dir);
        panic!("devmgr_on_demand_bind: BIND_DRIVERS ipc_call failed");
    };
    assert_eq!(
        reply.label,
        ipc::devmgr_errors::SUCCESS,
        "devmgr_on_demand_bind: BIND_DRIVERS status"
    );
}

/// devmgr binds a directory's drivers on demand, in a settle batch of its
/// own while the registry serves; the settle ends at its bound and destroys
/// a driver that never reports ready; a driver that fails its bootstrap is
/// destroyed; a served driver's death withdraws its endpoint (a call queued
/// on it returns) and leaves a tombstone at its ordinal while the later
/// ordinal keeps its driver; a second bind over the same directory binds
/// nothing.
fn on_demand_bind_phase(caps: &Caps)
{
    use ipc::devmgr_errors::{NO_DEVICE, SUCCESS, WITHDRAWN};
    use ipc::test_fault_labels::{FAULT_EXIT, FAULT_PING};

    let devmgr = caps.devmgr_bind;
    assert!(
        devmgr != 0,
        "devmgr_on_demand_bind: no devmgr.bind cap seeded"
    );
    let fault = caps.test_fault_class;
    assert!(
        fault != 0,
        "devmgr_on_demand_bind: no devmgr.class.test-fault cap seeded: {TEST_DEVICES_HINT}"
    );
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let memmgr = startup_info().memmgr_endpoint;
    let free_before = free_bytes(memmgr, ipc_buf);

    let start = Instant::now();
    bind_test_drivers(devmgr);

    // devmgr's registry workers serve a class already settled while the
    // bind's batch settles, which the never-ready fixture holds until the
    // bound: the input query returns before the bound has elapsed since the
    // request. A registry that served nothing during a settle would answer
    // it only after the bound.
    let bound = Duration::from_millis(ipc::devmgr_labels::SETTLE_TIMEOUT_MS);
    assert_granted(
        &query_input(caps.input_class, None),
        "input QUERY_DEVICE during the on-demand settle",
    );
    let served_during = start.elapsed();
    assert!(
        served_during < bound,
        "devmgr_on_demand_bind: the input query returned after {served_during:?}, not before \
         the bind's settle bound {bound:?}: the registry served nothing while it settled"
    );

    // Served once the bind's settle has ended: a query that finds no driver
    // waits for it.
    let first = match query_class(fault, 0, "test-fault")
    {
        Ok(cap) => cap,
        Err(NO_DEVICE) => panic!(
            "devmgr_on_demand_bind: no test-fault fixture bound; the pci-testdev functions \
             are missing: {TEST_DEVICES_HINT}"
        ),
        Err(label) => panic!("devmgr_on_demand_bind: test-fault ordinal 0 status {label:#x}"),
    };
    let settle = start.elapsed();
    assert!(
        settle >= bound,
        "devmgr_on_demand_bind: the settle ended after {settle:?}, before its bound {bound:?}, \
         with a fixture that never reports ready"
    );
    let second = query_class(fault, 1, "test-fault")
        .unwrap_or_else(|l| panic!("devmgr_on_demand_bind: test-fault ordinal 1 status {l:#x}"));
    assert_eq!(
        query_class(fault, 2, "test-fault"),
        Err(NO_DEVICE),
        "devmgr_on_demand_bind: only the two serving fixtures may be served"
    );

    // The fixture at ordinal 0 replies, then dies without receiving again, so
    // the PING sent after the reply is queued on its endpoint until devmgr
    // withdraws it.
    let exit = call_fixture(first, FAULT_EXIT).expect("FAULT_EXIT call failed");
    assert_eq!(exit.label, SUCCESS, "FAULT_EXIT reply");
    assert!(
        call_fixture(first, FAULT_PING).is_err(),
        "a call queued on a dead served driver's endpoint must return an error"
    );
    assert_eq!(
        query_class(fault, 0, "test-fault"),
        Err(WITHDRAWN),
        "the dead fixture's ordinal must reply WITHDRAWN"
    );

    // The ordinal after the tombstone keeps its live fixture.
    let again = query_class(fault, 1, "test-fault").unwrap_or_else(|l| {
        panic!("devmgr_on_demand_bind: test-fault ordinal 1 after the withdrawal status {l:#x}")
    });
    let ping = call_fixture(again, FAULT_PING).expect("FAULT_PING on ordinal 1 failed");
    assert_eq!(ping.label, SUCCESS, "FAULT_PING reply");

    // Retire the last fixture; its own withdrawal is not observed here.
    let _ = call_fixture(second, FAULT_EXIT);
    for cap in [first, second, again]
    {
        let _ = syscall::cap_delete(cap);
    }

    assert_holds_returned(memmgr, free_before);
    let rebind = assert_rebind_binds_nothing(devmgr, fault, bound);

    std::os::seraph::log!(
        "devmgr_on_demand_bind passed: settle ended at its bound after {settle:?}, \
         never-ready and refusing fixtures destroyed, dead driver withdrawn, later ordinal \
         kept, second bind settled after {rebind:?}"
    );
}

/// With every fixture gone, memmgr's free pool returns to `free_before`, its
/// level before the bind, only if devmgr destroyed the never-ready fixture
/// and the one that refused its bootstrap, each of which holds `HOLD_BYTES`
/// until it is destroyed; the two serving fixtures exited and are reaped.
/// Half of one hold absorbs the pool's incidental movement (the fixture
/// ELF's file-cache warming included), so either fixture left alive fails
/// it.
fn assert_holds_returned(memmgr: u64, free_before: u64)
{
    // A test wait bound: it limits only how long the phase polls for the
    // fixtures' pages to return before it fails.
    const RECLAIM_POLLS: u32 = 300;

    let ipc_buf = std::os::seraph::current_ipc_buf();
    let margin = (ipc::test_fault_labels::HOLD_BYTES / 2) as u64;
    let mut free_after = free_bytes(memmgr, ipc_buf);
    for _ in 0..RECLAIM_POLLS
    {
        if free_after + margin >= free_before
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        free_after = free_bytes(memmgr, ipc_buf);
    }
    assert!(
        free_after + margin >= free_before,
        "devmgr_on_demand_bind: the never-ready or the refusing fixture's pages did not \
         return (free_before={free_before} free_after={free_after}); it was not destroyed"
    );
}

/// A record is bound at most once a boot: a second bind over the same
/// directory starts nothing, so its settle ends well within `bound` and no
/// fixture joins the `test-fault` class (`fault`). Returns how long the
/// second bind took to settle.
fn assert_rebind_binds_nothing(devmgr_bind: u64, fault: u64, bound: Duration) -> Duration
{
    let start = Instant::now();
    bind_test_drivers(devmgr_bind);
    assert_eq!(
        query_class(fault, 2, "test-fault"),
        Err(ipc::devmgr_errors::NO_DEVICE),
        "devmgr_on_demand_bind: a second bind must bind no device again"
    );
    let rebind = start.elapsed();
    assert!(
        rebind < bound,
        "devmgr_on_demand_bind: the second bind's settle took {rebind:?}, not less than its \
         bound {bound:?}, with no driver to start"
    );
    rebind
}

/// The `test-dma` fixture's reply to `label` with no data, the fixture asked
/// of the `test-dma` class (`devmgr.class.test-dma`) at ordinal 0; `phase`
/// names the caller in a failure.
fn call_test_dma(caps: &Caps, label: u64, phase: &str) -> ipc::IpcMessage
{
    let class = caps.test_dma_class;
    assert!(
        class != 0,
        "{phase}: no devmgr.class.test-dma cap seeded: {TEST_DEVICES_HINT}"
    );
    // Served once the settle of devmgr's drivers-directory pass ends, which
    // can lag svctest's start as the input driver's does.
    let mut query = query_class(class, 0, "test-dma");
    for _ in 1..INPUT_ATTEMPTS
    {
        if query != Err(ipc::devmgr_errors::NO_DEVICE)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        query = query_class(class, 0, "test-dma");
    }
    let fixture = match query
    {
        Ok(cap) => cap,
        Err(ipc::devmgr_errors::NO_DEVICE) => panic!(
            "{phase}: no test-dma fixture bound; the edu device is missing: \
             {TEST_DEVICES_HINT}"
        ),
        Err(status) => panic!("{phase}: test-dma QUERY_DEVICE status {status:#x}"),
    };
    let reply = call_fixture(fixture, label)
        .unwrap_or_else(|e| panic!("{phase}: test-dma call {label:#x} failed: {e}"));
    let _ = syscall::cap_delete(fixture);
    reply
}

/// A copy through a mapped page arrives; behind an IOMMU, a copy to the
/// page's device address after its unmap does not, and devmgr takes a fault
/// for it.
fn dma_confinement_phase(caps: &Caps)
{
    use ipc::test_dma_labels::{DMA_PROBE, PROBE_PASSED, PROBE_SKIPPED};

    let probe = call_test_dma(caps, DMA_PROBE, "devmgr_dma");
    assert_eq!(probe.label, ipc::devmgr_errors::SUCCESS, "DMA_PROBE setup");
    let (outcome, landed, iova) = (probe.word(0), probe.word(1) != 0, probe.word(2));
    let confined = probe.word(3) == ipc::devmgr_dma_labels::DMA_CONFINED;
    let (faults, last_fault) = (probe.word(4), probe.word(5));

    if !confined
    {
        assert!(
            outcome == PROBE_PASSED || outcome == PROBE_SKIPPED,
            "devmgr_dma: a mapped copy did not arrive (outcome {outcome})"
        );
        assert_eq!(
            faults, 0,
            "devmgr_dma: devmgr counted faults for an unconfined device"
        );
        std::os::seraph::log!(
            "devmgr_dma_confinement passed unconfined: outcome {outcome}, device address {iova:#x}"
        );
        return;
    }
    assert_eq!(
        outcome, PROBE_PASSED,
        "devmgr_dma: a copy through a mapped IOVA did not arrive"
    );
    assert!(
        !landed,
        "devmgr_dma: a copy to IOVA {iova:#x} after its unmap reached the page"
    );
    assert!(
        faults >= 1,
        "devmgr_dma: no IOMMU fault taken for the device after the unmapped copy"
    );
    assert_eq!(
        last_fault,
        iova & !0xfff,
        "devmgr_dma: the latest fault names another IOVA"
    );
    std::os::seraph::log!(
        "devmgr_dma_confinement passed: mapped copy arrived at IOVA {iova:#x}, \
         the copy after its unmap faulted ({faults} faults)"
    );
}

/// The `edu` device's MSI vector, which devmgr gave its driver, delivers: the
/// fixture holds an MSI interrupt and the device's raise reaches it.
fn msi_delivery_phase(caps: &Caps)
{
    let probe = call_test_dma(
        caps,
        ipc::test_dma_labels::INTERRUPT_PROBE,
        "devmgr_msi_delivery",
    );
    assert_eq!(
        probe.label,
        ipc::devmgr_errors::SUCCESS,
        "devmgr_msi_delivery: INTERRUPT_PROBE status"
    );
    let (delivered, kind) = (probe.word(0) != 0, probe.word(1));
    assert_eq!(
        kind,
        driver_binding::resources::InterruptKind::Msi as u64,
        "devmgr_msi_delivery: the fixture holds interrupt kind {kind} (0 none, 1 wired, 3 MSI-X), \
         not MSI"
    );
    assert!(
        delivered,
        "devmgr_msi_delivery: the edu device's MSI did not reach the fixture within {} ms",
        ipc::test_dma_labels::INTERRUPT_WAIT_MS
    );
    std::os::seraph::log!("devmgr_msi_delivery passed: the edu device's MSI was delivered");
}

/// A confined device's message reaches only the targets devmgr gave it. The
/// fixture has the `edu` device's DMA engine write its own message, which is
/// delivered, then a forged one, which is not. On riscv64 the forged write
/// goes to the interrupt file page beside its target's, which the device's
/// domain does not map, so the IOMMU blocks it and devmgr counts the fault
/// for the device at that page. On `x86_64` the fixture's message must be
/// remappable, and the forged write names a remapping handle no entry holds;
/// QEMU's DMA engine writes carry no requester, so the remapping fault is
/// not attributed to the device, and the check there is non-delivery, not
/// an attributed fault. An unconfined device makes no forged write.
fn msi_forge_phase(caps: &Caps)
{
    const PHASE: &str = "devmgr_msi_forge";
    let probe = call_test_dma(caps, ipc::test_dma_labels::MSI_FORGE, PHASE);
    assert_eq!(
        probe.label,
        ipc::devmgr_errors::SUCCESS,
        "{PHASE}: MSI_FORGE status"
    );
    let made = probe.word(1) != 0;
    if probe.word(0) != ipc::devmgr_dma_labels::DMA_CONFINED
    {
        assert!(
            !made,
            "{PHASE}: the fixture forged a message for an unconfined device"
        );
        std::os::seraph::log!("{PHASE} passed unconfined: no forged write is made");
        return;
    }
    let (own, forged_delivered) = (probe.word(2) != 0, probe.word(3) != 0);
    let (address, forged, faults, last_fault) =
        (probe.word(4), probe.word(5), probe.word(6), probe.word(7));
    if cfg!(target_arch = "x86_64")
    {
        // Bit 4 of the message address: the remappable format.
        assert!(
            address & (1 << 4) != 0,
            "{PHASE}: the confined device's message address {address:#x} is not remappable"
        );
    }
    assert!(
        made,
        "{PHASE}: the fixture made no forged write (own message {address:#x})"
    );
    assert!(
        own,
        "{PHASE}: the device's write of its own message to {address:#x} was not delivered"
    );
    assert!(
        !forged_delivered,
        "{PHASE}: the device's forged message to {forged:#x} was delivered"
    );
    if cfg!(target_arch = "riscv64")
    {
        assert!(
            faults >= 1,
            "{PHASE}: no IOMMU fault taken for the forged write"
        );
        assert_eq!(
            last_fault,
            forged & !0xfff,
            "{PHASE}: the latest fault names another page than the forged write's"
        );
    }
    std::os::seraph::log!(
        "{PHASE} passed: own message at {address:#x} delivered, forged message at {forged:#x} \
         not delivered ({faults} faults)"
    );
}

/// The `edu` device raises its MSI in a loop while the fixture deletes the
/// `Interrupt` cap bound to it, and again while it deletes the bound
/// notification's last cap and then the binding's; after each, a spare copy
/// the fixture binds to a new notification receives the device's interrupt.
fn msi_churn_phase(caps: &Caps)
{
    use ipc::test_dma_labels::{CHURN_BOUND_CAP, CHURN_NOTIFICATION, INTERRUPT_CHURN};

    let churn = call_test_dma(caps, INTERRUPT_CHURN, "devmgr_msi_churn");
    assert_eq!(
        churn.label,
        ipc::devmgr_errors::SUCCESS,
        "devmgr_msi_churn: INTERRUPT_CHURN status"
    );
    let (passed, kind, raises) = (churn.word(0), churn.word(1), churn.word(2));
    assert_eq!(
        kind,
        driver_binding::resources::InterruptKind::Msi as u64,
        "devmgr_msi_churn: the fixture holds interrupt kind {kind}, not MSI"
    );
    assert!(
        raises > 0,
        "devmgr_msi_churn: the fixture's raise loop made no raise"
    );
    assert!(
        passed & CHURN_BOUND_CAP != 0,
        "devmgr_msi_churn: after the bound cap's delete under raises, the next binding \
         received no interrupt"
    );
    assert!(
        passed & CHURN_NOTIFICATION != 0,
        "devmgr_msi_churn: after the bound notification's and the binding's deletes under \
         raises, the next binding received no interrupt"
    );
    std::os::seraph::log!(
        "devmgr_msi_churn passed: both cases' next bindings received the MSI ({raises} raises)"
    );
}

/// The fixture exits with its interrupt raised, devmgr withdraws it, and
/// `system_ram == kernel_reserved + pool_total` holds. devmgr's control
/// thread releases the device, which frees the message-signaled target devmgr
/// minted for it, right after the class answers `WITHDRAWN`, and no request
/// svctest can make observes that release's end, so the assertion here may
/// precede the free; the `ram_accounted_identity` phase, which runs after
/// every devmgr phase, asserts the identity again once it has long run. The
/// last phase that uses the fixture: none serves the class afterwards.
fn msi_release_phase(caps: &Caps)
{
    // A test wait bound: it limits only how long the phase polls for the
    // withdrawal before it fails.
    const WITHDRAW_POLLS: u32 = 300;

    let exit = call_test_dma(
        caps,
        ipc::test_dma_labels::FIXTURE_EXIT,
        "devmgr_msi_release",
    );
    assert_eq!(
        exit.label,
        ipc::devmgr_errors::SUCCESS,
        "devmgr_msi_release: FIXTURE_EXIT status"
    );
    let mut query = query_class(caps.test_dma_class, 0, "test-dma");
    for _ in 1..WITHDRAW_POLLS
    {
        if query == Err(ipc::devmgr_errors::WITHDRAWN)
        {
            break;
        }
        if let Ok(cap) = query
        {
            let _ = syscall::cap_delete(cap);
        }
        std::thread::sleep(Duration::from_millis(10));
        query = query_class(caps.test_dma_class, 0, "test-dma");
    }
    if let Ok(cap) = query
    {
        let _ = syscall::cap_delete(cap);
    }
    assert_eq!(
        query,
        Err(ipc::devmgr_errors::WITHDRAWN),
        "devmgr_msi_release: the exited fixture was not withdrawn"
    );
    crate::phases::memmgr::ram_accounted_identity_phase(caps);
    std::os::seraph::log!(
        "devmgr_msi_release passed: the fixture's target was released and RAM stays accounted"
    );
}
