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
//! The location phase asks `QUERY_DEVICE_LOCATION` of the same ordinals and
//! asserts a PCI location for the keyboard, a PCI function, and `NO_DEVICE`
//! past it, and asks it of the `serial` class (`devmgr.class.serial`),
//! whose driver serves the machine's UART, a platform device, and asserts
//! `NO_LOCATION`.
//!
//! The on-demand bind phase sends `BIND_DRIVERS` on `devmgr.bind` with a cap
//! on `/tests/drivers/`, which holds the `test-fault` fixture, whose
//! declaration matches the five `pci-testdev` functions a test launch
//! attaches (`cargo xtask run --test-devices`): two the fixture serves, one
//! on which it exits before its next bootstrap request, bound between the
//! two, one on which it never reports ready, and one on which it refuses its
//! bootstrap. It asserts that the registry serves another class while the
//! bind's settle runs, that the settle ends no earlier than its bound with
//! the two serving fixtures at ordinals 0 and 1 and no other, located at
//! the two `pci-testdev` functions the launch attaches with no BAR 2, that devmgr
//! logged the death of the fixture that exits before its bootstrap request
//! (read from logd's history through `logd.query`) and went on binding, so
//! the second serving fixture holds ordinal 1, that a served
//! fixture's death withdraws it (a call queued on it returns, its ordinal
//! replies `WITHDRAWN`) while ordinal 1 keeps its fixture, that a fault of a
//! thread other than the main thread of the fixture at ordinal 1 withdraws
//! it the same way, that memmgr's
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
//! The IOMMU driver restart phase has the fixture start a DMA stream
//! (`DMA_STREAM_START`): a page of its memory stays mapped for the device while
//! a thread copies through it in a loop. It kills the IOMMU driver through the
//! debug authority and waits for a new instance of it and for the line devmgr
//! logs when it restarted the driver (read from logd's history through
//! `logd.query`), which must report at least one mapping installed again and one
//! hold released. It asserts that the stream's rounds continue after the
//! restart with none failed and no IOMMU fault taken for the device, that the
//! fixture's DMA probe and interrupt probe pass as in the phases above, and that
//! a read of the bootstrap bundle's header from the root filesystem succeeds.
//! Without an IOMMU confining the device the phase is skipped.
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
use crate::phases::drivers::DEVICE_WAIT_MS;
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
            name: "devmgr_device_location",
            run: device_location_phase,
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
            name: "devmgr_iommu_restart",
            run: iommu_restart_phase,
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

/// `QUERY_DEVICE`, `QUERY_DEVICE_LOCATION`, `WATCH_CLASS`, and
/// `MINT_CLASS_SEND` on `devmgr.registry`
/// and on `devmgr.bind`, neither of whose badges carries a class slot or
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
            ipc::devmgr_labels::WATCH_CLASS,
            "WATCH_CLASS",
            "a class slot",
        );
        assert_denies(
            cap,
            ipc::devmgr_labels::QUERY_DEVICE_LOCATION,
            "QUERY_DEVICE_LOCATION",
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

    // Served once the settle of devmgr's drivers-directory pass ends.
    let served = await_class(devmgr, "input")
        .unwrap_or_else(|l| panic!("input ordinal: no input driver served (status {l:#x})"));
    let _ = syscall::cap_delete(served);
    assert_granted(
        &query_input(devmgr, None),
        "input QUERY_DEVICE without an ordinal",
    );
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

/// `QUERY_DEVICE_LOCATION` of the input driver, a PCI function's, at its
/// ordinal and past it, and of the serial driver, a platform device's.
fn device_location_phase(caps: &Caps)
{
    use ipc::devmgr_errors::{NO_DEVICE, NO_LOCATION};

    let input = caps.input_class;
    assert!(input != 0, "location: no devmgr.class.input cap seeded");
    let serial = caps.serial_class;
    assert!(serial != 0, "location: no devmgr.class.serial cap seeded");
    for (class, what) in [(input, "input"), (serial, "serial")]
    {
        let served = await_class(class, what)
            .unwrap_or_else(|l| panic!("location: no {what} driver served (status {l:#x})"));
        let _ = syscall::cap_delete(served);
    }
    let keyboard = locate_class(input, 0, "input")
        .unwrap_or_else(|l| panic!("location: input ordinal 0 status {l:#x}"));
    assert_eq!(
        locate_class(input, 1, "input"),
        Err(NO_DEVICE),
        "location: input ordinal 1, past the one keyboard"
    );
    assert_eq!(
        locate_class(serial, 0, "serial"),
        Err(NO_LOCATION),
        "location: the serial driver's UART is a platform device"
    );
    std::os::seraph::log!(
        "devmgr_device_location passed: keyboard at {:04x}:{:02x}:{:02x}.{}, serial on none",
        keyboard.segment,
        keyboard.bus,
        keyboard.device,
        keyboard.function
    );
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

/// `QUERY_DEVICE_LOCATION` on the class SEND `class` at `ordinal`: where the
/// driver's device sits, or devmgr's refusal label.
fn locate_class(
    class: u64,
    ordinal: u64,
    what: &str,
) -> Result<ipc::devmgr_labels::PciLocation, u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    match unsafe { ipc::query_device_location(class, ordinal, ipc_buf) }
    {
        Ok(at) => Ok(at),
        Err(ipc::ClassCallError::Refused(label)) => Err(label),
        Err(e) => panic!("{what} QUERY_DEVICE_LOCATION ordinal {ordinal} failed: {e:?}"),
    }
}

/// The first live driver of the class SEND `class`, waited for on a
/// `WATCH_CLASS` watch for at most [`DEVICE_WAIT_MS`] while devmgr serves
/// none (`ipc::await_device`): the driver SEND, or devmgr's refusal label.
fn await_class(class: u64, what: &str) -> Result<u64, u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    match unsafe { ipc::await_device(class, DEVICE_WAIT_MS, ipc_buf, || {}) }
    {
        Ok(cap) => Ok(cap),
        Err(ipc::ClassCallError::Refused(label)) => Err(label),
        Err(e) => panic!("{what} QUERY_DEVICE failed: {e:?}"),
    }
}

/// `WATCH_CLASS` on the class SEND `class`: the watch, or devmgr's refusal
/// label.
fn watch_class(class: u64) -> Result<ipc::ClassWatch, u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    match unsafe { ipc::watch_class(class, ipc_buf) }
    {
        Ok(watch) => Ok(watch),
        Err(ipc::ClassCallError::Refused(label)) => Err(label),
        Err(e) => panic!("devmgr_on_demand_bind: WATCH_CLASS failed: {e:?}"),
    }
}

/// Wait at most `ms` milliseconds for devmgr to signal the class watch
/// `note`; asserts it signals `WATCH_CLASS_CHANGED`, the signal of `what`.
fn assert_signalled(note: u64, ms: u64, what: &str)
{
    let bits = syscall::notification_wait_timeout(note, ms)
        .unwrap_or_else(|e| panic!("devmgr_on_demand_bind: watch wait failed: {e}"));
    assert!(
        bits & ipc::devmgr_labels::WATCH_CLASS_CHANGED != 0,
        "devmgr_on_demand_bind: no watch signal within {ms} ms when {what}"
    );
}

/// A class holds at most `MAX_CLASS_WATCHERS` watches: with `held` live
/// watches on the class SEND `class`, fill it, find the next registration
/// refused with `WATCHERS_FULL`, and find one admitted once a watcher has
/// deleted its copy, which devmgr's sweep finds gone. Deletes every watch it
/// registered.
fn assert_watch_bound(class: u64, held: usize)
{
    use ipc::devmgr_labels::MAX_CLASS_WATCHERS;

    let mut notes = Vec::new();
    for _ in held..MAX_CLASS_WATCHERS
    {
        let watch = watch_class(class)
            .unwrap_or_else(|l| panic!("devmgr_on_demand_bind: watch below the bound: {l:#x}"));
        notes.push(watch.note);
    }
    assert_eq!(
        watch_class(class).map(|w| w.note),
        Err(ipc::devmgr_errors::WATCHERS_FULL),
        "devmgr_on_demand_bind: a watch past MAX_CLASS_WATCHERS must be refused"
    );
    if let Some(note) = notes.pop()
    {
        let _ = syscall::cap_delete(note);
    }
    let again = watch_class(class).unwrap_or_else(|l| {
        panic!("devmgr_on_demand_bind: a gone watch was not dropped for a new one: {l:#x}")
    });
    notes.push(again.note);
    for note in notes
    {
        let _ = syscall::cap_delete(note);
    }
}

/// Call a fault fixture with `label` and no data.
fn call_fixture(cap: u64, label: u64) -> Result<ipc::IpcMessage, i64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    unsafe { ipc::ipc_call(cap, &ipc::IpcMessage::new(label), ipc_buf) }
}

/// The absolute path of the directory the on-demand bind walks and names to
/// devmgr.
const TEST_DRIVERS_PATH: &str = "/tests/drivers";

/// Send `BIND_DRIVERS` on `devmgr.bind` with a cap on `/tests/drivers/` and
/// its path;
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
    let dir = std::os::seraph::namespace_lookup_dir(root, TEST_DRIVERS_PATH, rights)
        .unwrap_or_else(|e| panic!("devmgr_on_demand_bind: walk {TEST_DRIVERS_PATH} failed: {e}"));
    let builder = ipc::IpcMessage::builder(ipc::devmgr_labels::BIND_DRIVERS)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .cap(dir);
    let Some(builder) = ipc::with_name_block(
        builder,
        ipc::devmgr_labels::DRIVERS_DIR_PATH_WORD,
        TEST_DRIVERS_PATH.as_bytes(),
        ipc::devmgr_labels::DRIVERS_DIR_PATH_MAX,
    )
    else
    {
        let _ = syscall::cap_delete(dir);
        panic!("devmgr_on_demand_bind: path not sendable");
    };
    let msg = builder.build();
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
/// destroyed; a driver that dies before a bootstrap request is abandoned and
/// the bind goes on to the next function; a served driver's death withdraws
/// its endpoint (a call queued on it returns) and leaves a tombstone at its
/// ordinal while the later ordinal keeps its driver; a fault of a served
/// driver's worker thread withdraws it the same way; a second bind over the
/// same directory binds nothing. A `WATCH_CLASS` watch on the class is
/// signalled when the bind serves the fixtures and when the dead one is
/// withdrawn, and the class holds at most `MAX_CLASS_WATCHERS` watches, a gone
/// one dropped for a new one.
fn on_demand_bind_phase(caps: &Caps)
{
    use ipc::devmgr_errors::{NO_DEVICE, SUCCESS};
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
    // Registered before the free pool is read, so the Notification devmgr
    // creates for it is not counted against the fixtures' holds.
    let watch = watch_class(fault)
        .unwrap_or_else(|l| panic!("devmgr_on_demand_bind: WATCH_CLASS status {l:#x}"));
    assert_eq!(
        watch.ordinals, 0,
        "devmgr_on_demand_bind: the test-fault class served an ordinal before the bind"
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

    // The watch is signalled once the bind's settle has ended and devmgr
    // serves the fixtures; the query then names one.
    assert_signalled(
        watch.note,
        ipc::devmgr_labels::SETTLE_TIMEOUT_MS + DEVICE_WAIT_MS,
        "the bind served the test-fault fixtures",
    );
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
    assert_death_in_bootstrap_logged(caps.logd_query);
    // The function devmgr binds after the one whose fixture exits before its
    // next bootstrap request: served only when devmgr's wait for that request
    // saw the death and the bind went on.
    let second = query_class(fault, 1, "test-fault").unwrap_or_else(|l| {
        panic!(
            "devmgr_on_demand_bind: test-fault ordinal 1 status {l:#x}; a bind stopped at the \
             fixture that died before its bootstrap request leaves it unbound"
        )
    });
    assert_eq!(
        query_class(fault, 2, "test-fault"),
        Err(NO_DEVICE),
        "devmgr_on_demand_bind: only the two serving fixtures may be served"
    );
    assert_fixture_locations(fault);
    // Take the bits of the second fixture's serving, which the query above
    // waited for, so the next wait sees the withdrawal's.
    let _ = syscall::notification_try_wait(watch.note);

    // The fixture at ordinal 0 replies, then dies without receiving again, so
    // the PING sent after the reply is queued on its endpoint until devmgr
    // withdraws it.
    let exit = call_fixture(first, FAULT_EXIT).expect("FAULT_EXIT call failed");
    assert_eq!(exit.label, SUCCESS, "FAULT_EXIT reply");
    assert!(
        call_fixture(first, FAULT_PING).is_err(),
        "a call queued on a dead served driver's endpoint must return an error"
    );
    // The withdrawal signals the watch in the hold that leaves the
    // tombstone, before the revocation that returned the queued call.
    assert_signalled(watch.note, DEVICE_WAIT_MS, "the dead fixture was withdrawn");
    assert_ordinal_withdrawn(fault, 0);

    // The ordinal after the tombstone keeps its live fixture.
    let again = query_class(fault, 1, "test-fault").unwrap_or_else(|l| {
        panic!("devmgr_on_demand_bind: test-fault ordinal 1 after the withdrawal status {l:#x}")
    });
    let ping = call_fixture(again, FAULT_PING).expect("FAULT_PING on ordinal 1 failed");
    assert_eq!(ping.label, SUCCESS, "FAULT_PING reply");

    assert_worker_fault_withdraws(fault, again, watch.note);
    for cap in [first, second, again]
    {
        let _ = syscall::cap_delete(cap);
    }

    assert_holds_returned(memmgr, free_before);
    let rebind = assert_rebind_binds_nothing(devmgr, fault, bound);
    assert_watch_bound(fault, 1);
    let _ = syscall::cap_delete(watch.note);

    std::os::seraph::log!(
        "devmgr_on_demand_bind passed: settle ended at its bound after {settle:?}, \
         never-ready and refusing fixtures destroyed, bind abandoned for the fixture that died \
         before its bootstrap request, dead driver withdrawn, later ordinal \
         kept, driver whose worker thread faulted withdrawn, second bind settled after \
         {rebind:?}, watch signalled on serve and withdrawals"
    );
}

/// The line devmgr logs when a driver dies before a bootstrap request it
/// waits for (`serve_list_round` in `services/devmgr/src/spawn.rs`).
const DIED_IN_BOOTSTRAP: &[u8] = b"driver died during its bootstrap";

/// devmgr logged the death of the fixture that exits before its next
/// bootstrap request, read from logd's history through `query`
/// (`logd.query`): the function was bound, and devmgr's wait for that
/// request saw the death. Polled for at most [`DEVICE_WAIT_MS`], since the
/// line reaches logd's history after devmgr sends it.
fn assert_death_in_bootstrap_logged(query: u64)
{
    assert!(
        query != 0,
        "devmgr_on_demand_bind: no logd.query cap seeded"
    );
    let start = Instant::now();
    let wait = Duration::from_millis(DEVICE_WAIT_MS);
    loop
    {
        let logged = super::procmgr::logd_history_with(query, None, |entry| {
            entry
                .bytes
                .windows(DIED_IN_BOOTSTRAP.len())
                .any(|w| w == DIED_IN_BOOTSTRAP)
        })
        .into_iter()
        .any(|hit| hit);
        if logged
        {
            return;
        }
        assert!(
            start.elapsed() < wait,
            "devmgr_on_demand_bind: devmgr logged no driver death during its bootstrap within \
             {wait:?}: the fixture that exits before its next bootstrap request was not bound, or \
             its death was not seen"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
/// The `test-fault` class's (`fault`) `ordinal`, whose fixture died, replies
/// `WITHDRAWN` to `QUERY_DEVICE` and to `QUERY_DEVICE_LOCATION`.
fn assert_ordinal_withdrawn(fault: u64, ordinal: u64)
{
    use ipc::devmgr_errors::WITHDRAWN;
    assert_eq!(
        query_class(fault, ordinal, "test-fault"),
        Err(WITHDRAWN),
        "the dead fixture's ordinal must reply WITHDRAWN"
    );
    assert_eq!(
        locate_class(fault, ordinal, "test-fault"),
        Err(WITHDRAWN),
        "the dead fixture's ordinal must reply WITHDRAWN to QUERY_DEVICE_LOCATION"
    );
}

/// Where the launch puts the `pci-testdev` functions the `test-fault`
/// fixture serves, those with no BAR 2 (`TEST_FAULT_DEVICES` in
/// xtask/src/qemu.rs): slots 0x15 and 0x16 of segment 0's root bus, in the
/// order devmgr serves them.
const SERVING_FIXTURE_SLOTS: [u8; 2] = [0x15, 0x16];

/// The `test-fault` class's two served fixtures are located at the
/// functions they were bound to (`QUERY_DEVICE_LOCATION`), and past them
/// `NO_DEVICE`.
fn assert_fixture_locations(fault: u64)
{
    for (ordinal, device) in (0u64..).zip(SERVING_FIXTURE_SLOTS)
    {
        let expected = ipc::devmgr_labels::PciLocation {
            segment: 0,
            bus: 0,
            device,
            function: 0,
        };
        assert_eq!(
            locate_class(fault, ordinal, "test-fault"),
            Ok(expected),
            "devmgr_on_demand_bind: test-fault ordinal {ordinal} location"
        );
    }
    assert_eq!(
        locate_class(fault, 2, "test-fault"),
        Err(ipc::devmgr_errors::NO_DEVICE),
        "devmgr_on_demand_bind: test-fault ordinal 2 location past the two served"
    );
}

/// A fault of a thread other than the main thread of the served fixture at
/// ordinal 1 of the `test-fault` class (`fault`), reached through `fixture`,
/// withdraws it: the fixture replies to `FAULT_WORKER`, then receives nothing
/// more, and a thread of its own faults while its main thread lives on.
/// procmgr tears the fixture down, which posts no death for the main
/// thread, so only the observer devmgr had procmgr bind on its address space
/// sees it: the `FAULT_PING` queued meanwhile returns once devmgr withdraws
/// the fixture, the class watch (`note`) is signalled, and the ordinal then
/// replies `WITHDRAWN`.
fn assert_worker_fault_withdraws(fault: u64, fixture: u64, note: u64)
{
    use ipc::devmgr_errors::{SUCCESS, WITHDRAWN};
    use ipc::test_fault_labels::{FAULT_PING, FAULT_WORKER};

    let _ = syscall::notification_try_wait(note);
    let worker = call_fixture(fixture, FAULT_WORKER).expect("FAULT_WORKER call failed");
    assert_eq!(worker.label, SUCCESS, "FAULT_WORKER reply");
    assert!(
        call_fixture(fixture, FAULT_PING).is_err(),
        "a call queued on a served driver whose worker thread faulted must return an error"
    );
    assert_signalled(
        note,
        DEVICE_WAIT_MS,
        "the fixture whose worker thread faulted was withdrawn",
    );
    assert_eq!(
        query_class(fault, 1, "test-fault"),
        Err(WITHDRAWN),
        "the ordinal of the fixture whose worker thread faulted must reply WITHDRAWN"
    );
}

/// With every fixture gone, memmgr's free pool returns to `free_before`, its
/// level before the bind, only if devmgr destroyed the never-ready fixture
/// and the one that refused its bootstrap, each of which holds `HOLD_BYTES`
/// until it is destroyed; of the two serving fixtures, one exited and one was
/// torn down after its worker thread's fault.
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
        if free_after
            .checked_add(margin)
            .expect("devmgr_on_demand_bind: free_after + margin overflowed")
            >= free_before
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        free_after = free_bytes(memmgr, ipc_buf);
    }
    assert!(
        free_after
            .checked_add(margin)
            .expect("devmgr_on_demand_bind: free_after + margin overflowed")
            >= free_before,
        "devmgr_on_demand_bind: the never-ready or the refusing fixture's pages did not \
         return (free_before={free_before} free_after={free_after}); it was not destroyed"
    );
}

/// A pass binds a record at most once a boot: a second bind over the same
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
    // Served once the settle of devmgr's drivers-directory pass ends, as the
    // input driver is.
    let fixture = match await_class(class, "test-dma")
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
    let probe = assert_dma_probe(caps, "devmgr_dma");
    let (outcome, iova, faults) = (probe.outcome, probe.iova, probe.faults);
    if !probe.confined
    {
        std::os::seraph::log!(
            "devmgr_dma_confinement passed unconfined: outcome {outcome}, device address {iova:#x}"
        );
        return;
    }
    std::os::seraph::log!(
        "devmgr_dma_confinement passed: mapped copy arrived at IOVA {iova:#x}, \
         the copy after its unmap faulted ({faults} faults)"
    );
}

/// What `DMA_PROBE` found, asserted by [`assert_dma_probe`].
struct DmaProbe
{
    outcome: u64,
    iova: u64,
    faults: u64,
    confined: bool,
}

/// Run `DMA_PROBE` on the fixture and assert what the DMA confinement phase
/// does: a copy through a mapped page arrives; for a device an IOMMU confines,
/// a copy to the page's device address after its unmap does not reach the
/// page, and devmgr took a fault for the device at that address; for one it
/// does not, devmgr counted no fault. `phase` names the caller in a failure.
fn assert_dma_probe(caps: &Caps, phase: &str) -> DmaProbe
{
    use ipc::test_dma_labels::{DMA_PROBE, PROBE_PASSED, PROBE_SKIPPED};

    let probe = call_test_dma(caps, DMA_PROBE, phase);
    assert_eq!(probe.label, ipc::devmgr_errors::SUCCESS, "DMA_PROBE setup");
    let (outcome, landed, iova) = (probe.word(0), probe.word(1) != 0, probe.word(2));
    let confined = probe.word(3) == ipc::devmgr_dma_labels::DMA_CONFINED;
    let (faults, last_fault) = (probe.word(4), probe.word(5));
    let found = DmaProbe {
        outcome,
        iova,
        faults,
        confined,
    };

    if !confined
    {
        assert!(
            outcome == PROBE_PASSED || outcome == PROBE_SKIPPED,
            "{phase}: a mapped copy did not arrive (outcome {outcome})"
        );
        assert_eq!(
            faults, 0,
            "{phase}: devmgr counted faults for an unconfined device"
        );
        return found;
    }
    assert_eq!(
        outcome, PROBE_PASSED,
        "{phase}: a copy through a mapped IOVA did not arrive"
    );
    assert!(
        !landed,
        "{phase}: a copy to IOVA {iova:#x} after its unmap reached the page"
    );
    assert!(
        faults >= 1,
        "{phase}: no IOMMU fault taken for the device after the unmapped copy"
    );
    assert_eq!(
        last_fault,
        iova & !0xfff,
        "{phase}: the latest fault names another IOVA"
    );
    found
}

/// The `edu` device's MSI vector, which devmgr gave its driver, delivers: the
/// fixture holds an MSI interrupt and the device's raise reaches it.
fn msi_delivery_phase(caps: &Caps)
{
    assert_msi_delivered(caps, "devmgr_msi_delivery");
    std::os::seraph::log!("devmgr_msi_delivery passed: the edu device's MSI was delivered");
}

/// Run `INTERRUPT_PROBE` on the fixture and assert that it holds the device's
/// MSI vector and that the device's raise reached it; `phase` names the
/// caller in a failure.
fn assert_msi_delivered(caps: &Caps, phase: &str)
{
    let probe = call_test_dma(caps, ipc::test_dma_labels::INTERRUPT_PROBE, phase);
    assert_eq!(
        probe.label,
        ipc::devmgr_errors::SUCCESS,
        "{phase}: INTERRUPT_PROBE status"
    );
    let (delivered, kind) = (probe.word(0) != 0, probe.word(1));
    assert_eq!(
        kind,
        driver_binding::resources::InterruptKind::Msi as u64,
        "{phase}: the fixture holds interrupt kind {kind} (0 none, 1 wired, 3 MSI-X), \
         not MSI"
    );
    assert!(
        delivered,
        "{phase}: the edu device's MSI did not reach the fixture within {} ms",
        ipc::test_dma_labels::INTERRUPT_WAIT_MS
    );
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

/// The line devmgr logs when it restarted the IOMMU driver
/// (`Iommu::attempt` in `services/devmgr/src/iommu.rs`): the marker, then
/// `{D} domains attached again, {M} mappings installed again, {H} holds
/// released`.
const IOMMU_RESTARTED: &str = "IOMMU driver restarted: ";

/// The leading decimal number of `text`, when `text` ends with `suffix`.
fn counted(text: &str, suffix: &str) -> Option<u64>
{
    text.strip_suffix(suffix)?.trim().parse().ok()
}

/// The counts of an [`IOMMU_RESTARTED`] line in `entry`: domains attached
/// again, mappings installed again, holds released. `None` when the entry
/// holds no such line.
fn parse_restarted(entry: &[u8]) -> Option<(u64, u64, u64)>
{
    let text = std::str::from_utf8(entry).ok()?;
    let rest = text.get(
        text.find(IOMMU_RESTARTED)?
            .checked_add(IOMMU_RESTARTED.len())?..,
    )?;
    let mut parts = rest.trim_end().split(", ");
    let domains = counted(parts.next()?, " domains attached again")?;
    let mappings = counted(parts.next()?, " mappings installed again")?;
    let holds = counted(parts.next()?, " holds released")?;
    Some((domains, mappings, holds))
}

/// A `DMA_STREAM_COUNT` or `DMA_STREAM_STOP` request `label`: the reply's
/// first four words, `SUCCESS` asserted.
fn stream_words(caps: &Caps, label: u64, phase: &str) -> [u64; 4]
{
    let reply = call_test_dma(caps, label, phase);
    assert_eq!(
        reply.label,
        ipc::devmgr_errors::SUCCESS,
        "{phase}: the stream request {label:#x} status"
    );
    [reply.word(0), reply.word(1), reply.word(2), reply.word(3)]
}

/// Poll `DMA_STREAM_COUNT` until `rounds` rounds arrived, for at most
/// `bound`, asserting that none failed.
fn await_stream_rounds(caps: &Caps, rounds: u64, bound: Duration, phase: &str)
{
    let begun = Instant::now();
    loop
    {
        let [arrived, failed, ..] =
            stream_words(caps, ipc::test_dma_labels::DMA_STREAM_COUNT, phase);
        assert_eq!(
            failed, 0,
            "{phase}: {failed} stream rounds failed before the IOMMU driver was killed"
        );
        if arrived >= rounds
        {
            return;
        }
        assert!(
            begun.elapsed() < bound,
            "{phase}: only {arrived} stream rounds arrived within {bound:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Kill the IOMMU driver through `authority` and wait, for at most `bound`,
/// for a live process of its name other than the killed one and for devmgr's
/// [`IOMMU_RESTARTED`] line in logd's history (`logd.query`): the line's
/// counts, domains attached again, mappings installed again, holds released.
fn kill_and_await_restart(caps: &Caps, bound: Duration, phase: &str) -> (u64, u64, u64)
{
    let authority = caps.debug_authority;
    let name = super::process_kill::IOMMU_NAME.as_bytes();
    let killed = super::crash::badge_named(authority, name)
        .unwrap_or_else(|| panic!("{phase}: LIST_PROCESSES lists no IOMMU driver"));
    super::process_kill::kill(authority, killed, "the IOMMU driver", phase);

    let begun = Instant::now();
    loop
    {
        let new_instance = super::crash::badges_named(authority, name)
            .into_iter()
            .any(|badge| badge != killed);
        if new_instance
        {
            let line = super::procmgr::logd_history_with(caps.logd_query, None, |entry| {
                parse_restarted(entry.bytes)
            })
            .into_iter()
            .flatten()
            .next();
            if let Some(counts) = line
            {
                return counts;
            }
        }
        assert!(
            begun.elapsed() < bound,
            "{phase}: no new IOMMU driver instance with a '{IOMMU_RESTARTED}' line from devmgr \
             within {bound:?} (new instance listed: {new_instance})"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A DMA stream through a page that stays mapped carries a confined device's
/// copies through the death of the IOMMU driver, devmgr's restart of it and
/// the new instance's commit, with no round failed and no fault; the new
/// instance then serves a fresh mapping, an interrupt and a read from the
/// root filesystem.
fn iommu_restart_phase(caps: &Caps)
{
    use ipc::test_dma_labels::{DMA_STREAM_COUNT, DMA_STREAM_START, DMA_STREAM_STOP};

    // A test wait bound: how long the stream may take to arrive at its first
    // rounds.
    const STREAM_BOUND: Duration = Duration::from_secs(5);
    // A test wait bound: how long the restart may take.
    const RESTART_BOUND: Duration = Duration::from_secs(30);
    // Rounds the stream must have made before the kill.
    const ROUNDS_BEFORE: u64 = 8;
    const PHASE: &str = "devmgr_iommu_restart";

    assert_ne!(caps.debug_authority, 0, "{PHASE}: no debug authority");
    assert_ne!(caps.logd_query, 0, "{PHASE}: no logd.query cap seeded");

    let [started, iova, confined, faults0] = {
        let start = call_test_dma(caps, DMA_STREAM_START, PHASE);
        assert_eq!(
            start.label,
            ipc::devmgr_errors::SUCCESS,
            "{PHASE}: DMA_STREAM_START status"
        );
        [start.word(0), start.word(1), start.word(2), start.word(3)]
    };
    if confined != ipc::devmgr_dma_labels::DMA_CONFINED || started == 0
    {
        if started != 0
        {
            // The stream's thread would hold the fixture's DMA engine for the
            // phases after this one.
            let _ = stream_words(caps, DMA_STREAM_STOP, PHASE);
        }
        std::os::seraph::log!(
            "{PHASE} skipped: no IOMMU confines the edu device (stream started {started})"
        );
        return;
    }
    await_stream_rounds(caps, ROUNDS_BEFORE, STREAM_BOUND, PHASE);
    let (domains, mappings, holds) = kill_and_await_restart(caps, RESTART_BOUND, PHASE);
    assert!(
        holds >= 1,
        "{PHASE}: devmgr released {holds} holds after the restart, expected at least one"
    );
    assert!(
        mappings >= 1,
        "{PHASE}: devmgr installed {mappings} mappings again, expected at least one"
    );

    let [before, ..] = stream_words(caps, DMA_STREAM_COUNT, PHASE);
    std::thread::sleep(Duration::from_millis(200));
    let [arrived, failed, stopped_iova, faults] = stream_words(caps, DMA_STREAM_STOP, PHASE);
    assert!(
        arrived > before,
        "{PHASE}: the stream made no round after the restart (arrived {arrived}, {before} before)"
    );
    assert_eq!(
        failed, 0,
        "{PHASE}: {failed} stream rounds failed across the IOMMU driver's death and restart"
    );
    assert_eq!(
        stopped_iova, iova,
        "{PHASE}: the stream's device address changed"
    );
    assert_eq!(
        faults, faults0,
        "{PHASE}: devmgr took IOMMU faults for the device during the restart"
    );

    assert_dma_probe(caps, PHASE);
    assert_msi_delivered(caps, PHASE);
    super::fs_ipc::assert_bootstrap_bundle_header(PHASE);
    std::os::seraph::log!(
        "{PHASE} passed: {arrived} stream rounds arrived across the restart ({domains} domains \
         attached again, {mappings} mappings installed again, {holds} holds released), none \
         failed, no fault; DMA, interrupt and filesystem read served after it"
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
