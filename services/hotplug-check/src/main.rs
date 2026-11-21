// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/hotplug-check/src/main.rs

//! Hotplug fixture, in two modes. The device mode (no argument) waits for
//! devmgr to serve the `test-dma` fixture on an `edu` device the host
//! hot-adds behind a PCI Express root port and checks that the device's DMA
//! and its MSI work; then, once the host has removed the device, that devmgr
//! withdrew its driver, and once the host has added it again, that the new
//! device is served at the next ordinal, works, and holds none of its
//! predecessor's IOMMU faults. So `cargo xtask test hotplug` proves devmgr's
//! native hotplug add and removal paths from the slot to a bound driver and
//! back. The disk mode (`disk`, [`disk`]) follows a disk the host hot-adds,
//! removes and adds again through vfsd's mounts, and the loss of the root
//! filesystem's driver.
//!
//! The checks, and the markers it logs, are specified in
//! `services/hotplug-check/README.md`.

mod arch;
mod disk;

use driver_binding::resources::InterruptKind;
use ipc::ClassCallError;
use ipc::test_dma_labels::{DMA_PROBE, INTERRUPT_PROBE, PROBE_PASSED};

/// Logged once the fixture watches the `test-dma` class and devmgr serves no
/// driver of it: the host hot-adds the device on seeing it. Kept in sync
/// with `xtask/src/commands/test/hotplug.rs`.
const READY_MARKER: &str = "READY for the hot-added device";

/// Logged once the hot-added device passed its probes: the host removes it
/// on seeing it. Kept in sync with `xtask/src/commands/test/hotplug.rs`.
const REMOVE_MARKER: &str = "READY for the removal";

/// Logged once devmgr withdrew the removed device's driver: the host adds
/// the device again on seeing it. Kept in sync with
/// `xtask/src/commands/test/hotplug.rs`.
const READD_MARKER: &str = "WITHDRAWN at ordinal 0; READY for the re-added device";

/// Logged when every check passed, in either mode. Kept in sync with
/// `xtask/src/commands/test/hotplug.rs`.
pub(crate) const PASS_MARKER: &str = "PASS";

/// Logged, with the reason, when a check failed, in either mode. Kept in
/// sync with `xtask/src/commands/test/hotplug.rs`.
pub(crate) const FAIL_MARKER: &str = "FAIL";

/// How long the fixture waits for devmgr to serve the hot-added device's
/// driver, in milliseconds: past the host's hot-add, the poller's period,
/// the link wait, and the driver's settle.
const DEVICE_WAIT_MS: u64 = 120_000;

fn main()
{
    std::os::seraph::log::register_name(b"hotplug-check");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    if std::env::args().nth(1).as_deref() == Some("disk")
    {
        disk::run(info, ipc_buf);
        return;
    }
    match check(info.creator_endpoint, ipc_buf)
    {
        Ok((first, again)) => std::os::seraph::log!(
            "{PASS_MARKER}: test-dma served at ordinal 0, a buffer mapped at device address \
             {:#x} reached by DMA, MSI delivered; withdrawn at its removal; served again at \
             ordinal 1, DMA at {:#x} and MSI delivered, {} IOMMU faults as before",
            first.iova,
            again.iova,
            again.faults
        ),
        Err(why) => std::os::seraph::log!("{FAIL_MARKER}: {why}"),
    }
}

/// What the probes of one device found.
struct Probed
{
    /// The device address of the DMA probe's buffer.
    iova: u64,
    /// The IOMMU faults devmgr has taken for the device.
    faults: u64,
}

/// Take the `test-dma` class seed, wait for its driver and probe it, wait
/// for its withdrawal at the removal, then for the driver of the device
/// added again and probe it; what each probe found, or why a check failed.
fn check(creator_ep: u64, ipc_buf: *mut u64) -> Result<(Probed, Probed), String>
{
    let class = bootstrap_seed(creator_ep, ipc_buf).ok_or("no devmgr.class.test-dma seed")?;
    let mut ready = false;
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let found = unsafe {
        ipc::await_device(class, DEVICE_WAIT_MS, ipc_buf, || {
            if !ready
            {
                ready = true;
                std::os::seraph::log!("{READY_MARKER}");
            }
        })
    };
    let first = found.map_err(|e| format!("no test-dma driver served ({e:?})"))?;
    let _ = syscall::cap_delete(first);
    if !ready
    {
        return Err("a test-dma driver was served before the hot-add".into());
    }
    // The launch attaches no test device, so the hot-added one is the class's
    // only device: ordinal 0.
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let fixture = unsafe { ipc::query_device(class, 0, ipc_buf) }
        .map_err(|e| format!("QUERY_DEVICE test-dma ordinal 0 refused ({e:?})"))?;
    let first = probe(fixture, ipc_buf);
    let _ = syscall::cap_delete(fixture);
    let first = first?;
    std::os::seraph::log!("{REMOVE_MARKER}");
    withdrawn(class, ipc_buf)?;
    std::os::seraph::log!("{READD_MARKER}");
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let found = unsafe { ipc::await_device(class, DEVICE_WAIT_MS, ipc_buf, || {}) };
    let again = found.map_err(|e| format!("no test-dma driver served after the re-add ({e:?})"))?;
    let _ = syscall::cap_delete(again);
    // A withdrawn ordinal stays withdrawn, so the device added again is
    // served at the next one.
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let (ordinal, fixture) = unsafe { ipc::first_device_from(class, 1, ipc_buf) }
        .map_err(|e| format!("QUERY_DEVICE test-dma from ordinal 1 refused ({e:?})"))?;
    let again = if ordinal == 1
    {
        probe(fixture, ipc_buf)
    }
    else
    {
        Err(format!(
            "the re-added device is served at ordinal {ordinal}, not 1"
        ))
    };
    let _ = syscall::cap_delete(fixture);
    let again = again?;
    // Its predecessor's faults are not charged to it: each device's DMA
    // probe raises the same faults.
    if again.faults != first.faults
    {
        return Err(format!(
            "the re-added device holds {} IOMMU faults after its probe, the removed one {}",
            again.faults, first.faults
        ));
    }
    Ok((first, again))
}

/// Wait until devmgr answers `WITHDRAWN` at ordinal 0 of the class
/// `class`, the hot-added device's driver withdrawn at its removal: probe,
/// and while it still serves the driver wait on a class watch, up to
/// [`DEVICE_WAIT_MS`] each time.
fn withdrawn(class: u64, ipc_buf: *mut u64) -> Result<(), String>
{
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let watch = unsafe { ipc::watch_class(class, ipc_buf) }
        .map_err(|e| format!("WATCH_CLASS test-dma refused ({e:?})"))?;
    let result = loop
    {
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        match unsafe { ipc::query_device(class, 0, ipc_buf) }
        {
            Err(ClassCallError::Refused(ipc::devmgr_errors::WITHDRAWN)) => break Ok(()),
            Ok(cap) =>
            {
                let _ = syscall::cap_delete(cap);
            }
            Err(e) => break Err(format!("QUERY_DEVICE test-dma ordinal 0 refused ({e:?})")),
        }
        match syscall::notification_wait_timeout(watch.note, DEVICE_WAIT_MS)
        {
            Ok(0) => break Err("the removed device's driver was not withdrawn".into()),
            Ok(_) =>
            {}
            Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 =>
            {}
            Err(e) => break Err(format!("waiting on the class watch failed ({e})")),
        }
    };
    let _ = syscall::cap_delete(watch.note);
    result
}

/// The DMA probe and the interrupt probe of the `test-dma` fixture at
/// `fixture`: a copy through a mapped page arrives, and the device's MSI
/// reaches the fixture.
fn probe(fixture: u64, ipc_buf: *mut u64) -> Result<Probed, String>
{
    let dma = call(fixture, DMA_PROBE, ipc_buf)?;
    let (outcome, iova, faults) = (dma.word(0), dma.word(2), dma.word(4));
    if outcome != PROBE_PASSED
    {
        return Err(format!(
            "DMA_PROBE outcome {outcome} at device address {iova:#x}, not passed"
        ));
    }
    let interrupt = call(fixture, INTERRUPT_PROBE, ipc_buf)?;
    let (delivered, kind) = (interrupt.word(0) != 0, interrupt.word(1));
    if kind != InterruptKind::Msi as u64
    {
        return Err(format!(
            "the fixture holds interrupt kind {kind} (0 none, 1 wired, 3 MSI-X), not MSI"
        ));
    }
    if !delivered
    {
        return Err("the device's MSI did not reach the fixture".into());
    }
    Ok(Probed { iova, faults })
}

/// The fixture's `SUCCESS` reply to `label`, or why there is none.
fn call(fixture: u64, label: u64, ipc_buf: *mut u64) -> Result<ipc::IpcMessage, String>
{
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(fixture, &ipc::IpcMessage::new(label), ipc_buf) }
        .map_err(|e| format!("test-dma call {label:#x} failed ({e})"))?;
    if reply.label != ipc::devmgr_errors::SUCCESS
    {
        return Err(format!(
            "test-dma call {label:#x} replied {:#x}",
            reply.label
        ));
    }
    Ok(reply)
}

/// Pull the bootstrap round; slot 0 is the recipe's
/// `seed = devmgr.class.test-dma`.
fn bootstrap_seed(creator_ep: u64, ipc_buf: *mut u64) -> Option<u64>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let [cap] = unsafe { ipc::bootstrap::request_slots::<1>(creator_ep, ipc_buf) }.ok()?;
    (cap != 0).then_some(cap)
}
