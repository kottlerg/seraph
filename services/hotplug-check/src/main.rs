// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/hotplug-check/src/main.rs

//! Hotplug fixture: waits for devmgr to serve the `test-dma` fixture on an `edu`
//! device the host hot-adds behind a PCI Express root port, then checks
//! that the device's DMA and its MSI work, so `cargo xtask test-hotplug`
//! proves devmgr's native hotplug add path from the slot to a bound driver.
//!
//! The checks, and the markers it logs, are specified in
//! `services/hotplug-check/README.md`.

use driver_binding::resources::InterruptKind;
use ipc::test_dma_labels::{DMA_PROBE, INTERRUPT_PROBE, PROBE_PASSED};

/// Logged once the fixture watches the `test-dma` class and devmgr serves no
/// driver of it: the host hot-adds the device on seeing it. Kept in sync
/// with `xtask/src/commands/test_hotplug.rs`.
const READY_MARKER: &str = "READY for the hot-added device";

/// Logged when every check passed. Kept in sync with
/// `xtask/src/commands/test_hotplug.rs`.
const PASS_MARKER: &str = "PASS";

/// Logged, with the reason, when a check failed. Kept in sync with
/// `xtask/src/commands/test_hotplug.rs`.
const FAIL_MARKER: &str = "FAIL";

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

    match check(info.creator_endpoint, ipc_buf)
    {
        Ok(iova) => std::os::seraph::log!(
            "{PASS_MARKER}: test-dma served at ordinal 0, a buffer mapped at device address \
             {iova:#x} reached by DMA, MSI delivered"
        ),
        Err(why) => std::os::seraph::log!("{FAIL_MARKER}: {why}"),
    }
}

/// Take the `test-dma` class seed, wait for its driver, and run the checks;
/// the device address of the probe's buffer, or why a check failed.
fn check(creator_ep: u64, ipc_buf: *mut u64) -> Result<u64, String>
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
    let result = probe(fixture, ipc_buf);
    let _ = syscall::cap_delete(fixture);
    result
}

/// The DMA probe and the interrupt probe of the `test-dma` fixture at
/// `fixture`: a copy through a mapped page arrives, and the device's MSI
/// reaches the fixture.
fn probe(fixture: u64, ipc_buf: *mut u64) -> Result<u64, String>
{
    let dma = call(fixture, DMA_PROBE, ipc_buf)?;
    let (outcome, iova) = (dma.word(0), dma.word(2));
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
    Ok(iova)
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
