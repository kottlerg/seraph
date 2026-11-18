// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/test_dma_labels.rs

//! The `test-dma` fixture driver's service label
//! (services/drivers/test-dma/README.md).
//!
//! The fixture drives QEMU's `edu` device, whose DMA engine copies between
//! a 4 KiB buffer inside the device and a device address the driver
//! programs. A harness reaches it through the `test-dma` class
//! (`devmgr_labels::QUERY_DEVICE`). No badge bit is checked.

/// Run the DMA probe: map one page of the driver's memory for the
/// device (`devmgr_dma_labels::DMA_MAP`), copy a pattern from it into
/// the device's buffer and back to the page's second half, unmap the
/// page (`DMA_UNMAP`), and copy the buffer to the page's second half once
/// more at the withdrawn device address. Request: no data. Reply:
/// `SUCCESS` with `data[0]` = [`PROBE_PASSED`] when the mapped copies
/// arrived, [`PROBE_SKIPPED`] when the device address lies past the
/// device's 28-bit DMA reach (no IOMMU, and the page above 256 MiB), or
/// [`PROBE_FAILED`] when a mapped copy did not arrive or the device did
/// not complete a transfer; `data[1]` = whether the copy after the unmap
/// reached the page (1) or not (0); `data[2]` = the device address the
/// page was mapped at; `data[3]` = whether an IOMMU confines the device
/// (`devmgr_dma_labels::DMA_CONFINED`) or not (0); `data[4]` = the IOMMU
/// faults devmgr has taken for the device and `data[5]` the IOVA of the
/// latest (`devmgr_dma_labels::DMA_FAULTS`), which, for a confined
/// device, the fixture asks for until the copy after the unmap is
/// counted, within [`FAULT_WAIT_MS`]. Any other reply label is a setup
/// failure.
pub const DMA_PROBE: u64 = 1;
/// How long a confined fixture asks for its faults before it replies
/// with the count it has: past devmgr's take of the IOMMU driver's
/// recorded faults, which a `DMA_FAULTS` request makes itself.
pub const FAULT_WAIT_MS: u64 = 3000;
/// [`DMA_PROBE`] outcome: the mapped copies arrived.
pub const PROBE_PASSED: u64 = 0;
/// [`DMA_PROBE`] outcome: a mapped copy did not arrive, or the device did
/// not complete a transfer within the driver's bound.
pub const PROBE_FAILED: u64 = 1;
/// [`DMA_PROBE`] outcome: the device address lies past the device's DMA
/// reach, so no transfer was made.
pub const PROBE_SKIPPED: u64 = 2;
/// Run the interrupt probe: have the device raise its interrupt (the
/// `edu` interrupt-raise register), wait for it on the notification the
/// fixture bound its `Interrupt` resource to, for at most
/// [`INTERRUPT_WAIT_MS`], then acknowledge it at the device and with
/// `SYS_IRQ_ACK`. Request: no data. Reply: `SUCCESS` with `data[0]` =
/// whether the interrupt reached the notification (1) or not (0), and
/// `data[1]` = the kind of interrupt devmgr gave the fixture, a
/// `driver_binding::resources::InterruptKind` value, or 0 for none. Any
/// other reply label is a setup failure.
pub const INTERRUPT_PROBE: u64 = 2;
/// How long the [`INTERRUPT_PROBE`] waits for the interrupt it raised.
pub const INTERRUPT_WAIT_MS: u64 = 2000;
/// Run the interrupt churn: while a thread of the fixture has the device
/// raise its interrupt in a loop, delete the bound `Interrupt` cap (case
/// [`CHURN_BOUND_CAP`]), then the bound notification's last cap and the
/// binding's cap (case [`CHURN_NOTIFICATION`]); after each case, bind a
/// copy of the interrupt, derived before the case, to a new notification
/// and run the [`INTERRUPT_PROBE`] through it, which the binding left
/// after the churn then serves. Request: no data. Reply: `SUCCESS` with
/// `data[0]` = the cases whose next binding received the device's
/// interrupt, one bit each, `data[1]` = the kind of interrupt held (as
/// for [`INTERRUPT_PROBE`]), and `data[2]` = the raises the loop made.
/// Any other reply label is a setup failure.
pub const INTERRUPT_CHURN: u64 = 3;
/// [`INTERRUPT_CHURN`] case bit: the bound `Interrupt` cap deleted.
pub const CHURN_BOUND_CAP: u64 = 1 << 0;
/// [`INTERRUPT_CHURN`] case bit: the bound notification's last cap
/// deleted, then the binding's cap.
pub const CHURN_NOTIFICATION: u64 = 1 << 1;
/// Reply `SUCCESS`, have the device raise its interrupt and leave it
/// raised, and exit after [`EXIT_DELAY_MS`] without receiving again, so
/// devmgr releases the device and frees its message-signaled target.
/// Request: no data. No fixture serves the class for the rest of the
/// boot.
pub const FIXTURE_EXIT: u64 = 4;
/// How long the fixture waits between its [`FIXTURE_EXIT`] reply and its
/// exit.
pub const EXIT_DELAY_MS: u64 = 100;
/// Run the forged-message probe, when an IOMMU confines the device and
/// the fixture holds an MSI vector: have the device's DMA engine write
/// the fixture's own message (`SYS_CAP_INFO`'s
/// `CAP_INFO_IRQ_MSG_ADDRESS` and `CAP_INFO_IRQ_MSG_DATA`) to its own
/// address and wait for it on the fixture's notification for at most
/// [`INTERRUPT_WAIT_MS`], then write the same data to a forged message
/// address the device's targets do not allow and wait as long again. On
/// riscv64 the forged address is the interrupt file page beside the
/// target's (the paired hart's file, its own address with bit 12
/// flipped), and the fixture then asks for its faults as [`DMA_PROBE`]
/// does, until one names that page. On `x86_64` it is a remappable
/// message naming handle `0xFFFF`, which no remapping table holds, made
/// only when the fixture's own message is remappable; QEMU records no
/// requester for a fault the DMA engine's write raises, so devmgr
/// cannot count it for the device, and no fault is asked for. Request:
/// no data. Reply: `SUCCESS` with `data[0]` = whether an IOMMU confines
/// the device (`devmgr_dma_labels::DMA_CONFINED`) or not (0); `data[1]`
/// = whether the forged write was made (1) or not (0: the device is not
/// confined, the fixture holds no MSI vector, or on `x86_64` its message
/// is not remappable); `data[2]` = whether the device's write of the
/// fixture's own message reached the notification (1) or not (0);
/// `data[3]` = whether the forged write reached it (1) or not (0);
/// `data[4]` = the fixture's own message address, 0 when the device is
/// not confined or holds no MSI vector; `data[5]` = the forged address;
/// `data[6]` = the IOMMU faults devmgr has taken for the device and
/// `data[7]` the IOVA of the latest. Any other reply label is a setup
/// failure.
pub const MSI_FORGE: u64 = 5;
