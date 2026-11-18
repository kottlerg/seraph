// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/devmgr_dma_labels.rs

//! IPC labels for devmgr's DMA endpoint: the DMA-authorising capability of a
//! DMA-capable driver.
//!
//! devmgr gives each driver of a DMA-capable device a SEND on its DMA
//! endpoint badged with the device's badge, and serves it on a thread of its
//! own. A driver programs its device only with the device addresses
//! [`DMA_MAP`] returns, never with a physical address: devmgr chooses the
//! address, an IOVA in the device's IOMMU domain when an IOMMU confines the
//! device and the frames' physical address when none does. Every request
//! carries the caller's compiled [`DEVMGR_DMA_LABELS_VERSION`](crate::DEVMGR_DMA_LABELS_VERSION) in `data[0]`;
//! devmgr replies [`devmgr_dma_errors::LABEL_VERSION_MISMATCH`](crate::devmgr_dma_errors::LABEL_VERSION_MISMATCH) when it
//! differs. Specified in `docs/device-management.md` § DMA Authorisation.

/// Make the frames of a Memory cap reachable by the caller's device.
///
/// Request: `data[1]` = the access the device needs, a nonzero
/// combination of [`ACCESS_DEVICE_READ`] and [`ACCESS_DEVICE_WRITE`];
/// `caps[0]` = a Memory cap over the frames, which the request moves to
/// devmgr: a driver sends a derivation of its own cap and keeps the
/// original. The cap must carry `MAP` rights, and `MAP|WRITE` when the
/// device writes. The whole cap is made reachable. devmgr keeps the cap
/// while the mapping stands and deletes it at the mapping's
/// [`DMA_UNMAP`], at the device's withdrawal, or at once when it refuses
/// the request. Reply: label `SUCCESS` with `data[0]` = the device
/// address of the cap's first byte, the cap's frames lying contiguous
/// from it; or an error code. A reply the caller cannot take undoes the
/// mapping.
pub const DMA_MAP: u64 = 1;
/// Withdraw a mapping [`DMA_MAP`] made: the device can no longer reach
/// its frames through it.
///
/// Request: `data[1]` = the device address a `DMA_MAP` of this device
/// returned. Reply: empty body, label `SUCCESS`,
/// `devmgr_dma_errors::NO_MAPPING` (no mapping of the device at that
/// address), `devmgr_dma_errors::UNAUTHORIZED` (the device is withdrawn
/// or was never given DMA), `devmgr_dma_errors::IOMMU_FAILED` (the IOMMU
/// driver that confines the device did not remove the mapping, which
/// stays standing), or `devmgr_dma_errors::LABEL_VERSION_MISMATCH`.
pub const DMA_UNMAP: u64 = 2;
/// Report the DMA translation faults devmgr has taken for the caller's
/// device; an interrupt-remapping fault is logged only.
///
/// devmgr first takes the faults the IOMMU driver has recorded
/// (`iommu_labels::TAKE_FAULTS`) and logs each, as it does periodically.
/// Request: no field past `data[0]`. Reply: label `SUCCESS` with
/// `data[0]` = [`DMA_CONFINED`] when an IOMMU confines the device and 0
/// when none does; `data[1]` = the faults devmgr has taken for the device
/// since its DMA grant, 0 for an unconfined device; `data[2]` = the IOVA of the
/// latest, page aligned, 0 with none. Or `devmgr_dma_errors::UNAUTHORIZED`
/// (the device is withdrawn or was never given DMA), or
/// `devmgr_dma_errors::LABEL_VERSION_MISMATCH`.
pub const DMA_FAULTS: u64 = 3;
/// [`DMA_FAULTS`] reply word: an IOMMU confines the device.
pub const DMA_CONFINED: u64 = 1;
/// [`DMA_MAP`] access bit: the device reads the frames.
pub const ACCESS_DEVICE_READ: u64 = 1 << 0;
/// [`DMA_MAP`] access bit: the device writes the frames.
pub const ACCESS_DEVICE_WRITE: u64 = 1 << 1;
/// Every [`DMA_MAP`] access bit.
pub const ACCESS_MASK: u64 = ACCESS_DEVICE_READ | ACCESS_DEVICE_WRITE;
