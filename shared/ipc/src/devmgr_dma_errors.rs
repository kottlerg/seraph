// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/devmgr_dma_errors.rs

//! Error replies on devmgr's DMA endpoint ([`devmgr_dma_labels`](crate::devmgr_dma_labels)).

/// Request handled.
pub const SUCCESS: u64 = 0;
/// The request is malformed: no Memory cap, a cap that is not a Memory
/// cap or lacks the rights the access needs, or an access word that is
/// zero or sets a bit outside `devmgr_dma_labels::ACCESS_MASK`.
pub const INVALID_REQUEST: u64 = 1;
/// The badge names no device devmgr gives DMA: its driver was withdrawn,
/// or the SEND was never one devmgr minted.
pub const UNAUTHORIZED: u64 = 2;
/// Caller's compiled `DEVMGR_DMA_LABELS_VERSION`, carried in `data[0]`,
/// does not match devmgr's.
pub const LABEL_VERSION_MISMATCH: u64 = 3;
/// `DMA_UNMAP` names no mapping of the caller's device.
pub const NO_MAPPING: u64 = 4;
/// The device already holds its bound of mappings
/// (`devmgr_firmware::dma::MAX_MAPPINGS_PER_DEVICE`).
pub const TOO_MANY_MAPPINGS: u64 = 5;
/// The device address devmgr would give the frames is in use by another
/// mapping of the device: with no IOMMU, the same frames mapped twice.
pub const ADDRESS_IN_USE: u64 = 6;
/// devmgr could not make the frames reachable: an allocation failed, or
/// the device's IOVA space holds no free range of the cap's length.
pub const OUT_OF_RESOURCES: u64 = 7;
/// The IOMMU driver that confines the device did not complete the
/// request: it refused it, it timed out, or it is dead. A refused
/// `DMA_MAP` installs nothing; a refused `DMA_UNMAP` leaves the mapping
/// standing. Once the IOMMU driver is dead devmgr refuses every later
/// `DMA_MAP` of every device it confined.
pub const IOMMU_FAILED: u64 = 8;
/// Unknown opcode on the DMA endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFF;
