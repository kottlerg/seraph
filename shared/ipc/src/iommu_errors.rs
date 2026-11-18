// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/iommu_errors.rs

//! Error replies on an IOMMU driver's endpoint ([`iommu_labels`](crate::iommu_labels)).

/// Request handled.
pub const SUCCESS: u64 = 0;
/// The request is malformed: an unknown unit or domain, a requester ID
/// outside the unit's scope, an IOVA or reserved range that is
/// unaligned, empty, or past the unit's width, a missing or non-Memory
/// cap, an access word outside `devmgr_dma_labels::ACCESS_MASK`, an
/// `UNMAP` of a reserved range or an interrupt file, a `MAP_MSI` to
/// an IOMMU family that does not take it, or an interrupt remapping
/// request the remapping's state or bounds refuse (`REMAP_SETUP`,
/// `REMAP_SET`).
pub const INVALID_REQUEST: u64 = 1;
/// Caller's compiled `IOMMU_LABELS_VERSION`, carried in `data[0]`,
/// does not match the driver's.
pub const LABEL_VERSION_MISMATCH: u64 = 2;
/// The range overlaps one already installed in the domain.
pub const ADDRESS_IN_USE: u64 = 3;
/// `UNMAP` names no installed range of the domain.
pub const NO_MAPPING: u64 = 4;
/// The driver could not take the memory or domain the request needs.
pub const OUT_OF_RESOURCES: u64 = 5;
/// The unit did not complete an invalidation within the driver's bound;
/// the unit is treated as failed and the request is refused.
pub const HARDWARE_TIMEOUT: u64 = 6;
/// Unknown opcode on the IOMMU endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFF;
