// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/blk_errors.rs

//! Error replies from block device drivers.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// Device returned an error status byte (value is the `VirtIO` status byte).
/// Values 1 (IOERR), 2 (UNSUPP) per `VirtIO` 1.2 §5.2.6.
pub const DEVICE_STATUS_IOERR: u64 = 1;
/// Device returned the `VirtIO` UNSUPP status byte (2): it does not
/// support the request type.
pub const DEVICE_STATUS_UNSUPP: u64 = 2;
/// Read LBA is outside the bounds registered for the caller's badge, or
/// the badge names no registered range (never minted, or retired by
/// `BLK_RETIRE_PARTITION`) or no live region (a region ends at its
/// unregistration, at its partition's retire, at its client's lease end, and
/// when its client revoked the Memory cap it registered).
pub const OUT_OF_BOUNDS: u64 = 3;
/// Partition registration rejected (no authority or bad args).
pub const REGISTER_REJECTED: u64 = 4;
/// Memory cap rejected: `BLK_READ_INTO_MEMORY` target missing
/// `MAP|WRITE` rights, `BLK_WRITE_FROM_MEMORY` source missing
/// `MAP` rights, smaller than `count * block_size` bytes, or absent;
/// also returned when `count` is 0 or `count * block_size` exceeds `u32::MAX`
/// (an overflowing multiply included). The `u32` limit is the length
/// field of a `VirtIO` descriptor; a larger transfer takes more requests.
/// For a region: a `BLK_REGISTER_REGION` cap missing the rights its access
/// needs, empty, or absent, or an access outside the two the label defines;
/// a region transfer whose offset is not a multiple of the block size, whose
/// run passes the region's end, or that reads into a region the device only
/// reads.
pub const INVALID_MEMORY_CAP: u64 = 5;
/// Caller's compiled `BLK_LABELS_VERSION` does not match the receiver's.
/// `REGISTER_PARTITION`, `BLK_GET_GEOMETRY` and the four region labels
/// carry the caller's version as `data[0]` (with `REGISTER_PARTITION`'s
/// `base_lba` shifted to `data[1]` and `length_lba` to `data[2]`);
/// mismatch here means the caller was built against a different revision of
/// `shared/ipc`.
pub const LABEL_VERSION_MISMATCH: u64 = 6;
/// The request got no usable completion: devmgr refused to map its
/// Memory cap for the device, the device did not complete it within the
/// driver's timeout, published a malformed completion, wrote a status
/// byte outside `VirtIO`'s set, or the chain could not be queued.
/// After a lost request the driver resets the device, so the reply's
/// Memory cap is free of device DMA, and answers every later transfer and
/// `BLK_REGISTER_REGION` with this code (fail-stop).
pub const DEVICE_FAULT: u64 = 7;
/// `BLK_REGISTER_REGION` refused for want of room: the caller's partition
/// already holds `MAX_REGIONS_PER_PARTITION` regions, every one of the
/// driver's `MAX_REGIONS` region slots is taken, devmgr refused the mapping
/// at its `MAX_MAPPINGS_PER_DEVICE`, or the driver could not fund the
/// region's address range, capabilities or liveness object. A region the
/// caller or another client unregisters frees room.
pub const REGION_LIMIT: u64 = 8;
/// Unknown opcode on block endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFF;
