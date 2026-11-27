// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/blk_labels.rs

//! IPC labels for block device drivers.

/// Authority bit in the block-service-endpoint badge's high u64
/// bit. Set on caps minted for consumers that may invoke
/// [`REGISTER_PARTITION`] and may issue whole-disk sector reads
/// via [`BLK_READ_INTO_MEMORY`]. The bit is a verb — "may invoke
/// these labels" — not an identity: multiple consumers may hold
/// it, and the bit alone does not encode "is vfsd."
///
/// Disjoint from the badges the driver mints itself: partition-identity
/// badges, from a monotonic counter in the low 62 bits, and region badges
/// ([`BLK_REGISTER_REGION`]), which set bit 62. The driver keys each table
/// by the full badge value, so no two of them collide.
pub const MOUNT_AUTHORITY: u64 = 1u64 << 63;

/// Register a partition range, receiving back a badged SEND cap
/// scoped to that partition. Each registration is a new grant under a
/// badge no earlier registration had, until [`BLK_RETIRE_PARTITION`].
///
/// Caller's badge must have [`MOUNT_AUTHORITY`] set. The driver derives
/// the partition cap itself because [`MOUNT_AUTHORITY`] caps are
/// badged and the kernel rejects re-badging of a badged source.
/// Specified, with its replies, in
/// `services/drivers/virtio/blk/README.md` § Label 2:
/// `REGISTER_PARTITION`.
pub const REGISTER_PARTITION: u64 = 2;
/// Read one or more contiguous blocks into a caller-supplied Memory cap,
/// which the reply moves back. LBAs and counts are in the device's
/// logical blocks ([`BLK_GET_GEOMETRY`]). Specified, with its caps and
/// replies, in `services/drivers/virtio/blk/README.md` § Label 3:
/// `BLK_READ_INTO_MEMORY`.
pub const BLK_READ_INTO_MEMORY: u64 = 3;
/// Write one or more contiguous blocks from a caller-supplied Memory cap.
///
/// Mirror of [`BLK_READ_INTO_MEMORY`] for the write direction. The
/// caller fills the source page, then issues the request; the
/// driver reads `count * block_size` bytes starting at offset 0 and
/// writes them to disk.
///
/// Request: `data[0]` = starting LBA, `data[1]` = block count
/// (`>= 1`; defaults to `1` if `data[1]` is absent), both in the
/// device's logical blocks. Caps: `caps[0]` = source Memory cap (`MAP`
/// rights; the driver reads `count * block_size` bytes starting at
/// offset 0 of the page, packed contiguously). The page must be at
/// least `count * block_size` bytes; the driver rejects with
/// `INVALID_MEMORY_CAP` otherwise. `caps[1]` is reserved for a future
/// per-request release handle and is null today. `caps[2]` is a
/// reserved IPC-shape slot, null today: the driver maps the source cap
/// for its device itself, for the request's duration
/// ([`crate::devmgr_dma_labels::DMA_MAP`]).
/// Reply: empty body, label is the success or error code; the source
/// Memory cap is moved back to the caller in `caps[0]` of the reply (same
/// discipline as the read path).
pub const BLK_WRITE_FROM_MEMORY: u64 = 4;
/// Report the device's logical block size and the caller's addressable
/// length in blocks: the whole device for a [`MOUNT_AUTHORITY`] badge,
/// the registered partition for a partition badge.
///
/// Request: `data[0]` = caller's `BLK_LABELS_VERSION`. Reply: label
/// `SUCCESS`, `data[0]` = logical block size in bytes (a power of two,
/// 512 to 4096), `data[1]` = length in blocks; `OUT_OF_BOUNDS` for a
/// badge the driver registered no range for; `LABEL_VERSION_MISMATCH`.
/// Specified in `services/drivers/virtio/blk/README.md` § Label 5:
/// `BLK_GET_GEOMETRY`.
pub const BLK_GET_GEOMETRY: u64 = 5;
/// Register a staging buffer with the driver, which maps it for the device
/// once and keeps the mapping until [`BLK_UNREGISTER_REGION`], the end of
/// the client's lease, the retire of the partition it was registered
/// through ([`BLK_RETIRE_PARTITION`]), or devmgr's withdrawal of the
/// driver. Sent on a partition or whole-disk cap.
///
/// Request: `data[0]` = caller's `BLK_LABELS_VERSION`, `data[1]` = the
/// device's access, [`REGION_DEVICE_READS`] or
/// [`REGION_DEVICE_READS_WRITES`]; `caps[0]` = a Memory cap over the
/// region (`MAP`, and `MAP|WRITE` for read-write access), which the caller
/// keeps a copy of. Reply: `caps[0]` = the region cap, a SEND on the
/// driver's endpoint that names this region alone; `caps[1]` = the liveness
/// cap, whose last copy outside the driver ends the registration. Specified,
/// with its replies, in `services/drivers/virtio/blk/README.md` § Label 6:
/// `BLK_REGISTER_REGION`.
pub const BLK_REGISTER_REGION: u64 = 6;
/// Read blocks of the region cap's partition into the region, sent on the
/// region cap: `data[0]` = caller's `BLK_LABELS_VERSION`, `data[1]` = LBA
/// within the partition, `data[2]` = block count, `data[3]` = byte offset in
/// the region, a multiple of the logical block size. The driver makes no call
/// to devmgr. Specified in `services/drivers/virtio/blk/README.md` § Label 7:
/// `BLK_READ_REGION`.
pub const BLK_READ_REGION: u64 = 7;
/// Write blocks of the region cap's partition from the region: the words of
/// [`BLK_READ_REGION`]. Specified in `services/drivers/virtio/blk/README.md`
/// § Label 8: `BLK_WRITE_REGION`.
pub const BLK_WRITE_REGION: u64 = 8;
/// Unregister the region the region cap names, sent on it: `data[0]` =
/// caller's `BLK_LABELS_VERSION`. Once the reply arrives the device reaches
/// no frame of the region, and every copy of the region and liveness caps is
/// revoked. Specified in `services/drivers/virtio/blk/README.md` § Label 9:
/// `BLK_UNREGISTER_REGION`.
pub const BLK_UNREGISTER_REGION: u64 = 9;
/// Retire the partition grant whose cap it is sent on: `data[0]` = caller's
/// `BLK_LABELS_VERSION`. The driver refuses every later request carrying
/// the grant's badge, whenever it was sent, and unregisters every region
/// registered through it as [`BLK_UNREGISTER_REGION`] would, before the
/// reply. Whoever revokes a derivation of a partition cap it kept sends it
/// on that cap next, then deletes the cap; to grant the range again it
/// registers it again. Specified in `services/drivers/virtio/blk/README.md`
/// § Label 10: `BLK_RETIRE_PARTITION`.
pub const BLK_RETIRE_PARTITION: u64 = 10;
/// [`BLK_REGISTER_REGION`] access: the device only reads the region, so
/// the region serves [`BLK_WRITE_REGION`] alone.
pub const REGION_DEVICE_READS: u64 = 1;
/// [`BLK_REGISTER_REGION`] access: the device reads and writes the region,
/// which serves both transfer labels.
pub const REGION_DEVICE_READS_WRITES: u64 = 3;
