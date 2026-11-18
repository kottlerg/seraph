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
/// Disjoint from partition-identity badges. The driver allocates
/// partition badges from a monotonic counter in the low bits of
/// the u64 (top bit clear); the partition table is keyed by the
/// full badge value so collision is impossible.
pub const MOUNT_AUTHORITY: u64 = 1u64 << 63;

/// Register a partition range, receiving back a badged SEND cap
/// scoped to that partition.
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
