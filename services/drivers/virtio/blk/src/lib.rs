// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/blk/src/lib.rs

//! Host-testable request logic of the `VirtIO` block driver.
//!
//! The driver binary (`main.rs`, `io.rs`) owns the device, the virtqueue,
//! and the IPC loop. This library holds the pure decisions those paths
//! make on client- and device-supplied values: the device geometry the
//! driver serves in logical blocks, the transfer length a client's block
//! count asks for, the partition table that scopes a partition badge, and
//! the reply label a request's outcome maps to. Each is a wire-contract
//! decision (`shared/ipc::blk_labels`, `shared/ipc::blk_errors`), so they
//! live where a host test can pin them.

use ipc::blk_errors;

/// Bytes per `VirtIO` block sector: the unit of a request header's `sector`
/// field and of the `capacity` config field, whatever the device's logical
/// block size (`VirtIO` 1.2 §5.2.4, §5.2.6).
pub const VIRTIO_SECTOR_SIZE: u64 = 512;

/// Largest logical block size the driver serves: one page, the unit every
/// client reads into (a cache page, a GPT read buffer).
pub const MAX_BLOCK_SIZE: u32 = 4096;

/// `VIRTIO_BLK_F_BLK_SIZE` feature bit: the device reports its logical block
/// size in the `blk_size` config field (`VirtIO` 1.2 §5.2.3).
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;

/// Byte offset of the `blk_size` field in the device config (`VirtIO` 1.2
/// §5.2.4: after `capacity`, `size_max`, `seg_max`, and `geometry`).
pub const CONFIG_BLK_SIZE_OFFSET: u32 = 20;

/// Device status byte: request completed (`VIRTIO_BLK_S_OK`, `VirtIO` 1.2 §5.2.6).
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// Device status byte: I/O error (`VIRTIO_BLK_S_IOERR`).
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// Device status byte: request type unsupported (`VIRTIO_BLK_S_UNSUPP`).
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// The device geometry the driver serves: its logical block size, and its
/// capacity in those blocks. Every LBA and count on the wire is in logical
/// blocks; the driver converts to `VirtIO`'s 512-byte sectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry
{
    /// Logical block size in bytes: a power of two from 512 to
    /// [`MAX_BLOCK_SIZE`].
    pub block_size: u32,
    /// Device capacity in logical blocks.
    pub capacity: u64,
}

impl Geometry
{
    /// The geometry of a device reporting `capacity_sectors` 512-byte
    /// sectors, and, when it offered [`VIRTIO_BLK_F_BLK_SIZE`] (`blk_size`
    /// is `Some`), that logical block size. A device without the feature has
    /// 512-byte blocks.
    ///
    /// Returns `None` for a reported block size the driver cannot serve: not
    /// a power of two, below 512, or above [`MAX_BLOCK_SIZE`]. The value is
    /// device-written, so it is checked rather than trusted.
    #[must_use]
    pub fn new(capacity_sectors: u64, blk_size: Option<u32>) -> Option<Self>
    {
        let block_size = blk_size.unwrap_or(512);
        if !block_size.is_power_of_two() || !(512..=MAX_BLOCK_SIZE).contains(&block_size)
        {
            return None;
        }
        Some(Self {
            block_size,
            capacity: capacity_sectors / self::sectors_per_block(block_size),
        })
    }

    /// The `VirtIO` sector a logical block starts at. Exact for every LBA
    /// below `capacity`, which the driver checks before converting.
    #[must_use]
    pub fn device_sector(self, lba: u64) -> u64
    {
        lba * sectors_per_block(self.block_size)
    }

    /// Byte length of a transfer of `block_count` blocks, as the `u32` a
    /// `VirtIO` descriptor carries.
    ///
    /// Returns `None` when `block_count` is 0, when the byte count
    /// overflows `u64`, or when it exceeds `u32::MAX`; the driver answers
    /// each with `blk_errors::INVALID_MEMORY_CAP`, as the wire contract
    /// states.
    #[must_use]
    pub fn transfer_len(self, block_count: u64) -> Option<u32>
    {
        if block_count == 0
        {
            return None;
        }
        block_count
            .checked_mul(u64::from(self.block_size))
            .and_then(|n| u32::try_from(n).ok())
    }
}

/// 512-byte sectors per logical block of `block_size` bytes.
fn sectors_per_block(block_size: u32) -> u64
{
    u64::from(block_size) / VIRTIO_SECTOR_SIZE
}

/// Per-badge partition bound: the LBA range, in logical blocks, a
/// partition-badged caller may access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionBound
{
    pub badge: u64,
    pub base_lba: u64,
    pub length_lba: u64,
}

/// The partition ranges registered on the driver, keyed by partition badge.
///
/// A registration of a range already in the table returns that range's
/// badge: the badge is the range's identity, and a cap carrying it grants
/// exactly that range, so a remount of a partition reuses its entry. The
/// table therefore holds one entry per distinct range a `MOUNT_AUTHORITY`
/// holder registered, not one per registration. It grows on the heap with
/// the distinct ranges; nothing in it is fixed-size.
#[derive(Default)]
pub struct PartitionTable
{
    entries: Vec<PartitionBound>,
    /// Next fresh partition badge. Badges stay in the low 63 bits, so they
    /// are bit-disjoint from `blk_labels::MOUNT_AUTHORITY` by construction;
    /// reaching that bit takes 2^63 distinct ranges.
    next_badge: u64,
}

impl PartitionTable
{
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            entries: Vec::new(),
            next_badge: 1,
        }
    }

    /// The bound registered for `badge`, if any. Badge 0 (unbadged) never
    /// names one.
    #[must_use]
    pub fn lookup(&self, badge: u64) -> Option<PartitionBound>
    {
        if badge == 0
        {
            return None;
        }
        self.entries.iter().copied().find(|b| b.badge == badge)
    }

    /// Register the range `[base_lba, base_lba + length_lba)` and return its
    /// badge, reusing the badge of an identical range already registered.
    ///
    /// Returns `None` for an empty range, when the fresh-badge counter has
    /// reached `blk_labels::MOUNT_AUTHORITY`, or when the heap cannot grow the
    /// table. The caller checks the range against the device capacity first.
    pub fn register(&mut self, base_lba: u64, length_lba: u64) -> Option<u64>
    {
        if length_lba == 0
        {
            return None;
        }
        if let Some(b) = self
            .entries
            .iter()
            .find(|b| b.base_lba == base_lba && b.length_lba == length_lba)
        {
            return Some(b.badge);
        }
        let badge = self.next_badge;
        if badge & ipc::blk_labels::MOUNT_AUTHORITY != 0
        {
            return None;
        }
        self.entries.try_reserve(1).ok()?;
        self.next_badge += 1;
        self.entries.push(PartitionBound {
            badge,
            base_lba,
            length_lba,
        });
        Some(badge)
    }
}

/// How a submitted block request ended, as the driver observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOutcome
{
    /// The device completed the request and wrote `status` into the
    /// status byte.
    Completed
    {
        /// The status byte the device wrote.
        status: u8,
    },
    /// The descriptor chain could not be queued; the device never saw the
    /// request.
    NotQueued,
    /// The device did not complete the request within the timeout, or
    /// published a completion the virtqueue refused or that names another
    /// chain. The request may still be in flight, so the device may still
    /// access the request's data buffer.
    Lost,
}

impl IoOutcome
{
    /// The reply label for this outcome.
    ///
    /// A completion maps its status byte explicitly: `VIRTIO_BLK_S_OK` to
    /// `SUCCESS`, `VIRTIO_BLK_S_IOERR` to `DEVICE_STATUS_IOERR`,
    /// `VIRTIO_BLK_S_UNSUPP` to `DEVICE_STATUS_UNSUPP`. Every other outcome,
    /// a status byte outside the spec's set included, is `DEVICE_FAULT`; the
    /// raw byte is never forwarded, so it cannot alias another code.
    #[must_use]
    pub fn reply_label(self) -> u64
    {
        match self
        {
            IoOutcome::Completed {
                status: VIRTIO_BLK_S_OK,
            } => blk_errors::SUCCESS,
            IoOutcome::Completed {
                status: VIRTIO_BLK_S_IOERR,
            } => blk_errors::DEVICE_STATUS_IOERR,
            IoOutcome::Completed {
                status: VIRTIO_BLK_S_UNSUPP,
            } => blk_errors::DEVICE_STATUS_UNSUPP,
            IoOutcome::Completed { .. } | IoOutcome::NotQueued | IoOutcome::Lost =>
            {
                blk_errors::DEVICE_FAULT
            }
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn geometry(block_size: u32) -> Geometry
    {
        Geometry::new(1 << 20, Some(block_size)).expect("supported block size")
    }

    #[test]
    fn transfer_len_rejects_zero_overflowing_and_oversized_counts()
    {
        let g = geometry(512);
        assert_eq!(g.transfer_len(0), None);
        // 2^55 * 512 overflows u64: a bare multiply aborts the driver in a
        // dev build and wraps to 0 in release.
        assert_eq!(g.transfer_len(1 << 55), None);
        assert_eq!(g.transfer_len(u64::MAX), None);
        // One block past the u32 descriptor-length bound.
        assert_eq!(g.transfer_len(u64::from(u32::MAX) / 512 + 1), None);
    }

    #[test]
    fn transfer_len_counts_logical_blocks_up_to_the_descriptor_bound()
    {
        assert_eq!(geometry(512).transfer_len(1), Some(512));
        let g = geometry(4096);
        assert_eq!(g.transfer_len(1), Some(4096));
        let max = u64::from(u32::MAX) / 4096;
        assert_eq!(g.transfer_len(max).map(u64::from), Some(max * 4096));
        assert_eq!(g.transfer_len(max + 1), None);
    }

    #[test]
    fn geometry_without_the_feature_is_512_byte_blocks_over_the_sector_capacity()
    {
        let g = Geometry::new(1000, None).expect("default block size");
        assert_eq!((g.block_size, g.capacity), (512, 1000));
        assert_eq!(g.device_sector(7), 7);
    }

    #[test]
    fn geometry_of_a_4kn_device_counts_and_addresses_4096_byte_blocks()
    {
        // 1001 sectors hold 125 whole 4 KiB blocks; the partial tail block
        // is not addressable.
        let g = Geometry::new(1001, Some(4096)).expect("4Kn");
        assert_eq!((g.block_size, g.capacity), (4096, 125));
        // LBA 1, where a GPT header sits, is VirtIO sector 8.
        assert_eq!(g.device_sector(1), 8);
    }

    #[test]
    fn geometry_refuses_block_sizes_the_driver_cannot_serve()
    {
        for bad in [0, 256, 1536, 8192]
        {
            assert_eq!(Geometry::new(1000, Some(bad)), None, "block size {bad}");
        }
    }

    #[test]
    fn registering_a_range_twice_reuses_its_badge_and_entry()
    {
        let mut t = PartitionTable::new();
        let a = t.register(2048, 100).expect("fresh range");
        let b = t.register(4096, 100).expect("fresh range");
        assert_ne!(a, b);
        // A remount of the first range: same badge, no new entry, so the
        // table does not grow with registrations.
        assert_eq!(t.register(2048, 100), Some(a));
        assert_eq!(t.entries.len(), 2);
        assert_eq!(
            t.lookup(a),
            Some(PartitionBound {
                badge: a,
                base_lba: 2048,
                length_lba: 100
            })
        );
        // Overlapping but distinct ranges are distinct entries.
        assert_ne!(t.register(2048, 99), Some(a));
    }

    #[test]
    fn partition_table_refuses_empty_ranges_and_never_names_badge_zero()
    {
        let mut t = PartitionTable::new();
        assert_eq!(t.register(10, 0), None);
        assert_eq!(t.lookup(0), None);
        let a = t.register(10, 1).expect("fresh range");
        assert_ne!(a, 0);
        assert_eq!(t.lookup(a + 1), None);
    }

    #[test]
    fn partition_badges_stop_short_of_the_mount_authority_bit()
    {
        let mut t = PartitionTable::new();
        t.next_badge = ipc::blk_labels::MOUNT_AUTHORITY - 1;
        let last = t.register(0, 1).expect("last fresh badge");
        assert_eq!(last & ipc::blk_labels::MOUNT_AUTHORITY, 0);
        assert_eq!(t.register(1, 1), None);
        // An already-registered range still resolves.
        assert_eq!(t.register(0, 1), Some(last));
    }

    #[test]
    fn reply_label_maps_spec_status_bytes_to_their_blk_errors()
    {
        let completed = |status| IoOutcome::Completed { status }.reply_label();
        assert_eq!(completed(VIRTIO_BLK_S_OK), blk_errors::SUCCESS);
        assert_eq!(
            completed(VIRTIO_BLK_S_IOERR),
            blk_errors::DEVICE_STATUS_IOERR
        );
        assert_eq!(
            completed(VIRTIO_BLK_S_UNSUPP),
            blk_errors::DEVICE_STATUS_UNSUPP
        );
    }

    #[test]
    fn reply_label_is_device_fault_for_every_other_outcome()
    {
        // 0xFF is the driver's not-completed sentinel: forwarded raw it read
        // as UNKNOWN_OPCODE.
        for outcome in [
            IoOutcome::Completed { status: 0xFF },
            IoOutcome::Completed { status: 3 },
            IoOutcome::NotQueued,
            IoOutcome::Lost,
        ]
        {
            assert_eq!(outcome.reply_label(), blk_errors::DEVICE_FAULT);
        }
    }
}
