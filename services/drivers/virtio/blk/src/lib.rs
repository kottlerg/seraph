// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/blk/src/lib.rs

//! Host-testable request logic of the `VirtIO` block driver.
//!
//! The driver binary (`main.rs`, `io.rs`) owns the device, the virtqueue,
//! and the IPC loop. This library holds the pure decisions those paths
//! make on client- and device-supplied values: the transfer length a
//! client's sector count asks for, and the reply label a request's outcome
//! maps to. Both are wire-contract decisions (`shared/ipc::blk_errors`), so
//! they live where a host test can pin them.

use ipc::blk_errors;

/// Bytes per sector on the `BLK_READ_INTO_MEMORY` / `BLK_WRITE_FROM_MEMORY`
/// wire (`VirtIO` 1.2 §5.2.6 sectors are 512 bytes).
pub const SECTOR_SIZE: u64 = 512;

/// Device status byte: request completed (`VIRTIO_BLK_S_OK`, `VirtIO` 1.2 §5.2.6).
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// Device status byte: I/O error (`VIRTIO_BLK_S_IOERR`).
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// Device status byte: request type unsupported (`VIRTIO_BLK_S_UNSUPP`).
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Byte length of a transfer of `sector_count` sectors, as the `u32` a
/// `VirtIO` descriptor carries.
///
/// Returns `None` when `sector_count` is 0, when `sector_count * 512`
/// overflows `u64` (a client-supplied count of 2^55 or more), or when the
/// product exceeds `u32::MAX`; the driver answers each with
/// `blk_errors::INVALID_MEMORY_CAP`, as the wire contract states.
#[must_use]
pub fn transfer_len(sector_count: u64) -> Option<u32>
{
    if sector_count == 0
    {
        return None;
    }
    sector_count
        .checked_mul(SECTOR_SIZE)
        .and_then(|n| u32::try_from(n).ok())
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

    #[test]
    fn transfer_len_rejects_zero_overflowing_and_oversized_counts()
    {
        assert_eq!(transfer_len(0), None);
        // 2^55 * 512 overflows u64: a bare multiply aborts the driver in a
        // dev build and wraps to 0 in release.
        assert_eq!(transfer_len(1 << 55), None);
        assert_eq!(transfer_len(u64::MAX), None);
        // One sector past the u32 descriptor-length bound.
        assert_eq!(transfer_len(u64::from(u32::MAX) / SECTOR_SIZE + 1), None);
    }

    #[test]
    fn transfer_len_accepts_counts_up_to_the_descriptor_bound()
    {
        assert_eq!(transfer_len(1), Some(512));
        let max = u64::from(u32::MAX) / SECTOR_SIZE;
        assert_eq!(transfer_len(max).map(u64::from), Some(max * SECTOR_SIZE));
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
