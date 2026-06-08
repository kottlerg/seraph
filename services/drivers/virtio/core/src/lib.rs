// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/core/src/lib.rs

//! `VirtIO` transport and virtqueue primitives shared by all `VirtIO` drivers.
//!
//! Provides the modern PCI transport, virtqueue management, device negotiation,
//! and the startup message format used by devmgr to pass PCI capability info
//! to `VirtIO` drivers.

#![cfg_attr(not(test), no_std)]

pub mod pci;
pub mod virtqueue;

// ── Device status bits (VirtIO 1.2 §2.1) ───────────────────────────────────

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const STATUS_FAILED: u8 = 128;

// ── PCI capability info (startup message format) ────────────────────────────

/// `VirtIO` PCI capability location within a BAR.
///
/// Serialised into the driver's startup message by devmgr. The driver
/// deserialises it to locate `VirtIO` register regions within mapped BARs.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioCapLocation
{
    /// PCI BAR index (0-5) containing this capability's registers.
    pub bar: u8,
    /// Padding for alignment.
    pub pad: [u8; 3],
    /// Byte offset within the BAR.
    pub offset: u32,
    /// Length in bytes.
    pub length: u32,
}

/// Startup message written by devmgr for `VirtIO` PCI drivers.
///
/// Contains the locations of the four `VirtIO` PCI capability regions
/// and the notification offset multiplier. devmgr discovers these by
/// walking the PCI capability list during enumeration.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioPciStartupInfo
{
    /// Common configuration (type 1).
    pub common_cfg: VirtioCapLocation,
    /// Notification structure (type 2).
    pub notify_cfg: VirtioCapLocation,
    /// ISR status (type 3).
    pub isr_cfg: VirtioCapLocation,
    /// Device-specific configuration (type 4).
    pub device_cfg: VirtioCapLocation,
    /// Multiplier for queue-specific notification offsets.
    pub notify_off_multiplier: u32,
    /// Padding for alignment.
    pub pad: u32,
}

/// Schema version of the [`VirtioPciStartupInfo`] payload exchanged via
/// [`devmgr_labels::QUERY_DEVICE_INFO`]. Bump whenever the struct layout
/// changes; callers verify this value before deserialising.
///
/// [`devmgr_labels::QUERY_DEVICE_INFO`]: ../../../shared/ipc/index.html
pub const VIRTIO_PCI_INFO_VERSION: u32 = 1;

impl VirtioPciStartupInfo
{
    /// Size of the serialised startup message in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Deserialise from a byte slice (startup message).
    ///
    /// Returns `None` if the slice is too short.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self>
    {
        if bytes.len() < Self::SIZE
        {
            return None;
        }
        // SAFETY: VirtioPciStartupInfo is repr(C) with no padding invariants;
        // any bit pattern is valid. Slice length is checked above.
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }

    /// Serialise to a byte buffer. Returns `None` if the buffer is too small.
    #[must_use]
    pub fn to_bytes(&self, buf: &mut [u8]) -> Option<()>
    {
        if buf.len() < Self::SIZE
        {
            return None;
        }
        // SAFETY: buf has sufficient length; Self is repr(C) POD.
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref(self).cast::<u8>(),
                buf.as_mut_ptr(),
                Self::SIZE,
            );
        }
        Some(())
    }

    /// Number of 4 KiB pages spanned by the highest reach across all four
    /// capability regions in BAR 0. Drivers use this to size the VA
    /// reservation backing `mmio_map` for the BAR.
    #[must_use]
    pub fn bar_aperture_pages(&self) -> u64
    {
        const PAGE_SIZE: u64 = 0x1000;
        let mut max_reach: u64 = 0;
        for cap in [
            &self.common_cfg,
            &self.notify_cfg,
            &self.isr_cfg,
            &self.device_cfg,
        ]
        {
            let reach = u64::from(cap.offset).saturating_add(u64::from(cap.length));
            if reach > max_reach
            {
                max_reach = reach;
            }
        }
        max_reach.div_ceil(PAGE_SIZE).max(1)
    }
}

// ── VirtIO PCI capability types (VirtIO 1.2 §4.1.4) ────────────────────────

/// Common configuration capability type.
pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// Notification capability type.
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// ISR status capability type.
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// Device-specific configuration capability type.
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

#[cfg(test)]
mod tests
{
    use super::*;

    fn cap(bar: u8, offset: u32, length: u32) -> VirtioCapLocation
    {
        VirtioCapLocation {
            bar,
            pad: [0; 3],
            offset,
            length,
        }
    }

    fn populated() -> VirtioPciStartupInfo
    {
        VirtioPciStartupInfo {
            common_cfg: cap(1, 0x100, 0x10),
            notify_cfg: cap(2, 0x200, 0x20),
            isr_cfg: cap(3, 0x300, 0x30),
            device_cfg: cap(4, 0x400, 0x40),
            notify_off_multiplier: 0x55,
            pad: 0,
        }
    }

    #[test]
    fn startup_info_bytes_round_trip_preserves_populated_value()
    {
        let info = populated();
        let mut buf = [0u8; VirtioPciStartupInfo::SIZE];
        info.to_bytes(&mut buf).expect("buffer is SIZE bytes");
        // common_cfg.bar is byte 0: proves to_bytes actually wrote the value
        // (so the round trip below is not a zero-equals-zero tautology).
        assert_eq!(buf[0], 1);

        let back = VirtioPciStartupInfo::from_bytes(&buf).expect("slice is SIZE bytes");
        let mut reserialised = [0u8; VirtioPciStartupInfo::SIZE];
        back.to_bytes(&mut reserialised)
            .expect("buffer is SIZE bytes");
        assert_eq!(buf, reserialised);
    }

    #[test]
    fn startup_info_marshalling_rejects_undersized_buffer()
    {
        let info = populated();
        let mut small = [0u8; VirtioPciStartupInfo::SIZE - 1];
        assert!(info.to_bytes(&mut small).is_none());
        assert!(VirtioPciStartupInfo::from_bytes(&small).is_none());
    }

    #[test]
    fn bar_aperture_pages_spans_max_reach_across_all_caps()
    {
        let mut info = populated();
        // The 4th cap reaches furthest, one byte into the second page; the
        // result must take the max over all caps and round the partial page up.
        info.device_cfg = cap(0, 0x1000, 0x10);
        assert_eq!(info.bar_aperture_pages(), 2);
    }

    #[test]
    fn bar_aperture_pages_floors_to_one_page_when_all_zero()
    {
        assert_eq!(VirtioPciStartupInfo::default().bar_aperture_pages(), 1);
    }
}
