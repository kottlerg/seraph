// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/lib.rs

//! `VirtIO` transport and virtqueue primitives shared by all `VirtIO` drivers.
//!
//! Provides the modern PCI transport, virtqueue management, device negotiation,
//! the startup message format used by devmgr to pass PCI capability info
//! to `VirtIO` drivers, the register layout a driver maps every BAR it names
//! by ([`RegisterLayout`]), and the devmgr-to-driver bootstrap rounds
//! ([`bootstrap`]).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use syscall_abi::PAGE_SIZE;

pub mod bootstrap;
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

    /// Locate the device's register regions for the driver's register
    /// window: the distinct BARs they name and each region's place in the
    /// window (see [`RegisterLayout`]).
    ///
    /// Returns `None` when a region is absent (zero length) or names a BAR
    /// index outside 0-5. `VirtIO` 1.2 § 4.1.4 requires a modern PCI device
    /// to present the common, notification, and ISR regions, and a device
    /// type with device-specific configuration (block and input both have
    /// one) to present that region too, each in a BAR of the device's
    /// choosing; devmgr's scan keeps the first structure of each type that
    /// lies in an MMIO BAR, so an absent region means the device presents
    /// none the driver can map.
    #[must_use]
    pub fn register_layout(&self) -> Option<RegisterLayout>
    {
        let regions = [
            &self.common_cfg,
            &self.notify_cfg,
            &self.isr_cfg,
            &self.device_cfg,
        ];
        if regions
            .iter()
            .any(|r| r.length == 0 || r.bar >= PCI_BAR_COUNT)
        {
            return None;
        }
        let mut bars = [BarAperture::default(); MAX_VIRTIO_BARS];
        let mut bar_count = 0;
        // Ascending BAR index; each BAR spans the furthest reach of the
        // regions in it. Four regions name at most four BARs.
        for bar in 0..PCI_BAR_COUNT
        {
            let reach = regions
                .iter()
                .filter(|r| r.bar == bar)
                .map(|r| u64::from(r.offset) + u64::from(r.length))
                .max();
            if let Some(reach) = reach
            {
                bars[bar_count] = BarAperture {
                    bar,
                    pages: reach.div_ceil(PAGE_SIZE),
                };
                bar_count += 1;
            }
        }
        let mut layout = RegisterLayout {
            bars,
            bar_count,
            common: 0,
            notify: 0,
            isr: 0,
            device: 0,
            notify_off_multiplier: self.notify_off_multiplier,
        };
        layout.common = layout.region_offset(&self.common_cfg);
        layout.notify = layout.region_offset(&self.notify_cfg);
        layout.isr = layout.region_offset(&self.isr_cfg);
        layout.device = layout.region_offset(&self.device_cfg);
        Some(layout)
    }
}

/// BAR registers in a PCI type-0 configuration header; a `VirtIO`
/// capability naming an index at or above it names no BAR.
const PCI_BAR_COUNT: u8 = 6;

/// Most distinct BARs a `VirtIO` device's register regions name: one per
/// region (common, notification, ISR, and device configuration, the four
/// region types `VirtIO` 1.2 § 4.1.4 defines). A hardware-spec bound; the
/// one bootstrap round that delivers the BARs holds that many caps
/// ([`bootstrap`]).
pub const MAX_VIRTIO_BARS: usize = 4;

/// One BAR a device's register regions name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BarAperture
{
    /// PCI BAR index (0-5).
    pub bar: u8,
    /// 4 KiB pages from the BAR's start that the regions in it reach; at
    /// least 1. devmgr carves the BAR's `Mmio` cap to at most this many
    /// pages, and the driver maps it into that many pages of its window.
    pub pages: u64,
}

/// Where a `VirtIO` device's four register regions sit, for a driver that
/// maps every BAR they name into one register window.
///
/// The window holds one mapping per BAR in [`bars`](Self::bars) order
/// (ascending BAR index), each [`BarAperture::pages`] long and following the
/// previous one. A region's window offset is its BAR's offset in the window
/// plus the region's offset in the BAR. Built by
/// [`VirtioPciStartupInfo::register_layout`].
#[derive(Clone, Copy, Debug)]
pub struct RegisterLayout
{
    bars: [BarAperture; MAX_VIRTIO_BARS],
    bar_count: usize,
    /// Window offset of the common configuration region.
    pub common: u64,
    /// Window offset of the notification region.
    pub notify: u64,
    /// Window offset of the ISR status region.
    pub isr: u64,
    /// Window offset of the device-specific configuration region.
    pub device: u64,
    /// Multiplier for queue-specific notification offsets.
    pub notify_off_multiplier: u32,
}

impl RegisterLayout
{
    /// The distinct BARs the regions name, in ascending BAR index: the
    /// order devmgr delivers their caps in and the window lays them out in.
    #[must_use]
    pub fn bars(&self) -> &[BarAperture]
    {
        &self.bars[..self.bar_count]
    }

    /// Pages the whole register window spans: the sum of the BARs' pages.
    #[must_use]
    pub fn window_pages(&self) -> u64
    {
        self.bars().iter().map(|b| b.pages).sum()
    }

    /// Window offset of `region`: the offset of its BAR's mapping (the pages
    /// of every BAR before it) plus its offset in the BAR. Every region of
    /// the layout names one of its BARs.
    fn region_offset(&self, region: &VirtioCapLocation) -> u64
    {
        let bar_offset: u64 = self
            .bars()
            .iter()
            .take_while(|b| b.bar != region.bar)
            .map(|b| b.pages * PAGE_SIZE)
            .sum();
        bar_offset + u64::from(region.offset)
    }

    /// Whether `bar_indices`, the PCI BAR index of each delivered BAR cap in
    /// delivery order, names exactly this layout's BARs in its order, so the
    /// caps map into the window by position.
    #[must_use]
    pub fn matches_delivered(&self, bar_indices: &[u64]) -> bool
    {
        bar_indices.len() == self.bar_count
            && self
                .bars()
                .iter()
                .zip(bar_indices)
                .all(|(b, &i)| u64::from(b.bar) == i)
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

    fn layout_of(regions: [VirtioCapLocation; 4]) -> Option<RegisterLayout>
    {
        VirtioPciStartupInfo {
            common_cfg: regions[0],
            notify_cfg: regions[1],
            isr_cfg: regions[2],
            device_cfg: regions[3],
            notify_off_multiplier: 4,
            pad: 0,
        }
        .register_layout()
    }

    #[test]
    fn one_bar_spans_the_furthest_region_rounded_up_to_a_page()
    {
        // The device region reaches furthest, one byte past the first page;
        // the BAR takes the furthest reach, not the last region's, and
        // rounds the partial page up.
        let layout = layout_of([
            cap(0, 0, 0x38),
            cap(0, 0x800, 0x100),
            cap(0, 0x900, 4),
            cap(0, 0xFF0, 0x11),
        ])
        .expect("every region present");
        assert_eq!(layout.bars(), &[BarAperture { bar: 0, pages: 2 }]);
        assert_eq!(
            (layout.common, layout.notify, layout.isr, layout.device),
            (0, 0x800, 0x900, 0xFF0)
        );
    }

    #[test]
    fn regions_in_two_bars_are_placed_through_their_own_bars_mappings()
    {
        // Notification in BAR 2; the other three in BAR 4, reaching into its
        // third page. The window lays BAR 2 (one page) before BAR 4 (three),
        // and each region sits at its own BAR's window offset.
        let layout = layout_of([
            cap(4, 0, 0x38),
            cap(2, 0, 0x1000),
            cap(4, 0x1000, 4),
            cap(4, 0x2000, 8),
        ])
        .expect("every region present");
        assert_eq!(
            layout.bars(),
            &[
                BarAperture { bar: 2, pages: 1 },
                BarAperture { bar: 4, pages: 3 }
            ]
        );
        assert_eq!(layout.window_pages(), 4);
        assert_eq!(
            (layout.common, layout.notify, layout.isr, layout.device),
            (0x1000, 0, 0x2000, 0x3000)
        );
    }

    #[test]
    fn a_device_missing_a_register_region_has_no_layout()
    {
        let mut regions = [
            cap(0, 0, 0x38),
            cap(0, 0x1000, 0x1000),
            cap(0, 0x2000, 4),
            cap(0, 0x3000, 8),
        ];
        assert!(layout_of(regions).is_some());
        regions[3].length = 0;
        assert!(layout_of(regions).is_none());
    }

    #[test]
    fn a_region_naming_a_reserved_bar_index_has_no_layout()
    {
        assert!(
            layout_of([
                cap(0, 0, 0x38),
                cap(6, 0, 0x1000),
                cap(0, 0x2000, 4),
                cap(0, 0x3000, 8),
            ])
            .is_none()
        );
    }

    #[test]
    fn delivered_bars_match_only_the_layouts_bars_in_its_order()
    {
        let layout = layout_of([
            cap(4, 0, 0x38),
            cap(2, 0, 0x1000),
            cap(4, 0x1000, 4),
            cap(4, 0x2000, 8),
        ])
        .expect("every region present");
        assert!(layout.matches_delivered(&[2, 4]));
        assert!(!layout.matches_delivered(&[4, 2]));
        assert!(!layout.matches_delivered(&[2]));
        assert!(!layout.matches_delivered(&[2, 4, 5]));
    }
}
