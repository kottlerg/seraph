// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/lib.rs

//! `VirtIO` transport and virtqueue primitives shared by all `VirtIO` drivers.
//!
//! Provides the modern PCI transport, virtqueue management, device negotiation,
//! the startup message format used by devmgr to pass PCI capability info
//! to `VirtIO` drivers, the register layout by which a driver maps every BAR
//! the register regions name ([`RegisterLayout`]), the driver's reading of
//! the resource list devmgr delivers it ([`bootstrap`]), the mapping of a driver's buffers for its
//! device ([`dma`]), and the interrupt-service loop each driver runs on a
//! thread of its own ([`isr`]).

#![cfg_attr(not(test), no_std)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]

extern crate alloc;

use syscall_abi::PAGE_SIZE;

pub mod bootstrap;
pub mod dma;
pub mod isr;
pub mod pci;
pub mod virtqueue;

// ── Reserved feature bits (VirtIO 1.2 §6) ──────────────────────────────────

/// `VIRTIO_F_VERSION_1`: the device is a modern (`VirtIO` 1.x) device.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// `VIRTIO_F_ACCESS_PLATFORM`: the device reaches memory through the
/// platform's address translation (an IOMMU), so the driver programs it with
/// device addresses rather than physical ones. A driver accepts it whenever
/// offered, since it programs only the device addresses devmgr returns
/// ([`dma`]).
pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;

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
#[derive(Clone, Copy, Debug, Default)]
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

impl VirtioCapLocation
{
    /// The byte offset in the BAR just past the region.
    #[must_use]
    pub fn end(&self) -> u64
    {
        // Two `u32` values widened to `u64`: the sum cannot saturate.
        u64::from(self.offset).saturating_add(u64::from(self.length))
    }
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

/// Why the data words of a `QUERY_DEVICE_INFO` reply hold no
/// [`VirtioPciStartupInfo`] ([`VirtioPciStartupInfo::from_device_info`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceInfoError
{
    /// Fewer than the three header words (kind, version, byte length).
    TruncatedHeader,
    /// A kind other than `ipc::device_info_kind::VIRTIO_PCI`, or a version
    /// other than [`VIRTIO_PCI_INFO_VERSION`].
    KindVersionMismatch,
    /// A byte length other than [`VirtioPciStartupInfo::SIZE`], or fewer
    /// payload words than it takes.
    LengthMismatch,
}

impl DeviceInfoError
{
    /// What a driver logs for the error.
    #[must_use]
    pub const fn describe(self) -> &'static str
    {
        match self
        {
            Self::TruncatedHeader => "QUERY_DEVICE_INFO reply truncated (header)",
            Self::KindVersionMismatch => "QUERY_DEVICE_INFO reply kind/version mismatch",
            Self::LengthMismatch => "QUERY_DEVICE_INFO reply length mismatch",
        }
    }
}

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

    /// Decode the data words of a successful `QUERY_DEVICE_INFO` reply, the
    /// generic schema devmgr answers every `VirtIO` driver in: `words[0]` the
    /// kind, `words[1]` the version, `words[2]` the payload's byte length,
    /// and the payload bytes packed little-endian into the words after them.
    /// The words are another process's, so each is checked: a header word
    /// past its field's width is a mismatch, not a value to truncate.
    ///
    /// # Errors
    ///
    /// The [`DeviceInfoError`] the words fail on.
    pub fn from_device_info(words: &[u64]) -> Result<Self, DeviceInfoError>
    {
        let (&[kind, version, byte_len], payload) = words
            .split_first_chunk::<3>()
            .ok_or(DeviceInfoError::TruncatedHeader)?;
        if u32::try_from(kind).ok() != Some(ipc::device_info_kind::VIRTIO_PCI)
            || u32::try_from(version).ok() != Some(VIRTIO_PCI_INFO_VERSION)
        {
            return Err(DeviceInfoError::KindVersionMismatch);
        }
        if usize::try_from(byte_len).ok() != Some(Self::SIZE)
        {
            return Err(DeviceInfoError::LengthMismatch);
        }
        let payload = payload
            .get(..Self::SIZE.div_ceil(8))
            .ok_or(DeviceInfoError::LengthMismatch)?;
        let mut buf = [0u8; Self::SIZE];
        for (chunk, word) in buf.chunks_mut(8).zip(payload)
        {
            for (dst, src) in chunk.iter_mut().zip(word.to_le_bytes())
            {
                *dst = src;
            }
        }
        Self::from_bytes(&buf).ok_or(DeviceInfoError::LengthMismatch)
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
    /// Returns `None` when a region is not one the transport can use
    /// ([`structure_usable`]): absent (zero length), naming a BAR index
    /// outside 0-5, a common region shorter than the [`COMMON_CFG_LEN`]
    /// bytes of registers the transport addresses in it, or a common,
    /// notification, or device region whose offsets would make a register
    /// access misaligned. `VirtIO` 1.2 § 4.1.4 requires a modern PCI device
    /// to present the common, notification, and ISR regions, and a device
    /// type with device-specific configuration (block and input both have
    /// one) to present that region too, each in a BAR of the device's choosing;
    /// devmgr's scan keeps the first structure of each type that lies wholly
    /// inside one of the device's MMIO BARs and passes [`structure_usable`],
    /// so a region this refuses means the device presents none the driver
    /// can use.
    #[must_use]
    pub fn register_layout(&self) -> Option<RegisterLayout>
    {
        let regions = [
            (VIRTIO_PCI_CAP_COMMON_CFG, &self.common_cfg),
            (VIRTIO_PCI_CAP_NOTIFY_CFG, &self.notify_cfg),
            (VIRTIO_PCI_CAP_ISR_CFG, &self.isr_cfg),
            (VIRTIO_PCI_CAP_DEVICE_CFG, &self.device_cfg),
        ];
        if !regions
            .iter()
            .all(|&(ty, r)| structure_usable(ty, r, self.notify_off_multiplier))
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
                .map(|&(_, r)| r)
                .filter(|r| r.bar == bar)
                .map(VirtioCapLocation::end)
                .max();
            if let Some(reach) = reach
            {
                *bars.get_mut(bar_count)? = BarAperture {
                    bar,
                    pages: reach.div_ceil(PAGE_SIZE),
                };
                // Below MAX_VIRTIO_BARS before the increment: no saturation.
                bar_count = bar_count.saturating_add(1);
            }
        }
        let mut layout = RegisterLayout {
            bars,
            bar_count,
            regions: regions.map(|(_, r)| *r),
            common: 0,
            notify: 0,
            isr: 0,
            device: 0,
            notify_len: u64::from(self.notify_cfg.length),
            device_len: u64::from(self.device_cfg.length),
            notify_off_multiplier: self.notify_off_multiplier,
        };
        layout.common = layout.region_offset(&self.common_cfg)?;
        layout.notify = layout.region_offset(&self.notify_cfg)?;
        layout.isr = layout.region_offset(&self.isr_cfg)?;
        layout.device = layout.region_offset(&self.device_cfg)?;
        Some(layout)
    }
}

/// BAR registers in a PCI type-0 configuration header; a `VirtIO`
/// capability naming an index at or above it names no BAR.
const PCI_BAR_COUNT: u8 = 6;

/// Most distinct BARs a `VirtIO` device's register regions name: one per
/// region (common, notification, ISR, and device configuration, the four
/// region types `VirtIO` 1.2 § 4.1.4 defines). A hardware-spec bound.
pub const MAX_VIRTIO_BARS: usize = 4;

/// Most `Mmio` ranges devmgr delivers a `VirtIO` driver for the BARs its
/// register regions name: one per BAR, and two more, since each of the two
/// page spans devmgr withholds (those holding the function's MSI-X table and
/// Pending Bit Array) splits at most one range in two
/// (`driver_binding::resources::MAX_PCI_RANGES`). A driver refuses a resource
/// list that delivers more ([`bootstrap`]).
pub const MAX_VIRTIO_RANGES: usize = MAX_VIRTIO_BARS + 2;

/// One BAR a device's register regions name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BarAperture
{
    /// PCI BAR index (0-5).
    pub bar: u8,
    /// 4 KiB pages from the BAR's start that the regions in it reach; at
    /// least 1. devmgr carves the BAR's `Mmio` caps from at most this many
    /// pages, and the driver maps them into that many pages of its window.
    pub pages: u64,
}

/// One delivered `Mmio` range of a BAR: the driver's cap on it, the PCI BAR
/// index, the range's offset in the BAR, and its length. devmgr delivers a
/// BAR as one range from its start, or as several when it withholds pages of
/// it (docs/device-management.md § Message-Signaled Interrupts).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BarRange
{
    pub cap: u64,
    pub bar: u8,
    pub offset: u64,
    pub bytes: u64,
}

/// Where a `VirtIO` device's four register regions sit, for a driver that
/// maps every BAR they name into one register window.
///
/// The window gives each BAR in [`bars`](Self::bars) order (ascending BAR
/// index) [`BarAperture::pages`] pages, each BAR's following the previous
/// one's. A BAR range devmgr delivers maps at its BAR's window offset plus
/// the range's offset in the BAR ([`Self::place`]), and a region's window
/// offset is its BAR's window offset plus the region's offset in the BAR.
/// Built by [`VirtioPciStartupInfo::register_layout`].
#[derive(Clone, Copy, Debug)]
pub struct RegisterLayout
{
    bars: [BarAperture; MAX_VIRTIO_BARS],
    bar_count: usize,
    /// The common, notification, ISR, and device regions, in their BARs.
    regions: [VirtioCapLocation; 4],
    /// Window offset of the common configuration region.
    pub common: u64,
    /// Window offset of the notification region.
    pub notify: u64,
    /// Window offset of the ISR status region.
    pub isr: u64,
    /// Window offset of the device-specific configuration region.
    pub device: u64,
    /// Length in bytes of the notification region; every queue's doorbell
    /// must lie inside it ([`pci::doorbell_fits`]).
    pub notify_len: u64,
    /// Length in bytes of the device-specific configuration region; every
    /// read of it must lie inside it ([`pci::config_fits`]).
    pub device_len: u64,
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
        // `bar_count` never exceeds the array (`register_layout`).
        self.bars.get(..self.bar_count).unwrap_or_default()
    }

    /// Pages the whole register window spans: the sum of the BARs' pages.
    #[must_use]
    pub fn window_pages(&self) -> u64
    {
        self.bars().iter().map(|b| b.pages).sum()
    }

    /// Window offset of BAR `bar`'s pages: the pages of every BAR before it.
    /// `None` when the sum does not fit a `u64`.
    fn bar_offset(&self, bar: u8) -> Option<u64>
    {
        self.bars()
            .iter()
            .take_while(|b| b.bar != bar)
            .try_fold(0u64, |sum, b| {
                sum.checked_add(b.pages.checked_mul(PAGE_SIZE)?)
            })
    }

    /// Window offset of `region`: the offset of its BAR's pages plus its
    /// offset in the BAR. Every region of the layout names one of its BARs.
    /// `None` when the sum does not fit a `u64`.
    fn region_offset(&self, region: &VirtioCapLocation) -> Option<u64>
    {
        self.bar_offset(region.bar)?
            .checked_add(u64::from(region.offset))
    }

    /// The window offset each of the delivered BAR `ranges` maps at, in
    /// their order (the first `ranges.len()` entries): its BAR's window
    /// offset plus its offset in the BAR. `None` unless the ranges are this
    /// layout's own: at most [`MAX_VIRTIO_RANGES`], each in a BAR the layout
    /// names, at a page-aligned offset, its pages inside its BAR's
    /// [`BarAperture::pages`]; in ascending BAR and offset order with no two
    /// ranges' pages overlapping, so no mapping lands on another's; and every
    /// register region lying inside one range, so every register the
    /// transport reaches is mapped.
    #[must_use]
    pub fn place(&self, ranges: &[BarRange]) -> Option<[u64; MAX_VIRTIO_RANGES]>
    {
        if ranges.len() > MAX_VIRTIO_RANGES
        {
            return None;
        }
        let mut placed = [0; MAX_VIRTIO_RANGES];
        // The end of the previous range's pages, as (BAR, offset).
        let mut previous: Option<(u8, u64)> = None;
        for (slot, r) in placed.iter_mut().zip(ranges)
        {
            let aperture = self.bars().iter().find(|b| b.bar == r.bar)?;
            let end = r
                .bytes
                .checked_next_multiple_of(PAGE_SIZE)
                .and_then(|pages| r.offset.checked_add(pages))?;
            if !r.offset.is_multiple_of(PAGE_SIZE)
                || r.bytes == 0
                || aperture
                    .pages
                    .checked_mul(PAGE_SIZE)
                    .is_none_or(|bar_end| end > bar_end)
                || previous.is_some_and(|(bar, past)| (r.bar, r.offset) < (bar, past))
            {
                return None;
            }
            previous = Some((r.bar, end));
            *slot = self.bar_offset(r.bar)?.checked_add(r.offset)?;
        }
        let inside = |region: &VirtioCapLocation| {
            let start = u64::from(region.offset);
            let end = region.end();
            ranges.iter().any(|r| {
                r.bar == region.bar
                    && r.offset <= start
                    && r.offset
                        .checked_add(r.bytes)
                        .is_some_and(|r_end| end <= r_end)
            })
        };
        self.regions.iter().all(inside).then_some(placed)
    }
}

/// Offset of the `device_status` byte in the common configuration region
/// (`VirtIO` 1.2 §4.1.4.3). Writing 0 to it resets the device, which stops its
/// DMA and drops a pending interrupt (§2.4).
pub const COMMON_DEVICE_STATUS: u32 = 0x14;

/// Bytes of the common configuration region the transport addresses: the
/// registers from `device_feature_select` at 0 through `queue_device` at
/// 0x30..0x38 (`VirtIO` 1.2 §4.1.4.3). A device whose common region is
/// shorter presents no register layout
/// ([`VirtioPciStartupInfo::register_layout`]), so no register access in it
/// reaches past the region into the rest of the register window.
pub const COMMON_CFG_LEN: u32 = 0x38;

/// Where a reset writes a device's `device_status` byte: its PCI BAR index
/// and the byte's offset in the BAR. A holder of that BAR's `Mmio` cap checks
/// the offset against the span its cap covers before it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusRegister
{
    pub bar: u8,
    pub offset: u64,
}

impl VirtioPciStartupInfo
{
    /// The device-status byte's place ([`StatusRegister`]): in the common
    /// configuration region's BAR, at the region's offset plus
    /// [`COMMON_DEVICE_STATUS`]. `None` when the device presents no complete
    /// register layout ([`Self::register_layout`]), whose common region
    /// always holds the byte ([`COMMON_CFG_LEN`]).
    #[must_use]
    pub fn status_register(&self) -> Option<StatusRegister>
    {
        self.register_layout()?;
        let bar = self.common_cfg.bar;
        Some(StatusRegister {
            bar,
            offset: u64::from(self.common_cfg.offset)
                .checked_add(u64::from(COMMON_DEVICE_STATUS))?,
        })
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

/// Whether the transport can use a structure of `cfg_type` (one of the four
/// `VIRTIO_PCI_CAP_*` types above) at `loc`, with `notify_off_multiplier`
/// the multiplier a notification structure carries (read only for that
/// type).
///
/// A structure is usable when it is present (non-zero length) and names a
/// BAR index 0-5, and further:
///
/// - a common configuration structure holds the [`COMMON_CFG_LEN`] bytes
///   of registers the transport addresses and its offset is 4-aligned
///   (`VirtIO` 1.2 § 4.1.4.3.1), so each 16- and 32-bit register in it is
///   naturally aligned;
/// - a notification structure's offset and multiplier are both 2-aligned
///   (§ 4.1.4.4.1: the offset 2-byte aligned, the multiplier 0 or an even
///   power of 2), so every 16-bit doorbell is naturally aligned;
/// - a device-specific configuration structure's offset is 4-aligned
///   (§ 4.1.4.6), so its 32-bit reads ([`pci::config_fits`]) can be
///   naturally aligned.
///
/// The ISR structure is read a byte at a time and takes no alignment test.
///
/// The register window maps each BAR page-aligned, so an offset's alignment
/// in its BAR is its alignment in the window. devmgr's scan applies this to
/// each structure as it walks the capability list, keeping the first usable
/// one of each type (`VirtIO` 1.2 § 4.1.4.1), and
/// [`VirtioPciStartupInfo::register_layout`] refuses a layout with a region
/// that fails it. An unknown `cfg_type` is not usable.
#[must_use]
pub fn structure_usable(cfg_type: u8, loc: &VirtioCapLocation, notify_off_multiplier: u32) -> bool
{
    if loc.length == 0 || loc.bar >= PCI_BAR_COUNT
    {
        return false;
    }
    match cfg_type
    {
        VIRTIO_PCI_CAP_COMMON_CFG => loc.length >= COMMON_CFG_LEN && loc.offset.is_multiple_of(4),
        VIRTIO_PCI_CAP_NOTIFY_CFG =>
        {
            loc.offset.is_multiple_of(2) && notify_off_multiplier.is_multiple_of(2)
        }
        VIRTIO_PCI_CAP_DEVICE_CFG => loc.offset.is_multiple_of(4),
        VIRTIO_PCI_CAP_ISR_CFG => true,
        _ => false,
    }
}

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
            notify_off_multiplier: 0x40,
            pad: 0,
        }
    }

    #[test]
    fn the_status_register_is_in_the_common_regions_bar_past_its_offset()
    {
        // The common region of a VirtIO 1.x device: 0x38 bytes, holding `device_status`.
        let mut info = populated();
        info.common_cfg.length = 0x38;
        let status = info.status_register().expect("complete layout");
        assert_eq!(status.bar, 1);
        assert_eq!(status.offset, 0x100 + u64::from(COMMON_DEVICE_STATUS));
    }

    #[test]
    fn no_status_register_without_a_layout_or_room_for_the_byte()
    {
        let mut info = populated();
        info.common_cfg.length = COMMON_DEVICE_STATUS;
        assert_eq!(info.status_register(), None);
        let mut info = populated();
        info.isr_cfg.length = 0;
        assert_eq!(info.status_register(), None);
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

    /// The data words devmgr's `QUERY_DEVICE_INFO` reply carries for `info`.
    fn device_info_words(info: &VirtioPciStartupInfo) -> Vec<u64>
    {
        let mut buf = [0u8; VirtioPciStartupInfo::SIZE];
        info.to_bytes(&mut buf).expect("buffer is SIZE bytes");
        let mut words = vec![
            u64::from(ipc::device_info_kind::VIRTIO_PCI),
            u64::from(VIRTIO_PCI_INFO_VERSION),
            VirtioPciStartupInfo::SIZE as u64,
        ];
        words.extend(buf.chunks(8).map(|c| {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            u64::from_le_bytes(w)
        }));
        words
    }

    #[test]
    fn device_info_words_decode_to_the_info_devmgr_encoded()
    {
        let info = populated();
        let back = VirtioPciStartupInfo::from_device_info(&device_info_words(&info))
            .expect("a well-formed reply");
        assert_eq!(back.notify_cfg.offset, 0x200);
        assert_eq!(back.device_cfg.length, 0x40);
        assert_eq!(back.notify_off_multiplier, 0x40);
    }

    #[test]
    fn device_info_words_of_another_shape_are_refused()
    {
        let words = device_info_words(&populated());
        let decode = |w: &[u64]| VirtioPciStartupInfo::from_device_info(w).err();
        assert_eq!(decode(&words[..2]), Some(DeviceInfoError::TruncatedHeader));
        let with = |i: usize, value: u64| {
            let mut w = words.clone();
            w[i] = value;
            decode(&w)
        };
        // Another kind, another version, or a kind past the field's width
        // that would truncate to the right one.
        assert_eq!(with(0, 0), Some(DeviceInfoError::KindVersionMismatch));
        assert_eq!(
            with(1, u64::from(VIRTIO_PCI_INFO_VERSION) + 1),
            Some(DeviceInfoError::KindVersionMismatch)
        );
        assert_eq!(
            with(0, (1 << 32) | u64::from(ipc::device_info_kind::VIRTIO_PCI)),
            Some(DeviceInfoError::KindVersionMismatch)
        );
        // A byte length other than the struct's, or a payload one word short.
        assert_eq!(with(2, 8), Some(DeviceInfoError::LengthMismatch));
        assert_eq!(
            decode(&words[..words.len() - 1]),
            Some(DeviceInfoError::LengthMismatch)
        );
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
            cap(2, 0, 0x100),
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
        // The doorbell bound is the notification region's own length, not
        // the span of the page its BAR maps.
        assert_eq!(layout.notify_len, 0x100);
    }

    #[test]
    fn a_common_region_shorter_than_the_addressed_registers_has_no_layout()
    {
        // The queue_device pair ends at 0x38: one byte short, and its last
        // register would reach past the region.
        let mut regions = [
            cap(0, 0, COMMON_CFG_LEN - 1),
            cap(0, 0x1000, 0x1000),
            cap(0, 0x2000, 4),
            cap(0, 0x3000, 8),
        ];
        assert!(layout_of(regions).is_none());
        regions[0].length = COMMON_CFG_LEN;
        let layout = layout_of(regions).expect("every region long enough");
        // The device region's own length bounds its reads.
        assert_eq!(layout.device_len, 8);
    }

    #[test]
    fn a_common_region_at_an_offset_not_4_aligned_has_no_layout()
    {
        // At offset 2 the 32-bit `device_feature` register (0x04) would sit
        // at window offset 6.
        let mut regions = [
            cap(0, 2, 0x38),
            cap(0, 0x1000, 0x1000),
            cap(0, 0x2000, 4),
            cap(0, 0x3000, 8),
        ];
        assert!(layout_of(regions).is_none());
        regions[0].offset = 4;
        assert!(layout_of(regions).is_some());
    }

    #[test]
    fn a_notification_region_or_multiplier_not_2_aligned_has_no_layout()
    {
        let regions = |notify_offset| {
            [
                cap(0, 0, 0x38),
                cap(0, notify_offset, 0x1000),
                cap(0, 0x2000, 4),
                cap(0, 0x3000, 8),
            ]
        };
        let with_multiplier = |notify_offset, notify_off_multiplier| {
            let r = regions(notify_offset);
            VirtioPciStartupInfo {
                common_cfg: r[0],
                notify_cfg: r[1],
                isr_cfg: r[2],
                device_cfg: r[3],
                notify_off_multiplier,
                pad: 0,
            }
            .register_layout()
        };
        // An odd region offset puts queue 0's doorbell at an odd address.
        assert!(with_multiplier(0x1001, 4).is_none());
        // An odd multiplier puts queue 1's doorbell at an odd address.
        assert!(with_multiplier(0x1000, 3).is_none());
        assert!(with_multiplier(0x1002, 2).is_some());
        // A zero multiplier puts every doorbell at the region's start.
        assert!(with_multiplier(0x1000, 0).is_some());
    }

    #[test]
    fn every_type_but_isr_takes_an_alignment_test()
    {
        let odd = cap(0, 1, COMMON_CFG_LEN);
        assert!(!structure_usable(VIRTIO_PCI_CAP_COMMON_CFG, &odd, 0));
        assert!(!structure_usable(VIRTIO_PCI_CAP_NOTIFY_CFG, &odd, 0));
        assert!(structure_usable(VIRTIO_PCI_CAP_ISR_CFG, &odd, 0));
        assert!(!structure_usable(VIRTIO_PCI_CAP_DEVICE_CFG, &odd, 0));
        // 2-aligned is enough for the doorbells, not for the device
        // configuration's 32-bit reads.
        let half = cap(0, 2, COMMON_CFG_LEN);
        assert!(structure_usable(VIRTIO_PCI_CAP_NOTIFY_CFG, &half, 0));
        assert!(!structure_usable(VIRTIO_PCI_CAP_DEVICE_CFG, &half, 0));
        assert!(structure_usable(
            VIRTIO_PCI_CAP_DEVICE_CFG,
            &cap(0, 4, 8),
            0
        ));
        // The multiplier is read for the notification type only.
        let even = cap(0, 4, COMMON_CFG_LEN);
        assert!(structure_usable(VIRTIO_PCI_CAP_COMMON_CFG, &even, 3));
        assert!(!structure_usable(VIRTIO_PCI_CAP_NOTIFY_CFG, &even, 3));
        // Absent, past BAR 5, or of no transport type: not usable.
        assert!(!structure_usable(VIRTIO_PCI_CAP_ISR_CFG, &cap(0, 0, 0), 0));
        assert!(!structure_usable(VIRTIO_PCI_CAP_ISR_CFG, &cap(6, 0, 4), 0));
        assert!(!structure_usable(5, &even, 0));
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

    fn range(cap: u64, bar: u8, offset: u64, bytes: u64) -> BarRange
    {
        BarRange {
            cap,
            bar,
            offset,
            bytes,
        }
    }

    fn two_bar_layout() -> RegisterLayout
    {
        // BAR 2: notification, one page. BAR 4: common at 0, ISR at 0x1000,
        // device at 0x3000, four pages.
        layout_of([
            cap(4, 0, 0x38),
            cap(2, 0, 0x1000),
            cap(4, 0x1000, 4),
            cap(4, 0x3000, 8),
        ])
        .expect("every region present")
    }

    #[test]
    fn whole_bars_are_placed_at_their_bars_window_offsets()
    {
        let layout = two_bar_layout();
        let placed = layout
            .place(&[range(10, 2, 0, 0x1000), range(11, 4, 0, 0x4000)])
            .expect("the layout's own BARs");
        assert_eq!(&placed[..2], &[0, 0x1000]);
    }

    #[test]
    fn ranges_around_withheld_pages_are_placed_at_their_offsets()
    {
        // BAR 4's page at 0x2000 withheld: two ranges, each at its offset in
        // the BAR, and the regions all inside one of them.
        let layout = two_bar_layout();
        let placed = layout
            .place(&[
                range(10, 2, 0, 0x1000),
                range(11, 4, 0, 0x2000),
                range(12, 4, 0x3000, 0x1000),
            ])
            .expect("every region delivered");
        assert_eq!(&placed[..3], &[0, 0x1000, 0x4000]);
    }

    #[test]
    fn ranges_that_are_not_the_layouts_own_are_refused()
    {
        let layout = two_bar_layout();
        let whole = |bar, pages| range(10, bar, 0, pages * PAGE_SIZE);
        // A BAR missing, so its regions are not delivered.
        assert!(layout.place(&[whole(4, 4)]).is_none());
        // A BAR the layout does not name.
        assert!(
            layout
                .place(&[whole(2, 1), whole(4, 4), whole(5, 1)])
                .is_none()
        );
        // Out of order.
        assert!(layout.place(&[whole(4, 4), whole(2, 1)]).is_none());
        // Past the BAR's pages.
        assert!(layout.place(&[whole(2, 2), whole(4, 4)]).is_none());
        // An offset not page-aligned.
        assert!(
            layout
                .place(&[whole(2, 1), range(11, 4, 0x800, 0x3800)])
                .is_none()
        );
        // Two ranges of one BAR overlapping.
        assert!(
            layout
                .place(&[
                    whole(2, 1),
                    range(11, 4, 0, 0x2000),
                    range(12, 4, 0x1000, 0x3000)
                ])
                .is_none()
        );
        // The ISR's page withheld: the region is not delivered.
        assert!(
            layout
                .place(&[
                    whole(2, 1),
                    range(11, 4, 0, 0x1000),
                    range(12, 4, 0x2000, 0x2000)
                ])
                .is_none()
        );
        // A region reaching past its range's bytes, though inside its page.
        assert!(
            layout
                .place(&[whole(2, 1), range(11, 4, 0, 0x3004)])
                .is_none()
        );
        // More ranges than any delivery holds.
        let many = [range(10, 2, 0, 0x1000); MAX_VIRTIO_RANGES + 1];
        assert!(layout.place(&many).is_none());
    }
}
