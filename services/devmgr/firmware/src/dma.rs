// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/dma.rs

//! The DMA mappings devmgr keeps for each DMA-capable device, the device
//! addresses it gives them, and the check of a `DMA_MAP` request's access
//! against the rights of the Memory cap it carries.
//!
//! devmgr registers a device when it gives the device's driver its DMA
//! capability, with the device's confinement: unconfined, when no IOMMU
//! translates the device, so a mapping's device address is its frames'
//! physical address; or a domain of the IOMMU driver, when one does, so
//! devmgr allocates each mapping an IOVA in the device's own IOVA space,
//! below the device's IOVA limit ([`iova_limit`]). A mapping is recorded in
//! two steps around the IOMMU driver's `MAP`, which devmgr calls with no lock
//! held: [`DmaTable::reserve`] records it pending, holding its addresses so
//! no other mapping takes them, and [`DmaTable::commit`] makes it standing
//! once the IOMMU installed it, or [`DmaTable::abort`] drops it. An unmap is
//! two steps around the IOMMU driver's `UNMAP` the same way
//! ([`DmaTable::begin_unmap`], [`DmaTable::finish_unmap`] or
//! [`DmaTable::restore`]). Withdrawing a device removes it with every
//! mapping and returns the standing ones, whose caps devmgr then deletes; a
//! pending or unmapping mapping's cap stays with the thread mid-call, which
//! finds the device gone when it returns. A device holds at most
//! [`MAX_MAPPINGS_PER_DEVICE`] mappings, and no two of a device's mappings
//! overlap in device-address space. A confined device registers with the
//! firmware-reserved ranges its domain maps at their own addresses
//! ([`reserved_ranges`]), and holds the interrupt files its domain maps at
//! their own addresses ([`DmaTable::hold_interrupt_file`]); no mapping's IOVA
//! overlaps either, nor, for a device a VT-d unit confines, the interrupt
//! address range ([`INTERRUPT_RANGE`]). The table never reads or writes IOMMU
//! state. See `docs/device-management.md` § DMA
//! Authorisation and § IOMMU Discovery and Programming.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use ipc::devmgr_dma_labels::{ACCESS_DEVICE_WRITE, ACCESS_MASK};
use syscall_abi::{PAGE_SIZE, RIGHTS_MEM_MAP, RIGHTS_MEM_WRITE};

/// Mappings one device holds at once.
///
/// A device's driver maps its own rings and buffers once at setup and, for a
/// block device, the one client-lent buffer of its single in-flight request
/// (`services/drivers/virtio/blk/README.md`): three for virtio-blk, two for
/// virtio-input. Sixteen leaves room for a multi-queue device without
/// letting one driver grow devmgr's table without bound; `docs/limits.md`
/// classifies it.
pub const MAX_MAPPINGS_PER_DEVICE: usize = 16;

/// Firmware-reserved ranges one device's domain maps at once, after
/// [`reserved_ranges`] merges the ones that touch.
///
/// A device an RMRR names is a USB controller with legacy emulation, an
/// integrated graphics unit, or a storage unit, each named by one or two
/// regions on the platforms that carry them; four leaves room past that
/// without letting a malformed table grow the device's domain without
/// bound. `docs/limits.md` classifies it. A device with more is refused.
pub const MAX_RESERVED_RANGES_PER_DEVICE: usize = 4;

/// The lowest IOVA devmgr gives a confined device's mappings. The first MiB
/// of every domain stays unmapped but for the firmware-reserved ranges a
/// device's domain maps at their own addresses, so a device programmed with a
/// small stray address (a zero or an offset taken for an address) faults
/// instead of reaching a mapping.
pub const IOVA_BASE: u64 = 0x10_0000;

/// The x86 interrupt address range, `0xFEE0_0000` to `0xFEEF_FFFF`. VT-d
/// takes a device's write in it as an interrupt request and never translates
/// it through the device's domain (Intel VT-d specification § 3.14), so a
/// mapping there would be unreachable by the device's DMA; no mapping of a
/// device whose confinement keeps this range out
/// ([`Confinement::Domain`]'s `interrupt_range`) is given an IOVA in it.
pub const INTERRUPT_RANGE: core::ops::Range<u64> = 0xFEE0_0000..0xFF00_0000;

/// The end of the IOVA space devmgr allocates a confined device's mappings
/// in: the smaller of what its unit translates (`unit_bits`, from the IOMMU
/// driver's `QUERY_UNIT`) and what the device addresses (`device_bits`, the
/// DMA address width its driver's declaration states; `None` for no limit of
/// its own).
#[must_use]
pub fn iova_limit(unit_bits: u8, device_bits: Option<u8>) -> u64
{
    let end = |bits: u8| 1u64.checked_shl(u32::from(bits)).unwrap_or(u64::MAX);
    let unit = end(unit_bits);
    device_bits.map_or(unit, |bits| unit.min(end(bits)))
}

/// How a registered device reaches its frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confinement
{
    /// No IOMMU translates the device: a mapping's device address is the
    /// frames' physical address.
    Unconfined,
    /// The IOMMU driver confines the device in the domain `handle`; devmgr
    /// allocates its IOVAs in `[IOVA_BASE, limit)`, outside
    /// [`INTERRUPT_RANGE`] when `interrupt_range` is set.
    Domain
    {
        /// The domain handle the IOMMU driver's `ATTACH` returned.
        handle: u64,
        /// The end of the device's IOVA space ([`iova_limit`]).
        limit: u64,
        /// Whether the device's unit takes its writes in
        /// [`INTERRUPT_RANGE`] as interrupt requests, untranslated: set for
        /// a VT-d unit.
        interrupt_range: bool,
    },
}

/// One mapping of a device: `len` bytes of physically contiguous frames,
/// reachable by the device at `device_addr` with `access`, and the slot of
/// the Memory cap over them that devmgr keeps while the mapping stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping
{
    /// devmgr's slot of the mapped Memory cap, deleted when the mapping is
    /// removed.
    pub cap: u64,
    /// The device address of the first byte, the one `DMA_MAP` returns: an
    /// IOVA for a confined device, the physical address for an unconfined
    /// one.
    pub device_addr: u64,
    /// Bytes mapped; nonzero.
    pub len: u64,
    /// `ACCESS_DEVICE_READ` and/or [`ACCESS_DEVICE_WRITE`]
    /// (`ipc::devmgr_dma_labels`).
    pub access: u64,
}

impl Mapping
{
    /// Whether the device-address range of `self` shares a byte with
    /// `[addr, addr + len)`.
    fn overlaps(&self, addr: u64, len: u64) -> bool
    {
        self.device_addr < addr.saturating_add(len)
            && addr < self.device_addr.saturating_add(self.len)
    }
}

/// A firmware-reserved range of a confined device: whole pages its domain
/// maps at their own addresses, read-write, for its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservedRange
{
    /// The first byte; page-aligned.
    pub base: u64,
    /// Bytes; a nonzero multiple of the page size.
    pub len: u64,
}

impl ReservedRange
{
    /// Whether the range shares a byte with `[addr, addr + len)`.
    fn overlaps(&self, addr: u64, len: u64) -> bool
    {
        self.base < addr.saturating_add(len) && addr < self.base.saturating_add(self.len)
    }
}

/// Why a device's firmware-reserved ranges cannot be mapped, so the device
/// is refused ([`reserved_ranges`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedError
{
    /// The range, rounded out to whole pages, overlaps memory memmgr pools,
    /// which the device would then reach: a firmware error.
    Pooled(ReservedRange),
    /// The range ends past what the device's remapping unit translates, or
    /// past the end of the address space.
    PastWidth
    {
        /// The range's first byte, as the firmware gives it.
        base: u64,
        /// The range's last byte, as the firmware gives it.
        last: u64,
    },
    /// More than [`MAX_RESERVED_RANGES_PER_DEVICE`] ranges remain once the
    /// ones that touch are merged.
    TooMany,
    /// The list could not grow.
    OutOfMemory,
}

/// The firmware-reserved ranges a confined device's domain maps at their own
/// addresses, from the `(first, last)` byte of each region the firmware
/// reserves for it (a VT-d RMRR names it).
///
/// Each region is rounded out to whole pages, since a domain maps pages, and
/// ranges that overlap or abut are merged, in ascending order. `pooled` holds
/// the `(base, size)` of every extent of memory memmgr pools; `width_bits` is
/// what the device's remapping unit translates (`QUERY_UNIT`).
///
/// # Errors
/// [`ReservedError::PastWidth`] for a region whose rounded end passes the
/// unit's width or the address space; [`ReservedError::Pooled`] for a
/// rounded range that overlaps a `pooled` extent; [`ReservedError::TooMany`]
/// past [`MAX_RESERVED_RANGES_PER_DEVICE`]; [`ReservedError::OutOfMemory`]
/// when the list cannot grow.
pub fn reserved_ranges(
    regions: &[(u64, u64)],
    pooled: &[(u64, u64)],
    width_bits: u8,
) -> Result<Vec<ReservedRange>, ReservedError>
{
    let unit_end = 1u64.checked_shl(u32::from(width_bits)).unwrap_or(u64::MAX);
    let mut ranges: Vec<ReservedRange> = Vec::new();
    ranges
        .try_reserve(regions.len())
        .map_err(|_| ReservedError::OutOfMemory)?;
    for &(first, last) in regions
    {
        let past = ReservedError::PastWidth { base: first, last };
        let base = first & !(PAGE_SIZE - 1);
        let end = last
            .checked_add(1)
            .and_then(|e| e.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(past)?;
        if last < first || end > unit_end
        {
            return Err(past);
        }
        ranges.push(ReservedRange {
            base,
            len: end.saturating_sub(base),
        });
    }
    ranges.sort_unstable_by_key(|r| r.base);
    let mut merged: Vec<ReservedRange> = Vec::new();
    merged
        .try_reserve(ranges.len())
        .map_err(|_| ReservedError::OutOfMemory)?;
    for r in ranges
    {
        match merged.last_mut()
        {
            Some(prev) if r.base <= prev.base.saturating_add(prev.len) =>
            {
                let end = prev
                    .base
                    .saturating_add(prev.len)
                    .max(r.base.saturating_add(r.len));
                prev.len = end.saturating_sub(prev.base);
            }
            _ => merged.push(r),
        }
    }
    if let Some(r) = merged
        .iter()
        .find(|r| pooled.iter().any(|&(base, size)| r.overlaps(base, size)))
    {
        return Err(ReservedError::Pooled(*r));
    }
    if merged.len() > MAX_RESERVED_RANGES_PER_DEVICE
    {
        return Err(ReservedError::TooMany);
    }
    Ok(merged)
}

/// Why a mapping was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError
{
    /// The badge names no registered device.
    UnknownDevice,
    /// The access word is zero or sets an unknown bit, the mapping is empty
    /// or runs past the end of the address space, or an unconfined device's
    /// mapping comes without its physical address.
    InvalidRequest,
    /// The cap lacks the rights the access needs ([`required_rights`]).
    InsufficientRights,
    /// The device already holds [`MAX_MAPPINGS_PER_DEVICE`] mappings.
    TooMany,
    /// The device-address range overlaps another mapping of the device.
    AddressInUse,
    /// The device's IOVA space holds no free range of the mapping's length.
    NoAddressSpace,
    /// The table could not grow.
    OutOfMemory,
}

/// Why an unmap was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmapError
{
    /// The badge names no registered device.
    UnknownDevice,
    /// No standing mapping of the device starts at the address.
    NoMapping,
}

/// The Memory-cap rights a mapping with `access` needs: `MAP` for a device
/// that only reads, `MAP|WRITE` for one that writes. `None` when `access` is
/// zero or sets a bit other than the two access bits.
#[must_use]
pub fn required_rights(access: u64) -> Option<u64>
{
    if access == 0 || access & !ACCESS_MASK != 0
    {
        return None;
    }
    if access & ACCESS_DEVICE_WRITE != 0
    {
        Some(RIGHTS_MEM_MAP | RIGHTS_MEM_WRITE)
    }
    else
    {
        Some(RIGHTS_MEM_MAP)
    }
}

/// Check a `DMA_MAP` request's `access` against the `rights` of the Memory
/// cap it carries.
///
/// # Errors
/// [`MapError::InvalidRequest`] for an access word [`required_rights`]
/// refuses, and [`MapError::InsufficientRights`] when `rights` lacks a right
/// the access needs.
pub fn check_access(access: u64, rights: u64) -> Result<(), MapError>
{
    let required = required_rights(access).ok_or(MapError::InvalidRequest)?;
    if rights & required == required
    {
        Ok(())
    }
    else
    {
        Err(MapError::InsufficientRights)
    }
}

/// Where a mapping is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State
{
    /// Reserved, and the IOMMU driver's `MAP` not yet answered.
    Pending,
    /// Standing: the device reaches it.
    Standing,
    /// The IOMMU driver's `UNMAP` of it not yet answered.
    Unmapping,
}

#[derive(Clone, Copy)]
struct Entry
{
    mapping: Mapping,
    state: State,
}

/// A registered device, its confinement, its firmware-reserved ranges and
/// held interrupt files, and its mappings.
struct Device
{
    badge: u64,
    confinement: Confinement,
    /// The firmware-reserved ranges, then each interrupt file's page held
    /// since ([`DmaTable::hold_interrupt_file`]).
    reserved: Vec<ReservedRange>,
    /// How many of `reserved` are firmware-reserved ranges; the rest are
    /// held interrupt files.
    firmware: usize,
    entries: Vec<Entry>,
}

impl Device
{
    /// The interrupt files' pages the device holds.
    fn files(&self) -> &[ReservedRange]
    {
        self.reserved.get(self.firmware..).unwrap_or_default()
    }

    fn entry(&mut self, device_addr: u64, state: State) -> Option<&mut Entry>
    {
        self.entries
            .iter_mut()
            .find(|e| e.mapping.device_addr == device_addr && e.state == state)
    }

    /// The lowest page-aligned address in `[IOVA_BASE, limit)` where `len`
    /// bytes overlap none of the device's mappings, none of its reserved
    /// ranges, and, when `interrupt_range` is set, no byte of
    /// [`INTERRUPT_RANGE`].
    fn free_iova(&self, len: u64, limit: u64, interrupt_range: bool) -> Option<u64>
    {
        let len = len.checked_next_multiple_of(PAGE_SIZE)?;
        let mut start = IOVA_BASE;
        loop
        {
            let clash_end = if let Some(e) =
                self.entries.iter().find(|e| e.mapping.overlaps(start, len))
            {
                e.mapping.device_addr.saturating_add(e.mapping.len)
            }
            else if let Some(r) = self.reserved.iter().find(|r| r.overlaps(start, len))
            {
                r.base.saturating_add(r.len)
            }
            else if interrupt_range
                && INTERRUPT_RANGE.start < start.saturating_add(len)
                && start < INTERRUPT_RANGE.end
            {
                INTERRUPT_RANGE.end
            }
            else
            {
                break;
            };
            start = clash_end.checked_next_multiple_of(PAGE_SIZE)?;
        }
        (start.checked_add(len)? <= limit).then_some(start)
    }
}

/// A device removed from the table: its confinement and the mappings that
/// stood, whose caps the caller deletes only once the device can no longer
/// reach their frames ([`settle_withdrawal`]).
#[derive(Debug, PartialEq, Eq)]
pub struct Withdrawn
{
    /// How the device reached its frames.
    pub confinement: Confinement,
    /// Every standing mapping it held.
    pub mappings: Vec<Mapping>,
}

/// What becomes of the Memory caps a withdrawal took from a device's
/// standing mappings ([`settle_withdrawal`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawnMappings
{
    /// The device can no longer reach the frames: delete the caps.
    Release,
    /// The device may still write the frames: keep the caps for the rest of
    /// the boot, so memmgr keeps the frames out of its pool.
    Quarantine,
}

/// Whether the IOMMU blocks a withdrawn device's DMA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuBlock
{
    /// The IOMMU driver completed the device's `BLOCK`: the device reaches
    /// no frame.
    Blocked,
    /// The device is unconfined, its `BLOCK` did not complete, or it was
    /// withdrawn already, so nothing is left to block.
    NotBlocked,
}

/// Settle the withdrawal of a device whose DMA grant was withdrawn, `block`
/// telling whether the IOMMU now blocks it: run `stop`, devmgr's stop of the
/// device (Bus Master Enable cleared, its driver's BAR copies revoked, the
/// device reset), which reports whether every step confirmed, whatever
/// `block` is. Returns what becomes of the mappings' caps: deleted when the
/// device can no longer reach its driver's frames, blocked or confirmed
/// stopped, else kept (`docs/device-management.md` § DMA-Safe Teardown).
pub fn settle_withdrawal(block: IommuBlock, stop: impl FnOnce() -> bool) -> WithdrawnMappings
{
    let stopped = stop();
    match (block, stopped)
    {
        (IommuBlock::Blocked, _) | (IommuBlock::NotBlocked, true) => WithdrawnMappings::Release,
        (IommuBlock::NotBlocked, false) => WithdrawnMappings::Quarantine,
    }
}

/// Every device devmgr gives DMA, by badge, with its mappings.
#[derive(Default)]
pub struct DmaTable
{
    devices: Vec<Device>,
}

impl DmaTable
{
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            devices: Vec::new(),
        }
    }

    fn device_mut(&mut self, badge: u64) -> Option<&mut Device>
    {
        self.devices.iter_mut().find(|d| d.badge == badge)
    }

    /// Register the device `badge` with no mappings, `confinement`, and the
    /// firmware-reserved ranges its domain maps (`reserved`, empty for an
    /// unconfined device), so its driver's requests are served and no
    /// mapping's IOVA overlaps a reserved range. Registering a registered
    /// badge changes nothing.
    ///
    /// # Errors
    /// The allocation error when the table cannot grow; nothing is
    /// registered then.
    pub fn register(
        &mut self,
        badge: u64,
        confinement: Confinement,
        reserved: &[ReservedRange],
    ) -> Result<(), TryReserveError>
    {
        if self.device_mut(badge).is_some()
        {
            return Ok(());
        }
        let mut kept = Vec::new();
        kept.try_reserve_exact(reserved.len())?;
        kept.extend_from_slice(reserved);
        self.devices.try_reserve(1)?;
        self.devices.push(Device {
            badge,
            confinement,
            reserved: kept,
            firmware: reserved.len(),
            entries: Vec::new(),
        });
        Ok(())
    }

    /// The confinement of the device `badge`; `None` for an unregistered
    /// badge.
    #[must_use]
    pub fn confinement(&self, badge: u64) -> Option<Confinement>
    {
        self.devices
            .iter()
            .find(|d| d.badge == badge)
            .map(|d| d.confinement)
    }

    /// Reserve a mapping of `len` bytes of the cap `cap` with `access` for
    /// the device `badge`, pending until [`Self::commit`] or
    /// [`Self::abort`], and return it with its device address: `phys`, the
    /// frames' physical address, for an unconfined device, and the lowest
    /// free IOVA of the device's space for a confined one (`phys` unused),
    /// outside its reserved ranges, held interrupt files, and, behind a VT-d
    /// unit, [`INTERRUPT_RANGE`].
    ///
    /// # Errors
    /// [`MapError::UnknownDevice`] for an unregistered badge;
    /// [`MapError::InvalidRequest`] for an access word [`required_rights`]
    /// refuses, an empty mapping, one past the end of the address space, or
    /// an unconfined device's mapping with no `phys`;
    /// [`MapError::TooMany`] when the device holds its bound;
    /// [`MapError::AddressInUse`] when an unconfined device's frames overlap
    /// another mapping of the device; [`MapError::NoAddressSpace`] when a
    /// confined device's space has no room; [`MapError::OutOfMemory`] when
    /// the table cannot grow. Nothing is recorded on any error.
    pub fn reserve(
        &mut self,
        badge: u64,
        cap: u64,
        len: u64,
        access: u64,
        phys: Option<u64>,
    ) -> Result<Mapping, MapError>
    {
        let device = self.device_mut(badge).ok_or(MapError::UnknownDevice)?;
        if required_rights(access).is_none() || len == 0
        {
            return Err(MapError::InvalidRequest);
        }
        if device.entries.len() >= MAX_MAPPINGS_PER_DEVICE
        {
            return Err(MapError::TooMany);
        }
        let device_addr = match device.confinement
        {
            Confinement::Unconfined =>
            {
                let addr = phys.ok_or(MapError::InvalidRequest)?;
                if addr.checked_add(len).is_none()
                {
                    return Err(MapError::InvalidRequest);
                }
                if device.entries.iter().any(|e| e.mapping.overlaps(addr, len))
                {
                    return Err(MapError::AddressInUse);
                }
                addr
            }
            Confinement::Domain {
                limit,
                interrupt_range,
                ..
            } => device
                .free_iova(len, limit, interrupt_range)
                .ok_or(MapError::NoAddressSpace)?,
        };
        device
            .entries
            .try_reserve(1)
            .map_err(|_| MapError::OutOfMemory)?;
        let mapping = Mapping {
            cap,
            device_addr,
            len,
            access,
        };
        device.entries.push(Entry {
            mapping,
            state: State::Pending,
        });
        Ok(mapping)
    }

    /// Make the pending mapping of the device `badge` at `device_addr`
    /// standing. `false` when the device was withdrawn meanwhile, so the
    /// mapping and its cap are the caller's to drop.
    pub fn commit(&mut self, badge: u64, device_addr: u64) -> bool
    {
        let Some(entry) = self
            .device_mut(badge)
            .and_then(|d| d.entry(device_addr, State::Pending))
        else
        {
            return false;
        };
        entry.state = State::Standing;
        true
    }

    /// Drop the pending mapping of the device `badge` at `device_addr`,
    /// freeing its addresses; nothing when the device was withdrawn.
    pub fn abort(&mut self, badge: u64, device_addr: u64)
    {
        if let Some(d) = self.device_mut(badge)
        {
            d.entries
                .retain(|e| !(e.mapping.device_addr == device_addr && e.state == State::Pending));
        }
    }

    /// Start unmapping the standing mapping of the device `badge` at
    /// `device_addr`: it is no longer standing, and its addresses stay held
    /// until [`Self::finish_unmap`] or [`Self::restore`]. Returns it with the
    /// device's confinement.
    ///
    /// # Errors
    /// [`UnmapError::UnknownDevice`] for an unregistered badge, and
    /// [`UnmapError::NoMapping`] when no standing mapping of the device
    /// starts there.
    pub fn begin_unmap(
        &mut self,
        badge: u64,
        device_addr: u64,
    ) -> Result<(Mapping, Confinement), UnmapError>
    {
        let device = self.device_mut(badge).ok_or(UnmapError::UnknownDevice)?;
        let confinement = device.confinement;
        let entry = device
            .entry(device_addr, State::Standing)
            .ok_or(UnmapError::NoMapping)?;
        entry.state = State::Unmapping;
        Ok((entry.mapping, confinement))
    }

    /// Remove the mapping [`Self::begin_unmap`] started on, freeing its
    /// addresses; nothing when the device was withdrawn meanwhile.
    pub fn finish_unmap(&mut self, badge: u64, device_addr: u64)
    {
        if let Some(d) = self.device_mut(badge)
        {
            d.entries
                .retain(|e| !(e.mapping.device_addr == device_addr && e.state == State::Unmapping));
        }
    }

    /// Make the mapping [`Self::begin_unmap`] started on standing again, its
    /// unmap having failed. `false` when the device was withdrawn meanwhile,
    /// so the mapping's cap is the caller's to drop.
    pub fn restore(&mut self, badge: u64, device_addr: u64) -> bool
    {
        let Some(entry) = self
            .device_mut(badge)
            .and_then(|d| d.entry(device_addr, State::Unmapping))
        else
        {
            return false;
        };
        entry.state = State::Standing;
        true
    }

    /// Hold the page of an interrupt file at `file` out of the IOVA space of
    /// the confined device `badge`, beside its firmware-reserved ranges: its
    /// domain is to map the page at its own address
    /// (`iommu_labels::MAP_MSI`), so no mapping's IOVA may overlap it. Held
    /// before the page is mapped, so no mapping takes its IOVA meanwhile, and
    /// let go ([`Self::release_interrupt_file`]) when the mapping fails.
    /// Returns whether the page is newly held; `false` when the device holds
    /// it already, so its domain maps it already.
    ///
    /// # Errors
    /// [`MapError::UnknownDevice`] for an unregistered badge;
    /// [`MapError::InvalidRequest`] for an unconfined device or a `file` not
    /// page-aligned; [`MapError::AddressInUse`] when the page overlaps a
    /// mapping or a firmware-reserved range of the device;
    /// [`MapError::OutOfMemory`] when the table cannot grow. Nothing is held
    /// on any error.
    pub fn hold_interrupt_file(&mut self, badge: u64, file: u64) -> Result<bool, MapError>
    {
        let device = self.device_mut(badge).ok_or(MapError::UnknownDevice)?;
        if device.confinement == Confinement::Unconfined || !file.is_multiple_of(PAGE_SIZE)
        {
            return Err(MapError::InvalidRequest);
        }
        let page = ReservedRange {
            base: file,
            len: PAGE_SIZE,
        };
        if device.files().contains(&page)
        {
            return Ok(false);
        }
        if device.reserved.iter().any(|r| r.overlaps(file, PAGE_SIZE))
            || device
                .entries
                .iter()
                .any(|e| e.mapping.overlaps(file, PAGE_SIZE))
        {
            return Err(MapError::AddressInUse);
        }
        device
            .reserved
            .try_reserve(1)
            .map_err(|_| MapError::OutOfMemory)?;
        device.reserved.push(page);
        Ok(true)
    }

    /// Let go of the interrupt file's page at `file` the device `badge` holds
    /// ([`Self::hold_interrupt_file`]), its mapping having failed; nothing
    /// for an unregistered badge or a page it does not hold.
    pub fn release_interrupt_file(&mut self, badge: u64, file: u64)
    {
        let page = ReservedRange {
            base: file,
            len: PAGE_SIZE,
        };
        if let Some(d) = self.device_mut(badge)
            && let Some(at) = d.files().iter().position(|r| *r == page)
            && let Some(held) = d.firmware.checked_add(at)
        {
            d.reserved.remove(held);
        }
    }

    /// Remove the device `badge`, so its driver's later requests are refused,
    /// and return its confinement and the mappings that stood. A pending or
    /// unmapping mapping is not returned: its cap stays with the thread whose
    /// IOMMU call is in flight, which finds the device gone. `None` for an
    /// unregistered badge.
    pub fn withdraw(&mut self, badge: u64) -> Option<Withdrawn>
    {
        let idx = self.devices.iter().position(|d| d.badge == badge)?;
        let device = self.devices.swap_remove(idx);
        let mappings = device
            .entries
            .into_iter()
            .filter(|e| e.state == State::Standing)
            .map(|e| e.mapping)
            .collect();
        Some(Withdrawn {
            confinement: device.confinement,
            mappings,
        })
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::devmgr_dma_labels::ACCESS_DEVICE_READ;

    #[test]
    fn a_withdrawal_keeps_the_mapping_caps_of_a_device_neither_blocked_nor_stopped()
    {
        let mut stopped = false;
        assert_eq!(
            settle_withdrawal(IommuBlock::NotBlocked, || {
                stopped = true;
                false
            }),
            WithdrawnMappings::Quarantine
        );
        assert!(stopped, "the stop runs before the caps are settled");
    }

    #[test]
    fn an_unblocked_device_confirmed_stopped_releases_its_mapping_caps()
    {
        assert_eq!(
            settle_withdrawal(IommuBlock::NotBlocked, || true),
            WithdrawnMappings::Release
        );
    }

    #[test]
    fn a_blocked_device_releases_its_mapping_caps_and_is_still_stopped()
    {
        let mut stopped = false;
        assert_eq!(
            settle_withdrawal(IommuBlock::Blocked, || {
                stopped = true;
                false
            }),
            WithdrawnMappings::Release
        );
        assert!(
            stopped,
            "a blocked device is stopped and reset all the same"
        );
    }

    const RW: u64 = ACCESS_DEVICE_READ | ACCESS_DEVICE_WRITE;
    const DOMAIN: Confinement = Confinement::Domain {
        handle: 3,
        limit: IOVA_BASE + 4 * PAGE_SIZE,
        interrupt_range: false,
    };

    fn table_with(badge: u64, confinement: Confinement) -> DmaTable
    {
        let mut t = DmaTable::new();
        t.register(badge, confinement, &[]).unwrap();
        t
    }

    /// Reserve and commit an unconfined mapping at `addr`.
    fn map_at(t: &mut DmaTable, badge: u64, addr: u64, len: u64) -> Result<Mapping, MapError>
    {
        let m = t.reserve(badge, addr >> 12, len, RW, Some(addr))?;
        assert!(t.commit(badge, m.device_addr));
        Ok(m)
    }

    /// Reserve and commit a confined mapping; its IOVA.
    fn map_iova(t: &mut DmaTable, badge: u64, len: u64) -> Result<u64, MapError>
    {
        let m = t.reserve(badge, 1, len, RW, None)?;
        assert!(t.commit(badge, m.device_addr));
        Ok(m.device_addr)
    }

    fn unmap(t: &mut DmaTable, badge: u64, addr: u64) -> Result<Mapping, UnmapError>
    {
        let (m, _) = t.begin_unmap(badge, addr)?;
        t.finish_unmap(badge, addr);
        Ok(m)
    }

    #[test]
    fn a_device_that_writes_needs_the_write_right()
    {
        assert_eq!(check_access(ACCESS_DEVICE_READ, RIGHTS_MEM_MAP), Ok(()));
        assert_eq!(check_access(RW, RIGHTS_MEM_MAP | RIGHTS_MEM_WRITE), Ok(()));
        assert_eq!(
            check_access(ACCESS_DEVICE_WRITE, RIGHTS_MEM_MAP),
            Err(MapError::InsufficientRights)
        );
        assert_eq!(
            check_access(ACCESS_DEVICE_READ, RIGHTS_MEM_WRITE),
            Err(MapError::InsufficientRights)
        );
    }

    #[test]
    fn an_access_word_of_no_or_unknown_bits_is_refused()
    {
        let all = RIGHTS_MEM_MAP | RIGHTS_MEM_WRITE;
        assert_eq!(check_access(0, all), Err(MapError::InvalidRequest));
        assert_eq!(
            check_access(RW | 1 << 2, all),
            Err(MapError::InvalidRequest)
        );
    }

    #[test]
    fn an_unconfined_mapping_sits_at_its_physical_address_until_its_unmap()
    {
        let mut t = table_with(7, Confinement::Unconfined);
        let m = map_at(&mut t, 7, 0x8000, 0x2000).unwrap();
        assert_eq!(m.device_addr, 0x8000);
        assert_eq!(unmap(&mut t, 7, 0x8000), Ok(m));
        assert_eq!(unmap(&mut t, 7, 0x8000), Err(UnmapError::NoMapping));
    }

    #[test]
    fn an_unconfined_mapping_without_its_physical_address_is_refused()
    {
        let mut t = table_with(7, Confinement::Unconfined);
        assert_eq!(
            t.reserve(7, 1, PAGE_SIZE, RW, None),
            Err(MapError::InvalidRequest)
        );
    }

    #[test]
    fn confined_mappings_take_the_lowest_free_iovas_from_the_base()
    {
        let mut t = table_with(7, DOMAIN);
        assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(IOVA_BASE));
        assert_eq!(
            map_iova(&mut t, 7, 2 * PAGE_SIZE),
            Ok(IOVA_BASE + PAGE_SIZE)
        );
        unmap(&mut t, 7, IOVA_BASE).unwrap();
        // The freed first page is taken again by a mapping that fits it.
        assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(IOVA_BASE));
        assert_eq!(
            map_iova(&mut t, 7, PAGE_SIZE),
            Ok(IOVA_BASE + 3 * PAGE_SIZE)
        );
    }

    #[test]
    fn a_confined_mapping_past_the_device_iova_limit_is_refused()
    {
        let mut t = table_with(7, DOMAIN);
        assert_eq!(
            map_iova(&mut t, 7, 5 * PAGE_SIZE),
            Err(MapError::NoAddressSpace)
        );
        assert_eq!(map_iova(&mut t, 7, 4 * PAGE_SIZE), Ok(IOVA_BASE));
        assert_eq!(
            map_iova(&mut t, 7, PAGE_SIZE),
            Err(MapError::NoAddressSpace)
        );
    }

    #[test]
    fn a_pending_mapping_holds_its_iovas_until_it_is_aborted()
    {
        let mut t = table_with(7, DOMAIN);
        let pending = t.reserve(7, 1, PAGE_SIZE, RW, None).unwrap();
        assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(IOVA_BASE + PAGE_SIZE));
        t.abort(7, pending.device_addr);
        assert!(!t.commit(7, pending.device_addr));
        assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(IOVA_BASE));
    }

    #[test]
    fn a_pending_mapping_cannot_be_unmapped()
    {
        let mut t = table_with(7, DOMAIN);
        let pending = t.reserve(7, 1, PAGE_SIZE, RW, None).unwrap();
        assert_eq!(
            t.begin_unmap(7, pending.device_addr),
            Err(UnmapError::NoMapping)
        );
    }

    #[test]
    fn a_failed_unmap_restores_the_mapping()
    {
        let mut t = table_with(7, DOMAIN);
        let iova = map_iova(&mut t, 7, PAGE_SIZE).unwrap();
        let (_, confinement) = t.begin_unmap(7, iova).unwrap();
        assert_eq!(confinement, DOMAIN);
        assert_eq!(t.begin_unmap(7, iova), Err(UnmapError::NoMapping));
        assert!(t.restore(7, iova));
        assert!(unmap(&mut t, 7, iova).is_ok());
    }

    #[test]
    fn a_withdrawal_mid_call_leaves_the_in_flight_mapping_to_its_caller()
    {
        let mut t = table_with(7, DOMAIN);
        let standing = map_iova(&mut t, 7, PAGE_SIZE).unwrap();
        let unmapping = map_iova(&mut t, 7, PAGE_SIZE).unwrap();
        t.begin_unmap(7, unmapping).unwrap();
        let pending = t.reserve(7, 9, PAGE_SIZE, RW, None).unwrap();
        let w = t.withdraw(7).unwrap();
        assert_eq!(w.confinement, DOMAIN);
        assert_eq!(
            w.mappings.iter().map(|m| m.device_addr).collect::<Vec<_>>(),
            [standing]
        );
        assert!(!t.commit(7, pending.device_addr));
        assert!(!t.restore(7, unmapping));
    }

    #[test]
    fn an_unregistered_device_is_refused_every_request()
    {
        let mut t = table_with(7, Confinement::Unconfined);
        assert_eq!(
            t.reserve(8, 1, PAGE_SIZE, RW, Some(0x1000)),
            Err(MapError::UnknownDevice)
        );
        assert_eq!(t.begin_unmap(8, 0x1000), Err(UnmapError::UnknownDevice));
        assert_eq!(t.withdraw(8), None);
        assert_eq!(t.confinement(8), None);
    }

    #[test]
    fn overlapping_unconfined_ranges_are_refused_and_adjacent_ones_accepted()
    {
        let mut t = table_with(7, Confinement::Unconfined);
        map_at(&mut t, 7, 0x2000, 0x2000).unwrap();
        assert_eq!(
            map_at(&mut t, 7, 0x3000, 0x1000),
            Err(MapError::AddressInUse)
        );
        assert_eq!(
            map_at(&mut t, 7, 0x1000, 0x1001),
            Err(MapError::AddressInUse)
        );
        map_at(&mut t, 7, 0x1000, 0x1000).unwrap();
        map_at(&mut t, 7, 0x4000, 0x1000).unwrap();
    }

    #[test]
    fn devices_do_not_share_an_address_space()
    {
        let mut t = table_with(7, DOMAIN);
        t.register(8, DOMAIN, &[]).unwrap();
        assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(IOVA_BASE));
        assert_eq!(map_iova(&mut t, 8, PAGE_SIZE), Ok(IOVA_BASE));
    }

    #[test]
    fn an_empty_wrapping_or_accessless_mapping_is_refused()
    {
        let mut t = table_with(7, Confinement::Unconfined);
        assert_eq!(
            t.reserve(7, 1, 0, RW, Some(0x1000)),
            Err(MapError::InvalidRequest)
        );
        assert_eq!(
            t.reserve(7, 1, 0x1000, RW, Some(u64::MAX - 0xFFF)),
            Err(MapError::InvalidRequest)
        );
        assert_eq!(
            t.reserve(7, 1, 0x1000, 0, Some(0x1000)),
            Err(MapError::InvalidRequest)
        );
    }

    #[test]
    fn a_device_holds_at_most_its_bound_of_mappings()
    {
        let mut t = table_with(7, Confinement::Unconfined);
        for i in 0..MAX_MAPPINGS_PER_DEVICE as u64
        {
            map_at(&mut t, 7, i * 0x1000, 0x1000).unwrap();
        }
        let next = MAX_MAPPINGS_PER_DEVICE as u64 * 0x1000;
        assert_eq!(map_at(&mut t, 7, next, 0x1000), Err(MapError::TooMany));
        unmap(&mut t, 7, 0).unwrap();
        map_at(&mut t, 7, next, 0x1000).unwrap();
    }

    #[test]
    fn registering_a_registered_device_keeps_its_mappings_and_confinement()
    {
        let mut t = table_with(7, DOMAIN);
        let iova = map_iova(&mut t, 7, PAGE_SIZE).unwrap();
        t.register(7, Confinement::Unconfined, &[]).unwrap();
        assert_eq!(t.confinement(7), Some(DOMAIN));
        assert!(unmap(&mut t, 7, iova).is_ok());
    }

    const fn rr(base: u64, len: u64) -> ReservedRange
    {
        ReservedRange { base, len }
    }

    #[test]
    fn reserved_regions_are_rounded_out_to_pages_merged_and_sorted()
    {
        let regions = [
            (0x7c00_0000, 0x7c0f_ffff),
            // Inside the first page and its last byte: one page.
            (0x000e_8100, 0x000e_8eff),
            // Abuts the first region: merged with it.
            (0x7c10_0000, 0x7c10_0fff),
            // Overlaps the region above it.
            (0x7c0f_f800, 0x7c10_07ff),
        ];
        assert_eq!(
            reserved_ranges(&regions, &[], 39),
            Ok(vec![rr(0x000e_8000, PAGE_SIZE), rr(0x7c00_0000, 0x10_1000)])
        );
    }

    #[test]
    fn a_reserved_region_overlapping_pooled_memory_is_refused()
    {
        let pooled = [(0x10_0000, 0x7bf0_0000), (0x1_0000_0000, 0x4000_0000)];
        // Ends right below the pooled extent: accepted.
        assert_eq!(
            reserved_ranges(&[(0x000e_8000, 0x000e_8fff)], &pooled, 39),
            Ok(vec![rr(0x000e_8000, PAGE_SIZE)])
        );
        // Starts right past the first extent: accepted.
        assert!(reserved_ranges(&[(0x7c00_0000, 0x7c0f_ffff)], &pooled, 39).is_ok());
        // Its rounded first page reaches into the pooled extent's last page.
        assert_eq!(
            reserved_ranges(&[(0x7bff_f800, 0x7c00_0fff)], &pooled, 39),
            Err(ReservedError::Pooled(rr(0x7bff_f000, 0x2000)))
        );
        assert_eq!(
            reserved_ranges(&[(0x1_2000_0000, 0x1_2000_0fff)], &pooled, 39),
            Err(ReservedError::Pooled(rr(0x1_2000_0000, PAGE_SIZE)))
        );
    }

    #[test]
    fn a_reserved_region_past_the_units_width_or_the_address_space_is_refused()
    {
        let width_end = 1u64 << 39;
        assert_eq!(
            reserved_ranges(&[(width_end - PAGE_SIZE, width_end - 1)], &[], 39),
            Ok(vec![rr(width_end - PAGE_SIZE, PAGE_SIZE)])
        );
        assert_eq!(
            reserved_ranges(&[(width_end - PAGE_SIZE, width_end)], &[], 39),
            Err(ReservedError::PastWidth {
                base: width_end - PAGE_SIZE,
                last: width_end
            })
        );
        assert_eq!(
            reserved_ranges(&[(u64::MAX - 0xff, u64::MAX)], &[], 64),
            Err(ReservedError::PastWidth {
                base: u64::MAX - 0xff,
                last: u64::MAX
            })
        );
        assert_eq!(
            reserved_ranges(&[(0x2000, 0x1000)], &[], 39),
            Err(ReservedError::PastWidth {
                base: 0x2000,
                last: 0x1000
            })
        );
    }

    #[test]
    fn a_device_holds_at_most_its_bound_of_reserved_ranges()
    {
        let regions: Vec<_> = (0..=MAX_RESERVED_RANGES_PER_DEVICE as u64)
            .map(|i| (i * 0x10_0000, i * 0x10_0000 + 0xfff))
            .collect();
        assert_eq!(
            reserved_ranges(&regions, &[], 39),
            Err(ReservedError::TooMany)
        );
        assert_eq!(
            reserved_ranges(&regions[1..], &[], 39).map(|r| r.len()),
            Ok(MAX_RESERVED_RANGES_PER_DEVICE)
        );
    }

    #[test]
    fn no_confined_mapping_takes_an_iova_of_a_reserved_range()
    {
        let mut t = DmaTable::new();
        // The second page of the device's space, and one below IOVA_BASE.
        let reserved = [
            rr(IOVA_BASE + PAGE_SIZE, PAGE_SIZE),
            rr(0xe_8000, PAGE_SIZE),
        ];
        t.register(7, DOMAIN, &reserved).unwrap();
        assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(IOVA_BASE));
        // Two pages fit only past the reserved page.
        assert_eq!(
            map_iova(&mut t, 7, 2 * PAGE_SIZE),
            Ok(IOVA_BASE + 2 * PAGE_SIZE)
        );
        assert_eq!(
            map_iova(&mut t, 7, PAGE_SIZE),
            Err(MapError::NoAddressSpace)
        );
        // A withdrawal hands back the mappings alone: the reserved ranges
        // carry no cap.
        let w = t.withdraw(7).unwrap();
        assert_eq!(w.mappings.len(), 2);
    }

    #[test]
    fn a_held_interrupt_file_takes_no_mapping_iova_and_is_held_once()
    {
        let mut t = DmaTable::new();
        t.register(7, DOMAIN, &[rr(IOVA_BASE + 3 * PAGE_SIZE, PAGE_SIZE)])
            .unwrap();
        let file = IOVA_BASE + PAGE_SIZE;
        assert_eq!(t.hold_interrupt_file(7, file), Ok(true));
        // A second vector on the same file needs no second mapping.
        assert_eq!(t.hold_interrupt_file(7, file), Ok(false));
        assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(IOVA_BASE));
        assert_eq!(
            map_iova(&mut t, 7, PAGE_SIZE),
            Ok(IOVA_BASE + 2 * PAGE_SIZE)
        );
        // A file on a mapping or a firmware-reserved range, the very page
        // included, is refused.
        assert_eq!(
            t.hold_interrupt_file(7, IOVA_BASE),
            Err(MapError::AddressInUse)
        );
        assert_eq!(
            t.hold_interrupt_file(7, IOVA_BASE + 3 * PAGE_SIZE),
            Err(MapError::AddressInUse)
        );
        // Letting go of a firmware-reserved page lets go of nothing.
        t.release_interrupt_file(7, IOVA_BASE + 3 * PAGE_SIZE);
        assert_eq!(
            t.hold_interrupt_file(7, IOVA_BASE + 3 * PAGE_SIZE),
            Err(MapError::AddressInUse)
        );
        // A file let go of frees its IOVA again.
        t.release_interrupt_file(7, file);
        assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(file));
    }

    #[test]
    fn an_interrupt_file_is_held_only_for_a_confined_registered_device_and_a_page()
    {
        let mut t = table_with(7, Confinement::Unconfined);
        t.register(8, DOMAIN, &[]).unwrap();
        assert_eq!(
            t.hold_interrupt_file(7, 0x2800_0000),
            Err(MapError::InvalidRequest)
        );
        assert_eq!(
            t.hold_interrupt_file(8, 0x2800_0004),
            Err(MapError::InvalidRequest)
        );
        assert_eq!(
            t.hold_interrupt_file(9, 0x2800_0000),
            Err(MapError::UnknownDevice)
        );
    }

    #[test]
    fn a_device_behind_vtd_is_given_no_iova_in_the_interrupt_range()
    {
        let vtd = Confinement::Domain {
            handle: 3,
            limit: 1 << 32,
            interrupt_range: true,
        };
        let below = INTERRUPT_RANGE.start - PAGE_SIZE;
        for (confinement, two_pages, one_page) in [
            // Two pages do not fit below the range, so they go past it, and
            // the page below it, ending at its first byte, is given after.
            (vtd, INTERRUPT_RANGE.end, below),
            // A unit that translates the range gives it out as any other.
            (DOMAIN_4G, below, below + 2 * PAGE_SIZE),
        ]
        {
            let mut t = table_with(7, confinement);
            // Fill the space up to one page below the range.
            assert_eq!(map_iova(&mut t, 7, below - IOVA_BASE), Ok(IOVA_BASE));
            assert_eq!(map_iova(&mut t, 7, 2 * PAGE_SIZE), Ok(two_pages));
            assert_eq!(map_iova(&mut t, 7, PAGE_SIZE), Ok(one_page));
        }
        // A mapping that would straddle the range is placed past it.
        let mut t = table_with(7, vtd);
        map_iova(&mut t, 7, INTERRUPT_RANGE.start - 2 * PAGE_SIZE - IOVA_BASE).unwrap();
        assert_eq!(map_iova(&mut t, 7, 4 * PAGE_SIZE), Ok(INTERRUPT_RANGE.end));
    }

    const DOMAIN_4G: Confinement = Confinement::Domain {
        handle: 3,
        limit: 1 << 32,
        interrupt_range: false,
    };

    #[test]
    fn the_iova_limit_is_the_smaller_of_the_unit_and_device_widths()
    {
        assert_eq!(iova_limit(48, None), 1 << 48);
        assert_eq!(iova_limit(48, Some(28)), 1 << 28);
        assert_eq!(iova_limit(20, Some(28)), 1 << 20);
        assert_eq!(iova_limit(48, Some(64)), 1 << 48);
        assert_eq!(iova_limit(64, None), u64::MAX);
        assert_eq!(iova_limit(64, Some(64)), u64::MAX);
    }
}
