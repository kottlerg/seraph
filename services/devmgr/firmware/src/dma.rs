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
//! overlap in device-address space. The table never reads or writes IOMMU
//! state. See `docs/device-management.md` § DMA Authorisation.

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

/// The lowest IOVA devmgr gives a confined device. The first MiB of every
/// domain stays unmapped, so a device programmed with a small stray address
/// (a zero or an offset taken for an address) faults instead of reaching a
/// mapping.
pub const IOVA_BASE: u64 = 0x10_0000;

/// The IOVA limit of a device whose DMA reaches only 28 address bits:
/// QEMU's `edu` test device (PCI `1234:11e8`), whose default DMA mask is 28
/// bits.
pub const EDU_IOVA_LIMIT: u64 = 1 << 28;

/// PCI vendor and device ID of QEMU's `edu` test device.
pub const EDU_ID: (u16, u16) = (0x1234, 0x11e8);

/// The end of the IOVA space devmgr allocates a confined device's mappings
/// in: the smaller of what its unit translates (`width_bits`, from the IOMMU
/// driver's `QUERY_UNIT`) and what the device can address
/// ([`EDU_IOVA_LIMIT`] for the `edu` device; no limit of its own for every
/// other device).
#[must_use]
pub fn iova_limit(width_bits: u8, vendor: u16, device: u16) -> u64
{
    let unit = 1u64.checked_shl(u32::from(width_bits)).unwrap_or(u64::MAX);
    if (vendor, device) == EDU_ID
    {
        unit.min(EDU_IOVA_LIMIT)
    }
    else
    {
        unit
    }
}

/// How a registered device reaches its frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confinement
{
    /// No IOMMU translates the device: a mapping's device address is the
    /// frames' physical address.
    Unconfined,
    /// The IOMMU driver confines the device in the domain `handle`; devmgr
    /// allocates its IOVAs in `[IOVA_BASE, limit)`.
    Domain
    {
        /// The domain handle the IOMMU driver's `ATTACH` returned.
        handle: u64,
        /// The end of the device's IOVA space ([`iova_limit`]).
        limit: u64,
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
        self.device_addr < addr + len && addr < self.device_addr + self.len
    }
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

/// A registered device, its confinement, and its mappings.
struct Device
{
    badge: u64,
    confinement: Confinement,
    entries: Vec<Entry>,
}

impl Device
{
    fn entry(&mut self, device_addr: u64, state: State) -> Option<&mut Entry>
    {
        self.entries
            .iter_mut()
            .find(|e| e.mapping.device_addr == device_addr && e.state == state)
    }

    /// The lowest page-aligned address in `[IOVA_BASE, limit)` where `len`
    /// bytes overlap none of the device's mappings.
    fn free_iova(&self, len: u64, limit: u64) -> Option<u64>
    {
        let len = len.checked_next_multiple_of(PAGE_SIZE)?;
        let mut start = IOVA_BASE;
        while let Some(clash) = self.entries.iter().find(|e| e.mapping.overlaps(start, len))
        {
            start = (clash.mapping.device_addr + clash.mapping.len)
                .checked_next_multiple_of(PAGE_SIZE)?;
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

/// Settle the withdrawal of a device whose DMA grant was withdrawn, `blocked`
/// telling whether the IOMMU now blocks it: run `stop`, devmgr's stop of the
/// device (Bus Master Enable cleared, its driver's BAR copies revoked, the
/// device reset), which reports whether every step confirmed, whatever
/// `blocked` is. Returns whether the device can no longer reach its driver's
/// frames, blocked or confirmed stopped, and what becomes of the mappings'
/// caps: deleted only then, else kept (`docs/device-management.md`
/// § DMA-Safe Teardown).
pub fn settle_withdrawal(blocked: bool, stop: impl FnOnce() -> bool) -> (bool, WithdrawnMappings)
{
    let stopped = stop();
    if blocked || stopped
    {
        (true, WithdrawnMappings::Release)
    }
    else
    {
        (false, WithdrawnMappings::Quarantine)
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

    /// Register the device `badge` with no mappings and `confinement`, so its
    /// driver's requests are served. Registering a registered badge changes
    /// nothing.
    ///
    /// # Errors
    /// The allocation error when the table cannot grow; nothing is
    /// registered then.
    pub fn register(&mut self, badge: u64, confinement: Confinement)
    -> Result<(), TryReserveError>
    {
        if self.device_mut(badge).is_some()
        {
            return Ok(());
        }
        self.devices.try_reserve(1)?;
        self.devices.push(Device {
            badge,
            confinement,
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
    /// free IOVA of the device's space for a confined one (`phys` unused).
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
            Confinement::Domain { limit, .. } => device
                .free_iova(len, limit)
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
            settle_withdrawal(false, || {
                stopped = true;
                false
            }),
            (false, WithdrawnMappings::Quarantine)
        );
        assert!(stopped, "the stop runs before the caps are settled");
        assert_eq!(
            settle_withdrawal(false, || true),
            (true, WithdrawnMappings::Release)
        );
    }

    #[test]
    fn a_blocked_device_releases_its_mapping_caps_and_is_still_stopped()
    {
        let mut stopped = false;
        assert_eq!(
            settle_withdrawal(true, || {
                stopped = true;
                false
            }),
            (true, WithdrawnMappings::Release)
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
    };

    fn table_with(badge: u64, confinement: Confinement) -> DmaTable
    {
        let mut t = DmaTable::new();
        t.register(badge, confinement).unwrap();
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
        t.register(8, DOMAIN).unwrap();
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
        t.register(7, Confinement::Unconfined).unwrap();
        assert_eq!(t.confinement(7), Some(DOMAIN));
        assert!(unmap(&mut t, 7, iova).is_ok());
    }

    #[test]
    fn the_iova_limit_is_the_unit_width_narrowed_for_the_edu_device()
    {
        assert_eq!(iova_limit(48, 0x1af4, 0x1042), 1 << 48);
        assert_eq!(iova_limit(48, EDU_ID.0, EDU_ID.1), EDU_IOVA_LIMIT);
        assert_eq!(iova_limit(20, EDU_ID.0, EDU_ID.1), 1 << 20);
        assert_eq!(iova_limit(64, 0, 0), u64::MAX);
    }
}
