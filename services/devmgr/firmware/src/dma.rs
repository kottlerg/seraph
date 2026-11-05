// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/dma.rs

//! The DMA mappings devmgr keeps for each DMA-capable device, and the check
//! of a `DMA_MAP` request's access against the rights of the Memory cap it
//! carries.
//!
//! devmgr registers a device when it gives the device's driver its DMA
//! capability, records each mapping a `DMA_MAP` makes at the device address
//! devmgr chose for it, with the Memory cap the request moved in, removes
//! one at its `DMA_UNMAP`, and removes the device with every mapping it holds
//! when it withdraws the driver; each removal returns the mappings, whose
//! caps devmgr then deletes. A device
//! holds at most [`MAX_MAPPINGS_PER_DEVICE`] mappings, and no two of a
//! device's mappings overlap in device-address space. The table never reads
//! or writes IOMMU state: when an IOMMU confines the device, devmgr has the
//! IOMMU driver install what the table accepts and withdraw what it returns.
//! See
//! `docs/device-management.md` § DMA Authorisation.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use ipc::devmgr_dma_labels::{ACCESS_DEVICE_WRITE, ACCESS_MASK};
use syscall_abi::{RIGHTS_MEM_MAP, RIGHTS_MEM_WRITE};

/// Mappings one device holds at once.
///
/// A device's driver maps its own rings and buffers once at setup and, for a
/// block device, the one client-lent buffer of its single in-flight request
/// (`services/drivers/virtio/blk/README.md`): three for virtio-blk, two for
/// virtio-input. Sixteen leaves room for a multi-queue device without
/// letting one driver grow devmgr's table without bound; `docs/limits.md`
/// classifies it.
pub const MAX_MAPPINGS_PER_DEVICE: usize = 16;

/// One mapping of a device: `len` bytes of physically contiguous frames at
/// `phys`, reachable by the device at `device_addr` with `access`, and the
/// slot of the Memory cap over them that devmgr keeps while the mapping
/// stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping
{
    /// devmgr's slot of the mapped Memory cap, deleted when the mapping is
    /// removed.
    pub cap: u64,
    /// The device address of the first byte, the one `DMA_MAP` returned.
    pub device_addr: u64,
    /// The physical address of the first byte. Equal to `device_addr` while
    /// no IOMMU is programmed, and read by nothing until one is: it is what
    /// the IOMMU driver writes into the device's translation tables for
    /// `device_addr`.
    pub phys: u64,
    /// Bytes mapped; nonzero.
    pub len: u64,
    /// `ACCESS_DEVICE_READ` and/or [`ACCESS_DEVICE_WRITE`]
    /// (`ipc::devmgr_dma_labels`).
    pub access: u64,
}

impl Mapping
{
    /// Whether the device-address ranges of `self` and `other` share a byte.
    fn overlaps(&self, other: &Mapping) -> bool
    {
        self.device_addr < other.device_addr + other.len
            && other.device_addr < self.device_addr + self.len
    }
}

/// Why a mapping was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError
{
    /// The badge names no registered device.
    UnknownDevice,
    /// The access word is zero or sets an unknown bit, or the mapping is
    /// empty or runs past the end of the address space.
    InvalidRequest,
    /// The cap lacks the rights the access needs ([`required_rights`]).
    InsufficientRights,
    /// The device already holds [`MAX_MAPPINGS_PER_DEVICE`] mappings.
    TooMany,
    /// The device-address range overlaps another mapping of the device.
    AddressInUse,
    /// The table could not grow.
    OutOfMemory,
}

/// Why an unmap was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmapError
{
    /// The badge names no registered device.
    UnknownDevice,
    /// No mapping of the device starts at the address.
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

/// A registered device and the mappings it holds.
struct Device
{
    badge: u64,
    mappings: Vec<Mapping>,
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

    /// Register the device `badge` with no mappings, so its driver's
    /// requests are served. Registering a registered badge changes nothing.
    ///
    /// # Errors
    /// The allocation error when the table cannot grow; nothing is
    /// registered then.
    pub fn register(&mut self, badge: u64) -> Result<(), TryReserveError>
    {
        if self.device_mut(badge).is_some()
        {
            return Ok(());
        }
        self.devices.try_reserve(1)?;
        self.devices.push(Device {
            badge,
            mappings: Vec::new(),
        });
        Ok(())
    }

    /// Record `mapping` for the device `badge`.
    ///
    /// # Errors
    /// [`MapError::UnknownDevice`] for an unregistered badge;
    /// [`MapError::InvalidRequest`] for an access word [`required_rights`]
    /// refuses, an empty mapping, or one past the end of the address space;
    /// [`MapError::TooMany`] when the device holds its bound;
    /// [`MapError::AddressInUse`] when the range overlaps another mapping of
    /// the device; [`MapError::OutOfMemory`] when the table cannot grow.
    /// Nothing is recorded on any error.
    pub fn map(&mut self, badge: u64, mapping: Mapping) -> Result<(), MapError>
    {
        let device = self.device_mut(badge).ok_or(MapError::UnknownDevice)?;
        if required_rights(mapping.access).is_none()
            || mapping.len == 0
            || mapping.device_addr.checked_add(mapping.len).is_none()
        {
            return Err(MapError::InvalidRequest);
        }
        if device.mappings.len() >= MAX_MAPPINGS_PER_DEVICE
        {
            return Err(MapError::TooMany);
        }
        if device.mappings.iter().any(|m| m.overlaps(&mapping))
        {
            return Err(MapError::AddressInUse);
        }
        device
            .mappings
            .try_reserve(1)
            .map_err(|_| MapError::OutOfMemory)?;
        device.mappings.push(mapping);
        Ok(())
    }

    /// Remove and return the mapping of the device `badge` that starts at
    /// `device_addr`.
    ///
    /// # Errors
    /// [`UnmapError::UnknownDevice`] for an unregistered badge, and
    /// [`UnmapError::NoMapping`] when no mapping of the device starts there.
    pub fn unmap(&mut self, badge: u64, device_addr: u64) -> Result<Mapping, UnmapError>
    {
        let device = self.device_mut(badge).ok_or(UnmapError::UnknownDevice)?;
        let idx = device
            .mappings
            .iter()
            .position(|m| m.device_addr == device_addr)
            .ok_or(UnmapError::NoMapping)?;
        Ok(device.mappings.swap_remove(idx))
    }

    /// Remove the device `badge`, so its driver's later requests are refused,
    /// and return the mappings it held. `None` for an unregistered badge.
    pub fn withdraw(&mut self, badge: u64) -> Option<Vec<Mapping>>
    {
        let idx = self.devices.iter().position(|d| d.badge == badge)?;
        Some(self.devices.swap_remove(idx).mappings)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::devmgr_dma_labels::ACCESS_DEVICE_READ;

    const RW: u64 = ACCESS_DEVICE_READ | ACCESS_DEVICE_WRITE;

    fn mapping(device_addr: u64, len: u64) -> Mapping
    {
        Mapping {
            cap: device_addr >> 12,
            device_addr,
            phys: device_addr,
            len,
            access: RW,
        }
    }

    fn table_with(badge: u64) -> DmaTable
    {
        let mut t = DmaTable::new();
        t.register(badge).unwrap();
        t
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
    fn a_mapping_is_recorded_until_its_unmap_returns_it()
    {
        let mut t = table_with(7);
        t.map(7, mapping(0x1000, 0x2000)).unwrap();
        assert_eq!(t.unmap(7, 0x1000), Ok(mapping(0x1000, 0x2000)));
        assert_eq!(t.unmap(7, 0x1000), Err(UnmapError::NoMapping));
    }

    #[test]
    fn an_unregistered_device_is_refused_every_request()
    {
        let mut t = table_with(7);
        assert_eq!(
            t.map(8, mapping(0x1000, 0x1000)),
            Err(MapError::UnknownDevice)
        );
        assert_eq!(t.unmap(8, 0x1000), Err(UnmapError::UnknownDevice));
        assert_eq!(t.withdraw(8), None);
    }

    #[test]
    fn overlapping_ranges_of_one_device_are_refused_and_adjacent_ones_accepted()
    {
        let mut t = table_with(7);
        t.map(7, mapping(0x2000, 0x2000)).unwrap();
        assert_eq!(
            t.map(7, mapping(0x3000, 0x1000)),
            Err(MapError::AddressInUse)
        );
        assert_eq!(
            t.map(7, mapping(0x1000, 0x1001)),
            Err(MapError::AddressInUse)
        );
        t.map(7, mapping(0x1000, 0x1000)).unwrap();
        t.map(7, mapping(0x4000, 0x1000)).unwrap();
    }

    #[test]
    fn devices_do_not_share_an_address_space()
    {
        let mut t = table_with(7);
        t.register(8).unwrap();
        t.map(7, mapping(0x1000, 0x1000)).unwrap();
        t.map(8, mapping(0x1000, 0x1000)).unwrap();
        assert_eq!(t.unmap(8, 0x1000), Ok(mapping(0x1000, 0x1000)));
        assert_eq!(t.unmap(7, 0x1000), Ok(mapping(0x1000, 0x1000)));
    }

    #[test]
    fn an_empty_or_wrapping_or_accessless_mapping_is_refused()
    {
        let mut t = table_with(7);
        assert_eq!(t.map(7, mapping(0x1000, 0)), Err(MapError::InvalidRequest));
        assert_eq!(
            t.map(7, mapping(u64::MAX - 0xFFF, 0x1000)),
            Err(MapError::InvalidRequest)
        );
        let mut none = mapping(0x1000, 0x1000);
        none.access = 0;
        assert_eq!(t.map(7, none), Err(MapError::InvalidRequest));
    }

    #[test]
    fn a_device_holds_at_most_its_bound_of_mappings()
    {
        let mut t = table_with(7);
        for i in 0..MAX_MAPPINGS_PER_DEVICE as u64
        {
            t.map(7, mapping(i * 0x1000, 0x1000)).unwrap();
        }
        let next = MAX_MAPPINGS_PER_DEVICE as u64 * 0x1000;
        assert_eq!(t.map(7, mapping(next, 0x1000)), Err(MapError::TooMany));
        t.unmap(7, 0).unwrap();
        t.map(7, mapping(next, 0x1000)).unwrap();
    }

    #[test]
    fn withdrawing_a_device_returns_its_mappings_and_refuses_its_later_requests()
    {
        let mut t = table_with(7);
        t.map(7, mapping(0x1000, 0x1000)).unwrap();
        t.map(7, mapping(0x8000, 0x2000)).unwrap();
        let mut held = t.withdraw(7).unwrap();
        held.sort_by_key(|m| m.device_addr);
        assert_eq!(held, [mapping(0x1000, 0x1000), mapping(0x8000, 0x2000)]);
        assert_eq!(
            t.map(7, mapping(0x1000, 0x1000)),
            Err(MapError::UnknownDevice)
        );
    }

    #[test]
    fn registering_a_registered_device_keeps_its_mappings()
    {
        let mut t = table_with(7);
        t.map(7, mapping(0x1000, 0x1000)).unwrap();
        t.register(7).unwrap();
        assert_eq!(t.unmap(7, 0x1000), Ok(mapping(0x1000, 0x1000)));
    }
}
