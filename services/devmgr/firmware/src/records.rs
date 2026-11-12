// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/records.rs

//! The platform device records: every device the firmware describes other
//! than a PCI function, with its identity keys and its typed resources
//! ([docs/driver-binding.md](../../../../docs/driver-binding.md) § Device
//! Records).
//!
//! devmgr's enumerators (the boot framebuffer, the ACPI namespace, the SPCR,
//! and the platform description table) add records in that order, and the
//! records keep it: it is the firmware's table order an instance limit counts
//! in. One device has one record: a record whose `Mmio` or `IoPort` base an
//! earlier record already holds adds its identity keys to that record
//! ([`PlatformRecords::add`]) and keeps none of its own resources: the record
//! keeps the first `_HID`, SPCR interface type and platform key it is given,
//! and adds a later `_CID` while it has room ([`MAX_CIDS`]). Every record
//! carries at most [`MAX_RECORD_RESOURCES`] resources, and the set at most
//! [`MAX_PLATFORM_RECORDS`] records.

extern crate alloc;

use alloc::vec::Vec;

use crate::aml::{CrsResource, Id, MAX_CIDS};
use crate::binding::RecordKeys;

/// Most records the set holds; an enumerator's further devices are dropped.
pub const MAX_PLATFORM_RECORDS: usize = 64;

/// Most resources one record carries; a description's further resources are
/// dropped.
pub const MAX_RECORD_RESOURCES: usize = 8;

/// Most payload bytes a record's device info carries.
pub const MAX_INFO_BYTES: usize = 32;

/// A platform key (docs/driver-binding.md § Device Records), as a platform
/// description table names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformKey
{
    bytes: [u8; driver_binding::decl::MAX_PLATFORM_KEY_BYTES],
    len: u8,
}

impl PlatformKey
{
    /// The key `bytes`; `None` when it is empty or longer than
    /// `MAX_PLATFORM_KEY_BYTES`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self>
    {
        let mut key = Self {
            bytes: [0; driver_binding::decl::MAX_PLATFORM_KEY_BYTES],
            len: u8::try_from(bytes.len()).ok()?,
        };
        if bytes.is_empty()
        {
            return None;
        }
        key.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(key)
    }

    /// The key's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }
}

/// Opaque startup info devmgr serves the record's driver over
/// `QUERY_DEVICE_INFO`: a kind (`ipc::device_info_kind`), its schema version,
/// and the payload bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo
{
    pub kind: u32,
    pub version: u32,
    bytes: [u8; MAX_INFO_BYTES],
    len: u8,
}

impl DeviceInfo
{
    /// The info of `kind` and `version` holding `bytes`; `None` when the
    /// payload exceeds [`MAX_INFO_BYTES`].
    #[must_use]
    pub fn new(kind: u32, version: u32, bytes: &[u8]) -> Option<Self>
    {
        let mut info = Self {
            kind,
            version,
            bytes: [0; MAX_INFO_BYTES],
            len: u8::try_from(bytes.len()).ok()?,
        };
        info.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(info)
    }

    /// The payload bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8]
    {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }
}

/// The identity keys one enumerator gives a device.
#[derive(Clone, Copy, Debug, Default)]
pub struct Identity
{
    pub hid: Option<Id>,
    pub cids: [Option<Id>; MAX_CIDS],
    pub spcr: Option<u8>,
    pub platform: Option<PlatformKey>,
    pub boot_framebuffer: bool,
}

/// One platform device record.
#[derive(Clone, Debug)]
pub struct PlatformRecord
{
    identity: Identity,
    resources: [Option<CrsResource>; MAX_RECORD_RESOURCES],
    info: Option<DeviceInfo>,
}

impl PlatformRecord
{
    /// The record's resources, in the order its description gave them.
    pub fn resources(&self) -> impl Iterator<Item = CrsResource> + '_
    {
        self.resources.iter().filter_map(|r| *r)
    }

    /// The record's device info, if an enumerator attached one.
    #[must_use]
    pub fn info(&self) -> Option<&DeviceInfo>
    {
        self.info.as_ref()
    }

    /// The record's identity keys.
    #[must_use]
    pub fn identity(&self) -> &Identity
    {
        &self.identity
    }

    /// Run `f` on the record's identity keys, in the match table's form.
    pub fn with_keys<R>(&self, f: impl FnOnce(&RecordKeys<'_>) -> R) -> R
    {
        let mut cids: [&[u8]; MAX_CIDS] = [&[]; MAX_CIDS];
        let mut count = 0usize;
        for (slot, id) in cids.iter_mut().zip(self.identity.cids.iter().flatten())
        {
            *slot = id.as_bytes();
            // `cids` and `identity.cids` have the same length, so `count` stays within it.
            count = count.saturating_add(1);
        }
        let keys = RecordKeys {
            pci: None,
            acpi_hid: self.identity.hid.as_ref().map(Id::as_bytes),
            acpi_cids: cids.get(..count).unwrap_or_default(),
            spcr: self.identity.spcr,
            platform: self.identity.platform.as_ref().map(PlatformKey::as_bytes),
            iommu_family: None,
            boot_framebuffer: self.identity.boot_framebuffer,
        };
        f(&keys)
    }

    /// Attach `info` to the record, replacing what it held.
    pub fn set_info(&mut self, info: DeviceInfo)
    {
        self.info = Some(info);
    }

    /// Whether the record holds an `Mmio` or `IoPort` resource at the base
    /// one of `other` names.
    fn shares_base(&self, other: &[Option<CrsResource>]) -> bool
    {
        other
            .iter()
            .flatten()
            .filter_map(|r| base_of(*r))
            .any(|b| self.resources().filter_map(base_of).any(|own| own == b))
    }

    /// Add `identity`'s keys to the record's, each kind kept where the record
    /// already has one, `_CID`s appended while room is left.
    fn absorb(&mut self, identity: &Identity)
    {
        let own = &mut self.identity;
        own.hid = own.hid.or(identity.hid);
        own.spcr = own.spcr.or(identity.spcr);
        own.platform = own.platform.or(identity.platform);
        own.boot_framebuffer |= identity.boot_framebuffer;
        for cid in identity.cids.iter().flatten()
        {
            if own.cids.iter().flatten().any(|c| c == cid)
            {
                continue;
            }
            if let Some(slot) = own.cids.iter_mut().find(|c| c.is_none())
            {
                *slot = Some(*cid);
            }
        }
    }
}

/// The resource identity of `resource`: its kind and base, for an `Mmio` or
/// an `IoPort`.
fn base_of(resource: CrsResource) -> Option<(bool, u64)>
{
    match resource
    {
        CrsResource::Mmio { base, .. } => Some((true, base)),
        CrsResource::IoPort { base, .. } => Some((false, u64::from(base))),
        CrsResource::Interrupt { .. } => None,
    }
}

/// How [`PlatformRecords::add`] placed a description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added
{
    /// A record of its own, at this index.
    New(usize),
    /// Its keys merged into the earlier record at this index.
    Merged(usize),
    /// Dropped as unusable: it carries no `Mmio` or `IoPort` resource to
    /// carve, or no key to match.
    Unusable,
    /// Dropped because the set holds [`MAX_PLATFORM_RECORDS`] records or no
    /// memory was left for another.
    Full,
}

/// Every platform device record, in enumeration order.
#[derive(Default)]
pub struct PlatformRecords
{
    records: Vec<PlatformRecord>,
}

impl PlatformRecords
{
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            records: Vec::new(),
        }
    }

    /// Every record, in enumeration order.
    #[must_use]
    pub fn records(&self) -> &[PlatformRecord]
    {
        &self.records
    }

    /// Mutable access to the record at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut PlatformRecord>
    {
        self.records.get_mut(index)
    }

    /// Add the device `identity` and `resources` describe: merged into the
    /// first record holding an `Mmio` or `IoPort` base it names, else a
    /// record of its own carrying its first [`MAX_RECORD_RESOURCES`]
    /// resources. A description with no `Mmio` or `IoPort` resource cannot be
    /// carved for, and one with no key cannot be matched: both are dropped.
    pub fn add(
        &mut self,
        identity: Identity,
        resources: impl IntoIterator<Item = CrsResource>,
    ) -> Added
    {
        let mut own = [None; MAX_RECORD_RESOURCES];
        for (slot, r) in own.iter_mut().zip(resources)
        {
            *slot = Some(r);
        }
        if !own.iter().flatten().any(|r| base_of(*r).is_some())
        {
            return Added::Unusable;
        }
        if let Some((index, record)) = self
            .records
            .iter_mut()
            .enumerate()
            .find(|(_, r)| r.shares_base(&own))
        {
            record.absorb(&identity);
            return Added::Merged(index);
        }
        let keyed = identity.hid.is_some()
            || identity.cids.iter().any(Option::is_some)
            || identity.spcr.is_some()
            || identity.platform.is_some()
            || identity.boot_framebuffer;
        if !keyed
        {
            return Added::Unusable;
        }
        if self.records.len() >= MAX_PLATFORM_RECORDS || self.records.try_reserve(1).is_err()
        {
            return Added::Full;
        }
        let index = self.records.len();
        self.records.push(PlatformRecord {
            identity,
            resources: own,
            info: None,
        });
        Added::New(index)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn mmio(base: u64) -> CrsResource
    {
        CrsResource::Mmio { base, size: 0x1000 }
    }

    fn port(base: u16) -> CrsResource
    {
        CrsResource::IoPort { base, count: 8 }
    }

    fn irq(line: u32) -> CrsResource
    {
        CrsResource::Interrupt {
            line,
            mode: 0,
            shared: false,
            isa: true,
        }
    }

    fn hid(s: &str) -> Identity
    {
        Identity {
            hid: Id::new(s.as_bytes()),
            ..Identity::default()
        }
    }

    #[test]
    fn records_keep_enumeration_order()
    {
        let mut set = PlatformRecords::new();
        assert_eq!(
            set.add(hid("PNP0501"), [port(0x3F8), irq(4)]),
            Added::New(0)
        );
        assert_eq!(set.add(hid("PNP0B00"), [port(0x70)]), Added::New(1));
        let resources: Vec<_> = set.records()[0].resources().collect();
        assert_eq!(resources, [port(0x3F8), irq(4)]);
    }

    #[test]
    fn same_base_merges_keys_into_the_earlier_record()
    {
        let mut set = PlatformRecords::new();
        set.add(hid("PNP0501"), [mmio(0x1000_0000), irq(10)]);
        let spcr = Identity {
            spcr: Some(0x12),
            ..Identity::default()
        };
        assert_eq!(
            set.add(spcr, [mmio(0x1000_0000), irq(33)]),
            Added::Merged(0)
        );
        let record = &set.records()[0];
        assert_eq!(record.identity().spcr, Some(0x12));
        // The earlier record's resources stand.
        assert_eq!(
            record.resources().collect::<Vec<_>>(),
            [mmio(0x1000_0000), irq(10)]
        );
        record.with_keys(|k| {
            assert_eq!(k.acpi_hid, Some(&b"PNP0501"[..]));
            assert_eq!(k.spcr, Some(0x12));
        });
    }

    #[test]
    fn an_mmio_and_a_port_of_equal_value_are_different_identities()
    {
        let mut set = PlatformRecords::new();
        set.add(hid("A"), [mmio(0x70)]);
        assert_eq!(set.add(hid("B"), [port(0x70)]), Added::New(1));
    }

    #[test]
    fn merge_keeps_existing_keys_and_appends_cids()
    {
        let mut set = PlatformRecords::new();
        let mut first = hid("PNP0501");
        first.cids[0] = Id::new(b"PNP0500");
        set.add(first, [port(0x3F8)]);
        let mut second = hid("OTHER01");
        second.cids[0] = Id::new(b"PNP0500");
        second.cids[1] = Id::new(b"PNP0400");
        assert_eq!(set.add(second, [port(0x3F8)]), Added::Merged(0));
        set.records()[0].with_keys(|k| {
            assert_eq!(k.acpi_hid, Some(&b"PNP0501"[..]));
            assert_eq!(k.acpi_cids, [&b"PNP0500"[..], &b"PNP0400"[..]]);
        });
    }

    #[test]
    fn descriptions_without_a_base_or_a_key_are_dropped()
    {
        let mut set = PlatformRecords::new();
        assert_eq!(set.add(hid("PNP0C0F"), [irq(5)]), Added::Unusable);
        assert_eq!(
            set.add(Identity::default(), [mmio(0x1000)]),
            Added::Unusable
        );
        assert!(set.records().is_empty());
    }

    #[test]
    fn the_set_and_each_record_are_bounded()
    {
        let mut set = PlatformRecords::new();
        for i in 0..MAX_PLATFORM_RECORDS as u64
        {
            assert_eq!(
                set.add(hid("X"), [mmio(i * 0x1000)]),
                Added::New(i as usize)
            );
        }
        assert_eq!(set.add(hid("X"), [mmio(0x1000_0000)]), Added::Full);
        let mut set = PlatformRecords::new();
        set.add(hid("X"), (0..20).map(|i| mmio(i * 0x1000)));
        assert_eq!(set.records()[0].resources().count(), MAX_RECORD_RESOURCES);
    }

    #[test]
    fn keys_and_info_round_trip()
    {
        assert!(PlatformKey::new(b"").is_none());
        assert!(PlatformKey::new(&[b'a'; 33]).is_none());
        assert_eq!(
            PlatformKey::new(b"google,goldfish-rtc").map(|k| k.as_bytes().len()),
            Some(19)
        );
        assert!(DeviceInfo::new(1, 1, &[0; MAX_INFO_BYTES + 1]).is_none());
        let info = DeviceInfo::new(3, 1, &[0x32]);
        assert_eq!(info.map(|i| i.bytes().to_vec()), Some(vec![0x32]));
    }
}
