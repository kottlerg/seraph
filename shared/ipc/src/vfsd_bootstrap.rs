// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/vfsd_bootstrap.rs

//! Init → vfsd bootstrap payload layout.
//!
//! init serves vfsd's bootstrap in two rounds on vfsd's creator endpoint
//! (`services/init/docs/bootstrap.md`). This module is the single source of
//! truth for the data words of round 1, the boot device record; init writes
//! them and vfsd reads them. It versions with
//! [`VFSD_LABELS_VERSION`](crate::VFSD_LABELS_VERSION), which init's
//! `vfsd_labels::GET_SYSTEM_ROOT_CAP` handshake checks.
//!
//! Round 1 (`ipc::bootstrap` caps + data words):
//! * `caps[0]` — vfsd's service endpoint (full rights; its RECV side).
//! * `caps[1]` — the `block` class SEND on devmgr's registry endpoint.
//! * `data[0..BOOT_DEVICE_WORDS]` — the boot device ([`BootDevice`]), as
//!   the kernel copied it into `InitInfo.boot_device`:
//!   * `data[0]` — bits 0..32 the flags (bit 0 [`FLAG_ESP`], bit 1
//!     [`FLAG_PCI`], the rest zero), bits 32..64 the ESP's GPT partition
//!     number.
//!   * `data[1]` — the ESP's first logical block.
//!   * `data[2]` — the ESP's size in logical blocks.
//!   * `data[3]`, `data[4]` — the ESP's unique partition GUID, bytes 0..8
//!     and 8..16 in GPT on-disk byte order, each word little-endian.
//!   * `data[5]` — the controller's PCI location: bits 0..16 the segment,
//!     16..24 the bus, 24..32 the device, 32..40 the function, the rest zero.
//!
//!   A part whose flag is clear has all its fields zero.
//!
//! Round 2 (1 cap, 1 data word): the fatfs module's Memory cap and its size in
//! bytes.

#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// Data words of the boot device record in round 1.
pub const BOOT_DEVICE_WORDS: usize = 6;

/// Flag bit: the record carries the boot ESP's GPT descriptor.
pub const FLAG_ESP: u64 = 1 << 0;
/// Flag bit: the record carries the controller's PCI location.
pub const FLAG_PCI: u64 = 1 << 1;

/// The boot ESP's GPT `HardDrive` descriptor, as the bootloader read it from
/// the firmware's device path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EspDescriptor
{
    /// 1-based GPT partition number; never zero.
    pub partition_number: u32,
    /// First logical block.
    pub start_lba: u64,
    /// Size in logical blocks; never zero, and the extent ends inside the
    /// 64-bit block range.
    pub size_lba: u64,
    /// Unique partition GUID, in GPT on-disk byte order.
    pub partition_guid: [u8; 16],
}

/// The PCI location of the controller beneath the boot ESP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciLocation
{
    /// Segment group.
    pub segment: u16,
    /// Bus number, as the firmware numbered the buses.
    pub bus: u8,
    /// Device number, at most 31.
    pub device: u8,
    /// Function number, at most 7.
    pub function: u8,
}

/// The device the firmware booted from: each part the firmware reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootDevice
{
    /// The boot ESP's GPT descriptor.
    pub esp: Option<EspDescriptor>,
    /// The PCI location of the controller beneath it.
    pub location: Option<PciLocation>,
}

impl BootDevice
{
    /// The record's round-1 data words.
    #[must_use]
    pub fn to_words(&self) -> [u64; BOOT_DEVICE_WORDS]
    {
        let mut words = [0u64; BOOT_DEVICE_WORDS];
        if let Some(esp) = self.esp
        {
            words[0] |= FLAG_ESP | (u64::from(esp.partition_number) << 32);
            words[1] = esp.start_lba;
            words[2] = esp.size_lba;
            let (low, high) = esp.partition_guid.split_at(8);
            words[3] = u64::from_le_bytes(low.try_into().unwrap_or([0; 8]));
            words[4] = u64::from_le_bytes(high.try_into().unwrap_or([0; 8]));
        }
        if let Some(pci) = self.location
        {
            words[0] |= FLAG_PCI;
            words[5] = u64::from(pci.segment)
                | (u64::from(pci.bus) << 16)
                | (u64::from(pci.device) << 24)
                | (u64::from(pci.function) << 32);
        }
        words
    }

    /// The record `words` carry, or `None` when they are fewer than
    /// [`BOOT_DEVICE_WORDS`] or carry what no record encodes: an unknown
    /// flag bit or a set bit outside every field, a field of an absent part
    /// not zero, or a present part outside its ranges (a partition number or
    /// size of zero, an extent past the 64-bit block range, a device above 31,
    /// a function above 7).
    #[must_use]
    pub fn from_words(words: &[u64]) -> Option<Self>
    {
        let words: &[u64; BOOT_DEVICE_WORDS] = words.get(..BOOT_DEVICE_WORDS)?.try_into().ok()?;
        let flags = words[0] & 0xFFFF_FFFF;
        if flags & !(FLAG_ESP | FLAG_PCI) != 0 || words[5] >> 40 != 0
        {
            return None;
        }
        let esp = if flags & FLAG_ESP == 0
        {
            if words[0] >> 32 != 0 || words[1..5].iter().any(|&w| w != 0)
            {
                return None;
            }
            None
        }
        else
        {
            let mut partition_guid = [0u8; 16];
            partition_guid[..8].copy_from_slice(&words[3].to_le_bytes());
            partition_guid[8..].copy_from_slice(&words[4].to_le_bytes());
            let esp = EspDescriptor {
                partition_number: u32::try_from(words[0] >> 32).ok()?,
                start_lba: words[1],
                size_lba: words[2],
                partition_guid,
            };
            if esp.partition_number == 0
                || esp.size_lba == 0
                || esp
                    .size_lba
                    .checked_sub(1)
                    .and_then(|blocks| esp.start_lba.checked_add(blocks))
                    .is_none()
            {
                return None;
            }
            Some(esp)
        };
        let location = if flags & FLAG_PCI == 0
        {
            if words[5] != 0
            {
                return None;
            }
            None
        }
        else
        {
            let byte = |shift: u32| u8::try_from((words[5] >> shift) & 0xFF).ok();
            let pci = PciLocation {
                segment: u16::try_from(words[5] & 0xFFFF).ok()?,
                bus: byte(16)?,
                device: byte(24)?,
                function: byte(32)?,
            };
            if pci.device > 31 || pci.function > 7
            {
                return None;
            }
            Some(pci)
        };
        Some(Self { esp, location })
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn both() -> BootDevice
    {
        BootDevice {
            esp: Some(EspDescriptor {
                partition_number: 1,
                start_lba: 2048,
                size_lba: 131_072,
                partition_guid: [
                    0xd4, 0xc3, 0xb2, 0xa1, 0xf6, 0xe5, 0x90, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23,
                    0x45, 0x67, 0x89,
                ],
            }),
            location: Some(PciLocation {
                segment: 0x0102,
                bus: 0x03,
                device: 31,
                function: 7,
            }),
        }
    }

    // Defect caught: init and vfsd disagreeing on a field's word or bits, so
    // vfsd reads a different boot device than the kernel handed init.
    #[test]
    fn records_round_trip_through_their_words()
    {
        let records = [
            both(),
            BootDevice::default(),
            BootDevice {
                esp: both().esp,
                location: None,
            },
            BootDevice {
                esp: None,
                location: both().location,
            },
        ];
        for record in records
        {
            assert_eq!(BootDevice::from_words(&record.to_words()), Some(record));
        }
        let words = both().to_words();
        assert_eq!(words[0], FLAG_ESP | FLAG_PCI | (1 << 32));
        assert_eq!(words[3], 0x7890_e5f6_a1b2_c3d4);
        assert_eq!(words[5], 0x0007_1f03_0102);
        assert_eq!(BootDevice::default().to_words(), [0; BOOT_DEVICE_WORDS]);
    }

    // Defect caught: a round without the record, or with bits no record
    // encodes, decoded as a boot device.
    #[test]
    fn from_words_refuses_what_no_record_encodes()
    {
        let good = both().to_words();
        assert_eq!(BootDevice::from_words(&good[..BOOT_DEVICE_WORDS - 1]), None);
        assert_eq!(BootDevice::from_words(&[]), None);
        let mut flag = good;
        flag[0] |= 1 << 2;
        assert_eq!(BootDevice::from_words(&flag), None);
        let mut high = good;
        high[5] |= 1 << 40;
        assert_eq!(BootDevice::from_words(&high), None);
        // Fields of an absent part.
        let mut esp = good;
        esp[0] &= !FLAG_ESP;
        assert_eq!(BootDevice::from_words(&esp), None);
        let mut pci = good;
        pci[0] &= !FLAG_PCI;
        assert_eq!(BootDevice::from_words(&pci), None);
    }

    // Defect caught: a present part outside its ranges handed to vfsd's
    // matching as if a disk could carry it.
    #[test]
    fn from_words_refuses_impossible_parts()
    {
        let good = both().to_words();
        let mut number = good;
        number[0] &= 0xFFFF_FFFF;
        assert_eq!(BootDevice::from_words(&number), None);
        let mut size = good;
        size[2] = 0;
        assert_eq!(BootDevice::from_words(&size), None);
        let mut wraps = good;
        wraps[1] = u64::MAX;
        wraps[2] = 2;
        assert_eq!(BootDevice::from_words(&wraps), None);
        let mut device = good;
        device[5] = (device[5] & !(0xFF << 24)) | (32 << 24);
        assert_eq!(BootDevice::from_words(&device), None);
        let mut function = good;
        function[5] = (function[5] & !(0xFF << 32)) | (8 << 32);
        assert_eq!(BootDevice::from_words(&function), None);
    }
}
