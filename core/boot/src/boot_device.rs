// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/boot_device.rs

//! The boot device record ([`BootDevice`]): the reduction of the loaded
//! image's UEFI device path to the boot ESP's GPT `HardDrive` descriptor, and of
//! `EFI_PCI_IO_PROTOCOL.GetLocation`'s values to the PCI location of the
//! controller beneath it ([boot-flow.md](../docs/boot-flow.md) § Step 1).
//!
//! The functions here are pure: `crate::uefi` makes the firmware calls and
//! hands them the device path's node headers and bytes and `GetLocation`'s
//! values, so the host tests drive every reduction rule.

use boot_protocol::{BOOT_DEVICE_ESP, BOOT_DEVICE_PCI, BootDevice};

/// The longest device path, in bytes, the walk follows: a path past it is
/// treated as malformed. A partition's path is a few dozen bytes on every
/// platform Seraph boots on (`PciRoot`, one `Pci` node per bridge, a
/// messaging node, `HD`), so the bound only stops a walk of a path with no
/// end node.
pub const MAX_PATH_BYTES: usize = 4096;

/// Size of a device path node header: type, subtype, and a little-endian
/// 16-bit length that counts the header.
const NODE_HEADER: usize = 4;

/// Device path node type of an end node.
const END_TYPE: u8 = 0x7F;
/// End node subtype that ends the whole path (End Entire Device Path).
const END_ENTIRE: u8 = 0xFF;
/// Device path node type of a media node.
const MEDIA_TYPE: u8 = 0x04;
/// Media node subtype of a hard-drive partition (`HardDrive`).
const HARD_DRIVE: u8 = 0x01;
/// Length of a `HardDrive` node, header included.
const HARD_DRIVE_LEN: usize = 42;
/// `HardDrive` `MBRType` of a GPT partition.
const MBR_TYPE_GPT: u8 = 0x02;
/// `HardDrive` `SignatureType` of a GUID signature.
const SIGNATURE_GUID: u8 = 0x02;

/// Why a device path yields no ESP descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoEsp
{
    /// The path is malformed: a node shorter than its header, a node past
    /// the path's end, or no End Entire node within [`MAX_PATH_BYTES`].
    Malformed,
    /// The node before the end node is not a `HardDrive` node: the image was
    /// loaded from something other than a partition (a whole disk, a CD-ROM
    /// El Torito image, a network path).
    NotPartition,
    /// The `HardDrive` node describes an MBR partition or carries no GUID
    /// signature, so it names no GPT partition.
    NotGpt,
    /// The `HardDrive` node's fields describe no partition: a partition number
    /// or a size of zero, or an extent past the 64-bit block range.
    Invalid,
}

impl NoEsp
{
    /// The reason as a fixed phrase, for the boot log.
    pub const fn as_str(self) -> &'static str
    {
        match self
        {
            Self::Malformed => "malformed device path",
            Self::NotPartition => "not loaded from a partition",
            Self::NotGpt => "not a GPT partition",
            Self::Invalid => "invalid HardDrive node",
        }
    }
}

/// The boot ESP's GPT `HardDrive` descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EspDescriptor
{
    /// 1-based GPT partition number.
    pub partition_number: u32,
    /// First logical block.
    pub start_lba: u64,
    /// Size in logical blocks.
    pub size_lba: u64,
    /// Unique partition GUID, in GPT on-disk byte order.
    pub partition_guid: [u8; 16],
}

/// A PCI function's location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciLocation
{
    /// Segment group.
    pub segment: u16,
    /// Bus number.
    pub bus: u8,
    /// Device number, at most 31.
    pub device: u8,
    /// Function number, at most 7.
    pub function: u8,
}

/// The length in bytes, End Entire node included, of the device path whose
/// node header at byte `offset` `header_at(offset)` returns.
///
/// Walks the node headers from offset 0, each node's 16-bit length giving the
/// next node's offset, and stops at the End Entire node. `header_at` is
/// called only for offsets whose whole header lies inside a node the walk
/// has reached or right after it, and below [`MAX_PATH_BYTES`].
///
/// # Errors
/// [`NoEsp::Malformed`] when a node is shorter than its header, or no End
/// Entire node ends within [`MAX_PATH_BYTES`].
pub fn path_len(mut header_at: impl FnMut(usize) -> [u8; 4]) -> Result<usize, NoEsp>
{
    let mut offset = 0usize;
    while offset.saturating_add(NODE_HEADER) <= MAX_PATH_BYTES
    {
        let header = header_at(offset);
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if len < NODE_HEADER
        {
            return Err(NoEsp::Malformed);
        }
        let end = offset.saturating_add(len);
        if end > MAX_PATH_BYTES
        {
            return Err(NoEsp::Malformed);
        }
        if header[0] == END_TYPE && header[1] == END_ENTIRE
        {
            return Ok(end);
        }
        offset = end;
    }
    Err(NoEsp::Malformed)
}

/// The boot ESP's descriptor, from `path`, the whole device path of the
/// loaded image's device, End Entire node included (its [`path_len`]
/// bytes).
///
/// The node before the End Entire node must be a `HardDrive` node of a GPT
/// partition with a GUID signature, whose partition number and size are
/// nonzero and whose extent fits the 64-bit block range.
///
/// # Errors
/// The [`NoEsp`] that says why the path yields no descriptor.
pub fn reduce(path: &[u8]) -> Result<EspDescriptor, NoEsp>
{
    let mut rest = path;
    let mut last: Option<&[u8]> = None;
    loop
    {
        let header: [u8; NODE_HEADER] = rest
            .get(..NODE_HEADER)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(NoEsp::Malformed)?;
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if len < NODE_HEADER
        {
            return Err(NoEsp::Malformed);
        }
        let (node, after) = rest.split_at_checked(len).ok_or(NoEsp::Malformed)?;
        if header[0] == END_TYPE && header[1] == END_ENTIRE
        {
            if !after.is_empty()
            {
                return Err(NoEsp::Malformed);
            }
            break;
        }
        last = Some(node);
        rest = after;
    }
    let node = last.ok_or(NoEsp::NotPartition)?;
    if node.get(..2) != Some(&[MEDIA_TYPE, HARD_DRIVE][..])
    {
        return Err(NoEsp::NotPartition);
    }
    let node: &[u8; HARD_DRIVE_LEN] = node.try_into().map_err(|_| NoEsp::Malformed)?;
    if node[40] != MBR_TYPE_GPT || node[41] != SIGNATURE_GUID
    {
        return Err(NoEsp::NotGpt);
    }
    let u64_at = |at: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(node.get(at..at.saturating_add(8)).unwrap_or(&[0; 8]));
        u64::from_le_bytes(bytes)
    };
    let mut partition_guid = [0u8; 16];
    partition_guid.copy_from_slice(&node[24..40]);
    let esp = EspDescriptor {
        partition_number: u32::from_le_bytes([node[4], node[5], node[6], node[7]]),
        start_lba: u64_at(8),
        size_lba: u64_at(16),
        partition_guid,
    };
    // The record's own check is the one rule for a present ESP.
    if record(Some(esp), None).check().is_err()
    {
        return Err(NoEsp::Invalid);
    }
    Ok(esp)
}

/// The PCI location `GetLocation` returned, or `None` when a value lies
/// outside its PCI range (a segment above 65535, a bus above 255, a device
/// above 31, or a function above 7), which no record can carry.
pub fn pci_location(
    segment: usize,
    bus: usize,
    device: usize,
    function: usize,
) -> Option<PciLocation>
{
    let location = PciLocation {
        segment: u16::try_from(segment).ok()?,
        bus: u8::try_from(bus).ok()?,
        device: u8::try_from(device).ok().filter(|&d| d <= 31)?,
        function: u8::try_from(function).ok().filter(|&f| f <= 7)?,
    };
    Some(location)
}

/// The [`BootDevice`] record of an ESP descriptor and a PCI location, each
/// flagged present when given and all zero when not.
pub fn record(esp: Option<EspDescriptor>, location: Option<PciLocation>) -> BootDevice
{
    let mut device = BootDevice::none();
    if let Some(esp) = esp
    {
        device.flags |= BOOT_DEVICE_ESP;
        device.esp_partition_number = esp.partition_number;
        device.esp_start_lba = esp.start_lba;
        device.esp_size_lba = esp.size_lba;
        device.esp_partition_guid = esp.partition_guid;
    }
    if let Some(location) = location
    {
        device.flags |= BOOT_DEVICE_PCI;
        device.pci_segment = location.segment;
        device.pci_bus = location.bus;
        device.pci_device = location.device;
        device.pci_function = location.function;
    }
    device
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    /// A node of `node_type`/`subtype` with `body` after its header.
    fn node(node_type: u8, subtype: u8, body: &[u8]) -> Vec<u8>
    {
        let len = u16::try_from(NODE_HEADER + body.len()).unwrap();
        let mut bytes = vec![node_type, subtype];
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    /// `PciRoot(0x0)`: ACPI node, HID PNP0A03, UID 0.
    fn pci_root() -> Vec<u8>
    {
        let mut body = 0x0A03_41D0u32.to_le_bytes().to_vec();
        body.extend_from_slice(&0u32.to_le_bytes());
        node(0x02, 0x01, &body)
    }

    /// `Pci(device, function)`.
    fn pci(device: u8, function: u8) -> Vec<u8>
    {
        node(0x01, 0x01, &[function, device])
    }

    /// The GUID of the partition QEMU's tests boot, in on-disk byte order.
    const GUID: [u8; 16] = [
        0xd4, 0xc3, 0xb2, 0xa1, 0xf6, 0xe5, 0x90, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89,
    ];

    /// `HD(number, GPT, GUID, start, size)` with the given MBR and signature
    /// types.
    fn hard_drive(number: u32, start: u64, size: u64, mbr: u8, signature: u8) -> Vec<u8>
    {
        let mut body = number.to_le_bytes().to_vec();
        body.extend_from_slice(&start.to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&GUID);
        body.push(mbr);
        body.push(signature);
        node(MEDIA_TYPE, HARD_DRIVE, &body)
    }

    fn end() -> Vec<u8>
    {
        node(END_TYPE, END_ENTIRE, &[])
    }

    fn path(nodes: &[Vec<u8>]) -> Vec<u8>
    {
        nodes.concat()
    }

    /// The length `path_len` finds for `bytes`, padded with zero bytes so
    /// a walk past the path reads zero headers rather than panicking.
    fn len_of(bytes: &[u8]) -> Result<usize, NoEsp>
    {
        let mut padded = bytes.to_vec();
        padded.resize(MAX_PATH_BYTES + NODE_HEADER, 0);
        path_len(|at| [padded[at], padded[at + 1], padded[at + 2], padded[at + 3]])
    }

    // Defect caught: the walk stopping short of, or running past, the End
    // Entire node, which hands `reduce` a cut or overlong path.
    #[test]
    fn path_len_ends_at_the_end_entire_node()
    {
        let bytes = path(&[
            pci_root(),
            pci(3, 0),
            hard_drive(1, 2048, 131_072, 2, 2),
            end(),
        ]);
        assert_eq!(len_of(&bytes), Ok(bytes.len()));
        assert_eq!(len_of(&end()), Ok(NODE_HEADER));
        // An End Instance node (subtype 0x01) does not end the walk.
        let instance = path(&[pci_root(), node(END_TYPE, 0x01, &[]), pci(3, 0), end()]);
        assert_eq!(len_of(&instance), Ok(instance.len()));
    }

    // Defect caught: a zero or short node length looping forever, or a path
    // with no end node walked past the bound.
    #[test]
    fn path_len_refuses_short_nodes_and_unended_paths()
    {
        let zero = path(&[pci_root(), vec![0x01, 0x01, 0x00, 0x00]]);
        assert_eq!(len_of(&zero), Err(NoEsp::Malformed));
        let short = path(&[pci_root(), vec![0x01, 0x01, 0x03, 0x00]]);
        assert_eq!(len_of(&short), Err(NoEsp::Malformed));
        // A node whose length runs past the bound.
        let long = path(&[pci_root(), vec![0x01, 0x01, 0xFF, 0xFF]]);
        assert_eq!(len_of(&long), Err(NoEsp::Malformed));
        // Nodes of a valid length that never end: the walk stops at the bound.
        let mut endless = Vec::new();
        while endless.len() < MAX_PATH_BYTES + 64
        {
            endless.extend_from_slice(&pci(3, 0));
        }
        let mut header_calls = 0usize;
        let result = path_len(|at| {
            header_calls += 1;
            [
                endless[at],
                endless[at + 1],
                endless[at + 2],
                endless[at + 3],
            ]
        });
        assert_eq!(result, Err(NoEsp::Malformed));
        assert!(header_calls <= MAX_PATH_BYTES / 6 + 1);
    }

    // Defect caught: the ESP of a QEMU-shaped boot path not found, or its
    // fields read from the wrong offsets of the HardDrive node.
    #[test]
    fn reduce_reads_the_hard_drive_node()
    {
        let bytes = path(&[
            pci_root(),
            pci(3, 0),
            hard_drive(1, 2048, 131_072, 2, 2),
            end(),
        ]);
        let esp = reduce(&bytes).unwrap();
        assert_eq!(
            esp,
            EspDescriptor {
                partition_number: 1,
                start_lba: 2048,
                size_lba: 131_072,
                partition_guid: GUID,
            }
        );
        // Behind a bridge and an NVMe namespace node.
        let nvme = node(0x03, 0x17, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let deep = path(&[
            pci_root(),
            pci(1, 0),
            pci(0, 0),
            nvme,
            hard_drive(2, 4096, 8, 2, 2),
            end(),
        ]);
        assert_eq!(reduce(&deep).unwrap().partition_number, 2);
    }

    // Defect caught: a path that names no GPT partition reported as the
    // boot ESP.
    #[test]
    fn reduce_refuses_paths_that_name_no_gpt_partition()
    {
        let disk = path(&[pci_root(), pci(3, 0), end()]);
        assert_eq!(reduce(&disk), Err(NoEsp::NotPartition));
        assert_eq!(reduce(&end()), Err(NoEsp::NotPartition));
        // HardDrive not last: a file path node after it.
        let file = node(MEDIA_TYPE, 0x04, &[b'\\', 0, 0, 0]);
        let after = path(&[pci_root(), hard_drive(1, 2048, 8, 2, 2), file, end()]);
        assert_eq!(reduce(&after), Err(NoEsp::NotPartition));
        let mbr = path(&[pci_root(), hard_drive(1, 2048, 8, 1, 1), end()]);
        assert_eq!(reduce(&mbr), Err(NoEsp::NotGpt));
        let unsigned = path(&[pci_root(), hard_drive(1, 2048, 8, 2, 0), end()]);
        assert_eq!(reduce(&unsigned), Err(NoEsp::NotGpt));
    }

    // Defect caught: a HardDrive node describing no partition reported, which
    // the kernel would then refuse and halt the boot on.
    #[test]
    fn reduce_refuses_impossible_partitions()
    {
        let number = path(&[pci_root(), hard_drive(0, 2048, 8, 2, 2), end()]);
        assert_eq!(reduce(&number), Err(NoEsp::Invalid));
        let empty = path(&[pci_root(), hard_drive(1, 2048, 0, 2, 2), end()]);
        assert_eq!(reduce(&empty), Err(NoEsp::Invalid));
        let wraps = path(&[pci_root(), hard_drive(1, u64::MAX, 2, 2, 2), end()]);
        assert_eq!(reduce(&wraps), Err(NoEsp::Invalid));
    }

    // Defect caught: a cut path, a HardDrive node of the wrong length, or
    // bytes after the end node read as a valid path.
    #[test]
    fn reduce_refuses_malformed_paths()
    {
        let full = path(&[pci_root(), hard_drive(1, 2048, 8, 2, 2), end()]);
        assert_eq!(reduce(&full[..full.len() - 2]), Err(NoEsp::Malformed));
        let mut trailing = full.clone();
        trailing.extend_from_slice(&pci(3, 0));
        assert_eq!(reduce(&trailing), Err(NoEsp::Malformed));
        let mut short_hd = hard_drive(1, 2048, 8, 2, 2);
        short_hd.truncate(HARD_DRIVE_LEN - 1);
        short_hd[2] = u8::try_from(HARD_DRIVE_LEN - 1).unwrap();
        let short = path(&[pci_root(), short_hd, end()]);
        assert_eq!(reduce(&short), Err(NoEsp::Malformed));
        let zero = path(&[pci_root(), vec![0x01, 0x01, 0x00, 0x00], end()]);
        assert_eq!(reduce(&zero), Err(NoEsp::Malformed));
    }

    // Defect caught: a GetLocation value outside its PCI range truncated
    // into a record that names another function.
    #[test]
    fn pci_location_keeps_values_inside_their_ranges()
    {
        assert_eq!(
            pci_location(0, 0, 3, 0),
            Some(PciLocation {
                segment: 0,
                bus: 0,
                device: 3,
                function: 0,
            })
        );
        assert_eq!(
            pci_location(0xFFFF, 0xFF, 31, 7).map(|l| l.function),
            Some(7)
        );
        assert_eq!(pci_location(0x1_0000, 0, 0, 0), None);
        assert_eq!(pci_location(0, 0x100, 0, 0), None);
        assert_eq!(pci_location(0, 0, 32, 0), None);
        assert_eq!(pci_location(0, 0, 0, 8), None);
    }

    // Defect caught: a part's flag set without its fields, or fields written
    // for an absent part, either of which the kernel refuses.
    #[test]
    fn record_flags_exactly_the_parts_given()
    {
        let esp = EspDescriptor {
            partition_number: 1,
            start_lba: 2048,
            size_lba: 8,
            partition_guid: GUID,
        };
        let location = pci_location(0, 0, 3, 0);
        let both = record(Some(esp), location);
        assert_eq!(both.flags, BOOT_DEVICE_ESP | BOOT_DEVICE_PCI);
        assert_eq!(both.check(), Ok(()));
        assert_eq!(both.esp_partition_guid, GUID);
        assert_eq!(both.pci_device, 3);
        assert_eq!(record(None, None), BootDevice::none());
        let pci_only = record(None, location);
        assert_eq!(pci_only.flags, BOOT_DEVICE_PCI);
        assert_eq!(pci_only.check(), Ok(()));
        let esp_only = record(Some(esp), None);
        assert_eq!(esp_only.flags, BOOT_DEVICE_ESP);
        assert_eq!(esp_only.check(), Ok(()));
    }
}
