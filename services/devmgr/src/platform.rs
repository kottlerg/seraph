// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/platform.rs

//! The platform enumerators: the device records of everything the firmware
//! describes other than a PCI function and an IOMMU
//! ([docs/driver-binding.md](../../../docs/driver-binding.md) § Device
//! Records).
//!
//! In record order: the boot framebuffer, the static `Device` objects of the
//! DSDT and every SSDT, the SPCR's console UART, and the devices of the
//! platform description table whose OEM table ID is the XSDT's. Each
//! enumerator knows its firmware standard and no driver; the parsing is in
//! the host-tested `devmgr-firmware` crate (`aml`, `platform`, `records`).

use firmware::aml::{self, CrsResource};
use firmware::platform::{PlatformResource, PlatformTable, SpcrBase};
use firmware::records::{Added, DeviceInfo, Identity, PlatformKey, PlatformRecords};
use syscall_abi::PAGE_SIZE;

use crate::{caps, tables};

/// The ACPI identifiers of the CMOS-compatible RTC, whose century register's
/// CMOS RAM index the FADT's `CENTURY` field names (ACPI 6.x section 5.2.9).
const CMOS_RTC_IDS: [&[u8]; 3] = [b"PNP0B00", b"PNP0B01", b"PNP0B02"];

/// Enumerate the platform device records. `tables_found` are the platform
/// description tables among the boot modules; the one whose OEM table ID is
/// the XSDT's describes the devices the machine's tables do not. Every
/// record is logged.
pub fn enumerate(caps: &caps::DevmgrCaps, tables_found: &[PlatformTable]) -> PlatformRecords
{
    let mut records = PlatformRecords::new();
    boot_framebuffer(caps, &mut records);
    let acpi = tables::platform_tables(caps);
    for &block in &acpi.definition_blocks
    {
        let read = tables::with_acpi_table(caps, block, |bytes| {
            Some(aml::devices(bytes, |device| add_namespace_device(device, &mut records)))
        });
        if read.is_none()
        {
            std::os::seraph::log!("ACPI definition block at {:#x} not read", block);
        }
    }
    attach_century(caps, &mut records);
    if let Some(spcr) = acpi
        .spcr
        .and_then(|t| tables::with_acpi_table(caps, t, firmware::platform::spcr))
    {
        let identity = Identity {
            spcr: Some(spcr.interface),
            ..Identity::default()
        };
        let base = match spcr.base
        {
            // A 16550-compatible register block: one page of MMIO, eight
            // ports of I/O.
            SpcrBase::Mmio(base) => CrsResource::Mmio {
                base,
                size: PAGE_SIZE,
            },
            SpcrBase::IoPort(base) => CrsResource::IoPort { base, count: 8 },
        };
        let interrupt = spcr.interrupt.map(|i| CrsResource::Interrupt {
            line: i.line,
            mode: if i.isa { 0 } else { syscall::IRQ_MODE_LEVEL },
            shared: false,
            isa: i.isa,
        });
        records.add(identity, core::iter::once(base).chain(interrupt));
    }
    platform_table(acpi.oem_table_id, tables_found, &mut records);
    for (index, record) in records.records().iter().enumerate()
    {
        log_record(index, record);
    }
    records
}

/// The boot framebuffer's record: its linear framebuffer's pages, keyed
/// `boot-framebuffer`, with its geometry as device info.
fn boot_framebuffer(caps: &caps::DevmgrCaps, records: &mut PlatformRecords)
{
    let Some(fb) = caps.fb_info
    else
    {
        return;
    };
    let info = boot_protocol::FramebufferInfo {
        physical_base: fb.physical_base,
        width: fb.width,
        height: fb.height,
        stride: fb.stride,
        pixel_format: match fb.pixel_format
        {
            0 => boot_protocol::PixelFormat::Rgbx8,
            _ => boot_protocol::PixelFormat::Bgrx8,
        },
    };
    let mut buf = [0u8; boot_protocol::FramebufferInfo::SIZE];
    let info = info.to_bytes(&mut buf).and_then(|()| {
        DeviceInfo::new(
            ipc::device_info_kind::FRAMEBUFFER,
            boot_protocol::FRAMEBUFFER_INFO_VERSION,
            &buf,
        )
    });
    // The pages covering [physical_base, physical_base + stride * height),
    // the range the bootloader seeded into the MMIO apertures.
    let base = fb.physical_base & !(PAGE_SIZE - 1);
    let end = fb
        .physical_base
        .saturating_add(u64::from(fb.stride) * u64::from(fb.height))
        .div_ceil(PAGE_SIZE)
        * PAGE_SIZE;
    let identity = Identity {
        boot_framebuffer: true,
        ..Identity::default()
    };
    let mmio = CrsResource::Mmio {
        base,
        size: end - base,
    };
    if let (Added::New(i), Some(info)) = (records.add(identity, [mmio]), info)
        && let Some(record) = records.get_mut(i)
    {
        record.set_info(info);
    }
}

/// Add the namespace device `device` with the resources its `_CRS` gives.
fn add_namespace_device(device: &aml::AmlDevice<'_>, records: &mut PlatformRecords)
{
    let identity = Identity {
        hid: device.hid,
        cids: device.cids,
        ..Identity::default()
    };
    let mut resources = [None; firmware::records::MAX_RECORD_RESOURCES];
    let mut count = 0;
    if let Some(crs) = device.crs
    {
        aml::crs_resources(crs, |r| {
            if let Some(slot) = resources.get_mut(count)
            {
                *slot = Some(r);
                count += 1;
            }
        });
    }
    records.add(identity, resources.into_iter().flatten());
}

/// Attach the FADT's `CENTURY` index as device info to every record that
/// carries a CMOS RTC identifier: the driver reads the century from that
/// register. Nothing is attached when the FADT names none.
fn attach_century(caps: &caps::DevmgrCaps, records: &mut PlatformRecords)
{
    let index = tables::locate_table_by_sig(caps, *b"FACP")
        .and_then(|fadt| tables::with_acpi_table(caps, fadt, firmware::acpi::fadt_century_index));
    let Some(info) = index.and_then(|i| {
        DeviceInfo::new(
            ipc::device_info_kind::RTC_CENTURY,
            ipc::device_info_kind::RTC_CENTURY_VERSION,
            &[i],
        )
    })
    else
    {
        return;
    };
    for i in 0..records.records().len()
    {
        let identity = records.records()[i].identity();
        let cmos = identity
            .hid
            .iter()
            .chain(identity.cids.iter().flatten())
            .any(|id| CMOS_RTC_IDS.contains(&id.as_bytes()));
        if cmos && let Some(record) = records.get_mut(i)
        {
            record.set_info(info);
        }
    }
}

/// Add the devices of the platform description table among `tables_found`
/// whose OEM table ID is `oem_table_id`. With no such table no device is
/// added, logged once.
fn platform_table(
    oem_table_id: Option<[u8; 8]>,
    tables_found: &[PlatformTable],
    records: &mut PlatformRecords,
)
{
    let table = oem_table_id.and_then(|id| tables_found.iter().find(|t| t.is_for(&id)));
    let Some(table) = table
    else
    {
        std::os::seraph::log!(
            "no platform description table for this machine; no platform-table records"
        );
        return;
    };
    for device in table.devices()
    {
        let Some(key) = PlatformKey::new(device.key())
        else
        {
            continue;
        };
        let identity = Identity {
            platform: Some(key),
            ..Identity::default()
        };
        let resources = device.resources().map(|r| match r
        {
            PlatformResource::Mmio { base, size } => CrsResource::Mmio { base, size },
            PlatformResource::IoPort { base, count } => CrsResource::IoPort { base, count },
            PlatformResource::Wired { line, mode } => CrsResource::Interrupt {
                line,
                mode,
                shared: false,
                isa: false,
            },
        });
        records.add(identity, resources);
    }
}

/// Log record `index`: its first key and its resources.
fn log_record(index: usize, record: &firmware::records::PlatformRecord)
{
    let key = record.with_keys(|k| {
        let mut name = [0u8; 32];
        let src: &[u8] = k
            .acpi_hid
            .or(k.platform)
            .or_else(|| k.acpi_cids.first().copied())
            .unwrap_or(if k.boot_framebuffer
            {
                b"boot-framebuffer"
            }
            else
            {
                b"spcr"
            });
        let n = src.len().min(name.len());
        name[..n].copy_from_slice(&src[..n]);
        (name, n)
    });
    let name = core::str::from_utf8(&key.0[..key.1]).unwrap_or("?");
    std::os::seraph::log!("platform record {}: {}", index, name);
    for r in record.resources()
    {
        match r
        {
            CrsResource::Mmio { base, size } =>
            {
                std::os::seraph::log!("  mmio {:#x}+{:#x}", base, size);
            }
            CrsResource::IoPort { base, count } =>
            {
                std::os::seraph::log!("  io {:#x}+{}", base, count);
            }
            CrsResource::Interrupt {
                line, mode, isa, ..
            } =>
            {
                std::os::seraph::log!("  irq {} mode {:#x} isa {}", line, mode, isa);
            }
        }
    }
}
