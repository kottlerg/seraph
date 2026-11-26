// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/property/acpi.rs

//! The ACPI readings' contract: each MADT structure, RHCT node, SSDT, TPM2,
//! DMAR unit and SPCR reads as ACPI 6.5 § 5.2.12, the RHCT (ACPI 6.6
//! § 5.2.37), QEMU's VMGENID SSDT, the TCG ACPI Specification, Intel VT-d 4.1
//! § 8.3 and the SPCR lay it out, and the walks over them (the MADT's AIA
//! controllers, the RHCT's nodes, the SSDTs' VMGENID) combine their steps as
//! their documents say.

use boot_protocol::{AplicDomain, ImsicLayout};
use firmware_tables::acpi::madt_structures;
use firmware_tables::dmar::{DrhdUnit, drhd_units};

use super::{byte, le16, le32, le64};
use crate::acpi::{
    IoApic, MadtAia, aplic_structure, drhd_register_window, file_on_layout, find_vgia, imsic_base,
    imsic_structure, lapic_override, madt_aia, madt_cpu_id, madt_cpu_ids, madt_entries,
    madt_io_apic, madt_lapic_base, pick_vmgenid, rhct_hart_caps, rhct_node, rhct_node_isa,
    rintc_imsic_file, spcr_mmio_base, ssdt_vmgenid, tpm2_register_window, vmgenid_guid,
};
use crate::isa::{HART_CAP_NAMES, isa_string_has_ext};

/// The TPM window the check gives a platform: the x86-64 locality-0 to
/// locality-4 window.
const PLATFORM_TPM: (u64, u64) = (0xfed4_0000, 0x5000);

/// Check every ACPI reading on `input`, read as a MADT structure (its first
/// byte the type), a MADT, an RHCT, an SSDT, a TPM2, a DMAR and an SPCR.
///
/// # Panics
///
/// When a reading breaks its contract on `input`.
pub(crate) fn acpi_holds(input: &[u8])
{
    if let Some(&kind) = input.first()
    {
        structure_holds(kind, input);
    }
    madt_holds(input);
    rhct_holds(input);
    vgia_holds(input);
    tpm2_holds(input, Some(PLATFORM_TPM));
    tpm2_holds(input, None);
    for unit in drhd_units(input)
    {
        drhd_holds(&unit);
    }
    spcr_holds(input);
}

/// Check every reading of one MADT structure `entry` of type `kind`.
///
/// # Panics
///
/// When a reading breaks its contract.
pub(crate) fn structure_holds(kind: u8, entry: &[u8])
{
    let n = entry.len();
    // Processor Local APIC (0, 8 bytes) and Local x2APIC (9, 16 bytes):
    // enabled or online-capable; RINTC (0x18, through its UID at 20): enabled.
    let cpu = match kind
    {
        0 if n >= 8 =>
        {
            (le32(entry, 4).unwrap_or(0) & 3 != 0).then(|| u32::from(byte(entry, 3).unwrap_or(0)))
        }
        9 if n >= 16 => (le32(entry, 8).unwrap_or(0) & 3 != 0).then(|| le32(entry, 4).unwrap_or(0)),
        // The low 32 bits of the 64-bit hart ID.
        0x18 if n >= 20 && le32(entry, 4).unwrap_or(0) & 1 != 0 => le32(entry, 8),
        _ => None,
    };
    assert_eq!(madt_cpu_id(kind, entry), cpu);

    // RINTC: enabled and through its hart ID; its IMSIC file from 36 bytes.
    let file = (kind == 0x18 && n >= 16 && le32(entry, 4).unwrap_or(0) & 1 != 0).then(|| {
        let hart = le64(entry, 8).unwrap_or(0);
        if n >= 36
        {
            (
                hart,
                le64(entry, 24).unwrap_or(0),
                u64::from(le32(entry, 32).unwrap_or(0)),
            )
        }
        else
        {
            (hart, 0, 0)
        }
    });
    assert_eq!(rintc_imsic_file(kind, entry), file);

    // IMSIC (0x19, 16 bytes).
    let imsic = (kind == 0x19 && n >= 16).then(|| ImsicLayout {
        base: 0,
        ids: u32::from(le16(entry, 8).unwrap_or(0)),
        guest_index_bits: byte(entry, 12).unwrap_or(0),
        hart_index_bits: byte(entry, 13).unwrap_or(0),
        group_index_bits: byte(entry, 14).unwrap_or(0),
        group_index_shift: byte(entry, 15).unwrap_or(0),
    });
    assert_eq!(imsic_structure(kind, entry), imsic);

    // APLIC (0x1A, 36 bytes) with a non-zero base.
    let aplic_base = le64(entry, 24).unwrap_or(0);
    let aplic = (kind == 0x1A && n >= 36 && aplic_base != 0).then(|| AplicDomain {
        base: aplic_base,
        size: u64::from(le32(entry, 32).unwrap_or(0)),
        sources: u64::from(le16(entry, 18).unwrap_or(0)),
    });
    assert_eq!(aplic_structure(kind, entry), aplic);

    // Local APIC Address Override (5) and I/O APIC (1), 12 bytes each.
    assert_eq!(
        lapic_override(kind, entry),
        (kind == 5 && n >= 12).then(|| le64(entry, 4).unwrap_or(0))
    );
    assert_eq!(
        madt_io_apic(kind, entry),
        (kind == 1 && n >= 12).then(|| IoApic {
            id: u32::from(byte(entry, 2).unwrap_or(0)),
            phys_base: u64::from(le32(entry, 4).unwrap_or(0)),
            gsi_base: le32(entry, 8).unwrap_or(0),
        })
    );
}

/// Check the IMSIC layout's base and file steps for one hart.
///
/// # Panics
///
/// When a step breaks its contract.
pub(crate) fn layout_step_holds(layout: &ImsicLayout, hart: u64, addr: u64)
{
    let base = imsic_base(layout, hart, addr);
    match layout.s_file_offset(hart)
    {
        Some(offset) if let Some(d) = addr.checked_sub(offset) => assert_eq!(base, d),
        _ => assert_eq!(base, 0),
    }
    assert_eq!(
        file_on_layout(layout, hart, addr),
        addr != 0 && layout.s_file_address(hart) == Some(addr)
    );
}

/// Check the MADT walks of `madt`: its structures as `madt_entries` yields
/// them, each structure's readings, the CPU IDs, the AIA controllers and the
/// Local APIC base, in step with the walk.
///
/// # Panics
///
/// When a walk breaks its contract.
pub(crate) fn madt_holds(madt: &[u8])
{
    let mut entries = madt_entries(madt);
    for (kind, at, len) in madt_structures(madt).into_iter().flatten()
    {
        let entry = madt.get(at..at.saturating_add(len)).unwrap_or_default();
        assert_eq!(entries.next(), Some((kind, entry)));
        assert_eq!(byte(entry, 0), Some(kind));
        structure_holds(kind, entry);
    }
    assert_eq!(entries.next(), None);

    let mut ids = madt_cpu_ids(madt);
    for (kind, entry) in madt_entries(madt)
    {
        if let Some(id) = madt_cpu_id(kind, entry)
        {
            assert_eq!(ids.next(), Some(id));
        }
    }
    assert_eq!(ids.next(), None);

    let lapic = madt_entries(madt)
        .filter_map(|(k, e)| lapic_override(k, e))
        .last()
        .unwrap_or_else(|| u64::from(le32(madt, 36).unwrap_or(0)));
    assert_eq!(madt_lapic_base(madt), lapic);

    aia_holds(madt, &madt_aia(madt));
}

/// Check the AIA controllers `aia` the MADT `madt` reports.
fn aia_holds(madt: &[u8], aia: &MadtAia)
{
    let aplic = madt_entries(madt)
        .find_map(|(k, e)| aplic_structure(k, e))
        .unwrap_or(AplicDomain::zero());
    assert_eq!(aia.aplic, aplic);
    let layout = madt_entries(madt).find_map(|(k, e)| imsic_structure(k, e));
    let mut files = madt_entries(madt).filter_map(|(k, e)| rintc_imsic_file(k, e));
    let first = madt_entries(madt).find_map(|(k, e)| rintc_imsic_file(k, e));
    let (Some(mut layout), Some((hart, addr, _))) = (layout, first)
    else
    {
        assert_eq!(
            (aia.imsic, aia.off_layout_hart),
            (ImsicLayout::zero(), None)
        );
        return;
    };
    layout.base = imsic_base(&layout, hart, addr);
    layout_step_holds(&layout, hart, addr);
    match files.find(|&(h, a, _)| !file_on_layout(&layout, h, a))
    {
        Some((h, ..)) =>
        {
            assert_eq!(
                (aia.imsic, aia.off_layout_hart),
                (ImsicLayout::zero(), Some(h))
            );
        }
        None => assert_eq!((aia.imsic, aia.off_layout_hart), (layout, None)),
    }
}

/// The `HART_CAP_*` bits an ISA string names, read as underscore-separated
/// segments up to its first NUL.
fn isa_caps(isa: &[u8]) -> u64
{
    let nul = (0..isa.len()).find(|&at| isa.get(at) == Some(&0));
    let isa = isa.get(..nul.unwrap_or(isa.len())).unwrap_or_default();
    let mut caps = 0;
    for (ext, bit) in HART_CAP_NAMES
    {
        let mut start = 0;
        for at in 0..=isa.len()
        {
            if at == isa.len() || isa.get(at) == Some(&b'_')
            {
                if isa.get(start..at) == Some(ext)
                {
                    caps |= bit;
                }
                start = at.saturating_add(1);
            }
        }
    }
    caps
}

/// Check the ISA-string reading of `isa` for every recognized extension.
///
/// # Panics
///
/// When the reading breaks its contract.
pub(crate) fn isa_holds(isa: &[u8])
{
    let caps = isa_caps(isa);
    let has = HART_CAP_NAMES.map(|(ext, _)| isa_string_has_ext(isa, ext));
    for ((_, bit), has) in HART_CAP_NAMES.iter().zip(has)
    {
        assert_eq!(has, caps & bit != 0);
    }
    // The names are the table's own, so the lookup compares constants.
    assert_eq!(
        crate::isa::hart_caps(|ext| HART_CAP_NAMES
            .iter()
            .zip(has)
            .any(|((name, _), has)| *name == ext && has)),
        caps
    );
}

/// Check the RHCT node at `off` of `rhct`: its bounds and its ISA string's
/// (`rhct_node_isa_holds`), and the reading of the string (`isa_holds`).
///
/// # Panics
///
/// When the node's reading breaks its contract.
pub(crate) fn rhct_node_holds(rhct: &[u8], off: usize)
{
    rhct_node_isa_holds(rhct, off);
    let got = rhct_node(rhct, off);
    let Some((isa, end)) = rhct_node_isa(rhct, off)
    else
    {
        assert_eq!(got, None);
        return;
    };
    let caps = isa.map(|isa| {
        isa_holds(isa);
        isa_caps(isa)
    });
    assert_eq!(got, Some((caps, end)));
}

/// Check the bounds of the RHCT node at `off` of `rhct` and of its ISA
/// string.
///
/// # Panics
///
/// When the node's reading breaks its contract.
pub(crate) fn rhct_node_isa_holds(rhct: &[u8], off: usize)
{
    let got = rhct_node_isa(rhct, off);
    let (Some(kind), Some(len)) = (
        le16(rhct, off),
        off.checked_add(2).and_then(|a| le16(rhct, a)),
    )
    else
    {
        assert_eq!(got, None);
        return;
    };
    let len = usize::from(len);
    let end = off.checked_add(len);
    if off.checked_add(6).is_none_or(|e| e > rhct.len())
        || len < 6
        || end.is_none_or(|e| e > rhct.len())
    {
        assert_eq!(got, None);
        return;
    }
    let end = off.saturating_add(len);
    // The string's place in `rhct`, so that a slice of equal bytes elsewhere
    // does not pass for it.
    let at = |s: &[u8]| {
        (
            s.as_ptr().addr().wrapping_sub(rhct.as_ptr().addr()),
            s.len(),
        )
    };
    let isa = (kind == 0 && len >= 8).then(|| {
        let isa_len = usize::from(le16(rhct, off.saturating_add(6)).unwrap_or(0));
        let start = off.saturating_add(8);
        (
            start,
            start.saturating_add(isa_len).min(end).saturating_sub(start),
        )
    });
    assert_eq!(got.map(|(s, e)| (s.map(at), e)), Some((isa, end)));
}

/// Check the RHCT walk over `rhct`, in step with its nodes.
///
/// # Panics
///
/// When the walk breaks its contract.
pub(crate) fn rhct_holds(rhct: &[u8])
{
    let count = le32(rhct, 48).unwrap_or(0);
    let mut off = le32(rhct, 52).unwrap_or(0) as usize;
    let mut nodes = 0usize;
    let mut caps = u64::MAX;
    for _ in 0..count
    {
        rhct_node_holds(rhct, off);
        let Some((node_caps, next)) = rhct_node(rhct, off)
        else
        {
            break;
        };
        // A node is at least 6 bytes long, so the walk moves forward.
        assert!(next >= off.saturating_add(6));
        if let Some(c) = node_caps
        {
            nodes = nodes.saturating_add(1);
            caps &= c;
        }
        off = next;
    }
    assert_eq!(
        rhct_hart_caps(rhct),
        (
            le64(rhct, 40).unwrap_or(0),
            if nodes > 0 { caps } else { 0 }
        )
    );
}

/// Check the `VGIA` search and the VMGENID reading of `table`, read as an
/// SSDT. Returns the reading.
///
/// # Panics
///
/// When the search breaks its contract.
pub(crate) fn vgia_search_holds(table: &[u8]) -> Option<(u64, bool)>
{
    let pattern = [0x08, b'V', b'G', b'I', b'A', 0x0C];
    let mut found = None;
    if table.len() > 36
    {
        for at in 36..table.len()
        {
            if table.get(at..at.saturating_add(6)) == Some(&pattern[..])
            {
                found = Some(at.saturating_add(6));
                break;
            }
        }
    }
    let base = found
        .and_then(|at| le32(table, at))
        .filter(|&b| b != 0 && b % 4096 == 0);
    assert_eq!(find_vgia(table), base);
    let vmgenid = base.and_then(|b| {
        let oem = table.get(16..24)?;
        Some((u64::from(b) + 40, oem.starts_with(b"VMGENID")))
    });
    assert_eq!(ssdt_vmgenid(table), vmgenid);
    vmgenid
}

/// Check the `VGIA` search and the VMGENID reading of `table`, read as an
/// SSDT, and the choice over it, alone and twice over.
///
/// # Panics
///
/// When the search or the choice breaks its contract.
pub(crate) fn vgia_holds(table: &[u8])
{
    let vmgenid = vgia_search_holds(table);
    let guid = vmgenid.map_or(0, |(g, _)| g);
    assert_eq!(vmgenid_guid([table]), guid);
    assert_eq!(vmgenid_guid([table, table]), guid);
    assert_eq!(vmgenid_guid([&[][..], table]), guid);
    pick_holds([vmgenid, None, vmgenid]);
}

/// Check the choice of a VMGENID GUID over three SSDTs' readings
/// `readings`: the first marked one's, else the first one's with a GUID.
///
/// # Panics
///
/// When the choice breaks its contract.
pub(crate) fn pick_holds(readings: [Option<(u64, bool)>; 3])
{
    let marked = readings.iter().flatten().find(|(_, m)| *m);
    let first = readings.iter().flatten().next();
    let guid = marked.or(first).map_or(0, |(g, _)| *g);
    assert_eq!(pick_vmgenid(readings), guid);
}

/// Check the TPM2 window `table` and the platform's window `platform` give.
///
/// # Panics
///
/// When the reading breaks its contract.
pub(crate) fn tpm2_holds(table: &[u8], platform: Option<(u64, u64)>)
{
    let window = match (platform, le32(table, 48))
    {
        (Some(p), Some(6)) => Some(p),
        (Some((base, size)), Some(7)) =>
        {
            let control = le64(table, 40).unwrap_or(0);
            control
                .checked_sub(base)
                .is_some_and(|d| d < size)
                .then_some((base, size))
        }
        _ => None,
    };
    assert_eq!(tpm2_register_window(table, platform), window);
}

/// Check one remapping unit's register window.
///
/// # Panics
///
/// When the window breaks its contract.
pub(crate) fn drhd_holds(unit: &DrhdUnit)
{
    let window = unit
        .register_pages
        .checked_mul(4096)
        .filter(|&size| unit.register_base.checked_add(size).is_some())
        .map(|size| (unit.register_base, size));
    assert_eq!(drhd_register_window(unit), window);
}

/// Check the SPCR's MMIO base.
///
/// # Panics
///
/// When the reading breaks its contract.
pub(crate) fn spcr_holds(table: &[u8])
{
    let base = firmware_tables::spcr::spcr(table).and_then(|s| match s.base
    {
        firmware_tables::spcr::SpcrBase::Mmio(b) => Some(b),
        firmware_tables::spcr::SpcrBase::IoPort(_) => None,
    });
    assert_eq!(spcr_mmio_base(table), base);
}
