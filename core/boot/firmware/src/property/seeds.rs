// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/property/seeds.rs

//! The aperture seeds' contract: a seed of no bytes is never one, every
//! seed found is counted and written while its buffer has room, and an ACPI
//! table's seeds are the windows its structures name, in table order, as
//! `crate::seeds` lists them.

use boot_protocol::MmioAperture;
use firmware_tables::acpi::sdt_signature;
use firmware_tables::dmar::drhd_units;

use super::{byte, le32, le64};
use crate::acpi::{madt_entries, madt_lapic_base};
use crate::seeds::{AcpiSeedProfile, Seeds, acpi_table_seeds, madt_structure_seed, pci_windows};

/// Seeds of each kind the check collects.
const MAX_SEEDS: usize = 32;

/// Check the seeds of `input`, read as an ACPI table, under two profiles.
///
/// # Panics
///
/// When the seeds break their contract.
pub(crate) fn seeds_holds(input: &[u8])
{
    for profile in [
        AcpiSeedProfile {
            max_phys_addr_bits: 46,
            tpm_window: Some((0xfed4_0000, 0x5000)),
        },
        AcpiSeedProfile {
            max_phys_addr_bits: u32::from(input.first().copied().unwrap_or(0)),
            tpm_window: None,
        },
    ]
    {
        table_seeds_holds(input, &profile);
    }
    if let Some(&kind) = input.first()
    {
        structure_seed_holds(kind, input);
    }
    if let (Some(base), Some(&bits)) = (le64(input, 0), input.get(8))
    {
        pci_windows_holds(base, u32::from(bits));
        push_holds(
            (usize::from(bits & 3), usize::from((bits >> 2) & 3)),
            base,
            le64(input, 1).unwrap_or(0) & 0xff,
        );
    }
}

/// Check the heuristic windows of an ECAM whose bus 0 decodes at `base`.
///
/// # Panics
///
/// When the windows break their contract.
pub(crate) fn pci_windows_holds(base: u64, bits: u32)
{
    let (lo, hi) = pci_windows(base, bits);
    if base < 1 << 31
    {
        assert_eq!((lo, hi), ((1 << 30, 1 << 30), (1 << 34, 1 << 34)));
        return;
    }
    assert_eq!(lo, (1 << 31, base.saturating_sub(1 << 31)));
    let top = if bits >= 64 { u64::MAX } else { 1u64 << bits };
    assert_eq!(hi, (1 << 32, top.saturating_sub(1 << 32)));
    // Neither window wraps the address space.
    assert!(lo.0.checked_add(lo.1).is_some() && hi.0.checked_add(hi.1).is_some());
}

/// Check one seed of `size` bytes at `base`, named and heuristic, into
/// buffers of `room` named and heuristic slots, each at most 2.
///
/// # Panics
///
/// When the collection breaks its contract.
pub(crate) fn push_holds(room: (usize, usize), base: u64, size: u64)
{
    let zero = MmioAperture {
        phys_base: 0,
        size: 0,
    };
    let (mut named, mut heur) = ([zero; 2], [zero; 2]);
    let mut seeds = Seeds::new(
        named.get_mut(..room.0.min(2)).unwrap_or_default(),
        heur.get_mut(..room.1.min(2)).unwrap_or_default(),
    );
    seeds.named(base, size);
    seeds.heuristic(base, size);
    let (written, found) = (seeds.written, seeds.found);
    // A seed of no bytes is none; any other is counted, and written while
    // its buffer has a slot.
    let one = usize::from(size != 0);
    assert_eq!(found, (one, one));
    assert_eq!(written, (one.min(room.0.min(2)), one.min(room.1.min(2))));
    let at = |w: usize| if w == 1 { (base, size) } else { (0, 0) };
    assert_eq!(pair(&named[0]), at(written.0));
    assert_eq!(pair(&heur[0]), at(written.1));
}

/// An aperture's base and size, which `MmioAperture` does not compare.
fn pair(aperture: &MmioAperture) -> (u64, u64)
{
    (aperture.phys_base, aperture.size)
}

/// The seed of one MADT structure `e` of type `kind` as its layout gives
/// it to `named`: an I/O APIC's page (12 bytes, base at 4), an APLIC's
/// window (36 bytes, base at 24, size at 32), an enabled RINTC's IMSIC file
/// (36 bytes, flags bit 0 at 4, base at 24, size at 32) with a non-zero base
/// and an end inside the address space.
fn structure_reading(kind: u8, e: &[u8], named: &mut impl FnMut(u64, u64))
{
    match kind
    {
        1 if e.len() >= 12 => named(u64::from(le32(e, 4).unwrap_or(0)), 0x1000),
        0x1A if e.len() >= 36 => named(
            le64(e, 24).unwrap_or(0),
            u64::from(le32(e, 32).unwrap_or(0)),
        ),
        0x18 if e.len() >= 36 && le32(e, 4).unwrap_or(0) & 1 != 0 =>
        {
            let (base, size) = (
                le64(e, 24).unwrap_or(0),
                u64::from(le32(e, 32).unwrap_or(0)),
            );
            if base != 0 && base.checked_add(size).is_some()
            {
                named(base, size);
            }
        }
        _ =>
        {}
    }
}

/// Check the seed of one MADT structure `entry` of type `kind`.
///
/// # Panics
///
/// When the seed breaks its contract.
pub(crate) fn structure_seed_holds(kind: u8, entry: &[u8])
{
    let zero = MmioAperture {
        phys_base: 0,
        size: 0,
    };
    let mut want = None;
    structure_reading(kind, entry, &mut |b, s| {
        want = Some(MmioAperture {
            phys_base: b,
            size: s,
        });
    });
    let want = want.filter(|w| w.size != 0);
    let (mut named, mut heur) = ([zero; 2], [zero; 1]);
    let mut seeds = Seeds::new(&mut named, &mut heur);
    madt_structure_seed(kind, entry, &mut seeds);
    assert_eq!(seeds.found, (usize::from(want.is_some()), 0));
    assert_eq!(
        named.each_ref().map(pair),
        [want.as_ref().map_or((0, 0), pair), (0, 0)]
    );
}

/// The seeds of `table` as its layout gives them, each to `named` or
/// `heuristic`.
fn reading(
    table: &[u8],
    profile: &AcpiSeedProfile,
    named: &mut impl FnMut(u64, u64),
    heuristic: &mut impl FnMut(u64, u64),
)
{
    match &sdt_signature(table)
    {
        b"APIC" =>
        {
            for (kind, e) in madt_entries(table)
            {
                structure_reading(kind, e, named);
            }
            let lapic = madt_lapic_base(table);
            if lapic != 0
            {
                named(lapic, 0x1000);
            }
        }
        b"MCFG" =>
        {
            // Allocation entries of 16 bytes from 44, within the length the
            // header reports: base (u64), segment (u16), start and end bus.
            let len = le32(table, 4).map_or(0, |l| (l as usize).min(table.len()));
            let mut at = 44usize;
            while len >= 36 && at.saturating_add(16) <= len
            {
                let base = le64(table, at).unwrap_or(0);
                let (start, end) = (
                    byte(table, at.saturating_add(10)).unwrap_or(0),
                    byte(table, at.saturating_add(11)).unwrap_or(0),
                );
                let window = base.checked_add(u64::from(start) << 20);
                let size = (u64::from(end) + 1).saturating_sub(u64::from(start)) << 20;
                if let Some(window) = window
                    && base != 0
                    && end >= start
                    && window.checked_add(size).is_some()
                {
                    named(window, size);
                    let (lo, hi) = pci_windows(base, profile.max_phys_addr_bits);
                    heuristic(lo.0, lo.1);
                    heuristic(hi.0, hi.1);
                }
                at = at.saturating_add(16);
            }
        }
        b"DMAR" =>
        {
            for unit in drhd_units(table)
            {
                if let Some(size) = unit.register_pages.checked_mul(4096)
                    && unit.register_base.checked_add(size).is_some()
                {
                    named(unit.register_base, size);
                }
            }
        }
        b"TPM2" =>
        {
            if let Some((base, size)) = crate::acpi::tpm2_register_window(table, profile.tpm_window)
            {
                named(base, size);
            }
        }
        _ =>
        {}
    }
}

/// Check the seeds of `table` under `profile`: those the walk collects are
/// those the reading gives, less the seeds of no bytes, in order, and a
/// buffer too short keeps the first ones and counts the rest.
///
/// # Panics
///
/// When the seeds break their contract.
pub(crate) fn table_seeds_holds(table: &[u8], profile: &AcpiSeedProfile)
{
    let zero = MmioAperture {
        phys_base: 0,
        size: 0,
    };
    let mut want_named = [zero; MAX_SEEDS];
    let mut want_heur = [zero; MAX_SEEDS];
    let mut counts = (0usize, 0usize);
    {
        let mut named = |b, s| {
            if s != 0
            {
                if let Some(slot) = want_named.get_mut(counts.0)
                {
                    *slot = MmioAperture {
                        phys_base: b,
                        size: s,
                    };
                }
                counts.0 = counts.0.saturating_add(1);
            }
        };
        let mut heur_counts = 0usize;
        let mut heuristic = |b, s| {
            if s != 0
            {
                if let Some(slot) = want_heur.get_mut(heur_counts)
                {
                    *slot = MmioAperture {
                        phys_base: b,
                        size: s,
                    };
                }
                heur_counts = heur_counts.saturating_add(1);
            }
        };
        reading(table, profile, &mut named, &mut heuristic);
        counts.1 = heur_counts;
    }
    let mut named = [zero; MAX_SEEDS];
    let mut heur = [zero; MAX_SEEDS];
    let mut seeds = Seeds::new(&mut named, &mut heur);
    acpi_table_seeds(table, profile, &mut seeds);
    assert_eq!(seeds.found, counts);
    assert_eq!(
        seeds.written,
        (counts.0.min(MAX_SEEDS), counts.1.min(MAX_SEEDS))
    );
    let written = seeds.written;
    assert!(
        named
            .iter()
            .take(written.0)
            .map(pair)
            .eq(want_named.iter().take(written.0).map(pair))
    );
    assert!(
        heur.iter()
            .take(written.1)
            .map(pair)
            .eq(want_heur.iter().take(written.1).map(pair))
    );

    let mut counting = Seeds::counting();
    acpi_table_seeds(table, profile, &mut counting);
    assert_eq!((counting.found, counting.written), (counts, (0, 0)));
}
