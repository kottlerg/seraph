// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/seeds.rs

//! The MMIO aperture seeds the firmware tables name: the register windows of
//! the devices the kernel or a driver reaches, and the heuristic PCI windows,
//! which `core/boot`'s `memory_map::derive_mmio_apertures` merges into the
//! boot protocol's MMIO apertures (`core/boot/docs/firmware-parsing.md`
//! § Firmware exclusion).
//!
//! [`Seeds`] collects them into the caller's buffers, counting those past a
//! full buffer, so one walk with empty buffers sizes the buffers of the next.
//! [`acpi_table_seeds`] reads one ACPI table's; the device tree's are
//! [`crate::dtb::Tree::seeds`].

use boot_protocol::MmioAperture;
use firmware_tables::acpi::{madt_structures, mcfg_ecams, sdt_signature};

use crate::acpi::{
    dmar_register_windows, madt_lapic_base, madt_len, madt_type, tpm2_register_window,
};
use firmware_tables::bytes::{read_u32, read_u64};

/// The register window of one I/O APIC or Local APIC: one page.
const APIC_WINDOW: u64 = 0x1000;

/// The register-window and heuristic-window seeds a walk finds, written into
/// two caller buffers.
pub struct Seeds<'a>
{
    named: &'a mut [MmioAperture],
    heuristic: &'a mut [MmioAperture],
    /// Seeds written into the named and the heuristic buffer.
    pub written: (usize, usize),
    /// Seeds found, written or past a full buffer.
    pub found: (usize, usize),
}

impl<'a> Seeds<'a>
{
    /// Collect into `named` (register windows a table names) and `heuristic`
    /// (PCI windows a layout heuristic places).
    pub fn new(named: &'a mut [MmioAperture], heuristic: &'a mut [MmioAperture]) -> Self
    {
        Self {
            named,
            heuristic,
            written: (0, 0),
            found: (0, 0),
        }
    }

    /// Count the seeds and write none: the sizing walk.
    #[must_use]
    pub fn counting() -> Seeds<'static>
    {
        Seeds {
            named: &mut [],
            heuristic: &mut [],
            written: (0, 0),
            found: (0, 0),
        }
    }

    /// A register window `[base, base + size)` a table names; one of no
    /// bytes is not a seed.
    pub fn named(&mut self, base: u64, size: u64)
    {
        push(
            self.named,
            &mut self.written.0,
            &mut self.found.0,
            base,
            size,
        );
    }

    /// A heuristic PCI window `[base, base + size)`; one of no bytes is not a
    /// seed.
    pub fn heuristic(&mut self, base: u64, size: u64)
    {
        push(
            self.heuristic,
            &mut self.written.1,
            &mut self.found.1,
            base,
            size,
        );
    }
}

/// Count a seed of `size` bytes in `found`, and write it to `out[*written]`
/// when `out` has room. A seed of no bytes is dropped.
fn push(out: &mut [MmioAperture], written: &mut usize, found: &mut usize, phys_base: u64, size: u64)
{
    if size == 0
    {
        return;
    }
    // One per seed of one walk over bounded tables, far below `usize::MAX`.
    *found = found.saturating_add(1);
    if let Some(slot) = out.get_mut(*written)
    {
        *slot = MmioAperture { phys_base, size };
        // `*written` indexed a slot of `out`, so it is below `out.len()`.
        *written = written.saturating_add(1);
    }
}

/// What the ACPI seed walk takes from the architecture it runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcpiSeedProfile
{
    /// The CPU's physical address width, which bounds the q35 heuristic's
    /// 64-bit PCI window.
    pub max_phys_addr_bits: u32,
    /// The platform's TPM register window, which a `TPM2` table confirms
    /// ([`crate::acpi::tpm2_register_window`]); `None` where the platform has
    /// none.
    pub tpm_window: Option<(u64, u64)>,
}

/// Add the seeds of the ACPI table `table` to `seeds`:
/// - `APIC` (MADT): each I/O APIC's page, each APLIC's window, each
///   supervisor-level IMSIC file an enabled RINTC names, and the Local APIC
///   page ([`madt_lapic_base`]) when non-zero.
/// - `MCFG`: each ECAM window, and from each the heuristic 32-bit and 64-bit
///   PCI windows ([`pci_windows`]).
/// - `DMAR`: each VT-d remapping unit's register set.
/// - `TPM2`: the platform's TPM window, when the table names an interface the
///   TPM driver speaks.
///
/// Any other table adds nothing.
pub fn acpi_table_seeds(table: &[u8], profile: &AcpiSeedProfile, seeds: &mut Seeds<'_>)
{
    match &sdt_signature(table)
    {
        b"APIC" => madt_seeds(table, seeds),
        b"MCFG" =>
        {
            for ecam in mcfg_ecams(table)
            {
                seeds.named(ecam.phys_base, ecam.size);
                // The entry's base address, where bus 0 would decode: the
                // window less its start bus, which `mcfg_entry_ecam` added
                // without overflow.
                let base = ecam
                    .phys_base
                    .saturating_sub(u64::from(ecam.start_bus) << 20);
                let (lo, hi) = pci_windows(base, profile.max_phys_addr_bits);
                seeds.heuristic(lo.0, lo.1);
                seeds.heuristic(hi.0, hi.1);
            }
        }
        b"DMAR" =>
        {
            for (base, size) in dmar_register_windows(table)
            {
                seeds.named(base, size);
            }
        }
        b"TPM2" =>
        {
            if let Some((base, size)) = tpm2_register_window(table, profile.tpm_window)
            {
                seeds.named(base, size);
            }
        }
        _ =>
        {}
    }
}

/// The seeds of the MADT `madt` ([`acpi_table_seeds`]).
fn madt_seeds(madt: &[u8], seeds: &mut Seeds<'_>)
{
    for (kind, at, len) in madt_structures(madt).into_iter().flatten()
    {
        let Some(entry) = madt.get(at..at.saturating_add(len))
        else
        {
            continue;
        };
        madt_structure_seed(kind, entry, seeds);
    }
    let lapic = madt_lapic_base(madt);
    if lapic != 0
    {
        seeds.named(lapic, APIC_WINDOW);
    }
}

/// The seed of one MADT structure `entry` of type `kind`, if it names one:
/// an I/O APIC's page, an APLIC's window (`+24` base, `+32` size), or the
/// supervisor-level IMSIC file of an enabled RINTC (`+24` base, `+32` size)
/// with a non-zero base and an end inside the address space.
/// `derive_mmio_apertures` merges abutting files into one aperture per IMSIC
/// group and leaves the gaps between groups, which no table names, unseeded.
pub fn madt_structure_seed(kind: u8, entry: &[u8], seeds: &mut Seeds<'_>)
{
    match kind
    {
        madt_type::IO_APIC if entry.len() >= madt_len::IO_APIC =>
        {
            seeds.named(u64::from(read_u32(entry, 4)), APIC_WINDOW);
        }
        madt_type::APLIC if entry.len() >= madt_len::APLIC =>
        {
            seeds.named(read_u64(entry, 24), u64::from(read_u32(entry, 32)));
        }
        madt_type::RINTC
            if entry.len() >= madt_len::RINTC_IMSIC && read_u32(entry, 4) & 0x1 != 0 =>
        {
            let base = read_u64(entry, 24);
            let size = u64::from(read_u32(entry, 32));
            if base != 0 && base.checked_add(size).is_some()
            {
                seeds.named(base, size);
            }
        }
        // A Local APIC Address Override names the Local APIC's page, which
        // `madt_lapic_base` resolves over the whole table.
        _ =>
        {}
    }
}

/// The heuristic `((base, size), (base, size))` 32-bit and 64-bit PCI MMIO
/// windows for an MCFG entry whose bus 0 decodes at `ecam_base`.
///
/// Real hardware advertises its PCI windows through the host bridge's
/// `_CRS`, which the bootloader does not evaluate (it runs before acpid,
/// the AML-evaluating service; `services/acpid/README.md`), so the windows
/// follow QEMU's layouts:
/// - ECAM below 2 GiB, QEMU `virt` (RISC-V): the 32-bit window
///   `[1 GiB, 2 GiB)`, which QEMU fixes, and the 64-bit window
///   `[16 GiB, 32 GiB)`, which is QEMU's only for guests with at most about
///   14 GiB of RAM, because QEMU rounds the window's base up past the end of
///   RAM.
/// - ECAM at 2 GiB or above, q35 (x86-64): the 32-bit window from 2 GiB to
///   the ECAM base, and the 64-bit window `[4 GiB, 1 << max_phys_addr_bits)`,
///   which covers wherever firmware places it without per-CPU tuning.
///
/// Neither window is bounded by the memory map: the q35 32-bit window covers
/// low RAM above 2 GiB, the q35 64-bit window all RAM above 4 GiB, and the
/// `virt` 64-bit window RAM once a guest has more than about 14 GiB; on real
/// hardware either can span firmware-reserved memory. `derive_mmio_apertures`
/// clips heuristic seeds to the memory map's holes and MMIO descriptors, so
/// no aperture covers RAM or firmware-reserved memory.
#[must_use]
pub fn pci_windows(ecam_base: u64, max_phys_addr_bits: u32) -> ((u64, u64), (u64, u64))
{
    const TWO_GIB: u64 = 0x8000_0000;
    if ecam_base < TWO_GIB
    {
        return ((0x4000_0000, 0x4000_0000), (0x4_0000_0000, 0x4_0000_0000));
    }
    let hi_top = if max_phys_addr_bits >= 64
    {
        u64::MAX
    }
    else
    {
        1u64 << max_phys_addr_bits
    };
    let hi_base = 1u64 << 32;
    // `ecam_base` is at least 2 GiB on this branch.
    (
        (TWO_GIB, ecam_base.saturating_sub(TWO_GIB)),
        (hi_base, hi_top.saturating_sub(hi_base)),
    )
}

#[cfg(test)]
mod tests
{
    use firmware_tables::acpi::{MADT_ENTRIES_OFF, SDT_HDR_LEN, SDT_OFF_LENGTH};

    use super::*;

    /// The profile the x86-64 build passes: the 48-bit address width of the
    /// host-test CPUID stand-in and the PC Client TPM window.
    const X86_64: AcpiSeedProfile = AcpiSeedProfile {
        max_phys_addr_bits: 48,
        tpm_window: Some((0xFED4_0000, 0x5000)),
    };

    /// The profile the riscv64 build passes: 56-bit addresses and no TPM
    /// window.
    const RISCV64: AcpiSeedProfile = AcpiSeedProfile {
        max_phys_addr_bits: 56,
        tpm_window: None,
    };

    /// Seeds as `(base, size)` pairs.
    type Spans = Vec<(u64, u64)>;

    /// Offset of the signature in an SDT header.
    const SDT_OFF_SIGNATURE: usize = 0;
    /// Offset of the entries in an MCFG: the SDT header and 8 reserved bytes.
    const MCFG_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;

    /// A synthetic SDT: `signature`, the length field over `body`, then
    /// `body` after the 36-byte header.
    fn sdt(signature: [u8; 4], body: &[u8]) -> Vec<u8>
    {
        let mut t = vec![0u8; SDT_HDR_LEN];
        t[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4].copy_from_slice(&signature);
        t.extend_from_slice(body);
        let len = u32::try_from(t.len()).unwrap();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

    /// A synthetic `TPM2` table: `start_method`, the CRB control area at
    /// `control`, and no start-method parameters.
    fn tpm2(start_method: u32, control: u64) -> Vec<u8>
    {
        let mut body = vec![0u8; 4];
        body.extend_from_slice(&control.to_le_bytes());
        body.extend_from_slice(&start_method.to_le_bytes());
        body.extend_from_slice(&[0u8; 12]);
        sdt(*b"TPM2", &body)
    }

    /// The seeds `table` adds under `profile`: the named and the heuristic
    /// ones, each as `(base, size)`.
    fn table_seeds(table: &[u8], profile: &AcpiSeedProfile) -> (Spans, Spans)
    {
        let mut counting = Seeds::counting();
        acpi_table_seeds(table, profile, &mut counting);
        let (named, heuristic) = counting.found;
        let empty = MmioAperture {
            phys_base: 0,
            size: 0,
        };
        let mut out = vec![empty; named];
        let mut out_h = vec![empty; heuristic];
        let mut seeds = Seeds::new(&mut out, &mut out_h);
        acpi_table_seeds(table, profile, &mut seeds);
        assert_eq!(seeds.written, (named, heuristic));
        let spans = |a: &[MmioAperture]| a.iter().map(|a| (a.phys_base, a.size)).collect();
        (spans(&out), spans(&out_h))
    }

    /// The named seeds, sorted, that the ACPI walk finds in `table`.
    fn named_seeds(table: &[u8], profile: &AcpiSeedProfile) -> Vec<(u64, u64)>
    {
        let mut seeds = table_seeds(table, profile).0;
        seeds.sort_unstable();
        seeds
    }

    // Defect caught: the walk not reading the `TPM2` table, or seeding a
    // window on a platform whose profile places none.
    #[test]
    fn the_walk_seeds_the_arch_tpm_window_from_a_tpm2_table()
    {
        let expected: Vec<(u64, u64)> = X86_64.tpm_window.into_iter().collect();
        assert_eq!(named_seeds(&tpm2(7, 0xFED4_0040), &X86_64), expected);
    }

    // Defect caught: an ACPI count pass that finds a different number of
    // named or heuristic seeds than the fill pass writes, so a buffer sized
    // from it drops seeds the kernel needs as apertures.
    #[test]
    fn the_acpi_seed_count_pass_finds_every_seed_the_fill_pass_writes()
    {
        // MADT: a LAPIC base the override replaces, one I/O APIC, and the
        // `LocalApicAddressOverride`.
        let mut madt_body = Vec::new();
        madt_body.extend_from_slice(&0xFEE0_0000u32.to_le_bytes());
        madt_body.extend_from_slice(&0u32.to_le_bytes());
        madt_body.extend_from_slice(&[madt_type::IO_APIC, 12, 0, 0]);
        madt_body.extend_from_slice(&0xFEC0_0000u32.to_le_bytes());
        madt_body.extend_from_slice(&0u32.to_le_bytes());
        madt_body.extend_from_slice(&[madt_type::LAPIC_OVERRIDE, 12, 0, 0]);
        madt_body.extend_from_slice(&0xFEE0_1000u64.to_le_bytes());
        let madt = sdt(*b"APIC", &madt_body);
        // MCFG: one ECAM above 2 GiB (the q35 branch) and one below (virt),
        // each with its two heuristic PCI windows.
        let mut mcfg_body = vec![0u8; MCFG_ENTRIES_OFF - SDT_HDR_LEN];
        for base in [0xB000_0000u64, 0x3000_0000u64]
        {
            mcfg_body.extend_from_slice(&base.to_le_bytes());
            mcfg_body.extend_from_slice(&[0, 0, 0, 0xFF, 0, 0, 0, 0]);
        }
        let mcfg = sdt(*b"MCFG", &mcfg_body);
        let tables = [&madt[..], &mcfg[..]];

        let mut counting = Seeds::counting();
        for table in tables
        {
            acpi_table_seeds(table, &X86_64, &mut counting);
        }
        let (named, heuristic) = counting.found;
        // The arch's default apertures are appended by core/boot, not counted here.
        assert_eq!(named, 4, "LAPIC, I/O APIC and two ECAM windows");
        assert_eq!(heuristic, 4, "two PCI windows per ECAM");

        let empty = MmioAperture {
            phys_base: 0,
            size: 0,
        };
        let mut out = vec![empty; named + 4];
        let mut out_h = vec![empty; heuristic + 4];
        let mut seeds = Seeds::new(&mut out, &mut out_h);
        for table in tables
        {
            acpi_table_seeds(table, &X86_64, &mut seeds);
        }
        assert_eq!(seeds.written, (named, heuristic));
        assert_eq!(seeds.found, (named, heuristic));
        assert!(out[..named].iter().any(|a| a.phys_base == 0xFEE0_1000));

        // Buffers of exactly the counted sizes drop nothing.
        let mut exact = vec![empty; named];
        let mut exact_h = vec![empty; heuristic];
        let mut seeds = Seeds::new(&mut exact, &mut exact_h);
        for table in tables
        {
            acpi_table_seeds(table, &X86_64, &mut seeds);
        }
        assert_eq!(seeds.written, (named, heuristic));
        let spans =
            |a: &[MmioAperture]| a.iter().map(|a| (a.phys_base, a.size)).collect::<Vec<_>>();
        assert_eq!(spans(&exact), spans(&out[..named]));
        assert_eq!(spans(&exact_h), spans(&out_h[..heuristic]));
    }

    /// The MADT QEMU 11.1 `virt` with `aia=aplic-imsic` and 4 harts in one
    /// socket hands EDK2: four RINTC v1 structures (harts 0 to 3, files at
    /// `0x2800_0000 + hart * 0x1000`), one IMSIC, one supervisor-level APLIC.
    const QEMU_VIRT_AIA_MADT: &[u8] = include_bytes!("../testdata/qemu-virt-aia-smp4-madt.bin");

    /// Offset of hart `hart`'s RINTC structure in [`QEMU_VIRT_AIA_MADT`].
    fn qemu_rintc_off(hart: usize) -> usize
    {
        MADT_ENTRIES_OFF + hart * madt_len::RINTC_IMSIC
    }

    // Defect caught: the APLIC or the IMSIC files missing from the aperture
    // seeds, so devmgr has no aperture to carve them from.
    #[test]
    fn the_qemu_virt_aia_madt_seeds_the_aplic_and_the_imsic_files()
    {
        assert_eq!(
            named_seeds(QEMU_VIRT_AIA_MADT, &RISCV64),
            [
                (0xd00_0000, 0x8000),
                (0x2800_0000, 0x1000),
                (0x2800_1000, 0x1000),
                (0x2800_2000, 0x1000),
                (0x2800_3000, 0x1000),
            ]
        );
    }

    // Defect caught: one seed spanning every hart's file, which with two
    // IMSIC groups covers the address space between the groups that no table
    // names (QEMU `virt` with two sockets puts group 1 at `0x2900_0000`).
    #[test]
    fn the_imsic_seeds_leave_the_gap_between_groups_unseeded()
    {
        let mut madt = QEMU_VIRT_AIA_MADT.to_vec();
        for (hart, file) in [(2, 0x2900_0000u64), (3, 0x2900_1000)]
        {
            let at = qemu_rintc_off(hart) + 24;
            madt[at..at + 8].copy_from_slice(&file.to_le_bytes());
        }
        let seeds = named_seeds(&madt, &RISCV64);
        assert_eq!(
            seeds,
            [
                (0xd00_0000, 0x8000),
                (0x2800_0000, 0x1000),
                (0x2800_1000, 0x1000),
                (0x2900_0000, 0x1000),
                (0x2900_1000, 0x1000),
            ]
        );
        assert!(
            !seeds
                .iter()
                .any(|&(base, size)| base <= 0x2800_2000 && 0x2800_2000 < base + size)
        );
    }
}

#[cfg(kani)]
mod proofs
{
    use crate::property::seeds as property;

    /// Every seed, of any base and size, into buffers of 0 to 2 slots each,
    /// is counted when it has bytes and written while its buffer has room.
    /// No loop.
    #[kani::proof]
    fn every_seed_is_counted_and_written_while_room_lasts()
    {
        let room: (u8, u8) = kani::any();
        property::push_holds(
            (usize::from(room.0 % 3), usize::from(room.1 % 3)),
            kani::any(),
            kani::any(),
        );
    }

    /// Every MADT structure of at most 40 bytes, of any type, seeds the
    /// window its layout names: 36 bytes hold an APLIC and an RINTC through
    /// their windows, and 12 an I/O APIC. The loops of `acpi_table_seeds`
    /// over a table's structures, MCFG entries and DMAR units are the fuzz
    /// target's, against `table_seeds_holds`. No loop.
    #[kani::proof]
    fn every_madt_structure_seeds_its_window()
    {
        let bytes: [u8; 40] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::structure_seed_holds(kani::any(), &bytes[..len]);
    }

    /// Every ECAM base and physical address width give the heuristic
    /// windows of QEMU's layouts, neither wrapping the address space. No
    /// loop.
    #[kani::proof]
    fn every_ecam_base_gives_its_heuristic_windows()
    {
        property::pci_windows_holds(kani::any(), kani::any());
    }
}
