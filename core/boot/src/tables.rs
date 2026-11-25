// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/tables.rs

//! The firmware tables as byte slices.
//!
//! [`TableMap::view`] is the bootloader's one step from a firmware address
//! to the bytes there: it makes a slice only once the UEFI memory map gives
//! every byte of it to firmware data (`boot_firmware::region::firmware_range`),
//! so a length the firmware wrote, which is hostile input, cannot extend a
//! slice into memory the map types as memory-mapped I/O, a hole or free
//! memory (reserved memory is accepted, for the reason the document below
//! gives). The walks here, from
//! the RSDP to each ACPI table and from the device tree's header to its whole
//! blob, view each table that way; `boot_firmware` decodes the slices
//! (`core/boot/docs/firmware-parsing.md` § Table Bounds).
//!
//! Every read of the boot, before and after `ExitBootServices`, is bounded
//! by the one [`Snapshot`] taken at entry, so the count pass ahead of step 6
//! and step 9's fill pass see the same tables.

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use boot_firmware::dtb::{Limits, Tree};
use boot_firmware::region::{Refusal, firmware_range};
use boot_firmware::seeds::{AcpiSeedProfile, Seeds, acpi_table_seeds};
use firmware_tables::acpi::{
    RSDP_LEN, SDT_HDR_LEN, iter_xsdt_entries, rsdp_xsdt_phys, sdt_length, sdt_signature,
};
use firmware_tables::fdt::{FDT_MAGIC, HDR_TOTALSIZE};

use crate::bprintln;
use crate::firmware::FirmwareInfo;
use crate::uefi::{self, EfiBootServices, MemoryMapResult};

/// Bytes of a flattened device tree's header (Devicetree Specification 0.4
/// § 5.2).
const FDT_HDR_LEN: usize = 40;

/// Whether a refused view prints its diagnostic.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Report
{
    /// On the boot console.
    Console,
    /// Not at all: the console is not up yet.
    Silent,
}

/// The UEFI memory map a table's extent is checked against: its descriptors,
/// `stride` bytes apart.
#[derive(Clone, Copy)]
pub struct TableMap<'m>
{
    map: &'m [u8],
    stride: usize,
    report: Report,
}

impl<'m> TableMap<'m>
{
    /// The map in `map`, its descriptors `stride` bytes apart. A view it
    /// refuses prints a diagnostic.
    const fn new(map: &'m [u8], stride: usize) -> Self
    {
        Self {
            map,
            stride,
            report: Report::Console,
        }
    }

    /// The map `GetMemoryMap` wrote into `result`'s buffer.
    ///
    /// # Safety
    /// `result` describes a buffer `GetMemoryMap` filled, identity-mapped,
    /// which nothing writes while the map is in use.
    unsafe fn of(result: &'m MemoryMapResult) -> Self
    {
        // SAFETY: the caller guarantees `map_size` bytes at `buffer_phys` are
        // a filled map buffer, identity-mapped and unwritten for `'m`.
        let map = unsafe {
            core::slice::from_raw_parts(result.buffer_phys as *const u8, result.map_size)
        };
        Self::new(map, result.descriptor_size)
    }

    /// The same map, whose refused views print nothing: for the reads made
    /// before the console is up.
    pub const fn silent(self) -> Self
    {
        Self {
            report: Report::Silent,
            ..self
        }
    }

    /// The `len` bytes at physical address `phys`, when the map gives every
    /// one of them to firmware data. `None` for a zero address, and for a
    /// range the map refuses, which a diagnostic naming `what`, the range
    /// and the refusal reports.
    ///
    /// # Safety
    /// Memory the map gives to firmware data is identity-mapped, and nothing
    /// writes the returned bytes while the slice lives.
    pub unsafe fn view<'a>(
        &self,
        what: &dyn fmt::Display,
        phys: u64,
        len: usize,
    ) -> Option<&'a [u8]>
    {
        self.check(what, phys, len)?;
        // SAFETY: `check` accepted `[phys, phys + len)`, which is non-null and
        // lies wholly in memory the map gives to firmware data, identity-mapped
        // and left unwritten while the slice lives (caller contract).
        Some(unsafe { core::slice::from_raw_parts(phys as *const u8, len) })
    }

    /// [`Self::view`], writable: for the scrub of a secret the firmware left
    /// in a table.
    ///
    /// # Safety
    /// As [`Self::view`], and no other reference to the bytes exists while the
    /// slice lives.
    pub unsafe fn view_mut<'a>(
        &self,
        what: &dyn fmt::Display,
        phys: u64,
        len: usize,
    ) -> Option<&'a mut [u8]>
    {
        self.check(what, phys, len)?;
        // SAFETY: as `view`, and the caller guarantees the slice is the only
        // reference to the bytes.
        Some(unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, len) })
    }

    /// Whether the map accepts `[phys, phys + len)` for a view; a refusal is
    /// reported.
    fn check(&self, what: &dyn fmt::Display, phys: u64, len: usize) -> Option<()>
    {
        if phys == 0
        {
            return None;
        }
        let Ok(bytes) = u64::try_from(len)
        else
        {
            self.refused(what, phys, u64::MAX, Refusal::Overflow);
            return None;
        };
        match firmware_range(self.map, self.stride, phys, bytes)
        {
            Ok(()) => Some(()),
            Err(refusal) =>
            {
                self.refused(what, phys, bytes, refusal);
                None
            }
        }
    }

    /// Report that the map refused the `len` bytes of `what` at `phys`.
    fn refused(&self, what: &dyn fmt::Display, phys: u64, len: u64, refusal: Refusal)
    {
        if self.report == Report::Silent || !first_report(phys)
        {
            return;
        }
        let end = phys.saturating_add(len);
        match refusal
        {
            Refusal::Overflow =>
            {
                bprintln!(
                    "[--------] boot: {what} at {phys:#x}, {len:#x} bytes, not read: its end \
                     overflows the address space"
                );
            }
            Refusal::Kind { kind, at } =>
            {
                bprintln!(
                    "[--------] boot: {what} at [{phys:#x}, {end:#x}) not read: UEFI memory type \
                     {kind} at {at:#x} holds no firmware data"
                );
            }
            Refusal::Hole { at } =>
            {
                bprintln!(
                    "[--------] boot: {what} at [{phys:#x}, {end:#x}) not read: no firmware-data \
                     memory at {at:#x}"
                );
            }
        }
    }
}

/// The addresses whose refusal this boot has reported. A table is read several
/// times (by each consumer, before and after `ExitBootServices`), and one
/// report says the same as many; a refusal past the last slot is reported each
/// time.
static REPORTED: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];

/// Whether this is the first report of a refusal at `phys`, which is
/// recorded.
fn first_report(phys: u64) -> bool
{
    for slot in &REPORTED
    {
        match slot.compare_exchange(0, phys, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return true,
            Err(seen) if seen == phys => return false,
            Err(_) =>
            {}
        }
    }
    true
}

/// The memory map taken at entry, which bounds every firmware-table read of
/// the boot.
///
/// It is the only map a [`TableMap`] is made from, so every reader gets the
/// same verdict on each table: the count pass ahead of step 6 sizes the
/// buffers that step 9's fill pass, after `ExitBootServices`, fills from the
/// same tables, and with no map neither pass reads any.
pub struct Snapshot
{
    /// The map, or `None` when `GetMemoryMap` failed, which leaves every
    /// table unread.
    result: Option<MemoryMapResult>,
}

impl Snapshot
{
    /// Take the map now.
    ///
    /// # Safety
    /// `bs` must be valid boot services (before `ExitBootServices`).
    pub unsafe fn take(bs: *mut EfiBootServices) -> Self
    {
        // SAFETY: caller contract.
        let result = unsafe { uefi::get_memory_map(bs) }.ok();
        Self { result }
    }

    /// Whether the map was read.
    pub const fn is_read(&self) -> bool
    {
        self.result.is_some()
    }

    /// The map, for [`TableMap::view`]; with no map, one that refuses every
    /// range.
    pub fn map(&self) -> TableMap<'_>
    {
        let Some(result) = &self.result
        else
        {
            return TableMap::new(&[], 0);
        };
        // SAFETY: `take` filled the buffer through `GetMemoryMap`; it is the
        // bootloader's allocation, identity-mapped, and nothing writes it
        // before `retire` consumes the snapshot.
        unsafe { TableMap::of(result) }
    }

    /// Zero the map's buffer after its last read and give it back as its
    /// physical base and page count, for the kernel to reclaim; `None` when
    /// no map was read. Consuming the snapshot ends every view of the map.
    ///
    /// # Safety
    /// The buffer is still identity-mapped and writable: before the handoff.
    pub unsafe fn retire(self) -> Option<(u64, usize)>
    {
        let result = self.result?;
        // SAFETY: the buffer is `get_memory_map`'s allocation of
        // `buffer_size` bytes, identity-mapped and writable (caller
        // contract), and consuming the snapshot left no view of it.
        unsafe { core::ptr::write_bytes(result.buffer_phys as *mut u8, 0, result.buffer_size) };
        Some((result.buffer_phys, result.buffer_size / 4096))
    }
}

// ── ACPI ─────────────────────────────────────────────────────────────────────

/// An ACPI table named by its signature, for a refusal's diagnostic.
struct Signature([u8; 4]);

impl fmt::Display for Signature
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str("ACPI table ")?;
        for &b in &self.0
        {
            let c = if b.is_ascii_graphic()
            {
                char::from(b)
            }
            else
            {
                '?'
            };
            fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

/// The ACPI tables the RSDP's XSDT lists, each viewed through the map.
pub struct Acpi<'m, 't>
{
    map: TableMap<'m>,
    xsdt: &'t [u8],
}

impl<'m, 't> Acpi<'m, 't>
{
    /// Walk from the RSDP at `rsdp` to its XSDT: `None` for a zero
    /// `rsdp`, an RSDP or XSDT the map refuses, an RSDP before ACPI 2.0 or
    /// without an XSDT, or an XSDT whose signature or length is wrong.
    ///
    /// # Safety
    /// As [`TableMap::view`], for every table reached from the RSDP while the
    /// value lives.
    pub unsafe fn new(map: TableMap<'m>, rsdp: u64) -> Option<Self>
    {
        // SAFETY: caller contract.
        let rsdp = unsafe { map.view(&"ACPI RSDP", rsdp, RSDP_LEN) }?;
        // SAFETY: as above.
        let xsdt = unsafe { table_at(map, rsdp_xsdt_phys(rsdp)?) }?;
        (sdt_signature(xsdt) == *b"XSDT").then_some(Self { map, xsdt })
    }

    /// Each table the XSDT lists whose signature is one of `signatures`,
    /// whole, in XSDT order. An entry whose header or table the map refuses,
    /// or whose length is shorter than its header, is skipped.
    pub fn tables<'s>(&'s self, signatures: &'s [[u8; 4]]) -> impl Iterator<Item = &'t [u8]> + 's
    {
        let map = self.map;
        iter_xsdt_entries(self.xsdt).filter_map(move |phys| {
            // SAFETY: `Acpi::new`'s contract covers every table the XSDT lists.
            let header = unsafe { map.view(&"ACPI table header", phys, SDT_HDR_LEN) }?;
            let signature = sdt_signature(header);
            if !signatures.contains(&signature)
            {
                return None;
            }
            let len = usize::try_from(sdt_length(header)?).ok()?;
            // SAFETY: as above.
            unsafe { map.view(&Signature(signature), phys, len) }
        })
    }

    /// The first table the XSDT lists whose signature is `signature`.
    pub fn table(&self, signature: [u8; 4]) -> Option<&'t [u8]>
    {
        self.tables(&[signature]).next()
    }
}

/// The SDT at `phys`, whole: its header, then the length the header gives.
///
/// # Safety
/// As [`TableMap::view`].
unsafe fn table_at<'t>(map: TableMap<'_>, phys: u64) -> Option<&'t [u8]>
{
    // SAFETY: caller contract.
    let header = unsafe { map.view(&"ACPI table header", phys, SDT_HDR_LEN) }?;
    let len = usize::try_from(sdt_length(header)?).ok()?;
    // SAFETY: caller contract.
    unsafe { map.view(&Signature(sdt_signature(header)), phys, len) }
}

// ── The device tree ──────────────────────────────────────────────────────────

/// The device tree blob at `dtb`, whole: its header, then the `totalsize`
/// the header gives. `None` for a zero `dtb`, a bad magic, or a blob the
/// map refuses.
///
/// # Safety
/// As [`TableMap::view`].
pub unsafe fn device_tree<'t>(map: TableMap<'_>, dtb: u64) -> Option<&'t [u8]>
{
    // SAFETY: caller contract.
    let len = unsafe { tree_len(map, dtb) }?;
    // SAFETY: caller contract.
    unsafe { map.view(&"device tree", dtb, len) }
}

/// [`device_tree`], writable.
///
/// # Safety
/// As [`TableMap::view_mut`].
pub unsafe fn device_tree_mut<'t>(map: TableMap<'_>, dtb: u64) -> Option<&'t mut [u8]>
{
    // SAFETY: caller contract.
    let len = unsafe { tree_len(map, dtb) }?;
    // SAFETY: caller contract.
    unsafe { map.view_mut(&"device tree", dtb, len) }
}

/// The `totalsize` of the device tree at `dtb`, when its header lies in
/// firmware data and carries the magic.
///
/// # Safety
/// As [`TableMap::view`].
unsafe fn tree_len(map: TableMap<'_>, dtb: u64) -> Option<usize>
{
    // SAFETY: caller contract.
    let header = unsafe { map.view(&"device tree header", dtb, FDT_HDR_LEN) }?;
    let word = |at: usize| Some(u32::from_be_bytes(*header.get(at..)?.first_chunk::<4>()?));
    if word(0)? != FDT_MAGIC
    {
        return None;
    }
    usize::try_from(word(HDR_TOTALSIZE)?).ok()
}

/// Whether a walk has reported nodes nested past its depth, once per boot:
/// the tree is read several times, and one report says the same as many.
static REPORTED_TOO_DEEP: AtomicBool = AtomicBool::new(false);
/// Whether a walk has reported a property past its entry bound, once per boot
/// for the reason [`REPORTED_TOO_DEEP`] gives.
static REPORTED_TRUNCATED: AtomicBool = AtomicBool::new(false);

/// Report what the walks over `tree` met past their bounds, each the first
/// time a walk of this boot meets it.
pub fn report_limits(tree: &Tree<'_>)
{
    let Limits {
        too_deep,
        truncated,
    } = tree.limits();
    if too_deep && !REPORTED_TOO_DEEP.swap(true, Ordering::Relaxed)
    {
        bprintln!("[--------] boot: DTB: nodes nested past MAX_DEPTH; their properties skipped");
    }
    if truncated && !REPORTED_TRUNCATED.swap(true, Ordering::Relaxed)
    {
        bprintln!(
            "[--------] boot: DTB: a reg property past its entry bound; surplus entries dropped"
        );
    }
}

// ── The aperture seeds ───────────────────────────────────────────────────────

/// Add the aperture seeds of every firmware table to `seeds`: the ACPI
/// tables' (`boot_firmware::seeds::acpi_table_seeds` over each `APIC`,
/// `MCFG`, `DMAR` and `TPM2`), then, once the RSDP and XSDT were read, the
/// architecture's default apertures and PCI windows
/// (`crate::arch::current::default_mmio_apertures`,
/// `default_pci_windows`), then the device tree's
/// (`boot_firmware::dtb::Tree::seeds`). With empty buffers it counts the
/// seeds that size the buffers of a later walk over the same tables.
///
/// # Safety
/// As [`TableMap::view`].
pub unsafe fn aperture_seeds(firm: &FirmwareInfo, map: TableMap<'_>, seeds: &mut Seeds<'_>)
{
    // SAFETY: caller contract.
    if let Some(acpi) = unsafe { Acpi::new(map, firm.acpi_rsdp) }
    {
        let profile = AcpiSeedProfile {
            max_phys_addr_bits: u32::from(crate::arch::current::max_phys_addr_bits()),
            tpm_window: crate::arch::current::tpm_register_window(),
        };
        for table in acpi.tables(&[*b"APIC", *b"MCFG", *b"DMAR", *b"TPM2"])
        {
            acpi_table_seeds(table, &profile, seeds);
        }
        // Some firmware builds publish ACPI without an MCFG table (the EDK2 of
        // Ubuntu's `qemu-efi-riscv64` package), and no table read here names
        // the riscv64 UART and Goldfish RTC pages: core/boot/docs/acpi.md
        // § Tables Consumed.
        for &(base, size) in crate::arch::current::default_mmio_apertures()
        {
            seeds.named(base, size);
        }
        for &(base, size) in crate::arch::current::default_pci_windows()
        {
            seeds.heuristic(base, size);
        }
    }
    // SAFETY: caller contract.
    if let Some(tree) = unsafe { device_tree(map, firm.device_tree) }.and_then(Tree::new)
    {
        tree.seeds(seeds);
        report_limits(&tree);
    }
}
