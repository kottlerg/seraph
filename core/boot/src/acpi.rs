// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/acpi.rs

//! Minimal ACPI table parser: RSDP → XSDT → MADT, MCFG.
//!
//! Reads tables in-place from identity-mapped physical memory. No allocation.
//! Architecture-neutral: runs on any platform where `acpi_rsdp != 0`, which
//! includes both x86-64 (primary source) and RISC-V platforms booted under
//! UEFI firmware that publishes ACPI tables (e.g. QEMU+EDK2 virt).
//!
//! Error handling: malformed tables log a warning and return partial results.
//! Only ACPI 2.0+ (XSDT-based) is supported; ACPI 1.0 (RSDT-only) is skipped.
//!
//! # Surface
//! - [`parse_cpu_topology`]: MADT walk producing `BootInfo.cpu_count` and
//!   `BootInfo.cpu_ids`.
//! - [`parse_aperture_seed`]: MADT + MCFG walk producing MMIO aperture
//!   seeds fed into [`super::memory_map::derive_mmio_apertures`].
//!
//! Arch-specific `kernel_mmio` extractors (LAPIC+IOAPIC on x86-64;
//! PLIC+UART on RISC-V) consume the byte helpers and layout constants
//! exposed here but live under [`crate::arch`].

use crate::bprintln;
use boot_protocol::{MAX_CPUS, MmioAperture};

// ── Layout constants ──────────────────────────────────────────────────────────

// RSDP (ACPI 2.0, offset from base):
//   0: signature[8]  8: checksum  9: oemid[6]  15: revision
//  16: rsdt_address(u32)  20: length(u32)  24: xsdt_address(u64)
//  32: extended_checksum  33: reserved[3]

pub(crate) const RSDP_SIG: &[u8; 8] = b"RSD PTR ";
pub(crate) const RSDP_OFF_REVISION: usize = 15;
pub(crate) const RSDP_OFF_XSDT: usize = 24;

// SDT header (36 bytes, common to all ACPI description tables):
//   0: signature[4]  4: length(u32)  8: revision  9: checksum
//  10: oemid[6]  16: oemtableid[8]  24: oemrev(u32)  28: creatorid(u32)
//  32: creatorrev(u32)

pub(crate) const SDT_HDR_LEN: usize = 36;
pub(crate) const SDT_OFF_SIGNATURE: usize = 0;
pub(crate) const SDT_OFF_LENGTH: usize = 4;

// MADT entries start at offset 44 (after the SDT header + 4-byte
// `LocalApicAddress` + 4-byte flags).
pub(crate) const MADT_ENTRIES_OFF: usize = 44;

// MADT entry types:
const MADT_TYPE_LAPIC: u8 = 0; // x86-64: Processor Local APIC, length 8
pub(crate) const MADT_TYPE_IOAPIC: u8 = 1;
const MADT_TYPE_RINTC: u8 = 0x18; // RISC-V INTC (MADT type 24), length 36
pub(crate) const MADT_TYPE_PLIC: u8 = 0x1B; // RISC-V PLIC (MADT type 27)

// MCFG: entries start at offset 44 (SDT_HDR_LEN + 8 reserved bytes).
const MCFG_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;
const MCFG_ENTRY_SIZE: usize = 16;

// ── Byte-level read helpers ───────────────────────────────────────────────────

/// Read a little-endian u32 at byte `off` within `buf`. Returns 0 on short read.
pub(crate) fn read_u32(buf: &[u8], off: usize) -> u32
{
    if off + 4 > buf.len()
    {
        return 0;
    }
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a little-endian u64 at byte `off` within `buf`. Returns 0 on short read.
pub(crate) fn read_u64(buf: &[u8], off: usize) -> u64
{
    if off + 8 > buf.len()
    {
        return 0;
    }
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Read a u8 at byte `off` within `buf`. Returns 0 on short read.
pub(crate) fn read_u8(buf: &[u8], off: usize) -> u8
{
    buf.get(off).copied().unwrap_or(0)
}

/// Return a byte slice view of `len` bytes at physical address `phys`.
///
/// # Safety
/// `phys` must be a valid, identity-mapped physical address with at least
/// `len` accessible bytes. The caller must ensure the region lives long enough.
pub(crate) unsafe fn phys_slice<'a>(phys: u64, len: usize) -> &'a [u8]
{
    // SAFETY: caller guarantees phys is valid identity-mapped address with ≥len bytes.
    unsafe { core::slice::from_raw_parts(phys as *const u8, len) }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Walk the ACPI MADT starting from `rsdp_addr` and collect CPU topology.
///
/// Returns `(cpu_count, bsp_id, cpu_ids)`:
/// - `cpu_count`: number of enabled CPUs (at most [`MAX_CPUS`]).
/// - `bsp_id`: hardware identifier of the bootstrap processor, passed in by
///   the caller (LAPIC ID on x86-64 from CPUID; boot hart ID on RISC-V from
///   `EFI_RISCV_BOOT_PROTOCOL`).
/// - `cpu_ids`: per-CPU hardware IDs indexed by logical CPU index; `[0]` is
///   always the BSP, `[1..cpu_count]` are APs in MADT discovery order.
///
/// Parses MADT entry types:
/// - Type 0 (Processor Local APIC, x86-64): enabled if `flags & 1 || flags & 2`.
/// - Type 0x18 (RISC-V INTC, RINTC): enabled if `flags & 1`.
///
/// If the firmware reports more than [`MAX_CPUS`] enabled CPUs, the surplus
/// is dropped and a diagnostic is printed; the caller is cap-bounded so the
/// kernel can still boot on the leading [`MAX_CPUS`] processors.
///
/// Returns `(1, bsp_id, [bsp_id, 0, …])` on any parse failure so the system
/// falls back to single-CPU operation rather than refusing to boot.
///
/// # Safety
/// `rsdp_addr` must be a physical address of a valid, identity-mapped ACPI RSDP.
pub unsafe fn parse_cpu_topology(rsdp_addr: u64, bsp_id: u32) -> (u32, u32, [u32; MAX_CPUS])
{
    let mut cpu_ids = [0u32; MAX_CPUS];
    cpu_ids[0] = bsp_id;

    if rsdp_addr == 0
    {
        return (1, bsp_id, cpu_ids);
    }

    // Validate RSDP.
    // SAFETY: caller guarantees rsdp_addr is valid, identity-mapped ACPI RSDP.
    let rsdp = unsafe { phys_slice(rsdp_addr, 36) };
    if &rsdp[..8] != RSDP_SIG || read_u8(rsdp, RSDP_OFF_REVISION) < 2
    {
        return (1, bsp_id, cpu_ids);
    }
    let xsdt_addr = read_u64(rsdp, RSDP_OFF_XSDT);
    if xsdt_addr == 0
    {
        return (1, bsp_id, cpu_ids);
    }

    // Validate XSDT.
    // SAFETY: xsdt_addr from validated RSDP; firmware guarantees physical mapping.
    let xsdt_hdr = unsafe { phys_slice(xsdt_addr, SDT_HDR_LEN) };
    if &xsdt_hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"XSDT"
    {
        return (1, bsp_id, cpu_ids);
    }
    let xsdt_len = read_u32(xsdt_hdr, SDT_OFF_LENGTH) as usize;
    if xsdt_len < SDT_HDR_LEN
    {
        return (1, bsp_id, cpu_ids);
    }
    // SAFETY: xsdt_len validated >= SDT_HDR_LEN above; firmware guarantees mapping.
    let xsdt = unsafe { phys_slice(xsdt_addr, xsdt_len) };
    let entries_bytes = &xsdt[SDT_HDR_LEN..];
    let entry_count = entries_bytes.len() / 8;

    for i in 0..entry_count
    {
        let table_addr = read_u64(entries_bytes, i * 8);
        if table_addr == 0
        {
            continue;
        }
        // SAFETY: table_addr from XSDT entry; firmware guarantees physical mapping.
        let hdr = unsafe { phys_slice(table_addr, SDT_HDR_LEN) };
        if &hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] == b"APIC"
        {
            let table_len = read_u32(hdr, SDT_OFF_LENGTH) as usize;
            if table_len >= SDT_HDR_LEN
            {
                // SAFETY: table_len validated; firmware guarantees mapping.
                let table = unsafe { phys_slice(table_addr, table_len) };
                return parse_madt_topology(table, bsp_id, cpu_ids);
            }
        }
    }

    (1, bsp_id, cpu_ids)
}

/// Walk MADT entries to collect CPU hardware IDs (LAPIC or RINTC).
///
/// Returns `(cpu_count, bsp_id, cpu_ids)`. The BSP is placed at index 0,
/// APs fill indices `1..cpu_count` in MADT order. Entries beyond
/// [`MAX_CPUS`] are dropped with a diagnostic.
fn parse_madt_topology(
    table: &[u8],
    bsp_id: u32,
    mut cpu_ids: [u32; MAX_CPUS],
) -> (u32, u32, [u32; MAX_CPUS])
{
    // Collect all enabled IDs first, then place BSP at index 0.
    let mut all_ids = [0u32; MAX_CPUS];
    let mut all_count: usize = 0;
    let mut truncated = false;

    let mut off = MADT_ENTRIES_OFF;
    while off + 2 <= table.len()
    {
        let entry_type = read_u8(table, off);
        let entry_len = read_u8(table, off + 1) as usize;
        if entry_len < 2 || off + entry_len > table.len()
        {
            break;
        }

        match entry_type
        {
            MADT_TYPE_LAPIC if entry_len >= 8 =>
            {
                // Type 0 (Processor Local APIC), length 8:
                //   off+0: type  off+1: length  off+2: acpi_proc_id  off+3: apic_id
                //   off+4: flags(u32)  bit0=enabled  bit1=online-capable
                let apic_id = u32::from(read_u8(table, off + 3));
                let flags = read_u32(table, off + 4);
                if (flags & 0x1 != 0) || (flags & 0x2 != 0)
                {
                    if all_count < MAX_CPUS
                    {
                        all_ids[all_count] = apic_id;
                        all_count += 1;
                    }
                    else
                    {
                        truncated = true;
                    }
                }
            }
            MADT_TYPE_RINTC if entry_len >= 20 =>
            {
                // Type 0x18 (RISC-V INTC / RINTC), length 36:
                //   off+0: type  off+1: length  off+2: version  off+3: reserved
                //   off+4: flags(u32)  bit0=enabled
                //   off+8: hart_id(u64)  off+16: acpi_proc_uid(u32)  …
                let flags = read_u32(table, off + 4);
                // hart_id from MADT RINTC is u64 but only the lower 32 bits are used.
                #[allow(clippy::cast_possible_truncation)]
                let hart_id = read_u64(table, off + 8) as u32;
                if flags & 0x1 != 0
                {
                    if all_count < MAX_CPUS
                    {
                        all_ids[all_count] = hart_id;
                        all_count += 1;
                    }
                    else
                    {
                        truncated = true;
                    }
                }
            }
            _ =>
            {}
        }

        off += entry_len;
    }

    if truncated
    {
        bprintln!(
            "[--------] boot: ACPI: MADT reported more than MAX_CPUS enabled CPUs; surplus dropped"
        );
    }

    if all_count == 0
    {
        // No processors found in MADT — single-CPU fallback.
        return (1, bsp_id, cpu_ids);
    }

    // Place BSP at index 0, APs at subsequent indices.
    let mut logical_idx: usize = 1;
    cpu_ids[0] = bsp_id;
    for &id in &all_ids[..all_count]
    {
        if id != bsp_id && logical_idx < MAX_CPUS
        {
            cpu_ids[logical_idx] = id;
            logical_idx += 1;
        }
    }

    // all_count is at most MAX_CPUS (512), which fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let cpu_count = (all_count as u32).min(MAX_CPUS as u32);
    (cpu_count, bsp_id, cpu_ids)
}

// ── Aperture seeder (protocol v6) ────────────────────────────────────────────

/// MADT entry type 5 — `LocalApicAddressOverride` (overrides the 32-bit
/// `LocalApicAddress` in the MADT header with a 64-bit value).
pub(crate) const MADT_TYPE_LAPIC_OVERRIDE: u8 = 5;

/// Walk ACPI tables and collect MMIO extents into `out` for aperture
/// seeding.
///
/// Writes up to `out.len()` [`MmioAperture`] entries covering:
/// - Local APIC register window, when non-zero (x86-64 only: from the
///   MADT header, or from a `LocalApicAddressOverride` entry).
/// - Each I/O APIC register window (x86-64, MADT type 1).
/// - Each RISC-V PLIC register window (MADT type 0x1B, present on
///   RISC-V platforms that expose ACPI such as QEMU+EDK2 virt).
/// - Each MCFG ECAM window, plus a 32-bit and 64-bit PCI MMIO aperture
///   placed by a QEMU q35 / virt layout heuristic (ECAM-base-dependent).
///
/// Callable unconditionally on every supported architecture; a zero
/// `rsdp_addr` (no ACPI) is a fast no-op that returns 0. The caller
/// typically also calls [`super::dtb::parse_aperture_seed`] to cover
/// DTB-only platforms, and merges both into
/// [`super::memory_map::derive_mmio_apertures`].
///
/// Returns the number of entries written.
///
/// # Safety
/// `rsdp_addr` must be the physical address of a valid, identity-mapped
/// ACPI RSDP. A zero `rsdp_addr` returns 0 without reading.
// too_many_lines: linear walk over MADT and MCFG with per-entry push dispatch;
// the cases are flat and inline-local, splitting them loses the walk's shape.
#[allow(clippy::too_many_lines)]
pub unsafe fn parse_aperture_seed(rsdp_addr: u64, out: &mut [MmioAperture]) -> usize
{
    let mut n: usize = 0;

    macro_rules! push {
        ($base:expr, $size:expr) => {
            if n < out.len() && $size > 0
            {
                out[n] = MmioAperture {
                    phys_base: $base,
                    size: $size,
                };
                n += 1;
            }
        };
    }

    if rsdp_addr == 0
    {
        return n;
    }
    // SAFETY: caller contract.
    let rsdp = unsafe { phys_slice(rsdp_addr, 36) };
    if &rsdp[..8] != RSDP_SIG || read_u8(rsdp, RSDP_OFF_REVISION) < 2
    {
        return n;
    }
    let xsdt_addr = read_u64(rsdp, RSDP_OFF_XSDT);
    if xsdt_addr == 0
    {
        return n;
    }

    // SAFETY: validated RSDP.
    let xsdt_hdr = unsafe { phys_slice(xsdt_addr, SDT_HDR_LEN) };
    if &xsdt_hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"XSDT"
    {
        return n;
    }
    let xsdt_len = read_u32(xsdt_hdr, SDT_OFF_LENGTH) as usize;
    if xsdt_len < SDT_HDR_LEN
    {
        return n;
    }
    // SAFETY: length validated.
    let xsdt = unsafe { phys_slice(xsdt_addr, xsdt_len) };
    let entries_bytes = &xsdt[SDT_HDR_LEN..];

    for i in 0..(entries_bytes.len() / 8)
    {
        let table_addr = read_u64(entries_bytes, i * 8);
        if table_addr == 0
        {
            continue;
        }
        // SAFETY: table_addr read from validated XSDT.
        let hdr = unsafe { phys_slice(table_addr, SDT_HDR_LEN) };
        let sig: [u8; 4] = [hdr[0], hdr[1], hdr[2], hdr[3]];
        let table_len = read_u32(hdr, SDT_OFF_LENGTH) as usize;
        if table_len < SDT_HDR_LEN
        {
            continue;
        }
        // SAFETY: length validated.
        let table = unsafe { phys_slice(table_addr, table_len) };

        if &sig == b"APIC"
        {
            // LAPIC base from header; may be overridden by MADT type 5.
            // Zero on RISC-V (no LAPIC); emitted only when non-zero.
            let mut lapic = u64::from(read_u32(table, SDT_HDR_LEN));
            let mut off = MADT_ENTRIES_OFF;
            while off + 2 <= table.len()
            {
                let entry_type = read_u8(table, off);
                let entry_len = read_u8(table, off + 1) as usize;
                if entry_len < 2 || off + entry_len > table.len()
                {
                    break;
                }
                match entry_type
                {
                    MADT_TYPE_IOAPIC if entry_len >= 12 =>
                    {
                        push!(u64::from(read_u32(table, off + 4)), 0x1000u64);
                    }
                    MADT_TYPE_LAPIC_OVERRIDE if entry_len >= 12 =>
                    {
                        lapic = read_u64(table, off + 4);
                    }
                    MADT_TYPE_PLIC if entry_len >= 36 =>
                    {
                        // Type 0x1B (RISC-V PLIC), ACPI 6.5+:
                        //   off+ 0: type(u8) | off+ 1: length(u8)
                        //   off+ 2: version(u8) | off+ 3: id(u8)
                        //   off+ 4: hardware_id(8B)
                        //   off+12: total_ext_int_sources(u16) | off+14: max_priority(u16)
                        //   off+16: flags(u32)
                        //   off+20: size(u32)
                        //   off+24: base(u64)
                        //   off+32: gsi_base(u32)
                        let size = u64::from(read_u32(table, off + 20));
                        let base = read_u64(table, off + 24);
                        push!(base, size);
                    }
                    _ =>
                    {}
                }
                off += entry_len;
            }
            if lapic != 0
            {
                push!(lapic, 0x1000u64);
            }
        }
        else if &sig == b"MCFG"
        {
            let mut off = MCFG_ENTRIES_OFF;
            while off + MCFG_ENTRY_SIZE <= table.len()
            {
                let base = read_u64(table, off);
                let start_bus = read_u8(table, off + 10);
                let end_bus = read_u8(table, off + 11);
                if base != 0
                {
                    let num_buses = u64::from(end_bus).saturating_sub(u64::from(start_bus)) + 1;
                    let ecam_size = num_buses * 256 * 4096;
                    push!(base, ecam_size);
                    // PCI BAR windows. Real hardware advertises these
                    // through the host bridge's `_CRS`, which the
                    // bootloader does not evaluate (no AML interpreter).
                    // We seed conservatively: the 32-bit window is the
                    // chipset-conventional band below 4 GiB; the 64-bit
                    // window is `[4 GiB, 1 << MAXPHYADDR)` — wide enough
                    // to cover any firmware/hypervisor placement on the
                    // architecture without per-machine tuning. Apertures
                    // are permission checks, not allocations, so a wide
                    // upper bound is harmless.
                    let (lo_base, lo_size) = if base < 0x8000_0000
                    {
                        (0x4000_0000u64, 0x4000_0000u64)
                    }
                    else
                    {
                        (0x8000_0000u64, base - 0x8000_0000)
                    };
                    push!(lo_base, lo_size);
                    let maxphyaddr = crate::arch::current::max_phys_addr_bits();
                    let hi_top: u64 = if maxphyaddr >= 64
                    {
                        u64::MAX
                    }
                    else
                    {
                        1u64 << maxphyaddr
                    };
                    let hi_base: u64 = 1u64 << 32;
                    let hi_size: u64 = hi_top.saturating_sub(hi_base);
                    push!(hi_base, hi_size);
                }
                off += MCFG_ENTRY_SIZE;
            }
        }
    }

    n
}
