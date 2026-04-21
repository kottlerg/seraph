// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/acpi.rs

//! Minimal ACPI table parser: RSDP → XSDT → MADT, MCFG, SPCR.
//!
//! Reads tables in-place from identity-mapped physical memory. No allocation.
//! Architecture-neutral: runs on any platform where `acpi_rsdp != 0`.
//!
//! Error handling: malformed tables log a warning and return partial results.
//! Only ACPI 2.0+ (XSDT-based) is supported; ACPI 1.0 (RSDT-only) is skipped.
//!
//! # Extending
//! To parse additional ACPI tables, add a new arm to the `match sig` block in
//! `parse_acpi_resources`. Tables are identified by their 4-byte ASCII signature.

use crate::bprintln;
use boot_protocol::{PlatformResource, ResourceType};

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

// MADT offsets (relative to table start, after SDT header):
const MADT_OFF_LAPIC_BASE: usize = SDT_HDR_LEN; // u32
// MADT entries start at offset 44.
const MADT_ENTRIES_OFF: usize = 44;

// MADT entry types:
const MADT_TYPE_LAPIC: u8 = 0; // x86-64: Processor Local APIC, length 8
const MADT_TYPE_IOAPIC: u8 = 1;
const MADT_TYPE_ISO: u8 = 2;
const MADT_TYPE_RINTC: u8 = 0x18; // RISC-V INTC (MADT type 24), length 36
const MADT_TYPE_PLIC: u8 = 0x1B; // RISC-V PLIC (MADT type 27)

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

/// Read a u16 little-endian at byte `off` within `buf`. Returns 0 on short read.
fn read_u16(buf: &[u8], off: usize) -> u16
{
    if off + 2 > buf.len()
    {
        return 0;
    }
    u16::from_le_bytes([buf[off], buf[off + 1]])
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

/// Parse ACPI tables starting from `rsdp_addr` and write [`PlatformResource`]
/// entries into `out`. Returns the number of entries written.
///
/// Non-fatal: malformed tables log a warning and yield partial results.
///
/// Resources extracted:
/// - MADT: local APIC MMIO base, I/O APIC [`MmioRanges`], interrupt ISOs ([`IrqLine`])
/// - MCFG: PCI ECAM windows ([`PciEcam`])
/// - RSDP region: [`PlatformTable`]
///
/// # Safety
/// `rsdp_addr` must be a physical address of a valid, identity-mapped ACPI RSDP.
// The function walks RSDP → XSDT → subtables and dispatches to per-table helpers;
// splitting it further would scatter context across many small private functions.
#[allow(clippy::too_many_lines)]
pub unsafe fn parse_acpi_resources(rsdp_addr: u64, out: &mut [PlatformResource]) -> usize
{
    let mut count = 0;

    /// Push a [`PlatformResource`] into `out` if space remains.
    macro_rules! push {
        ($res:expr) => {
            if count < out.len()
            {
                out[count] = $res;
                count += 1;
            }
        };
    }

    // ── Validate RSDP ─────────────────────────────────────────────────────────

    // RSDP v2.0 is 36 bytes; read enough for all needed fields.
    // SAFETY: caller guarantees rsdp_addr is valid, identity-mapped ACPI RSDP.
    let rsdp = unsafe { phys_slice(rsdp_addr, 36) };
    if &rsdp[..8] != RSDP_SIG
    {
        bprintln!("[--------] boot:     ACPI: bad RSDP signature, skipping");
        return 0;
    }
    if read_u8(rsdp, RSDP_OFF_REVISION) < 2
    {
        bprintln!("[--------] boot:     ACPI: RSDP revision < 2 (no XSDT), skipping");
        return 0;
    }
    let xsdt_addr = read_u64(rsdp, RSDP_OFF_XSDT);
    if xsdt_addr == 0
    {
        bprintln!("[--------] boot:     ACPI: XSDT address is zero, skipping");
        return 0;
    }

    // Record the RSDP blob as a PlatformTable (id=0: RSDP).
    push!(PlatformResource {
        resource_type: ResourceType::PlatformTable,
        flags: 0,
        base: rsdp_addr,
        size: 36,
        id: 0,
    });

    // ── Validate XSDT ─────────────────────────────────────────────────────────

    // SAFETY: xsdt_addr read from validated RSDP; firmware guarantees physical mapping.
    let xsdt_hdr = unsafe { phys_slice(xsdt_addr, SDT_HDR_LEN) };
    if &xsdt_hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"XSDT"
    {
        bprintln!("[--------] boot:     ACPI: bad XSDT signature, skipping subtables");
        return count;
    }
    let xsdt_len = read_u32(xsdt_hdr, SDT_OFF_LENGTH) as usize;
    if xsdt_len < SDT_HDR_LEN
    {
        bprintln!("[--------] boot:     ACPI: XSDT length too small, skipping subtables");
        return count;
    }
    // SAFETY: xsdt_len validated >= SDT_HDR_LEN above; firmware guarantees mapping.
    let xsdt = unsafe { phys_slice(xsdt_addr, xsdt_len) };

    // XSDT entries: array of u64 physical addresses starting after the header.
    let entries_bytes = &xsdt[SDT_HDR_LEN..];
    let entry_count = entries_bytes.len() / 8;

    // Track if MADT was found (used to conditionally add legacy x86 I/O ports).
    let mut found_madt = false;

    for i in 0..entry_count
    {
        let table_addr = read_u64(entries_bytes, i * 8);
        if table_addr == 0
        {
            continue;
        }

        // Read just the SDT header to get signature and length.
        // SAFETY: table_addr from XSDT entry; firmware guarantees physical mapping.
        let hdr = unsafe { phys_slice(table_addr, SDT_HDR_LEN) };
        let sig = &hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4];
        let table_len = read_u32(hdr, SDT_OFF_LENGTH) as usize;
        if table_len < SDT_HDR_LEN
        {
            continue;
        }
        // SAFETY: table_len validated >= SDT_HDR_LEN above; firmware guarantees mapping.
        let table = unsafe { phys_slice(table_addr, table_len) };

        match sig
        {
            b"APIC" =>
            {
                // MADT: local APIC base + I/O APICs + ISOs.
                found_madt = true;
                parse_madt(table, table_addr, &mut count, out);
            }
            b"MCFG" =>
            {
                parse_mcfg(table, &mut count, out);
            }
            b"SPCR" =>
            {
                // Record the SPCR table as PlatformTable for devmgr.
                push!(PlatformResource {
                    resource_type: ResourceType::PlatformTable,
                    flags: 0,
                    base: table_addr,
                    size: table_len as u64,
                    id: 1,
                });

                // Extract the UART MMIO base from the SPCR GAS and emit an
                // MmioRange so init/ktest can map the serial port directly.
                // GAS layout at SDT_HDR_LEN+4: addr_space_id(u8), ..., address(u64 at +4).
                let gas_off = SDT_HDR_LEN + 4;
                if table_len >= gas_off + 12
                {
                    let addr_space = table[gas_off]; // 0 = MMIO
                    let uart_base = read_u64(table, gas_off + 4);
                    if addr_space == 0 && uart_base != 0
                    {
                        push!(PlatformResource {
                            resource_type: ResourceType::MmioRange,
                            flags: 0,
                            base: uart_base,
                            size: 4096, // single page covers 16550 register set
                            id: 0,
                        });
                    }
                }
            }
            b"FACP" =>
            {
                // FADT: record as PlatformTable (id=3) so userspace can parse
                // power management registers (PM1a_CNT_BLK, SLP_TYPa, etc.).
                push!(PlatformResource {
                    resource_type: ResourceType::PlatformTable,
                    flags: 0,
                    base: table_addr,
                    size: table_len as u64,
                    id: 3,
                });

                // Record the DSDT as PlatformTable (id=4). DSDT physical address
                // is at FADT offset 40 (u32) or X_DSDT at offset 140 (u64).
                let dsdt_addr = if table_len >= 148
                {
                    let x_dsdt = read_u64(table, 140);
                    if x_dsdt != 0
                    {
                        x_dsdt
                    }
                    else
                    {
                        u64::from(read_u32(table, 40))
                    }
                }
                else if table_len > 44
                {
                    u64::from(read_u32(table, 40))
                }
                else
                {
                    0
                };

                if dsdt_addr != 0
                {
                    // Read the DSDT's own length from its SDT header.
                    // SAFETY: dsdt_addr from FADT; firmware guarantees physical mapping.
                    let dsdt_hdr = unsafe { phys_slice(dsdt_addr, SDT_HDR_LEN) };
                    let dsdt_len = read_u32(dsdt_hdr, SDT_OFF_LENGTH);
                    #[allow(clippy::cast_possible_truncation)]
                    // SDT_HDR_LEN is 36, always fits u32.
                    if dsdt_len >= SDT_HDR_LEN as u32
                    {
                        push!(PlatformResource {
                            resource_type: ResourceType::PlatformTable,
                            flags: 0,
                            base: dsdt_addr,
                            size: u64::from(dsdt_len),
                            id: 4,
                        });
                    }
                }
            }
            _ =>
            {} // Skip unknown tables gracefully.
        }
    }

    // x86-64 I/O port capabilities are created directly by the kernel
    // (root IoPortRange covering the full 64K space) — not from bootloader
    // PlatformResources. The bootloader only enumerates discovered hardware.
    let _ = found_madt;

    count
}

/// Walk the ACPI MADT starting from `rsdp_addr` and collect CPU topology.
///
/// Returns `(cpu_count, bsp_id, cpu_ids)`:
/// - `cpu_count`: number of enabled CPUs (at most 64).
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
/// Returns `(1, bsp_id, [bsp_id, 0, …])` on any parse failure so the system
/// falls back to single-CPU operation rather than refusing to boot.
///
/// # Safety
/// `rsdp_addr` must be a physical address of a valid, identity-mapped ACPI RSDP.
pub unsafe fn parse_cpu_topology(rsdp_addr: u64, bsp_id: u32) -> (u32, u32, [u32; 64])
{
    let mut cpu_ids = [0u32; 64];
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
/// APs fill indices `1..cpu_count` in MADT order.
fn parse_madt_topology(table: &[u8], bsp_id: u32, mut cpu_ids: [u32; 64]) -> (u32, u32, [u32; 64])
{
    // cpu_count starts at 0; BSP is inserted at index 0, APs appended after.
    // We collect all enabled IDs first, then place BSP at index 0.
    let mut all_ids = [0u32; 64];
    let mut all_count: usize = 0;

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
                if ((flags & 0x1 != 0) || (flags & 0x2 != 0)) && all_count < 64
                {
                    all_ids[all_count] = apic_id;
                    all_count += 1;
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
                if flags & 0x1 != 0 && all_count < 64
                {
                    all_ids[all_count] = hart_id;
                    all_count += 1;
                }
            }
            _ =>
            {}
        }

        off += entry_len;
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
        if id != bsp_id && logical_idx < 64
        {
            cpu_ids[logical_idx] = id;
            logical_idx += 1;
        }
    }

    // If BSP was not found in the MADT, count still includes it at [0].
    // all_count is at most 64, so the cast to u32 is always exact.
    #[allow(clippy::cast_possible_truncation)]
    let cpu_count = (all_count as u32).min(64);
    (cpu_count, bsp_id, cpu_ids)
}

// ── Private table parsers ─────────────────────────────────────────────────────

/// Parse a MADT table and append resources to `out[*count..]`.
///
/// Adds:
/// - Local APIC `MmioRange` (base from MADT header, size=4096)
/// - I/O APIC `MmioRanges` (one per type-1 entry)
/// - IRQ source overrides as `IrqLine` entries (one per type-2 entry)
// too_many_lines: sequential parsing of MADT entry types (IOAPIC, ISO, PLIC)
// that share accumulator state; splitting would obscure the linear table walk.
#[allow(clippy::too_many_lines)]
fn parse_madt(table: &[u8], _table_addr: u64, count: &mut usize, out: &mut [PlatformResource])
{
    macro_rules! push {
        ($res:expr) => {
            if *count < out.len()
            {
                out[*count] = $res;
                *count += 1;
            }
        };
    }

    // Local APIC base address (u32 at offset 36).
    let lapic_base = u64::from(read_u32(table, MADT_OFF_LAPIC_BASE));
    if lapic_base != 0
    {
        push!(PlatformResource {
            resource_type: ResourceType::MmioRange,
            flags: 0,
            base: lapic_base,
            size: 4096,
            id: 0,
        });
    }

    // Walk MADT interrupt controller structure entries.
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
                // Type 1 (I/O APIC), total length = 12:
                //   off+0: type  off+1: length  off+2: io_apic_id  off+3: reserved
                //   off+4: io_apic_address(u32)  off+8: global_system_interrupt_base(u32)
                let io_apic_id = u64::from(read_u8(table, off + 2));
                let io_apic_addr = u64::from(read_u32(table, off + 4));
                if io_apic_addr != 0
                {
                    push!(PlatformResource {
                        resource_type: ResourceType::MmioRange,
                        flags: 0,
                        base: io_apic_addr,
                        size: 4096,
                        id: io_apic_id,
                    });
                }
            }
            MADT_TYPE_ISO if entry_len >= 10 =>
            {
                // Type 2 (Interrupt Source Override), total length = 10:
                //   off+0: type  off+1: length  off+2: bus  off+3: source
                //   off+4: global_system_interrupt(u32)  off+8: flags(u16)
                let gsi = u64::from(read_u32(table, off + 4));
                let iso_flags = read_u16(table, off + 8);
                // Map ACPI trigger/polarity flags to boot-protocol IrqLine flags:
                //   trigger bits [3:2]: 3=level→bit0=0, else edge→bit0=1
                //   polarity bits [1:0]: 3=active-low→bit1=1, else active-high→bit1=0
                let trigger = (iso_flags >> 2) & 3;
                let polarity = iso_flags & 3;
                let resource_flags = u32::from(trigger != 3) | (u32::from(polarity == 3) << 1);
                push!(PlatformResource {
                    resource_type: ResourceType::IrqLine,
                    flags: resource_flags,
                    base: 0,
                    size: 0,
                    id: gsi,
                });
            }
            MADT_TYPE_PLIC if entry_len >= 24 =>
            {
                // Type 0x1B (RISC-V PLIC), RISC-V ACPI:
                //   off+2: version(u8)  off+3: id(u8)
                //   off+8: base_address(u64)  off+16: size(u32)
                //   off+24: max_irq_count(u32)  ...
                let plic_base = read_u64(table, off + 8);
                let max_sources = if entry_len >= 28
                {
                    read_u32(table, off + 24)
                }
                else
                {
                    // Conservative default if field not present.
                    64
                };
                // Record PLIC MMIO region.
                let plic_size = read_u32(table, off + 16);
                if plic_base != 0 && plic_size > 0
                {
                    push!(PlatformResource {
                        resource_type: ResourceType::MmioRange,
                        flags: 0,
                        base: plic_base,
                        size: u64::from(plic_size),
                        id: 0,
                    });
                }
                // Create IrqLine resources for PLIC sources. Source 0 is
                // reserved. Capped at 36 sources (1-35) to fit within the
                // ProcessInfo page cap descriptor limit (~165 descriptors).
                let plic_max = max_sources.min(36);
                for src in 1u32..plic_max
                {
                    push!(PlatformResource {
                        resource_type: ResourceType::IrqLine,
                        flags: 0,
                        base: 0,
                        size: 0,
                        id: u64::from(src),
                    });
                }
            }
            _ =>
            {} // Skip unknown MADT entry types.
        }

        off += entry_len;
    }
}

/// Parse a MCFG table and append `PciEcam` entries to `out[*count..]`.
///
/// Each 16-byte MCFG entry maps a PCI segment group to an ECAM window.
fn parse_mcfg(table: &[u8], count: &mut usize, out: &mut [PlatformResource])
{
    macro_rules! push {
        ($res:expr) => {
            if *count < out.len()
            {
                out[*count] = $res;
                *count += 1;
            }
        };
    }

    let mut off = MCFG_ENTRIES_OFF;
    while off + MCFG_ENTRY_SIZE <= table.len()
    {
        // MCFG entry layout (16 bytes):
        //   0: base_address(u64)  8: pci_segment_group(u16)
        //  10: start_bus(u8)     11: end_bus(u8)    12-15: reserved
        let base = read_u64(table, off);
        let segment = u64::from(read_u16(table, off + 8));
        let start_bus = read_u8(table, off + 10);
        let end_bus = read_u8(table, off + 11);

        if base != 0
        {
            let num_buses = u64::from(end_bus).saturating_sub(u64::from(start_bus)) + 1;
            // Each bus has 256 devices × 4096 bytes = 1 MiB per bus.
            let size = num_buses * 256 * 4096;
            let flags = u32::from(start_bus) | (u32::from(end_bus) << 8);
            push!(PlatformResource {
                resource_type: ResourceType::PciEcam,
                flags,
                base,
                size,
                id: segment,
            });

            // PCI 32-bit MMIO aperture for BAR assignments.
            // TODO: parse ACPI _CRS for real hardware; heuristic for QEMU.
            //
            // QEMU q35 (x86-64): ECAM at 0xB0000000+, BARs at 0x80000000+.
            //   Window: 0x8000_0000 – 0xAFFF_FFFF (below ECAM).
            // QEMU virt (RISC-V): ECAM at 0x30000000, BARs at 0x40000000+.
            //   Window: 0x4000_0000 – 0x7FFF_FFFF.
            //
            // Use ECAM base to select the appropriate window.
            let (win_base, win_size) = if base < 0x8000_0000
            {
                // RISC-V virt: ECAM low, BARs above ECAM.
                (0x4000_0000u64, 0x4000_0000u64)
            }
            else
            {
                // x86-64 q35: ECAM high, BARs below ECAM.
                (0x8000_0000u64, base - 0x8000_0000)
            };

            push!(PlatformResource {
                resource_type: ResourceType::MmioRange,
                flags: 0,
                base: win_base,
                size: win_size,
                id: 0,
            });

            // PCI 64-bit MMIO aperture for 64-bit BAR assignments.
            // TODO: parse ACPI _CRS for real hardware; heuristic for QEMU.
            //
            // QEMU q35 (x86-64): 64-bit window at 0x3800_0000_0000, 4 GiB.
            // QEMU virt (RISC-V): 64-bit window at 0x4_0000_0000, 16 GiB.
            let (hi_base, hi_size) = if base < 0x8000_0000
            {
                // RISC-V virt.
                (0x4_0000_0000u64, 0x4_0000_0000u64)
            }
            else
            {
                // x86-64 q35.
                (0x3800_0000_0000u64, 0x1_0000_0000u64)
            };

            push!(PlatformResource {
                resource_type: ResourceType::MmioRange,
                flags: 0,
                base: hi_base,
                size: hi_size,
                id: 0,
            });
        }

        off += MCFG_ENTRY_SIZE;
    }
}
