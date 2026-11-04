// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/acpi.rs

//! Minimal ACPI table parser: RSDP → XSDT → MADT, MCFG, RHCT, SSDT (VMGENID).
//!
//! Reads tables in-place from identity-mapped physical memory. No allocation.
//! Architecture-neutral: runs on any platform where `acpi_rsdp != 0`, which
//! includes both x86-64 (primary source) and RISC-V platforms booted under
//! UEFI firmware that publishes ACPI tables (e.g. QEMU+EDK2 virt).
//!
//! Malformed tables and ACPI 1.0 (RSDT-only) systems yield empty or
//! partial results without a diagnostic; see
//! [`core/boot/docs/acpi.md`](../docs/acpi.md) § Error Handling and
//! § Revision Gating.
//!
//! # Surface
//! - [`cpu_topology_capacity`]: MADT walk counting the CPU entries, which
//!   sizes the CPU-id pages.
//! - [`parse_cpu_topology`]: MADT walk producing `BootInfo.cpu_count` and
//!   the hardware IDs `BootInfo.cpu_ids` names.
//! - [`count_aperture_seed`]: the aperture-seed walk counting the register
//!   and heuristic-window seeds, which sizes the seed buffers.
//! - [`parse_aperture_seed`]: MADT + MCFG walk, plus the arch's
//!   platform-default MMIO apertures and PCI windows
//!   (`core/boot/docs/acpi.md` § Tables Consumed), producing the register
//!   and heuristic-window MMIO aperture seeds fed into
//!   [`super::memory_map::derive_mmio_apertures`].
//! - [`parse_hart_caps`]: RHCT walk (RISC-V, ACPI 6.5+) producing the
//!   `time` CSR frequency and the `HART_CAP_*` bits every hart advertises.
//! - [`parse_vmgenid_paddr`]: SSDT walk (QEMU VMGENID) producing the
//!   physical address of the 16-byte VM Generation ID GUID, or `0`.
//!
//! Arch-specific `kernel_mmio` extractors (LAPIC+IOAPIC on x86-64;
//! PLIC+UART on RISC-V) consume the byte helpers and layout constants
//! exposed here but live under [`crate::arch`].

use crate::bprintln;
use boot_protocol::MmioAperture;

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
const SDT_OFF_OEM_TABLE_ID: usize = 16;
const SDT_OEM_TABLE_ID_LEN: usize = 8;

// MADT entries start at offset 44 (after the SDT header + 4-byte
// `LocalApicAddress` + 4-byte flags).
pub(crate) const MADT_ENTRIES_OFF: usize = 44;

// MADT entry types:
const MADT_TYPE_LAPIC: u8 = 0; // x86-64: Processor Local APIC, length 8
pub(crate) const MADT_TYPE_IOAPIC: u8 = 1;
const MADT_TYPE_LOCAL_X2APIC: u8 = 9; // x86-64: Processor Local x2APIC, length 16
const MADT_TYPE_RINTC: u8 = 0x18; // RISC-V INTC (MADT type 24), length 36
pub(crate) const MADT_TYPE_PLIC: u8 = 0x1B; // RISC-V PLIC (MADT type 27)

// MCFG: entries start at offset 44 (SDT_HDR_LEN + 8 reserved bytes).
const MCFG_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;
const MCFG_ENTRY_SIZE: usize = 16;

// ── Byte-level read helpers ───────────────────────────────────────────────────

/// Read a little-endian u16 at byte `off` within `buf`. Returns 0 on short read.
///
/// Only the RHCT walker below consumes u16 fields; on x86-64 that walker
/// has no caller, so this helper is dead there (the module is compiled on
/// every architecture).
#[allow(dead_code)]
pub(crate) fn read_u16(buf: &[u8], off: usize) -> u16
{
    if off + 2 > buf.len()
    {
        return 0;
    }
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

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

/// Walk RSDP → XSDT and return the XSDT entry array (the 8-byte table
/// pointers after the XSDT's own SDT header), or `None` when the RSDP/XSDT
/// is absent or malformed.
///
/// # Safety
/// `rsdp_addr` must be zero or the physical address of a valid,
/// identity-mapped ACPI RSDP whose referenced tables are identity-mapped.
unsafe fn xsdt_entries<'a>(rsdp_addr: u64) -> Option<&'a [u8]>
{
    if rsdp_addr == 0
    {
        return None;
    }
    // SAFETY: caller guarantees rsdp_addr is valid and identity-mapped.
    let rsdp = unsafe { phys_slice(rsdp_addr, 36) };
    if &rsdp[..8] != RSDP_SIG || read_u8(rsdp, RSDP_OFF_REVISION) < 2
    {
        return None;
    }
    let xsdt_addr = read_u64(rsdp, RSDP_OFF_XSDT);
    if xsdt_addr == 0
    {
        return None;
    }

    // SAFETY: xsdt_addr from validated RSDP; firmware guarantees mapping.
    let xsdt_hdr = unsafe { phys_slice(xsdt_addr, SDT_HDR_LEN) };
    if &xsdt_hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"XSDT"
    {
        return None;
    }
    let xsdt_len = read_u32(xsdt_hdr, SDT_OFF_LENGTH) as usize;
    if xsdt_len < SDT_HDR_LEN
    {
        return None;
    }
    // SAFETY: length validated above; firmware guarantees mapping.
    let xsdt = unsafe { phys_slice(xsdt_addr, xsdt_len) };
    Some(&xsdt[SDT_HDR_LEN..])
}

/// Return the length-validated table at XSDT entry index `i` if its SDT
/// signature is `sig`.
///
/// # Safety
/// `entries_bytes` must come from [`xsdt_entries`]; every referenced table
/// must be identity-mapped.
unsafe fn table_at<'a>(entries_bytes: &[u8], i: usize, sig: [u8; 4]) -> Option<&'a [u8]>
{
    let table_addr = read_u64(entries_bytes, i * 8);
    if table_addr == 0
    {
        return None;
    }
    // SAFETY: table_addr read from validated XSDT; firmware guarantees mapping.
    let hdr = unsafe { phys_slice(table_addr, SDT_HDR_LEN) };
    if hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != sig
    {
        return None;
    }
    let table_len = read_u32(hdr, SDT_OFF_LENGTH) as usize;
    if table_len < SDT_HDR_LEN
    {
        return None;
    }
    // SAFETY: length validated above; firmware guarantees mapping.
    Some(unsafe { phys_slice(table_addr, table_len) })
}

/// Walk RSDP → XSDT and return the first table whose SDT signature is `sig`,
/// as a length-validated byte slice covering the whole table.
///
/// Returns `None` when the RSDP/XSDT is absent or malformed, or no table
/// matches.
///
/// # Safety
/// `rsdp_addr` must be zero or the physical address of a valid,
/// identity-mapped ACPI RSDP whose referenced tables are identity-mapped.
pub(crate) unsafe fn find_acpi_table<'a>(rsdp_addr: u64, sig: [u8; 4]) -> Option<&'a [u8]>
{
    // SAFETY: forwarded caller contract.
    let entries_bytes = unsafe { xsdt_entries(rsdp_addr)? };
    for i in 0..(entries_bytes.len() / 8)
    {
        // SAFETY: entries from xsdt_entries; forwarded caller contract.
        if let Some(table) = unsafe { table_at(entries_bytes, i, sig) }
        {
            return Some(table);
        }
    }
    None
}

// ── VMGENID (VM Generation ID, QEMU SSDT) ────────────────────────────────────
//
// QEMU publishes the VM Generation ID as an ACPI device in an SSDT whose AML
// contains a named DWORD `VGIA`, patched by the firmware's bios-linker-loader
// with the guest address of the `etc/vmgenid_guid` fw_cfg blob (4 KiB-aligned,
// below 4 GiB). The 16-byte GUID lives at offset 40 into that blob; the AML
// `ADDR` method adds the offset at evaluation time, so a no-AML consumer must
// add it itself. Discovery here is QEMU-specific by design: the
// Microsoft-spec generic path requires evaluating `ADDR`, and the bootloader
// has no AML interpreter (see the `_CRS` note in `parse_aperture_seed`).

/// AML byte pattern for QEMU's VGIA named object: `NameOp`, bare `NameSeg`
/// `"VGIA"`, `DWordPrefix`. The patched u32 (little-endian) follows.
const VGIA_PATTERN: [u8; 6] = [0x08, b'V', b'G', b'I', b'A', 0x0C];

/// Offset of the GUID within the `etc/vmgenid_guid` blob (QEMU
/// `VMGENID_GUID_OFFSET`).
const VMGENID_GUID_OFFSET: u64 = 40;

/// Scan an SSDT for the `VGIA` named DWORD and return the patched blob base.
///
/// Returns `None` when the pattern is absent, the trailing u32 is truncated,
/// or the value is implausible (zero, or not 4 KiB-aligned — the
/// linker-loader allocates the blob page-aligned).
fn find_vgia(table: &[u8]) -> Option<u32>
{
    let body = table.get(SDT_HDR_LEN..)?;
    let pos = body
        .windows(VGIA_PATTERN.len())
        .position(|w| w == VGIA_PATTERN)?;
    let val_off = pos + VGIA_PATTERN.len();
    if val_off + 4 > body.len()
    {
        return None;
    }
    let base = read_u32(body, val_off);
    if base == 0 || !base.is_multiple_of(4096)
    {
        return None;
    }
    Some(base)
}

/// Walk RSDP → XSDT over every SSDT and return the physical address of the
/// 16-byte VMGENID GUID (blob base + [`VMGENID_GUID_OFFSET`]), or `0` when
/// absent.
///
/// SSDTs whose OEM table ID starts with `VMGENID` (QEMU's marker) are
/// preferred; any other SSDT carrying the `VGIA` pattern is accepted as a
/// fallback.
///
/// # Safety
/// Same contract as [`find_acpi_table`].
pub(crate) unsafe fn parse_vmgenid_paddr(rsdp_addr: u64) -> u64
{
    // SAFETY: forwarded caller contract.
    let Some(entries_bytes) = (unsafe { xsdt_entries(rsdp_addr) })
    else
    {
        return 0;
    };

    let mut fallback: u64 = 0;
    for i in 0..(entries_bytes.len() / 8)
    {
        // SAFETY: entries from xsdt_entries; forwarded caller contract.
        let Some(table) = (unsafe { table_at(entries_bytes, i, *b"SSDT") })
        else
        {
            continue;
        };
        let Some(base) = find_vgia(table)
        else
        {
            continue;
        };
        let guid_paddr = u64::from(base) + VMGENID_GUID_OFFSET;
        let oem_id = &table[SDT_OFF_OEM_TABLE_ID..SDT_OFF_OEM_TABLE_ID + SDT_OEM_TABLE_ID_LEN];
        if oem_id.starts_with(b"VMGENID")
        {
            return guid_paddr;
        }
        if fallback == 0
        {
            fallback = guid_paddr;
        }
    }
    fallback
}

// ── RHCT (RISC-V Hart Capabilities Table, ACPI 6.5+) ─────────────────────────
//
// Only the riscv64 arch extractor calls this walker; the module is compiled
// on every architecture (arch dispatch happens at the caller), so the whole
// section is dead code on x86-64. The single allow on `parse_hart_caps` covers
// it: rustc treats an allowed item as live, and with it everything it reaches.

// RHCT layout after the 36-byte SDT header:
//  36: flags(u32)  40: time_base_frequency(u64)
//  48: node_count(u32)  52: node_offset(u32, from table start)
// Node array: each node is {type(u16), length(u16), revision(u16), payload}.
//  Type 0 (ISA string node): {isa_len(u16), isa[isa_len] (null-terminated)}.
//  Type 0xFFFF (hart info node): per-hart offsets into the shared nodes.
const RHCT_OFF_TIMEBASE: usize = 40;
const RHCT_OFF_NODE_COUNT: usize = 48;
const RHCT_OFF_NODE_OFFSET: usize = 52;
const RHCT_NODE_HDR_LEN: usize = 6;
const RHCT_NODE_TYPE_ISA_STRING: u16 = 0;

/// Parse an RHCT table body: return `(time_base_frequency, hart_caps)`.
///
/// Each `HART_CAP_*` bit is set only when at least one ISA-string node
/// exists and every ISA-string node names the corresponding extension —
/// a conservative per-bit AND. Firmware deduplicates identical ISA
/// strings into shared nodes referenced by the per-hart hart-info nodes;
/// requiring each extension in every ISA-string node is the conservative
/// reading and avoids the hart-info offset indirection.
fn parse_rhct(table: &[u8]) -> (u64, u64)
{
    let timebase = read_u64(table, RHCT_OFF_TIMEBASE);
    let node_count = read_u32(table, RHCT_OFF_NODE_COUNT) as usize;
    let mut off = read_u32(table, RHCT_OFF_NODE_OFFSET) as usize;

    let mut isa_nodes: usize = 0;
    let mut all_caps = u64::MAX;

    for _ in 0..node_count
    {
        if off + RHCT_NODE_HDR_LEN > table.len()
        {
            break;
        }
        let node_type = read_u16(table, off);
        let node_len = read_u16(table, off + 2) as usize;
        if node_len < RHCT_NODE_HDR_LEN || off + node_len > table.len()
        {
            break;
        }

        if node_type == RHCT_NODE_TYPE_ISA_STRING && node_len >= RHCT_NODE_HDR_LEN + 2
        {
            let isa_len = read_u16(table, off + RHCT_NODE_HDR_LEN) as usize;
            let isa_off = off + RHCT_NODE_HDR_LEN + 2;
            let isa_end = isa_off.saturating_add(isa_len).min(off + node_len);
            let isa = &table[isa_off.min(isa_end)..isa_end];
            isa_nodes += 1;
            let mut node_caps = 0u64;
            for (ext, bit) in crate::dtb::HART_CAP_NAMES
            {
                if crate::dtb::isa_string_has_ext(isa, ext)
                {
                    node_caps |= bit;
                }
            }
            all_caps &= node_caps;
        }

        off += node_len;
    }

    (timebase, if isa_nodes > 0 { all_caps } else { 0 })
}

/// Parse the ACPI hart capabilities from the RHCT: the `time` CSR frequency
/// and the `HART_CAP_*` bits every hart advertises.
///
/// Returns `(0, 0)` when no ACPI or no RHCT is present.
///
/// # Safety
/// `rsdp_addr` must be zero or the physical address of a valid,
/// identity-mapped ACPI RSDP whose referenced tables are identity-mapped.
// dead_code: the only caller is core/boot/src/arch/riscv64/acpi_kernel_mmio.rs;
// the module is compiled on every arch.
#[allow(dead_code)]
pub unsafe fn parse_hart_caps(rsdp_addr: u64) -> (u64, u64)
{
    // SAFETY: caller contract.
    match unsafe { find_acpi_table(rsdp_addr, *b"RHCT") }
    {
        Some(table) => parse_rhct(table),
        None => (0, 0),
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Walk the ACPI MADT starting from `rsdp_addr` and collect the CPU hardware
/// IDs into `out`, sized by [`cpu_topology_capacity`].
///
/// Returns `cpu_count`, the number of distinct enabled CPUs, the BSP counted
/// once whether or not the MADT lists it (at most `out.len()`, itself at most
/// [`boot_protocol::MAX_CPUS`]). `out[..cpu_count]` holds the per-CPU hardware IDs indexed by
/// logical CPU index: `[0]` is always `bsp_id` (the LAPIC ID on x86-64 from
/// CPUID; the boot hart ID on RISC-V from `EFI_RISCV_BOOT_PROTOCOL`), and
/// `[1..cpu_count]` are the APs in MADT discovery order. The entry types read
/// are [`madt_cpu_ids`]'.
///
/// If the firmware reports more than [`boot_protocol::MAX_CPUS`] enabled CPUs, the surplus
/// is dropped and a diagnostic is printed, so the kernel can still boot on
/// the leading [`boot_protocol::MAX_CPUS`] processors.
///
/// Returns 1, with `out[0] = bsp_id`, on any parse failure so the system
/// falls back to single-CPU operation rather than refusing to boot.
///
/// # Safety
/// `rsdp_addr` must be zero or the physical address of a valid, identity-mapped
/// ACPI RSDP. `out` must hold at least one slot.
pub unsafe fn parse_cpu_topology(rsdp_addr: u64, bsp_id: u32, out: &mut [u32]) -> u32
{
    // SAFETY: caller contract.
    if let Some(table) = unsafe { find_madt(rsdp_addr) }
    {
        return parse_madt_topology(table, bsp_id, out);
    }
    out[0] = bsp_id;
    1
}

/// Slots [`parse_cpu_topology`] needs in its `out` array for the MADT reached
/// from `rsdp_addr`: one per enabled CPU entry plus one for a BSP the MADT may
/// omit, capped at [`boot_protocol::MAX_CPUS`] (`firmware::cpu_id_capacity`). One when there
/// is no valid MADT.
///
/// # Safety
/// As [`parse_cpu_topology`].
pub unsafe fn cpu_topology_capacity(rsdp_addr: u64) -> usize
{
    // SAFETY: caller contract.
    let entries = unsafe { find_madt(rsdp_addr) }.map_or(0, |t| madt_cpu_ids(t).count());
    crate::firmware::cpu_id_capacity(entries)
}

/// The MADT (`APIC`) the XSDT reached from `rsdp_addr` lists, or `None` when
/// the RSDP, the XSDT or every MADT candidate fails validation.
///
/// # Safety
/// `rsdp_addr` must be zero or the physical address of a valid,
/// identity-mapped ACPI RSDP.
unsafe fn find_madt(rsdp_addr: u64) -> Option<&'static [u8]>
{
    if rsdp_addr == 0
    {
        return None;
    }
    // SAFETY: caller guarantees rsdp_addr is valid, identity-mapped ACPI RSDP.
    let rsdp = unsafe { phys_slice(rsdp_addr, 36) };
    if &rsdp[..8] != RSDP_SIG || read_u8(rsdp, RSDP_OFF_REVISION) < 2
    {
        return None;
    }
    let xsdt_addr = read_u64(rsdp, RSDP_OFF_XSDT);
    if xsdt_addr == 0
    {
        return None;
    }
    // SAFETY: xsdt_addr from validated RSDP; firmware guarantees physical mapping.
    let xsdt_hdr = unsafe { phys_slice(xsdt_addr, SDT_HDR_LEN) };
    if &xsdt_hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"XSDT"
    {
        return None;
    }
    let xsdt_len = read_u32(xsdt_hdr, SDT_OFF_LENGTH) as usize;
    if xsdt_len < SDT_HDR_LEN
    {
        return None;
    }
    // SAFETY: xsdt_len validated >= SDT_HDR_LEN above; firmware guarantees mapping.
    let xsdt = unsafe { phys_slice(xsdt_addr, xsdt_len) };
    let entries_bytes = &xsdt[SDT_HDR_LEN..];
    for i in 0..entries_bytes.len() / 8
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
                return Some(unsafe { phys_slice(table_addr, table_len) });
            }
        }
    }
    None
}

/// Walk MADT entries to collect CPU hardware IDs (LAPIC, x2APIC, or RINTC)
/// into `out`.
///
/// Returns `cpu_count`. The BSP is placed at index 0, APs fill indices
/// `1..cpu_count` in MADT order, each distinct hardware ID once; `cpu_count`
/// counts the BSP once whether or not the MADT lists it. CPUs beyond `out`'s
/// length, at most [`boot_protocol::MAX_CPUS`], are dropped with a diagnostic.
fn parse_madt_topology(table: &[u8], bsp_id: u32, out: &mut [u32]) -> u32
{
    let (cpu_count, truncated) = madt_topology(table, bsp_id, out);
    if truncated
    {
        bprintln!(
            "[--------] boot: ACPI: MADT reported more than MAX_CPUS enabled CPUs (BSP \
             included); surplus dropped"
        );
    }
    cpu_count
}

/// The walk behind [`parse_madt_topology`], without the console output:
/// returns `(cpu_count, truncated)`, where `truncated` is set when a distinct
/// enabled CPU found no slot in `out`.
fn madt_topology(table: &[u8], bsp_id: u32, out: &mut [u32]) -> (u32, bool)
{
    crate::firmware::place_cpu_ids(bsp_id, madt_cpu_ids(table), out)
}

/// The hardware IDs of the MADT's enabled CPU entries, in table order, a CPU
/// listed in both a Local APIC and a Local x2APIC entry yielded twice:
/// - Type 0 (Processor Local APIC, x86-64): enabled if `flags & 1 || flags & 2`.
/// - Type 9 (Processor Local x2APIC, x86-64, 32-bit IDs): enabled if
///   `flags & 1 || flags & 2`.
/// - Type 0x18 (RISC-V INTC, RINTC): enabled if `flags & 1`.
fn madt_cpu_ids(table: &[u8]) -> impl Iterator<Item = u32> + '_
{
    let mut off = MADT_ENTRIES_OFF;
    core::iter::from_fn(move || {
        while off + 2 <= table.len()
        {
            let entry_type = read_u8(table, off);
            let entry_len = read_u8(table, off + 1) as usize;
            if entry_len < 2 || off + entry_len > table.len()
            {
                return None;
            }
            let at = off;
            off += entry_len;
            match entry_type
            {
                MADT_TYPE_LAPIC if entry_len >= 8 =>
                {
                    // Type 0 (Processor Local APIC), length 8:
                    //   off+0: type  off+1: length  off+2: acpi_proc_id  off+3: apic_id
                    //   off+4: flags(u32)  bit0=enabled  bit1=online-capable
                    let flags = read_u32(table, at + 4);
                    if (flags & 0x1 != 0) || (flags & 0x2 != 0)
                    {
                        return Some(u32::from(read_u8(table, at + 3)));
                    }
                }
                MADT_TYPE_LOCAL_X2APIC if entry_len >= 16 =>
                {
                    // Type 9 (Processor Local x2APIC), length 16:
                    //   off+0: type  off+1: length  off+2: reserved(2)
                    //   off+4: x2apic_id(u32)
                    //   off+8: flags(u32)  bit0=enabled  bit1=online-capable
                    //   off+12: acpi_proc_uid(u32)
                    let flags = read_u32(table, at + 8);
                    if (flags & 0x1 != 0) || (flags & 0x2 != 0)
                    {
                        return Some(read_u32(table, at + 4));
                    }
                }
                // Type 0x18 (RISC-V INTC / RINTC), length 36:
                //   off+0: type  off+1: length  off+2: version  off+3: reserved
                //   off+4: flags(u32)  bit0=enabled
                //   off+8: hart_id(u64)  off+16: acpi_proc_uid(u32)  …
                MADT_TYPE_RINTC if entry_len >= 20 && read_u32(table, at + 4) & 0x1 != 0 =>
                {
                    // hart_id from MADT RINTC is u64 but only the lower 32 bits are used.
                    #[allow(clippy::cast_possible_truncation)]
                    return Some(read_u64(table, at + 8) as u32);
                }
                _ =>
                {}
            }
        }
        None
    })
}

// ── Aperture seeder ──────────────────────────────────────────────────────────

/// MADT entry type 5 — `LocalApicAddressOverride` (overrides the 32-bit
/// `LocalApicAddress` in the MADT header with a 64-bit value).
pub(crate) const MADT_TYPE_LAPIC_OVERRIDE: u8 = 5;

/// The named and heuristic seeds a walk wrote, and those it found.
struct SeedWalk
{
    written: (usize, usize),
    found: (usize, usize),
}

/// Write the ACPI aperture seeds into `out` and `heuristic` (see
/// [`walk_aperture_seed`] for what each holds); returns the number written to
/// each. A seed past its buffer is dropped with a diagnostic, which a buffer
/// sized by [`count_aperture_seed`] never needs.
///
/// # Safety
/// As [`walk_aperture_seed`].
pub unsafe fn parse_aperture_seed(
    rsdp_addr: u64,
    out: &mut [MmioAperture],
    heuristic: &mut [MmioAperture],
) -> (usize, usize)
{
    // SAFETY: caller contract.
    let walk = unsafe { walk_aperture_seed(rsdp_addr, out, heuristic) };
    if walk.found != walk.written
    {
        bprintln!("[--------] boot: ACPI: aperture seeds past the seed buffers dropped");
    }
    walk.written
}

/// The number of named and heuristic seeds [`parse_aperture_seed`] would
/// write into buffers large enough for every one: the same walk, writing
/// nothing. The bootloader sizes the seed buffers from it before
/// `ExitBootServices`; the tables are firmware memory that does not change
/// between the two walks.
///
/// # Safety
/// As [`walk_aperture_seed`].
pub unsafe fn count_aperture_seed(rsdp_addr: u64) -> (usize, usize)
{
    // SAFETY: caller contract.
    unsafe { walk_aperture_seed(rsdp_addr, &mut [], &mut []) }.found
}

/// Walk ACPI tables and collect MMIO extents for aperture seeding: the
/// register windows tables name into `out`, and the heuristic PCI windows
/// into `heuristic`.
///
/// Writes up to `out.len()` [`MmioAperture`] entries covering:
/// - Local APIC register window, when non-zero (x86-64 only: from the
///   MADT header, or from a `LocalApicAddressOverride` entry).
/// - Each I/O APIC register window (x86-64, MADT type 1).
/// - Each RISC-V PLIC register window (MADT type 0x1B, present on
///   RISC-V platforms that expose ACPI such as QEMU+EDK2 virt).
/// - Each MCFG ECAM window.
/// - The arch's platform-default register windows from
///   `crate::arch::current::default_mmio_apertures` (empty on x86-64),
///   appended once the RSDP and XSDT validate.
///
/// Writes up to `heuristic.len()` entries covering the 32-bit and 64-bit PCI
/// MMIO windows a QEMU q35 / virt layout heuristic places from each ECAM
/// base, and the arch's default PCI windows
/// (`crate::arch::current::default_pci_windows`, empty on x86-64). These
/// windows ignore the memory map; [`super::memory_map::derive_mmio_apertures`]
/// clips them to the map's holes and MMIO descriptors, where it clips the
/// `out` seeds only to the gaps the RAM-class and firmware-exclusive ranges
/// leave (`core/boot/docs/firmware-parsing.md` § Firmware exclusion).
///
/// Callable unconditionally on every supported architecture; a zero
/// `rsdp_addr` (no ACPI) is a fast no-op that finds nothing. The caller
/// typically also calls [`super::dtb::parse_aperture_seed`] to cover
/// DTB-only platforms, and merges both into
/// [`super::memory_map::derive_mmio_apertures`].
///
/// Returns the number of entries written to `out` and to `heuristic`, and the
/// number found (written, or past a full buffer and not written).
///
/// # Safety
/// `rsdp_addr` must be the physical address of a valid, identity-mapped
/// ACPI RSDP. A zero `rsdp_addr` returns zero counts without reading.
// too_many_lines: linear walk over MADT and MCFG with per-entry push dispatch;
// the cases are flat and inline-local, splitting them loses the walk's shape.
#[allow(clippy::too_many_lines)]
unsafe fn walk_aperture_seed(
    rsdp_addr: u64,
    out: &mut [MmioAperture],
    heuristic: &mut [MmioAperture],
) -> SeedWalk
{
    let mut n: usize = 0;
    let mut h: usize = 0;
    // Every seed found, written or not: the count pass sizes the buffers.
    let mut found_n: usize = 0;
    let mut found_h: usize = 0;

    macro_rules! push {
        ($base:expr, $size:expr) => {
            if $size > 0
            {
                found_n += 1;
                if n < out.len()
                {
                    out[n] = MmioAperture {
                        phys_base: $base,
                        size: $size,
                    };
                    n += 1;
                }
            }
        };
    }
    macro_rules! push_heuristic {
        ($base:expr, $size:expr) => {
            if $size > 0
            {
                found_h += 1;
                if h < heuristic.len()
                {
                    heuristic[h] = MmioAperture {
                        phys_base: $base,
                        size: $size,
                    };
                    h += 1;
                }
            }
        };
    }

    if rsdp_addr == 0
    {
        return SeedWalk {
            written: (n, h),
            found: (found_n, found_h),
        };
    }
    // SAFETY: caller contract.
    let rsdp = unsafe { phys_slice(rsdp_addr, 36) };
    if &rsdp[..8] != RSDP_SIG || read_u8(rsdp, RSDP_OFF_REVISION) < 2
    {
        return SeedWalk {
            written: (n, h),
            found: (found_n, found_h),
        };
    }
    let xsdt_addr = read_u64(rsdp, RSDP_OFF_XSDT);
    if xsdt_addr == 0
    {
        return SeedWalk {
            written: (n, h),
            found: (found_n, found_h),
        };
    }

    // SAFETY: validated RSDP.
    let xsdt_hdr = unsafe { phys_slice(xsdt_addr, SDT_HDR_LEN) };
    if &xsdt_hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"XSDT"
    {
        return SeedWalk {
            written: (n, h),
            found: (found_n, found_h),
        };
    }
    let xsdt_len = read_u32(xsdt_hdr, SDT_OFF_LENGTH) as usize;
    if xsdt_len < SDT_HDR_LEN
    {
        return SeedWalk {
            written: (n, h),
            found: (found_n, found_h),
        };
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
                if let Some((ecam_base, ecam_size)) = mcfg_ecam_window(base, start_bus, end_bus)
                {
                    push!(ecam_base, ecam_size);
                    // PCI BAR windows. Real hardware advertises these
                    // through the host bridge's `_CRS`, which the
                    // bootloader does not evaluate (no AML interpreter).
                    // We seed via an ECAM-base heuristic:
                    //   ECAM < 2 GiB ⇒ QEMU virt (RISC-V): 32-bit window
                    //     `[1 GiB, 2 GiB)`, fixed by QEMU; 64-bit window
                    //     `[16 GiB, 32 GiB)`, which is QEMU's 64-bit window
                    //     only for guests with at most about 14 GiB of RAM,
                    //     because QEMU rounds the window base up past the
                    //     end of RAM.
                    //   ECAM ≥ 2 GiB ⇒ q35 (x86-64): 32-bit window
                    //     below ECAM; 64-bit window `[4 GiB, 1<<MAXPHYADDR)`
                    //     so it covers wherever firmware places it
                    //     without per-CPU tuning.
                    // Neither window is bounded by the memory map here: the
                    // q35 32-bit window covers lowmem RAM above 2 GiB, the
                    // q35 64-bit window all RAM above 4 GiB, and the virt
                    // 64-bit window RAM once a guest has more than about
                    // 14 GiB, and on real hardware either can span
                    // firmware-reserved DRAM. Both go to `heuristic`, which
                    // `derive_mmio_apertures` clips to the memory map's
                    // holes and MMIO descriptors, so no aperture init
                    // receives covers RAM or firmware-reserved memory
                    // (core/boot/docs/firmware-parsing.md § Firmware exclusion).
                    let (lo_base, lo_size) = if base < 0x8000_0000
                    {
                        (0x4000_0000u64, 0x4000_0000u64)
                    }
                    else
                    {
                        (0x8000_0000u64, base - 0x8000_0000)
                    };
                    push_heuristic!(lo_base, lo_size);
                    let (hi_base, hi_size) = if base < 0x8000_0000
                    {
                        (0x4_0000_0000u64, 0x4_0000_0000u64)
                    }
                    else
                    {
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
                        (hi_base, hi_top.saturating_sub(hi_base))
                    };
                    push_heuristic!(hi_base, hi_size);
                }
                off += MCFG_ENTRY_SIZE;
            }
        }
    }

    // Per-arch platform-default MMIO apertures; the early returns above
    // skip them when ACPI is absent or malformed. They exist because some
    // firmware builds publish ACPI without an MCFG table (e.g. the EDK2
    // shipped with Ubuntu's `qemu-efi-riscv64` package, observed on CI),
    // leaving devmgr no ECAM frame, and because no table this walker reads
    // names the riscv64 UART and Goldfish RTC pages. What the defaults
    // cover and how they merge is in core/boot/docs/acpi.md § Tables
    // Consumed.
    for &(base, size) in crate::arch::current::default_mmio_apertures()
    {
        push!(base, size);
    }
    for &(base, size) in crate::arch::current::default_pci_windows()
    {
        push_heuristic!(base, size);
    }

    SeedWalk {
        written: (n, h),
        found: (found_n, found_h),
    }
}

/// ECAM window `(phys_base, size)` of one MCFG allocation entry: the MCFG
/// base is where bus 0 would decode, so the window starts `start_bus` MiB
/// above it and spans 1 MiB per bus through `end_bus`. Returns `None` for a
/// zero base, an end bus below the start bus, or a window whose start or end
/// overflows a 64-bit physical address, so a malformed entry is skipped.
fn mcfg_ecam_window(base: u64, start_bus: u8, end_bus: u8) -> Option<(u64, u64)>
{
    if base == 0 || end_bus < start_bus
    {
        return None;
    }
    let size = (u64::from(end_bus) - u64::from(start_bus) + 1) << 20;
    let window = base.checked_add(u64::from(start_bus) << 20)?;
    window.checked_add(size)?;
    Some((window, size))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::MAX_CPUS;

    #[test]
    fn mcfg_window_from_bus_zero_starts_at_the_base()
    {
        assert_eq!(
            mcfg_ecam_window(0xB000_0000, 0, 255),
            Some((0xB000_0000, 256 << 20))
        );
    }

    #[test]
    fn mcfg_window_above_bus_zero_starts_at_its_start_bus()
    {
        assert_eq!(
            mcfg_ecam_window(0xB000_0000, 4, 7),
            Some((0xB000_0000 + (4 << 20), 4 << 20))
        );
    }

    #[test]
    fn mcfg_window_with_zero_base_is_skipped()
    {
        assert_eq!(mcfg_ecam_window(0, 0, 255), None);
    }

    #[test]
    fn mcfg_window_with_end_bus_below_start_bus_is_skipped()
    {
        assert_eq!(mcfg_ecam_window(0xB000_0000, 8, 7), None);
    }

    #[test]
    fn mcfg_window_whose_start_overflows_is_skipped()
    {
        assert_eq!(mcfg_ecam_window(u64::MAX - (1 << 20) + 1, 1, 1), None);
    }

    #[test]
    fn mcfg_window_whose_end_overflows_is_skipped()
    {
        assert_eq!(mcfg_ecam_window(u64::MAX - (1 << 20) + 2, 0, 0), None);
    }

    /// Build a synthetic MADT: SDT header, LAPIC address and flags, then the
    /// given entries as `(type, apic_or_hart_id)` pairs, each enabled.
    fn madt(entries: &[(u8, u32)]) -> Vec<u8>
    {
        let mut t = vec![0u8; MADT_ENTRIES_OFF];
        t[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4].copy_from_slice(b"APIC");
        for &(entry_type, id) in entries
        {
            match entry_type
            {
                MADT_TYPE_LAPIC =>
                {
                    t.extend_from_slice(&[MADT_TYPE_LAPIC, 8, 0, id as u8]);
                    t.extend_from_slice(&1u32.to_le_bytes());
                }
                MADT_TYPE_LOCAL_X2APIC =>
                {
                    t.extend_from_slice(&[MADT_TYPE_LOCAL_X2APIC, 16, 0, 0]);
                    t.extend_from_slice(&id.to_le_bytes());
                    t.extend_from_slice(&1u32.to_le_bytes());
                    t.extend_from_slice(&0u32.to_le_bytes());
                }
                MADT_TYPE_RINTC =>
                {
                    let mut e = vec![MADT_TYPE_RINTC, 36, 1, 0];
                    e.extend_from_slice(&1u32.to_le_bytes());
                    e.extend_from_slice(&u64::from(id).to_le_bytes());
                    e.resize(36, 0);
                    t.extend_from_slice(&e);
                }
                other => panic!("madt(): unsupported entry type {other}"),
            }
        }
        let len = t.len() as u32;
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

    /// A synthetic SDT: `signature`, the length field over `body`, then
    /// `body` after the 36-byte header.
    fn sdt(signature: &[u8; 4], body: &[u8]) -> Vec<u8>
    {
        let mut t = vec![0u8; SDT_HDR_LEN];
        t[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4].copy_from_slice(signature);
        t.extend_from_slice(body);
        let len = t.len() as u32;
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
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
        madt_body.extend_from_slice(&[MADT_TYPE_IOAPIC, 12, 0, 0]);
        madt_body.extend_from_slice(&0xFEC0_0000u32.to_le_bytes());
        madt_body.extend_from_slice(&0u32.to_le_bytes());
        madt_body.extend_from_slice(&[MADT_TYPE_LAPIC_OVERRIDE, 12, 0, 0]);
        madt_body.extend_from_slice(&0xFEE0_1000u64.to_le_bytes());
        let madt = sdt(b"APIC", &madt_body);
        // MCFG: one ECAM above 2 GiB (the q35 branch) and one below (virt),
        // each with its two heuristic PCI windows.
        let mut mcfg_body = vec![0u8; MCFG_ENTRIES_OFF - SDT_HDR_LEN];
        for base in [0xB000_0000u64, 0x3000_0000u64]
        {
            mcfg_body.extend_from_slice(&base.to_le_bytes());
            mcfg_body.extend_from_slice(&[0, 0, 0, 0xFF, 0, 0, 0, 0]);
        }
        let mcfg = sdt(b"MCFG", &mcfg_body);
        let mut xsdt_body = Vec::new();
        xsdt_body.extend_from_slice(&(madt.as_ptr() as u64).to_le_bytes());
        xsdt_body.extend_from_slice(&(mcfg.as_ptr() as u64).to_le_bytes());
        let xsdt = sdt(b"XSDT", &xsdt_body);
        let mut rsdp = vec![0u8; 36];
        rsdp[..8].copy_from_slice(RSDP_SIG);
        rsdp[RSDP_OFF_REVISION] = 2;
        rsdp[RSDP_OFF_XSDT..RSDP_OFF_XSDT + 8]
            .copy_from_slice(&(xsdt.as_ptr() as u64).to_le_bytes());
        let addr = rsdp.as_ptr() as u64;

        // SAFETY: rsdp, xsdt, madt and mcfg are live, well-formed tables at
        // the addresses they name.
        let (named, heuristic) = unsafe { count_aperture_seed(addr) };
        let defaults = crate::arch::current::default_mmio_apertures().len();
        let pci_defaults = crate::arch::current::default_pci_windows().len();
        assert_eq!(named, 4 + defaults, "LAPIC, I/O APIC and two ECAM windows");
        assert_eq!(heuristic, 4 + pci_defaults, "two PCI windows per ECAM");

        let empty = MmioAperture {
            phys_base: 0,
            size: 0,
        };
        let mut out = vec![empty; named + 4];
        let mut out_h = vec![empty; heuristic + 4];
        // SAFETY: as above.
        let written = unsafe { parse_aperture_seed(addr, &mut out, &mut out_h) };
        assert_eq!(written, (named, heuristic));
        assert!(out[..named].iter().any(|a| a.phys_base == 0xFEE0_1000));

        // Buffers of exactly the counted sizes drop nothing.
        let mut exact = vec![empty; named];
        let mut exact_h = vec![empty; heuristic];
        // SAFETY: as above.
        let exact_written = unsafe { parse_aperture_seed(addr, &mut exact, &mut exact_h) };
        assert_eq!(exact_written, (named, heuristic));
        let spans =
            |a: &[MmioAperture]| a.iter().map(|a| (a.phys_base, a.size)).collect::<Vec<_>>();
        assert_eq!(spans(&exact), spans(&out[..named]));
        assert_eq!(spans(&exact_h), spans(&out_h[..heuristic]));
    }

    /// Run `madt_topology` over a synthetic MADT; returns the count, the
    /// filled IDs, and the truncation flag.
    fn topology_full(entries: &[(u8, u32)], bsp_id: u32) -> (u32, Vec<u32>, bool)
    {
        let table = madt(entries);
        let mut ids = vec![0u32; crate::firmware::cpu_id_capacity(madt_cpu_ids(&table).count())];
        let (count, truncated) = madt_topology(&table, bsp_id, &mut ids);
        (count, ids[..count as usize].to_vec(), truncated)
    }

    fn topology(entries: &[(u8, u32)], bsp_id: u32) -> (u32, Vec<u32>)
    {
        let (count, ids, truncated) = topology_full(entries, bsp_id);
        assert!(!truncated);
        (count, ids)
    }

    #[test]
    fn madt_bsp_listed_first_places_aps_in_order()
    {
        let entries = [
            (MADT_TYPE_LAPIC, 0),
            (MADT_TYPE_LAPIC, 1),
            (MADT_TYPE_LAPIC, 2),
        ];
        assert_eq!(topology(&entries, 0), (3, vec![0, 1, 2]));
    }

    #[test]
    fn madt_bsp_listed_twice_is_counted_once()
    {
        let entries = [
            (MADT_TYPE_LAPIC, 0),
            (MADT_TYPE_LOCAL_X2APIC, 0),
            (MADT_TYPE_LAPIC, 1),
        ];
        assert_eq!(topology(&entries, 0), (2, vec![0, 1]));
    }

    #[test]
    fn madt_bsp_absent_keeps_every_ap()
    {
        let entries = [(MADT_TYPE_LAPIC, 1), (MADT_TYPE_LAPIC, 2)];
        assert_eq!(topology(&entries, 0), (3, vec![0, 1, 2]));
    }

    #[test]
    fn madt_duplicated_ap_is_listed_once()
    {
        let entries = [
            (MADT_TYPE_LAPIC, 0),
            (MADT_TYPE_LAPIC, 1),
            (MADT_TYPE_LOCAL_X2APIC, 1),
        ];
        assert_eq!(topology(&entries, 0), (2, vec![0, 1]));
    }

    #[test]
    fn madt_rintc_harts_follow_the_boot_hart()
    {
        let entries = [
            (MADT_TYPE_RINTC, 0),
            (MADT_TYPE_RINTC, 1),
            (MADT_TYPE_RINTC, 2),
        ];
        assert_eq!(topology(&entries, 2), (3, vec![2, 0, 1]));
    }

    #[test]
    fn madt_without_cpu_entries_falls_back_to_the_bsp()
    {
        assert_eq!(topology(&[], 7), (1, vec![7]));
    }

    #[test]
    fn madt_surplus_beyond_max_cpus_is_dropped_and_reported()
    {
        let max = MAX_CPUS as u32;
        let entries: Vec<(u8, u32)> = (0..=max).map(|id| (MADT_TYPE_LOCAL_X2APIC, id)).collect();
        let (count, ids, truncated) = topology_full(&entries, 0);
        assert_eq!(count, max);
        assert_eq!(ids, (0..max).collect::<Vec<u32>>());
        assert!(truncated);
    }

    #[test]
    fn madt_full_without_the_bsp_drops_one_ap_and_reports_it()
    {
        let max = MAX_CPUS as u32;
        let entries: Vec<(u8, u32)> = (1..=max).map(|id| (MADT_TYPE_LOCAL_X2APIC, id)).collect();
        let (count, ids, truncated) = topology_full(&entries, 0);
        assert_eq!(count, max);
        assert_eq!(ids, (0..max).collect::<Vec<u32>>());
        assert!(truncated);
    }

    #[test]
    fn madt_exactly_max_cpus_with_the_bsp_is_not_truncated()
    {
        let max = MAX_CPUS as u32;
        let entries: Vec<(u8, u32)> = (0..max).map(|id| (MADT_TYPE_LOCAL_X2APIC, id)).collect();
        assert_eq!(topology(&entries, 0), (max, (0..max).collect::<Vec<u32>>()));
    }

    /// Build a synthetic RHCT: SDT header + flags/timebase/node-count/offset
    /// header, followed by the given nodes as `(type, payload)` pairs.
    fn rhct(timebase: u64, nodes: &[(u16, &[u8])]) -> Vec<u8>
    {
        let mut t = vec![0u8; 56];
        t[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4].copy_from_slice(b"RHCT");
        t[RHCT_OFF_TIMEBASE..RHCT_OFF_TIMEBASE + 8].copy_from_slice(&timebase.to_le_bytes());
        t[RHCT_OFF_NODE_COUNT..RHCT_OFF_NODE_COUNT + 4]
            .copy_from_slice(&(nodes.len() as u32).to_le_bytes());
        t[RHCT_OFF_NODE_OFFSET..RHCT_OFF_NODE_OFFSET + 4].copy_from_slice(&56u32.to_le_bytes());

        for &(node_type, payload) in nodes
        {
            let node_len = (RHCT_NODE_HDR_LEN + payload.len()) as u16;
            t.extend_from_slice(&node_type.to_le_bytes());
            t.extend_from_slice(&node_len.to_le_bytes());
            t.extend_from_slice(&1u16.to_le_bytes()); // revision
            t.extend_from_slice(payload);
        }

        let len = t.len() as u32;
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

    /// ISA-string node payload: `{isa_len(u16), isa bytes incl. NUL}`.
    fn isa_payload(isa: &[u8]) -> Vec<u8>
    {
        let mut p = Vec::new();
        p.extend_from_slice(&((isa.len() + 1) as u16).to_le_bytes());
        p.extend_from_slice(isa);
        p.push(0);
        p
    }

    #[test]
    fn rhct_timebase_and_caps()
    {
        use boot_protocol::{HART_CAP_SSTC, HART_CAP_SVINVAL, HART_CAP_SVNAPOT, HART_CAP_SVPBMT};
        let isa = isa_payload(b"rv64imafdcvh_zicsr_sstc_svpbmt_svinval_svnapot_svadu");
        let table = rhct(10_000_000, &[(RHCT_NODE_TYPE_ISA_STRING, &isa)]);
        assert_eq!(
            parse_rhct(&table),
            (
                10_000_000,
                HART_CAP_SSTC | HART_CAP_SVPBMT | HART_CAP_SVINVAL | HART_CAP_SVNAPOT
            )
        );
    }

    #[test]
    fn rhct_caps_absent_from_isa_string()
    {
        let isa = isa_payload(b"rv64imafdc_zicsr");
        let table = rhct(10_000_000, &[(RHCT_NODE_TYPE_ISA_STRING, &isa)]);
        assert_eq!(parse_rhct(&table), (10_000_000, 0));
    }

    #[test]
    fn rhct_cap_denied_only_for_the_bit_a_node_lacks()
    {
        use boot_protocol::HART_CAP_SVINVAL;
        // Per-bit AND: the second node advertises only svinval.
        let with = isa_payload(b"rv64imafdc_sstc_svinval");
        let without = isa_payload(b"rv64imafdc_svinval");
        let table = rhct(
            10_000_000,
            &[
                (RHCT_NODE_TYPE_ISA_STRING, &with),
                (RHCT_NODE_TYPE_ISA_STRING, &without),
            ],
        );
        assert_eq!(parse_rhct(&table).1, HART_CAP_SVINVAL);
    }

    #[test]
    fn rhct_skips_non_isa_nodes()
    {
        use boot_protocol::HART_CAP_SSTC;
        let isa = isa_payload(b"rv64imafdc_sstc");
        // Hart-info node (type 0xFFFF): num_offsets=1, uid=0, one offset.
        let hart_info: &[u8] = &[1, 0, 0, 0, 0, 0, 56, 0, 0, 0];
        let table = rhct(
            10_000_000,
            &[(RHCT_NODE_TYPE_ISA_STRING, &isa), (0xFFFF, hart_info)],
        );
        assert_eq!(parse_rhct(&table), (10_000_000, HART_CAP_SSTC));
    }

    #[test]
    fn rhct_no_isa_nodes_means_no_caps()
    {
        let table = rhct(10_000_000, &[]);
        assert_eq!(parse_rhct(&table), (10_000_000, 0));
    }

    #[test]
    fn rhct_truncated_node_is_rejected_safely()
    {
        let isa = isa_payload(b"rv64imafdc_sstc");
        let mut table = rhct(10_000_000, &[(RHCT_NODE_TYPE_ISA_STRING, &isa)]);
        // Truncate mid-node: the walker must stop without panicking, and
        // without having confirmed any capability from a complete node.
        table.truncate(60);
        let (freq, caps) = parse_rhct(&table);
        assert_eq!(freq, 10_000_000);
        assert_eq!(caps, 0);
    }

    /// Build a synthetic SSDT: SDT header + the given AML body bytes.
    fn ssdt(body: &[u8]) -> Vec<u8>
    {
        let mut t = vec![0u8; SDT_HDR_LEN];
        t[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4].copy_from_slice(b"SSDT");
        t.extend_from_slice(body);
        let len = t.len() as u32;
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

    /// `Name(VGIA, DWordConst)` AML fragment with the given patched value.
    fn vgia_fragment(value: u32) -> Vec<u8>
    {
        let mut f = VGIA_PATTERN.to_vec();
        f.extend_from_slice(&value.to_le_bytes());
        f
    }

    #[test]
    fn vgia_found_amid_surrounding_aml()
    {
        let mut body = vec![0x10, 0x2A, 0x5C, 0x00]; // arbitrary leading AML bytes
        body.extend_from_slice(&vgia_fragment(0x7FDE_1000));
        body.extend_from_slice(&[0xA4, 0x00]); // trailing bytes
        assert_eq!(find_vgia(&ssdt(&body)), Some(0x7FDE_1000));
    }

    #[test]
    fn vgia_absent_pattern_yields_none()
    {
        assert_eq!(find_vgia(&ssdt(&[0x10, 0x2A, 0x5C, 0x00])), None);
    }

    #[test]
    fn vgia_truncated_after_prefix_yields_none()
    {
        let mut body = VGIA_PATTERN.to_vec();
        body.extend_from_slice(&[0x00, 0x10]); // only 2 of 4 value bytes
        assert_eq!(find_vgia(&ssdt(&body)), None);
    }

    #[test]
    fn vgia_zero_value_yields_none()
    {
        assert_eq!(find_vgia(&ssdt(&vgia_fragment(0))), None);
    }

    #[test]
    fn vgia_unaligned_value_yields_none()
    {
        assert_eq!(find_vgia(&ssdt(&vgia_fragment(0x7FDE_1004))), None);
    }

    #[test]
    fn vgia_pattern_in_header_is_ignored()
    {
        // The scan starts after the SDT header; a coincidental pattern in the
        // OEM table ID bytes must not match.
        let mut t = ssdt(&[0x00; 16]);
        t[SDT_OFF_OEM_TABLE_ID..SDT_OFF_OEM_TABLE_ID + 6].copy_from_slice(&VGIA_PATTERN);
        assert_eq!(find_vgia(&t), None);
    }
}
