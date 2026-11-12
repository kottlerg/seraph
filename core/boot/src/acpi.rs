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
//! - [`parse_aperture_seed`]: MADT + MCFG + DMAR walk, plus the arch's
//!   platform-default MMIO apertures and PCI windows
//!   (`core/boot/docs/acpi.md` § Tables Consumed), producing the register
//!   and heuristic-window MMIO aperture seeds fed into
//!   [`super::memory_map::derive_mmio_apertures`].
//! - [`parse_hart_caps`]: RHCT walk (RISC-V, ACPI 6.5+) producing the
//!   `time` CSR frequency and the `HART_CAP_*` bits every hart advertises.
//! - [`parse_vmgenid_paddr`]: SSDT walk (QEMU VMGENID) producing the
//!   physical address of the 16-byte VM Generation ID GUID, or `0`.
//! - [`madt_aia`]: MADT walk (RISC-V, ACPI 6.5+) producing the
//!   supervisor-level APLIC domain and IMSIC layout.
//!
//! Arch-specific `kernel_mmio` extractors (LAPIC+IOAPIC on x86-64;
//! APLIC+IMSIC+UART on RISC-V) consume the byte helpers and layout
//! constants exposed here but live under [`crate::arch`].

use crate::bprintln;
use boot_protocol::{AplicDomain, ImsicLayout, MmioAperture};

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
const MADT_TYPE_IMSIC: u8 = 0x19; // RISC-V IMSIC (MADT type 25), length 16
const MADT_TYPE_APLIC: u8 = 0x1A; // RISC-V APLIC (MADT type 26), length 36

// MCFG: entries start at offset 44 (SDT_HDR_LEN + 8 reserved bytes).
const MCFG_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;
const MCFG_ENTRY_SIZE: usize = 16;

// ── Byte-level read helpers ───────────────────────────────────────────────────

/// The `N` bytes at byte `off` within `buf`, or `None` on a short read or an
/// offset that overflows.
fn read_array<const N: usize>(buf: &[u8], off: usize) -> Option<[u8; N]>
{
    buf.get(off..)?.first_chunk::<N>().copied()
}

/// Read a little-endian u16 at byte `off` within `buf`. Returns 0 on short read.
///
/// Only the RHCT walker below consumes u16 fields; on x86-64 that walker
/// has no caller, so this helper is dead there (the module is compiled on
/// every architecture).
#[allow(dead_code)]
pub(crate) fn read_u16(buf: &[u8], off: usize) -> u16
{
    read_array(buf, off).map_or(0, u16::from_le_bytes)
}

/// Read a little-endian u32 at byte `off` within `buf`. Returns 0 on short read.
pub(crate) fn read_u32(buf: &[u8], off: usize) -> u32
{
    read_array(buf, off).map_or(0, u32::from_le_bytes)
}

/// Read a little-endian u64 at byte `off` within `buf`. Returns 0 on short read.
pub(crate) fn read_u64(buf: &[u8], off: usize) -> u64
{
    read_array(buf, off).map_or(0, u64::from_le_bytes)
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

/// The signature of the SDT whose header is `hdr`, or `None` for a header
/// shorter than the signature.
pub(crate) fn sdt_sig(hdr: &[u8]) -> Option<[u8; 4]>
{
    read_array(hdr, SDT_OFF_SIGNATURE)
}

/// The table address in XSDT entry `i` of `entries_bytes`; `0` (which every
/// walker skips) for an entry past the array.
pub(crate) fn xsdt_entry_addr(entries_bytes: &[u8], i: usize) -> u64
{
    i.checked_mul(8)
        .map_or(0, |off| read_u64(entries_bytes, off))
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
    if !rsdp.starts_with(RSDP_SIG) || read_u8(rsdp, RSDP_OFF_REVISION) < 2
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
    if sdt_sig(xsdt_hdr) != Some(*b"XSDT")
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
    xsdt.get(SDT_HDR_LEN..)
}

/// Return the header of the table at XSDT entry index `i`, or `None` for an
/// absent (zero) entry.
///
/// # Safety
/// `entries_bytes` must come from [`xsdt_entries`]; every referenced table
/// must be identity-mapped.
unsafe fn table_header_at<'a>(entries_bytes: &[u8], i: usize) -> Option<(u64, &'a [u8])>
{
    let table_addr = xsdt_entry_addr(entries_bytes, i);
    if table_addr == 0
    {
        return None;
    }
    // SAFETY: table_addr read from validated XSDT; firmware guarantees mapping.
    Some((table_addr, unsafe { phys_slice(table_addr, SDT_HDR_LEN) }))
}

/// Return the length-validated table at XSDT entry index `i` if its SDT
/// signature is `sig`.
///
/// # Safety
/// `entries_bytes` must come from [`xsdt_entries`]; every referenced table
/// must be identity-mapped.
unsafe fn table_at<'a>(entries_bytes: &[u8], i: usize, sig: [u8; 4]) -> Option<&'a [u8]>
{
    // SAFETY: forwarded caller contract.
    let (table_addr, hdr) = unsafe { table_header_at(entries_bytes, i)? };
    if sdt_sig(hdr) != Some(sig)
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
    // `pos` is the start of a match inside `body`, so the sum cannot overflow.
    let val_off = pos.saturating_add(VGIA_PATTERN.len());
    if val_off.checked_add(4)? > body.len()
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
        // `base` is a `u32`, so adding the small GUID offset cannot overflow.
        let guid_paddr = u64::from(base).saturating_add(VMGENID_GUID_OFFSET);
        let Some(oem_id) =
            table.get(SDT_OFF_OEM_TABLE_ID..SDT_OFF_OEM_TABLE_ID + SDT_OEM_TABLE_ID_LEN)
        else
        {
            continue;
        };
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
        let Some(hdr_end) = off.checked_add(RHCT_NODE_HDR_LEN)
        else
        {
            break;
        };
        if hdr_end > table.len()
        {
            break;
        }
        let node_type = read_u16(table, off);
        // The node header lies inside `table`, so `off + 2` cannot overflow.
        let node_len = read_u16(table, off.saturating_add(2)) as usize;
        let Some(node_end) = off.checked_add(node_len)
        else
        {
            break;
        };
        if node_len < RHCT_NODE_HDR_LEN || node_end > table.len()
        {
            break;
        }

        if node_type == RHCT_NODE_TYPE_ISA_STRING && node_len >= RHCT_NODE_HDR_LEN + 2
        {
            let isa_len = read_u16(table, hdr_end) as usize;
            // The node is at least `RHCT_NODE_HDR_LEN + 2` bytes inside `table`.
            let isa_off = hdr_end.saturating_add(2);
            let isa_end = isa_off.saturating_add(isa_len).min(node_end);
            let isa = table.get(isa_off.min(isa_end)..isa_end).unwrap_or(&[]);
            isa_nodes = isa_nodes.saturating_add(1);
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

        off = node_end;
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
/// falls back to single-CPU operation rather than refusing to boot. An `out`
/// with no slot places nothing and returns 0; the caller sizes it to at least
/// one slot.
///
/// # Safety
/// `rsdp_addr` must be zero or the physical address of a valid, identity-mapped
/// ACPI RSDP.
pub unsafe fn parse_cpu_topology(rsdp_addr: u64, bsp_id: u32, out: &mut [u32]) -> u32
{
    // SAFETY: caller contract.
    if let Some(table) = unsafe { find_madt(rsdp_addr) }
    {
        return parse_madt_topology(table, bsp_id, out);
    }
    // The BSP alone, in slot 0; an `out` with no slot places nothing.
    let Some(slot) = out.first_mut()
    else
    {
        return 0;
    };
    *slot = bsp_id;
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
    // SAFETY: caller contract.
    let entries_bytes = unsafe { xsdt_entries(rsdp_addr)? };
    for i in 0..entries_bytes.len() / 8
    {
        // SAFETY: entries from xsdt_entries; forwarded caller contract.
        if let Some(table) = unsafe { table_at(entries_bytes, i, *b"APIC") }
        {
            return Some(table);
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
    madt_entries(table).filter_map(|(entry_type, e)| match entry_type
    {
        MADT_TYPE_LAPIC if e.len() >= 8 =>
        {
            // Type 0 (Processor Local APIC), length 8:
            //   off+0: type  off+1: length  off+2: acpi_proc_id  off+3: apic_id
            //   off+4: flags(u32)  bit0=enabled  bit1=online-capable
            let flags = read_u32(e, 4);
            ((flags & 0x1 != 0) || (flags & 0x2 != 0)).then(|| u32::from(read_u8(e, 3)))
        }
        MADT_TYPE_LOCAL_X2APIC if e.len() >= 16 =>
        {
            // Type 9 (Processor Local x2APIC), length 16:
            //   off+0: type  off+1: length  off+2: reserved(2)
            //   off+4: x2apic_id(u32)
            //   off+8: flags(u32)  bit0=enabled  bit1=online-capable
            //   off+12: acpi_proc_uid(u32)
            let flags = read_u32(e, 8);
            ((flags & 0x1 != 0) || (flags & 0x2 != 0)).then(|| read_u32(e, 4))
        }
        // Type 0x18 (RISC-V INTC / RINTC), length 36:
        //   off+0: type  off+1: length  off+2: version  off+3: reserved
        //   off+4: flags(u32)  bit0=enabled
        //   off+8: hart_id(u64)  off+16: acpi_proc_uid(u32)  …
        MADT_TYPE_RINTC if e.len() >= 20 && read_u32(e, 4) & 0x1 != 0 =>
        {
            // hart_id from MADT RINTC is u64 but only the lower 32 bits are used.
            #[allow(clippy::cast_possible_truncation)]
            let hart_id = read_u64(e, 8) as u32;
            Some(hart_id)
        }
        _ => None,
    })
}

// ── AIA discovery (RISC-V APLIC and IMSIC, ACPI 6.5+) ────────────────────────

/// Lengths of the MADT's RISC-V AIA structures.
mod madt_len
{
    /// A RINTC structure that carries its hart's IMSIC file address
    /// (version 1 and later).
    pub(super) const RINTC_IMSIC: usize = 36;
    /// The IMSIC structure.
    pub(super) const IMSIC: usize = 16;
    /// The APLIC structure.
    pub(super) const APLIC: usize = 36;
}

/// The MADT entries of `table` as `(type, entry)`, in table order, ending at
/// the first entry whose length is under 2 or runs past the table.
pub(crate) fn madt_entries(table: &[u8]) -> impl Iterator<Item = (u8, &[u8])> + '_
{
    let mut off = MADT_ENTRIES_OFF;
    core::iter::from_fn(move || {
        let entry_len = usize::from(*table.get(off.checked_add(1)?)?);
        if entry_len < 2
        {
            return None;
        }
        let entry = table.get(off..off.checked_add(entry_len)?)?;
        // The entry ends inside `table`, so `off + entry_len` cannot overflow.
        off = off.saturating_add(entry_len);
        Some((*entry.first()?, entry))
    })
}

/// The supervisor-level IMSIC file each enabled RINTC structure of `table`
/// names, as `(hart_id, file_address, file_size)`; address and size zero for a
/// RINTC too short to carry them.
///
/// RINTC structure layout (version 1, 36 bytes):
/// - `+ 4`: `flags(u32)`, bit 0 = enabled
/// - `+ 8`: `hart_id(u64)`
/// - `+16`: `acpi_processor_uid(u32)`
/// - `+20`: `external_interrupt_controller_id(u32)`
/// - `+24`: `imsic_base_address(u64)`
/// - `+32`: `imsic_size(u32)`
fn rintc_imsic_files(table: &[u8]) -> impl Iterator<Item = (u64, u64, u64)> + '_
{
    madt_entries(table).filter_map(|(ty, e)| {
        if ty != MADT_TYPE_RINTC || e.len() < 16 || read_u32(e, 4) & 0x1 == 0
        {
            return None;
        }
        let (addr, size) = if e.len() >= madt_len::RINTC_IMSIC
        {
            (read_u64(e, 24), u64::from(read_u32(e, 32)))
        }
        else
        {
            (0, 0)
        };
        Some((read_u64(e, 8), addr, size))
    })
}

/// What the MADT reports of the supervisor's AIA interrupt controllers
/// ([`madt_aia`]).
pub(crate) struct MadtAia
{
    /// The first APLIC structure with a non-zero base; zero when none.
    pub aplic: AplicDomain,
    /// The IMSIC layout; zero when the MADT has no IMSIC structure, no
    /// enabled RINTC, or [`Self::off_layout_hart`] is set.
    pub imsic: ImsicLayout,
    /// The hart ID of the first enabled RINTC whose IMSIC file address does
    /// not lie at [`ImsicLayout::s_file_address`] of its hart ID under the
    /// layout the first enabled RINTC fixes.
    pub off_layout_hart: Option<u64>,
}

/// The supervisor's APLIC domain and IMSIC layout the MADT `table` reports.
///
/// The IMSIC structure gives the index widths and the identity count; the
/// RINTC structures give each hart's file address. The layout's base is the
/// first enabled RINTC's file address less [`ImsicLayout::s_file_offset`] of
/// its hart ID, and the layout is reported only when every enabled RINTC's
/// file lies at [`ImsicLayout::s_file_address`] of its own hart ID.
///
/// IMSIC structure layout (16 bytes):
/// - `+ 4`: `flags(u32)`
/// - `+ 8`: `supervisor_interrupt_identities(u16)`
/// - `+10`: `guest_interrupt_identities(u16)`
/// - `+12`: `guest_index_bits(u8)`, `+13`: `hart_index_bits(u8)`,
///   `+14`: `group_index_bits(u8)`, `+15`: `group_index_shift(u8)`
///
/// APLIC structure layout (36 bytes):
/// - `+ 3`: `aplic_id(u8)`, `+ 4`: `flags(u32)`, `+ 8`: `hardware_id(8B)`
/// - `+16`: `idc_count(u16)`, `+18`: `external_interrupt_sources(u16)`
/// - `+20`: `gsi_base(u32)`, `+24`: `base(u64)`, `+32`: `size(u32)`
#[cfg_attr(
    all(not(target_arch = "riscv64"), not(test)),
    expect(
        dead_code,
        reason = "the only non-test caller is core/boot/src/arch/riscv64/acpi_kernel_mmio.rs; \
                  the module is compiled on every arch"
    )
)]
pub(crate) fn madt_aia(table: &[u8]) -> MadtAia
{
    let mut found = MadtAia {
        aplic: AplicDomain::zero(),
        imsic: ImsicLayout::zero(),
        off_layout_hart: None,
    };
    let mut layout = None;
    for (ty, e) in madt_entries(table)
    {
        match ty
        {
            MADT_TYPE_IMSIC if e.len() >= madt_len::IMSIC && layout.is_none() =>
            {
                layout = Some(ImsicLayout {
                    base: 0,
                    ids: u32::from(read_u16(e, 8)),
                    guest_index_bits: read_u8(e, 12),
                    hart_index_bits: read_u8(e, 13),
                    group_index_bits: read_u8(e, 14),
                    group_index_shift: read_u8(e, 15),
                });
            }
            MADT_TYPE_APLIC
                if e.len() >= madt_len::APLIC && found.aplic.base == 0 && read_u64(e, 24) != 0 =>
            {
                found.aplic = AplicDomain {
                    base: read_u64(e, 24),
                    size: u64::from(read_u32(e, 32)),
                    sources: u64::from(read_u16(e, 18)),
                };
            }
            _ =>
            {}
        }
    }

    let Some(mut layout) = layout
    else
    {
        return found;
    };
    let mut harts = 0usize;
    for (hart_id, addr, _) in rintc_imsic_files(table)
    {
        if harts == 0
        {
            layout.base = layout
                .s_file_offset(hart_id)
                .and_then(|offset| addr.checked_sub(offset))
                .unwrap_or(0);
        }
        // `harts` counts RINTC entries of one table, far below `usize::MAX`.
        harts = harts.saturating_add(1);
        if addr == 0 || layout.s_file_address(hart_id) != Some(addr)
        {
            found.off_layout_hart = Some(hart_id);
            return found;
        }
    }
    if harts > 0
    {
        found.imsic = layout;
    }
    found
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
/// - Each RISC-V APLIC register window (MADT type 0x1A), and each
///   supervisor-level IMSIC file an enabled RINTC structure (MADT type 0x18)
///   names, one seed per file.
/// - Each MCFG ECAM window.
/// - Each VT-d remapping unit's register set (DMAR DRHD), which no other
///   table names.
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
// too_many_lines: linear walk over MADT, MCFG, and DMAR with per-entry push dispatch;
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
                // The counts index seeds found in one table walk, far below
                // `usize::MAX`.
                found_n = found_n.saturating_add(1);
                if let Some(slot) = out.get_mut(n)
                {
                    *slot = MmioAperture {
                        phys_base: $base,
                        size: $size,
                    };
                    n = n.saturating_add(1);
                }
            }
        };
    }
    macro_rules! push_heuristic {
        ($base:expr, $size:expr) => {
            if $size > 0
            {
                found_h = found_h.saturating_add(1);
                if let Some(slot) = heuristic.get_mut(h)
                {
                    *slot = MmioAperture {
                        phys_base: $base,
                        size: $size,
                    };
                    h = h.saturating_add(1);
                }
            }
        };
    }

    // SAFETY: caller contract.
    let Some(entries_bytes) = (unsafe { xsdt_entries(rsdp_addr) })
    else
    {
        return SeedWalk {
            written: (n, h),
            found: (found_n, found_h),
        };
    };

    for i in 0..(entries_bytes.len() / 8)
    {
        // SAFETY: entries from xsdt_entries; forwarded caller contract.
        let Some((table_addr, hdr)) = (unsafe { table_header_at(entries_bytes, i) })
        else
        {
            continue;
        };
        let sig = sdt_sig(hdr).unwrap_or([0; 4]);
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
            for (entry_type, e) in madt_entries(table)
            {
                match entry_type
                {
                    MADT_TYPE_IOAPIC if e.len() >= 12 =>
                    {
                        push!(u64::from(read_u32(e, 4)), 0x1000u64);
                    }
                    MADT_TYPE_LAPIC_OVERRIDE if e.len() >= 12 =>
                    {
                        lapic = read_u64(e, 4);
                    }
                    MADT_TYPE_APLIC if e.len() >= madt_len::APLIC =>
                    {
                        // Layout at `madt_aia`.
                        let size = u64::from(read_u32(e, 32));
                        let base = read_u64(e, 24);
                        push!(base, size);
                    }
                    MADT_TYPE_RINTC
                        if e.len() >= madt_len::RINTC_IMSIC && read_u32(e, 4) & 0x1 != 0 =>
                    {
                        // Layout at `rintc_imsic_files`. One seed per file:
                        // `derive_mmio_apertures` merges abutting files into
                        // one aperture per IMSIC group and leaves the gaps
                        // between groups, which no table names, unseeded.
                        let base = read_u64(e, 24);
                        let size = u64::from(read_u32(e, 32));
                        if base != 0 && base.checked_add(size).is_some()
                        {
                            push!(base, size);
                        }
                    }
                    _ =>
                    {}
                }
            }
            if lapic != 0
            {
                push!(lapic, 0x1000u64);
            }
        }
        else if &sig == b"MCFG"
        {
            let entries = table.get(MCFG_ENTRIES_OFF..).unwrap_or(&[]);
            for e in entries.as_chunks::<MCFG_ENTRY_SIZE>().0
            {
                let base = read_u64(e, 0);
                let start_bus = read_u8(e, 10);
                let end_bus = read_u8(e, 11);
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
                        // `base` is at least 2 GiB on this branch.
                        (0x8000_0000u64, base.saturating_sub(0x8000_0000))
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
            }
        }
        else if &sig == b"DMAR"
        {
            // Each VT-d remapping unit's register set: no other table names
            // it, and devmgr hands it to the IOMMU driver as an `Mmio` cap.
            let mut rest = table.get(DMAR_STRUCTURES_OFF..).unwrap_or(&[]);
            while rest.len() >= 4
            {
                let kind = read_u16(rest, 0);
                let len = usize::from(read_u16(rest, 2));
                if len < 4
                {
                    break;
                }
                let Some((entry, tail)) = rest.split_at_checked(len)
                else
                {
                    break;
                };
                if let Some((base, size)) = drhd_register_window(entry, kind)
                {
                    push!(base, size);
                }
                rest = tail;
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

/// First DMAR remapping structure: after the header, the host address width
/// (u8), the flags (u8), and 10 reserved bytes (Intel VT-d specification,
/// section 8.1).
const DMAR_STRUCTURES_OFF: usize = SDT_HDR_LEN + 12;

/// Register window `(phys_base, size)` of one DMAR remapping structure
/// `entry` of type `kind`, when it is a DMA Remapping Hardware Unit
/// Definition (type 0, VT-d section 8.3): its register base (u64 at 8) and
/// `2^size` pages (the low nibble of the u8 at 5). Returns `None` for any
/// other structure, one shorter than a DRHD's 16 fixed bytes, or a base that
/// is zero, not page-aligned, or whose window overflows.
fn drhd_register_window(entry: &[u8], kind: u16) -> Option<(u64, u64)>
{
    if kind != 0 || entry.len() < 16
    {
        return None;
    }
    let base = read_u64(entry, 8);
    let size = 0x1000u64 << (read_u8(entry, 5) & 0x0f);
    if base == 0 || base & 0xfff != 0
    {
        return None;
    }
    base.checked_add(size)?;
    Some((base, size))
}

/// ECAM window `(phys_base, size)` of one MCFG allocation entry: the MCFG
/// base is where bus 0 would decode, so the window starts `start_bus` MiB
/// above it and spans 1 MiB per bus through `end_bus`. Returns `None` for a
/// zero base, an end bus below the start bus, or a window whose start or end
/// overflows a 64-bit physical address, so a malformed entry is skipped.
fn mcfg_ecam_window(base: u64, start_bus: u8, end_bus: u8) -> Option<(u64, u64)>
{
    if base == 0
    {
        return None;
    }
    let buses = end_bus.checked_sub(start_bus)?;
    // `buses` is at most 255, so the count of buses is at most 256.
    let size = u64::from(buses).saturating_add(1) << 20;
    let window = base.checked_add(u64::from(start_bus) << 20)?;
    window.checked_add(size)?;
    Some((window, size))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::MAX_CPUS;

    /// A DRHD of `size` (log2 pages) at register `base`, with no scopes.
    fn drhd(size: u8, base: u64) -> [u8; 16]
    {
        let mut e = [0u8; 16];
        e[2] = 16;
        e[5] = size;
        e[8..16].copy_from_slice(&base.to_le_bytes());
        e
    }

    #[test]
    fn a_drhd_seeds_its_register_window()
    {
        assert_eq!(
            drhd_register_window(&drhd(0, 0xfed9_0000), 0),
            Some((0xfed9_0000, 0x1000))
        );
        assert_eq!(
            drhd_register_window(&drhd(2, 0xfed9_0000), 0),
            Some((0xfed9_0000, 0x4000))
        );
    }

    #[test]
    fn a_non_drhd_or_malformed_drhd_seeds_nothing()
    {
        assert_eq!(drhd_register_window(&drhd(0, 0xfed9_0000), 1), None);
        assert_eq!(drhd_register_window(&drhd(0, 0xfed9_0000)[..12], 0), None);
        assert_eq!(drhd_register_window(&drhd(0, 0), 0), None);
        assert_eq!(drhd_register_window(&drhd(0, 0xfed9_0010), 0), None);
        assert_eq!(drhd_register_window(&drhd(0, !0xfff), 0), None);
    }

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
                    t.extend_from_slice(&[MADT_TYPE_LAPIC, 8, 0, u8::try_from(id).unwrap()]);
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
        let len = u32::try_from(t.len()).unwrap();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

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
        let mut xsdt_body = Vec::new();
        xsdt_body.extend_from_slice(&(madt.as_ptr() as u64).to_le_bytes());
        xsdt_body.extend_from_slice(&(mcfg.as_ptr() as u64).to_le_bytes());
        let xsdt = sdt(*b"XSDT", &xsdt_body);
        let mut rsdp = [0u8; 36];
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

    /// The MADT QEMU 11.1 `virt` with `aia=aplic-imsic` and 4 harts in one
    /// socket hands EDK2: four RINTC v1 structures (harts 0 to 3, files at
    /// `0x2800_0000 + hart * 0x1000`), one IMSIC, one supervisor-level APLIC.
    const QEMU_VIRT_AIA_MADT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/qemu-virt-aia-smp4-madt.bin"
    ));
    /// The RHCT of the same machine (`-cpu max` with Ssaia and Smaia).
    const QEMU_VIRT_AIA_RHCT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/qemu-virt-aia-smp4-rhct.bin"
    ));

    /// Offset of hart `hart`'s RINTC structure in [`QEMU_VIRT_AIA_MADT`].
    fn qemu_rintc_off(hart: usize) -> usize
    {
        MADT_ENTRIES_OFF + hart * madt_len::RINTC_IMSIC
    }

    // Defect caught: an IMSIC or APLIC structure read at the wrong offsets, a
    // layout base not derived from the RINTC file addresses, or the APLIC's
    // source count taken from its IDC count.
    #[test]
    fn madt_aia_reports_the_qemu_virt_aplic_and_imsic()
    {
        let aia = madt_aia(QEMU_VIRT_AIA_MADT);
        assert_eq!(
            aia.aplic,
            AplicDomain {
                base: 0xd00_0000,
                size: 0x8000,
                sources: 96,
            }
        );
        assert_eq!(
            aia.imsic,
            ImsicLayout {
                base: 0x2800_0000,
                ids: 255,
                guest_index_bits: 0,
                hart_index_bits: 2,
                group_index_bits: 0,
                group_index_shift: 24,
            }
        );
        assert_eq!(aia.off_layout_hart, None);
    }

    // Defect caught: an IMSIC reported although a hart's RINTC names a file
    // elsewhere than the layout puts it, so the kernel would deliver that
    // hart's interrupts to another hart's file.
    #[test]
    fn madt_aia_refuses_a_rintc_file_off_the_layout()
    {
        let mut madt = QEMU_VIRT_AIA_MADT.to_vec();
        // Swap the files of harts 1 and 2.
        let one = qemu_rintc_off(1) + 24;
        let two = qemu_rintc_off(2) + 24;
        madt[one..one + 8].copy_from_slice(&0x2800_2000u64.to_le_bytes());
        madt[two..two + 8].copy_from_slice(&0x2800_1000u64.to_le_bytes());
        let aia = madt_aia(&madt);
        assert_eq!(aia.imsic, ImsicLayout::zero());
        assert_eq!(aia.off_layout_hart, Some(1));
        // The APLIC does not depend on the IMSIC layout.
        assert_eq!(aia.aplic.base, 0xd00_0000);
    }

    // Defect caught: a layout reported with no IMSIC structure, or one
    // derived from a disabled hart's RINTC.
    #[test]
    fn madt_aia_needs_an_imsic_structure_and_skips_disabled_harts()
    {
        let mut madt = QEMU_VIRT_AIA_MADT.to_vec();
        // Hart 0 disabled, with a file no layout reaches: the base comes from
        // hart 1.
        let h0 = qemu_rintc_off(0);
        madt[h0 + 4..h0 + 8].copy_from_slice(&0u32.to_le_bytes());
        madt[h0 + 24..h0 + 32].copy_from_slice(&0x1234_5000u64.to_le_bytes());
        assert_eq!(madt_aia(&madt).imsic.base, 0x2800_0000);

        // Retype the IMSIC structure: no IMSIC, so no layout and no refusal.
        let imsic = qemu_rintc_off(4);
        assert_eq!(madt[imsic], MADT_TYPE_IMSIC);
        madt[imsic] = 0x7f;
        let aia = madt_aia(&madt);
        assert_eq!(aia.imsic, ImsicLayout::zero());
        assert_eq!(aia.off_layout_hart, None);
    }

    /// The named seeds, sorted, that the ACPI walk finds in an XSDT holding
    /// only `madt`, less the arch's platform defaults.
    fn madt_named_seeds(madt: &[u8]) -> Vec<(u64, u64)>
    {
        let mut xsdt_body = Vec::new();
        xsdt_body.extend_from_slice(&(madt.as_ptr() as u64).to_le_bytes());
        let xsdt = sdt(*b"XSDT", &xsdt_body);
        let mut rsdp = [0u8; 36];
        rsdp[..8].copy_from_slice(RSDP_SIG);
        rsdp[RSDP_OFF_REVISION] = 2;
        rsdp[RSDP_OFF_XSDT..RSDP_OFF_XSDT + 8]
            .copy_from_slice(&(xsdt.as_ptr() as u64).to_le_bytes());
        let addr = rsdp.as_ptr() as u64;

        let empty = MmioAperture {
            phys_base: 0,
            size: 0,
        };
        // SAFETY: rsdp, xsdt and the MADT are live, well-formed tables at the
        // addresses they name.
        let (named, heuristic) = unsafe { count_aperture_seed(addr) };
        let mut out = vec![empty; named];
        let mut out_h = vec![empty; heuristic];
        // SAFETY: as above.
        unsafe { parse_aperture_seed(addr, &mut out, &mut out_h) };
        let defaults = crate::arch::current::default_mmio_apertures().len();
        let mut seeds: Vec<(u64, u64)> = out[..named - defaults]
            .iter()
            .map(|a| (a.phys_base, a.size))
            .collect();
        seeds.sort_unstable();
        seeds
    }

    // Defect caught: the APLIC or the IMSIC files missing from the aperture
    // seeds, so devmgr has no aperture to carve them from.
    #[test]
    fn the_qemu_virt_aia_madt_seeds_the_aplic_and_the_imsic_files()
    {
        assert_eq!(
            madt_named_seeds(QEMU_VIRT_AIA_MADT),
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
        let seeds = madt_named_seeds(&madt);
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

    // Defect caught: Ssaia missing from the extensions the RHCT ISA string is
    // read for, so the kernel cannot tell the harts implement it.
    #[test]
    fn the_qemu_virt_aia_rhct_confirms_ssaia()
    {
        let (timebase, caps) = parse_rhct(QEMU_VIRT_AIA_RHCT);
        assert_eq!(timebase, 10_000_000);
        assert_ne!(caps & boot_protocol::HART_CAP_SSAIA, 0);
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
        let max = u32::try_from(MAX_CPUS).unwrap();
        let entries: Vec<(u8, u32)> = (0..=max).map(|id| (MADT_TYPE_LOCAL_X2APIC, id)).collect();
        let (count, ids, truncated) = topology_full(&entries, 0);
        assert_eq!(count, max);
        assert_eq!(ids, (0..max).collect::<Vec<u32>>());
        assert!(truncated);
    }

    #[test]
    fn madt_full_without_the_bsp_drops_one_ap_and_reports_it()
    {
        let max = u32::try_from(MAX_CPUS).unwrap();
        let entries: Vec<(u8, u32)> = (1..=max).map(|id| (MADT_TYPE_LOCAL_X2APIC, id)).collect();
        let (count, ids, truncated) = topology_full(&entries, 0);
        assert_eq!(count, max);
        assert_eq!(ids, (0..max).collect::<Vec<u32>>());
        assert!(truncated);
    }

    #[test]
    fn madt_exactly_max_cpus_with_the_bsp_is_not_truncated()
    {
        let max = u32::try_from(MAX_CPUS).unwrap();
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
            .copy_from_slice(&u32::try_from(nodes.len()).unwrap().to_le_bytes());
        t[RHCT_OFF_NODE_OFFSET..RHCT_OFF_NODE_OFFSET + 4].copy_from_slice(&56u32.to_le_bytes());

        for &(node_type, payload) in nodes
        {
            let node_len = u16::try_from(RHCT_NODE_HDR_LEN + payload.len()).unwrap();
            t.extend_from_slice(&node_type.to_le_bytes());
            t.extend_from_slice(&node_len.to_le_bytes());
            t.extend_from_slice(&1u16.to_le_bytes()); // revision
            t.extend_from_slice(payload);
        }

        let len = u32::try_from(t.len()).unwrap();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

    /// ISA-string node payload: `{isa_len(u16), isa bytes incl. NUL}`.
    fn isa_payload(isa: &[u8]) -> Vec<u8>
    {
        let mut p = Vec::new();
        p.extend_from_slice(&u16::try_from(isa.len() + 1).unwrap().to_le_bytes());
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
        let len = u32::try_from(t.len()).unwrap();
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

    #[test]
    fn byte_readers_at_an_offset_past_the_buffer_return_zero()
    {
        let buf = [0xffu8; 8];
        assert_eq!(read_u16(&buf, usize::MAX), 0);
        assert_eq!(read_u32(&buf, usize::MAX - 1), 0);
        assert_eq!(read_u64(&buf, 1), 0);
        assert_eq!(read_u64(&buf, 0), u64::MAX);
    }

    #[test]
    fn an_xsdt_entry_past_the_array_is_an_absent_table()
    {
        let entries = 0x1000u64.to_le_bytes();
        assert_eq!(xsdt_entry_addr(&entries, 0), 0x1000);
        assert_eq!(xsdt_entry_addr(&entries, 1), 0);
        assert_eq!(xsdt_entry_addr(&entries, usize::MAX), 0);
    }

    #[test]
    fn a_cpu_topology_walk_with_no_out_slot_places_nothing()
    {
        // SAFETY: a zero RSDP address reads nothing.
        assert_eq!(unsafe { parse_cpu_topology(0, 7, &mut []) }, 0);
        let mut out = [0u32; 2];
        // SAFETY: as above.
        assert_eq!(unsafe { parse_cpu_topology(0, 7, &mut out) }, 1);
        assert_eq!(out[0], 7);
    }

    #[test]
    fn madt_entries_stop_at_a_length_that_runs_past_the_table()
    {
        let mut t = vec![0u8; MADT_ENTRIES_OFF];
        t.extend_from_slice(&[MADT_TYPE_IOAPIC, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        t.extend_from_slice(&[MADT_TYPE_IOAPIC, 12, 0, 0]); // truncated entry
        assert_eq!(madt_entries(&t).count(), 1);
        let mut t = vec![0u8; MADT_ENTRIES_OFF];
        t.extend_from_slice(&[MADT_TYPE_IOAPIC, 1]); // length under 2
        assert_eq!(madt_entries(&t).count(), 0);
        assert_eq!(madt_entries(&t[..MADT_ENTRIES_OFF]).count(), 0);
        assert_eq!(madt_entries(&[]).count(), 0);
    }

    #[test]
    fn mcfg_window_spans_one_mib_per_bus()
    {
        assert_eq!(
            mcfg_ecam_window(0x1000_0000, 0, 0),
            Some((0x1000_0000, 1 << 20))
        );
        assert_eq!(
            mcfg_ecam_window(0x1000_0000, 0, 255),
            Some((0x1000_0000, 256 << 20))
        );
    }
}
