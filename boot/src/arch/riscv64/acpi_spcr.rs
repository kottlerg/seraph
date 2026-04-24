// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/acpi_spcr.rs

//! Shared ACPI SPCR walker for the RISC-V UART base.
//!
//! Two callers on RISC-V consume this: the pre-Step-1 serial-init path
//! in [`crate::arch::riscv64::serial`] (needs a UART base so early
//! diagnostics work), and the Step-5 `kernel_mmio` extractor in
//! [`super::acpi_kernel_mmio`] (records the same base into
//! [`KernelMmio::uart_base`](boot_protocol::KernelMmio)).
//!
//! The generic ACPI table-walk primitives (RSDP/XSDT validation, byte
//! readers, `phys_slice`) live in [`crate::acpi`]; only the SPCR
//! layout constants and the SPCR-specific scan are here.

use crate::acpi::{
    RSDP_OFF_REVISION, RSDP_OFF_XSDT, RSDP_SIG, SDT_HDR_LEN, SDT_OFF_LENGTH, SDT_OFF_SIGNATURE,
    phys_slice, read_u8, read_u32, read_u64,
};

// SPCR GAS base_address field offset from table start:
//   36: interface_type(u8)  37-39: reserved  40: GAS(12 bytes)
//   GAS layout: address_space_id(u8), bit_width(u8), bit_offset(u8),
//               access_size(u8), address(u64)
const SPCR_OFF_GAS: usize = SDT_HDR_LEN + 4;
const SPCR_GAS_ADDR_SPACE_ID: usize = SPCR_OFF_GAS; // u8, 0=MMIO
const SPCR_GAS_ADDRESS: usize = SPCR_OFF_GAS + 4; // u64

/// Find the UART base address published by the ACPI SPCR table.
///
/// Walks RSDP → XSDT for the `SPCR` signature and returns the Generic
/// Address Structure's address when its address-space identifier is
/// System Memory (MMIO, `address_space_id == 0`). Returns `None` if the
/// RSDP is invalid, no SPCR is present, or the address space is not
/// MMIO (a serial I/O-port specifier is not usable on architectures
/// that reach the UART via MMIO).
///
/// # Safety
/// `rsdp_addr` must be the physical address of a valid, identity-mapped
/// ACPI RSDP. A zero `rsdp_addr` returns `None` without reading.
pub unsafe fn find_spcr_base(rsdp_addr: u64) -> Option<u64>
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

    // SAFETY: xsdt_addr read from validated RSDP.
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
    // SAFETY: length validated above.
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
        // SAFETY: table_addr read from validated XSDT.
        let hdr = unsafe { phys_slice(table_addr, SDT_HDR_LEN) };
        if &hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"SPCR"
        {
            continue;
        }
        let table_len = read_u32(hdr, SDT_OFF_LENGTH) as usize;
        if table_len < SPCR_GAS_ADDRESS + 8
        {
            return None;
        }
        // SAFETY: length validated above.
        let table = unsafe { phys_slice(table_addr, table_len) };
        if read_u8(table, SPCR_GAS_ADDR_SPACE_ID) != 0
        {
            return None;
        }
        let base = read_u64(table, SPCR_GAS_ADDRESS);
        if base != 0
        {
            return Some(base);
        }
    }

    None
}
