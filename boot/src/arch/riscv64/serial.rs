// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/serial.rs

//! RISC-V UART backend: runtime-discovered MMIO 16550 address.
//!
//! The UART base is discovered at boot via ACPI SPCR (primary path for QEMU
//! virt with EDK2) or Device Tree (ns16550a-compatible node), with a fallback
//! to the QEMU virt default of 0x10000000.
//!
//! Call `discover_uart(st)` before `serial_init()` to update the base. If
//! discovery is skipped or fails, the hardcoded QEMU default is used silently.

use crate::acpi::{
    RSDP_OFF_REVISION, RSDP_OFF_XSDT, RSDP_SIG, SDT_HDR_LEN, SDT_OFF_LENGTH, SDT_OFF_SIGNATURE,
    phys_slice, read_u8, read_u32, read_u64,
};
use crate::uefi::{EFI_ACPI_20_TABLE_GUID, EFI_DTB_TABLE_GUID, EfiSystemTable};

/// UART MMIO base address; updated by `discover_uart` before first use.
///
/// Default: QEMU virt 0x10000000 (ns16550a at the standard QEMU address).
static mut UART_BASE_ADDR: usize = 0x1000_0000;

/// UART register offsets (byte-addressed).
const UART_TX: usize = 0; // transmit holding register
const UART_LSR: usize = 5; // line status register

// ── SPCR layout constants ─────────────────────────────────────────────────────

// SPCR GAS base_address field offset from table start:
//   36: interface_type(u8)  37-39: reserved  40: GAS(12 bytes)
//   GAS layout: address_space_id(u8), bit_width(u8), bit_offset(u8),
//               access_size(u8), address(u64)
const SPCR_OFF_GAS: usize = SDT_HDR_LEN + 4;
const SPCR_GAS_ADDR_SPACE_ID: usize = SPCR_OFF_GAS; // u8, 0=MMIO
const SPCR_GAS_ADDRESS: usize = SPCR_OFF_GAS + 4; // u64

// ── UART discovery ────────────────────────────────────────────────────────────

/// Find the UART base address from the ACPI SPCR table.
///
/// Returns `None` if RSDP is invalid, SPCR is not found, or the base address
/// space is not MMIO (`address_space_id != 0`).
///
/// # Safety
/// `rsdp_addr` must be a physical address of a valid, identity-mapped RSDP.
unsafe fn find_spcr_uart_base(rsdp_addr: u64) -> Option<u64>
{
    // SAFETY: rsdp_addr is a valid identity-mapped RSDP physical address; caller guarantees validity and accessibility.
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

    // SAFETY: xsdt_addr read from validated RSDP; identity-mapped and accessible during boot.
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
    // SAFETY: xsdt_addr and xsdt_len validated from XSDT header; identity-mapped and accessible.
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
        // SAFETY: table_addr read from validated XSDT entry; identity-mapped and accessible during boot.
        let hdr = unsafe { phys_slice(table_addr, SDT_HDR_LEN) };
        let sig = &hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4];
        if sig != b"SPCR"
        {
            continue;
        }
        let table_len = read_u32(hdr, SDT_OFF_LENGTH) as usize;
        if table_len < SPCR_GAS_ADDRESS + 8
        {
            return None;
        }
        // SAFETY: table_addr and table_len validated from SPCR header; identity-mapped and accessible.
        let table = unsafe { phys_slice(table_addr, table_len) };
        let addr_space = read_u8(table, SPCR_GAS_ADDR_SPACE_ID);
        if addr_space != 0
        {
            // 0 = System Memory (MMIO). I/O port (1) not useful for our mapping.
            return None;
        }
        let uart_base = read_u64(table, SPCR_GAS_ADDRESS);
        if uart_base != 0
        {
            return Some(uart_base);
        }
    }

    None
}

/// Find the UART base from a Device Tree (ns16550a-compatible node).
///
/// Returns `None` if `dtb_addr` is invalid or no ns16550a node has a `reg`
/// entry.
///
/// # Safety
/// `dtb_addr` must be a physical address of a valid, identity-mapped FDT blob.
unsafe fn find_dtb_uart_base(dtb_addr: u64) -> Option<u64>
{
    // SAFETY: dtb_addr is a valid identity-mapped FDT blob physical address; caller guarantees validity.
    let fdt = unsafe { crate::dtb::Fdt::from_raw(dtb_addr) }?;
    let mut base: Option<u64> = None;
    fdt.for_each_compatible(b"ns16550a", |node| {
        if base.is_none() && node.reg_count > 0
        {
            base = Some(node.reg_entries[0].0);
        }
    });
    base
}

/// Discover the UART MMIO base from ACPI SPCR or Device Tree.
///
/// Tries ACPI SPCR first (primary path for QEMU virt with EDK2), then DTB
/// (ns16550a-compatible node). Falls back to 0x10000000 silently if both fail.
///
/// Must be called before `serial_init()` and `serial_write_byte()`.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table.
pub unsafe fn discover_uart(st: *mut EfiSystemTable)
{
    // Try ACPI SPCR first (EDK2 on QEMU virt provides ACPI, not DTB).
    // SAFETY: st is a valid UEFI system table pointer; caller guarantees validity.
    if let Some(rsdp_ptr) = unsafe { crate::uefi::find_config_table(st, &EFI_ACPI_20_TABLE_GUID) }
    {
        let rsdp_addr = rsdp_ptr as u64;
        // SAFETY: rsdp_addr obtained from UEFI config table; identity-mapped and accessible during boot.
        if let Some(base) = unsafe { find_spcr_uart_base(rsdp_addr) }
        {
            // SAFETY: single-threaded boot phase; no concurrent access to static mut; usize is 64-bit on all supported UEFI targets; no truncation.
            #[allow(clippy::cast_possible_truncation)]
            unsafe {
                UART_BASE_ADDR = base as usize;
            };
            return;
        }
    }

    // Try Device Tree (bare-metal RISC-V or non-EDK2 firmware with DTB).
    // SAFETY: st is a valid UEFI system table pointer; caller guarantees validity.
    if let Some(dtb_ptr) = unsafe { crate::uefi::find_config_table(st, &EFI_DTB_TABLE_GUID) }
    {
        let dtb_addr = dtb_ptr as u64;
        // SAFETY: dtb_addr obtained from UEFI config table; identity-mapped and accessible during boot.
        if let Some(base) = unsafe { find_dtb_uart_base(dtb_addr) }
        {
            // SAFETY: single-threaded boot phase; no concurrent access to static mut; usize is 64-bit on all supported UEFI targets; no truncation.
            #[allow(clippy::cast_possible_truncation)]
            unsafe {
                UART_BASE_ADDR = base as usize;
            };
        }
    }
    // Both failed: UART_BASE_ADDR retains the QEMU default (0x10000000).
}

/// Return the currently configured UART MMIO base address.
///
/// Call after `discover_uart` for the discovered value; before it, returns the
/// default 0x10000000.
pub fn uart_base() -> usize
{
    // SAFETY: single-threaded boot phase; no concurrent access to static mut.
    unsafe { UART_BASE_ADDR }
}

/// Initialize the UART.
///
/// QEMU pre-initializes the UART at reset; this performs a minimal re-enable
/// (8N1, no FIFO) in case a prior stage left it in an unexpected state.
///
/// # Safety
/// Must be called at most once, after `discover_uart`. The MMIO region at
/// `UART_BASE_ADDR` must be accessible and not MMU-protected.
pub unsafe fn serial_init()
{
    // SAFETY: single-threaded boot phase; no concurrent access to static mut.
    let base = unsafe { UART_BASE_ADDR } as *mut u8;
    // SAFETY: UART_BASE_ADDR is a valid MMIO mapping; register offsets within 16550 UART range; volatile ensures ordering.
    unsafe {
        // IER = 0: disable all interrupts.
        core::ptr::write_volatile(base.add(1), 0x00);
        // LCR DLAB = 1: access divisor latch.
        core::ptr::write_volatile(base.add(3), 0x80);
        // Divisor = 1 (assume clock pre-configured by QEMU).
        core::ptr::write_volatile(base.add(0), 0x01);
        core::ptr::write_volatile(base.add(1), 0x00);
        // LCR = 0x03: 8N1, DLAB = 0.
        core::ptr::write_volatile(base.add(3), 0x03);
        // FCR = 0: disable FIFO (QEMU virt does not need it).
        core::ptr::write_volatile(base.add(2), 0x00);
    }
}

/// Write a single byte to the UART, spinning until the transmit buffer is ready.
///
/// # Safety
/// `serial_init` must have been called before this function.
pub unsafe fn serial_write_byte(byte: u8)
{
    // SAFETY: single-threaded boot phase; no concurrent access to static mut.
    let base = unsafe { UART_BASE_ADDR } as *mut u8;

    // Spin on LSR bit 5 (THRE — Transmit Holding Register Empty).
    // SAFETY: UART_BASE_ADDR is a valid MMIO mapping; LSR offset within 16550 UART range; volatile ensures ordering.
    while unsafe { core::ptr::read_volatile(base.add(UART_LSR)) } & 0x20 == 0
    {}

    // SAFETY: UART_BASE_ADDR is a valid MMIO mapping; TX offset within 16550 UART range; THRE bit set; volatile ensures ordering.
    unsafe {
        core::ptr::write_volatile(base.add(UART_TX), byte);
    }
}
