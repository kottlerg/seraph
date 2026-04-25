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

use super::acpi_spcr::find_spcr_base;
use crate::uefi::{EFI_ACPI_20_TABLE_GUID, EFI_DTB_TABLE_GUID, EfiSystemTable};

/// UART MMIO base address; updated by `discover_uart` before first use.
///
/// Default: QEMU virt 0x10000000 (ns16550a at the standard QEMU address).
static mut UART_BASE_ADDR: usize = 0x1000_0000;

/// UART register offsets (byte-addressed).
const UART_TX: usize = 0; // transmit holding register
const UART_LSR: usize = 5; // line status register

// ── UART discovery ────────────────────────────────────────────────────────────

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
        // SAFETY: rsdp obtained from UEFI config table; identity-mapped during boot.
        if let Some(base) = unsafe { find_spcr_base(rsdp_ptr as u64) }
        {
            // SAFETY: single-threaded boot phase; no concurrent access to static mut.
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
