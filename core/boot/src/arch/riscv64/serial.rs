// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/riscv64/serial.rs

//! RISC-V UART backend: runtime-discovered MMIO 16550 address.
//!
//! The UART base is discovered at boot via ACPI SPCR (primary path for QEMU
//! virt with EDK2) or Device Tree (ns16550a-compatible node), with a fallback
//! to the QEMU virt default of 0x10000000.
//!
//! Call `discover_uart(st, tables)` before `serial_init()` to update the base.
//! If discovery is skipped or fails, the hardcoded QEMU default is used
//! silently.

use boot_firmware::dtb::Tree;

use super::acpi_kernel_mmio::spcr_uart_base;
use crate::tables::{Acpi, TableMap, device_tree};
use crate::uefi::{EFI_ACPI_20_TABLE_GUID, EFI_DTB_TABLE_GUID, EfiSystemTable, find_config_table};

/// UART MMIO base address; updated by `discover_uart` before first use.
///
/// Default: QEMU virt 0x10000000 (ns16550a at the standard QEMU address).
static mut UART_BASE_ADDR: usize = 0x1000_0000;

/// UART register offsets (byte-addressed).
const UART_TX: usize = 0; // transmit holding register
const UART_LSR: usize = 5; // line status register

// ── UART discovery ────────────────────────────────────────────────────────────

/// Set the UART base from the firmware tables, each read through `tables`:
/// the first ACPI SPCR with a memory-mapped base (EDK2 on QEMU virt provides
/// ACPI, not a DTB), else the first `ns16550a` node's window in the device
/// tree (bare-metal RISC-V, or firmware that provides a DTB). When neither
/// names one, the QEMU default (0x10000000) stays.
///
/// # Safety
/// `st` must be a valid UEFI system table pointer, and the tables `tables`
/// bounds meet [`TableMap::view`]'s contract.
pub unsafe fn discover_uart(st: *mut EfiSystemTable, tables: TableMap<'_>)
{
    // SAFETY: st is valid (caller contract).
    let rsdp = unsafe { find_config_table(st, &EFI_ACPI_20_TABLE_GUID) }.map_or(0, |p| p as u64);
    // SAFETY: caller contract.
    let spcr = unsafe { Acpi::new(tables, rsdp) }.and_then(|acpi| spcr_uart_base(&acpi));
    let base = spcr.or_else(|| {
        // SAFETY: st is valid (caller contract).
        let dtb = unsafe { find_config_table(st, &EFI_DTB_TABLE_GUID) }.map_or(0, |p| p as u64);
        // SAFETY: caller contract.
        let tree = unsafe { device_tree(tables, dtb) }.and_then(Tree::new)?;
        tree.uart().map(|(base, _)| base)
    });
    if let Some(base) = base
    {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "usize is 64-bit on all supported UEFI targets, so the cast is exact"
        )]
        // SAFETY: single-threaded boot phase; no concurrent access to static mut.
        unsafe {
            UART_BASE_ADDR = base as usize;
        };
    }
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
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every operation reaches a 16550 register at a constant offset below 8 from the \
                  UART base the caller's contract maps"
    )]
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

    // SAFETY: UART_LSR is a constant offset within the 16550 register range at `base`.
    let lsr = unsafe { base.add(UART_LSR) };
    // Spin on LSR bit 5 (THRE — Transmit Holding Register Empty).
    // SAFETY: UART_BASE_ADDR is a valid MMIO mapping; LSR offset within 16550 UART range; volatile ensures ordering.
    while unsafe { core::ptr::read_volatile(lsr) } & 0x20 == 0
    {}

    // SAFETY: UART_TX is a constant offset within the 16550 register range at `base`.
    let tx = unsafe { base.add(UART_TX) };
    // SAFETY: UART_BASE_ADDR is a valid MMIO mapping; TX offset within 16550 UART range; THRE bit set; volatile ensures ordering.
    unsafe {
        core::ptr::write_volatile(tx, byte);
    }
}
