// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/console.rs

//! ns16550-compatible UART backend for RISC-V.
//!
//! The physical base is supplied by the bootloader through
//! `BootInfo.kernel_mmio.uart_base` and resolved at Phase 1 console init via
//! [`crate::arch::riscv64::platform::uart_base_for_boot_info`]. After Phase 3
//! activates the kernel's page tables, the UART is no longer accessible at
//! its physical address; call [`rebase_serial`] to switch the accessor to the
//! direct-map virtual address.
//!
//! Firmware is assumed to have pre-configured the UART clock (divisor 1).
//! The init sequence here performs a minimal re-enable in case a prior stage
//! left the device in an unexpected state.

/// UART register offsets (byte-addressed).
const UART_TX: usize = 0; // transmit holding register
const UART_LSR: usize = 5; // line status register

/// Resolved UART physical base, recorded by [`serial_init`] so [`uart_phys_base`]
/// can return it across the Phase 3 page-table switch (when `BootInfo` is no
/// longer accessible).
///
/// SAFETY: written exactly once during Phase 1, single-threaded; subsequent
/// reads happen after SMP is active but observe a fully-written value because
/// the write precedes SMP bring-up.
static mut UART_PHYS: u64 = 0;

/// Current UART virtual base address.
///
/// Initialized to the physical address (identity-mapped by the bootloader).
/// Updated by [`rebase_serial`] after Phase 3 switches to the direct map.
/// Single-threaded early boot: no locking required.
// SAFETY: accessed only from the single kernel boot thread before SMP, then
// read-only across all CPUs once SMP is active.
static mut UART_BASE: u64 = 0;

/// Resolved UART physical base captured at [`serial_init`] time.
///
/// Returns 0 before [`serial_init`] has been called.
#[must_use]
pub fn uart_phys_base() -> u64
{
    // SAFETY: see UART_PHYS doc; written once pre-SMP, read after.
    unsafe { UART_PHYS }
}

/// Switch the UART accessor to a new virtual base address.
///
/// Call this after Phase 3 activates the kernel's page tables, passing
/// `phys_to_virt(uart_phys_base())` so subsequent serial output uses the
/// direct-map address instead of the now-unmapped physical address.
///
/// # Safety
/// Must be called from the single kernel boot thread after the direct
/// physical map is active (i.e. after `activate` returns successfully).
pub unsafe fn rebase_serial(new_base: u64)
{
    // SAFETY: single-threaded boot; no concurrent access.
    unsafe { UART_BASE = new_base };
}

/// Initialize the ns16550 UART at `phys_base`.
///
/// Records the physical base for later [`uart_phys_base`] queries, sets the
/// initial virtual base to the (identity-mapped) physical address, then
/// performs a minimal re-enable (8N1, no FIFO, divisor 1).
///
/// # Safety
/// Caller must ensure this is called at most once, that the MMIO region at
/// `phys_base` is accessible (identity-mapped pre-Phase 3), and not protected
/// by the MMU.
pub unsafe fn serial_init(phys_base: u64)
{
    // SAFETY: single-threaded Phase 1; called exactly once.
    unsafe {
        UART_PHYS = phys_base;
        UART_BASE = phys_base;
    }
    let base = phys_base as *mut u8;
    // SAFETY: UART MMIO region is valid at base; volatile writes configure the 16550.
    unsafe {
        // IER = 0: disable all interrupts.
        core::ptr::write_volatile(base.add(1), 0x00);
        // LCR DLAB = 1: access divisor latch.
        core::ptr::write_volatile(base.add(3), 0x80);
        // Divisor = 1 (firmware pre-configured the clock).
        core::ptr::write_volatile(base.add(0), 0x01);
        core::ptr::write_volatile(base.add(1), 0x00);
        // LCR = 0x03: 8N1, DLAB = 0.
        core::ptr::write_volatile(base.add(3), 0x03);
        // FCR = 0: disable FIFO.
        core::ptr::write_volatile(base.add(2), 0x00);
    }
}

/// Write a single byte to the UART, spinning until the transmit buffer is ready.
///
/// # Safety
/// `serial_init` must have been called before this function.
pub unsafe fn serial_write_byte(byte: u8)
{
    // SAFETY: UART_BASE is valid (set by serial_init or rebase_serial).
    let base = unsafe { UART_BASE } as *mut u8;

    // Spin on LSR bit 5 (THRE — Transmit Holding Register Empty).
    // SAFETY: UART MMIO region is valid; LSR is a status register at offset 5.
    while unsafe { core::ptr::read_volatile(base.add(UART_LSR)) } & 0x20 == 0
    {}

    // SAFETY: UART MMIO region is valid; writing to TX register transmits the byte.
    unsafe {
        core::ptr::write_volatile(base.add(UART_TX), byte);
    }
}
