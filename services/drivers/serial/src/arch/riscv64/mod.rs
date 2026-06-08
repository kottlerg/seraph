// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/serial/src/arch/riscv64/mod.rs

//! RISC-V serial I/O via a memory-mapped NS16550 UART.
//!
//! The driver maps the `Mmio` cap devmgr delegated (the ACPI-SPCR
//! UART base; `0x10000000` on QEMU virt) into its own address space, then
//! writes the transmit register and drains the receive register after polling
//! the line status register. Registers are byte-addressed (reg-shift 0),
//! matching the bootloader's NS16550 access. The UART was programmed by an
//! earlier boot stage and that state persists; the one piece that must be
//! re-enabled here is the receive-data interrupt (every boot stage left
//! `IER = 0`), so RX raises the PLIC source the driver routes to its client.

use core::sync::atomic::{AtomicU64, Ordering};
use std::os::seraph::{fund_aspace_pt_budget, reserve_pages};

/// NS16550 register offsets (byte-addressed).
const UART_RX: u64 = 0; // receive holding register
const UART_TX: u64 = 0; // transmit holding register
const UART_IER: u64 = 1; // interrupt enable register (bit 0 = ERBFI)
const UART_LSR: u64 = 5; // line status register

/// Mapped UART base virtual address, set once by [`serial_init`].
static UART_BASE: AtomicU64 = AtomicU64::new(0);

/// Reserve a VA page, map the UART `Mmio` cap into it, and enable the
/// receive-data interrupt when `enable_rx_irq` is set. The reservation lives
/// for the process's lifetime. `self_thread` is unused on RISC-V. Returns
/// `false` if reservation or mapping fails.
pub fn serial_init(_self_thread: u32, self_aspace: u32, mmio_cap: u32, enable_rx_irq: bool)
-> bool
{
    let Ok(range) = reserve_pages(1)
    else
    {
        return false;
    };
    let base_va = range.va_start();
    if !fund_aspace_pt_budget(self_aspace, 1)
    {
        return false;
    }
    if syscall::mmio_map(self_aspace, mmio_cap, base_va, 0).is_err()
    {
        return false;
    }
    if enable_rx_irq
    {
        // Enable Received Data Available interrupt (ERBFI). Earlier boot stages
        // left IER cleared; without this the NS16550 never raises its PLIC
        // source. Skipped when the driver holds no IRQ cap (RX then polls).
        // SAFETY: base_va was just mapped via mmio_map; IER is within the page.
        unsafe { core::ptr::write_volatile((base_va + UART_IER) as *mut u8, 0x01) };
    }
    UART_BASE.store(base_va, Ordering::Release);
    true
}

/// Read one byte from the UART if the receive register holds data, else
/// `None`. No-ops to `None` if [`serial_init`] never mapped the UART.
pub fn serial_read_byte() -> Option<u8>
{
    let base = UART_BASE.load(Ordering::Acquire);
    if base == 0
    {
        return None;
    }
    let lsr = (base + UART_LSR) as *const u8;
    let rx = (base + UART_RX) as *const u8;
    // SAFETY: `base` was mapped via mmio_map in serial_init; the LSR offset is
    // within the mapped page and byte-aligned. Reading it is side-effect-free.
    if unsafe { core::ptr::read_volatile(lsr) } & 0x01 == 0
    {
        return None;
    }
    // SAFETY: same mapping; reading the RBR returns the next received byte and
    // clears the data-ready bit.
    Some(unsafe { core::ptr::read_volatile(rx) })
}

/// Write one byte to the UART, spinning until the transmit holding register
/// is empty (LSR bit `0x20`). No-ops if [`serial_init`] never mapped the
/// UART.
pub fn serial_write_byte(byte: u8)
{
    let base = UART_BASE.load(Ordering::Acquire);
    if base == 0
    {
        return;
    }
    let tx = (base + UART_TX) as *mut u8;
    let lsr = (base + UART_LSR) as *const u8;
    // SAFETY: `base` was mapped via mmio_map in serial_init; both offsets are
    // within the mapped page and byte-aligned.
    while unsafe { core::ptr::read_volatile(lsr) } & 0x20 == 0
    {}
    // SAFETY: same mapping; writing one byte to the transmit register.
    unsafe {
        core::ptr::write_volatile(tx, byte);
    }
}
