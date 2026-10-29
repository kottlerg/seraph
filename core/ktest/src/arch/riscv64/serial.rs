// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/serial.rs

//! RISC-V serial UART for ktest: the QEMU virt MMIO 16550 (`0x1000_0000`)
//! through an `Mmio` cap and `mmio_map`. `crate::serial` owns the ready flag
//! and the line framing.

use init_protocol::{CapType, InitInfo};

/// QEMU virt UART physical address.
pub const UART_PHYS: u64 = 0x1000_0000;

/// Virtual address where the UART MMIO page is mapped.
///
/// Below the randomized heap zone (which starts at `0x4000_0000`) and
/// distinct from every other ktest fixed VA.
pub(crate) const SERIAL_VA: u64 = 0x3000_0000;

/// Current UART virtual base (set after `mmio_map`).
// SAFETY: ktest is single-threaded on the serial path.
static mut UART_VA: u64 = 0;

/// UART register offsets.
const TX: usize = 0;
const LSR: usize = 5;

/// Initialise MMIO serial output; returns whether the UART is ready.
///
/// Finds the `Mmio` cap for the UART, maps it into `aspace_cap`, then
/// programs the UART to 8N1. The UART is memory-mapped, so `_thread_cap`
/// (the x86-64 port-binding target) is unused here.
///
/// # Safety
/// Must be called once, from the main thread, after `InitInfo` is mapped.
pub unsafe fn init(info: &InitInfo, aspace_cap: u32, _thread_cap: u32) -> bool
{
    let Some((slot, size)) = find_uart_cap(info)
    else
    {
        return false; // no UART Mmio cap — serial stays uninitialised
    };
    // The whole region is mapped from SERIAL_VA, so it must end below the
    // low scratch band (crate docs § Scratch VAs).
    if size > crate::SCRATCH_LOW_BASE - SERIAL_VA
    {
        return false;
    }

    // SAFETY: `aspace_cap` is ktest's own address space; the span from
    // SERIAL_VA ends below the low scratch band (checked above), in a range
    // no other ktest mapping and no Rust object uses, and this once-only call
    // is its sole mapper.
    if unsafe { syscall::mmio_map(aspace_cap, slot, SERIAL_VA, 0) }.is_err()
    {
        return false;
    }

    // SAFETY: single-threaded; mmio_map succeeded.
    unsafe { UART_VA = SERIAL_VA };

    // SAFETY: UART_VA points to a valid MMIO mapping.
    unsafe { serial_hw_init() };
    true
}

/// The `CSpace` slot and byte size of the `Mmio` cap whose base is the UART,
/// if `InitInfo` carries one.
fn find_uart_cap(info: &InitInfo) -> Option<(u32, u64)>
{
    crate::init_info::descriptors(info)
        .iter()
        .find(|d| d.cap_type == CapType::Mmio && d.aux0 == UART_PHYS)
        .map(|d| (d.slot, d.aux1))
}

/// Program the 16550 UART to 8N1 (minimal re-init; QEMU pre-configures it).
///
/// # Safety
/// `UART_VA` must point to a valid MMIO mapping.
unsafe fn serial_hw_init()
{
    // SAFETY: UART_VA set by init after successful mmio_map.
    let base = unsafe { UART_VA } as *mut u8;
    // SAFETY: UART MMIO region is mapped and writable; volatile writes
    // configure the 16550 registers.
    unsafe {
        core::ptr::write_volatile(base.add(1), 0x00); // IER = 0
        core::ptr::write_volatile(base.add(3), 0x80); // DLAB = 1
        core::ptr::write_volatile(base.add(0), 0x01); // divisor low = 1
        core::ptr::write_volatile(base.add(1), 0x00); // divisor high = 0
        core::ptr::write_volatile(base.add(3), 0x03); // 8N1, DLAB = 0
        core::ptr::write_volatile(base.add(2), 0x00); // FCR = 0 (no FIFO)
    }
}

/// Write a single byte, spinning until the transmit buffer is empty.
///
/// Called only once [`init`] has returned `true`.
pub fn write_byte(byte: u8)
{
    // SAFETY: UART_VA set during init; single-threaded.
    let base = unsafe { UART_VA } as *mut u8;

    // Spin on LSR bit 5 (THRE).
    // SAFETY: LSR is a status register at offset 5 in the MMIO region.
    while unsafe { core::ptr::read_volatile(base.add(LSR)) } & 0x20 == 0
    {}

    // SAFETY: THRE set; writing to TX register transmits the byte.
    unsafe { core::ptr::write_volatile(base.add(TX), byte) };
}
