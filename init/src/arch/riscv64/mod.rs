// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/arch/riscv64.rs

//! RISC-V serial output via 16550 UART MMIO and architecture constants.

use init_protocol::{CapType, InitInfo};

/// ELF machine type for RISC-V.
pub const EXPECTED_ELF_MACHINE: u16 = elf::EM_RISCV;

const UART_PHYS: u64 = 0x1000_0000;
const SERIAL_VA: u64 = 0x0000_0000_3000_0000;
static mut UART_BASE: u64 = 0;

/// Initialise UART serial output via MMIO.
///
/// Scans `MmioRegion` descriptors for the aperture containing `UART_PHYS`,
/// maps the full aperture at `SERIAL_VA`, and records the UART's virtual
/// address including its in-aperture offset. v6 apertures are coarse —
/// the UART is typically one of several devices inside the aperture.
pub fn serial_init(info: &InitInfo, _thread_cap: u32)
{
    let descriptors = crate::descriptors(info);
    let mut aperture: Option<(u32, u64, u64)> = None;
    for d in descriptors
    {
        if d.cap_type != CapType::MmioRegion
        {
            continue;
        }
        if UART_PHYS >= d.aux0 && UART_PHYS < d.aux0 + d.aux1
        {
            aperture = Some((d.slot, d.aux0, d.aux1));
            break;
        }
    }
    let Some((slot, base, _size)) = aperture
    else
    {
        return;
    };
    if syscall::mmio_map(info.aspace_cap, slot, SERIAL_VA, 0).is_err()
    {
        return;
    }
    let uart_offset = UART_PHYS - base;
    let uart_va = SERIAL_VA + uart_offset;
    // SAFETY: single-threaded init; UART MMIO programming. The full
    // aperture is mapped at SERIAL_VA; UART sits at uart_offset inside it.
    unsafe {
        UART_BASE = uart_va;
        let ptr = uart_va as *mut u8;
        core::ptr::write_volatile(ptr.add(1), 0x00);
        core::ptr::write_volatile(ptr.add(3), 0x80);
        core::ptr::write_volatile(ptr, 0x01);
        core::ptr::write_volatile(ptr.add(1), 0x00);
        core::ptr::write_volatile(ptr.add(3), 0x03);
    }
}

/// Write one byte to the UART, spinning until the transmit register is ready.
pub fn serial_write_byte(byte: u8)
{
    // SAFETY: single-threaded init; reading the static set during serial_init().
    let base = unsafe { UART_BASE };
    if base == 0
    {
        return;
    }
    let p = base as *mut u8;
    // SAFETY: UART MMIO region is mapped at UART_BASE; reading LSR is safe.
    while unsafe { core::ptr::read_volatile(p.add(5)) } & 0x20 == 0
    {}
    // SAFETY: UART MMIO region is mapped at UART_BASE; writing data register.
    unsafe { core::ptr::write_volatile(p, byte) };
}
