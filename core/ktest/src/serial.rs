// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/serial.rs

//! Direct serial output for ktest.
//!
//! Drives the serial port from userspace using capabilities received via the
//! init protocol, eliminating the need for `SYS_DEBUG_LOG`.
//!
//! - **x86-64**: COM1 (I/O port 0x3F8) via `IoPortRange` cap + `ioport_bind`.
//! - **RISC-V**: MMIO 16550 (`0x1000_0000`) via `MmioRegion` cap + `mmio_map`.
//!
//! Call [`init`] once during early startup (after `InitInfo` is available, before
//! any logging). After that, [`write_str`] and [`write_byte`] are available.

use init_protocol::{CapDescriptor, CapType, InitInfo};

/// Whether serial has been successfully initialised.
///
/// `write_byte` / `write_str` silently no-op when false.
// SAFETY: ktest is single-threaded on the serial output path.
static mut SERIAL_READY: bool = false;

// ── Cap discovery ────────────────────────────────────────────────────────────

/// Read the `CapDescriptor` array from the `InitInfo` page.
fn descriptors(info: &InitInfo) -> &[CapDescriptor]
{
    let base = core::ptr::from_ref::<InitInfo>(info).cast::<u8>();
    // SAFETY: cap_descriptors_offset is set by the kernel to point within the
    // same read-only page; the descriptor array contains cap_descriptor_count
    // valid entries. The offset is aligned to CapDescriptor's alignment (the
    // kernel writes it at size_of::<InitInfo>(), which is 4-byte aligned and
    // CapDescriptor is repr(C) starting with a u32).
    // cast_ptr_alignment: InitInfo is 4-byte aligned and CapDescriptor array
    // immediately follows it at a 4-byte-aligned offset.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let ptr = base
            .add(info.cap_descriptors_offset as usize)
            .cast::<CapDescriptor>();
        core::slice::from_raw_parts(ptr, info.cap_descriptor_count as usize)
    }
}

/// Scan the `CapDescriptor` array for a cap matching `wanted_type` and
/// `wanted_aux0`. Returns the `CSpace` slot index if found.
#[allow(dead_code)] // Used on RISC-V (MmioRegion lookup), not on x86-64.
fn find_cap(info: &InitInfo, wanted_type: CapType, wanted_aux0: u64) -> Option<u32>
{
    for d in descriptors(info)
    {
        if d.cap_type == wanted_type && d.aux0 == wanted_aux0
        {
            return Some(d.slot);
        }
    }
    None
}

/// Scan the `CapDescriptor` array for the first cap matching `wanted_type`.
/// Returns the `CSpace` slot index if found.
#[allow(dead_code)] // Used on x86-64 (IoPortRange lookup), not on RISC-V.
fn find_cap_by_type(info: &InitInfo, wanted_type: CapType) -> Option<u32>
{
    for d in descriptors(info)
    {
        if d.cap_type == wanted_type
        {
            return Some(d.slot);
        }
    }
    None
}

// ── x86-64: COM1 via I/O ports ───────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod arch
{
    /// COM1 base I/O port.
    const COM1: u16 = 0x3F8;

    /// Initialise COM1 serial output.
    ///
    /// Finds the `IoPortRange` cap covering COM1, binds it to the current
    /// thread, then programs the UART to 115200 8N1.
    ///
    /// # Safety
    /// Must be called once, from the main thread, after `InitInfo` is mapped.
    pub unsafe fn init(info: &super::InitInfo, thread_cap: u32)
    {
        let Some(slot) = super::find_cap_by_type(info, super::CapType::IoPortRange)
        else
        {
            return; // no IoPortRange cap — serial stays uninitialised
        };

        if syscall::ioport_bind(thread_cap, slot).is_err()
        {
            return;
        }

        // SAFETY: ioport_bind succeeded; I/O port access is permitted.
        unsafe { serial_hw_init() };

        // SAFETY: single-threaded; serial hardware ready.
        unsafe { super::SERIAL_READY = true };
    }

    /// Program COM1 to 115200 baud, 8N1.
    ///
    /// # Safety
    /// I/O port access to COM1 must be permitted (via `ioport_bind`).
    unsafe fn serial_hw_init()
    {
        // SAFETY: COM1 port range bound to this thread.
        unsafe {
            outb(COM1 + 1, 0x00); // disable all interrupts
            outb(COM1 + 3, 0x80); // DLAB = 1
            outb(COM1, 0x01); // divisor low  = 1 → 115200 baud
            outb(COM1 + 1, 0x00); // divisor high = 0
            outb(COM1 + 3, 0x03); // DLAB = 0, 8N1
            outb(COM1 + 2, 0xC7); // enable FIFO, clear, 14-byte threshold
            outb(COM1 + 4, 0x0B); // DTR + RTS + OUT2
        }
    }

    /// Write a single byte, spinning until the transmit buffer is empty.
    pub fn write_byte(byte: u8)
    {
        // Spin on LSR bit 5 (THRE — Transmit Holding Register Empty).
        // SAFETY: serial_hw_init completed; I/O port access permitted.
        while unsafe { inb(COM1 + 5) } & 0x20 == 0
        {}
        // SAFETY: THRE set; writing to data register transmits the byte.
        unsafe { outb(COM1, byte) };
    }

    #[inline]
    unsafe fn outb(port: u16, val: u8)
    {
        // SAFETY: caller guarantees port access is permitted.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    #[inline]
    unsafe fn inb(port: u16) -> u8
    {
        let val: u8;
        // SAFETY: caller guarantees port access is permitted.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") val,
                options(nomem, nostack, preserves_flags),
            );
        }
        val
    }
}

// ── RISC-V: MMIO 16550 ──────────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
mod arch
{
    /// QEMU virt UART physical address.
    const UART_PHYS: u64 = 0x1000_0000;

    /// Virtual address where the UART MMIO page is mapped.
    ///
    /// Chosen to avoid conflict with `TEST_VA` (`0x4000_0000`) and
    /// `MMIO_TEST_VA` (`0x5000_0000`) used by ktest's mm and hw tests.
    const SERIAL_VA: u64 = 0x3000_0000;

    /// Current UART virtual base (set after `mmio_map`).
    // SAFETY: ktest is single-threaded on the serial path.
    static mut UART_VA: u64 = 0;

    /// UART register offsets.
    const TX: usize = 0;
    const LSR: usize = 5;

    /// Initialise MMIO serial output.
    ///
    /// Finds the `MmioRegion` cap for the UART, maps it into the address
    /// space, then programs the UART to 8N1.
    ///
    /// # Safety
    /// Must be called once, from the main thread, after `InitInfo` is mapped.
    pub unsafe fn init(info: &super::InitInfo, aspace_cap: u32)
    {
        let Some(slot) = super::find_cap(info, super::CapType::MmioRegion, UART_PHYS)
        else
        {
            return; // no UART MmioRegion cap — serial stays uninitialised
        };

        if syscall::mmio_map(aspace_cap, slot, SERIAL_VA, 0).is_err()
        {
            return;
        }

        // SAFETY: single-threaded; mmio_map succeeded.
        unsafe { UART_VA = SERIAL_VA };

        // SAFETY: UART_VA points to a valid MMIO mapping.
        unsafe { serial_hw_init() };

        // SAFETY: single-threaded; serial hardware ready.
        unsafe { super::SERIAL_READY = true };
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
}

// ── Public interface ─────────────────────────────────────────────────────────

/// Initialise the serial port using capabilities from the init protocol.
///
/// On x86-64, binds the COM1 `IoPortRange` cap to the current thread.
/// On RISC-V, maps the UART `MmioRegion` cap into the address space.
///
/// # Safety
/// Must be called once during early ktest startup, before any `write_str`
/// or `write_byte` call.
pub unsafe fn init(info: &InitInfo, aspace_cap: u32, thread_cap: u32)
{
    #[cfg(target_arch = "x86_64")]
    // SAFETY: caller guarantees at-most-once, single-threaded.
    unsafe {
        arch::init(info, thread_cap);
    }

    #[cfg(target_arch = "riscv64")]
    // SAFETY: caller guarantees at-most-once, single-threaded.
    unsafe {
        arch::init(info, aspace_cap);
    }

    // Suppress unused-variable warnings on the arch that doesn't use each cap.
    #[cfg(target_arch = "x86_64")]
    let _ = aspace_cap;
    #[cfg(target_arch = "riscv64")]
    let _ = thread_cap;
}

/// Write a single byte to the serial port.
///
/// No-op if serial has not been initialised.
#[inline]
pub fn write_byte(byte: u8)
{
    // SAFETY: single-threaded read of flag set during init.
    if unsafe { !SERIAL_READY }
    {
        return;
    }
    arch::write_byte(byte);
}

/// Write a string to the serial port, inserting `\r` before each `\n`.
///
/// No-op if serial has not been initialised.
pub fn write_str(s: &str)
{
    // SAFETY: single-threaded read of flag set during init.
    if unsafe { !SERIAL_READY }
    {
        return;
    }
    for &b in s.as_bytes()
    {
        if b == b'\n'
        {
            arch::write_byte(b'\r');
        }
        arch::write_byte(b);
    }
}
