// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/init/src/arch/x86_64/mod.rs

//! x86-64 serial output via COM1 and architecture constants.

use core::sync::atomic::{AtomicBool, Ordering};

use init_protocol::InitInfo;

/// ELF machine type for x86-64.
pub const EXPECTED_ELF_MACHINE: u16 = elf::EM_X86_64;

const COM1: u16 = 0x3F8;

/// Whether every thread of init that writes serial holds COM1's port
/// binding: set by `serial_init` once the main thread's bind succeeded and
/// the port is programmed, and cleared by [`serial_unbound`] when init-logd's
/// bind fails. Until it is set, and after it is cleared, serial writes are
/// dropped, as riscv64 drops them before its UART is mapped: a port access
/// without the binding raises #GP under the all-denied I/O bitmap.
static PORTS_BOUND: AtomicBool = AtomicBool::new(false);

/// Initialise COM1 serial output at 115200 8N1.
pub fn serial_init(info: &InitInfo, thread_cap: u64)
{
    let Some(slot) = crate::find_cap_by_type(info, init_protocol::CapType::IoPort)
    else
    {
        return;
    };
    if syscall::ioport_bind(thread_cap, slot).is_err()
    {
        return;
    }
    // SAFETY: single-threaded init; COM1 hardware programming sequence.
    // Ports are bound to this thread via ioport_bind above.
    unsafe {
        outb(COM1 + 1, 0x00); // disable interrupts
        outb(COM1 + 3, 0x80); // DLAB = 1
        outb(COM1, 0x01); // divisor low = 1 → 115200 baud
        outb(COM1 + 1, 0x00); // divisor high = 0
        outb(COM1 + 3, 0x03); // 8N1, DLAB = 0
        outb(COM1 + 2, 0xC7); // FIFO enable
        outb(COM1 + 4, 0x0B); // DTR + RTS + OUT2
    }
    PORTS_BOUND.store(true, Ordering::Release);
}

/// Drop every later serial write: init-logd, which writes serial beside the
/// main thread, could not take COM1's port binding.
pub fn serial_unbound()
{
    PORTS_BOUND.store(false, Ordering::Release);
}

/// Release init's serial mapping: a no-op on x86-64, where COM1 is reached
/// through I/O ports bound to the writing thread, not a mapping that would
/// hold init's address space live past its reap.
pub fn serial_release() {}

/// Write one byte to COM1, spinning until the transmit register is ready;
/// dropped while [`PORTS_BOUND`] is clear.
pub fn serial_write_byte(byte: u8)
{
    if !PORTS_BOUND.load(Ordering::Acquire)
    {
        return;
    }
    // SAFETY: PORTS_BOUND is set only once the main thread holds COM1's
    // binding, and init-logd, the only other thread that writes, binds the
    // same ports before it starts or clears the flag (`serial_unbound`);
    // reading LSR is a side-effect-free I/O port read on COM1.
    while unsafe { inb(COM1 + 5) } & 0x20 == 0
    {}
    // SAFETY: writing one byte to the COM1 data register.
    unsafe { outb(COM1, byte) };
}

/// # Safety
///
/// `port` must be a valid I/O port bound to the calling thread.
#[inline]
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: caller guarantees port is a valid I/O port bound to this thread.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val,
            options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
///
/// `port` must be a valid I/O port bound to the calling thread.
#[inline]
unsafe fn inb(port: u16) -> u8
{
    let val: u8;
    // SAFETY: caller guarantees port is a valid I/O port bound to this thread.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val,
            options(nomem, nostack, preserves_flags));
    }
    val
}
