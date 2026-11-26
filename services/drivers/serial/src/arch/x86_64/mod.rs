// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/arch/x86_64/mod.rs

//! x86-64 serial I/O via an I/O-port 16550 UART.
//!
//! The driver binds the `IoPort` cap devmgr delivered (the range the UART's
//! device record names: `0x3F8`, eight ports, for COM1 on QEMU) to the
//! thread that sets the UART up, and reaches the registers with `in` and
//! `out` from that thread alone ([`Uart`]).

use core::marker::PhantomData;

use driver_binding::resources::Resource;
use serial::uart;

/// The UART's register file, reachable from the thread [`serial_init`]
/// bound its ports to. Not `Send`: the binding is that thread's, and an
/// `in` or `out` from another thread faults.
#[derive(Clone, Copy)]
pub struct Uart
{
    /// The UART's first port.
    port: u16,
    /// Keeps the handle on its thread.
    _thread: PhantomData<*const ()>,
}

/// Bind the UART's `IoPort` range, `registers`, to `self_thread`, the
/// calling thread, so `in`/`out` against it do not fault. `self_aspace` is
/// unused on x86-64. `None` if `registers` is not an `IoPort` range of at
/// least the eight ports a 16550 spans, or the bind fails.
///
/// # Safety
/// None on x86-64: the UART is reached through I/O ports and nothing is
/// mapped. The function is `unsafe` for the arch-dispatch surface, whose
/// riscv64 implementation maps the cap it is handed.
pub unsafe fn serial_init(self_thread: u64, _self_aspace: u64, registers: &Resource)
-> Option<Uart>
{
    let Resource::IoPort { cap, base, count } = *registers
    else
    {
        return None;
    };
    let port = u16::try_from(base).ok()?;
    if port == 0
        || count < u64::from(uart::REGISTERS)
        || syscall::ioport_bind(self_thread, cap).is_err()
    {
        return None;
    }
    Some(Uart {
        port,
        _thread: PhantomData,
    })
}

impl Uart
{
    /// Read the register at `offset` (one of [`uart`]'s, below
    /// [`uart::REGISTERS`]).
    pub fn read(self, offset: u8) -> u8
    {
        // SAFETY: the port lies in the UART's eight-port range, bound to this
        // thread by `serial_init` (the handle is not `Send`).
        unsafe { inb(self.register(offset)) }
    }

    /// Write `value` to the register at `offset` (one of [`uart`]'s, below
    /// [`uart::REGISTERS`]).
    pub fn write(self, offset: u8, value: u8)
    {
        // SAFETY: as for `read`.
        unsafe { outb(self.register(offset), value) };
    }

    /// The port of the register at `offset`. The `IoPort` range
    /// `serial_init` bound holds the eight ports from `port` within the
    /// 16-bit port space, so the sum never saturates.
    fn register(self, offset: u8) -> u16
    {
        self.port
            .saturating_add(u16::from(offset % uart::REGISTERS))
    }
}

/// # Safety
///
/// `port` must be a valid I/O port bound to the calling thread.
#[inline]
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: caller guarantees port is bound to this thread.
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
    // SAFETY: caller guarantees port is bound to this thread.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val,
            options(nomem, nostack, preserves_flags));
    }
    val
}
