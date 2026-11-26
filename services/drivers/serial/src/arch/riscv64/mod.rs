// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/arch/riscv64/mod.rs

//! RISC-V serial I/O via a memory-mapped NS16550 UART.
//!
//! The driver maps the `Mmio` range devmgr delivered (the range the UART's
//! device record names; `0x10000000` on QEMU virt) into its own address
//! space and reaches the registers with volatile byte accesses ([`Uart`]).
//! Registers are byte-addressed (reg-shift 0), matching the bootloader's
//! NS16550 access.

use core::marker::PhantomData;
use std::os::seraph::{mmio_map_funded, reserve_pages};

use driver_binding::resources::Resource;
use serial::uart;
use syscall_abi::PAGE_SIZE;

/// The UART's register file, mapped by [`serial_init`] for the process's
/// lifetime. Not `Send`, as on x86-64, where the register access is the
/// setting-up thread's alone, so the driver's threads are the same on both.
#[derive(Clone, Copy)]
pub struct Uart
{
    /// The virtual address the UART's page is mapped at.
    base: u64,
    /// Keeps the handle on its thread.
    _thread: PhantomData<*const ()>,
}

/// Reserve a VA page and map the UART's `Mmio` range, `registers`, into it.
/// The reservation lives for the process's lifetime. `self_thread` is unused
/// on RISC-V. `None` if `registers` is not a page-aligned `Mmio` range of at
/// most one page holding the registers, or reservation or mapping fails.
///
/// # Safety
/// `self_aspace` must be this process's own address space, and `registers`
/// the range devmgr delivered: its cap spans the range from its page-aligned
/// base to the page end, so a range of at most one page keeps the
/// whole-region mapping inside the one-page reservation
/// (`syscall::mmio_map`'s contract).
pub unsafe fn serial_init(_self_thread: u64, self_aspace: u64, registers: &Resource)
-> Option<Uart>
{
    let Resource::Mmio {
        cap: mmio_cap,
        phys,
        bytes,
        ..
    } = *registers
    else
    {
        return None;
    };
    if phys % PAGE_SIZE != 0 || !(u64::from(uart::REGISTERS)..=PAGE_SIZE).contains(&bytes)
    {
        return None;
    }
    let range = reserve_pages(1).ok()?;
    let base = range.va_start();
    // SAFETY: `range` is a fresh one-page reservation from the per-process
    // arena, owned for the process's lifetime, and the caller's contract
    // bounds the region to one page, so the whole-region mapping stays
    // inside it: VA no Rust object or IPC page occupies.
    // This module's UART accessors reach the mapping only through raw
    // volatile loads and stores, never a reference, and the reservation
    // stays held for the process's lifetime (`mmio_map` § Safety), mapped
    // or not.
    if unsafe { mmio_map_funded(self_aspace, mmio_cap, base, 1) }.is_err()
    {
        return None;
    }
    Some(Uart {
        base,
        _thread: PhantomData,
    })
}

impl Uart
{
    /// Read the register at `offset` (one of [`uart`]'s, below
    /// [`uart::REGISTERS`]).
    pub fn read(self, offset: u8) -> u8
    {
        // SAFETY: `serial_init` mapped the UART's page at `base` for the
        // process's lifetime, and the register lies inside it, byte-aligned.
        unsafe { core::ptr::read_volatile(self.register(offset)) }
    }

    /// Write `value` to the register at `offset` (one of [`uart`]'s, below
    /// [`uart::REGISTERS`]).
    pub fn write(self, offset: u8, value: u8)
    {
        // SAFETY: as for `read`.
        unsafe { core::ptr::write_volatile(self.register(offset).cast_mut(), value) };
    }

    /// The address of the register at `offset`; every register lies inside
    /// the mapped page, so the sum never saturates.
    fn register(self, offset: u8) -> *const u8
    {
        self.base
            .saturating_add(u64::from(offset % uart::REGISTERS)) as *const u8
    }
}
