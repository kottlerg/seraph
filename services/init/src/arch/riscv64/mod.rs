// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/init/src/arch/riscv64/mod.rs

//! RISC-V serial output via 16550 UART MMIO and architecture constants.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use init_protocol::{CapType, InitInfo};

/// ELF machine type for RISC-V.
pub const EXPECTED_ELF_MACHINE: u16 = elf::EM_RISCV;

const UART_PHYS: u64 = 0x1000_0000;
const SERIAL_VA: u64 = 0x0000_0000_3000_0000;
/// The UART's virtual address once `serial_init` has mapped and programmed
/// it; 0 before that and after `serial_release`. Published with Release after
/// the programming, so a thread that loads it with Acquire sees the device
/// set up.
static UART_BASE: AtomicU64 = AtomicU64::new(0);
/// The Mmio cap slot `serial_init` mapped the UART aperture through; 0 until
/// it maps one and after `serial_release` takes it.
static UART_MMIO_CAP: AtomicU32 = AtomicU32::new(0);

/// Initialise UART serial output via MMIO.
///
/// Scans `Mmio` descriptors for the aperture containing `UART_PHYS`,
/// maps the full aperture at `SERIAL_VA`, and records the UART's virtual
/// address including its in-aperture offset. v6 apertures are coarse —
/// the UART is typically one of several devices inside the aperture.
pub fn serial_init(info: &InitInfo, _thread_cap: u32)
{
    let descriptors = crate::descriptors(info);
    let mut aperture: Option<(u32, u64, u64)> = None;
    for d in descriptors
    {
        if d.cap_type != CapType::Mmio
        {
            continue;
        }
        if UART_PHYS >= d.aux0 && UART_PHYS < d.aux0 + d.aux1
        {
            aperture = Some((d.slot, d.aux0, d.aux1));
            break;
        }
    }
    let Some((slot, base, size)) = aperture
    else
    {
        return;
    };
    // The whole aperture is mapped from SERIAL_VA, so it must end below the
    // next page of init's VA plan, the main thread's IPC buffer.
    if size > crate::INIT_IPC_BUF_VA - SERIAL_VA
    {
        return;
    }
    // SAFETY: `info.aspace_cap` is init's own address space; the span
    // `[SERIAL_VA, SERIAL_VA + size)` lies in init's private VA plan below
    // INIT_IPC_BUF_VA (checked above), where nothing else is mapped and no
    // Rust object lies.
    if unsafe { syscall::mmio_map(info.aspace_cap, slot, SERIAL_VA, 0) }.is_err()
    {
        return;
    }
    let uart_offset = UART_PHYS - base;
    let uart_va = SERIAL_VA + uart_offset;
    UART_MMIO_CAP.store(slot, Ordering::Release);
    // SAFETY: UART MMIO programming before any other thread exists (init-logd
    // starts later). The full aperture is mapped at SERIAL_VA; UART sits at
    // uart_offset inside it.
    unsafe {
        let ptr = uart_va as *mut u8;
        core::ptr::write_volatile(ptr.add(1), 0x00);
        core::ptr::write_volatile(ptr.add(3), 0x80);
        core::ptr::write_volatile(ptr, 0x01);
        core::ptr::write_volatile(ptr.add(1), 0x00);
        core::ptr::write_volatile(ptr.add(3), 0x03);
    }
    UART_BASE.store(uart_va, Ordering::Release);
}

/// Release init's serial mapping: delete the Mmio cap `serial_init` mapped the
/// UART aperture through, which unmaps it and drops the reference its mapping
/// record holds on init's address space, so the reap's delete of that address
/// space frees it and its mappings of the frames init donates
/// (`docs/process-lifecycle.md` § Init reap). Later serial writes are dropped.
///
/// Called by init-logd as it exits after the handover, when no thread of init
/// writes the UART again: the main thread logs through init-logd once it runs.
pub fn serial_release()
{
    UART_BASE.store(0, Ordering::Release);
    let slot = UART_MMIO_CAP.swap(0, Ordering::AcqRel);
    if slot != 0
    {
        let _ = syscall::cap_delete(slot);
    }
}

/// Write one byte to the UART, spinning until the transmit register is ready.
pub fn serial_write_byte(byte: u8)
{
    let base = UART_BASE.load(Ordering::Acquire);
    if base == 0
    {
        return;
    }
    let p = base as *mut u8;
    // SAFETY: a nonzero UART_BASE names the UART inside the aperture
    // serial_init mapped, which stays mapped until serial_release, run by the
    // last writer as it exits; reading LSR is side-effect free.
    while unsafe { core::ptr::read_volatile(p.add(5)) } & 0x20 == 0
    {}
    // SAFETY: as above; writing the data register.
    unsafe { core::ptr::write_volatile(p, byte) };
}
