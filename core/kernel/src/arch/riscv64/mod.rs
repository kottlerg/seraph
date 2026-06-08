// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/mod.rs

//! RISC-V 64-bit architecture module for the kernel.

pub mod ap_trampoline;
pub mod console;
pub mod context;
pub mod cpu;
pub mod fpu;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod paging;
pub mod platform;
pub mod sbi;
pub mod syscall;
pub mod timer;
pub mod trap_frame;

/// Architecture name string for use in diagnostic output.
pub const ARCH_NAME: &str = "riscv64";

/// Maximum PLIC source number the kernel programs. Sources 1–`MAX_IRQ_ID`
/// are usable; source 0 is reserved by the PLIC spec.
///
/// Part of the arch-interface contract; no current in-tree consumer.
#[allow(dead_code)]
pub const MAX_IRQ_ID: u32 = 127;

/// Minimum valid PLIC source number. PLIC source 0 is reserved and never
/// wired to a real device.
#[allow(dead_code)]
pub const MIN_IRQ_ID: u32 = 1;

/// RISC-V has no I/O port space; `IoPort` resources are silently skipped.
pub const HAS_IO_PORTS: bool = false;

/// RISC-V exposes SBI firmware; one root `SbiControl` capability is minted.
pub const HAS_SBI: bool = true;

/// Width of the root `Interrupt` range capability minted at Phase 7. The PLIC
/// spec maximum is 1024 sources; most platforms expose far fewer. Oversizing
/// is safe — `plic_enable` rejects out-of-range ids.
pub const ROOT_IRQ_COUNT: u32 = 1024;

/// Size of the I/O Permission Bitmap. Zero on RISC-V (no I/O port concept).
/// Used to size the `iopb` field in `ThreadControlBlock` uniformly across arches.
pub const IOPB_SIZE: usize = 0;

/// Forward a sanctioned SBI call to M-mode firmware, mapping any SBI error to a
/// generic failure. Cap-rights enforcement happens in the neutral
/// `syscall::sbi` handler before this is reached.
#[cfg(not(test))]
pub fn sbi_forward(extension: u64, function: u64, a0: u64, a1: u64, a2: u64) -> Result<u64, ()>
{
    let ret = sbi::sbi_call(extension, function, a0, a1, a2);
    if ret.error != 0
    {
        return Err(());
    }
    Ok(ret.value)
}

/// No-op on RISC-V: there are no per-CPU GDT/TSS/IST tables or NMI-backtrace
/// slab — those are x86-64 concepts. Present so the SMP bring-up path calls it
/// unconditionally on both arches.
#[cfg(not(test))]
pub fn init_ap_percpu_storage(_cpu_count: usize, _allocator: &mut crate::mm::BuddyAllocator) {}

// MMIO regions that must be direct-mapped during Phase 3 page-table setup
// are supplied by [`platform::collect_mmio_direct_map_regions`], which always
// returns 0 entries on RISC-V: PLIC and UART lie inside the physical RAM
// range that the large-page direct map already covers on every supported
// UEFI-on-RISC-V layout.
