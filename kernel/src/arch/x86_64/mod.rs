// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/mod.rs

//! x86-64 architecture module for the kernel.

pub mod ap_trampoline;
pub mod console;
pub mod context;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod ioapic;
pub mod paging;
pub mod platform;
pub mod syscall;
pub mod timer;
pub mod trap_frame;

/// Architecture name string for use in diagnostic output.
pub const ARCH_NAME: &str = "x86_64";

/// Maximum valid GSI (Global System Interrupt) number on x86-64.
/// I/O APIC delivers GSIs 0–255.
///
/// Part of the arch-interface contract; no current in-tree consumer.
#[allow(dead_code)]
pub const MAX_IRQ_ID: u32 = 255;

/// Minimum valid GSI number on x86-64. GSI 0 (PIT timer) is a legitimate
/// platform resource; nothing is reserved at the low end.
#[allow(dead_code)]
pub const MIN_IRQ_ID: u32 = 0;

/// x86-64 has I/O port space; `IoPortRange` resources are valid here.
#[allow(dead_code)]
pub const HAS_IO_PORTS: bool = true;

/// Size of the I/O Permission Bitmap in bytes (re-exported from gdt for use
/// in architecture-independent code such as `ThreadControlBlock`).
pub use gdt::IOPB_SIZE;

// MMIO regions that must be direct-mapped during Phase 3 page-table setup are
// supplied by [`platform::collect_mmio_direct_map_regions`], which reads
// xAPIC + I/O APIC bases from `BootInfo.kernel_mmio`.
