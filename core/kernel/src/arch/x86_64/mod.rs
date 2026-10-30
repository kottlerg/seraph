// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/mod.rs

//! x86-64 architecture module for the kernel.

pub mod ap_trampoline;
pub mod console;
pub mod context;
pub mod cpu;
#[cfg(not(test))]
pub mod entropy;
pub mod fpu;
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

/// ELF machine type of userspace images this kernel loads (init/ktest).
pub const EXPECTED_ELF_MACHINE: u16 = elf::EM_X86_64;

/// Maximum GSI (Global System Interrupt) number the IRQ id range admits on x86-64: 22, the
/// last GSI with an IDT gate (`ioapic::DEVICE_GSI_COUNT`, vectors 33-55, dispatched by
/// `idt::irq_dispatch`). `SYS_IRQ_REGISTER` refuses an id above it, so no GSI is routed to an
/// ungated or reserved vector.
pub const MAX_IRQ_ID: u32 = ioapic::DEVICE_GSI_COUNT - 1;

/// Minimum valid GSI number on x86-64. GSI 0 (PIT timer) is a legitimate
/// platform resource; nothing is reserved at the low end.
// dead_code: host test builds compile out its readers (`sys_irq_register`,
// `dealloc_object_one`).
#[cfg_attr(test, allow(dead_code))]
pub const MIN_IRQ_ID: u32 = 0;

/// x86-64 has I/O port space; `IoPort` resources are valid here.
pub const HAS_IO_PORTS: bool = true;

/// x86-64 has no SBI firmware interface; `SbiControl` is a RISC-V-only concept.
pub const HAS_SBI: bool = false;

/// Width of the root `Interrupt` range capability minted at Phase 7: GSI 0..256, matching the
/// `irq` routing table (`irq::MAX_IRQ`). The discovered I/O APICs cover only their reported
/// pins, and the IDT dispatches only GSIs 0-22 ([`MAX_IRQ_ID`]): a split names the ids above
/// it, `SYS_IRQ_REGISTER` refuses them, and the Interrupt teardown leaves their routing
/// untouched.
pub const ROOT_IRQ_COUNT: u32 = 256;

/// Size of the I/O Permission Bitmap in bytes (re-exported from gdt for use
/// in architecture-independent code such as `ThreadControlBlock`).
pub use gdt::IOPB_SIZE;

/// Forward a sanctioned SBI call — unsupported on x86-64.
///
/// x86-64 has no SBI firmware interface, so this always fails. Unreachable in
/// practice: `syscall::sbi::sys_sbi_call` gates on [`HAS_SBI`] before calling.
#[cfg(not(test))]
pub fn sbi_forward(_extension: u64, _function: u64, _a0: u64, _a1: u64, _a2: u64)
-> Result<u64, ()>
{
    Err(())
}

/// Allocate the x86-64 per-CPU tables (per-AP GDT/TSS, AP IST stacks, and the
/// NMI-backtrace request slab) for `cpu_count` CPUs. Called once on the BSP in Phase 4, from
/// `sched::init_per_cpu_storage`, before Phase 5 and SMP bring-up.
#[cfg(not(test))]
pub fn init_ap_percpu_storage(cpu_count: usize, allocator: &mut crate::mm::BuddyAllocator)
{
    gdt::init_ap_storage(cpu_count, allocator);
    ap_trampoline::init_ap_ist_storage(cpu_count, allocator);
    interrupts::init_nmi_backtrace_storage(cpu_count, allocator);
}

// MMIO regions that must be direct-mapped during Phase 3 page-table setup are
// supplied by [`platform::collect_mmio_direct_map_regions`], which reads
// xAPIC + I/O APIC bases from `BootInfo.kernel_mmio`.
