// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/mod.rs

//! RISC-V 64-bit architecture module for the kernel.

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
pub mod paging;
pub mod platform;
pub mod sbi;
pub mod syscall;
pub mod timer;
pub mod trap_frame;

/// Architecture name string for use in diagnostic output.
pub const ARCH_NAME: &str = "riscv64";

/// ELF machine type of the init image; selects the `RELATIVE` relocation
/// type when Phase 9 applies init's `.rela.dyn` fix-ups (`mm::init_reloc`).
pub const EXPECTED_ELF_MACHINE: u16 = elf::EM_RISCV;

/// Maximum PLIC source number the kernel programs (`interrupts::PLIC_NUM_SOURCES`).
/// Sources 1–`MAX_IRQ_ID` are usable; source 0 is reserved by the PLIC spec.
/// `SYS_IRQ_REGISTER` refuses an id outside them.
pub const MAX_IRQ_ID: u32 = 127;

/// Minimum valid PLIC source number. PLIC source 0 is reserved and never
/// wired to a real device.
// dead_code: host test builds compile out its readers (`sys_irq_register`,
// `dealloc_object_one`).
#[cfg_attr(test, allow(dead_code))]
pub const MIN_IRQ_ID: u32 = 1;

/// RISC-V has no I/O port space: no root `IoPort` capability is minted and
/// the `sys_ioport_*` syscalls return `NotSupported`.
pub const HAS_IO_PORTS: bool = false;

/// RISC-V exposes SBI firmware; one root `SbiControl` capability is minted.
pub const HAS_SBI: bool = true;

/// Width of the root `Interrupt` range capability minted at Phase 7: the
/// PLIC's 1024-entry id space (id 0 reserved, sources 1–1023); most platforms
/// expose far fewer. The cap spans ids the kernel does not program; a split can
/// name them, `SYS_IRQ_REGISTER` refuses any outside `MIN_IRQ_ID..=MAX_IRQ_ID`
/// with `InvalidArgument`, and the teardown of a cap naming one leaves the
/// routing table and the PLIC untouched.
pub const ROOT_IRQ_COUNT: u32 = 1024;

/// Size of the I/O Permission Bitmap (re-exported from gdt for use in
/// architecture-independent code such as `ThreadControlBlock`).
pub use gdt::IOPB_SIZE;

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
// returns 0 entries on RISC-V: the PLIC and UART on the QEMU `virt` machine
// sit below the RAM ceiling, inside the [0, ceiling) span the large-page
// direct map already covers.
