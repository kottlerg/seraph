// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/handoff.rs

//! Kernel handoff for RISC-V 64-bit.
//!
//! Provides the trampoline stub and `perform_handoff`, which installs the
//! initial Sv48 page table and transfers control to the kernel entry point.

core::arch::global_asm!(
    ".section .text.trampoline, \"ax\"",
    ".global _handoff_trampoline",
    ".global _handoff_trampoline_end",
    "_handoff_trampoline:",
    "    csrci sstatus, 0b10", // clear bit 1 (SIE) — disables S-mode interrupts
    "    csrw  satp, t0",      // install new page table
    "    sfence.vma x0, x0",   // flush all TLB entries
    "    mv    sp, t2",        // set stack
    "    jr    t1",            // jump to entry (t1)
    "_handoff_trampoline_end:",
);

unsafe extern "C" {
    /// Linker symbol at the first byte of the handoff trampoline stub.
    pub static _handoff_trampoline: u8;
    static _handoff_trampoline_end: u8;
}

/// Transfer control to the kernel on RISC-V (RV64IMAC, soft-float).
///
/// Constructs the Sv48 SATP value from `page_table_root`, resolves the
/// handoff trampoline address, and transfers control. The trampoline
/// installs the new page table via `satp`, flushes the TLB, sets the
/// stack pointer, and jumps to the kernel entry point. Does not return.
///
/// `boot_hart_id` is passed to the kernel in `a1` (SBI boot hart convention).
/// It should come from [`crate::arch::current::discover_boot_hart_id`].
///
/// # Safety
/// - `page_table_root` must be the physical address (4 KiB-aligned) of a
///   complete Sv48 root page table covering all addresses the kernel will
///   access at entry, including an RX identity mapping of the trampoline page.
/// - `entry` must be the kernel's virtual entry point address, canonical in Sv48.
/// - `boot_info` must be the physical address of a valid, populated `BootInfo`,
///   identity-mapped readable in the new page tables.
/// - `stack_top` must be a valid stack pointer, identity-mapped writable.
/// - UEFI boot services must have exited before this call.
/// - `sstatus.SIE` must be clear (interrupts disabled).
pub unsafe fn perform_handoff(
    page_table_root: u64,
    entry: u64,
    boot_info: u64,
    stack_top: u64,
    boot_hart_id: u64,
) -> !
{
    // Sv48 SATP: mode=9 (bits [63:60]), ASID=0, PPN = root >> 12.
    let satp = (9u64 << 60) | (page_table_root >> 12);

    let trampoline = core::ptr::addr_of!(_handoff_trampoline) as u64;

    let hart_id: u64 = boot_hart_id;

    // Register contract for the trampoline (see trampoline asm above):
    //   t0 = satp value  t1 = kernel entry VA  t2 = stack top
    //   a0 = boot_info   a1 = hart_id
    // Explicit register constraints prevent the compiler from assigning an
    // input to a target register, which would cause a subsequent mv to
    // clobber it before use.
    // SAFETY: All arguments satisfy the function contract above. The
    // trampoline is identity-mapped RX, so jr lands in valid executable memory.
    unsafe {
        core::arch::asm!(
            "jr {trampoline}",
            in("t0") satp,
            in("t1") entry,
            in("t2") stack_top,
            in("a0") boot_info,
            in("a1") hart_id,
            trampoline = in(reg) trampoline,
            options(noreturn),
        );
    }
}

/// Return the physical address range (`first_page`, `last_page`) of the handoff
/// trampoline stub, page-aligned. Used by the bootloader to identity-map the
/// trampoline in the initial page tables.
pub fn trampoline_page_range() -> (u64, u64)
{
    let start = core::ptr::addr_of!(_handoff_trampoline) as u64;
    let end = core::ptr::addr_of!(_handoff_trampoline_end) as u64;

    let last_byte = if end > start { end - 1 } else { start };

    let first_page = start & !0xFFF;
    let last_page = last_byte & !0xFFF;
    (first_page, last_page)
}
