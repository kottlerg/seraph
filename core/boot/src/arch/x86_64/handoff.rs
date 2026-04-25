// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/x86_64/handoff.rs

//! Kernel handoff for x86-64.
//!
//! Provides the trampoline stub and `perform_handoff`, which installs the
//! initial PML4 page table via CR3 and transfers control to the kernel entry
//! point.

// Trampoline: a small position-independent stub in .text that executes
// across the CR3 switch. Under UEFI x86-64, VA == PA (1:1 mapping), so
// the symbol address is both the current VA and the physical address.
// We identity-map the page(s) containing the trampoline as RX in the new
// page tables so the CPU can fetch instructions after mov cr3.
//
// Parameter convention (caller loads before jmp):
//   rax = CR3 (physical PML4 base)
//   rbx = entry (kernel virtual entry point)
//   rcx = boot_info (physical address, identity-mapped)
//   rdx = stack_top (physical address, identity-mapped)
//
// The stub itself uses no memory, no RIP-relative references — fully
// position-independent by construction.
core::arch::global_asm!(
    ".section .text",
    ".global _handoff_trampoline",
    ".global _handoff_trampoline_end",
    "_handoff_trampoline:",
    "    cld",
    "    cli",
    "    mov cr3, rax",
    "    mov rsp, rdx",
    "    mov rdi, rcx",
    "    jmp rbx",
    "_handoff_trampoline_end:",
);

unsafe extern "C" {
    static _handoff_trampoline: u8;
    static _handoff_trampoline_end: u8;
}

/// Return the first and last 4 KiB page physical addresses that contain the
/// handoff trampoline code. Under UEFI x86-64, VA == PA.
///
/// Use these to identity-map the trampoline as RX in the new page tables
/// before installing them via CR3, so the CPU can fetch from the same VA
/// after the switch.
pub fn trampoline_page_range() -> (u64, u64)
{
    let start = core::ptr::addr_of!(_handoff_trampoline) as u64;
    let end = core::ptr::addr_of!(_handoff_trampoline_end) as u64;

    // end points one byte past the last trampoline instruction.
    // Subtract 1 to get a byte that is inside the trampoline.
    let last_byte = if end > start { end - 1 } else { start };

    let first_page = start & !0xFFF;
    let last_page = last_byte & !0xFFF;
    (first_page, last_page)
}

/// Transfer control to the kernel on x86-64.
///
/// Loads the handoff parameters into registers, then jumps to the
/// `_handoff_trampoline` stub. The trampoline clears direction/interrupt
/// flags, installs the new page table via CR3, sets the stack pointer,
/// loads the `BootInfo` argument, and jumps to the kernel entry point.
///
/// The trampoline page must be identity-mapped RX in the new page tables
/// before calling this function (see [`trampoline_page_range`] and the
/// caller in `main.rs`).
///
/// `_boot_hart_id` is unused on x86-64 (RISC-V-only concept); accepted for
/// API symmetry with the RISC-V handoff.
///
/// # Safety
/// - `page_table_root` must be the physical address of a valid, complete PML4
///   table covering all addresses the kernel will access at entry, including
///   an RX identity mapping of the trampoline page(s).
/// - `entry` must be the kernel's virtual entry point address.
/// - `boot_info` must be the physical address of a valid, populated `BootInfo`.
/// - `stack_top` must be a valid stack pointer, 16-byte aligned.
/// - UEFI boot services must have exited before this call.
pub unsafe fn perform_handoff(
    page_table_root: u64,
    entry: u64,
    boot_info: u64,
    stack_top: u64,
    _boot_hart_id: u64,
) -> !
{
    let trampoline = core::ptr::addr_of!(_handoff_trampoline) as u64;

    // Jump to trampoline with registers pre-loaded by LLVM via explicit constraints.
    // rbx is reserved by LLVM and cannot be used as an input constraint directly;
    // instead, LLVM places `entry` in a free GPR and we move it into rbx in the
    // template before the jump. rax/rcx/rdx are not reserved and are constrained
    // directly, so no aliasing risk exists for those three.
    // No cld/cli here — the trampoline handles both.
    // SAFETY: caller ensures all parameters are valid; asm clobbers no memory, never returns.
    unsafe {
        core::arch::asm!(
            "mov rbx, {entry}",
            "jmp {trampoline}",
            in("rax") page_table_root,
            entry = in(reg) entry,
            in("rcx") boot_info,
            in("rdx") stack_top,
            trampoline = in(reg) trampoline,
            options(noreturn),
        );
    }
}
