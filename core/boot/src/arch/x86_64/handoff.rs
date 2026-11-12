// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/x86_64/handoff.rs

//! Kernel handoff for x86-64.
//!
//! Provides the two trampoline stubs and `perform_handoff`, which installs the
//! initial page tables via CR3 and transfers control to the kernel entry
//! point. When the negotiated paging depth equals the firmware's, the
//! handoff is a CR3 write ([`_handoff_trampoline`]). When it differs, the
//! LA57 toggle trampoline leaves long mode, flips `CR4.LA57` with paging off,
//! and re-enters long mode on the new tables; it runs from a page below
//! 4 GiB that [`install_la57_toggle`] fills, since its compatibility-mode
//! half executes with 32-bit addresses
//! (`core/boot/docs/page-tables.md` § x86-64: Negotiated Paging Depth).

use core::sync::atomic::{AtomicU64, Ordering};

// Trampoline: a small position-independent stub in .text that executes
// across the CR3 switch. Under UEFI x86-64, VA == PA (1:1 mapping), so
// the symbol address is both the current VA and the physical address.
// We identity-map the page(s) containing the trampoline as RX in the new
// page tables so the CPU can fetch instructions after mov cr3.
//
// Parameter convention (caller loads before jmp):
//   rax = CR3 (physical root table base)
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

// LA57 toggle trampoline: a position-independent template, never executed in
// place. `install_la57_toggle` copies `_la57_toggle .. _la57_toggle_end` into
// a page below 4 GiB; `perform_handoff` jumps to the copy under the
// firmware's tables. `CR4.LA57` can change only outside IA-32e mode, so the
// copy leaves long mode, sets the depth with paging off, and re-enters long
// mode on the new tables (Intel SDM Vol. 3A § 10.8.5, "Initializing IA-32e
// Mode", and § 4.1.2, "Paging-Mode Enabling").
//
// Parameter convention (caller loads before jmp):
//   rax = CR3 (physical root table base; below 4 GiB)
//   rbx = entry (kernel virtual entry point)
//   rcx = boot_info (physical address, identity-mapped)
//   rdx = stack_top (physical address, identity-mapped)
//   rsi = CR4.LA57 value to install (0 or 1 << 12)
//
// Every 64-bit value the far side needs is stored into the copy's parameter
// block first: the upper halves of the general-purpose registers are
// undefined after a pass through legacy protected mode (Intel SDM Vol. 1
// § 3.4.1.1). The copy's own linear address is below 4 GiB, so the
// compatibility-mode half addresses it through EBX; the stores and far
// pointers it patches lie in the copy, which the firmware maps writable. The
// GDT descriptors are written with the accessed bit set, so no segment load
// writes the page after the switch, where it is mapped read-execute.
//
// Selectors: 0x08 = 64-bit code, 0x10 = 32-bit code, 0x18 = flat data.
// Clobbers every general-purpose register, CR0, CR3, CR4 (PCIDE cleared,
// LA57 set from rsi), GDTR, and every segment register; never returns.
core::arch::global_asm!(
    ".section .text",
    ".global _la57_toggle",
    ".global _la57_toggle_end",
    ".code64",
    "_la57_toggle:",
    "    cli",
    "    cld",
    "    mov qword ptr [rip + .Lla57_cr3], rax",
    "    mov qword ptr [rip + .Lla57_entry], rbx",
    "    mov qword ptr [rip + .Lla57_boot_info], rcx",
    "    mov qword ptr [rip + .Lla57_stack], rdx",
    "    mov qword ptr [rip + .Lla57_cr4_la57], rsi",
    // Patch the GDTR base and both far pointers with the copy's addresses.
    "    lea rax, [rip + .Lla57_gdt]",
    "    mov qword ptr [rip + .Lla57_gdtr + 2], rax",
    "    lea eax, [rip + .Lla57_compat]",
    "    mov dword ptr [rip + .Lla57_fp_compat], eax",
    "    lea eax, [rip + .Lla57_long]",
    "    mov dword ptr [rip + .Lla57_fp_long], eax",
    // EBX addresses the parameter block from compatibility mode: RIP-relative
    // references to local labels resolve at assembly time, so this names the
    // copy, never the template.
    "    lea rbx, [rip + .Lla57_params]",
    // CR0.PG cannot be cleared while CR4.PCIDE is set.
    "    mov rax, cr4",
    "    btr rax, 17",
    "    mov cr4, rax",
    "    lgdt [rip + .Lla57_gdtr]",
    "    jmp fword ptr [rip + .Lla57_fp_compat]",
    ".code32",
    ".Lla57_compat:",
    "    mov eax, 0x18",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ss, ax",
    "    mov fs, ax",
    "    mov gs, ax",
    // Clear CR0.PG: IA32_EFER.LMA drops to 0 and the CPU runs in legacy
    // protected mode with paging off, at the same (identity) address.
    "    mov eax, cr0",
    "    and eax, 0x7FFFFFFF",
    "    mov cr0, eax",
    "    mov eax, cr4",
    "    and eax, 0xFFFFEFFF",
    "    or eax, dword ptr [ebx + 8]", // .Lla57_cr4_la57
    "    mov cr4, eax",
    "    mov eax, dword ptr [ebx]", // .Lla57_cr3
    "    mov cr3, eax",
    // Set CR0.PG: with EFER.LME still set, IA-32e mode re-activates on the
    // new tables, in compatibility mode until the far jump loads the 64-bit
    // code segment.
    "    mov eax, cr0",
    "    or eax, 0x80000000",
    "    mov cr0, eax",
    "    jmp fword ptr [ebx + 16]", // .Lla57_fp_long
    ".code64",
    ".Lla57_long:",
    "    mov rsp, qword ptr [rip + .Lla57_stack]",
    "    mov rdi, qword ptr [rip + .Lla57_boot_info]",
    "    jmp qword ptr [rip + .Lla57_entry]",
    "    .balign 8",
    ".Lla57_gdt:",
    "    .quad 0",
    "    .quad 0x00AF9B000000FFFF",
    "    .quad 0x00CF9B000000FFFF",
    "    .quad 0x00CF93000000FFFF",
    ".Lla57_gdtr:",
    "    .word 31",
    "    .quad 0",
    "    .balign 8",
    ".Lla57_fp_compat:",
    "    .long 0",
    "    .word 0x10",
    "    .balign 8",
    // Parameter block; the compatibility-mode half reads its first three
    // fields at fixed offsets from EBX (+0, +8, +16).
    ".Lla57_params:",
    ".Lla57_cr3:",
    "    .quad 0",
    ".Lla57_cr4_la57:",
    "    .quad 0",
    ".Lla57_fp_long:",
    "    .long 0",
    "    .word 0x08",
    "    .balign 8",
    ".Lla57_entry:",
    "    .quad 0",
    ".Lla57_boot_info:",
    "    .quad 0",
    ".Lla57_stack:",
    "    .quad 0",
    "_la57_toggle_end:",
);

unsafe extern "C" {
    static _handoff_trampoline: u8;
    static _handoff_trampoline_end: u8;
    static _la57_toggle: u8;
    static _la57_toggle_end: u8;
}

/// Physical address of the installed LA57 toggle page, or 0 when the
/// handoff keeps the firmware's paging depth. Written once by
/// [`install_la57_toggle`] during step 5; the bootloader is single-threaded.
static LA57_TOGGLE_PAGE: AtomicU64 = AtomicU64::new(0);

/// Physical address of the installed LA57 toggle page, or 0 when none is
/// installed.
pub fn la57_toggle_page() -> u64
{
    LA57_TOGGLE_PAGE.load(Ordering::Relaxed)
}

/// Copy the LA57 toggle trampoline into `page` and select it for the handoff.
///
/// Returns `false`, installing nothing, when the assembled template does not
/// fit the page; the caller then keeps the firmware's paging depth.
///
/// `page` must lie below 4 GiB (the compatibility-mode half runs with 32-bit
/// addresses) and be executable under the firmware's tables (an
/// `EfiLoaderCode` allocation); [`trampoline_page_range`] then names it, so
/// step 6 maps it read-execute in the new tables.
///
/// # Safety
/// `page` must be an exclusively-owned, identity-mapped, writable 4 KiB
/// frame below 4 GiB, and the call must precede step 6, which maps the
/// trampoline page.
pub unsafe fn install_la57_toggle(page: u64) -> bool
{
    let start = core::ptr::addr_of!(_la57_toggle);
    let end = core::ptr::addr_of!(_la57_toggle_end);
    let Some(len) = (end as usize).checked_sub(start as usize)
    else
    {
        return false;
    };
    // The template is a few hundred bytes of `.text`; a larger one is an
    // assembly defect, refused here rather than copied past the page.
    if len > 4096
    {
        return false;
    }
    // SAFETY: start..end is the assembled template in this image's .text;
    // page is an exclusively-owned writable frame (caller contract) and the
    // template fits it (checked above).
    unsafe {
        core::ptr::copy_nonoverlapping(start, page as *mut u8, len);
    }
    LA57_TOGGLE_PAGE.store(page, Ordering::Relaxed);
    true
}

/// Return the first and last 4 KiB page physical addresses that contain the
/// handoff trampoline code: the installed LA57 toggle page when there is
/// one, else the `.text` pages holding `_handoff_trampoline`. Under UEFI
/// x86-64, VA == PA.
///
/// Use these to identity-map the trampoline as RX in the new page tables
/// before installing them via CR3, so the CPU can fetch from the same VA
/// after the switch.
pub fn trampoline_page_range() -> (u64, u64)
{
    let toggle = la57_toggle_page();
    if toggle != 0
    {
        return (toggle, toggle);
    }

    let start = core::ptr::addr_of!(_handoff_trampoline) as u64;
    let end = core::ptr::addr_of!(_handoff_trampoline_end) as u64;

    // end points one byte past the last trampoline instruction.
    // Subtract 1 to get a byte that is inside the trampoline.
    // `end` is above `start`, so it is at least 1.
    let last_byte = if end > start
    {
        end.saturating_sub(1)
    }
    else
    {
        start
    };

    let first_page = start & !0xFFF;
    let last_page = last_byte & !0xFFF;
    (first_page, last_page)
}

/// Transfer control to the kernel on x86-64.
///
/// Loads the handoff parameters into registers, then jumps to the installed
/// LA57 toggle page when the negotiated depth differs from the firmware's,
/// or to the `_handoff_trampoline` stub otherwise. Either trampoline clears
/// direction/interrupt flags, installs the new page table via CR3 (the
/// toggle after setting `CR4.LA57` to `cr4_la57`), sets the stack pointer,
/// loads the `BootInfo` argument, and jumps to the kernel entry point.
///
/// The trampoline page must be identity-mapped RX in the new page tables
/// before calling this function (see [`trampoline_page_range`] and
/// `install_handoff_trampoline_mapping` in `core/boot/src/main.rs`).
///
/// `_boot_hart_id` is unused on x86-64 (RISC-V-only concept); accepted for
/// API symmetry with the RISC-V handoff.
///
/// # Safety
/// - `page_table_root` must be the physical address of a valid, complete
///   root table of the negotiated depth covering all addresses the kernel
///   will access at entry, including an RX identity mapping of the
///   trampoline page(s), and must lie below 4 GiB.
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
    let toggle = la57_toggle_page();
    let (trampoline, cr4_la57) = if toggle != 0
    {
        let la57 = super::paging::negotiated_depth().la57();
        (
            toggle,
            if la57
            {
                boot_protocol::x86_paging::CR4_LA57
            }
            else
            {
                0
            },
        )
    }
    else
    {
        (core::ptr::addr_of!(_handoff_trampoline) as u64, 0)
    };

    // Jump to trampoline with registers pre-loaded by LLVM via explicit constraints.
    // rbx is reserved by LLVM and cannot be used as an input constraint directly;
    // instead, LLVM places `entry` in a free GPR and we move it into rbx in the
    // template before the jump. rax/rcx/rdx/rsi are not reserved and are
    // constrained directly, so no aliasing risk exists for those four; the
    // `_handoff_trampoline` stub ignores rsi.
    // No cld/cli here — the trampoline handles both.
    // SAFETY: caller ensures all parameters are valid; never returns. The
    // asm writes no memory the compiler owns: `_handoff_trampoline` writes
    // none, and the LA57 toggle writes only its own page's parameter block,
    // GDTR base and far pointers, which no Rust object occupies.
    unsafe {
        core::arch::asm!(
            "mov rbx, {entry}",
            "jmp {trampoline}",
            in("rax") page_table_root,
            entry = in(reg) entry,
            in("rcx") boot_info,
            in("rdx") stack_top,
            in("rsi") cr4_la57,
            trampoline = in(reg) trampoline,
            options(noreturn),
        );
    }
}
