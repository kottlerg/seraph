/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 George Kottler <mail@kottlerg.com>
 *
 * kernel/linker/riscv64.ld
 *
 * Linker script for the Seraph kernel (RISC-V RV64IMAC, soft-float).
 * Mirrors the x86-64 layout: kernel image at 0xFFFFFFFF80000000, physical direct map at
 * 0xFFFF800000000000 (established at runtime). Uses the medany code model.
 *
 * AT() clauses set each section's p_paddr relative to KERNEL_PBASE, defining
 * the image's relative physical layout; p_vaddr stays at KERNEL_VBASE. The
 * bootloader allocates one contiguous span at any free physical address,
 * places the sections at their relative offsets, and maps them at p_vaddr in
 * the initial page tables. KERNEL_PBASE is the link-time origin only, not a
 * runtime placement contract.
 */

KERNEL_VBASE = 0xFFFFFFFF80000000;
KERNEL_PBASE = 0x80200000;

ENTRY(kernel_entry)

SECTIONS
{
    . = KERNEL_VBASE;

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VBASE + KERNEL_PBASE)
    {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VBASE + KERNEL_PBASE)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VBASE + KERNEL_PBASE)
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VBASE + KERNEL_PBASE)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
