/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 George Kottler <mail@kottlerg.com>
 *
 * kernel/linker/riscv64.ld
 *
 * Linker script for the Seraph kernel (RISC-V RV64GC). Mirrors the x86-64
 * layout: kernel image at 0xFFFFFFFF80000000, physical direct map at
 * 0xFFFF800000000000 (established at runtime). Uses the medany code model.
 *
 * AT() clauses set p_paddr for each section to a low physical address
 * (KERNEL_PBASE), while p_vaddr remains at KERNEL_VBASE. The bootloader
 * allocates physical frames at p_paddr via AllocateAddress and maps them
 * at p_vaddr in the initial page tables.
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
