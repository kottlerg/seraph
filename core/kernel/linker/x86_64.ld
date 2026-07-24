/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 George Kottler <mail@kottlerg.com>
 *
 * kernel/linker/x86_64.ld
 *
 * Linker script for the Seraph kernel (x86-64). The kernel links as a
 * static-PIE (ET_DYN) image at KERNEL_VBASE, the zero-bias virtual origin;
 * the bootloader chooses the load bias (KASLR) and applies the RELATIVE
 * relocations in .rela.dyn before handoff. The physical direct map base is
 * established at runtime from BootInfo.
 *
 * The dynamic-linking sections lld emits under -pie (.rela.dyn, .dynamic,
 * .got, ...) are placed explicitly inside [__rodata_start, __rodata_end) so
 * the image keeps a single linear VA->PA offset with 4 KiB section alignment
 * and Phase 3 maps them read-only; the bootloader fills .got while the span
 * is still plain RAM, so no writable mapping is ever needed.
 *
 * AT() clauses set each section's p_paddr relative to KERNEL_PBASE, defining
 * the image's relative physical layout; p_vaddr stays at KERNEL_VBASE. The
 * bootloader allocates one contiguous span at any free physical address,
 * places the sections at their relative offsets, and maps them at biased
 * p_vaddr in the initial page tables. KERNEL_PBASE is the link-time origin
 * only, not a runtime placement contract.
 */

KERNEL_VBASE = 0xFFFFFFFF80000000;
KERNEL_PBASE = 0x00200000;

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
    }

    .rela.dyn :
    {
        *(.rela.dyn)
    }

    .gnu.hash :
    {
        *(.gnu.hash)
    }

    .dynsym :
    {
        *(.dynsym)
    }

    .dynstr :
    {
        *(.dynstr)
    }

    /* lld flags .dynamic/.got SHF_WRITE, so they form an RW program header
       even though nothing writes them after the bootloader's relocation
       pass; page alignment keeps that header 4 KiB-clean for the loader.
       Phase 3 remaps them read-only via [__rodata_start, __rodata_end). */
    .dynamic ALIGN(4K) :
    {
        *(.dynamic)
    }

    .got :
    {
        *(.got .got.plt)
    }

    __rodata_end = .;

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
