/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 George Kottler <mail@kottlerg.com>
 *
 * boot/loader/linker/riscv64-uefi.ld
 *
 * Linker script for the RISC-V UEFI bootloader. Produces an ELF that
 * llvm-objcopy converts to a flat PE32+ binary. The hand-crafted PE/COFF
 * header from header.S is placed at offset 0x000; the entry trampoline
 * and Rust code begin at 0x1000.
 */

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)

ENTRY(_start)

SECTIONS
{
    . = 0x0;

    /* PE/COFF header block, hand-assembled in header.S. */
    .pecoff_header : {
        KEEP(*(.pecoff_header))
    }

    /* Page-align to 0x1000 before the first section's data. */
    . = 0x1000;

    /* _start: RVA of the entry trampoline, placed in AddressOfEntryPoint. */
    _start = .;

    .text : {
        /* Entry trampoline must be first so it sits at AddressOfEntryPoint. */
        KEEP(*(.text.entry))

        /* Force align handoff trampoline into its own 4KiB page. */
        . = ALIGN(0x1000);
        KEEP(*(.text.trampoline))
        KEEP(*(.text.trampoline.*))
        *(.text .text.*)
    }

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    }

    /* Advance the location counter to a page boundary and record it as
     * _etext. This is where the PE .text section (RX) ends and the PE
     * .data section (RW) begins. Using ". = ALIGN" (not "symbol = ALIGN")
     * is required to actually advance the LMA/VMA before the next section. */
    . = ALIGN(0x1000);
    _etext = .;

    .data : ALIGN(8) {
        *(.data .data.*)
    }

    .bss : ALIGN(8) {
        *(.bss .bss.*)
        *(COMMON)
    }

    /* _ebss: end of BSS, page-aligned. PE .data section VirtualSize ends here.
     * llvm-objcopy -O binary zero-fills all ALLOC regions including .bss, so
     * [_etext, _ebss) is fully present in the flat binary. */
    . = ALIGN(0x1000);
    _ebss = .;

    /* Base-relocation table — required by EFI loaders even for PIC images. */
    .reloc : ALIGN(0x1000) {
        _reloc_start = .;
        KEEP(*(.reloc))
        _reloc_end = .;
    }

    /* _image_end: total image size in memory, aligned to SectionAlignment. */
    _image_end = ALIGN(0x1000);

    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
        *(.comment)
        *(.riscv.attributes)
    }
}
