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
        /* PLT/iplt stubs: expected empty under plt-by-default:no + -Bsymbolic;
         * captured here (RX) so they never land as an orphan section. */
        *(.plt)
        *(.plt.*)
        *(.iplt)
    }

    /* Advance the location counter to a page boundary and record it as
     * _etext. This is where the PE .text section (RX, code only) ends and the
     * PE .data section (RW) begins. Using ". = ALIGN" (not "symbol = ALIGN")
     * is required to actually advance the LMA/VMA before the next section. */
    . = ALIGN(0x1000);
    _etext = .;

    /* Everything from here lives in the RW PE .data section. The static-PIE
     * R_RISCV_RELATIVE relocations target absolute data pointers held in
     * .rodata / .data.rel.ro / .got; the self-relocation loop in header.S
     * WRITES those targets at entry, so they must be in a writable region.
     * EDK2 maps the RX .text PE section read-only, so .rodata cannot stay
     * there. W^X is preserved: code is RX (above), this data region is RW+NX. */
    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.data.rel.ro .data.rel.ro.*)
    }

    /* Relocation metadata. The self-relocation loop only reads these, but they
     * share this RW .data PE region with the targets below (no separate RO
     * mapping). Bounded by __rela_dyn_start/__rela_dyn_end. */
    .dynamic : ALIGN(8) {
        __dynamic_start = .;
        *(.dynamic)
        __dynamic_end = .;
    }

    .rela.dyn : ALIGN(8) {
        __rela_dyn_start = .;
        *(.rela .rela.*)
        __rela_dyn_end = .;
    }

    .data : ALIGN(8) {
        /* GOT entries are written by the self-relocation loop (each holds an
         * R_RISCV_RELATIVE address). Under -z notext + plt-by-default:no it is
         * usually empty; placed here defensively. */
        *(.got)
        *(.got.plt)
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    .bss : ALIGN(8) {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
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

    /* Dynamic-linking metadata that a static-PIE never consults at runtime.
     * Discarding these keeps them from becoming ALLOC sections placed outside
     * [_start, _ebss) (which UEFI would not map). Safe only while .rela.dyn is
     * RELATIVE-only (no symbolic entries reference .dynsym/.dynstr); verified
     * post-build via `llvm-readobj --dyn-relocations`. */
    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
        *(.comment)
        *(.riscv.attributes)
        *(.interp)
        *(.hash)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
        *(.gnu.version*)
    }
}
