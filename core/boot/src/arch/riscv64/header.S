// SPDX-License-Identifier: GPL-2.0-only
//
// Derived from the Linux kernel file arch/riscv/kernel/efi-header.S
// Copyright (C) 2020 Western Digital Corporation or its affiliates.
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>
//
// The Linux RISC-V EFI header is adapted from the ARM64 implementation
// by Ard Biesheuvel and ARM64 Linux contributors.

// boot/src/arch/riscv64/header.S

// UEFI firmware loads EFI applications as PE32+ images. LLVM's PE/COFF backend
// does not support RISC-V, so we compile the bootloader as a PIC ELF and
// prepend this header. `llvm-objcopy -O binary` then produces a flat binary
// where byte 0 is the DOS MZ signature — exactly what UEFI expects.
//
// Layout (all offsets relative to image base = pecoff_header_start = 0):
//   0x000: DOS MZ stub (64 bytes)
//   0x040: PE signature (4 bytes)
//   0x044: COFF file header (20 bytes)
//   0x058: PE32+ optional header (240 bytes)
//   0x148: .text  section header (40 bytes) — code only, RX
//   0x170: .data  section header (40 bytes) — rodata + relocs + data + bss, RW
//   0x198: .reloc section header (40 bytes) — base relocs,  discardable
//   0x1C0: padding to 0x1000 (page boundary)
//   0x1000: .text section — entry trampoline, then Rust code (RX, code only)
//   _etext: .data section — .rodata/.data.rel.ro, .dynamic/.rela.dyn, .got,
//           initialised data, then BSS (RW; reloc targets, written at entry)
//   _ebss:  .reloc section — minimal base-relocation block
//
// References:
//   - Linux kernel arch/riscv/kernel/efi-header.S
//   - UEFI Specification §2.1.1 (PE32+ image)
//   - PE/COFF spec §3 (COFF file header), §4 (optional header)

    .section ".pecoff_header", "a"

    .global pecoff_header_start
pecoff_header_start:

// ── DOS MZ stub ───────────────────────────────────────────────────────────────
// Bytes 0x00..0x3F: minimal DOS stub required by PE loaders.
// Only e_magic and e_lfanew (PE header offset at 0x3C) are significant.

    .short  0x5A4D                                  // e_magic: 'MZ'
    .skip   58, 0                                   // unused fields / stub code
    .long   pe_header - pecoff_header_start         // e_lfanew: PE header offset

// ── PE signature ──────────────────────────────────────────────────────────────
pe_header:
    .ascii  "PE\0\0"                                // Signature

// ── COFF file header (20 bytes) ───────────────────────────────────────────────

    .short  0x5064          // Machine: IMAGE_FILE_MACHINE_RISCV64
    .short  3               // NumberOfSections (.text + .data + .reloc)
    .long   0               // TimeDateStamp (0 = reproducible)
    .long   0               // PointerToSymbolTable (deprecated)
    .long   0               // NumberOfSymbols (deprecated)
    .short  opt_hdr_end - opt_hdr   // SizeOfOptionalHeader
    // Characteristics:
    //   IMAGE_FILE_EXECUTABLE_IMAGE      0x0002
    //   IMAGE_FILE_LINE_NUMS_STRIPPED    0x0004
    //   IMAGE_FILE_LOCAL_SYMS_STRIPPED   0x0008
    //   IMAGE_FILE_DEBUG_STRIPPED        0x0200
    .short  0x020E

// ── PE32+ optional header (240 bytes) ─────────────────────────────────────────
opt_hdr:
    // Standard fields (24 bytes)
    .short  0x020B                                  // Magic: PE32+
    .byte   0                                       // MajorLinkerVersion
    .byte   0                                       // MinorLinkerVersion
    .long   _etext - _start                         // SizeOfCode (code only)
    .long   _ebss  - _etext                         // SizeOfInitializedData (rodata + relocs + data + bss, in file)
    .long   0                                       // SizeOfUninitializedData (bss zero-fill included above)
    .long   _start - pecoff_header_start            // AddressOfEntryPoint (RVA)
    .long   _start - pecoff_header_start            // BaseOfCode (RVA)

    // Windows-specific fields for PE32+ (88 bytes)
    .quad   0                   // ImageBase (EFI firmware relocates to a free region)
    .long   0x1000              // SectionAlignment (4 KiB)
    .long   0x1000              // FileAlignment (flat binary; same as SectionAlignment)
    .short  0                   // MajorOperatingSystemVersion
    .short  0                   // MinorOperatingSystemVersion
    .short  0                   // MajorImageVersion
    .short  0                   // MinorImageVersion
    .short  0                   // MajorSubsystemVersion
    .short  0                   // MinorSubsystemVersion
    .long   0                   // Win32VersionValue (reserved, must be 0)
    .long   _image_end - pecoff_header_start        // SizeOfImage
    .long   _start - pecoff_header_start            // SizeOfHeaders
    .long   0                   // CheckSum
    .short  0x000A              // Subsystem: EFI_APPLICATION
    .short  0x0000              // DllCharacteristics
    .quad   0                   // SizeOfStackReserve
    .quad   0                   // SizeOfStackCommit
    .quad   0                   // SizeOfHeapReserve
    .quad   0                   // SizeOfHeapCommit
    .long   0                   // LoaderFlags (reserved, must be 0)
    .long   16                  // NumberOfRvaAndSizes

    // Data directory entries (16 × 8 bytes = 128 bytes).
    // Only entry [5] (base relocation table) is non-zero.
    .quad   0               // [0]  Export table
    .quad   0               // [1]  Import table
    .quad   0               // [2]  Resource table
    .quad   0               // [3]  Exception table
    .quad   0               // [4]  Certificate table
    // [5] Base relocation table
    .long   _reloc_start - pecoff_header_start  // VirtualAddress
    .long   _reloc_end - _reloc_start           // Size
    .quad   0               // [6]  Debug
    .quad   0               // [7]  Architecture
    .quad   0               // [8]  Global pointer
    .quad   0               // [9]  TLS table
    .quad   0               // [10] Load config table
    .quad   0               // [11] Bound import
    .quad   0               // [12] Import address table
    .quad   0               // [13] Delay import descriptor
    .quad   0               // [14] CLR runtime header
    .quad   0               // [15] Reserved

opt_hdr_end:

// ── Section headers (3 × 40 bytes) ────────────────────────────────────────────

    // .text section header — code only, read+execute only.
    .ascii  ".text\0\0\0"                           // Name (8 bytes, zero-padded)
    .long   _etext - _start                         // VirtualSize (code only)
    .long   _start - pecoff_header_start            // VirtualAddress (RVA)
    .long   _etext - _start                         // SizeOfRawData (all present in file)
    .long   _start - pecoff_header_start            // PointerToRawData (file offset)
    .long   0                                       // PointerToRelocations
    .long   0                                       // PointerToLinenumbers
    .short  0                                       // NumberOfRelocations
    .short  0                                       // NumberOfLinenumbers
    // Characteristics:
    //   IMAGE_SCN_CNT_CODE                0x20
    //   IMAGE_SCN_MEM_EXECUTE             0x20000000
    //   IMAGE_SCN_MEM_READ                0x40000000
    .long   0x60000020

    // .data section header — .rodata/.data.rel.ro, reloc metadata, .got, .data,
    // .bss; read+write so the entry self-relocation loop can write reloc targets.
    // llvm-objcopy -O binary zero-fills ALLOC/NOBITS regions (.bss), so the
    // flat binary contains bytes for the entire [_etext, _ebss) range.
    // Using SizeOfRawData = _ebss - _etext (page-aligned, always non-zero) avoids
    // EFI_INVALID_PARAMETER from EDK2's PE loader, which rejects SizeOfRawData=0
    // or non-FileAlignment-aligned values in non-discardable sections.
    .ascii  ".data\0\0\0"                           // Name (8 bytes, zero-padded)
    .long   _ebss - _etext                          // VirtualSize (data + bss)
    .long   _etext - pecoff_header_start            // VirtualAddress (RVA)
    .long   _ebss - _etext                          // SizeOfRawData (data + bss zero-fill, in file)
    .long   _etext - pecoff_header_start            // PointerToRawData (file offset)
    .long   0                                       // PointerToRelocations
    .long   0                                       // PointerToLinenumbers
    .short  0                                       // NumberOfRelocations
    .short  0                                       // NumberOfLinenumbers
    // Characteristics:
    //   IMAGE_SCN_CNT_INITIALIZED_DATA    0x40
    //   IMAGE_SCN_MEM_READ                0x40000000
    //   IMAGE_SCN_MEM_WRITE               0x80000000
    .long   0xC0000040

    // .reloc section header — minimal base-relocation block, discardable.
    .ascii  ".reloc\0\0"                            // Name (8 bytes, zero-padded)
    .long   _reloc_end - _reloc_start               // VirtualSize
    .long   _reloc_start - pecoff_header_start      // VirtualAddress (RVA)
    .long   _reloc_end - _reloc_start               // SizeOfRawData
    .long   _reloc_start - pecoff_header_start      // PointerToRawData (file offset)
    .long   0                                       // PointerToRelocations
    .long   0                                       // PointerToLinenumbers
    .short  0                                       // NumberOfRelocations
    .short  0                                       // NumberOfLinenumbers
    // Characteristics:
    //   IMAGE_SCN_CNT_INITIALIZED_DATA    0x40
    //   IMAGE_SCN_MEM_DISCARDABLE         0x02000000
    //   IMAGE_SCN_MEM_READ                0x40000000
    .long   0x42000040

// ── Entry trampoline ──────────────────────────────────────────────────────────
//
// Placed first in .text so it sits at AddressOfEntryPoint (RVA 0x1000).
// UEFI firmware calls this as:
//
//   EFI_STATUS EFIAPI entry(EFI_HANDLE image_handle,
//                           EFI_SYSTEM_TABLE *system_table);
//
// The RISC-V UEFI calling convention is the standard lp64d ABI:
//   a0 = image_handle, a1 = system_table
//
// efi_main is declared `extern "efiapi"` in main.rs; on RISC-V that is the
// same as the C lp64d ABI. We tail-call it so a0/a1 pass through unchanged.

    .balign 0x1000

    .section ".text.entry", "ax"
    .global _start
_start:
    // ── Static-PIE self-relocation ────────────────────────────────────────────
    //
    // UEFI loads this flat image at an arbitrary base. The bootloader is linked
    // as a position-independent executable, so absolute data pointers (slice
    // data pointers, &str, fn-ptr/vtable tables, GOT slots) are recorded as
    // R_RISCV_RELATIVE entries in .rela.dyn with addends relative to image base
    // 0. Apply them here, before any Rust code runs, using only PC-relative
    // addressing so this loop itself needs no relocation.
    //
    // a0 = image_handle, a1 = system_table — preserved for efi_main (only the
    // t0..t5 temporaries are used).
    //
    // Elf64_Rela is 24 bytes: r_offset (+0), r_info (+8), r_addend (+16).
    // R_RISCV_RELATIVE == 3 (low 32 bits of r_info; symbol index 0). Fixup:
    //   *(u64 *)(bias + r_offset) = bias + r_addend
    //
    // pecoff_header_start is linked at 0, so its runtime address == the load
    // bias.
    lla     t0, pecoff_header_start     // t0 = load bias
    lla     t1, __rela_dyn_start        // t1 = cursor
    lla     t2, __rela_dyn_end          // t2 = end
1:
    bgeu    t1, t2, 2f                  // while (cursor < end)
    ld      t3, 8(t1)                   // t3 = r_info
    slli    t4, t3, 32
    srli    t4, t4, 32                  // t4 = r_info & 0xffffffff = r_type
    li      t5, 3                       // R_RISCV_RELATIVE
    bne     t4, t5, 3f                  // skip non-RELATIVE entries defensively
    ld      t3, 0(t1)                   // t3 = r_offset
    ld      t4, 16(t1)                  // t4 = r_addend
    add     t3, t3, t0                  // t3 = bias + r_offset (target address)
    add     t4, t4, t0                  // t4 = bias + r_addend (relocated value)
    sd      t4, 0(t3)                   // store fixup
3:
    addi    t1, t1, 24                  // cursor += sizeof(Elf64_Rela)
    j       1b
2:
    // Only .rodata/.data/.got were patched (data, never instruction-fetched),
    // so no fence.i is required before transferring control.
    //
    // Tail-call into the Rust UEFI entry point.
    // `tail` is a PC-relative far jump using t1; does not save ra.
    tail    efi_main

// ── Minimal base-relocation block ─────────────────────────────────────────────
//
// The EFI loader checks for a .reloc section to confirm the image is
// relocatable and to permit loading at a non-preferred base. Firmware does not
// understand RISC-V R_RISCV_RELATIVE entries, so this PE base-relocation table
// is left empty (SizeOfBlock = 8 = header only, zero entries); the actual
// fixups are applied by the self-relocation loop in _start from .rela.dyn.
//
// BaseRelocationBlock layout:
//   uint32_t VirtualAddress   -- page RVA covered by this block
//   uint32_t SizeOfBlock      -- total byte size including this header

    .section ".reloc", "a"
    .long   0       // VirtualAddress (page 0 of image)
    .long   8       // SizeOfBlock (8 = header only, no entries)
