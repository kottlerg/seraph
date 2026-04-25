# RISC-V UEFI Boot

UEFI requires PE32+ bootloader images. LLVM's RISC-V backend has no PE/COFF output
mode, so the Seraph RISC-V bootloader uses a hand-crafted PE32+ header in assembly,
prepended to a position-independent ELF and converted to a flat binary via
`llvm-objcopy`. x86-64 uses the standard Rust PE/COFF output path.

---

## PE/COFF Workaround

LLVM's RISC-V backend produces ELF only; UEFI will not load an ELF file. The
approach (following Linux `arch/riscv/kernel/efi-header.S`):

1. Write a minimal PE32+ header in assembly describing the image structure.
2. Place this header at the start of the output image.
3. Use a custom linker script to position the header before the Rust code.
4. Convert the ELF to a flat binary with `llvm-objcopy -O binary`, producing a
   file whose byte 0 is the DOS MZ signature that UEFI expects.

---

## PE/COFF Header Layout

The header is defined in [`boot/src/arch/riscv64/header.S`](../src/arch/riscv64/header.S).
All offsets are relative to `pecoff_header_start`, which the linker places at
address 0 in the final binary (image base = 0 for an EFI application; UEFI
relocates it to a free region).

```
Offset   Size   Content
──────   ────   ───────
0x000    64     DOS MZ stub
                  0x00: e_magic = 0x5A4D ('MZ')
                  0x3C: e_lfanew = offset of PE signature (0x40)
0x040     4     PE signature = "PE\0\0"
0x044    20     COFF file header
                  Machine          = 0x5064 (IMAGE_FILE_MACHINE_RISCV64)
                  NumberOfSections = 2 (.text, .reloc)
                  TimeDateStamp    = 0 (reproducible builds)
                  SizeOfOptionalHeader = sizeof(optional header)
                  Characteristics  = 0x020E
0x058   240     PE32+ optional header
                  Magic            = 0x020B (PE32+)
                  AddressOfEntryPoint = RVA of _start (= 0x1000)
                  BaseOfCode       = RVA of _start (= 0x1000)
                  ImageBase        = 0 (UEFI relocates)
                  SectionAlignment = 0x1000 (4 KiB)
                  FileAlignment    = 0x1000 (flat binary)
                  Subsystem        = 0x000A (EFI_APPLICATION)
                  NumberOfRvaAndSizes = 16
                  Data directories: only [5] (base relocation) is non-zero
0x148    40     .text section header
                  Name             = ".text\0\0\0"
                  VirtualAddress   = RVA of _start
                  SizeOfRawData    = _etext - _start
                  PointerToRawData = offset of _start in flat binary
                  Characteristics  = 0x60000020 (code, executable, readable)
0x170    40     .reloc section header
                  Name             = ".reloc\0\0"
                  VirtualAddress   = RVA of _reloc_start
                  SizeOfRawData    = 8 (one empty block, header only)
                  Characteristics  = 0x42000040 (initialised data, discardable, readable)
0x198   ~1640   Padding to 0x1000 (page boundary)
0x1000   —      .text section: entry trampoline (_start) followed by compiled Rust code
  ...    —      .reloc section: minimal base-relocation block (8 bytes)
```

The `Characteristics` field in the COFF file header is `0x020E`:
- `IMAGE_FILE_EXECUTABLE_IMAGE` (0x0002)
- `IMAGE_FILE_LINE_NUMS_STRIPPED` (0x0004)
- `IMAGE_FILE_LOCAL_SYMS_STRIPPED` (0x0008)
- `IMAGE_FILE_DEBUG_STRIPPED` (0x0200)

---

## Entry Trampoline

The entry trampoline is placed at `_start`, which is at `RVA 0x1000` — the
`AddressOfEntryPoint` in the PE32+ optional header.

`_start` tail-calls `efi_main`. RISC-V UEFI uses the lp64d calling
convention; `a0` holds the image handle and `a1` the system table
pointer, matching the `extern "efiapi"` declaration of `efi_main` on
RISC-V. The `tail` pseudo-instruction expands to a PC-relative far jump
using a temporary register and does not save `ra`, so control passes to
`efi_main` as if UEFI had called it directly. See
[`boot/src/arch/riscv64/header.S`](../src/arch/riscv64/header.S) for the
asm.

---

## Minimal Base-Relocation Block

UEFI checks that the loaded image has a `.reloc` section before loading
it. The section must contain at least one base-relocation block. The
bootloader is compiled as a PIC ELF (no absolute addresses), so there
are no actual relocations to apply — the `.reloc` section holds a single
empty block (8 bytes: `VirtualAddress = 0`, `SizeOfBlock = 8`, zero
relocation entries). An empty block is valid per the PE/COFF
specification; its presence satisfies the UEFI loader's requirement for
a `.reloc` section without altering the image's runtime behaviour. See
[`boot/src/arch/riscv64/header.S`](../src/arch/riscv64/header.S) for the
asm.

---

## Linker Script

[`boot/linker/riscv64-uefi.ld`](../linker/riscv64-uefi.ld) controls the
layout of the flat binary. It places `.pecoff_header` at output offset
`0x0`, pins `.text` at `0x1000` (aligned to the PE32+ section
granularity) with `_start` as the first symbol, follows with the
standard `.rodata` / `.data` / `.bss` tails, emits a `.reloc` section
for UEFI to find, and discards `.eh_frame`, `.note.*`, `.comment`, and
`.gnu.*` sections that would otherwise inflate the flat binary.
`ENTRY(_start)` selects the entry symbol. The script is the
authoritative layout description — do not duplicate it here.

The key symbols exported by the linker script for use in `header.S`:

| Symbol | Meaning |
|---|---|
| `_start` | First byte of the entry trampoline; also `AddressOfEntryPoint` RVA |
| `_etext` | End of the `.text` section; used to compute `SizeOfCode` |
| `_reloc_start` | Start of the `.reloc` section; base-relocation VirtualAddress |
| `_reloc_end` | End of the `.reloc` section |
| `_image_end` | End of the entire image; used for `SizeOfImage` |
| `pecoff_header_start` | Byte 0 of the image; all RVAs are relative to this symbol |

---

## Custom Target JSON

The RISC-V bootloader uses a custom Cargo target specification,
`targets/riscv64gc-seraph-uefi.json`. Key differences from the kernel target
(`riscv64gc-seraph-none.json`):

| Field | UEFI bootloader | Kernel |
|---|---|---|
| `os` | `"uefi"` | `"none"` |
| `llvm-target` | `"riscv64"` | `"riscv64"` |
| `relocation-model` | `"pic"` | `"static"` |
| `code-model` | `"medium"` | `"medium"` |
| `disable-redzone` | `true` | `true` |
| `features` | `"+m,+a,+f,+d,+c"` (RV64GC) | `"+m,+a,+f,+d,+c"` |
| `linker` | `"rust-lld"` | `"rust-lld"` |
| `linker-flavor` | `"ld.lld"` | `"ld.lld"` |
| `pre-link-args` | custom linker script | custom linker script |

The `relocation-model: "pic"` setting is critical — it instructs LLVM to emit PIC
code (PC-relative addressing, no absolute symbols). This is required because UEFI
loads the image at an arbitrary address chosen at runtime; the assembled flat binary
must be position-independent.

---

## Build Pipeline

The RISC-V UEFI image is produced by `cargo xtask build --arch riscv64`.
Internally the pipeline runs in three steps:

1. The bootloader crate is compiled against `riscv64gc-seraph-uefi`,
   producing an ELF that contains the `.pecoff_header` section (assembled
   from `header.S`) at load address `0x0`, followed by `.text` at `0x1000`.
2. `llvm-objcopy -O binary` strips all ELF structure and emits only the
   section data in load-address order. Byte 0 of the output is the MZ
   signature from `.pecoff_header`; byte `0x1000` is the entry trampoline.
3. The resulting `seraph-boot.efi` is staged to `\EFI\seraph\` on the ESP.

The intermediate ELF is not a usable UEFI image — UEFI does not
understand ELF headers — but it shares a symbol table with the flat
binary, so GDB / LLDB can set symbolic breakpoints against the ELF even
though UEFI loads the flat binary. See [xtask/README.md](../../../xtask/README.md)
for the authoritative command surface; the steps above are descriptive,
not a manual recipe.

---

## Maintenance Notes

### Obsolescence Path

If LLVM gains a RISC-V PE/COFF backend in a future release, the entire workaround
in this document becomes unnecessary. The RISC-V bootloader could use a standard
`riscv64-unknown-uefi` target (or equivalent Seraph custom target without `pic`
relocation model), and `header.S`, `riscv64-uefi.ld`, and this document could be
removed. Monitoring LLVM release notes for RISC-V PE/COFF backend support is
recommended.

### Validation Against UEFI Specification

The PE32+ header must conform to:
- UEFI Specification §2.1.1 — PE32+ image format requirements for EFI applications
- Microsoft PE/COFF Specification §3 (COFF file header), §4 (optional header),
  §5 (section table), §6 (base relocations)

Changes to the header structure (field values, section count, data directory entries)
must be validated against both specifications. In particular:
- `SizeOfImage` must be the exact byte size of the loaded image rounded up to
  `SectionAlignment`, not the flat file size
- `NumberOfRvaAndSizes` must match the number of data directory entries written
- The `.reloc` section's `VirtualAddress` in the data directory must match the
  section header's `VirtualAddress`

### Linux Kernel Reference

The design of `header.S` follows the approach in
`arch/riscv/kernel/efi-header.S` in the Linux kernel. That file documents the same
technique and has been validated against UEFI firmware implementations on production
RISC-V hardware. Divergences between the Linux kernel's header and the Seraph header
should be understood and documented; do not assume the Linux version is always correct
for Seraph's specific binary layout.

---

## Summarized By

[boot/README.md](../README.md)
