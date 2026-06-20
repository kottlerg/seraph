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
                  NumberOfSections = 3 (.text, .data, .reloc)
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
0x170    40     .data section header
                  Name             = ".data\0\0\0"
                  VirtualAddress   = RVA of _etext
                  SizeOfRawData    = _ebss - _etext
                  Characteristics  = 0xC0000040 (initialised data, readable, writable)
0x198    40     .reloc section header
                  Name             = ".reloc\0\0"
                  VirtualAddress   = RVA of _reloc_start
                  SizeOfRawData    = 8 (one empty block, header only)
                  Characteristics  = 0x42000040 (initialised data, discardable, readable)
0x1C0   ~1600   Padding to 0x1000 (page boundary)
0x1000   —      .text section: entry trampoline (_start) + compiled Rust code
                  only (RX); ends at the _etext page boundary
  ...    —      .data section: .rodata / .data.rel.ro, the .dynamic / .rela.dyn
                  relocation metadata, .got, initialised data, .bss zero-fill
                  (RW — the self-relocation loop writes the reloc targets here)
  ...    —      .reloc section: empty PE base-relocation block (8 bytes)
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

## Relocation: static-PIE self-relocation

The bootloader is linked as a position-independent executable (`-pie`).
Position-independence makes *code* references PC-relative, but absolute
*data* pointers — slice data pointers, `&str`, fn-pointer / vtable tables,
`core::fmt` infrastructure, and any GOT slots — are recorded as
`R_RISCV_RELATIVE` dynamic relocations in `.rela.dyn`, each with an addend
relative to image base 0. They must be fixed up by adding the runtime load
bias, or dereferencing them faults at a low link-time address (the failure
mode that motivated this design; see issue #399).

UEFI firmware does not understand RISC-V `R_RISCV_RELATIVE` entries, so the
bootloader applies them itself. The entry trampoline at `_start` runs a
PC-relative-only assembly loop *before any Rust code executes*: it computes
the load bias from `lla pecoff_header_start` (linked at 0, so its runtime
address is the bias), walks the `Elf64_Rela` array between
`__rela_dyn_start` and `__rela_dyn_end`, and for each `R_RISCV_RELATIVE`
entry writes `*(bias + r_offset) = bias + r_addend`. The loop touches only
data (`.rodata`/`.data.rel.ro`/`.got`), never instructions, so no `fence.i`
is needed. The relocation *targets* live in `.rodata` / `.data.rel.ro` /
`.got`, which the linker script places in the **writable** PE `.data`
section range (`[_etext, _ebss)`); EDK2 maps the RX `.text` section
read-only, so the loop could not store fixups if those targets stayed
there. `.rela.dyn` and `.dynamic` share that `.data` range, so UEFI maps
them without a dedicated PE section header.

The PE `.reloc` section is retained but left as a single empty block
(8 bytes: `VirtualAddress = 0`, `SizeOfBlock = 8`, zero entries). UEFI
checks for a `.reloc` section before loading an image at a non-preferred
base; an empty block satisfies that check (valid per the PE/COFF
specification) while the real fixups are applied by the self-relocation
loop. See [`boot/src/arch/riscv64/header.S`](../src/arch/riscv64/header.S)
for the asm.

---

## Linker Script

[`boot/linker/riscv64-uefi.ld`](../linker/riscv64-uefi.ld) controls the
layout of the flat binary. It places `.pecoff_header` at output offset
`0x0`, pins `.text` at `0x1000` (aligned to the PE32+ section
granularity) with `_start` as the first symbol and **code only**, then
sets `_etext` at the next page boundary (end of the RX `.text` PE
section). Everything after `_etext` is in the **writable** `.data` PE
section: `.rodata` / `.data.rel.ro` (relocation targets), the `.dynamic`
/ `.rela.dyn` metadata, `.got`, then the `.data` / `.bss` tails. They are
placed after `_etext` precisely so EDK2 maps them RW and the
self-relocation loop can write the fixups. The script emits the empty
`.reloc` section for UEFI to find, and discards `.eh_frame`, `.note.*`,
`.comment`, and the dynamic-linking metadata (`.interp` / `.dynsym` /
`.dynstr` / hash tables) that a self-relocating static-PIE never consults
at runtime. `ENTRY(_start)` selects the entry symbol. The script is the
authoritative layout description — do not duplicate it here.

The key symbols exported by the linker script for use in `header.S`:

| Symbol | Meaning |
|---|---|
| `_start` | First byte of the entry trampoline; also `AddressOfEntryPoint` RVA |
| `_etext` | End of the `.text` section; used to compute `SizeOfCode` |
| `__rela_dyn_start` / `__rela_dyn_end` | Bound the `.rela.dyn` array walked by the self-relocation loop |
| `_reloc_start` | Start of the `.reloc` section; base-relocation VirtualAddress |
| `_reloc_end` | End of the `.reloc` section |
| `_image_end` | End of the entire image; used for `SizeOfImage` |
| `pecoff_header_start` | Byte 0 of the image; runtime address equals the load bias |

---

## Custom Target JSON

The RISC-V bootloader uses a custom Cargo target specification,
`targets/riscv64imac-seraph-uefi.json`. Key differences from the kernel target
(`riscv64imac-seraph-none.json`):

| Field | UEFI bootloader | Kernel |
|---|---|---|
| `os` | `"uefi"` | `"none"` |
| `llvm-target` | `"riscv64"` | `"riscv64"` |
| `relocation-model` | `"pic"` | `"static"` |
| `code-model` | `"medium"` | `"medium"` |
| `disable-redzone` | `true` | `true` |
| `features` | `"+m,+a,+c"` (RV64IMAC) | `"+m,+a,+c"` (RV64IMAC) |
| `linker` | `"rust-lld"` | `"rust-lld"` |
| `linker-flavor` | `"ld.lld"` | `"ld.lld"` |
| `pre-link-args` | custom linker script | custom linker script |

The `relocation-model: "pic"` setting (with `-pie`,
`position-independent-executables`, and `static-position-independent-executables`)
is critical. It makes code PC-relative and, crucially, causes absolute *data*
pointers to be emitted as `R_RISCV_RELATIVE` entries in `.rela.dyn` rather than
baked-in link-time constants. This is required because UEFI loads the image at an
arbitrary address chosen at runtime; the self-relocation loop in `header.S` then
applies those relocations at entry (see "Relocation: static-PIE self-relocation").
`-Bsymbolic` and `--no-dynamic-linker` keep `.rela.dyn` free of symbolic entries
so every relocation is a base-relative `R_RISCV_RELATIVE`.

---

## Build Pipeline

The RISC-V UEFI image is produced by `cargo xtask build --arch riscv64`.
Internally the pipeline runs in three steps:

1. The bootloader crate is compiled against `riscv64imac-seraph-uefi`,
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
