# boot

UEFI bootloader for Seraph. Loads the kernel ELF and the
`\EFI\seraph\bootstrap.bundle` (init plus boot modules) from hardcoded ESP paths,
parses init's ELF into `InitImage`, establishes
initial page tables with W^X enforcement, discovers firmware table addresses (ACPI
RSDP / Device Tree blob) for passthrough to userspace, and jumps to the kernel entry
point. The full sequence is in [core/boot/docs/boot-flow.md](docs/boot-flow.md).

The boot protocol contract — `BootInfo` layout, `BOOT_PROTOCOL_VERSION`,
`KernelMmio` / `MmioAperture` shape, and the compliant-bootloader
requirements — is owned by the
[`abi/boot-protocol/`](../../abi/boot-protocol/) crate.
The CPU state and register contents at the kernel entry point are
documented in [core/boot/docs/kernel-handoff.md](docs/kernel-handoff.md).

---

## Source Layout

```
core/boot/
├── Cargo.toml                  # boot crate (UEFI application)
├── linker/
│   └── riscv64-uefi.ld         # Linker script for RISC-V PE/COFF pipeline
└── src/
    ├── main.rs                 # efi_main — boot sequence orchestrator
    ├── uefi.rs                 # UEFI protocol wrappers and memory services
    ├── elf.rs                  # UEFI-allocation layer over `shared/elf` + InitImage construction
    ├── firmware.rs             # ACPI RSDP / DTB address discovery (UEFI config table)
    ├── acpi.rs                 # ACPI walker (CPUs, hart caps, apertures, VMGENID)
    ├── dtb.rs                  # DTB walker (CPUs, hart caps, mmu-type, apertures, rng-seed)
    ├── memory_map.rs           # UEFI memory map → MemoryType; mmio_apertures derivation
    ├── framebuffer.rs          # Framebuffer text renderer (uses shared/font)
    ├── console.rs              # Early console: dual serial + framebuffer writer
    ├── paging.rs               # Initial page table construction (arch-neutral)
    ├── error.rs                # Bootloader error type
    └── arch/
        ├── mod.rs              # Re-exports the active arch module
        ├── x86_64/
        │   ├── mod.rs              # x86-64 arch-dispatch surface (hooks + re-exports)
        │   ├── paging.rs           # x86-64 4-level page table implementation
        │   ├── handoff.rs          # CR3 write + kernel jump
        │   ├── serial.rs           # 16550 serial output for early debug
        │   └── acpi_kernel_mmio.rs # ACPI MADT kernel_mmio extraction
        └── riscv64/
            ├── mod.rs              # RISC-V arch-dispatch surface (hooks + re-exports)
            ├── paging.rs           # RISC-V page tables + paging-mode negotiation
            ├── handoff.rs          # satp write + sfence + kernel jump
            ├── serial.rs           # UART serial output for early debug
            ├── acpi_kernel_mmio.rs # ACPI MADT/RHCT kernel_mmio extraction
            ├── acpi_spcr.rs        # ACPI SPCR UART discovery
            ├── dtb_kernel_mmio.rs  # DTB kernel_mmio fill-in
            └── header.S            # Hand-crafted PE32+ header and entry trampoline
```

---

## Crate Structure

**`boot-protocol`** (`abi/boot-protocol/`) — a `no_std` crate with no dependencies.
Defines `BootInfo` and all associated types as a stable `#[repr(C)]` interface shared
between the bootloader and the kernel. Also exports the `BOOT_PROTOCOL_VERSION`
constant. Neither crate links to the other; both depend on `boot-protocol` as a
workspace member. The contract is specified in
[abi/boot-protocol/README.md](../../abi/boot-protocol/README.md).

**`boot`** (`core/boot/`) — the UEFI application. Depends on `boot-protocol` for the
`BootInfo` type it populates. Architecture-specific code is isolated to
`core/boot/src/arch/<target>/`;
`#[cfg(target_arch)]` appears only at the arch-module declaration site in
`core/boot/src/arch/mod.rs`, per [docs/coding-standards.md](../../docs/coding-standards.md)
§ C. Architecture Invariants. Each shared module dispatches to the active arch implementation via
the re-exports in `core/boot/src/arch/mod.rs`.

[`shared/elf/`](../../shared/elf/README.md) is the workspace's authoritative ELF format decoder
(header validation, `PT_LOAD` segment enumeration, entry point, `PT_TLS` and stack-note
extraction, load-span computation, and `RELATIVE` relocation support).
`core/boot/src/elf.rs` is a thin UEFI-allocation layer over it: for the kernel
image it allocates one contiguous span at any available physical base via
`AllocatePages(AllocateAnyPages, …)` and places each `PT_LOAD` segment at
its ELF-relative offset within the span, so kernel placement tolerates any
firmware memory layout; for the init image it allocates at any available
address while preserving the in-page byte offset of `p_vaddr`, then
constructs the `BootInfo.init_image` ABI surface so the kernel never needs
an ELF parser. Boot modules are loaded as opaque flat binaries with no
parsing. Both loading paths are specified in [core/boot/docs/elf-loading.md](docs/elf-loading.md).

W^X is enforced for both images; where each segment kind is rejected is in
[core/boot/docs/elf-loading.md](docs/elf-loading.md) § LOAD Segment Processing. ELF format
errors arrive in boot as `elf::ElfError` and bridge to `BootError::InvalidElf` via
the `From` impl in `core/boot/src/error.rs`.

---

## Build

The bootloader is built as part of the Seraph workspace. Refer to
[xtask/README.md](../../xtask/README.md) for the full build procedure. Key points:

| Architecture | Target triple | Output |
|---|---|---|
| x86-64 | `x86_64-unknown-uefi` | `.efi` (PE/COFF, direct from linker) |
| RISC-V | `riscv64imac-seraph-uefi` | `.efi` (flat binary via `llvm-objcopy`) |

On x86-64, the Rust toolchain emits a PE/COFF `.efi` directly. On RISC-V, LLVM has
no PE/COFF backend, so the output ELF is converted to a flat binary with a
hand-crafted header prepended. See [core/boot/docs/riscv-uefi-boot.md](docs/riscv-uefi-boot.md)
for details.

---

## Documentation

| Document | Content |
|---|---|
| [core/boot/docs/kernel-handoff.md](docs/kernel-handoff.md) | Kernel entry contract: CPU state, register contents, handoff sequence |
| [core/boot/docs/boot-flow.md](docs/boot-flow.md) | Ten-step boot sequence, `BootInfo` population, kernel handoff |
| [core/boot/docs/uefi-environment.md](docs/uefi-environment.md) | UEFI protocols, memory allocation, `ExitBootServices`, error handling |
| [core/boot/docs/elf-loading.md](docs/elf-loading.md) | ELF validation, LOAD segment processing, boot module loading |
| [core/boot/docs/firmware-parsing.md](docs/firmware-parsing.md) | ACPI and Device Tree extractors: CPU topology, kernel-facing MMIO bases, coarse MMIO apertures, the DTB rng-seed fallback, and the VMGENID GUID address |
| [core/boot/docs/acpi.md](docs/acpi.md) | ACPI table-walk invariants (RSDP, XSDT, MADT, MCFG, SPCR, RHCT, SSDT) |
| [core/boot/docs/dtb.md](docs/dtb.md) | Flat Device Tree walk invariants (header validation, compatible matching, rng-seed extraction and scrub) |
| [core/boot/docs/memory-map.md](docs/memory-map.md) | UEFI memory map → `BootInfo.memory_map` translation policy |
| [core/boot/docs/console.md](docs/console.md) | Early console (serial + framebuffer): backend discovery, glyph rendering, handoff |
| [core/boot/docs/page-tables.md](docs/page-tables.md) | Initial page table construction for x86-64 and RISC-V |
| [core/boot/docs/riscv-uefi-boot.md](docs/riscv-uefi-boot.md) | RISC-V PE/COFF workaround: header, linker script, build pipeline |

---

## Entry Point

`efi_main` in `core/boot/src/main.rs` is the Rust UEFI entry point, declared
`extern "efiapi"`. On x86-64, UEFI firmware calls it directly with
`(image_handle, system_table)` after loading and relocating the image. On RISC-V, firmware
enters the `_start` trampoline in `core/boot/src/arch/riscv64/header.S`, which applies the
image's `R_RISCV_RELATIVE` relocations itself and tail-calls `efi_main` with the same
arguments ([core/boot/docs/riscv-uefi-boot.md](docs/riscv-uefi-boot.md) § Relocation:
static-PIE self-relocation). It does not return; the final act is a one-way jump
to `kernel_entry` in the kernel binary. The steps between entry and that jump are in
[core/boot/docs/boot-flow.md](docs/boot-flow.md).

The CPU state established at the kernel entry point is specified in
[core/boot/docs/kernel-handoff.md](docs/kernel-handoff.md).

---

## What the Bootloader Does Not Do

- **No UEFI runtime services.** UEFI boot services are exited before the kernel runs,
  and Seraph makes no runtime-services calls
  ([core/boot/docs/uefi-environment.md](docs/uefi-environment.md) § ExitBootServices).
- **Narrow firmware extraction only.** The bootloader records the ACPI RSDP
  and Device Tree blob addresses in `BootInfo` so userspace can re-parse
  them, and extracts only the CPU topology (`cpu_count` / `bsp_id` / `cpu_ids`), the
  arch-specific MMIO bases and riscv64 hart facts the kernel itself needs
  (`BootInfo.kernel_mmio`), a short list of coarse MMIO apertures
  (`BootInfo.mmio_apertures`) derived from the UEFI memory map's MMIO ranges unioned with
  firmware-table seeds (interrupt-controller, UART, ECAM, PCI BAR, and `virtio,mmio`
  windows) and the GOP framebuffer, the DTB `/chosen/rng-seed` entropy fallback, and the
  VMGENID GUID address. No per-device descriptors, no
  IRQ descriptors, no PCI enumeration. Namespace evaluation and
  device-level assignment are userspace's responsibility. Extraction scope is in
  [core/boot/docs/firmware-parsing.md](docs/firmware-parsing.md).
- **No boot menu or interactive UI.** The kernel, bundle, and `nokaslr` knob
  ESP paths are hardcoded and are the only files the bootloader opens, so
  there is no boot configuration file beyond the presence-only knob
  ([core/boot/docs/elf-loading.md](docs/elf-loading.md) § File Paths). There is no
  kernel command line: `BootInfo` carries no command-line field
  ([abi/boot-protocol/src/lib.rs](../../abi/boot-protocol/src/lib.rs)).
- **No permanent page tables.** The initial tables are minimal and temporary; the
  kernel replaces them during
  [Phase 3](../kernel/docs/initialization.md#phase-3-kernel-page-tables) of its
  initialisation sequence
  ([core/boot/docs/page-tables.md](docs/page-tables.md)).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System-wide design philosophy and microkernel boundary |
| [docs/memory-model.md](../../docs/memory-model.md) | Virtual address space layout the bootloader must establish |
| [docs/capability-model.md](../../docs/capability-model.md) | Initial capabilities minted from `mmio_apertures` and memory-map regions |
| [docs/device-management.md](../../docs/device-management.md) | How `devmgr` uses the resources the bootloader provides |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

[core/ktest/README.md](../ktest/README.md), [rootfs/README.md](../../rootfs/README.md)
