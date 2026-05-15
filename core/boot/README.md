# boot

UEFI bootloader for Seraph. Reads boot configuration from `\EFI\seraph\boot.conf`,
loads the kernel ELF and boot modules, parses init's ELF into `InitImage`, establishes
initial page tables with W^X enforcement, discovers firmware table addresses (ACPI
RSDP / Device Tree blob) for passthrough to userspace, and jumps to the kernel entry
point.

The boot protocol contract — `BootInfo` layout, `BOOT_PROTOCOL_VERSION`,
`KernelMmio` / `MmioAperture` shape, and the compliant-bootloader
requirements — is owned by the
[`abi/boot-protocol/`](../../abi/boot-protocol/) crate.
The CPU state and register contents at the kernel entry point are
documented in [docs/kernel-handoff.md](docs/kernel-handoff.md).

---

## Source Layout

```
boot/
├── Cargo.toml                  # seraph-boot crate (UEFI application)
├── linker/
│   └── riscv64-uefi.ld         # Linker script for RISC-V PE/COFF pipeline
└── src/
    ├── main.rs                 # efi_main — boot sequence orchestrator
    ├── config.rs               # Boot configuration file parser (boot.conf)
    ├── uefi.rs                 # UEFI protocol wrappers and memory services
    ├── elf.rs                  # UEFI-allocation layer over `shared/elf` + InitImage construction
    ├── firmware.rs             # ACPI / Device Tree address discovery (dispatch)
    ├── acpi.rs                 # ACPI RSDP/XSDT/MADT/MCFG walker (CPU topology, kernel_mmio, aperture seeds)
    ├── dtb.rs                  # Flat Device Tree walker (CPU topology, kernel_mmio, aperture seeds)
    ├── memory_map.rs           # UEFI memory map → boot_protocol::MemoryType + mmio_apertures derivation
    ├── framebuffer.rs          # GOP framebuffer setup
    ├── console.rs              # Early framebuffer console (uses shared/font)
    ├── paging.rs               # Initial page table construction (arch-neutral)
    ├── error.rs                # Bootloader error type
    └── arch/
        ├── mod.rs              # Re-exports the active arch module
        ├── x86_64/
        │   ├── mod.rs          # x86-64 arch re-exports
        │   ├── paging.rs       # x86-64 4-level page table implementation
        │   ├── handoff.rs      # CR3 write + kernel jump
        │   └── serial.rs       # 16550 serial output for early debug
        └── riscv64/
            ├── mod.rs          # RISC-V arch re-exports
            ├── paging.rs       # RISC-V Sv48 page table implementation
            ├── handoff.rs      # satp write + sfence + kernel jump
            ├── serial.rs       # UART serial output for early debug
            └── header.S        # Hand-crafted PE32+ header and entry trampoline
```

---

## Crate Structure

**`boot-protocol`** (`abi/boot-protocol/`) — a `no_std` crate with no dependencies.
Defines `BootInfo` and all associated types as a stable `#[repr(C)]` interface shared
between the bootloader and the kernel. Also exports the `BOOT_PROTOCOL_VERSION`
constant. Neither crate links to the other; both depend on `boot-protocol` as a
workspace member.

**`seraph-boot`** (`boot/`) — the UEFI application. Depends on `boot-protocol` for the
`BootInfo` type it populates. Architecture-specific code is isolated to `arch/<target>/`;
`#[cfg(target_arch)]` appears only at the arch-module declaration site in
`arch/mod.rs`. Each shared module dispatches to the active arch implementation via
the re-exports in `arch/mod.rs`.

`shared/elf/` is the workspace's authoritative ELF format decoder
(header validation, `PT_LOAD` segment iteration, entry point, TLS).
`boot/src/elf.rs` is a thin UEFI-allocation layer over it: for the kernel
image it allocates each `PT_LOAD` segment at the ELF-declared `p_paddr`
via `AllocatePages(AllocateAddress, …)`; for the init image it allocates
at any available address while preserving the in-page byte offset of
`p_vaddr`, then constructs the `BootInfo.init_image` ABI surface so the
kernel never needs an ELF parser. Boot modules are loaded as opaque flat
binaries with no parsing.

W^X policy is enforced by the bootloader's page-table builder
(`boot/src/paging.rs` and `boot/src/arch/*/paging.rs`); a `PT_LOAD`
segment with both `PF_W` and `PF_X` is rejected when its first page is
mapped, surfaced as `BootError::WxViolation`. ELF format errors arrive
in boot as `elf::ElfError` and bridge to `BootError::InvalidElf` via the
`From` impl in `error.rs`.

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
hand-crafted header prepended. See [docs/riscv-uefi-boot.md](docs/riscv-uefi-boot.md)
for details.

---

## Documentation

| Document | Content |
|---|---|
| [docs/kernel-handoff.md](docs/kernel-handoff.md) | Kernel entry contract: CPU state, register contents, handoff sequence |
| [docs/boot-flow.md](docs/boot-flow.md) | Ten-step boot sequence, `BootInfo` population, kernel handoff |
| [docs/uefi-environment.md](docs/uefi-environment.md) | UEFI protocols, memory allocation, `ExitBootServices`, error handling |
| [docs/elf-loading.md](docs/elf-loading.md) | ELF validation, LOAD segment processing, boot module loading |
| [docs/firmware-parsing.md](docs/firmware-parsing.md) | ACPI and Device Tree extractors: kernel-facing MMIO bases and coarse MMIO apertures |
| [docs/acpi.md](docs/acpi.md) | ACPI table-walk invariants (RSDP/XSDT/MADT/MCFG) |
| [docs/dtb.md](docs/dtb.md) | Flat Device Tree walk invariants (header validation, compatible matching) |
| [docs/memory-map.md](docs/memory-map.md) | UEFI memory map → `BootInfo.memory_map` translation policy |
| [docs/console.md](docs/console.md) | Early console (serial + framebuffer): backend discovery, glyph rendering, handoff |
| [docs/page-tables.md](docs/page-tables.md) | Initial page table construction for x86-64 and RISC-V |
| [docs/riscv-uefi-boot.md](docs/riscv-uefi-boot.md) | RISC-V PE/COFF workaround: header, linker script, build pipeline |

---

## Entry Point

`efi_main` in `src/main.rs` is the UEFI application entry point, declared
`extern "efiapi"`. UEFI firmware calls it with `(image_handle, system_table)` after
loading and relocating the image. It does not return; the final act is a one-way jump
to `kernel_entry` in the kernel binary.

The CPU state established at the kernel entry point is specified in
[docs/kernel-handoff.md](docs/kernel-handoff.md).

---

## What the Bootloader Does Not Do

- **No UEFI runtime services.** UEFI is fully exited before the kernel runs.
- **Narrow firmware extraction only.** The bootloader records the ACPI RSDP
  and Device Tree blob addresses in `BootInfo` so userspace can re-parse
  them, extracts the arch-specific MMIO bases the kernel itself needs
  (`BootInfo.kernel_mmio`), and derives a short list of coarse MMIO
  apertures (`BootInfo.mmio_apertures`) from the UEFI memory map unioned
  with firmware-advertised PCI windows. No per-device descriptors, no
  IRQ descriptors, no PCI enumeration. Namespace evaluation and
  device-level assignment are userspace's responsibility.
- **No boot menu or interactive UI.** File paths come from `boot.conf`; the kernel
  command line is an opaque string passed through to `BootInfo`.
- **No permanent page tables.** The initial tables are minimal and temporary; the
  kernel replaces them during Phase 3 of its initialisation sequence.

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

None
