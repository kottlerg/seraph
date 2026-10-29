# abi/boot-protocol

Binary boot protocol contract between the bootloader and the kernel.

---

## Overview

Defines `BootInfo` and all associated types passed from the bootloader to the
kernel entry point. Includes the `BOOT_PROTOCOL_VERSION` constant; the kernel
halts at entry if the bootloader's version does not match (see
[core/kernel/docs/initialization.md](../../core/kernel/docs/initialization.md)
§ Phase 0: Entry Validation).

**Constraints:** `no_std`, `#[repr(C)]` for every struct and `#[repr(u32)]` for every
enum `BootInfo` carries, no dependencies outside `core`. Changes that alter `BootInfo`
layout or the CPU entry contract MUST increment `BOOT_PROTOCOL_VERSION`.

The crate source under `src/` is the authoritative specification — `lib.rs` for
the `BootInfo` layout and the sibling modules for the bundle, layout-arithmetic, paging, and
GUID contracts (see Source Layout); type fields, discriminants, doc-comment invariants, and
version-history rationale all live there, not duplicated in markdown.
Beyond the crate's structure, this README covers only what the source cannot: the
third-party-bootloader policy and the high-level responsibilities required of any
compliant bootloader.

What each bootloader step establishes, and the sequence of steps the
reference bootloader takes, is documented at the component level in
[`core/boot/docs/`](../../core/boot/docs/) — particularly
[`core/boot/docs/kernel-handoff.md`](../../core/boot/docs/kernel-handoff.md) for the
CPU-state contract at entry, and
[`core/boot/docs/boot-flow.md`](../../core/boot/docs/boot-flow.md) for the ten-step
sequence.

---

## Compliant Bootloader

The Seraph bootloader in [`core/boot/`](../../core/boot/README.md) is the **reference
implementation**. Any compliant bootloader that satisfies the contract
defined by this crate — the `BootInfo` layout, the
`BOOT_PROTOCOL_VERSION` check, and the CPU/memory state at kernel entry
— MAY be used in its place. The kernel has no knowledge of the specific
bootloader that produced a `BootInfo`; only the contract matters.

### Contract for a compliant bootloader

A compliant bootloader MUST, before jumping to the kernel entry point:

- Verify the kernel ELF is valid and has a recognisable entry point.
- Load all ELF LOAD segments into allocated physical memory; on x86-64, wholly
  below 4 GiB (`BootInfo.kernel_physical_base` in [`src/lib.rs`](src/lib.rs)).
- Zero BSS segments.
- Respect ELF segment permissions (readable, writable, executable) when
  establishing initial page table entries; never map any region as both
  writable and executable (W^X; see
  [docs/memory-model.md](../../docs/memory-model.md) § W^X Enforcement).
- Obtain the final UEFI memory map after all allocations are complete.
- Call `ExitBootServices` successfully before jumping to the kernel.
- Populate every field of `BootInfo` per the per-field semantics in
  [`src/lib.rs`](src/lib.rs).
- Set `BootInfo.version = BOOT_PROTOCOL_VERSION` at the version defined
  by the crate the kernel was built against.
- Guarantee that the `BootInfo` structure and all referenced data
  remain mapped and readable at kernel entry.
- Establish the CPU state documented in
  [`core/boot/docs/kernel-handoff.md`](../../core/boot/docs/kernel-handoff.md)
  for the target architecture.

A compliant bootloader MUST NOT:

- Leave UEFI boot services active at kernel entry.
- Assume anything about the kernel's internal layout beyond the ELF
  headers.
- Include in `BootInfo.mmio_apertures` any region that is inaccessible,
  RAM (a region the memory map classifies as `Usable`, `Loaded`,
  `AcpiReclaimable`, or `Persistent`), or reserved for firmware's exclusive
  use: UEFI runtime-services code and data, ACPI NVS, and firmware-reserved
  memory that no naming source names as a device's registers or frame buffer.
  The naming sources are a firmware table, the device tree, the framebuffer,
  and a register window the bootloader fixes for a platform it identifies (a
  UART, RTC, or ECAM window at a platform-defined address). A region firmware
  reports as reserved MAY be included where a naming source names it (the GOP
  framebuffer, an interrupt controller, an ECAM window). A PCI window placed by
  a layout heuristic rather than named by such a source MUST exclude every
  range the memory map describes other than MMIO. The reference bootloader's rule is
  [core/boot/docs/firmware-parsing.md](../../core/boot/docs/firmware-parsing.md)
  § Firmware exclusion. The kernel rejects an aperture that intersects RAM at
  Phase 6
  ([core/kernel/docs/initialization.md](../../core/kernel/docs/initialization.md)
  § Phase 6).

---

## Source Layout

```
boot-protocol/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs           # BootInfo and its types, BOOT_PROTOCOL_VERSION, MAX_CPUS, the
    │                    #   KernelMmio and HART_CAP_* facts, KASLR_* flags
    ├── bundle.rs        # bootstrap.bundle wire format (header, entries, INIT_ENTRY_NAME)
    ├── layout.rs        # direct-map layout arithmetic both bootloader and kernel use
    ├── riscv_paging.rs  # RISC-V paging-mode constants and satp encoding
    └── role_guids.rs    # GPT partition type GUIDs for role-based discovery
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [core/boot/docs/kernel-handoff.md](../../core/boot/docs/kernel-handoff.md) | CPU and memory state at kernel entry |
| [core/boot/docs/boot-flow.md](../../core/boot/docs/boot-flow.md) | Reference bootloader's steps, including `BootInfo` population |
| [core/kernel/docs/initialization.md](../../core/kernel/docs/initialization.md) | Phase 0 entry validation of `BootInfo` |
| [docs/bootstrap.md](../../docs/bootstrap.md) | Boot lifecycle: the bootloader loading the bundle `bundle.rs` encodes and handing over `BootInfo` |
| [docs/memory-model.md](../../docs/memory-model.md) | Kernel virtual layout (direct map, KASLR), W^X enforcement, boot-time memory map |
| [docs/storage.md](../../docs/storage.md) | GPT role-GUID discovery, whose partition type GUIDs `role_guids.rs` defines |

---

## Summarized By

[core/boot/README.md](../../core/boot/README.md),
[Boot Flow](../../core/boot/docs/boot-flow.md),
[Firmware Parsing](../../core/boot/docs/firmware-parsing.md),
[Kernel Handoff Contract](../../core/boot/docs/kernel-handoff.md),
[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md),
[Build System](../../docs/build-system.md), [Memory Model](../../docs/memory-model.md)
