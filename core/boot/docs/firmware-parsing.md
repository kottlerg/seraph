# Firmware Parsing

The bootloader performs narrow, targeted firmware parsing to populate
five parts of `BootInfo`:

1. `cpu_count` / `bsp_id` / `cpu_ids` — the CPU topology handed to the
   kernel for SMP bring-up.
2. `kernel_mmio` — the arch-specific MMIO register bases the kernel
   itself consumes (LAPIC / IOAPIC on x86-64 via ACPI MADT; PLIC / UART
   on RISC-V via ACPI MADT + SPCR, with any fields left zero by ACPI
   filled from the DTB; see [acpi.md](acpi.md)), plus the riscv64 hart
   facts carried in the same struct (`timebase_freq`, `hart_caps`). Not a
   capability surface, except on RISC-V, where the kernel mints one
   additional `Mmio` capability over the console UART range (`uart_base` /
   `uart_size`). That range can also lie inside an aperture: the ACPI
   seeder's arch defaults (`default_mmio_apertures`) cover the QEMU virt UART
   page, and the DTB seeder adds any `ns16550a` node's first `reg` entry (see
   [docs/capability-model.md](../../../docs/capability-model.md#initial-capability-distribution)).
3. `mmio_apertures` — firmware parsing contributes coarse `{phys_base, size}`
   MMIO seed regions, which are merged with the UEFI memory map's MMIO
   classifications into the final aperture list this field carries (see
   [`mmio_apertures` construction](#mmio_apertures-construction)). The kernel mints
   one `Mmio` capability per aperture entry its Phase 6 validates (see
   [initialization.md](../../kernel/docs/initialization.md#phase-7-capability-system)).
4. `boot_entropy_seed` / `boot_entropy_len` — the DTB `/chosen/rng-seed`
   fallback, consulted only when `EFI_RNG_PROTOCOL` yields no seed
   (DTB-only; see [boot-flow.md](boot-flow.md) step 5c).
5. `vmgenid_paddr` — the VM Generation ID GUID address from the QEMU
   VMGENID SSDT scan, run wherever an RSDP is present (only x86-64 QEMU
   wires the device today); zero when absent.

The bootloader does **not** emit per-device capabilities, interrupt
descriptors, PCI ECAM descriptors, or firmware-table read-only caps.
Device-level work lives in userspace, which re-parses ACPI / DTB from
the passthrough addresses in `BootInfo.acpi_rsdp` and
`BootInfo.device_tree` (see
[device-management.md](../../../docs/device-management.md#raw-firmware-passthrough)).

Detailed per-parser invariants — ACPI table-walk and DTB-walk specifics —
are owned by [acpi.md](acpi.md) and [dtb.md](dtb.md). This document covers
the surface the bootloader consumes from firmware and the dispatch rules.

---

## Architecture Dispatch

Firmware table location is obtained from `EFI_CONFIGURATION_TABLE`:

| GUID | `BootInfo` field | Typical architecture |
|---|---|---|
| `EFI_ACPI_20_TABLE_GUID` | `acpi_rsdp` | x86-64 (and ACPI-capable RISC-V platforms such as QEMU+EDK2 virt) |
| `EFI_DTB_TABLE_GUID` | `device_tree` | RISC-V firmware that installs the FDT table (not QEMU+EDK2, which publishes ACPI only) |

The configuration table is a flat array (`SystemTable->NumberOfTableEntries`
entries, each a `(GUID, pointer)` pair). The bootloader scans the array
unconditionally for each GUID, stopping at the first matching entry, and
records the physical address of each found table in the appropriate
`BootInfo` field. If a GUID is
absent, its field is zeroed.

Both fields may be non-zero on a platform that exposes both ACPI and a
DTB; no currently targeted host does, since QEMU+EDK2 on RISC-V hands
the bootloader ACPI only. On RISC-V the bootloader runs ACPI first for
`kernel_mmio` and then lets the DTB pass fill in any field ACPI left
zero; the two never overwrite each other. Userspace handles both
passthrough addresses the same way.

---

## Per-parser invariants

Table-walk details — RSDP/XSDT/MADT/MCFG validation, entry-type
handling, signature matching, per-field extraction rules — live
with the parser each covers:

- ACPI walk invariants: [acpi.md](acpi.md).
- Device Tree walk invariants: [dtb.md](dtb.md).

This document covers only the cross-parser coordination: dispatch
(above), aperture construction (below), and parsing-depth policy.

---

## `mmio_apertures` construction

The aperture list delivered in `BootInfo.mmio_apertures` is assembled
after `ExitBootServices` by
[`core/boot/src/memory_map.rs::derive_mmio_apertures`](../src/memory_map.rs):

1. Collect `EfiMemoryMappedIO` and `EfiMemoryMappedIOPortSpace`
   descriptors from the raw UEFI memory map.
2. Union with the seeds produced by
   [`core/boot/src/acpi.rs::parse_aperture_seed`](../src/acpi.rs) and
   [`core/boot/src/dtb.rs::parse_aperture_seed`](../src/dtb.rs) for every
   firmware source that is present, and with the GOP framebuffer, which
   UEFI typically reports as `EfiReservedMemoryType` and only the bootloader can
   carry past `ExitBootServices`. Seeds beyond the `MAX_APERTURE_SEEDS` (64)
   seed buffer, the framebuffer seed included, are dropped without a diagnostic.
   The ACPI seeder's heuristic PCI windows go to a separate buffer
   (`MAX_HEURISTIC_SEEDS`, 16); windows beyond it are dropped without a
   diagnostic. Each seed is first clipped to the memory map as
   [§ Firmware exclusion](#firmware-exclusion) defines, so it contributes only
   the gaps the subtracted ranges leave, and a seed wholly inside one contributes
   nothing.
3. Sort by `phys_base`.
4. Merge adjacent and overlapping entries into a minimal non-overlapping
   list.
5. Cap at `MAX_APERTURES` (16, [`abi/boot-protocol`](../../../abi/boot-protocol/src/lib.rs));
   surplus, and any entry collected in steps 1–2 beyond the
   `derive_mmio_apertures` scratch buffer (`MAX_APERTURES` × 4), is dropped with a
   diagnostic.

The UEFI memory map on every currently-targeted host is the primary
source; firmware-table seeds cover the regions the UEFI map often
classifies as `Reserved` rather than `MemoryMappedIO` (LAPIC / IOAPIC /
PLIC / ECAM / BAR windows).

### Firmware exclusion

Apertures are coarse but **not indiscriminate**. No aperture covers RAM or
firmware-exclusive state. Step 1 collects only MMIO descriptors, and step 2
clips each seed by its class:

- **Named seeds** are windows a firmware table, the DTB, or GOP names as a device's
  registers or frame buffer, or that the arch defaults fix at a platform-defined
  register address (`default_mmio_apertures`: on riscv64 the QEMU virt ECAM, UART,
  and RTC windows): LAPIC, IOAPIC, PLIC, ECAM, UART, RTC, `virtio,mmio` and other
  DTB nodes, and the framebuffer. Every range of
  the RAM-class types (`EfiConventionalMemory`, `EfiBootServicesCode`,
  `EfiBootServicesData`, `EfiLoaderCode`, `EfiLoaderData`, `EfiACPIReclaimMemory`,
  `EfiPersistentMemory`) and of the firmware-exclusive types
  (`EfiRuntimeServicesCode`, `EfiRuntimeServicesData`, `EfiACPIMemoryNVS`) is
  subtracted. `EfiReservedMemoryType` is not, because firmware reports the GOP
  framebuffer and some interrupt-controller and ECAM windows as Reserved, and a
  named seed covers such a range only where the device it names lives.
- **Heuristic windows** are the MCFG-derived 32-bit and 64-bit PCI BAR windows and the
  riscv64 default PCI windows (`default_pci_windows`), placed by a QEMU layout
  heuristic rather than named by firmware. Every range the memory map describes,
  except MMIO, is subtracted, `EfiReservedMemoryType` included, so only the map's
  holes and MMIO descriptors remain. Firmware-reserved DRAM inside such a window
  (SMM memory, graphics stolen memory) therefore never becomes an aperture.

Userspace therefore never receives an `Mmio` capability over RAM, over
runtime-services or ACPI NVS memory, or over Reserved memory that no named seed
covers (see
[abi/boot-protocol](../../../abi/boot-protocol/README.md#contract-for-a-compliant-bootloader)).
The kernel re-checks the RAM half at Phase 6, rejecting any aperture that intersects a
RAM-class memory-map region
([initialization.md](../../kernel/docs/initialization.md#phase-6-platform-resource-validation)).

---

## Parsing Depth

The bootloader's firmware parsing is deliberately narrow. It does not:

- Evaluate ACPI AML bytecode (DSDT, SSDT method evaluation).
- Walk the ACPI namespace to resolve `_CRS`, `_HID`, or device
  dependencies.
- Parse DTB `interrupt-map` properties or complex `ranges` translations
  beyond the PCI host-bridge ranges.
- Enumerate PCI buses or read PCI configuration space.
- Identify specific device models or driver requirements.
- Enumerate IOMMU topology.
- Produce per-device capabilities of any kind.

All of these are `devmgr`'s responsibility. The bootloader produces the
minimum set of coarse descriptors the kernel needs to mint initial
capabilities; per-device assignment is a userspace concern re-derived
from the ACPI/DTB passthrough addresses in `BootInfo` (see
[device-management.md](../../../docs/device-management.md#raw-firmware-passthrough)).

---

## Summarized By

[core/boot/README.md](../README.md), [ACPI Parsing](acpi.md), [Boot Flow](boot-flow.md),
[Device Tree Parsing](dtb.md), [UEFI Environment](uefi-environment.md),
[Device Management](../../../docs/device-management.md),
[services/drivers/goldfish-rtc/README.md](../../../services/drivers/goldfish-rtc/README.md)
