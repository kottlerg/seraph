# Firmware Parsing

The bootloader performs narrow, targeted firmware parsing to populate
three parts of `BootInfo`:

1. `cpu_count` / `bsp_id` / `cpu_ids` — the CPU topology handed to the
   kernel for SMP bring-up.
2. `kernel_mmio` — the arch-specific MMIO register bases the kernel
   itself consumes (LAPIC / IOAPIC on x86-64 via ACPI MADT; PLIC / UART
   on RISC-V via ACPI MADT + SPCR, with any fields left zero by ACPI
   filled from the DTB). Not a capability surface.
3. `mmio_apertures` — a short list of coarse `{phys_base, size}` MMIO
   regions, used as seeds into the final aperture list that is merged
   with the UEFI memory map's MMIO classifications. The kernel mints
   one `MmioRegion` capability per aperture entry.

The bootloader does **not** emit per-device capabilities, interrupt
descriptors, PCI ECAM descriptors, or firmware-table read-only caps.
Device-level work lives in userspace, which re-parses ACPI / DTB from
the passthrough addresses in `BootInfo.acpi_rsdp` and
`BootInfo.device_tree`.

Detailed per-parser invariants — ACPI table-walk and DTB-walk specifics —
are owned by [acpi.md](acpi.md) and [dtb.md](dtb.md). This document covers
the surface the bootloader consumes from firmware and the dispatch rules.

---

## Architecture Dispatch

Firmware table location is obtained from `EFI_CONFIGURATION_TABLE`:

| GUID | `BootInfo` field | Typical architecture |
|---|---|---|
| `EFI_ACPI_20_TABLE_GUID` | `acpi_rsdp` | x86-64 (and ACPI-capable RISC-V platforms such as QEMU+EDK2 virt) |
| `EFI_DTB_TABLE_GUID` | `device_tree` | RISC-V (and any DTB-capable x86-64 platform) |

The configuration table is a flat array (`SystemTable->NumberOfTableEntries`
entries, each a `(GUID, pointer)` pair). The bootloader scans the entire
array unconditionally for both GUIDs, recording the physical address of
each found table in the appropriate `BootInfo` field. If a GUID is
absent, its field is zeroed.

Both fields may be non-zero on a platform that exposes both ACPI and a
DTB (UEFI RISC-V firmware commonly does). On RISC-V the bootloader runs
ACPI first for `kernel_mmio` and then lets the DTB pass fill in any
field ACPI left zero; the two never overwrite each other. Userspace
handles both passthrough addresses the same way.

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
[`boot/src/memory_map.rs::derive_mmio_apertures`](../src/memory_map.rs):

1. Collect `EfiMemoryMappedIO` and `EfiMemoryMappedIOPortSpace`
   descriptors from the raw UEFI memory map.
2. Union with the seeds produced by
   [`boot/src/acpi.rs::parse_aperture_seed`](../src/acpi.rs) and
   [`boot/src/dtb.rs::parse_aperture_seed`](../src/dtb.rs) for every
   firmware source that is present.
3. Sort by `phys_base`.
4. Merge adjacent and overlapping entries into a minimal non-overlapping
   list.
5. Cap at [`MAX_APERTURES`] (16); surplus is dropped with a diagnostic.

The UEFI memory map on every currently-targeted host is the primary
source; firmware-table seeds cover the regions the UEFI map often
classifies as `Reserved` rather than `MemoryMappedIO` (LAPIC / IOAPIC /
PLIC / ECAM / BAR windows).

### Firmware exclusion

Apertures are coarse but **not indiscriminate**: regions classified as
`EfiRuntimeServices*`, `EfiACPIMemoryNVS`, or `EfiReserved` are omitted
from the aperture list (they are neither `EfiMemoryMappedIO` nor
explicitly added by the firmware-table extractors). Userspace therefore
never receives capabilities that cover firmware-exclusive state.

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
from the ACPI/DTB passthrough addresses in `BootInfo`.

---

## Summarized By

[boot/README.md](../README.md)
