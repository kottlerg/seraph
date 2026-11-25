# Firmware Parsing

The bootloader performs narrow, targeted firmware parsing to populate
five parts of `BootInfo`:

1. `cpu_count` / `bsp_id` / `cpu_ids` — the CPU topology handed to the
   kernel for SMP bring-up.
2. `kernel_mmio` — the arch-specific MMIO register bases the kernel
   itself consumes (LAPIC / IOAPIC on x86-64 via ACPI MADT; UART
   and the supervisor-level APLIC domain and IMSIC layout on RISC-V via
   ACPI MADT + SPCR, with any fields left zero by ACPI filled from the DTB;
   see [acpi.md](acpi.md) and [dtb.md](dtb.md)), plus the riscv64 hart
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

## Table Bounds

Every firmware table is hostile input: its own length field (an SDT header's `Length`, a device
tree header's `totalsize`) is a value the firmware wrote, and a bootloader that made a slice of
that many bytes from the table's address would read wherever the value points. The bootloader
therefore makes a slice of firmware memory in one place,
[`core/boot/src/tables.rs::TableMap::view`](../src/tables.rs), and only for a range the UEFI
memory map gives wholly to firmware data:

1. The RSDP is viewed at its fixed 36 bytes; each SDT, the XSDT included, first as its 36-byte
   header, then at the length the header reports; the device tree first as its 40-byte header,
   then at its `totalsize`.
2. Each view is checked by `boot_firmware::region::firmware_range` against the memory map's
   descriptors: every byte of the range must lie in a descriptor of an accepted type, abutting
   descriptors joined, and no descriptor of a refused type may overlap it. A range whose end
   overflows the address space is refused.
3. A refused view makes no slice. The table reads as absent, as a malformed one does, and the
   console reports the table, its address range, and the memory type or the hole that refused it
   (once per address; the reads before the serial console is up report nothing).

The memory map is the cap on a hostile length: whatever a length field says, a slice cannot reach
memory-mapped I/O, a hole, or free memory. No constant caps a table's size. The decoders in
`core/boot/firmware` and `shared/firmware-tables` then read only inside the slice they are
given, which their property checks, fuzz targets and proof harnesses establish
([core/boot/firmware/README.md](../firmware/README.md),
[docs/testing.md](../../../docs/testing.md#bounded-verification)).

The map is the one `efi_main` takes before the console is up, for every read up to the count
pass ahead of step 6, after which it is freed; a table lies in memory whose type the boot never
changes (allocations change only free memory to a loader type), so that map bounds each table as
well as a later one. From step 9 on, after `ExitBootServices`, the reads use step 7's final map,
the last of them ahead of that map's scrub. When the first `GetMemoryMap` fails, every view is
refused and the boot proceeds as on a platform without firmware tables.

The accepted types are those UEFI 2.10 lets a table or a device tree occupy:

| Type | Accepted | Why |
|---|---|---|
| `EfiACPIReclaimMemory` | yes | ACPI tables loaded at boot may live here (recommended) (§ 2.3.2 and the per-architecture § 2.3.x lists); the device tree must (§ 4.6.1.3; EBBR § 2.4.2) |
| `EfiACPIMemoryNVS` | yes | ACPI tables may live here, and the FACS must (§ 2.3.x) |
| `EfiRuntimeServicesData` | yes | a configuration table loaded at boot may live here (recommended) (§ 2.3.x); the RSDP is one (§ 4.6) |
| `EfiBootServicesData` | yes | a configuration table loaded at boot may live here (§ 2.3.x); EDK2's QEMU platforms leave the device tree here |
| `EfiLoaderData` | yes | a UEFI application may modify or replace the device tree (§ 4.6.1.3), and its data is this type (Table 7.5) |
| `EfiReservedMemoryType` | yes | § 2.3.2 states an intent that no configuration table lives here, not a requirement; accepted so firmware that leaves a table there still boots with it |
| `EfiLoaderCode`, `EfiBootServicesCode`, `EfiRuntimeServicesCode` | no | code, which holds no table |
| `EfiConventionalMemory` | no | free memory (Table 7.5), which no table occupies |
| `EfiUnusableMemory` | no | memory with errors (Table 7.5) |
| `EfiMemoryMappedIO`, `EfiMemoryMappedIOPortSpace` | no | device registers, whose reads have side effects |
| `EfiPalCode` | no | Itanium firmware code |
| `EfiPersistentMemory` | no | `AllocatePages` refuses the type (§ 7.2.1), so firmware cannot place a table there |
| `EfiUnacceptedMemoryType` | no | memory not yet accepted by the guest, which faults on access |
| any other value | no | undefined types, and the OEM and OS ranges, whose contents UEFI does not define |

No real-hardware memory map has been checked against this list; QEMU's (q35 and virt, under EDK2)
place every table the bootloader reads in an accepted type.

---

## Per-parser invariants

Table-walk details — RSDP/XSDT/MADT/MCFG validation, entry-type
handling, signature matching, per-field extraction rules — live
with the parser each covers:

- ACPI walk invariants: [acpi.md](acpi.md).
- Device Tree walk invariants: [dtb.md](dtb.md).

The decoders are slice-taking functions in two host-tested crates: the format layer both the
bootloader and devmgr read (RSDP, SDT header, XSDT, MADT and DMAR structure steps, MCFG, SPCR,
the flattened device tree's header and token walk) in
[shared/firmware-tables](../../../shared/firmware-tables/README.md), and the bootloader's own
readings of them (CPU IDs, AIA, hart capabilities, the TPM and VMGENID scans, the aperture
seeds, the memory-map check) in [core/boot/firmware](../firmware/README.md).

This document covers only the cross-parser coordination: dispatch
(above), table bounds (above), aperture construction (below), and parsing-depth policy.

---

## `mmio_apertures` construction

The aperture list delivered in `BootInfo.mmio_apertures` is assembled
after `ExitBootServices` by
[`core/boot/src/memory_map.rs::derive_mmio_apertures`](../src/memory_map.rs):

1. Collect `EfiMemoryMappedIO` and `EfiMemoryMappedIOPortSpace`
   descriptors from the raw UEFI memory map.
2. Union with the seeds produced by
   [`core/boot/src/tables.rs::aperture_seeds`](../src/tables.rs) for every
   firmware source that is present (`boot_firmware::seeds::acpi_table_seeds` over
   each ACPI table, the arch defaults, then `boot_firmware::dtb::Tree::seeds`), and
   with the GOP framebuffer, which
   UEFI typically reports as `EfiReservedMemoryType` and only the bootloader can
   carry past `ExitBootServices`. The seeds go to a buffer step 6 sized from a
   count pass of the same walk over the same tables, ahead of step 6,
   one slot more for the framebuffer, so every seed has a slot; the ACPI
   seeder's heuristic PCI windows go to a separate buffer, sized the same way. A
   seed past its buffer would be dropped with a diagnostic, which only a table
   changed between the two passes could cause. Each seed is first clipped to the memory map as
   [§ Firmware exclusion](#firmware-exclusion) defines, so it contributes only
   the gaps the subtracted ranges leave, and a seed wholly inside one contributes
   nothing.
3. Merge every piece, as it is collected, into the output list kept sorted by
   `phys_base`, joining adjacent and overlapping entries, so the list is minimal
   and non-overlapping at every step and no scratch buffer bounds the input.
4. Cap at the array's capacity, `memory_map::aperture_capacity` of the step 6
   entry array's capacity: every aperture starts at a descriptor's base, a seed's
   base, or the end of a descriptor clipped out of a seed, and no map read from the
   step 7 buffer holds more descriptors than the entry array
   ([memory-map.md](memory-map.md) § Sizing the Entry Array), so with the seeds step 6
   counted the apertures always fit. When more pieces than
   the capacity are disjoint at once, a later piece could still bridge them, so the
   list is rebuilt by taking the pieces in ascending `phys_base` order, which keeps
   exactly the lowest apertures the array holds of the full merge; when the full
   merge holds more, the highest are dropped with a diagnostic.

The UEFI memory map on every currently-targeted host is the primary
source; firmware-table seeds cover the regions the UEFI map often
classifies as `Reserved` rather than `MemoryMappedIO` (LAPIC / IOAPIC /
APLIC / IMSIC / ECAM / BAR windows).

### Firmware exclusion

Apertures are coarse but **not indiscriminate**. No aperture covers RAM or
firmware-exclusive state. Step 1 collects only MMIO descriptors, and step 2
clips each seed by its class:

- **Named seeds** are LAPIC, IOAPIC, APLIC, IMSIC, ECAM, VT-d remapping units (DMAR), the
  TPM's register window (TPM2), UART, RTC, `virtio,mmio` and other DTB nodes, and the
  framebuffer. They are windows a firmware table, the DTB, or GOP names as a device's registers
  or frame buffer, or that the arch defaults fix at a platform-defined register address
  (`default_mmio_apertures`, and `tpm_register_window` for a TPM the `TPM2` table reports).
  - Every range of the RAM-class types (`EfiConventionalMemory`, `EfiBootServicesCode`,
    `EfiBootServicesData`, `EfiLoaderCode`, `EfiLoaderData`, `EfiACPIReclaimMemory`,
    `EfiPersistentMemory`) and of the firmware-exclusive types (`EfiRuntimeServicesCode`,
    `EfiRuntimeServicesData`, `EfiACPIMemoryNVS`) is subtracted.
  - `EfiReservedMemoryType` is not subtracted: firmware reports the GOP framebuffer and
    some interrupt-controller and ECAM windows as Reserved, and a named seed covers such a
    range only where the device it names lives.
  - The riscv64 defaults are the QEMU virt ECAM, UART, and RTC windows. The bootloader does
    not identify the platform, so it appends them on every riscv64 boot whose ACPI
    validates. They hold only on QEMU virt, the one riscv64 platform it is built for. On any
    other platform those addresses name no device, and Reserved memory under them stays in
    an aperture.
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

- Evaluate ACPI AML bytecode (DSDT, SSDT method evaluation); acpid, a userspace service, does
  ([services/acpid/README.md](../../../services/acpid/README.md)).
- Walk the ACPI namespace to resolve `_CRS`, `_HID`, or device
  dependencies.
- Parse DTB `interrupt-map` properties or complex `ranges` translations
  beyond the PCI host-bridge ranges.
- Enumerate PCI buses or read PCI configuration space.
- Identify specific device models or driver requirements.
- Enumerate IOMMU topology: of the ACPI DMAR it reads only each VT-d unit's register window, to
  seed an aperture over it ([acpi.md](acpi.md)); the units' scopes, reserved regions, and
  programming are devmgr's.
- Produce per-device capabilities of any kind.

All of these but AML evaluation are `devmgr`'s responsibility. The bootloader produces the
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
