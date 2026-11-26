# core/boot/firmware

The bootloader's decoding of the firmware tables, over byte slices: what `core/boot` takes from
the ACPI tables and the flattened device tree, and the check that a table lies in memory the UEFI
memory map gives to firmware data.

`no_std`, allocation-free and host-tested, so the bootloader's UEFI image links it and every
decoder runs on the host; it depends on `abi/boot-protocol` for the handoff types it fills and on
`shared/firmware-tables` for the table formats it shares with devmgr. No function reads outside
the slice it is given, whatever a length or offset field inside the slice says; the bootloader
makes each slice only once `region::firmware_range` has accepted its extent
([core/boot/docs/firmware-parsing.md](../docs/firmware-parsing.md#table-bounds) § Table Bounds).
It provides:

- **The table bounds** (`region`): the UEFI memory map's descriptors (`descriptor`), the memory
  types that may hold a firmware table (`holds_firmware_data`), and whether a range lies wholly in
  descriptors of those types, contiguous ones joined in any order (`firmware_range`), with the
  reason for a refusal (`Refusal`).
- **ACPI** (`acpi`): the MADT's CPUs (`madt_cpu_ids`), I/O APICs (`madt_io_apic`), Local APIC
  base (`madt_lapic_base`) and AIA controllers (`madt_aia`); the RHCT's timebase and the hart
  capabilities every ISA node names (`rhct_hart_caps`); the VMGENID SSDT's GUID address
  (`vmgenid_guid`); the TPM2 table's register window (`tpm2_register_window`); the DMAR's remapping
  units' register windows (`dmar_register_windows`); and the SPCR's MMIO UART (`spcr_mmio_base`).
- **The device tree** (`dtb`): `Tree`, over a blob `firmware_tables::fdt::Fdt` accepts, with its
  walks (`CompatibleWalk`, `CpuWalk`, `CpuIntcWalk`) and what they met past their bounds
  (`Limits`): the CPUs, their hart IDs, ISA capabilities and paging modes, the timebase, the AIA
  controllers, the UART, the `rng-seed` property and the aperture seeds.
- **The aperture seeds** (`seeds`): `Seeds`, which collects the MMIO windows a table names and
  the heuristic PCI windows into the caller's buffers and counts those past a full one, and the
  ACPI tables' seeds (`acpi_table_seeds`).
- **The CPU placement** (`cpus`): the boot protocol's `cpu_ids` array, BSP first
  (`place_cpu_ids`, `record_cpu_id`, `cpu_id_capacity`).
- **The ISA string** (`isa`): the RISC-V extensions a hart's ISA string names.

The firmware tables are hostile input to the bootloader
([docs/threat-model.md](../../../docs/threat-model.md)), so the crate carries the parser rule's
property and its three drivers ([docs/testing.md](../../../docs/testing.md#fuzzing) § Fuzzing,
§ Bounded verification). The property, `property::boot_firmware_holds`, holds every decoder to
the layout its specification gives, on any input. Its drivers are the fuzz target
`boot-firmware` (`xtask/fuzz/targets`), which starts from the seeds under
`fuzz/boot-firmware/seeds/` (QEMU's q35 and `virt` tables and device tree, and hand-built memory
maps, TPM2 tables, a VMGENID SSDT and CPU lists); the replay of those seeds and any
`fuzz/boot-firmware/regressions/` in the crate's tests; and the Kani proofs in each module's
`proofs`, whose comments state their bounds and the walks the fuzz target checks instead.

No stability obligation; internal code reuse only.

---

## Source Layout

```
core/boot/firmware/
├── Cargo.toml                  # Workspace member; no_std library
├── README.md
├── fuzz/
│   └── boot-firmware/
│       └── seeds/              # Checked-in inputs of the `boot-firmware` fuzz target
└── src/
    ├── lib.rs                  # Crate root; the replay of the fuzz inputs
    ├── region.rs               # The memory map's descriptors and the table bounds
    ├── acpi.rs                 # MADT, RHCT, VMGENID SSDT, TPM2, DMAR and SPCR readings
    ├── dtb.rs                  # The device tree's walks and Tree
    ├── seeds.rs                # The MMIO aperture seeds
    ├── cpus.rs                 # The CPU-ID placement
    ├── isa.rs                  # The RISC-V ISA string
    └── property/               # The decoders' contract as one property (host tests,
                                #   proofs and fuzzing only), one file per module
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [core/boot/docs/firmware-parsing.md](../docs/firmware-parsing.md) | What the bootloader reads from the firmware, the table bounds |
| [core/boot/docs/acpi.md](../docs/acpi.md) | The ACPI tables the bootloader reads |
| [core/boot/docs/dtb.md](../docs/dtb.md) | The device-tree reading |
| [shared/firmware-tables/README.md](../../../shared/firmware-tables/README.md) | The table formats shared with devmgr |
| [docs/testing.md](../../../docs/testing.md) | The parser rule: property, fuzz target, proofs |

---

## Summarized By

[core/boot/README.md](../README.md),
[Firmware Parsing](../docs/firmware-parsing.md)
