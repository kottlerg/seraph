# PCI Enumeration

PCI device enumeration via ECAM MMIO: configuration space access, BAR
discovery, interrupt routing resolution, and device-to-driver matching.

---

## ECAM Configuration Space

PCI Express Enhanced Configuration Access Mechanism (ECAM) maps the 4 KiB
extended configuration space of each PCI function to a contiguous MMIO
region. devmgr locates the ECAM itself as a `firmware::EcamLocation`
(`phys_base`, `size`, `start_bus`, `end_bus`) from the ACPI MCFG table, else
the Device Tree blob's `pci-host-ecam-generic` node, else the riscv64 QEMU
`virt` platform default (`arch::current::platform_default_ecam`), reading the
firmware tables through the read-only Memory caps init delivers. It then
carves the ECAM `Mmio` sub-cap from the boot-provided MMIO aperture cap that
covers it.

### Address Calculation

```
offset = (bus << 20) | (device << 15) | (function << 12) + register
```

Each function occupies 4 KiB (one page). The bus range is the
`EcamLocation`'s `start_bus` / `end_bus` fields: the MCFG entry's start and
end bus numbers; for a DTB node, bus 0 through the last bus the `reg` size
covers (capped at 255; a `reg` smaller than one bus yields no ECAM); for the
platform default, 0..=255.

### Scan Procedure

1. Map the ECAM `Mmio` cap into devmgr's address space.
2. For each bus in range, each device 0-31, function 0:
   - Read vendor ID (offset 0x00, u16). Skip if `0xFFFF`.
   - Read header type (offset 0x0E, u8). If bit 7 set, scan functions 1-7.
3. For each present function:
   - Read device ID (offset 0x02), class (0x0B), subclass (0x0A).
   - Read BARs (offsets 0x10-0x24 for type-0 headers).
   - Read interrupt line (0x3C) and interrupt pin (0x3D).

### BAR Discovery

To determine BAR size: write `0xFFFF_FFFF` to the BAR register, read back,
restore the original value, and decode. Bit 0 distinguishes MMIO (0) from
I/O (1). For MMIO BARs, bits 2:1 encode the type (0 = 32-bit, 2 = 64-bit).

---

## VirtIO Device Matching

VirtIO PCI devices use vendor ID `0x1AF4`. Device IDs:

| Device ID | Type |
|---|---|
| `0x1001` | Transitional virtio-blk |
| `0x1042` | Modern virtio-blk |
| `0x1000` | Transitional virtio-net |
| `0x1041` | Modern virtio-net |

devmgr matches discovered devices against known driver binaries (boot
modules) by device class and vendor/device ID.

---

## Per-Device Capability Creation

For each matched device, devmgr:

1. Splits the PCI MMIO window cap to carve per-BAR `Mmio` sub-caps.
2. Matches the PCI interrupt line to an Interrupt cap from init.
3. Requests procmgr to create the driver process (`CREATE_PROCESS`).
4. Injects per-device caps into the driver's `CSpace` via `cap_copy`.
5. Patches the driver's `ProcessInfo` with `CapDescriptor` entries.
6. Starts the driver (`START_PROCESS`).

---

## Summarized By

[devmgr Responsibilities and Capabilities](responsibilities.md)
