# PCI Enumeration

PCI device enumeration via ECAM MMIO: configuration space access, BAR
discovery, interrupt routing resolution, and device-to-driver matching.

---

## ECAM Configuration Space

PCI Express Enhanced Configuration Access Mechanism (ECAM) maps the 4 KiB
extended configuration space of each PCI function to a contiguous MMIO
region. devmgr locates every ECAM window itself, each as a
`firmware::EcamLocation` (`phys_base`, `size`, `segment`, `start_bus`,
`end_bus`): one per allocation entry of the ACPI MCFG table, else one per
`pci-host-ecam-generic` node of the Device Tree blob, else the riscv64 QEMU
`virt` platform default (`arch::current::platform_default_ecam`), reading the
firmware tables through the read-only Memory caps init delivers. Each read
maps only the pages that hold the table, at the table's own offset in its
ACPI region (`firmware::acpi::table_window`), so a table anywhere in a region
is readable; the DTB is mapped whole. An MCFG entry or DTB node that yields
no window is skipped and the walk continues. For each window devmgr then
carves the ECAM `Mmio` sub-cap from the boot-provided MMIO aperture cap that
covers it, maps it, and scans it. A window no aperture covers, or that
cannot be mapped, is logged and not scanned; the boot halts only when no
window is scanned.

### Address Calculation

```
offset = ((bus - start_bus) << 20) | (device << 15) | (function << 12) | register
```

The offset is from the window's `phys_base`, the configuration space of
`start_bus`; an MCFG entry's base address is where bus 0 would decode, so
devmgr places the window `start_bus` MiB above it. Each function occupies
4 KiB (one page). The bus range is the `EcamLocation`'s `start_bus` /
`end_bus` fields: the MCFG entry's start and end bus numbers; for a DTB node,
its `bus-range` property, else bus 0 onward, clamped to the buses its `reg`
covers and to 255 (the `reg` is decoded in the parent's `#address-cells` /
`#size-cells`, and its address is the configuration space of the first bus);
for the platform default, 0..=255. The window's `size` is 1 MiB per bus of
that range on every path. Its `segment` is the MCFG entry's PCI segment
group; for a DTB node, its `linux,pci-domain` property, else its ordinal
among the ECAM nodes; for the platform default, 0. A table whose window is empty, inverted, or
overflows a 64-bit physical address yields no ECAM. The offset arithmetic is
`firmware::pci::config_offset`; devmgr reads a bus outside
`start_bus..=end_bus` as all-ones.

### Scan Procedure

The walk is `firmware::scan::scan`, which reaches configuration space through
the `ConfigSpace` accessor devmgr implements over the mapped window. It
collects every present function into a growable list; when the list cannot
grow, the scan stops, logged with the first function it could not record,
and keeps the functions found before it. The functions of every window are
then ordered by segment, bus, device, and function.

1. Map the ECAM `Mmio` cap into devmgr's address space.
2. For each bus in range, each device 0-31, function 0:
   - Read vendor ID (offset 0x00, u16). Skip if `0xFFFF`.
   - Read header type (offset 0x0E, u8). If bit 7 set, scan functions 1-7.
3. For each present function:
   - Read device ID (offset 0x02).
   - For a type-0 header, read class (0x0B) and subclass (0x0A), which
     exempt a host bridge from the decode toggle below, and size the BARs
     (offsets 0x10-0x24).
   - Read interrupt line (0x3C) and interrupt pin (0x3D).

### BAR Discovery

To determine BAR size: write `0xFFFF_FFFF` to the BAR register, read back,
restore the original value, and decode. Bit 0 distinguishes MMIO (0) from
I/O (1). For MMIO BARs, bits 2:1 encode the type (0 = 32-bit, 2 = 64-bit).
A 64-bit MMIO BAR is sized from both registers: the upper register is probed
the same way, and the two read-backs form one 64-bit mask. The size is the
lowest writable address bit of the mask (`firmware::pci::mmio_bar_size` /
`io_bar_size`), so a device that hardwires its high address bits to zero
keeps its size.

I/O and Memory decode (Command register bits 0 and 1) are cleared for the
probe, so the device never decodes at the all-ones sizing address, and the
original Command value is restored afterwards; the Command register is
written only when a decode bit was set. A host bridge (base class 0x06,
subclass 0x00) is probed with decode left on, since turning it off can cut
off resources the running system decodes through it.

---

## VirtIO Device Matching

VirtIO PCI devices use vendor ID `0x1AF4`. Device IDs:

| Device ID | Type |
|---|---|
| `0x1001` | Transitional virtio-blk |
| `0x1042` | Modern virtio-blk |
| `0x1012` | Transitional virtio-input |
| `0x1052` | Modern virtio-input |

devmgr matches discovered devices against its driver binaries by vendor and
device ID: a boot module for virtio-blk, an on-disk driver for virtio-input.
Every matching device gets its own driver process, in segment, bus, device,
function order. Class-based matching is design intent (#165).

---

## Per-Device Capability Creation

For each matched device, devmgr:

1. Refuses the device, logging both BAR indices, when a VirtIO register
   region it names (notify, ISR, or device configuration) lies in a BAR other
   than the common-configuration region's: a VirtIO driver is delivered one
   BAR.
2. Carves an `Mmio` sub-cap for the device's VirtIO common-config BAR out of
   the boot-provided MMIO aperture that covers it, spanning the BAR's first
   `bar_aperture_pages` pages at most (the reach of its VirtIO capability
   structures). The driver reserves that many pages of VA for the BAR, and
   `SYS_MMIO_MAP` maps a cap's whole region, so a larger cap would map past
   the driver's reservation. The aperture's lower and upper remainders stay
   in devmgr's growable aperture table (`firmware::resource::SpanTable`) as
   caps of their own.
3. Splits a single-IRQ `Interrupt` cap for the device's GSI (its
   firmware-programmed IRQ line, else the arch `INTx` fallback) off devmgr's
   Interrupt range cap. The lines below and above it stay in devmgr's
   interrupt table, so devices are served in any GSI order.
4. Requests procmgr to create the driver process: `CREATE_PROCESS` for a
   boot-module driver (virtio-blk, at enumeration, from a derived copy of the
   module cap per device; the original is released once every device is
   served) or `CREATE_FROM_FILE` for an on-disk one (virtio-input, whose
   steps 4-6 run later, once `SET_DRIVERS_DIR` delivers the drivers
   directory).
5. Starts the driver (`START_PROCESS`).
6. Serves the driver's bootstrap rounds over `ipc::bootstrap`: round 1
   carries the BAR `Mmio`, the IRQ, and the driver's service endpoint (BAR
   and service only when there is no IRQ, a shape only virtio-input accepts,
   so virtio-blk is not spawned without one); round 2 carries a per-device
   badged SEND on devmgr's registry endpoint and ends the bootstrap.

---

## Summarized By

[devmgr Responsibilities and Capabilities](responsibilities.md)
