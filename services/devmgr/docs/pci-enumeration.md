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
window yields a scan.

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
group; for a DTB node, its `linux,pci-domain` property, else the lowest
segment no other ECAM node's property or earlier fallback takes; for the
platform default, 0. A DTB node whose `linux,pci-domain` is short or above
65535 yields no window. A table whose window is empty, inverted, or
overflows a 64-bit physical address yields no ECAM. The offset arithmetic is
`firmware::pci::config_offset`; devmgr reads a bus outside
`start_bus..=end_bus` as all-ones.

### Scan Procedure

The walk is `firmware::scan::scan`, which reaches configuration space through
the `ConfigSpace` accessor devmgr implements over the mapped window. It
collects every present function into a growable list; when the list cannot
grow, the scan stops, logged with the first function it could not record,
and keeps the functions found before it (a window that recorded any counts
as scanned). The functions of every window are
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
function order, except a virtio-blk device that gets no IRQ cap (for
instance, its line lies outside the Interrupt range devmgr holds):
virtio-blk requires one. A
device on a line another device already holds gets an IRQ cap too (step 3).
Class-based matching is design intent (#165).

---

## Per-Device Capability Creation

For each matched device, devmgr:

1. Locates the device's VirtIO register regions
   (`VirtioPciStartupInfo::register_layout`): the distinct BARs the common,
   notification, ISR, and device-configuration regions name, at most four,
   in ascending BAR index, each sized to the pages the regions in it reach.
   The scan (`firmware::scan`) takes, for each type, the first structure in
   the capability list that lies wholly inside one of the device's MMIO BARs
   (VirtIO 1.2 § 4.1.4.1), skipping a later structure of a type already
   located, one in an I/O BAR, one naming a reserved BAR index, and one
   reaching past its BAR's end. A device left with no
   region of one of the four types (VirtIO 1.2 § 4.1.4 requires all four of a
   block or input device) is refused, logged.
2. Carves an `Mmio` sub-cap for each of those BARs out of the boot-provided
   MMIO aperture that covers it, spanning the BAR's first pages up to that
   reach at most. The driver maps each BAR into that many pages of its
   register window, and `SYS_MMIO_MAP` maps a cap's whole region, so a
   larger cap would map past the BAR's share of the window. A BAR that is
   not an MMIO BAR, or that no aperture covers, refuses the device, logged,
   with the caps already carved released. The aperture's lower and upper
   remainders stay in devmgr's growable aperture table
   (`firmware::resource::SpanTable`) as caps of their own.
3. Gives the device its own single-line `Interrupt` cap for its GSI (its
   firmware-programmed IRQ line, else the arch `INTx` fallback). The first
   time any device asks for a GSI, devmgr splits the line's cap off its
   Interrupt range cap; the lines below and above it stay in devmgr's
   interrupt table, so devices are served in any GSI order. devmgr keeps
   the split line cap for the boot in a table of held lines, one entry per
   GSI (`firmware::lines::HeldLines`), and gives the device a derivation of
   it (`SYS_CAP_DERIVE`, NOTIFY); a later device whose GSI is already held
   gets another derivation of the same cap, so devices on a shared `INTx`
   line each bind their own receiver (docs/device-management.md
   § Interrupt Delivery). Releasing a device's caps deletes only its own
   derivation; the line stays held for the others.
4. Requests procmgr to create the driver process: `CREATE_PROCESS` for a
   boot-module driver (virtio-blk, at enumeration, from a derived copy of the
   module cap per device; the original is released once every device is
   served) or `CREATE_FROM_FILE` for an on-disk one (virtio-input, whose
   steps 4-8 run later, once `SET_DRIVERS_DIR` delivers the drivers
   directory).
5. Starts the driver (`START_PROCESS`).
6. Serves the driver's bootstrap rounds over `ipc::bootstrap`, in the shape
   `virtio_core::bootstrap` specifies: round 1 carries the BAR `Mmio` caps in
   the order of step 1, with each cap's PCI BAR index as the matching data
   word; round 2 carries the positional slots service endpoint, IRQ, and a
   SEND badged with the device's badge on the private driver endpoint of the
   driver's settle batch, packed with `ipc::bootstrap::pack_slots` (presence
   word in `data[0]`), and ends the bootstrap. The IRQ slot is absent when the
   device got no IRQ cap in step 3; virtio-input then polls, and virtio-blk,
   which requires the IRQ, is not spawned. A driver checks the delivered BAR indices
   against the layout it computes from its `QUERY_DEVICE_INFO` reply and exits
   on a mismatch.
7. Binds a death observer on the driver's thread to devmgr's driver death
   queue, with the device badge as the correlator, and keeps the driver's
   process handle until its batch settles.
8. Once every driver of the batch (the boot batch: virtio-blk, serial, and
   framebuffer; the on-disk batch: the RTC and virtio-input) has been
   spawned, settles the batch: serves the drivers' `QUERY_DEVICE_INFO` and
   `DRIVER_READY` calls on the private endpoint and takes their deaths until
   every driver has reported ready or died or the settle bound elapses, then
   takes every death still queued, revokes the private endpoint, serves the
   drivers that reported ready and were not seen to die, at instance
   ordinals fixed from then on, and withdraws the rest, destroying any still
   pending. A served driver's later death withdraws it and leaves a
   tombstone at its ordinal (see
   [responsibilities.md](responsibilities.md#responsibilities)
   § Responsibilities).

---

## Summarized By

[devmgr Responsibilities and Capabilities](responsibilities.md)
