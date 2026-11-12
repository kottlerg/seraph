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
window yields a scan. After the scan devmgr unmaps the window and keeps its
cap, with its location, in a table of its own (`DevmgrCaps.config_space`,
apart from the apertures, so no BAR carve can reach configuration space),
from which it carves the configuration page of each function it binds a
driver to (step 3 of § Per-Device Capability Creation). A window that table
cannot hold is logged, and its functions get no driver.

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
   - Read device ID (offset 0x02), and the revision ID and class code
     (0x08-0x0B: revision, programming interface, subclass, class), which
     the match keys of § Driver Matching include and of which the class and
     subclass exempt a host bridge from the decode toggle below.
   - For a type-0 header, read the subsystem vendor and subsystem ID (0x2C,
     0x2E) and size the BARs (offsets 0x10-0x24). For a type-1 (PCI-to-PCI
     bridge) header, read the
     secondary (0x19) and subordinate (0x1A) bus numbers, the buses behind
     the bridge, against which devmgr resolves the device scopes of the ACPI
     DMAR.
   - Read interrupt line (0x3C) and interrupt pin (0x3D).
   - For a function of the VirtIO vendor ID (`0x1AF4`), walk its capability
     list for the VirtIO register regions (§ Per-Device Capability Creation,
     step 1).

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

## Driver Matching

devmgr matches each function against the declarations its driver binaries
carry, by the function's identity keys: vendor and device ID, and class code
(class, subclass, programming interface) under a declaration's mask
([docs/driver-binding.md](../../../docs/driver-binding.md#matching)
§ Matching). It binds each function at most once, to its most specific
match, in segment, bus, device, function order, in the boot pass over the
boot modules' declarations and the drivers-directory pass at
`SET_DRIVERS_DIR` ([responsibilities.md](responsibilities.md#responsibilities)
§ Responsibilities). The scan names no device: the VirtIO device IDs each
VirtIO driver serves are in its own declaration. A function a declaration
requires an interrupt for but that gets no IRQ cap (for instance, its line
lies outside the Interrupt range devmgr holds) is not bound. A function on a
line another function already holds gets an IRQ cap too (step 4). The
subsystem IDs and revision are recorded; matching on them is design intent;
not yet implemented ([#165](https://github.com/kottlerg/seraph/issues/165)).

---

## Per-Device Capability Creation

For each matched device, devmgr:

1. For a function that presents the VirtIO register layout, locates its
   VirtIO register regions
   (`VirtioPciStartupInfo::register_layout`): the distinct BARs the common,
   notification, ISR, and device-configuration regions name, at most four,
   in ascending BAR index, each sized to the pages the regions in it reach.
   The scan (`firmware::scan`) takes, for each type, the first structure in
   the capability list that lies wholly inside one of the device's MMIO BARs
   and that the transport can use (`virtio_core::structure_usable`; VirtIO
   1.2 § 4.1.4.1), skipping a later structure of a type already located, one
   in an I/O BAR, one naming a reserved BAR index, one reaching past its
   BAR's end, a common structure shorter than the 0x38 bytes of registers
   the transport addresses in it (`COMMON_CFG_LEN`) or at an offset not
   4-aligned (§ 4.1.4.3.1), and a notification structure whose offset or
   `notify_off_multiplier` is not 2-aligned (§ 4.1.4.4.1), since either
   would make a register access misaligned. A function left with no region
   of one of the four types (VirtIO 1.2 § 4.1.4 requires all four of a
   block or input device) presents no layout; it is refused, logged, when
   its driver declares the VirtIO status reset, and bound as any other
   function otherwise.
2. Carves an `Mmio` sub-cap for each of those BARs out of the boot-provided
   MMIO aperture that covers it, spanning the BAR's first pages up to that
   reach at most. The driver maps each BAR into that many pages of its
   register window, and `SYS_MMIO_MAP` maps a cap's whole region, so a
   larger cap would map past the BAR's share of the window. For any other
   function it carves a sub-cap for every MMIO BAR, whole; I/O BARs are not
   delivered. A BAR the layout names that is
   not an MMIO BAR, or a BAR no aperture covers, refuses the device, logged,
   with the caps already carved released. The aperture's lower and upper
   remainders stay in devmgr's growable aperture table
   (`firmware::resource::SpanTable`) as caps of their own.
3. Carves the `Mmio` cap of the function's configuration page (4 KiB at
   `firmware::pci::function_config_phys`) out of the kept ECAM window that
   decodes its segment and bus. devmgr keeps the cap and delegates it to no
   driver: at the bind it writes the Command register through it (Memory
   Space Enable on, Bus Master Enable on only for a DMA declaration,
   Interrupt Disable clear only for a driver given the line), and when it
   withdraws the driver it clears the function's Bus Master Enable through it
   before it takes the BAR caps, and sets its Interrupt Disable after (see
   [responsibilities.md](responsibilities.md#responsibilities)
   § Responsibilities). A function no kept window decodes, or whose carve
   fails, refuses the device, logged, with its BAR caps released. For a DMA
   declaration devmgr then gives the device DMA. Where an IOMMU unit
   translates the device, it
   first attaches the device to an IOMMU domain of its own through the IOMMU
   driver and maps there, at their own addresses, the ranges an RMRR reserves
   for it, and refuses a device whose reserved ranges cannot be mapped, whose
   unit it could not hand over, or whose attach fails (see
   [docs/device-management.md](../../../docs/device-management.md#iommu-discovery-and-programming)
   § IOMMU Discovery and Programming). It registers the device in its DMA
   table with that confinement and derives the device's DMA capability, a
   SEND badged with the device badge on its DMA endpoint
   ([responsibilities.md](responsibilities.md) § Responsibilities). A device
   that cannot be given DMA is refused, logged, with its BAR and
   configuration-page caps released.
4. For a declaration that takes an interrupt, gives the device its own
   single-line `Interrupt` cap for its GSI (its
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
   derivation; the line stays held for the others. The device's IRQ comes
   with its line's `SYS_IRQ_REGISTER` mode, the same for every device on
   the line. On x86-64 devmgr reads the MADT's Interrupt Source Overrides
   once at startup (`firmware::acpi::madt_source_overrides`), logging each,
   and takes the line's trigger and polarity from the override naming its
   GSI, field by field; a field the override leaves conforming to its bus,
   and a line no override names, take the PCI default, level-triggered and
   active-low (`firmware::acpi::line_mode`). A missing MADT, or one whose
   header is malformed, is logged once and every line takes the PCI default;
   a structure malformed partway through ends the walk after the overrides
   before it, logged once (`firmware::acpi::madt_well_formed`), and a line a
   later override would have named takes the default. On riscv64 every line
   takes level-triggered, active-high, which the kernel validates and
   programs nothing from.
5. Requests procmgr to create the driver process: `CREATE_PROCESS` for a
   boot-module driver (in the boot pass, from a derived copy of the module
   cap per device; the original is released once the pass ends) or
   `CREATE_FROM_FILE` for a drivers-directory one (in the drivers-directory
   pass, once `SET_DRIVERS_DIR` delivers the drivers directory), a DMA
   declaration's with `CREATE_PINNED` and `CREATE_DMA_HOLD`, so procmgr
   holds the driver's memory after its death until devmgr releases it, at
   the priority of its declared tier as its source allows.
6. Starts the driver (`START_PROCESS`). A driver whose bootstrap fails after
   this step is withdrawn from its device as a live driver.
7. Serves the driver's bootstrap as the resource list of
   `driver_binding::resources`
   ([shared/driver-binding/README.md](../../../shared/driver-binding/README.md)):
   one round per resource, each naming its kind in `data[0]`: an `Mmio`
   round per BAR cap of step 2, in carve order, with its PCI BAR index,
   physical base, and size, then, with an IRQ cap from step 4, an
   `Interrupt` round of kind `Wired` with the line's mode of step 4, which
   the driver passes to `SYS_IRQ_REGISTER`. The terminal round carries the
   service endpoint, a SEND badged with the device's badge on the private
   driver endpoint of the driver's settle batch, and, for a DMA declaration,
   a copy of the device's DMA capability. With no `Interrupt` resource
   virtio-input and virtio-console poll. A VirtIO driver checks the delivered
   BAR indices against the layout it computes from its `QUERY_DEVICE_INFO`
   reply and exits on a mismatch.
8. Binds a death observer on the driver's thread to devmgr's driver death
   queue, with the device badge as the correlator, and keeps the driver's
   process handle for the rest of the boot.
9. Once every driver of the batch (the boot batch: the boot pass, then the
   serial and framebuffer drivers; the on-disk batch: the RTC driver, then
   the drivers-directory pass) has been spawned, settles the batch: serves
   the drivers' `QUERY_DEVICE_INFO` and `DRIVER_READY` calls on the private
   endpoint and takes their deaths until every driver has reported ready or
   died or the settle bound elapses, then takes every death still queued,
   revokes the private endpoint, serves the drivers that reported ready and
   were not seen to die, at instance ordinals fixed from then on, and
   withdraws the rest, destroying any still pending. A served driver's later
   death withdraws it and leaves a tombstone at its ordinal (see
   [responsibilities.md](responsibilities.md#responsibilities)
   § Responsibilities).

---

## Summarized By

[Device Management](../../../docs/device-management.md),
[devmgr Responsibilities and Capabilities](responsibilities.md)
