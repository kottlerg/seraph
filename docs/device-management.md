# Device Management

Device management is a userspace concern. The kernel mints initial capabilities from
boot-provided resource descriptors and enforces hardware access control. All
enumeration, binding, and policy live in `devmgr`.

---

## Boot-Provided Resource Descriptors (summary — [`abi/boot-protocol/`](../abi/boot-protocol/))

The kernel consumes `BootInfo.mmio_apertures` during Phase 7 of
initialization and mints one `MmioRegion` capability per entry. These
coarse apertures, together with the arch-specific `BootInfo.kernel_mmio`
the kernel reads directly, are the only structured hardware descriptors
the bootloader produces. Firmware parsing (ACPI / DTB table walking) is
a userspace concern; the kernel's TCB contains no parser.

See [`abi/boot-protocol/src/lib.rs`](../abi/boot-protocol/src/lib.rs) for
the `MmioAperture`, `MmioApertureSlice`, and `KernelMmio` type
definitions.

---

## Raw Firmware Passthrough

The `acpi_rsdp` and `device_tree` fields in `BootInfo` are passed through
to userspace as opaque physical addresses. Device-level discovery —
resolving which aperture covers which device, which GSI goes to which
pin, the PCI bus topology — happens in userspace by re-walking ACPI and
DTB from these passthrough addresses.

The kernel treats the regions they point at as opaque byte ranges.

---

## devmgr: Userspace Device Manager

`devmgr` is a privileged userspace process launched during bootstrap (started by init
via procmgr). It is the single point responsible for platform enumeration and driver
binding in a running system.

### What devmgr receives from init

At startup, devmgr receives from init (via `SYS_CAP_INSERT`):

- **MMIO aperture capabilities** — one `MmioRegion` cap per
  `BootInfo.mmio_apertures` entry, covering coarse non-RAM physical
  regions. Init narrows these into device-sized sub-caps as needed and
  delegates them to drivers.
- **Interrupt capabilities** — produced on demand via the runtime
  IRQ-registration syscall (`SYS_IRQ_REGISTER`) after init has walked
  firmware tables and located the relevant GSI / PLIC source.
- **Firmware-table access** — access to ACPI and DTB physical memory so
  devmgr can resolve per-device descriptors that the bootloader no longer
  enumerates.
- **SchedControl capability** — for assigning elevated priorities to latency-sensitive
  driver threads.

Init retains derived copies to revoke devmgr's authority if devmgr crashes.

### What devmgr does

1. **Parse firmware tables** — walks ACPI or Device Tree to resolve interrupt
   routing, power domains, and the full PCI hierarchy.

2. **Enumerate PCI** — maps the ECAM region and reads configuration space to
   discover all devices, BARs, and interrupt assignments.

3. **Bind drivers** — for each device, spawns a driver process, delegates
   per-device capabilities (MMIO, interrupt, optionally DMA), and routes the
   driver's endpoint to the consuming service.

4. **Expose a device registry** — maintains an IPC service for querying device
   capabilities.

5. **Handle hotplug** — on supported platforms, receives hotplug notifications
   and dynamically spawns or terminates driver processes.

### Security boundary

devmgr holds only the capabilities delegated to it by init. Its authority is
revocable; init can kill devmgr and restart it with a fresh capability set.

---

## DMA Safety Model

DMA access in Seraph operates in one of two modes, distinguished by whether an
IOMMU is present and whether devmgr has programmed it to scope DMA for a given
device:

**IOMMU-isolated (safe):** When an IOMMU is present and devmgr has configured
it for the target device, DMA transactions initiated by that device are
confined by the IOMMU's translation tables to the physical frames devmgr has
explicitly mapped. A driver cannot DMA outside its authorised regions even if
its process is compromised. This is the expected mode on modern x86-64
hardware and on RISC-V platforms that implement the IOMMU extension.

**DMA-unsafe:** When no IOMMU is present, or when devmgr chooses not to
configure an available IOMMU for a device, unconfined DMA is physically
possible. A driver may still be authorised by devmgr to DMA in this mode,
but no hardware enforcement constrains the device; a compromised driver
can reach any physical address the device can address.

devmgr is responsible for detecting the platform IOMMU situation, deciding
per-device policy, and programming the IOMMU itself when present. For
devices that require DMA on a platform without IOMMU protection, devmgr may:
- Refuse to bind the driver.
- Bind the driver after warning the operator.
- Bind the driver in a restricted mode that avoids DMA entirely.

This decision is entirely userspace policy. The kernel is agnostic to DMA
mode: it does not read or write IOMMU registers, does not track per-device
DMA state, and does not return a DMA-safety verdict.

---

## IOMMU Discovery and Programming

IOMMU topology is a userspace concern. The bootloader does **not** emit a
dedicated resource variant for IOMMU units; it passes ACPI and DTB tables
through unchanged via `PlatformTable` entries, and `devmgr` performs the
IOMMU-topology walk itself (DMAR on x86-64, `iommu` / `iommu-map` nodes on
RISC-V).

For each IOMMU discovered, `devmgr` acquires an MMIO-region capability for
that IOMMU's register range and programs the translation tables directly.
The kernel does not read or write IOMMU registers and holds no per-IOMMU
state.

When devmgr binds a DMA-capable driver, devmgr (a) programs the IOMMU
translation tables for that driver's device, and (b) derives and transfers a
DMA-authorising capability to the driver. On platforms without an IOMMU,
devmgr still derives the authorising capability, but the physical isolation is
absent — this is a userspace policy decision (refuse / warn / restrict), not a
kernel-enforced mode. The kernel is agnostic to both outcomes.

### Known Divergence

*Known divergence from current implementation.* The boot ABI has been
stripped of its `IommuUnit` resource variant as of `BOOT_PROTOCOL_VERSION`
5; boot-side IOMMU discovery is gone. Residual kernel-side IOMMU
capability types and programming paths remain, scheduled for removal per
the repo-local `TODO.md` entry "IOMMU stripping (Shape A migration)".
Until that migration lands, the kernel's internal IOMMU surface exists
alongside the boot-side stripping documented here.

---

## Relationship to Other Services

```
init
 ├── devmgr  (platform caps + firmware table caps)
 │    ├── driver/ethernet  (MMIO cap, IRQ cap, DMA grant)
 │    ├── driver/nvme      (MMIO cap, IRQ cap, DMA grant)
 │    └── driver/usb-hcd   (MMIO cap, IRQ cap, DMA grant)
 ├── vfsd  (receives storage endpoint from devmgr)
 ├── netd  (receives network endpoint from devmgr)
 └── ...
```

devmgr is not a dependency of vfsd or netd directly — those services receive device
endpoints after devmgr has completed initial binding. The dependency ordering is
managed by init's bootstrap sequence (for early boot) and svcmgr (for restarts).

---

## Summarized By

[Architecture Overview](architecture.md), [devmgr](../devmgr/README.md), [drivers](../drivers/README.md)
