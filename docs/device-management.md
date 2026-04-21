# Device Management

Device management is a userspace concern. The kernel mints initial capabilities from
boot-provided resource descriptors and enforces hardware access control. All
enumeration, binding, and policy live in `devmgr`.

---

## Boot-Provided Resource Descriptors (summary — [boot-protocol.md](boot-protocol.md))

The kernel consumes `PlatformResource` entries from `BootInfo.platform_resources`
and mints capabilities from them during Phase 7 of initialization. Firmware parsing
is outside the kernel's TCB.

See [boot-protocol.md](boot-protocol.md) for the `PlatformResource` type and field
definitions.

---

## Raw Firmware Passthrough

The `acpi_rsdp` and `device_tree` fields in `BootInfo` are passed through to
userspace as opaque physical addresses. The kernel creates read-only frame
capabilities for these regions so that devmgr (or any other process init authorises)
can parse them directly.

The kernel treats these regions as opaque byte ranges.

---

## devmgr: Userspace Device Manager

`devmgr` is a privileged userspace process launched during bootstrap (started by init
via procmgr). It is the single point responsible for platform enumeration and driver
binding in a running system.

### What devmgr receives from init

At startup, devmgr receives from init (via `SYS_CAP_INSERT`):

- **Platform resource capabilities** — one per `PlatformResource` entry: MMIO,
  interrupt, IoPortRange, and IOMMU unit caps.
- **Firmware table capabilities** — read-only frame caps for the ACPI RSDP and/or
  Device Tree blob.
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

## IommuUnit Resources

`IommuUnit` entries in `PlatformResource` describe the register base and scope
of one IOMMU. The kernel mints one MMIO capability per `IommuUnit` during the
capability-minting phase of kernel initialization and hands the set to init at
the init ABI gate; init delegates the IOMMU MMIO caps to devmgr. devmgr
programs the IOMMU directly through those MMIO capabilities — the kernel does
not read or write IOMMU registers and holds no per-IOMMU state.

When devmgr binds a DMA-capable driver, devmgr (a) programs the IOMMU
translation tables for that driver's device, and (b) derives and transfers a
DMA-authorising capability to the driver. On platforms without an IOMMU,
devmgr still derives the authorising capability, but the physical isolation is
absent — this is a userspace policy decision (refuse / warn / restrict), not a
kernel-enforced mode. The kernel is agnostic to both outcomes.

### Known Divergence

*Known divergence from current implementation.* As of this writing, kernel
code includes an `IommuUnit` capability type and IOMMU-programming paths
that this section describes as devmgr-owned. The kernel-side IOMMU surface
is scheduled for removal; see the repo-local `TODO.md` entry "IOMMU
stripping (Shape A migration)" for the plan. Until that migration lands,
kernel code and this document will disagree on the kernel/userspace split.

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
