# Device Management

Device management is a userspace concern. The kernel mints initial capabilities from
boot-provided resource descriptors and enforces hardware access control. All
enumeration, binding, and policy live in `devmgr`.

---

## Boot-Provided Resource Descriptors

The kernel consumes `BootInfo.mmio_apertures` during Phase 7 of
initialization and mints one `Mmio` capability per entry; on RISC-V it mints one more for
the console UART range `BootInfo.kernel_mmio` names, which lies outside every aperture.
These apertures, the arch-specific `BootInfo.kernel_mmio`, and the framebuffer description
are the only device descriptors the bootloader produces. Firmware parsing (ACPI / DTB table
walking) is a userspace concern; the kernel's TCB contains no parser.

The kernel mints these capabilities in
[`core/kernel/docs/initialization.md`](../core/kernel/docs/initialization.md) § Phase 7:
Capability System; the full set it mints is listed in
[`docs/capability-model.md`](capability-model.md) § Initial Capability Distribution; the
bootloader's descriptor production is specified in
[`core/boot/docs/firmware-parsing.md`](../core/boot/docs/firmware-parsing.md).

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

The kernel parses neither table: it reads only the DTB header's magic and `totalsize` (to
size the blob's cap and keep its pages out of the buddy pool) and mints read-only Memory
caps over the RSDP page, the DTB blob, and each `AcpiReclaimable` region, which init
forwards to devmgr.

---

## devmgr: Userspace Device Manager

`devmgr` is a privileged userspace process launched during bootstrap (started by init
via procmgr). It is the single point responsible for platform enumeration and driver
binding in a running system.

### What devmgr receives from init

devmgr receives from init a platform capability set sufficient for
enumeration and per-driver delegation (MMIO apertures, firmware-table
Memory caps, the IRQ range, and the root `IoPort` on x86-64 or `SbiControl`
on RISC-V); its SchedControl band arrives from procmgr via `ProcessInfo`.
Init exits after bootstrap; devmgr is `restart = never`, `critical = yes`,
so its death triggers a graceful shutdown rather than re-delegation. The
per-round list of what init delivers is specified in
[`services/init/docs/bootstrap.md`](../services/init/docs/bootstrap.md) §
Per-stage authority transfers.

### What devmgr does

devmgr's per-responsibility specification — firmware-table parsing,
PCI enumeration, driver binding, device-registry IPC, and hotplug —
is in [`services/devmgr/docs/responsibilities.md`](../services/devmgr/docs/responsibilities.md)
§ Responsibilities. This document covers only the system-scope
boundary devmgr sits inside.

### Security boundary

devmgr's hardware, platform, and scheduling authority is only what it receives at bootstrap
(the platform set init delegates, plus the SchedControl band procmgr delivers in its
`ProcessInfo`) and the `/services/drivers/` cap svcmgr sends after handover (see Driver
binary sources). Its authority is not re-delegable after bootstrap: init exits, and svcmgr
treats devmgr as `restart = never`, `critical = yes`, so devmgr's death triggers a graceful
shutdown.

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

devmgr is responsible for detecting the platform IOMMU situation,
deciding per-device policy, and programming the IOMMU itself when
present. No IOMMU support is implemented yet, so devmgr spawns every
DMA-capable driver unconfined, in the DMA-unsafe mode, with no refuse or
warn path.

The kernel is agnostic to DMA mode: it does not read or write IOMMU
registers, does not track per-device DMA state, and does not return a
DMA-safety verdict.

---

## IOMMU Discovery and Programming

IOMMU topology is a userspace concern. The bootloader emits no IOMMU
descriptor; ACPI and DTB reach userspace only as the opaque
`BootInfo.acpi_rsdp` / `BootInfo.device_tree` physical addresses (see Raw
Firmware Passthrough), over which the kernel mints read-only Memory caps,
and `devmgr` is to perform the IOMMU-topology walk itself.

Once implemented, for each IOMMU discovered `devmgr` will acquire an `Mmio`
cap for that IOMMU's register range through the same aperture-carving flow
as any other device and program the translation tables directly; no IOMMU
support exists today. The kernel does not read or write IOMMU registers and
holds no per-IOMMU state.

When devmgr binds a DMA-capable (PCI BAR + IRQ) driver, it spawns the driver
with `procmgr_labels::CREATE_PINNED`, so the driver's memory is eager-mapped,
and delivers its BAR `Mmio`, optional IRQ, and endpoint caps. No
DMA-authorising capability type exists, and with no IOMMU programmed the
physical isolation is absent; whether to refuse, warn, or restrict is a
userspace policy decision, not a kernel-enforced mode. The kernel is
agnostic to both outcomes.

Memory physical-base addresses, where drivers need them (e.g. to program
device DMA transports on no-IOMMU systems), are supplied to drivers by
memmgr in the `REQUEST_MEMORY_CAPS` reply alongside the Memory caps themselves (see
[`services/memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)).
`SYS_CAP_INFO`'s `CAP_INFO_MEMORY_PHYS_BASE` selector also returns a Memory cap's physical
base to its holder (see
[`core/kernel/docs/cross-boundary-disclosure.md`](../core/kernel/docs/cross-boundary-disclosure.md)
§ Physical-address surfaces); a driver that receives a client-supplied Memory cap uses it to program
that cap's address.

---

## Relationship to Other Services

```
init
 ├── devmgr  (platform caps + firmware table caps)
 │    ├── driver/virtio-blk        (MMIO + IRQ caps; QUERY_BLOCK_DEVICE)
 │    ├── driver/virtio-input      (MMIO + opt. IRQ; QUERY_INPUT_DEVICE; on-disk)
 │    ├── driver/serial            (UART hw + IRQ caps; QUERY_SERIAL_DEVICE)
 │    ├── driver/framebuffer       (MMIO cap; QUERY_FRAMEBUFFER_DEVICE)
 │    └── driver/{cmos-rtc,goldfish-rtc} (RTC hw cap; QUERY_RTC_DEVICE)
 ├── vfsd  (receives storage endpoint via QUERY_BLOCK_DEVICE)
 ├── ...
 └── svcmgr
      ├── logd     (serial, framebuffer endpoints via QUERY_*_DEVICE)
      ├── pwrmgr   (ACPI tables + shutdown hw via QUERY_ACPI_TABLE / QUERY_SHUTDOWN_DEVICE)
      ├── timed    (RTC endpoint via QUERY_RTC_DEVICE)
      └── terminal (input, framebuffer, serial endpoints via QUERY_*_DEVICE)
```

vfsd and the consumers svcmgr launches after handover (logd, pwrmgr, timed, terminal)
query devmgr's registry for their device endpoints and hardware caps, which devmgr serves
only after initial enumeration and binding complete. The dependency ordering is fixed by
init's bootstrap sequence (devmgr before vfsd) and by svcmgr launching those consumers only
after handover; devmgr and vfsd are `restart = never`, so no restart ordering exists.

### Driver binary sources

devmgr loads driver binaries from one of two places:

- **Boot bundle** — bootstrap-essentials (virtio-blk, serial,
  framebuffer) ship in the bundle and arrive as Memory caps in devmgr's
  MODULE bootstrap round. devmgr spawns them via
  `procmgr_labels::CREATE_PROCESS` during initial enumeration.
- **On-disk rootfs** — non-essentials (the per-arch RTC and the
  [virtio-input keyboard driver](../services/drivers/virtio/input/README.md)) live at
  `/services/drivers/` and are loaded via `procmgr_labels::CREATE_FROM_FILE`. The test-only
  `test-orphan` binary also lives there; devmgr spawns it only on
  `devmgr_labels::TEST_SPAWN_ORPHAN`. virtio-input is PCI-enumerated during the initial scan — its
  BAR/IRQ caps are carved and stashed then — but its spawn is deferred to this path, since a
  keyboard is not on the read-the-disk critical path. A PCI device that shares an `INTx` line may
  get no private IRQ cap; such a driver is delivered a 2-cap bootstrap round (BAR + service, no IRQ)
  and polls its queue. Post-handover, svcmgr walks its universal root to `/services/drivers/` and
  hands devmgr that subtree cap via `devmgr_labels::SET_DRIVERS_DIR` (gated by
  `DRIVERS_DIR_AUTHORITY`, minted from the devmgr-registry source init endows svcmgr with; sent at
  `LOOKUP | READ` rights only — devmgr cannot reach outside the drivers subtree). The handshake is
  specified in [`services/init/docs/bootstrap.md`](../services/init/docs/bootstrap.md) and
  [`services/svcmgr/docs/ipc-interface.md`](../services/svcmgr/docs/ipc-interface.md). Devmgr
  replies SUCCESS before doing any spawn work so svcmgr never blocks on driver bring-up; the actual
  walk + `CREATE_FROM_FILE` + bootstrap rounds run after `ipc_reply` and before devmgr returns to
  its next `ipc_recv`. The spawn is at-most-once per boot; on failure (binary missing, ELF corrupt,
  hardware-carve failure, OOM, etc.) devmgr replies `devmgr_errors::NO_DEVICE` on subsequent
  `QUERY_RTC_DEVICE` / `QUERY_INPUT_DEVICE` calls and clients ([timed](../services/timed/README.md)
  degrades to its no-RTC path; the terminal, today's only `QUERY_INPUT_DEVICE` consumer, logs and
  exits). Keeping non-essentials out of the boot bundle keeps the ESP-loaded image to what the
  system needs before the rootfs is mounted, so on-disk loading is preferred for anything not on
  the read-the-disk-in-the-first-place critical path.

Storage-side cap delegation downstream of devmgr (whole-disk
endpoint → vfsd → partition-scoped endpoint → fs driver) is
specified in [`docs/storage.md`](storage.md).

---

## Summarized By

[Device Tree Parsing](../core/boot/docs/dtb.md),
[Firmware Parsing](../core/boot/docs/firmware-parsing.md), [Architecture Overview](architecture.md),
[Memory Model](memory-model.md), [Platform Requirements](platform-requirements.md),
[Storage](storage.md),
[devmgr Responsibilities and Capabilities](../services/devmgr/docs/responsibilities.md),
[services/drivers/README.md](../services/drivers/README.md),
[services/drivers/cmos/README.md](../services/drivers/cmos/README.md),
[services/drivers/goldfish-rtc/README.md](../services/drivers/goldfish-rtc/README.md),
[services/drivers/test-orphan/README.md](../services/drivers/test-orphan/README.md),
[services/drivers/virtio/blk/README.md](../services/drivers/virtio/blk/README.md),
[services/drivers/virtio/input/README.md](../services/drivers/virtio/input/README.md),
[init Bootstrap Stages](../services/init/docs/bootstrap.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md),
[services/vfsd/README.md](../services/vfsd/README.md)
