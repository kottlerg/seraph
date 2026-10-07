# devmgr Responsibilities and Capabilities

The responsibilities devmgr carries, the capabilities it receives at bootstrap, and its
authority over driver processes.

---

## Responsibilities

devmgr is launched by init early in the bootstrap sequence. It is a privileged service whose
hardware, platform, and scheduling authority is only what it receives at bootstrap (from init,
plus the SchedControl band procmgr delivers) and the `/services/drivers/` cap svcmgr sends after
handover. Init exits after handover, and devmgr is `restart = never`, `critical = yes`, so its
death triggers a graceful shutdown rather than re-delegation (see
[docs/device-management.md § Security boundary](../../../docs/device-management.md#security-boundary)).
The full design is specified in [docs/device-management.md](../../../docs/device-management.md);
devmgr's responsibilities are:

- **Parse firmware tables** — locate the PCI ECAM, from read-only memory
  capabilities, through the ACPI MCFG table (RSDP → XSDT → MCFG; preferred on
  either architecture whenever an RSDP is present) or, as the fallback, the
  Device Tree blob's `pci-host-ecam-generic` node; and serve ACPI tables to
  pwrmgr (below). devmgr derives per-device interrupt lines from PCI
  configuration space; resolving interrupt routing and power domains from
  firmware tables is design intent; not yet implemented.
- **Enumerate PCI devices** — reserve VA, fund the AS's page-table growth
  budget via `fund_aspace_pt_budget`, then map the ECAM MMIO region via
  `mmio_map`, read configuration space, discover devices and BARs, resolve
  interrupt assignments. See
  [`docs/pci-enumeration.md`](pci-enumeration.md).
- **Bind drivers** — match discovered devices to driver binaries in
  [`drivers/`](../../drivers/README.md), request procmgr to create driver
  processes, and delegate per-device capabilities (MMIO, interrupt, and
  IoPort where applicable). PCI devices spawn through the
  BAR/IRQ-shaped path; fixed-location platform devices (the serial
  UART, the platform RTC chip — `cmos-rtc` on x86-64, `goldfish-rtc`
  on RISC-V) spawn through a simpler path that delivers a service
  endpoint and one arch authority cap (`IoPort` for COM1 and
  CMOS, `Mmio` for an NS16550 or the goldfish RTC at `0x101000`).
  Drivers that need physical-base addresses for device DMA
  programming obtain them from memmgr's `REQUEST_MEMORY_CAPS` reply alongside
  the Memory caps. No IOMMU support exists, so every DMA-capable driver runs
  DMA-unsafe today; DMA isolation programmed by devmgr through IOMMU hardware
  it acquires via the `Mmio` cap flow is design intent; not yet implemented
  (see
  [docs/device-management.md § IOMMU Discovery and Programming](../../../docs/device-management.md#iommu-discovery-and-programming)).

  Driver binaries are sourced from one of two places:

  - **Boot bundle** — bootstrap-essentials (virtio-blk, serial,
    framebuffer) arrive as `procmgr_labels::CREATE_PROCESS`-ready Memory
    caps in devmgr's MODULE bootstrap round. devmgr spawns these
    during initial enumeration, before the registry loop opens.
  - **On-disk rootfs** — non-essential drivers (the per-arch RTC and
    virtio-input) live at `/services/drivers/<driver>` and are loaded via
    `procmgr_labels::CREATE_FROM_FILE`. virtio-input is PCI-enumerated at
    boot, with its BAR and IRQ caps carved then and its spawn deferred to
    this path. svcmgr delivers a `LOOKUP | READ`-attenuated
    `/services/drivers/` subtree cap via `devmgr_labels::SET_DRIVERS_DIR`
    after handover (gated by `DRIVERS_DIR_AUTHORITY`); devmgr replies
    SUCCESS immediately (so svcmgr never blocks on driver work), then walks
    to each driver's binary and spawns it between `ipc_reply` and the next
    `ipc_recv`. Each spawn is at-most-once per boot; failure is sticky and
    surfaced as `devmgr_errors::NO_DEVICE` on subsequent `QUERY_RTC_DEVICE`
    and `QUERY_INPUT_DEVICE` queries. See
    [docs/device-management.md § Driver binary sources](../../../docs/device-management.md#driver-binary-sources).
- **Expose device registry** — maintain an IPC service that other services
  query to discover device endpoints after drivers are bound: vfsd resolves
  the block device (`QUERY_BLOCK_DEVICE`), logd resolves the serial driver
  (`QUERY_SERIAL_DEVICE`), `programs/terminal` resolves the framebuffer and
  input drivers (`QUERY_FRAMEBUFFER_DEVICE` / `QUERY_INPUT_DEVICE`), timed
  resolves the platform RTC (`QUERY_RTC_DEVICE`), and netd (design intent; not
  yet implemented, #30). devmgr owns each driver's service endpoint and mints a
  badged SEND on query.
- **Broker ACPI and shutdown hardware to pwrmgr** — devmgr is the sole
  owner of the ACPI Memory caps and the only service that walks the ACPI
  table tree (RSDP → XSDT). `QUERY_ACPI_TABLE` locates a table by
  signature or physical address and serves a read-only view of it (devmgr
  reads only the directory and table headers, never a table body).
  `QUERY_SHUTDOWN_DEVICE` carves the shutdown-actuator caps pwrmgr asks
  for — two narrow `IoPort` caps on x86-64, one over the PM1a control port
  (the port pwrmgr computed from the FADT) and one over the 8042 reset port,
  or a `cap_derive` copy of `SbiControl` on RISC-V. The caps are re-derived
  from devmgr's root caps on every call, so nothing is consumed and a
  restarted pwrmgr re-acquires them cleanly. devmgr runs no shutdown logic;
  it brokers the hardware, pwrmgr interprets and actuates. Both are gated on
  `REGISTRY_QUERY_AUTHORITY`.
- **Handle hotplug** (design intent; not yet implemented) — on platforms that support it,
  receive hotplug notifications and dynamically spawn or terminate driver processes. See
  [`docs/hotplug.md`](hotplug.md).

---

## Capabilities Received

devmgr receives the following capabilities during bootstrap. Init delivers them over
the bootstrap protocol in rounds. Round 1 carries the registry endpoint, then whichever
of the Interrupt range, RSDP, and DTB caps are present, with a presence bitmap, the
RSDP and DTB page bases, and the DTB size in its data words. Each later round names
its kind in `data[0]`: `APERTURE` and `ACPI_REGION` rounds carry up to four Memory
caps each with their base/size pairs; one `MODULE` round carries the boot-bundle
driver images, each tagged with its module class; a cap-less `FRAMEBUFFER_INFO`
round carries the framebuffer geometry (a zero base means no framebuffer); and the
terminal `SVCMGR_BUNDLE` round carries the svcmgr publish cap and the arch
shutdown-authority cap (root `IoPort` on x86-64, `SbiControl` on RISC-V). Init's
side of the transfer is summarized in
[services/init/docs/bootstrap.md § Per-stage authority transfers](../../init/docs/bootstrap.md#per-stage-authority-transfers).
See [docs/capability-model.md](../../../docs/capability-model.md) for capability type
definitions and [docs/device-management.md](../../../docs/device-management.md) for
how devmgr uses them.

| Capability | Rights | Purpose |
|---|---|---|
| Endpoint (devmgr registry, round 1 `caps[0]`) | `RIGHTS_ALL` (incl. Recv, Send, Grant) | Service endpoint for the device-registry IPC: devmgr serves every `QUERY_*` request (`QUERY_*_DEVICE`, `QUERY_DEVICE_INFO`, `QUERY_ACPI_TABLE`, `QUERY_SHUTDOWN_DEVICE`) and `SET_DRIVERS_DIR` on it, and mints from it the badged SENDs drivers use for `QUERY_DEVICE_INFO` |
| Mmio (one per boot-provided aperture) | Map, Write | Split per device into BAR / register sub-caps for drivers |
| Interrupt (root IRQ range) | Notify | Split with `SYS_IRQ_SPLIT` into per-line Interrupt caps delegated to drivers |
| IoPort (x86-64, root) | Use / carve | Carve narrow per-driver port caps (CMOS, COM1) and pwrmgr's PM1a + 8042 reset ports |
| SbiControl (RISC-V, Reset + Suspend) | Reset / Suspend | Steady-state holder of the platform power-state SBI authority (init is reaped); broker a Reset-only copy to pwrmgr for SBI SRST shutdown / reboot. Suspend held for a future power path |
| Memory (firmware tables) | Map (read-only) | Parse ACPI RSDP / Device Tree blob; broker read-only ACPI tables to pwrmgr via `QUERY_ACPI_TABLE`. Parsing IOMMU topology (DMAR on x86-64, `iommu` / `iommu-map` on RISC-V) is design intent; not yet implemented |
| Memory (driver modules, MODULE round) | As held by init | Boot-bundle driver images (virtio-blk, serial, framebuffer) spawned via `procmgr_labels::CREATE_PROCESS` |
| svcmgr publish authority (Endpoint, SVCMGR_BUNDLE round) | Send, Grant (`PUBLISH_AUTHORITY` badge) | Register service caps in svcmgr's registry; held but unused today, reserved for future devmgr publications |
| SchedControl (baseline, via `ProcessInfo`) | band `[1, 26]` (`sched_policy::DEVMGR_BAND_MAX`) | Place spawned drivers at their assigned levels (serial/virtio-blk at 26, framebuffer/RTC/virtio-input at 25 — the `CREATE_PRIORITY` field of each driver spawn) and set devmgr's own threads' priorities. Like every process, devmgr receives this from procmgr (`ProcessInfo.sched_control_cap`); init requests the deliberately-elevated ceiling (above devmgr's own level 24) via the create label's `CREATE_BAND_MAX` field |

IOMMU register regions are not pre-minted as distinct capabilities.
Design intent; not yet implemented: `devmgr` will discover IOMMU units
from the firmware passthrough (DMAR or DTB) and acquire `Mmio` caps for
their register ranges through the same aperture-carving flow as any
other device (see
[docs/device-management.md § IOMMU Discovery and Programming](../../../docs/device-management.md#iommu-discovery-and-programming)).

---

## Relationship to drivers

devmgr is the sole authority for spawning device drivers; supervising (restarting) them
is design intent; not yet implemented (#17, #262). After discovering a device, devmgr
requests procmgr to create the driver process and then delegates the per-device
capability set via IPC. Drivers MUST NOT be started independently of devmgr. See
[`drivers/README.md`](../../drivers/README.md) for the driver model.

---

## Summarized By

[Device Tree Parsing](../../../core/boot/docs/dtb.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md), [services/devmgr/README.md](../README.md),
[services/drivers/README.md](../../drivers/README.md),
[services/drivers/cmos/README.md](../../drivers/cmos/README.md),
[Driver Model](../../drivers/docs/driver-model.md),
[services/drivers/framebuffer/README.md](../../drivers/framebuffer/README.md),
[services/drivers/goldfish-rtc/README.md](../../drivers/goldfish-rtc/README.md),
[services/drivers/serial/README.md](../../drivers/serial/README.md),
[services/drivers/virtio/input/README.md](../../drivers/virtio/input/README.md),
[services/init/README.md](../../init/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md),
[Restart Protocol](../../svcmgr/docs/restart-protocol.md)
