# devmgr Responsibilities and Capabilities

The responsibilities devmgr carries, the capabilities it receives at bootstrap, and its
authority over driver processes.

---

## Responsibilities

devmgr is launched by init early in the bootstrap sequence. It is a privileged
service but holds only the capabilities init delegates to it at bootstrap. Init
exits after handover, and devmgr is `restart = never`, `critical = yes`, so its
death triggers a graceful shutdown rather than re-delegation (see
[docs/device-management.md § Security boundary](../../../docs/device-management.md#security-boundary)).
The full design is specified in
[docs/device-management.md](../../../docs/device-management.md); devmgr's
responsibilities are:

- **Parse firmware tables** — read ACPI tables (x86-64) or Device Tree blob
  (RISC-V) from read-only memory capabilities to resolve interrupt routing,
  power domains, and the PCI hierarchy.
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
  - **On-disk rootfs** — non-essential drivers (today: the per-arch
    RTC) live at `/services/drivers/<chip>` and are loaded via
    `procmgr_labels::CREATE_FROM_FILE`. svcmgr delivers a
    `LOOKUP | READ`-attenuated `/services/drivers/` subtree cap via
    `devmgr_labels::SET_DRIVERS_DIR` after handover (gated by
    `DRIVERS_DIR_AUTHORITY`); devmgr replies SUCCESS immediately (so
    svcmgr never blocks on driver work), then walks the per-arch driver
    name and spawns the driver between `ipc_reply` and the next
    `ipc_recv`. At-most-once per boot; failure is sticky and surfaced as
    `devmgr_errors::NO_DEVICE` on subsequent queries. See
    [docs/device-management.md § Driver binary sources](../../../docs/device-management.md#driver-binary-sources).
- **Expose device registry** — maintain an IPC service that other services
  query to discover device endpoints after drivers are bound: vfsd resolves
  the block device (`QUERY_BLOCK_DEVICE`), logd resolves the serial driver
  (`QUERY_SERIAL_DEVICE`), `programs/terminal` resolves the framebuffer and
  input drivers (`QUERY_FRAMEBUFFER_DEVICE` / `QUERY_INPUT_DEVICE`), timed
  resolves the platform RTC (`QUERY_RTC_DEVICE`), and netd in due course.
  devmgr owns each driver's service endpoint and mints a badged SEND on query.
- **Broker ACPI and shutdown hardware to pwrmgr** — devmgr is the sole
  owner of the ACPI Memory caps and the only service that walks the ACPI
  table tree (RSDP → XSDT). `QUERY_ACPI_TABLE` locates a table by
  signature or physical address and serves a read-only view of it (devmgr
  reads only the directory and table headers, never a table body).
  `QUERY_SHUTDOWN_DEVICE` carves the shutdown-actuator caps pwrmgr asks
  for — a narrow `IoPort` over the PM1a control and 8042 reset ports
  on x86-64 (the port pwrmgr computed from the FADT), or a `cap_derive`
  copy of `SbiControl` on RISC-V. The caps are re-derived from devmgr's root caps on
  every call, so nothing is consumed and a restarted pwrmgr re-acquires them
  cleanly. devmgr runs no shutdown logic; it brokers the hardware, pwrmgr
  interprets and actuates. Both are gated on `REGISTRY_QUERY_AUTHORITY`.
- **Handle hotplug** — on platforms that support it, receive hotplug
  notifications and dynamically spawn or terminate driver processes. See
  [`docs/hotplug.md`](hotplug.md).

---

## Capabilities Received

devmgr receives the following capabilities during bootstrap (the per-round init
delivery is specified in [services/init/docs/bootstrap.md](../../init/docs/bootstrap.md)
§ Per-stage authority transfers). See
[docs/capability-model.md](../../../docs/capability-model.md) for capability type
definitions and [docs/device-management.md](../../../docs/device-management.md) for
how devmgr uses them.

| Capability | Rights | Purpose |
|---|---|---|
| Mmio (one per boot-provided aperture) | Map, Write | Split per device into BAR / register sub-caps for drivers |
| Interrupt (root IRQ range) | Notify | Split with `SYS_IRQ_SPLIT` into per-line Interrupt caps delegated to drivers |
| IoPort (x86-64, root) | Use / carve | Carve narrow per-driver port caps (CMOS, COM1) and pwrmgr's PM1a + 8042 reset ports |
| SbiControl (RISC-V, Reset + Suspend) | Reset / Suspend | Steady-state holder of the platform power-state SBI authority (init is reaped); broker a Reset-only copy to pwrmgr for SBI SRST shutdown / reboot. Suspend held for a future power path |
| Memory (firmware tables) | Map (read-only) | Parse ACPI RSDP / Device Tree blob; broker read-only ACPI tables to pwrmgr via `QUERY_ACPI_TABLE`. Parsing IOMMU topology (DMAR on x86-64, `iommu` / `iommu-map` on RISC-V) is design intent; not yet implemented |
| Memory (driver modules, MODULE rounds) | As held by init | Boot-bundle driver images (virtio-blk, serial, framebuffer) spawned via `procmgr_labels::CREATE_PROCESS` |
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

[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md), [services/devmgr/README.md](../README.md),
[services/drivers/README.md](../../drivers/README.md),
[Driver Model](../../drivers/docs/driver-model.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md)
