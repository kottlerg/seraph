# devmgr

Userspace device manager responsible for platform enumeration, hardware
discovery, and driver binding.

---

## Source Layout

```
devmgr/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs                     # Bootstrap, registry service loop, QUERY_* handlers
│   ├── caps.rs                     # Capability absorbers and device-info catalog
│   ├── firmware/                   # ACPI / DTB parsing helpers
│   ├── pci.rs                      # PCI ECAM enumeration + BAR splitting
│   └── spawn.rs                    # Driver-process spawn helpers (simple-device, virtio-blk, ...)
└── docs/
    ├── pci-enumeration.md          # PCI enumeration via ECAM MMIO
    └── hotplug.md                  # Hotplug event handling
```

---

## Responsibilities

devmgr is launched by init early in the bootstrap sequence. It is a privileged
service but holds only the capabilities init delegates to it — init retains
intermediary copies so that devmgr's authority can be revoked and re-delegated
on restart. The full design is specified in
[docs/device-management.md](../../docs/device-management.md); devmgr's
responsibilities are:

- **Parse firmware tables** — read ACPI tables (x86-64) or Device Tree blob
  (RISC-V) from read-only memory capabilities to resolve interrupt routing,
  power domains, and the PCI hierarchy.
- **Enumerate PCI devices** — reserve VA, fund the AS's page-table growth
  budget via `fund_aspace_pt_budget`, then map the ECAM MMIO region via
  `mmio_map`, read configuration space, discover devices and BARs, resolve
  interrupt assignments. See
  [`docs/pci-enumeration.md`](docs/pci-enumeration.md).
- **Bind drivers** — match discovered devices to driver binaries in
  [`drivers/`](../drivers/README.md), request procmgr to create driver
  processes, and delegate per-device capabilities (MMIO, interrupt, and
  IoPort where applicable). PCI devices spawn through the
  BAR/IRQ-shaped path; fixed-location platform devices (the serial
  UART, the platform RTC chip — `cmos-rtc` on x86-64, `goldfish-rtc`
  on RISC-V) spawn through a simpler path that delivers a service
  endpoint and one arch authority cap (`IoPort` for COM1 and
  CMOS, `Mmio` for an NS16550 or the goldfish RTC at `0x101000`).
  Drivers that need physical-base addresses for device DMA
  programming obtain them from memmgr's `REQUEST_MEMORY_CAPS` reply alongside
  the Memory caps; DMA isolation, when established, is programmed by devmgr
  through IOMMU hardware it acquires via the `Mmio` cap flow.

  Driver binaries are sourced from one of two places:

  - **Boot bundle** — bootstrap-essentials (virtio-blk, serial,
    framebuffer) arrive as `procmgr_labels::CREATE_PROCESS`-ready Memory
    caps in devmgr's MODULE bootstrap round. devmgr spawns these
    during initial enumeration, before the registry loop opens.
  - **On-disk rootfs** — non-essential drivers (today: the per-arch
    RTC) live at `/services/drivers/<chip>` and are loaded via
    `procmgr_labels::CREATE_FROM_FILE`. Init delivers a
    `LOOKUP | READ`-attenuated `/services/drivers/` subtree cap via
    `devmgr_labels::SET_DRIVERS_DIR` post-vfsd-mount; devmgr replies
    SUCCESS immediately (so init never blocks on driver work), then
    walks the per-arch driver name and spawns the driver between
    `ipc_reply` and the next `ipc_recv`. At-most-once per boot; failure
    is sticky and surfaced as `devmgr_errors::NO_DEVICE` on subsequent
    queries.
- **Expose device registry** — maintain an IPC service that other services
  query to discover device endpoints after drivers are bound: vfsd resolves
  the block device (`QUERY_BLOCK_DEVICE`), logd resolves the serial driver
  (`QUERY_SERIAL_DEVICE`), `programs/fb-charset` resolves the framebuffer
  driver (`QUERY_FRAMEBUFFER_DEVICE`), timed resolves the platform RTC
  (`QUERY_RTC_DEVICE`), and netd in due course. devmgr owns each driver's
  service endpoint and mints a badged SEND on query.
- **Broker ACPI and shutdown hardware to pwrmgr** — devmgr is the sole
  owner of the ACPI Memory caps and the only service that walks the ACPI
  table tree (RSDP → XSDT). `QUERY_ACPI_TABLE` locates a table by
  signature or physical address and serves a read-only view of it (devmgr
  reads only the directory and table headers, never a table body).
  `QUERY_SHUTDOWN_DEVICE` carves the shutdown-actuator caps pwrmgr asks
  for — a narrow `IoPort` over the PM1a control and 8042 reset ports
  on x86-64 (the port pwrmgr computed from the FADT), or a `cap_derive`
  copy of `SbiControl` on RISC-V. devmgr runs no shutdown logic; it brokers
  the hardware, pwrmgr interprets and actuates. Both are gated on
  `REGISTRY_QUERY_AUTHORITY`.
- **Handle hotplug** — on platforms that support it, receive hotplug
  notifications and dynamically spawn or terminate driver processes. See
  [`docs/hotplug.md`](docs/hotplug.md).

---

## Capabilities Received

devmgr receives the following capabilities from init during bootstrap. See
[docs/capability-model.md](../../docs/capability-model.md) for capability type
definitions and [docs/device-management.md](../../docs/device-management.md) for
how devmgr uses them.

| Capability | Rights | Purpose |
|---|---|---|
| MMIO Region (per platform resource) | Map | Map device register regions into driver address spaces |
| Interrupt (per IRQ line) | — | Delegate to drivers for hardware interrupt delivery |
| IoPort (x86-64, root) | Use / carve | Carve narrow per-driver port caps (CMOS, COM1) and pwrmgr's PM1a + 8042 reset ports |
| SbiControl (RISC-V, Reset + Suspend) | Reset / Suspend | Steady-state holder of the platform power-state SBI authority (init is reaped); broker a Reset-only copy to pwrmgr for SBI SRST shutdown / reboot. Suspend held for a future power path |
| Memory (firmware tables) | Map (read-only) | Parse ACPI RSDP / Device Tree blob (incl. IOMMU topology: DMAR on x86-64, `iommu` / `iommu-map` on RISC-V); broker read-only ACPI tables to pwrmgr via `QUERY_ACPI_TABLE` |
| SchedControl (baseline, via `ProcessInfo`) | band `[1, 20]` | Set driver/thread priorities within the baseline band. Like every process, devmgr receives this from procmgr (`ProcessInfo.sched_control_cap`), not the init bootstrap rounds; elevated bands for latency-sensitive drivers require an explicit init grant (not currently wired) |

IOMMU register regions are not pre-minted as distinct capabilities.
`devmgr` discovers IOMMU units from the firmware passthrough (DMAR or
DTB) and acquires MMIO-region caps for their register ranges through
the same `Mmio` flow as any other device.

---

## Relationship to drivers/

devmgr is the sole authority for spawning and supervising device drivers.
After discovering a device, devmgr requests procmgr to create the driver
process and then delegates the per-device capability set via IPC. Drivers
MUST NOT be started independently of devmgr. See
[`drivers/README.md`](../drivers/README.md) for the driver model.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../docs/device-management.md) | Full device management design, DMA safety, security boundary |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, rights, delegation, revocation |
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, service roles |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, device registry endpoint |
| [abi/boot-protocol/](../../abi/boot-protocol/) | Platform resource descriptors, firmware table passthrough |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

[docs/device-management.md](../../docs/device-management.md), [docs/storage.md](../../docs/storage.md)
