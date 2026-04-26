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
│   └── main.rs                     # Entry point (stub)
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
  (RISC-V) from read-only frame capabilities to resolve interrupt routing,
  power domains, and the PCI hierarchy.
- **Enumerate PCI devices** — map the ECAM MMIO region, read configuration
  space, discover devices and BARs, resolve interrupt assignments. See
  [`docs/pci-enumeration.md`](docs/pci-enumeration.md).
- **Bind drivers** — match discovered devices to driver binaries in
  [`drivers/`](../drivers/README.md), request procmgr to create driver
  processes, and delegate per-device capabilities (MMIO, interrupt, and
  IoPortRange where applicable). Drivers that need physical-base
  addresses for device DMA programming obtain them from memmgr's
  `REQUEST_FRAMES` reply alongside the Frame caps; DMA isolation, when
  established, is programmed by devmgr through IOMMU hardware it
  acquires via the `MmioRegion` cap flow.
- **Expose device registry** — maintain an IPC service that other services
  (vfsd, netd) query to discover device endpoints after drivers are bound.
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
| IoPortRange (x86-64, per range) | Use | Delegate to drivers requiring port I/O |
| Frame (firmware tables) | Map (read-only) | Parse ACPI RSDP / Device Tree blob, including full IOMMU topology (DMAR on x86-64, `iommu` / `iommu-map` on RISC-V) |
| SchedControl | Elevate | Assign elevated priorities to latency-sensitive drivers |

IOMMU register regions are not pre-minted as distinct capabilities.
`devmgr` discovers IOMMU units from the firmware passthrough (DMAR or
DTB) and acquires MMIO-region caps for their register ranges through
the same `MmioRegion` flow as any other device.

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

None
