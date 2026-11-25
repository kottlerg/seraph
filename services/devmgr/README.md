# devmgr

Userspace device manager responsible for platform enumeration, hardware
discovery, and driver binding.

---

## Source Layout

```
devmgr/
├── Cargo.toml
├── README.md
├── firmware/                       # `devmgr-firmware`: host-tested ACPI / DTB interpretations
│                                   #   (over `shared/firmware-tables`' formats), PCI scan,
│                                   #   aperture / IRQ range-cap table, driver-settle roster,
│                                   #   served-driver ordinal table (tombstones),
│                                   #   class watcher lists,
│                                   #   held interrupt-line table, DMA mapping table and
│                                   #   IOVA allocator, DMA Remapping table (VT-d units,
│                                   #   scopes, RMRRs), RISC-V IO Mapping Table (PCI
│                                   #   IOMMUs, ID mappings), driver-declaration binding
│                                   #   (PCI identity keys, match ranking, declaration
│                                   #   bounds), the served-class table, bounded image reads,
│                                   #   the AML `Device` walker (on `shared/aml`'s encodings
│                                   #   and resource-template decoder), platform device
│                                   #   records, the platform description table parser,
│                                   #   PCI device records (states, appends, INTx routes),
│                                   #   acpid's side (region policy, configuration access,
│                                   #   per-bridge results), PCI Express hotplug (slots,
│                                   #   control grant, poller decisions, BAR placement),
│                                   #   the driver restart policy, the firmware-table
│                                   #   decoders' fuzz property (`src/property/`) and its
│                                   #   checked-in inputs (`fuzz/devmgr-firmware/`)
├── platform/                       # Platform description tables, one `<machine>.platform` each
├── src/
│   ├── main.rs                     # Bootstrap, the registry's workers and control thread,
│   │                               #   class SEND handlers (QUERY_DEVICE, WATCH_CLASS,
│   │                               #   DECLINE_RESTART, QUERY_DEVICE_LOCATION), device catalog
│   ├── acpi.rs                     # acpid's requests: region grants, configuration access, pushes
│   ├── arch/                       # Arch dispatch: ECAM/INTx defaults, port carves, shutdown
│   │   ├── mod.rs                  # `arch::current` re-export (the only cfg(target_arch) site)
│   │   ├── x86_64/mod.rs           # IoPort carves (platform records, FADT blocks); no ECAM default
│   │   └── riscv64/mod.rs          # QEMU virt ECAM default; SbiControl
│   ├── bind.rs                     # Binding PCI and platform records to matching driver
│   │                               #   declarations; withdrawal of a bound driver
│   ├── caps.rs                     # Bootstrap-round capability absorbers, DevmgrCaps, and the
│   │                               #   firmware-table caps the registry's workers share
│   ├── decls.rs                    # Driver declarations read from boot modules and the drivers
│   │                               #   directory
│   ├── dma.rs                      # DMA endpoint and its thread: per-device DMA caps, map/unmap
│   ├── headroom.rs                 # devmgr's own CSpace held above its low-water mark
│   ├── hotplug.rs                  # PCI Express hotplug: managed slots, poller, acpid's jobs,
│   │                               #   add and removal jobs
│   ├── intremap.rs                 # VT-d interrupt remapping: enable, per-source remapping entries
│   ├── iommu.rs                    # IOMMU units, driver spawn/restart, attach, fail-closed client
│   ├── pci.rs                      # ECAM configuration-space accessor for the PCI scan
│   ├── phys.rs                     # Physical-address credential (a memmgr page with `Phys`)
│   ├── platform.rs                 # Platform enumerators: boot framebuffer, ACPI namespace, SPCR,
│   │                               #   platform description table
│   ├── settle.rs                   # Driver death watch and job notification; batch settle:
│   │                               #   ready, deaths, bound
│   ├── spawn.rs                    # Driver-process spawn helpers (bound, IOMMU)
│   └── tables.rs                   # Firmware-table mapping: ECAM discovery, ACPI table lookup
└── docs/
    ├── responsibilities.md         # Responsibilities, bootstrap capabilities, CSpace headroom,
    │                               #   driver authority
    ├── pci-enumeration.md          # PCI enumeration via ECAM MMIO
    └── hotplug.md                  # Hotplug event sources, native and ACPI slots, add, removal
```

---

## Responsibilities

devmgr parses firmware tables, enumerates PCI devices, binds and spawns drivers, exposes the device
registry, brokers ACPI tables to acpid and the RISC-V shutdown cap to pwrmgr, and adds the functions
a card brings to a PCI Express hotplug slot, one it controls natively or one whose firmware's events
acpid posts, and withdraws and removes them when the card leaves; it is the sole authority for
spawning device drivers, and restarts a served driver that dies. Each responsibility, the
capabilities devmgr receives at bootstrap, and its relationship to driver processes are specified in
[docs/responsibilities.md](docs/responsibilities.md); the system-scope design is
[docs/device-management.md](../../docs/device-management.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/responsibilities.md](docs/responsibilities.md) | Responsibilities, bootstrap capabilities, CSpace headroom, authority over drivers |
| [docs/pci-enumeration.md](docs/pci-enumeration.md) | PCI enumeration via ECAM MMIO |
| [docs/hotplug.md](docs/hotplug.md) | Hotplug event sources, native and ACPI hotplug slots, the add and removal paths |
| [docs/device-management.md](../../docs/device-management.md) | Full device management design, DMA safety, security boundary |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, rights, delegation, revocation |
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, service roles |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, device registry endpoint |
| [abi/boot-protocol/](../../abi/boot-protocol/) | Platform resource descriptors, firmware table passthrough |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
