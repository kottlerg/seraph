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
    ├── responsibilities.md         # Responsibilities, bootstrap capabilities, driver authority
    ├── pci-enumeration.md          # PCI enumeration via ECAM MMIO
    └── hotplug.md                  # Hotplug event handling
```

---

## Responsibilities

devmgr parses firmware tables, enumerates PCI devices, binds and spawns drivers, exposes the
device registry, and brokers ACPI and shutdown hardware to pwrmgr (hotplug handling is design
intent; not yet implemented); it is the sole authority for spawning device drivers. Each
responsibility, the capabilities devmgr receives at bootstrap, and its relationship to driver
processes are specified in [docs/responsibilities.md](docs/responsibilities.md); the
system-scope design is [docs/device-management.md](../../docs/device-management.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/responsibilities.md](docs/responsibilities.md) | Responsibilities, bootstrap capabilities, authority over drivers |
| [docs/pci-enumeration.md](docs/pci-enumeration.md) | PCI enumeration via ECAM MMIO |
| [docs/hotplug.md](docs/hotplug.md) | Hotplug event handling |
| [docs/device-management.md](../../docs/device-management.md) | Full device management design, DMA safety, security boundary |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, rights, delegation, revocation |
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, service roles |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, device registry endpoint |
| [abi/boot-protocol/](../../abi/boot-protocol/) | Platform resource descriptors, firmware table passthrough |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
