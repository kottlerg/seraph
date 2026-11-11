# devmgr

Userspace device manager responsible for platform enumeration, hardware
discovery, and driver binding.

---

## Source Layout

```
devmgr/
├── Cargo.toml
├── README.md
├── firmware/                       # `devmgr-firmware`: host-tested ACPI / DTB parsers, PCI scan,
│                                   #   aperture / IRQ range-cap table, driver-settle roster,
│                                   #   served-driver ordinal table (tombstones),
│                                   #   held interrupt-line table, DMA mapping table and
│                                   #   IOVA allocator, DMA Remapping table (VT-d units,
│                                   #   scopes, RMRRs), RISC-V IO Mapping Table (PCI
│                                   #   IOMMUs, ID mappings), driver-declaration binding
│                                   #   (PCI identity keys, match ranking, declaration
│                                   #   bounds), the served-class table, bounded image reads
├── src/
│   ├── main.rs                     # Bootstrap, registry loop, QUERY_* handlers, device catalog
│   ├── arch/                       # Arch dispatch: ECAM/INTx defaults, UART/RTC carves, shutdown
│   │   ├── mod.rs                  # `arch::current` re-export (the only cfg(target_arch) site)
│   │   ├── x86_64/mod.rs           # IoPort carves (COM1, CMOS, PM1a + 8042); no ECAM default
│   │   └── riscv64/mod.rs          # QEMU virt windows (ECAM, NS16550, goldfish-RTC); SbiControl
│   ├── bind.rs                     # Binding PCI records to matching driver declarations;
│   │                               #   withdrawal of a bound driver
│   ├── caps.rs                     # Bootstrap-round capability absorbers and DevmgrCaps
│   ├── decls.rs                    # Driver declarations read from boot modules and the drivers
│   │                               #   directory
│   ├── dma.rs                      # DMA endpoint and its thread: per-device DMA caps, map/unmap
│   ├── iommu.rs                    # IOMMU units, driver spawn, device attach, fail-closed client
│   ├── pci.rs                      # ECAM configuration-space accessor for the PCI scan
│   ├── phys.rs                     # Physical-address credential (a memmgr page with `Phys`)
│   ├── settle.rs                   # Driver death watch; batch settle: ready, deaths, bound
│   ├── spawn.rs                    # Driver-process spawn helpers (bound, simple, IOMMU)
│   └── tables.rs                   # Firmware-table mapping: ECAM discovery, ACPI table lookup
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
