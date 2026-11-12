# drivers

Userspace device drivers, each running as an isolated process with per-device
capabilities delegated by devmgr.

---

## Source Layout

```
services/drivers/
├── README.md
├── cmos/                           # x86-64 CMOS / MC146818 RTC driver (binary + lib)
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       ├── lib.rs                  # CMOS register snapshot (host-tested)
│       └── main.rs
├── framebuffer/                    # Linear-framebuffer text driver (binary + lib)
│   ├── Cargo.toml
│   ├── README.md                   # Framebuffer IPC interface (FB_WRITE_BYTES, FB_SET_ATTRS)
│   └── src/
│       ├── authority.rs            # WRITE_AUTHORITY verb-bit gate (host-tested)
│       ├── lib.rs                  # Library root exposing authority and render (host-tested)
│       ├── main.rs
│       ├── render.rs               # 9×20 bitmap glyph blit + cursor + scroll
│       └── arch/                   # Per-arch MMIO mapping (x86_64 / riscv64)
├── goldfish-rtc/                   # RISC-V Goldfish RTC driver (binary)
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       └── main.rs
├── iommu/
│   ├── core/                       # Family-independent IOMMU driver logic (library)
│   │   ├── Cargo.toml
│   │   ├── README.md
│   │   └── src/
│   │       ├── lib.rs              # The Backend trait each family implements
│   │       ├── bootstrap.rs        # Unit rounds and scopes (host-tested)
│   │       ├── faults.rs           # Polled fault queue (host-tested)
│   │       ├── service.rs          # iommu_labels service, domain records (host-tested)
│   │       └── table.rs            # The TableStore the family tables are built in
│   ├── riscv/                      # RISC-V IOMMU driver for devmgr (binary + lib; riscv64)
│   │   ├── Cargo.toml
│   │   ├── README.md
│   │   └── src/
│   │       ├── lib.rs              # Register, command, and table logic (host-tested)
│   │       ├── regs.rs             # Registers, commands, fault records
│   │       ├── tables.rs           # Device directory, device context, first-stage tables
│   │       ├── main.rs
│   │       └── backend.rs          # The RISC-V IOMMU Backend
│   ├── store/                      # Table pages from memmgr, for both drivers (library)
│   │   ├── Cargo.toml
│   │   ├── README.md
│   │   └── src/
│   │       └── lib.rs
│   └── vtd/                        # VT-d IOMMU driver for devmgr (binary + lib; x86-64)
│       ├── Cargo.toml
│       ├── README.md
│       └── src/
│           ├── lib.rs              # Register and table logic (host-tested)
│           ├── regs.rs             # Register offsets and fields
│           ├── tables.rs           # Root, context, and second-level tables
│           ├── main.rs
│           ├── backend.rs          # The VT-d Backend
│           └── arch/               # Cache-line flushing (x86_64)
├── serial/                         # Serial (UART) device driver (binary)
│   ├── Cargo.toml
│   ├── README.md                   # Serial-driver IPC interface (SERIAL_WRITE_BYTES)
│   └── src/
│       ├── main.rs
│       └── arch/                   # Per-arch UART access (x86_64 COM1, riscv64 NS16550)
├── test-dma/                       # Test-only driver for QEMU's edu DMA device (binary)
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       └── main.rs
├── test-fault/                     # Test-only fault-injection driver for devmgr settle (binary)
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       └── main.rs
├── virtio/
│   ├── core/                       # Shared VirtIO transport and queue primitives (library)
│   │   ├── Cargo.toml
│   │   ├── README.md
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── pci.rs              # Modern PCI transport register access
│   │       └── virtqueue.rs        # Split virtqueue rings and descriptors
│   ├── blk/                        # VirtIO block device driver (binary + lib)
│   │   ├── Cargo.toml
│   │   ├── README.md               # Block-driver IPC interface
│   │   │                           #   (BLK_READ_INTO_MEMORY, REGISTER_PARTITION)
│   │   └── src/
│   │       ├── lib.rs              # Request-length and reply-label logic (host-tested)
│   │       ├── main.rs
│   │       └── io.rs
│   ├── input/                      # VirtIO input (keyboard) device driver (binary + lib)
│   │   ├── Cargo.toml
│   │   ├── README.md               # Input-driver IPC interface (INPUT_READ_EVENTS)
│   │   └── src/
│   │       ├── lib.rs              # READ_AUTHORITY verb-bit gate (host-tested)
│   │       ├── main.rs
│   │       ├── input.rs            # Event virtqueue receive-buffer ring
│   │       └── decode.rs           # Keycode → keysym tables + modifier state
│   └── console/                    # VirtIO console driver: the debug port (binary + lib)
│       ├── Cargo.toml
│       ├── README.md               # Debug-port binding, serial protocol, queues
│       └── src/
│           ├── lib.rs              # Serial verb-bit gate, received-byte queue (host-tested)
│           └── main.rs
└── docs/
    ├── driver-model.md             # Driver lifecycle and capability delegation
    └── virtio-architecture.md      # VirtIO transport abstraction and queue internals
```

---

## Driver Model

Each driver is a separate userspace process with its own address space. Drivers
receive only the capabilities for the specific device they manage (see
[docs/architecture.md](../../docs/architecture.md)); device DMA is confined to what
their driver mapped where an IOMMU translates the device (VT-d on x86-64), and
unconfined elsewhere (see
[docs/device-management.md](../../docs/device-management.md#dma-safety-model)).
The full driver lifecycle is specified in
[docs/device-management.md](../../docs/device-management.md); the key points are:

- **Isolation** — every driver runs in its own address space. A driver crash
  cannot corrupt another driver's or the kernel's memory through the CPU, nor
  through its device's DMA where an IOMMU confines the device (see
  [docs/device-management.md](../../docs/device-management.md#dma-safety-model)
  § DMA Safety Model and [docs/architecture.md](../../docs/architecture.md)).
- **Per-device capabilities** —
  [devmgr](../devmgr/docs/responsibilities.md#responsibilities) delegates the
  minimum capability set for each device: MMIO region, optional interrupt line, the
  service endpoint, IoPort (x86-64) where applicable, the DMA capability of a
  DMA-capable device (below), and a devmgr query cap: a badged SEND on the private
  endpoint of the driver's spawn batch, on which a driver that fetches runtime
  metadata (the framebuffer, the VirtIO PCI drivers) sends device-info queries, and
  every driver reports `DRIVER_READY` once its device is set up (devmgr serves a
  driver only after that report, and revokes the private endpoint once the batch
  settles). See [docs/capability-model.md](../../docs/capability-model.md) for
  capability types and rights.
- **Spawning** — [devmgr](../devmgr/docs/responsibilities.md#responsibilities)
  discovers devices (PCI enumeration, firmware tables, the boot framebuffer, a platform
  description table), matches each device record to the most
  specific driver declaration (every driver binary carries one in the ELF note section
  `.note.seraph.driver`, emitted by `driver_binding::driver_declaration!`; see
  [docs/driver-binding.md](../../docs/driver-binding.md)), and requests procmgr to create driver
  processes. devmgr then delegates per-device capabilities to the new process.
- **Communication** — drivers expose IPC endpoints for their clients (e.g. a
  block driver exposes a read/write endpoint consumed by filesystem drivers via
  vfsd; see [docs/storage.md](../../docs/storage.md)). See
  [docs/ipc-design.md](../../docs/ipc-design.md) for IPC semantics.
- **DMA** — devmgr gives each DMA-capable driver a DMA
  capability, a SEND badged with its device on devmgr's DMA endpoint. The driver
  maps every buffer its device reaches through it (`DMA_MAP`) and programs the
  device only with the device addresses it returns, never with a physical
  address ([docs/device-management.md](../../docs/device-management.md#dma-authorisation)
  § DMA Authorisation), which it cannot read: its grants lack the Memory `Phys`
  right ([docs/device-management.md](../../docs/device-management.md#physical-addresses)
  § Physical Addresses). devmgr spawns each such driver `CREATE_PINNED` and
  `CREATE_DMA_HOLD`, so its memory is freed only once devmgr has confirmed its
  device's DMA stopped
  ([docs/device-management.md](../../docs/device-management.md#dma-safe-teardown)
  § DMA-Safe Teardown). devmgr attaches each such device to an IOMMU domain of
  its own before its grant, through the IOMMU driver of the architecture's
  family, `iommu-vtd` on x86-64 and `iommu-riscv` on riscv64 (below). The
  IOMMU-isolated vs DMA-unsafe model is
  specified in [docs/device-management.md](../../docs/device-management.md#dma-safety-model)
  § DMA Safety Model.

---

## Existing Drivers

| Crate | Type | Purpose |
|---|---|---|
| [`virtio/core/`](virtio/core/README.md) | Library | Shared VirtIO transport primitives: device initialisation, virtqueue setup, descriptor chain management |
| [`virtio/blk/`](virtio/blk/README.md) | Binary + library | VirtIO block device driver — exposes per-request DMA block-read IPC endpoint |
| [`virtio/input/`](virtio/input/README.md) | Binary + library | VirtIO input (keyboard) device driver — decodes `EV_KEY` events into keysyms; answers `INPUT_READ_EVENTS` behind devmgr's `QUERY_DEVICE` on the `input` class |
| [`virtio/console/`](virtio/console/README.md) | Binary + library | VirtIO console device driver — the debug port; serves the serial protocol behind devmgr's `QUERY_DEVICE` on the `debug-port` class |
| [`serial/`](serial/README.md) | Binary | Serial (UART) device driver — COM1 (x86-64) / NS16550 (RISC-V); sole driver-mediated serial-byte sink |
| [`framebuffer/`](framebuffer/README.md) | Binary + library | Linear framebuffer text driver — owns the GOP framebuffer MMIO; sole driver-mediated framebuffer-byte sink |
| [`cmos/`](cmos/README.md) | Binary + library | x86-64 CMOS / MC146818 RTC driver — bound by devmgr to the `PNP0B00` record; answers `RTC_GET_EPOCH_TIME` behind devmgr's `QUERY_DEVICE` on the `rtc` class |
| [`goldfish-rtc/`](goldfish-rtc/README.md) | Binary | RISC-V Goldfish RTC driver — bound by devmgr to the `google,goldfish-rtc` platform record; answers `RTC_GET_EPOCH_TIME` behind devmgr's `QUERY_DEVICE` on the `rtc` class |
| [`iommu/core/`](iommu/core/README.md) | Library | Family-independent IOMMU driver logic: the bootstrap devmgr serves, the `iommu_labels` service and its per-domain checks, the polled fault queue, and the `Backend` trait |
| [`iommu/riscv/`](iommu/riscv/README.md) | Binary + library | RISC-V IOMMU driver (riscv64) — devmgr-spawned at boot; programs each IOMMU's queues, device directory, and first-stage tables and confines each DMA-capable device to its own domain |
| [`iommu/store/`](iommu/store/README.md) | Library | The table-page store both IOMMU drivers build their translation structures in: zeroed pages from memmgr, mapped, with their physical addresses |
| [`iommu/vtd/`](iommu/vtd/README.md) | Binary + library | VT-d IOMMU driver (x86-64) — devmgr-spawned at boot; programs the remapping units' tables and confines each DMA-capable device to its own domain |
| [`test-dma/`](test-dma/README.md) | Binary | Test-only driver for QEMU's `edu` device — svctest checks a mapped DMA copy arrives and one to an unmapped IOVA is stopped |
| [`test-fault/`](test-fault/README.md) | Binary | Test-only fault-injection driver, installed in `/tests/drivers/` and bound through `BIND_DRIVERS` — serves and dies on request, never reports ready, or fails its bootstrap, so svctest exercises devmgr's settle bound, orphan teardown, and driver withdrawal |

---

## Adding a Driver

The driver-authoring rules are specified in
[docs/driver-model.md](docs/driver-model.md#adding-a-driver) § Adding a Driver. In
summary, a driver is a std binary crate (ruststd) targeting the std-userspace
Seraph target (see [docs/build-system.md](../../docs/build-system.md#custom-targets)),
holds only the capabilities
[devmgr](../devmgr/docs/responsibilities.md#responsibilities) delegates, serves client
requests on the service endpoint devmgr creates and delivers at spawn (devmgr mints
client SEND caps from its registry; see
[services/devmgr/docs/responsibilities.md](../devmgr/docs/responsibilities.md#responsibilities)
§ Responsibilities), acknowledges each interrupt delivery promptly when it holds a binding on a
line devmgr may share, and reuses shared crates such as
[`virtio/core/`](virtio/core/README.md) for transport logic.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/driver-model.md](docs/driver-model.md) | Driver lifecycle and capability delegation |
| [docs/virtio-architecture.md](docs/virtio-architecture.md) | VirtIO transport abstraction and queue internals |
| [docs/device-management.md](../../docs/device-management.md) | Driver lifecycle, DMA safety, security boundary |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/architecture.md](../../docs/architecture.md) | Driver isolation and per-device authority |
| [docs/build-system.md](../../docs/build-system.md) | Std-userspace target drivers build for |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, rights, delegation |
| [docs/console-model.md](../../docs/console-model.md) | Console output ownership; the serial driver's place in it |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [docs/storage.md](../../docs/storage.md) | Block-driver delegation chain via vfsd |

---

## Summarized By

None
