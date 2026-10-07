# drivers

Userspace device drivers, each running as an isolated process with per-device
capabilities delegated by devmgr.

---

## Source Layout

```
services/drivers/
├── README.md
├── cmos/                           # x86-64 CMOS / MC146818 RTC driver (binary)
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       └── main.rs
├── framebuffer/                    # Linear-framebuffer text driver (binary)
│   ├── Cargo.toml
│   ├── README.md                   # Framebuffer IPC interface (FB_WRITE_BYTES, FB_SET_ATTRS)
│   └── src/
│       ├── main.rs
│       ├── render.rs               # 9×20 bitmap glyph blit + cursor + scroll
│       └── arch/                   # Per-arch MMIO mapping (x86_64 / riscv64)
├── goldfish-rtc/                   # RISC-V Goldfish RTC driver (binary)
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       └── main.rs
├── serial/                         # Serial (UART) device driver (binary)
│   ├── Cargo.toml
│   ├── README.md                   # Serial-driver IPC interface (SERIAL_WRITE_BYTES)
│   └── src/
│       ├── main.rs
│       └── arch/                   # Per-arch UART access (x86_64 COM1, riscv64 NS16550)
├── test-orphan/                    # Test-only fault-injection driver for devmgr (binary)
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
│   ├── blk/                        # VirtIO block device driver (binary)
│   │   ├── Cargo.toml
│   │   ├── README.md               # Block-driver IPC interface
│   │   │                           #   (BLK_READ_INTO_MEMORY, REGISTER_PARTITION)
│   │   └── src/
│   │       ├── main.rs
│   │       └── io.rs
│   └── input/                      # VirtIO input (keyboard) device driver (binary)
│       ├── Cargo.toml
│       ├── README.md               # Input-driver IPC interface (INPUT_READ_EVENTS)
│       └── src/
│           ├── main.rs
│           ├── input.rs            # Event virtqueue receive-buffer ring
│           └── decode.rs           # Keycode → keysym tables + modifier state
└── docs/
    ├── driver-model.md             # Driver lifecycle and capability delegation
    └── virtio-architecture.md      # VirtIO transport abstraction and queue internals
```

---

## Driver Model

Each driver is a separate userspace process with its own address space. Drivers
receive only the capabilities for the specific device they manage (see
[docs/architecture.md](../../docs/architecture.md)); device DMA is the exception,
unconfined until IOMMU support lands (see
[docs/device-management.md](../../docs/device-management.md#dma-safety-model)).
The full driver lifecycle is specified in
[docs/device-management.md](../../docs/device-management.md); the key points are:

- **Isolation** — every driver runs in its own address space. A driver crash
  cannot corrupt another driver's or the kernel's memory through the CPU; device
  DMA is unconfined until IOMMU support lands (see
  [docs/device-management.md](../../docs/device-management.md#dma-safety-model)
  § DMA Safety Model and [docs/architecture.md](../../docs/architecture.md)).
- **Per-device capabilities** — [devmgr](../devmgr/README.md) delegates the
  minimum capability set for each device: MMIO region, optional interrupt line,
  the service endpoint, IoPort (x86-64) where applicable, and, for drivers that
  fetch runtime metadata (PCI drivers, the framebuffer), a badged SEND on
  devmgr's registry-query endpoint. See
  [docs/capability-model.md](../../docs/capability-model.md) for capability types
  and rights.
- **Spawning** — [devmgr](../devmgr/README.md) discovers devices (PCI
  enumeration, firmware tables), matches them to driver binaries, and requests
  procmgr to create driver processes. devmgr then delegates per-device
  capabilities to the new process.
- **Communication** — drivers expose IPC endpoints for their clients (e.g. a
  block driver exposes a read/write endpoint consumed by filesystem drivers via
  vfsd; see [docs/storage.md](../../docs/storage.md)). See
  [docs/ipc-design.md](../../docs/ipc-design.md) for IPC semantics.
- **DMA** — no DMA-authorising capability type exists. devmgr spawns each
  DMA-capable (PCI BAR + IRQ) driver `CREATE_PINNED`, and DMA is unconfined
  until IOMMU support lands. DMA targets are Memory caps whose physical base the
  driver reads from memmgr's `REQUEST_MEMORY_CAPS` reply or via `SYS_CAP_INFO`
  (see [docs/device-management.md](../../docs/device-management.md#iommu-discovery-and-programming)
  § IOMMU Discovery and Programming). The IOMMU-isolated vs DMA-unsafe model is
  specified in [docs/device-management.md](../../docs/device-management.md#dma-safety-model)
  § DMA Safety Model.

---

## Existing Drivers

| Crate | Type | Purpose |
|---|---|---|
| [`virtio/core/`](virtio/core/README.md) | Library | Shared VirtIO transport primitives: device initialisation, virtqueue setup, descriptor chain management |
| [`virtio/blk/`](virtio/blk/README.md) | Binary | VirtIO block device driver — exposes per-request DMA block-read IPC endpoint |
| [`virtio/input/`](virtio/input/README.md) | Binary | VirtIO input (keyboard) device driver — decodes `EV_KEY` events into keysyms; answers `INPUT_READ_EVENTS` behind devmgr's `QUERY_INPUT_DEVICE` |
| [`serial/`](serial/README.md) | Binary | Serial (UART) device driver — COM1 (x86-64) / NS16550 (RISC-V); sole driver-mediated serial-byte sink |
| [`framebuffer/`](framebuffer/README.md) | Binary | Linear framebuffer text driver — owns the GOP framebuffer MMIO; sole driver-mediated framebuffer-byte sink |
| [`cmos/`](cmos/README.md) | Binary | x86-64 CMOS / MC146818 RTC driver — devmgr-spawned; answers `RTC_GET_EPOCH_TIME` behind devmgr's `QUERY_RTC_DEVICE` |
| [`goldfish-rtc/`](goldfish-rtc/README.md) | Binary | RISC-V Goldfish RTC driver — devmgr-spawned; answers `RTC_GET_EPOCH_TIME` behind devmgr's `QUERY_RTC_DEVICE` |
| [`test-orphan/`](test-orphan/README.md) | Binary | Test-only fault-injection driver — forces a mid-bootstrap spawn failure so svctest exercises devmgr's orphan-teardown path |

---

## Adding a Driver

The driver-authoring rules are specified in
[docs/driver-model.md](docs/driver-model.md#adding-a-driver) § Adding a Driver. In
summary, a driver is a std binary crate (ruststd) targeting the std-userspace
Seraph target (see [docs/build-system.md](../../docs/build-system.md#custom-targets)),
holds only the capabilities [devmgr](../devmgr/README.md) delegates, serves client
requests on the service endpoint devmgr creates and delivers at spawn (devmgr mints
client SEND caps from its registry; see
[services/devmgr/docs/responsibilities.md](../devmgr/docs/responsibilities.md#responsibilities)
§ Responsibilities), and reuses shared crates such as
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
