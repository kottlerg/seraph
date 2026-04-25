# drivers

Userspace device drivers, each running as an isolated process with per-device
capabilities delegated by devmgr.

---

## Source Layout

```
drivers/
├── README.md
├── virtio/
│   ├── core/                       # Shared VirtIO transport and queue primitives (library)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs
│   └── blk/                        # VirtIO block device driver (binary)
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
└── docs/
    ├── driver-model.md             # Driver lifecycle and capability delegation
    └── virtio-architecture.md      # VirtIO transport abstraction and queue internals
```

---

## Driver Model

Each driver is a separate userspace process with its own address space. Drivers
receive only the capabilities for the specific device they manage — no driver
holds ambient hardware authority. The full driver lifecycle is specified in
[docs/device-management.md](../docs/device-management.md); the key points are:

- **Isolation** — every driver runs in its own address space. A driver crash
  cannot corrupt another driver or the kernel.
- **Per-device capabilities** — devmgr delegates the minimum capability set
  for each device: MMIO region, interrupt line, and optionally DMA grant and
  IoPortRange (x86-64). See
  [docs/capability-model.md](../docs/capability-model.md) for capability types
  and rights.
- **Spawning** — devmgr discovers devices (PCI enumeration, firmware tables),
  matches them to driver binaries, and requests procmgr to create driver
  processes. devmgr then delegates per-device capabilities to the new process.
- **Communication** — drivers expose IPC endpoints for their clients (e.g. a
  block driver exposes a read/write endpoint consumed by filesystem drivers via
  vfsd). See [docs/ipc-design.md](../docs/ipc-design.md) for IPC semantics.
- **DMA** — requires explicit DMA grant capability. The DMA safety model
  (IOMMU-isolated vs DMA-unsafe) is specified in
  [docs/device-management.md](../docs/device-management.md).

---

## Existing Drivers

| Crate | Type | Purpose |
|---|---|---|
| `virtio/core/` | Library | Shared VirtIO transport primitives: device initialisation, virtqueue setup, descriptor chain management |
| `virtio/blk/` | Binary | VirtIO block device driver — exposes block read/write IPC endpoint |

---

## Adding a Driver

1. Create a subdirectory under `drivers/` (grouped by bus or device family
   where appropriate, e.g. `virtio/`, `pci/`, `platform/`).
2. Add a `Cargo.toml` for a `no_std` binary crate targeting the userspace
   Seraph target.
3. The driver binary receives its device capabilities from devmgr after
   creation. It MUST NOT assume any capabilities beyond what devmgr delegates.
4. Expose an IPC endpoint for clients (block read/write, network send/receive,
   etc.) and register it with devmgr's device registry.
5. Use shared library crates (e.g. `virtio/core/`) where applicable to avoid
   duplicating transport logic.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../docs/device-management.md) | Driver lifecycle, DMA safety, security boundary |
| [docs/ipc-design.md](../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/capability-model.md](../docs/capability-model.md) | Capability types, rights, delegation |
| [docs/coding-standards.md](../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
