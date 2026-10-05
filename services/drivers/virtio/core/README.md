# virtio/core

Shared VirtIO library crate (`virtio-core`, `no_std`) used by the VirtIO drivers: modern PCI
transport register access, split-virtqueue management, device-status negotiation, and the
startup-message format devmgr uses to pass PCI capability locations to VirtIO drivers. The
design is specified in [docs/virtio-architecture.md](../../docs/virtio-architecture.md).

---

## Source Layout

```
virtio/core/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs            # Device status bits, VirtioPciStartupInfo startup-message format
    ├── pci.rs            # Modern PCI transport register access
    └── virtqueue.rs      # Split virtqueue rings and descriptors
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/virtio-architecture.md](../../docs/virtio-architecture.md) | VirtIO transport abstraction and queue internals |
| [docs/device-management.md](../../../../docs/device-management.md) | Driver lifecycle, DMA safety |

---

## Summarized By

[services/drivers/README.md](../../README.md)
