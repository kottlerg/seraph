# virtio/core

Shared VirtIO library crate (`virtio-core`, `no_std`) used by the VirtIO drivers and by devmgr:
modern PCI transport register access, split-virtqueue management, device-status negotiation, and
the `VirtioPciStartupInfo` payload (versioned by `VIRTIO_PCI_INFO_VERSION`) that carries PCI
capability locations, which devmgr serialises into its `QUERY_DEVICE_INFO` reply to a VirtIO
driver. The design is specified in [docs/virtio-architecture.md](../../docs/virtio-architecture.md).

---

## Source Layout

```
virtio/core/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs            # Device status bits, VirtioPciStartupInfo QUERY_DEVICE_INFO reply payload
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

None
