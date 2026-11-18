# VirtIO Architecture

VirtIO transport abstraction as implemented in `virtio/core/`: device
initialisation, virtqueue management, descriptor chain handling, and feature
negotiation, and the VirtIO device drivers built on it.

TODO: specify the transport abstraction and queue internals; until then the
[`virtio/core/`](../virtio/core/README.md) sources are the only description.

---

## Device Drivers

Each VirtIO device type the system drives has one driver, a process of its own built on
`virtio/core/` over the modern PCI transport. Each declares its device's transitional and modern
PCI device IDs (vendor `1AF4`), the device class through which devmgr hands clients its service
endpoint ([docs/driver-binding.md](../../../docs/driver-binding.md) § Device Classes), and DMA,
which devmgr confines behind the platform IOMMU when one is present; the launchers attach every one
of these devices modern-only (`disable-legacy=on`) and, when they attach an IOMMU, behind it
(`iommu_platform=on`).

| Driver | Device (VirtIO 1.2) | PCI IDs | Class | Queues the driver uses |
|---|---|---|---|---|
| [virtio-blk](../virtio/blk/README.md) | block (§ 5.2) | `1001`, `1042` | `block` | requestq |
| [virtio-input](../virtio/input/README.md) | input (§ 5.8) | `1012`, `1052` | `input` | eventq |
| [virtio-console](../virtio/console/README.md) | console (§ 5.3) | `1003`, `1043` | `debug-port` | receiveq and transmitq of port 0 |
| [virtio-rng](../virtio/rng/README.md) | entropy (§ 5.4) | `1005`, `1044` | `hwrng` | requestq |

The entropy device has no device-specific configuration region (§ 5.4.4), so its driver's
declaration names none (`VirtioDeviceConfig::Absent`) and its register layout maps none. Its
driver serves the `hwrng` class protocol
([shared/hwrng-protocol](../../../shared/hwrng-protocol/README.md)), one `READ(n)` label, and
holds no kernel authority: what consumes the bytes is the class's consumer's decision. The
firmware drives the same device before the kernel starts: EDK2's `VirtioRngDxe` binds it and, on
riscv64, serves the bootloader's `EFI_RNG_PROTOCOL` draw
([core/kernel/docs/entropy.md](../../../core/kernel/docs/entropy.md)).

---

## Summarized By

[services/drivers/virtio/core/README.md](../virtio/core/README.md)
