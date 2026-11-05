# test-dma

Test-only driver for QEMU's `edu` device (PCI `1234:11e8`), which xtask attaches to every x86-64
launch, behind the IOMMU when one is attached. devmgr binds it on demand through its
`TEST_SPAWN_DMA_DRIVER` shim, gated on `TEST_LABEL_AUTHORITY`, which only svctest's seed-only
`devmgr.test` cap carries, so a boot without svctest never spawns it. devmgr gives the device its
DMA grant, attaching it to its IOMMU domain where a remapping unit translates it, turns on its
memory decode and bus mastering, and spawns this driver through the PCI spawn path: round 1
carries the cap of the first page of BAR 0, round 2 the service endpoint, the devmgr query cap,
and the device's DMA capability.

The driver checks the device's identification register, reports ready, and answers
`ipc::test_dma_labels::DMA_PROBE`. The probe maps one page of the driver's memory for the device
(`DMA_MAP`), has the device's DMA engine copy a pattern from the page into its 4 KiB buffer and
back to the page's second half, unmaps the page (`DMA_UNMAP`), clears the second half, and has
the device copy its buffer to the same device address once more. It reports whether the mapped
copies arrived, whether the copy after the unmap reached the page, and the device address. Where
an IOMMU confines the device that last copy is stopped and the IOMMU records a fault. The device
reaches 28 address bits, so with no IOMMU a page above 256 MiB is not copied to.

[svctest](../../svctest/README.md)'s DMA confinement phase drives it. Slated for removal with the
devmgr enumeration redesign ([#165](https://github.com/kottlerg/seraph/issues/165)).

---

## Source Layout

```
test-dma/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Bootstrap, edu register access, the DMA probe
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../docs/device-management.md) | DMA authorisation, IOMMU discovery and programming |
| [devmgr Responsibilities](../../devmgr/docs/responsibilities.md) | Driver settle, withdrawal, and the test-only shims |

---

## Summarized By

[Testing](../../../docs/testing.md), [services/drivers/README.md](../README.md),
[services/svctest/README.md](../../svctest/README.md)
