# test-dma

Test-only driver for QEMU's `edu` device (PCI `1234:11e8`), which xtask attaches only to a test
launch (`cargo xtask run --test-devices`), behind the IOMMU when one is attached. The driver carries
a declaration (PCI `1234:11e8`, class `test-dma`, an optional interrupt asking for one MSI vector,
DMA with a 28-bit address width, no reset, instance limit 1, auxiliary tier) in the ELF note section
`.note.seraph.driver`, and devmgr binds it to the `edu` device in its drivers-directory pass at
`SET_DRIVERS_DIR` (see [driver-binding.md](../../../docs/driver-binding.md)). devmgr gives the
device its DMA grant, attaching it to its IOMMU domain where a remapping unit translates it, turns
on its memory decode and bus mastering, and spawns this driver with the resource list of
`driver_binding::resources`: the `Mmio` cap of BAR 0, whole, the `Interrupt` cap of the device's one
MSI vector (its wired line where devmgr cannot give MSI), then the end round with the service
endpoint, the devmgr query cap, and the device's DMA capability.

The driver checks the device's identification register, binds its interrupt to a notification of
its own (`SYS_IRQ_REGISTER`), reports ready, and answers `ipc::test_dma_labels::INTERRUPT_PROBE`
and `ipc::test_dma_labels::DMA_PROBE`. The interrupt probe has the device raise its interrupt
(register `0x60`), waits for the notification for at most `test_dma_labels::INTERRUPT_WAIT_MS`,
acknowledges it at the device (register `0x64`) and with `SYS_IRQ_ACK`, and reports whether it was
delivered and the kind of interrupt the driver holds. The DMA probe maps one page of the driver's
memory for the device (`DMA_MAP`), has the device's DMA engine copy a pattern from the page into its
4 KiB buffer and back to the page's second half, unmaps the page (`DMA_UNMAP`), clears the second
half, and has the device copy its buffer to the same device address once more. It reports whether
the mapped copies arrived, whether the copy after the unmap reached the page, and the device
address. Where an IOMMU confines the device that last copy is stopped and the IOMMU records a fault.
The driver then asks devmgr for its device's faults (`devmgr_dma_labels::DMA_FAULTS`) until the
stopped copy is counted, for at most `test_dma_labels::FAULT_WAIT_MS`, and reports with the probe
whether an IOMMU confines the device, the fault count, and the latest fault's IOVA. The device
reaches 28 address bits, so with no IOMMU a page above 256 MiB is not copied to.

[svctest](../../svctest/README.md)'s DMA confinement and MSI delivery phases reach it through the
`test-dma` class (`QUERY_DEVICE`) and drive it.

---

## Source Layout

```
test-dma/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Bootstrap, edu register access, the interrupt and DMA probes
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../docs/device-management.md) | DMA authorisation, IOMMU discovery and programming, interrupt delivery |
| [devmgr Responsibilities](../../devmgr/docs/responsibilities.md) | Driver settle, withdrawal, and the DMA endpoint |

---

## Summarized By

[Testing](../../../docs/testing.md), [services/drivers/README.md](../README.md),
[services/svctest/README.md](../../svctest/README.md)
