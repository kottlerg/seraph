# virtio/core

Shared VirtIO library crate (`virtio-core`, `no_std`) used by the VirtIO drivers and by devmgr:
modern PCI transport register access, split-virtqueue management, device-status negotiation, and the
`VirtioPciStartupInfo` payload (versioned by `VIRTIO_PCI_INFO_VERSION`) that carries PCI capability
locations, which devmgr serialises into its `QUERY_DEVICE_INFO` reply to a VirtIO driver, and the
register layout derived from it for the device-configuration requirement its driver declares
(`VirtioDeviceConfig`: the distinct BARs the common, notification, and ISR regions and, when
required, the device-configuration region name, up to `MAX_VIRTIO_BARS`, each region's place in
the driver's register window, and the place there of each BAR range devmgr delivers,
`RegisterLayout::place`), and where a reset writes the device's `device_status` byte
(`RegisterLayout::status_register`), which devmgr
uses when it withdraws a driver ([driver-model.md](../../docs/driver-model.md#withdrawal) §
Withdrawal). It also reads, on the driver side, the resource list devmgr delivers a VirtIO PCI
driver (`bootstrap::DeliveredDevice`, over `driver_binding::resources`), maps a driver's buffers
for its device through the device's DMA
capability (`dma`; see
[docs/device-management.md](../../../../docs/device-management.md#dma-authorisation) § DMA
Authorisation), routes a driver's queues to its interrupt (`PciTransport::route_queue`, MSI-X
vector 0 under MSI-X, and configuration changes to `NO_VECTOR`, `PciTransport::route_config`), and
provides the interrupt-service loop (`isr::serve_interrupts`) each VirtIO driver runs on a thread of
its own: on a wired line it acknowledges every delivery, a request in flight or not
([driver-model.md](../../docs/driver-model.md) rule 5), and on an MSI-X vector, which owes no
acknowledgement, it relays each delivery. The design is specified in
[docs/virtio-architecture.md](../../docs/virtio-architecture.md).

---

## Source Layout

```
virtio/core/
├── Cargo.toml
├── README.md
├── fuzz/
│   └── virtio-core/
│       └── seeds/        # Checked-in inputs of the `virtio-core` fuzz target, replayed by
│                         #   `cargo xtask test`
└── src/
    ├── lib.rs            # Reserved feature bits, device status bits, VirtioPciStartupInfo
    │                     #   QUERY_DEVICE_INFO payload, RegisterLayout (per-BAR register
    │                     #   window), StatusRegister (where a reset writes `device_status`)
    ├── bootstrap.rs      # DeliveredDevice, DeviceInterrupt: the resource list of a VirtIO driver
    ├── dma.rs            # Map and unmap a driver's buffers for its device (DMA capability)
    ├── isr.rs            # Interrupt-service loop (wired: bounded wait, ISR read, acknowledge,
    │                     #   signal; MSI-X: wait, signal)
    ├── pci.rs            # Modern PCI transport register access, MSI-X vector routing, the
    │                     #   decode of a configuration read (config_word_addr, settle)
    ├── property.rs       # The decoders' contract over any input (virtio_core_holds), for the
    │                     #   fuzz target, the replay test and the proofs; test, Kani and fuzz
    │                     #   builds only
    └── virtqueue.rs      # Split virtqueue rings and descriptors: the shell over the driver's
                          #   bookkeeping (Chains), which decodes the used ring
```

The decoders of what a device writes for its driver, the used ring and a configuration read, are
host-tested (`cargo xtask test`), fuzzed (target `virtio-core`,
[docs/testing.md](../../../../docs/testing.md#fuzzing) § Fuzzing), and proved by the Kani harnesses
of the `proofs` modules of `virtqueue.rs` and `pci.rs`
([docs/testing.md](../../../../docs/testing.md#bounded-verification) § Bounded verification).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/virtio-architecture.md](../../docs/virtio-architecture.md) | VirtIO transport abstraction and queue internals |
| [docs/device-management.md](../../../../docs/device-management.md) | Driver lifecycle, DMA safety |
| [docs/driver-model.md](../../docs/driver-model.md) | Driver rules, including rule 5's prompt acknowledgement on a shared line |

---

## Summarized By

None
