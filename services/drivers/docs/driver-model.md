# Driver Model

Driver lifecycle specification: device discovery, driver binding, per-device
capability delegation, service-endpoint delivery, and driver teardown.

§ Adding a Driver is written here, and § Withdrawal summarizes devmgr's withdrawal of a driver;
devmgr's discovery, binding, delegation, and withdrawal are specified in
[services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md).
TODO: specify a driver's own teardown: how a driver stops its device and releases what it holds
when it exits on its own.

---

## Adding a Driver

1. A driver lives in a subdirectory of `services/drivers/`, grouped by bus or device family
   where appropriate (e.g. `virtio/`).
2. A driver is a std binary crate (ruststd) built for the std-userspace Seraph target; see
   [docs/build-system.md](../../../docs/build-system.md#custom-targets) § Custom Targets.
3. A driver receives its device capabilities from [devmgr](../../devmgr/README.md) at spawn.
   It MUST NOT assume any capabilities beyond what devmgr delegates. A driver devmgr binds to a
   PCI or platform device record carries a declaration in the ELF note section
   `.note.seraph.driver` (`driver_binding::driver_declaration!`) and receives the resource list
   of `driver_binding::resources` (a platform driver decodes it with
   `driver_binding::resources::PlatformDelivery`); only the IOMMU driver takes bootstrap rounds
   of its own; [docs/driver-binding.md](../../../docs/driver-binding.md) is the
   design.
4. A driver serves client requests on the service endpoint devmgr creates and delivers in its
   bootstrap; devmgr keeps the endpoint and mints client SEND caps from its device
   registry (`QUERY_*_DEVICE`). A driver MUST report `DRIVER_READY` on its devmgr query cap once
   its device is set up, immediately before its service loop (`ipc::report_driver_ready`), and
   exit when devmgr refuses the report: devmgr serves its endpoint only after that report, and
   destroys and withdraws a driver that has not reported within its settle bound; see
   [services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md#responsibilities)
   § Responsibilities.
5. A driver holding an IRQ binding on a line devmgr may share (a PCI `INTx` line) MUST
   acknowledge each delivery promptly (`SYS_IRQ_ACK`), whether or not it has a request in flight:
   the line stays masked until every binding on it has acknowledged, so a driver that acknowledges
   only inside its request path holds the line masked for every other device on it while it is
   idle (see [docs/device-management.md](../../../docs/device-management.md#interrupt-delivery)
   § Interrupt Delivery). The VirtIO drivers run an interrupt-service thread, the only waiter on
   the line's notification, which reads the device's interrupt status and acknowledges every
   delivery, and reads the status on a bounded timeout too, so an interrupt whose edge was lost on
   an x86-64 line programmed edge-triggered is still seen (`virtio_core::isr::serve_interrupts`,
   at most `ISR_POLL_MS` late). Every driver on a line passes `SYS_IRQ_REGISTER` the line's mode
   devmgr delivers with the IRQ (docs/device-management.md § Interrupt Delivery). A
   driver that does not acknowledge promptly needs its line kept exclusive: the serial driver
   acknowledges only when its client reads
   ([services/drivers/serial/README.md](../serial/README.md#interrupts) § Interrupts), so devmgr
   keeps the UART line exclusive. The UART line is never a PCI `INTx` line on either machine
   (x86-64 COM1 is ISA IRQ 4, the riscv64 `virt` NS16550 is APLIC source 10 against `INTx` sources
   32 to 35), so the exclusivity costs no device a cap in practice. A message-signaled vector
   (MSI or MSI-X) is its device's alone: the kernel never masks it, so it owes no
   acknowledgement. A driver given vectors names them in its device's own registers
   and holds its device's interrupts off at the device (VirtIO's `NO_VECTOR` and event
   suppression), since devmgr alone writes the MSI-X table and its masks
   ([docs/device-management.md](../../../docs/device-management.md#message-signaled-interrupts)
   § Message-Signaled Interrupts).
6. A driver SHOULD use shared library crates (e.g. `services/drivers/virtio/core/`) where
   applicable rather than duplicating transport logic.

---

## Withdrawal

devmgr withdraws every driver it does not, or no longer, serves: one that dies, fails its device
setup, overruns its settle bound, or that devmgr cannot record or serve. For a driver bound to a PCI
device it takes the device from the driver in an order that frees the driver's memory only once the
device's DMA is confirmed stopped or blocked: it first withdraws the device's DMA capability,
revoking every copy and dropping the device's mappings, which also blocks the device where an
IOMMU confines it (the IOMMU driver's `BLOCK`); then it clears the function's Bus Master
Enable through a configuration-page cap it keeps and no driver holds, so the device issues no
further DMA; revokes the driver's mappings of its BARs; sets the function's Command Interrupt
Disable bit and clears its MSI Enable and MSI-X Enable bits, MSI-X's Function Mask set, through
the same cap; runs the reset
the driver's declaration names (the VirtIO status reset, `device_status` 0 complete once the
status reads back 0 within `RESET_TIMEOUT`, or a PCI Express Function Level Reset, complete once
the function answers after `FLR_COMPLETION_MS`; or none, and a device with none is never confirmed
quiet); and destroys the driver. Every driver of a DMA declaration is created
`CREATE_DMA_HOLD`, so procmgr holds its memory after its death, however it died, until devmgr
releases it, which devmgr does only when the IOMMU blocked the device, or when the Bus Master
Enable read-back is clear, every BAR copy is revoked and the reset is confirmed; otherwise the
memory stays quarantined for the rest of the boot. A driver that dies while its device asserts a
shared level-triggered line leaves the line's other receivers no assertion to loop on once the
reset lands; between the driver's death, which releases its binding, and the reset, they may see
re-deliveries their own devices did not raise
([docs/device-management.md](../../../docs/device-management.md#interrupt-delivery)
§ Interrupt Delivery). The withdrawal, the reset among its steps, is specified in
[services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md#responsibilities)
§ Responsibilities.

---

## Summarized By

[Device Management](../../../docs/device-management.md), [services/drivers/README.md](../README.md),
[services/drivers/virtio/blk/README.md](../virtio/blk/README.md),
[services/drivers/virtio/console/README.md](../virtio/console/README.md),
[services/drivers/virtio/core/README.md](../virtio/core/README.md),
[services/drivers/virtio/input/README.md](../virtio/input/README.md)
