# Driver Model

Driver lifecycle specification: device discovery, driver binding, per-device
capability delegation, service-endpoint delivery, and driver teardown.

Only § Adding a Driver is written here; devmgr's discovery, binding, and delegation are
specified in
[services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md).
TODO: specify driver teardown.

---

## Adding a Driver

1. A driver lives in a subdirectory of `services/drivers/`, grouped by bus or device family
   where appropriate (e.g. `virtio/`).
2. A driver is a std binary crate (ruststd) built for the std-userspace Seraph target; see
   [docs/build-system.md](../../../docs/build-system.md#custom-targets) § Custom Targets.
3. A driver receives its device capabilities from [devmgr](../../devmgr/README.md) at spawn.
   It MUST NOT assume any capabilities beyond what devmgr delegates.
4. A driver serves client requests on the service endpoint devmgr creates and delivers in its
   bootstrap round; devmgr keeps the endpoint and mints client SEND caps from its device
   registry (`QUERY_*_DEVICE`). A driver MUST report `DRIVER_READY` on its devmgr query cap once
   its device is set up, immediately before its service loop (`ipc::report_driver_ready`), and
   exit when devmgr refuses the report: devmgr serves its endpoint only after that report, and
   withdraws and destroys a driver that has not reported within its settle bound; see
   [services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md#responsibilities)
   § Responsibilities.
5. A driver holding an IRQ binding on a line devmgr may share (a PCI `INTx` line) MUST
   acknowledge each delivery promptly (`SYS_IRQ_ACK`), whether or not it has a request in flight:
   the line stays masked until every binding on it has acknowledged, so a driver that acknowledges
   only inside its request path holds the line masked for every other device on it while it is
   idle (see [docs/device-management.md](../../../docs/device-management.md#interrupt-delivery)
   § Interrupt Delivery). The VirtIO drivers run an interrupt-service thread, the only waiter on
   the line's notification, which reads the device's interrupt status and acknowledges on every
   wake, and reads the status on a bounded timeout too, so an interrupt whose edge was lost on
   x86-64 is still seen (`virtio_core::isr::serve_interrupts`, at most `ISR_POLL_MS` late). A
   driver that does not acknowledge promptly needs its line kept exclusive: the serial
   driver acknowledges only when its client reads
   ([services/drivers/serial/README.md](../serial/README.md#interrupts) § Interrupts), so devmgr
   keeps the UART line exclusive. The UART line is never a PCI `INTx` line on either machine
   (x86-64 COM1 is ISA IRQ 4, the riscv64 `virt` NS16550 is PLIC source 10 against `INTx` sources
   32 to 35), so the exclusivity costs no device a cap in practice.
6. A driver SHOULD use shared library crates (e.g. `services/drivers/virtio/core/`) where
   applicable rather than duplicating transport logic.

---

## Summarized By

[Device Management](../../../docs/device-management.md), [services/drivers/README.md](../README.md),
[services/drivers/virtio/blk/README.md](../virtio/blk/README.md),
[services/drivers/virtio/core/README.md](../virtio/core/README.md)
