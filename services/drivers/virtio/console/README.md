# virtio/console

VirtIO console device driver: the debug port. Drives a `virtio-console` device's port 0 as a
byte transport and serves it with the serial protocol (`shared/ipc::serial_labels`), so a
debugger stub, the GDB stub ([services/gdbstub/README.md](../../../gdbstub/README.md)), speaks to a
host debugger over it while the console keeps the UART.

---

## Source Layout

```
virtio/console/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                 # Serial-protocol verb-bit gate, received-byte queue (host-tested)
    └── main.rs                # Driver entry, PCI bring-up, queues, interrupt service, IPC loop
```

---

## Endpoint

Devmgr binds the first `virtio-console` PCI device it enumerates as the debug port: it carves
the device's capabilities (an `Mmio` cap for every BAR its VirtIO register regions name, its
own derivation of its line's `Interrupt` cap, and the device's DMA capability) and spawns this
driver from the rootfs (`/services/drivers/virtio-console`) through its `SET_DRIVERS_DIR`
subtree cap, in the same on-disk batch as the virtio-input drivers (see
[docs/device-management.md](../../../../docs/device-management.md)). A further console device
is left unbound. The driver reports `DRIVER_READY` on its devmgr query endpoint once its device
is set up, immediately before its service loop, and devmgr serves its endpoint only after that
report. Devmgr owns the service endpoint and mints a `WRITE_AUTHORITY | READ_AUTHORITY`-badged
SEND cap on it only through `devmgr_labels::QUERY_DEBUG_PORT_DEVICE`, which only a caller
holding `DEBUG_PORT_AUTHORITY` reaches: the seed-only `devmgr.debug` name, which only a service
whose definition seeds it holds (see
[devmgr Responsibilities](../../../devmgr/docs/responsibilities.md#responsibilities)). A boot
whose machine presents no console device, every boot that does not ask for the debug port, has
no debug port.

QEMU presents the device when a launch takes `--debug-port <PORT>`
([xtask/README.md](../../../../xtask/README.md#cargo-xtask-run)): a `virtio-serial-pci` device
with one `virtconsole` port, whose host end is a TCP server on `127.0.0.1:<PORT>`.

The driver serves the serial protocol rather than a protocol of its own, so its consumer does
not learn the transport. A driver of another device that serves the same protocol, a UART
driver on hardware with a second serial port, standing in for it as the debug port is design
intent; not yet implemented.

---

## Messages

The three operations of the serial protocol, with the labels, wire shapes, and verb-bit gates
[services/drivers/serial/README.md](../../serial/README.md) § Messages specifies:

- `SERIAL_WRITE_BYTES` sends the bytes through the transmit queue and replies once the device
  has taken them. The wait has no bound of its own, as a UART's wait for its transmit register
  has none. QEMU's `virtconsole` port completes each transmission at once and drops the bytes
  its host end cannot take then (no client connected, or the client's socket buffer full),
  since QEMU holds bytes back only for a port other than port 0, which needs
  `VIRTIO_CONSOLE_F_MULTIPORT`; a host client that reads as the bytes arrive loses none.
- `SERIAL_READ_BYTES` replies at once with the bytes received and not yet read, up to 512,
  possibly none.
- `SERIAL_REGISTER_RX_NOTIFY` has the interrupt-service thread signal the client's notification
  on each interrupt of the device from then on, replacing an earlier registration. It replies
  `REGISTER_FAILED` when devmgr delivered no IRQ cap or no notification came; the client's
  bounded wait then polls.

---

## Queues and DMA Discipline

The driver negotiates `VIRTIO_F_VERSION_1` and `VIRTIO_F_ACCESS_PLATFORM` and none of the
console's own features: without `VIRTIO_CONSOLE_F_MULTIPORT` the device carries port 0 alone,
on the receive queue (virtqueue 0) and the transmit queue (virtqueue 1). It maps the queues'
rings, one page of receive buffers, and one page for the transmit buffer for the device once at
setup, through its DMA capability, and programs the device only with the device addresses
devmgr returns, never with a physical address
([docs/device-management.md](../../../../docs/device-management.md#dma-authorisation)
§ DMA Authorisation).

- **Receive.** Eight 512-byte buffers (fewer when the device's queue is smaller) are posted
  device-writable. A read moves each filled buffer's bytes, its device-written length clamped
  to the buffer, into a 1024-byte queue and re-posts the buffer, then replies from the queue. A
  filled buffer is taken only while the queue has room for all of it, so no received byte is
  dropped: while no client reads, the buffers stay with the device and it stops taking input.
- **Transmit.** One write is in flight at a time, through a one-entry transmit queue; a write
  waits for its completion before it replies.

With an IRQ cap, an interrupt-service thread is the only waiter on the notification bound to
the device's line. It reads the ISR and acknowledges every delivery at once, as a driver on a
shared line must ([driver-model.md](../../docs/driver-model.md) rule 5), reads the ISR on a
bounded timeout too, as virtio-core's `isr::serve_interrupts` does, and signals both the
driver's own notification, which a write waits on with a bounded timeout, and the client's RX
notification. Without an IRQ cap the write's wait is a timed poll.

---

## Testing

`cargo xtask test-debug-port` boots the `debug-echo` fixture
([services/debug-echo/README.md](../../../debug-echo/README.md)) with the debug port attached
and drives a GDB remote serial protocol exchange with it from the host, and `cargo xtask test-gdb`
boots the GDB stub ([services/gdbstub/README.md](../../../gdbstub/README.md)) with it and runs a
host GDB session over it. The two boots are the driver's device cell, `debug-port`, in
[docs/testing.md](../../../../docs/testing.md#coverage-tiers) § Coverage tiers: no canonical CI
boot attaches the device.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/drivers/docs/driver-model.md](../../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [services/drivers/docs/virtio-architecture.md](../../docs/virtio-architecture.md) | VirtIO transport abstraction, virtqueue internals |
| [docs/device-management.md](../../../../docs/device-management.md) | Driver lifecycle, on-disk loading, DMA safety |
| [docs/console-model.md](../../../../docs/console-model.md) | The console's UART, which the debug port is apart from |
| [docs/capability-model.md](../../../../docs/capability-model.md) | Capability types, rights, delegation, badges |

---

## Summarized By

[Console Model](../../../../docs/console-model.md), [Testing](../../../../docs/testing.md),
[xtask/README.md](../../../../xtask/README.md)
