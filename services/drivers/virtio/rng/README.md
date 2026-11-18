# virtio/rng

VirtIO entropy device (virtio-rng) driver: the driver of the `hwrng` device class. It serves
[`hwrng_protocol::READ`](../../../../shared/hwrng-protocol/README.md), answering each read with
bytes the device wrote. It holds the device's capabilities and nothing more: no kernel authority,
and no say in what the bytes are used for. Whoever reads the class decides that.

---

## Source Layout

```
virtio/rng/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                 # READ_AUTHORITY verb-bit gate, read length arithmetic (host-tested)
    └── main.rs                # Driver entry, PCI bring-up, requestq, IPC service loop
```

---

## Endpoint

The driver carries a declaration in the ELF note section `.note.seraph.driver` (PCI `1AF4:1005` and
`1AF4:1044`, class `hwrng`, interrupt optional with one MSI-X vector, DMA, no device-configuration
region, auxiliary tier, no instance limit). Devmgr binds it to each matching virtio-rng PCI device,
carves the device's per-device capabilities (an `Mmio` cap for every range of the BARs its VirtIO
register regions name, its interrupt: one MSI-X vector, else its own derivation of its line's
`Interrupt` cap, a line another device shares included; and the device's DMA capability), and
spawns this driver from the rootfs (`/services/drivers/virtio-rng`). It is not
bootstrap-essential, so it loads lazily through devmgr's `SET_DRIVERS_DIR` subtree cap (see
[docs/device-management.md](../../../../docs/device-management.md)). The driver reports
`DRIVER_READY` on its devmgr query endpoint once its device is set up, immediately before its
service loop, and devmgr serves its endpoint only after that report. Devmgr owns the service
endpoint and mints clients a SEND badged with the `hwrng` class file's verb bits
(`rootfs/config/devmgr/classes/hwrng.class`: `hwrng_protocol::READ_AUTHORITY`) via
`devmgr_labels::QUERY_DEVICE` on the `devmgr.class.hwrng` class SEND (see [devmgr
Responsibilities](../../../devmgr/docs/responsibilities.md#responsibilities)).

---

## Messages

Synchronous call/reply (`SYS_IPC_CALL`). The label, its reply codec, the verb bit and the error
codes live in [`shared/hwrng-protocol`](../../../../shared/hwrng-protocol/README.md), which
specifies the wire shape. No label takes a cap: the driver deletes every cap a request carries
before it replies.

### Label 1: `READ`

**Request:** `data[0]` is `n`, the most bytes the caller takes (no data word asks for 0). Gated
by `READ_AUTHORITY`: a caller whose badge lacks it gets `UNAUTHORIZED` (`2`) at once, and
nothing is posted to the device.

**Reply (`SUCCESS`):** `data[0]` is the byte count `k`, at most `min(n, MAX_READ_BYTES)` (504),
and the bytes follow from `data[1]`, packed little-endian. `READ(0)` answers `k` = 0 without
touching the device. **Reply `NOT_READY` (`3`)**, with no data, when the device fills nothing
within the driver's wait bound (`READ_WAIT`, 1 s); the caller asks again later.

The driver serves one request at a time, so a read waits at most `READ_WAIT` behind the one before
it.

---

## DMA Discipline

The driver owns one DMA page, the request buffer, and the rings of the requestq (virtqueue 0), the
device's only queue (VirtIO 1.2 § 5.4.2). It maps both for the device once at setup, through its
DMA capability, and programs the device only with the device addresses devmgr returns, never with a
physical address
([docs/device-management.md](../../../../docs/device-management.md#dma-authorisation) § DMA
Authorisation). The queue is one descriptor long, so at most one buffer is ever posted.

A `READ` of `n` bytes posts the first `min(n, MAX_READ_BYTES)` bytes of the page as one
device-writable descriptor and notifies the device, then waits for the used ring to return it. The
used length is the device's word, so the driver clamps it to the posted length before it reads,
then to `n`. It copies those bytes into the reply and zeroes them in the page, so a later
completion whose reported length the device did not fill hands out zeros, never bytes already handed
out. A read that times out leaves its buffer posted, and the next read waits for that buffer rather
than posting another; its length is the earlier read's, and the next caller still gets at most what
it asked for.

With an interrupt, an interrupt-service thread is the only waiter on the notification bound to it:
it runs virtio-core's `isr::serve_interrupts`, which on the wired line reads the ISR and
acknowledges every delivery at once, a read in flight or not, as a driver on a shared line must
([driver-model.md](../../docs/driver-model.md) rule 5), and on an MSI-X vector relays each
delivery; either way it signals the read's `wake` notification. Under MSI-X the driver routes the
requestq to vector 0 and configuration changes, which the device has none of, to `NO_VECTOR`; a
device that refuses either leaves the driver with no interrupt. The read's wait on `wake` carries a
10 ms timeout and re-polls the used ring each tick, so a read still completes with no interrupt.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [shared/hwrng-protocol/README.md](../../../../shared/hwrng-protocol/README.md) | The `hwrng` class protocol: `READ`, its reply, the verb bit |
| [services/drivers/docs/driver-model.md](../../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [services/drivers/docs/virtio-architecture.md](../../docs/virtio-architecture.md) | VirtIO transport abstraction, the VirtIO drivers and their classes |
| [docs/driver-binding.md](../../../../docs/driver-binding.md) | Driver declarations and device classes |
| [docs/device-management.md](../../../../docs/device-management.md) | Driver lifecycle, on-disk loading, DMA safety |
| [core/kernel/docs/entropy.md](../../../../core/kernel/docs/entropy.md) | The kernel entropy pool the class is meant to feed |

---

## Summarized By

None
