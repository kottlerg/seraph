# virtio/blk

VirtIO block device driver. Exposes a per-request DMA IPC interface for
filesystem drivers; the data segment of every read targets a Memory
capability the caller transfers in. Every LBA and count on the interface is
in the device's logical blocks: 512 bytes, or the size the device reports
when it offers `VIRTIO_BLK_F_BLK_SIZE` (up to 4096, so 4Kn media serve in
4096-byte blocks). The driver converts to VirtIO's 512-byte request sectors.

---

## Source Layout

```
virtio/blk/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                 # Geometry, transfer-length bound, partition table,
    │                          #   outcome-to-reply mapping (host-tested)
    ├── main.rs                # Driver entry, IPC service loop, interrupt-service thread, fail-stop
    └── io.rs                  # IoLayout (header + status DMA), descriptor chain submission
```

---

## Endpoint

Devmgr spawns the driver, creates its service endpoint, and delivers an `Mmio`
cap for every BAR the device's VirtIO register regions name in the first
bootstrap round, each with its PCI BAR index, then the service endpoint, the
IRQ with its line's `SYS_IRQ_REGISTER` mode, a per-device badged devmgr
query endpoint, and the device's DMA capability in the second (the rounds
`virtio_core::bootstrap` specifies).
The driver maps the BARs into one
register window and reaches each region through its own BAR's mapping. Once
its device is set up, immediately before its service loop, the driver reports
`DRIVER_READY` on the devmgr query endpoint; devmgr serves the driver's
endpoint only after that report, so a driver that exits in its device setup
is never handed to a client (see [devmgr
Responsibilities](../../../devmgr/docs/responsibilities.md#responsibilities)). vfsd
obtains a `MOUNT_AUTHORITY`-badged whole-disk `SEND_GRANT` cap through
devmgr's `QUERY_BLOCK_DEVICE`. The delegation chain is owned by
[docs/storage.md](../../../../docs/storage.md) § Capability Delegation Chain.

Two access tiers exist on this endpoint, distinguished by the kernel-supplied
caller badge; unbadged callers are rejected:

1. **Whole-disk (`MOUNT_AUTHORITY`-badged)** — minted by devmgr on
   `QUERY_BLOCK_DEVICE` and held by vfsd. Reads and writes are bounded only
   by device capacity. Permitted to issue `REGISTER_PARTITION`.
2. **Per-partition (partition badge, `MOUNT_AUTHORITY` clear)** — minted by
   the driver and returned in the `REGISTER_PARTITION` reply; vfsd hands them
   to filesystem drivers. The kernel rejects re-badging a badged source, so
   the caller cannot derive partition caps itself. Reads and writes are
   bounded by the partition LBA range registered for the badge.

---

## Messages

All operations use `SYS_IPC_CALL` (synchronous call/reply). Labels are
defined in `shared/ipc::blk_labels`; error codes in `shared/ipc::blk_errors`.

### Label 2: `REGISTER_PARTITION`

Register a partition LBA range and receive a partition-badged `SEND_GRANT`
cap scoped to it. Callable only with a `MOUNT_AUTHORITY`-badged cap (the
whole-disk cap); callers whose badge lacks it receive `REGISTER_REJECTED`.
The badge identifies the range: registering a range already registered
returns a cap carrying that range's badge, so a remount reuses its entry, and
the driver's table holds one entry per distinct range. The table grows with
those ranges and has no fixed size.

**Request:**

| Field | Value |
|---|---|
| label | 2 |
| data[0] | Caller's `BLK_LABELS_VERSION` |
| data[1] | Base LBA |
| data[2] | Length in blocks (`>= 1`; base + length within device capacity) |

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success), `REGISTER_REJECTED` (4), or `LABEL_VERSION_MISMATCH` (6) |
| caps[0] | On success, the partition-badged `SEND_GRANT` cap on this endpoint |

### Label 3: `BLK_READ_INTO_MEMORY`

Read one or more contiguous blocks into a caller-supplied Memory cap. The
driver writes `count * block_size` bytes starting at offset 0 of the
supplied page, packed contiguously; the rest of the page is unspecified.

**Request:**

| Field | Value |
|---|---|
| label | 3 |
| data[0] | Starting LBA (relative to the caller badge's partition base) |
| data[1] | Block count (`>= 1`; defaults to `1` if absent) |
| caps[0] | Target Memory cap, `MAP | WRITE`, at least `count * block_size` bytes |
| caps[1] | Reserved (null today; future per-request release handle) |
| caps[2] | Reserved IPC-shape slot (null today) |

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success) or one of the error codes below |
| caps[0] | The target Memory cap, moved back to the caller |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `DEVICE_STATUS_IOERR` | VirtIO device returned `VIRTIO_BLK_S_IOERR` |
| 2 | `DEVICE_STATUS_UNSUPP` | VirtIO device returned `VIRTIO_BLK_S_UNSUPP` |
| 3 | `OUT_OF_BOUNDS` | LBA outside the caller badge's partition range |
| 5 | `INVALID_MEMORY_CAP` | Target Memory cap missing `MAP|WRITE`, smaller than `count * block_size`, or absent; or `count` is 0 or `count * block_size` exceeds the u32 descriptor length |
| 7 | `DEVICE_FAULT` | No usable completion: devmgr refused to map the Memory cap for the device, the request could not be queued, the device wrote a status outside `VirtIO`'s set, or the device lost the request (timeout or malformed completion); after a lost request, every later request (see DMA Discipline) |

#### Reserved cap slots

`caps[2]` is a reserved IPC-shape slot, null today. A client lends the
driver only the Memory cap in `caps[0]`; the driver maps it for the device
itself, through its DMA capability, for the request's duration (DMA
Discipline below), so the client passes no grant of its own. DMA
authorisation is defined in
[docs/device-management.md](../../../../docs/device-management.md#dma-authorisation)
§ DMA Authorisation.

`caps[1]` is reserved for a per-request release handle if the cooperative
release protocol grows a block-layer analogue; today the cap is null and
the slot is unused.

### Label 4: `BLK_WRITE_FROM_MEMORY`

Mirror of `BLK_READ_INTO_MEMORY` for the write direction. The driver
reads `count * block_size` bytes starting at offset 0 of the supplied page
and writes them to disk. The memory cap contents past the requested run are not
read.

**Request:**

| Field | Value |
|---|---|
| label | 4 |
| data[0] | Starting LBA (relative to the caller badge's partition base) |
| data[1] | Block count (`>= 1`; defaults to `1` if absent) |
| caps[0] | Source Memory cap, `MAP` rights, at least `count * block_size` bytes |
| caps[1] | Reserved (null today; future per-request release handle) |
| caps[2] | Reserved IPC-shape slot (null today) |

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success) or one of the error codes below |
| caps[0] | The source Memory cap, moved back to the caller |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `DEVICE_STATUS_IOERR` | VirtIO device returned `VIRTIO_BLK_S_IOERR` |
| 2 | `DEVICE_STATUS_UNSUPP` | VirtIO device returned `VIRTIO_BLK_S_UNSUPP` |
| 3 | `OUT_OF_BOUNDS` | LBA outside the caller badge's partition range |
| 5 | `INVALID_MEMORY_CAP` | Source Memory cap missing `MAP`, smaller than `count * block_size`, or absent; or `count` is 0 or `count * block_size` exceeds the u32 descriptor length |
| 7 | `DEVICE_FAULT` | No usable completion: devmgr refused to map the Memory cap for the device, the request could not be queued, the device wrote a status outside `VirtIO`'s set, or the device lost the request (timeout or malformed completion); after a lost request, every later request (see DMA Discipline) |

### Label 5: `BLK_GET_GEOMETRY`

Report the device's logical block size and the caller's addressable length.
Callable with either tier's cap: a `MOUNT_AUTHORITY` badge addresses the
whole device, a partition badge its registered range. vfsd reads the block
size before it reads the GPT, and fatfs before it reads the BPB; the geometry
is fixed for the device's life.

**Request:**

| Field | Value |
|---|---|
| label | 5 |
| data[0] | Caller's `BLK_LABELS_VERSION` |

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success), `OUT_OF_BOUNDS` (3) for a badge naming no range, or `LABEL_VERSION_MISMATCH` (6) |
| data[0] | On success, the logical block size in bytes (a power of two, 512 to 4096) |
| data[1] | On success, the length in blocks: the device capacity, or the partition's length |

---

## DMA Discipline

The driver programs the device only with device addresses devmgr returns
from `DMA_MAP` on the driver's DMA capability, never with a physical address
([docs/device-management.md](../../../../docs/device-management.md#dma-authorisation)
§ DMA Authorisation). It maps its virtqueue rings and its single 1-page DMA
buffer for the request header and status byte (offsets 0 and 1024) once at
setup, for the device to read and write. The data segment of every read or
write is the caller-supplied Memory cap: after checking its rights and size,
the driver maps a derivation of it for the device (to write for a read, to
read for a write) without mapping it into its own address space (the driver
never touches the data), programs the descriptor chain with the device
address devmgr returned, and unmaps it once the request completed or, for a
lost request, once the device is quiesced, before it replies. Each transfer
therefore makes two calls to devmgr's DMA thread besides the device's own
work. The Memory cap is moved back to the caller in every reply, so it never
accumulates in the driver's `CSpace`; a reply the caller cannot take (the caller
died, or its `CSpace` is full) leaves the cap with the driver, which then deletes
it, since the transfer is over and the reference would otherwise keep the frame
out of memmgr's pool for the boot. While the driver holds the cap, memmgr keeps
the frame out of its pool even when the client releases it or dies
([docs/device-management.md](../../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown).

The driver keeps one request in flight and waits for the completion of
that chain, polling and parking on the completion notification, for at most
50 seconds. An interrupt-service thread, the only waiter on the
notification bound to the device's line, signals the completion
notification: it runs virtio-core's `isr::serve_interrupts`, which reads
the ISR and acknowledges every delivery at once, a request in flight or
not, as a driver on a shared line must
([driver-model.md](../../docs/driver-model.md) rule 5), and reads the ISR
on a bounded timeout too, so an interrupt whose edge was lost is still
seen. The depth of 1 is the design: the service loop receives one
request, waits for its completion, and replies before it receives the next,
so the virtqueue is sized to one three-descriptor chain (four descriptors,
one ring page). A device whose queue cannot hold three descriptors is
refused at setup: the driver logs and exits.

A request the device loses, by timing out or by publishing a used-ring element the virtqueue refuses
(an id heading no outstanding chain) or one naming another chain, may still be in flight, so its
Memory cap cannot go back while the device can still DMA into or out of it. The driver resets the
device first: once the reset is acknowledged, the device no longer accesses the virtqueue or the
buffers it describes (`VirtIO` 1.2 §2.4.1). It then replies `DEVICE_FAULT` with the cap moved back,
and fails stop: every later read or write is answered `DEVICE_FAULT` with its cap moved back, so
clients see an error rather than block on an endpoint nobody serves. A device that does not
acknowledge the reset within a bounded poll may still be transferring (the driver waits up to five
seconds on the monotonic clock), so the driver logs and exits without replying; the cap stays in the
driver's `CSpace`, which procmgr keeps for the dead driver until devmgr has confirmed the device
stopped and released the driver's hold, instead of returning to a caller who could reuse the
memory, so memmgr returns the frame to its pool only after that release.

The notify-after-avail-update memory-ordering pair (release fence on the
producer, the device's implicit load-acquire on the doorbell MMIO)
matches the VirtIO 1.2 §2.9.3 driver-notification contract.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/drivers/docs/driver-model.md](../../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [services/drivers/docs/virtio-architecture.md](../../docs/virtio-architecture.md) | VirtIO transport abstraction, virtqueue internals |
| [services/fs/docs/fs-driver-protocol.md](../../../fs/docs/fs-driver-protocol.md) | Filesystem-driver IPC; the only client of this driver today |
| [docs/device-management.md](../../../../docs/device-management.md) | Driver lifecycle, DMA safety, security boundary |
| [docs/ipc-design.md](../../../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/capability-model.md](../../../../docs/capability-model.md) | Capability types, rights, delegation, badges |

---

## Summarized By

[Storage](../../../../docs/storage.md),
[Filesystem Driver Protocol](../../../fs/docs/fs-driver-protocol.md)
