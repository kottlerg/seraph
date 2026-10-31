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
    ├── main.rs                # Driver entry, IPC service loop, fail-stop
    └── io.rs                  # IoLayout (header + status DMA), descriptor chain submission
```

---

## Endpoint

Devmgr spawns the driver, creates its service endpoint, and delivers BAR
MMIO, IRQ, and the service endpoint in the first bootstrap round, then a
per-device badged devmgr query endpoint in the second. vfsd obtains a
`MOUNT_AUTHORITY`-badged whole-disk `SEND_GRANT` cap through devmgr's
`QUERY_BLOCK_DEVICE`. The delegation chain is owned by
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
| caps[2] | Reserved IPC-shape slot (null today; future userspace-IOMMU grant) |

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
| 7 | `DEVICE_FAULT` | No usable completion: the request could not be queued, the device wrote a status outside `VirtIO`'s set, or the device lost the request (timeout or malformed completion); after a lost request, every later request (see DMA Discipline) |

#### Reserved cap slots and the IOMMU forward-compat shape

`caps[2]` holds the IPC-shape position for a future userspace-IOMMU grant
capability. The kernel transports nothing for this slot today and has no
awareness of any IOMMU semantics at any point in the IOMMU lifecycle —
IOMMU drivers, enforcement, and policy live permanently in userspace. Once
the userspace IOMMU driver lands, that driver and the block driver agree
on a userspace cap shape to occupy this slot, and the block driver
inspects, consumes, and releases the cap entirely in userspace before
issuing the I/O. Reserving the slot now keeps the wire shape stable across
that introduction. IOMMU ownership is defined in
[docs/device-management.md](../../../../docs/device-management.md) § IOMMU Discovery and
Programming.

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
| caps[2] | Reserved IPC-shape slot (null today; future userspace-IOMMU grant) |

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
| 7 | `DEVICE_FAULT` | No usable completion: the request could not be queued, the device wrote a status outside `VirtIO`'s set, or the device lost the request (timeout or malformed completion); after a lost request, every later request (see DMA Discipline) |

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

The driver owns a single 1-page DMA buffer for the request header and
status byte (offsets 0 and 1024). The data segment of every read or
write is the caller-supplied Memory cap: the driver queries `phys_base` via
`cap_info` without mapping the memory cap into its own address space (the
device DMAs to or from the physical address; the driver never touches
the data), then programs the descriptor chain to point at `phys_base`.
The Memory cap is moved back to the caller in every reply, so it never
accumulates in the driver's `CSpace`.

The driver keeps one request in flight and waits for the completion of
that chain, polling and parking on the IRQ notification, for at most
50 seconds. The depth of 1 is the design: the service loop receives one
request, waits for its completion, and replies before it receives the next,
so the virtqueue is sized to one three-descriptor chain (four descriptors,
one ring page). A device whose queue cannot hold three descriptors is
refused at setup: the driver logs and exits.

A request the device loses, by timing out or by publishing a used-ring
element the virtqueue refuses (an id heading no outstanding chain) or one
naming another chain, may still be in flight, so its Memory cap cannot go
back while the device can still DMA into or out of it. The driver resets the device first: once the
reset is acknowledged, the device no longer accesses the virtqueue or
the buffers it describes (`VirtIO` 1.2 §2.4.1). It then replies
`DEVICE_FAULT` with the cap moved back, and fails stop: every later read
or write is answered `DEVICE_FAULT` with its cap moved back, so clients
see an error rather than block on an endpoint nobody serves. A device
that does not acknowledge the reset within a bounded poll may still be
transferring (the driver waits up to five seconds on the monotonic clock),
so the driver logs and exits without replying; the cap is
destroyed with the driver's `CSpace` instead of returning to a caller
who could reuse the memory.

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
