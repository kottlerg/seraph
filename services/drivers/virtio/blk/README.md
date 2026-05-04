# virtio/blk

VirtIO block device driver. Exposes a per-request DMA IPC interface for
filesystem drivers; the data segment of every read targets a Frame
capability the caller transfers in.

---

## Source Layout

```
virtio/blk/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                # Driver entry, IPC service loop, partition table
    └── io.rs                  # IoLayout (header + status DMA), descriptor chain submission
```

---

## Endpoint

Devmgr spawns the driver and delegates per-device capabilities (BAR MMIO,
IRQ, MSI-X). The driver creates a service endpoint and registers it with
devmgr's device registry; vfsd queries devmgr to obtain the whole-disk
SEND cap.

Two access tiers exist on this endpoint, distinguished by the kernel-supplied
caller token:

1. **Whole-disk (untokened)** — vfsd holds this cap directly. Permitted to
   issue `REGISTER_PARTITION` to mint partition-scoped tokens.
2. **Per-partition (tokened)** — derived by vfsd from the whole-disk cap and
   handed to filesystem drivers. Reads are bounded by the partition LBA range
   registered for the token.

---

## Messages

All operations use `SYS_IPC_CALL` (synchronous call/reply). Labels are
defined in `shared/ipc::blk_labels`; error codes in `shared/ipc::blk_errors`.

### Label 2: `REGISTER_PARTITION`

Mint a partition-scoped binding for a tokened SEND cap. Callable only over
the whole-disk endpoint; tokened callers are rejected.

**Request:**

| Field | Value |
|---|---|
| label | 2 |
| data[0] | Token to bind |
| data[1] | Base LBA |
| data[2] | Length in sectors |

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success) or `RegisterRejected` (4) |

### Label 3: `BLK_READ_INTO_FRAME`

Read one or more contiguous sectors into a caller-supplied Frame. The
driver writes `count * 512` bytes starting at offset 0 of the supplied
page, packed contiguously; the rest of the page is unspecified.

**Request:**

| Field | Value |
|---|---|
| label | 3 |
| data[0] | Starting LBA (relative to the caller token's partition base) |
| data[1] | Sector count (`>= 1`; defaults to `1` if absent) |
| caps[0] | Target Frame, `MAP \| WRITE`, at least `count * 512` bytes |
| caps[1] | Reserved (null today; future per-request release handle) |
| caps[2] | Reserved IPC-shape slot (null today; future userspace-IOMMU grant) |

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success) or one of the error codes below |
| caps[0] | The target Frame, moved back to the caller |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `DeviceStatusIoerr` | VirtIO device returned `VIRTIO_BLK_S_IOERR` |
| 2 | `DeviceStatusUnsupp` | VirtIO device returned `VIRTIO_BLK_S_UNSUPP` |
| 3 | `OutOfBounds` | LBA outside the caller token's partition range |
| 5 | `InvalidFrameCap` | Target Frame missing `MAP\|WRITE`, sized other than one page, or absent |

#### Reserved cap slots and the IOMMU forward-compat shape

`caps[2]` holds the IPC-shape position for a future userspace-IOMMU grant
capability. The kernel transports nothing for this slot today and has no
awareness of any IOMMU semantics at any point in the IOMMU lifecycle —
IOMMU drivers, enforcement, and policy live permanently in userspace. Once
the userspace IOMMU driver lands, that driver and the block driver agree
on a userspace cap shape to occupy this slot, and the block driver
inspects, consumes, and releases the cap entirely in userspace before
issuing the I/O. Reserving the slot now keeps the wire shape stable across
that introduction.

`caps[1]` is reserved for a per-request release handle if the cooperative
release protocol grows a block-layer analogue; today the cap is null and
the slot is unused.

---

## DMA Discipline

The driver owns a single 1-page DMA buffer for the request header and
status byte (offsets 0 and 1024). The data segment of every read is the
caller-supplied Frame: the driver queries `phys_base` via `cap_info`
without mapping the frame into its own address space (the device DMAs to
the physical address; the driver never reads the data), then programs
the descriptor chain to point at `phys_base`. The Frame cap is
moved back to the caller in the reply on every outcome, so it never
accumulates in the driver's `CSpace`.

The notify-after-avail-update memory-ordering pair (release fence on the
producer, the device's implicit load-acquire on the doorbell MMIO)
matches the VirtIO 1.2 §2.9.3 driver-notification contract.

---

## Sentinel Values

Capabilities injected at driver creation time are identified by sentinel
values in the `CapDescriptor.aux0` field, per
[services/drivers/docs/driver-model.md](../../docs/driver-model.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/drivers/docs/driver-model.md](../../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [services/drivers/docs/virtio-architecture.md](../../docs/virtio-architecture.md) | VirtIO transport abstraction, virtqueue internals |
| [services/fs/docs/fs-driver-protocol.md](../../../fs/docs/fs-driver-protocol.md) | Filesystem-driver IPC; the only client of this driver today |
| [docs/device-management.md](../../../../docs/device-management.md) | Driver lifecycle, DMA safety, security boundary |
| [docs/ipc-design.md](../../../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/capability-model.md](../../../../docs/capability-model.md) | Capability types, rights, delegation, tokens |

---

## Summarized By

None
