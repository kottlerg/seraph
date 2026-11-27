# virtio/blk

VirtIO block device driver. Exposes two DMA IPC interfaces to block clients:
per-request transfers, whose data segment is a Memory capability the caller
transfers in with each request, and registered regions, staging buffers a
client registers once, which the driver maps for the device once and which
each transfer names by a region cap and an offset. Every LBA and count on the interface is
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
    ├── lib.rs                 # Geometry, transfer-length bound, partition table, region table
    │                          #   (slots, generations, badges, correlators, region bounds),
    │                          #   outcome-to-reply mapping, request timing (host-tested)
    ├── main.rs                # Driver entry, IPC service loop, region handlers, sweeper thread,
    │                          #   interrupt-service thread, fail-stop
    └── io.rs                  # IoLayout (header + status DMA), descriptor chain submission
```

---

## Endpoint

The driver carries a declaration in the ELF note section `.note.seraph.driver` (PCI `1AF4:1001`
and `1AF4:1042`, class `block`, interrupt required, DMA, VirtIO status reset, boot tier), and
devmgr binds it to each matching device ([driver-binding.md](../../../../docs/driver-binding.md)).
Devmgr spawns the driver, creates its service endpoint, and delivers the resource list of
`driver_binding::resources`: an `Mmio` cap for every range of the BARs the device's VirtIO
register regions name, each with its PCI BAR index and its offset in the BAR, clipped to the pages
the regions reach and less any page holding the device's MSI-X table or Pending Bit Array, the
interrupt (one MSI-X vector, which the declaration asks for, or the wired line with its
`SYS_IRQ_REGISTER` mode), then the end round with the service endpoint, a per-device badged devmgr
query endpoint, and the device's DMA capability (read by
`virtio_core::bootstrap::DeliveredDevice`). The driver maps the ranges into one register window
and reaches each region through its own BAR's mapping. Under MSI-X it routes the requestq to vector
0 and configuration changes to `NO_VECTOR`, and exits if the device refuses either; it logs the
interrupt it was given (`interrupt: MSI-X, 1 vector` or `interrupt: wired line`). Once
its device is set up, immediately before its service loop, the driver reports
`DRIVER_READY` on the devmgr query endpoint; devmgr serves the driver's
endpoint only after that report, so a driver that exits in its device setup
is never handed to a client (see [devmgr
Responsibilities](../../../devmgr/docs/responsibilities.md#responsibilities)). vfsd
obtains a `MOUNT_AUTHORITY`-badged whole-disk `SEND_GRANT` cap through
devmgr's `QUERY_DEVICE` on the `block` class SEND. The delegation chain is owned by
[docs/storage.md](../../../../docs/storage.md) § Capability Delegation Chain.

Two access tiers exist on this endpoint, distinguished by the kernel-supplied
caller badge; unbadged callers are rejected:

1. **Whole-disk (`MOUNT_AUTHORITY`-badged)** — minted by devmgr on
   `QUERY_DEVICE` on the `block` class and held by vfsd. Reads and writes are bounded only
   by device capacity. Permitted to issue `REGISTER_PARTITION`.
2. **Per-partition (partition badge, `MOUNT_AUTHORITY` clear)** — minted by
   the driver and returned in the `REGISTER_PARTITION` reply; vfsd keeps each
   and hands a derivation of it to the filesystem driver. The kernel rejects
   re-badging a badged source, so the caller cannot derive partition caps
   itself. Reads and writes are bounded by the partition LBA range registered
   for the badge.

Either tier's cap may register regions (`BLK_REGISTER_REGION`). Each region
gets its own **region cap**, a `SEND` on this endpoint the driver mints with
a region badge: bit 62 set, with the region's slot and the slot's generation
below it. A region cap serves only the three region labels, and names its one
region, bounded by the range of the badge that registered it; every holder of
a partition cap shares the partition badge, so the partition badge alone names
no region. Partition badges stay below bit 62, and `MOUNT_AUTHORITY` is bit
63, so the three kinds never collide. A slot's generation advances at each
registration, so a region cap of an earlier registration of the slot names
nothing. One more badge in the region space, `SWEEPER_BADGE`, is held only by
the driver's own sweeper thread (§ DMA Discipline).

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

### Label 6: `BLK_REGISTER_REGION`

Register a staging buffer. Sent on a partition or whole-disk cap. The driver
checks the Memory cap, maps it for the device once with the access the
request names (`DMA_MAP`), and keeps it, and the mapping, until the region is
unregistered: by `BLK_UNREGISTER_REGION`, by `BLK_END_REGIONS` on the
registering badge, by the end of the client's lease (the last copy of the
liveness cap outside the driver is gone, its process having died or deleted
it), by the next transfer after the client revoked the Memory cap it
registered, or by devmgr's withdrawal of the driver. The
client keeps its own copy of the Memory cap, and keeps only the partition's
own data in the region: the device may write it for the whole registration,
so the client copies data out once before it parses or checks it.

**Request:**

| Field | Value |
|---|---|
| label | 6 |
| data[0] | Caller's `BLK_LABELS_VERSION` |
| data[1] | The device's access: `REGION_DEVICE_READS` (1), the device only reads the region, which serves `BLK_WRITE_REGION` alone; or `REGION_DEVICE_READS_WRITES` (3), which serves both transfer labels |
| caps[0] | Memory cap over the region, `MAP`, and `MAP | WRITE` for access 3; the driver keeps it (the caller keeps a copy) |

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success) or one of the error codes below |
| caps[0] | On success, the region cap: a `SEND` on this endpoint naming this region alone |
| caps[1] | On success, the liveness cap: a rights-less derivation of a Notification the driver made for the region; the registration ends once no copy of it is left outside the driver |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 3 | `OUT_OF_BOUNDS` | The badge is neither a whole-disk badge nor a registered partition's |
| 5 | `INVALID_MEMORY_CAP` | The cap is absent, not a Memory cap, empty, or missing the rights the access needs; or `data[1]` names no access |
| 6 | `LABEL_VERSION_MISMATCH` | `data[0]` is not the driver's `BLK_LABELS_VERSION` |
| 7 | `DEVICE_FAULT` | The driver has failed stop after a lost request, or devmgr refused the mapping for a reason other than its bounds |
| 8 | `REGION_LIMIT` | The partition already holds `MAX_REGIONS_PER_PARTITION` (4) regions, the driver's `MAX_REGIONS` (32) slots are taken, devmgr refused the mapping at its `MAX_MAPPINGS_PER_DEVICE` or for want of device address space or memory (`OUT_OF_RESOURCES`), or the driver could not fund the region's capabilities |

A refused request deletes the Memory cap it carried.

### Label 7: `BLK_READ_REGION`

Read blocks of the region's partition into the region. Sent on a region cap.
The driver programs the chain at the region's device address plus the
offset and makes no call to devmgr.

**Request:**

| Field | Value |
|---|---|
| label | 7 |
| data[0] | Caller's `BLK_LABELS_VERSION` |
| data[1] | Starting LBA, relative to the base of the partition that registered the region |
| data[2] | Block count (`>= 1`) |
| data[3] | Byte offset in the region, a multiple of the logical block size |

**Reply:** label 0 (success) or one of the error codes below; no data, no
cap. A cap the request carries is deleted.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `DEVICE_STATUS_IOERR` | VirtIO device returned `VIRTIO_BLK_S_IOERR` |
| 2 | `DEVICE_STATUS_UNSUPP` | VirtIO device returned `VIRTIO_BLK_S_UNSUPP` |
| 3 | `OUT_OF_BOUNDS` | The cap names no live region, or the run leaves the partition; or the Memory cap the driver kept for the region no longer answers `cap_info`, its client having revoked the cap it registered, and the driver has unregistered the region as label 9 does, before programming the device |
| 5 | `INVALID_MEMORY_CAP` | The offset is not a block multiple, the run passes the region's end, the count is 0 or past the u32 descriptor length, or the region is one the device only reads |
| 6 | `LABEL_VERSION_MISMATCH` | `data[0]` is not the driver's `BLK_LABELS_VERSION` |
| 7 | `DEVICE_FAULT` | No usable completion: the request could not be queued, the device wrote a status outside `VirtIO`'s set, or the device lost the request; after a lost request, every later request (see DMA Discipline). The region stays registered |

### Label 8: `BLK_WRITE_REGION`

Write blocks of the region's partition from the region: the request words,
reply and error codes of `BLK_READ_REGION`, with label 8, and either access
serves it.

### Label 9: `BLK_UNREGISTER_REGION`

Unregister the region. Sent on its region cap, `data[0]` the caller's
`BLK_LABELS_VERSION`. Before the reply the driver withdraws the region's
mapping (`DMA_UNMAP`, which replies once the device reaches none of its
frames), deletes the Memory cap it kept, and revokes every copy of the
region cap and of the liveness cap. Served after the driver has failed stop
too. Reply: label 0 (success), `OUT_OF_BOUNDS` (3) for a cap naming no live
region (a second unregistration included), or `LABEL_VERSION_MISMATCH` (6).

### Label 10: `BLK_END_REGIONS`

End every region registered through the badge of the partition or
whole-disk cap the request is sent on, `data[0]` the caller's
`BLK_LABELS_VERSION`. The driver unregisters each as `BLK_UNREGISTER_REGION`
does, all before the reply, so once the reply arrives the device reaches no
frame of them and no copy of their region or liveness caps is left. Served
after the driver has failed stop too. Reply: label 0 (success), whether or
not the badge held a region; `OUT_OF_BOUNDS` (3) on a region cap or an
unbadged cap; or `LABEL_VERSION_MISMATCH` (6).

A region outlives the partition cap it was registered on: its region cap is
minted from this endpoint, so a revoke of the partition cap does not reach
it. Whoever grants derivations of a partition or whole-disk cap and revokes
them therefore MUST send `BLK_END_REGIONS` on the cap it kept after each
revoke, before it deletes that cap or grants a new derivation; vfsd does so
at each revoke
([namespace-composition.md](../../../vfsd/docs/namespace-composition.md#revocation)
§ Revocation). The order makes the end complete: after the revoke the cut-off
holder can send no registration, and one it sent before the revoke is ahead
of the end on this endpoint's queue, which the driver serves in order, so the
end unregisters it too. A driver that died between the revoke and the end
took its regions with it: devmgr withdraws a dead driver and revokes its
service endpoint, from which every region cap derives
([docs/device-management.md](../../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown), so the granter's call failing for the driver's death
leaves no region; any other failure leaves the cut-off
holder's regions reachable through their region caps until it unregisters
them or its process ends, and the granter then grants the partition to no
new holder. Any holder of a badge can end that badge's regions: on a
partition, the one holder the granter allows at a time; on the whole-disk
badge, the `MOUNT_AUTHORITY` holders.

### Internal label: `SWEEP`

`virtio_blk::SWEEP` (`0x100`) is the sweeper thread's request to the service
loop, `data[0]` the correlator of a sole-reference post (§ DMA Discipline).
The driver honours it only from `SWEEPER_BADGE`, which only the sweeper
holds; any other caller is answered `UNKNOWN_OPCODE`.

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
out of memmgr's pool for the boot. While the driver holds the cap, and while
the data segment's mapping stands, memmgr keeps the frame out of its pool even
when the client releases it or dies
([docs/device-management.md](../../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown).

A registered region is mapped once, at `BLK_REGISTER_REGION`, and its
transfers make no call to devmgr, with or without an IOMMU: the device reaches
the region from the registration's reply to the unregistration's reply. The
driver keeps the region's Memory cap, from which devmgr's copy for the
mapping is derived, and a region record of its partition, slot, generation,
device address, length and access, in a table of `MAX_REGIONS` slots; each
partition holds at most `MAX_REGIONS_PER_PARTITION` (4) live regions, the
whole-disk badge counting as one partition. Unmapping is synchronous:
`BLK_UNREGISTER_REGION` replies only after `DMA_UNMAP` has, so no
deferred-unmap window exists.

A client whose process ends without unregistering its regions loses its
lease through the liveness cap. The driver binds each region's liveness
Notification to an event queue of its own with `SYS_CAP_BIND_SOLE_REFERENCE`,
the correlator the region's slot and generation, so the kernel posts once the
driver's parent cap is the Notification's only reference: once the client's
`CSpace` teardown, or its own deletion of the cap, has removed every copy. A
sweeper thread waits on the queue and hands each post to the service loop as
a `SWEEP` request on a `SEND` of its own, so the region table is touched
only by the service loop's thread and no lock is held across a device wait or
a call to devmgr. The service loop unregisters the region the post names as
`BLK_UNREGISTER_REGION` would, with no further block request needed; a post
for an earlier generation of the slot is dropped. An unregistered region's
binding posts too, when the unregistration revokes the liveness cap: its slot
is retiring until that post, which frees it, so each slot has at most one
binding awaiting its post and the queue's `MAX_REGIONS` observer nodes
cover every binding. Until the region is unregistered, its frames stay out of
memmgr's pool through the driver's Memory cap and devmgr's
([memory-pool.md](../../../memmgr/docs/memory-pool.md) § Reclamation), unless
the client revokes the cap it registered, which takes both copies with it:
before each region transfer the driver checks that its kept cap still
answers `cap_info`, and unregisters a region whose cap does not, so the
frames of a revoked region reach the device during at most the one request
in flight, the window the per-transfer path has
([docs/device-management.md](../../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown).
Unregistration relies on the depth of 1 below: no request on the region is
in flight while the service loop unregisters it. A deeper queue would count
each region's requests and unmap once none is left.

The driver keeps one request in flight and waits for the completion of
that chain, checking the used ring and parking on the completion
notification, for at most 50 seconds. An interrupt-service thread, the only
waiter on the notification bound to the device's interrupt, signals the
completion notification: it runs virtio-core's `isr::serve_interrupts`. On
the wired line that reads the ISR and acknowledges every delivery at once,
a request in flight or not, as a driver on a shared line must
([driver-model.md](../../docs/driver-model.md) rule 5), and reads the ISR
on a bounded timeout too, so an interrupt whose edge was lost is still
seen; on an MSI-X vector it relays each delivery. The depth of 1 is the
design: the service loop receives one request, waits for its completion,
and replies before it receives the next, so the virtqueue is sized to one
three-descriptor chain (four descriptors, one ring page). A device whose
queue cannot hold three descriptors is refused at setup: the driver logs and
exits.

A request the device loses, by timing out or by publishing a used-ring element the virtqueue refuses
(an index past the outstanding chains, or an id heading none) or one naming another chain, may still
be in flight, so its Memory cap cannot go back while the device can still DMA into or out of it. The
driver resets the device first: once the reset is acknowledged, the device no longer accesses the
virtqueue or the buffers it describes (`VirtIO` 1.2 §2.4.1). It then replies `DEVICE_FAULT` with the
cap moved back, and fails stop: every later read or write is answered `DEVICE_FAULT` with its cap
moved back, and so is every region transfer and registration, so clients see an error rather than
block on an endpoint nobody serves. A lost region transfer leaves its region registered: the reset
device reaches none of it, and its unregistration is still served. A device that
does not acknowledge the reset within a bounded poll may still be transferring (the driver waits up
to five seconds on the monotonic clock), so the driver logs and exits without replying, leaving the
data segment's DMA mapping standing; the cap is destroyed with the driver's `CSpace` instead of
returning to a caller who could reuse the memory, and devmgr's capability for the standing mapping
keeps the frame out of memmgr's pool until devmgr has confirmed the device stopped
([docs/device-management.md](../../../../docs/device-management.md#dma-safe-teardown) § DMA-Safe
Teardown).

The notify-after-avail-update memory-ordering pair (release fence on the
producer, the device's implicit load-acquire on the doorbell MMIO)
matches the VirtIO 1.2 §2.9.3 driver-notification contract.

---

## Slow requests

A request that takes one second or longer, from the start of its data segment's map to the end
of its unmap, is logged before its reply as a warning saying where the time went: the map and
the unmap (each a call to devmgr's DMA thread, which programs the IOMMU when one confines the
device), and the device's work from the submission to the completion, with what ended the last
completion wait before the completion was found (an interrupt the interrupt-service thread
relayed, the wait's end with no signal, a failed wait, or no wait at all) and how many waits there
were (one line, wrapped here):

```text
slow request: read of 8 blocks at sector 34816 (badge 0x2) took 43512 ms:
    map 43497 ms, device 12 ms (completion by interrupt, wait count 1), unmap 3 ms
```

A region transfer makes no map or unmap, so its line shows both as 0 ms and its time is the
device's. The badge is the client's partition badge, one with `MOUNT_AUTHORITY` set, or a region
badge (bit 62 set). A request lost
after 50 seconds logs this line besides its own. A request takes milliseconds otherwise; the
bound is a fifth of vfsd's bound on a filesystem driver's answer to `FS_UNMOUNT`
(`FS_UNMOUNT_TIMEOUT_MS`, 5 s, [docs/limits.md](../../../../docs/limits.md)), the tightest bound a
client puts on a call that waits on a filesystem driver and so on this driver, since a filesystem
request makes several block calls. The fatfs driver logs a request it held too long, with the
time its block calls took ([fat § Slow requests](../../../fs/fat/README.md#slow-requests)). The
line adds four clock reads to a request and nothing else to its path.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/drivers/docs/driver-model.md](../../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [services/drivers/docs/virtio-architecture.md](../../docs/virtio-architecture.md) | VirtIO transport abstraction, virtqueue internals |
| [services/fs/docs/fs-driver-protocol.md](../../../fs/docs/fs-driver-protocol.md) | Filesystem-driver IPC; the filesystem drivers are clients of this driver |
| [services/swapd/docs/operation.md](../../../swapd/docs/operation.md) | The swap service, the other client: raw slot reads and writes through its partition cap (`BLK_GET_GEOMETRY`, `BLK_READ_INTO_MEMORY`, `BLK_WRITE_FROM_MEMORY`) |
| [docs/device-management.md](../../../../docs/device-management.md) | Driver lifecycle, DMA safety, security boundary |
| [docs/ipc-design.md](../../../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/capability-model.md](../../../../docs/capability-model.md) | Capability types, rights, delegation, badges |

---

## Summarized By

[Storage](../../../../docs/storage.md),
[Filesystem Driver Protocol](../../../fs/docs/fs-driver-protocol.md)
