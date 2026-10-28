# Filesystem Driver Protocol

IPC surface a filesystem driver implements **on top of** the cap-
native namespace protocol. The namespace surface (`NS_LOOKUP`,
`NS_STAT`, `NS_READDIR`, name validation, rights composition, error
codes) is specified in
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md);
this document covers the labels that remain fs-driver-specific:

- `FS_MOUNT` — vfsd-to-driver BPB-validation probe at mount time.
- `FS_READ` — inline read on a per-node badged cap.
- `FS_READ_MEMORY` / `FS_RELEASE_MEMORY` / `FS_RELEASE_ACK` — memory-cap
  read protocol with cooperative release.
- `FS_CLOSE` — release driver-side per-node bookkeeping; the holder
  still `cap_delete`s its node cap to drop the kernel reference.
- `END_OF_DIR` — readdir terminator, reused by `NS_READDIR`.

A driver runs as a separate process. After `FS_MOUNT` succeeds, the
driver dispatches incoming requests by their badge shape:

- `badge == 0` — service-level request from vfsd (only `FS_MOUNT`
  today).
- `badge != 0` carrying namespace rights in bits 40..64 — node-cap
  request (badge layout per
  [`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
  § Badge shape). Per-node opcodes (`NS_*`, `FS_READ`, `FS_READ_MEMORY`,
  `FS_RELEASE_MEMORY`, `FS_CLOSE`) are dispatched by label.

---

## Endpoint surface

A filesystem driver exposes one IPC endpoint, used as both:

- the un-badged **service endpoint** (vfsd holds a SEND, derives
  per-node badged SENDs); and
- the un-badged **namespace endpoint** routed through
  [`namespace_protocol::dispatch_request`] for `NS_*` dispatch.

vfsd delivers the endpoint cap (all rights: receive and badge
derivation) in the driver's bootstrap round; see
[Bootstrap caps](#bootstrap-caps). The same endpoint is also the
kernel-derivation parent for every node cap the driver ever issues
via `cap_derive_badge`.

Numeric label values live in [`ipc::fs_labels`] (this document) and
[`ipc::ns_labels`] (namespace-protocol document).

---

## Label 10: `FS_MOUNT`

Mount-time probe. Sent by vfsd on the un-badged service endpoint
after the driver process is spawned and the partition is registered
with virtio-blk. The driver MUST read the superblock / BPB through
its block device endpoint and reply success or a typed error.

**Request**

| Field | Value |
|---|---|
| `label` | `10` |
| `data[0]` | Caller's `ipc::FS_LABELS_VERSION` |

**Reply (success)**: `label = 0`, empty body.

**Reply (error)**: `label = ipc::fs_errors::*`:
`LABEL_VERSION_MISMATCH` when `data[0]` differs from the driver's
`FS_LABELS_VERSION` (checked before the BPB is read), else e.g.
`IO_ERROR`, or `NOT_FOUND` for a malformed BPB or one whose sector size
is not 512 bytes (the only size the FAT driver reads).

The block device endpoint arrives in the driver's bootstrap round;
see [Bootstrap caps](#bootstrap-caps).

---

## Label 2: `FS_READ`

Inline read against a per-node badged cap. The kernel delivers the
node's `(NodeId, NamespaceRights)` badge to the driver via
`ipc_recv.badge`; the driver MUST verify the `READ` rights bit and
reject with `fs_errors::PERMISSION_DENIED` otherwise.

Used for short reads (≤ 504 bytes that fit within the current page);
larger or page-straddling reads use
[`FS_READ_MEMORY`](#label-7-fs_read_memory). Which label a read uses is
client-side policy: the server accepts either, and answers an inline
request for more than 504 bytes with a short read of at most 504; see
[Inline-vs-memory-cap crossover](#inline-vs-memory-cap-crossover-client-policy).

**Request**

| Field | Value |
|---|---|
| `label` | `2` |
| `data[0]` | Byte offset |
| `data[1]` | Maximum bytes to read; the server clamps it to 504 bytes (`(MSG_DATA_WORDS_MAX - 1) × 8`, the inline reply ceiling after the count word) |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | Bytes actually read |
| `data[1..]` | File data, packed little-endian |

A read at or past end of file succeeds with `data[0] = 0`.

**Reply (error)**: `label = ipc::fs_errors::*`: `PERMISSION_DENIED`
(the badge lacks `READ`), `INVALID_BADGE` (the badge names no node, or
a directory), `IO_ERROR` (the file's cluster chain is corrupt or a
block read failed).

---

## Label 7: `FS_READ_MEMORY`

Memory-cap read. The driver returns a single-page Memory cap with
attenuated rights (`MAP` only: read-only mapping authority) covering
the cached page that contains the requested byte. The client maps the
memory cap, reads up to `bytes_valid` bytes starting at
`memory_data_offset`, then releases the page either synchronously after
the read, by sending [`FS_RELEASE_MEMORY`](#client-to-driver-release)
on the node cap, or in response to a driver-initiated
[`FS_RELEASE_MEMORY`](#driver-to-client-release) arriving on the
per-process release endpoint.

The request `offset` has no alignment requirement; the driver reports
where the file's content for `offset` lives within the returned memory cap
(`memory_data_offset`) and how many contiguous valid bytes follow
(`bytes_valid`). `bytes_valid` is bounded by file end, the underlying
filesystem cluster boundary, and the page tail
(`PAGE_SIZE - memory_data_offset`).

The cookie is client-chosen, opaque to the driver, and MUST be non-
zero (`0` collides with the driver-side `OutstandingPage::None`
sentinel).

**Request**

| Field | Value |
|---|---|
| `label` | `7` |
| `data[0]` | Byte offset (any) |
| `data[1]` | Release cookie (non-zero, client-chosen) |
| `caps[0]` | Optional per-process release-endpoint SEND (see below) |

A client that takes part in cooperative release sends its per-process
release-endpoint SEND in `caps[0]` of an `FS_READ_MEMORY` for the file,
and MAY repeat it on later `FS_READ_MEMORY` requests until one carrying
it gets a success reply. Clients that opt out of cooperative release
omit the cap on every call, and eviction then revokes the page without
the cooperative round-trip. The driver deletes every carried SEND it
does not record, and every cap beyond `caps[0]`.

The driver keeps this read-side bookkeeping (outstanding pages and the
recorded release endpoint) in a lazily-allocated `OpenFile` slot keyed
by node, not by (client, file) pair. Every client that opens a file
resolves to the same node and so shares that one slot. The driver
records the first release SEND carried by an `FS_READ_MEMORY` that
reaches the node's slot (one refused before the slot exists has its
SEND deleted), so the eviction worker routes cooperative
[`FS_RELEASE_MEMORY`](#label-8-fs_release_memory) for any client's
page to that client, and a later client is in effect opted out.
One client's [`FS_CLOSE`](#label-3-fs_close) revokes every client's
outstanding pages on the file. This sharing is a defect: the driver
cannot tell the clients of one node apart, tracked in
[#530](https://github.com/kottlerg/seraph/issues/530).

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | `bytes_valid` (zero on EOF) |
| `data[1]` | Cookie echoed back |
| `data[2]` | `memory_data_offset` |
| `caps[0]` | Memory cap (`MAP` rights, single page; omitted on EOF) |

**Reply (error)**: `label = ipc::fs_errors::*`: `PERMISSION_DENIED`
(the badge lacks `READ`), `INVALID_BADGE` (the badge names no node, or
a directory), `BAD_MEMORY_OFFSET` (cookie zero), `TOO_MANY_OPEN` (the
driver's open-file table, or the node's outstanding-page table, is
full), `IO_ERROR` (the file's cluster chain is corrupt, a block read
failed, or every cache page is held; the client MAY retry, since the
driver queues a held page for eviction).

---

## Inline-vs-memory-cap crossover (client policy)

The choice between [`FS_READ`](#label-2-fs_read) and
[`FS_READ_MEMORY`](#label-7-fs_read_memory) is **client-side policy**, not
protocol. The server accepts whichever label arrives; the cost of the
wrong pick falls entirely on the client.

The reference policy lives in `runtime/ruststd/src/sys/fs/seraph.rs`:

```text
inline iff  want <= READ_INLINE_THRESHOLD
       AND  (offset mod PAGE_SIZE) + want <= PAGE_SIZE
memory cap  otherwise
```

`READ_INLINE_THRESHOLD = 504` bytes. This is the FS_READ IPC payload
ceiling — `MSG_DATA_WORDS_MAX` (64, in `abi/syscall`) data words × 8
bytes, minus the 8-byte length prefix in word 0. Above this size a
single inline reply cannot carry the bytes; below it the per-call cost
is strictly cheaper than the memory-cap path on both supported architectures.

The page-alignment clause forces the memory-cap path for any read that straddles a
page tail even if its size fits inline, because the memory-cap path's
single-page granularity matches the on-disk page-cache layout, whereas
an inline reply spanning two pages would force the server to assemble
contiguous bytes across the boundary.

### Measured per-call cost (`fsbench`, debug builds)

Source: [programs/fsbench/README.md](../../../programs/fsbench/README.md), which owns the
method. The bench loops 256 timed iterations of "seek to 0; read N bytes via the chosen
path" against a 64 KiB fixture (`/data/svctest/bench.bin`); the per-path buffer sizes and
cycle sources are in that README's
[§ Method](../../../programs/fsbench/README.md#method). Numbers below are `cycles_mean`.

**x86_64 (KVM-accelerated, TSC = hardware cycles)**

| Size (B) | Inline calls | Inline cycles | Memory-cap calls | Memory-cap cycles |
|---------:|-------------:|--------------:|------------:|-------------:|
| 16       | 1            | 61 426        | 1           | 123 139      |
| 1 024    | 3            | 236 906       | 1           | 130 553      |
| 4 096    | 9            | 938 019       | 1           | 244 221      |
| 16 384   | 36           | 3 780 641     | 4           | 1 000 699    |
| 65 536   | 144          | 15 347 991    | 16          | 3 987 730    |

**riscv64 (TCG-emulated, `cycle` CSR via `scounteren.CY`)**

| Size (B) | Inline calls | Inline cycles | Memory-cap calls | Memory-cap cycles |
|---------:|-------------:|--------------:|------------:|-------------:|
| 16       | 1            | 548 333       | 1           | 1 232 195    |
| 1 024    | 3            | 2 131 616     | 1           | 1 383 683    |
| 4 096    | 9            | 8 205 397     | 1           | 2 389 154    |
| 16 384   | 36           | 33 249 701    | 4           | 9 735 094    |
| 65 536   | 144          | 134 748 016   | 16          | 39 159 872   |

**Reading the table:** the single-call inline cost is consistently
≈ 0.5× the single-call memory-cap cost on both architectures. Once the
request exceeds 504 bytes the inline path must issue ≥ 2 calls and
loses to the single memory-cap call. Below 504 bytes inline always wins.
The threshold is therefore set to the IPC payload ceiling: not by
coincidence, but by measurement.

Absolute riscv64 cycles run ≈ 10× x86_64 because riscv64 boots under
TCG (no KVM); the *ratio* between paths is what informs the policy.

---

## Label 8: `FS_RELEASE_MEMORY`

Release of a previously-returned Memory cap, in either direction:
driver-to-client for cooperative eviction, and client-to-driver for
synchronous release after a read.

### Driver-to-client release

Sent by the driver's eviction worker on the per-process release
endpoint cap recorded in the node's `OpenFile` slot, the first one an
[`FS_READ_MEMORY`](#label-7-fs_read_memory) reaching that slot carried
(per-node sharing, a defect tracked in
[#530](https://github.com/kottlerg/seraph/issues/530)). Clients that
delivered the SEND get the cooperative path: the driver waits up to
100 ms for [`FS_RELEASE_ACK`](#label-9-fs_release_ack), then
`cap_revoke`s the parent Memory cap and deletes it whether or not the
ack came. Clients that omitted the SEND (opt-out) skip straight to the
revoke on every eviction, and so does a client whose SEND the driver
cannot copy or whose watchdog it cannot start. The driver sends no
release for a page the client's own release or `FS_CLOSE` has already
removed from the open-file table. See
[`runtime/ruststd/src/sys/fs/release_handler.rs`](../../../runtime/ruststd/src/sys/fs/release_handler.rs)
for the receive-side state machine.

**Request**

| Field | Value |
|---|---|
| `label` | `8` |
| `data[0]` | Release cookie identifying the Memory cap |

The client unmaps the matching Memory cap and replies with
[`FS_RELEASE_ACK`](#label-9-fs_release_ack). The client matches the
cookie among all its open files, since the release may arrive on the
SEND of a file other than the one that read the page. If a local copy
from the page is still in progress, the client holds its reply until
the copy ends, within the window below and once per cookie (a repeated
release of a cookie whose wait ran out is refused at once); this covers
a release the driver sends before its reply to the cookie's
[`FS_READ_MEMORY`](#label-7-fs_read_memory) arrives. After the reply,
or after the cooperative-release watchdog window (100 ms) with none,
the driver revokes every cap derived from the parent Memory cap,
deletes the parent, and releases the page-cache slot, unless the
client's [client-to-driver release](#client-to-driver-release) or
[`FS_CLOSE`](#label-3-fs_close) has already done so: each page is
cleaned up once, by whichever path removes it from the open-file
table first. The ack tells the driver the client unmapped in time.
The revoke invalidates the client's derived cap but removes no mapping
([Capability Model § Revocation](../../../docs/capability-model.md#revocation)),
and the released slot may be refilled with other data, so a client
that has not unmapped the page by then can read what the cache loads
there next; a client MUST unmap before it acks. A copy that outlasts
the window can read the recycled page, and a client that starts its
own wait only when the release arrives cannot detect every such copy
([#516](https://github.com/kottlerg/seraph/issues/516)).
A reply with any other label is not an
acknowledgement; a client that cannot unmap the page, or whose copy
outlasts the window, replies `IO_ERROR` (2).

### Client-to-driver release

Sent by the client on the per-node badged cap the page was read
through, once it has finished reading the page; the client then tears
down its local mapping. No release endpoint and no
[`FS_RELEASE_ACK`](#label-9-fs_release_ack) are involved.

**Request**

| Field | Value |
|---|---|
| `label` | `8` |
| `data[0]` | Release cookie from the [`FS_READ_MEMORY`](#label-7-fs_read_memory) reply |

The driver revokes every cap derived from the matching outstanding
page's parent Memory cap, deletes that parent, and releases the
page-cache slot.

**Reply (success)**: `label = 0`, empty body. A cookie that matches
no outstanding page on the node (including a node with no open-file
slot) is a no-op success.

**Reply (error)**: `label = fs_errors::PERMISSION_DENIED` when the
badge carries no namespace rights.

---

## Label 9: `FS_RELEASE_ACK`

Synchronous client-to-driver reply to
[`FS_RELEASE_MEMORY`](#label-8-fs_release_memory). Empty body. It
tells the driver the client unmapped the page in time; the driver
revokes the parent cap and drops its page-cache refcount after any
reply, or after the window with none, per
[§ Label 8](#label-8-fs_release_memory).

**Reply**

| Field | Value |
|---|---|
| `label` | `9` |

---

## Label 3: `FS_CLOSE`

Release driver-side bookkeeping bound to a node cap (the lazily-
allocated per-`OpenFile` slot, outstanding `FS_READ_MEMORY` pages,
the recorded release endpoint). The slot is per node and shared by
every client of the file, so one client's `FS_CLOSE` revokes every
client's outstanding pages on it (a defect, tracked in
[#530](https://github.com/kottlerg/seraph/issues/530); see
[`FS_READ_MEMORY`](#label-7-fs_read_memory)). The kernel-side cap is
**not** freed here — the holder still `cap_delete`s its node cap to
drop the kernel reference.

**Request**

| Field | Value |
|---|---|
| `label` | `3` |
| body | empty (target identified by badge) |

**Reply (success)**: `label = 0`, empty body.

`FS_CLOSE` is best-effort cleanup. The driver MAY have already
evicted the per-node slot under cache pressure; in that case
`FS_CLOSE` is a no-op success.

---

## Label 4: `FS_WRITE`

Inline write to a file. Badge = file cap; the badge must carry the
`WRITE` namespace right.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_WRITE \| (byte_len << 16)` (bits 0-15 = label, bits 16-31 = payload bytes, ≤504) |
| `data[0]` | File byte offset |
| `bytes(1, &payload)` | Payload bytes (`byte_len` of them) starting at byte 8 |

**Reply (success)**: `label = 0`, `data[0]` = bytes_written. May be
short on `NO_SPACE`; callers iterate.

**Errors**: `INVALID_BADGE`, `IS_A_DIRECTORY`, `IO_ERROR`,
`PERMISSION_DENIED`, `NO_SPACE` (no free cluster, or the write would end
past `u32::MAX` bytes, the largest FAT file size; the driver refuses
the latter before allocating).

---

## Label 12: `FS_WRITE_MEMORY`

Bulk write from a caller-supplied source Memory cap. Mirror of
`FS_READ_MEMORY` for the write direction. Threshold for inline vs
the memory-cap path is the same 504-byte boundary that governs reads today; the
crossover Issue tracks per-arch tuning.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_WRITE_MEMORY` (12) |
| `data[0]` | File byte offset |
| `data[1]` | Bytes to write from the memory cap (`≤ PAGE_SIZE - memory_data_offset`) |
| `data[2]` | Byte offset within the source memory cap where the data begins |
| `caps[0]` | Source Memory cap (`MAP` rights, read-only mapping authority; one page) |

**Reply (success)**: `label = 0`, `data[0]` = bytes_written,
`caps[0]` = the source Memory cap moved back to the caller.

The driver mem-maps the source memory cap read-only into its own address
space for the duration of the copy. The cap returns to the caller in
every outcome (mirror of the read-memory ownership discipline). The
driver MUST NOT keep a mapping of the source page, or any capability to
it, past its reply: once the reply arrives the caller may return the
page to memmgr's pool, which another process can then be granted.

**Errors**: `INVALID_BADGE`, `IS_A_DIRECTORY`, `IO_ERROR`,
`PERMISSION_DENIED`, `NO_SPACE` (as for [`FS_WRITE`](#label-4-fs_write)),
`BAD_MEMORY_OFFSET`.

---

## Label 13: `FS_CREATE`

Create a new file in a directory. Badge = parent-directory cap; the
badge must carry the `MUTATE_DIR` namespace right.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_CREATE \| (name_len << 16)` |
| `bytes(0, &name)` | Name bytes starting at byte 0 |

**Reply (success)**: `label = 0`, `data[0]` = `NodeKind` (= File),
`caps[0]` = node cap for the newly-created file. The new file starts
empty (size 0, no allocated cluster).

**Errors**: `INVALID_BADGE`, `EXISTS` (the directory already holds an
entry of that name), `NO_SPACE`, `IO_ERROR`, `PERMISSION_DENIED`,
`TOO_MANY_OPEN` (the driver's node table is full; the entry was
created).

---

## Label 14: `FS_REMOVE`

Unlink a file or empty directory. Badge = parent-directory cap with
`MUTATE_DIR`.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_REMOVE \| (name_len << 16)` |
| `bytes(0, &name)` | Name bytes |

**Reply (success)**: `label = 0`, empty body.

**Errors**: `NOT_FOUND`, `NOT_EMPTY` (directory has entries other
than `.` and `..`), `IO_ERROR`, `PERMISSION_DENIED`, `INVALID_BADGE`
(the badge is not a directory node).

`FS_REMOVE` is not atomic: an error reply can leave any of
[`crash-safety.md`](../fat/docs/crash-safety.md)'s `FS_REMOVE` states, and
the driver's cached copy of a sector whose write failed keeps the new bytes
until a later write of that sector succeeds or the page is evicted. Once
the cached view shows the entry deleted, the driver drops the entry's node,
so caps held on it no longer name it
([#447](https://github.com/kottlerg/seraph/issues/447)).

---

## Label 15: `FS_MKDIR`

Create a new (empty) directory. Same shape as `FS_CREATE`. Allocates
one cluster, zero-fills it, and populates `.` / `..` entries before
the directory entry is inserted in the parent.

**Reply (success)**: `label = 0`, `data[0]` = `NodeKind` (= Dir),
`caps[0]` = node cap for the new directory.

**Errors**: as `FS_CREATE`.

---

## Label 16: `FS_RENAME`

Rename a directory entry within a single directory. Badge =
directory cap with `MUTATE_DIR`.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_RENAME` (16) |
| `data[0]` | Source name length |
| `data[1]` | Destination name length |
| `bytes(2, &concat(src, dst))` | Source bytes immediately followed by destination bytes (no padding) starting at byte 16 |

Both names share the data area after the two length words, so
`data[0] + data[1]` MUST be at most `(MSG_DATA_WORDS_MAX - 2) * 8` =
496 bytes. The bound is less than two names of the per-name maximum
(`MAX_NAME_LEN`, 255 bytes, per
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)):
a pair of individually valid names can exceed it, and a client MUST NOT
send such a pair. The server replies `IO_ERROR` to a zero length, or to
lengths whose sum exceeds the name bytes the message carries after the two
length words.

**Reply (success)**: `label = 0`, empty body.

Cross-directory rename is deferred: servers cannot introspect the
badge packed in a received cap, so a second-directory cap cannot
resolve to a `NodeId`. Supporting it needs either a kernel-level
`cap_info` selector that reports a cap's badge or a wire shape that
conveys the destination directory's `NodeId` out-of-band (design
intent; not yet implemented). Tracked as
[Issue #89](https://github.com/kottlerg/seraph/issues/89).

`FS_RENAME` is not atomic — see
[`services/fs/fat/docs/crash-safety.md`](../fat/docs/crash-safety.md)
for the post-crash visible states. The server does not roll a failed rename
back, so an error reply can leave any of those states too, with the same
cached-sector caveat as `FS_REMOVE`; once the cached view shows the source
deleted, the driver drops the source's node, on success and on error. Rollback
of a failed rename is tracked in
[#447](https://github.com/kottlerg/seraph/issues/447).

**Errors**: `NOT_FOUND` (source missing), `EXISTS` (destination
occupied), `NO_SPACE`, `IO_ERROR` (malformed name lengths, an invalid name),
`PERMISSION_DENIED`, `INVALID_BADGE` (the badge is not a directory node).

---

## Label 17: `FS_TRUNCATE`

Set a file's length. Badge = file cap with `WRITE`.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_TRUNCATE` (17) |
| `data[0]` | New length in bytes |

**Reply (success)**: `label = 0`, empty body.

v1 supports only `new_len == 0`; non-zero replies `IO_ERROR`. The
wire shape is forward-compatible with later extend-with-zero-fill
semantics, tracked by the `ruststd::fs` completeness-gaps issue. The
truncate-to-zero path frees the entire FAT cluster chain
and patches the directory entry's first-cluster + size fields to 0.

**Errors**: `INVALID_BADGE`, `IS_A_DIRECTORY`, `PERMISSION_DENIED`,
`IO_ERROR` (chain walk / `FSInfo` flush failure, or non-zero
`new_len` until the v2 extend path lands).

---

## Label 6: `END_OF_DIR`

End-of-directory marker reused as a reply label by `NS_READDIR`. See
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md).
No request side; clients distinguish "end of iteration" from "name
at this index" by reply label.

---

## Bootstrap caps

A filesystem driver obtains its service-specific caps in a single
`ipc::bootstrap` round: at startup it calls
`ipc::bootstrap::request_round` on its `creator_endpoint`, and vfsd
replies with one round marked done, carrying two caps and zero data
words:

| Slot | Cap |
|---|---|
| `caps[0]` | Block device endpoint (SEND, partition-scoped badge on virtio-blk) |
| `caps[1]` | Driver service endpoint (all rights: receive and badge derivation) |

A round with fewer than two caps, or not marked done, is a bootstrap
failure and the driver exits. The log and procmgr endpoints are not
part of this round; the driver takes them from `ProcessInfo` (read
through `std::os::seraph::startup_info()`), per
[abi/process-abi/README.md](../../../abi/process-abi/README.md)
§ ProcessInfo.

The block device endpoint is partition-scoped: vfsd registers the
partition bound with virtio-blk before delivering this cap, so the
driver reads by partition-relative LBA and virtio-blk enforces the
bound on every `BLK_READ_INTO_MEMORY`. See
[`services/vfsd/docs/vfs-ipc-interface.md`](../../vfsd/docs/vfs-ipc-interface.md)
§ Label 10: `MOUNT` for the registration step and
[`services/drivers/virtio/blk/README.md`](../../drivers/virtio/blk/README.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md) | `NS_*` wire surface, name and rights rules |
| [docs/namespace-model.md](../../../docs/namespace-model.md) | Cap-as-namespace principles |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC message format, cap transfer |
| [services/vfsd/docs/namespace-composition.md](../../vfsd/docs/namespace-composition.md) | How vfsd composes the system root from per-mount caps |
| [services/drivers/virtio/blk/README.md](../../drivers/virtio/blk/README.md) | Block device IPC, partition badges |

---

## Summarized By

[Storage](../../../docs/storage.md),
[programs/fsbench/README.md](../../../programs/fsbench/README.md),
[services/fs/README.md](../README.md), [services/fs/fat/README.md](../fat/README.md),
[services/vfsd/README.md](../../vfsd/README.md),
[vfsd Service Interface](../../vfsd/docs/vfs-ipc-interface.md)
