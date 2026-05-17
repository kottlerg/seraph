# Filesystem Driver Protocol

IPC surface a filesystem driver implements **on top of** the cap-
native namespace protocol. The namespace surface (`NS_LOOKUP`,
`NS_STAT`, `NS_READDIR`, name validation, rights composition, error
codes) is specified in
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md);
this document covers the labels that remain fs-driver-specific:

- `FS_MOUNT` — vfsd-to-driver BPB-validation probe at mount time.
- `FS_READ` — inline read on a per-node tokened cap.
- `FS_READ_FRAME` / `FS_RELEASE_FRAME` / `FS_RELEASE_ACK` — frame-cap
  read protocol with cooperative release.
- `FS_CLOSE` — release driver-side per-node bookkeeping; the holder
  still `cap_delete`s its node cap to drop the kernel reference.
- `END_OF_DIR` — readdir terminator, reused by `NS_READDIR`.

A driver runs as a separate process. After `FS_MOUNT` succeeds, the
driver dispatches incoming requests by their token shape:

- `token == 0` — service-level request from vfsd (only `FS_MOUNT`
  today).
- `token != 0` carrying namespace rights in bits 40..64 — node-cap
  request. Per-node opcodes (`NS_*`, `FS_READ`, `FS_READ_FRAME`,
  `FS_RELEASE_FRAME`, `FS_CLOSE`) are dispatched by label.

---

## Endpoint surface

A filesystem driver exposes one IPC endpoint, used as both:

- the un-tokened **service endpoint** (vfsd holds a SEND, derives
  per-node tokened SENDs); and
- the un-tokened **namespace endpoint** routed through
  [`namespace_protocol::dispatch_request`] for `NS_*` dispatch.

The receive-side cap is injected into the driver's CSpace at two-
phase process creation. The same endpoint is also the kernel-
derivation parent for every node cap the driver ever issues via
`cap_derive_token`.

Numeric label values live in [`ipc::fs_labels`] (this document) and
[`ipc::ns_labels`] (namespace-protocol document).

---

## Label 10: `FS_MOUNT`

Mount-time probe. Sent by vfsd on the un-tokened service endpoint
after the driver process is spawned and the partition is registered
with virtio-blk. The driver MUST read the superblock / BPB through
its block device endpoint and reply success or a typed error.

**Request**

| Field | Value |
|---|---|
| `label` | `10` |
| body | empty |

**Reply (success)**: `label = 0`, empty body.

**Reply (error)**: `label = ipc::fs_errors::*` (e.g. `IO_ERROR`,
`NOT_FOUND` for a malformed BPB).

The block device endpoint arrives in the driver's CSpace at creation
time; see [Bootstrap caps](#bootstrap-caps).

---

## Label 2: `FS_READ`

Inline read against a per-node tokened cap. The kernel delivers the
node's `(NodeId, NamespaceRights)` token to the driver via
`ipc_recv.token`; the driver MUST verify the `READ` rights bit and
reject with `NsError::PermissionDenied` otherwise.

Used for short reads (≤ 504 bytes that fit within the current page);
larger or page-straddling reads use
[`FS_READ_FRAME`](#label-7-fs_read_frame). The threshold is
client-side policy, not server-enforced; see
[Inline-vs-frame crossover](#inline-vs-frame-crossover-client-policy).

**Request**

| Field | Value |
|---|---|
| `label` | `2` |
| `data[0]` | Byte offset |
| `data[1]` | Maximum bytes to read (capped at the IPC inline ceiling, 512 bytes) |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | Bytes actually read |
| `data[1..]` | File data, packed little-endian |

**Reply (error)**: `label = NsError::*` (`NotFound`,
`PermissionDenied`, `IsADirectory`, `IoError`).

---

## Label 7: `FS_READ_FRAME`

Frame-cap read. The driver returns a single-page Frame cap with
attenuated rights (`MAP|READ`) covering the cached page that contains
the requested byte. The client maps the frame, reads up to
`bytes_valid` bytes starting at `frame_data_offset`, then releases
the page either synchronously after the read or in response to a
driver-initiated [`FS_RELEASE_FRAME`](#label-8-fs_release_frame)
arriving on the per-process release endpoint.

The request `offset` has no alignment requirement; the driver reports
where the file's content for `offset` lives within the returned frame
(`frame_data_offset`) and how many contiguous valid bytes follow
(`bytes_valid`). `bytes_valid` is bounded by file end, the underlying
filesystem cluster boundary, and the page tail
(`PAGE_SIZE - frame_data_offset`).

The cookie is client-chosen, opaque to the driver, and MUST be non-
zero (`0` collides with the driver-side `OutstandingPage::None`
sentinel).

**Request**

| Field | Value |
|---|---|
| `label` | `7` |
| `data[0]` | Byte offset (any) |
| `data[1]` | Release cookie (non-zero, client-chosen) |
| `caps[0]` | Per-process release-endpoint SEND, transferred only on the first `FS_READ_FRAME` for a given (client, file) pair (see below) |

The first `FS_READ_FRAME` for a given (client, file) pair MAY carry
the client's per-process release-endpoint SEND in `caps[0]`. The
driver records it on the lazily-allocated `OpenFile` slot so the
eviction worker can route cooperative
[`FS_RELEASE_FRAME`](#label-8-fs_release_frame) back to the client.
Subsequent `FS_READ_FRAME`s for the same pair carry no caps; clients
that opt out of cooperative release omit the cap on every call,
falling back to the eviction worker's hard-revoke path.

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | `bytes_valid` (zero on EOF) |
| `data[1]` | Cookie echoed back |
| `data[2]` | `frame_data_offset` |
| `caps[0]` | Frame cap (`MAP\|READ`, single page; omitted on EOF) |

**Reply (error)**: `label = NsError::*` or
`fs_errors::BAD_FRAME_OFFSET` (cookie zero).

---

## Inline-vs-frame crossover (client policy)

The choice between [`FS_READ`](#label-2-fs_read) and
[`FS_READ_FRAME`](#label-7-fs_read_frame) is **client-side policy**, not
protocol. The server accepts whichever label arrives; the cost of the
wrong pick falls entirely on the client.

The reference policy lives in `runtime/ruststd/src/sys/fs/seraph.rs`:

```text
inline iff  want <= READ_INLINE_THRESHOLD
       AND  (offset mod PAGE_SIZE) + want <= PAGE_SIZE
frame  otherwise
```

`READ_INLINE_THRESHOLD = 504` bytes. This is the FS_READ IPC payload
ceiling — 63 data words × 8 bytes minus the 8-byte length prefix in
word 0 (`MSG_DATA_WORDS_MAX` in `abi/syscall`). Above this size a
single inline reply cannot carry the bytes; below it the per-call cost
is strictly cheaper than the frame path on both supported architectures.

The page-alignment clause forces frame for any read that straddles a
page tail even if its size fits inline, because the frame path's
single-page granularity matches the on-disk page-cache layout, whereas
an inline reply spanning two pages would force the server to assemble
contiguous bytes across the boundary.

### Measured per-call cost (`fsbench`, debug builds)

Source: `base/fsbench/src/main.rs`. The bench loops 256 timed iterations
of "seek to 0; read N bytes via the chosen path" against a 64 KiB
fixture (`/usertest/bench.bin`). The inline path chunks into ≤ 504-byte
non-straddling reads; the frame path always passes a full-page buffer
so `want > 504` forces a frame call. `cycles_now()` uses `rdtsc` on
x86_64 and `csrr cycle` on riscv64. Numbers below are `cycles_mean`.

**x86_64 (KVM-accelerated, TSC = hardware cycles)**

| Size (B) | Inline calls | Inline cycles | Frame calls | Frame cycles |
|---------:|-------------:|--------------:|------------:|-------------:|
| 16       | 1            | 61 426        | 1           | 123 139      |
| 1 024    | 3            | 236 906       | 1           | 130 553      |
| 4 096    | 9            | 938 019       | 1           | 244 221      |
| 16 384   | 33           | 3 780 641     | 4           | 1 000 699    |
| 65 536   | 130          | 15 347 991    | 16          | 3 987 730    |

**riscv64 (TCG-emulated, `cycle` CSR via `scounteren.CY`)**

| Size (B) | Inline calls | Inline cycles | Frame calls | Frame cycles |
|---------:|-------------:|--------------:|------------:|-------------:|
| 16       | 1            | 548 333       | 1           | 1 232 195    |
| 1 024    | 3            | 2 131 616     | 1           | 1 383 683    |
| 4 096    | 9            | 8 205 397     | 1           | 2 389 154    |
| 16 384   | 33           | 33 249 701    | 4           | 9 735 094    |
| 65 536   | 130          | 134 748 016   | 16          | 39 159 872   |

**Reading the table:** the single-call inline cost is consistently
≈ 0.5× the single-call frame cost on both architectures. Once the
request exceeds 504 bytes the inline path must issue ≥ 2 calls and
loses to the single frame call. Below 504 bytes inline always wins.
The threshold is therefore set to the IPC payload ceiling: not by
coincidence, but by measurement.

Absolute riscv64 cycles run ≈ 10× x86_64 because riscv64 boots under
TCG (no KVM); the *ratio* between paths is what informs the policy.

---

## Label 8: `FS_RELEASE_FRAME`

Driver-to-client request to release a previously-returned Frame.
Sent by the driver's eviction worker on the client's per-process
release endpoint cap, recorded by the driver from `caps[0]` of the
client's first [`FS_READ_FRAME`](#label-7-fs_read_frame) for the
file. Clients that delivered the SEND get the cooperative path; the
driver waits up to 100 ms for [`FS_RELEASE_ACK`](#label-9-fs_release_ack)
before falling through to a hard `cap_revoke` of the parent Frame
cap. Clients that omitted the SEND (opt-out) skip straight to the
hard-revoke path on every eviction. See
[`runtime/ruststd/src/sys/fs/release_handler.rs`](../../../runtime/ruststd/src/sys/fs/release_handler.rs)
for the receive-side state machine.

**Request**

| Field | Value |
|---|---|
| `label` | `8` |
| `data[0]` | Release cookie identifying the Frame |

The client unmaps the matching Frame and replies with
[`FS_RELEASE_ACK`](#label-9-fs_release_ack). If the client does not
acknowledge within the cooperative-release watchdog window (100 ms),
the driver `cap_revoke`s the parent Frame cap.

---

## Label 9: `FS_RELEASE_ACK`

Synchronous client-to-driver reply to
[`FS_RELEASE_FRAME`](#label-8-fs_release_frame). Empty body. The
driver's outstanding-Frame refcount decrements on receipt.

**Reply**

| Field | Value |
|---|---|
| `label` | `9` |

---

## Label 3: `FS_CLOSE`

Release driver-side bookkeeping bound to a node cap (the lazily-
allocated per-`OpenFile` slot, outstanding `FS_READ_FRAME` pages,
the recorded release endpoint). The kernel-side cap is **not** freed
here — the holder still `cap_delete`s its node cap to drop the
kernel reference.

**Request**

| Field | Value |
|---|---|
| `label` | `3` |
| body | empty (target identified by token) |

**Reply (success)**: `label = 0`, empty body.

`FS_CLOSE` is best-effort cleanup. The driver MAY have already
evicted the per-node slot under cache pressure; in that case
`FS_CLOSE` is a no-op success.

---

## Label 4: `FS_WRITE`

Inline write to a file. Token = file cap; the token must carry the
`WRITE` namespace right.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_WRITE \| (byte_len << 16)` (bits 0-15 = label, bits 16-31 = payload bytes, ≤504) |
| `data[0]` | File byte offset |
| `bytes(1, &payload)` | Payload bytes (`byte_len` of them) starting at byte 8 |

**Reply (success)**: `label = 0`, `data[0]` = bytes_written. May be
short on `NO_SPACE`; callers iterate.

**Errors**: `INVALID_TOKEN`, `IS_A_DIRECTORY`, `IO_ERROR`,
`PERMISSION_DENIED`, `NO_SPACE`.

---

## Label 12: `FS_WRITE_FRAME`

Bulk write from a caller-supplied source Frame cap. Mirror of
`FS_READ_FRAME` for the write direction. Threshold for inline vs
frame is the same 504-byte boundary that governs reads today; the
crossover Issue tracks per-arch tuning.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_WRITE_FRAME` (12) |
| `data[0]` | File byte offset |
| `data[1]` | Bytes to write from the frame (`≤ PAGE_SIZE - frame_data_offset`) |
| `data[2]` | Byte offset within the source frame where the data begins |
| `caps[0]` | Source Frame cap (`MAP \| READ` rights; one page) |

**Reply (success)**: `label = 0`, `data[0]` = bytes_written,
`caps[0]` = the source Frame cap moved back to the caller.

The driver mem-maps the source frame read-only into its own address
space for the duration of the copy. The cap returns to the caller in
every outcome (mirror of the read-frame ownership discipline).

**Errors**: `INVALID_TOKEN`, `IS_A_DIRECTORY`, `IO_ERROR`,
`PERMISSION_DENIED`, `NO_SPACE`, `BAD_FRAME_OFFSET`.

---

## Label 13: `FS_CREATE`

Create a new file in a directory. Token = parent-directory cap; the
token must carry the `MUTATE_DIR` namespace right.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_CREATE \| (name_len << 16)` |
| `bytes(0, &name)` | Name bytes starting at byte 0 |

**Reply (success)**: `label = 0`, `data[0]` = `NodeKind` (= File),
`caps[0]` = node cap for the newly-created file. The new file starts
empty (size 0, no allocated cluster).

**Errors**: `INVALID_TOKEN`, `EXISTS` (the dispatch may currently
surface `NO_SPACE` for duplicate names — to be tightened),
`NO_SPACE`, `IO_ERROR`, `PERMISSION_DENIED`.

---

## Label 14: `FS_REMOVE`

Unlink a file or empty directory. Token = parent-directory cap with
`MUTATE_DIR`.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_REMOVE \| (name_len << 16)` |
| `bytes(0, &name)` | Name bytes |

**Reply (success)**: `label = 0`, empty body.

**Errors**: `NOT_FOUND`, `NOT_EMPTY` (directory has entries other
than `.` and `..`), `IO_ERROR`, `PERMISSION_DENIED`.

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

Rename a directory entry within a single directory. Token =
directory cap with `MUTATE_DIR`.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_RENAME` (16) |
| `data[0]` | Source name length |
| `data[1]` | Destination name length |
| `bytes(2, &concat(src, dst))` | Source bytes immediately followed by destination bytes (no padding) starting at byte 16 |

**Reply (success)**: `label = 0`, empty body.

Cross-directory rename is deferred: servers cannot introspect the
token packed in a received cap, so a second-directory cap cannot
resolve to a `NodeId`. A future Issue may add a wire shape that
conveys the destination directory's `NodeId` explicitly.

`FS_RENAME` is not atomic — see
[`services/fs/fat/docs/crash-safety.md`](../fat/docs/crash-safety.md)
for the post-crash visible states.

**Errors**: `NOT_FOUND` (source missing), `EXISTS` (destination
occupied), `NO_SPACE`, `IO_ERROR`, `PERMISSION_DENIED`.

---

## Label 6: `END_OF_DIR`

End-of-directory marker reused as a reply label by `NS_READDIR`. See
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md).
No request side; clients distinguish "end of iteration" from "name
at this index" by reply label.

---

## Bootstrap caps

A filesystem driver receives the following caps in its CSpace at
two-phase process creation, identified by sentinel values in the
`CapDescriptor.aux0` field:

| Sentinel | Meaning |
|---|---|
| `0xFFFF_FFFF_FFFF_FFFF` | Log endpoint |
| `0xFFFF_FFFF_FFFF_FFFE` | Service endpoint (Receive-side) |
| `0xFFFF_FFFF_FFFF_FFFD` | Block device endpoint (Send-side, partition-scoped) |
| `0x0000_0000_0000_0000` (aux0 and aux1 both zero) | procmgr endpoint |

All sentinels use `CapType::Frame` as the discriminant — the actual
kernel object is an Endpoint, but the `CapType` field is overloaded
for sentinel identification.

The block device endpoint is partition-scoped: vfsd registers the
partition bound with virtio-blk before delivering this cap, so the
driver reads by partition-relative LBA and virtio-blk enforces the
bound on every `BLK_READ_INTO_FRAME`. See
[`services/drivers/virtio/blk/README.md`](../../drivers/virtio/blk/README.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md) | `NS_*` wire surface, name and rights rules |
| [docs/namespace-model.md](../../../docs/namespace-model.md) | Cap-as-namespace principles |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC message format, cap transfer |
| [services/vfsd/docs/namespace-composition.md](../../vfsd/docs/namespace-composition.md) | How vfsd composes the system root from per-mount caps |
| [services/drivers/virtio/blk/README.md](../../drivers/virtio/blk/README.md) | Block device IPC, partition tokens |

---

## Summarized By

[services/fs/README.md](../README.md)
