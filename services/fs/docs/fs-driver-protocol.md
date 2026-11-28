# Filesystem Driver Protocol

IPC surface a filesystem driver implements **on top of** the cap-
native namespace protocol. The namespace surface (`NS_LOOKUP`,
`NS_STAT`, `NS_READDIR`, name validation, rights composition, error
codes) is specified in
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md);
this document covers the labels that remain fs-driver-specific:

- `FS_MOUNT` — vfsd-to-driver BPB-validation probe at mount time.
- `FS_UNMOUNT` — vfsd-to-driver unmount, after which the driver exits.
- `FS_SESSION` — start a session, whose opens' records live in pages
  charged to a node of the client.
- `FS_OPEN` — mint a per-open cap on a file node cap, in a session the
  request names.
- `FS_READ` — inline read on a file node cap or open cap.
- `FS_READ_MEMORY` / `FS_RELEASE_MEMORY` / `FS_RELEASE_ACK` — memory-cap
  read protocol with cooperative release, per open.
- `FS_CLOSE` — release an open's driver-side bookkeeping; the holder
  still `cap_delete`s its open cap.
- `FS_WRITE` / `FS_WRITE_MEMORY` — inline and memory-cap writes on a
  file node cap or open cap.
- `FS_CREATE` / `FS_MKDIR` — create a file or an empty directory in a
  directory; a create can open the new file in a session in the same
  request.
- `FS_REMOVE` — unlink a file or empty directory.
- `FS_RENAME` — rename an entry within one directory.
- `FS_TRUNCATE` — set a file's length.
- `END_OF_DIR` — readdir terminator, reused by `NS_READDIR`.

A driver runs as a separate process. After `FS_MOUNT` succeeds, the
driver dispatches incoming requests by their badge shape:

- `badge == 0` — service-level request from vfsd (`FS_MOUNT` and
  `FS_UNMOUNT`).
- `badge != 0` carrying namespace rights in bits 40..64, with the
  `OPEN_INSTANCE` (48) and `SESSION` (49) bits clear — node-cap request (badge layout per
  [`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
  § Badge shape). Per-node opcodes (`NS_*`, `FS_SESSION`, `FS_OPEN`, `FS_READ`,
  `FS_WRITE`, `FS_WRITE_MEMORY`, `FS_TRUNCATE`, `FS_CREATE`, `FS_REMOVE`,
  `FS_MKDIR`, `FS_RENAME`) are dispatched by label.
- `badge != 0` with `OPEN_INSTANCE` set alone — open-cap request: the
  badge names one open the driver minted at [`FS_OPEN`](#label-18-fs_open),
  by a 54-bit id in bits 0..40 and 50..64.
  The open's own opcodes (`FS_READ_MEMORY`, `FS_RELEASE_MEMORY`,
  `FS_CLOSE`) and the stateless file opcodes (`FS_READ`, `FS_WRITE`,
  `FS_WRITE_MEMORY`, `FS_TRUNCATE`) are dispatched by label, the latter on
  the open's node.
- `badge != 0` with `SESSION` set alone — a session cap, minted at
  [`FS_SESSION`](#label-23-fs_session). It carries no request of its own;
  `FS_OPEN`, and `FS_CREATE` with `CREATE_OPEN`, carry a copy of it as a
  capability.

A badge with both kind bits names nothing. A label sent on such a badge
or on the wrong kind of cap (an open's own label on a node cap, `FS_OPEN`
or a directory label on an open cap, any label on a session cap) is
answered `fs_errors::INVALID_BADGE`, as is any request on an open cap
whose open is closed, whose node was freed, or whose session ended. `NS_*`
on an open cap or a session cap is answered `NsError::NotSupported` by the
namespace dispatch.

---

## Endpoint surface

A filesystem driver exposes one IPC endpoint, used as both:

- the un-badged **service endpoint** (vfsd holds a SEND, derives
  per-node badged SENDs, and the driver derives per-open badged SENDs);
  and
- the un-badged **namespace endpoint** routed through
  `namespace_protocol::dispatch_request` for `NS_*` dispatch.

vfsd delivers the endpoint cap (all rights: receive and badge
derivation) in the driver's bootstrap round; see
[Bootstrap caps](#bootstrap-caps). The same endpoint is also the
kernel-derivation parent for every node cap the driver ever issues
via `cap_derive_badge`.

Numeric label values live in `ipc::fs_labels` (this document) and
`ipc::ns_labels` (namespace-protocol document).

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
`IO_ERROR` (the block device's `BLK_GET_GEOMETRY` or the BPB read failed),
or `NOT_FOUND` for a malformed BPB, one whose sector size is not the
device's logical block size (the driver reads one block per sector, 512 to
4096 bytes), one whose sectors per cluster are not a power of two, one
that declares more sectors than the partition holds, or one with fewer
than 4085 clusters (FAT12, which the driver does not read).

The block device endpoint arrives in the driver's bootstrap round;
see [Bootstrap caps](#bootstrap-caps).

---

## Label 19: `FS_UNMOUNT`

Unmount. Sent by vfsd on the un-badged service endpoint, as `FS_MOUNT` is,
when it serves an `UNMOUNT`
([services/vfsd/docs/vfs-ipc-interface.md](../../vfsd/docs/vfs-ipc-interface.md#label-11-unmount)
§ Label 11). After a success reply the driver exits and serves no further
request.

**Request**

| Field | Value |
|---|---|
| `label` | `19`, with the flag bits below |
| `data[0]` | Caller's `ipc::FS_LABELS_VERSION` |

| Label bit | Flag |
|---|---|
| 16 | `fs_labels::UNMOUNT_FORCE`: unmount although opens are live, releasing them |

The request carries no caps; the driver deletes any it carries. The label
on a node cap or an open cap is answered `UNKNOWN_OPCODE`.

The driver first ends every session whose client is gone, as the sweep of
[§ Label 23](#label-23-fs_session) does, which releases the opens made in
it; every open left is live. Without `UNMOUNT_FORCE`, a live open makes the
driver reply `BUSY`, with the number of live opens in `data[0]`, and serve
on; a session with no open does not count. Otherwise it releases every open
as [`FS_CLOSE`](#label-3-fs_close) does: it revokes the open's outstanding
pages and deletes its release SEND. It ends every session left, which revokes
the copies of the session's liveness cap and gives its pages back to memmgr.
It then writes the volume's `FSInfo` hints (FAT32), replies success, and
exits with `fs_labels::EXIT_UNMOUNTED` ([§ Driver exit](#driver-exit)).

Only opens make the driver busy. A node cap, such as a client's working
directory, is not counted, since the driver cannot count the holders of a
capability. A page a client mapped stays mapped after the release, since a
revoke removes no mapping
([Capability Model § Revocation](../../../docs/capability-model.md#revocation)).

The driver serves one request at a time, so an unmount runs after the
request in flight and before any later one. After the reply the driver
receives nothing: a client that calls through a node cap or an open cap
afterwards finds no receiver until vfsd tears the endpoint down. vfsd does
that after any answer but `BUSY` to an unforced request, and after no
answer in its timeout: it revokes the partition cap and the service
endpoint, waits a bounded time for the driver's death, and destroys the
process, so a driver that does not exit is killed
([services/vfsd/docs/namespace-composition.md](../../vfsd/docs/namespace-composition.md#unmount)
§ Unmount).

**Reply (success)**: `label = 0`, empty body; the driver then exits.

**Reply (error)**: `label = ipc::fs_errors::*`: `LABEL_VERSION_MISMATCH`
when `data[0]` differs from the driver's `FS_LABELS_VERSION` (checked
before anything else), or `BUSY` (live opens remain and `UNMOUNT_FORCE` is
clear; `data[0]` is their number). The driver serves on after either.

---

## Label 18: `FS_OPEN`

Open a file in a session. The driver records a new **open** of the node the
file node cap names in the session the request's session cap names
([§ Label 23](#label-23-fs_session)) and replies with an **open cap**: a
badged SEND on its endpoint whose badge names the open by a 54-bit id,
carries the node cap's rights in bits 40..48, and sets the `OPEN_INSTANCE`
kind bit (48)
([`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
§ Badge shape). Every open is distinct: two opens of one file, by one client
or two, are two opens, each with its own outstanding pages and release
endpoint. The open's records live in the session's pages, charged to the
client's node, and the open lives no longer than its session. Every open is
made in a session, so every record the driver keeps of a client's opens is
paid for by that client's node, and a client at its node's max is refused
while other clients' opens go on: an `FS_OPEN` without a session cap is
refused.

**Request**

| Field | Value |
|---|---|
| `label` | `18` |
| body | empty (target identified by the node cap's badge) |
| `caps[0]` | A copy of the session cap, with any rights (std and procmgr send a `SEND`-only copy) |
| `caps[1]` | Optional release-endpoint SEND for the open's cooperative [`FS_RELEASE_MEMORY`](#driver-to-client-release) |

The badge must carry a non-empty rights mask and name a file. The driver
reads the badge of `caps[0]` on its own endpoint and deletes the cap once
read. No `caps[0]`, or a capability on any other endpoint, is refused
`INVALID_ARGUMENT`; a capability on the driver's endpoint whose badge names
no live session (an ended session's cap, an open cap, a node cap) is refused
`INVALID_BADGE`. The driver records the release SEND on the open and deletes
every cap beyond those; a client that omits it opts out of cooperative
release for this open, and eviction then revokes the open's pages without
the round trip.

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `caps[0]` | Open cap (`SEND_GRANT`, the node cap's rights) |

[`FS_READ_MEMORY`](#label-7-fs_read_memory),
[`FS_RELEASE_MEMORY`](#client-to-driver-release), and
[`FS_CLOSE`](#label-3-fs_close) MUST be sent on the open cap. The stateless
file labels ([`FS_READ`](#label-2-fs_read), [`FS_WRITE`](#label-4-fs_write),
[`FS_WRITE_MEMORY`](#label-12-fs_write_memory),
[`FS_TRUNCATE`](#label-17-fs_truncate)) accept either the node cap or the
open cap, with the rights its badge carries.

**Reply (error)**: `label = ipc::fs_errors::*`: `INVALID_BADGE` (the badge
names no node, or a directory, or is an open or session cap; or `caps[0]` is
a capability on the driver's endpoint that names no live session),
`PERMISSION_DENIED` (the badge carries no rights), `INVALID_ARGUMENT` (no
`caps[0]`, or one on another endpoint; or the open's record needs another
page and memmgr refuses the session's handle, as it does once the node's
handle state has ended), `LIMIT` (the open's record needs another page and
the max of the session's node or of an ancestor refuses it),
`TOO_MANY_OPEN` (the open ids are spent, or the heap or the driver's
`CSpace` cannot grow, or the driver cannot map a session's page),
`OUT_OF_MEMORY` (the open's record needs another page and memmgr refuses it
for want of memory: the free pool is at a floor the session's node may not
take), `IO_ERROR` (the driver could not mint the cap, or memmgr's call fails
or its reply carries no usable page). Every refusal deletes the carried
caps.

**Lifetime and bounds of an open.** It lives until its
`FS_CLOSE`, until an [`FS_REMOVE`](#label-14-fs_remove) or
[`FS_RENAME`](#label-16-fs_rename) frees its node, which releases every open
of the node, or until its session ends ([§ Label 23](#label-23-fs_session)).
Its id is drawn from one 54-bit counter, shared with session ids, that never
repeats in the driver's life, so an open cap kept past its open's end is
answered `INVALID_BADGE`, never with another open's state; once the counter
is spent the driver answers `TOO_MANY_OPEN`. Its client pays for its record,
in its session's pages, and holds it to the session node's max. An open cap
alone does not keep the open alive: its session does (§ Label 23,
**Delegation**).

An `FS_OPEN` whose reply cannot reach the client (it died mid-call, or its
`CSpace` cannot take the reply's cap) moves no cap, and the driver releases
that open before it serves another request.

The std client opens each file in its process's session with the file's
driver ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md)
§ Filesystem sessions), and sends `FS_CLOSE` for every open `File` when its
process exits normally, through `main` returning or `std::process::exit`
([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Process
Entry and `StartupInfo`); a crash or a kill sends none, and the open goes
when its session ends, at the sweep memmgr's signal of the process's death
starts (§ Label 23, **Session end**). Until then its release SEND keeps the
client's release endpoint alive past the client's death, so memmgr holds the
frame the endpoint lives in out of its pool until the SEND goes
([services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md#reclamation)
§ Reclamation). procmgr opens the file of each image read in a session of
its own for that read
([procmgr IPC interface](../../procmgr/docs/ipc-interface.md#label-13-create_from_file)
§ Label 13, **Read session**).

## Label 23: `FS_SESSION`

Start a **session**: a client's account with the driver, whose records live
in pages the client pays for. The client makes a node for its sessions (a
sub-node of its own, with the max it grants the filesystem), derives a
charge-only handle to it (`NODE_CHARGE_HANDLE`,
[services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md#node-handles)
§ Node Handles), and passes the handle here. The driver takes each page the
session needs as a one-page grant charged to that node
(`REQUEST_MEMORY_CAPS` with `REQUEST_CHARGE_NODE`, [§ Label
1](../../memmgr/docs/ipc-interface.md#label-1-request_memory_caps)), so the
records of the session's opens, and of the pages they hold, cost the
client's node and not the driver's: a client at its node's max is refused
`LIMIT` while other clients' requests go on. The reply carries a **session
cap**, which every [`FS_OPEN`](#label-18-fs_open) in the session carries,
as does every [`FS_CREATE`](#label-13-fs_create) that opens its file in it,
and the session's **liveness cap**.

**Request**

| Field | Value |
|---|---|
| `label` | `23` |
| body | empty |
| `caps[0]` | Node handle to the client's node, charge-only (`NODE_CHARGE_HANDLE`), which the driver keeps for the session's life |

The badge is any node cap of the driver with a non-empty rights mask; the
session is not tied to that node. The driver deletes every cap beyond
`caps[0]`.

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `caps[0]` | Session cap (`SEND` and `IDENTIFY`, no namespace rights): its badge sets the `SESSION` kind bit (49) and carries the session's 54-bit id ([`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md) § Badge shape) |
| `caps[1]` | Liveness cap (a Notification cap with no rights) |

**Reply (error)**: `label = ipc::fs_errors::*`: `INVALID_BADGE` (an open cap
or a session cap, or a node cap whose node the driver no longer holds, as
after an [`FS_REMOVE`](#label-14-fs_remove) of its entry; the mount's root
cap is always accepted), `PERMISSION_DENIED` (the badge carries no rights),
`INVALID_ARGUMENT` (`caps[0]` is missing, or memmgr refuses it as a node
handle), `LIMIT` (the max of the node or of an ancestor refuses the
session's first page), `OUT_OF_MEMORY` (memmgr refuses that page for want of
memory: the free pool is at a floor the node may not take, as outside the
system reserve while memory is critical), `IO_ERROR` (the call to memmgr
fails, or its reply carries no usable page),
`TOO_MANY_OPEN` (the session ids are spent, or the heap or the driver's
`CSpace` cannot grow, or the driver cannot create the liveness object or map
the page). Every refusal deletes the handle.

**Session cap.** A session cap names its session to `FS_OPEN` and carries no
request of its own: a filesystem label sent on it is answered
`INVALID_BADGE`, and an `NS_*` label `NsError::NotSupported`. Whoever holds
a copy can open, with any file node cap of the driver it holds, in the
session, charged to the session's node. Its `IDENTIFY` right lets the client
ask the kernel whether a node cap it holds is on the same endpoint
(`SYS_ENDPOINT_IDENTIFY`,
[core/kernel/docs/syscalls.md](../../../core/kernel/docs/syscalls.md#sys_endpoint_identify-73)), so
a client with sessions on several drivers finds the one a file's driver keeps without asking any
server; the copy an `FS_OPEN` carries needs only `SEND`.

**Pages and records.** A session's pages hold its records and nothing of the
driver's own. Each page is 64 slots of 64 bytes, the first a header. The
session's first page, taken at `FS_SESSION`, holds the session's record and
is held for the session's life. An open's record takes two slots, and each
page an open holds from [`FS_READ_MEMORY`](#label-7-fs_read_memory) one
more, in the lowest page of the session with room. When no page has room,
the driver takes the session another page charged to the node, and an
`FS_OPEN` or `FS_READ_MEMORY` whose page the node's max refuses is answered
`LIMIT`. A page other than the first goes back to memmgr, its charge to the
node with it, when its last record goes.

What stays on the driver's own node: for each session the slots of three
capabilities (the handle, the liveness object's parent, the first page's
Memory cap) and the liveness Notification, from the driver's own memory; a
capability slot for each further page; for each open in a session the slot
of its release SEND, when it carried one, and for each page it holds the
slot of the page's capability; and the index from ids to records, at most
two 4-byte heads per live session or open. The client pays in its own
`CSpace` for the capabilities it receives.

**Liveness cap.** For each session the driver retypes one Notification
from its own memory, so the driver funds the object, keeps a capability to
it, and hands the client a derivation of that capability with no rights,
which can neither signal nor wait. The session lives while any copy of the
liveness cap lives outside the driver: its client keeps the cap for the
session's life, and a client that dies takes its copy with its `CSpace`.
Ending the session revokes every copy of the liveness cap still in the
subtree of the driver's capability and frees the object once no copy is
left. The client's own copy stays in that subtree wherever an IPC transfer
or `SYS_CAP_MOVE` takes it, so it dies exactly when the session does. A
copy derived from another copy, the client's or any later holder's, stays in
the subtree wherever its derivation path runs, since deleting a capability
and tearing down the `CSpace` holding it both hand its derivations to the
nearest ancestor outside that `CSpace`, as
[core/kernel/docs/capability-internals.md](../../../core/kernel/docs/capability-internals.md#teardown-drain)
§ Teardown Drain states. A revoke at the driver's capability therefore
reaches every copy, including one derived through a dead `CSpace`.

**Session end.** The driver ends a session whose client holds no copy of its
liveness cap any more: it releases every open made in it as `FS_CLOSE`
would, revokes the copies of the liveness cap, deletes the handle, and gives
every page back, which returns the session's whole charge to its node. It
finds such sessions by asking the kernel whether its own capability is the
only reference left to the session's Notification (`SYS_CAP_INFO`
`CAP_INFO_SOLE_REFERENCE`,
[core/kernel/docs/syscalls.md](../../../core/kernel/docs/syscalls.md#sys_cap_info-36)
§ `SYS_CAP_INFO`); once it is, it stays so, since only the driver holds a
capability through which to add a reference. It reads every session so in a
**sweep**, which it makes when memmgr signals it the end of a donation (`REGISTER_DONATION_END`,
[§ Label
34](../../memmgr/docs/ipc-interface.md#label-34-register_donation_end): the
release of a node the driver holds a charged grant on, or the death of the
node's owner), on `FS_SESSION` once the sessions made since its last sweep
reach the larger of 64 and the live sessions that sweep left, so a sweep
costs at most two inquiries per session made, and at
[`FS_UNMOUNT`](#label-19-fs_unmount). It reads one session so at an
[`FS_CLOSE`](#label-3-fs_close) that closes the session's last open. A client
ends a session by deleting its liveness cap and then releasing the session's
node (`NODE_RELEASE`), which signals the driver; a session whose liveness
cap is deleted and whose node lives on ends at the next sweep, or at the close
of its last open. A client that deletes its liveness cap before it closes the
session's last open has the session ended by that close, its charge returned
before the reply. Until the session ends its pages stay charged to its node,
after the node's release too, and a page it needs then is refused with
`INVALID_ARGUMENT`. When the driver dies, memmgr returns
every page of its sessions, and the charge, to the nodes they were charged
to ([§ Driver exit](#driver-exit)).

**Delegation.** An open made in a session lives only while a copy of the
session's liveness cap is held. A holder other than the client keeps a
delegated open alive only by also holding such a copy, which the delegator
hands over beside the open cap, and that copy keeps the whole session, every
open made in it and their charge to the creator's node, alive while it
lives. A delegator SHOULD move its own copy (an IPC transfer or
`SYS_CAP_MOVE`) rather than derive one for the holder, so the copy stays
one the session's end revokes.

---

## Label 2: `FS_READ`

Inline read against a file node cap or open cap. The kernel delivers the
badge to the driver via `ipc_recv.badge`; the driver MUST verify the
`READ` rights bit and reject with `fs_errors::PERMISSION_DENIED`
otherwise.

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
(the badge lacks `READ`), `INVALID_BADGE` (the badge names no node, a
directory, or a closed open), `IO_ERROR` (the file's cluster chain is
corrupt, a block read failed, or every cache page is held; the client MAY
retry, since the driver queues a held page for eviction whenever a request
finds the cache full).

---

## Label 7: `FS_READ_MEMORY`

Memory-cap read. The driver returns a single-page Memory cap with
attenuated rights (`MAP` only: read-only mapping authority) covering
the cached page that contains the requested byte. The client maps the
memory cap, reads up to `bytes_valid` bytes starting at
`memory_data_offset`, then releases the page either synchronously after
the read, by sending [`FS_RELEASE_MEMORY`](#client-to-driver-release)
on the open cap, or in response to a driver-initiated
[`FS_RELEASE_MEMORY`](#driver-to-client-release) arriving on the
release endpoint the open's [`FS_OPEN`](#label-18-fs_open) carried. The
request MUST be sent on an open cap; a node cap is answered
`INVALID_BADGE`.

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

The request carries no caps; the driver deletes any it carries. The
returned page is an outstanding page of the open the badge names, and of
no other: the open's own [`FS_RELEASE_MEMORY`](#client-to-driver-release)
or [`FS_CLOSE`](#label-3-fs_close) releases it, and eviction sends its
cooperative release to that open's release endpoint. One open holds at
most as many outstanding pages as the cache has slots. A success reply
whose memory cap the client's `CSpace` cannot take arrives as
`IPC_REPLY_TRANSFER_FAILED` with no cap, and the driver then releases the
page as `FS_RELEASE_MEMORY` would, so the open holds no page the client
never received.

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | `bytes_valid` (zero on EOF) |
| `data[1]` | Cookie echoed back |
| `data[2]` | `memory_data_offset` |
| `caps[0]` | Memory cap (`MAP` rights, single page; omitted on EOF) |

**Reply (error)**: `label = ipc::fs_errors::*`: `PERMISSION_DENIED`
(the badge lacks `READ`), `INVALID_BADGE` (a node cap, a closed open, or
an open whose node was freed), `BAD_MEMORY_OFFSET` (cookie zero),
`TOO_MANY_OPEN` (the open's outstanding-page table is full, the driver's
`CSpace` cannot grow, or, in a session, the page's record needs another
session page the driver cannot map), `LIMIT`, `OUT_OF_MEMORY` and
`INVALID_ARGUMENT` (in a session: the page's record needs another session
page, refused as for
[`FS_OPEN`](#label-18-fs_open)), `IO_ERROR`
(the file's cluster chain is corrupt, a block read
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

Source: [services/fixtures/fsbench/README.md](../../fixtures/fsbench/README.md), which owns the
method. The full benchmark (`fsbench` with no iteration argument) loops 256 timed
iterations of "seek to 0; read N bytes via the chosen path" against a 64 KiB fixture
(`/data/svctest/bench.bin`); the per-path buffer sizes and cycle sources are in that
README's [§ Method](../../fixtures/fsbench/README.md#method). Numbers below are the mean
cycles of the timed iterations of one size and path; `fsbench` reports their percentiles
([§ Output](../../fixtures/fsbench/README.md#output)).

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

Sent by the driver's eviction worker on the release endpoint SEND the
[`FS_OPEN`](#label-18-fs_open) of the open that read the page carried, so
each page's release reaches the client that read it. Opens that carried
a SEND get the cooperative path: the driver waits up to
100 ms for [`FS_RELEASE_ACK`](#label-9-fs_release_ack), then
`cap_revoke`s the parent Memory cap and deletes it whether or not the
ack came. Opens that omitted the SEND (opt-out) skip straight to the
revoke on every eviction, and so does an open whose SEND the driver
cannot copy or whose watchdog it cannot start. The driver sends no
release for a page the client's own release or `FS_CLOSE` has already
removed from its open. See
[`runtime/ruststd/src/sys/fs/release_handler.rs`](../../../runtime/ruststd/src/sys/fs/release_handler.rs)
for the receive-side state machine.

**Request**

| Field | Value |
|---|---|
| `label` | `8` |
| `data[0]` | Release cookie identifying the Memory cap |

The client unmaps the matching Memory cap and replies with
[`FS_RELEASE_ACK`](#label-9-fs_release_ack). The release arrives on the
SEND of the open that read the page, whose badge the client chose, so the
client can match the cookie among that open's pages. If a local copy
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
cleaned up once, by whichever path removes it from its open first.
The ack tells the driver the client unmapped in time.
The revoke invalidates the client's derived cap but removes no mapping
([Capability Model § Revocation](../../../docs/capability-model.md#revocation)).
The driver still never refills the page under a live client mapping. Before it
reuses a released slot whose page it handed out, on any of the three release
paths, it revokes every derivation of the slot's cap and reads the page's
mapping count (`SYS_CAP_INFO` `CAP_INFO_MEMORY_MAPPINGS`). It refills the page only
when the count shows its own mapping alone. Otherwise it moves the slot onto a
replacement page and quarantines the still-mapped one, which is never refilled
and never returned to memmgr until no address space maps it. A client that keeps
a page mapped after the release, or whose copy outlasts the window, therefore
never sees the page refilled with other data. Until the page is quarantined, its bytes
change only by write-through of the sectors it caches; those may belong to other files
or to the FAT. A
client SHOULD still unmap before it acks: the driver takes at most 32 pages
beyond its cache slots to replace still-mapped ones, and past that a still-mapped
slot stays out of service, so a client that never unmaps shrinks the cache, and a
read that finds no reusable slot is answered `IO_ERROR` (2). A slot whose revoke
does not complete keeps its page and still serves cache hits, but the page is not
refilled with other data until a later revoke completes. A quarantined page
likewise becomes a spare only after a revoke of it completes.
A reply with any other label is not an
acknowledgement; a client that cannot unmap the page, or whose copy
outlasts the window, replies `IO_ERROR` (2).

### Client-to-driver release

Sent by the client on the open cap the page was read through, once it
has finished reading the page and torn down its local
mapping: a page still mapped when the driver next reuses its slot costs
the driver a quarantined page (see [Label 8](#label-8-fs_release_memory)).
No release endpoint and no
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
no outstanding page of the open is a no-op success.

**Reply (error)**: `label = fs_errors::*`: `PERMISSION_DENIED` when the
badge carries no namespace rights, `INVALID_BADGE` on a node cap or a
closed open.

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

End the open the open cap names: the driver revokes that open's
outstanding [`FS_READ_MEMORY`](#label-7-fs_read_memory) pages, deletes its
recorded release endpoint, and retires its id, so the open cap answers
`INVALID_BADGE` from then on. Other opens of the file, by this client or
another, keep their pages. The node itself is not freed: every holder of
the entry shares it, so it lives until
[`FS_REMOVE`](#label-14-fs_remove) or [`FS_RENAME`](#label-16-fs_rename)
unlinks the entry, and the node cap the open was made from still reaches
its file. The open cap is **not** freed here — the holder still
`cap_delete`s its open cap to free its slot. The open leaves its session's
pages: a page other than the session's first goes back to
memmgr, its charge with it, when its last record goes
([§ Label 23](#label-23-fs_session)); the session lives on with its
other opens. A close that leaves a session with no open, when its client
holds no copy of the session's liveness cap any more, ends the session as a
sweep would before the driver replies, so its whole charge is back on its
node when the reply arrives ([§ Label 23](#label-23-fs_session), Session
end).

**Request**

| Field | Value |
|---|---|
| `label` | `3` |
| body | empty (target identified by the open cap's badge) |

**Reply (success)**: `label = 0`, empty body.

**Reply (error)**: `label = fs_errors::*`: `INVALID_BADGE` on a node cap
or a session cap, or on an open already closed, released with its node, or
ended with its session.

---

## Label 4: `FS_WRITE`

Inline write to a file. Badge = file node cap or open cap; the badge must
carry the `WRITE` namespace right.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_WRITE \| (byte_len << 16)` (bits 0-15 = label, bits 16-31 = payload bytes, ≤504) |
| `data[0]` | File byte offset |
| `bytes(1, &payload)` | Payload bytes (`byte_len` of them) starting at byte 8 |

**Reply (success)**: `label = 0`, `data[0]` = bytes_written. A caller iterates on a short
count; the FAT driver always reports the whole payload and replies an error (`NO_SPACE`)
instead of a short count.

A write whose offset lies past the file's end extends the file, and the bytes between the old
end and the offset read as zeros, through [`FS_READ`](#label-2-fs_read) and
[`FS_READ_MEMORY`](#label-7-fs_read_memory) alike. A driver MUST NOT return a byte the file
never held, whatever its on-disk format leaves in the storage the write takes: a freed file's
data, or a block past the old end.

**Errors**: `INVALID_BADGE`, `IS_A_DIRECTORY`, `INVALID_ARGUMENT` (a
`byte_len` of zero, or one past the payload bytes the message carries),
`IO_ERROR`, `PERMISSION_DENIED`, `NO_SPACE` (no free cluster, or the write would end
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
it, past its reply: once the reply arrives the caller may write the page
again and lend it for its next write, or return it to memmgr's pool,
which another process can then be granted.

A write whose offset lies past the file's end leaves the gap reading as zeros, as for
[`FS_WRITE`](#label-4-fs_write).

**Errors**: `INVALID_BADGE`, `IS_A_DIRECTORY`, `IO_ERROR`,
`PERMISSION_DENIED`, `NO_SPACE` (as for [`FS_WRITE`](#label-4-fs_write)),
`BAD_MEMORY_OFFSET`.

---

## Label 13: `FS_CREATE`

Create a new file in a directory, and, with the `CREATE_OPEN` flag, open it
in the same request. Badge = parent-directory cap; the badge must carry the
`MUTATE_DIR` namespace right.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_CREATE \| (name_len << 16)`, with the flags below in bits 32 and 33 |
| `bytes(0, &name)` | Name bytes starting at byte 0 |
| `caps[0]` | With `CREATE_OPEN` only: a copy of the session cap, as [`FS_OPEN`](#label-18-fs_open) takes it |
| `caps[1]` | With `CREATE_OPEN` only: optional release-endpoint SEND for the open, as `FS_OPEN` takes it |

The flags (`ipc::fs_labels`):

- `CREATE_OPEN` (bit 32): open the new file in the session `caps[0]` names
  and reply with the open cap instead of a node cap.
- `CREATE_OPEN_EXISTING` (bit 33), valid only with `CREATE_OPEN`: when the
  directory already holds a file of that name, open that file instead of
  answering `EXISTS`. Opening a file found by name resolves the name, so the
  badge must then carry `LOOKUP` too, as an `NS_LOOKUP` of it would.

A request without `CREATE_OPEN` carries no cap, and the driver deletes any it
carries.

**Reply (success)**, without `CREATE_OPEN`: `label = 0`, `data[0]` =
`NodeKind` (= File), `caps[0]` = node cap for the newly-created file. The
new file starts empty (size 0, no allocated cluster). The cap's rights are
the parent cap's rights intersected with `STAT | READ | WRITE | EXEC`.

**Reply (success)**, with `CREATE_OPEN`: `label = 0`, `data[0]` =
`NodeKind` (= File), `data[1]` = the file's size (0 for a new file),
`caps[0]` = the open cap, as `FS_OPEN` replies it, carrying the rights a
node cap on the file would; no node cap. The open lives as one `FS_OPEN`
made, in the session `caps[0]` named.

**Atomic create and open.** With `CREATE_OPEN`, the driver settles
everything that can refuse the open before it writes the directory entry: it
reads the session cap, records the open in the session (taking the session
another page when its pages are full, charged to the session's node), takes
the new node's slot in its node table, and mints the open cap. An open the
client's node refuses therefore leaves no entry, and a client needs no
`FS_REMOVE` to undo a create whose open failed, which would race any other
process that reached the new file in between. A write of the entry that
fails closes the open. A reply the client cannot take (it died mid-call, or
its `CSpace` cannot take the cap) moves no cap; the driver closes the open,
and the entry stays, as after a plain `FS_CREATE` whose client died.

**Errors**, in the order the driver checks them; each refusal deletes the
carried caps:

- `INVALID_BADGE` (the badge names no directory), `PERMISSION_DENIED` (the
  badge lacks `MUTATE_DIR`, or it carries none of `STAT`, `READ`, `WRITE`,
  and `EXEC`, so the new file's cap would carry no rights).
- `INVALID_ARGUMENT`: `CREATE_OPEN_EXISTING` without `CREATE_OPEN`; or, with
  `CREATE_OPEN`, no `caps[0]` or one on another endpoint. `INVALID_BADGE`:
  a `caps[0]` on the driver's endpoint that names no live session.
- `INVALID_ARGUMENT`: an empty name, one longer than the message, an invalid
  name (one `namespace_protocol::validate_name` refuses), or one no FAT long
  name can hold (holding U+FFFF, or longer than 255 UTF-16 code units).
- With `CREATE_OPEN`, the open's refusals as `FS_OPEN` lists them (`LIMIT`,
  `OUT_OF_MEMORY`, `INVALID_ARGUMENT`, `TOO_MANY_OPEN`, `IO_ERROR`), and
  `IO_ERROR` when the driver cannot mint the open cap.
- `TOO_MANY_OPEN`: the driver's node table is full or the heap cannot grow
  it.
- With `CREATE_OPEN_EXISTING`, when the directory holds an entry of that
  name: `PERMISSION_DENIED` (the badge lacks `LOOKUP`), `IS_A_DIRECTORY` (the
  entry is a directory).
- `EXISTS` (the directory already holds an entry of that name, and the
  request does not open an existing file), `NO_SPACE`, `IO_ERROR`: writing
  the entry failed.

Every refusal but the last group leaves the directory as it was: the driver
refuses before writing anything, and no entry is created.

The std client creates every file with `CREATE_OPEN`, and opens an existing
one for `OpenOptions::create` with `CREATE_OPEN_EXISTING`
([runtime/ruststd/README.md](../../../runtime/ruststd/README.md)
§ Filesystem sessions).

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

**Errors**: `INVALID_ARGUMENT` (an empty name, or one longer than the
message), `NOT_FOUND`, `NOT_EMPTY` (directory has entries other than `.`
and `..`), `IO_ERROR`, `PERMISSION_DENIED`, `INVALID_BADGE` (the badge is
not a directory node).

`FS_REMOVE` is not atomic: the driver marks the entry's LFN slots, then
its 8.3 slot, each with its own block write (see
[`crash-safety.md`](../fat/docs/crash-safety.md)). A sector write the block
device fails leaves the driver's cached copy of that sector as it was
before the write, though the device may hold either version. When a
block access of the removal fails, the driver settles the request by
where it left the 8.3 slot: a failure before the 8.3 slot's own write
leaves the entry live, and when that write failed, the driver reads the
slot back from the device, past its cache:

- **Entry still live**: the driver writes back the first bytes of the LFN
  slots it marked and replies the error (`IO_ERROR`). The entry stays,
  with its long name and its node, so caps held on it keep working. An
  LFN slot whose restore also fails stays marked, leaving the entry
  visible only under its short alias.
- **Entry deleted**: the removal took effect. The driver frees the entry's
  cluster chain, drops its node, and replies as for a removal whose writes
  all succeeded.
- **Slot unreadable** (only after the 8.3 slot's write failed): the
  driver replies `IO_ERROR` and drops the entry's node, since it may be
  gone; caps held on it then reply `INVALID_BADGE`. The entry may remain
  on the device without its LFN run.

A node the driver drops no longer names anything, so a later `FS_CREATE`
that reuses the slot cannot reach a stale node through a held cap. The
driver reuses a dropped node's id for a later node under a new generation,
so a held cap on the dropped node is answered `INVALID_BADGE`, never with
the content of the node that reused the id.

---

## Label 15: `FS_MKDIR`

Create a new (empty) directory. Same shape as `FS_CREATE`. Allocates
one cluster, zero-fills it, and populates `.` / `..` entries before
the directory entry is inserted in the parent.

**Reply (success)**: `label = 0`, `data[0]` = `NodeKind` (= Dir),
`caps[0]` = node cap for the new directory, carrying the parent cap's
rights.

It takes neither `FS_CREATE` flag: a request carrying `CREATE_OPEN` or
`CREATE_OPEN_EXISTING` is refused `INVALID_ARGUMENT`.

**Errors**: as `FS_CREATE` without `CREATE_OPEN`, except that
`PERMISSION_DENIED` means only a missing `MUTATE_DIR`: a directory's cap
keeps every parent right, so it is never empty.

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
send such a pair. The server replies `INVALID_ARGUMENT` to a zero length, or
to lengths whose sum exceeds the name bytes the message carries after the
two length words.

**Reply (success)**: `label = 0`, empty body.

Cross-directory rename is deferred: the request carries one directory
cap, so a destination in another directory cannot be named. A server
can resolve a second directory cap on its own endpoint to a `NodeId`
by reading its badge with `SYS_ENDPOINT_BADGE`, which needs Receive on
that endpoint; no driver does so yet. Tracked as
[Issue #89](https://github.com/kottlerg/seraph/issues/89).

`FS_RENAME` is not atomic — see
[`services/fs/fat/docs/crash-safety.md`](../fat/docs/crash-safety.md)
for the post-crash visible states. The driver inserts the destination
entry, then removes the source as [`FS_REMOVE`](#label-14-fs_remove) does,
and drops the source's node once the source is gone. An error inserting
the destination is replied as it stands. When a block access of the
source's removal fails, the driver settles the request by where it left
the source's 8.3 slot, as `FS_REMOVE` does:

- **Source still live**: the driver undoes the rename. It marks the
  destination's slots deleted first, so a failure part-way leaves at
  worst both names and never neither, then writes back the first bytes of
  the source's LFN slots it marked, and replies the error (`IO_ERROR`).
  The source keeps its node.
- **Source deleted**: the rename took effect. The driver drops the
  source's node and replies success.
- **Slot unreadable** (only after the source's 8.3 write failed): the
  driver replies `IO_ERROR` without undoing anything and drops the
  source's node. Both names may remain.

**Errors**: `INVALID_ARGUMENT` (malformed name lengths, an invalid source or
destination name, or a destination no FAT long name can hold, as `FS_CREATE`
refuses them), `NOT_FOUND` (source missing), `EXISTS` (destination
occupied), `NO_SPACE`, `IO_ERROR` (a failed block access, or a corrupt
directory), `PERMISSION_DENIED`, `INVALID_BADGE` (the badge is not a
directory node). None of the `INVALID_ARGUMENT` refusals writes anything.

---

## Label 17: `FS_TRUNCATE`

Set a file's length. Badge = file node cap or open cap with `WRITE`.

**Request**:

| Field | Value |
|---|---|
| `label` | `FS_TRUNCATE` (17) |
| `data[0]` | New length in bytes |

**Reply (success)**: `label = 0`, empty body.

v1 supports only `new_len == 0`; non-zero replies `IO_ERROR`. The
wire shape is forward-compatible with later extend-with-zero-fill
semantics, tracked by the `ruststd::fs` completeness-gaps issue. The
truncate-to-zero path patches the directory entry's first-cluster and
size fields to 0, then frees the old FAT cluster chain. An `IO_ERROR`
from freeing the chain arrives after the patch: the file is already
empty and its old clusters are orphaned, as
[`crash-safety.md`](../fat/docs/crash-safety.md) states.

**Errors**: `INVALID_BADGE`, `IS_A_DIRECTORY`, `PERMISSION_DENIED`,
`IO_ERROR` (directory-entry write or chain walk failure, or non-zero
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
| `caps[0]` | Block device endpoint (`SEND_GRANT`, partition-scoped badge on virtio-blk; GRANT because every block request moves the Memory cap it fills or drains) |
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
bound on every `BLK_READ_INTO_MEMORY`. The cap is a derivation of the
partition cap vfsd keeps for the mount, so vfsd can revoke it. See
[`services/vfsd/docs/vfs-ipc-interface.md`](../../vfsd/docs/vfs-ipc-interface.md)
§ Label 10: `MOUNT` for the registration step and
[`services/drivers/virtio/blk/README.md`](../../drivers/virtio/blk/README.md).
Revoking it takes the device from the driver for good, as
[Loss of the block device](#loss-of-the-block-device) describes.

---

## Loss of the block device

The driver loses its block device for good when the capability's holder
revokes it. It tells that loss from a failure that passes by asking the
kernel about the block device capability whenever a block request's
`SYS_IPC_CALL` fails (`SYS_CAP_INFO`,
[core/kernel/docs/syscalls.md](../../../core/kernel/docs/syscalls.md#sys_cap_info-36)
§ `SYS_CAP_INFO`): a capability that names nothing any more
(`InvalidCapability`) was revoked. The driver then logs the loss, answers
the request in flight as for any failed block access (`IO_ERROR`, or what
the label's section names), issues no further block request, and exits with
`fs_labels::EXIT_DEVICE_GONE` ([§ Driver exit](#driver-exit)) before it
receives another request. A request the driver took up while it answered an
earlier one, before the loss was found, is answered as for any failed block
access as well, and the capabilities it carried are deleted. The exception
is an `FS_UNMOUNT` whose `FSInfo` write finds the loss: it replies success
and exits with `EXIT_UNMOUNTED`, as § Driver exit states. Until a block
request reaches the device, the driver does not learn of the loss: an idle
driver, or one serving requests from its page cache, serves on. A failed
call through a capability that still names its endpoint, and an error reply
from the block driver, are transient: the request fails as its label's
section states, and the driver serves on.

---

## Driver exit

A driver ends its service in two cases, each with its own exit code, a
`fs_labels` constant. Its death observers receive the exit reason
`syscall_abi::encode_exit_code(code)`
([abi/syscall/src/lib.rs](../../../abi/syscall/src/lib.rs) § Exit reason
constants).

| Code | Constant | Cause |
|---|---|---|
| `0` | `EXIT_UNMOUNTED` | The driver replied success to [`FS_UNMOUNT`](#label-19-fs_unmount) |
| `1` | `EXIT_DEVICE_GONE` | A block request found the block device capability revoked ([§ Loss of the block device](#loss-of-the-block-device)) |

A driver's death in any way returns its sessions' pages, and their charge,
to the nodes they were charged to: memmgr releases a dead process's grants
([services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md#distribution-policy)
§ Distribution policy, **Charged grants**).

An `FS_UNMOUNT` whose `FSInfo` write is the request that finds the
capability revoked still replies success and exits with `EXIT_UNMOUNTED`:
the `FSInfo` fields are hints, and every open was released before the
write.

A driver also ends on its own before or outside its service, with codes
that are not `fs_labels` constants:

- the reason `0` when its bootstrap round, its page-cache setup, or the
  spawn of its eviction worker fails, before it serves any request;
- ruststd's startup-failure codes (`0x0F01..=0x0F02`), before `main`;
- `EXIT_RECV_WEDGE` (`0x0F10`), when its receive loop wedges
  ([docs/ipc-design.md](../../../docs/ipc-design.md) § Receive-Failure
  Policy).

Any other end of a driver is a fault or a kill, such as vfsd's
destruction of a driver that an unmount found still running
([§ Label 19](#label-19-fs_unmount)).

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

[Namespace Model](../../../docs/namespace-model.md), [Storage](../../../docs/storage.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[services/fixtures/fsbench/README.md](../../fixtures/fsbench/README.md),
[services/fs/README.md](../README.md), [services/fs/fat/README.md](../fat/README.md),
[services/vfsd/README.md](../../vfsd/README.md),
[vfsd Service Interface](../../vfsd/docs/vfs-ipc-interface.md)
