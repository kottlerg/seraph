# fat

Seraph FAT16 / FAT32 filesystem driver, one process per mount.

---

## Source Layout

```
fat/
├── Cargo.toml
├── README.md
├── fat-parse/                  # `fatfs-parse`: BPB/dir decoders, slot scans, cluster bounds,
│                               #   FAT entries, file positions, name encoding, LFN slots
│                               #   and tails, node slab, cache bounds and victim pick,
│                               #   session pool (records in client-paid pages),
│                               #   session sweep schedule
├── docs/
│   ├── crash-safety.md         # Per-op write ordering and post-crash visible states
│   └── storage-layout.md       # Allocator, directory mutation, page cache, NodeTable, eviction
└── src/
    ├── main.rs                 # Dispatch loop, pressure thread, FS_* handlers, write engine
    ├── held.rs                 # Slow-request line of the dispatch loop
    ├── bpb.rs                  # BPB parser, FatState fields
    ├── alloc.rs                # Cluster allocator, FAT-mirror writes, FSInfo flush
    ├── dir.rs                  # Directory walks and mutation (insert/remove/rename)
    ├── fat.rs                  # FAT-entry reads and chain walks
    ├── cache.rs                # PageCache: read/write through BLK_*_FROM_MEMORY
    ├── eviction.rs             # Cooperative-release eviction worker
    ├── file.rs                 # Opens: sessions and the opens made in them, held pages
    ├── session.rs              # Session pages: window, memmgr charged grants
    └── backend.rs              # NamespaceBackend impl + NodeTable
```

---

## IPC surface

Each label's wire shape and error set are specified in
[`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md).

| Label | Unbadged? | Description |
|---|---|---|
| `FS_MOUNT` | yes | vfsd's BPB-validation probe at mount time |
| `FS_UNMOUNT` | yes | vfsd's unmount: refused `BUSY` while an open is live unless forced, else every open released, every session ended, and the driver exits |
| `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` | no | namespace dispatch |
| `FS_SESSION` | no | start a session whose records live in pages charged to the client's node, on a node cap |
| `FS_OPEN` | no | mint a per-open cap on a file cap, in the session the request's session cap names |
| `FS_READ` | no | inline read on a file cap or open cap |
| `FS_READ_MEMORY` | no | zero-copy read via a returned `Memory` cap, on an open cap |
| `FS_RELEASE_MEMORY` | no | synchronous client release of an `FS_READ_MEMORY` page (the eviction worker sends the cooperative release; fatfs does not receive it) |
| `FS_CLOSE` | no | end one open, releasing its pages, its release SEND and its records |
| `FS_WRITE` | no | inline write on a file cap or open cap |
| `FS_WRITE_MEMORY` | no | caller-supplied source `Memory` cap |
| `FS_CREATE` | no | new file in a directory; with `CREATE_OPEN`, opened in a session in the same request, the open recorded before the entry is written |
| `FS_REMOVE` | no | unlink a file or empty directory |
| `FS_MKDIR` | no | new empty directory |
| `FS_RENAME` | no | rename within a single directory |
| `FS_TRUNCATE` | no | shrink a file to zero (v1: `new_len == 0` only) |

`FS_RENAME` is single-directory only: the request carries one directory
cap, so a destination in another directory cannot be named.
Cross-directory rename is deferred; see
[`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md) § Label 16: `FS_RENAME`.

Per-label rights gating (`WRITE` for the write / truncate labels,
`MUTATE_DIR` for the directory-mutation labels) goes through
[`namespace-protocol::gate`](../../../shared/namespace-protocol/src/gate.rs), as
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
§ Rights gate specifies. The exact wire shapes are defined in
[`shared/ipc/src/fs_labels.rs`](../../../shared/ipc/src/fs_labels.rs) and
[`fs_errors.rs`](../../../shared/ipc/src/fs_errors.rs), and documented in
[`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md).

Cap-monotonic attenuation: `FS_CREATE` / `FS_MKDIR` mint a child cap
with rights `caller_parent ∩ kind_max` where `kind_max` is
`{STAT, READ, WRITE, EXEC}` for files and `NamespaceRights::ALL` for
directories. A caller with `MUTATE_DIR`-only on a parent cannot widen
into `READ` or `WRITE` on the created entry. A file whose cap would
carry no rights (a parent with none of the file rights) is refused with
`PERMISSION_DENIED` before anything is written, so no entry is created
(see [`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md) § Label 13: `FS_CREATE`).

---

## Storage layout

The driver's storage engine is a cluster allocator (`src/alloc.rs`), directory mutation
(`src/dir.rs`), a write-through page cache whose slots take pages on demand and give idle ones
back under memory pressure, up to 256 or 1/512 of RAM, whichever is more, and which fills a
sequential scan's miss with a run of up to 16 pages in one block request (`src/cache.rs`), a
node table that dedupes by on-disk slot and recycles the nodes of removed or renamed entries
(`src/backend.rs`), the sessions and the opens made in them, whose records live in pages charged
to a node of their client (`src/file.rs`, `src/session.rs`), and a cooperative-release
eviction worker (`src/eviction.rs`). Sectors are the
device's logical blocks, 512 to 4096 bytes. Each component's behavior is specified in
[docs/storage-layout.md](docs/storage-layout.md).

---

## Slow requests

One thread serves every request of a mount, so a request it holds delays every request queued
behind it. A request held 5 seconds or longer, from its receipt to the end of its dispatch after
the reply, is logged once that turn ends, as a warning naming its label and saying how much of
its time its block calls took and how many it made:

```text
slow request: FS_REMOVE (label 14) held 12034 ms, 11870 ms of it in 2311 block calls
```

The bound is vfsd's bound on the driver's answer to `FS_UNMOUNT` (`FS_UNMOUNT_TIMEOUT_MS`,
[docs/limits.md](../../../docs/limits.md)), the tightest a client puts on a call to this driver: a
request held that long has outlasted the bound of any such call queued behind it, and an unmount
queued behind it has timed out, so vfsd tears the mount down without the driver's cooperation.
The other bounds on a call to this driver, procmgr's on a call on a file cap and vfsd's on a
fall-through call and on the mount probe, are 10 seconds.
A request whose block calls took most of its time stalled in the block path, which the
virtio-blk driver's own slow-request line splits further
([virtio/blk § Slow requests](../../drivers/virtio/blk/README.md#slow-requests)); one whose
block calls took little stalled in fatfs or in another service it called. A request held less
costs two clock reads, and each block call two more.

---

## Crash window

FAT has no commit ordering. Per-op write ordering is documented in
[`docs/crash-safety.md`](docs/crash-safety.md), including the
post-crash visible states for each mutation. v0.1.0 accepts these
windows.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/crash-safety.md](docs/crash-safety.md) | Per-op write ordering and post-crash visible states |
| [docs/storage-layout.md](docs/storage-layout.md) | Allocator, directory mutation, page cache, NodeTable, eviction |
| [services/fs/docs/fs-driver-protocol.md](../docs/fs-driver-protocol.md) | Wire shapes for every FS_* label |
| [docs/namespace-model.md](../../../docs/namespace-model.md) | Cap-as-namespace, rights attenuation |
| [shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md) | `NS_*` wire surface and `NamespaceBackend` trait |

---

## Summarized By

None
