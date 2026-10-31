# fat

Seraph FAT16 / FAT32 filesystem driver, one process per mount.

---

## Source Layout

```
fat/
├── Cargo.toml
├── README.md
├── fat-parse/                  # `fatfs-parse`: BPB/dir decoders, slot scans, cluster bounds,
│                               #   name encoding and tails, node slab, cache bounds
├── docs/
│   ├── crash-safety.md         # Per-op write ordering and post-crash visible states
│   └── storage-layout.md       # Allocator, directory mutation, page cache, NodeTable, eviction
└── src/
    ├── main.rs                 # Dispatch loop, FS_* handlers, write engine
    ├── bpb.rs                  # BPB parser, FatState fields
    ├── alloc.rs                # Cluster allocator, FAT-mirror writes, FSInfo flush
    ├── dir.rs                  # Directory walks and mutation (insert/remove/rename)
    ├── fat.rs                  # FAT-entry reads and chain walks
    ├── cache.rs                # PageCache: read/write through BLK_*_FROM_MEMORY
    ├── eviction.rs             # Cooperative-release eviction worker
    ├── file.rs                 # OpenFile / OutstandingPage bookkeeping
    └── backend.rs              # NamespaceBackend impl + NodeTable
```

---

## IPC surface

Each label's wire shape and error set are specified in
[`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md).

| Label | Unbadged? | Description |
|---|---|---|
| `FS_MOUNT` | yes | vfsd's BPB-validation probe at mount time |
| `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` | no | namespace dispatch |
| `FS_READ` | no | inline read on a file cap |
| `FS_READ_MEMORY` | no | zero-copy read via a returned `Memory` cap |
| `FS_RELEASE_MEMORY` | no | synchronous client release of an `FS_READ_MEMORY` page (the eviction worker sends the cooperative release; fatfs does not receive it) |
| `FS_CLOSE` | no | release per-file driver-side bookkeeping |
| `FS_WRITE` | no | inline write on a file cap |
| `FS_WRITE_MEMORY` | no | caller-supplied source `Memory` cap |
| `FS_CREATE` | no | new file in a directory |
| `FS_REMOVE` | no | unlink a file or empty directory |
| `FS_MKDIR` | no | new empty directory |
| `FS_RENAME` | no | rename within a single directory |
| `FS_TRUNCATE` | no | shrink a file to zero (v1: `new_len == 0` only) |

`FS_RENAME` is single-directory only because servers cannot introspect
the badge packed in a received cap, so a second directory cap cannot
resolve to a `NodeId`. Cross-directory rename is deferred; see
[`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md) § Label 16: `FS_RENAME`.

Per-label rights gating (`WRITE` for the write / truncate labels,
`MUTATE_DIR` for the directory-mutation labels) goes through
[`namespace-protocol::gate`](../../../shared/namespace-protocol/src/gate.rs), as
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
§ Rights gate specifies. The exact wire shapes are defined in
[`shared/ipc/src/lib.rs`](../../../shared/ipc/src/lib.rs) and documented
in [`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md).

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
(`src/dir.rs`), a write-through page cache of up to 128 slots taken on first use (`src/cache.rs`), a
node table that dedupes by on-disk slot and recycles closed nodes (`src/backend.rs`), and a
cooperative-release eviction worker (`src/eviction.rs`). Sectors are the device's logical blocks,
512 to 4096 bytes. Each component's behavior is specified in
[docs/storage-layout.md](docs/storage-layout.md).

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
