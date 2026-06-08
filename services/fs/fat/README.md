# fat

Seraph FAT16 / FAT32 filesystem driver, one process per mount.

---

## Source Layout

```
fat/
├── Cargo.toml
├── README.md
├── fat-parse/                  # `fatfs-parse` crate: pure host-tested BPB + directory decoders
├── docs/
│   └── crash-safety.md         # Per-op write ordering and post-crash visible states
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

| Label | Unbadged? | Description |
|---|---|---|
| `FS_MOUNT` | yes | vfsd's BPB-validation probe at mount time |
| `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` | no | namespace dispatch |
| `FS_READ` | no | inline read on a file cap |
| `FS_READ_MEMORY` | no | zero-copy read via a returned `Memory` cap |
| `FS_RELEASE_MEMORY` | no | client-side cooperative release |
| `FS_CLOSE` | no | release per-file driver-side bookkeeping |
| `FS_WRITE` | no | inline write on a file cap |
| `FS_WRITE_MEMORY` | no | caller-supplied source `Memory` cap |
| `FS_CREATE` | no | new file in a directory |
| `FS_REMOVE` | no | unlink a file or empty directory |
| `FS_MKDIR` | no | new empty directory |
| `FS_RENAME` | no | rename within a single directory |
| `FS_TRUNCATE` | no | shrink a file to zero (v1: `new_len == 0` only) |

`FS_RENAME` is single-directory only at v0.1.0 because servers cannot
introspect the badge packed in a received cap; cross-directory rename
needs either a kernel-level `cap_info` selector for badges or a wire
shape that conveys the destination `NodeId` out-of-band. Tracked as
[Issue #89](https://github.com/kottlerg/seraph/issues/89).

Per-label rights gating (`WRITE` for the write / truncate labels,
`MUTATE_DIR` for the directory-mutation labels) goes through
[`namespace-protocol::gate`](../../../shared/namespace-protocol/src/gate.rs).
The exact wire shapes are defined in
[`shared/ipc/src/lib.rs`](../../../shared/ipc/src/lib.rs) and documented
in [`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md).

Cap-monotonic attenuation: `FS_CREATE` / `FS_MKDIR` mint a child cap
with rights `caller_parent ∩ kind_max` where `kind_max` is
`{STAT, READ, WRITE, EXEC}` for files and `NamespaceRights::ALL` for
directories. A caller with `MUTATE_DIR`-only on a parent cannot widen
into `READ` or `WRITE` on the created entry.

---

## Storage layout

* **Cluster allocator** (`src/alloc.rs`): linear FAT scan seeded from
  the FAT32 FSInfo `FSI_Nxt_Free` advisory hint. Mirror writes across
  all FAT copies. Invalidates the per-`FatState` private
  `cached_fat_sector` after every FAT-sector write to keep chain walks
  consistent. Best-effort FSInfo write-back after every allocation /
  free.
* **Directory mutation** (`src/dir.rs`): `insert_entry` / `remove_entry`
  / `update_entry_metadata`. Strict-8.3 short names round-trip
  exactly; non-strict names take a `NUMERIC_TAIL` (`~1..~6`) basis
  with an LFN run packed in reverse-sequence order. The trailing
  `0x40` LFN sequence flag and `LDIR_Chksum` computation match the
  Microsoft FAT specification.
* **Page cache** (`src/cache.rs`): 128 single-page slots backed by
  `BLK_READ_INTO_MEMORY` for fills and a process-static scratch memory cap
  for single-sector `BLK_WRITE_FROM_MEMORY` writebacks. Write-through:
  the cached page is updated in place before the on-disk write so any
  outstanding `FS_READ_MEMORY` cap aliasing the page observes new bytes
  immediately.
* **NodeTable** (`src/backend.rs`): dedupes by on-disk slot
  `(sector_lba, offset_in_sector)`; two distinct on-disk entries
  always allocate distinct `NodeId`s, even when both are empty files
  at cluster 0. `FS_REMOVE` and `FS_RENAME` invalidate the entry for
  the unlinked slot.
* **Eviction worker** (`src/eviction.rs`): unchanged from the read-side
  cooperative-release design; outstanding write paths return their
  caps before reply so they do not create new eviction pressure.

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
| [services/fs/docs/fs-driver-protocol.md](../docs/fs-driver-protocol.md) | Wire shapes for every FS_* label |
| [docs/namespace-model.md](../../../docs/namespace-model.md) | Cap-as-namespace, rights attenuation |
| [shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md) | `NS_*` wire surface and `NamespaceBackend` trait |

---

## Summarized By

None
