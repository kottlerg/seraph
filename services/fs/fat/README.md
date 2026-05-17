# fat

Seraph FAT16 / FAT32 filesystem driver. Read-write since
[Issue #6](https://github.com/kottlerg/seraph/issues/6) +
[Issue #7](https://github.com/kottlerg/seraph/issues/7).

The driver is one process per mount; vfsd spawns and tears down
instances, captures each driver's root cap at mount time, and forwards
walks through it. The driver implements the cap-native namespace
protocol (`NS_LOOKUP` / `NS_STAT` / `NS_READDIR`) for directory walks
and the per-node filesystem labels for I/O and mutation.

---

## IPC surface

| Label | Untokened? | Description |
|---|---|---|
| `FS_MOUNT` | yes | vfsd's BPB-validation probe at mount time |
| `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` | no | namespace dispatch |
| `FS_READ` | no | inline read on a file cap |
| `FS_READ_FRAME` | no | zero-copy read via a returned `Frame` cap |
| `FS_RELEASE_FRAME` | no | client-side cooperative release |
| `FS_CLOSE` | no | release per-file driver-side bookkeeping |
| `FS_WRITE` | no | inline write on a file cap |
| `FS_WRITE_FRAME` | no | caller-supplied source `Frame` cap |
| `FS_CREATE` | no | new file in a directory |
| `FS_REMOVE` | no | unlink a file or empty directory |
| `FS_MKDIR` | no | new empty directory |
| `FS_RENAME` | no | rename within a single directory |

`FS_RENAME` is single-directory only at v0.1.0 because servers cannot
introspect the token packed in a received cap; cross-directory rename
needs either a kernel-level `cap_info` selector for tokens or a wire
shape that conveys the destination `NodeId` out-of-band.

Per-label rights gating (`WRITE` for the write labels, `MUTATE_DIR`
for the mutation labels) goes through
[`namespace-protocol::gate`](../../shared/namespace-protocol/src/gate.rs).
The exact wire shapes are defined in
[`shared/ipc/src/lib.rs`](../../shared/ipc/src/lib.rs) and documented
in [`../docs/fs-driver-protocol.md`](../docs/fs-driver-protocol.md).

---

## Storage layout

* **Cluster allocator** (`src/alloc.rs`): linear FAT scan seeded from
  the FAT32 FSInfo `FSI_Nxt_Free` advisory hint. Mirror writes across
  all FAT copies. Invalidates the per-`FatState` private
  `cached_fat_sector` after every FAT-sector write to keep chain walks
  consistent.
* **Directory mutation** (`src/dir.rs`): `insert_entry` / `remove_entry`
  / `update_entry_metadata`. Strict-8.3 short names round-trip
  exactly; non-strict names take a `NUMERIC_TAIL` (`~1..~6`) basis
  with an LFN run packed in reverse-sequence order. The trailing
  `0x40` LFN sequence flag and `LDIR_Chksum` computation match the
  Microsoft FAT specification.
* **Page cache** (`src/cache.rs`): 128 single-page slots backed by
  `BLK_READ_INTO_FRAME` for fills and a process-static scratch frame
  for single-sector `BLK_WRITE_FROM_FRAME` writebacks. Write-through:
  the cached page is updated in place before the on-disk write so any
  outstanding `FS_READ_FRAME` cap aliasing the page observes new bytes
  immediately.
* **Eviction worker** (`src/eviction.rs`): unchanged from the read-side
  cooperative-release design; outstanding write paths return their
  caps before reply so they do not create new eviction pressure.

---

## Crash window

FAT has no commit ordering. Per-op write ordering is documented in
[`docs/crash-safety.md`](docs/crash-safety.md), including the
post-crash visible states for each mutation. v0.1.0 accepts these
windows — no journal, no boot-time fsck.
