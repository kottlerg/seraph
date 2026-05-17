# fs-fat crash safety

FAT has no commit ordering. Every mutation in `services/fs/fat` is a
sequence of independent block writes, and the on-disk state between
any two of them is a legitimate FAT layout the driver will accept on
the next mount. v0.1.0 accepts these windows — there is no journal
and no boot-time fsck.

This document enumerates the windows so callers can reason about what
they may observe after an interrupted operation.

---

## Write ordering

| Operation | Per-block order | Post-crash visible states |
|---|---|---|
| `FS_WRITE` (extending) | data cluster(s) → FAT chain link(s) → directory `size` | (a) old size, no data; (b) old size, new data orphaned in unreferenced clusters; (c) old size, data + FAT link, dir entry unchanged → orphaned chain past EOF; (d) new size, new data |
| `FS_WRITE` (in-place) | data cluster sector | (a) old bytes; (b) new bytes. Single-sector RMW; partial sector writes never observed because the cache page is updated in place before the on-disk write. |
| `FS_CREATE` | (none yet — first cluster allocated lazily by the first `FS_WRITE`) → directory entry | (a) no entry; (b) entry present with `first_cluster = 0`, `size = 0` |
| `FS_MKDIR` | allocate cluster → zero-fill cluster → write "."/".." → directory entry | (a) no entry; (b) orphaned zeroed cluster; (c) orphaned cluster with "."/".." (looks like a stray empty directory by inode); (d) entry present pointing at the new cluster |
| `FS_REMOVE` | dir entry → `0xE5`; LFN slots → `0xE5`; FAT chain → free | (a) entry present; (b) entry deleted, chain still linked → orphan cluster chain; (c) entry deleted, chain freed |
| `FS_RENAME` | insert dest entry → mark src entry `0xE5` | (a) only src present; (b) **both** src and dst present (two names referring to the same cluster chain — readers see the file twice); (c) only dst present |

The FAT mirror copies (`num_fats == 2` on the default xtask-formatted
image) are written in `0..num_fats` order. A crash between them
leaves an inconsistent FAT pair; `fsck.vfat` reports a discrepancy
but reconciles to FAT 0.

---

## Orphan classes

* **Orphan cluster chain**: clusters marked allocated in the FAT but
  with no directory entry pointing at them. Walking the FAT finds them;
  walking the directory tree does not. Result: lost space. Recoverable
  by `fsck.vfat` (Linux) or `chkdsk /F` (Windows). v0.1.0 does not
  schedule a boot-time fsck; orphans persist until manual repair.

* **Orphan directory entry**: an entry whose `first_cluster` points at a
  cluster the FAT has freed (or marked bad). Reading via the entry
  returns garbage from whatever was last on those sectors. Writing
  through it could corrupt unrelated data once those clusters are
  reused.

* **Duplicate entry (rename window c)**: two directory entries with the
  same `first_cluster`. Reads via either entry behave correctly until
  the chain is mutated through one of them; subsequent reads via the
  other entry see the mutation. Removing one entry frees the chain
  the other entry still references — silent data loss on the survivor.

---

## What v0.1.0 does *not* do

* No fsync wire label. Every `FS_WRITE` is write-through to the block
  device by the time the reply lands; there is no "data acknowledged
  but unflushed" window in fatfs itself. The block device may itself
  buffer (virtio-blk on QEMU does not, but the design space includes
  drivers that do). A separate `FS_FSYNC` label is a follow-up.

* No journal. The write-back-cache work tracked as a follow-up Issue
  would need its own crash-safety story before it lands; write-through
  is intentionally chosen first so v0.1.0 has a simpler crash window.

* No boot-time fsck. A consistency check at mount would catch
  orphan-chain and duplicate-entry cases; the design space is
  reasonable but not in v0.1.0 scope.

---

## Tested ordering invariants

`usertest`'s `fs_write_cache_coherence_phase` confirms that
write-through means `FS_READ` after `FS_WRITE` observes the new bytes
without any explicit flush — no scenario in v0.1.0 requires a flush
between write and read for correctness within the lifetime of a
process.

The other write-side phases (`fs_write_phase`, `fs_create_remove_phase`,
`fs_mkdir_phase`, `fs_rename_phase`, `fs_write_frame_phase`) are
golden-path round-trip tests; the windows above are not exercised
by deliberate crash injection at v0.1.0. A two-boot QEMU harness for
remount-survive testing is tracked as a follow-up.

---

## Summarized By

[services/fs/fat/README.md](../README.md)
