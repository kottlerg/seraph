# fs-fat storage layout

How `services/fs/fat` lays out its storage engine: the cluster allocator, directory mutation, the
page cache, the node table, and the eviction worker. The wire surface is specified in
[fs-driver-protocol.md](../../docs/fs-driver-protocol.md), and the write ordering of each mutation
in [crash-safety.md](crash-safety.md).

---

## Components

* **Cluster allocator** (`src/alloc.rs`): linear FAT scan seeded from
  the FAT32 FSInfo `FSI_Nxt_Free` advisory hint. Mirror writes across
  all FAT copies. Invalidates the per-`FatState` private
  `cached_fat_sector` after every FAT-sector write to keep chain walks
  consistent. Best-effort FSInfo write-back after every allocation /
  free.
* **Directory mutation** (`src/dir.rs`): `insert_entry` / `remove_entry`
  / `update_entry_metadata`. Strict-8.3 short names round-trip
  exactly; non-strict names take the specification's numeric tail
  (`~1` to `~999999`, the basis shortened to fit) at the lowest tail no
  short name in the directory carries for that basis, found in one pass
  (`fat_parse::TailSet`; a directory's 65536-entry cap always leaves one
  free), with an LFN run packed in reverse-sequence order. The long name is
  the UTF-8 name encoded as UTF-16 code units (`fat_parse::encode_lfn`, at
  most 255). The trailing `0x40` LFN sequence flag and `LDIR_Chksum`
  computation match the Microsoft FAT specification.
* **Page cache** (`src/cache.rs`): up to `SLOT_COUNT` (128) single-page slots backed by
  `BLK_READ_INTO_MEMORY` for fills and a process-static scratch memory cap for single-sector
  `BLK_WRITE_FROM_MEMORY` writebacks and single-sector device reads. A sector is one logical block
  of the device, whose size `FS_MOUNT` reads with `BLK_GET_GEOMETRY` before the BPB; a page holds
  `PAGE_SIZE` over it. A slot takes its page from memmgr the first time a miss finds no free slot,
  and the cache evicts only once all `SLOT_COUNT` slots hold a page or memmgr refuses one, so an
  idle mount pays only for the pages it fills. Cache init funds the fs's own `CSpace` with general
  headroom for every slot page, the quarantine's replacements, the scratch page, and 64 more
  (`std::os::seraph::fund_cspace_slot_budget`), so growing the cache never meets an exhausted
  `CSpace`; a failed funding fails cache init. Write-through: the cached page is updated in place
  before the on-disk write so any outstanding `FS_READ_MEMORY` cap aliasing the page observes new
  bytes immediately, and the sector is put back when the write fails. `reload_sector` reads one
  sector from the device past the cache and refreshes the cached copy; a failed `FS_REMOVE` or
  `FS_RENAME` whose 8.3 slot write failed uses it to learn whether that slot was deleted. A slot
  whose page went to a client through `FS_READ_MEMORY` is reused only once `SYS_CAP_INFO`'s mappings
  count shows the cache's own mapping alone. A page a client still maps is quarantined, and the slot
  gets a replacement page. The cache takes at most 32 pages beyond its slots for replacements, past
  which a still-mapped slot stays out of service (`src/cache.rs` module docs; [fs-driver-protocol.md
  § Label 8](../../docs/fs-driver-protocol.md#label-8-fs_release_memory)).
* **NodeTable** (`src/backend.rs`): dedupes by on-disk slot
  `(sector_lba, offset_in_sector)`; two distinct on-disk entries
  always allocate distinct `NodeId`s, even when both are empty files
  at cluster 0. The table is a heap-grown `fat_parse::node_slab::NodeSlab`:
  a `NodeId` packs a 24-bit index and a 16-bit generation, and every holder
  of an entry shares its one node. `FS_CLOSE` frees no node, since the
  driver cannot tell which holder a close comes from; `FS_REMOVE` and
  `FS_RENAME` free the unlinked slot's node, and its open-file slot with
  it. A freed index is reused under the next generation and retired when
  the generation would wrap, so a stale cap names no node.
* **Open-file table** (`src/file.rs`): one slot per node read through
  `FS_READ_MEMORY`, grown on demand and reused once closed; each slot's
  outstanding-page table grows up to the cache's slot count.
* **Eviction worker** (`src/eviction.rs`): the read-side cooperative release. It sends
  `FS_RELEASE_MEMORY`, waits up to 100 ms for the ack, then revokes the page's caps and drops the
  slot. The send runs on a watchdog thread, which a client that never replies leaves blocked; with
  `MAX_WATCHDOGS` (4) such threads alive, the worker revokes without sending. Reuse of the slot is
  then subject to the page cache's mapping check above. Outstanding write paths return their caps
  before reply, so they create no eviction pressure.

---

## Summarized By

[services/fs/fat/README.md](../README.md)
