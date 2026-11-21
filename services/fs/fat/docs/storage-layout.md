# fs-fat storage layout

How `services/fs/fat` lays out its storage engine: the cluster allocator, directory mutation, the
page cache, the node table, the opens and sessions, and the eviction worker. The wire surface is
specified in [fs-driver-protocol.md](../../docs/fs-driver-protocol.md), and the write ordering of
each mutation in [crash-safety.md](crash-safety.md).

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
* **Page cache** (`src/cache.rs`): up to its slot ceiling of single-page slots, fixed at init from
  the RAM memmgr reports (`QUERY_POOL_STATUS`): one slot per `SLOT_RAM_DIVISOR` (512) pages of RAM,
  never fewer than `SLOT_COUNT` (256; `fat_parse::slot_ceiling`). A miss fills its slot with one
  `BLK_READ_INTO_MEMORY` of the page, except an `FS_READ_MEMORY` miss on a sequential scan (the
  read starts where the open's last one ended, or at 0 on a fresh open), which fills a run: one
  `BLK_READ_INTO_MEMORY` of up to `fat_parse::RUN_PAGES` (16) pages from the read's page, bounded
  by the clusters the file's chain holds at consecutive numbers from the read's cluster, by the
  file's end, and by the first page already cached, each page then copied into a slot of its own.
  Each block request pays a fixed cost (devmgr's DMA mapping and unmapping for the driver, the
  interrupt, the IPC round trips), which a run pays once; the copy is the price, since the slots
  are separate pages that the cache gives back to memmgr one by one. A run read the device refuses
  falls back to the page's own fill. Runs land in a process-static run buffer of `RUN_PAGES`
  contiguous pages, which memmgr may refuse at init (no run fills then), and a run read whose
  reply loses its cap ends run fills for the mount. A separate process-static scratch page serves
  single-sector `BLK_WRITE_FROM_MEMORY` writebacks and single-sector device reads, so no data
  read puts them at risk. A sector is one logical block of the device, whose size `FS_MOUNT` reads
  with `BLK_GET_GEOMETRY` before the BPB; a page holds `PAGE_SIZE` over it. A slot takes its page
  from memmgr when a miss finds no slot that holds a page and no sector run, and the cache evicts
  only once every slot holds a page or memmgr refuses one, so an idle mount pays only for the pages
  it fills. When memmgr's memory-pressure level turns `Low` or `Critical`, a pressure thread, which
  waits on the runtime's pressure Notification, wakes the dispatch loop with an unbadged call on the
  service endpoint, and the loop gives memmgr back every page no reference holds and no client maps,
  after the mapping check below for a page that went to a client, but the `RELEASE_KEEP` (4) most
  recently used, which a miss evicts when memmgr refuses a page, as at `Critical`; it gives back
  every spare page of the quarantine and every page a failed fill left without a cap, too, and the
  slots take pages again on demand. An open holds at most the slot ceiling of outstanding
  `FS_READ_MEMORY` pages. Cache init funds the fs's own `CSpace` with general headroom for every
  slot page, the quarantine's replacements, a per-read ancestor cap for every slot (each outstanding
  page holds one), the scratch page, the run buffer, and 64 more
  (`std::os::seraph::fund_cspace_slot_budget`), so growing the cache, or holding every slot
  outstanding, never meets an exhausted `CSpace`; a failed funding fails cache init. Before it
  records an open's release SEND, and an unpaid open's liveness cap, each `FS_OPEN` (and each
  `FS_SESSION`) tops the `CSpace` up so the same
  funding stays free, less the slot pages, scratch page and run buffer the cache already holds, so
  the opens' caps grow it rather than starve reads. Write-through: the cached page is updated in
  place before the on-disk write so any outstanding `FS_READ_MEMORY` cap aliasing the page observes
  new bytes immediately, and the sector is put back when the write fails. `reload_sector` reads one
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
  of an entry shares its one node. `FS_CLOSE` frees an open, never a
  node; `FS_REMOVE` and `FS_RENAME` free the unlinked slot's node, and
  every open of it with it. A freed index is reused under the next
  generation and retired when the generation would wrap, so a stale cap
  names no node.
* **Open table** (`src/file.rs`): one `OpenFile` per `FS_OPEN` made
  without a session, the unpaid path, in a heap-grown
  `fat_parse::open_slab::OpenSlab` whose generation-checked id is the open
  cap's badge; at most 2^24 - 1 live unpaid opens, with no per-client bound.
  Each holds its own release SEND, the parent of its liveness cap, and an
  outstanding-page table that grows up to the cache's slot count. An open of
  either kind also keeps the offset its next
  sequential `FS_READ_MEMORY` takes (the page cache's run fills key on
  it) and a cursor into the file's cluster chain, `fat_parse::ChainCursor`:
  the cluster index and cluster its last `FS_READ_MEMORY` reached, so the
  next one walks on from there instead of from the chain's head
  (`fat_parse::walk_start`). A cursor serves only a read at or past it
  on the same first cluster and in the same chain epoch, a counter
  (`FatState::chain_epoch`) that every FAT entry write moves, so no
  cursor outlives a change to a link it passed. A sweep on the schedule
  `fat_parse::open_slab::SweepSchedule` sets releases the unpaid opens whose
  liveness cap has no copy left outside the driver
  ([fs-driver-protocol.md § Label 18](../../docs/fs-driver-protocol.md#label-18-fs_open)).
* **Sessions** (`src/session.rs`, `src/file.rs`): the records of each
  session and of the opens made in it live in pages charged to the node of
  the session's charge-only handle, in a `fat_parse::session_pool::SessionPool`
  (its module docs give the layout). Each page is a one-page grant memmgr
  charges to that node (`REQUEST_CHARGE_NODE`), mapped writable into a
  window of the driver's address space reserved at start for as many pages
  as the machine has RAM; a session takes its first page at `FS_SESSION`
  and holds it for its life, and further ones as its opens and their held
  pages need them, each given back with `RELEASE_MEMORY_CAPS` when its last
  record goes. An open in a session holds its release SEND and its
  outstanding pages like an unpaid one, its records in the session's pages,
  and no liveness cap of its own: the session's liveness cap keeps all its
  opens. Session and session-open ids come from one 54-bit counter that never
  repeats, indexed through a table of chain heads on the driver's heap that
  doubles and halves with the live records. A donation-end thread waits on
  the Notification registered with memmgr (`REGISTER_DONATION_END`) and has
  the dispatch loop sweep the sessions; `FS_SESSION` and `FS_UNMOUNT` sweep
  them too
  ([fs-driver-protocol.md § Label 23](../../docs/fs-driver-protocol.md#label-23-fs_session)).
* **Eviction worker** (`src/eviction.rs`): the read-side cooperative release. It sends
  `FS_RELEASE_MEMORY`, waits up to 100 ms for the ack, then revokes the page's caps and drops the
  slot. The send runs on a watchdog thread, which a client that never replies leaves blocked; with
  `MAX_WATCHDOGS` (4) such threads alive, the worker revokes without sending. Reuse of the slot is
  then subject to the page cache's mapping check above. Outstanding write paths return their caps
  before reply, so they create no eviction pressure.

---

## Summarized By

[services/fs/fat/README.md](../README.md)
