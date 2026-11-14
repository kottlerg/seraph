# memmgr Memory Pool

Authoritative specification of memmgr's memory-cap pool: how memmgr
ingests memory caps at boot, how it allocates them, how it tracks per-process
ownership, how it reclaims on process death, and how it coalesces freed
runs to sustain contiguous-allocation success.

---

## Pool Ingest

memmgr receives the userspace RAM memory-cap pool from init at boot. The
kernel populates init's CSpace with one Memory capability per contiguous
usable physical-RAM extent: it coalesces physically-adjacent drained buddy
blocks before minting, so the cap count tracks memory-map fragmentation, not
total RAM (see
[`docs/capability-model.md`](../../../docs/capability-model.md) §"Initial
Capability Distribution" and
[`docs/userspace-memory-model.md`](../../../docs/userspace-memory-model.md#ownership-boundaries)
§"Ownership Boundaries"). Memory cap sizes vary — they reflect the firmware
memory map and may span many MiB each. Init moves the RAM caps left after its
own bootstrap allocations into memmgr's CSpace (every one while memmgr's CSpace
keeps the headroom init reserves in it), so from the handover memmgr's slot is
the only one naming each run, which the kernel requires of a run memmgr splits
or merges (see
[`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_memory_split-33)
§"`SYS_MEMORY_SPLIT`"). The phys-table page is one of these runs: memmgr reads it
through the read-only derivation the bootstrap round carries, and once memmgr
deletes that derivation the page is a splittable run like any other. Init forwards
the memmgr/procmgr/init bootstrap arenas as in-use runs, and transfers the slot
range `(memory_base, memory_count)` to memmgr in its bootstrap IPC round; any
RAM caps init did not forward join the pool through the init-reap donation
below (see
[`docs/process-lifecycle.md`](../../../docs/process-lifecycle.md#init--memmgr)
§"Init → memmgr"). memmgr reads each ingested cap's size and physical base
from the kernel (`cap_info`), as it does for a donation, so the round bounds
neither the cap count nor a cap's size; a run's page count is a `u64`.

memmgr does not split the ingested memory caps eagerly. The free pool retains
each ingested cap at its native size; splitting happens on the
allocation path via `memory_split`, and coalescing reverses the split on
the free path.

Beyond the bootstrap pool, memmgr also receives RAM at init's reap
(`DONATE_MEMORY_CAPS`: RAM caps beyond the bootstrap round, init's
`MemoryAlloc` leftovers, init's ELF segments, InitInfo, stack, boot-module ELF
sources, reclaim scratch, AP trampoline; see
[`services/init/docs/bootstrap.md`](../../init/docs/bootstrap.md#handover)
§"Handover"). Both entry points feed the same free
pool, so every pool frame is uniform anonymous RAM: a consumer may map any of
it read-only, read-write, or read-execute (W^X still enforced at map time).
This requires each pool frame's Memory cap to carry **WRITE, EXECUTE,
RETYPE, and PHYS** rights — memmgr derives the R/RW/RX inner from the pooled
outer on demand and `cap_derive` only narrows rights, so a frame whose outer
lacks WRITE (or EXECUTE) cannot satisfy a writable (or executable) map and would
fail the consumer's fault, and PHYS lets memmgr read each run's physical base,
the right it strips from every grant but a phys-class caller's (see
[Allocation](#allocation)). The kernel mints every donatable RAM cap with these
rights; rights gate derivation, not the live mapping (see
[`docs/capability-model.md`](../../../docs/capability-model.md#memory) §"Memory");
memmgr enforces the invariant at
both ingest and donation, rejecting a donated frame that lacks them and panicking if the first
bootstrap cap lacks them (the kernel mints the bootstrap batch uniformly, so
one cap is sufficient), so a mint-rights regression fails loudly rather than
surfacing as an intermittent consumer fault.

---

## Free-Pool Data Structure

Each free run (a Memory cap, its page count, and its physical base) is a node
in the metadata arena (below), linked on one list sorted by physical base. The
run count is therefore bounded by RAM, not by a constant: no run is turned
away for want of a slot, short of the arena being unable to grow with its
reserve spent. The pool keeps running totals of its free pages and runs.
Selection walks the list:

- **Smallest fit.** The smallest run covering at least `N` pages serves a
  `REQUIRE_CONTIGUOUS` request and the single-run case of best-effort
  allocation.
- **Largest run.** Best-effort allocation falls back to repeatedly taking the
  largest run when no single run is large enough, and a demand fault to
  taking it once, whole (see [Demand faults](#demand-faults)).

Taking a whole run frees its node; splitting one keeps the node for the
remainder, whose sorted position does not change. Returning a run inserts it
at its sorted position. A reclaimed frame's descriptor node is rewritten into
the run's node in place, so reclamation never allocates and cannot fail. When
the arena has no free node outside its reserve (below) and the pool cannot
fund an arena page, the returned run funds it itself: its first page (all of
it, for a one-page run) becomes the arena page. When that carve fails (both
arena zones are spent, the split of its first page fails, or the page cannot
be mapped because memmgr's page tables cannot be funded), the run takes a
reserved node; when the split of its first page cannot be merged back, the
remainder takes the reserved node before the head page. A run a growth path
takes from the pool and cannot use goes back without growing the arena: merged
back into the remainder its split left, else into a free node, the reserve
included. A run stays owned and counted in `pool_total` but out of circulation
only when it reaches the reserve with the reserve already spent and the arena
unable to grow.

---

## Allocation

`REQUEST_MEMORY_CAPS(want_pages, flags)`:

1. **`REQUIRE_CONTIGUOUS` set.** Select the smallest run that covers
   `want_pages`. On hit: detach the run, split off exactly `want_pages` via
   `memory_split` if the run is larger than requested, return one Memory
   cap. On miss, or if the split fails: return `OUT_OF_MEMORY_CONTIGUOUS`.
   memmgr does not migrate live pages to produce a contiguous run;
   coalescing is the only mechanism that restores contiguity.
2. **Best-effort.** First try a single best-fit run — the smallest run
   that covers `want_pages` whole. One run is the fewest possible caps,
   and best-fit reuses a freed run of the requested size instead of
   re-splitting a larger one, so a workload that repeatedly frees and
   re-requests a fixed size (e.g. ruststd's per-thread Thread-retype slab)
   cycles the same run — and the same tracking anchor — rather than minting
   a fresh anchor each request. Only when no single run is large enough,
   fall back, when the pool's free pages cover `want_pages`, to taking runs
   largest first, at most as many as the IPC reply-side cap-slot limit
   allows. When those runs cover less than `want_pages`, the reply is a
   **partial grant**: success with fewer pages, which the caller requests
   again for the remainder (the RAM exists, spread over more runs than one
   reply carries). When the free pages do not cover `want_pages`, return
   `OUT_OF_MEMORY_BEST_EFFORT`. The same code is returned if deriving the
   caller's copy of a selected cap fails. A failure of pool selection carries
   three diagnostic data words (total free pages, free-run count, and the
   largest run in pages); a failure to derive the caller's copy carries none.

A selection that fails, contiguous or best-effort, first rechecks the deferred
list (see [Reclamation](#reclamation)) and, when a run moved to the pool,
selects once more before memmgr returns the out-of-memory code.

Each Memory cap returned to the caller is a derive-twice copy: memmgr
retains an intermediary in its own CSpace and hands the second derivation
to the caller. The intermediary lets memmgr reclaim the cap on
`PROCESS_DIED` even if the caller's CSpace has been torn down. The second
derivation passes every right but `RIGHTS_MEM_PHYS`, which it passes only to
a caller whose badge marks it phys-class (devmgr and the IOMMU drivers; see
[`ipc-interface.md`](ipc-interface.md#label-3-register_process) § Label 3), so
no other caller can read where its frames lie. Each grant run is recorded on
the caller's entry under the next id of the entry's region-id sequence, which
the reply returns in place of a physical address and `RELEASE_MEMORY_CAPS`
takes back (see [Per-Process Tracking](#per-process-tracking)).

---

## Frame contents

Every page memmgr hands out reads zero: each run of a `REQUEST_MEMORY_CAPS` grant, and each run a
demand fault maps (see [Demand faults](#demand-faults)). A pooled run can hold what its last owner
wrote, and what the kernel left in it: a reclaimed frame keeps the bytes of the objects that were
retyped from it, since the kernel credits a dead object's bytes back to its Memory object without
clearing them. memmgr does not rely on any path that returns a run to the pool to clear it, so it
clears each run once, at hand-out, after selection and before the run is accounted, derived, or
mapped into the process.

memmgr maps the run read-write into its own address space through a scrub window of 512 pages
(2 MiB, the span of one leaf page table, at a base aligned to it), zeroes it, and unmaps it again,
one window at a time for a larger run. A plain unmap keeps the window's page table, so only the
first scrub funds page tables, from the free pool as every map into memmgr's own address space
does ([Metadata Arena](#metadata-arena)). The window holds a run only while memmgr clears it, and
no other process can read memmgr's address space.

When a run cannot be mapped into the window, memmgr unmaps whatever part the failed map left
mapped and keeps the run: a grant goes back to the pool whole and the request fails with `QUOTA`,
and a demand fault's run goes back to the pool and the fault is declined with code 9
([`ipc-interface.md`](ipc-interface.md) § Kernel-origin fault message).

The clearing costs one map, one pass of stores over the run, and one unmap per hand-out. svctest's
`demand_fault_cost` phase reports the mean cost of a 16-page demand fault, the measure of a change
to that work.

---

## Per-Process Tracking

memmgr maintains a per-process table keyed on the per-process badge memmgr
mints at procmgr's `REGISTER_PROCESS` and that is delivered with every
`REQUEST_MEMORY_CAPS` call. procmgr's own record is keyed on the bootstrap
badge init mints for it, and two reserved records (memmgr-self and init-self)
hold the memmgr and init bootstrap arenas; memmgr inserts all three at boot
and never reclaims them. Each entry records:

- The badge (process identity).
- The head of an intrusive list of the Memory cap slots memmgr has handed
  to this process, cumulatively, since `REGISTER_PROCESS`, other than the
  runs that back its demand regions: its grants, the page-table runs memmgr
  donated to its address space, and, for a reserved record, the bootstrap
  arenas.
- The head of an intrusive list of the demand-paged regions the process has
  registered (`REGISTER_REGION`), each with its chunk table, which holds the
  runs that back the region ([Chunk table](#chunk-table)).
- The delegated child `AddressSpace` cap, when demand-paged.
- The next region id: a sequence from 1 that numbers the process's grants.
  Each grant's frame node keeps its id, which no later grant of the process
  reuses; bootstrap arenas and demand-fault runs carry none.

The frame, region, and chunk-table nodes live in a self-hosted metadata arena (below),
not in the record, so per-process frame and region counts are bounded by RAM —
not by a fixed constant. The arena is what makes the demand-paged thread-stack
consumer (one region plus many lazily-grown frames per thread) viable: a fixed
per-process array would cap thread count at a small constant. Allocation fails
only when the arena cannot grow because system RAM is exhausted, surfaced as
`QUOTA`.

Each record is itself an arena node, so the number of tracked processes is
bounded by RAM, not by a constant. Records are found by badge through a
linear-hash index: a bucket array of arena indices, in its own window of
memmgr's address space, that grows one page of buckets at a time from the pool.
Linear hashing splits one bucket per step once the mean chain length passes
two, so the array only ever appends and lookup stays constant-time on average;
when the window is spent, buckets stop splitting and chains lengthen, which
costs lookup time and bounds no capacity. The window's base is fixed, not
drawn per boot like the arena's: the array holds only arena indices. `REGISTER_PROCESS` returns
`TOO_MANY_PROCESSES` only when the record's node cannot be allocated: system
RAM is exhausted.

---

## Demand faults

A demand-paged region is backed in chunks of `DEMAND_CHUNK_PAGES` (16) pages, aligned to the
region's base and clamped to its end. On a fault in a region, memmgr backs the part of the
faulting page's chunk that no earlier run backs: the largest span of the chunk that holds the
faulting page and no page of a run memmgr mapped before, which it reads from the chunk's entry in
the region's chunk table ([Chunk table](#chunk-table)). On a pool with a free run that covers the
span, that is the whole chunk on its first fault, backed by one run.

memmgr first selects a run covering the span, as a `REQUIRE_CONTIGUOUS` request would, with the
deferred recheck before it fails (see [Reclamation](#reclamation)). When no free run covers the
span, it takes the largest free run whole, which needs no split, and maps it over the part of the
span around the faulting page: from the faulting page up, moved down only as far as needed to stay
inside the span. A later fault on a page of the span the run did not cover is backed the same way,
so the chunk fills in parts, each part one run and one frame record. A fault is therefore declined
for want of RAM (code 7, [`ipc-interface.md`](ipc-interface.md) § Kernel-origin fault message)
only when the free pool holds no page, or when the split of a run larger than the span fails.

Each run is zeroed before it is mapped ([Frame contents](#frame-contents)), mapped with the
region's protection, and recorded on its chunk's entry with its mapped VA and no region id, so
`UNREGISTER_REGION` unmaps and reclaims it and `PROCESS_DIED` reclaims it (see
[Reclamation](#reclamation)). The pages move from a free run to the process, so `pool_total` is
unchanged.

---

## Chunk table

Each demand region carries a chunk table with one entry for each chunk a fault has backed. An
entry records:

- The backed mask: one bit per page of the chunk, set when a run backs the page.
- The chunk's state: unbacked; resident, its pages backed by the runs on the entry's run list and
  mapped in the process; evicting; or swapped.
- A pin flag and a two-bit age.
- A link: the head of the chunk's run list while it is resident or evicting, the handle of its
  stored pages while it is swapped.

The evicting and swapped states, the pin flag, and the age are the swap path's: memmgr reclaiming
a cold chunk's runs under memory pressure and storing its pages, a fault restoring them. That path
is design intent; not yet implemented ([#230](https://github.com/kottlerg/seraph/issues/230)).
Today nothing evicts a chunk, so a fault finds its chunk unbacked or resident.

The table is a radix tree of [Metadata Arena](#metadata-arena) slots rooted in the region's node.
A directory node holds `DIR_FANOUT` (5) children: the slot indices that fit in the slot's largest
payload, so a directory node does not enlarge the slot. A leaf holds one chunk's entry. The tree is
indexed by the chunk's index in the region, its offset from the region's base in chunks, one
base-5 digit per level. Its height is fixed by the region's chunk count, as the fewest directory
levels that give every chunk a leaf: none for a region of one chunk, seven for a region of 2^14
chunks (1 GiB), eighteen for one that fills a 57-bit address space's user half. A node exists only
on the path to a chunk that has an entry. The table therefore costs slots in proportion to the
chunks the process touched, at most one more than the height per chunk, not in proportion to the
VA it registered.

A fault reads the region's node and the chunk's path through the table, the height plus two slots,
whatever runs the process or the region holds. Recording a run takes a slot for its descriptor
and one for each node of the chunk's path that does not exist yet. memmgr secures those slots
before it selects the run, holds them through any page-table funding the map needs, and records
the run only once the map has succeeded: the descriptor goes onto the chunk's run list, its pages
into the mask, and any missing node of the path into the tree, all in one step. A declined fault
leaves the entry as it was.

`UNREGISTER_REGION` and `PROCESS_DIED` free a region's table with a walk that keeps its pending
nodes on a stack threaded through their own `next` links, which no table node uses otherwise. The
walk needs no memory and no recursion. It rewrites each run's descriptor into a run node in place,
which joins the free pool or the deferred list as any reclaimed frame does (see
[Reclamation](#reclamation)), and returns every directory and leaf node to the arena's free list.

---

## Client page-table funding

memmgr maps a demand-fault run ([Demand faults](#demand-faults)) into the faulting process's
address space, and the kernel takes the page tables that map needs from that address space's own
page-table growth pool
([docs/capability-model.md](../../../docs/capability-model.md) § Address-space and CSpace growth
budgets). The pool is shared by every mapping in the address space, the process's own and the
pager's. A process that funds the pool before it registers a region (ruststd's
`fund_aspace_pt_budget`) cannot reserve that funding for the region: any later mapping may draw it
first. So memmgr does not depend on it. When the map of a run fails with `OutOfMemory`, memmgr
funds the pool itself and maps the run again, at most four times:

1. It selects a contiguous run of four pages from the free pool, or of two when no four-page run
   is free. A donation can keep one page for the kernel's donation bookkeeping, so it never
   donates a single page.
2. It records the run on the process's entry like a grant it did not map: no mapped VA and no
   region id. No `RELEASE_MEMORY_CAPS` or `UNREGISTER_REGION` can take it back.
3. It donates the run to the pool with augment-mode `cap_create_aspace` on the delegated
   `AddressSpace` cap, and keeps its own cap to the run as the reclaim anchor. When the kernel
   refuses the donation, memmgr takes the record back and returns the run to the free pool.

The donated pages stay in the address space until it is destroyed, and `PROCESS_DIED` reclaims
them with the process's other frames. The address space's teardown releases the donation, so the
run is quiescent by then, or waits on the deferred list until it is (see
[Reclamation](#reclamation)). The pages move from a free run to the process's entry, so
`pool_total` is unchanged.

A fault whose map still fails, because the free pool cannot fund the pool or the map fails for
another reason, is declined with code 9 ([`ipc-interface.md`](ipc-interface.md) § Kernel-origin
fault message). A failed map can leave the first pages of the run mapped. memmgr unmaps the
run's span before it returns the run to the free pool, so no page of a pooled run stays
mapped in the process. When that unmap fails, the run stays recorded on the process's entry
until `PROCESS_DIED`.

---

## Metadata Arena

All of memmgr's bookkeeping — free runs, deferred runs, process records,
per-process frame and region descriptors, and the regions' chunk tables — is
nodes drawn from a self-hosted arena rather than fixed `.bss` arrays. memmgr
is `no_std` and cannot bootstrap
a general heap against itself, but it *can* host fixed-size nodes in pages
carved from its own pool:

- Nodes are fixed-size `Slot`s (a tagged run, process, region, frame,
  chunk-directory, chunk, or free payload plus a `next` index) reached by a
  `u64` index, so the index never bounds the
  arena before the address space does.
- A free list threads the unused slots. Allocation pops the head; free pushes
  it back.
- The last `ARENA_RETURN_RESERVE` (1) free slot is held back from every
  allocation except a last-resort return of a run to the pool (above), so
  every other allocation sees the arena as full while that slot is still free,
  and the arena grows first.
- When no slot outside the reserve is free, memmgr pulls one frame from the pool
  (contiguous, one page), maps it at the next arena page in its own address
  space, and carves it into free slots. When the pool itself is empty (the
  first ingest, before it holds anything), the run being inserted funds the
  page (see [Free-Pool Data Structure](#free-pool-data-structure)).

Arena pages lie in two zones of memmgr's address space. The low zone runs from
a per-boot drawn base (ASLR) up to the lowest bootstrap window
`shared/process-layout` draws, past the std heap and reservation-arena zones,
which memmgr, having no std runtime, does not use. The high zone continues
above the shared 2^38 layout ceiling and exists only where the boot's paging
mode has a wider user half (x86-64 4- or 5-level paging, Sv48, Sv57); under Sv39 the
kernel refuses the map and the arena ends with the low zone, which outlasts any
RAM such a machine holds. Growth stops when neither zone has a page left or RAM
is exhausted, surfaced as `QUOTA`.

Each arena or index page memmgr maps can need new page-table pages in its own
`AddressSpace`, whose page-table pool init seeds at creation. When the kernel
reports that pool exhausted, memmgr funds it from its own free pool: it donates
a contiguous run of `ASPACE_TOPUP_PAGES` (4) frames, or two when no such run is
free, with augment-mode `cap_create_aspace` against its own `AddressSpace`,
deletes the frame's cap (the donation holds its own reference), and retries the
map. Like arena pages, donated frames leave the free pool for good and stay in
`pool_total` as memmgr-owned metadata.

The arena only grows, and a page once carved is permanent memmgr-owned metadata.
This preserves the all-RAM-accounted identity: the page was counted in
`pool_total` at ingest and is never returned, exactly like an in-use bootstrap
arena. Growth stops at the peak concurrent node count — freed nodes return to
the arena's own free list and are reused — so spawn/grow/die churn leaks no
pages. Refilling the free list can draw a pool frame and map it from inside a
fault handler; this is bounded (one frame, plus its page-table funding, plus at
most one deferred recheck per turn of the receive loop when a selection fails;
see [Reclamation](#reclamation)), with no recursion into per-process
accounting, and never breaks the identity.

---

## Concurrency

memmgr is single-threaded today: one receive loop owns all bookkeeping. The
bookkeeping is shaped so the SMP pager
([#266](https://github.com/kottlerg/seraph/issues/266)), over per-thread IPC
buffers ([IPC Design](../../../docs/ipc-design.md) § Multi-threaded servers),
is a service-internal change rather than a rewrite of this layer:

- The arena, the free pool, the deferred list, and the process index are
  plain values with no global state, mutated only through exclusive
  references, and held together in one ledger; every growth path that needs a
  syscall sits outside them.
- Several ledgers can coexist, each with its own arena and free pool, so a
  pool shard per CPU or NUMA node is one ledger per shard.

The sharded pager is design intent; not yet implemented. Its intended rules:
each shard's ledger sits behind its own lock, taken for one request and never
held across an IPC; a request that needs a second shard (a refill from a
neighbour, or a record whose frames came from several shards) takes shard
locks in ascending shard order; and the all-RAM-accounted identity is the sum
over shards, with `pool_total` kept in one counter updated under any shard's
lock with an atomic add.

memmgr cannot use the worker-pool receive helper
([shared/recv-pool/README.md](../../../shared/recv-pool/README.md)), which spawns
`std` threads: memmgr is `no_std`. Its receive threads are design intent; not yet
implemented. memmgr would create each with the raw thread syscalls, register a
page of its own for each with `SYS_IPC_BUFFER_SET`, and keep the rules of
[IPC Design](../../../docs/ipc-design.md) § Multi-threaded servers in its own
code; how the threads share the ledgers is the sharding above.

---

## CSpace headroom

memmgr's own `CSpace` takes a slot for every frame split and inner derivation a grant makes, and
each split's tail body a 128-byte chunk of its body arena, which takes whole pages from the same
growth budget (core/kernel/docs/capability-internals.md § Body Arena), so a burst of requests draws
both fast. A `CSpace` keeps its last `CSPACE_IPC_RECV_RESERVE` free
slots for IPC capability transfer, so general allocations fail before receives do
([docs/capability-model.md](../../../docs/capability-model.md) § Address-space and CSpace growth
budgets). memmgr cannot request memory from anyone else, so it funds its own slot-page pool:

- Before every receive, memmgr reads its headroom (`CAP_INFO_CSPACE_CAPACITY` less
  `CAP_INFO_CSPACE_USED` and the reserve) and its growth budget (`CAP_INFO_CSPACE_BUDGET`).
- When the headroom falls below `CSPACE_LOW_WATER` (256 slots) plus a page, or the budget below a
  page, so a split could not carve an arena page (`syscall_abi::cspace_topup_pages`), it pulls a
  contiguous run of `CSPACE_TOPUP_PAGES` (16) frames from the pool, or a single frame when no such
  run is free, and donates it with augment-mode `cap_create_cspace` against its own `CSpace` cap. It
  then deletes the frame's cap: the donation holds its own reference on the frame.
- A refused donation returns the frame to the pool, and the check runs again before the next
  receive.

Like arena pages, donated frames leave the free pool for good and stay in `pool_total` as
memmgr-owned metadata, so the all-RAM-accounted identity is unaffected.

---

## Reclamation

Reclamation takes frames back from a process and returns each one to the free pool only when no
other process can still reach it. A frame reclaimed from one process can still be reachable from
another in three ways:

- **A kernel object retyped from it is alive.** An object's bytes return to its source Memory
  object only when the object's last reference goes
  ([`docs/capability-model.md`](../../../docs/capability-model.md#auto-reclaim) §"Auto-reclaim"),
  and a capability another process holds is such a reference: an endpoint a dead process created
  lives on while a server keeps a SEND to it. The live object sits below the region's retype bump
  cursor, so a pooled run would be grantable only whole and unmappable below the cursor.
- **Another address space maps it.** A user mapping outlives the revocation of the capability it
  was made through ([`docs/capability-model.md`](../../../docs/capability-model.md#memory)
  §"Memory"), so a process that still maps a frame keeps reading and writing it whoever owns it
  next.
- **Another process holds a Memory capability to it.** A capability the grantee moved to another
  process stays a derivation child of memmgr's intermediary, and one the grantee derived and handed
  out becomes a derivation root when the grantee's `CSpace` is torn down; either way its holder can
  map the frame after memmgr grants it again, or a driver holding it for a transfer can have its
  device still writing it.

memmgr therefore checks each reclaimed frame through its retained intermediary, which shares the
Memory object of every derivation it granted. The frame is **quiescent** when all four hold:

1. The intermediary is the only reference to that Memory object (`CAP_INFO_SOLE_REFERENCE`): no
   other capability to it in any `CSpace`, moved, derived, or orphaned into a derivation root, and
   no kernel-internal reference such as a retype lease or a page-pool donation. memmgr reads this
   first: once it holds it keeps holding, since no other process has a capability through which to
   add a reference or a mapping, so the reads after it cannot be raced.
2. The intermediary's size (`CAP_INFO_MEMORY_SIZE`) still covers every page memmgr granted. The
   kernel refuses a grantee's split or merge of its grant, since memmgr's intermediary names the
   same object ([`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md)
   §"`SYS_MEMORY_SPLIT`" and §"`SYS_MEMORY_MERGE`"), so the size cannot change while memmgr holds
   the intermediary; memmgr reads it as a backstop.
3. Its available bytes (`CAP_INFO_MEMORY_AVAILABLE`) equal its size: no byte of the region is
   retyped into a live kernel object, donated to a page pool, or held by a kept body-arena page
   (the kernel credits the last such byte back and resets the region's retype allocator to virgin
   at the same point).
4. No address space maps any page of it (`CAP_INFO_MEMORY_MAPPINGS`, read window by window).

A query that fails answers no. A quiescent frame joins the free pool. Any other frame joins the
**deferred list**: its descriptor node is rewritten into a run node in place, as a pooled frame's
is, so reclamation still never allocates and cannot fail. A deferred run is owned by memmgr and
counted in `pool_total`, lent to no process, and never granted. Before every `PROCESS_DIED`,
`RELEASE_MEMORY_CAPS`, and `UNREGISTER_REGION`, and before any selection from the free pool fails (a
`REQUEST_MEMORY_CAPS` grant, a demand fault's run, or memmgr's own arena, index, page-table, or
`CSpace` growth), memmgr rechecks the deferred list, oldest run first: each run that has become
quiescent joins the free pool (and the failed selection runs once more), and each that has not goes
to the back of the list, so successive rechecks visit every run. Only the first of these in a turn
of the receive loop rechecks; later ones in the same turn find the recheck done. A turn starts when
a receive returns, with a message or with an error: it is the message's handling, if any, then the
`CSpace` top-up before the next receive. A handler's recheck at entry therefore always runs, and so
does the top-up's before a failed receive's retry, which is what refills a spent receive reserve.
One recheck checks at most `DEFERRED_RECHECK_BATCH` (64) runs and spends at most
`DEFERRED_RECHECK_WINDOWS` (256) mapping-count queries of up to 512 pages each, plus the rest of the
run that crosses that budget, after which it stops and leaves the runs behind at the head for the
next recheck. A turn's deferred kernel queries are therefore bounded by three per run checked plus
256, plus the windows of the largest deferred run. No timer drives it; a run that becomes quiescent
while no message arrives waits for the next one, or for the next retry of a failed receive. A run
whose reaching capability, object, or mapping never goes, held by a process that never drops it,
stays deferred for the rest of the boot, and `QUERY_POOL_STATUS` reports the deferred total (see
[`ipc-interface.md`](ipc-interface.md#label-6-query_pool_status) § Label 6).

memmgr does not revoke its intermediary's derivations before pooling: a revoke reaches neither a
derivation the grantee made and handed out, which its `CSpace`'s teardown leaves a derivation
root, nor any mapping already made, and it would drop the reference a driver holds on a frame its
device may still write. The frame waits instead, until its holder drops the capability.

On `PROCESS_DIED(badge)` from procmgr, which procmgr holds back for a started
`CREATE_DMA_HOLD` process until its creator releases it, the frames staying on
the record until then (see [`ipc-interface.md`](ipc-interface.md#label-4-process_died)
§ Label 4):

1. Recheck the deferred list.
2. Remove the per-process record from the index. If absent (untracked
   badge), skip to step 5 — the death notification is idempotent.
3. For each frame node in the record's frame list and on the run lists of
   its regions' chunk tables, rewrite the node into a run of the retained
   Memory cap and insert it into the free pool at its sorted position when
   the frame is quiescent, else onto the deferred list (no fresh node, so
   the step cannot fail).
4. Return every chunk-table node, every region node, and the record's own
   node to the arena free list.
5. Run coalescing across the newly-freed runs and their adjacent
   neighbours.

No unmap is performed: the dead process's CSpace is torn down by procmgr
(which revokes the AddressSpace cap; see
[`docs/capability-model.md`](../../../docs/capability-model.md) §"Kill
process pattern"), which already tore down the child's mappings. The
caller-side derivation copies of the Memory caps that stayed in the dead
process's CSpace are freed with it; a copy the process moved or derived into
another CSpace outlives it, and its reference keeps the frame on the deferred
list until it goes (check 1 above). memmgr's intermediary copies remain valid
and are what the free-pool insertion uses.

`RELEASE_MEMORY_CAPS` from a live process is the mid-life counterpart for a
caller-owned grant. The caller usually cannot transfer the cap back — having
retyped the region (e.g. into a Thread) and dropped its inner copy, it no
longer holds one — so it names each region by the region id memmgr reported
at grant. memmgr matches that id against the entry's frame list (grants only;
demand-fault runs, which carry no id and sit in their region's chunk table,
are reclaimed by `UNREGISTER_REGION`), takes the frame off the record, returns it to the pool
when it is quiescent and to the deferred list otherwise (the node becomes
the run's node in either case), and coalesces the freed runs with their
physical neighbours, leaving the entry's other records untouched. Unmatched
ids are ignored, so release is idempotent (a racing join-plus-reaper
double-release is harmless), and an id the entry never reissues cannot take a
later grant of the same run. The caller must have deleted every capability
to the region and every object retyped from it, and unmapped it, first; a
region released while any of them remains waits on the deferred list until
all are gone, so no other process reaches a pooled run and its next grantee
can always split it, map it whole, and retype it.

`UNREGISTER_REGION` from a live process is the mid-life counterpart for a
demand-paged region: memmgr finds the region node and **actively unmaps** the
whole region span from the delegated child `AddressSpace` in one
`mem_unmap_reclaim` call, which also returns the emptied page tables to that
address space's page-table budget (the process is still alive, so the mappings
must be removed before the frames return to the pool). It then removes the
region node and frees its chunk table ([Chunk table](#chunk-table)), returning
each backing run's cap to the pool, or to the deferred list when the run is not
quiescent (each descriptor node becoming its run's node), and coalesces the
freed runs with their physical neighbours. The entry's frame list, which holds
the frames the caller mapped itself, is left untouched. This is the reclamation
path the ruststd guarded-stack consumer uses on `join()`.

---

## Coalescing

Coalescing is a reverse-`memory_split`: two adjacent free Memory caps
covering physically-contiguous page ranges are merged into one larger
cap. Eligibility:

- Both caps are present in the free pool.
- The physical-base addresses are adjacent (`base_a + size_a == base_b`).
- The kernel's `memory_merge` accepts the operation (see
  [`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_memory_merge-50)
  §"`SYS_MEMORY_MERGE`"): the caps must be derivation siblings with identical
  rights, the tail must be virgin (never retyped or sub-allocated), and no
  other slot may name either cap's object (no derivation or copy of either
  object, linked to it or not).

Coalescing runs explicitly after every reclamation — `PROCESS_DIED`,
`RELEASE_MEMORY_CAPS`, and `UNREGISTER_REGION` alike — so a freed run rejoins
its physical neighbours immediately rather than staying discrete. Together
with best-fit best-effort selection (above), this bounds the pool's run count
under long spawn/free/die churn, and with it the per-run tracking anchor
memmgr holds in its own CSpace: best-fit keeps a fixed-size churn cycling one
run, and the explicit merge keeps residual fragmentation from drifting the run
(and anchor) count up over time. Left un-coalesced, reclaimed runs stay
discrete and their anchors persist, slowly consuming memmgr's CSpace and arena
even while its RAM footprint stays bounded. A reclaimed run whose source
`MemoryObject` still holds a live retype would decline `memory_merge` (the
kernel requires a virgin tail; see
[`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_memory_merge-50)
§"`SYS_MEMORY_MERGE`"), but such a run waits on the deferred list, not in the
pool (see [Reclamation](#reclamation)), so every pooled run is virgin.
Coalescing cost scales with the live run count, which best-fit and this pass
jointly keep small, so the per-reclamation merge is negligible.

The free-run list is sorted by physical base, so mergeable runs are list
neighbours: memmgr attempts `memory_merge` on each pair of physically adjacent
neighbours (`base_a + size_a == base_b`) and skips every other pair without a
syscall; the kernel declines any attempted pair that fails the remaining
preconditions above. A declined pair stays as two discrete runs.

---

## Failure Modes

| Failure | Cause | Caller observation |
|---|---|---|
| `OUT_OF_MEMORY_CONTIGUOUS` | No free run satisfies `REQUIRE_CONTIGUOUS` | Reply with error label; caller may retry without the flag, or fail |
| `OUT_OF_MEMORY_BEST_EFFORT` | The pool's free pages do not cover `want_pages` | Reply with error label; caller treats as system-wide RAM exhaustion |
| `QUOTA` | Tracking-metadata arena could not grow, or a selected run could not be mapped to zero it ([Frame contents](#frame-contents)); either means system RAM exhausted | Reply with error label; caller treats as system-wide RAM exhaustion |
| `TOO_MANY_PROCESSES` | A process record could not be allocated (system RAM exhausted) | `REGISTER_PROCESS` from procmgr fails; procmgr handles this as a process-creation failure |

memmgr never panics on allocation failure. The caller's response policy
(panic, retry, fail the operation) is its own concern; for std-built
services the heap allocator returns null, std's abort path traps, and the
terminal fault tears down the whole process (see
[`docs/userspace-memory-model.md`](../../../docs/userspace-memory-model.md#byte-heap)
§"Byte Heap").

---

## Non-Goals

- **Swap.** memmgr never moves pages to backing store. RAM exhaustion
  surfaces as an out-of-memory error reply to the caller.
- **Live migration.** memmgr does not relocate pages held by a live
  process to defragment the pool. Defragmentation depends on processes
  exiting (or calling `RELEASE_MEMORY_CAPS`) and the resulting coalesce.
- **MMIO and IOMMU memory caps.** Out of scope; see
  [`docs/device-management.md`](../../../docs/device-management.md).
- **Quota policy.** Per-process frame and region counts are bounded by RAM
  (the metadata arena), not by a security policy. System-wide quota and
  pressure mechanisms are out of scope for the first cut.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | System-wide memory ownership and memory-cap contract |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Process-death notification flow that drives reclamation |
| [docs/capability-model.md](../../../docs/capability-model.md) | Memory cap rights, derivation tree, revocation |
| [memmgr/docs/ipc-interface.md](ipc-interface.md) | Wire shape of `REQUEST_MEMORY_CAPS`, `PROCESS_DIED`, etc. |

---

## Summarized By

[abi/process-abi/README.md](../../../abi/process-abi/README.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md),
[Memory Model](../../../docs/memory-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[Userspace Memory Model](../../../docs/userspace-memory-model.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md),
[Filesystem Driver Protocol](../../fs/docs/fs-driver-protocol.md),
[services/memmgr/README.md](../README.md),
[memmgr IPC Interface](ipc-interface.md)
