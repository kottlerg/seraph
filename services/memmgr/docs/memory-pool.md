# memmgr Memory Pool

Authoritative specification of memmgr's memory-cap pool: how memmgr
ingests memory caps at boot, how it allocates them, how it tracks per-process
ownership, how it reclaims on process death, how it coalesces freed
runs to sustain contiguous-allocation success, and how it bounds what each
process may take.

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

`REQUEST_MEMORY_CAPS(want_pages, flags)` first admits `want_pages` against the caller's budget node
(§ Distribution policy): a request over the max of the node or of an ancestor fails `LIMIT`, and one
that would leave fewer free pages outside `promised` ([Commit](#commit)) than the growth floor (the
system reserve and, while chunks are swapped, the restore headroom; § Distribution policy), from a
caller outside the reserve, or than none, fails with the out-of-memory code of its flags, before any
run leaves the pool. An admitted request then selects:

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
selects once more before memmgr returns the out-of-memory code. A refused
admission does the same before it fails: a pooled run releases its charge and
adds free pages.

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
takes back (see [Per-Process Tracking](#per-process-tracking)), and charged to
the entry's budget node. A best-effort grant charges the pages it carries, which
can be fewer than the admitted `want_pages`.

---

## Frame contents

Every page memmgr hands out reads zero, or, for a chunk restored from the compressed store, reads
the contents it was stored with ([Eviction](#eviction)): each
run of a `REQUEST_MEMORY_CAPS` grant, and each run a demand fault maps (see [Demand
faults](#demand-faults)). A pooled run can hold what its last owner
wrote, and what the kernel left in it: the kernel zeroes a dead object's bytes when it frees them,
but a frame objects were retyped from keeps the retype allocator's free-list links, region offsets
and page counts
([core/kernel/docs/memory-internals.md](../../../core/kernel/docs/memory-internals.md) § Kernel
Object Memory). memmgr does not rely on any path that returns a run to the pool to clear it, so it
clears each run once, at hand-out, after selection and before the run is accounted, derived, or
mapped into the process. A restore's full write of the run, below, takes the place of that clear.

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
`demand_fault_cost` phase reports the cycles of a 16-page demand fault and of a grant-and-map of
the same size, the measure of a change to that work
([programs/demandpaged/README.md](../../../programs/demandpaged/README.md#bench-mode) § Bench
mode).

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
- The index of its caps node, an arena node made and freed with the record,
  so the record stays within the arena's slot size: it holds the delegated
  child `AddressSpace` cap, when demand-paged, the Notification cap
  `REGISTER_PRESSURE` gave, with the bits it is signalled with
  ([Memory pressure](#memory-pressure)), the head of the list of node
  handle states the process owns, and the head of the list of the limit
  registrations it made ([Distribution policy](#distribution-policy)), and
  the count of its pages that are swapped ([Eviction](#eviction)), all of
  which go with the record.
- The next region id: a sequence from 1 that numbers the process's grants.
  Each grant's frame node keeps its id, which no later grant of the process
  reuses; bootstrap arenas and demand-fault runs carry none.
- The index of its budget node (§ Distribution policy), to which every run on
  the record and on its regions' chunk tables is charged. The three boot
  records have top-level reserve nodes with no max, so their bootstrap arenas
  are charged too.

The frame, region, commitment, and chunk-table nodes live in a self-hosted metadata arena (below),
not in the record, so per-process frame and region counts are bounded by RAM —
not by a fixed constant. The arena is what makes the demand-paged thread-stack
consumer (one region plus many lazily-grown frames per thread) viable: a fixed
per-process array would cap thread count at a small constant. Allocation fails
only when the arena cannot grow because system RAM is exhausted, surfaced as
`QUOTA`.

Each record is itself an arena node, so the number of tracked processes is bounded by RAM, not by a
constant. Records are found by badge, and node handle states by the key their handles carry, through
one linear-hash index: a bucket array of arena indices, in its own window of memmgr's address space,
that grows one page of buckets at a time from the pool. Linear hashing splits one bucket per step
once the mean chain length passes two, so the array only ever appends and lookup stays constant-time
on average; when the window is spent, buckets stop splitting and chains lengthen, which costs lookup
time and bounds no capacity. The window's base is fixed, not drawn per boot like the arena's: the
array holds only arena indices. `REGISTER_PROCESS` returns `TOO_MANY_PROCESSES` only when the
record's node, its caps node, its budget node or, when procmgr asks for a node handle, its handle
state cannot be allocated: system RAM is exhausted.

---

## Demand faults

A demand-paged region is backed in chunks of `DEMAND_CHUNK_PAGES` (16) pages, aligned to the
region's base and clamped to its end. On a fault in a region, memmgr backs the part of the
faulting page's chunk that no earlier run backs: the largest span of the chunk that holds the
faulting page and no page of a run memmgr mapped before, which it reads from the chunk's entry in
the region's chunk table ([Chunk table](#chunk-table)). On a pool with a free run that covers the
span, that is the whole chunk on its first fault, backed by one run.

The span is a fault-around preference, and the process's budget node bounds it. memmgr first admits
as much of the span as the node takes ([Distribution policy](#distribution-policy)): the span,
clamped to what the max of the node and of every ancestor leaves, and to the free pages outside
`promised` ([Commit](#commit)) above, for a node outside the system reserve, the growth floor (the
reserve and, while chunks are swapped, the restore headroom). A fault in a committed region skips
this admission: its commitment carries the span's charge, and `promised` its pages
([Commit](#commit)). A fault is declined with code 7 when the growth floor admits not even the
faulting page. It is declined with code 10 only when the max admits not even the faulting page, or,
when the map needs page-table funding, not the faulting page and the least donation beside it, and
with code 9 when the growth floor refuses that donation. A longer run whose funding is refused is
shortened first ([Client page-table funding](#client-page-table-funding)). It then selects a run
covering the admitted pages, as a `REQUIRE_CONTIGUOUS` request would, with the deferred recheck
before it fails (see [Reclamation](#reclamation)). When no free run covers them, it takes the
largest free run whole, which needs no split, and maps it over the part of the span around the
faulting page: from the faulting page up, moved down only as far as needed to stay inside the span.
A later fault on a page of the span the run did not cover is backed the same way, so the chunk fills
in parts, each part one run and one frame record. A fault is therefore declined for want of RAM
(code 7, [`ipc-interface.md`](ipc-interface.md) § Kernel-origin fault message) only when the free
pool holds no page, when every free page is in the growth floor (the system reserve and, while
chunks are swapped, the restore headroom) and the process's node is outside the reserve, or when the
split of a run larger than the pages to back fails. A fault on an evicting or compressed chunk first
makes the chunk resident, a restore with its own admission ([Eviction](#eviction)).

Each run is zeroed before it is mapped ([Frame contents](#frame-contents)), mapped with the region's
protection, and recorded on its chunk's entry with its mapped VA and no region id, and charged to
the process's budget node, so `UNREGISTER_REGION` unmaps and reclaims it and `PROCESS_DIED` reclaims
it (see [Reclamation](#reclamation)). The pages move from a free run to the process, so `pool_total`
is unchanged.

---

## Chunk table

Each demand region carries a chunk table with one entry for each chunk a fault has backed. An
entry records:

- The backed mask: one bit per page of the chunk, set when a run backs the page.
- The chunk's state: unbacked; resident, its pages backed by the runs on the entry's run list and
  mapped in the process; evicting; compressed; writing or on disk, its pages taken by the swap
  service ([Disk tier](#disk-tier)); or lost, its swap slot's bytes having failed authentication.
- A pin flag and a two-bit age.
- The job slot of its eviction while it is evicting, so a completion is applied only to the
  eviction it was posted for.
- A link: the head of the chunk's run list while it is resident or evicting, the head of the list
  of store runs its pages are stored in while it is compressed, and its disk node while it is
  writing or on disk.

The evicting and compressed states, the pin flag, and the age are the swap path's: memmgr reclaiming
a cold chunk's runs under memory pressure and storing its pages, a fault restoring them
([Eviction](#eviction)); the writing, on-disk and lost states are the disk tier's. A fault on an
evicting, compressed or writing chunk makes the whole chunk resident before it backs anything, so a
resident chunk's every backed page is mapped; a fault on a chunk on disk is redirected to the swap
service, and one on a lost chunk is declined.

The table is a radix tree of [Metadata Arena](#metadata-arena) slots rooted in the region's node.
A directory node holds `DIR_FANOUT` (6) children: the slot indices that fit in the slot's largest
payload, so a directory node does not enlarge the slot. A leaf holds one chunk's entry. The tree is
indexed by the chunk's index in the region, its offset from the region's base in chunks, one
base-6 digit per level. Its height is fixed by the region's chunk count, as the fewest directory
levels that give every chunk a leaf: none for a region of one chunk, six for a region of 2^14
chunks (1 GiB), sixteen for one that fills a 57-bit address space's user half. A node exists only
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
[Reclamation](#reclamation)), returns each store run of a compressed or writing chunk, which no
process ever mapped, to the free pool, frees an on-disk chunk's swap slot and disk node, cancels a
writing chunk's write ([Disk tier](#disk-tier)), and returns every directory and leaf node to the
arena's free list.

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

1. It admits four pages against the process's budget node, or two when four would take the
   subtree of the node or of an ancestor over its max, or would take the growth floor. The demand
   run whose map needs the funding is charged only once it is recorded, so the donation is
   admitted against the max beside that run's pages. It then
   selects a contiguous run of the admitted size from the free pool, or of two when no four-page
   run is free. A donation can keep one page for the kernel's donation bookkeeping, so it never
   donates a single page. A fault in a committed region instead draws a two-page donation from the
   region's page-table reservation, which carries its charge, and admits nothing; once the
   reservation no longer holds one, its donation is admitted as above ([Commit](#commit)).
2. It records the run on the process's entry like a grant it did not map: no mapped VA and no
   region id, charged to the budget node. No `RELEASE_MEMORY_CAPS` or `UNREGISTER_REGION` can take
   it back.
3. It donates the run to the pool with augment-mode `cap_create_aspace` on the delegated
   `AddressSpace` cap, and keeps its own cap to the run as the reclaim anchor. When the kernel
   refuses the donation, memmgr takes the record back and returns the run to the free pool.

The donated pages stay in the address space until it is destroyed, and `PROCESS_DIED` reclaims
them with the process's other frames. The address space's teardown releases the donation, so the
run is quiescent by then, or waits on the deferred list until it is (see
[Reclamation](#reclamation)). The pages move from a free run to the process's entry, so
`pool_total` is unchanged.

When the budget refuses the funding, because not even two pages fit under the max of the process's
node or of an ancestor beside the run being mapped, or the growth floor refuses it, and the run is
longer than one page, memmgr returns the run to the free pool and backs the fault again with a run
at least two pages shorter, down to one page, around the faulting page as before. So the funding a
fault needs never spends the room its faulting page would fit in. A one-page run whose funding the
budget refuses is declined with code 10, and one whose funding the floor refuses with code 9. A
fault whose map still fails, because the free pool cannot fund the pool or the map fails for another
reason, is declined with code 9 ([`ipc-interface.md`](ipc-interface.md) § Kernel-origin fault
message). A failed map can leave the first pages of the run mapped. memmgr unmaps the run's span,
keeping its page tables ([Commit](#commit)), before it returns the run to the free pool, so no page
of a pooled run stays mapped in the process. When that unmap fails, the run stays recorded on the
process's entry until `PROCESS_DIED`.

---

## Metadata Arena

All of memmgr's bookkeeping — free runs, deferred runs, process records and
their budget nodes, node handle states and limit registrations, per-process frame and region
descriptors, and the regions' chunk tables — is
nodes drawn from a self-hosted arena rather than fixed `.bss` arrays. memmgr
is `no_std` and cannot bootstrap
a general heap against itself, but it *can* host fixed-size nodes in pages
carved from its own pool:

- Nodes are fixed-size `Slot`s (a tagged run, deferred run, budget, process,
  process caps, node handle, limit registration, region, commitment, frame,
  chunk-directory, chunk, or free payload plus a `next` index)
  reached by a
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
accounting, and never breaks the identity. For a fault in a committed region,
the pages a growth takes are drawn from the region's metadata bound
([Commit](#commit)).

---

## Concurrency

One receive loop owns all of memmgr's bookkeeping. memmgr's second thread,
the compression worker of [Eviction](#eviction), owns none of it: it reads
the pages the loop mapped for its job and writes the job's own buffer, and a
job slot's state word, written with release and read with acquire ordering,
hands each slot between the two. The
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
  out stays under that intermediary when the grantee's `CSpace` is torn down; either way its holder
  can map the frame after memmgr grants it again, or a driver holding it for a transfer can have its
  device still writing it.

memmgr therefore checks each reclaimed frame through its retained intermediary, which shares the
Memory object of every derivation it granted. The frame is **quiescent** when all four hold:

1. The intermediary is the only reference to that Memory object (`CAP_INFO_SOLE_REFERENCE`): no
   other capability to it in any `CSpace`, moved or derived, and no kernel-internal reference such
   as a retype lease or a page-pool donation. memmgr reads this first: once it holds it keeps
   holding, since no other process has a capability through which to add a reference or a mapping,
   so the reads after it cannot be raced.
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

A query that fails answers no. A quiescent frame joins the free pool, and its pages are uncharged
from the budget node they were charged to. Any other frame joins the **deferred list**: its
descriptor node is rewritten into a run node in place, as a pooled frame's is, so reclamation
still never allocates and cannot fail. A deferred run is owned by memmgr and counted in
`pool_total`, lent to no process, and never granted; it keeps its budget node and stays charged
to it until a recheck pools it (§ Distribution policy). Before every `PROCESS_DIED`,
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

memmgr does not revoke its intermediary's derivations before pooling: a revoke reaches no mapping
already made, and it would cut off every holder below the intermediary, a holder of a derivation
the grantee made and handed out included, since the grantee's `CSpace` teardown leaves that
derivation under the intermediary, and among them a driver whose device may still write the frame.
The frame waits instead, until its holder drops the capability.

On `PROCESS_DIED(badge)` from procmgr, which procmgr holds back for a started
`CREATE_DMA_HOLD` process until its creator releases it, the frames staying on
the record until then (see [`ipc-interface.md`](ipc-interface.md#label-4-process_died)
§ Label 4):

1. When the badge names a record, take the record's pressure registration
   and delete the cap it carried ([Memory pressure](#memory-pressure)). The
   cap keeps the process's Notification, and the frame it was retyped from,
   alive, so it goes before the reclaim: the frame then passes the quiescence
   check of step 4 instead of waiting on the deferred list.
2. Recheck the deferred list.
3. Remove the per-process record from the index. If absent (untracked
   badge), skip to step 6 — the death notification is idempotent.
4. For each frame node in the record's frame list and on the run lists of
   its regions' chunk tables, rewrite the node into a run of the retained
   Memory cap and insert it into the free pool at its sorted position when
   the frame is quiescent, else onto the deferred list (no fresh node, so
   the step cannot fail).
5. Return every chunk-table node, every region node, the commitment node of
   each committed region, the record's own node, and its caps node to the
   arena free list, and drop the record's reference
   to its budget node, which is freed with it unless a deferred run is still
   charged to it.
6. Run coalescing across the newly-freed runs and their adjacent
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
region node, with its commitment node when it is committed ([Commit](#commit)),
and frees its chunk table ([Chunk table](#chunk-table)), returning
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

## Distribution policy

The kernel sets no ceiling on a process's memory: a process holds what it has been granted through
accounted, retyped Memory caps, and the kernel forbids no legitimate consumption
([docs/memory-model.md](../../../docs/memory-model.md) § Frame Allocation is Fallible). Containing
a process's memory is therefore the distributor's policy, and memmgr, which lends every page of
userspace RAM, is the distributor. The kernel accounts; memmgr decides which charges it serves.

**Budget nodes.** memmgr charges every page it lends to a process to a budget node, a memmgr object
separate from the process record. A node has a parent link, an optional max in pages, and a charge
counter for its subtree: the pages charged to the node and to every node below it. A process record
points at a node; nothing assumes one node per process. The charge covers each grant, demand-fault
run of an uncommitted region and page-table donation memmgr accounts to the process ([Per-Process
Tracking](#per-process-tracking)), each committed region's pages and what is left of its page-table
reservation, charged whole when the region is committed whether or not its pages hold frames
([Commit](#commit)), and each such run on the deferred list until it rejoins the free pool
([Reclamation](#reclamation)). What memmgr draws from the pool for its own metadata (arena and
index pages, its page tables and its `CSpace` growth) is charged to no node. A node outlives its
process while a node below it is alive or a run charged to it is on the deferred list, and its
charge stays in its parent's subtree meanwhile, so a process cannot hand its frames to another
process, die, and free its subtree's budget while the frames stay held.

**Charging.** A charge is checked against the max of the node and of every ancestor. A request
that would take a subtree over its max fails with `LIMIT`, distinct from the out-of-memory codes of
system exhaustion. A demand fault first shortens its run to what the max allows, and is declined
with code 10, distinct from code 7, only when the max admits not even the faulting page (and the
least page-table donation its map needs), so a crash report tells a budget kill from an exhaustion
kill ([Demand faults](#demand-faults)). Lowering a max reclaims
nothing and kills no process: it refuses new charges until the subtree's usage falls below it. A
node without a max is limited only by its ancestors and the system reserve. No recipe, and nothing
else in the default image, sets a max, so no default per-process ceiling exists.

**System reserve.** The reserve is a count of free pages that only a charge to a reserve node may
take: a charge to any other node fails as exhaustion when it would leave fewer free pages outside
`promised` ([Commit](#commit)) than the growth floor, which is the reserve and, while chunks are
swapped, the restore headroom above it ([Eviction](#eviction), Restore headroom), and a demand fault
of such a node in an uncommitted region backs only the free pages outside `promised` above the
growth floor, declined with code 7 when they hold not even the faulting page. A charge to a reserve
node may take the reserve, but not a page `promised` holds. It is a floor for the core and a limit
on no process: memmgr's self-funding, which is charged to no node, and the reserve nodes draw on it.
Reserve membership is an attribute each node takes when it is created, not one its children inherit.
The nodes of memmgr's boot records (procmgr's, and memmgr's and init's own) and of init's children
(devmgr, vfsd and svcmgr) are reserve nodes, and so is the node of a process created with procmgr's
reserve creation flag (`CREATE_RESERVE`), which procmgr honours only from a reserve creator, as it
does `CREATE_PHYS_ACCESS`. A process a reserve creator creates without the flag is outside the
reserve, so svcmgr's services are outside it unless the recipe's `reserve = yes` has svcmgr pass the
flag, as oomd's, sessiond's, crashd's and logd's do
([services/svcmgr/docs/service-definitions.md](../../svcmgr/docs/service-definitions.md)
§ `reserve`). The reserve is `pool_total / 64` ([docs/limits.md](../../../docs/limits.md) § memmgr).

**Create-time ceiling.** procmgr registers each process with its creator's node as the parent (a
child of init is a top-level node: init's own record holds only init's bootstrap arenas and parents
no process) and, when the creator asks for one with `CREATE_MEMORY_MAX`, a max in pages. memmgr
clamps the max to what the parent and every ancestor have left, and refuses a reserve node under a
parent outside the reserve; procmgr relays the max the node took to the creator in the create reply
([services/procmgr/docs/ipc-interface.md](../../procmgr/docs/ipc-interface.md)
§ Label 1, **Memory max and reserve**). A process reads its node's usage, its max and its subtree's
usage with `QUERY_MEMORY_USAGE`.

**Server-side charges.** Memory a server spends on a client's behalf (procmgr's process-table
entry, vfsd's and fatfs's per-client state) is charged to the server's node, not to the client's.
A client can therefore make a server spend memory beyond the client's own max, bounded only by the
server's node and the reserve. This is a known gap; charging that state to the client is
[#1100](https://github.com/kottlerg/seraph/issues/1100).

**Node handles.** Authority over a node is a capability: a node handle, a SEND on memmgr's
endpoint badged with the node-handle verb bit and a random key that names one node
([ipc-interface.md](ipc-interface.md) § Node Handles). A holder sets the node's max
(`NODE_SET_MAX`), clamped to its usage plus what its parent chain has left, so a max set while
the process runs never exceeds what its ancestors allow and lowering it reclaims nothing, as
above; makes sub-nodes under it (`NODE_CREATE`), so siblings charged to one sub-node share its
budget; reads its usage (`NODE_QUERY_USAGE`); and registers a Notification for its limit event
(`NODE_REGISTER_LIMIT`). procmgr hands a creator its child's handle on request
(`CREATE_NODE_HANDLE`), and charges a new child to the node of a handle the creator passes
(`CREATE_CHARGE_NODE`); a process makes sub-nodes of its own node with `CREATE_SUB_NODE`; no
process holds a handle to its own node, so none can raise the max its creator set. A node's
handle state, the key its handles carry and the index of its limit registration, is an arena node
named by the budget node's slot link and found through the record index by its key; it holds a
reference on its node. It belongs to a process: the node's own process, or for a sub-node the owner
of the node it was made under, or the process that called `CREATE_SUB_NODE`. It goes when that
process dies or, for a sub-node, on `NODE_RELEASE`; every handle carrying its key is refused from
then on, and the node itself lives on while a process, a node below it or a charge refers to it.
The limit registration, the Notification cap and its bits, is an arena node of its own on the list
of its registrant, the process whose memmgr SEND the request carried: it goes when the registrant
dies, when a later registration replaces it, or with the handle state, so no holder leaves a cap in
memmgr past its own life.

**Limit event.** After each request memmgr walks the chain from the node the request charged, or
whose max it set, to the top, and sends each node's registered bits on its Notification when the
node's subtree holds its max or more, or when the node's own max refused the request's charge. A
charge that brings a subtree to its max, each refused charge, and a max set at or below the usage
each send the bits once; a send never blocks, and the bits of sends not yet taken coalesce.

---

## Commit

A region registered with `REGION_COMMIT` is committed ([ipc-interface.md](ipc-interface.md) § Label
7). memmgr admits and charges its whole length when it registers it, and each growth by
`EXTEND_REGION` (§ Label 12) when it accepts that growth, so a fault in a committed region is not
declined for budget or RAM while the region's page-table reservation lasts, which only the process's
own mappings and unmaps can spend early (Faults below): a refusal reaches the process as the error
reply of the call that asked, where it can fail an allocation, not as a fault. std's heap grows this
way. It keeps its uncommitted floor and registers one committed growth region directly above it on
its first grow, which each later grow extends, so a heap is two regions however large it grows and
holds no Memory caps ([Userspace Memory Model § Byte
Heap](../../../docs/userspace-memory-model.md#byte-heap)).

**Promised.** memmgr counts in `promised` what the committed regions can still take from the free
pool: for each, its pages that hold no frame yet, and what is left of its page-table reservation and
of a bound on the metadata its chunk table and run descriptors can take. Every admission reads the
free pages outside it: a grant, a committed registration or growth, an uncommitted demand run and a
page-table donation are each admitted only when `free - promised - F >= want`, with F the growth
floor (the system reserve and, while chunks are swapped, the restore headroom) for a charge to a
node outside the reserve and 0 for a charge to a reserve node ([Distribution
policy](#distribution-policy)). So no charge takes a free page a committed region's fault needs.
`QUERY_POOL_STATUS` reports `promised` in `data[8]`, and the pressure level is computed from the
free pages outside it ([Memory pressure](#memory-pressure)).

**What a commitment holds.** A committed region of `pages` pages charges its budget node its
pages and a page-table reservation: two pages (`PT_DONATION_PAGES`, the size of its page-table
donations; see Faults below) for each intermediate page table a map of the whole region can need
under any paging depth (`pool_funding::pt_pages_for`). It adds those to `promised` with a metadata
bound: for each chunk, a run descriptor for each of its pages, its leaf and its share of the
directory nodes, and one directory node for each level of the table, in arena pages
([Chunk table](#chunk-table), [Metadata Arena](#metadata-arena)). The max of the node and its
ancestors bounds the pages and the reservation; the metadata bound is charged to no node, as
memmgr's metadata never is. The commitment's state (what is left of the reservation and of the
metadata bound, and the largest length the region has had) takes an arena slot of its own beside the
region's. Each part is computed from the region's whole length, so a region grown in many small
steps is charged and promised what one registration of its final length would be; the reservation is
that of the largest length the region has had, since a cut keeps it (Shrink and release below). The
computation is the host-tested `free-pool` module `commit`.

**Faults.** A fault in a committed region is admitted without the budget and RAM tests of an
uncommitted one, and its run is selected as any demand run's ([Demand faults](#demand-faults)). The
run's pages were charged with the commitment, so recording the run charges nothing more and lowers
`promised` by its pages. A page-table donation its map needs ([Client page-table
funding](#client-page-table-funding)) is two pages, drawn from the region's reservation without
admission: the donation's pages leave the reservation and `promised`, and are charged once, as the
donation. The address space's page-table pool is shared, so any other mapping of the process can
take the pages a donation leaves in it. Between two maps the reservation covers the region's
donations whatever those mappings take. The kernel keeps at most one page of a donation for its
bookkeeping, so each two-page donation adds at least one page, and a map that still runs out after a
donation needs more pages than the pool held: the donations of one map take at most two pages for
each page table it creates. The tables a committed region's maps create lie in its span and stay
until it is unregistered: memmgr unmaps a cut's pages, and a run whose fault it declines in any
region, without reclaiming page tables, since the kernel reclaims a table once it is empty, whatever
span emptied it, so only the process's own unmaps and its unregistering of a region reclaim them. So
they number at most `pool_funding::pt_pages_for` of its largest length, which the `commit` module's
host tests check against a pool that every other mapping empties between two maps. Two cases, both
of the process's own doing, spend the reservation faster: a thread of the process that maps between
two rounds of one map can take the donated pages first, which costs that map a round and the
reservation a donation, and a table in the region's span that a reclaiming unmap the process made or
asked for removed (its own unmap of pages in a span that shares the table, or its unregistering of a
region that shares it) is built again. A donation the reservation no longer holds is admitted as any
other, so the process's budget and the growth floor bound what it takes, and the fault is declined
with code 10 when the max refuses even that donation, or with code 9 when the floor does. A
committed fault is also declined, with code 9, when its map fails as any map can: no two contiguous
pages are free for a donation, or a thread of the process maps between the rounds of one map and
takes the donated pages faster than four rounds fund them. The arena's growth to record a committed
fault's run ([Metadata Arena](#metadata-arena)) is drawn from the region's metadata bound as a
donation is from its reservation, without admission: the pages the growth takes from the pool, the
arena page and any page tables memmgr's own map of it needs, leave the bound and `promised`, so the
free pages outside `promised` do not fall for metadata the commitment already counts. Growth past
what is left of the bound takes free pages outside `promised`, as an uncommitted region's does.

**Shrink and release.** `SHRINK_REGION` (§ Label 13) lowers a committed region's top to a chunk
multiple: memmgr unmaps the pages past it, cuts the chunks past it from the chunk table, which drops
the directory levels the shorter region does not need, and takes back each run on them, pooled or
deferred ([Reclamation](#reclamation)). It releases the commitment of the pages cut: the charge of
those that held no run, and their part of `promised`, their metadata bound at most what is left of
the region's. It unmaps them without reclaiming page tables, so the tables of the pages cut stay in
the address space until the region is unregistered, and the region keeps its page-table reservation:
a regrowth up to the largest length the region has had adds none. `UNREGISTER_REGION` and
`PROCESS_DIED` release a committed region's whole commitment: the charge of its pages that hold no
run and of what is left of its reservation, and its part of `promised`, what is left of its metadata
bound with it.

**Discard.** `DISCARD_RANGE` (§ Label 20) takes back the frames of whole chunks of a region, of
any region, its length kept: memmgr unmaps the pages without reclaiming page tables and clears
their chunks from the chunk table (`chunk::clear`), each run on them pooled or deferred. In an
uncommitted region each run retires charged to the process's budget node, so it is uncharged as it
rejoins the pool. A committed region keeps its commitment, whose charge carries its pages whether
they hold a frame or not: its runs retire charged to no node, and `promised` rises by their pages,
which hold no frame again, and by the metadata the cleared chunks gave back
(`commit::meta_of_chunks`), what is left of the region's metadata bound rising by it, at most to
the bound of its length. A refault of a discarded page is then admitted from `promised` as its first
touch was, and is backed by a zero-filled run ([Frame contents](#frame-contents)). A discard frees
RAM without raising the free pages outside `promised`; a cut does both. std's heap discards whole
free chunks of a large freed block and cuts the free chunks at its top ([Userspace Memory Model §
Byte Heap](../../../docs/userspace-memory-model.md#byte-heap)).

**Retries.** A committed registration or growth whose reply does not reach the caller is undone,
as a grant whose reply fails is rolled back, so a caller whose call was interrupted makes it again
and is charged once. A cut repeated finds the region at its new length and succeeds, and a discard
repeated finds no run in its range and succeeds.

---

## Memory pressure

memmgr tells processes how close the free pool is to the growth floor, so a process holding
memory it can give back (a cache) gives it back before a grant is refused. It acts on the level in
no other way: it only signals, and kills nothing.

**Levels.** The level is computed from the free pool's pages outside `promised`
([Commit](#commit)), deferred pages excluded, against `pool_total`. It is `CRITICAL` at or below the
growth floor, the system reserve and, while chunks are swapped, the restore headroom (§ Distribution
policy; § Eviction, Restore headroom), where a grant to a process outside the reserve is refused;
`LOW` below `pool_total / PRESSURE_LOW_DIVISOR` pages; and `NORMAL` otherwise. A worse level applies
at once. A better one applies only once the free pool clears that level's threshold by a hysteresis
band of `pool_total / PRESSURE_BAND_DIVISOR` pages, and at least one, so a pool that hovers at a
threshold does not flip the level on every turn: the level becomes the one the free pool less the
band gives, and no worse than before. The constants are tuning values proportional to RAM
([docs/limits.md](../../../docs/limits.md) § memmgr); the computation is the host-tested `free-pool`
module `pressure`.

**Signal.** A process registers a Notification cap and the bits to send on it with
`REGISTER_PRESSURE` ([ipc-interface.md](ipc-interface.md) § Label 11); the std runtime registers
every process at start. The cap sits in the record's caps node ([Per-Process
Tracking](#per-process-tracking)), so a process holds one slot of memmgr's `CSpace`: a second
registration replaces the first and memmgr deletes the cap the first carried. `PROCESS_DIED`
deletes the cap before it takes the process's frames back, since the cap keeps the Notification,
and the frame it was retyped from, alive ([Reclamation](#reclamation)).

At the top of each turn of its receive loop, after the `CSpace` top-up, memmgr recomputes the
level, and on a change it sends each registrant its bits once. The send ORs the bits into the
Notification and never blocks, so no client can hold memmgr, and bits not yet taken coalesce: a
registrant that wakes knows the level changed at least once, and reads the level, which
`QUERY_POOL_STATUS` returns in `data[7]`. A send that fails, to a cap the client revoked, is
dropped. The broadcast walks every record through the index, a cost paid only on a change of
level.

---

## Eviction

Under memory pressure memmgr evicts cold pages it mapped as pager into a compressed store it keeps
in RAM, and restores them on the next fault on them. The store's pages are part of `pool_total`;
memmgr performs no device I/O ([Non-Goals](#non-goals)).

**Eligible pages.** memmgr evicts only pages it mapped as pager: the runs it backs on a demand
fault. It never evicts a granted frame, since a client holding a Memory cap to it may have retyped,
sent or DMA-mapped it; a page of a process whose budget node is a reserve node ([Distribution
policy](#distribution-policy)), since those processes free memory under exhaustion and must not
wait on a restore to do so; a page of a region registered with `REGION_NO_EVICT`
([`ipc-interface.md`](ipc-interface.md) § Label 7); or a page of a process with no delegated
address space, whose accessed bits memmgr cannot read. A spawned thread's IPC buffer is a grant
([Userspace Memory Model § Page
Reservations](../../../docs/userspace-memory-model.md#page-reservations)), and init, memmgr and
procmgr have no pager, so eviction never reaches a page the kernel's non-restartable IPC-buffer
copies use.

**Overcommit allowance.** Every admission's test ([Commit](#commit)) is to gain an overcommit
allowance A: `free - promised - R + A >= want`. A is 0, so a fault on a committed page draws from
`promised`, and is not declined for budget or RAM ([Commit](#commit)), and memmgr evicts only
uncommitted pages (thread stacks, heap floors, `register_demand_paged` regions): evicting an
uncommitted chunk frees its frames less the store pages its contents take, while evicting a
committed chunk would only add store pages against `promised`. An allowance above 0 is design
intent; not yet implemented ([#230](https://github.com/kottlerg/seraph/issues/230)): heap pages
would be evictable too, and a committed fault that finds no frame would compress a victim within
its turn or be declined as a commit overrun.

**Selection.** While the pool's pressure level reads `LOW` ([Memory pressure](#memory-pressure)),
memmgr reclaims in the background until it reads `NORMAL`, and stops there. It does not reclaim in
the background at `CRITICAL`: the free pages above the growth floor are gone, so every frame an
eviction frees past the restore headroom goes to the next admission, which a process draining the
pool makes before any victim faults. Eviction makes room for the processes that run while memory is
low; at `CRITICAL` only a restore evicts, for itself (Direct reclaim, below), and the pool is
otherwise left to the out-of-memory path (crashd's hold of a declined fault, oomd's stop of a job).
While the level reads `LOW` or `CRITICAL`, the receive loop waits for a message a bounded time and,
at most once per sweep interval, runs a slice of the clock: a hand walks the eligible regions of
each process in turn, a bounded number of steps a slice ([docs/limits.md](../../../docs/limits.md)
§ memmgr gives the interval and the bounds). For each span of up to 256 chunks it reads and clears
the accessed bits with one `SYS_ASPACE_HARVEST`, and ages each resident chunk of the span with its
two-bit age ([Chunk table](#chunk-table)): a chunk with no accessed page in two sweeps is cold, and
at `LOW` the slice posts one job for each cold chunk, as many as the compression worker has free job
slots. The victims a slice finds and posts no job for are kept, a bounded number, for direct
reclaim; at `CRITICAL` a slice finds the chunks with no accessed page in one sweep. A slice ends at
the end of a pass, so no slice ages a chunk twice. The granule is the chunk: one unmap and one
restore fault per chunk, over every run on its run list.

**States.** memmgr unmaps a victim chunk with `SYS_MEM_UNMAP`, leaving its page tables, maps its
runs into the job slot's input window of its own address space, and the chunk is evicting while
the compression worker stores its pages. A fault on an evicting chunk maps the same runs back and
cancels the eviction: the job's completion is then stale, since the chunk's entry names the job
slot of the eviction in flight. Once stored, the chunk is compressed: its runs return to the
free pool and its entry's link holds the head of its store-run list. An all-zero page takes no store
space, and a chunk whose every page is zero takes no store page. A stream that would take as many
pages as the chunk's backed pages gains nothing: memmgr maps the runs back, and the chunk stays
resident.

A fault on a compressed chunk is restored in the fault arm within the turn, since the restore is
bounded by one chunk's decompression. A restore is not admitted against the max of the node or of
any ancestor, since the node stays charged for its evicted pages, so it is never declined with code
10. A restore of an uncommitted chunk passes the RAM test of an uncommitted demand run, `free -
promised - R >= want`, with want the chunk's backed pages and R the system reserve for a node
outside it and 0 for a reserve node, after the deferred recheck ([Distribution
policy](#distribution-policy), System reserve): R, not the growth floor, so the restore draws on the
restore headroom (below). When the free pages do not admit it, memmgr reclaims
directly (Direct reclaim, below), and declines the restore with code 7 only when that does not make
room, the chunk staying compressed and its store kept. With an allowance above 0, a restore of a
committed chunk would be a committed fault, drawing from `promised` as any committed fault does
([Commit](#commit)). The chunk is the granule, so a restore is never clamped to part of a chunk.
memmgr takes runs covering exactly the chunk's backed pages (no run spans an unbacked page of a
chunk backed in parts), selected as a demand fault selects ([Demand faults](#demand-faults), run
selection only), maps the chunk's store runs at a stream window and each new run at the scrub window
of its own address space ([Frame contents](#frame-contents)), and writes every byte of every page of
each run there before it maps the run into the process: it decompresses each stored page and
zero-fills each all-zero page. That full write replaces the hand-out clear of [Frame
contents](#frame-contents), so no byte of a run's earlier owner reaches the process. It then returns
the store runs to the free pool and resumes the thread. A stream that does not decode, which only a
corruption of memmgr's memory makes, declines the fault with code 9 and detail 0, the chunk staying
compressed.

**Direct reclaim.** A restore the free pages do not admit evicts victims itself, in its turn, before
it is declined: the kept victim of the greatest age first, checked again as resident, eligible, and
unaccessed for at least one sweep, and its pages' accessed bits read once more
(`SYS_ASPACE_HARVEST`), since its age is the one the last sweep over it recorded: a set bit resets
its age and passes it over. So a chunk accessed or restored since the last sweep is never taken and
two processes cannot trade one chunk turn after turn. Any eligible process's chunk may be
taken, the faulting process's own included. For each, memmgr unmaps the chunk, maps its runs at the
input window of a synchronous slot of its own, compresses it into that slot's output buffer with a
hash table of its own, so it shares nothing with the worker, unmaps the window, takes the store
pages, writes the stream and swaps the chunk, whose runs return to the free pool in the same turn; a
stream that gains nothing maps the chunk back. It stops when the restore is admitted, or after a
bounded number of victims ([docs/limits.md](../../../docs/limits.md) § memmgr), and the restore is
then declined with code 7. The store pages a victim takes can dip below the reserve for the rest of
the turn, where no other admission runs, and each victim kept leaves more free pages than it took.
Only a restore reclaims directly: a first touch of an unbacked page grows its node's charge, and at
the growth floor that growth stays the out-of-memory path's, while a restore returns pages its node
is charged for already. Compression in the loop costs a restore's turn at most that bound's
compressions, on a fault that would otherwise be declined; background eviction compresses in the
worker, so its latency lands on no fault or grant.

**Restore headroom.** While chunks are swapped, a charge to a node outside the reserve leaves a
restore headroom H free above the reserve R: the swapped pages, and at most R, so it is admitted
when `free - promised - R - H >= want` with `H = min(swapped, R)`, and the level is `CRITICAL` at or
below `R + H` ([Memory pressure](#memory-pressure)). A restore is admitted against R alone, so it
draws on H. Without it, the frames background eviction frees at `LOW` go to a process draining the
pool, whose grants are never victims, and by `CRITICAL` the evicted chunks of idle processes, a
filesystem driver's thread stacks woken by the pressure signal among them, find neither a free page
nor a victim, and their faults are declined. With it, the restores of up to R swapped pages find
their frames whatever a drainer took, and direct reclaim covers the rest. The cost falls on growth:
each chunk eviction swaps raises H by its pages and frees them less its store pages, so eviction
gives growth no page until H reaches R. With nothing swapped H is 0, and every admission and level
is as it is without eviction. H is at most R, a sixty-fourth of the pool, so `LOW`'s threshold stays
above `CRITICAL`'s. `QUERY_POOL_STATUS` reports `R + H` as `growth_floor_bytes`
([ipc-interface.md](ipc-interface.md) § Label 6). The computation is the host-tested `free-pool`
function `budget::growth_floor`.

**Compression worker.** Compression runs in one raw `no_std` thread of memmgr, at the top of the
fair class (`ipc::sched_policy::MEMMGR_WORKER_PRIORITY`), below the receive loop's priority. It
touches no ledger state: it waits on a Notification, takes each job the loop posted, compresses
the chunk from the slot's input window into the slot's own output buffer in memmgr's image, and
marks the slot done. A slot's state word, written with release and read with acquire ordering,
hands the slot's buffer from one thread to the other. The loop drains the done slots at each turn:
it unmaps the input window, takes exactly the store pages the stream needs from the free pool,
writes the stream into them through the stream window, and swaps the chunk. No Notification can
wake a receive on an endpoint, so while a job is in flight the loop's receive waits a bounded time
([docs/limits.md](../../../docs/limits.md) § memmgr), and a receive with no job in flight and no
reclaim waits for a message as before. The compressor is LZ4-class, `no_std`, and written in the
tree (`memmgr-free-pool`'s `compress.rs`), as is the stream format (`store.rs`): each backed page
as a two-byte header and the page compressed, raw, or, for an all-zero page, nothing. When memmgr
cannot start the worker at boot it evicts nothing.

**Accounting.** The identity `system_ram == kernel_reserved + pool_total` holds across eviction and
restore, with `pool_total = free + deferred + Σ records + metadata + store`, where `store` is the
pages the compressed store holds. The worker's thread and Notification are memmgr's metadata. A
budget node stays charged for its evicted pages: a charge counts logical pages, resident and
swapped. `QUERY_POOL_STATUS` reports the store's size and the swapped pages' size, and
`QUERY_MEMORY_USAGE` a process's resident and swapped pages apart
([`ipc-interface.md`](ipc-interface.md)). The swapped pages count every evicted chunk: compressed,
writing, on disk and lost ([Disk tier](#disk-tier)).

**Debugger reads.** `SYS_THREAD_READ_MEM` fails on a page that is not present and does not ask
the pager
([`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_thread_read_mem-60)
§ `SYS_THREAD_READ_MEM`). A debugger or crash service that gets that failure on a page of an
evicted chunk asks procmgr, through the debug authority, to make the range resident
(`MAKE_RESIDENT`, [procmgr's IPC interface](../../procmgr/docs/ipc-interface.md)); only a holder of
the debug authority may ask, and memmgr takes the request from procmgr alone
([`ipc-interface.md`](ipc-interface.md) § Label 21). memmgr restores each compressed chunk of the
range, and maps back each evicting one; either counts as an access in the chunk's age. It walks
only the chunks that have an entry, and one request makes at most a few chunks resident and visits
at most a bounded number ([docs/limits.md](../../../docs/limits.md) § memmgr); its reply says where
it stopped, and the reader asks again from there, so a request's turn delays the faults and grants
behind it no more than a few restores would. The reader then retries its read. The request
restores and backs nothing else: a page no fault has backed stays not present. memmgr reads no
swap slot and waits on no swap service, so a chunk on disk it asks the swap service for: when the
swap service registered a want Notification, memmgr posts the chunk's slot word to a short list the
swap service takes (`SWAP_WANTED`), sends on the Notification, and replies that the range is
pending at that chunk; the swap service reads the slot and restores the chunk ahead of a fault, and
the reader, after a pause, asks again. A reader gives the range up after about a second of pending
replies, so a swap service that is down or cannot read the slot leaves the page not present. A lost
chunk, and a chunk on disk with no swap service to ask, are passed over; a page of either stays not
present ([Disk tier](#disk-tier)).

---

## Disk tier

A compressed chunk can leave memmgr's store for a swap slot the swap service holds on disk
([#43](https://github.com/kottlerg/seraph/issues/43)). memmgr performs no device I/O and waits on no
peer: the swap service drives every step over memmgr's swap labels, and a fault on a chunk on disk
is redirected to it by a fault reply ([`ipc-interface.md`](ipc-interface.md) § Labels 22 to 26).
The labels are served only on the swap authority, a SEND on memmgr's endpoint badged
`SWAP_AUTHORITY` alone, which init mints and svcmgr publishes seed-only as `memmgr.swap`.

**Slots.** `SWAP_REGISTER` names the swap service's restore endpoint and how many slots its
partition holds. A slot holds one chunk, at the slot's index times a chunk's bytes into the
partition, so any free slot holds any chunk, whatever it compresses to. memmgr owns the slots: a
slot map grown a page at a time as far as the highest slot taken, in a window of memmgr's own
address space ([docs/limits.md](../../../docs/limits.md) § memmgr), maps each taken slot to its
chunk's disk node and threads the free slots on a list, so a slot is taken and freed in constant
time and the swap service keeps no table. The map's pages leave the pool for good and stay in its
total as memmgr's metadata, as the process index's pages do. A registration replaces the one before
it and ends every write in flight, since a new swap service knows nothing of its predecessor's; the
chunks on disk stay, so a restarted swap service restores every one of them.

**Write-out.** `SWAP_TAKE` takes the next compressed chunk: a hand over every process's regions,
walking only the chunks that have an entry, a bounded number of steps a request. memmgr copies the
chunk's stream from its store runs into a buffer of its own, seals it there, takes a slot and a
disk node, and only then copies the slot's bytes into the swap service's buffer, a Memory cap the
request carries, which memmgr maps itself at a window of its own address space. No memmgr frame
leaves memmgr, and memmgr writes the swap service's buffer through its own mapping, which neither
faults nor blocks: a revoke of the cap does not withdraw a mapping
([`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md) § `SYS_CAP_REVOKE`). One
`SWAP_TAKE`'s time in memmgr's loop is bounded by that walk, one copy of a stream shorter than a
chunk, one seal of it, and one copy of the sealed bytes, the order of a chunk's restore. The chunk
is then writing: its store runs stay, held on its disk node, until `SWAP_DONE` ends the write. A
written chunk is on disk and its store runs return to the free pool; an unwritten one is compressed
again on them. A fault on a writing chunk restores it from those store runs and cancels the write;
its slot is freed only at `SWAP_DONE`, so a late write never lands on a slot taken since.

**Encryption.** A slot holds the chunk's stream encrypted and authenticated with ChaCha20-Poly1305
(`shared/crypto`) under a 256-bit key memmgr draws from `SYS_GETRANDOM` at start, followed by the
16-byte tag. The key is in memmgr's memory only and is never sent: the swap service and the disk see
only ciphertext. The nonce is a 64-bit counter memmgr never repeats within a boot, recorded on the
chunk's disk node, so a slot's bytes open only as the seal memmgr last made of the chunk that holds
it: another chunk's bytes, an older seal, or any change fail the tag. A failed key draw leaves the
disk tier off: `SWAP_REGISTER` is refused. The rule is [docs/storage.md](../../../docs/storage.md)
§ Data at Rest's.

**Read-back.** A fault on a chunk on disk replies `FAULT_REPLY_REDIRECT` naming the swap service's
endpoint ([docs/fault-handling.md](../../../docs/fault-handling.md) § Reply), with the slot word as
the redirect word: the slot, its byte count, and the generation of the seal it holds, the low bits
of its nonce counter. The faulting thread stays fault-blocked, and the swap service reads the slot
and hands memmgr its bytes and the word with `SWAP_RESTORE`, then resumes the thread. A word whose
slot holds no chunk on disk, or one under another seal, was made for a use of the slot that ended
(the chunk restored, by another thread's fault or ahead of one, or torn down, and the slot taken
again since): memmgr replies `RESTORE_STALE` and changes nothing, and the swap service resumes the
thread, which faults again and is served as the chunk now stands. So a late or repeated request
never reaches a chunk it was not made for, and a tag failure is always the failure of the chunk's
own slot. memmgr maps the
buffer read-only, copies the bytes into its own buffer, and checks the tag there, so the check and
the decryption read one snapshot. A good slot is restored as a compressed chunk is
([Eviction](#eviction), States): admitted, with direct reclaim, its pages written whole into new
runs and mapped, its slot and disk node freed. A restore memmgr cannot make is declined with that
restore's code, and the chunk stays on disk. A tag failure makes the chunk lost, its slot freed: the
reply carries the decline word of code 12 with detail 1, which the swap service forwards the held
fault with, so the faulting thread is killed, as every later fault on the chunk is. A fault on a
chunk on disk with no swap service registered is declined with code 12 and detail 0. `SWAP_RESTORE`
names a slot word, which `SWAP_TAKE`'s reply also carries, not a fault, so the swap service may also
restore ahead of one, as it does for a debugger's `MAKE_RESIDENT` of a chunk on disk: memmgr posts
the chunk's slot word to a list of at most `SWAP_WANTED_WORDS` words, sends on the Notification the
swap service registered for it, and the swap service takes the words with `SWAP_WANTED`
([Eviction](#eviction), Debugger reads).

**Read-back is serial.** virtio-blk keeps one request in flight
([virtio-blk README](../../drivers/virtio/blk/README.md)), and one driver instance serves the root,
data and swap partitions of a disk, so a restore's read waits behind the request in flight (a
slot's write-out, or a filesystem request), and restores are served one after another.

**Accounting.** A writing chunk's store runs stay in `store`; an on-disk or lost chunk holds no
page of `pool_total`. The swapped pages count every evicted chunk, and the budget node stays
charged for its pages throughout, until a restore or a teardown; a lost chunk's charge goes with
its region. `QUERY_POOL_STATUS` reports the pages on disk and the free slots apart
([`ipc-interface.md`](ipc-interface.md) § Label 6). A disk node is an arena slot, and the slot
map's pages are memmgr's metadata.

---

## Failure Modes

| Failure | Cause | Caller observation |
|---|---|---|
| `OUT_OF_MEMORY_CONTIGUOUS` | No free run satisfies `REQUIRE_CONTIGUOUS`, or the grant would take a page `promised` holds, or the growth floor from a caller outside the system reserve | Reply with error label; caller may retry without the flag, or fail |
| `OUT_OF_MEMORY_BEST_EFFORT` | The pool's free pages do not cover `want_pages`, or the grant, or a committed registration or growth, would take a page `promised` holds, or the growth floor from a caller outside the system reserve ([Commit](#commit)) | Reply with error label; caller treats as system-wide RAM exhaustion |
| `LIMIT` | `want_pages`, or a committed registration's or growth's charge, would take the subtree of the caller's budget node, or of an ancestor, over its max | Reply with error label; caller treats as its own budget refusing, not as RAM exhaustion |
| `QUOTA` | Tracking-metadata arena could not grow, or a selected run could not be mapped to zero it ([Frame contents](#frame-contents)); either means system RAM exhausted | Reply with error label; caller treats as system-wide RAM exhaustion |
| `TOO_MANY_PROCESSES` | A process record, its caps node or its budget node could not be allocated (system RAM exhausted) | `REGISTER_PROCESS` from procmgr fails; procmgr handles this as a process-creation failure |

memmgr never panics on allocation failure. The caller's response policy
(panic, retry, fail the operation) is its own concern; for std-built
services the heap allocator returns null, std's abort path traps, and the
terminal fault tears down the whole process (see
[`docs/userspace-memory-model.md`](../../../docs/userspace-memory-model.md#byte-heap)
§"Byte Heap").

---

## Non-Goals

- **Disk I/O.** The eviction store ([Eviction](#eviction)) is compressed
  RAM inside `pool_total`. Its disk tier ([Disk tier](#disk-tier)) is a
  separate swap service's, which reads and writes the slots; memmgr performs
  no device I/O and waits on no swap service. memmgr evicts only pages it
  mapped as pager, never a grant, a page of a process whose budget node is a
  reserve node, or a no-evict region.
- **Live migration.** memmgr does not relocate pages held by a live
  process to defragment the pool. Defragmentation depends on processes
  exiting (or calling `RELEASE_MEMORY_CAPS`) and the resulting coalesce.
- **MMIO and IOMMU memory caps.** Out of scope; see
  [`docs/device-management.md`](../../../docs/device-management.md).

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
[Fault Handling](../../../docs/fault-handling.md),
[Memory Model](../../../docs/memory-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[Userspace Memory Model](../../../docs/userspace-memory-model.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[Crash Block Format](../../crashd/docs/block-format.md),
[Core Format](../../crashd/docs/core-format.md),
[devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md),
[Filesystem Driver Protocol](../../fs/docs/fs-driver-protocol.md),
[services/gdbstub/README.md](../../gdbstub/README.md),
[services/memmgr/README.md](../README.md),
[memmgr IPC Interface](ipc-interface.md)
