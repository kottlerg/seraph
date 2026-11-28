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
in the metadata arena (below), on two lists at once. One holds every run,
doubly linked in order of physical base, so physical neighbours are list
neighbours (see [Coalescing](#coalescing)). The other is the list of the run's
size class, a two-level segregated fit: each power of two of pages splits into
eight classes of equal width, every count below 16 pages is a class of its own,
a bitmap marks the non-empty classes of each power, and a word marks the
non-empty powers. The run count is therefore bounded by RAM, not by a
constant: no run is turned away for want of a slot, short of the arena being
unable to grow with its reserve spent. The pool keeps running totals of its
free pages and runs. Selection reads the size classes, never the whole pool:

- **Size-class fit.** A run covering at least `N` pages serves a
  `REQUIRE_CONTIGUOUS` request and the single-run case of best-effort
  allocation: the first run of `N`'s own class when it covers `N`, else the
  first run of the lowest non-empty class above it, which the bitmaps find
  and every run of which covers `N`, even when a run behind the first of
  `N`'s class would cover `N` too. The steps are the same however many runs
  the pool holds and in whatever order they came back, so a grant's cost
  does not follow the history of the pool's frees. Below 16 pages every run
  of `N`'s class has `N` pages, so the fit is exact. Above it, the first run
  of `N`'s class exceeds `N` by less than one class width (an eighth of its
  power of two), and a run from a class above by less than the width of that
  class plus its distance from `N`. Only when no class above `N`'s holds a
  run is `N`'s own class walked for a covering run, so a request a run
  covers never fails.
- **Largest run.** Best-effort allocation falls back to repeatedly taking the
  largest run when no single run is large enough, and a demand fault to
  taking it once, whole (see [Demand faults](#demand-faults)): the largest run
  of the highest non-empty class, a walk of that one class.

Taking a whole run frees its node, unlinked from both lists without a walk;
splitting one keeps the node for the remainder, whose physical position does not
change and which is filed again at the head of its size class, the same steps
whether or not its class changed. Returning a run inserts it at its physical
position, found by a walk of the list, and at the head of its size class. A
reclaimed frame's descriptor node is rewritten into the run's node in place, so
reclamation never allocates and cannot fail. When the arena has no free node
outside its reserve (below) and the pool cannot fund an arena page, the returned
run funds it itself: its first page (all of it, for a one-page run) becomes the
arena page. When that carve fails (both arena zones are spent, the split of its
first page fails, or the page cannot be mapped because memmgr's page tables
cannot be funded), the run takes a reserved node; when the split of its first
page cannot be merged back, the remainder takes the reserved node before the
head page. A run a growth path takes from the pool and cannot use goes back
without growing the arena: merged back into the remainder its split left, else
into a free node, the reserve included. A run stays owned and counted in
`pool_total` but out of circulation only when it reaches the reserve with the
reserve already spent and the arena unable to grow.

---

## Allocation

`REQUEST_MEMORY_CAPS(want_pages, flags)` first admits `want_pages` against the budget node the grant
is charged to, the caller's own or, with `REQUEST_CHARGE_NODE`, the handle's (§ Distribution
policy): a request over the max of the node or of an ancestor fails `LIMIT`, and one that would
leave fewer free pages outside `promised` ([Commit](#commit)) than the growth floor (the system
reserve and, while chunks are swapped, the restore headroom; § Distribution policy), charged to a
node outside the reserve, or than none, fails with the out-of-memory code of its flags, before any
run leaves the pool. An admitted request then selects:

1. **`REQUIRE_CONTIGUOUS` set.** Select a run that covers `want_pages`
   by the size-class fit (§ Free-Pool Data Structure). On hit: detach
   the run, split off exactly `want_pages` via `memory_split` if the run
   is larger than requested, return one Memory cap. On miss, or if the
   split fails: return `OUT_OF_MEMORY_CONTIGUOUS`. memmgr does not
   migrate live pages to produce a contiguous run; coalescing is the
   only mechanism that restores contiguity.
2. **Best-effort.** First try a single run that covers `want_pages`
   whole, chosen as for `REQUIRE_CONTIGUOUS`. One run is the fewest possible
   caps, and the size-class fit reuses a freed run of the requested size
   instead of re-splitting a larger one (the latest freed run of a class is
   its first), so a workload that repeatedly frees and
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

The kernel clears the run through its direct map: memmgr calls `SYS_MEMORY_ZERO` on the run's
capability, again from where a call stopped until every page is zero
([core/kernel/docs/syscalls.md](../../../core/kernel/docs/syscalls.md#sys_memory_zero-79)
§ `SYS_MEMORY_ZERO` (79)). The clear maps nothing into memmgr's address space, so it takes no page
table and unmaps nothing. A zero frame of the zero object ([Memory objects](#memory-objects)) is
cleared the same way when memmgr takes it.

When the kernel refuses the zero, memmgr keeps the run: a grant goes back to the pool whole and the
request fails with `QUOTA`, and a demand fault's run goes back to the pool and the fault is
declined with code 9 ([`ipc-interface.md`](ipc-interface.md) § Kernel-origin fault message).

The clearing costs one `SYS_MEMORY_ZERO` call per run, the kernel's stores over its pages in its
16-page batches. The ubench suite's `ubench.fault_fill` lines report the cycles of a 16-page demand
fault and of a grant-and-map of the same size, the measure of a change to that work
([services/ubench/README.md](../../ubench/README.md#benchmarks) § Benchmarks).

**Copy window.** A run memmgr writes whole before it hands it out needs no clear. memmgr writes
such a run, and the pages of a Memory capability a request carries for memmgr to write into,
through a copy window of 512 pages in its own address space (2 MiB, the span of one leaf page table,
at a base aligned to it): it maps the pages read-write there, writes them, and unmaps them again.
Five request paths map the window, and no other does:

- a write fault in a private attachment of an object, and `MAKE_PRIVATE`, which gives a page as
  that fault does: the copy of the object page ([Memory objects](#memory-objects), Faults);
- `FILL_REGION`: the copies of an object's pages that back the caller's pages (Memory objects,
  Read and fill);
- `OBJECT_READ`: the caller's destination pages (Memory objects, Read and fill);
- `CAPTURE_CHUNKS`: the destination pages procmgr's request carries
  ([`ipc-interface.md`](ipc-interface.md) § Label 31: `CAPTURE_CHUNKS`);
- a restore of a compressed or on-disk chunk: each new run ([Eviction](#eviction)).

memmgr funds the window's leaf page table at startup, before its first receive, while the pool is
full: it maps one free page there, unmaps it, and returns the page to the pool. A plain unmap keeps
the table, so no copy funds page tables, a restore under memory pressure among them, which the
restore headroom ([Eviction](#eviction)) counts no page-table page for. Should the startup map
fail, the first copy funds the table from the free pool, as every map into memmgr's own address
space does ([Metadata Arena](#metadata-arena)). The
window holds a run only while memmgr writes it, and no other process can read memmgr's address
space. Each unmap of the window invalidates its leaves on every CPU that runs memmgr's address
space before it returns.

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
  `REGISTER_PRESSURE` gave, with the bits it is signalled with on a change
  of level and on an opening of the draw room
  ([Memory pressure](#memory-pressure)), the head of the list of node
  handle states and memory objects the process owns
  ([Memory objects](#memory-objects)), and the head of the list of the limit
  registrations it made and of its donation-end registration
  ([Distribution policy](#distribution-policy)), and
  the count of its pages that are swapped ([Eviction](#eviction)), all of
  which go with the record.
- The next region id: a sequence from 1 that numbers the process's grants.
  Each grant's frame node keeps its id, which no later grant of the process
  reuses; bootstrap arenas and demand-fault runs carry none.
- The index of its budget node (§ Distribution policy), to which every run on
  the record and on its regions' chunk tables is charged, but a grant charged
  to a node handle's node, whose frame node names that node instead. The three boot
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
constant. Records are found by badge, and node handle states and memory objects by the key their
handles carry, through one linear-hash index: a bucket array of arena indices, in its own window of
memmgr's address space, that grows one page of buckets at a time from the pool. Linear hashing
splits one bucket per step once the mean chain length passes two, so the array only ever appends and
lookup stays constant-time on average; when the window is spent, buckets stop splitting and chains
lengthen, which costs lookup time and bounds no capacity. A fault and a request for memory move
their caller's record to the head of its chain as they find it, so a process's repeated faults and
grants read one slot of the chain whatever records the badges of the boot placed before it. The
window's base is fixed, not drawn per boot like the arena's: the array holds only arena indices.
`REGISTER_PROCESS` returns `TOO_MANY_PROCESSES` only when the record's node, its caps node, its
budget node or, when procmgr asks for a node handle, its handle state cannot be allocated: system
RAM is exhausted.

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
in parts, each part one run and one frame record. A fault in an uncommitted region is therefore
declined for want of RAM (code 7, [`ipc-interface.md`](ipc-interface.md) § Kernel-origin fault
message) only when the free pool holds no page, when every free page is in the growth floor (the
system reserve and, while chunks are swapped, the restore headroom) and the process's node is
outside the reserve, or when the split of a run larger than the pages to back fails. A fault in a
committed region is declined with code 7 only for that failed split; when its draw finds no page,
even after memmgr evicted victims in its turn, it is declined with code 11 ([Commit](#commit),
Overcommit). A fault on an evicting or raw chunk maps its runs back, and one on a compressed chunk
first makes the chunk resident, a restore with its own admission ([Eviction](#eviction)).

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
  mapped in the process; evicting; compressed; raw, its runs held unmapped on the entry's run list
  until the swap service takes them for a slot; writing or on disk, its pages taken by the swap
  service ([Disk tier](#disk-tier)); or lost, its swap slot's bytes having failed authentication.
  A raw flag marks a chunk held raw, from then until it is resident again or lost.
- A pin flag and a two-bit age.
- The job slot of its eviction while it is evicting, so a completion is applied only to the
  eviction it was posted for.
- A link: the head of the chunk's run list while it is resident, evicting or raw, and while a raw
  chunk is writing; the head of the list of store runs its pages are stored in while it is
  compressed, and while a compressed chunk is writing.
- Its disk node while it is writing or on disk, and, over the same time, the tag of a raw chunk's
  seal ([Disk tier](#disk-tier), Write-out).

The evicting, compressed and raw states, the pin flag, and the age are the swap path's: memmgr
reclaiming a cold chunk's runs under memory pressure and storing its pages, a fault restoring them
([Eviction](#eviction)); the writing, on-disk and lost states are the disk tier's. A fault on an
evicting, compressed, raw or writing chunk makes the whole chunk resident before it backs anything,
so a resident chunk's every backed page is mapped; a fault on a chunk on disk is redirected to the
swap service, and one on a lost chunk is declined.

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
[Reclamation](#reclamation)), returns each store run of a compressed chunk, writing or not, which no
process ever mapped, to the free pool, retires each run of a raw chunk, writing or not, as a
resident chunk's runs, frees an on-disk chunk's swap slot and disk node, cancels a writing chunk's
write ([Disk tier](#disk-tier)), and returns every directory and leaf node to the arena's free list.

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
funds the pool itself and maps the run again, at most four times for each leaf-table window of the
run, as it maps its own pages ([Metadata Arena](#metadata-arena)); a run lies in one window unless
it crosses a 2 MiB boundary:

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
their budget nodes and the nodes' reclaim states, node handle states, their holder links and limit
registrations, per-process frame and region descriptors, and the regions' chunk tables — is
nodes drawn from a self-hosted arena rather than fixed `.bss` arrays. memmgr
is `no_std` and cannot bootstrap
a general heap against itself, but it *can* host fixed-size nodes in pages
carved from its own pool:

- Nodes are fixed-size `Slot`s (a tagged run, deferred run, budget, reclaim state, process,
  process caps, node handle, holder link, limit registration, memory object, region,
  commitment, frame, chunk-directory, chunk, or free payload plus a `next`
  index)
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
a per-boot drawn base (ASLR) up to the object zone, the 64 GiB below the lowest
bootstrap window `shared/process-layout` draws where memmgr maps its own view of
the memory objects' frames ([Memory objects](#memory-objects)), past the std heap
and reservation-arena zones, which memmgr, having no std runtime, does not use.
The high zone continues above the shared 2^38 layout ceiling and exists only where the boot's paging
mode has a wider user half (x86-64 4- or 5-level paging, Sv48, Sv57); under Sv39 the
kernel refuses the map and the arena ends with the low zone, which outlasts any
RAM such a machine holds. Growth stops when neither zone has a page left or RAM
is exhausted, surfaced as `QUOTA`.

Each page memmgr maps in its own `AddressSpace` (an arena or index page, a page of a window it
clears or copies through, its own view of an object's frames) can need new page-table pages there,
taken from the page-table pool init seeds at creation. When the kernel reports that pool
exhausted, memmgr funds it from its own free pool: it donates a contiguous run of
`ASPACE_TOPUP_PAGES` (4) frames, or two when no such run is free, with augment-mode
`cap_create_aspace` against its own `AddressSpace`, deletes the frame's cap (the donation holds
its own reference), and retries the map. memmgr makes each map one leaf-table window at a time,
the 512 pages (2 MiB) one leaf page table maps under every paging mode, and funds each window at
most `PT_FUND_ROUNDS` (4) times. A window needs at most one new page table for each level below
the root, four under 5-level paging and Sv57, and a donation adds at least one, so a map of any
length, the own view of a grant that spans many leaf tables among them, maps while the pool can
spare its page tables. The bound stays for the map a donation does not cure: the kernel also
refuses a map with `OutOfMemory` for a frame already named by `u32::MAX` mappings, and without a
bound memmgr would turn its free pool into page tables no map uses. The window that fails ends its
map, which then unmaps every page it mapped, so a failed map costs at most four donations and
leaves none of its span mapped. Like arena pages, donated frames leave the free pool for good and
stay in `pool_total` as memmgr-owned metadata.

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
([Commit](#commit)). `QUERY_POOL_STATUS` reports the metadata's pages, the arena's, the index's,
the swap slot map's, the zero frames and the pages retyped into memmgr's own kernel objects, as
`metadata_bytes` ([`ipc-interface.md`](ipc-interface.md) § Label 6).

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

## Receive loop

memmgr serves with `SYS_IPC_REPLY_RECV`: a handler leaves its reply in an `ipc::serve::Reply` slot
and does not send it, and the reply goes out with the loop's next receive, so the receive that
follows a reply is the one the kernel's prediction of a serving receiver reads, and a fair or
lower-RT caller that is not pinned can be placed on memmgr's CPU (core/kernel/docs/scheduler.md §
Thread Assignment). A turn runs from one receive's return to the next receive, in this order:

1. **The request.** The handler applies the request and sets the reply, or a request that took no
   effect sets its refusal.
2. **Retire objects.** The objects the request queued are freed (§ Memory objects, Release).
3. **Limit signals.** The limit event of each node the request's charge marked is sent
   (§ Distribution policy).
4. **Eviction.** The compression jobs the worker marked done are drained, and a slice of the clock
   runs when one is due (§ Eviction).
5. **`CSpace` top-up** (§ CSpace headroom).
6. **Pressure signal.** The level and the draw room are recomputed, and every registrant signalled
   on a change (§ Memory pressure).
7. **The receive**, which sends the reply still set, waiting a bounded time while the clock runs or
   a job is in flight (§ Eviction); a turn whose earlier send bound a call (below) makes none, and
   that call is the next turn's request.

A turn that received no message (the bounded wait ended, or the receive failed) runs steps 4 to 7,
and one whose receive failed skips step 4, so that the top-up before the retry is what refills a
spent receive reserve (§ Reclamation).

**Work in front of a reply.** Each of steps 2, 4, 5 and 6 first checks whether it has work to do,
and a step that has sends the reply before doing it, with a receive that does not wait
(`SYS_IPC_REPLY_RECV` at `WAIT_TRY_ONCE`), so no caller waits for a freed object's teardown, a
drain, a clock slice, a donation or a broadcast. A plain `SYS_IPC_REPLY` would not do: a caller the
call placed on memmgr's CPU, which memmgr outranks, would have its reply wake queued there behind
memmgr until it parks, while the reply of a `SYS_IPC_REPLY_RECV` whose receive does not park wakes
the caller off memmgr's CPU (core/kernel/docs/scheduler.md § Thread Assignment). A call that receive
binds is the next turn's request, served once the turn's work is done, which it would have waited
for in the endpoint's queue in any case. The checks are: an object queued for retirement; a job slot
marked done, or a clock slice due (the clock runs and `SWEEP_INTERVAL_US` has passed since the
last); the headroom or the growth budget low enough to call for a top-up; a change of the level or
an opening of the draw room. A reply that rides the receive therefore waits behind the request's own
handling and, past it, only these checks (an atomic load per job slot, a clock read while the clock
runs, the three `cap_info` reads of the headroom, and the pressure computation) and step 3's sends,
one Notification send per node of the charged chain that is at its limit or refused the charge,
which never block. A job the worker finishes after step 4 looked is drained by the next turn: the
receive waits a bounded time while a job is in flight. A turn that sent its reply before its work
ends in a plain receive, or in none when that send bound a call, so after a plain receive the kernel
predicts no serving receiver for the next caller; such turns are those that do memmgr's background
work.

**A reply not delivered.** The kernel wakes a caller that is gone, or whose `CSpace` cannot take a
reply's caps, with a transfer failure instead of the reply, and moves none of the reply's caps. Each
request whose effect would stay charged, or stranded in memmgr's `CSpace`, when its caller does not
learn of it leaves beside its reply the undo of that effect, which runs as soon as the send that
carried the reply returns, before memmgr reads the ledger for anything else: a grant's frames and
runs and inner derivations (`REQUEST_MEMORY_CAPS`), a registration and its caps
(`REGISTER_PROCESS`), a committed region (`REGISTER_REGION`), a region's growth (`EXTEND_REGION`),
an attachment and the zero frame it took (`ATTACH_OBJECT`), a node handle (`NODE_CREATE`,
`CREATE_SUB_NODE`), and a sealed object and its handle (`SEAL_OBJECT`). A reply whose caps memmgr
keeps no use for, a charge-only handle (`NODE_CHARGE_HANDLE`) or the buffer a disk-tier request
hands back (`SWAP_TAKE`, `SWAP_RESTORE`), deletes them when it is not delivered. Nothing faults in,
maps or names what the undo takes back first: memmgr serves one message at a time, and between a
handler and the send of its reply run only step 3's sends and the other steps' checks, since a step
with work sends the reply first. They can count the effect: a limit event sent in that span can
count a charge that the undo then takes back, at worst one signal more than the ledger then shows.
The pressure step, whose broadcast reaches every registrant, reads the level and the draw room again
after a send it made, so it signals the ledger past the undo.

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
memmgr-owned metadata, so the all-RAM-accounted identity is unaffected. Nothing bounds the growth
but the pool, so a cap memmgr kept by mistake would not wedge its receive loop; it shows instead in
its used slots, which `QUERY_POOL_STATUS` reports in `data[19]`
([ipc-interface.md](ipc-interface.md) § Label 6).

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
rest of the turn up to the next receive, the `CSpace` top-up among it (§ Receive loop). A handler's
recheck at entry therefore always runs, and so does the top-up's before a failed receive's retry,
which is what refills a spent receive reserve.
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
3. Send the donation-end Notification of each process holding grants charged
   to the node of a node handle state the record owns
   ([Distribution policy](#distribution-policy)), drop those states and the
   memory objects the record owns ([Memory objects](#memory-objects)), then
   remove the per-process record
   from the index. If absent (untracked badge), skip to step 6 — the death
   notification is idempotent.
4. For each frame node in the record's frame list and on the run lists of
   its regions' chunk tables, rewrite the node into a run of the retained
   Memory cap and insert it into the free pool at its sorted position when
   the frame is quiescent, else onto the deferred list (no fresh node, so
   the step cannot fail).
5. Return every chunk-table node, every region node, the commitment node of
   each committed region, the record's own node, and its caps node to the
   arena free list, and drop the record's reference
   to its budget node, which is freed with it unless a node below it refers
   to it, or a deferred run, a grant another process holds or a memory
   object's frames are still charged to it.
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
with size-class selection (above), this bounds the pool's run count
under long spawn/free/die churn, and with it the per-run tracking anchor
memmgr holds in its own CSpace: the size-class fit keeps a fixed-size churn cycling
one
run, and the explicit merge keeps residual fragmentation from drifting the run
(and anchor) count up over time. Left un-coalesced, reclaimed runs stay
discrete and their anchors persist, slowly consuming memmgr's CSpace and arena
even while its RAM footprint stays bounded. A reclaimed run whose source
`MemoryObject` still holds a live retype would decline `memory_merge` (the
kernel requires a virgin tail; see
[`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_memory_merge-50)
§"`SYS_MEMORY_MERGE`"), but such a run waits on the deferred list, not in the
pool (see [Reclamation](#reclamation)), so every pooled run is virgin.
Coalescing cost scales with the live run count, which the size-class fit and this pass
jointly keep small, so the per-reclamation merge is negligible.

The physical-order list holds the runs sorted by base, so mergeable runs are list
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
process while a node below it is alive, a run charged to it is on the deferred list, a grant another
process holds is charged to it (Node handles, below), or a memory object's frames are charged to it
([Memory objects](#memory-objects)), and its charge stays in its
parent's subtree meanwhile, so a process cannot hand its frames to another
process, die, and free its subtree's budget while the frames stay held.

**Charging.** A charge is checked against the max of the node and of every ancestor. A request that
would take a subtree over its max fails with `LIMIT`, distinct from the out-of-memory codes of
system exhaustion. A demand fault first shortens its run to what the max allows, and is declined
with code 10, distinct from code 7, only when the max admits not even the faulting page (and the
least page-table donation its map needs), or, on a chunk memmgr is evicting, holds raw or evicted,
not the donation the map of the chunk's runs needs ([Eviction](#eviction)), so a crash report tells
a budget kill from an exhaustion kill ([Demand faults](#demand-faults)). Lowering a max reclaims
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
A sub-node (`NODE_CREATE`, `CREATE_SUB_NODE`) is outside the reserve unless its creator asks with
`SUB_NODE_RESERVE`, which memmgr honours only under a reserve parent and with a finite max: the max
bounds what the sub-node's subtree can take of the reserve, and `NODE_SET_MAX` may lower it but
never raise it, so what one sub-node's subtree can take of the reserve is at most the max its
creator stated. A reserve sub-node may make reserve sub-nodes of its own on the same terms, each
inside its max. The flag is a decision of the creator of each sub-node: procmgr sets it for the
one-page node of a read session charged to a reserve account (the create of a reserve service, or a
`READ_VERIFIED` of a reserve sender), so a reserve service's restart is backed from the reserve as
its own pages are ([services/procmgr/docs/ipc-interface.md](../../procmgr/docs/ipc-interface.md) §
Label 13, **Read session**); every other sub-node in the default image, sessiond's session nodes
among them, is made without it and stays outside the reserve, since what a session's users charge is
not the recovery the reserve keeps memory for. The nodes of memmgr's boot records (procmgr's, and
memmgr's and init's own) and of init's children (devmgr, vfsd and svcmgr) are reserve nodes, and so
is the node of a process created with procmgr's reserve creation flag (`CREATE_RESERVE`), which
procmgr honours only from a reserve creator, as it does `CREATE_PHYS_ACCESS`. A process a reserve
creator creates without the flag is outside the reserve, so svcmgr's services are outside it unless
the recipe's `reserve = yes` has svcmgr pass the flag, as oomd's, sessiond's, crashd's and logd's do
([services/svcmgr/docs/service-definitions.md](../../svcmgr/docs/service-definitions.md) §
`reserve`). The reserve is `pool_total / 64` ([docs/limits.md](../../../docs/limits.md) § memmgr).

**Create-time ceiling.** procmgr registers each process with its creator's node as the parent (a
child of init is a top-level node: init's own record holds only init's bootstrap arenas and parents
no process) and, when the creator asks for one with `CREATE_MEMORY_MAX`, a max in pages. memmgr
clamps the max to what the parent and every ancestor have left, and refuses a reserve node under a
parent outside the reserve; procmgr relays the max the node took to the creator in the create reply
([services/procmgr/docs/ipc-interface.md](../../procmgr/docs/ipc-interface.md)
§ Label 1, **Memory max and reserve**). A process reads its node's usage, its max and its subtree's
usage with `QUERY_MEMORY_USAGE`.

**Server-side charges.** Memory a server spends on a client's behalf is charged to the server's
node, not to the client's. procmgr keeps, for each live process, its process-table entry (448
bytes), 6 to 13 capability slots in procmgr's `CSpace` (72 bytes each) and two death-observer nodes
(40 bytes each), about 0.9 to 1.8 KiB with the growth of their containers, and 96 bytes for each
thread it registers. Every page of the process itself, at least 55 (its address-space and `CSpace`
slabs, its thread, its `ProcessInfo` page and the rest of its image), is requested on its own
account and charged to its own node, in its creator's subtree, so procmgr's share is at most 0.85%
of what that node pays, and it goes with the process. A create the max of the child's node or of an
ancestor refuses fails with procmgr's `LIMIT`
([services/procmgr/docs/ipc-interface.md](../../procmgr/docs/ipc-interface.md) § Label 1, **Memory
max and reserve**). vfsd keeps no per-client state: the capability a lookup derives leaves with its
reply. A server can charge such state to its client instead, with a grant charged to the node of a
charge-only handle the client hands it (Node handles, below). fatfs does so for a filesystem session
([services/fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md) § Label 23): the
records of the session, of each open made in it (128 bytes) and of each page such an open holds
mapped (64 bytes) live in pages charged to the session's node, the first held for the session's life
and each later one given back when its last record goes, and a session or an open the node's max
refuses fails with fatfs's `LIMIT` while other clients' requests go on. What stays on fatfs's own
node is, for each session, about 0.35 KiB (three 72-byte capability slots and a 128-byte
Notification) against the 4 KiB first page the client pays; a 72-byte capability slot for each
further page; for each open in a session the 72-byte slot of its release SEND, and for each page
it holds the slot of the page's capability, each matched by the 72-byte slot the client's own
`CSpace` gives the capability it receives; and the index from ids to records, at most 8 bytes per
live session or open, which halves as they go. The page tables that map session pages into fatfs
stay at the most pages mapped at once, at most 8 bytes per page. fatfs refuses an open made without
a session, so a client can make fatfs spend on its own node only these slots and index entries, each
beside a record the client's node pays for. std makes one session for each filesystem driver a
process opens files on, charged to a sub-node of the process's own node with no max of its own, a
design decision: the process's node bounds what its sessions charge, and a fixed max would cap the
files the process can hold open whatever memory its creator granted it
([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Filesystem sessions). procmgr
makes one session for each image or `READ_VERIFIED` read, charged to a sub-node of the account the
read's buffer is granted on with a max of one page, a design decision too: that node is not
procmgr's own but the creator's, charged once per read, and one page holds the session, its one open
and the one page procmgr holds at a time
([services/procmgr/docs/ipc-interface.md](../../procmgr/docs/ipc-interface.md) § Label 13, **Read
session**).

**Node handles.** Authority over a node is a capability: a node handle, a SEND on memmgr's
endpoint badged with the node-handle verb bit and a random key that names one node
([ipc-interface.md](ipc-interface.md) § Node Handles). A holder sets the node's max
(`NODE_SET_MAX`), clamped to its usage plus what its parent chain has left, so a max set while
the process runs never exceeds what its ancestors allow and lowering it reclaims nothing, as
above; makes sub-nodes under it (`NODE_CREATE`), so siblings charged to one sub-node share its
budget; reads its usage (`NODE_QUERY_USAGE`); sets its floor and weight (`NODE_SET_RECLAIM`,
Floors and weights, below); and registers a Notification for its limit event
(`NODE_REGISTER_LIMIT`). procmgr hands a creator its child's handle on request
(`CREATE_NODE_HANDLE`), and charges a new child to the node of a handle the creator passes
(`CREATE_CHARGE_NODE`); a process makes sub-nodes of its own node with `CREATE_SUB_NODE`; no
process holds a handle to its own node, so none can raise the max its creator set. A node's
handle state, the key its handles carry and the index of its limit registration, is an arena node
named by the link of the node's reclaim state (Floors and weights, below) and found through the
record index by its key; it holds a
reference on its node. It belongs to a process: the node's own process, or for a sub-node the owner
of the node it was made under, or the process that called `CREATE_SUB_NODE`. It goes when that
process dies or, for a sub-node, on `NODE_RELEASE`; every handle carrying its key is refused from
then on, and the node itself lives on while a process, a node below it or a charge refers to it.
The limit registration, the Notification cap and its bits, is an arena node of its own on the list
of its registrant, the process whose memmgr SEND the request carried: it goes when the registrant
dies, when a later registration replaces it, or with the handle state, so no holder leaves a cap in
memmgr past its own life.

**Charged grants.** A holder of a node handle derives a charge-only handle to the node
(`NODE_CHARGE_HANDLE`), which serves only that and `NODE_QUERY_USAGE`, and hands it to a server;
the server charges a grant to the node by passing a copy with `REQUEST_CHARGE_NODE`
([ipc-interface.md](ipc-interface.md) § Label 1), admitted against the node's chain and refused with
`LIMIT` at its max. The grant's frame node stays on the server's record and names the node it is
charged to, so its release, and the server's death, return the charge to that node. The handle
state counts its holders: a holder link, an arena node on the state's list, names each process
holding grants charged to the node and how many frame nodes it holds, and goes when the last of them
returns or with the state. When the state goes, on `NODE_RELEASE` or at its owner's death, memmgr
sends the donation-end Notification of each process on that list (`REGISTER_DONATION_END`), a
registration with no handle state on the registrant's limit list, which goes with the registrant;
the charges stay on the node, which outlives the state while they do, inside its parent's subtree,
so neither the client nor the owner sheds them by releasing the node or dying, and no server holds
frames charged to no node. `SEAL_OBJECT` refuses a charged grant, whose charge an object, which
outlives its sealer, could not return.

**Floors and weights.** A node handle also sets the node's floor and weight (`NODE_SET_RECLAIM`,
[ipc-interface.md](ipc-interface.md) § Label 32), which divide eviction ([Eviction](#eviction))
between nodes; admission reads neither. Each node counts its subtree's evictable resident pages R:
the backed pages of the resident chunks eviction may take ([Eviction](#eviction), Eligible pages),
counted apart for uncommitted and committed regions, since a committed chunk is evictable only
while a swap service has registered slots (Committed pages there). Each change of a chunk into or
out of the resident state updates the counts of its record's node and every ancestor, as a charge
does. The floor is the hard guarantee: memmgr evicts no chunk, in the background or by direct
reclaim, that would take R of the node, or of an ancestor with a floor, below that floor. The
weight, 1 to 10000 and 100 for a node none was set on ([docs/limits.md](../../../docs/limits.md)
§ memmgr), is the soft preference: above its floor a node's reclaim rate is
`(R - floor) / (R * weight)`, or `1 / weight` with no floor, and 0 at its floor or below; the
rate of a process's chunks is the least over its node and every ancestor, so a floor or a weight
covers the node's whole subtree and the most protective of a chain holds. The clock visits each
node's records in proportion to that rate (Selection there), so it takes idle pages from a node in
proportion to `(R - floor) / weight`. With no floor or weight set every rate is equal, and the
clock sweeps every record every pass, as with no reclaim state at all.

A floor reserves nothing. The free pages it covers are free pages like any others until the
subtree's own pages take them, and a charge to any node is admitted against them as before. So when
every evictable page left lies under some floor, reclaim finds no victim and the out-of-memory path
decides (crashd's hold of a declined fault, oomd's stop of a job), as when nothing is evictable; the
all-RAM-accounted identity holds throughout, since a floor moves no page. No ancestor bounds the
floor or the weight set on a node below it: any process can already exempt every page of its own
from eviction with `REGION_NO_EVICT` ([ipc-interface.md](ipc-interface.md) § Label 7), so a floor or
a heavy weight gives a subtree nothing its processes could not take without one, and a floored page,
like a no-evict page, is charged and limited by the node's max and every ancestor's, which bounds
what either withholds from reclaim.

**Limit event.** After each request memmgr walks the chain from the node the request charged, or
whose max it set, to the top, and sends each node's registered bits on its Notification when the
node's subtree holds its max or more, or when the node's own max refused the request's charge. A
charge that brings a subtree to its max, each refused charge, and a max set at or below the usage
each send the bits once; a send never blocks, and the bits of sends not yet taken coalesce.

---

## Commit

A region registered with `REGION_COMMIT` is committed ([ipc-interface.md](ipc-interface.md) § Label
7). memmgr admits and charges its whole length when it registers it, and each growth by
`EXTEND_REGION` (§ Label 12) when it accepts that growth, so a refusal reaches the process as the
error reply of the call that asked, where it can fail an allocation, not as a fault, and a fault in
a committed region is declined only in the cases
[ipc-interface.md](ipc-interface.md#committed-fault-declines) § Committed fault declines lists, each
from a mechanism below (Faults, Overcommit). std's heap grows this way. It keeps its uncommitted
floor and registers one committed growth region directly above it on its first grow, which each
later grow extends, so a heap is two regions however large it grows and holds no Memory caps
([Userspace Memory Model § Byte Heap](../../../docs/userspace-memory-model.md#byte-heap)).

**Promised.** memmgr counts in `promised` what the committed regions can still take from the free
pool: for each, its pages that hold no frame yet, and what is left of its page-table reservation and
of a bound on the metadata its chunk table and run descriptors can take. Every admission reads the
free pages outside it, U: a grant, an uncommitted demand run and a page-table donation are each
admitted only when `U - F >= want`, with F the growth floor (the system reserve and, while chunks
are swapped, the restore headroom) for a charge to a node outside the reserve and 0 for a charge to
a reserve node ([Distribution policy](#distribution-policy)), and a committed registration or growth
as Overcommit below says. While the overcommit allowance is 0, which it is while no swap service has
registered a slot (Overcommit below), U is `free - promised`, so no charge takes a free page a
committed region's fault needs. `QUERY_POOL_STATUS` reports `promised` in `data[8]` and U in
`data[17]`, and the pressure level is computed from U ([Memory pressure](#memory-pressure)).

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
admission, as is one the map of a committed chunk's runs needs on its restore or when its eviction
is cancelled ([Eviction](#eviction), States): the donation's pages leave the reservation and
`promised`, and are charged once, as the donation. The address space's page-table pool is shared, so
any other mapping of the process can take the pages a donation leaves in it. Between two maps the
reservation covers the region's donations whatever those mappings take. The kernel keeps at most one
page of a donation for its bookkeeping, so each two-page donation adds at least one page, and a map
that still runs out after a donation needs more pages than the pool held: the donations of one map
take at most two pages for each page table it creates. The tables a committed region's maps create
lie in its span and stay until it is unregistered: memmgr unmaps a cut's pages, and a run whose
fault it declines in any region, without reclaiming page tables, since the kernel reclaims a table
once it is empty, whatever span emptied it, so only the process's own unmaps and its unregistering
of a region reclaim them. So they number at most `pool_funding::pt_pages_for` of its largest length,
which the `commit` module's host tests check against a pool that every other mapping empties between
two maps. Two cases, both of the process's own doing, spend the reservation faster: a thread of the
process that maps between two rounds of one map can take the donated pages first, which costs that
map a round and the reservation a donation, and a table in the region's span that a reclaiming unmap
the process made or asked for removed (its own unmap of pages in a span that shares the table, or
its unregistering of a region that shares it) is built again. A donation the reservation no longer
holds is admitted as any other, so the process's budget and the growth floor bound what it takes,
and the fault is declined with code 10 when the max refuses even that donation, or with code 9 when
the floor does. A committed fault is also declined, with code 9, when its map fails as any map can:
no two contiguous pages are free for a donation, or a thread of the process maps between the rounds
of one map and takes the donated pages faster than four rounds fund them. The arena's growth to
record a committed fault's run ([Metadata Arena](#metadata-arena)) is drawn from the region's
metadata bound as a donation is from its reservation, without admission: the pages the growth takes
from the pool, the arena page and any page tables memmgr's own map of it needs, leave the bound and
`promised`, so the free pages outside `promised` do not fall for metadata the commitment already
counts. Growth past what is left of the bound takes free pages outside `promised`, as an uncommitted
region's does.

**Overcommit.** An overcommit allowance A lets memmgr promise past its free pages. A commitment,
which takes no frame when it is made, is admitted when `free + A - promised - F >= want`; every
other admission takes its frames at once and reads U, the lesser of `free + A - promised` and
`free`, so the growth floor stays one of free frames, and so does the pressure level ([Memory
pressure](#memory-pressure)). A is derived from the swap tier ([Disk tier](#disk-tier)): a chunk's
pages for each free swap slot, since a slot takes one chunk, whose eviction and write free at most a
chunk's pages; less the pages the chunks evicted and not on disk (compressed, writing or lost)
already freed, their backed pages less their store pages, since each takes a slot for what is left;
plus the pages of the evicted chunks of committed regions, which `promised` holds again and which
the frames they freed or the slots they hold back: `A = 16 * free_slots - (swapped - disk - store) +
committed_swapped`. So an eviction moves a committed chunk's pages between tiers and leaves `free +
A - promised` as it was; a write spends what its chunk's slot holds no frame for, at most a chunk's
pages less one, so a partly backed chunk spends some of what A promised. `QUERY_POOL_STATUS` reports
A in `data[15]`. With no swap service registered no slot is free and no committed chunk is evicted,
A is 0, and every committed page has a free page held for it, short only of what memmgr's own
metadata, which takes free pages without admission, took. While a swap service has registered swap
slots (`Ledger::overcommits`; a registration is never withdrawn) a committed region's chunks, other
than an attachment's ([Memory objects](#memory-objects)), are evictable, and A can be spent to 0
(every slot taken, writes of partly backed chunks) with the pool still short of `promised`
([Eviction](#eviction), Committed pages): evicting one returns its runs to the pool and adds its
pages to `promised` again, since its restore draws from `promised` as its first touch did. A
committed draw, a fault in a committed region or a restore of a committed chunk, takes any free page
while no swap slot is registered; while one is, it takes only the pages above the growth floor for a
node outside the reserve, and any for a reserve node, whether or not the free pool covers
`promised`, since the allowance lets admission leave fewer free frames than `promised` and the
floor, and the frames that cover `promised` can then be the reserve's and the restore headroom's.
That is the draw room, which `QUERY_POOL_STATUS` reports in `data[16]` for a node outside the
reserve. So an overcommitted pool leaves the reserve to the reserve nodes and the restore headroom
to the restores of uncommitted chunks. While the free pool does not cover `promised`, or a
committed draw has found too few free pages since the draw room last opened, and the free frames
stand at or below the growth floor and the hysteresis band, memmgr evicts for frames in the
background ([Eviction](#eviction), Selection), so write-out to swap brings the draw room back while
the level stays `CRITICAL`. When a draw finds no page, memmgr also evicts victims in its turn
as a restore's direct reclaim does ([Eviction](#eviction), Direct reclaim), each evictable chunk
whose eviction frees a page above the growth floor (a committed chunk, or an uncommitted one once H
reaches R) for a node outside the reserve, any for a reserve node, never the one the fault backs, up
to the same bound; a fault's span is then clamped to the pages found, at least its faulting page. A
draw still short is declined with code 11, a commit overrun ([ipc-interface.md](ipc-interface.md) §
Kernel-origin fault message); with no swap slot registered that is a pool with no free page at all.
The draw room is open at a demand chunk's pages or more, room for any one committed draw, and memmgr
signals its opening to every `REGISTER_PRESSURE` registrant that gave bits for it ([Memory
pressure](#memory-pressure), Signal); crashd holds a commit overrun until then ([crashd Operation §
Hold](../../crashd/docs/operation.md#hold)). The turn that ends with the draw room open ends that
eviction, signalled or not, and another draw can close the room again before crashd reads it, so
`QUERY_POOL_STATUS` reports in `data[22]`, with the draw room in the same reply, whether a committed
draw has found too few pages since the room last opened. A held commit overrun that reads the room
short and that word 0 is re-asked: crashd resumes it, and memmgr backs it or declines it again,
which starts the eviction again. A decline of code 7 does not start it. The admission and draw
rules and A are the host-tested `free-pool` ledger's (`promise_free`, `uncommitted_free`,
`draw_room`, `frames_short` and `allowance`).

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
free chunks of a large freed block and cuts the free chunks at its top ([Userspace Memory Model
§ Byte Heap](../../../docs/userspace-memory-model.md#byte-heap)).

**Retries.** A committed registration or growth whose reply does not reach the caller is undone,
as a grant whose reply fails is rolled back, so a caller whose call was interrupted makes it again
and is charged once. A cut repeated finds the region at its new length and succeeds, and a discard
repeated finds no run in its range and succeeds.

## Memory objects

A memory object is an immutable set of frames that any number of processes map, each charged for
what it maps ([ipc-interface.md](ipc-interface.md) § Labels 27 to 29). The zero object is a
memory object of any length whose every page reads zero.

**Seal.** `SEAL_OBJECT` takes grants of the caller into a new object: memmgr moves the grants'
frame nodes off the record's frame list onto the object's, in the order the request names them,
which is the order of the object's pages. It seals only grants that pass the quiescence check
([Reclamation](#reclamation)), so no capability but memmgr's own reaches a sealed frame, no byte of
it is retyped and no address space maps it: no process can write a frame once it is sealed. memmgr
then maps its own view of the frames (Own view) before it records the seal. A
phys-class caller is refused, since a device it programmed may still write the frames. The frames
stay charged to the sealer's budget node, which the object names, until the object is freed;
procmgr seals the image objects the instances of a binary share on a record of its own, its image
store ([services/procmgr/README.md](../../procmgr/README.md#image-sharing) § Image Sharing). The
object is an arena node, found through the record index by the key of its handle
([ipc-interface.md](ipc-interface.md) § Object Handles) and listed on the sealer's record with its
node handle states ([Per-Process Tracking](#per-process-tracking)). A seal whose reply does not
reach the caller is undone: memmgr unmaps its view, and the frames go back onto the record's frame
list under their region ids.

**Own view.** From the seal until the object is freed, memmgr maps each frame of the object
read-only into its own address space, at a span of its object zone that holds the object's pages in
their order, and records each page's address there in the frame's descriptor. The object zone is 64
GiB of memmgr's address space just below the lowest bootstrap window `shared/process-layout` draws,
so it exists under every paging mode, Sv39 included ([Metadata Arena](#metadata-arena)). Its spans
come from a free pool of their own, which takes a span that holds an object's pages by the same
size-class fit and merges a span given back with its free neighbours. A seal that finds no span is
refused with `QUOTA`, and one whose map fails with `OUT_OF_MEMORY_BEST_EFFORT`, the part already
mapped unmapped and its span given back. The view serves two ends. memmgr copies an object page for
a private write, or for `MAKE_PRIVATE`, from it (Faults). And it is a leaf of each object frame that
no process holds, so every object frame a process maps has at least two leaves: the kernel refuses a
text write of `SYS_THREAD_WRITE_MEM` with `InvalidState` on a read-only page whose frame is mapped
more than once ([docs/fault-handling.md](../../../docs/fault-handling.md) § Debugging), which keeps
a holder of a process's thread from patching, through an executable attachment, a frame other
processes map (Attach, Make private). The view's page tables are memmgr's own, taken as an arena
page's are ([Metadata Arena](#metadata-arena)), about one page per 512 pages sealed at once, and
kept for reuse when a view is unmapped.

**Release.** `OBJECT_RELEASE`, or the sealer's `PROCESS_DIED`, drops the object's handle state:
its key leaves the index, so every handle is refused from then on. Each attachment holds a
reference on the object, and the object is freed when it has neither. The request whose turn takes
the last of them away, whichever it is, queues the object, and memmgr frees every queued object
after the turn's handler returns: it unmaps its own view, gives the span back to the object zone,
and then each frame retires through
the quiescence check as a reclaimed frame does, pooled and uncharged from the sealer's budget node,
or deferred and still charged to it ([Reclamation](#reclamation)). A charge keeps a budget node
alive, so the node outlives the sealer while the object's frames are charged to it.

**Attach.** `ATTACH_OBJECT` registers a region whose pages are the object's, from a first object
page on, or the zero object's. An attachment is a committed region whose commitment names its
origin ([Commit](#commit)), and is charged as a committed region of its length is, its pages and
its page-table reservation, so a process pays for every page it maps however many others map it.
A private attachment is admitted and promised as a committed region is, since a write to each of
its pages can take a page. A shared one is never writable and takes no page but its page tables
and the copies `MAKE_PRIVATE` gives it (Make private): its pages count against the max of the
budget node and its ancestors, and only its page-table reservation against the free pages outside
`promised`, so `promised` holds that reservation and no data page or metadata bound for it but
those copies. An attachment is never evicted, and is never resized or
discarded, since its pages are its object's; `UNREGISTER_REGION` and `PROCESS_DIED` detach it
and release its commitment as a committed region's (Commit, Shrink and release), a shared one's
holding no data page. An object's attachment may be executable, but never writable and executable
both, as a region may not be. An executable map needs a capability with the execute right, and a
leaf mapped through one lets a text write of `SYS_THREAD_WRITE_MEM` change its frame while no other
leaf maps it
([core/kernel/docs/memory-internals.md](../../../core/kernel/docs/memory-internals.md#leaf-grant)
§ Leaf Grant): memmgr's own view is that other leaf for every object frame (Own view), so the write
is refused while the page maps the object's frame. A zero-object attachment is never executable,
since no view of memmgr's maps a zero frame.

**Faults.** A read fault in an attachment, or a fetch fault in an executable one, maps its origin
read-only, and executable in an executable attachment, over the part of the faulting page's chunk
that no write has given a page of its own ([Chunk table](#chunk-table)): the object's pages there
that the frame holding the faulting page holds, in one map, or its zero frame at each page. memmgr
maps them through a capability it derives from its own with the map right alone, and the execute
right for an executable attachment, and deletes after the map; the kernel keeps the mapping. A leaf
records the write and execute rights of the capability it was mapped through as its grant (§ Leaf
Grant), so no leaf of an origin carries write, and `SYS_MEM_PROTECT` cannot make a frame others map
writable; a text write, which an executable leaf's grant admits, the frame's other leaves refuse
(Own view). A write to a private attachment gives the faulting page a page of its own, drawn from
the commitment as a committed region's fault draws its run (Commit, Faults) and recorded on its
chunk as any run is. For an object it is one page: memmgr maps the page at its copy window ([Frame
contents](#frame-contents)) and copies the object page into it from its own view, which leaves no
byte to clear, unmaps the page's read-only leaf from the process, and maps the copy with the
region's protection. For the zero object it is the span a committed region's fault backs, zeroed,
mapped once memmgr has unmapped the span's leaves of its zero frame. The unmap invalidates each leaf
on every CPU before it returns, so no thread of the process reads the origin through a stale entry
at a page that is then mapped writable. A write to a shared attachment, and a fetch from one that is
not executable, is declined as its protection refuses it ([ipc-interface.md](ipc-interface.md) §
Kernel-origin fault message).

**Mapping bound.** The kernel counts the leaves that map each frame in a `u32` and refuses a map
that would take the count past it (core/kernel/docs/memory-internals.md §
[Frame Map Table](../../../core/kernel/docs/memory-internals.md#frame-map-table-mmframe_maprs)),
so a frame many address spaces map must stay under that count, or one attacher could make
another's read fail. Each attachment maps a page of its origin at most once. An object takes at
most `OBJECT_MAX_ATTACHMENTS` (2^31) attachments at once, and memmgr maps an object frame itself
once, in its own view (Own view), so an object frame carries at most 2^31 + 1 leaves. Each
zero-object attachment maps one zero
frame, which backs at most `ZERO_FRAME_SPAN` (2^31) pages of the attachments it is chosen for:
memmgr chooses the fullest whose span still takes the attachment's pages, and takes a new one only
when none does; a detach gives its pages back to the span. An attachment past either bound, an
object attached `OBJECT_MAX_ATTACHMENTS` times or a zero-object attachment longer than
`ZERO_FRAME_SPAN` pages, is refused with `LIMIT` ([ipc-interface.md](ipc-interface.md)
§ Label 28); a longer zero region is attached in several attachments.

**Make private.** `MAKE_PRIVATE` ([ipc-interface.md](ipc-interface.md) § Label 30), which procmgr
sends for a holder of its debug authority, gives each page of a range of a process's attachments
that still maps its origin a page of its own: the page a write fault in a private attachment
gives it (Faults), a copy of the object page or a zeroed page for the zero object, mapped with the
region's protection and recorded on its chunk. A debugger asks for it before it writes a
breakpoint into text the process maps from an object: the write is refused while the page maps the
object's frame (Own view), and once the page is the process's own it patches the process alone. A
private attachment promised its pages when it attached, and the copy draws one of them. A shared
one promised none, so each copy first promises a page, admitted as a committed region's pages are
against the free pages and the overcommit allowance outside `promised`, less the growth floor
outside the system reserve ([Commit](#commit)), and the copy then draws that page, so `promised`
and the attachment's release stay exact. The charge does not move, since the copy lies inside the
pages the attachment is charged for. A copy is never evicted, as no page of an attachment is, and
is freed with its attachment.

**Read and fill.** `OBJECT_READ` ([ipc-interface.md](ipc-interface.md) § Label 35) copies pages of
an object whose handle the caller presents from memmgr's own view into Memory caps it presents,
mapped at the copy window only while the copy runs; a process with no pager, procmgr among them,
reads an object so. `FILL_REGION` (§ Label 36) backs pages of the caller's own demand regions, or of
its private zero-object attachments, with copies of an object's pages, as a write fault backs a
page: the run selection, the charge to the caller's budget node, the page-table funding and the
chunk record are the fault's ([Demand faults](#demand-faults)), with the copy from the own view in
place of the zero. A named page that holds data already is left as it is, so a repeated request,
after a failure part way or a lost reply, backs only the pages still holding none; a chunk the clock
has taken takes no run, and a request naming a page of it that holds no data is refused. The pages
are the caller's own, sharing no frame with the object, so the object can be released once the fill
replies.

**Checkpoint mark.** An object carries a checkpoint mark (`MemObject.checkpoint`) once procmgr's
`MARK_CHECKPOINT` (§ Label 37) sets it: procmgr marks the object it sealed from a complete
checkpoint of a quiesced process, presenting the account it sealed it on, and memmgr marks it only
when that account's badge is the record that sealed it
([docs/checkpoint-restore.md](../../../docs/checkpoint-restore.md#checkpoint) § Checkpoint). The
mark is set once, kept for the object's life, and read by `OBJECT_READ`; no label clears it.

**Zero frames.** A zero frame is a page taken from the free pool when no zero frame's span takes a
new zero-object attachment, which is refused when the pool cannot spare it, zeroed, and recorded
in an arena node on the ledger's list of zero frames. A request refused after it took the frame
gives it back to the pool; otherwise it is kept for memmgr's life and charged to no budget node,
as memmgr's metadata is. Since a zero frame is taken only when every other one's span is too full
for the new attachment, the zero frames grow only with the zero-object attachments standing at
once, each of which holds arena slots and page tables of its own.

---

## Memory pressure

memmgr tells processes how close the free pool is to the growth floor, so a process holding
memory it can give back (a cache) gives it back before a grant is refused. It acts on the level in
no other way: it only signals, and kills nothing.

**Levels.** The level is computed from the free pool's pages outside `promised` ([Commit](#commit)),
deferred pages excluded, against `pool_total`. It is `CRITICAL` at or below the growth floor, the
system reserve and, while chunks of uncommitted regions are swapped, the restore headroom (§
Distribution policy; § Eviction, Restore headroom), where a grant charged to a node outside the
reserve is refused; `LOW` below `pool_total / PRESSURE_LOW_DIVISOR` pages; and `NORMAL` otherwise. A
worse level applies at once. A better one applies only once the free pool clears that level's
threshold by a hysteresis band of `pool_total / PRESSURE_BAND_DIVISOR` pages, and at least one, so a
pool that hovers at a threshold does not flip the level on every turn: the level becomes the one the
free pool less the band gives, and no worse than before. The constants are tuning values
proportional to RAM ([docs/limits.md](../../../docs/limits.md) § memmgr); the computation is the
host-tested `free-pool` module `pressure`.

**Signal.** A process registers a Notification cap and the bits to send on it with
`REGISTER_PRESSURE` ([ipc-interface.md](ipc-interface.md) § Label 11), one mask for a change of
the level and one for an opening of the draw room, each in the low 32 bits so the two fit the caps
node; the std runtime registers every process at start, with a bit for each. The cap sits in the
record's caps node ([Per-Process Tracking](#per-process-tracking)), so a process holds one slot of
memmgr's `CSpace`: a second
registration replaces the first and memmgr deletes the cap the first carried. `PROCESS_DIED`
deletes the cap before it takes the process's frames back, since the cap keeps the Notification,
and the frame it was retyped from, alive ([Reclamation](#reclamation)).

Near the end of each turn of its receive loop, after the `CSpace` top-up and before the receive
(§ Receive loop), memmgr recomputes the
level and the draw room ([Commit](#commit), Overcommit), and sends each registrant, in one send,
its level bits on a change of the level and its draw-room bits on an opening of the draw room. The
send ORs the bits into the Notification and never blocks, so no client can hold memmgr, and bits not
yet taken coalesce: a registrant that wakes with its level bits knows the level changed at least
once, perhaps back to where it was, and with its draw-room bits that the draw room opened, and reads
the level and the draw room, which `QUERY_POOL_STATUS` returns in `data[7]` and `data[16]`. The
host-tested `free-pool` module `pressure` chooses the bits (`PressureBits`). A send that
fails, to a cap the client revoked, is dropped. The broadcast walks every record through the index,
a cost paid only on such a change.

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
([`ipc-interface.md`](ipc-interface.md) § Label 7); a page of a memory-object attachment
([Memory objects](#memory-objects)), since its pages are its object's or a zero frame's, which
other address spaces may map; or a page of a process with no delegated address space, whose
accessed bits memmgr cannot read. A spawned thread's IPC buffer is a grant
([Userspace Memory Model § Page
Reservations](../../../docs/userspace-memory-model.md#page-reservations)), and init, memmgr and
procmgr have no pager, so eviction never reaches a page the kernel's non-restartable IPC-buffer
copies use.

**Committed pages.** With no swap slot registered ([Commit](#commit), Overcommit), memmgr evicts
only uncommitted pages (thread stacks, heap floors, `register_demand_paged` regions): evicting an
uncommitted chunk frees its frames less the store pages its contents take, while evicting a
committed chunk adds its pages to `promised` again and only takes store pages from the free pages
outside it. While a swap service has registered swap slots heap pages are evictable too, and the
allowance counts an evicted committed chunk's pages again ([Commit](#commit), Overcommit). A victim
of background eviction at `LOW` must raise the free pages outside `promised`. While slots are
registered no eviction changes the pages a commitment may still promise: an uncommitted chunk's
pages take swap the allowance no longer offers, and a committed chunk's join `promised` again. So an
eviction then raises the free pages outside `promised` only while a chunk's pages more in `promised`
keep it within the allowance, where the free pool, not `promised`, bounds those pages. A restore of
an uncommitted chunk and a reserve node's committed draw take any victim, since they need free
frames alone; eviction for frames and any other committed draw take a victim whose eviction frees a
page above the growth floor (Selection, below).

**Selection.** While the pool's pressure level reads `LOW` ([Memory pressure](#memory-pressure)),
memmgr reclaims in the background until it reads `NORMAL`, and stops there. It also evicts for
frames: while the free pool does not cover `promised`, or a committed draw has found too few free
pages since the draw room last opened ([Commit](#commit), Overcommit), and the free frames stand at
or below the growth floor and the hysteresis band (or a demand chunk's pages, when the band is
less), it evicts in the background at either level, each evictable idle chunk whose eviction frees
a page above the growth floor a victim (a committed chunk, or an uncommitted one once the restore
headroom has reached the reserve), since the frames go to the committed draws, which `promised`
keeps them for or which wait for them, and to the restores. While the free pool covers `promised`
only the growth floor keeps a draw short, and a frame an eviction frees above the floor can go to
the next admission as well, so memmgr waits for a draw that found too few and stops when the draw
room opens. Otherwise it
does not reclaim in the background at `CRITICAL`: the free pages above the growth floor are gone, so
every frame an eviction frees past the restore headroom goes to the next admission, which a process
draining the pool makes before any victim faults. Eviction makes room for the processes that run
while memory is low; at `CRITICAL` only a restore or a committed draw evicts, for itself (Direct
reclaim, below), and the pool is otherwise left to the out-of-memory path (crashd's hold of a
declined fault, oomd's stop of a job). While the level reads `LOW` or `CRITICAL`, the receive loop
waits for a message a bounded time and, at most once per sweep interval, runs a slice of the clock:
a hand walks the eligible regions of each process in turn, a bounded number of steps a slice
([docs/limits.md](../../../docs/limits.md) § memmgr gives the interval and the bounds). It takes
the processes in the order of their badges, which no lookup of the process index changes, so a pass
sweeps each process once whatever faults and grants land between its slices, and a hand whose
process is gone goes on at the next badge; `SWAP_TAKE`'s hand (below) takes them in the same order.
A pass
sweeps the records of a budget node only as often as the node's reclaim rate allows ([Distribution
policy](#distribution-policy), Floors and weights): at its first record in a pass the node's credit
grows by its rate over the greatest rate of a node the previous pass found an idle chunk of, at most
by a whole sweep, and the pass sweeps the node's records when a whole sweep has built up, spending
it, and otherwise passes each over in one step, its accessed bits left for its next sweep. A node at
its floor or below is never swept, and when the previous pass found no idle chunk every other node
is. For each
span of up to 256 chunks it reads and clears the accessed bits with one `SYS_ASPACE_HARVEST`, and
ages each resident chunk of the span with its two-bit age ([Chunk table](#chunk-table)): a chunk
with no accessed page in two sweeps is cold, and the slice posts one job for each cold chunk whose
eviction raises the free pages outside `promised` at `LOW` (Committed pages, above), and for each
whose eviction frees a page above the growth floor while memmgr evicts for frames (Selection,
above), as many as the compression worker has free job slots. While memmgr evicts for frames, a
victim of that kind takes the place of one the slice found before it once the slice's list is full,
so the chunks a committed draw needs are not crowded out by those it does not. The victims a slice
finds and posts no job for are kept, a bounded number, for direct reclaim; when the list is full,
one whose eviction frees a page above the growth floor while memmgr evicts for frames takes the
place of one whose eviction does not; at `CRITICAL` a slice finds the chunks with no accessed page
in one sweep. A slice ends at the end of a pass, so no slice ages a chunk twice. The granule is the
chunk: one unmap and one restore fault per chunk, over every run on its run list.

**States.** memmgr unmaps a victim chunk with `SYS_MEM_UNMAP`, leaving its page tables, maps its
runs into the job slot's input window of its own address space, and the chunk is evicting while the
compression worker stores its pages. A fault on an evicting chunk maps the same runs back and
cancels the eviction: the job's completion is then stale, since the chunk's entry names the job slot
of the eviction in flight. Once stored, the chunk is compressed: its runs return to the free pool
and its entry's link holds the head of its store-run list. An all-zero page takes no store space,
and a chunk whose every page is zero takes no store page. A stream that would take as many pages as
the chunk's backed pages gains nothing. While the disk tier takes one (a swap service is registered,
and more of its slots are free than raw chunks wait for one), the chunk is then raw: its runs stay
on its entry, mapped nowhere, until the swap service takes it for a slot ([Disk tier](#disk-tier),
Write-out), and a fault on it maps the same runs back, as on an evicting chunk. Otherwise memmgr
maps the runs back, and the chunk stays resident. A raw chunk keeps its frames and their charge
until its write ends, and only then frees them and counts as swapped. A slot was free for each raw
chunk when it became raw, but `SWAP_TAKE` takes compressed and raw chunks in one walk and a new
registration can lower the slots, so a raw chunk can wait, its frames held, until a slot is free
again or a fault maps it back.

A fault on a compressed chunk is restored in the fault arm within the turn, since the restore is
bounded by one chunk's decompression. A restore is not admitted against the max of the node or of
any ancestor for its pages, since the node stays charged for its evicted pages; a page-table
donation its map needs is admitted as any other ([Client page-table
funding](#client-page-table-funding)), and declined with code 10 at the max or 9 at the growth
floor, unless the chunk is a committed region's, whose reservation carries it ([Commit](#commit),
Faults). A restore of an uncommitted chunk passes `F - R >= want` after the deferred recheck
([Distribution policy](#distribution-policy), System reserve), with want the chunk's backed pages
and R the system reserve for a node outside it and 0 for a reserve node. F is the free frames while
a swap service has registered slots, and otherwise U, the free pages outside `promised`
([Commit](#commit), Promised), the RAM test of an uncommitted demand run, so every promised page
keeps its frame. With slots, a restore takes frames and no promise, since the allowance offers again
the swap its pages took, and U can stand below the growth floor (Restore headroom, below). The test
reads R, not the growth floor, so the restore draws on the restore headroom. When the free pages do
not admit it, memmgr reclaims directly (Direct reclaim, below), and declines the restore with code 7
only when that does not make room, the chunk staying compressed and its store kept. A restore of a
committed chunk, which only registered swap slots let memmgr evict, is a committed draw instead
([Commit](#commit), Overcommit): it draws from `promised`, and is declined with code 11 when it
finds no frame. The chunk is the granule, so a restore is never clamped to part of a chunk. memmgr
takes runs covering exactly the chunk's backed pages (no run spans an unbacked page of a chunk
backed in parts), selected as a demand fault selects ([Demand faults](#demand-faults), run selection
only), maps the chunk's store runs at a stream window and each new run at the copy window of its
own address space ([Frame contents](#frame-contents)), and writes every byte of every page of each
run there before it maps the run into the process: it decompresses each stored page and zero-fills
each all-zero page. That full write replaces the hand-out clear of [Frame
contents](#frame-contents), so no byte of a run's earlier owner reaches the process. It then returns
the store runs to the free pool and resumes the thread. A stream that does not decode, which only a
corruption of memmgr's memory makes, declines the fault with code 9 and detail 0, the chunk staying
compressed.

**Direct reclaim.** A restore the free pages do not admit evicts victims itself, in its turn, before
it is declined: the kept victim of the greatest age first, checked again as resident, eligible,
unaccessed for at least one sweep, and above the floors of its node's chain, and its pages' accessed
bits read once more (`SYS_ASPACE_HARVEST`), since its age is the one the last sweep over it
recorded: a set bit resets its age and passes it over. So a chunk accessed or restored since the
last sweep is never taken and two processes cannot trade one chunk turn after turn. Any eligible
process's chunk may be taken, the faulting process's own included. For each, memmgr unmaps the
chunk, maps its runs at the input window of a synchronous slot of its own, compresses it into that
slot's output buffer with a hash table of its own, so it shares nothing with the worker, unmaps the
window, takes the store pages, writes the stream and swaps the chunk, whose runs return to the free
pool in the same turn; a stream that gains nothing keeps the chunk raw, or maps it back, as above
(States). It stops when the restore is admitted, or after a bounded number of victims
([docs/limits.md](../../../docs/limits.md) § memmgr), and the restore is then declined with code 7.
The store pages a victim takes can dip below the reserve for the rest of the turn, where no other
admission runs, and each victim kept leaves more free pages than it took. Only a restore and a
committed draw ([Commit](#commit), Overcommit) reclaim directly: a first touch of an unbacked page
of an uncommitted region grows its node's charge, and at the growth floor that growth stays the
out-of-memory path's, while a restore returns pages its node is charged for already and a committed
draw takes pages its commitment was charged and promised. Compression in the loop costs a restore's
turn at most that bound's compressions, on a fault that would otherwise be declined; background
eviction compresses in the worker, so its latency lands on no fault or grant.

**Restore headroom.** While chunks of uncommitted regions are swapped, a charge to a node outside
the reserve leaves a restore headroom H free above the reserve R: their swapped pages, and at most
R, so it is admitted when `U - R - H >= want` with `H = min(swapped - committed_swapped, R)`, and
the level is `CRITICAL` at or below `R + H` ([Memory pressure](#memory-pressure)). A restore of an
uncommitted chunk is admitted against R alone (States, above), so it draws on H; while slots are
registered it reads the free frames, since the allowance can bound U, and then the evictions that
raised H freed frames and left U where it was. A committed chunk's restore is a committed draw, from
`promised` ([Commit](#commit), Overcommit), so its pages raise no H. Without H, the frames
background eviction frees at `LOW` go to a process draining the pool, whose grants are never
victims, and by `CRITICAL` the evicted chunks of idle processes, a filesystem driver's thread stacks
woken by the pressure signal among them, find neither a free page nor a victim, and their faults are
declined. With H, the restores of up to R swapped pages find their frames whatever a drainer took,
and direct reclaim covers the rest. The cost falls on growth: each uncommitted chunk's eviction
raises H by its pages and frees them less its store pages, so eviction gives growth, and a committed
draw, no page until H reaches R; a committed chunk's eviction moves no H. A raw chunk moves neither
H nor the free pages until its write ends: mapping its own frames back needs none. With nothing
swapped H is 0, and every admission and level is as it is without eviction. H is at most R, a
sixty-fourth of the pool, so `LOW`'s threshold stays above `CRITICAL`'s. `QUERY_POOL_STATUS` reports
`R + H` as `growth_floor_bytes` ([ipc-interface.md](ipc-interface.md) § Label 6). The computation is
the host-tested `free-pool` function `budget::growth_floor`.

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
pages the compressed store holds. `QUERY_POOL_STATUS` reports each term, the records' pages as
`held_bytes` and the metadata's as `metadata_bytes`, so a page in none of them shows
([`ipc-interface.md`](ipc-interface.md) § Label 6). The worker's thread and Notification are
memmgr's metadata. A budget node stays charged for its evicted pages: a charge counts logical pages,
resident and swapped. A raw chunk's runs stay in its record's terms until its write ends.
`QUERY_POOL_STATUS` reports the store's size and the swapped pages' size, and `QUERY_MEMORY_USAGE` a
process's resident and swapped pages apart ([`ipc-interface.md`](ipc-interface.md)). The swapped
pages count every evicted chunk that holds no frame of its own: compressed, writing, on disk and
lost, a raw chunk once its write ends ([Disk tier](#disk-tier)).

*Debugger reads.** `SYS_THREAD_READ_MEM` fails on a page that is not present and does not ask the
pager
([`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_thread_read_mem-60) §
`SYS_THREAD_READ_MEM`). A debugger or crash service that gets that failure on a page of an evicted
chunk, or on a page of an attachment the process has not touched, asks procmgr, through the debug
authority, to make the range resident (`MAKE_RESIDENT`,
[procmgr's IPC interface](../../procmgr/docs/ipc-interface.md)); only a holder of the debug
authority may ask, and memmgr takes the request from procmgr alone
([`ipc-interface.md`](ipc-interface.md) § Label 21). memmgr restores each compressed chunk of the
range, and maps back each evicting or raw one; either counts as an access in the chunk's age. Over a
page of an attachment with no copy of its own it maps the origin, read-only, as a read fault does
([Memory objects](#memory-objects), Faults), which takes no page and no new charge. It walks only
the chunks that have an entry, and each chunk of an attachment, and one request makes at most a few
chunks resident and visits at most a bounded number ([docs/limits.md](../../../docs/limits.md) §
memmgr); its reply says where it stopped, and the reader asks again from there, so a request's turn
delays the faults and grants behind it no more than a few restores would. The reader then retries
its read. The request restores, maps and backs nothing else: a page of an ordinary region no fault
has backed stays not present, since a read fault there would take a fresh zeroed page. memmgr reads
no swap slot and waits on no swap service, so a chunk on disk it asks the swap service for: when the
swap service registered a want Notification, memmgr posts the chunk's slot word to a short list the
swap service takes (`SWAP_WANTED`), sends on the Notification, and replies that the range is pending
at that chunk; the swap service reads the slot and restores the chunk ahead of a fault, and the
reader, after a pause, asks again. After about a second of pauses a reader asks on from where
memmgr's walk stopped, past the chunks on disk, so a swap service that is down or cannot read the
slot leaves their pages not present and the rest of the range resident. A lost chunk, and a chunk on
disk with no swap service to ask, are passed over; a page of either stays not present
([Disk tier](#disk-tier)).

---

## Disk tier

A compressed chunk, or a raw one ([Eviction](#eviction), States), can leave memory for a swap slot
the swap service holds on disk
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

**Write-out.** `SWAP_TAKE` takes the next compressed or raw chunk: a hand over every process's
regions, walking only the chunks that have an entry, a bounded number of steps a request. memmgr
copies the chunk's stream from its store runs, or a raw chunk's backed pages in page order from its
runs, into a buffer of its own, seals it there, takes a slot and a disk node, and only then copies
the slot's bytes into the swap service's buffer, a Memory cap the request carries, which memmgr maps
itself at a window of its own address space. No memmgr frame leaves memmgr, and memmgr writes the
swap service's buffer through its own mapping, which neither faults nor blocks: a revoke of the cap
does not withdraw a mapping ([`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md)
§ `SYS_CAP_REVOKE`). One `SWAP_TAKE`'s time in memmgr's loop is bounded by that walk, one copy of at
most a chunk's bytes, one seal of them, and one copy of the sealed bytes, the order of a chunk's
restore. The chunk is then writing: its store runs, or a raw chunk's runs, stay on its entry until
`SWAP_DONE` ends the write. A written chunk is on disk and those runs return to the free pool, a raw
chunk's pages then counting as swapped; an unwritten one is compressed, or raw, again on them. A
fault on a writing chunk restores it from its store runs, or maps a raw chunk's runs back, and
cancels the write; its slot is freed only at `SWAP_DONE`, so a late write never lands on a slot
taken since.

**Encryption.** A slot holds the chunk's stream encrypted and authenticated with ChaCha20-Poly1305
(`shared/crypto`) under a 256-bit key memmgr draws from `SYS_GETRANDOM` at start, followed by the
16-byte tag. A raw chunk's pages can fill the slot, so its slot holds the sealed pages alone and
memmgr keeps the tag, on the chunk's entry. The key is in memmgr's memory only and is never sent:
the swap service and the disk see only ciphertext. The nonce is a 64-bit counter memmgr never
repeats within a boot, recorded on the chunk's disk node, so a slot's bytes open only as the seal
memmgr last made of the chunk that holds it: another chunk's bytes, an older seal, or any change
fail the tag. A failed key draw leaves the disk tier off: `SWAP_REGISTER` is refused. The rule is
[docs/storage.md](../../../docs/storage.md) § Data at Rest's.

**Read-back.** A fault on a chunk on disk replies `FAULT_REPLY_REDIRECT` naming the swap service's
endpoint ([docs/fault-handling.md](../../../docs/fault-handling.md) § Reply), with the slot word as
the redirect word: the slot, its byte count, and the generation of the seal it holds, the low bits
of its nonce counter. The word's 16-bit length field holds the byte count less one, so it names
every count from 1 byte to a full slot's 65536, a raw chunk's sixteen pages. The faulting thread
stays fault-blocked, and the swap service reads the slot and hands memmgr its bytes and the word
with `SWAP_RESTORE`, then resumes the thread. A word whose slot holds no chunk on disk, or one under
another seal, was made for a use of the slot that ended (the chunk restored, by another thread's
fault or ahead of one, or torn down, and the slot taken again since): memmgr replies `RESTORE_STALE`
and changes nothing, and the swap service resumes the thread, which faults again and is served as
the chunk now stands. So a late or repeated request never reaches a chunk it was not made for, and a
tag failure is always the failure of the chunk's own slot. memmgr maps the buffer read-only, copies
the bytes into its own buffer, and checks the tag there, so the check and the decryption read one
snapshot. A good slot is restored as a compressed chunk is ([Eviction](#eviction), States), a raw
chunk's opened pages copied whole into the new runs: admitted, with direct reclaim, its pages
written whole into new runs and mapped, its slot and disk node freed. A restore memmgr cannot make
is declined with that restore's code, and the chunk stays on disk. A tag failure makes the chunk
lost, its slot freed: the reply carries the decline word of code 12 with detail 1, which the swap
service forwards the held fault with, so the faulting thread is killed, as every later fault on the
chunk is. A fault on a chunk on disk with no swap service registered is declined with code 12 and
detail 0. Detail 2 is the swap service's own: it could not read the chunk's slot, and it forwards
the held fault with it; the chunk stays on disk. memmgr produces details 0 and 1 only.
`SWAP_RESTORE` names a slot word, which `SWAP_TAKE`'s reply also carries, not a fault, so the swap
service may also restore ahead of one, as it does for a debugger's `MAKE_RESIDENT` or procmgr's
`CAPTURE_CHUNKS` of a chunk on disk: memmgr posts the chunk's slot word to a list of at most
`SWAP_WANTED_WORDS` words, sends on the Notification the swap service registered for it, and the
swap service takes the words with `SWAP_WANTED` ([Eviction](#eviction), Debugger reads).

**Read-back is serial.** virtio-blk keeps one request in flight
([virtio-blk README](../../drivers/virtio/blk/README.md)), and one driver instance serves the root,
data and swap partitions of a disk, so a restore's read waits behind the request in flight (a
slot's write-out, or a filesystem request), and restores are served one after another.

**Accounting.** A writing chunk's store runs stay in `store`, and a raw chunk's runs with its
record, until the write ends; an on-disk or lost chunk holds no page of `pool_total`. The swapped
pages count every evicted chunk, a raw one once it is written, and the budget node stays charged for
its pages throughout, until a restore or a teardown; a lost chunk's charge goes with its region.
`QUERY_POOL_STATUS` reports the pages on disk and the free slots apart
([`ipc-interface.md`](ipc-interface.md) § Label 6). The free slots and the chunks evicted and not on
disk give the overcommit allowance ([Commit](#commit), Overcommit). A disk node is an arena slot,
and the slot map's pages are memmgr's metadata.

---

## Failure Modes

| Failure | Cause | Caller observation |
|---|---|---|
| `OUT_OF_MEMORY_CONTIGUOUS` | No free run satisfies `REQUIRE_CONTIGUOUS`, or the grant would take a page `promised` holds, or the growth floor by a charge to a node outside the system reserve | Reply with error label; caller may retry without the flag, or fail |
| `OUT_OF_MEMORY_BEST_EFFORT` | The pool's free pages do not cover `want_pages`, or the grant, or a committed registration or growth, would take a page `promised` holds, or the growth floor by a charge to a node outside the system reserve ([Commit](#commit)) | Reply with error label; caller treats as system-wide RAM exhaustion |
| `LIMIT` | `want_pages`, or a committed registration's or growth's charge, would take the subtree of the budget node it is charged to (the caller's own, or with `REQUEST_CHARGE_NODE` the handle's), or of an ancestor, over its max | Reply with error label; caller treats as that node's budget refusing, not as RAM exhaustion |
| `QUOTA` | Tracking-metadata arena could not grow (system RAM exhausted), or the kernel refused to zero a selected run ([Frame contents](#frame-contents)) | Reply with error label; caller treats the arena's failure as system-wide RAM exhaustion |
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
  reserve node, a no-evict region, or a memory-object attachment.
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

