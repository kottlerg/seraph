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
memory map and may span many MiB each. Init copies the RAM caps left after its
own bootstrap allocations into memmgr's CSpace via the derive-twice pattern
(every one while both memmgr's CSpace and init's own keep the headroom init
reserves in each), forwards
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
This requires each pool frame's Memory cap to carry **WRITE, EXECUTE, and
RETYPE** rights — memmgr derives the R/RW/RX inner from the pooled outer on
demand and `cap_derive` only narrows rights, so a frame whose outer lacks WRITE
(or EXECUTE) cannot satisfy a writable (or executable) map and would fail the
consumer's fault. The kernel mints every donatable RAM cap with these rights
(rights gate derivation, not the live mapping; see
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
run count is therefore bounded by RAM, not by a constant: no run is ever
turned away for want of a slot. The pool keeps running totals of its free
pages and runs. Selection walks the list:

- **Smallest fit.** The smallest run covering at least `N` pages serves a
  `REQUIRE_CONTIGUOUS` request and the single-run case of best-effort
  allocation.
- **Largest run.** Best-effort allocation falls back to repeatedly taking the
  largest run when no single run is large enough.

Taking a whole run frees its node; splitting one keeps the node for the
remainder, whose sorted position does not change. Returning a run inserts it
at its sorted position. A reclaimed frame's descriptor node is rewritten into
the run's node in place, so reclamation never allocates and cannot fail. When
the arena has no free node and the pool cannot fund an arena page, the
returned run funds it itself: its first page (all of it, for a one-page run)
becomes the arena page. A run stays owned and counted in `pool_total` but out
of circulation only when that page cannot be carved: both arena zones are
spent, the split of its first page fails, or the page cannot be mapped
(memmgr's page tables cannot be funded). A run a growth path takes from the
pool and cannot use goes back without growing the arena: merged back into
the remainder its split left, else into a free node, either the one its take
freed or one node the arena keeps in reserve for these returns. Such a run
stays out of circulation only when it has no remainder to merge into and the
reserve is spent by an earlier return the arena could not yet replace.

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

Each Memory cap returned to the caller is a derive-twice copy: memmgr
retains an intermediary in its own CSpace and hands the second derivation
to the caller. The intermediary lets memmgr reclaim the cap on
`PROCESS_DIED` even if the caller's CSpace has been torn down.

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
  to this process, cumulatively, since `REGISTER_PROCESS`.
- The head of an intrusive list of the demand-paged regions the process has
  registered (`REGISTER_REGION`).
- The delegated child `AddressSpace` cap, when demand-paged.

The frame and region list nodes live in a self-hosted metadata arena (below),
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

## Metadata Arena

All of memmgr's bookkeeping — free runs, process records, and per-process
frame and region descriptors — is nodes drawn from a self-hosted arena rather
than fixed `.bss` arrays. memmgr is `no_std` and cannot bootstrap a general
heap against itself, but it *can* host fixed-size nodes in pages carved from
its own pool:

- Nodes are fixed-size `Slot`s (a tagged run/process/region/frame/free payload
  plus a `next` index) reached by a `u64` index, so the index never bounds the
  arena before the address space does.
- A free list threads the unused slots. Allocation pops the head; free pushes
  it back.
- When the free list is empty, memmgr pulls one frame from the pool
  (contiguous, one page), maps it at the next arena page in its own address
  space, and carves it into free slots. When the pool itself is empty (the
  first ingest, before it holds anything), the run being inserted funds the
  page (see [Free-Pool Data Structure](#free-pool-data-structure)).

Arena pages lie in two zones of memmgr's address space. The low zone runs from
a per-boot drawn base (ASLR) up to the lowest bootstrap window
`shared/process-layout` draws, past the std heap and reservation-arena zones,
which memmgr, having no std runtime, does not use. The high zone continues
above the shared 2^38 layout ceiling and exists only where the boot's paging
mode has a wider user half (x86-64 4-level paging, Sv48, Sv57); under Sv39 the
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
fault handler; this is bounded (one frame, plus its page-table funding, with no
recursion into per-process accounting) and never breaks the identity.

---

## Concurrency

memmgr is single-threaded today: one receive loop owns all bookkeeping. The
bookkeeping is shaped so the SMP pager
([#266](https://github.com/kottlerg/seraph/issues/266)), over per-thread IPC
buffers ([#254](https://github.com/kottlerg/seraph/issues/254)), is a
service-internal change rather than a rewrite of this layer:

- The arena, the free pool, and the process index are plain values with no
  global state, mutated only through exclusive references, and held together
  in one ledger; every growth path that needs a syscall sits outside them.
- Several ledgers can coexist, each with its own arena and free pool, so a
  pool shard per CPU or NUMA node is one ledger per shard.

The sharded pager is design intent; not yet implemented. Its intended rules:
each shard's ledger sits behind its own lock, taken for one request and never
held across an IPC; a request that needs a second shard (a refill from a
neighbour, or a record whose frames came from several shards) takes shard
locks in ascending shard order; and the all-RAM-accounted identity is the sum
over shards, with `pool_total` kept in one counter updated under any shard's
lock with an atomic add.

---

## CSpace headroom

memmgr's own `CSpace` takes a slot for every frame split and inner derivation a grant makes, so a
burst of requests draws slots fast. A `CSpace` keeps its last `CSPACE_IPC_RECV_RESERVE` free
slots for IPC capability transfer, so general allocations fail before receives do
([docs/capability-model.md](../../../docs/capability-model.md) § Address-space and CSpace growth
budgets). memmgr cannot request memory from anyone else, so it funds its own slot-page pool:

- Before every receive, memmgr reads its headroom: `CAP_INFO_CSPACE_CAPACITY` less
  `CAP_INFO_CSPACE_USED` and the reserve.
- Below `CSPACE_LOW_WATER` (256 slots), it pulls a contiguous run of `CSPACE_TOPUP_PAGES` (16)
  frames from the pool, or a single frame when no such run is free, and donates it with
  augment-mode `cap_create_cspace` against its own `CSpace` cap. It then deletes the frame's cap:
  the donation holds its own reference on the frame.
- A refused donation returns the frame to the pool, and the check runs again before the next
  receive.

Like arena pages, donated frames leave the free pool for good and stay in `pool_total` as
memmgr-owned metadata, so the all-RAM-accounted identity is unaffected.

---

## Reclamation

On `PROCESS_DIED(badge)` from procmgr:

1. Remove the per-process record from the index. If absent (untracked
   badge), return silently — the death notification is idempotent.
2. For each frame node in the record's frame list, rewrite the node into a
   free run of the retained Memory cap and insert it into the free pool at
   its sorted position (no fresh node, so the step cannot fail).
3. Return every region node and the record's own node to the arena free
   list.
4. Run coalescing across the newly-freed runs and their adjacent
   neighbours.

No unmap is performed: the dead process's CSpace is torn down by procmgr
(which revokes the AddressSpace cap; see
[`docs/capability-model.md`](../../../docs/capability-model.md) §"Kill
process pattern"), which already tore down the child's mappings. The
caller-side derivation copies of the Memory caps become unreachable as part
of that teardown; memmgr's intermediary copies remain valid and are what the
free-pool insertion uses.

`RELEASE_MEMORY_CAPS` from a live process is the mid-life counterpart for a
caller-owned grant. The caller usually cannot transfer the cap back — having
retyped the region (e.g. into a Thread) and dropped its inner copy, it no
longer holds one — so it names each region by the `phys_base` memmgr reported
at grant. memmgr matches that base against the entry's frame list
(`FRAME_VA_UNMAPPED` grants only; demand-mapped chunks are reclaimed by
`UNREGISTER_REGION`), inserts the retained intermediary cap back into the pool,
frees the node, and coalesces the freed runs with their physical neighbours,
leaving the entry's other records untouched. Unmatched bases are ignored, so
release is idempotent (a racing join-plus-reaper double-release is harmless).
The caller must have deleted every object retyped from the region first;
releasing a still-retyped region is correctness-safe (the kernel refuses to
re-hand-out live bytes) but the run is only re-grantable whole — its retype
bump pointer blocks `memory_split`, per
[`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_memory_split-33)
§"`SYS_MEMORY_SPLIT`" — until the retype is freed, and its next grantee cannot `mem_map` it
below that pointer either (`InvalidArgument`; see
[`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_mem_map-16)
§"`SYS_MEM_MAP`"), so a mapping grant of such a run fails until the retype is freed.

`UNREGISTER_REGION` from a live process is the mid-life counterpart for a
demand-paged region: memmgr removes the region node and **actively unmaps** the
whole region span from the delegated child `AddressSpace` in one
`mem_unmap_reclaim` call, which also returns the emptied page tables to that
address space's page-table budget (the process is still alive, so the mappings
must be removed before the frames return to the pool). It then inserts each
backing frame's cap back into the pool, frees the frame nodes, and coalesces
the freed runs with their physical neighbours. Frames the caller mapped itself
are left untouched. This is the reclamation path the ruststd guarded-stack
consumer uses on `join()`.

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
  rights, the tail must be virgin (never retyped or sub-allocated), and neither
  may have derivation children.

Coalescing runs explicitly after every reclamation — `PROCESS_DIED`,
`RELEASE_MEMORY_CAPS`, and `UNREGISTER_REGION` alike — so a freed run rejoins
its physical neighbours immediately rather than staying discrete. Together
with best-fit best-effort selection (above), this bounds the pool's run count
under long spawn/free/die churn, and with it the per-run tracking anchor
memmgr holds in its own CSpace: best-fit keeps a fixed-size churn cycling one
run, and the explicit merge keeps residual fragmentation from drifting the run
(and anchor) count up over time. Left un-coalesced, reclaimed runs stay
discrete and their anchors persist, slowly consuming memmgr's CSpace and arena
even while its RAM footprint stays bounded. A "dirty" released run — one whose
source `MemoryObject` kept its retype bump pointer advanced — declines
`memory_merge` (the kernel requires a virgin tail; see
[`core/kernel/docs/syscalls.md`](../../../core/kernel/docs/syscalls.md#sys_memory_merge-50)
§"`SYS_MEMORY_MERGE`") and stays a discrete, re-grantable-whole run.
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
| `QUOTA` | Tracking-metadata arena could not grow (system RAM exhausted) | Reply with error label; caller treats as system-wide RAM exhaustion |
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
[Memory Model](../../../docs/memory-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md), [services/memmgr/README.md](../README.md),
[memmgr IPC Interface](ipc-interface.md),
[Userspace Memory Model](../../../docs/userspace-memory-model.md)
