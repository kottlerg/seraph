# memmgr Memory Pool

Authoritative specification of memmgr's memory-cap pool: how memmgr
ingests memory caps at boot, how it allocates them, how it tracks per-process
ownership, how it reclaims on process death, and how it coalesces freed
runs to sustain contiguous-allocation success.

---

## Pool Ingest

memmgr receives the userspace RAM memory-cap pool from init at boot. The
kernel populates init's CSpace with one Memory capability per usable
physical-RAM region in `BootInfo` (see
[`docs/capability-model.md`](../../../docs/capability-model.md) §"Initial
Capability Distribution"). Memory cap sizes vary — they reflect the firmware
memory map and may be multiple MiB each. Init copies the entire RAM
range into memmgr's CSpace via the derive-twice pattern, then transfers
the slot range `(memory_base, memory_count)` to memmgr in a
single bootstrap IPC round.

memmgr does not split the ingested memory caps eagerly. The free pool retains
each ingested cap at its native size; splitting happens on the
allocation path via `memory_split`, and coalescing reverses the split on
the free path.

Beyond the bootstrap pool, memmgr also receives reclaimed frames at init's reap
(`DONATE_MEMORY_CAPS`: init's ELF segments, InitInfo, stack, boot-module ELF
sources, reclaim scratch, AP trampoline). Both entry points feed the same free
pool, so every pool frame is uniform anonymous RAM: a consumer may map any of
it read-only, read-write, or read-execute (W^X still enforced at map time).
This requires each pool frame's Memory cap to carry **WRITE, EXECUTE, and
RETYPE** rights — memmgr derives the R/RW/RX inner from the pooled outer on
demand and `cap_derive` only narrows rights, so a frame whose outer lacks WRITE
(or EXECUTE) cannot satisfy a writable (or executable) map and would fail the
consumer's fault. The kernel mints every donatable RAM cap with these rights
(rights gate derivation, not the live mapping); memmgr enforces the invariant at
both ingest and donation, rejecting (or, for the bootstrap pool, panicking on) a
frame that lacks them so a mint-rights regression fails loudly rather than
surfacing as an intermittent consumer fault.

---

## Free-Pool Data Structure

memmgr is `no_std` and has no general allocator; the free pool itself is
sized at compile time (per-process descriptors instead live in the
RAM-backed metadata arena above). The free pool is organised for two access
patterns:

- **Contiguous allocation fast path.** A `REQUIRE_CONTIGUOUS` request
  for `N` pages must locate a free run of at least `N` pages in O(1) or
  O(log N). Buckets indexed by run length (in pages, by power-of-two
  size class) hold pointers to the head of each free run in that class.
- **Best-effort allocation.** Without `REQUIRE_CONTIGUOUS`, memmgr may
  satisfy a request from multiple runs; the smaller-end of the bucket
  array suffices.

Per-bucket entries are statically sized. If a bucket fills, that size
class is at capacity for the moment and memmgr falls back to the next
larger or smaller class. The implementation MAY choose any concrete
representation (intrusive linked list embedded in metadata pages,
fixed-size arrays per class, etc.) consistent with the `no_std`
constraint.

---

## Allocation

`REQUEST_MEMORY_CAPS(want_pages, flags)`:

1. **`REQUIRE_CONTIGUOUS` set.** Walk buckets from the smallest class
   that can hold `want_pages` upward. On hit: detach the run, split off
   exactly `want_pages` via `memory_split` if the run is larger than
   requested, return one Memory cap. On miss: return
   `OutOfMemory{contiguous}`. memmgr does not migrate live pages to
   produce a contiguous run; coalescing is the only mechanism that
   restores contiguity.
2. **Best-effort.** Walk buckets to satisfy the request from one or
   more runs. Prefer larger runs first to minimise the returned-cap
   count. Bound the returned-cap count by the IPC reply-side cap-slot
   limit; if the pool cannot satisfy `want_pages` within that bound,
   return `OutOfMemory{best_effort}`.

Each Memory cap returned to the caller is a derive-twice copy: memmgr
retains an intermediary in its own CSpace and hands the second derivation
to the caller. The intermediary lets memmgr reclaim the cap on
`PROCESS_DIED` even if the caller's CSpace has been torn down.

---

## Per-Process Tracking

memmgr maintains a per-process table keyed on the procmgr-minted badge
delivered with every `REQUEST_MEMORY_CAPS` call (and established at
`REGISTER_PROCESS`). Each entry records:

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
`OutOfMemory{quota}`.

The table itself is statically bounded by the maximum number of
concurrently-tracked processes (`MAX_PROCESSES`). `REGISTER_PROCESS` returns
`OutOfMemory{too_many_processes}` if the table is full. Lifting that bound to a
hardware-bound process count, reusing this arena, is tracked separately.

---

## Metadata Arena

Per-process frame and region descriptors are nodes drawn from a self-hosted
arena rather than fixed `.bss` arrays. memmgr is `no_std` and cannot bootstrap
a general heap against itself, but it *can* host fixed-size descriptor nodes in
pages carved from its own pool:

- Nodes are fixed-size `Slot`s (a tagged region/frame/free payload plus a `next`
  index) reached by index from a contiguous VA window in memmgr's own address
  space.
- A global free list threads the unused slots. Allocation pops the head; free
  pushes it back.
- When the free list is empty, memmgr pulls one frame from the pool
  (`select_memory_caps`, contiguous, one page), maps it at the next arena page
  in its own address space, and carves it into free slots.

The arena only grows, and a page once carved is permanent memmgr-owned metadata.
This preserves the all-RAM-accounted identity: the page was counted in
`pool_total` at ingest and is never returned, exactly like an in-use bootstrap
arena. Growth stops at the peak concurrent node count — freed nodes return to
the arena's own free list and are reused — so spawn/grow/die churn leaks no
pages. Refilling the free list can draw a pool frame and map it from inside a
fault handler; this is bounded (one frame, no recursion into per-process
accounting) and never breaks the identity.

---

## Reclamation

On `PROCESS_DIED(badge)` from procmgr:

1. Look up the per-process entry. If absent (untracked badge), return
   silently — the death notification is idempotent.
2. For each frame node in the entry's frame list:
   a. Insert the retained Memory cap into the appropriate free-pool bucket.
   b. Return the node to the arena free list.
3. Return every region node to the arena free list.
4. Run coalescing across the newly-freed runs and their adjacent
   neighbours.
5. Clear the per-process entry.

No unmap is performed: the dead process's CSpace is torn down by procmgr
(which revokes the AddressSpace cap; see
[`docs/capability-model.md`](../../../docs/capability-model.md) §"Kill
process pattern"), which already tore down the child's mappings. The
caller-side derivation copies of the Memory caps become unreachable as part
of that teardown; memmgr's intermediary copies remain valid and are what the
free-pool insertion uses.

`RELEASE_MEMORY_CAPS` from a live process follows the same path for the
listed slots without touching the per-process entry's other records.

`UNREGISTER_REGION` from a live process is the mid-life counterpart for a
demand-paged region: memmgr removes the region node, and for each frame it
backed inside that region **actively unmaps** the page from the delegated
child `AddressSpace` (the process is still alive, so the mapping must be
removed before the frame returns to the pool), inserts the cap back into the
pool, and frees the node. Frames the caller mapped itself are left untouched.
This is the reclamation path the ruststd guarded-stack consumer uses on
`join()`.

---

## Coalescing

Coalescing is a reverse-`memory_split`: two adjacent free Memory caps
covering physically-contiguous page ranges are merged into one larger
cap. Eligibility:

- Both caps are present in the free pool.
- The physical-base addresses are adjacent (`base_a + size_a == base_b`).
- The kernel's `memory_merge` (or equivalent) accepts the operation —
  the caps must share a common ancestor in the derivation tree, which
  the original boot-time ingest guarantees for caps derived from the
  same `BootInfo` Memory cap.

Coalescing runs after every `PROCESS_DIED` reclamation and after every
`RELEASE_MEMORY_CAPS` whose freed range adjoins another free run. It is
bounded: a single reclamation that frees `K` pages can produce at most
`K` coalesce operations, each O(log pool_size) to update bucket indices.

Coalescing across boot-time ingest boundaries (between two distinct
`BootInfo` Memory caps) is not attempted — those caps have no common
derivation ancestor.

---

## Failure Modes

| Failure | Cause | Caller observation |
|---|---|---|
| `OutOfMemory{contiguous}` | No free run satisfies `REQUIRE_CONTIGUOUS` | Reply with error label; caller may retry without the flag, or fail |
| `OutOfMemory{best_effort}` | Pool cannot cover `want_pages` even fragmented | Reply with error label; caller treats as system-wide RAM exhaustion |
| `OutOfMemory{quota}` | Tracking-metadata arena could not grow (system RAM exhausted) | Reply with error label; caller treats as system-wide RAM exhaustion |
| `OutOfMemory{too_many_processes}` | Per-process table at static cap | `REGISTER_PROCESS` from procmgr fails; procmgr handles this as a process-creation failure |

memmgr never panics on allocation failure. The caller's response policy
(panic, retry, fail the operation) is its own concern; for std-built
services the heap allocator returns null and the std panic handler
exits the thread, matching today's behaviour.

---

## Non-Goals

- **Swap.** memmgr never moves pages to backing store. RAM exhaustion
  surfaces as `OutOfMemory` to the caller.
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

[memmgr/README.md](../README.md)
