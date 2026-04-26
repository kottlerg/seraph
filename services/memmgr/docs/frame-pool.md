# memmgr Frame Pool

Authoritative specification of memmgr's physical-frame pool: how memmgr
ingests frames at boot, how it allocates them, how it tracks per-process
ownership, how it reclaims on process death, and how it coalesces freed
runs to sustain contiguous-allocation success.

---

## Pool Ingest

memmgr receives the userspace RAM frame pool from init at boot. The
kernel populates init's CSpace with one Frame capability per usable
physical-RAM region in `BootInfo` (see
[`docs/capability-model.md`](../../../docs/capability-model.md) §"Initial
Capability Distribution"). Frame sizes vary — they reflect the firmware
memory map and may be multiple MiB each. Init copies the entire RAM
range into memmgr's CSpace via the derive-twice pattern, then transfers
the slot range `(memory_frame_base, memory_frame_count)` to memmgr in a
single bootstrap IPC round.

memmgr does not split the ingested frames eagerly. The free pool retains
each ingested cap at its native size; splitting happens on the
allocation path via `frame_split`, and coalescing reverses the split on
the free path.

---

## Free-Pool Data Structure

memmgr is `no_std` and cannot allocate — every data structure is sized
at compile time. The free pool is organised for two access patterns:

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

`REQUEST_FRAMES(want_pages, flags)`:

1. **`REQUIRE_CONTIGUOUS` set.** Walk buckets from the smallest class
   that can hold `want_pages` upward. On hit: detach the run, split off
   exactly `want_pages` via `frame_split` if the run is larger than
   requested, return one Frame cap. On miss: return
   `OutOfMemory{contiguous}`. memmgr does not migrate live pages to
   produce a contiguous run; coalescing is the only mechanism that
   restores contiguity.
2. **Best-effort.** Walk buckets to satisfy the request from one or
   more runs. Prefer larger runs first to minimise the returned-cap
   count. Bound the returned-cap count by the IPC reply-side cap-slot
   limit; if the pool cannot satisfy `want_pages` within that bound,
   return `OutOfMemory{best_effort}`.

Each Frame cap returned to the caller is a derive-twice copy: memmgr
retains an intermediary in its own CSpace and hands the second derivation
to the caller. The intermediary lets memmgr reclaim the cap on
`PROCESS_DIED` even if the caller's CSpace has been torn down.

---

## Per-Process Tracking

memmgr maintains a per-process table keyed on the procmgr-minted token
delivered with every `REQUEST_FRAMES` call (and established at
`REGISTER_PROCESS`). Each entry records:

- The token (process identity).
- The list of Frame slots memmgr has handed to this process,
  cumulatively, since `REGISTER_PROCESS`.

The list is statically bounded — there is a maximum number of frame
records per process. Allocations beyond that bound return
`OutOfMemory{quota}`. The bound is sized to cover practical workloads
including a multi-MiB heap, driver DMA regions, and zero-copy file
mappings; it is not a security quota.

The table itself is statically bounded by the maximum number of
concurrently-tracked processes. `REGISTER_PROCESS` returns
`OutOfMemory{too_many_processes}` if the table is full.

---

## Reclamation

On `PROCESS_DIED(token)` from procmgr:

1. Look up the per-process entry. If absent (untracked token), return
   silently — the death notification is idempotent.
2. For each Frame slot in the entry:
   a. Walk back to the original cap memmgr retained at allocation time.
   b. Insert it into the appropriate free-pool bucket.
3. Run coalescing across the newly-freed runs and their adjacent
   neighbours.
4. Clear the per-process entry.

The dead process's CSpace is torn down by procmgr (which revokes the
AddressSpace cap; see
[`docs/capability-model.md`](../../../docs/capability-model.md) §"Kill
process pattern"). The caller-side derivation copies of the Frame caps
become unreachable as part of that teardown. memmgr's intermediary
copies remain valid and are what the free-pool insertion uses.

`RELEASE_FRAMES` from a live process follows the same path for the
listed slots without touching the per-process entry's other records.

---

## Coalescing

Coalescing is a reverse-`frame_split`: two adjacent free Frame caps
covering physically-contiguous page ranges are merged into one larger
cap. Eligibility:

- Both caps are present in the free pool.
- The physical-base addresses are adjacent (`base_a + size_a == base_b`).
- The kernel's `frame_merge` (or equivalent) accepts the operation —
  the caps must share a common ancestor in the derivation tree, which
  the original boot-time ingest guarantees for caps derived from the
  same `BootInfo` Frame.

Coalescing runs after every `PROCESS_DIED` reclamation and after every
`RELEASE_FRAMES` whose freed range adjoins another free run. It is
bounded: a single reclamation that frees `K` pages can produce at most
`K` coalesce operations, each O(log pool_size) to update bucket indices.

Coalescing across boot-time ingest boundaries (between two distinct
`BootInfo` Frame caps) is not attempted — those caps have no common
derivation ancestor.

---

## Failure Modes

| Failure | Cause | Caller observation |
|---|---|---|
| `OutOfMemory{contiguous}` | No free run satisfies `REQUIRE_CONTIGUOUS` | Reply with error label; caller may retry without the flag, or fail |
| `OutOfMemory{best_effort}` | Pool cannot cover `want_pages` even fragmented | Reply with error label; caller treats as system-wide RAM exhaustion |
| `OutOfMemory{quota}` | Per-process frame-record list at static cap | Reply with error label; caller is consuming an unreasonable number of frames |
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
  exiting (or calling `RELEASE_FRAMES`) and the resulting coalesce.
- **MMIO and IOMMU frames.** Out of scope; see
  [`docs/device-management.md`](../../../docs/device-management.md).
- **Quota policy.** The static per-process frame-record cap is a
  resource ceiling, not a security policy. System-wide quota and
  pressure mechanisms are out of scope for the first cut.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | System-wide memory ownership and frame contract |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Process-death notification flow that drives reclamation |
| [docs/capability-model.md](../../../docs/capability-model.md) | Frame cap rights, derivation tree, revocation |
| [memmgr/docs/ipc-interface.md](ipc-interface.md) | Wire shape of `REQUEST_FRAMES`, `PROCESS_DIED`, etc. |

---

## Summarized By

[memmgr/README.md](../README.md)
