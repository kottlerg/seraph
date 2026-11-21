# memmgr

Tier-1 userspace service that owns the userspace physical-memory-cap pool. memmgr
allocates Memory capabilities to all std-built services on demand, tracks
per-process memory-cap ownership, and reclaims memory caps when a process dies.

memmgr is a `no_std` binary: it cannot bootstrap a general heap against
itself, so it has none. Its free pool, process table, per-process frame and
region descriptors, and the regions' chunk tables all live in a self-hosted
metadata arena carved from its own pool (see [`docs/memory-pool.md`](docs/memory-pool.md) §"Metadata
Arena"). After memmgr is in place, the only `no_std` userspace services in the
system are `init` and `memmgr` (see
[`docs/process-lifecycle.md`](../../docs/process-lifecycle.md) §"Userspace
Boot Order").

---

## Source Layout

```
memmgr/
├── Cargo.toml                  # Workspace member; no_std binary
├── clippy.toml                 # Clippy settings; frame threshold of memmgr's 48 KiB stack
├── README.md
├── free-pool/                  # `memmgr-free-pool` crate: pure host-tested
│                               # arena, free pool, deferred list, process
│                               # index, budget nodes, region logic,
│                               # memory objects and attachments,
│                               # per-region chunk tables, commitment
│                               # bounds (`commit.rs`), the compressed
│                               # store's page codec and chunk stream
│                               # (`compress.rs`, `store.rs`), the swap
│                               # slot map and slot sealing (`disk.rs`)
├── src/
│   ├── main.rs                 # _start() entry point, IPC dispatch loop
│   ├── evict.rs                # Eviction: the clock's slices, the compression
│                               # worker, the store, restore
│   ├── capture.rs              # CAPTURE_CHUNKS: a held target's regions described,
│                               # their content written into procmgr's frames
│   └── disk.rs                # Disk tier: the swap labels, the per-boot
│                               # key, the fault redirect to the swap service
└── docs/
    ├── memory-pool.md          # Pool, allocation, reclamation, coalescing
    └── ipc-interface.md        # memmgr IPC labels and wire shapes
```

---

## Role

memmgr is the sole holder of the userspace RAM memory-cap pool. Every std-built
process bootstraps its heap by calling memmgr; drivers acquiring DMA-capable
memory call memmgr; vfsd and fs drivers backing zero-copy file pages call
memmgr. memmgr returns Memory capabilities; callers map them into their own
address space at virtual addresses they choose themselves (see
[`docs/userspace-memory-model.md`](../../docs/userspace-memory-model.md) §"Memory
Allocation Contract").

## Responsibilities

- **Memory-cap allocation** — serve the `REQUEST_MEMORY_CAPS` IPC, returning one or
  more Memory caps that cumulatively cover the requested page count, or, when
  the free RAM is spread over more runs than one reply carries, a partial
  grant the caller requests again for the rest. Honour the `REQUIRE_CONTIGUOUS`
  flag for callers that need a single multi-page cap (DMA buffers, large heap
  grow operations). Wire shape in
  [`docs/ipc-interface.md`](docs/ipc-interface.md) §"Label 1: `REQUEST_MEMORY_CAPS`".
- **Per-process tracking** — maintain a per-process record of the Memory
  caps memmgr has handed out, keyed on a per-process badge (memmgr-minted at
  procmgr's `REGISTER_PROCESS`; procmgr's own is a bootstrap badge init mints
  for it; see [`docs/memory-pool.md`](docs/memory-pool.md) §"Per-Process Tracking").
- **Reclamation on process death** — on `PROCESS_DIED` from procmgr, reclaim the
  dead process's memory caps into the free pool, holding a frame another process
  can still reach (a capability to it, a live kernel object retyped from it, or
  a mapping of it) on a deferred list until it is unreachable (see
  [`docs/memory-pool.md`](docs/memory-pool.md) §"Reclamation"); procmgr holds it
  back for a DMA-capable driver until devmgr has confirmed the driver's device
  stopped its DMA (see [`docs/ipc-interface.md`](docs/ipc-interface.md)
  § Label 4).
- **Mid-life reclamation** — on `RELEASE_MEMORY_CAPS` (or `UNREGISTER_REGION`,
  `SHRINK_REGION` or `DISCARD_RANGE` for a demand-paged region) from a live
  process, return the named grant to the
  free pool so a per-unit-of-work retype loop holds a bounded footprint without
  waiting for process death. Best-fit best-effort selection (reuse a freed run
  of the requested size rather than re-split a larger one) plus a coalesce after
  every reclamation bound this on both sides: the caller's pool footprint *and*
  memmgr's own per-run tracking-anchor (CSpace) footprint. A high-volume
  spawn/free churn — e.g. ruststd thread creation, which grants and frees a
  fresh Thread-retype slab per spawn — therefore cannot drift memmgr's CSpace
  toward exhaustion even though its RAM stays flat. Selection and reclamation
  rules live in [`docs/memory-pool.md`](docs/memory-pool.md) §"Allocation" and
  §"Reclamation".
- **Budget accounting** — charge every page lent to a process to its budget
  node, refuse a charge over the max of the node or an ancestor with `LIMIT`
  (a demand fault with decline code 10), and keep the system reserve for the
  core (see [`docs/memory-pool.md`](docs/memory-pool.md) § Distribution
  policy).
- **Disk tier** — serve the swap service's swap labels on the swap authority alone: hand it
  compressed chunks, and chunks whose stream gains nothing as their pages, sealed under a per-boot
  key that never leaves memmgr, redirect a fault on a chunk on disk to it, and restore the chunk
  from the bytes it hands back once their tag checks (see
  [`docs/memory-pool.md`](docs/memory-pool.md#disk-tier) § Disk tier and
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § Labels 22 to 26).
- **Memory objects** — seal a process's grants into an immutable memory object, and attach
  it, or the zero object, as a region of any process holding its handle, shared read-only or
  private, a write then copying the page, executable for an object, each attacher charged for what
  it maps; keep a read-only view of every object's frames, so no text write patches a frame others
  map, and give a debugged process's pages copies of their own on procmgr's `MAKE_PRIVATE` (see
  [`docs/memory-pool.md`](docs/memory-pool.md#memory-objects) § Memory objects and
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § Labels 27 to 29 and § Label 30).
- **Coalescing** — fold adjacent free pages back into larger contiguous
  Memory caps via reverse-`memory_split`, sustaining the success rate of
  `REQUIRE_CONTIGUOUS` requests as the pool fragments. Runs after every
  reclamation (death, release, unregister), so reclaimed runs rejoin their
  physical neighbours instead of accumulating as discrete parked runs (see
  [`docs/memory-pool.md`](docs/memory-pool.md) §"Coalescing").

## What memmgr deliberately does NOT do

- **Choose virtual addresses.** Each process owns its own VA policy. memmgr
  hands back Memory caps; the caller maps them where it wants.
- **Manage process lifecycles.** That is procmgr's role. memmgr learns of
  process births and deaths via IPC from procmgr, but it does not create,
  schedule, or terminate processes.
- **Serve MMIO or IOMMU memory caps.** memmgr's pool is RAM only. MMIO Memory
  caps come from devmgr (see [device-management.md](../../docs/device-management.md));
  memmgr never sees them.
- **Perform device I/O.** memmgr serves the page faults and heap growth of
  every service on the storage path, so it never waits on one of them and reads
  or writes no device itself. Memory caps are allocated out of physical RAM,
  and as the default pager memmgr fills a demand-paged fault from that RAM too
  (see [docs/fault-handling.md](../../docs/fault-handling.md) § Demand Paging
  and the Default System Pager); a failed allocation returns an out-of-memory
  error to the caller (see [`docs/memory-pool.md`](docs/memory-pool.md)
  §"Failure Modes"). Under memory pressure memmgr evicts cold pages it mapped
  as pager into a compressed store it keeps in RAM, and restores them on the
  next fault (see [`docs/memory-pool.md`](docs/memory-pool.md#eviction)
  § Eviction). Swap to
  disk is that store's second tier: a separate swap service, swapd, takes chunks memmgr
  seals under a per-boot key it alone holds, writes them to its partition, and
  hands their bytes back on a fault memmgr redirects to it; memmgr reads and
  writes no slot and waits on no swap service (see
  [`docs/memory-pool.md`](docs/memory-pool.md#disk-tier) § Disk tier).
- **Operate a page cache.** Caching of file pages (when fs drivers
  implement it) lives in the fs driver, not in memmgr.

---

## IPC Interface

The full memmgr IPC specification is in
[`docs/ipc-interface.md`](docs/ipc-interface.md). Key operations:

- `REQUEST_MEMORY_CAPS(want_pages, flags) → memory_caps[..], region_ids[..]` (no physical
  address; `RIGHTS_MEM_PHYS` only for a phys-class caller)
- `RELEASE_MEMORY_CAPS(region_id[..])` — return granted regions mid-life, named by the
  opaque region ids the grant returned
- `REGISTER_PROCESS(flags, parent_badge, max[, charge_node_handle])
  → badge, max, badged_endpoint_cap[, node_handle]` (procmgr-only); creates the process's
  budget node, under a given node handle's node on request, and on request a node handle to it
- `PROCESS_DIED(badge)` (procmgr-only)
- `DONATE_MEMORY_CAPS(memory_caps[..])` — hand init's reaped RAM to the pool
  (procmgr-only)
- `QUERY_POOL_STATUS` — read the all-RAM-accounted identity terms, the free and deferred
  totals, the largest free run, the system reserve, the memory-pressure level, and the pages
  promised to committed regions
- `REGISTER_REGION` / `UNREGISTER_REGION` — register and tear down a demand-paged region;
  `REGION_COMMIT` makes it a committed region
- `EXTEND_REGION` / `SHRINK_REGION` — grow a committed region in place, or lower its top to a
  64 KiB chunk multiple
- `DISCARD_RANGE` — take back the frames of whole 64 KiB chunks of a region, committed or not;
  a later touch faults in a zero-filled page, and a committed region keeps its commitment
- `QUERY_MEMORY_USAGE` — read the caller's own budget usage, its max, and its subtree's usage
- `REGISTER_PRESSURE(bits, draw_room_bits, notification_cap)` — register the Notification memmgr
  signals with `bits` on a change of the memory-pressure level and with `draw_room_bits` on each
  opening of the draw room; a second replaces the first, and the std runtime registers every
  process at start
- `DELEGATE_ASPACE(child_badge, aspace_cap)` — delegate a demand-paged child's
  address space (procmgr-only)
- `CREATE_SUB_NODE(max) → max, node_handle` — make a sub-node of the caller's own budget node
- `SEAL_OBJECT(region_id[..]) → pages, object_handle` — seal unmapped grants of the caller into
  an immutable memory object
- `ATTACH_OBJECT(va, len, prot, first_page, flags[, object_handle])` — attach an object, or the
  zero object without a handle, as a region of the caller, shared or `ATTACH_PRIVATE`
- Over an object handle only: `OBJECT_RELEASE` — drop the object's handle state
- `MAKE_PRIVATE(badge, va, len) → reached` — give each page of a range of a process's attachments
  that maps its origin a copy of its own, for a debugger (procmgr-only)
- `CAPTURE_CHUNKS(badge, cursor, end, flags, offset, pages…) → cursor, written, need, descriptors`
  — describe a held target's regions, and write what memmgr holds of each into the Memory caps the
  request carries, for procmgr's `SNAPSHOT` (procmgr-only)
- Over a node handle only: `NODE_SET_MAX(max) → max`, `NODE_CREATE(max) → max, node_handle`,
  `NODE_QUERY_USAGE`, `NODE_REGISTER_LIMIT(bits, notification_cap, registrant_send)` and
  `NODE_RELEASE` — set, divide, read and watch the budget node the handle names, and drop a
  sub-node's handle state

---

## Sizing constants

memmgr's bookkeeping is RAM-bound, not capped by a constant: free runs,
process records, their budget nodes, node handle states and limit registrations, memory
objects, per-process region, commitment and frame descriptors, and the regions' chunk-table nodes
are nodes in a self-hosted metadata arena carved from memmgr's own pool, indexed by `u64` (see
[`docs/memory-pool.md`](docs/memory-pool.md) §"Metadata Arena"). Records are
found through a linear-hash index that grows with them. The arena grows until
RAM is exhausted or its address-space zones are spent; the high zone,
above the shared 2^38 layout ceiling, exists on paging modes whose user half
is wider. memmgr funds its own `CSpace` and page-table growth from its pool,
so neither init-seeded budget bounds it. A failed growth surfaces as `QUOTA`
(or `TOO_MANY_PROCESSES` from `REGISTER_PROCESS`). It also funds a
demand-paged process's page-table pool when a fault's map finds it exhausted,
accounted to that process (see [`docs/memory-pool.md`](docs/memory-pool.md)
§"Client page-table funding").

The remaining constants are tuning values that bound no capacity:

| Constant | Value | Role |
|---|---|---|
| `DEMAND_CHUNK_PAGES` | 16 | Pages one demand fault backs on an unfragmented pool; on a fragmented one, as many as the largest free run holds. Also the unit `SHRINK_REGION` and `DISCARD_RANGE` take, which clients read as `memmgr_labels::DEMAND_CHUNK_BYTES` |
| `SCRUB_WINDOW_PAGES` | 512 pages | Pages one pass maps to zero a run before hand-out ([`docs/memory-pool.md`](docs/memory-pool.md) § Frame contents) |
| `CSPACE_LOW_WATER`, `CSPACE_TOPUP_PAGES` | 256 slots, 16 pages | `CSpace` self-funding mark and step |
| `ASPACE_TOPUP_PAGES`, `PT_FUND_ROUNDS` | 4 pages, 4 rounds | Page-table funding step and retries per map, for memmgr's own maps and a demand fault's map into a process |
| `MAX_LOAD` | 2 | Mean index chain length before a bucket split |
| `ARENA_RETURN_RESERVE` | 1 slot | Arena slot kept for last-resort returns of a run to the pool |
| `DEFERRED_RECHECK_BATCH` | 64 runs | Deferred runs one recheck checks; a run not pooled goes to the back |
| `DEFERRED_RECHECK_WINDOWS` | 256 windows | Mapping-count windows one recheck spends; the run that crosses the budget is still read whole |
| `PROCESS_INDEX_VA`..`PROCESS_INDEX_END` | 1 GiB | Bucket-array window; past it chains lengthen |
| `SYSTEM_RESERVE_DIVISOR` | 64 | The system reserve is `pool_total / 64` free pages, which only a reserve budget node's charge may take; the pressure level is `CRITICAL` at or below the growth floor, the reserve and, while chunks are swapped, the restore headroom ([`docs/memory-pool.md`](docs/memory-pool.md) § Eviction) |
| `PRESSURE_LOW_DIVISOR` | 16 | The pressure level is `LOW` below `pool_total / 16` free pages outside `promised` ([`docs/memory-pool.md`](docs/memory-pool.md) § Memory pressure) |
| `PRESSURE_BAND_DIVISOR` | 128 | Hysteresis band of `pool_total / 128` pages, at least one, that the free pool clears before the level improves |

The catalogue entry for each bound is in [`docs/limits.md`](../../docs/limits.md)
§"memmgr".

---

## Bootstrap

memmgr is created by init. At init's entry, the kernel has placed Memory
caps for all usable physical RAM in init's CSpace (see
[`docs/capability-model.md`](../../docs/capability-model.md) §"Initial
Capability Distribution"). Init parses the memmgr ELF from its boot
module, creates memmgr's AddressSpace, CSpace, and Thread, and moves the
RAM Memory caps into memmgr's CSpace, so memmgr is the sole holder of each
run. Init then starts memmgr's thread and proceeds to spawn procmgr — installing
a SEND cap on memmgr's service endpoint into procmgr's `ProcessInfo`
so procmgr's heap-bootstrap path reaches memmgr on its first IPC.

Authoritative description of the boot order, capability flow, and
ProcessInfo handover lives in [`docs/process-lifecycle.md`](../../docs/process-lifecycle.md).

### Bootstrap-IPC round

Init delivers RAM Memory caps to memmgr in a single bootstrap-IPC round that
names them by slot range only (`ipc::memmgr_bootstrap`); memmgr reads each
cap's size and physical base from the kernel (`cap_info`), so the round bounds
neither the cap count nor a cap's size. Init moves every remaining RAM cap
into memmgr's `CSpace`, which leaves memmgr the sole holder of each run, while
that `CSpace` keeps the headroom the `MemoryAlloc` tail, the phys-table page,
and the in-use arenas need (they have no `InitInfo` descriptor and must ride
this round). Any RAM caps beyond that are not lost:
init donates them at its reap, and procmgr forwards them to memmgr's pool via
`DONATE_MEMORY_CAPS`, which has no per-round cap. The round's place in the
boot sequence is described in
[`docs/process-lifecycle.md`](../../docs/process-lifecycle.md) §"Init → memmgr",
and the donation in §"Init reap".

---

## Relationship to procmgr

memmgr and procmgr are sister tier-1 services with disjoint authority:

- **memmgr** owns the RAM memory-cap pool and answers `REQUEST_MEMORY_CAPS`.
- **procmgr** owns process lifecycle, ELF loading, and `ProcessInfo`
  population; it is itself a memmgr client (procmgr is std-using and
  bootstraps its own heap against memmgr). See
  [`services/procmgr/README.md`](../procmgr/README.md).

procmgr is the privileged caller that registers new processes with
memmgr (so memmgr can tag the per-process memory-cap list) and notifies
memmgr of deaths (so memmgr can reclaim). Ordinary callers cannot
mint or retire process badges (see [`docs/ipc-interface.md`](docs/ipc-interface.md)
§"Badge Discipline").

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | System-wide memory ownership, memory-cap contract, page-reservation contract |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Boot order, ProcessInfo/InitInfo handover, process-death flow |
| [docs/capability-model.md](../../docs/capability-model.md) | Memory cap rights, derivation, revocation |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Demand paging, with memmgr as the default system pager |
| [docs/architecture.md](../../docs/architecture.md) | System design, tier-1 service roles |
| [services/procmgr/README.md](../procmgr/README.md) | Sister tier-1 service for process lifecycle |
| [services/init/README.md](../init/README.md) | Boot-time origin of memmgr's memory-cap pool |

---

## Summarized By

[abi/process-abi/README.md](../../abi/process-abi/README.md),
[Architecture Overview](../../docs/architecture.md),
[Capability Model](../../docs/capability-model.md),
[Userspace Memory Model](../../docs/userspace-memory-model.md),
[init Bootstrap Stages](../init/docs/bootstrap.md)

