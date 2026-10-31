# memmgr

Tier-1 userspace service that owns the userspace physical-memory-cap pool. memmgr
allocates Memory capabilities to all std-built services on demand, tracks
per-process memory-cap ownership, and reclaims memory caps when a process dies.

memmgr is a `no_std` binary: it cannot bootstrap a general heap against
itself, so it has none. Its free pool, process table, and per-process frame
and region descriptors all live in a self-hosted metadata arena carved from
its own pool (see [`docs/memory-pool.md`](docs/memory-pool.md) §"Metadata
Arena"). After memmgr is in place, the only `no_std` userspace services in the
system are `init` and `memmgr` (see
[`docs/process-lifecycle.md`](../../docs/process-lifecycle.md) §"Userspace
Boot Order").

---

## Source Layout

```
memmgr/
├── Cargo.toml                  # Workspace member; no_std binary
├── README.md
├── free-pool/                  # `memmgr-free-pool` crate: pure host-tested
│                               # arena, free pool, process index, region logic
├── src/
│   └── main.rs                 # _start() entry point, IPC dispatch loop
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
- **Reclamation on process death** — on `PROCESS_DIED` from procmgr,
  reclaim the dead process's memory caps into the free pool (see
  [`docs/memory-pool.md`](docs/memory-pool.md) §"Reclamation").
- **Mid-life reclamation** — on `RELEASE_MEMORY_CAPS` (or `UNREGISTER_REGION`
  for a demand-paged region) from a live process, return the named grant to the
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
- **Implement swap, paging, or page-fault handling.** Memory caps are allocated
  out of physical RAM; there is no backing store. A failed allocation
  returns an out-of-memory error to the caller (see
  [`docs/memory-pool.md`](docs/memory-pool.md) §"Failure Modes").
- **Operate a page cache.** Caching of file pages (when fs drivers
  implement it) lives in the fs driver, not in memmgr.

---

## IPC Interface

The full memmgr IPC specification is in
[`docs/ipc-interface.md`](docs/ipc-interface.md). Key operations:

- `REQUEST_MEMORY_CAPS(want_pages, flags) → memory_caps[..]`
- `RELEASE_MEMORY_CAPS(phys_base[..])` — return granted regions mid-life
- `REGISTER_PROCESS(...) → badged_endpoint_cap` (procmgr-only)
- `PROCESS_DIED(badge)` (procmgr-only)
- `DONATE_MEMORY_CAPS(memory_caps[..])` — hand init's reaped RAM to the pool
  (procmgr-only)
- `QUERY_POOL_STATUS` — read the all-RAM-accounted identity terms and the free total
- `REGISTER_REGION` / `UNREGISTER_REGION` — register and tear down a demand-paged region
- `DELEGATE_ASPACE(child_badge, aspace_cap)` — delegate a demand-paged child's
  address space (procmgr-only)

---

## Sizing constants

memmgr's bookkeeping is RAM-bound, not capped by a constant: free runs,
process records, and per-process region and frame descriptors are nodes in a
self-hosted metadata arena carved from memmgr's own pool, indexed by `u64`
(see [`docs/memory-pool.md`](docs/memory-pool.md) §"Metadata Arena"). Records
are found through a linear-hash index that grows with them. The arena grows
until RAM is exhausted or its address-space zones are spent; the high zone,
above the shared 2^38 layout ceiling, exists on paging modes whose user half
is wider. memmgr funds its own `CSpace` and page-table growth from its pool,
so neither init-seeded budget bounds it. A failed growth surfaces as `QUOTA`
(or `TOO_MANY_PROCESSES` from `REGISTER_PROCESS`).

The remaining constants are tuning values that bound no capacity:

| Constant | Value | Role |
|---|---|---|
| `DEMAND_CHUNK_PAGES` | 16 | Pages one demand fault backs |
| `CSPACE_LOW_WATER`, `CSPACE_TOPUP_PAGES` | 256 slots, 16 pages | `CSpace` self-funding mark and step |
| `ASPACE_TOPUP_PAGES`, `PT_FUND_ROUNDS` | 4 pages, 4 rounds | Page-table self-funding step and retries per map |
| `MAX_LOAD` | 2 | Mean index chain length before a bucket split |
| `PROCESS_INDEX_VA`..`PROCESS_INDEX_END` | 1 GiB | Bucket-array window; past it chains lengthen |

The catalogue entry for each bound is in [`docs/limits.md`](../../docs/limits.md)
§"memmgr".

---

## Bootstrap

memmgr is created by init. At init's entry, the kernel has placed Memory
caps for all usable physical RAM in init's CSpace (see
[`docs/capability-model.md`](../../docs/capability-model.md) §"Initial
Capability Distribution"). Init parses the memmgr ELF from its boot
module, creates memmgr's AddressSpace, CSpace, and Thread, and copies the
RAM Memory caps into memmgr's CSpace using the derive-twice pattern. Init
then starts memmgr's thread and proceeds to spawn procmgr — installing
a SEND cap on memmgr's service endpoint into procmgr's `ProcessInfo`
so procmgr's heap-bootstrap path reaches memmgr on its first IPC.

Authoritative description of the boot order, capability flow, and
ProcessInfo handover lives in [`docs/process-lifecycle.md`](../../docs/process-lifecycle.md).

### Bootstrap-IPC round

Init delivers RAM Memory caps to memmgr in a single bootstrap-IPC round that
names them by slot range only (`ipc::memmgr_bootstrap`); memmgr reads each
cap's size and physical base from the kernel (`cap_info`), so the round bounds
neither the cap count nor a cap's size. Init forwards every remaining RAM cap
while memmgr's `CSpace` and its own keep the headroom the `MemoryAlloc` tail, the
phys-table page, and the in-use arenas need (they have no `InitInfo`
descriptor and must ride this round). Any RAM caps beyond that are not lost:
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
