# memmgr

Tier-1 userspace service that owns the userspace physical-memory-cap pool. memmgr
allocates Memory capabilities to all std-built services on demand, tracks
per-process memory-cap ownership, and reclaims memory caps when a process dies.

memmgr is a `no_std` binary: it cannot bootstrap a heap against itself, so
its bookkeeping uses statically-bounded data structures only. After memmgr
is in place, the only `no_std` userspace services in the system are `init`
and `memmgr`.

---

## Source Layout

```
memmgr/
├── Cargo.toml                  # Workspace member; no_std binary
├── README.md
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
address space at virtual addresses they choose themselves.

## Responsibilities

- **Memory-cap allocation** — serve the `REQUEST_MEMORY_CAPS` IPC, returning one or
  more Memory caps that cumulatively cover the requested page count. Honour
  the `REQUIRE_CONTIGUOUS` flag for callers that need a single multi-page
  cap (DMA buffers, large heap grow operations).
- **Per-process tracking** — maintain a per-process record of the Memory
  caps memmgr has handed out, keyed on a procmgr-minted badge.
- **Reclamation on process death** — on `PROCESS_DIED` from procmgr,
  reclaim the dead process's memory caps into the free pool.
- **Coalescing** — fold adjacent free pages back into larger contiguous
  Memory caps via reverse-`memory_split`, sustaining the success rate of
  `REQUIRE_CONTIGUOUS` requests as the pool fragments.

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
  returns an out-of-memory error to the caller.
- **Operate a page cache.** Caching of file pages (when fs drivers
  implement it) lives in the fs driver, not in memmgr.

---

## IPC Interface

The full memmgr IPC specification is in
[`docs/ipc-interface.md`](docs/ipc-interface.md). Key operations:

- `REQUEST_MEMORY_CAPS(want_pages, flags) → memory_caps[..]`
- `RELEASE_MEMORY_CAPS(memory_caps[..])`
- `REGISTER_PROCESS(...) → badged_endpoint_cap` (procmgr-only)
- `PROCESS_DIED(badge)` (procmgr-only)

---

## Sizing constants

Per-process region and frame descriptors are RAM-bound, not capped by a
constant: they are nodes in a self-hosted metadata arena carved from memmgr's
own pool (see [`docs/memory-pool.md`](docs/memory-pool.md) §"Metadata Arena").
The two remaining fixed bounds below are picked for current early-boot
workloads; they are documented here so the revisit triggers are easy to find
when those workloads grow.

| Constant | Value | Surface effect on overflow | Revisit when |
|---|---|---|---|
| `MAX_PROCESSES` | 64 | `REGISTER_PROCESS` returns `TooManyProcesses` | a workload approaches ~50 concurrent processes |
| `MAX_FREE_RUNS` | 512 | `push_or_coalesce` parks the run after a coalesce retry: still owned and counted in `pool_total`, but with no free-pool slot (unreachable for allocation until a later coalesce frees one) | post-coalesce free-run count regularly approaches 512 |

Donation and reclamation push through `push_or_coalesce`, which coalesces
and retries before parking, so the `MAX_FREE_RUNS` park path is reachable
only if fragmentation exceeds what coalescing can recover. A parked run is
an allocatability degradation only — it never breaks the all-RAM-accounted
identity, because `pool_total` counts owned RAM regardless of slot residency.

Both remaining constants are fixed static bounds: any value is permanently
either undersized (parks RAM / rejects work under load) or oversized
(wastes static RAM), so neither can scale to a hardware-bound process count.
Eliminating them via the same self-hosted, dynamically-sized bookkeeping the
per-process descriptors now use is tracked as a separate redesign rather than
resolved by raising a number. The former `MAX_PER_PROC` and
`MAX_REGIONS_PER_PROC` per-process caps were removed when per-process
descriptors moved to the metadata arena.

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

### Bootstrap-IPC memory-cap-count cap

Init delivers RAM Memory caps to memmgr in a single bootstrap-IPC round,
packed two page-counts per `u64` after a three-word prefix. The capacity
of a single round is `MEMMGR_BOOTSTRAP_MAX_MEMORY_CAPS = 122` memory caps. Init
currently has ~90 RAM memory caps at boot, so this fits comfortably.

If a future memory map (or an architecture with fragmented physical RAM)
produces more than 122 RAM memory caps, memmgr will own only the first
122 and the rest will sit unused in init's CSpace. Resolutions when
needed:

- **Multi-round bootstrap.** init does N `serve_round`s, each carrying
  up to 122 page-counts; memmgr's `_start` does N `request_round`s.
  Small change to memmgr's bootstrap parser and init's main.
- **Memory-cap-count discovery via a kernel syscall** that reads the size
  from the cap itself. No such syscall exists today; would also enable
  cleaner per-cap accounting throughout.

Not pressing until init's memory-cap count grows past 122.

---

## Relationship to procmgr

memmgr and procmgr are sister tier-1 services with disjoint authority:

- **memmgr** owns the RAM memory-cap pool and answers `REQUEST_MEMORY_CAPS`.
- **procmgr** owns process lifecycle, ELF loading, and `ProcessInfo`
  population; it is itself a memmgr client (procmgr is std-using and
  bootstraps its own heap against memmgr).

procmgr is the privileged caller that registers new processes with
memmgr (so memmgr can tag the per-process memory-cap list) and notifies
memmgr of deaths (so memmgr can reclaim). Ordinary callers cannot
mint or retire process badges.

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

[Userspace Memory Model](../../docs/userspace-memory-model.md), [Process Lifecycle](../../docs/process-lifecycle.md), [Architecture Overview](../../docs/architecture.md)
