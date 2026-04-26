# memmgr

Tier-1 userspace service that owns the userspace physical-frame pool. memmgr
allocates Frame capabilities to all std-built services on demand, tracks
per-process frame ownership, and reclaims frames when a process dies.

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
    ├── frame-pool.md           # Pool, allocation, reclamation, coalescing
    └── ipc-interface.md        # memmgr IPC labels and wire shapes
```

---

## Role

memmgr is the sole holder of the userspace RAM frame pool. Every std-built
process bootstraps its heap by calling memmgr; drivers acquiring DMA-capable
memory call memmgr; vfsd and fs drivers backing zero-copy file pages call
memmgr. memmgr returns Frame capabilities; callers map them into their own
address space at virtual addresses they choose themselves.

## Responsibilities

- **Frame allocation** — serve the `REQUEST_FRAMES` IPC, returning one or
  more Frame caps that cumulatively cover the requested page count. Honour
  the `REQUIRE_CONTIGUOUS` flag for callers that need a single multi-page
  cap (DMA buffers, large heap grow operations).
- **Per-process tracking** — maintain a per-process record of the Frame
  caps memmgr has handed out, keyed on a procmgr-minted token.
- **Reclamation on process death** — on `PROCESS_DIED` from procmgr,
  reclaim the dead process's frames into the free pool.
- **Coalescing** — fold adjacent free pages back into larger contiguous
  Frame caps via reverse-`frame_split`, sustaining the success rate of
  `REQUIRE_CONTIGUOUS` requests as the pool fragments.

## What memmgr deliberately does NOT do

- **Choose virtual addresses.** Each process owns its own VA policy. memmgr
  hands back Frame caps; the caller maps them where it wants.
- **Manage process lifecycles.** That is procmgr's role. memmgr learns of
  process births and deaths via IPC from procmgr, but it does not create,
  schedule, or terminate processes.
- **Serve MMIO or IOMMU frames.** memmgr's pool is RAM only. MMIO Frame
  caps come from devmgr (see [device-management.md](../../docs/device-management.md));
  memmgr never sees them.
- **Implement swap, paging, or page-fault handling.** Frames are allocated
  out of physical RAM; there is no backing store. A failed allocation
  returns an out-of-memory error to the caller.
- **Operate a page cache.** Caching of file pages (when fs drivers
  implement it) lives in the fs driver, not in memmgr.

---

## IPC Interface

The full memmgr IPC specification is in
[`docs/ipc-interface.md`](docs/ipc-interface.md). Key operations:

- `REQUEST_FRAMES(want_pages, flags) → frame_caps[..]`
- `RELEASE_FRAMES(frame_caps[..])`
- `REGISTER_PROCESS(...) → tokened_endpoint_cap` (procmgr-only)
- `PROCESS_DIED(token)` (procmgr-only)

---

## Bootstrap

memmgr is created by init. At init's entry, the kernel has placed Frame
caps for all usable physical RAM in init's CSpace (see
[`docs/capability-model.md`](../../docs/capability-model.md) §"Initial
Capability Distribution"). Init parses the memmgr ELF from its boot
module, creates memmgr's AddressSpace, CSpace, and Thread, and copies the
RAM Frame caps into memmgr's CSpace using the derive-twice pattern. Init
then starts memmgr's thread and proceeds to spawn procmgr — installing
a SEND cap on memmgr's service endpoint into procmgr's `ProcessInfo`
so procmgr's heap-bootstrap path reaches memmgr on its first IPC.

Authoritative description of the boot order, capability flow, and
ProcessInfo handover lives in [`docs/process-lifecycle.md`](../../docs/process-lifecycle.md).

---

## Relationship to procmgr

memmgr and procmgr are sister tier-1 services with disjoint authority:

- **memmgr** owns the RAM frame pool and answers `REQUEST_FRAMES`.
- **procmgr** owns process lifecycle, ELF loading, and `ProcessInfo`
  population; it is itself a memmgr client (procmgr is std-using and
  bootstraps its own heap against memmgr).

procmgr is the privileged caller that registers new processes with
memmgr (so memmgr can tag the per-process frame list) and notifies
memmgr of deaths (so memmgr can reclaim). Ordinary callers cannot
mint or retire process tokens.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | System-wide memory ownership, frame contract, page-reservation contract |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Boot order, ProcessInfo/InitInfo handover, process-death flow |
| [docs/capability-model.md](../../docs/capability-model.md) | Frame cap rights, derivation, revocation |
| [docs/architecture.md](../../docs/architecture.md) | System design, tier-1 service roles |
| [services/procmgr/README.md](../procmgr/README.md) | Sister tier-1 service for process lifecycle |
| [services/init/README.md](../init/README.md) | Boot-time origin of memmgr's frame pool |

---

## Summarized By

[Userspace Memory Model](../../docs/userspace-memory-model.md), [Process Lifecycle](../../docs/process-lifecycle.md), [Architecture Overview](../../docs/architecture.md)
