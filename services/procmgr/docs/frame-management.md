# Frame Management

procmgr owns the userspace physical memory pool and allocates frames on behalf
of all processes it creates.

---

## Pool Design

At bootstrap, init delegates all remaining memory frame caps into procmgr's
CSpace via `cap_copy` (derive-twice pattern). The caps occupy contiguous slots
starting at `initial_caps_base` for `initial_caps_count` entries, as recorded
in procmgr's `ProcessInfo` page.

Each delegated cap is a Frame capability covering one or more contiguous
physical pages. Frame sizes vary — the kernel reports whatever the firmware's
memory map provides (often multi-MiB regions). procmgr splits these into
individual pages using `frame_split` as needed.

---

## Allocation Strategy

Bump allocator (`FramePool`). Maintains a cursor into the delegated cap range:

1. Take the current Frame cap.
2. Call `frame_split(cap, PAGE_SIZE)` to split off one 4 KiB page.
3. If split succeeds: use the page cap, keep the remainder as current.
4. If split fails (frame is exactly one page): use the cap directly, advance
   to the next delegated cap.
5. When all delegated caps are consumed, allocation fails.

No free list. Frames are consumed forward and not returned to the pool.
Reclamation is deferred (see below).

---

## Per-Process Accounting

procmgr maintains a `ProcessTable` with a fixed-size entry per created process.
Each entry records:

- Process ID (procmgr-assigned)
- AddressSpace cap (revoke to kill the process)
- CSpace cap (for future cap management)
- Thread cap (for lifecycle queries)
- Frame count allocated during process creation

The frame count is computed by snapshotting the pool's cumulative allocation
counter before and after `create_process`.

---

## Reclamation (Deferred)

On process exit or crash, procmgr revokes the process's AddressSpace cap. This
stops all threads bound to that address space and releases the kernel's page
table structures. However, the physical Frame caps allocated to the process are
not currently returned to the pool.

Full reclamation requires tracking individual frame caps per process (not just
the count). The `ProcessTable` structure is designed to accommodate this — a
per-process frame list or bitmap can be added when teardown is implemented.

---

## Runtime Frame Requests (Deferred)

Services that need physical memory at runtime (drivers for DMA buffers, vfsd
for buffer cache) will request frames from procmgr via a `REQUEST_FRAMES` IPC
operation. The operation transfers Frame caps from procmgr's pool into the
requester's CSpace. This is not implemented in Tier 2.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/capability-model.md](../../docs/capability-model.md) | Frame cap rights, derivation, revocation |
| [docs/memory-model.md](../../docs/memory-model.md) | Virtual address layout, page sizes |
| [procmgr/docs/ipc-interface.md](ipc-interface.md) | IPC operations including CREATE_PROCESS |

---

## Summarized By

None
