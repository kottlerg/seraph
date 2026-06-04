# memmgr IPC Interface

IPC interface specification for memmgr: message labels, wire shapes,
capability transfer semantics, and the privilege model that
distinguishes the procmgr-only labels from the universally-callable
ones.

---

## Endpoint

memmgr listens on a single IPC endpoint. Init holds the Receive-side at
boot and transfers it to memmgr during memmgr's bootstrap-IPC round.
Init then derives a badged SEND cap on memmgr's endpoint and installs
it into procmgr's `ProcessInfo.memmgr_endpoint_cap` so procmgr's heap
bootstrap reaches memmgr on its first call.

For all subsequent processes, procmgr is the chooser: it calls
`REGISTER_PROCESS` (below) before spawning a child, receives a badged
SEND cap on memmgr's endpoint, and installs that cap into the child's
`ProcessInfo.memmgr_endpoint_cap`. The child's std heap-bootstrap path
calls `REQUEST_MEMORY_CAPS` on it with no further setup.

---

## Badge Discipline

Every memmgr-callable message arrives over a badged endpoint cap. The
badge is the procmgr-minted process identity established at
`REGISTER_PROCESS`; memmgr uses it to key the per-process tracking table
(see [`memory-pool.md`](memory-pool.md) §"Per-Process Tracking").

Two privilege classes:

- **Procmgr-only** labels (`REGISTER_PROCESS`, `PROCESS_DIED`,
  `DELEGATE_ASPACE`) are callable only over the cap that init transfers
  to procmgr at procmgr's bootstrap round. memmgr identifies this cap by
  badge and rejects procmgr-only calls received over any other badged cap.
- **Universal** labels (`REQUEST_MEMORY_CAPS`, `RELEASE_MEMORY_CAPS`,
  `REGISTER_REGION`, `UNREGISTER_REGION`) are callable over any badged cap,
  including those memmgr returned from `REGISTER_PROCESS`. `REGISTER_REGION`
  and `UNREGISTER_REGION` are attributed to the caller by its own badge.

Badges cannot be forged: they are minted by `cap_derive_badge` only
under the kernel's derivation rules, and procmgr is the only process
that holds memmgr's procmgr-only cap.

A third, kernel-origin class is the **fault message**: when a demand-paged
process's thread takes a page fault, the kernel (not a userspace caller)
synthesises an IPC to memmgr's endpoint with label `FAULT_LABEL`
(`u64::MAX - 1`) and `badge` set to the faulting process's memmgr badge.
Userspace cannot forge it — no SEND cap to the fault delivery is
distributed; the binding is installed by procmgr via
`SYS_THREAD_SET_FAULT_HANDLER` and the kernel owns the send. See
[docs/fault-handling.md](../../../docs/fault-handling.md).

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message
label field identifies the operation. Data words and capability slots
carry arguments; the reply carries results.

### Label 1: `REQUEST_MEMORY_CAPS`

Allocate one or more Memory capabilities covering at least `want_pages`
pages. Privilege: universal.

**Request:**

| Field | Value |
|---|---|
| label | 1 |
| data[0] | `want_pages` (u32, low half of word) \| `flags` (u32, high half) |

`flags` bits:

| Bit | Name | Meaning |
|---|---|---|
| 0 | `REQUIRE_CONTIGUOUS` | Reply MUST contain exactly one Memory cap covering all `want_pages`, or fail |

`flags` bits not listed above are reserved and MUST be zero.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | `returned_cap_count` (u32) |
| data[1 + i] | `page_count_for_cap_i` (u32) for each returned cap, `i ∈ [0, count)` |
| data[1 + count + i] | `phys_base_for_cap_i` (u64) — physical base address of the contiguous page run described by `page_count_for_cap_i`, `i ∈ [0, count)` |
| cap[0..returned_cap_count] | Memory capabilities (MAP\|WRITE rights) |

The cumulative `sum(page_count_for_cap_i) == want_pages` for both
contiguous and best-effort replies. With `REQUIRE_CONTIGUOUS` the reply
always carries exactly one cap with `page_count_for_cap_0 == want_pages`.

The `phys_base_for_cap_i` field is the host physical address of the
first page of the i-th returned cap. It is what DMA-issuing drivers
program into device transports (VirtIO PCI rings, e.g.). DMA isolation,
when present, is established through devmgr-managed IOMMU policy
outside the kernel surface; memmgr exposes only the addresses, not the
isolation policy.

There is no fixed ceiling on `returned_cap_count` other than the IPC
reply-side cap-slot limit (see [`docs/ipc-design.md`](../../../docs/ipc-design.md)).
Best-effort replies may use the full reply-side capacity.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `OutOfMemoryContiguous` | `REQUIRE_CONTIGUOUS` set; no run satisfies |
| 2 | `OutOfMemoryBestEffort` | Pool cannot cover `want_pages` even fragmented |
| 3 | `Quota` | Tracking-metadata arena could not grow (system RAM exhausted) |
| 4 | `InvalidArgument` | `want_pages == 0`, `flags` reserved bits set, or badge unknown |

### Label 2: `RELEASE_MEMORY_CAPS`

Voluntarily return Memory caps to the pool. Privilege: universal.
Typically called by `unreserve_pages` after the caller has unmapped the
range, or by long-lived services pruning their working set.

**Request:**

| Field | Value |
|---|---|
| label | 2 |
| data[0] | `cap_count` (u32) |
| data[1+i] | `page_count_for_cap_i` (u32) for each released cap |
| cap[0..cap_count] | Memory capabilities being released |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `InvalidArgument` | `cap_count == 0`, cap not previously issued to this badge, or page-count mismatch |

memmgr removes the listed caps from the per-process tracking entry,
inserts them back into the appropriate free-pool buckets, and runs
coalescing on adjacent runs.

### Label 3: `REGISTER_PROCESS`

Procmgr informs memmgr of a new process. Memmgr allocates a per-process
tracking entry and returns a badged SEND cap on memmgr's endpoint
that procmgr will install in the new process's
`ProcessInfo.memmgr_endpoint_cap`. Privilege: procmgr-only.

**Request:**

| Field | Value |
|---|---|
| label | 3 |

The badge of the requesting endpoint identifies procmgr; memmgr verifies
this and rejects the call otherwise. memmgr mints a fresh badge for the
new process internally — procmgr does not supply it.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | Memmgr-side process badge (procmgr forwards this in `PROCESS_DIED`) |
| cap[0] | Badged SEND cap on memmgr's endpoint, identifying the new process |

The badge is also encoded in the returned cap, but userspace currently
has no syscall to read a cap's badge, so memmgr returns it explicitly
in `data[0]` for procmgr to record alongside the cap and forward in
the eventual `PROCESS_DIED`.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 5 | `Unauthorized` | Caller is not procmgr |
| 6 | `TooManyProcesses` | Per-process table at static cap |

### Label 4: `PROCESS_DIED`

Procmgr signals process death. memmgr looks up the per-process tracking
entry by badge, reclaims every Memory cap memmgr has issued to that
process, and runs coalescing. Privilege: procmgr-only.

**Request:**

| Field | Value |
|---|---|
| label | 4 |
| data[0] | Memmgr-side process badge of the dead process |

The badge is the value memmgr returned in `REGISTER_PROCESS` reply
`data[0]`. Procmgr stores it in its per-process record alongside the
badged SEND cap and replays it here on death. Procmgr cap-deletes
its own copy of the dead process's badged SEND cap separately, after
the `PROCESS_DIED` round trip; the cap is **not** transferred in this
IPC. Idempotent on stale badges (already-reaped or never-registered).

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 5 | `Unauthorized` | Caller is not procmgr |

`PROCESS_DIED` for an unknown badge is not an error — memmgr returns
success. Reclamation is idempotent.

### Label 7: `REGISTER_REGION`

A demand-paged process registers an anonymous region it has reserved (but
not backed). A later page fault inside the region is backed on demand by
the fault arm below; a fault outside every registered region is declined
(the thread is killed), preserving segfault semantics. Privilege:
universal — attributed to the caller by `recv.badge`.

**Request:**

| Field | Value |
|---|---|
| label | 7 |
| data[0] | `va_base` (page-aligned virtual address) |
| data[1] | `len_bytes` (region length; page-multiple, nonzero) |
| data[2] | `prot` (MAP_* protection bits; W^X enforced) |

**Reply (success):** `label` 0. No mapping is installed — backing happens
lazily on fault, and only once procmgr has delegated this process's
`AddressSpace` cap via `DELEGATE_ASPACE`.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 3 | `Quota` | Tracking-metadata arena could not grow (system RAM exhausted) |
| 4 | `InvalidArgument` | Bad alignment, zero length, W^X violation, unknown prot bit, unknown badge, or overlap |

Per-process region and frame counts are bounded by RAM (the self-hosted
node arena), not by a fixed constant; `Quota` therefore signals genuine RAM
exhaustion, not a per-process ceiling.

### Label 8: `DELEGATE_ASPACE`

Procmgr delegates a demand-paged child's `AddressSpace` cap to memmgr so
the pager can map backing frames into it on fault. Sent at process
finalize, after the child address space exists (so it cannot ride on the
earlier `REGISTER_PROCESS` handshake). Privilege: procmgr-only.

**Request:**

| Field | Value |
|---|---|
| label | 8 |
| data[0] | `child_memmgr_badge` (from the child's `REGISTER_PROCESS` reply) |
| cap[0] | the child `AddressSpace` cap (MAP rights); ownership transfers to memmgr |

memmgr stores the cap against the child's tracking entry and drops it on
`PROCESS_DIED`.

**Reply (success):** `label` 0.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `InvalidArgument` | Unknown badge or missing cap (a stray transferred cap is dropped) |
| 5 | `Unauthorized` | Caller is not procmgr |

### Label 9: `UNREGISTER_REGION`

Unregister a region previously registered with `REGISTER_REGION`, reclaiming
every frame memmgr mapped inside it. Privilege: universal — attributed to the
caller by `recv.badge`. Used when a demand-paged anonymous region is torn down
mid-life — e.g. ruststd freeing a joined thread's guarded stack.

**Request:**

| Field | Value |
|---|---|
| label | 9 |
| data[0] | `va_base` (must equal the registered base) |
| data[1] | `len_bytes` (must equal the registered length) |

memmgr finds the exact-match region, unmaps each backing frame from the
caller's delegated `AddressSpace`, returns the frame to the free pool, and
frees the region. Frames the caller mapped itself (e.g. `REQUEST_MEMORY_CAPS`
grants) are never unmapped — only frames memmgr backed on fault inside the
region. The frames return to the pool as on `PROCESS_DIED`, so the
all-RAM-accounted identity is unaffected.

**Reply (success):** `label` 0.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `InvalidArgument` | Unknown badge, or no region matches `[va_base, len)` exactly |

### Kernel-origin fault message (`FAULT_LABEL`)

Not a callable label. When a demand-paged process's thread takes a page
fault the kernel cannot resolve, it synthesises an IPC to memmgr's
endpoint with label `FAULT_LABEL` (`u64::MAX - 1`), `badge` = the faulting
process's memmgr badge, and data words `[kind, faulting_va, access, ip]`
(see [docs/fault-handling.md](../../../docs/fault-handling.md)). For a
`FAULT_KIND_VM` fault whose `faulting_va` lies in a registered region of a
process with a delegated address space, memmgr allocates one frame, maps
it at the faulting page with the region's protection, and replies
`FAULT_REPLY_RESUME` to retry the access. Every other case — non-VM fault,
unknown process, address outside every region, no delegated AS, or any
allocation/map failure — replies `FAULT_REPLY_KILL`. Demand frames are
tracked exactly like `REQUEST_MEMORY_CAPS` allocations, so `PROCESS_DIED`
reclaims them and the all-RAM-accounted identity is unaffected (the page
moves from a free run to the process record; it was already owned).

---

## Capability Transfer

Every Memory cap memmgr returns is a derive-twice copy: memmgr retains
an intermediary in its own CSpace, the caller receives the second
derivation. This guarantees memmgr can reclaim on `PROCESS_DIED` even
after the caller's CSpace is torn down.

`RELEASE_MEMORY_CAPS` and `PROCESS_DIED` move caps out of the caller's
CSpace via IPC transfer; the caller's slots become null. memmgr does
not derive further from received caps — it inserts the underlying
intermediary back into the free pool.

---

## Out-of-Order and Reordered Calls

memmgr serialises all incoming calls on a single thread; there is no
ordering hazard between concurrent callers. Within a single caller,
the kernel guarantees that `REQUEST_MEMORY_CAPS` and `RELEASE_MEMORY_CAPS`
execute in the order the caller issued them.

`PROCESS_DIED` for process P MUST NOT race ahead of P's last
`REQUEST_MEMORY_CAPS` reply: procmgr observes P's death (via the existing
supervision path) only after the kernel has stopped all of P's threads,
which in turn cannot occur while P is mid-IPC with memmgr. The
reply-then-death ordering is therefore enforced by the kernel.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [memmgr/docs/memory-pool.md](memory-pool.md) | Pool structure, allocation, reclamation, coalescing |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Boot order, ProcessInfo handover, death-notification flow |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC message format, cap transfer protocol, reply-side limits |
| [abi/process-abi](../../../abi/process-abi/README.md) | `ProcessInfo.memmgr_endpoint_cap` placement |

---

## Summarized By

[memmgr/README.md](../README.md)
