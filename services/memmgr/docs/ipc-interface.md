# memmgr IPC Interface

IPC interface specification for memmgr: message labels, wire shapes,
capability transfer semantics, and the privilege model that
distinguishes the procmgr-only labels from the universally-callable
ones.

---

## Endpoint

memmgr listens on a single IPC endpoint. Init holds the Receive-side at
boot and transfers it to memmgr during memmgr's bootstrap-IPC round.
Init then derives a tokened SEND cap on memmgr's endpoint and installs
it into procmgr's `ProcessInfo.memmgr_endpoint_cap` so procmgr's heap
bootstrap reaches memmgr on its first call.

For all subsequent processes, procmgr is the chooser: it calls
`REGISTER_PROCESS` (below) before spawning a child, receives a tokened
SEND cap on memmgr's endpoint, and installs that cap into the child's
`ProcessInfo.memmgr_endpoint_cap`. The child's std heap-bootstrap path
calls `REQUEST_FRAMES` on it with no further setup.

---

## Token Discipline

Every memmgr-callable message arrives over a tokened endpoint cap. The
token is the procmgr-minted process identity established at
`REGISTER_PROCESS`; memmgr uses it to key the per-process tracking table
(see [`frame-pool.md`](frame-pool.md) §"Per-Process Tracking").

Two privilege classes:

- **Procmgr-only** labels (`REGISTER_PROCESS`, `PROCESS_DIED`) are
  callable only over the cap that init transfers to procmgr at
  procmgr's bootstrap round. memmgr identifies this cap by token and
  rejects procmgr-only calls received over any other tokened cap.
- **Universal** labels (`REQUEST_FRAMES`, `RELEASE_FRAMES`) are
  callable over any tokened cap, including those memmgr returned from
  `REGISTER_PROCESS`.

Tokens cannot be forged: they are minted by `cap_derive_token` only
under the kernel's derivation rules, and procmgr is the only process
that holds memmgr's procmgr-only cap.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message
label field identifies the operation. Data words and capability slots
carry arguments; the reply carries results.

### Label 1: `REQUEST_FRAMES`

Allocate one or more Frame capabilities covering at least `want_pages`
pages. Privilege: universal.

**Request:**

| Field | Value |
|---|---|
| label | 1 |
| data[0] | `want_pages` (u32, low half of word) \| `flags` (u32, high half) |

`flags` bits:

| Bit | Name | Meaning |
|---|---|---|
| 0 | `REQUIRE_CONTIGUOUS` | Reply MUST contain exactly one Frame cap covering all `want_pages`, or fail |

`flags` bits not listed above are reserved and MUST be zero.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | `returned_cap_count` (u32) |
| data[1 + i] | `page_count_for_cap_i` (u32) for each returned cap, `i ∈ [0, count)` |
| data[1 + count + i] | `phys_base_for_cap_i` (u64) — physical base address of the contiguous frame run described by `page_count_for_cap_i`, `i ∈ [0, count)` |
| cap[0..returned_cap_count] | Frame capabilities (MAP\|WRITE rights) |

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
| 3 | `Quota` | Per-process frame-record list at static cap |
| 4 | `InvalidArgument` | `want_pages == 0`, `flags` reserved bits set, or token unknown |

### Label 2: `RELEASE_FRAMES`

Voluntarily return Frame caps to the pool. Privilege: universal.
Typically called by `unreserve_pages` after the caller has unmapped the
range, or by long-lived services pruning their working set.

**Request:**

| Field | Value |
|---|---|
| label | 2 |
| data[0] | `cap_count` (u32) |
| data[1+i] | `page_count_for_cap_i` (u32) for each released cap |
| cap[0..cap_count] | Frame capabilities being released |

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
| 4 | `InvalidArgument` | `cap_count == 0`, cap not previously issued to this token, or page-count mismatch |

memmgr removes the listed caps from the per-process tracking entry,
inserts them back into the appropriate free-pool buckets, and runs
coalescing on adjacent runs.

### Label 3: `REGISTER_PROCESS`

Procmgr informs memmgr of a new process. Memmgr allocates a per-process
tracking entry and returns a tokened SEND cap on memmgr's endpoint
that procmgr will install in the new process's
`ProcessInfo.memmgr_endpoint_cap`. Privilege: procmgr-only.

**Request:**

| Field | Value |
|---|---|
| label | 3 |

The token of the requesting endpoint identifies procmgr; memmgr verifies
this and rejects the call otherwise. memmgr mints a fresh token for the
new process internally — procmgr does not supply it.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | Memmgr-side process token (procmgr forwards this in `PROCESS_DIED`) |
| cap[0] | Tokened SEND cap on memmgr's endpoint, identifying the new process |

The token is also encoded in the returned cap, but userspace currently
has no syscall to read a cap's token, so memmgr returns it explicitly
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
entry by token, reclaims every Frame cap memmgr has issued to that
process, and runs coalescing. Privilege: procmgr-only.

**Request:**

| Field | Value |
|---|---|
| label | 4 |
| data[0] | Memmgr-side process token of the dead process |

The token is the value memmgr returned in `REGISTER_PROCESS` reply
`data[0]`. Procmgr stores it in its per-process record alongside the
tokened SEND cap and replays it here on death. Procmgr cap-deletes
its own copy of the dead process's tokened SEND cap separately, after
the `PROCESS_DIED` round trip; the cap is **not** transferred in this
IPC. Idempotent on stale tokens (already-reaped or never-registered).

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

`PROCESS_DIED` for an unknown token is not an error — memmgr returns
success. Reclamation is idempotent.

---

## Capability Transfer

Every Frame cap memmgr returns is a derive-twice copy: memmgr retains
an intermediary in its own CSpace, the caller receives the second
derivation. This guarantees memmgr can reclaim on `PROCESS_DIED` even
after the caller's CSpace is torn down.

`RELEASE_FRAMES` and `PROCESS_DIED` move caps out of the caller's
CSpace via IPC transfer; the caller's slots become null. memmgr does
not derive further from received caps — it inserts the underlying
intermediary back into the free pool.

---

## Out-of-Order and Reordered Calls

memmgr serialises all incoming calls on a single thread; there is no
ordering hazard between concurrent callers. Within a single caller,
the kernel guarantees that `REQUEST_FRAMES` and `RELEASE_FRAMES`
execute in the order the caller issued them.

`PROCESS_DIED` for process P MUST NOT race ahead of P's last
`REQUEST_FRAMES` reply: procmgr observes P's death (via the existing
supervision path) only after the kernel has stopped all of P's threads,
which in turn cannot occur while P is mid-IPC with memmgr. The
reply-then-death ordering is therefore enforced by the kernel.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [memmgr/docs/frame-pool.md](frame-pool.md) | Pool structure, allocation, reclamation, coalescing |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Boot order, ProcessInfo handover, death-notification flow |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC message format, cap transfer protocol, reply-side limits |
| [abi/process-abi](../../../abi/process-abi/README.md) | `ProcessInfo.memmgr_endpoint_cap` placement |

---

## Summarized By

[memmgr/README.md](../README.md)
