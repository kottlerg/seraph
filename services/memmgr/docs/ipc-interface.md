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
calls `REQUEST_MEMORY_CAPS` on it with no further setup. See
[docs/process-lifecycle.md](../../../docs/process-lifecycle.md) §"Steady-State Process Creation".

---

## Badge Discipline

Every memmgr-callable message arrives over a badged endpoint cap. The
badge is the process identity memmgr mints at procmgr's `REGISTER_PROCESS`,
or, for procmgr itself, the bootstrap badge init mints and passes in
memmgr's bootstrap round; memmgr uses it to key the per-process tracking
table (see [`memory-pool.md`](memory-pool.md) §"Per-Process Tracking").

Two privilege classes:

- **Procmgr-only** labels (`REGISTER_PROCESS`, `PROCESS_DIED`,
  `DONATE_MEMORY_CAPS`, `DELEGATE_ASPACE`) are callable only over the cap
  that init transfers to procmgr at procmgr's bootstrap round. memmgr
  identifies this cap by badge and rejects procmgr-only calls received over
  any other badged cap, replying `UNAUTHORIZED`.
- **Universal** labels (`REQUEST_MEMORY_CAPS`, `RELEASE_MEMORY_CAPS`,
  `QUERY_POOL_STATUS`, `REGISTER_REGION`, `UNREGISTER_REGION`) are callable
  over any badged cap, including those memmgr returned from
  `REGISTER_PROCESS`. `REGISTER_REGION` and `UNREGISTER_REGION` are
  attributed to the caller by its own badge.

The badge on an ordinary IPC message is the badge of the sender's cap,
and it cannot be forged: badges are minted by `cap_derive_badge` only
under the kernel's derivation rules, and procmgr is the only process
that holds memmgr's procmgr-only cap. See
[docs/capability-model.md](../../../docs/capability-model.md) §"Badges".
The fault-message badge carries the same guarantee, as below.

A third, kernel-origin class is the **fault message**: when a demand-paged
process's thread takes a page fault, the kernel synthesises an IPC to
memmgr's endpoint with label `FAULT_LABEL` (`u64::MAX - 1`) and `badge`
set to the derivation badge of the Endpoint cap bound by
`SYS_THREAD_SET_FAULT_HANDLER`. The binding is installed by procmgr for a
process's main thread, binding the process's own badged memmgr cap
(`ProcessInfo.pager_endpoint_cap`), and copied by the runtime onto each thread
it spawns (`SYS_THREAD_INHERIT_FAULT_HANDLER`), so the badge is the process's memmgr
badge. The fault endpoint is memmgr's client endpoint, so any holder of a
badged SEND cap can also send a message labelled `FAULT_LABEL`; memmgr
does not distinguish it from a kernel delivery, and either way the message
carries the badge of a cap the sender holds, so it is attributed to the
sender. A client may bind its own threads to this endpoint, but the binder
cannot choose the badge (see
[docs/fault-handling.md](../../../docs/fault-handling.md) §"Security"), so
a client holding only its own memmgr cap cannot make memmgr back a fault
in another process's regions: memmgr's attribution of a fault rests on the
derivation-locked badge, not on badge secrecy.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message
label field identifies the operation. Data words and capability slots
carry arguments; the reply carries results. Error codes below are the
`memmgr_errors` constants in `shared/ipc`. A label memmgr does not define
replies `INVALID_ARGUMENT`.

### Label 1: `REQUEST_MEMORY_CAPS`

Allocate one or more Memory capabilities covering `want_pages` pages, or,
for a best-effort partial grant, fewer. Privilege: universal.

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
| data[1 + count + i] | `region_id_for_cap_i` (u64) — opaque id of the grant of the contiguous page run described by `page_count_for_cap_i`, `i ∈ [0, count)` |
| cap[0..returned_cap_count] | Memory capabilities carrying every right of their pool frames but `RIGHTS_MEM_PHYS`, which only a phys-class caller's keep (pool frames carry WRITE, EXECUTE, RETYPE, and PHYS, see [`memory-pool.md`](memory-pool.md) §"Pool Ingest") |

With `REQUIRE_CONTIGUOUS` the reply always carries exactly one cap with
`page_count_for_cap_0 == want_pages`. A best-effort reply has
`sum(page_count_for_cap_i) <= want_pages`: when no single run covers the
request, memmgr takes the largest runs, at most `MSG_CAP_SLOTS_MAX` of them,
and when those fall short while the pool's free pages still cover
`want_pages`, the reply is a partial grant. The caller MUST compare the sum
with `want_pages` and request the remainder (see
[`memory-pool.md`](memory-pool.md) §"Allocation").

The `region_id_for_cap_i` field is the name `RELEASE_MEMORY_CAPS` takes
for the i-th returned cap's run. It is a per-process sequence number from 1:
memmgr gives each grant to a process the next id of that process's record and
never reissues one while the record lives, so an id names one grant of its
caller and carries no address, no count of other processes' grants, and
nothing about memmgr's layout. The reply carries no physical address, and
the returned caps lack `RIGHTS_MEM_PHYS`, so `CAP_INFO_MEMORY_PHYS_BASE`
refuses them, except to a phys-class caller (devmgr and the IOMMU drivers,
[Label 3](#label-3-register_process)), whose caps keep the right. A
DMA-issuing driver programs the device addresses devmgr returns when it maps
a cap for the driver's device (see
[docs/device-management.md](../../../docs/device-management.md#dma-authorisation)
§ DMA Authorisation); the surfaces that still carry physical addresses are
classified in
[core/kernel/docs/cross-boundary-disclosure.md](../../../core/kernel/docs/cross-boundary-disclosure.md)
§ Physical-address surfaces.

There is no fixed ceiling on `returned_cap_count` other than the IPC
reply-side cap-slot limit (see [`docs/ipc-design.md`](../../../docs/ipc-design.md)).
Best-effort replies may use the full reply-side capacity.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |
| data[0..3] | Only on codes 1 and 2, and only when pool selection fails (not when deriving the caller's copy fails): total free pages, free-run count, and the largest free run in pages |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `OUT_OF_MEMORY_CONTIGUOUS` | `REQUIRE_CONTIGUOUS` set; no run satisfies |
| 2 | `OUT_OF_MEMORY_BEST_EFFORT` | Best-effort: the pool's free pages do not cover `want_pages`, no run could be taken, or deriving the caller's copy failed |
| 3 | `QUOTA` | Tracking-metadata arena could not grow (system RAM exhausted), memmgr could not map a selected run to zero it ([`memory-pool.md`](memory-pool.md#frame-contents) § Frame contents), or the caller's region-id sequence is spent (unreachable: 2^64 − 1 grants) |
| 4 | `INVALID_ARGUMENT` | `want_pages == 0`, `flags` reserved bits set, or badge unknown |

### Label 2: `RELEASE_MEMORY_CAPS`

Voluntarily return previously-granted Memory caps to the pool mid-life.
Privilege: universal. Called by a long-lived process pruning its working
set — e.g. ruststd releasing a reclaimed thread's Thread-retype slab so a
bounded thread-churn loop holds a bounded pool footprint.

The caller names each region by the region id memmgr reported in the
granting `REQUEST_MEMORY_CAPS` reply, *not* by transferring the cap: a
caller that has retyped the region (e.g. into a Thread) and dropped the
inner cap no longer holds a cap to send back. memmgr keeps the outer cap
as the per-process tracking anchor and uses the region id to find it.

**Request:**

| Field | Value |
|---|---|
| label | 2 |
| data[0] | `count` (u32) |
| data[1+i] | `region_id_i` (u64) — region id of region `i` to release |
| cap[..] | none; memmgr deletes any cap attached (see [Capability Transfer](#capability-transfer)) |

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
| 4 | `INVALID_ARGUMENT` | caller's badge is unknown |

For each region id, memmgr finds the caller's grant that carries it in the
per-process tracking entry, takes it off the entry, and returns its run to the
free pool (coalescing where possible), the tracking node becoming the run's
node. Ids that match no outstanding grant of the caller are ignored — release
is idempotent, so a racing double-release (join plus reaper) is harmless, and
since a record never reissues an id, a late duplicate never takes a later
grant of the same run. Bootstrap arenas and demand-paged chunks carry no id,
so no release names them. The caller MUST have already deleted every capability to
the region and every kernel object retyped from it, and unmapped it from every
address space. A region released while any of them remains is held on memmgr's
deferred list, granted to no one, until all are gone; the release still
succeeds and the region is no longer the caller's. A region the caller lent a
DMA-capable driver for a transfer is such a region: the driver's capability,
and devmgr's for the region's DMA mapping, keep it deferred until the transfer
completed or the device is confirmed stopped
([docs/device-management.md](../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown). Every release first
rechecks the deferred list, so a release naming no grant (`count` 0) only
rechecks. See [`memory-pool.md`](memory-pool.md) §"Reclamation".

### Label 3: `REGISTER_PROCESS`

Procmgr informs memmgr of a new process. Memmgr allocates a per-process
tracking entry and returns a badged SEND cap on memmgr's endpoint
that procmgr will install in the new process's
`ProcessInfo.memmgr_endpoint_cap`. Privilege: procmgr-only.

**Request:**

| Field | Value |
|---|---|
| label | 3 |
| data[0] | Caller's `MEMMGR_LABELS_VERSION` |
| data[1] | Flags: bit 0 `REGISTER_PHYS_CLASS` registers the process phys-class; other bits reserved, zero |

The badge of the requesting endpoint identifies procmgr; memmgr verifies
this and rejects the call otherwise. memmgr mints a fresh badge for the
new process internally — procmgr does not supply it: 63 random bits, and bit
63 (`PHYS_CLASS_BADGE_BIT`) set for a phys-class process and clear for every
other. A phys-class process's grants keep `RIGHTS_MEM_PHYS`
([Label 1](#label-1-request_memory_caps)); the kernel stamps the badge on the
process's SEND cap, so no process can claim the class. procmgr sets the flag
only for a child created with `CREATE_PHYS_ACCESS`, which it accepts only from
an un-badged or phys-class creator: init creates devmgr with it and devmgr the
IOMMU driver (see the
[procmgr IPC interface](../../procmgr/docs/ipc-interface.md#label-1-create_process)).
init clears the bit in the badge it mints for procmgr on memmgr's endpoint,
and memmgr refuses a bootstrap whose procmgr badge carries it, so procmgr's
own grants lack the right.

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
| 4 | `INVALID_ARGUMENT` | Reserved `data[1]` flag bits set |
| 5 | `UNAUTHORIZED` | Caller is not procmgr |
| 6 | `TOO_MANY_PROCESSES` | The tracking table could not take a new entry (its record node could not be allocated: system RAM exhausted), the badge draw failed, or the reply cap could not be derived |
| 7 | `LABEL_VERSION_MISMATCH` | `data[0]` is not memmgr's `MEMMGR_LABELS_VERSION` |

### Label 4: `PROCESS_DIED`

Procmgr signals process death. memmgr looks up the per-process tracking entry
by badge, takes back every Memory cap memmgr has issued to that process, and
runs coalescing (see [`memory-pool.md`](memory-pool.md) §"Reclamation"). A
frame another process can still reach, through a capability to it, a kernel
object retyped from it, or a user mapping of it, waits on memmgr's deferred
list rather than joining the free pool, until a later recheck finds it
unreachable. Privilege: procmgr-only.

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
| 5 | `UNAUTHORIZED` | Caller is not procmgr |

`PROCESS_DIED` for an unknown badge is not an error — memmgr returns
success. Reclamation is idempotent.

**When procmgr sends it.** procmgr sends `PROCESS_DIED` after its teardown of
the process, except for a started process created with
`procmgr_labels::CREATE_DMA_HOLD`, whose `PROCESS_DIED` procmgr sends only when
the creator releases the hold (`procmgr_labels::RELEASE_HOLD`, which procmgr
serves only on the release token of the process's create reply,
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md#label-3-release_hold)
§ Label 3). Until then memmgr keeps the process's record, and every frame on it
stays out of the free pool and counted, as for a live process; a hold that is
never released keeps them so for the rest of the boot. devmgr creates every
DMA-capable driver so and releases the hold only once the driver's device is
confirmed to have stopped its DMA, so memmgr never hands out a frame of the
driver's own record that such a device may still write
([docs/device-management.md](../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown). A frame a client lends the driver for a transfer is on
the client's record, which the hold does not cover. memmgr keeps it out of the
pool, on its deferred list once the client releases it or dies, while the
driver, or devmgr's DMA mapping of it, still holds a capability to it; the
device reaches the frame only through that mapping, and devmgr deletes its
capability only once the device is confirmed stopped or blocked. memmgr
itself treats a held-back `PROCESS_DIED` like any other.

procmgr also never sends `PROCESS_DIED` for a child whose create failed because procmgr could
not unmap a window it copied the child's argv and env through (it replies
`procmgr_errors::ARGV_ENV_STILL_MAPPED`;
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md#label-1-create_process) § Label 1,
**argv and env**). That window may still map the child's frames, so memmgr keeps the child's
record, and every frame on it out of the free pool, for the rest of the boot.

### Label 5: `DONATE_MEMORY_CAPS`

Permanently transfer Memory caps into memmgr's pool. Privilege: procmgr-only.
memmgr does not check a donated cap's provenance, and the RAM Memory caps a
client holds derive from memmgr's own grants, so a client's donation would
alias frames memmgr has already lent out back into the free pool and count
them in `pool_total` twice. Used by procmgr's init reap to hand over
init's reclaimed memory: the usable-RAM caps init did not forward in memmgr's
bootstrap round, the free remainders `MemoryAlloc` abandoned, ELF segments,
`InitInfo`, stack, the bootloader/bundle reclaim ranges, the AP-trampoline
frame, and boot-module ELF sources. See
[docs/process-lifecycle.md](../../../docs/process-lifecycle.md#init-reap) §"Init reap".

**Request:**

| Field | Value |
|---|---|
| label | 5 |
| cap[..] | Memory caps to donate; each MUST carry WRITE, EXECUTE, RETYPE, and PHYS rights |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | `accepted_caps` — number of transferred caps memmgr accepted |
| data[1] | `accepted_pages` — total pages across the accepted caps |
| data[2] | `pool_total_pages` — memmgr's owned page count after the donation |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 5 | `UNAUTHORIZED` | Caller is not procmgr; every transferred cap is deleted and none is counted |

A procmgr donation always succeeds. memmgr validates each cap with
`cap_info`; a cap that is not a Memory cap or lacks a required right is
deleted and not counted. Each accepted cap is owned by memmgr for the rest of its life: it
is added to `pool_total` (see Label 6) at its whole size, read with `cap_info`
(a page count of any width), and placed in the free pool, coalescing where
possible. When no arena node is free outside the arena's reserve and none can
be carved, the run takes the reserved node; it stays owned and counted but
out of circulation only when that reserve is already spent and the arena
cannot grow (see [`memory-pool.md`](memory-pool.md) §"Free-Pool Data
Structure").

### Label 6: `QUERY_POOL_STATUS`

Read-only query of the all-RAM-accounted identity plus the current free,
deferred and largest-run totals. Privilege: universal — returns aggregate
counts only, no caps and no state change.

**Request:** label 6, no words, no caps.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | `system_ram_bytes` — total installed RAM the kernel computed at boot |
| data[1] | `kernel_reserved_bytes` — the fixed kernel reserve |
| data[2] | `pool_total_bytes` — every page memmgr owns (free runs, in-use arenas, reap donations); monotonic |
| data[3] | `free_bytes` — subset of `pool_total_bytes` in free runs, lent to no process |
| data[4] | `deferred_bytes` — subset of `pool_total_bytes` reclaimed but held out of the free runs while another process can still reach it |
| data[5] | `largest_free_bytes` — the largest single free run, the most one `REQUIRE_CONTIGUOUS` grant can take; 0 when the pool is empty |

The all-RAM-accounted identity is `data[0] == data[1] + data[2]`: every page
is either fixed kernel reserve or in memmgr's pool. `pool_total` counts owned
RAM and is invariant across a process's lifetime, so it cannot witness
reclamation. `free_bytes` (`data[3]`) is the byte count currently in free
runs: it falls as `REQUEST_MEMORY_CAPS` lends pages and rises as
`PROCESS_DIED`, `RELEASE_MEMORY_CAPS`, and `UNREGISTER_REGION` return them.
`deferred_bytes` (`data[4]`) is the byte count those three took back but
hold on the deferred list, because another process can still reach the
frames (see [`memory-pool.md`](memory-pool.md) §"Reclamation"); it falls as
a later recheck moves them to the free runs. A caller asserting that a dead
process's pages were reclaimed polls `data[3]` back to its pre-spawn
baseline, and `data[4]` shows what is held instead. `largest_free_bytes`
(`data[5]`) shows how fragmented the free runs are: below
`DEMAND_CHUNK_PAGES` pages while `data[3]` is not zero, a demand fault is
backed from a smaller run (§ Kernel-origin fault message). `data[3]` to
`data[5]` are appended after the identity terms; readers needing only the
identity may ignore them.

### Label 7: `REGISTER_REGION`

A demand-paged process registers an anonymous region it has reserved (but
not backed). A later page fault inside the region that its protection permits
is backed on demand by the fault arm below; a fault outside every registered
region, or one its protection refuses, is declined, preserving segfault
semantics: a user-mode access kills the thread, and a restartable syscall's
kernel copy fails its syscall with `InvalidAddress`
([docs/fault-handling.md](../../../docs/fault-handling.md) § Kernel Copies).
Privilege: universal — attributed to the caller by `recv.badge`.

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
| 3 | `QUOTA` | Tracking-metadata arena could not grow (system RAM exhausted) |
| 4 | `INVALID_ARGUMENT` | Bad alignment, zero length, W^X violation, unknown prot bit, unknown badge, or overlap |

Per-process region and frame counts are bounded by RAM (the self-hosted
node arena), not by a fixed constant; `QUOTA` therefore signals genuine RAM
exhaustion, not a per-process ceiling. See [`memory-pool.md`](memory-pool.md)
§"Metadata Arena".

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
| 4 | `INVALID_ARGUMENT` | Unknown badge or missing cap (a stray transferred cap is dropped) |
| 5 | `UNAUTHORIZED` | Caller is not procmgr |

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

memmgr finds the exact-match region and tears the whole span down in one
`mem_unmap_reclaim` call against the caller's delegated `AddressSpace`: the
kernel clears the span's leaf PTEs and returns the now-empty intermediate page
tables to that address space's PT growth budget (observable via
`CAP_INFO_ASPACE_PT_BUDGET`; see
[docs/capability-model.md](../../../docs/capability-model.md)
§"Address-space and CSpace growth budgets") under a single coarse TLB shootdown (plus one span
invalidation each time the cleared frames overflow the kernel's frame-map release batch).
memmgr then returns each backing frame to the free pool and frees the region (see
[`memory-pool.md`](memory-pool.md) §"Reclamation"). The region
occupies its own VA surface, so the span unmap touches only frames memmgr
backed on fault; frames the caller mapped itself (e.g. `REQUEST_MEMORY_CAPS`
grants) live on a disjoint surface and are untouched. The frames return to the
pool as on `PROCESS_DIED`, so the all-RAM-accounted identity is unaffected.

**Reply (success):** `label` 0.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | Unknown badge, or no region matches `[va_base, len)` exactly |

### Kernel-origin fault message (`FAULT_LABEL`)

Not a callable label. When a demand-paged process's thread takes a page
fault the kernel cannot resolve, it synthesises an IPC to memmgr's
endpoint with label `FAULT_LABEL` (`u64::MAX - 1`), `badge` = the derivation
badge of the Endpoint cap bound by `SYS_THREAD_SET_FAULT_HANDLER` (procmgr binds
the process's own badged memmgr cap on its main thread, and the runtime copies
that binding onto each thread it spawns with `SYS_THREAD_INHERIT_FAULT_HANDLER`,
so this is the process's memmgr badge), and data words `[kind, faulting_va, access, ip]`
(see [docs/fault-handling.md](../../../docs/fault-handling.md)). For a
`FAULT_KIND_VM` fault whose `faulting_va` lies in a registered region of a
process with a delegated address space, and whose `access` the region's
protection grants, memmgr backs the part of the region's chunk containing
the page that no earlier run backs — one zeroed Memory cap mapped across up to
`DEMAND_CHUNK_PAGES` pages — with the region's protection, and replies
`FAULT_REPLY_RESUME` to retry the access; a fault on a page an earlier run
already backed (another thread's fault on the same chunk, delivered before the
mapping) is resumed without backing. When no free run covers that part, the
largest free run backs the pages around the faulting one, so the fault is
declined for want of RAM only when no page is free
([`memory-pool.md`](memory-pool.md#demand-faults) § Demand faults). Backing a
chunk rather than a single page keeps cap-slot consumption to one cap per chunk
on an unfragmented pool, so a deep demand stack cannot exhaust memmgr's CSpace;
stacks grow contiguously, so a chunk's pages are consumed as the stack
descends. The page tables the map needs come from the process address space's own page-table
pool. When the kernel reports that pool exhausted, memmgr funds it from its free pool, accounted
to the process, and maps the chunk again, at most four times
([`memory-pool.md`](memory-pool.md#client-page-table-funding) § Client page-table funding). So a
fault in a region does not depend on the process having funded the pool beforehand. A non-VM
fault replies `FAULT_REPLY_KILL`, and every other case — unknown process, address outside every
region, a write to a region without `MAP_WRITABLE` or an instruction fetch from one
without `MAP_EXECUTABLE` (which no backing satisfies), no delegated AS, or any allocation/map
failure — replies `FAULT_REPLY_FORWARD`; each carries data word 0 the decline reason: the code below
in its low 32 bits, and in its high 32 the magnitude of the failed syscall's error for code 9, else
zero. The kernel hands the fault to the thread's exception handler, the crash endpoint procmgr
binds, with the word as data word 4; with no exception handler bound, or for the fault of a kernel
copy (a restartable syscall's user copy, which then fails with `InvalidAddress`), the forward is a
decline, and the kernel prints the word on the kill diagnostic of a user-mode access
([docs/fault-handling.md § Reply](../../../docs/fault-handling.md#reply)). Either way the fault
takes the decline's outcome unless that handler resumes it, and memmgr waits on no handler it
forwards to.

| Code | Decline |
|---|---|
| 1 | Not a `FAULT_KIND_VM` fault |
| 2 | No process record carries the badge |
| 3 | `faulting_va` lies in no registered region |
| 4 | The region's protection refuses the access |
| 5 | No delegated address space |
| 6 | The metadata arena cannot grow for the run's frame descriptor |
| 7 | No free page can back the faulting page: the free pool is empty after the deferred runs are rechecked, or the split of a run larger than the span to back failed |
| 8 | The run's frame descriptor cannot be recorded |
| 9 | A map of the run failed: into memmgr, to zero it ([`memory-pool.md`](memory-pool.md#frame-contents) § Frame contents), or into the process, after the page-table funding above when the pool was exhausted; memmgr unmaps whatever part of the run the failed map left mapped |

Demand chunks are tracked exactly like `REQUEST_MEMORY_CAPS` allocations, so
`PROCESS_DIED` / `UNREGISTER_REGION` reclaim them and the all-RAM-accounted
identity is unaffected (the pages move from a free run to the process record;
they were already owned). The runs memmgr donates to the process's page-table
pool are tracked the same way and reclaimed by `PROCESS_DIED` only.

---

## Capability Transfer

Every Memory cap memmgr returns is a derive-twice copy: memmgr retains
an intermediary in its own CSpace, the caller receives the second
derivation. This guarantees memmgr can reclaim on `PROCESS_DIED` even
after the caller's CSpace is torn down. See [`memory-pool.md`](memory-pool.md)
§"Allocation".

Neither `RELEASE_MEMORY_CAPS` nor `PROCESS_DIED` transfers the caps it
reclaims. `RELEASE_MEMORY_CAPS` names each region by its region id, and
`PROCESS_DIED` names the dead process by badge. Reclamation returns memmgr's
retained intermediary to the free pool; memmgr does not derive from the
caller's cap.

Only two labels carry caps in their contract: `DONATE_MEMORY_CAPS` (every
attached cap) and `DELEGATE_ASPACE` (`cap[0]`). memmgr deletes every other
cap a message carries before it handles the message, whatever the label,
the caller, or the reply: the caps attached to any other label (a
`FAULT_LABEL` message and an unknown label included) and the caps after
`cap[0]` on `DELEGATE_ASPACE`. It deletes the contract caps as well when the
caller is not procmgr, and in the error cases the two labels' sections
state. An attached cap therefore never outlives the call that carried it
unless memmgr takes ownership of it, so no client can fill memmgr's `CSpace`
by attaching caps until its receive loop fails and memmgr exits with
`EXIT_RECV_WEDGE` (see
[docs/ipc-design.md](../../../docs/ipc-design.md#receive-failure-policy)
§"Receive-Failure Policy").

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

[Kernel Cross-Boundary Disclosure Inventory](../../../core/kernel/docs/cross-boundary-disclosure.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md),
[Fault Handling](../../../docs/fault-handling.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[Userspace Memory Model](../../../docs/userspace-memory-model.md),
[programs/capexhaust/README.md](../../../programs/capexhaust/README.md),
[programs/demandpaged/README.md](../../../programs/demandpaged/README.md),
[programs/stackoverflow/README.md](../../../programs/stackoverflow/README.md),
[programs/threadchurn/README.md](../../../programs/threadchurn/README.md),
[programs/threadstack/README.md](../../../programs/threadstack/README.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[services/memmgr/README.md](../README.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md)
