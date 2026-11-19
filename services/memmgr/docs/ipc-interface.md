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
  `QUERY_POOL_STATUS`, `REGISTER_REGION`, `UNREGISTER_REGION`,
  `QUERY_MEMORY_USAGE`, `REGISTER_PRESSURE`, `EXTEND_REGION`,
  `SHRINK_REGION`, `CREATE_SUB_NODE`, `DISCARD_RANGE`) are callable over any
  badged cap but a node handle, including those memmgr returned from
  `REGISTER_PROCESS`. `REGISTER_REGION`, `UNREGISTER_REGION`,
  `QUERY_MEMORY_USAGE`, `REGISTER_PRESSURE`, `EXTEND_REGION`,
  `SHRINK_REGION`, `CREATE_SUB_NODE` and `DISCARD_RANGE` are attributed to
  the caller by its own badge.
- **Node** labels (`NODE_SET_MAX`, `NODE_CREATE`, `NODE_QUERY_USAGE`,
  `NODE_REGISTER_LIMIT`, `NODE_RELEASE`) are callable only over a node
  handle, and act on the budget node it names (§ Node Handles).
- **Swap** labels (`SWAP_REGISTER`, `SWAP_TAKE`, `SWAP_DONE`,
  `SWAP_RESTORE`, `SWAP_WANTED`) are callable only over the swap authority, a
  `SEND|GRANT` badged `SWAP_AUTHORITY` (bit 61) alone, which init mints on
  memmgr's endpoint and svcmgr publishes seed-only as `memmgr.swap`: the swap
  service's interface to the disk tier (§ Labels 22 to 26).

memmgr tells the classes apart by two verb bits, the node-handle bit
`NODE_HANDLE_TAG` (bit 62) and the swap authority's `SWAP_AUTHORITY` (bit
61), the pattern of
[docs/capability-model.md](../../../docs/capability-model.md) § Verb-bit
authority pattern: it serves the node labels only on a badge that carries bit
62, the swap labels only on one that carries bit 61, and every other label
only on one that carries neither, and replies `UNAUTHORIZED` otherwise,
deleting any cap the message carries. No process badge carries either:
memmgr draws a process badge with every verb bit of `ipc::VERB_BIT_MASK`
(bits 58 to 63) clear but the phys-class bit 63, and a node handle's key with
them clear but bit 62, and init mints procmgr's badge on memmgr's endpoint
with all six clear.

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

## Node Handles

A node handle is the authority to control one budget node
([`memory-pool.md`](memory-pool.md) § Distribution policy): a SEND+GRANT cap
on memmgr's endpoint whose badge is `NODE_HANDLE_TAG` and a key of 58 random
bits outside `VERB_BIT_MASK`, drawn until no process badge or other key in
use matches it. memmgr derives it, and only memmgr, from its own endpoint, so
the set-once badge rule makes the key unforgeable by any holder; the key is a
name, and the cap is the authority. memmgr derives a handle in three places:

- `REGISTER_PROCESS` with `REGISTER_NODE_HANDLE` (§ Label 3): the new
  process's node, which procmgr passes to the creator that asked for it
  with `CREATE_NODE_HANDLE`;
- `NODE_CREATE` (§ Label 15): a sub-node under the handle's node;
- `CREATE_SUB_NODE` (§ Label 19): a sub-node under the caller's own node.

A holder can derive copies of a handle, which carry the same badge. Every
handle to a node names its handle state, which belongs to one process: the
node's own process, or for a sub-node the owner of the state of the node it
was made under (`NODE_CREATE`), or the caller (`CREATE_SUB_NODE`). The state
goes when that process's `PROCESS_DIED` arrives, or, for a sub-node, on
`NODE_RELEASE`, and memmgr deletes its limit Notification then; the
Notification goes earlier when its registrant dies (§ Label 17). From then on
memmgr refuses every handle carrying its key with `INVALID_ARGUMENT`. A node
outlives its handle state while a process, a node below it or a charge refers
to it, so a process charged to a released sub-node keeps its budget.

A creator that holds a handle can charge a new child to the handle's node by
passing a copy with `CREATE_CHARGE_NODE`
([procmgr IPC interface](../../procmgr/docs/ipc-interface.md#label-1-create_process)),
which procmgr hands to memmgr with `REGISTER_CHARGE_NODE` (§ Label 3).

No process receives a handle to its own node through these paths, so none can
raise the max its creator set; the handles it holds name its children's nodes
and the sub-nodes it made. Nothing is reclaimed or killed through a handle.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message
label field identifies the operation. Data words and capability slots
carry arguments; the reply carries results. Error codes below are the
`memmgr_errors` constants in `shared/ipc`. A label memmgr does not define
replies `INVALID_ARGUMENT`, or `UNAUTHORIZED` over a node handle. Every
label but the node labels also replies `UNAUTHORIZED` over a node handle, and
every label but the swap labels over the swap authority (§ Badge
Discipline); the node labels' tables list the refusal over any other badge, as
§ Labels 22 to 26 does for the swap labels.

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

memmgr admits the whole of `want_pages` against the caller's budget node before it selects a run,
and charges the node each page it grants ([`memory-pool.md`](memory-pool.md) § Distribution policy).
A request over the max of the node or of an ancestor fails `LIMIT`, whatever part of it the pool
could serve; one that would leave fewer free pages outside `promised`
([`memory-pool.md`](memory-pool.md) § Commit) than the growth floor (the system reserve and, while
chunks are swapped, the restore headroom; `memory-pool.md` § Distribution policy), from a caller
outside the reserve, or than none, fails as exhaustion, with code 1 or 2.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |
| data[0..3] | Only on codes 1 and 2, and only when pool selection fails (not when deriving the caller's copy fails): total free pages, free-run count, and the largest free run in pages |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `OUT_OF_MEMORY_CONTIGUOUS` | `REQUIRE_CONTIGUOUS` set; no run satisfies, or the grant would take the growth floor from a caller outside the system reserve |
| 2 | `OUT_OF_MEMORY_BEST_EFFORT` | Best-effort: the pool's free pages do not cover `want_pages`, no run could be taken, the grant would take the growth floor from a caller outside the system reserve, or deriving the caller's copy failed |
| 3 | `QUOTA` | Tracking-metadata arena could not grow (system RAM exhausted), memmgr could not map a selected run to zero it ([`memory-pool.md`](memory-pool.md#frame-contents) § Frame contents), or the caller's region-id sequence is spent (unreachable: 2^64 − 1 grants) |
| 4 | `INVALID_ARGUMENT` | `want_pages == 0`, `flags` reserved bits set, or badge unknown |
| 8 | `LIMIT` | `want_pages` would take the subtree of the caller's budget node, or of an ancestor, over its max |

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
tracking entry and the process's budget node, and returns a badged SEND cap
on memmgr's endpoint that procmgr will install in the new process's
`ProcessInfo.memmgr_endpoint_cap`. Privilege: procmgr-only.

**Request:**

| Field | Value |
|---|---|
| label | 3 |
| data[0] | Caller's `MEMMGR_LABELS_VERSION` |
| data[1] | Flags: bit 0 `REGISTER_PHYS_CLASS` registers the process phys-class; bit 1 `REGISTER_RESERVE` makes its budget node a reserve node; bit 2 `REGISTER_MAX` gives the node the max in `data[3]`; bit 3 `REGISTER_NODE_HANDLE` returns a handle to the node in `cap[1]`; bit 4 `REGISTER_CHARGE_NODE` puts the node under the node of the handle in `cap[0]`; other bits reserved, zero |
| data[2] | Memmgr-side badge of the process whose budget node is the new node's parent, or 0 for a top-level node; ignored with `REGISTER_CHARGE_NODE` |
| data[3] | With `REGISTER_MAX`: the node's max in pages, `u64::MAX` for none; ignored otherwise |
| cap[0] | With `REGISTER_CHARGE_NODE`: a node handle (§ Node Handles), which procmgr took from the creator's `CREATE_CHARGE_NODE` request; ownership transfers to memmgr, which deletes it on every path. Absent otherwise; a cap sent without the flag is deleted |

The budget node ([`memory-pool.md`](memory-pool.md) § Distribution policy)
is created under the node of the process `data[2]` names, or with
`REGISTER_CHARGE_NODE` under the node of the handle in `cap[0]`, so a
creator that holds a handle charges its child to that node: two children
charged to one sub-node share its budget. memmgr reads the handle's key with
`SYS_ENDPOINT_BADGE`, which only the holder of Receive on its endpoint can
call, so the cap, not a key a caller names, is the authority. memmgr clamps a
max to what the parent and every ancestor have left, so a node never asks
for more than its chain can grant, and replies with the max the node took.
Without `REGISTER_MAX` the node has no max, and only its ancestors and the
system reserve limit it. memmgr refuses a reserve node under a parent outside
the reserve; whether a creator may ask for a reserve child, and what max it
asks, is procmgr's to check before it registers.

The badge of the requesting endpoint identifies procmgr; memmgr verifies
this and rejects the call otherwise. memmgr mints a fresh badge for the
new process internally — procmgr does not supply it: the 58 bits outside
`ipc::VERB_BIT_MASK` drawn at random, the verb bits 58 to 62 clear, and bit 63
(`PHYS_CLASS_BADGE_BIT`) set for a phys-class process and clear for every
other (§ Badge Discipline). A phys-class process's grants keep `RIGHTS_MEM_PHYS`
([Label 1](#label-1-request_memory_caps)); the kernel stamps the badge on the
process's SEND cap, so no process can claim the class. procmgr sets the flag
only for a child created with `CREATE_PHYS_ACCESS`, which it accepts only from
an un-badged or phys-class creator: init creates devmgr with it and devmgr the
IOMMU driver (see the
[procmgr IPC interface](../../procmgr/docs/ipc-interface.md#label-1-create_process)).
init clears every verb bit in the badge it mints for procmgr on memmgr's
endpoint, and memmgr refuses a bootstrap whose procmgr badge carries one, so
procmgr's own grants lack the right and its badge is no node handle.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | Memmgr-side process badge (procmgr forwards this in `PROCESS_DIED`) |
| data[1] | The max the budget node took, in pages, after the clamp; `u64::MAX` for none |
| cap[0] | Badged SEND cap on memmgr's endpoint, identifying the new process |
| cap[1] | With `REGISTER_NODE_HANDLE`: a node handle to the new process's budget node (§ Node Handles), owned by the new process's record; absent otherwise |

The badge is also encoded in the returned cap, but `SYS_ENDPOINT_BADGE`
reads a cap's badge only for the holder of Receive on its endpoint, which
procmgr is not, so memmgr returns it explicitly in `data[0]` for procmgr
to record alongside the cap and forward in the eventual `PROCESS_DIED`.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | Reserved `data[1]` flag bits set; `data[2]` names no process, or memmgr's or init's own boot record; with `REGISTER_CHARGE_NODE`, `cap[0]` missing, or no node handle whose key names a handle state; or `REGISTER_RESERVE` under a parent outside the reserve |
| 5 | `UNAUTHORIZED` | Caller is not procmgr |
| 6 | `TOO_MANY_PROCESSES` | The tracking table could not take a new entry (its record node, its budget node or, with `REGISTER_NODE_HANDLE`, its handle state could not be allocated: system RAM exhausted), the badge or key draw failed, or a reply cap could not be derived |
| 7 | `LABEL_VERSION_MISMATCH` | `data[0]` is not memmgr's `MEMMGR_LABELS_VERSION` |

### Label 4: `PROCESS_DIED`

Procmgr signals process death. memmgr looks up the per-process tracking entry
by badge, deletes the process's `REGISTER_PRESSURE` cap, takes back every
Memory cap memmgr has issued to that process, and runs coalescing (see
[`memory-pool.md`](memory-pool.md) §"Reclamation"). A frame another process
can still reach, through a capability to it, a kernel object retyped from it,
or a user mapping of it, waits on memmgr's deferred list rather than joining
the free pool, until a later recheck finds it unreachable. Privilege:
procmgr-only.

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
bootstrap round, the free remainders `MemoryAlloc` abandoned, the page that
carried the spawned services' `SERAPH_LOG` entries when init allocated one, ELF
segments, `InitInfo`, stack, the bootloader/bundle reclaim ranges, the
AP-trampoline frame, and boot-module ELF sources. See
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
deferred, largest-run and promised totals and the memory-pressure level. Privilege:
universal — returns aggregate counts only, no caps and no state change.

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
| data[6] | `reserve_bytes` — the system reserve: the free pages only a charge to a reserve node may take ([`memory-pool.md`](memory-pool.md) § Distribution policy) |
| data[7] | `pressure` — the memory-pressure level: 0 `PRESSURE_NORMAL`, 1 `PRESSURE_LOW`, 2 `PRESSURE_CRITICAL`, at or below the growth floor ([`memory-pool.md`](memory-pool.md) § Memory pressure) |
| data[8] | `promised_bytes` — what the committed regions can still take from the free runs: their pages that hold no frame yet, and bounds on the page tables and metadata they can need ([`memory-pool.md`](memory-pool.md) § Commit) |
| data[9] | `store_bytes` — subset of `pool_total_bytes` the compressed store holds: the stored pages of every evicted chunk ([`memory-pool.md`](memory-pool.md#eviction) § Eviction) |
| data[10] | `swapped_bytes` — the pages of every evicted chunk, in either tier (compressed in the store, being written, on disk, or lost), which their processes' budget nodes stay charged for |
| data[11] | `growth_floor_bytes` — the free pages outside `promised` a charge to a budget node outside the reserve may not take: the system reserve and, while chunks are swapped, the restore headroom, `data[6]` plus the lesser of `data[10]` and `data[6]` ([`memory-pool.md`](memory-pool.md#eviction) § Eviction, Restore headroom) |
| data[12] | `disk_bytes` — the pages of every chunk on disk, the subset of `data[10]` only the swap service's slots hold ([`memory-pool.md`](memory-pool.md#disk-tier) § Disk tier) |
| data[13] | `swap_slots_free` — the swap slots registered and not taken; `0` while no swap service is registered (§ Labels 22 to 26) |

The all-RAM-accounted identity is `data[0] == data[1] + data[2]`: every page
is either fixed kernel reserve or in memmgr's pool. `pool_total` counts owned
RAM and is invariant across a process's lifetime, so it cannot witness
reclamation. `free_bytes` (`data[3]`) is the byte count currently in free
runs: it falls as `REQUEST_MEMORY_CAPS` lends pages and rises as
`PROCESS_DIED`, `RELEASE_MEMORY_CAPS`, `UNREGISTER_REGION`, `SHRINK_REGION`
and `DISCARD_RANGE` return them. `deferred_bytes` (`data[4]`) is the byte
count those took back but
hold on the deferred list, because another process can still reach the
frames (see [`memory-pool.md`](memory-pool.md) §"Reclamation"); it falls as
a later recheck moves them to the free runs. A caller asserting that a dead
process's pages were reclaimed polls `data[3]` back to its pre-spawn
baseline, and `data[4]` shows what is held instead. `largest_free_bytes`
(`data[5]`) shows how fragmented the free runs are: below
`DEMAND_CHUNK_PAGES` pages while `data[3]` is not zero, a demand fault is
backed from a smaller run (§ Kernel-origin fault message). `reserve_bytes`
(`data[6]`) is `pool_total / 64` pages. `growth_floor_bytes` (`data[11]`) is
the reserve while nothing is swapped: a process outside the reserve has its
grants refused, and its demand faults declined, once `data[3]` less
`data[8]` less the request would fall below it, and the level is
`PRESSURE_CRITICAL` at or below it. `pressure` (`data[7]`) is the
level memmgr last signalled to the `REGISTER_PRESSURE` registrants, so a
registrant woken by its bit reads here the level the bit announced, or a later
one. `promised_bytes` (`data[8]`) is held for the committed regions' faults:
every admission reads `data[3]` less it, so a free page it counts is refused to
every other charge. `store_bytes` (`data[9]`) and `swapped_bytes`
(`data[10]`) rise as memmgr evicts cold chunks under pressure and fall as
faults restore them or their regions go; their ratio is the store's
compression; a chunk on disk leaves `data[9]` and stays in `data[10]`, and
`data[12]` counts it. `data[3]` to `data[13]` are appended after the identity terms;
readers needing only the identity may ignore them.

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
| data[3] | flags: bit 0 `REGION_COMMIT`, bit 1 `REGION_NO_EVICT`; 0 for none |

**Reply (success):** `label` 0. No mapping is installed — backing happens
lazily on fault, and only once procmgr has delegated this process's
`AddressSpace` cap via `DELEGATE_ASPACE`.

**Committed regions.** With `REGION_COMMIT`, memmgr admits and charges the
region's whole length before it registers it: its pages and a page-table
reservation to the caller's budget node, and those and a metadata bound to
`promised` (`QUERY_POOL_STATUS` `data[8]`). A fault in a committed region is
then not declined for budget or RAM (codes 7 and 10 below) while the region's
page-table reservation, which its page-table donations draw on, lasts: a thread
of the process that maps while a committed fault's map is funded, or a
reclaiming unmap of page tables in the region's span the process made or asked
for, can spend it, and a donation past it is admitted as any other, so the
fault can then be declined with code 10 or 9. Only a committed region grows by
`EXTEND_REGION` (§ Label 12) or shrinks by `SHRINK_REGION` (§ Label 13); a
discard by `DISCARD_RANGE` (§ Label 20) keeps its commitment, so a refault of
a discarded page is admitted as its first touch was. A
refused commitment registers nothing. A reply that does not reach the caller
unregisters the region again, as a grant whose reply fails is rolled back, so a
caller whose call was interrupted makes it again
([`memory-pool.md`](memory-pool.md) § Commit). The std heap registers its
growth region this way.

**No-evict regions.** With `REGION_NO_EVICT`, memmgr never evicts a page of
the region into its compressed store, so every page a fault backed stays
mapped until the region is unregistered or the page discarded. Without it,
memmgr may evict a cold chunk of an uncommitted region under memory pressure
and restores it on the next fault on it, which only a debugger's
`SYS_THREAD_READ_MEM` can tell apart ([`memory-pool.md`](memory-pool.md#eviction)
§ Eviction).

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 2 | `OUT_OF_MEMORY_BEST_EFFORT` | A committed region's charge would leave fewer free pages outside `promised` than the growth floor, for a caller outside the system reserve, or than none |
| 3 | `QUOTA` | Tracking-metadata arena could not grow (system RAM exhausted) |
| 4 | `INVALID_ARGUMENT` | Bad alignment, zero length, W^X violation, unknown prot or flag bit, unknown badge, or overlap |
| 8 | `LIMIT` | A committed region's charge would take the subtree of the caller's budget node, or of an ancestor, over its max |

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
memmgr then removes the region and frees its chunk table, returning each run on it to the free
pool (see [`memory-pool.md`](memory-pool.md) §"Reclamation"). The region
occupies its own VA surface, so the span unmap touches only frames memmgr
backed on fault; frames the caller mapped itself (e.g. `REQUEST_MEMORY_CAPS`
grants) live on a disjoint surface and are untouched. The frames return to the
pool as on `PROCESS_DIED`, so the all-RAM-accounted identity is unaffected.

**Reply (success):** `label` 0.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | Unknown badge, or no region matches `[va_base, len)` exactly |

### Label 10: `QUERY_MEMORY_USAGE`

Read-only query of the caller's own budget node
([`memory-pool.md`](memory-pool.md) § Distribution policy). Privilege:
universal — attributed to the caller by `recv.badge`; it reads no other
process's node, carries no caps and changes no state.

**Request:** label 10, no words, no caps.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | `own_pages` — pages charged to the caller's node |
| data[1] | `max_pages` — the node's max, `u64::MAX` for none |
| data[2] | `subtree_pages` — pages charged to the node and to every node below it |
| data[3] | `resident_pages` — the pages of `own_pages` not swapped |
| data[4] | `swapped_pages` — the pages of `own_pages` memmgr evicted, in either tier (its compressed store or the swap service's slots), which the node stays charged for ([`memory-pool.md`](memory-pool.md#eviction) § Eviction) |

The charge counts each grant, demand chunk of an uncommitted region and
page-table donation memmgr accounts to the caller, each committed region's
pages and what is left of its page-table reservation, charged whole when the
region is committed whether or not its pages hold frames (§ Label 7), and each
such run held on the deferred list after the caller released it, until the run
rejoins the free pool. A max below
`subtree_pages` is not an error: a lowered max refuses new charges until the
usage falls below it.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | Unknown badge |

### Label 11: `REGISTER_PRESSURE`

Register the Notification memmgr signals when the memory-pressure level
changes ([`memory-pool.md`](memory-pool.md) § Memory pressure). Privilege:
universal — attributed to the caller by `recv.badge`. The std runtime
registers every process at start (`runtime/ruststd/README.md` § Process
Entry), so a process waits on the signal with no call of its own.

**Request:**

| Field | Value |
|---|---|
| label | 11 |
| data[0] | `bits` — the bits to send on a change of level; nonzero |
| cap[0] | a Notification cap with Notify rights; ownership transfers to memmgr |

memmgr keeps one registration per process: a second replaces the first, and
memmgr deletes the cap the first carried, so a client holds one slot of
memmgr's `CSpace` however often it registers. `PROCESS_DIED` deletes the cap.
On each change of level memmgr sends `bits` on the cap once, without
blocking: a send to a Notification ORs the bits in and never waits, and bits
not yet taken coalesce. The bit says that the level changed; the level is read
from `QUERY_POOL_STATUS` `data[7]`. A send that fails, for a cap the client
revoked, is dropped.

**Reply (success):** label 0, no words, no caps.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | Unknown badge, zero `bits`, or `cap[0]` missing or not a Notification with Notify rights; memmgr deletes the cap, and any earlier registration stays |

### Label 12: `EXTEND_REGION`

Grow a committed region (§ Label 7, `REGION_COMMIT`) of the caller in place,
its base kept. Privilege: universal — attributed to the caller by
`recv.badge`. The std heap grows by it.

**Request:**

| Field | Value |
|---|---|
| label | 12 |
| data[0] | `va_base` (the registered base) |
| data[1] | `new_len_bytes` (page-multiple, at least the length) |

memmgr admits and charges the growth as a committed registration of it:
each part of the commitment is computed from the whole length, so a region
grown in steps is charged what one registration of its final length would be,
and the page-table reservation from the largest length the region has had, so
a regrowth after a cut (§ Label 13) adds none up to it
([`memory-pool.md`](memory-pool.md) § Commit). The region's chunk table gains
the directory levels the new length needs. A reply that does not reach the
caller undoes the growth, its page-table reservation included, so a caller
whose call was interrupted makes it again without being charged twice.

**Reply (success):** `label` 0, also for a `new_len_bytes` equal to the
length.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 2 | `OUT_OF_MEMORY_BEST_EFFORT` | The growth's charge would leave fewer free pages outside `promised` than the growth floor, for a caller outside the system reserve, or than none |
| 3 | `QUOTA` | Tracking-metadata arena could not grow for the chunk table's new levels |
| 4 | `INVALID_ARGUMENT` | Unknown badge, no committed region based at `va_base`, a length unaligned, smaller, or past the address space, or growth that meets another region |
| 8 | `LIMIT` | The growth's charge would take the subtree of the caller's budget node, or of an ancestor, over its max |

### Label 13: `SHRINK_REGION`

Lower the top of a committed region (§ Label 7, `REGION_COMMIT`) of the
caller, its base kept. Privilege: universal — attributed to the caller by
`recv.badge`.

**Request:**

| Field | Value |
|---|---|
| label | 13 |
| data[0] | `va_base` (the registered base) |
| data[1] | `new_len_bytes` (a nonzero multiple of the 64 KiB demand chunk, at most the length) |

memmgr unmaps the pages past the new top from the caller's delegated
`AddressSpace`, then cuts the chunks past it from the region's chunk table,
returning each run on them to the free pool or the deferred list as
`UNREGISTER_REGION` does (§ Label 9), and releases the commitment of the pages
cut: their charge and their part of `promised`. It keeps the page tables of
the pages cut, and with them the region's page-table reservation, until the
region is unregistered ([`memory-pool.md`](memory-pool.md) § Commit). A repeat of a cut finds the
region at its new length and succeeds, so an interrupted call is safe to
repeat.

**Reply (success):** `label` 0, also for a `new_len_bytes` equal to the
length.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | Unknown badge, no committed region based at `va_base`, or a length that is zero, not a chunk multiple, or larger than the length |

### Label 14: `NODE_SET_MAX`

Set the max of the handle's budget node while its processes run
([`memory-pool.md`](memory-pool.md) § Distribution policy). Privilege: node,
over a node handle (§ Node Handles).

**Request:**

| Field | Value |
|---|---|
| label | 14 |
| data[0] | `max_pages` — the max asked for, `u64::MAX` for none |

memmgr clamps the max to the node's subtree usage plus what its parent chain
has left, as `REGISTER_PROCESS` clamps a new node's, so a node grows only into
room its ancestors still have; `u64::MAX` stays unbounded, limited by the chain
at each charge. A max below the usage is kept: it reclaims and kills nothing,
and refuses new charges until the usage falls below it. A max at or below the
usage signals the node's limit event (§ Label 17).

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | the max the node took, `u64::MAX` for none |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | The handle's key names no handle state (released, or its owner gone) |
| 5 | `UNAUTHORIZED` | The badge is not a node handle |

### Label 15: `NODE_CREATE`

Make a sub-node under the handle's node and return a handle to it. Privilege:
node, over a node handle (§ Node Handles). Processes charged to one sub-node
share its budget; procmgr's charge to a sub-node at process creation is the
next phase of [#1097](https://github.com/kottlerg/seraph/issues/1097).

**Request:**

| Field | Value |
|---|---|
| label | 15 |
| data[0] | `max_pages` — the sub-node's max, `u64::MAX` for none |

The sub-node is outside the reserve, and its max is clamped to what the
handle's node and its ancestors have left. Its handle state belongs to the
owner of the handle's state, and goes when that process dies or on
`NODE_RELEASE` (§ Label 18). A reply that does not reach the caller drops the
state, so no unnamed sub-node is left behind.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | the max the sub-node took, `u64::MAX` for none |
| cap[0] | a node handle to the sub-node |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 3 | `QUOTA` | The node, its handle state or its index entry could not be allocated (system RAM exhausted), the key draw failed, or the handle could not be derived |
| 4 | `INVALID_ARGUMENT` | The handle's key names no handle state, or its owner holds no record |
| 5 | `UNAUTHORIZED` | The badge is not a node handle |

### Label 16: `NODE_QUERY_USAGE`

Read-only query of the handle's node. Privilege: node, over a node handle
(§ Node Handles); it changes no state.

**Request:** label 16, no words, no caps.

**Reply (success):** as `QUERY_MEMORY_USAGE` (§ Label 10), for the handle's
node: `data[0]` `own_pages`, `data[1]` `max_pages` (`u64::MAX` for none),
`data[2]` `subtree_pages`.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | The handle's key names no handle state |
| 5 | `UNAUTHORIZED` | The badge is not a node handle |

### Label 17: `NODE_REGISTER_LIMIT`

Register the Notification memmgr signals on the limit event of the handle's
node ([`memory-pool.md`](memory-pool.md) § Distribution policy). Privilege:
node, over a node handle (§ Node Handles).

**Request:**

| Field | Value |
|---|---|
| label | 17 |
| data[0] | `bits` — the bits to send on the limit event; nonzero |
| cap[0] | a Notification cap with Notify rights; ownership transfers to memmgr |
| cap[1] | a copy of the registrant's own SEND on memmgr's endpoint, the cap `ProcessInfo.memmgr_endpoint_cap` names; memmgr reads its badge with `SYS_ENDPOINT_BADGE` and deletes it |

memmgr keeps one registration per handle state, and it belongs to its
registrant, the process `cap[1]` names: a second registration replaces the
first, and memmgr deletes the cap the first carried. The registrant's
`PROCESS_DIED` deletes the cap, so a holder of a node handle that is not the
state's owner cannot leave a Notification in memmgr past its own life, and
the state's end (its owner's `PROCESS_DIED`, or `NODE_RELEASE`) deletes it
too. After each request,
memmgr checks the chain from the node the request charged, or whose max it
set, to the top, and sends `bits` once, without blocking, to each node on it
whose subtree holds its max or more, or whose own max refused the request's
charge. A charge that brings the subtree to its max, each refused charge, and
a max set at or below the usage each send once; bits not yet taken coalesce,
and a send that fails, for a cap the holder revoked, is dropped. A refusal for
want of free RAM, not of a max, signals no node.

**Reply (success):** label 0, no words, no caps.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | The handle's key names no handle state, zero `bits`, `cap[0]` missing or not a Notification with Notify rights, or `cap[1]` missing, not a cap on memmgr's endpoint, or a node handle, or its badge names no process; memmgr deletes both caps, and any earlier registration stays |
| 5 | `UNAUTHORIZED` | The badge is not a node handle; memmgr deletes the caps |
| 6 | `TOO_MANY_PROCESSES` | The registration's arena slot could not be allocated: system RAM exhausted; memmgr deletes both caps, and any earlier registration stays |

### Label 18: `NODE_RELEASE`

Drop the handle state of a sub-node. Privilege: node, over a node handle
(§ Node Handles).

**Request:** label 18, no words, no caps.

memmgr drops the state and deletes its limit cap; every handle carrying its key
is refused from then on. The sub-node itself lives on while a process, a node
below it or a charge refers to it, so a process charged to it keeps its
budget. A process's own node is refused: its handle state goes with the
process.

**Reply (success):** label 0, no words, no caps.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | The handle's key names no handle state, or it names a process's own node |
| 5 | `UNAUTHORIZED` | The badge is not a node handle |

### Label 19: `CREATE_SUB_NODE`

Make a sub-node under the caller's own budget node and return a handle to it.
Privilege: universal — attributed to the caller by `recv.badge`. A process
divides its own budget this way; it holds no handle to its own node.

**Request:**

| Field | Value |
|---|---|
| label | 19 |
| data[0] | `max_pages` — the sub-node's max, `u64::MAX` for none |

As `NODE_CREATE` (§ Label 15), with the caller's node as the parent and the
caller as the owner of the sub-node's handle state.

**Reply (success):** as `NODE_CREATE`: `data[0]` the max the sub-node took,
`cap[0]` a node handle to it.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 3 | `QUOTA` | As `NODE_CREATE` |
| 4 | `INVALID_ARGUMENT` | Unknown badge |
| 5 | `UNAUTHORIZED` | The badge is a node handle |

### Label 20: `DISCARD_RANGE`

Discard pages of a demand region of the caller, committed or not: memmgr takes
back the frames that back them, and the next touch of each faults in a
zero-filled page. Privilege: universal — attributed to the caller by
`recv.badge`.

**Request:**

| Field | Value |
|---|---|
| label | 20 |
| data[0] | `va` (a whole number of 64 KiB demand chunks above the base of the region that holds it) |
| data[1] | `len_bytes` (nonzero; a whole number of chunks, or reaching the region's end) |

memmgr unmaps the pages from the caller's delegated `AddressSpace` without
reclaiming page tables, then clears the range's chunks from the region's chunk
table, returning each run on them to the free pool or the deferred list as
`UNREGISTER_REGION` does (§ Label 9). The region keeps its length and its
page tables. In an uncommitted region each run is uncharged from the caller's
budget node as it rejoins the pool. A committed region (§ Label 7) keeps its
commitment: its charge stays, and the pages taken back, with the metadata their
chunks gave back, return to `promised`, so a refault of a discarded page is
not declined for budget or RAM, as its first touch was not
([`memory-pool.md`](memory-pool.md#commit) § Commit). A range that holds no
run changes nothing, so an interrupted call is safe to repeat.

**Reply (success):** `label` 0, also for a range already discarded.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_ARGUMENT` | Unknown badge, no region holds `va`, or a range that breaks the rule above or leaves the region |
| 5 | `UNAUTHORIZED` | The badge is a node handle |

### Label 21: `MAKE_RESIDENT`

Make a range of a process's demand regions resident for a debugger: memmgr
restores each chunk of the range it holds in its store, compressed or writing,
and maps back each it is evicting, so a `SYS_THREAD_READ_MEM` that failed on a
page of it succeeds when the reader retries. memmgr reads no swap slot and
waits on no swap service, so a chunk on disk it asks the swap service for: when
the registered swap service gave a want Notification (§ Label 22), memmgr posts
the chunk's slot word to it, sends on the Notification, and replies pending
(below); the swap service takes the word (`SWAP_WANTED`, § Label 26), reads the
slot and restores the chunk ahead of a fault (`SWAP_RESTORE`, § Label 25), and
the reader asks again. A page no fault has backed stays not present, and so
does a page of a lost chunk, or of a chunk on disk with no swap service to ask,
which memmgr passes over
([`memory-pool.md`](memory-pool.md#disk-tier) § Disk tier).
Privilege: procmgr only, which sends it for a holder of its debug authority
(`services/procmgr/docs/ipc-interface.md` § `MAKE_RESIDENT`).

**Request:**

| Field | Value |
|---|---|
| label | 21 |
| data[0] | the process's memmgr badge (from its `REGISTER_PROCESS` reply) |
| data[1] | `va` |
| data[2] | `len_bytes` (nonzero) |

Each restore is admitted and made as a fault's on the chunk
([`memory-pool.md`](memory-pool.md#eviction) § Eviction), and counts as an
access in the chunk's age. A process with no delegated address space has
nothing evicted, and the request succeeds. memmgr walks only the chunks that
have an entry, in address order, and stops after `MAKE_RESIDENT_CHUNKS` (4)
chunks made resident or `MAKE_RESIDENT_VISITS` (64) chunks and regions
visited ([docs/limits.md](../../../docs/limits.md) § memmgr).

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 |
| data[0] | where memmgr stopped: `va + len_bytes` when the whole range is done, else the address to send the request again from, with the rest of the range |
| data[1] | `RESIDENT_PENDING` (1) when memmgr posted a chunk on disk of the range to the swap service: `data[0]` is then the first such chunk's base (or `va`, when that is above it), and the reader asks again from there after a pause, once the swap service has had time to restore it; else `0` |
| data[2] | where the walk stopped: `data[0]` when `data[1]` is `0`, else past every chunk on disk memmgr posted; a reader that will wait no longer asks again from there, passing those chunks over |

memmgr walks on past a chunk it posts, posting each chunk on disk and restoring
each chunk in RAM it meets within its bounds. A word stays posted until the swap
service takes it, at most `SWAP_WANTED_WORDS` (8) at a time, a full list dropping
its oldest word for a new one; a reader whose word was dropped posts it again when
it asks again. `ipc::make_resident` pauses 2 ms (`ipc::PENDING_PAUSE_MS`) after
each pending reply, and after 500 pauses in all (`ipc::PENDING_TRIES`), about a
second, it asks on from `data[2]` with no pause, passing the chunks on disk over;
crashd counts the pauses over a whole dump. A swap service that is down,
restarting, or cannot read the slot leaves those pages not present, and the reader
reads them as such, while the rest of the range is still made resident.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 2 | `OUT_OF_MEMORY_BEST_EFFORT` | A chunk could not be restored: its restore was not admitted, or a map failed; the chunks before it are resident |
| 4 | `INVALID_ARGUMENT` | Unknown badge, zero length, or a range past the address space |
| 5 | `UNAUTHORIZED` | The caller is not procmgr |

### Labels 22 to 26: the swap labels

The swap service's interface to memmgr's disk tier
([`memory-pool.md`](memory-pool.md#disk-tier) § Disk tier). Privilege: the
swap authority only (§ Badge Discipline); every other badge is refused
`UNAUTHORIZED`, its caps deleted. memmgr performs no device I/O and waits on
no swap service: each label is a request the swap service makes, and the
redirect of a fault on a chunk on disk is a fault reply (§ Kernel-origin fault
message). `SWAP_REGISTER` gives memmgr its caps to keep; each other label that
carries a cap moves it to memmgr for the call, and memmgr moves it back on every
reply.

#### Label 22: `SWAP_REGISTER`

Register the swap service: its restore endpoint and its slot count. A slot
holds one chunk (`DEMAND_CHUNK_BYTES`).

| Field | Value |
|---|---|
| label | 22 |
| data[0] | the slots the swap service's partition holds |
| data[1] | with `caps[1]`, the bits memmgr sends on it; nonzero |
| caps[0] | a SEND on the endpoint memmgr redirects each fault on a chunk on disk to, with any rights; memmgr keeps it |
| caps[1] | optional: a Notification with the Notify right memmgr sends `data[1]` on when `MAKE_RESIDENT` posts a slot word for the swap service (§ Label 21, § Label 26); memmgr keeps it |

Without `caps[1]`, `MAKE_RESIDENT` passes the chunks on disk over, as a lost
chunk. A registration replaces the one before it, whose caps memmgr deletes, and
ends every write in flight: each writing chunk is compressed again on its store runs,
and each slot whose write a restore or a teardown cancelled is freed. The
chunks on disk stay, and so do the slot words posted for the swap service: memmgr
sends on the new Notification at once when any are posted, so a restarted swap
service restores them. The reply's `data[0]` is the slots memmgr uses: the count,
clamped to the slot map's window ([docs/limits.md](../../../docs/limits.md)
§ memmgr).

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | Registered; `data[0]` the slots memmgr uses |
| 4 | `INVALID_ARGUMENT` | `caps[0]` missing, no Endpoint cap, or a cap on memmgr's own endpoint; `caps[1]` present and no Notification with the Notify right, or `data[1]` zero with it; the count below a slot ever taken, one on the free list included; or memmgr's key draw failed at start, so the disk tier is off. memmgr deletes the caps, and any earlier registration stays |

#### Label 23: `SWAP_TAKE`

Take the next compressed chunk for a swap slot, and write the slot's bytes into
the swap service's buffer.

| Field | Value |
|---|---|
| label | 23 |
| caps[0] | a Memory cap of at least `DEMAND_CHUNK_BYTES` with the write right: the swap service's buffer |

memmgr walks its records' regions for a compressed chunk, a bounded number of
steps a request (`TAKE_STEPS`, [docs/limits.md](../../../docs/limits.md)
§ memmgr), from where the last walk stopped. It copies the chunk's stream into
its own buffer, seals it there under its per-boot key and the next nonce,
takes a slot and a disk node, and writes the slot's bytes, the sealed stream
and its 16-byte tag, into the buffer from offset 0 through its own mapping of
the cap. The chunk is writing until `SWAP_DONE`.

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | `data[0]` the slot, `data[1]` its byte count, `data[2]` its slot word, the word a fault on the chunk is redirected with (§ Kernel-origin fault message) |
| 3 | `QUOTA` | The arena or the slot map could not grow, or the chunk's store runs could not be mapped |
| 4 | `INVALID_ARGUMENT` | No swap service is registered, or `caps[0]` missing, no Memory cap, smaller than a chunk, or not mappable writable |
| 9 | `NOTHING_TO_TAKE` | The walk found no compressed chunk within its bound; the next request goes on from where it stopped |
| 10 | `SWAP_FULL` | Every registered slot is taken |

#### Label 24: `SWAP_DONE`

End the write of a slot `SWAP_TAKE` named.

| Field | Value |
|---|---|
| label | 24 |
| data[0] | the slot |
| data[1] | `0` when the slot is written, nonzero when it is not |

A written chunk is on disk, its store runs returned to the free pool; an
unwritten one is compressed again on them, its slot freed. A write a restore or a
teardown cancelled while it was in flight frees its slot either way.

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | The write ended |
| 4 | `INVALID_ARGUMENT` | The slot holds no write in flight: never taken, ended already, or ended by a later `SWAP_REGISTER` |

#### Label 25: `SWAP_RESTORE`

Hand memmgr a slot's bytes, read back for a fault redirected to the swap
service or ahead of one.

| Field | Value |
|---|---|
| label | 25 |
| data[0] | the slot word: the redirect's (§ Kernel-origin fault message), or `SWAP_TAKE`'s `data[2]` |
| caps[0] | a Memory cap holding the slot's bytes from offset 0 |

The slot word names one use of a slot: the slot, its byte count, and the
generation of the seal it holds. A word whose slot holds no chunk on disk, or
holds one under another seal, was made for a use that has ended (the chunk
restored by another fault or ahead of one, or torn down, and the slot taken
again since): memmgr replies `RESTORE_STALE` and changes nothing, so a late
or repeated request never reaches a chunk it was not made for. Two uses of a
slot share a word only when `2^20` seals, or a multiple, came between them.
Otherwise memmgr maps the cap read-only, copies the slot's bytes into its own
buffer, and checks the tag there under the nonce of the chunk's last seal. A
good slot is restored as a fault restores a compressed chunk (§ Kernel-origin
fault message), its slot and disk node freed. A tag failure makes the chunk
lost and frees its slot.

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | The chunk is resident |
| 4 | `INVALID_ARGUMENT` | `caps[0]` missing, no Memory cap, smaller than the slot's bytes, or not mappable: a request the swap service corrects; the fault it holds stays held |
| 11 | `RESTORE_DECLINED` | `data[0]` the fault decline word the swap service forwards the held fault with (`FAULT_REPLY_FORWARD`): code 12 with detail 1 when the tag failed and the chunk is lost, else the code of the restore memmgr could not make, the chunk staying on disk |
| 12 | `RESTORE_STALE` | The word names no chunk on disk; nothing changed. The swap service resumes the held fault (`FAULT_REPLY_RESUME`): the thread faults again and memmgr serves the fault as the chunk now stands, mapped when another restore made it resident |

#### Label 26: `SWAP_WANTED`

Take the slot words of the chunks on disk `MAKE_RESIDENT` posted for the swap
service since the last request (§ Label 21), oldest first, and empty memmgr's list
of them. The swap service reads each slot and hands memmgr its bytes with
`SWAP_RESTORE` (§ Label 25), ahead of a fault; a word whose use of its slot has
ended since (the chunk restored by a fault, or torn down) replies `RESTORE_STALE`
there and changes nothing.

| Field | Value |
|---|---|
| label | 26 |

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | `data[0]` the count of words, at most `SWAP_WANTED_WORDS` (8); the words in `data[1]` on |

### Kernel-origin fault message (`FAULT_LABEL`)

Not a callable label. When a demand-paged process's thread takes a page fault the kernel cannot
resolve, it synthesises an IPC to memmgr's endpoint with label `FAULT_LABEL` (`u64::MAX - 1`),
`badge` = the derivation badge of the Endpoint cap bound by `SYS_THREAD_SET_FAULT_HANDLER` (procmgr
binds the process's own badged memmgr cap on its main thread, and the runtime copies that binding
onto each thread it spawns with `SYS_THREAD_INHERIT_FAULT_HANDLER`, so this is the process's memmgr
badge), and data words `[kind, faulting_va, access, ip]` (see
[docs/fault-handling.md](../../../docs/fault-handling.md)). For a `FAULT_KIND_VM` fault whose
`faulting_va` lies in a registered region of a process with a delegated address space, and whose
`access` the region's protection grants, memmgr backs the part of the region's chunk containing the
page that no earlier run backs — one zeroed Memory cap mapped across up to `DEMAND_CHUNK_PAGES`
pages — with the region's protection, and replies `FAULT_REPLY_RESUME` to retry the access; a fault
on a page an earlier run already backed (another thread's fault on the same chunk, delivered before
the mapping) is resumed without backing. When no free run covers that part, the largest free run
backs the pages around the faulting one, so the fault is declined for want of RAM only when no page
it may take is free ([`memory-pool.md`](memory-pool.md#demand-faults) § Demand faults). A fault in a
committed region (§ Label 7) takes the pages `promised` holds for it, and is admitted without the
budget and RAM tests that follow ([`memory-pool.md`](memory-pool.md#commit) § Commit). For an
uncommitted region of a process whose budget node is outside the system reserve, neither the pages
`promised` holds nor the growth floor's pages are among them: the fault is declined with code 7 when
no free page lies above the floor, and with code 9 when the floor refuses the page-table funding its
map needs ([`memory-pool.md`](memory-pool.md#distribution-policy) § Distribution policy). Backing a
chunk rather than a single page keeps cap-slot consumption to one cap per chunk on an unfragmented
pool, so a deep demand stack cannot exhaust memmgr's CSpace; stacks grow contiguously, so a chunk's
pages are consumed as the stack descends. The page tables the map needs come from the process
address space's own page-table pool. When the kernel reports that pool exhausted, memmgr funds it
from its free pool, accounted to the process, and maps the chunk again, at most four times
([`memory-pool.md`](memory-pool.md#client-page-table-funding) § Client page-table funding). So a
fault in a region does not depend on the process having funded the pool beforehand. A non-VM fault
replies `FAULT_REPLY_KILL`, and every other case — unknown process, address outside every region, a
write to a region without `MAP_WRITABLE` or an instruction fetch from one without `MAP_EXECUTABLE`
(which no backing satisfies), no delegated AS, a charge over the max of the process's budget node or
an ancestor, or any allocation/map failure — replies `FAULT_REPLY_FORWARD`; each carries data word 0
the decline reason: the code below in its low 32 bits, and in its high 32 the magnitude of the
failed syscall's error for code 9, else zero. The kernel hands the fault to the thread's exception
handler, the crash endpoint procmgr binds, with the word as data word 4; with no exception handler
bound, or for the fault of a kernel copy (a restartable syscall's user copy, which then fails with
`InvalidAddress`), the forward is a decline, and the kernel prints the word on the kill diagnostic
of a user-mode access ([docs/fault-handling.md § Reply](../../../docs/fault-handling.md#reply)).
Either way the fault takes the decline's outcome unless that handler resumes it, and memmgr waits on
no handler it forwards to.

A fault on a chunk memmgr is evicting maps the chunk's runs back and resumes; a
fault on a chunk it evicted restores the whole chunk from its compressed store
before it resumes, declined with code 7 when the free pages outside
`promised` and, for a process outside it, the system reserve do not cover the
chunk's backed pages, and with code 9 when a map fails or, with detail 0, the
stored chunk does not decode; the chunk then stays evicted
([`memory-pool.md`](memory-pool.md#eviction) § Eviction). A fault on a writing
chunk is restored from its store runs as a compressed chunk's, and its write
cancelled. A fault on a chunk on disk replies `FAULT_REPLY_REDIRECT` naming
the registered swap service's endpoint, with data word 0 the slot word, which
the endpoint receives as data word `FAULT_REDIRECT_WORD` (4): the slot in its
low 28 bits, the slot's byte count in the next 16, and in the top 20 the low
bits of the nonce counter of the seal the slot holds
(`free_pool::disk::slot_word`). The thread stays fault-blocked until the
swap service, having handed memmgr the slot's bytes with the word (§ Label
25), resumes it on `SUCCESS` or `RESTORE_STALE`, or forwards it with the
decline word of `RESTORE_DECLINED`. Two threads faulting on one chunk on disk
are redirected twice; the first restore makes the chunk resident, the second
is `RESTORE_STALE`, and both threads resume onto the mapped chunk. A fault on
a chunk on disk with no swap service registered, and one on a lost chunk, are declined with
code 12 ([`memory-pool.md`](memory-pool.md#disk-tier) § Disk tier).

| Code | Decline |
|---|---|
| 1 | Not a `FAULT_KIND_VM` fault |
| 2 | No process record carries the badge |
| 3 | `faulting_va` lies in no registered region |
| 4 | The region's protection refuses the access |
| 5 | No delegated address space |
| 6 | The metadata arena cannot grow for the slots recording the run takes: its descriptor, and the chunk's path in the region's chunk table |
| 7 | No free page can back the faulting page: the free pool is empty after the deferred runs are rechecked, every free page outside `promised` is in the growth floor and the process's budget node is outside the system reserve, or none is outside `promised` (a fault in an uncommitted region), or the split of a run larger than the pages to back failed |
| 8 | The run cannot be recorded on its chunk in the region's chunk table |
| 9 | A map of the run failed: into memmgr, to zero it ([`memory-pool.md`](memory-pool.md#frame-contents) § Frame contents), or into the process, after the page-table funding above when the pool was exhausted; memmgr unmaps whatever part of the run the failed map left mapped |
| 10 | In an uncommitted region, the faulting page, or the faulting page and the least page-table funding its map needs, would take the subtree of the process's budget node, or of an ancestor, over its max; in a committed region, the least page-table funding would, once the region's page-table reservation no longer holds it (§ Label 7); a longer run is shortened before the fault is declined ([`memory-pool.md`](memory-pool.md) § Client page-table funding) |
| 12 | The faulting page's chunk is on disk: detail 0 when no swap service is registered to restore it, detail 1 when its slot's bytes failed authentication and the chunk is lost, detail 2 when the swap service could not read the chunk's slot (swapd forwards a held fault with it) and the chunk stays on disk; memmgr itself produces details 0 and 1 only |

Each demand run is recorded on its chunk in the region's chunk table, so
`PROCESS_DIED` / `UNREGISTER_REGION` reclaim it and the all-RAM-accounted
identity is unaffected (the pages move from a free run to the chunk table;
they were already owned). The runs memmgr donates to the process's page-table
pool are recorded on the process record, like a grant, and reclaimed by
`PROCESS_DIED` only. Both are charged to the process's budget node: memmgr
admits as much of the span as the node takes, at least the faulting page,
before it selects the run, and each donation, beside the run whose map needs
it, before it makes it ([`memory-pool.md`](memory-pool.md) § Demand faults).

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

Only eight labels carry caps in their contract: `DONATE_MEMORY_CAPS` (every
attached cap), `DELEGATE_ASPACE` (`cap[0]`), `REGISTER_PRESSURE` (`cap[0]`),
`REGISTER_PROCESS` (`cap[0]`), `NODE_REGISTER_LIMIT` (`cap[0]` and
`cap[1]`), and the swap labels `SWAP_REGISTER` (`cap[0]` and `cap[1]`), `SWAP_TAKE` and
`SWAP_RESTORE` (`cap[0]`). memmgr deletes every other cap a message carries before it
handles the message, whatever the label, the caller, or the reply: the caps
attached to any other label (a `FAULT_LABEL` message and an unknown label
included), the caps after `cap[0]` on `DELEGATE_ASPACE`, `REGISTER_PRESSURE`,
`REGISTER_PROCESS`, `SWAP_TAKE` and `SWAP_RESTORE`, every cap on `SWAP_DONE` and
`SWAP_WANTED`, and the caps after `cap[1]` on `NODE_REGISTER_LIMIT` and
`SWAP_REGISTER`. It deletes the contract caps as well when a
procmgr-only label's caller is not procmgr, when a label's class does not
match the badge (§ Badge Discipline), and in the error cases the labels'
sections state. `SWAP_REGISTER` keeps its `cap[0]` as the swap service's
endpoint, and its `cap[1]`, when present, as the swap service's want Notification;
`SWAP_TAKE` and `SWAP_RESTORE` move their `cap[0]` back on every reply, and delete it
only when that reply cannot reach the caller. `REGISTER_PROCESS` reads the
badge of its `cap[0]` and deletes it on every path, and `NODE_REGISTER_LIMIT` its `cap[1]`. An
attached cap therefore never outlives the call that carried it unless memmgr takes ownership of it,
so no client can fill memmgr's `CSpace` by attaching caps until its receive loop fails and memmgr
exits with `EXIT_RECV_WEDGE` (see
[docs/ipc-design.md](../../../docs/ipc-design.md#receive-failure-policy) §"Receive-Failure Policy").

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
[Session Supervision](../../../docs/session-supervision.md),
[Userspace Memory Model](../../../docs/userspace-memory-model.md),
[programs/capexhaust/README.md](../../../programs/capexhaust/README.md),
[programs/demandpaged/README.md](../../../programs/demandpaged/README.md),
[programs/stackoverflow/README.md](../../../programs/stackoverflow/README.md),
[programs/threadchurn/README.md](../../../programs/threadchurn/README.md),
[programs/threadstack/README.md](../../../programs/threadstack/README.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[services/memmgr/README.md](../README.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md)
