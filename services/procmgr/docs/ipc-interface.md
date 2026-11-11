# procmgr IPC Interface

IPC interface specification for procmgr: message labels, capability transfer
semantics, and error conditions for process lifecycle operations.

---

## Endpoint

procmgr listens on a single IPC endpoint. Init holds the Send-side capability
and passes it (or a derived copy) to any service that needs to create processes.
procmgr holds the Receive-side capability.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The low 16 bits of the
message label (`label & 0xFFFF`) select the operation; the create labels carry
further fields in the upper bits. Data words and capability slots carry
arguments. The reply label is `procmgr_errors::SUCCESS` (0) or an error code.
Label numbers, error codes, and query states are defined in
[`shared/ipc/src/lib.rs`](../../../shared/ipc/src/lib.rs) (`procmgr_labels`,
`procmgr_errors`, `procmgr_process_state`).

`START_PROCESS`, `DESTROY_PROCESS`, `QUERY_PROCESS`, `CONFIGURE_PIPE`, and
`CONFIGURE_NAMESPACE` are sent on a **process handle** (the badged endpoint a
create call returns), and `RELEASE_HOLD` on a **release token** (the third cap
a `CREATE_DMA_HOLD` create returns); procmgr identifies the target process by
the badge `ipc_recv` delivers. A process handle is badged with the child's
process badge and `procmgr_labels::PROCESS_HANDLE_TAG` (bit 59, a bit of
`ipc::VERB_BIT_MASK`, which no process badge carries), which tells it from the
child's own procmgr cap (`ProcessInfo.procmgr_endpoint_cap`), badged with the
process badge alone. procmgr clears the tag before it serves a request, so a
handle names its child to every label, and refuses `DECLARE_NO_DEBUG` and
`REGISTER_THREAD`, which name their sender, on a badge carrying it with
`INVALID_BADGE`, deleting the caps the request carried: only the child itself
sends them (§ Label 21, § Label 22). Labels 14–18 are specified in § `REGISTER_DEATH_EQ`,
§ `REGISTER_INIT_TEARDOWN`, § `INIT_TEARDOWN_DONE`, § `QUERY_INIT_REAP`, and
§ `QUERY_LIVE_PROCESSES` below, and labels 19–24 in § Crash Endpoint and Debug Authority.
Labels 4–7 and 10
are unassigned; procmgr replies `UNKNOWN_OPCODE` (`0xFFFF`) to them and to any
other unknown opcode, and deletes the caps such a request carried (see
§ Capability Transfer).

Memory-cap allocation is owned by memmgr, not procmgr, per
[docs/process-lifecycle.md](../../../docs/process-lifecycle.md)
§ Authority Boundaries Between memmgr and procmgr.
See
[`services/memmgr/docs/ipc-interface.md`](../../memmgr/docs/ipc-interface.md)
for `REQUEST_MEMORY_CAPS` and related labels.

### Label 1: `CREATE_PROCESS`

Create a new process from a raw ELF module. The process is created in a
**suspended** state — the thread is not started. Between create and
`START_PROCESS` the caller configures the child through the returned process
handle (`CONFIGURE_PIPE`, `CONFIGURE_NAMESPACE`).

**Request:**

| Field | Value |
|---|---|
| label bits `[0..16]` | 1 |
| label bits `[16..31]` | Create flags and scheduling fields (see **Pinned flag**, **Scheduling fields**, **argv and env**, and **Physical-address flag** below) |
| label bits `[31..64]` | Reserved, zero |
| data[0..4] | When `CREATE_ARGV_ENV` is set: the `ArgvEnvHeader`, `args_bytes`, `args_count`, `env_bytes`, `env_count`, one `u64` each |
| cap[0] | Memory capability for the ELF module image |
| cap[1] | Optional creator endpoint, copied into the child's `ProcessInfo.creator_endpoint_cap` |
| last cap | When `CREATE_ARGV_ENV` is set: Memory cap holding the argv and env blobs |

procmgr maps the module, parses the ELF, creates the child's address space,
CSpace, and thread, maps LOAD segments, and populates the `ProcessInfo`
handover page, with the child's argv and env in the pages after it (see
**argv and env** below). procmgr deletes its copies of cap[0], cap[1], and
the argv/env cap whether creation succeeds or fails, and deletes any further
cap. A
failed creation releases everything procmgr acquired for the child, including
the child's memmgr record: procmgr sends memmgr `PROCESS_DIED` for it, so the
pages already allocated to the child return to memmgr's pool.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| cap[0] | Process handle (a SEND on procmgr's endpoint badged with the child's process badge and `procmgr_labels::PROCESS_HANDLE_TAG`; § Messages) |
| cap[1] | Child `Thread` capability (Control, Observe, and Upcall rights, `RIGHTS_THREAD`) |
| cap[2] | With `CREATE_DMA_HOLD` only: the release token (a SEND on procmgr's endpoint badged with the child's process badge and `procmgr_labels::HOLD_RELEASE_AUTHORITY`; **DMA hold flag** below) |

The process handle is a badged endpoint capability. The caller uses it for the
per-process operations — the badge identifies the process without a forgeable
PID. The `Thread` cap allows the caller to bind death notifications or
stop/configure the thread.

The reply's cap transfer is all-or-nothing
([docs/ipc-design.md](../../../docs/ipc-design.md#message-format) § Message Format). When the
caller's `CSpace` cannot take every cap (or the caller is gone), the caller
resumes with `IPC_REPLY_TRANSFER_FAILED` and no caps. procmgr then deletes the
caps and destroys the suspended child as `DESTROY_PROCESS` does, since no one
holds a handle to it.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `INVALID_ELF` | No module capability was transferred |
| 2 | `OUT_OF_MEMORY` | Creation failed: module mapping, ELF validation or loading, kernel-object or memory-cap allocation, or, with `CREATE_DMA_HOLD`, the room for the child's held reclaim or the derivation of its release token (the child, never started, is destroyed and its pages returned) |
| 7 | `INVALID_ARGUMENT` | Reserved label bits `[31..64]` set, the scheduling fields violate the resolution rules below (band above the creator's ceiling, or priority above the resolved band), the argv and env violate the rules of **argv and env** below, or `CREATE_PHYS_ACCESS` comes from a creator that is not phys-class (**Physical-address flag** below) |
| 14 | `ARGV_ENV_STILL_MAPPED` | A copy window of the argv and env would not unmap; the caller withholds its argv/env run (**argv and env** below) |

**argv and env.** The label's bit 29 (`CREATE_ARGV_ENV`, in the window shared with
`CREATE_FROM_FILE`) marks a request that carries the child's argv and env in a Memory cap the caller
sizes and funds: one run holding the argv blob at byte 0 and the env blob directly after it, each a
concatenation of NUL-terminated UTF-8 strings (env entries `KEY=VALUE`), with the
`ipc::procmgr_labels::ArgvEnvHeader` of the two blobs' byte lengths and string counts in four data
words. The cap is the last one before the death relay (`CREATE_FROM_FILE`), or the last cap without
one, so the creator endpoint stays at cap[1]. Without the flag the child gets no argv and no env,
and the request carries neither the header nor the cap. procmgr refuses the request with
`INVALID_ARGUMENT`, before it acquires anything for the child, when the flag is set without a cap of
its own, a header word was not delivered, the cap is not a Memory cap, or the blobs reach past the
cap or together exceed `process_abi::ARGV_ENV_MAX_BYTES`. Otherwise, once it has registered the
child with memmgr and before it creates anything else, procmgr copies the blobs into fresh pages on
the child's account, through two windows of `ARGV_ENV_COPY_WINDOW_PAGES` (64) pages re-mapped for
each chunk, so its own page-table cost per create stays that of two 256 KiB spans whatever the
blobs' size. That copy also refuses the create with `INVALID_ARGUMENT` when the caller's cap cannot
be mapped (it lacks the map right, or the kernel refuses its pages for a reason other than procmgr's
memory), and when, on the copy, a blob's NULs disagree with its count or a nonempty blob does not
end in a NUL; a caller that rewrites its pages meanwhile changes only the copy that is checked. A
shortfall of procmgr's or the child's memory replies `OUT_OF_MEMORY`. Should procmgr fail to unmap a
copy window, which may then still map the caller's pages read-only and the child's writable, it
replies `ARGV_ENV_STILL_MAPPED` (14), keeps the window's VA reserved, and withholds the child's
memmgr record (sends no `PROCESS_DIED` for it); the caller MUST then withhold its run too (not
return it to memmgr), so memmgr re-grants no frame procmgr may still map. `ArgvEnvCap::settle` does
so. procmgr maps the copy read-only directly after the child's `ProcessInfo` page, where
`ProcessInfo`'s `args_offset` and `env_offset` locate it
([abi/process-abi/README.md](../../../abi/process-abi/README.md) § argv / env region), funding the
child's page tables for a region past one last-level table's span (512 pages) from the child's
account. procmgr deletes its copy of the cap before it replies, so the caller can return the run to
memmgr as soon as the call returns. `std::os::seraph::process::ArgvEnvCap` builds the cap and the
header for a std-built sender.

**Pinned flag.** Demand paging is the default: at finalize procmgr binds every child's main thread
fault handler to memmgr (the system pager) via `SYS_THREAD_SET_FAULT_HANDLER`, for the
virtual-memory class (`FAULT_CLASS_VM`; the exception class is bound to the crash endpoint, as
§ Crash Endpoint and Debug Authority says, and the upcall class stays unbound), delegates the
child `AddressSpace` to memmgr via `memmgr_labels::DELEGATE_ASPACE`,
and then sets `ProcessInfo.pager_endpoint_cap` (the child's badged memmgr cap, whose derivation
badge the kernel stamps on each fault) and `pager_badge` (that badge), which tell the runtime the
process is demand-paged; the runtime copies the spawning thread's bindings, this one among them,
onto each thread it
spawns (`SYS_THREAD_INHERIT_FAULT_HANDLER`). The
child then backs reserved regions lazily via
`std::os::seraph::register_demand_paged`. The label's bit 16 (`CREATE_PINNED`,
in the `[16..31]` window shared with `CREATE_FROM_FILE`) opts out: the
child is left eager-mapped with no pager. Set it only for a process that cannot
depend on the fault path — a DMA driver. init, memmgr, and procmgr are pre-pager
and never routed through this path, so they are pinned by construction. See
[docs/fault-handling.md](../../../docs/fault-handling.md). The binding is
best-effort: a failure degrades to "no pager" (faults kill), never blocking
creation. procmgr writes `pager_endpoint_cap` and `pager_badge` only after the
delegation and the main thread's binding have both taken effect, so the page never
names a pager the child does not have; a child whose binding failed, or whose page
procmgr could not map to advertise it, reads zero and keeps its memory eager.

**DMA hold flag.** The label's bit 28 (`CREATE_DMA_HOLD`, in the window shared
with `CREATE_FROM_FILE`) holds back the child's memory reclaim. Once the child
has been started, its teardown, however it comes (its death, a death resync, or
`DESTROY_PROCESS`), revokes and deletes its kernel objects as for any child but
does not send memmgr `PROCESS_DIED`: procmgr parks the child's memmgr record
until the creator sends `RELEASE_HOLD` (§ Label 3) on the child's release
token, and until then memmgr keeps the child's frames on that record, out of
its free pool. Set it for a driver whose device may DMA into its frames after
it dies: the creator releases the hold once it has confirmed the device's DMA
stopped, and never when it cannot, which leaves the frames quarantined for the
rest of the boot
([docs/device-management.md](../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown). The release token is the create reply's cap[2], a SEND
badged with the child's process badge and `procmgr_labels::HOLD_RELEASE_AUTHORITY`,
a verb bit no process badge carries; procmgr mints it only here, so only the
creator, or a process the creator hands it to, can release the hold. On any
label but `RELEASE_HOLD` the token names no process: procmgr answers it as for
a badge no process holds. A child destroyed before `START_PROCESS` never ran,
so it touched no device, and its teardown sends `PROCESS_DIED` at once.
procmgr reserves the room the child's parked record takes before it replies to
the create, so no teardown frees a held child's pages for want of a record;
when it cannot, or cannot derive the token, the create fails with
`OUT_OF_MEMORY`.

**Physical-address flag.** The label's bit 30 (`CREATE_PHYS_ACCESS`, in the window shared with
`CREATE_FROM_FILE`) creates the child phys-class: procmgr registers it with memmgr with
`REGISTER_PHYS_CLASS`, so memmgr's grants to it keep `RIGHTS_MEM_PHYS` and the child can read
the physical bases of the Memory caps it holds
([services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) § Label 3).
procmgr retypes every child's address space, a phys-class child's included, through a
derivation of its slab without `RIGHTS_MEM_PHYS`, so no child's address space carries
`RIGHTS_AS_READ` and procmgr, which keeps it for the child's life, cannot translate its pages;
devmgr, the phys-class child every boot creates, checks its own at startup
([services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md)
§ Capabilities Received). procmgr honours `CREATE_PHYS_ACCESS` only from a creator that is
phys-class itself: an un-badged one (badge 0: init, or svcmgr's mint source) or one whose memmgr
badge carries `memmgr_labels::PHYS_CLASS_BADGE_BIT`; from any other it replies
`INVALID_ARGUMENT` before any resource is acquired. init sets it for devmgr and devmgr for the
IOMMU driver, the processes
[docs/device-management.md](../../../docs/device-management.md#dma-authorisation) § DMA
Authorisation names; every other process, every device driver included, is created without it.

**Scheduling fields.** Bits `[18..23]` (`CREATE_PRIORITY`) and `[23..28]`
(`CREATE_BAND_MAX`) of the label window — shared by `CREATE_PROCESS` and
`CREATE_FROM_FILE` — carry the child's scheduling placement; bits `[31..64]`
remain reserved and MUST be zero (`INVALID_ARGUMENT` otherwise, which keeps a
future field addition provably additive). Resolution, against the **creator's
band ceiling** (badge 0 = init, ceiling `sched_policy::BASELINE_PRIORITY_MAX`;
a badged caller's ceiling is its own minted `band_max`; an unknown badge falls
back to `sched_policy::DEFAULT_SPAWN_PRIORITY`):

| Field | 0 (unspecified) | Nonzero |
|---|---|---|
| `CREATE_BAND_MAX` | copy of the creator's band | `[1, band_max]`; must be ≤ the creator's ceiling |
| `CREATE_PRIORITY` | `DEFAULT_SPAWN_PRIORITY` clamped to the band | must be ≤ the resolved `band_max` (so the child's own band always covers its starting level) |

Violations reply `INVALID_ARGUMENT` before any resource is acquired. On
success procmgr creates the child's initial thread at the resolved priority
(via its own baseline `SchedControl`), mints the child's band — a plain
`cap_copy` of the baseline for a full-width band, copy-then-`SYS_SCHED_SPLIT`
for a narrowed one — into `ProcessInfo.sched_control_cap`, and records the
resolved priority in `ProcessInfo.initial_priority` so the runtime spawns
further threads at the same level by default, unless
`std::os::seraph::thread::BuilderExt::spawn_at_priority` places one
elsewhere in the band.

### Label 2: `START_PROCESS`

Start a previously created (suspended) process. The caller must have
completed any `CONFIGURE_PIPE` and `CONFIGURE_NAMESPACE` calls before calling
this operation. procmgr copies the namespace caps installed by
`CONFIGURE_NAMESPACE` into the child's CSpace and `ProcessInfo`, configures the
thread, and starts it.

**Request:**

| Field | Value |
|---|---|
| endpoint | Process handle (badged endpoint from the create reply's cap[0]) |
| label | 2 |

No data words are required — the process is identified by the badge
embedded in the endpoint capability.

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
| 2 | `OUT_OF_MEMORY` | Installing the namespace caps in the child failed |
| 3 | `THREAD_CONFIGURE_FAILED` | `thread_configure_with_tls` failed |
| 4 | `INVALID_BADGE` | No process with the given badge exists |
| 5 | `ALREADY_STARTED` | Process was already started |
| 6 | `THREAD_START_FAILED` | `thread_start` failed with an error other than `Interrupted`, which procmgr retries |

### Label 3: `RELEASE_HOLD`

Release the held memory reclaim of a torn-down child created with
`CREATE_DMA_HOLD` (§ Label 1, **DMA hold flag**). Sent on the child's release
token, the create reply's cap[2], with no data words or caps. procmgr sends
memmgr `PROCESS_DIED` for the child's memmgr badge, deletes its copy of the
child's badged memmgr SEND, and drops the held record, so memmgr returns the
child's frames to its free pool.

procmgr serves the label only when the sender's badge carries
`procmgr_labels::HOLD_RELEASE_AUTHORITY`, and looks the child up by the badge
with every verb bit (`ipc::VERB_BIT_MASK`) cleared. Any other sender carrying
the child's badge, its process handle and the child's own procmgr cap included,
however the child granted a copy onward before it died, is refused
`UNAUTHORIZED` and the hold stays. Like every badge-gated label, the token can
be minted by a holder of an un-badged SEND on procmgr's endpoint, which only
init and svcmgr hold (§ `REGISTER_INIT_TEARDOWN`).

procmgr serves its requests in order, so a `DESTROY_PROCESS` the creator sends
first has torn the child down, and parked its record, before the release is
served, whether or not procmgr had reaped the child already. A release that
finds no held record changes nothing: the child is live, was never started or
never held, or was released already. procmgr never hands a held record's badge
to a new child.

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success): the held reclaim was sent; or a nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_BADGE` | procmgr holds no reclaim for the token's child |
| 13 | `UNAUTHORIZED` | The sender's badge lacks `HOLD_RELEASE_AUTHORITY`: it is not a release token; any hold stays |

### Label 8: `DESTROY_PROCESS`

Destroy a process. Sent on the process handle with no data words or caps.
procmgr removes the process entry, revokes and deletes the child's `Thread`,
`CSpace`, `AddressSpace`, `ProcessInfo` Memory cap, and TLS Memory cap, deletes
any namespace caps never consumed by `START_PROCESS`, and sends memmgr
`PROCESS_DIED` for the child's memmgr badge, unless the child was created with
`CREATE_DMA_HOLD` and started, whose reclaim waits for `RELEASE_HOLD`
(§ Label 3).

**Reply:** label 0 (success), always. An unknown or already-destroyed badge is
a no-op.

### Label 9: `QUERY_PROCESS`

Query a process's state without blocking on a death event. Sent on the process
handle with no data words or caps.

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | State: 0 `ALIVE`, 1 `CREATED` (not yet started), 2 `UNKNOWN` (no entry; reaped or destroyed more than `RECENT_EXIT_RETENTION_NS` ago, dropped early under heap exhaustion, or never valid), 3 `EXITED` |
| data[1] | Kernel-encoded exit reason when `data[0]` is `EXITED`; 0 otherwise |

A live entry whose thread the kernel reports as exited answers `EXITED` before
procmgr reaps it. After the reap, or after a `DESTROY_PROCESS` teardown, the
badge answers `EXITED` for `RECENT_EXIT_RETENTION_NS` (30 s) of monotonic time,
however many other processes die in the window, while procmgr's heap can hold
their records, and `UNKNOWN` after that. Retention is best-effort: when the heap
cannot hold a new record, the oldest record makes room (or, with none held, the
new one is dropped), so such a badge can answer `UNKNOWN` early. A destroyed
process's reason is the one the kernel retained if its main thread had already
exited, else `EXIT_KILLED`.

### Label 11: `CONFIGURE_PIPE`

Install one direction's shmem-backed stdio pipe on a created, not yet started
child. Sent on the process handle.

**Request:**

| Field | Value |
|---|---|
| label | 11 |
| data[0] | Direction: 0 `PIPE_DIR_STDIN`, 1 `PIPE_DIR_STDOUT`, 2 `PIPE_DIR_STDERR` |
| data[1] | Ring byte capacity (informational; the spawner has already initialised the `SpscHeader`) |
| cap[0] | Memory capability for the shmem ring page |
| cap[1] | Data-available notification capability |
| cap[2] | Space-available notification capability |

procmgr copies each cap into the child's CSpace and writes the slots into the
direction's `<dir>_memory_cap`, `<dir>_data_notification_cap`, and
`<dir>_space_notification_cap` fields of the child's `ProcessInfo`, then deletes
its own copies. It deletes every cap the request carried on success and on
every failure, including caps past cap[2]. Every check precedes the copies, and
a copy that fails revokes the copies already made, so a refused call installs
nothing in the child. A spawner calls this once per piped direction. A second
call for a direction already configured is refused, since procmgr cannot remove
the earlier triple from the child's CSpace.

**Error codes:** 2 `OUT_OF_MEMORY` (mapping or `cap_copy` failed), 4
`INVALID_BADGE`, 5 `ALREADY_STARTED`, 7 `INVALID_ARGUMENT` (fewer than three
caps, a zero cap, an unknown direction, or a direction already configured).

### Label 12: `CONFIGURE_NAMESPACE`

Install the namespace caps a created, not yet started child receives. Sent on
the process handle. procmgr holds no namespace cap of its own; this call is the
only path that installs `ProcessInfo.system_root_cap` and
`ProcessInfo.current_dir_cap`, and without it both stay zero.

**Request:**

| Field | Value |
|---|---|
| label | 12 |
| cap[0] | Root namespace cap for the child (mandatory) |
| cap[1] | Current-directory cap for the child (optional; absent leaves `current_dir_cap` zero) |

procmgr stores the caps, deletes any previously installed pair, and copies
them into the child's CSpace at `START_PROCESS`. It does not validate cap shape.
procmgr consumes the transferred caps on success and failure alike, and deletes
any cap past cap[1].

**Error codes:** 4 `INVALID_BADGE`, 5 `ALREADY_STARTED`, 7 `INVALID_ARGUMENT`
(no cap in cap[0]).

### Label 13: `CREATE_FROM_FILE`

Create a suspended process from an ELF binary the caller has already resolved:
the caller walks its own namespace cap to the binary node and transfers the
resulting file cap. procmgr opens it (`FS_OPEN`), streams the ELF with `FS_READ` /
`FS_READ_MEMORY` against its own open, and never holds a namespace cap of its own. Loading, the
**Pinned flag**, the **Scheduling fields**, and **argv and env** are as for `CREATE_PROCESS`.

**Request:**

| Field | Value |
|---|---|
| label bits `[0..16]` | 13 |
| label bits `[16..31]` | As for `CREATE_PROCESS`; bit 17 (`CREATE_DEATH_RELAY`) marks a trailing death-relay cap |
| label bits `[31..64]` | Reserved, zero |
| data[0] | `file_size` in bytes, from the caller's `NS_LOOKUP` size hint |
| data[1..5] | When `CREATE_ARGV_ENV` is set: the `ArgvEnvHeader`, as for `CREATE_PROCESS` |
| cap[0] | File cap for the binary |
| cap[1] | Optional creator endpoint, copied into the child's `ProcessInfo.creator_endpoint_cap` |
| next-to-last cap, or last without a relay | When `CREATE_ARGV_ENV` is set: the argv/env Memory cap, as for `CREATE_PROCESS` |
| last cap | When `CREATE_DEATH_RELAY` is set: POST-only `EventQueue` cap |

procmgr deletes the file cap once it has opened it, `FS_CLOSE`s and deletes its open after the load,
whether it succeeds or fails, and deletes its copies of the creator endpoint and the argv/env cap
and any cap the layout does not name; a request refused before the open deletes the file cap
unopened. When present, the death-relay cap is the last cap in the message, so the creator-endpoint
slot stays at cap[1]; it is a cap of its own, as the argv/env cap is, so a request needs one cap
past the file cap for each of `CREATE_DEATH_RELAY` and `CREATE_ARGV_ENV` it sets, and one that sets
more than its caps can supply is refused with `INVALID_ARGUMENT`. Once the child is recorded,
procmgr binds the relay as an `AddressSpace` death observer (correlator 0) on the child, using one
of the relay queue's observer nodes, so a terminal fault in any of the child's threads posts the
fault class to the spawner's own death queue, then deletes its copy; a failed creation deletes it
unbound. `CREATE_PROCESS` ignores bit 17.

**Reply (success):** as for `CREATE_PROCESS` (cap[0] process handle, cap[1]
child `Thread` cap, and, with `CREATE_DMA_HOLD`, cap[2] the release token),
including the destruction of a child whose reply caps cannot be delivered. A
failed creation releases what procmgr acquired for the child, its memmgr record
included, as for `CREATE_PROCESS`.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `INVALID_ELF` | `file_size` is zero, or ELF validation or relocation failed (the TLS block's checks aside; see `OUT_OF_MEMORY`) |
| 2 | `OUT_OF_MEMORY` | Memory-cap, kernel-object, or badge allocation failed, the main thread's TLS block could not be built (whatever the cause: an oversized or overaligned `PT_TLS`, a short `.tdata` read, or a mapping), the stack or IPC-buffer pages could not be mapped, or, with `CREATE_DMA_HOLD`, the room for the child's held reclaim or the derivation of its release token (the child, never started, is destroyed and its pages returned) |
| 7 | `INVALID_ARGUMENT` | No file cap, `CREATE_DEATH_RELAY` or `CREATE_ARGV_ENV` set without a cap of its own, reserved label bits `[31..64]` set, `CREATE_PHYS_ACCESS` from a creator that is not phys-class (Label 1's **Physical-address flag**), the scheduling fields violate the resolution rules (band above the creator's ceiling, or priority above the resolved band), or the argv and env violate the rules of **argv and env** (§ Label 1) |
| 10 | `IO_ERROR` | The `FS_OPEN` of the file cap failed, an `FS_READ` of the ELF header against procmgr's open failed, or a segment's file bytes did not all arrive: an `FS_READ_MEMORY` failed or returned zero bytes, its cache page could not be mapped, or its reply named a range past that page |
| 11 | `MAP_FAILED` | Mapping failed during segment load |
| 12 | `INSUFFICIENT_RIGHTS` | Rights derivation failed during segment load |
| 14 | `ARGV_ENV_STILL_MAPPED` | As for `CREATE_PROCESS` (§ Label 1, **argv and env**) |

---

## Capability Transfer

Capability transfer uses the IPC message's cap slot array (up to 4 caps per
message). On `CREATE_PROCESS`, the caller's Memory cap is moved into procmgr's
CSpace atomically with the message delivery (as is the argv/env Memory cap of
either create label), per
[docs/ipc-design.md](../../../docs/ipc-design.md#capability-semantics-in-ipc)
§ Capability Semantics in IPC.
procmgr consumes the cap during
process creation and does not return it.

Every cap a request transfers lands in procmgr's CSpace, whether or not the
request's layout names it. procmgr deletes the caps a layout does not name
(caps past the last named position, and every cap of a label that names none:
`START_PROCESS`, `RELEASE_HOLD`, `DESTROY_PROCESS`, `QUERY_PROCESS`,
`INIT_TEARDOWN_DONE`, and unknown opcodes), and every cap of a refused request, a refused
`REGISTER_THREAD`'s thread cap among them, except the init-reap
refusals of an un-badged sender that keep caps init may still be running on
(§ `REGISTER_INIT_TEARDOWN`). A padded or refused request from any badged sender
therefore cannot grow procmgr's CSpace. Replies to the calls procmgr makes on a
caller-supplied file cap are treated the same way: procmgr deletes every reply
cap it does not use.

On a create reply, procmgr transfers a badged process handle endpoint (for
subsequent per-process operations), a derived copy of the child's `Thread`
capability (Control, Observe, and Upcall rights, `RIGHTS_THREAD`), and, for a
`CREATE_DMA_HOLD` child, its release token to the caller. procmgr retains the
original caps for process lifecycle management.

---

## REGISTER_DEATH_EQ — install logd's death queue

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_DEATH_EQ` (14) |
| caller's cap badge | MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY` (`1 << 62`); svcmgr mints this badged `SEND\|GRANT` cap for real-logd on each launch, from the badge-0 `SEND\|GRANT` procmgr source init hands it at the handover (see the [svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)) |
| `caps[0]` | `EventQueue` cap with `POST` right; it needs no death-observer nodes, since nothing binds it |

Procmgr stores the cap in
[`process::LOGD_DEATH_EQ`](../src/process.rs). From that moment onward,
every teardown procmgr runs (`teardown_entry`: the reap of a death event, the
death resync, and `DESTROY_PROCESS`) posts the two-word death entry
`(exit_reason, process badge)` to it with `SYS_EVENT_POST`, the full `u64`
badge in the correlator word (`syscall::DeathEvent`), after the process's
objects are torn down. procmgr, not the kernel, is the source of logd's death
events: a worker thread's terminal fault that tears down its process reaches
logd too, and `DESTROY_PROCESS` posts the reason the kernel retained if the
process's main thread had already exited, else `EXIT_KILLED`. A process torn down
before the registration posts nothing. A post the full queue refuses
(`QueueFull`) is dropped, as the kernel drops a post to a full queue; logd's
full-drain resync recovers it.

Reply: `procmgr_errors::SUCCESS` once stored, `UNAUTHORIZED` if the
caller lacks `DEATH_EQ_AUTHORITY` or a death EQ is already registered,
`INVALID_ARGUMENT` if no cap was transferred. Registration is first-wins:
procmgr deletes the cap a second registration transfers and keeps the first,
so a restarted logd receives no death events. procmgr deletes every cap a
refused request carried, and any cap past `caps[0]`.

logd derives a `POST`-only copy from its `RECV+POST` event queue
before sending — the kernel's cap-transfer moves the sent cap into
procmgr's CSpace (per
[docs/capability-model.md](../../../docs/capability-model.md#transfer) § Transfer),
so logd must retain `RECV` on its own copy to
keep `wait_set_add` and `event_try_recv` working.

---

## QUERY_LIVE_PROCESSES — list live process badges

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::QUERY_LIVE_PROCESSES` (18) |
| caller's cap badge | MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY`, as for `REGISTER_DEATH_EQ`; a badge names a process handle, so the list is not public |
| `data[0]` | `0` to start the walk, `1` to resume after the badge in `data[1]` |
| `data[1]` | The cursor badge when `data[0]` is `1` |
| caps | none; procmgr deletes any cap the message carried |

Reply `SUCCESS` with `data[0]` = the page's count and `data[1..=count]` = the
badges of live processes above the cursor, ascending, at most
`LIVE_PROCESSES_PAGE` (`MSG_DATA_WORDS_MAX - 1` = 63). A page shorter than that
ends the walk; a full page is followed by a call resuming after its last badge.
A process that stays live across the whole walk is listed exactly once,
whatever spawns and deaths happen between pages. `UNAUTHORIZED` for any other
badge; `INVALID_ARGUMENT` for a `data[0]` other than 0 or 1.

Real-logd walks it to resync its slots after its death queue may have dropped a
post (see [logd IPC interface](../../logd/docs/ipc-interface.md) § Death-queue
resync), from a helper thread rather than its main thread.

---

## REGISTER_INIT_TEARDOWN — init reap handoff

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_INIT_TEARDOWN` (15) |
| `data[0]` | `1` on the first round (carrying kernel-object caps); `0` on subsequent donation rounds |
| `caps[0..]` | Round 1: 4 kernel-object caps (`AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`) — MOVED out of init's CSpace via IPC cap-transfer. Subsequent rounds: 1-4 reclaimable Memory caps per round (every reclaimable Memory cap init solely owns; the set is in [docs/process-lifecycle.md](../../../docs/process-lifecycle.md#init-reap) § Init reap). |

**Gate.** Labels 15 and 16 are accepted only on an un-badged cap
(`req.badge == 0`). Init holds one; the only other badge-0 holder is svcmgr,
whose `procmgr_death_auth_source` is a mint source for real-logd's
`DEATH_EQ_AUTHORITY` cap and a debug-authority holder's `DEBUG_AUTHORITY` cap (see the
[svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)), a trusted minter.
Every other process holds only SENDs on procmgr badged with a process badge (or
a badge svcmgr mints from its source), so none of them can stage a handoff or
hand procmgr caps to forward to memmgr's `DONATE_MEMORY_CAPS`. The handoff is
one-shot: once the reap has run, every further round and `INIT_TEARDOWN_DONE`
is refused. The gate is badge 0 rather than a verb bit
([docs/capability-model.md](../../../docs/capability-model.md) § Verb-bit
authority pattern) because the handoff's sender is init itself, which holds
procmgr's un-badged endpoint from before any badge is minted; a verb bit would
only add a badged cap for init to derive and for svcmgr's mint source to be
able to forge.

On the first round procmgr stores the kernel-object caps and binds a death
observer from its death queues (§ Process table and death queues of the
[README](../README.md#process-table-and-death-queues)) on both init threads
under the same correlator:
`deaths.bind_thread(main_thread, procmgr_labels::INIT_REAP_CORRELATOR)`
and the same call on `logd_thread`, expecting two deaths; the reap runs on the
second death. Either bind failing rejects the round with `INVALID_ARGUMENT`.
Subsequent rounds append to the donation Memory cap list. `INIT_TEARDOWN_DONE`
(label 16, no caps, no data words) closes the stream and arms the state machine.

Reply: `procmgr_errors::SUCCESS` on accept; `UNAUTHORIZED` from a badged sender;
`INVALID_ARGUMENT` when a first round arrives while a handoff is open or after
the reap, a first round carries other than 4 caps, either death-EQ bind fails,
or a donation round arrives before the first round or after the reap. procmgr
deletes the caps of a badged sender's round, and of any round refused after the
reap. The caps of an un-badged round refused before the reap stay in procmgr's
CSpace: they may be init's live `AddressSpace` or Memory
caps, which procmgr cannot delete while init's threads run on them or its
address space maps them.

## INIT_TEARDOWN_DONE — end-of-stream notification

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::INIT_TEARDOWN_DONE` (16) |
| caps | none |

Procmgr replies `SUCCESS` then arms the state machine, `UNAUTHORIZED` from a
badged sender, or `INVALID_ARGUMENT` when no handoff is open (none yet, or the
reap ran) or the state machine is already armed; it deletes any cap the message
carried. Init proceeds to `sys_thread_exit` immediately (per
[services/init/docs/bootstrap.md](../../init/docs/bootstrap.md#handover) § Handover).
Each death-EQ event with
`INIT_REAP_CORRELATOR` (reserved `u64::MAX`) calls
[`init_reap::run_reap`](../src/init_reap.rs), which counts the death and, on the
second, executes the six-step teardown (Threads → AddressSpace →
DONATE_MEMORY_CAPS → revoke and delete procmgr's CSpace capability, the last
reference to init's CSpace, which frees it and releases the caps init still holds →
log), whether or not `INIT_TEARDOWN_DONE` has armed the reap: a threadless init can
send no further round.
init-logd normally exits last, once real-logd's `HANDOVER_RELEASE` releases it;
procmgr never force-stops it. If the handover never completes, init-logd serves on
and init's caps stay held until shutdown — a benign hold, not a wedge (see the
[logd handover protocol](../../logd/docs/handover-protocol.md) § Failure modes).
The system-scope reap model is in
[docs/process-lifecycle.md](../../../docs/process-lifecycle.md) § Init reap.

## QUERY_INIT_REAP — init reap outcome

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::QUERY_INIT_REAP` (17) |
| caps | none |

Accepted on any procmgr cap, badged or not: it returns two words and changes no
state. Procmgr deletes any cap the message carried. Reply `SUCCESS` with:

| Field | Meaning |
|---|---|
| `data[0]` | `1` once the reap has run, `0` before |
| `data[1]` | The release probe's outcome: `INIT_REAP_PROBE_UNCHECKED` (0) before the reap, or when procmgr could not place the probe; `INIT_REAP_PROBE_RELEASED` (1) when deleting procmgr's CSpace capability freed init's CSpace; `INIT_REAP_PROBE_HELD` (2) when it did not |

The probe is an Endpoint procmgr retypes from a one-page memmgr grant and moves
into init's CSpace through its CSpace capability after the donation step and
before the revoke and delete. Freeing init's CSpace releases the endpoint, whose
bytes return to the grant, and nothing else retypes from or returns bytes to the
grant. procmgr reads the grant's `available_bytes` before the move and again after
the revoke and delete, re-reading with a yield between reads for up to 500 ms of
wall-clock time (a concurrent syscall pin on init's CSpace defers its free to the
pin's release, and a time bound outlasts a loaded scheduler that stretches each
yield). It
reports `RELEASED` once the value rose, and returns the page to memmgr
(`RELEASE_MEMORY_CAPS`); otherwise it reports `HELD` and keeps the page, which the
endpoint still backs. svctest's `init_cspace_released` phase asserts `RELEASED`.

---

## Crash Endpoint and Debug Authority

procmgr creates one **crash endpoint** at startup, before any process, and holds it for its life.
At finalize it binds every child's main-thread exception class (`FAULT_CLASS_EXCEPTION`) to a SEND
on it badged with the child's process badge, whether or not the child is pinned; the runtime copies
the binding onto every thread the child spawns, and procmgr binds each thread that registers
(Label 22) again under a **crash badge** of the thread's own, so a fault message's badge names the
faulting thread: the process badge its main thread, or a thread that never registered and kept its
spawner's binding; a crash badge, which carries bit 63 (a bit of `ipc::VERB_BIT_MASK`, which no
process badge carries) and is unique for procmgr's life, the registered thread procmgr bound under
it. memmgr forwards each page fault it cannot back to
the same class (`FAULT_REPLY_FORWARD`), so the endpoint receives every fault that would kill a
procmgr-created process that has not declared itself undebuggable (Label 21), except a page fault of
a child created `CREATE_PINNED` or whose pager binding failed, which no pager forwards
([docs/fault-handling.md](../../../docs/fault-handling.md) § Crash Reports). A fault of a
restartable syscall's user copy, which the process survives, does not reach it either: the forward
of one is a decline. A failure to create the endpoint, or to bind a child, is logged and leaves the
class unbound; it never fails a creation.

While no crash service is registered, a procmgr thread of its own, the **decliner**, receives on
the endpoint and declines each fault with `FAULT_REPLY_KILL`, carrying the forwarder's reason for a
forwarded page fault (data word 4) and no reason for an exception: the fault takes the outcome it
has with no handler bound, and the kernel's decline line for a forwarded fault is the one the
pager's own decline printed. The decliner shares nothing with the request loop but a wake
notification, so a receive on the endpoint never waits behind a request.

Labels 19–21, 23, and 24 are the **debug authority**, and label 22 the **thread registry** it
reads. `REGISTER_CRASH_SERVICE`, `ATTACH_PROCESS`, `LIST_PROCESSES`, and `DETACH_PROCESS` are
served only on a badge carrying `procmgr_labels::DEBUG_AUTHORITY`, which svcmgr mints, from the
un-badged procmgr source init endows it, for a service whose definition sets
`debug_authority = yes` ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md));
no other path mints it, so an image that stages no such service has no attach path. The crash
service ([services/crashd/README.md](../../crashd/README.md)) and the GDB stub
([services/gdbstub/README.md](../../gdbstub/README.md)) are its consumers.

### Label 19: `REGISTER_CRASH_SERVICE`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_CRASH_SERVICE` (19) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `caps[0]` | A Thread cap of the service's main thread (any rights); further caps are deleted |

procmgr parks the decliner, keeps the thread cap, and replies `SUCCESS` with one cap, `RECV` on the
crash endpoint. The park is a message on the endpoint itself: procmgr's request loop calls the
endpoint, un-badged and with a label no fault carries, and the decliner, which receives it only
after every fault queued ahead of it and declines those, answers it and waits on its wake
notification. The service then receives every fault on the endpoint. procmgr checks the kept cap on
every pass of its loop, which the service's own death, or any request, wakes: once the cap is gone
(procmgr's teardown of the service revokes every cap derived from its main thread) or its thread
has exited, procmgr deletes the cap and signals the decliner, which receives again, declining the
faults already queued. Replies: `UNAUTHORIZED` without the authority; `INVALID_ARGUMENT` without a
thread cap, or when procmgr has no crash endpoint; `CRASH_SERVICE_PRESENT` while a registered
service lives; `OUT_OF_MEMORY` when the `RECV` cap cannot be derived or the park fails. A refused
request's caps are deleted. A `SUCCESS` reply that cannot deliver the `RECV` cap (the caller's
`CSpace` cannot take it, or the caller is gone) registers nothing: procmgr deletes the `RECV` cap
and the kept thread cap and signals the decliner, as at the take-back. svctest's `crash_endpoint`
phase drives the registration, the refusal of a second one, the handover, the take-back, and a
registration after it.

### Label 20: `ATTACH_PROCESS`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::ATTACH_PROCESS` (20) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `data[0]` | The target: its process badge, or a thread's crash badge as a fault message on the crash endpoint carries it |
| `data[1]` | The index of the first thread to return |
| `caps[0]` | Optional: the **debugger watch**, a Thread cap of the caller's own main thread, of any rights; further caps are deleted |

Reply `SUCCESS` with:

| Field | Meaning |
|---|---|
| `data[0]` | The number of threads in the target's list: its main thread, then each thread it registered (Label 22) that procmgr still holds |
| `data[1]` | The image's load bias |
| `data[2]`, `data[3]` | The biased start and end (exclusive) of the image's executable segments; both `0` for an image with none |
| `data[4]` | The address of the target's `ProcessInfo` page |
| `data[5]` | The target's process badge (`ATTACH_WORD_PROCESS_BADGE`) |
| `data[6]` | The list index of the thread `data[0]` names (`ATTACH_WORD_NAMED_THREAD`): `0`, the main thread, for a process badge; the registered thread bound under a crash badge; `ATTACH_NO_THREAD` (`u64::MAX`) when that thread is no longer listed |
| caps | The Thread caps of threads `data[1]..`, each with `OBSERVE`, `CONTROL`, and `UPCALL`, at most `ATTACH_THREADS_PAGE` (`MSG_CAP_SLOTS_MAX`, 4); none past the count |

The list is the main thread at index 0, then the registered threads in registration order. Before
it replies, procmgr drops from the target's registry each thread that has exited or whose cap the
runtime revoked (its reclaim of a joined or reaped thread does), so no thread that exited before
the request is listed; a thread blocked on a fault has not exited and stays listed. A thread whose
cap the runtime revokes between that sweep and the derivation of the reply's caps is swept out and
the page derived again, in at most four derivations in all. The list can change between two calls
of a paged walk, as threads register and exit; the named thread's index is the one in the reply
that carries it, and a caller that needs that thread's cap from a later page reads `data[6]` of
that page's reply too. The caps are derivations of procmgr's own; procmgr's teardown of the target,
and the runtime's reclaim of a registered thread, revoke them. A debugger that binds a listed
thread's exception or upcall class MUST bind it under a badge carrying
`procmgr_labels::DEBUGGER_BADGE_TAG` (bit 62) with bit 63 clear: the **debugger tag**, by which
procmgr tells a debugger's binding from its own crash bindings (the process badge `data[5]` returns,
and the crash badges, bit 63) and from a handler the target bound itself (§ Label 22, § Label 24).

A debugger that rebinds the target's threads sends the watch with its first request. When the attach
succeeds, procmgr keeps the watch as the target's debugger, replacing, and deleting, the one an
earlier attach left; a watch that is not a Thread cap, or that a refused attach carried, is deleted.
An attach whose reply cannot deliver its caps (the caller's `CSpace` cannot take them, or the caller
is gone) has not succeeded: procmgr deletes the caps derived for it and the watch, and keeps the
earlier one.
procmgr reads the watched thread's state on every pass of its loop, which a process's death wakes:
once the thread has exited, or its cap went with its process's teardown, procmgr logs `debugger
gone; crash bindings restored` and restores the target's crash bindings as `DETACH_PROCESS` does
(Label 24). So a debugger that dies attached leaves no thread of its target bound to an endpoint no
one receives on: a fault the target takes meanwhile waits there, and the restore delivers it again
to the crash endpoint ([docs/fault-handling.md](../../../docs/fault-handling.md) § Delivery, Resume,
and Kill, Rebind), and an upcall the debugger posted is dropped and its thread resumes. A thread the
target spawned while the debugger's binding was on its spawner copies that binding: when it
registers after the restore, procmgr binds it back then, and when its registration is refused at the
registry's bound or for procmgr's heap, at the refusal, under the process badge (§ Label 22). A
thread whose registration never reached procmgr, its cap derivation or its IPC buffer having
failed, the kernel having cancelled its call before procmgr received it, or its runtime having
stopped registering after a `NOT_ATTACHABLE` refusal, keeps the binding it copied, which procmgr
cannot reach. The target's `DECLARE_NO_DEBUG` deletes the watch (§ Label 21). The restore cannot
undo the dead debugger's own changes to the target, a breakpoint it planted among them. procmgr
only reads the watched thread's state, which takes no right.

`data[5]`, `data[6]`, the crash-badge form of `data[0]`, and the watch extend the reply and the
target's domain without changing what an earlier request means: a request that carries no cap is
answered as before, a request naming a process badge means what it meant, and a caller that
reads only `data[0]` to `data[4]` and pages from index 0 sees the main thread first, as before,
with the registered threads after it. Refusals, in order: `UNAUTHORIZED` without the authority;
`INVALID_BADGE` when no live process carries the badge, or no registered thread of a live process
the crash badge, which covers init, memmgr, and procmgr, none of which procmgr created;
`NOT_ATTACHABLE` when the target declared itself undebuggable (Label 21); `OUT_OF_MEMORY` when the
cap of a thread still listed cannot be derived, or threads keep going through four derivations of
the page, the caps already derived for the reply then deleted. The refusal order is
`process_table::attach_target`.

### Label 21: `DECLARE_NO_DEBUG`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::DECLARE_NO_DEBUG` (21) |
| caller's cap badge | The sender's own process badge (its `ProcessInfo.procmgr_endpoint_cap`); a process handle is refused (§ Messages) |
| caps | none; procmgr deletes any cap the message carried |

The sender declares itself undebuggable: procmgr marks it; deletes the debugger watch an attach left
(Label 20), so no debugger's death binds it back; unbinds the exception class of its main thread and
of every thread it registered (Label 22) wherever procmgr bound it (under the process badge or a
crash badge) or a debugger did (under the debugger tag, Label 20), and the upcall class wherever a
debugger bound it, leaving a handler the process bound itself; releases the registered threads; and
refuses `ATTACH_PROCESS` and `REGISTER_THREAD` on it from then on. A debugger attached at the
declaration loses its bindings on the threads procmgr holds, the watch, and the registered threads'
caps its attach was given, which procmgr revokes. The main thread's cap it was given keeps its
rights, since procmgr cannot revoke it without revoking the creator's: such a debugger can still
stop that thread and bind its classes, and nothing binds back what it binds after the declaration.
A process sends it before it spawns a thread: a thread spawned before that copies its spawner's
binding, and the declaration reaches it only once it is registered. One whose registration reaches
procmgr after the declaration is unbound then (Label 22). One procmgr does not hold at the
declaration, its runtime having sent no registration, or its registration having been refused at
the registry's bound or for procmgr's heap, keeps a binding: the one it copied, or procmgr's under
the process badge when that was a debugger's (Label 22).
The senders are the processes a stop of which would deadlock a debug-authority holder, which waits
on them for its log output or its own progress: logd, the serial and framebuffer drivers, the debug
port's virtio-console driver, through which the GDB stub reaches its host for every packet, and
every debug-authority holder, so none attaches to itself. Replies `SUCCESS`, or `INVALID_BADGE` when
the badge names no live process or the request came on a process handle.

Any process may declare itself, on its own cap alone: the badge names the sender, and the process
handle its creator holds carries `procmgr_labels::PROCESS_HANDLE_TAG`, on which procmgr refuses the
request (§ Messages), so a declaration affects the declarer and no other process, apart from
another process's thread the declarer registered (Label 22), whose crash or debugger binding is
unbound with the declarer's own since procmgr tells a binding by its badge alone; and it removes no
authority a debug-authority holder needs over another. It is one-way: nothing makes a declared
process debuggable again for its life. No restore of another process's crash bindings (Label 24)
binds a thread of a declared process back to the crash endpoint, whichever registry lists it,
unless that registry's process registered it as its own, as procmgr can take it to be (Label 22). A
process that holds a cap of a declared process's thread, as its creator holds the main thread's, can
still register that thread in its own registry (Label 22), and so list it to a debugger attached to
that process, which gains on it the `CONTROL` the cap's holder already has.
Until it declares, a process is bound and attachable like any other: a fault of logd or one of
those drivers between its creation and its declaration, which each sends before its bootstrap,
reaches the crash service, whose log output then waits on the faulting process until the crash
service's watchdog bound ([crashd Operation](../../crashd/docs/operation.md) § Bounds) declines
the fault.

### Label 22: `REGISTER_THREAD`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_THREAD` (22) |
| caller's cap badge | The sender's own process badge (its `ProcessInfo.procmgr_endpoint_cap`); a process handle is refused (§ Messages) |
| `caps[0]` | A Thread cap with `OBSERVE`, `CONTROL`, and `UPCALL` (`RIGHTS_THREAD`); further caps are deleted |

The sender hands procmgr a cap of one of its threads, which procmgr keeps in the process's registry
until the thread exits, the cap is revoked, or the process is torn down; `ATTACH_PROCESS` lists it.
The runtime sends it from each thread it spawns, before the thread runs its code, with a copy of
the thread's own cap ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Thread
registration). When the thread's exception class is bound under the sender's process badge or under
a crash badge, any badge with bit 63 set, as a thread that copied its spawner's bindings is
(whether or not that spawner is still registered), procmgr binds it again under a fresh crash
badge. So it does when the class is bound under the debugger tag (Label 20) while the process has
no debugger watch: the thread copied a debugger's binding from its spawner, and that debugger has
since detached or died; procmgr then also unbinds the upcall class a debugger bound on it. A
debugger's binding while a watch is held, a binding of another handler, or none, is left, and the
thread is then listed without a crash badge. procmgr reads the binding's badge, which
`SYS_THREAD_GET_FAULT_HANDLER` returns, not its endpoint, so it tells its own binding and a
debugger's by the badge alone: a debugger binds under the debugger tag (Label 20), and a handler a
process binds on its own threads under a badge that carries neither bit 62 nor bit 63, or procmgr
takes it for a debugger's or its own.

Before it adds the thread, procmgr drops from the registry the threads that have exited or whose cap
was revoked, when the registry has reached the count its last sweep set (64 at first, then twice
what the sweep kept, at least 64), or the bound when that count lies past it, and at least half as
many registrations as it holds, refused ones included, came since the last sweep. A sweep therefore
comes after at least half as many requests as threads it reads, so the sweeps cost at most two
thread-state reads per request on average, and threads that are gone hold the bound for at most
half a registry's worth of requests.

The registry holds at most `procmgr_labels::REGISTERED_THREADS_MAX` (16384) threads per process
([docs/limits.md](../../../docs/limits.md) § Shared IPC and protocol crates); past it a thread runs
unregistered, so no spawn fails for the bound. A thread refused there, or for procmgr's heap, that
carries a binding under the debugger tag, a watched debugger's included, is bound back to the crash
endpoint under the process badge at the refusal, with a debugger's upcall binding unbound, since no
attach lists an unregistered thread and no restore reaches it. procmgr does not compare a
registration against the threads it holds: a thread registered twice takes two entries, both
counting toward the bound, and the runtime registers each thread once: it does not repeat a call
that failed, since the kernel can cancel a call with `Interrupted` after procmgr received it and
carried it out, so the runtime cannot tell such a thread registered or not
([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Thread registration).

procmgr does not check that the thread runs in the sender's address space, which no kernel query
gives: a sender can register only a thread it holds `CONTROL` on, which already lets it read and
change that thread. It records with each thread whose it is, as the binding shows before procmgr
rebinds it: another live process's when the binding is that process's badge, or a crash badge that
process's registry lists; unknown when the class is unbound; the sender's own otherwise (its process
badge, a crash badge its own registry or no registry lists, the debugger tag, or another handler's
badge). A restore reads it (Label 24). Another process's thread bound under its own process badge
(that process's main thread, or a thread that copied it and has not registered yet) is listed in the
sender's registry but not rebound. One bound under a crash badge is rebound into the sender's
registry: that thread's faults then reach the crash service under a crash badge the sender's process
holds, and are reported against the sender's image; the other process's `DECLARE_NO_DEBUG` still
unbinds it while that process's registry holds it, since the declaration unbinds any crash badge
(Label 21), and no restore of the sender's binds it back (Label 24). One bound under the debugger
tag while the sender has no debugger watch is rebound into the sender's registry too, whichever
process's debugger bound it, since procmgr cannot tell; the sender's declaration (Label 21) and
restore (Label 24) likewise treat a debugger's binding on such a thread as one on the sender's own,
and procmgr records the thread as the sender's, as it does one under a crash badge no live registry
lists, so a restore of the sender's binds it back to the crash endpoint even once its own process
has declared itself undebuggable (Label 21). Such a cap comes from the other process itself, from a
debug-authority holder's attach, or, for the other process's main thread alone, from its creation
(`CREATE_PROCESS` and `CREATE_FROM_FILE` give the creator that cap), whose binding is its process
badge, which procmgr does not rebind and records as that process's, none once that process has
declared itself undebuggable, the debugger tag while a debugger attached to that process holds it,
or a crash badge another registry put on it. So no process gains this over a spawned thread it was
not given, and no restore of the creator's binds a declared child's main thread back (Label 24)
unless that thread carried the debugger tag, or a crash badge no live registry lists, when the
creator registered it.

Replies `SUCCESS`; refusals, in order: `INVALID_BADGE` when the badge names no live process, or the
request came on a process handle (§ Messages);
`NOT_ATTACHABLE` when the process declared itself undebuggable (Label 21), after procmgr unbinds
the thread as the declaration unbinds the declarer's threads, and on which the runtime sends no
further registration; `INVALID_ARGUMENT` without a Thread cap carrying `RIGHTS_THREAD`;
`THREAD_LIMIT` at the bound, after any sweep due; `OUT_OF_MEMORY` when procmgr's heap cannot hold
the entry. A refused request's caps are deleted.

### Label 23: `LIST_PROCESSES`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::LIST_PROCESSES` (23) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `data[0]` | `0` to start the walk, `1` to resume after the badge in `data[1]` |
| `data[1]` | The cursor badge when `data[0]` is `1` |
| caps | none; procmgr deletes any cap the message carried |

Reply `SUCCESS` with `data[0]` = the page's count, then, for each live process above the cursor in
ascending badge order, `LIST_PROCESSES_WORDS_PER_ENTRY` (10) words: its process badge, its name's
length in bytes, and the name in eight words, little-endian and zero-padded
(`procmgr_labels::pack_list_entry`, `unpack_list_entry`). A page holds at most
`LIST_PROCESSES_PAGE` (`(MSG_DATA_WORDS_MAX - 1) / 10` = 6) entries; a page shorter than that ends
the walk, and a full page is followed by a call resuming after its last badge. A process that stays
live across the whole walk is listed exactly once, as for `QUERY_LIVE_PROCESSES`; a cursor whose
process died resumes at the next badge above it.

A process's name is the first string of the argv its creator passed (`CREATE_ARGV_ENV`), up to
its NUL, truncated to `svcmgr_labels::NAME_MAX` (64) bytes, or empty for a process created
without argv. For a service it is the first word of its recipe's `argv`. procmgr records it at
creation and never changes it. It is a label the creator chose, not an identity: two processes can
share one, and a debugger that looks a process up by name takes the first match in badge order.
The walk lists every live process procmgr created, those that declared themselves undebuggable
(Label 21) among them, which then refuse the attach. Refusals: `UNAUTHORIZED` without the
authority; `INVALID_ARGUMENT` for a `data[0]` other than 0 or 1. The GDB stub walks it to find the
process its host names ([services/gdbstub/README.md](../../gdbstub/README.md)).

### Label 24: `DETACH_PROCESS`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::DETACH_PROCESS` (24) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `data[0]` | The target's process badge |
| caps | none; procmgr deletes any cap the message carried |

procmgr hands the target's crash bindings back after a debugger's attach. It binds the main thread
to the crash endpoint again under the process badge when its exception class is bound under the
debugger tag (Label 20), is unbound, or is bound by procmgr under another badge. A registered thread
(Label 22) it restores by whose thread it recorded at the registration
(`process_table::ProcessTable::restore_action`):

- The target's own, by the main thread's rule: when its class is bound under the debugger tag, is
  unbound, or is bound by procmgr under a badge other than the thread's crash badge, it binds again
  under that crash badge, minting one for a thread that has none (one that registered while the
  debugger's binding was on it, which a registration leaves).
- Another process's that procmgr left under that process's own badge at the registration, while
  that process lives and has not declared itself undebuggable: bound back under that badge from a
  debugger's binding alone.
- Any other thread of another process (one procmgr rebound under a crash badge at the
  registration, which may be a declared process's thread that a third registry had rebound before
  the target registered it, or one of a process that has declared itself undebuggable or is gone),
  or a thread whose class was unbound at its registration: never bound to the crash endpoint, and
  a debugger's binding on it is unbound, so no restore binds a thread procmgr did not record as the
  target's own back for a declared process.

A thread bound to any other handler is left: one the target bound itself, or another process's
thread bound under that process's own badge. Since procmgr tells whose a thread is by its binding at
the registration, another process's thread that then carried the debugger tag, or a crash badge no
live registry lists, is restored as the target's own (Label 22). procmgr also unbinds each listed
thread's upcall class that is bound under the debugger tag, and deletes the debugger watch the
attach left (Label 20). A thread whose bind fails keeps the binding it has, as does each thread
that needs a fresh crash badge when procmgr's heap cannot hold them, which procmgr logs; a failure
to bind the main thread is logged. procmgr rebinds over the debugger's binding, so no thread it
binds back is unbound meanwhile, and a fault in flight under the debugger's binding is delivered
again to the crash endpoint; on a thread whose debugger's binding it unbinds instead, such a fault
is unhandled; an upcall pending under the debugger's binding is dropped and its thread resumes (§
Delivery, Resume, and Kill, Rebind, and § Asynchronous Upcalls, in
[docs/fault-handling.md](../../../docs/fault-handling.md)). A debugger holds no SEND on the crash
endpoint, so it cannot restore those bindings itself: it writes back the text it changed and
resumes the threads it held, then sends this, and then unbinds any other class it bound. procmgr
restores the bindings the same way, unasked, when the watched debugger thread has exited. A
declared process (Label 21) is never bound back: the declaration deleted its watch, and this
request refuses it.

procmgr restores its own crash bindings, not what the attach found: a handler the target bound on
a thread's exception class itself, which the debugger's bind replaced, is not bound back, and that
thread's faults reach the crash endpoint from then on. procmgr binds no other class, so the
target's own handler of another class the debugger bound over is not bound back either.

Replies `SUCCESS`; refusals, in order: `UNAUTHORIZED` without the authority; `INVALID_BADGE` when
no live process carries the badge (a thread's crash badge names no process here); `NOT_ATTACHABLE`
when the target declared itself undebuggable (Label 21). The refusal order is
`process_table::detach_target`. svctest's `crash_endpoint` phase drives a `LIST_PROCESSES` walk to
a process it attached to, this request's restore of a registered thread whose exception and upcall
classes it rebound, and the same restore once an attach's watch thread exits.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC message format, cap transfer protocol |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | System-scope creation order; procmgr's role and authority boundary with memmgr |
| [abi/process-abi](../../../abi/process-abi/README.md) | ProcessInfo handover struct |
| [abi/syscall](../../../abi/syscall/README.md) | Syscall numbers and register conventions |
| [services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) | Memory-cap allocation IPC |

---

## Summarized By

[Kernel Cross-Boundary Disclosure Inventory](../../../core/kernel/docs/cross-boundary-disclosure.md),
[Scheduler Internals](../../../core/kernel/docs/scheduler.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md),
[Fault Handling](../../../docs/fault-handling.md),
[Namespace Model](../../../docs/namespace-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[crashd Operation](../../crashd/docs/operation.md),
[devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md),
[services/drivers/virtio/console/README.md](../../drivers/virtio/console/README.md),
[services/gdbstub/README.md](../../gdbstub/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[services/logd/README.md](../../logd/README.md),
[logd IPC interface](../../logd/docs/ipc-interface.md),
[memmgr IPC Interface](../../memmgr/docs/ipc-interface.md),
[services/procmgr/README.md](../README.md),
[Restart Protocol](../../svcmgr/docs/restart-protocol.md),
[`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)
