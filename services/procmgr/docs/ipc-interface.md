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

`START_PROCESS`, `RELEASE_HOLD`, `DESTROY_PROCESS`, `QUERY_PROCESS`, `CONFIGURE_PIPE`,
and `CONFIGURE_NAMESPACE` are sent on a **process handle** (the badged endpoint a
create call returns); procmgr identifies the target process by the badge
`ipc_recv` delivers. Labels 14–18 are specified in § `REGISTER_DEATH_EQ`,
§ `REGISTER_INIT_TEARDOWN`, § `INIT_TEARDOWN_DONE`, § `QUERY_INIT_REAP`, and
§ `QUERY_LIVE_PROCESSES` below. Labels 4–7 and 10
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
| label bits `[16..31]` | Create flags and scheduling fields (see **Pinned flag**, **Scheduling fields**, and **argv and env** below) |
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
| cap[0] | Process handle (badged endpoint identifying this process) |
| cap[1] | Child `Thread` capability (Control and Observe rights, `RIGHTS_THREAD`) |

The process handle is a badged endpoint capability. The caller uses it for the
per-process operations — the badge identifies the process without a forgeable
PID. The `Thread` cap allows the caller to bind death notifications or
stop/configure the thread.

The reply's cap transfer is all-or-nothing
([docs/ipc-design.md](../../../docs/ipc-design.md#message-format) § Message Format). When the
caller's `CSpace` cannot take both caps (or the caller is gone), the caller
resumes with `IPC_REPLY_TRANSFER_FAILED` and no caps. procmgr then deletes both
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
| 2 | `OUT_OF_MEMORY` | Creation failed: module mapping, ELF validation or loading, kernel-object or memory-cap allocation, or, with `CREATE_DMA_HOLD`, the room for the child's held reclaim (the child, never started, is destroyed and its pages returned) |
| 7 | `INVALID_ARGUMENT` | Reserved label bits `[31..64]` set, the scheduling fields violate the resolution rules below (band above the creator's ceiling, or priority above the resolved band), or the argv and env violate the rules of **argv and env** below |
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

**Pinned flag.** Demand paging is the default: at finalize procmgr binds every
child's main thread fault handler to memmgr (the system pager) via
`SYS_THREAD_SET_FAULT_HANDLER`, delegates the child `AddressSpace` to memmgr via
`memmgr_labels::DELEGATE_ASPACE`, and then sets `ProcessInfo.pager_endpoint_cap` (the
child's badged memmgr cap, whose derivation badge the kernel stamps on each fault)
and `pager_badge` (that badge) so the runtime inherits the handler onto spawned
threads. The
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
until the creator sends `RELEASE_HOLD` (§ Label 3) on the child's process
handle, and until then memmgr keeps the child's frames on that record, out of
its free pool. Set it for a driver whose device may DMA into its frames after
it dies: the creator releases the hold once it has confirmed the device's DMA
stopped, and never when it cannot, which leaves the frames quarantined for the
rest of the boot
([docs/device-management.md](../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown). A child destroyed before
`START_PROCESS` never ran, so it touched no device, and its teardown sends
`PROCESS_DIED` at once. procmgr reserves the room the child's parked record
takes before it replies to the create, so no teardown frees a held child's
pages for want of a record; when it cannot, the create fails with
`OUT_OF_MEMORY`.

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
`CREATE_DMA_HOLD` (§ Label 1, **DMA hold flag**). Sent on the process handle
with no data words or caps. procmgr sends memmgr `PROCESS_DIED` for the child's
memmgr badge, deletes its copy of the child's badged memmgr SEND, and drops the
held record, so memmgr returns the child's frames to its free pool.

procmgr serves its requests in order, so a `DESTROY_PROCESS` the creator sends
first has torn the child down, and parked its record, before the release is
served, whether or not procmgr had reaped the child already. A release that
finds no held record changes nothing: the child is live, was never started or
never held, or was released already. procmgr cannot tell the creator's
handle from any other SEND carrying the child's badge: the child's own procmgr
cap carries it too, and the child may have granted a copy onward before it
died, so any holder of such a copy can release the hold once the child is torn
down. A dead child itself cannot. procmgr never hands a held record's badge to a
new child.

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success): the held reclaim was sent; or a nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_BADGE` | procmgr holds no reclaim for the handle's badge |

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
child `Thread` cap), including the destruction of a child whose reply caps
cannot be delivered. A failed creation releases what procmgr acquired for the
child, its memmgr record included, as for `CREATE_PROCESS`.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `INVALID_ELF` | `file_size` is zero, or ELF validation or relocation failed (the TLS block's checks aside; see `OUT_OF_MEMORY`) |
| 2 | `OUT_OF_MEMORY` | Memory-cap, kernel-object, or badge allocation failed, the main thread's TLS block could not be built (whatever the cause: an oversized or overaligned `PT_TLS`, a short `.tdata` read, or a mapping), or, with `CREATE_DMA_HOLD`, the room for the child's held reclaim (the child, never started, is destroyed and its pages returned) |
| 7 | `INVALID_ARGUMENT` | No file cap, `CREATE_DEATH_RELAY` or `CREATE_ARGV_ENV` set without a cap of its own, reserved label bits `[31..64]` set, the scheduling fields violate the resolution rules (band above the creator's ceiling, or priority above the resolved band), or the argv and env violate the rules of **argv and env** (§ Label 1) |
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
`INIT_TEARDOWN_DONE`, and unknown opcodes), and every cap of a refused request, except the init-reap
refusals of an un-badged sender that keep caps init may still be running on
(§ `REGISTER_INIT_TEARDOWN`). A padded or refused request from any badged sender
therefore cannot grow procmgr's CSpace. Replies to the calls procmgr makes on a
caller-supplied file cap are treated the same way: procmgr deletes every reply
cap it does not use.

On a create reply, procmgr transfers a badged process handle endpoint (for
subsequent per-process operations) and a derived copy of the child's `Thread`
capability (Control and Observe rights, `RIGHTS_THREAD`) to the caller. procmgr
retains the original caps for process lifecycle management.

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
`DEATH_EQ_AUTHORITY` cap (see the
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

[Scheduler Internals](../../../core/kernel/docs/scheduler.md),
[Capability Model](../../../docs/capability-model.md),
[Fault Handling](../../../docs/fault-handling.md),
[Namespace Model](../../../docs/namespace-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[services/logd/README.md](../../logd/README.md),
[logd IPC interface](../../logd/docs/ipc-interface.md),
[memmgr IPC Interface](../../memmgr/docs/ipc-interface.md),
[services/procmgr/README.md](../README.md),
[Restart Protocol](../../svcmgr/docs/restart-protocol.md),
[`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)
