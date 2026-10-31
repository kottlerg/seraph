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
create call returns); procmgr identifies the target process by the badge
`ipc_recv` delivers. Labels 14–18 are specified in § `REGISTER_DEATH_EQ`,
§ `REGISTER_INIT_TEARDOWN`, § `INIT_TEARDOWN_DONE`, § `QUERY_INIT_REAP`, and
§ `QUERY_LIVE_PROCESSES` below. Labels 3–7 and 10
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
| label bits `[16..32]` | Create flags and scheduling fields (see **Pinned flag** and **Scheduling fields** below) |
| label bits `[32..48]` | `args_bytes`: byte length of the argv blob (at most `ipc::ARGS_BLOB_MAX`, 256) |
| label bits `[48..56]` | `args_count`: number of NUL-terminated argv strings |
| label bits `[56..64]` | `env_count`: number of NUL-terminated `KEY=VALUE` strings |
| data[0..] | argv blob (`args_bytes.div_ceil(8)` words); when `env_count > 0`, one word carrying `env_bytes` (low 16 bits), then the env blob (`env_bytes.div_ceil(8)` words, at most 256 bytes) |
| cap[0] | Memory capability for the ELF module image |
| cap[1] | Optional creator endpoint, copied into the child's `ProcessInfo.creator_endpoint_cap` |

procmgr maps the module, parses the ELF, creates the child's address space,
CSpace, and thread, maps LOAD segments, and populates the `ProcessInfo`
handover page. The whole data area is bounded by `MSG_DATA_WORDS_MAX` (64
words), so argv and env cannot both reach 256 bytes; the sender keeps the packed
layout within it. An oversized argv or env blob degrades to empty, and procmgr
never reads past the data area: an `args_bytes` over 256 degrades env along
with argv (the env header position derives from it), an env header word beyond
the delivered word count degrades env to empty, and blob bytes declared beyond
the delivered words read as zero. procmgr deletes its copies of cap[0] and
cap[1] whether creation succeeds or fails, and deletes any further cap. A
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
| 2 | `OUT_OF_MEMORY` | Creation failed: module mapping, ELF validation or loading, or kernel-object or memory-cap allocation |
| 7 | `INVALID_ARGUMENT` | Reserved label bits `[28..32]` set, or the scheduling fields violate the resolution rules below (band above the creator's ceiling, or priority above the resolved band) |

**Pinned flag.** Demand paging is the default: at finalize procmgr binds every
child's main thread fault handler to memmgr (the system pager) via
`SYS_THREAD_SET_FAULT_HANDLER`, delegates the child `AddressSpace` to memmgr via
`memmgr_labels::DELEGATE_ASPACE`, and sets `ProcessInfo.pager_endpoint_cap` (the
child's badged memmgr cap, whose derivation badge the kernel stamps on each fault)
and `pager_badge` (that badge) so the runtime inherits the handler onto spawned
threads. The
child then backs reserved regions lazily via
`std::os::seraph::register_demand_paged`. The label's bit 16 (`CREATE_PINNED`,
in the `[16..32]` window shared with `CREATE_FROM_FILE`) opts out: the
child is left eager-mapped with no pager. Set it only for a process that cannot
depend on the fault path — a DMA driver. init, memmgr, and procmgr are pre-pager
and never routed through this path, so they are pinned by construction. See
[docs/fault-handling.md](../../../docs/fault-handling.md). The binding is
best-effort: a failure degrades to "no pager" (faults kill), never blocking
creation.

**Scheduling fields.** Bits `[18..23]` (`CREATE_PRIORITY`) and `[23..28]`
(`CREATE_BAND_MAX`) of the label window — shared by `CREATE_PROCESS` and
`CREATE_FROM_FILE` — carry the child's scheduling placement; bits `[28..32]`
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
further threads at the same level.

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

### Label 8: `DESTROY_PROCESS`

Destroy a process. Sent on the process handle with no data words or caps.
procmgr removes the process entry, revokes and deletes the child's `Thread`,
`CSpace`, `AddressSpace`, `ProcessInfo` Memory cap, and TLS Memory cap, deletes
any namespace caps never consumed by `START_PROCESS`, and sends memmgr
`PROCESS_DIED` for the child's memmgr badge.

**Reply:** label 0 (success), always. An unknown or already-destroyed badge is
a no-op.

### Label 9: `QUERY_PROCESS`

Query a process's state without blocking on a death event. Sent on the process
handle with no data words or caps.

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | State: 0 `ALIVE`, 1 `CREATED` (not yet started), 2 `UNKNOWN` (no entry; reaped or never valid), 3 `EXITED` |
| data[1] | Kernel-encoded exit reason when `data[0]` is `EXITED`; 0 otherwise |

A live entry whose thread the kernel reports as exited answers `EXITED` before
procmgr reaps it. After the reap, the badge answers `EXITED` for
`RECENT_EXIT_RETENTION_NS` (30 s) of monotonic time, however many other
processes die meanwhile, and `UNKNOWN` after that.

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
resulting file cap. procmgr streams the ELF with `FS_READ` / `FS_READ_MEMORY`
against that cap and never holds a namespace cap of its own. Loading, the
**Pinned flag**, and the **Scheduling fields** are as for `CREATE_PROCESS`.

**Request:**

| Field | Value |
|---|---|
| label bits `[0..16]` | 13 |
| label bits `[16..32]` | As for `CREATE_PROCESS`; bit 17 (`CREATE_DEATH_RELAY`) marks a trailing death-relay cap |
| label bits `[32..64]` | `args_bytes`, `args_count`, `env_count`, as for `CREATE_PROCESS` |
| data[0] | `file_size` in bytes, from the caller's `NS_LOOKUP` size hint |
| data[1..] | argv blob, then the optional env header word and env blob, laid out as for `CREATE_PROCESS` |
| cap[0] | File cap for the binary |
| cap[1] | Optional creator endpoint, copied into the child's `ProcessInfo.creator_endpoint_cap` |
| last cap | When `CREATE_DEATH_RELAY` is set: POST-only `EventQueue` cap |

procmgr `FS_CLOSE`s and deletes the file cap after the load, whether it succeeds or fails, and
deletes its copy of the creator endpoint and any cap the layout does not name. When present, the
death-relay cap is the last cap in the message, so the creator-endpoint slot stays at cap[1]; it is
a cap of its own, so a request that sets `CREATE_DEATH_RELAY` carries at least two caps, and one
whose only cap is the file cap is refused with `INVALID_ARGUMENT`. Once the child is recorded,
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
| 1 | `INVALID_ELF` | `file_size` is zero, or ELF validation or relocation failed |
| 2 | `OUT_OF_MEMORY` | Memory-cap, kernel-object, or badge allocation failed |
| 7 | `INVALID_ARGUMENT` | No file cap, `CREATE_DEATH_RELAY` set with only the file cap, reserved label bits `[28..32]` set, or the scheduling fields violate the resolution rules (band above the creator's ceiling, or priority above the resolved band) |
| 10 | `IO_ERROR` | An `FS_READ` of the ELF header against the file cap failed, or a segment's file bytes did not all arrive: an `FS_READ_MEMORY` failed or returned zero bytes, its cache page could not be mapped, or its reply named a range past that page |
| 11 | `MAP_FAILED` | Mapping failed during segment load |
| 12 | `INSUFFICIENT_RIGHTS` | Rights derivation failed during segment load |

---

## Capability Transfer

Capability transfer uses the IPC message's cap slot array (up to 4 caps per
message). On `CREATE_PROCESS`, the caller's Memory cap is moved into procmgr's
CSpace atomically with the message delivery, per
[docs/ipc-design.md](../../../docs/ipc-design.md#capability-semantics-in-ipc)
§ Capability Semantics in IPC.
procmgr consumes the cap during
process creation and does not return it.

Every cap a request transfers lands in procmgr's CSpace, whether or not the
request's layout names it. procmgr deletes the caps a layout does not name
(caps past the last named position, and every cap of a label that names none:
`START_PROCESS`, `DESTROY_PROCESS`, `QUERY_PROCESS`, `INIT_TEARDOWN_DONE`, and
unknown opcodes), and every cap of a refused request, except the init-reap
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

## REGISTER_DEATH_EQ — install logd's death observer

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_DEATH_EQ` (14) |
| caller's cap badge | MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY` (`1 << 62`); svcmgr mints this badged `SEND\|GRANT` cap for real-logd on each launch, from the badge-0 `SEND\|GRANT` procmgr source init hands it at the handover (see the [svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)) |
| `caps[0]` | `EventQueue` cap with `POST` right and an observer node per supervised process; procmgr binds it as a second death observer on the main thread of every supervised process |

Procmgr stores the cap in
[`process::LOGD_DEATH_EQ`](../src/process.rs) and immediately
walks its process table, calling
`sys_thread_bind_notification(entry.thread_cap, logd_eq,
correlator_of(entry.badge))` on every live entry, where `entry.thread_cap`
is the process's main thread and the correlator is the badge's low 32 bits,
which procmgr keeps unique among live processes. From that moment onward,
[`finalize_creation`](../src/process.rs) also binds the same EQ on
the main thread of every newly spawned child (the same correlator). Threads
a process creates itself carry no logd binding.

Reply: `procmgr_errors::SUCCESS` on bind, `UNAUTHORIZED` if the
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

On the first round procmgr stores the kernel-object caps and binds a death-EQ
observer on both init threads under the same correlator:
`syscall::thread_bind_notification(main_thread, death_eq, procmgr_labels::INIT_REAP_CORRELATOR)`
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
`INIT_REAP_CORRELATOR` (reserved `u32::MAX`) calls
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
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[services/logd/README.md](../../logd/README.md),
[logd IPC interface](../../logd/docs/ipc-interface.md), [services/procmgr/README.md](../README.md),
[Restart Protocol](../../svcmgr/docs/restart-protocol.md),
[`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)
