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
`ipc_recv` delivers. Labels 14–16 are specified in § `REGISTER_DEATH_EQ`,
§ `REGISTER_INIT_TEARDOWN`, and § `INIT_TEARDOWN_DONE` below. Labels 3–7 and 10
are unassigned; procmgr replies `UNKNOWN_OPCODE` (`0xFFFF`) to them and to any
other unknown opcode.

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
handover page. An oversized argv or env blob degrades to empty. procmgr deletes
its copies of cap[0] and cap[1] whether creation succeeds or fails.

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
`memmgr_labels::DELEGATE_ASPACE`, and sets `ProcessInfo.pager_endpoint_cap` /
`pager_badge` so the runtime inherits the handler onto spawned threads. The
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
remain reserved and MUST be zero (`InvalidArgument` otherwise, which keeps a
future field addition provably additive). Resolution, against the **creator's
band ceiling** (badge 0 = init, ceiling `sched_policy::BASELINE_PRIORITY_MAX`;
a badged caller's ceiling is its own minted `band_max`; an unknown badge falls
back to `sched_policy::DEFAULT_SPAWN_PRIORITY`):

| Field | 0 (unspecified) | Nonzero |
|---|---|---|
| `CREATE_BAND_MAX` | copy of the creator's band | `[1, band_max]`; must be ≤ the creator's ceiling |
| `CREATE_PRIORITY` | `DEFAULT_SPAWN_PRIORITY` clamped to the band | must be ≤ the resolved `band_max` (so the child's own band always covers its starting level) |

Violations reply `InvalidArgument` before any resource is acquired. On
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
| 3 | (none) | `thread_configure_with_tls` failed |
| 4 | `INVALID_BADGE` | No process with the given badge exists |
| 5 | `ALREADY_STARTED` | Process was already started |
| 6 | (none) | `thread_start` failed |

Codes 3 and 6 are raw values with no `procmgr_errors` constant.

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
procmgr reaps it. After the reap, the badge answers `EXITED` while it remains
in procmgr's recent-exits ring; retention is best-effort, and once the ring
rotates the badge answers `UNKNOWN`.

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
its own copies on success and on every failure but one: when fewer than three
caps are attached, procmgr replies `INVALID_ARGUMENT` without deleting the
attached caps, which stay in procmgr's CSpace (#449). A spawner calls this
once per piped direction; a later call for the same direction overwrites the
earlier one.

**Error codes:** 2 `OUT_OF_MEMORY` (mapping or `cap_copy` failed), 4
`INVALID_BADGE`, 5 `ALREADY_STARTED`, 7 `INVALID_ARGUMENT` (fewer than three
caps, a zero cap, or an unknown direction).

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
procmgr consumes the transferred caps on success and failure alike.

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

procmgr `FS_CLOSE`s and deletes the file cap after the load, whether it
succeeds or fails. When present, the death-relay cap is the last cap in the
message, so the creator-endpoint slot stays at cap[1]. At finalize procmgr binds
it as an `AddressSpace` death observer (correlator 0) on the child, so a
terminal fault in any of the child's threads posts the fault class to the
spawner's own death queue, then deletes its copy. `CREATE_PROCESS` ignores
bit 17.

**Reply (success):** as for `CREATE_PROCESS` (cap[0] process handle, cap[1]
child `Thread` cap).

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `INVALID_ELF` | `file_size` is zero, or ELF validation or relocation failed |
| 2 | `OUT_OF_MEMORY` | Memory-cap, kernel-object, or badge allocation failed |
| 7 | `INVALID_ARGUMENT` | No file cap, reserved label bits `[28..32]` set, or the scheduling fields violate the resolution rules (band above the creator's ceiling, or priority above the resolved band) |
| 10 | `IO_ERROR` | `FS_READ` against the file cap failed; detecting a failed or zero-byte `FS_READ_MEMORY` mid-segment is design intent; not yet implemented (#449): today the segment tail stays zeroed and creation succeeds |
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
| caller's cap badge | MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY` (`1 << 62`); svcmgr mints this badged SEND for real-logd on each launch, from the badge-0 `SEND\|GRANT` procmgr source init hands it at the handover (see the [svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)) |
| `caps[0]` | `EventQueue` cap with `POST` right; procmgr binds it as a second death observer on every supervised thread |

Procmgr stores the cap in
[`process::LOGD_DEATH_EQ`](../src/process.rs) and immediately
walks its process table, calling
`sys_thread_bind_notification(entry.thread_cap, logd_eq,
entry.badge as u32)` on every live entry. From that moment onward,
[`finalize_creation`](../src/process.rs) also binds the same EQ on
every newly spawned child (correlator = process badge).

Reply: `procmgr_errors::SUCCESS` on bind, `UNAUTHORIZED` if the
caller lacks `DEATH_EQ_AUTHORITY` or a death EQ is already registered,
`INVALID_ARGUMENT` if no cap was transferred. Registration is first-wins:
procmgr deletes the cap a second registration transfers and keeps the first,
so a restarted logd receives no death events. A request refused for a missing
`DEATH_EQ_AUTHORITY` badge keeps its transferred cap in procmgr's CSpace
([#449](https://github.com/kottlerg/seraph/issues/449)).

logd derives a `POST`-only copy from its `RECV+POST` event queue
before sending — the kernel's cap-transfer moves the sent cap into
procmgr's CSpace (per
[docs/capability-model.md](../../../docs/capability-model.md#transfer) § Transfer),
so logd must retain `RECV` on its own copy to
keep `wait_set_add` and `event_try_recv` working.

---

## REGISTER_INIT_TEARDOWN — init reap handoff

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_INIT_TEARDOWN` (15) |
| `data[0]` | `1` on the first round (carrying kernel-object caps); `0` on subsequent donation rounds |
| `caps[0..]` | Round 1: 4 kernel-object caps (`AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`) — MOVED out of init's CSpace via IPC cap-transfer. Subsequent rounds: 1-4 reclaimable Memory caps per round (every reclaimable Memory cap init solely owns; the set is in [docs/process-lifecycle.md](../../../docs/process-lifecycle.md#init-reap) § Init reap). |

On the first round procmgr stores the kernel-object caps and binds a death-EQ
observer on both init threads under the same correlator:
`syscall::thread_bind_notification(main_thread, death_eq, procmgr_labels::INIT_REAP_CORRELATOR)`
and the same call on `logd_thread`, expecting two deaths (`pending_deaths = 2`); the
reap runs only after the second death. Either bind failing rejects the round with
`INVALID_ARGUMENT`. Subsequent rounds append to the donation Memory cap list.
`INIT_TEARDOWN_DONE` (label 16, no caps, no data words) closes the stream and arms
the state machine.

Reply: `procmgr_errors::SUCCESS` on accept, `INVALID_ARGUMENT` when a first round arrives while an
unreaped teardown is pending, a first round carries other than 4 caps, either death-EQ bind fails,
or a donation round arrives while no teardown is pending. The pending teardown is cleared once the
reap runs. The caps a rejected round moved into procmgr's CSpace stay there.

## INIT_TEARDOWN_DONE — end-of-stream notification

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::INIT_TEARDOWN_DONE` (16) |
| caps | none |

Procmgr replies `SUCCESS` then arms the state machine, or `INVALID_ARGUMENT`
when no teardown is pending or the state machine is already armed. Init proceeds
to `sys_thread_exit` immediately (per
[services/init/docs/bootstrap.md](../../init/docs/bootstrap.md#handover) § Handover).
Each death-EQ event with
`INIT_REAP_CORRELATOR` (reserved `u32::MAX`) calls
[`init_reap::run_reap`](../src/init_reap.rs), which counts the death (also one
observed before `INIT_TEARDOWN_DONE` arms the reap) and, on the second, executes
the six-step teardown (Threads → AddressSpace → DONATE_MEMORY_CAPS → drop procmgr's CSpace
reference → log).
init-logd normally exits last, once real-logd's `HANDOVER_RELEASE` releases it;
procmgr never force-stops it. If the handover never completes, init-logd serves on
and init's caps stay held until shutdown — a benign hold, not a wedge (see the
[logd handover protocol](../../logd/docs/handover-protocol.md) § Failure modes).
The system-scope reap model is in
[docs/process-lifecycle.md](../../../docs/process-lifecycle.md) § Init reap.

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
[`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)
