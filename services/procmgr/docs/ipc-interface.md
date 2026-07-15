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

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message label
field identifies the operation. Data words and capability slots carry arguments;
the reply carries results.

### Label 1: `CREATE_PROCESS`

Create a new process from a raw ELF module. The process is created in a
**suspended** state — the thread is not started. The caller receives the
child's `CSpace` capability and `ProcessInfo` memory capability so it can
inject initial capabilities and write `CapDescriptor` / startup message data
before starting the process via `START_PROCESS`.

**Request:**

| Field | Value |
|---|---|
| label | 1 |
| cap[0] | Memory capability for the ELF module image |

The caller transfers a Memory cap covering the raw ELF bytes. procmgr maps
the memory cap, parses the ELF, creates an address space, CSpace, and thread,
maps LOAD segments, and populates the `ProcessInfo` handover page with
identity caps. The thread is **not** started.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| cap[0] | Process handle (badged endpoint identifying this process) |
| cap[1] | Child `CSpace` capability (full rights) |
| cap[2] | `ProcessInfo` memory capability (MAP\|WRITE rights) |
| cap[3] | Child `Thread` capability (Control right) |

The process handle is a badged endpoint capability. The caller uses it
to send `START_PROCESS` (and future per-process operations) — the badge
identifies the process without a forgeable PID. The `CSpace` cap allows
the caller to inject capabilities into the child's capability space via
`cap_copy`. The `ProcessInfo` memory cap allows the caller to map the page
writable and patch `initial_caps_base`, `initial_caps_count`,
`cap_descriptor_count`, `cap_descriptors_offset`, and startup message
fields. The `Thread` cap allows the caller to bind death notifications or
stop/configure the thread.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |
| data[0] | 0 |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `InvalidElf` | ELF validation failed (bad magic, wrong arch, corrupt headers) |
| 2 | `OutOfMemory` | Insufficient memory caps to allocate stack, ProcessInfo page, or IPC buffer |
| 3 | `CSpaceFull` | Cannot allocate kernel objects (address space, CSpace, thread) |

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
completed any capability injection and `ProcessInfo` patching before
calling this operation.

The call is sent to the **process handle** (badged endpoint) returned by
`CREATE_PROCESS`, not to the main procmgr endpoint. The badge identifies
which process to start.

**Request:**

| Field | Value |
|---|---|
| endpoint | Process handle (badged endpoint from `CREATE_PROCESS` reply cap[0]) |
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
| 4 | `InvalidBadge` | No process with the given badge exists |
| 5 | `AlreadyStarted` | Process was already started |

### Label 3: `EXIT_PROCESS`

Deferred. Not implemented.

### Label 4: `QUERY_PROCESS`

Deferred. Not implemented.

### Label 5: reserved

Memory-cap allocation is owned by memmgr, not procmgr. See
[`services/memmgr/docs/ipc-interface.md`](../../memmgr/docs/ipc-interface.md)
for `REQUEST_MEMORY_CAPS` and related labels.

### Label 6: `CREATE_PROCESS_FROM_VFS`

Create a new process by loading an ELF binary from the virtual filesystem.
Requires that a vfsd endpoint has been configured via `SET_VFSD_ENDPOINT`.
The process is created in a **suspended** state, identical to `CREATE_PROCESS`.

**Request:**

| Field | Value |
|---|---|
| label | `6 \| (path_len << 16)` |
| data[0..] | File path bytes packed into u64 words (up to 48 bytes) |

procmgr opens the file via vfsd, reads the ELF binary into an internal
buffer, parses and loads it using the same pipeline as `CREATE_PROCESS`,
then returns a suspended process.

**Reply (success):**

Same as `CREATE_PROCESS`:

| Field | Value |
|---|---|
| label | 0 (success) |
| cap[0] | Process handle (badged endpoint) |
| cap[1] | Child `CSpace` capability (full rights) |
| cap[2] | `ProcessInfo` memory capability (MAP\|WRITE rights) |
| cap[3] | Child `Thread` capability (Control right) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `InvalidElf` | ELF validation failed |
| 2 | `OutOfMemory` | Insufficient memory caps |
| 3 | `CSpaceFull` | Cannot allocate kernel objects |
| 8 | `NoVfsEndpoint` | No vfsd endpoint configured |
| 9 | `FileNotFound` | vfsd OPEN failed for the given path |
| 10 | `IoError` | vfsd READ or STAT failed |

### Label 7: `SET_VFSD_ENDPOINT`

Configure the vfsd Send endpoint for VFS-based process creation. Init sends
this after vfsd is running and the root filesystem is mounted. One-time
configuration; subsequent calls overwrite the stored endpoint.

**Request:**

| Field | Value |
|---|---|
| label | 7 |
| cap[0] | vfsd Send endpoint capability |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |

---

## Capability Transfer

Capability transfer uses the IPC message's cap slot array (up to 4 caps per
message). On `CREATE_PROCESS`, the caller's Memory cap is moved into procmgr's
CSpace atomically with the message delivery. procmgr consumes the cap during
process creation and does not return it.

On reply, procmgr transfers a badged process handle endpoint (for
subsequent per-process operations) and derived copies of the child's
`CSpace`, `ProcessInfo` memory cap, and `Thread` capabilities to the caller.
procmgr retains the original caps for process lifecycle management.

---

## REGISTER_DEATH_EQ — install logd's death observer

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_DEATH_EQ` (14) |
| caller's cap badge | MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY` (`1 << 62`); init mints this badged SEND cap and gives it exclusively to real-logd at bootstrap |
| `caps[0]` | `EventQueue` cap with `POST` right; procmgr binds it as a second death observer on every supervised thread |

Procmgr stores the cap in
[`process::LOGD_DEATH_EQ`](../src/process.rs) and immediately
walks its process table, calling
`sys_thread_bind_notification(entry.thread_cap, logd_eq,
entry.badge as u32)` on every live entry. From that moment onward,
[`finalize_creation`](../src/process.rs) also binds the same EQ on
every newly spawned child (correlator = process badge).

Reply: `procmgr_errors::SUCCESS` on bind, `UNAUTHORIZED` if the
caller lacks `DEATH_EQ_AUTHORITY`, `INVALID_ARGUMENT` if no cap was
transferred. Re-registration replaces the previous cap.

logd derives a `POST`-only copy from its `RECV+POST` event queue
before sending — the kernel's cap-transfer moves the sent cap into
procmgr's CSpace, so logd must retain `RECV` on its own copy to
keep `wait_set_add` and `event_try_recv` working.

---

## REGISTER_INIT_TEARDOWN — init reap handoff

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_INIT_TEARDOWN` (15) |
| `data[0]` | `1` on the first round (carrying kernel-object caps); `0` on subsequent donation rounds |
| `caps[0..]` | Round 1: 4 kernel-object caps (`AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`) — MOVED out of init's CSpace via IPC cap-transfer. Subsequent rounds: 1-4 reclaimable Memory caps per round (segments, stack, `InitInfo` pages, IPC buffer). |

On the first round procmgr stores the kernel-object caps and calls
`syscall::thread_bind_notification(main_thread, death_eq,
procmgr_labels::INIT_REAP_CORRELATOR)`. Subsequent rounds append to
the donation Memory cap list. `INIT_TEARDOWN_DONE` (label 16, no
caps, no data words) closes the stream and arms the state machine.

Reply: `procmgr_errors::SUCCESS` on accept, `INVALID_ARGUMENT` on
wrong round shape (wrong cap count on round 1, or `done` before any
round 1).

## INIT_TEARDOWN_DONE — end-of-stream notification

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::INIT_TEARDOWN_DONE` (16) |
| caps | none |

Procmgr replies `SUCCESS` then arms the state machine. Init proceeds
to `sys_thread_exit` immediately; the death-EQ event with
`INIT_REAP_CORRELATOR` (reserved `u32::MAX`) triggers
[`init_reap::run_reap`](../src/init_reap.rs) which executes the six-step
teardown (Threads → AddressSpace → DONATE_MEMORY_CAPS → CSpace → log).

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

[procmgr/README.md](../README.md)
