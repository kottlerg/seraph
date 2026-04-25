# svcmgr IPC Interface

IPC interface specification for svcmgr: service registration, handover
protocol, and status queries.

---

## Endpoint

svcmgr listens on a single IPC endpoint (the svcmgr service endpoint). Init
holds the Send-side capability and uses it to register services during
bootstrap. svcmgr holds the Receive-side capability and multiplexes it with
death notification EventQueues via a WaitSet.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message label
field identifies the operation.

### Label 1: `REGISTER_SERVICE`

Register a service for health monitoring and (optionally) automatic restart.
Init sends one `REGISTER_SERVICE` per top-level service during bootstrap.

Drivers spawned by devmgr and filesystem processes spawned by vfsd are NOT
registered with svcmgr — their respective parents supervise them.

**Request:**

| Field | Value |
|---|---|
| label | `1 \| (name_len << 16)` |
| data[0] | Restart policy: 0 = Always, 1 = OnFailure, 2 = Never |
| data[1] | Criticality: 0 = Fatal, 1 = Normal |
| data[2..] | Service name bytes packed into u64 words (up to 32 bytes) |
| cap[0] | Thread capability (Control right) for death notification binding |
| cap[1] | Module Frame capability for restart (0 if VFS-loaded or no restart) |
| cap[2] | Log endpoint Send capability (for restart cap injection) |

The Thread cap is used to bind a death notification EventQueue. The module
cap and log endpoint are stored as the service's restart recipe — svcmgr
replays them on restart.

For Fatal-criticality services, cap[1] and cap[2] may be omitted (no restart
recipe needed).

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
| 1 | `TableFull` | Service table is full (max 16 entries) |
| 2 | `InvalidName` | Name length is 0 or exceeds 32 bytes |

### Label 2: `HANDOVER_COMPLETE`

Signals that init has finished registering all services and is about to exit.
svcmgr transitions from registration phase to monitoring phase.

**Request:**

| Field | Value |
|---|---|
| label | 2 |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |

After this message, svcmgr enters its monitor loop and no longer accepts
new registrations (future: dynamic registration may be added).

### Label 3: `QUERY_STATUS`

Deferred. Not implemented.

---

## Death Notification

For each registered service, svcmgr:

1. Creates an EventQueue capability (`SYS_CAP_CREATE_EVENT_Q`, capacity 4).
2. Binds the EventQueue to the service's thread via
   `SYS_THREAD_BIND_NOTIFICATION(thread_cap, eventq_cap)`.
3. Adds the EventQueue to a WaitSet with a token encoding the service index.

When a thread exits (clean or fault), the kernel posts `exit_reason` to the
bound EventQueue:

- `0` = clean exit (`SYS_THREAD_EXIT`)
- `1–255` = fault (exception vector + 1 on x86-64, scause + 1 on RISC-V)

svcmgr's WaitSet wakes, identifies the service, and applies restart policy.

---

## Restart Policy

| Policy | Behavior |
|--------|----------|
| Always (0) | Restart unconditionally on any exit |
| OnFailure (1) | Restart only if exit_reason is nonzero (fault) |
| Never (2) | Do not restart; log only |

Restart attempts are counted per service. After 5 consecutive restarts, the
service is marked **degraded** and not restarted automatically.

---

## Criticality

| Level | Behavior on crash |
|-------|------------------|
| Fatal (0) | Log the crash, halt the system (graceful shutdown deferred) |
| Normal (1) | Apply restart policy |

Fatal services include procmgr, devmgr, and vfsd. Their crash indicates a
system-level failure that cannot be recovered by simple restart.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC message format, EventQueue semantics |
| [docs/capability-model.md](../../docs/capability-model.md) | Thread cap rights, EventQueue cap rights |
| [restart-protocol.md](restart-protocol.md) | Restart sequencing and cap re-delegation |

---

## Summarized By

[svcmgr/README.md](../README.md)
