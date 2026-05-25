# svcmgr IPC Interface

IPC interface specification for svcmgr: service registration (v3 wire),
handover-driven reconciliation, and the discovery-registry publish /
query surface.

---

## Endpoint

svcmgr listens on a single IPC endpoint (the svcmgr service endpoint).
Init holds the Send-side capability and uses it to register currently-
running services and publish well-known caps during bootstrap. svcmgr
holds the Receive-side capability and multiplexes it with the shared
death-notification EventQueue via a WaitSet.

A SEND on the same endpoint (without the [`PUBLISH_AUTHORITY`](#publish-authority)
verb bit) is delivered to every process via
`ProcessInfo.service_registry_cap` so userspace consumers can
`QUERY_ENDPOINT` for published names.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message
label field identifies the operation.

### Label 1: `REGISTER_SERVICE` (v3)

Register a currently-running service for supervision.

Post-#21 the recipe (binary, argv, env, restart policy, criticality,
namespace shape, seed names) lives on disk at
`/config/svcmgr/services/<name>.svc`. This message conveys only what
cannot be on disk: which named recipe the running process implements,
and the thread cap svcmgr binds death-notification on at
reconciliation time.

**Request:**

| Field | Value |
|---|---|
| label | `1` |
| word 0 | `SVCMGR_LABELS_VERSION` (currently `3`) handshake |
| word 1 | `name_len` (byte length of the service name) |
| words 2.. | service name bytes packed into `u64` words (up to 32 bytes) |
| caps[0] | Thread capability (Control right) for death-notification binding |

**Reply:**

| label value | Meaning |
|---|---|
| `0` (`SUCCESS`) | Entry parked in svcmgr's pending-registration table |
| `LABEL_VERSION_MISMATCH` | `word 0` does not equal svcmgr's `SVCMGR_LABELS_VERSION` |
| `INVALID_NAME` | `name_len` is 0 or exceeds 32 |
| `TABLE_FULL` | Pending table is full |
| `INSUFFICIENT_CAPS` | `caps[0]` missing or zero |

At register time svcmgr does **not** bind death-notification — the
matching `.svc` definition may not yet exist; reconciliation happens
on [`HANDOVER_COMPLETE`](#label-2-handover_complete).

### Label 2: `HANDOVER_COMPLETE`

Signals that init has finished registering services and publishing
well-known caps. svcmgr replies `SUCCESS` immediately (so init can
proceed to teardown), then runs
[`definitions::reconcile::reconcile_and_launch`](../src/definitions/reconcile.rs):

1. Scan `/config/svcmgr/services/`, parse each `.svc` into a
   [`Definition`](../src/definitions/mod.rs).
2. Reconcile against the pending-registration table:
   * **registered AND defined** — bind death-notification, record a
     `ServiceEntry` with the parsed recipe.
   * **defined only** — launch via [`definitions::launch`](../src/definitions/launch.rs).
   * **registered without definition** — log `registered without
     definition: <name>; refusing to bind`.
3. After reconciliation the supervision loop continues unchanged.

See [service-definitions.md](service-definitions.md) for the
authoritative reconciliation table.

**Request:**

| Field | Value |
|---|---|
| label | `2` |

**Reply:**

| label value | Meaning |
|---|---|
| `0` (`SUCCESS`) | Always returned — reconciliation runs after the reply. |

### Label 3: `PUBLISH_ENDPOINT`

Insert a `name → cap` mapping into svcmgr's discovery registry.

**Request:**

| Field | Value |
|---|---|
| label | `3 \| (name_len << 16)` |
| words 0.. | `name` bytes |
| caps[0] | The endpoint the name resolves to (transferred to svcmgr). |
| token | MUST carry [`PUBLISH_AUTHORITY`](#publish-authority); rejected with `UNAUTHORIZED` otherwise. |

**Reply:**

| label value | Meaning |
|---|---|
| `0` (`SUCCESS`) | Stored |
| `UNAUTHORIZED` | Caller's token lacks `PUBLISH_AUTHORITY` |
| `INVALID_NAME` | `name_len` is 0 or exceeds `registry::NAME_MAX` |
| `INSUFFICIENT_CAPS` | `caps[0]` missing or zero |
| `REGISTER_REJECTED` | Registry is full or name already registered |

### Label 4: `QUERY_ENDPOINT`

Look up a name in the discovery registry; reply transfers a
freshly-derived `RIGHTS_SEND` cap on the published endpoint.

**Request:**

| Field | Value |
|---|---|
| label | `4 \| (name_len << 16)` |
| words 0.. | `name` bytes |

**Reply:**

| label value | Caps | Meaning |
|---|---|---|
| `0` (`SUCCESS`) | `[derived_send]` | Name resolved; cap transferred |
| `UNKNOWN_NAME` | — | No mapping for `name` |
| `INSUFFICIENT_CAPS` | — | Stored cap could not be derived (publisher gone); entry evicted |
| `INVALID_NAME` | — | `name_len` is 0 or exceeds `registry::NAME_MAX` |

---

## Publish authority

`svcmgr_labels::PUBLISH_AUTHORITY` is a verb-bit (the top bit of the
caller's cap token) gating `PUBLISH_ENDPOINT`. Init mints
`PUBLISH_AUTHORITY`-tokened SENDs on svcmgr's service endpoint locally
from the un-tokened source it owns; the SEND distributed to every
process via `ProcessInfo.service_registry_cap` carries a per-process
token *without* the bit, so it is accepted for `QUERY_ENDPOINT` only.

Cap derivation for the publish cap MUST use `RIGHTS_SEND_GRANT`, not
`RIGHTS_SEND`: `PUBLISH_ENDPOINT` carries the value cap in the
message body, and the IPC kernel requires the GRANT bit on the
caller's send-cap to transfer caps.

See [`docs/capability-model.md`](../../../docs/capability-model.md)
"verb-bit authority pattern" for the rationale and parallel use in
`pwrmgr_labels::SHUTDOWN_AUTHORITY`.

---

## Death notification

svcmgr maintains one shared EventQueue (`deaths_eq`). At
reconciliation time, every supervised service has its main thread
bound to `deaths_eq` with `correlator = service_table_index`. The
WaitSet has two members: the service endpoint (token 0) and the
deaths queue (token 1).

When a thread exits (clean or fault), the kernel posts
`(correlator << 32) | exit_reason` to `deaths_eq`. svcmgr drains the
queue and routes each payload to its `ServiceEntry` via the
correlator, then dispatches through
[`restart::handle_death`](../src/restart.rs).

Exit reason encoding:

| Value | Meaning |
|---|---|
| `0` | clean exit (`SYS_THREAD_EXIT`) |
| `EXIT_FAULT_BASE..` | fault (exception vector / scause + base) |

---

## Restart policy

See [service-definitions.md](service-definitions.md#restart) for the
`.svc` representation. svcmgr's in-memory shape:

| Policy | Behaviour |
|---|---|
| `POLICY_NEVER` | Never restart |
| `POLICY_ON_FAILURE` | Restart only when `exit_reason >= EXIT_FAULT_BASE` |
| `POLICY_ALWAYS` | Restart on every exit |

Restart attempts are counted per service. After `MAX_RESTARTS`
consecutive restarts the service is marked degraded and not
restarted automatically — see
[restart-protocol.md](restart-protocol.md).

---

## Criticality

See [service-definitions.md](service-definitions.md#critical) for the
`.svc` representation. svcmgr's in-memory shape:

| Level | Behaviour on death |
|---|---|
| `CRITICALITY_LOW` | Logged; service marked inactive |
| `CRITICALITY_NORMAL` | Apply restart policy; degrade on budget exhaustion |
| `CRITICALITY_HIGH` | Apply restart policy; on unrecoverable death, initiate graceful shutdown via `published_names::PWRMGR_SHUTDOWN` |

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC message format, EventQueue semantics |
| [docs/capability-model.md](../../../docs/capability-model.md) | Verb-bit authority, cap rights |
| [service-definitions.md](service-definitions.md) | `.svc` recipe format and reconciliation |
| [restart-protocol.md](restart-protocol.md) | Restart sequencing, shared spawn primitives |

---

## Summarized By

[svcmgr/README.md](../README.md)
