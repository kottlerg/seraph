# svcmgr IPC Interface

IPC interface specification for svcmgr: the init handover endowment,
handover-driven reconciliation, and the discovery-registry publish /
query surface.

---

## Endpoint

svcmgr listens on a single IPC endpoint (the svcmgr service endpoint).
svcmgr holds the Receive-side capability (delivered in the handover
endowment) and multiplexes it with the shared death-notification
EventQueue via a WaitSet.

A SEND on the same endpoint (without the [`PUBLISH_AUTHORITY`](#publish-authority)
verb bit) is delivered to every process via
`ProcessInfo.service_registry_cap` so userspace consumers can
`QUERY_ENDPOINT` for published names.

---

## Handover endowment (bootstrap rounds)

svcmgr's entire startup state arrives over init's bootstrap-round
protocol (the same mechanism that delivers every service's startup caps),
not a dedicated registration label. init serves the rounds on its
bootstrap endpoint; svcmgr drains them in
[`service::bootstrap_caps`](../src/service.rs). Each round is tagged by
kind in `data[0]`:

**Round 1 — `CAPS` (`data[0] = 1`, not terminal):**

| Field | Value |
|---|---|
| caps[0] | svcmgr's service endpoint (RECV) |
| caps[1] | svcmgr's own bootstrap endpoint (RECV — serves launched/restarted children) |
| caps[2] | SEND on the root filesystem's namespace endpoint (published as `rootfs.root`; `0` if init could not derive it) |
| caps[3] | `SEND\|GRANT`, token-0 source on devmgr's registry endpoint (`0` if absent) |
| data[0] | `1` (`CAPS`) |
| data[1] | `SVCMGR_LABELS_VERSION` (currently `4`) handshake |

svcmgr mints the `devmgr.registry` publish cap
(`REGISTRY_QUERY_AUTHORITY`) and the `SET_DRIVERS_DIR` cap
(`DRIVERS_DIR_AUTHORITY`) from caps[3]. A version mismatch in `data[1]`
aborts bootstrap (svcmgr exits).

**Rounds 2..N — `SUBSTRATE` (`data[0] = 2`; the final round is terminal):**
one per init-bootstrapped substrate service (memmgr, procmgr, devmgr,
vfsd, logd).

| Field | Value |
|---|---|
| caps[0] | the service's main thread cap (Control right) for death-notification binding |
| data[0] | `2` (`SUBSTRATE`) |
| data[1] | `name_len` (byte length of the service name) |
| data[2..] | service name bytes packed LE into `u64` words (≤ 32 bytes) |

svcmgr parks each pair in its pending-registration table. It does **not**
bind death-notification at endowment time — the matching `.svc`
definition is paired at reconciliation, on
[`HANDOVER_COMPLETE`](#label-2-handover_complete). After draining the
endowment svcmgr publishes the well-known names it owns (`rootfs.root`,
`svcmgr`, `devmgr.registry`) into its own registry and installs devmgr's
`/services/drivers/` cap via `SET_DRIVERS_DIR`, before entering the event
loop.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message
label field identifies the operation.

### Label 2: `HANDOVER_COMPLETE`

Signals that init has finished serving the handover endowment. svcmgr
replies `SUCCESS` immediately (so init can proceed to teardown), then runs
[`definitions::reconcile::reconcile_and_launch`](../src/definitions/reconcile.rs):

1. Scan `/config/svcmgr/services/`, parse each `.svc` into a
   [`Definition`](../src/definitions/mod.rs).
2. Reconcile against the pending-registration table (the substrate pairs
   parked from the endowment):
   * **parked AND defined** — bind death-notification, record a
     `ServiceEntry` with the parsed recipe.
   * **defined only** — launch via [`definitions::launch`](../src/definitions/launch.rs).
   * **parked without definition** — log `registered without
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
caller's cap token) gating `PUBLISH_ENDPOINT` for *external* publishers.
svcmgr publishes the well-known names it owns (`rootfs.root`, `svcmgr`,
`devmgr.registry`, and each provider's `provides` names) directly into
its own registry, so those need no token. The gate exists for a future
external publisher — devmgr holds a `PUBLISH_AUTHORITY`-tokened SEND from
its bootstrap bundle, reserved for driver registrations. The SEND
distributed to every process via `ProcessInfo.service_registry_cap`
carries a per-process token *without* the bit, so it is accepted for
`QUERY_ENDPOINT` only.

Cap derivation for an external publish cap MUST use `RIGHTS_SEND_GRANT`,
not `RIGHTS_SEND`: `PUBLISH_ENDPOINT` carries the value cap in the
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
`.svc` representation. svcmgr's in-memory shape is a single
`ServiceEntry.system_critical: bool`, consulted only once a service is
permanently down (restart is decided independently by the restart
policy + budget):

| `system_critical` | Behaviour once permanently down |
|---|---|
| `false` (`critical = no`) | Logged; service marked inactive; system continues degraded |
| `true` (`critical = yes`) | Initiate graceful shutdown via `published_names::PWRMGR_SHUTDOWN` |

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
