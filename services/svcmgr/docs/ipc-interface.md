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

A SEND on the same endpoint (carrying neither the
[`PUBLISH_AUTHORITY`](#publish-authority) nor the
[`HANDOVER_AUTHORITY`](#label-2-handover_complete) verb bit) is delivered to
every process via
[`ProcessInfo.service_registry_cap`](../../../abi/process-abi/README.md#processinfo)
so userspace consumers can
`QUERY_ENDPOINT` for the public published names.

---

## Handover endowment (bootstrap rounds)

svcmgr's entire startup state arrives over init's bootstrap-round
protocol (the same mechanism that delivers every service's startup caps),
not a dedicated registration label. init serves the rounds on its
bootstrap endpoint; svcmgr drains them in
[`service::bootstrap_caps`](../src/service.rs). Each round is tagged by
kind in `data[0]`. The kernel refuses a message carrying a null cap slot,
so a source cap init could not provide is not sent as `0`: the `CAPS` and
`LOGD_SOURCES` rounds carry only the caps present, in slot order, and a
presence word sets bit `i` when optional slot `i` is present. A round whose
presence word names a bit with no slot, or a different number of caps than
the round delivered, is malformed. The round kinds and this encoding are
the [`svcmgr-endowment`](../endowment/README.md) crate, which init encodes
and svcmgr decodes with.

**Round 1 — `CAPS` (`data[0] = 1`, not terminal):**

| Field | Value |
|---|---|
| caps[0] | svcmgr's service endpoint (RECV; required) |
| caps[1] | svcmgr's own bootstrap endpoint (RECV — serves launched/restarted children; required) |
| caps[2..] | the present optional slots, in slot order |
| optional slot 0 | SEND on the root filesystem's namespace endpoint (published as `rootfs.root`; absent if init could not derive it) |
| optional slot 1 | `SEND\|GRANT`, badge-0 source on devmgr's registry endpoint (absent if init holds none or its derive fails) |
| data[0] | `1` (`CAPS`) |
| data[1] | `SVCMGR_LABELS_VERSION` (currently `7`) handshake |
| data[2] | presence word: bit 0 `ROOTFS_ROOT`, bit 1 `DEVMGR_REGISTRY` |

svcmgr mints the `devmgr.registry` publish cap
(`REGISTRY_QUERY_AUTHORITY`), the `devmgr.shutdown` and `devmgr.test`
publish caps (`REGISTRY_QUERY_AUTHORITY` plus `SHUTDOWN_DEVICE_AUTHORITY`
or `TEST_LABEL_AUTHORITY`), and the `SET_DRIVERS_DIR` cap
(`DRIVERS_DIR_AUTHORITY`) from the devmgr-registry source. A version
mismatch in `data[1]`, or a malformed `CAPS` round, aborts bootstrap
(svcmgr exits).

**Rounds 2..N — `SUBSTRATE` (`data[0] = 2`, not terminal):**
one per init-bootstrapped substrate service (memmgr, procmgr, devmgr,
vfsd) whose thread cap init captured; logd is not a substrate. See init's
[Handover](../../init/docs/bootstrap.md#handover) stage.

| Field | Value |
|---|---|
| caps[0] | the service's main thread cap (Control right) for death-notification binding |
| data[0] | `2` (`SUBSTRATE`) |
| data[1] | `name_len` (byte length of the service name) |
| data[2..] | service name bytes packed LE into `u64` words (≤ 32 bytes) |

**Final round — `LOGD_SOURCES` (`data[0] = 3`, terminal):**

| Field | Value |
|---|---|
| caps[..] | the present slots, in slot order |
| slot 0 | `master_log_source`: `RIGHTS_ALL` source on init's master log endpoint; svcmgr mints real-logd's master-log RECV from it on every (re)launch and the first-launch handover SEND (the `HANDOVER_PULL` drain then `HANDOVER_RELEASE`; see [`log_sink`](service-definitions.md#log_sink)); holding it keeps the log endpoint alive across a logd crash (absent if its derive fails) |
| slot 1 | `procmgr_death_auth_source`: badge-0 `SEND\|GRANT` source on procmgr's service endpoint; svcmgr mints real-logd's `DEATH_EQ_AUTHORITY` `SEND\|GRANT` cap from it per launch (absent if its derive fails) |
| data[0] | `3` (`LOGD_SOURCES`) |
| data[1] | presence word: bit 0 `MASTER_LOG`, bit 1 `PROCMGR_DEATH_AUTH` |

After a failed `CAPS` round init ends the endowment with an empty
`LOGD_SOURCES` round (no caps, presence `0`), so svcmgr leaves its round
loop and exits. svcmgr logs a malformed `LOGD_SOURCES` round, deletes the
caps it delivered, and continues with both sources absent.

svcmgr holds both sources for the system's life and mints real-logd's
[`log_sink`](service-definitions.md#log_sink) bootstrap round from them on
every (re)launch. An absent source leaves the matching slot of logd's round
absent, which the round's presence word records (see
[`seed`](service-definitions.md#seed)); logd runs without that slot's cap, or,
for the master-log source, exits at startup.

svcmgr parks each substrate pair in its pending-registration table. It does **not**
bind death-notification at endowment time — the matching `.svc`
definition is paired at reconciliation, on
[`HANDOVER_COMPLETE`](#label-2-handover_complete). After draining the
endowment svcmgr publishes the well-known names it owns (`rootfs.root`,
`svcmgr`, `devmgr.registry`, `devmgr.shutdown`, `devmgr.test`) into its own
registry and installs devmgr's
`/services/drivers/` cap via `SET_DRIVERS_DIR`, before entering the event
loop.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message
label field identifies the operation.

### Label 2: `HANDOVER_COMPLETE`

Notifications that init has finished serving the handover endowment.
svcmgr honours it once, and only from a caller whose badge carries the
`svcmgr_labels::HANDOVER_AUTHORITY` verb-bit (bit 62): init derives a
SEND with that badge for the call and deletes it after. Only svcmgr and
its trusted minters hold an unbadged SEND on the endpoint (init, and
procmgr's per-child source), and every other SEND is already badged without the
bit: devmgr's with `PUBLISH_AUTHORITY`, the published `svcmgr` name's with
`svcmgr_labels::PUBLISHED_SEND_BADGE`, and each per-process
`service_registry_cap` with a process badge procmgr keeps clear of verb
bits (see [Capability Model](../../../docs/capability-model.md#verb-bit-authority-pattern)).
Any other caller, and any repeat, gets `UNAUTHORIZED` and triggers
nothing. The decision is `svcmgr_defs::handover_permitted`. On the
honoured call svcmgr replies `SUCCESS` immediately (so init can proceed
to teardown), then runs
[`definitions::reconcile::reconcile_and_launch`](../src/definitions/reconcile.rs):

1. Scan `/config/svcmgr/services/`, parse each `.svc` into a
   [`Definition`](../src/definitions/mod.rs).
2. Reconcile against the pending-registration table (the substrate pairs
   parked from the endowment):
   * **parked AND defined** — bind death-notification, record the
     recipe's fixed fields on the `ServiceEntry` and its argv/env/cwd/seed,
     log-sink flag, and scheduling fields in the parallel `RestartRecipe`
     table.
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
| badge | MUST carry `HANDOVER_AUTHORITY`; rejected with `UNAUTHORIZED` otherwise. |

**Reply:**

| label value | Meaning |
|---|---|
| `0` (`SUCCESS`) | Handover accepted; reconciliation runs after the reply. |
| `UNAUTHORIZED` | Caller's badge lacks `HANDOVER_AUTHORITY`, or the handover already ran. |

### Label 3: `PUBLISH_ENDPOINT`

Insert a `name → cap` mapping into svcmgr's discovery registry. The name is
public: svcmgr cannot read the delivered cap's badge, so any
[`QUERY_ENDPOINT`](#label-4-query_endpoint) caller resolves it, and a
publisher MUST NOT publish a verb-bit cap through this label.

**Request:**

| Field | Value |
|---|---|
| label | `3 \| (name_len << 16)` |
| words 0.. | `name` bytes |
| caps[0] | The endpoint the name resolves to (transferred to svcmgr). |
| badge | MUST carry [`PUBLISH_AUTHORITY`](#publish-authority); rejected with `UNAUTHORIZED` otherwise. |

**Reply:**

| label value | Meaning |
|---|---|
| `0` (`SUCCESS`) | Stored |
| `UNAUTHORIZED` | Caller's badge lacks `PUBLISH_AUTHORITY` |
| `INVALID_NAME` | `name_len` is 0 or exceeds `registry::NAME_MAX` |
| `INSUFFICIENT_CAPS` | `caps[0]` missing or zero |
| `REGISTER_REJECTED` | Registry is full or name already registered |

### Label 4: `QUERY_ENDPOINT`

Look up a name in the discovery registry; reply transfers a
freshly-derived `RIGHTS_EP_SEND` cap on the published endpoint.

Only public names resolve. A name whose cap carries authority is published
seed-only and answers `UNKNOWN_NAME`, as an unknown name does: `rootfs.root`,
the three `devmgr.*` names, and each provider name whose badge carries a verb
bit (`ipc::VERB_BIT_MASK`; the `:auth` entries, today `pwrmgr.shutdown`). A
seed-only name reaches a process only through a recipe's `seed = ...` line,
which svcmgr resolves itself, so its authority stays with the recipes that
seed it ([service-definitions.md § `seed`](service-definitions.md#seed)). The
public names are `svcmgr`, `pwrmgr.deny`, `timed`, and any name published
through [`PUBLISH_ENDPOINT`](#label-3-publish_endpoint).

**Request:**

| Field | Value |
|---|---|
| label | `4 \| (name_len << 16)` |
| words 0.. | `name` bytes |

**Reply:**

| label value | Caps | Meaning |
|---|---|---|
| `0` (`SUCCESS`) | `[derived_send]` | Name resolved; cap transferred |
| `UNKNOWN_NAME` | — | No mapping for `name`, or `name` is seed-only |
| `INSUFFICIENT_CAPS` | — | Stored cap could not be derived (publisher gone); entry evicted |
| `INVALID_NAME` | — | `name_len` is 0 or exceeds `registry::NAME_MAX` |

---

## Publish authority

`svcmgr_labels::PUBLISH_AUTHORITY` is a verb-bit (the top bit of the
caller's cap badge) gating `PUBLISH_ENDPOINT` for *external* publishers.
svcmgr publishes the well-known names it owns (`rootfs.root`, `svcmgr`,
the three `devmgr.*` names, and each provider's `provides` names) directly into
its own registry, so those need no badge. The gate exists for a future
external publisher — devmgr holds a `PUBLISH_AUTHORITY`-badged SEND from
its bootstrap bundle, reserved for driver registrations. The SEND
distributed to every process via `ProcessInfo.service_registry_cap`
carries a per-process badge *without* the bit, so it is accepted for
`QUERY_ENDPOINT` only.

Cap derivation for an external publish cap MUST use `RIGHTS_EP_SEND_GRANT`,
not `RIGHTS_EP_SEND`: `PUBLISH_ENDPOINT` carries the value cap in the
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
WaitSet has two members: the service endpoint (badge 0) and the
deaths queue (badge 1).

When a thread exits (clean or fault), the kernel posts
`(correlator << 32) | exit_reason` to `deaths_eq` (see
[restart-protocol.md](restart-protocol.md#death-detection)). svcmgr drains the
queue and routes each payload to its `ServiceEntry` via the
correlator, then dispatches through
[`restart::handle_death`](../src/restart.rs).

Exit reason encoding:

| Value | Meaning |
|---|---|
| `0` | clean exit (`SYS_THREAD_EXIT`) |
| `1..=0x0FFF` | voluntary exit code |
| `0x1000..=0x1FFF` (`EXIT_FAULT_BASE + vector`) | fault (exception vector / scause + base) |
| `0x2000` (`EXIT_KILLED`) | killed |

The full space is defined in
[process-lifecycle.md](../../../docs/process-lifecycle.md#exit-reason).

---

## Restart policy

See [service-definitions.md](service-definitions.md#restart) for the
`.svc` representation. svcmgr's in-memory shape:

| Policy | Behaviour |
|---|---|
| `POLICY_NEVER` | Never restart |
| `POLICY_ON_FAILURE` | Restart only when `exit_reason >= EXIT_FAULT_BASE` |
| `POLICY_ALWAYS` | Restart on every exit |

Restarts are counted per service over its lifetime (no window, no
reset). Once `MAX_RESTARTS` restarts have run, the service's next death
leaves it permanently down — degraded, or a graceful shutdown for
`critical = yes` — see
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

[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[services/init/README.md](../../init/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md),
[services/svcmgr/endowment/README.md](../endowment/README.md),
[services/svcmgr/README.md](../README.md),
[services/svctest/README.md](../../svctest/README.md),
[shared/registry/README.md](../../../shared/registry/README.md),
[shared/registry-client/README.md](../../../shared/registry-client/README.md)
