# svcmgr IPC Interface

IPC interface specification for svcmgr: the init handover endowment,
handover-driven reconciliation, the discovery-registry publish /
query surface, and the stop authority's stop and list.

---

## Endpoint

svcmgr listens on a single IPC endpoint (the svcmgr service endpoint).
svcmgr holds the Receive-side capability (delivered in the handover
endowment) and multiplexes it with the death-notification EventQueues
via a WaitSet.

A SEND on the same endpoint (carrying none of the
[`PUBLISH_AUTHORITY`](#publish-authority),
[`HANDOVER_AUTHORITY`](#label-2-handover_complete) and
[`STOP_AUTHORITY`](#stop-authority) verb bits) is delivered to
every process via
[`ProcessInfo.service_registry_cap`](../../../abi/process-abi/README.md#processinfo)
so userspace consumers can
`QUERY_ENDPOINT` for the public published names. Besides devmgr's `PUBLISH_AUTHORITY` SEND, only the
seeds of `svcmgr.grant` hold a `SEND|GRANT` on the endpoint.

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
presence word sets bit `i` when slot `i` is present. A round whose
presence word names a bit with no slot, or a different number of caps than
the round delivered, is malformed. The round kinds and this encoding are
the [`svcmgr-endowment`](../endowment/README.md) crate, which init encodes
and svcmgr decodes with.

**First rounds — `CAPS` (`data[0] = 1`, not terminal):** a positional
slot list, split into windows of `MSG_CAP_SLOTS_MAX` slots, one `CAPS`
round per window (`ipc::bootstrap::slot_rounds`); the nine slots below
take three rounds (slots 0-3, 4-7, then 8), and a longer list takes more with
no change to the encoding.

| Field | Value |
|---|---|
| slot 0 | svcmgr's service endpoint (RECV; required) |
| slot 1 | svcmgr's own bootstrap endpoint (RECV — serves launched/restarted children; required) |
| slot 2 | SEND on vfsd's synthetic root (the namespace root, which crosses mounts; [namespace-composition.md](../../vfsd/docs/namespace-composition.md)), derived from init's system-root cap (published as `rootfs.root`; absent if init could not derive it) |
| slot 3 | `SEND\|GRANT`, badge-0 source on devmgr's registry endpoint (absent if init holds none or its derive fails) |
| slot 4 | `vfsd_labels::MOUNT_AUTHORITY`-badged SEND on vfsd's service endpoint (published seed-only as `vfsd.mount`; absent if its derive fails) |
| slot 5 | `vfsd_labels::DENY_BADGE`-badged SEND on vfsd's service endpoint (published seed-only as `vfsd.deny`; absent if its derive fails) |
| slot 6 | `vfsd_labels::SWAP_AUTHORITY`-badged SEND on vfsd's service endpoint (published seed-only as `vfsd.swap`; absent if its derive fails) |
| slot 7 | `EntropyControl` source carrying `Contribute`, derived from the root capability the kernel mints into init; svcmgr never publishes it, and derives the [`entropy_authority`](service-definitions.md#entropy_authority) service's copy from it on every launch (absent if init holds none or its derive fails) |
| slot 8 | `memmgr_labels::SWAP_AUTHORITY`-badged `SEND\|GRANT` on memmgr's endpoint (published seed-only, its seeds keeping `GRANT`, as `memmgr.swap`; absent if its derive fails) |
| caps[..] | the present slots of the round's window, in slot order |
| data[0] | `1` (`CAPS`) |
| data[1] | `SVCMGR_LABELS_VERSION` (currently `17`) handshake, in every `CAPS` round |
| data[2] | presence word, relative to the round's window: bit `i` is set when window slot `i` is present |
| data[3] | rounds left: the number of `CAPS` rounds after this one (`0` on the last) |

svcmgr mints the `devmgr.registry` publish cap
(`REGISTRY_QUERY_AUTHORITY`), the `devmgr.shutdown`, `devmgr.bind` and `devmgr.acpi` publish caps
(`REGISTRY_QUERY_AUTHORITY` plus `SHUTDOWN_DEVICE_AUTHORITY`, `BIND_AUTHORITY` or
`ACPI_AUTHORITY`), the
`MINT_CLASS_SEND` cap (`CLASS_AUTHORITY`) with which it configures devmgr's device classes
([service-definitions.md § Device class files](service-definitions.md#device-class-files)), and
the `SET_DRIVERS_DIR` cap (`DRIVERS_DIR_AUTHORITY`) from the devmgr-registry source, and publishes
the three vfsd SENDs as they arrive (their badges ride through to the
seeding recipe unchanged). A version
mismatch in `data[1]`, or a malformed `CAPS` round (including one past the
rounds the list takes, one whose rounds-left word disagrees with them, one
that carries a slot past the list, or a last round that leaves a required
endpoint absent), aborts bootstrap (svcmgr exits).

**After the `CAPS` rounds — `SUBSTRATE` (`data[0] = 2`, not terminal):**
one per init-bootstrapped substrate service (memmgr, procmgr, devmgr,
vfsd) whose thread cap init captured; logd is not a substrate. See init's
[Handover](../../init/docs/bootstrap.md#handover) stage.

| Field | Value |
|---|---|
| caps[0] | the service's main thread cap (Control right) for death-notification binding |
| caps[1] | the observer cap, present exactly when `data[2]` is non-zero |
| data[0] | `2` (`SUBSTRATE`) |
| data[1] | `name_len` (byte length of the service name) |
| data[2] | `observer_kind`: `0` none; `1` address space (caps[1] is a Control-only `AddressSpace` cap); `2` process handle (caps[1] is the service's procmgr process handle) |
| data[3..] | service name bytes packed LE into `u64` words (`svcmgr_labels::pack_name`; at most `svcmgr_labels::NAME_MAX` = 64 bytes) |

**Final round — `LOGD_SOURCES` (`data[0] = 3`, terminal):**

| Field | Value |
|---|---|
| caps[..] | the present slots, in slot order |
| slot 0 | `master_log_source`: `RIGHTS_ALL` source on init's master log endpoint; svcmgr mints real-logd's master-log RECV from it on every (re)launch, and the handover SEND (the `HANDOVER_PULL` drain then `HANDOVER_RELEASE`) on the first launch and on a restart until procmgr reports init reaped (see [`log_sink`](service-definitions.md#log_sink)), and the `LOG_QUERY_AUTHORITY`, `LOG_FOLLOW_AUTHORITY`, `LOG_CONTROL_AUTHORITY` and `LOG_FLUSH_AUTHORITY` caps it publishes as `logd.query`, `logd.follow`, `logd.control` and `logd.flush`; holding it keeps the log endpoint alive across a logd crash (absent if its derive fails) |
| slot 1 | `procmgr_death_auth_source`: badge-0 `SEND\|GRANT` source on procmgr's service endpoint; svcmgr mints real-logd's `DEATH_EQ_AUTHORITY` `SEND\|GRANT` cap from it per launch (absent if its derive fails), and the `DEBUG_AUTHORITY` `SEND\|GRANT` cap of a `debug_authority = yes` service |
| slot 2 | `kernel_log_source`: `KernelLog` source carrying `Read`, derived by init from the root `KernelLog` capability the kernel mints into it; svcmgr mints real-logd's slot-5 `KernelLog` cap (`RIGHTS_KLOG_READ`) from it per launch (absent if init holds none or its derive fails) |
| data[0] | `3` (`LOGD_SOURCES`) |
| data[1] | presence word: bit 0 `MASTER_LOG`, bit 1 `PROCMGR_DEATH_AUTH`, bit 2 `KERNEL_LOG` (`logd_present::KERNEL_LOG`) |

After a failed `CAPS` round init ends the endowment with an empty
`LOGD_SOURCES` round (no caps, presence `0`), so svcmgr leaves its round
loop and exits. svcmgr logs a malformed `LOGD_SOURCES` round, deletes the
caps it delivered, and continues with every source absent.

svcmgr holds the sources for the system's life and mints real-logd's
[`log_sink`](service-definitions.md#log_sink) bootstrap round from them on
every (re)launch. An absent source leaves the matching slot of logd's round
absent, which the round's presence word records (see
[`seed`](service-definitions.md#seed)); logd runs without that slot's cap, or,
for the master-log source, exits at startup.

svcmgr parks each substrate `(name, thread, observer)` triple in its pending-registration
table. memmgr and procmgr carry an address-space cap, devmgr and vfsd a process handle; svcmgr
keeps the cap as the entry's `aspace_cap` or `process_handle`. Through devmgr's and vfsd's it
binds the second death observer at reconciliation; through memmgr's and procmgr's, with their
thread caps, it binds both of theirs at its start on the core-death queue, not on its own death
queues ([restart-protocol.md](restart-protocol.md#death-detection)). It does **not**
bind devmgr's or vfsd's death-notification at endowment time — the matching `.svc`
definition is paired at reconciliation, on
[`HANDOVER_COMPLETE`](#label-2-handover_complete). After draining the
endowment svcmgr publishes the well-known names it owns (`rootfs.root`,
`svcmgr`, `svcmgr.grant`, `devmgr.registry`, `devmgr.shutdown`, `devmgr.bind`, `devmgr.acpi`,
`vfsd.mount`, `vfsd.deny`, `vfsd.swap`, `memmgr.swap`, `logd.query`,
`logd.follow`, `logd.control`, `logd.flush`) into its own registry,
configures devmgr's device classes and publishes each as `devmgr.class.<stem>` (the class file's
name without `.class`), and installs devmgr's `/services/drivers/` cap via `SET_DRIVERS_DIR`,
with the cap of `/config/devmgr/platform/` as its optional second cap when the walk to it
succeeds, before entering the event loop. Both read through vfsd and call devmgr, and are skipped
when either is dead ([restart-protocol.md § Death detection](restart-protocol.md#death-detection)).

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message
label field identifies the operation.

A request's caps arrive in svcmgr's `CSpace` before svcmgr serves it. svcmgr deletes every cap a
request carries, whatever its label or badge, a label it does not serve (`UNKNOWN_OPCODE`)
included, apart from `PUBLISH_ENDPOINT`'s `caps[0]`, which it stores or deletes (§ Label 3).

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

1. Read the signed `index` of `/config/svcmgr/services/` and each `.svc` it names through
   procmgr's `READ_VERIFIED` in the configuration role, and parse each verified body into a
   [`Definition`](../src/definitions/mod.rs).
2. Reconcile against the pending-registration table (the substrate triples
   parked from the endowment):
   * **parked AND defined** — bind death-notification (devmgr and vfsd;
     memmgr's and procmgr's observers are already on the core-death
     queue), record the
     recipe's fixed fields on the `ServiceEntry` and its argv/env/cwd/seed,
     log-sink, debug-authority, stop-authority, entropy-authority, `oom_stop`, `reserve` and
     `private_image` flags, `stop_source` class, and scheduling fields in the parallel
     `RestartRecipe` table.
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
| `INVALID_NAME` | `name_len` is 0 or exceeds `svcmgr_labels::NAME_MAX` (64), or the message carries fewer name words than `name_len` needs |
| `INSUFFICIENT_CAPS` | `caps[0]` missing or zero |
| `REGISTER_REJECTED` | Name already registered, or svcmgr's heap cannot grow the registry |

### Label 4: `QUERY_ENDPOINT`

Look up a name in the discovery registry; reply transfers a
freshly-derived `RIGHTS_EP_SEND` cap on the published endpoint. `QUERY_ENDPOINT` never yields
`GRANT`, for any name.

Only public names resolve. A name whose cap carries authority is published seed-only and answers
`UNKNOWN_NAME`, as an unknown name does: `rootfs.root`, the five `devmgr.*` names (`devmgr.bind` and
`devmgr.acpi` included), `vfsd.mount`, `vfsd.swap`, `memmgr.swap`, `logd.query`, `logd.follow`,
`logd.control`, `logd.flush`, and each provider name whose badge carries a verb bit
(`ipc::VERB_BIT_MASK`; the `:auth` and `:grant` entries, today `pwrmgr.shutdown`, `acpid.power`,
`swapd.restore`, `sessiond.operator` and
`crashd.core`).
`vfsd.deny` and `svcmgr.grant` carry no authority but are seed-only too: they are svctest's test
twins, reached only through svctest's recipe. `svcmgr.grant` is a `SEND|GRANT` on svcmgr's own
service endpoint under the published `svcmgr` badge, through which svctest sends requests that
carry caps, which svcmgr deletes. A seed-only name reaches a process only through a recipe's
`seed = ...` line, which svcmgr resolves itself, so its authority stays with the recipes that seed
it ([service-definitions.md § `seed`](service-definitions.md#seed)). A seed is `SEND` except
`devmgr.bind`, `memmgr.swap`, `logd.query`, `logd.follow`, `svcmgr.grant` and each `:grant` entry
(`sessiond.operator`, `crashd.core`), which are `SEND|GRANT`: `BIND_DRIVERS` moves a directory cap
and the kernel requires `GRANT` for that, the swap labels move caps to memmgr, `LOG_SUBSCRIBE` moves
a signal to logd, and a `:grant` name's seeds move caps to its provider. The public
names are `svcmgr`, `pwrmgr.deny`, `acpid.deny`, `timed`, and any name published through
[`PUBLISH_ENDPOINT`](#label-3-publish_endpoint).

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
| `INVALID_NAME` | — | `name_len` is 0 or exceeds `svcmgr_labels::NAME_MAX` (64), or the message carries fewer name words than `name_len` needs |

### Label 5: `STOP_CANDIDATE`

Stop a supervised service for a [stop-authority](#stop-authority) holder: the shared stop label
`stop_labels::STOP_CANDIDATE`, which svcmgr serves as the service class's stop source
([Session Supervision § Stop Sources](../../../docs/session-supervision.md#stop-sources)). The
service is named by the key [`LIST_CANDIDATES`](#label-6-list_candidates) lists it under: the
`DeathTag` correlator `(instance << 32) | slot` of its table slot and the instance that runs
([Death notification](#death-notification)), so a key names one instance and no other. svcmgr
stops the service only when the eligibility rule allows it
([service-definitions.md § `oom_stop`](service-definitions.md#oom_stop)) and the instance the key
names runs. It destroys the process through the procmgr process handle it holds as the service's
creator (`procmgr_labels::DESTROY_PROCESS`), so the authority to kill a process never leaves
svcmgr, replies `SUCCESS`, and then routes the death as `EXIT_KILLED` (`0x2000`) through the
service's restart policy and budget ([Restart policy](#restart-policy)), as it routes a death the
kernel posts: an `on_failure` or `always` service restarts while its budget lasts, and a death
past it leaves the service permanently down. The reply precedes the restart, so the holder does
not wait on it. A death post of the destroyed instance that arrives later names the old instance
and is dropped, and the restarted instance has a new key.

Each refusal is logged with its reason and changes nothing. A request delivers no cap, and svcmgr
deletes any it carries. The reply labels are the stop labels' codes, not `svcmgr_errors`.

**Request:**

| Field | Value |
|---|---|
| label | `5` |
| data[0] | The key: `(instance << 32) \| slot` |
| badge | MUST carry [`STOP_AUTHORITY`](#stop-authority); rejected with `UNAUTHORIZED` otherwise. |

**Reply**, the first that applies, in this order:

| label value | Meaning |
|---|---|
| `UNAUTHORIZED` (1) | Caller's badge lacks `STOP_AUTHORITY` |
| `NO_CANDIDATE` (2) | The slot holds no service, the eligibility rule refuses the service (a `restart = never` service among them, which svcmgr never restarts), no instance runs (it is restarting, waits for memory, or is permanently down; a death the kernel shows that svcmgr has not yet routed is routed after the reply), or the key's instance is not the one that runs |
| `UNAVAILABLE` (3) | memmgr or procmgr is dead, so a destroy would not be answered, or procmgr did not destroy the process |
| `0` (`SUCCESS`) | The instance is destroyed; its death is routed after the reply |

### Label 6: `LIST_CANDIDATES`

List, one page per call, the services a [`STOP_CANDIDATE`](#label-5-stop_candidate) would stop
now: the shared stop label `stop_labels::LIST_CANDIDATES`, each entry with its key, its rank,
the pages its memory budget node and that node's subtree hold, and its name. A service is listed
when the eligibility rule allows it, an instance runs, and svcmgr holds a node handle to its budget
node: svcmgr asks procmgr for one (`CREATE_NODE_HANDLE`) at each create of an `oom_stop = yes`
service, and reads the usage through it (memmgr `NODE_QUERY_USAGE`'s `data[2]`;
[memmgr IPC Interface § Node Handles](../../memmgr/docs/ipc-interface.md#node-handles)). A service
whose usage memmgr does not give is logged and left out of the page. Every service has the rank
`stop_labels::RANK_SERVICE` (0).

The walk is in svcmgr's table order, from a slot cursor: the first call passes `0`, and each next
call passes the reply's `data[1]`. A page holds at most `stop_labels::LIST_CANDIDATES_PAGE` (5)
entries, and a page of fewer ends the walk. svcmgr never reuses a slot, so a cursor names the same
place for svcmgr's lifetime; a service that starts or stops between two calls is listed by the
state at the call that reaches its slot. A request delivers no cap, and svcmgr deletes any it
carries.

Every stop source serves this label with this layout, and a source of the program class lists its
jobs at `stop_labels::RANK_JOB` (0) and its sessions at `stop_labels::RANK_SESSION` (1); its
cursor is its own.

**Request:**

| Field | Value |
|---|---|
| label | `6` |
| data[0] | Cursor: `0`, or the `data[1]` of the previous reply |
| badge | MUST carry [`STOP_AUTHORITY`](#stop-authority); rejected with `UNAUTHORIZED` otherwise. |

**Reply:**

| label value | Meaning |
|---|---|
| `0` (`SUCCESS`) | One page, laid out below |
| `UNAUTHORIZED` (1) | Caller's badge lacks `STOP_AUTHORITY` |
| `UNAVAILABLE` (3) | memmgr or procmgr is dead, so no usage can be read |

| Field | Value |
|---|---|
| data[0] | Entries in this page, `0..=LIST_CANDIDATES_PAGE` |
| data[1] | The cursor the next call passes, greater than the one asked; svcmgr's is the table's length when the walk reached its end |
| data[2 + 12·i] | Entry `i`: the key [`STOP_CANDIDATE`](#label-5-stop_candidate) names it by |
| data[3 + 12·i] | Entry `i`: the rank within its source's class, the lower stopped first |
| data[4 + 12·i] | Entry `i`: the pages its budget node and subtree hold |
| data[5 + 12·i] | Entry `i`: the name's length in bytes, `1..=NAME_MAX` |
| data[6 + 12·i ..= 13 + 12·i] | Entry `i`: the name's bytes, packed as `svcmgr_labels::pack_name` packs them |

`stop_labels::pack_candidate` and `unpack_candidate` write and read an entry.

### Label 7: `LIST_STOP_SOURCES`

List, one page per call, the stop sources other than svcmgr: the running services whose recipes
set [`stop_source`](service-definitions.md#stop_source), each with its class and a SEND on its
service endpoint badged with [`STOP_AUTHORITY`](#stop-authority), on which the source serves
[`STOP_CANDIDATE`](#label-5-stop_candidate) and [`LIST_CANDIDATES`](#label-6-list_candidates)
([Session Supervision § Stop Sources](../../../docs/session-supervision.md#stop-sources)). svcmgr
derives each SEND (`cap_derive_badge`) from the original of the endpoint it holds for the
service's life, the one it provides the service's names from; the endpoint persists across the
source's restarts. The class is the recipe's, never the source's own claim. A service is listed
while an instance runs; one whose SEND svcmgr cannot derive is logged and left out of the page.

The walk is in svcmgr's table order, from a slot cursor, as
[`LIST_CANDIDATES`](#label-6-list_candidates)' is. A page holds at most
`svcmgr_labels::LIST_STOP_SOURCES_PAGE` (4) entries, one per cap a message carries
(`MSG_CAP_SLOTS_MAX`), and a page of fewer ends the walk. The reply moves each SEND out of
svcmgr's CSpace into the caller's; a reply that does not deliver deletes them. A request delivers
no cap, and svcmgr deletes any it carries.

**Request:**

| Field | Value |
|---|---|
| label | `7` |
| data[0] | Slot cursor: `0`, or the `data[1]` of the previous reply |
| badge | MUST carry [`STOP_AUTHORITY`](#stop-authority); rejected with `UNAUTHORIZED` otherwise. |

**Reply:**

| label value | Caps | Meaning |
|---|---|---|
| `0` (`SUCCESS`) | `[send_0, …, send_(n-1)]` | One page of `n` entries, laid out below; `caps[i]` is entry `i`'s SEND |
| `UNAUTHORIZED` | — | Caller's badge lacks `STOP_AUTHORITY` |

| Field | Value |
|---|---|
| data[0] | Entries in this page, `0..=LIST_STOP_SOURCES_PAGE` |
| data[1] | The cursor the next call passes; the table's length when the walk reached its end |
| data[2 + 10·i] | Entry `i`: the class, `stop_labels::CLASS_PROGRAM` (1) for `stop_source = program` |
| data[3 + 10·i] | Entry `i`: the name's length in bytes |
| data[4 + 10·i ..= 11 + 10·i] | Entry `i`: the name's bytes, packed as `svcmgr_labels::pack_name` packs them |

`svcmgr_labels::pack_stop_source` and `unpack_stop_source` write and read an entry.

---

## Publish authority

`svcmgr_labels::PUBLISH_AUTHORITY` is a verb-bit (the top bit of the
caller's cap badge) gating `PUBLISH_ENDPOINT` for *external* publishers.
svcmgr publishes the well-known names it owns (`rootfs.root`, `svcmgr`, `svcmgr.grant`, the four
`devmgr.*` names, the three `vfsd.*` names, `logd.query`, `logd.follow`, `logd.control`,
`logd.flush`, and each provider's `provides` names) directly into its own registry, so those need no
badge. The gate exists for a future
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

## Stop authority

`stop_labels::STOP_AUTHORITY` (bit 61) is the verb bit that gates the stop labels,
[`STOP_CANDIDATE`](#label-5-stop_candidate) and [`LIST_CANDIDATES`](#label-6-list_candidates),
and [`LIST_STOP_SOURCES`](#label-7-list_stop_sources). svcmgr mints a SEND on its own service
endpoint with that badge for a service whose recipe sets
[`stop_authority = yes`](service-definitions.md#stop_authority), at each launch and restart, and
delivers it in the service's bootstrap rounds, in the slot after the seeds and the debug-authority
slot. The cap reaches no process by any other path: the name is never published, the per-process
`service_registry_cap` and the published `svcmgr` SEND carry no verb bit, and procmgr keeps the
process badges it mints clear of verb bits
([Capability Model](../../../docs/capability-model.md#verb-bit-authority-pattern)). A holder learns
which services it may stop and stops one; it never holds a process handle or any other kill
authority, and a service the eligibility rule refuses stays out of its reach.

The same bit on a SEND to a stop source's endpoint authorises that source's stop labels. svcmgr
mints such a SEND only in a [`LIST_STOP_SOURCES`](#label-7-list_stop_sources) reply, to a holder
of its own stop authority. The parser accepts `stop_source` only on a recipe whose every provided
name is badged ([service-definitions.md § `stop_source`](service-definitions.md#stop_source)), so
no holder of a source's provided name holds the bit.

---

## Death notification

svcmgr maintains a growable set of death EventQueues. At
reconciliation time, every supervised service has its main thread
bound to one of them, and its address space bound to one, each with the
`DeathTag` correlator `(instance << 32) | slot`. The
WaitSet holds the service endpoint (badge 0), every death queue
(badge 1), and the memory-pressure Notification that wakes a restart
waiting for memory (badge 2; [restart-protocol.md § Decision
tree](restart-protocol.md#decision-tree)).

When the main thread exits (clean or fault), or any thread makes the address space's first terminal
end (a fault or an exit), the kernel posts the death entry `(exit_reason, correlator)` to the queue
its observer was bound on (see [restart-protocol.md](restart-protocol.md#death-detection)). svcmgr
drains every queue and routes each payload whose tag names the slot's active, current instance
to its `ServiceEntry`, then dispatches through
[`restart::handle_death`](../src/restart.rs).

Exit reason encoding:

| Value | Meaning |
|---|---|
| `0` | clean exit (`SYS_THREAD_EXIT`) |
| `1..=0x0FFF` | voluntary exit code |
| `0x1000..=0x1FFF` (`EXIT_FAULT_BASE + vector`, or `EXIT_RUN_LIMIT`) | fault (exception vector / scause + base, or a run-limit fault) |
| `0x2000` (`EXIT_KILLED`) | killed, by procmgr or by svcmgr's [`STOP_CANDIDATE`](#label-5-stop_candidate) |

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

Restarts are budgeted per window (`restart_budget::RestartBudget`: three per
60 s). A death once the open window's restarts are spent leaves the service
permanently down — degraded, or a graceful shutdown for `critical = yes` —
see [restart-protocol.md](restart-protocol.md).

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
| `true` (`critical = yes`) | Initiate graceful shutdown through the [`shutdown_actuator`](service-definitions.md#shutdown_actuator) |

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
[Supervision](../../../docs/supervision.md),
[services/init/README.md](../../init/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md),
[services/svcmgr/README.md](../README.md),
[services/svcmgr/endowment/README.md](../endowment/README.md),
[services/svctest/README.md](../../svctest/README.md),
[shared/registry-client/README.md](../../../shared/registry-client/README.md),
[shared/registry/README.md](../../../shared/registry/README.md)
