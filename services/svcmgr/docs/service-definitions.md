# `.svc` Service Definitions

Authoritative spec for the `/config/svcmgr/services/<name>.svc` files
svcmgr scans at `HANDOVER_COMPLETE` to reconcile the substrate
registrations init delivers in the handover endowment with the on-disk
service recipes.

## Authority

`.svc` files are the **single source of truth** for a service's
recipe. First-launch (svcmgr launches the service post-handover) and
restart (svcmgr respawns a crashed service) read the same file. No
recipe travels on the wire.

## Filesystem layout

* Directory: `/config/svcmgr/services/`
* Filename: `<name>.svc`. The `<name>` portion is the key under which
  the service is reconciled with svcmgr — for a substrate service, the
  `name` carried in its
  [handover-endowment `SUBSTRATE` round](ipc-interface.md#handover-endowment-bootstrap-rounds).
  Filenames are ASCII; case-sensitive `.svc` suffix.
* Files are shipped via `rootfs/config/svcmgr/services/` and installed
  into the sysroot by xtask's recursive `install_rootfs` copy. No
  build-system change is required to add a new recipe — drop the
  file in `rootfs/config/svcmgr/services/` and rebuild.

## Grammar

Line-oriented `key = value`. Lines starting with `#` are comments.
Blank lines are tolerated. Whitespace around `=` is tolerated.
Unknown keys are **hard errors** — a typo cannot silently degrade a
service.

```
# /tests/svctest — services-surface test harness.
binary    = /tests/svctest
priority  = 10
sched_max = 10
argv      = svctest run
env       = SERAPH_TEST=1 SERAPH_MODE=boot
restart   = never
critical  = no
namespace = universal
cwd       = /data
seed      = rootfs.root pwrmgr.shutdown pwrmgr.deny
```

## Keys

| Key | Required | Value |
|---|---|---|
| `binary` | yes | Absolute path under svcmgr's root. Walked from `system_root_cap` at launch / restart. |
| `argv` | no | Space-separated badges. Becomes NUL-separated, NUL-terminated bytes on the wire. |
| `env` | no | Space-separated `KEY=VAL` badges. Same NUL packing as `argv`. |
| `restart` | yes | One of `never`, `on_failure`, `always`. |
| `critical` | yes | `yes` or `no`. Whether the system is viable without this service once it is permanently down. Orthogonal to `restart`. |
| `namespace` | yes | One of `none`, `universal`, `subtree:<path>:<rights>`. |
| `cwd` | no | Path interpreted relative to svcmgr's universal root. Forbidden when `namespace = none`. |
| `seed` | no | Space-separated discovery-registry names, resolved positionally (cap[i] = i-th name). |
| `provides` | no | Space-separated `name[:auth\|:deny]` entries. svcmgr creates this service's endpoint, serves its RECV as bootstrap `cap[0]`, and publishes one badged SEND per entry into the discovery registry. See [`provides`](#provides). |
| `log_sink` | no | `yes` or `no` (default `no`). Marks the service as the system log sink (real-logd); svcmgr mints its bootstrap round from the reserved log-sink sources init endows. Mutually exclusive with `seed` and `provides`. See [`log_sink`](#log_sink). |
| `priority` | no | Priority level (`1..=30`) the service's initial thread is created at. Unset: procmgr's default (`sched_policy::DEFAULT_SPAWN_PRIORITY`, clamped to the band). See [`priority` / `sched_max`](#priority--sched_max). |
| `sched_max` | no | Band ceiling (`1..=30`): the service's `SchedControl` covers `[1, sched_max]`. Must be ≥ `priority` when both are set. Unset: the service inherits a copy of svcmgr's own band. |

There is deliberately no paging key. Demand paging is procmgr's system-wide default
(see [Fault Handling](../../../docs/fault-handling.md#default-system-pager)); every
svcmgr-launched service is demand-paged. A pinned opt-out
(`procmgr_labels::CREATE_PINNED`) exists for DMA drivers, which devmgr spawns — not svcmgr.
A declarative paging key here is a reserved future extension, to be added only when the
first pinned svcmgr-launched service exists.

## `restart`

| Value | Semantics |
|---|---|
| `never` | Service is one-shot; never restarted, even on fault. Used for integration-test fixtures (e.g. `svctest`) whose clean exit is the success notification. |
| `on_failure` | Restart only on a fault exit (`exit_reason >= EXIT_FAULT_BASE`). Clean exits are treated as intentional. |
| `always` | Restart on every exit, clean or faulty. Default for daemons that should never terminate during normal operation. |

Restart attempts are counted per service. After
`service::MAX_RESTARTS` (currently `1`) consecutive restarts in a
short window, the service is marked degraded and not restarted
automatically — see [restart-protocol.md](restart-protocol.md).

## `critical`

`critical` answers one question — *can the system keep running without
this service once it is permanently down?* — and nothing else. It is
**orthogonal to `restart`**: `restart` (+ the budget) alone decides
whether and when svcmgr respawns a dead service; `critical` is consulted
only once a service is permanently down (restart not attempted, budget
exhausted, or a restart attempt failed).

| Value | Behaviour once permanently down |
|---|---|
| `no` | Logged; service marked inactive. The system continues degraded. |
| `yes` | svcmgr logs `critical service unrecoverable: <name>; initiating graceful shutdown` and issues [`pwrmgr_labels::SHUTDOWN`](../../../shared/ipc/src/lib.rs) via the cap it resolves from [`published_names::PWRMGR_SHUTDOWN`](../../../shared/ipc/src/lib.rs). |

Because the two fields are independent, any combination is valid — e.g.
`restart = always` + `critical = no` (the `crasher` fixture: respawned on
every fault, but its eventual permanent death is non-fatal).

**pwrmgr's own death** is the edge case. pwrmgr is `restart = on_failure`
+ `critical = no`: a crashed pwrmgr is recoverable (svcmgr re-creates it
and it re-acquires its actuator caps from devmgr — see
[services/pwrmgr/README.md](../../pwrmgr/README.md)), and its *permanent*
death is deliberately non-fatal. It is `critical = no` precisely because
the graceful-shutdown escalation routes through `pwrmgr.shutdown` — if
pwrmgr is the dead service, that source is gone, so escalation would be
circular. The honest terminal state is logged-and-continue. Setting
`critical = yes` on pwrmgr would be self-defeating for this reason.

## `namespace`

The primary lever for confining a service to only what it needs.

| Form | Effect |
|---|---|
| `none` | No namespace cap delivered. The child's `ProcessInfo.system_root_cap` stays zero; std-side absolute-path filesystem operations return `Unsupported`. Default tight choice for services with no filesystem dependency. |
| `universal` | `cap_copy` of svcmgr's own root (the system universal root). Reserved for services that need genuine root authority (vfsd as the namespace authority, devmgr for `/dev`, procmgr for walking `/services` and `/programs`, svctest as the namespace tester). |
| `subtree:<path>:<rights>` | Walk `<path>` from svcmgr's root requesting `<rights>` per hop, hand the resulting directory cap to the child. `<rights>` is a `+`-joined list of named badges (`LOOKUP`, `READDIR`, `STAT`, `READ`, `WRITE`, `EXEC`, `MUTATE_DIR`, `ADMIN` — see [`shared/namespace-protocol/src/rights.rs`](../../../shared/namespace-protocol/src/rights.rs)). Unknown badges are parser errors. Empty rights list is a parser error. |

Example subtree clause:

```
namespace = subtree:/data:LOOKUP+READDIR+STAT+READ+WRITE
```

## `cwd`

When set, svcmgr walks `<cwd>` from its own root with
`LOOKUP+READDIR+STAT+READ` rights and passes the resulting directory
cap as the child's `ProcessInfo.current_dir_cap`. The path must
resolve inside the namespace. With `namespace = none`, `cwd` is a
parser error.

`std::env::current_dir()` returns `Unsupported` until a path string
is recorded via `std::env::set_current_dir`; the cap and the
path-string surface are independent. See svctest's
`env_cwd_unset_phase` for the assertion.

## `priority` / `sched_max`

The service's scheduling placement, forwarded as the `CREATE_PRIORITY` /
`CREATE_BAND_MAX` fields of svcmgr's `CREATE_FROM_FILE` label (see
[procmgr's IPC interface](../../procmgr/docs/ipc-interface.md)) and
replayed byte-for-byte on every restart:

* `priority` — the level the service's initial thread is created at; the
  runtime spawns its further threads at the same level. Unset: procmgr's
  default, `sched_policy::DEFAULT_SPAWN_PRIORITY` clamped to the band.
* `sched_max` — the ceiling of the `SchedControl` band the service
  receives (`[1, sched_max]`), which is also its own spawn ceiling for
  `std::process::Command` children. Unset: a copy of svcmgr's band.

Both values are validated by procmgr against svcmgr's own band ceiling
(`sched_policy::SVCMGR_PRIORITY`, currently 21) — a recipe requesting more
than svcmgr holds fails the spawn with `INVALID_ARGUMENT`. The parser
rejects values outside `1..=30` and `sched_max < priority` (a service's
band must cover its own starting level). The system-wide level map lives
in `shared/ipc`'s `sched_policy` module; recipes carry only the levels of
svcmgr-launched services.

## `seed`

Space-separated discovery-registry names. svcmgr resolves each name
to a freshly-derived `RIGHTS_SEND` cap on the published endpoint and
injects them positionally into the child's bootstrap round:

```
seed = rootfs.root pwrmgr.shutdown pwrmgr.deny
```

becomes `caps = [rootfs_root_send, pwrmgr_shutdown_send,
pwrmgr_deny_send]` on the child's `bootstrap::request_round`. The
list is truncated to `MSG_CAP_SLOTS_MAX` (currently 4) entries; any
truncation is logged.

An unresolved name leaves slot `i` as `0`. Consumers that already
tolerate `cap == 0 → skip` (e.g. svctest's pwrmgr phases) continue
to work; consumers that don't fail on first use, which is the right
surface for a real misconfiguration.

Well-known names are centralised in
[`ipc::published_names`](../../../shared/ipc/src/lib.rs):

| Name | Publisher (today) | Cap shape |
|---|---|---|
| `rootfs.root` | init Phase 3 | badged SEND on the root filesystem's namespace endpoint at its root directory (FS-driver-agnostic) |
| `pwrmgr.shutdown` | svcmgr (`pwrmgr.svc` provider) | `SHUTDOWN_AUTHORITY`-badged SEND on pwrmgr's service endpoint |
| `pwrmgr.deny` | svcmgr (`pwrmgr.svc` provider) | no-authority SEND on pwrmgr's service endpoint (negative-test twin) |
| `timed` | svcmgr (`timed.svc` provider) | un-badged SEND on timed's service endpoint (wall-clock) |
| `svcmgr` | init Phase 3 | un-badged SEND on svcmgr's own service endpoint |
| `devmgr.registry` | init Phase 3 | `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's registry endpoint |

## `provides`

Declares the registry names a service's own endpoint is published under.
svcmgr creates a service endpoint, serves its RECV as bootstrap `cap[0]`
(ahead of the `seed` caps), and publishes one SEND per entry. Providers
launch ahead of pure consumers during reconciliation, so a provided name
is resolvable before any consumer queries it. The endpoint persists across
restarts (svcmgr holds the source), so a cached client cap survives a
crash-restart and no re-publish is needed.

Each space-separated entry is `name[:auth|:deny]`; the suffix selects the
badge svcmgr stamps on that name's SEND (the badge rides through a
consumer's `QUERY_ENDPOINT` lookup unchanged):

| Suffix | Badge | Use |
|---|---|---|
| *(none)* | `0` (unbadged) | Plain SEND. e.g. `timed`. |
| `:auth` | `1 << 63` | The universal verb-authority bit shared by every `*_AUTHORITY` constant — the server's `badge & (1 << 63)` gate passes. e.g. `pwrmgr.shutdown:auth`. |
| `:deny` | `1` | Present so the cap resolves, but the authority gate fails. The negative-test twin. e.g. `pwrmgr.deny:deny`. |

```
provides = pwrmgr.shutdown:auth pwrmgr.deny:deny
```

## `log_sink`

`yes` marks the service as the system's master log sink — real-logd, the
receive-side owner of the master log endpoint. Exactly one recipe carries
`log_sink = yes`.

A log-sink service's bootstrap round is **not** assembled from `seed` or
`provides`. svcmgr mints it from the reserved log-sink sources init endows
at handover (the master-log endpoint source and the procmgr `SEND|GRANT`
death-auth source — see
[`process-lifecycle.md`](../../../docs/process-lifecycle.md)) plus the
`devmgr.registry` source. The round is four positional caps:

| Index | Cap |
|---|---|
| 0 | `RECV` on the master log endpoint |
| 1 | `SEND` on the master log endpoint (single-use; `HANDOVER_PULL` only). `0` on a restart — no init-logd remains to pull from |
| 2 | badged `SEND` on procmgr carrying `DEATH_EQ_AUTHORITY` (logd registers per-sender death-notifications for slot reclaim) |
| 3 | badged `SEND` on devmgr's registry carrying `REGISTRY_QUERY_AUTHORITY` (logd resolves the serial driver via `QUERY_SERIAL_DEVICE`) |

Because these slots are svcmgr-minted, `seed` and `provides` have no
position in the round; declaring either alongside `log_sink = yes` is a
parser error. The same svcmgr-minted round drives both the first launch
(`cap[1]` present, history pulled from init-logd) and every restart
(`cap[1] = 0`, history pull skipped) — svcmgr holds the master-log source
for the system's life, so each (re)launched logd re-attaches a fresh RECV
to the same endpoint object every sender already targets. `restart` and
`critical` behave exactly as for any other service.

```
binary    = /services/logd
restart   = on_failure
critical  = yes
namespace = none
log_sink  = yes
```

## Reconciliation

At `HANDOVER_COMPLETE` svcmgr scans `/config/svcmgr/services/`, parses each
`<name>.svc`, and reconciles against the pending-registration table
(substrate pairs parked from the handover endowment):

| Definition | Pending registration | Outcome |
|---|---|---|
| present | present | **bind only** — bind death-notification on the endowed thread cap; record a `ServiceEntry` with the parsed recipe for restart use. |
| present | absent | **launching** — svcmgr launches the service via [`definitions::launch`](../src/definitions/launch.rs): walk `binary`, `CREATE_FROM_FILE` with argv/env, `CONFIGURE_NAMESPACE` with the namespace+cwd, `START_PROCESS`, serve the seed bootstrap round. If `restart != never`, bind death-notification and record a `ServiceEntry`. |
| absent | present | **error** — `registered without definition: <name>; refusing to bind`. svcmgr has no recipe; an endowed name without a matching `.svc` is a configuration error. |

## Relevant Design Documents

| Document | Content |
|---|---|
| [README.md](../README.md) | Component scope, responsibilities, restart policy |
| [ipc-interface.md](ipc-interface.md) | handover endowment, `HANDOVER_COMPLETE`, `PUBLISH_ENDPOINT` / `QUERY_ENDPOINT` |
| [restart-protocol.md](restart-protocol.md) | Restart sequencing, shared spawn primitives, criticality semantics |
| [shared/ipc/src/lib.rs](../../../shared/ipc/src/lib.rs) | `published_names` constants, `svcmgr_labels::*`, `svcmgr_errors::*` |

---

## Summarized By

[svcmgr/README.md](../README.md)
