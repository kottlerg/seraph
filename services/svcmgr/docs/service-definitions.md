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
  `<name>` is 1 to `ipc::svcmgr_labels::NAME_MAX` (64) bytes, the svcmgr
  protocol's one name limit; a longer name is a parser error.
  Filenames are ASCII; case-sensitive `.svc` suffix.
* Files are shipped via `rootfs/config/svcmgr/services/` and installed
  into the sysroot by xtask's recursive `install_rootfs` copy (see
  [Build System](../../../docs/build-system.md#build-output-the-sysroot)). No
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
sched_max = 21
argv      = svctest run
env       = SERAPH_TEST=1 SERAPH_MODE=boot
restart   = never
critical  = no
namespace = universal
cwd       = /data
seed      = rootfs.root pwrmgr.shutdown devmgr.registry devmgr.test vfsd.mount vfsd.deny
```

## Keys

| Key | Required | Value |
|---|---|---|
| `binary` | yes | Absolute path under svcmgr's root, at most `ipc::MAX_PATH_LEN` (4096) bytes, the one recipe path limit; a longer path is a parser error. The entry svcmgr restarts from holds it at its own length (see [Restart Protocol](restart-protocol.md#recipe-storage)). Walked from `system_root_cap` at launch / restart. |
| `argv` | no | Space-separated tokens. Becomes NUL-separated, NUL-terminated bytes on the wire. Bounded; see [`argv` / `env`](#argv--env). |
| `env` | no | Space-separated `KEY=VAL` tokens. Same NUL packing and bounds as `argv`. |
| `restart` | yes | One of `never`, `on_failure`, `always`. |
| `critical` | yes | `yes` or `no`. Whether the system is viable without this service once it is permanently down. Orthogonal to `restart`. |
| `namespace` | yes | One of `none`, `universal`, `subtree:<path>:<rights>`. |
| `cwd` | no | Path interpreted relative to svcmgr's universal root; must lie inside the namespace (see [`cwd`](#cwd)). Forbidden when `namespace = none`. |
| `seed` | no | Space-separated discovery-registry names, resolved positionally (cap[i] = i-th name; cap[i+1] for a `provides` service). Any number of names; slots past one bootstrap round's `MSG_CAP_SLOTS_MAX` (4) caps ride in further rounds; see [`seed`](#seed). |
| `provides` | no | Space-separated `name[:auth\|:deny]` entries. svcmgr creates this service's endpoint, serves its RECV as bootstrap `cap[0]`, and publishes one badged SEND per entry into the discovery registry. See [`provides`](#provides). |
| `log_sink` | no | `yes` or `no` (default `no`). Marks the service as the system log sink (real-logd); svcmgr mints its bootstrap round from the reserved log-sink sources init endows. Mutually exclusive with `seed` and `provides`. See [`log_sink`](#log_sink). |
| `shutdown_actuator` | no | One name of this recipe's `provides` list, carrying `:auth`. Declares the service the system's shutdown actuator: svcmgr calls the shutdown request through that name when a `critical = yes` service is permanently down. Needs `restart` other than `never`. See [`shutdown_actuator`](#shutdown_actuator). |
| `debug_authority` | no | `yes` or `no` (default `no`). Endows the service with procmgr's debug authority, a `DEBUG_AUTHORITY` `SEND\|GRANT` on procmgr, in the bootstrap slot after its `seed` caps. Mutually exclusive with `log_sink`. See [`debug_authority`](#debug_authority). |
| `priority` | no | Priority level (`1..=30`) the service's initial thread is created at. Unset: procmgr's default (`sched_policy::DEFAULT_SPAWN_PRIORITY`, clamped to the band). See [`priority` / `sched_max`](#priority--sched_max). |
| `sched_max` | no | Band ceiling (`1..=30`): the service's `SchedControl` covers `[1, sched_max]`. Must be ≥ `priority` when both are set. Unset: the service inherits a copy of svcmgr's own band. |

There is deliberately no paging key. Demand paging is procmgr's system-wide default
(see [Fault Handling](../../../docs/fault-handling.md#default-system-pager)); every
svcmgr-launched service is demand-paged. A pinned opt-out
(`procmgr_labels::CREATE_PINNED`) exists for DMA drivers, which devmgr spawns — not svcmgr.
A declarative paging key here is a reserved future extension, to be added only when the
first pinned svcmgr-launched service exists.

## `argv` / `env`

Both lists are packed as NUL-separated, NUL-terminated bytes into the
argv/env Memory cap svcmgr's `CREATE_FROM_FILE` to procmgr carries (see
[procmgr's IPC interface](../../procmgr/docs/ipc-interface.md#label-1-create_process)
§ Label 1, **argv and env**) and replayed on every restart. The parser
rejects a recipe whose packing the child could not receive:

* the two blobs together, counting one NUL per token, are at most
  `process_abi::ARGV_ENV_MAX_BYTES` (just under 1 GiB), the child's argv/env
  region ([abi/process-abi/README.md](../../../abi/process-abi/README.md)
  § argv / env region); no token count or per-blob bound applies below it
  (`TooLarge`);
* no token contains a NUL byte: the blob is NUL-delimited, so an embedded
  NUL would add a string boundary the header's count does not carry, and
  procmgr would refuse the create. The parser rejects such a line as
  `InvalidValue`.

An `env` entry `SERAPH_LOG=<level>` sets the most verbose level a std-built service's
`seraph::log!` sends ([logd IPC interface](../../logd/docs/ipc-interface.md) § Levels).

## `restart`

| Value | Semantics |
|---|---|
| `never` | Service is one-shot; never restarted, even on fault. Used for integration-test fixtures (e.g. `svctest`) whose clean exit is the success notification. |
| `on_failure` | Restart only on a fault exit (`exit_reason >= EXIT_FAULT_BASE`). Clean exits are treated as intentional. |
| `always` | Restart on every exit, clean or faulty. Default for daemons that should never terminate during normal operation. |

Restarts are budgeted per window: a service may restart three times
(`RESTART_BURST`) within one 60 s window (`RESTART_WINDOW_NS`), the window
opening at the first restart after the previous one has passed. A death
once the open window's restarts are spent leaves the service permanently
down: degraded, or a graceful shutdown for `critical = yes` (see
[`critical`](#critical)). A service that crashes less often than that
restarts every time. See [restart-protocol.md](restart-protocol.md).

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
| `yes` | svcmgr logs `critical service unrecoverable: <name>; initiating graceful shutdown` and issues [`pwrmgr_labels::SHUTDOWN`](../../../shared/ipc/src/lib.rs) through the [`shutdown_actuator`](#shutdown_actuator). See [restart-protocol.md](restart-protocol.md). |

Because the two fields are independent, any combination is valid — e.g.
`restart = always` + `critical = no` (the `crasher` fixture: respawned on
every fault, but its eventual permanent death is non-fatal).

**The shutdown actuator's own death** is the edge case. pwrmgr, the
actuator, is `restart = on_failure` + `critical = no`: a crashed pwrmgr is
recoverable (svcmgr re-creates it and it re-acquires its actuator caps from
devmgr — see [services/pwrmgr/README.md](../../pwrmgr/README.md)), and its
*permanent* death is deliberately non-fatal. It is `critical = no` precisely
because the graceful-shutdown escalation routes through the actuator — if
the actuator is the dead service, nothing can power the system off, so
escalation would be circular. The honest terminal state is
logged-and-continue. Setting `critical = yes` on the actuator would be
self-defeating for this reason: svcmgr logs the degraded state instead of
shutting down (see [`shutdown_actuator`](#shutdown_actuator)).

## `namespace`

The primary lever for confining a service to only what it needs.

| Form | Effect |
|---|---|
| `none` | No namespace cap delivered. The child's `ProcessInfo.system_root_cap` stays zero; std-side absolute-path filesystem operations return `Unsupported` (see [Namespace Model](../../../docs/namespace-model.md#initial-capability-delivery)). Default tight choice for services with no filesystem dependency. |
| `universal` | `cap_copy` of svcmgr's own root (the system universal root). Reserved for services that need genuine root authority. The recipes that declare it are `svctest` (the namespace tester), `usertest`, and `terminal`, which resolve and spawn programs; the recipes of the init-bootstrapped substrate services declare `none`, since init, not svcmgr, spawned them. |
| `subtree:<path>:<rights>` | Walk `<path>` from svcmgr's root requesting `<rights>` per hop, hand the resulting directory cap to the child. `<path>` is absolute, names a directory below the root, and is at most `ipc::MAX_PATH_LEN` (4096) bytes, the same bound as `binary`; longer is a parser error, and so is a path with no components (`subtree:/`, which no namespace server would attenuate; use `universal`). `<rights>` is a `+`-joined list of rights names (`LOOKUP`, `READDIR`, `STAT`, `READ`, `WRITE`, `EXEC`, `MUTATE_DIR`, `ADMIN` — see [`shared/namespace-protocol/src/rights.rs`](../../../shared/namespace-protocol/src/rights.rs)). Unknown rights names are parser errors. Empty rights list is a parser error. |

Example subtree clause:

```
namespace = subtree:/data:LOOKUP+READDIR+STAT+READ+WRITE
```

## `cwd`

When set, svcmgr walks `<cwd>` from its own root with
`LOOKUP+READDIR+STAT+READ` rights and passes the resulting directory
cap as the child's `ProcessInfo.current_dir_cap`; under
`namespace = subtree:<path>:<rights>` it requests only those of the four
rights that `<rights>` grants, so the cwd cap never exceeds the namespace
cap. The path must resolve inside the namespace. With a subtree
namespace, a `cwd` that is neither `<path>` nor a path below it
(compared by whole components, so `/data2` is outside `/data`) is a
parser error, as is a `cwd` whose `<rights>` lack `LOOKUP`; namespace
servers reject `.` and `..` components, so an accepted path cannot walk
back out. Under `namespace = universal`, a `cwd` of `/` is a parser
error: it names svcmgr's root itself, and rights narrow only at an
`NS_LOOKUP` hop, as
[Namespace Model § Per-Entry Rights and Visibility](../../../docs/namespace-model.md#per-entry-rights-and-visibility)
defines, so the walk cannot hand over the root with those rights. With
`namespace = none`, `cwd` is a parser error.

`std::env::current_dir()` returns `Unsupported` until a path string
is recorded via `std::env::set_current_dir`; the cap and the
path-string surface are independent (see
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md#namespace-capabilities)).
See svctest's `env_cwd_unset_phase` for the assertion.

## `priority` / `sched_max`

The service's scheduling placement, forwarded as the `CREATE_PRIORITY` /
`CREATE_BAND_MAX` fields of svcmgr's `CREATE_FROM_FILE` label (see
[procmgr's IPC interface](../../procmgr/docs/ipc-interface.md)) and
replayed byte-for-byte on every restart:

* `priority` — the level the service's initial thread is created at; the
  runtime spawns its further threads at the same level by default, unless
  `std::os::seraph::thread::BuilderExt::spawn_at_priority` places one
  elsewhere in the band. Unset: procmgr's default,
  `sched_policy::DEFAULT_SPAWN_PRIORITY` clamped to the band.
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
to a freshly-derived `RIGHTS_EP_SEND` cap on the published endpoint and
injects them positionally into the child's bootstrap rounds:

```
seed = rootfs.root pwrmgr.shutdown pwrmgr.deny
```

becomes slots `[rootfs_root_send, pwrmgr_shutdown_send,
pwrmgr_deny_send]` of the child's bootstrap rounds. A `provides`
service's provider RECV takes slot 0, ahead of the seeds. A recipe may
name any number of seeds.

A bootstrap round carries at most `MSG_CAP_SLOTS_MAX` (currently 4) caps, so svcmgr splits the slot
list into windows of that many slots and serves one round per window, the last marked done
(`ipc::bootstrap::slot_rounds`); a list of four slots or fewer is one round. An unresolved name
leaves its slot absent. The kernel refuses a message carrying a null cap slot, so each round
transfers only its window's present caps, in slot order, and carries a presence word in `data[0]`:
bit `i` is set when slot `i` of the window holds a cap (`ipc::bootstrap::pack_slots`). The child
concatenates the rounds with `ipc::bootstrap::request_slots`, which yields `0` for an absent slot,
releases a cap past the slots the child reads, and refuses a round whose word is missing, sets a bit
at or above `MSG_CAP_SLOTS_MAX`, or names a different number of caps than the round delivered. The
[`log_sink`](#log_sink) round uses the same encoding. Consumers that tolerate `cap == 0 → skip`
continue to work; consumers that don't fail on first use, which is the right surface for a real
misconfiguration. svctest does both: its `ns` phase skips on a zero cap, and its svcmgr seed-only
and second-seed-round phases fail the run on any unresolved seed (per [services/svctest/README.md §
Run Sequence](../../svctest/README.md#run-sequence)).

Well-known names are centralised in
[`ipc::published_names`](../../../shared/ipc/src/lib.rs). Every name
resolves as a seed; only those marked in the Query column also resolve
through `QUERY_ENDPOINT`, which refuses a seed-only name
([ipc-interface.md § Label 4](ipc-interface.md#label-4-query_endpoint)):

| Name | Publisher | Cap shape | Query |
|---|---|---|---|
| `rootfs.root` | svcmgr (endowed `rootfs.root` SEND) | badged SEND on the root filesystem's namespace endpoint at its root directory (FS-driver-agnostic) | no |
| `pwrmgr.shutdown` | svcmgr (`pwrmgr.svc` provider) | `SHUTDOWN_AUTHORITY`-badged SEND on pwrmgr's service endpoint | no |
| `pwrmgr.deny` | svcmgr (`pwrmgr.svc` provider) | no-authority SEND on pwrmgr's service endpoint (negative-test twin) | yes |
| `timed` | svcmgr (`timed.svc` provider) | un-badged SEND on timed's service endpoint (wall-clock) | yes |
| `svcmgr` | svcmgr (its own service endpoint) | `PUBLISHED_SEND_BADGE`-badged SEND on svcmgr's own service endpoint (no verb-bit) | yes |
| `devmgr.registry` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's registry endpoint | no |
| `devmgr.shutdown` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY \| SHUTDOWN_DEVICE_AUTHORITY`-badged SEND on devmgr's registry endpoint (seeded by pwrmgr only) | no |
| `devmgr.test` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY \| TEST_LABEL_AUTHORITY`-badged SEND on devmgr's registry endpoint (seeded by svctest only; TODO(#165)) | no |
| `devmgr.class.<class>` | svcmgr (a `MINT_CLASS_SEND` reply, one per class file) | class SEND on devmgr's registry endpoint: the badge names the class's slot and the class file's verbs ([Device class files](service-definitions.md#device-class-files)) | no |
| `vfsd.mount` | svcmgr (endowed `MOUNT_AUTHORITY` SEND) | `MOUNT_AUTHORITY`-badged SEND on vfsd's service endpoint (seeded by svctest only) | no |
| `vfsd.deny` | svcmgr (endowed `DENY_BADGE` SEND) | no-authority (`DENY_BADGE`) SEND on vfsd's service endpoint, the negative-test twin (seeded by svctest only) | no |
| `logd.query` | svcmgr (minted from the reserved master-log source) | `LOG_QUERY_AUTHORITY`-badged SEND on the master log endpoint: logd's `QUERY_SLOTS` and `QUERY_HISTORY` ([logd IPC interface](../../logd/docs/ipc-interface.md) § Queries; seeded by svctest only) | no |

## `provides`

Declares the registry names a service's own endpoint is published under.
svcmgr creates a service endpoint, serves its RECV as bootstrap `cap[0]`
(ahead of the `seed` caps), and publishes one SEND per entry. If the RECV
derive fails, on first launch or on a restart, svcmgr destroys the new
child instead of shifting the seeds down into cap[0]. Providers
launch ahead of pure consumers during reconciliation, so a provided name
is resolvable before any consumer queries it. The endpoint persists across
restarts (svcmgr holds the source), so a cached client cap survives a
crash-restart and no re-publish is needed.

Each space-separated entry is `name[:auth|:deny]`; the suffix selects the
badge svcmgr stamps on that name's SEND (the badge rides through to a
consumer unchanged), and a badge carrying a verb bit makes the name
seed-only ([ipc-interface.md § Label 4](ipc-interface.md#label-4-query_endpoint)):

| Suffix | Badge | Use |
|---|---|---|
| *(none)* | `0` (unbadged) | Plain SEND, for an endpoint whose server gates no label on a verb-bit: a consumer can badge an unbadged SEND itself ([Capability Model](../../../docs/capability-model.md#verb-bit-authority-pattern)). e.g. `timed`. |
| `:auth` | `1 << 63` | The first verb bit, the one a server's primary `*_AUTHORITY` gate tests — the server's `badge & (1 << 63)` gate passes. Seed-only: `QUERY_ENDPOINT` refuses the name. e.g. `pwrmgr.shutdown:auth`. |
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
`devmgr.registry` source. The round has five positional slots, carried with a presence word as
[`seed`](#seed) describes, so an absent slot rides as no cap:

| Index | Cap |
|---|---|
| 0 | `RECV` on the master log endpoint |
| 1 | `SEND` on the master log endpoint (single-use; the `HANDOVER_PULL` drain then the terminal `HANDOVER_RELEASE`, then deleted; see the [logd handover protocol](../../logd/docs/handover-protocol.md#call-shape)). Absent on a restart — no init-logd remains to pull from |
| 2 | badged `SEND\|GRANT` on procmgr carrying `DEATH_EQ_AUTHORITY` (logd registers per-sender death-notifications for slot reclaim; see [logd README](../../logd/README.md#bootstrap-caps)) |
| 3 | the `serial` class SEND, derived from the `devmgr.class.serial` publication (logd resolves the serial driver via `QUERY_DEVICE`; see [logd README](../../logd/README.md#bootstrap-caps)) |
| 4 | the `framebuffer` class SEND, derived from the `devmgr.class.framebuffer` publication (logd resolves the framebuffer driver via `QUERY_DEVICE`) |

Because these slots are svcmgr-minted, `seed` and `provides` have no
position in the round; declaring either alongside `log_sink = yes` is a
parser error. The same svcmgr-minted round drives the first launch (`cap[1]`
present, history pulled from init-logd per the
[logd handover protocol](../../logd/docs/handover-protocol.md)). A slot whose source is absent
from the endowment, or whose derive fails, is absent from the round; logd requires only `cap[0]`.
svcmgr holds the master-log source for the system's life, so the round is designed to also
drive every restart (`cap[1]` absent, history pull skipped), each relaunched logd
re-attaching a fresh RECV to the same endpoint object every sender already
targets, with `restart` and `critical` behaving as for any other service;
design intent; not yet implemented (#262). Today, on a logd death svcmgr's
death handler makes `log!` calls on the master-log endpoint with no logd
receiving; each is dropped once its bound expires
([shared/log](../../../shared/log/README.md)), so the handler reaches the
restart and the critical graceful-shutdown path late, not never (per
[restart-protocol.md](restart-protocol.md#supervision-hierarchy)).

```
binary    = /services/logd
restart   = on_failure
critical  = yes
namespace = none
log_sink  = yes
```

## `shutdown_actuator`

`shutdown_actuator = <name>` declares the service the system's shutdown actuator, the one service
that powers the platform off. `<name>` is one entry of the recipe's own [`provides`](#provides)
list and carries `:auth`. When a `critical = yes` service is permanently down, svcmgr derives a
SEND stamped with that entry's badge, the authority bit the actuator's gate tests, from the
actuator's own service endpoint, and calls
[`pwrmgr_labels::SHUTDOWN`](../../../shared/ipc/src/lib.rs), the request label the actuator
serves, through it. It does not resolve `<name>` from the discovery registry, which keeps a
name's first publisher: the registry's entry for `<name>` may be another service's endpoint, or,
when the recipe also lists `<name>:deny` first, the no-authority SEND. svcmgr knows the actuator
only by this key; its code names no service.

The actuator is supervised: the parser rejects the key on a `restart = never` recipe, a name that
is not one of the recipe's `provides` entries, an entry without `:auth`, a value of more than one
name, and a repeated key. Only the first recipe that declares the key, in reconciliation's launch
order, is the actuator; svcmgr logs each later one (`<service> also declares shutdown_actuator; not
recognised`) and launches it as an ordinary service. An actuator whose entry holds no service
endpoint (one init spawned, which svcmgr only binds) is not recorded, and svcmgr logs that
graceful shutdown is unavailable.

svcmgr calls the actuator only while it runs: its entry is active and the kernel reports its
thread not exited. The actuator's service endpoint outlives it, so a call to a dead actuator would
block svcmgr with no receiver to answer. An actuator whose entry is active but whose thread has
exited has a death svcmgr has not yet routed; svcmgr routes it first, so the actuator restarts
under its own `restart` policy or ends down, and then checks again. When no actuator is recorded,
or the recorded one is down (its own permanent death included), svcmgr logs `graceful shutdown
impossible` and the system continues degraded. An actuator that dies during the call still leaves
svcmgr blocked.

```
binary            = /services/pwrmgr
restart           = on_failure
critical          = no
namespace         = none
provides          = pwrmgr.shutdown:auth pwrmgr.deny:deny
seed              = devmgr.shutdown
shutdown_actuator = pwrmgr.shutdown
```

## `debug_authority`

`yes` endows the service with procmgr's debug authority: on its first launch and on every restart,
svcmgr mints a `SEND|GRANT` on procmgr badged `procmgr_labels::DEBUG_AUTHORITY` from the un-badged
procmgr source init endows it, and delivers it in the bootstrap slot after the `seed` caps (after a
`provides` service's own RECV and its seeds; `cap[0]` for a service with neither). A derive that
fails leaves the slot absent. The authority serves procmgr's `REGISTER_CRASH_SERVICE`,
`ATTACH_PROCESS`, `LIST_PROCESSES`, and `DETACH_PROCESS`
([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md) § Crash Endpoint and Debug
Authority); this key is the only path that mints it, so an image whose recipes set it nowhere has
no attach path. A holder declares itself undebuggable to procmgr itself (`DECLARE_NO_DEBUG`), so no
holder attaches to another or to itself. The crash service's recipe, `crashd.svc`, sets it
([services/crashd/README.md](../../crashd/README.md)), as does the GDB stub's template,
`config/svcmgr/debug/gdbstub.svc` ([services/gdbstub/README.md](../../gdbstub/README.md)).

`debug_authority = yes` alongside `log_sink = yes` is a parser error: the log sink's round is
minted from the log-sink sources and has no slot for it.

```
binary          = /services/crashd
restart         = on_failure
critical        = no
namespace       = none
debug_authority = yes
```

## Device class files

devmgr's device classes are configured from class files, not from source. svcmgr reads every
`/config/devmgr/classes/<class>.class` file, shipped from `rootfs/config/devmgr/classes/`, before
it sends `SET_DRIVERS_DIR`. For each file it sends devmgr `devmgr_labels::MINT_CLASS_SEND`, on a
`CLASS_AUTHORITY`-badged derivation of its endowed badge-0 devmgr-registry source, and publishes
the class SEND devmgr replies with seed-only as `devmgr.class.<class>`
(`ipc::published_names::DEVMGR_CLASS_PREFIX`). A service reaches a class only when its `seed`
line names that publication. A file that cannot be read or parsed, or whose class devmgr refuses,
is logged and skipped.

The grammar is the `.svc` grammar: line-oriented `key = value`, `#` comments, an unknown or
repeated key an error. The class name is the file name without `.class`: 1 to
`ipc::devmgr_labels::MAX_CLASS_NAME_BYTES` (32) bytes of `[a-z0-9_-]`. The keys:

| Key | Required | Value |
|---|---|---|
| `verbs` | yes | Space-separated bit positions, each in `ipc::VERB_BIT_MASK` (58 to 63), none repeated: the verb bits a `QUERY_DEVICE` reply through the class SEND carries |
| `boot_only` | no | `yes` or `no` (default `no`): the class's drivers come from the boot bundle only, and devmgr refuses a drivers-directory declaration of the class |

The shipped classes:

| Class | `verbs` | `boot_only` |
|---|---|---|
| `block` | 63 (`blk_labels::MOUNT_AUTHORITY`) | `yes` |
| `serial` | 63 62 (serial `WRITE`, `READ`) | `no` |
| `framebuffer` | 63 (framebuffer `WRITE`) | `no` |
| `rtc` | 63 (rtc `READ`) | `no` |
| `input` | 63 (input `READ`) | `no` |
| `debug-port` | 63 62 (serial `WRITE`, `READ`) | `no` |

init requests the `block` class SEND itself, for vfsd's root mount.

## Reconciliation

At `HANDOVER_COMPLETE` svcmgr scans `/config/svcmgr/services/`, parses each
`<name>.svc`, and reconciles against the pending-registration table
(substrate pairs parked from the handover endowment):

| Definition | Pending registration | Outcome |
|---|---|---|
| present | present | **bind only** — bind death-notification on the endowed thread cap; record the recipe's fixed fields on a `ServiceEntry` and its argv/env/cwd/seed, log-sink flag, and scheduling fields in the parallel `RestartRecipe` table for restart use. |
| present | absent | **launching** — svcmgr launches the service via [`definitions::launch`](../src/definitions/launch.rs): walk `binary`, `CREATE_FROM_FILE` with argv/env, `CONFIGURE_NAMESPACE` with the namespace+cwd, bind death-notification (when `restart != never`, so the observer is in place before the thread runs), `START_PROCESS`, serve the seed bootstrap rounds, and (when `restart != never`) record a `ServiceEntry`. |
| absent | present | **error** — `registered without definition: <name>; refusing to bind`. svcmgr has no recipe; an endowed name without a matching `.svc` is a configuration error. |

Out of memory changes two outcomes. When the scan has no room for the list of parsed recipes, it
launches nothing and releases every pending registration's thread cap: each endowed service runs
on unsupervised, and none is reported as a configuration error. When a **bind only** entry's
`ServiceEntry` or restart recipe cannot be built, svcmgr logs `no memory for <name>'s entry;
running unsupervised` and releases that thread cap; a **launching** entry in the same state is
not launched. A recipe the heap cannot copy at parse time is dropped like a malformed one.

## Relevant Design Documents

| Document | Content |
|---|---|
| [README.md](../README.md) | Component scope, responsibilities, restart policy |
| [ipc-interface.md](ipc-interface.md) | handover endowment, `HANDOVER_COMPLETE`, `PUBLISH_ENDPOINT` / `QUERY_ENDPOINT` |
| [restart-protocol.md](restart-protocol.md) | Restart sequencing, shared spawn primitives, criticality semantics |
| [shared/ipc/src/lib.rs](../../../shared/ipc/src/lib.rs) | `published_names` constants, `svcmgr_labels::*`, `svcmgr_errors::*` |

---

## Summarized By

[Fault Handling](../../../docs/fault-handling.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[services/crashd/README.md](../../crashd/README.md),
[crashd Operation](../../crashd/docs/operation.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[services/logd/README.md](../../logd/README.md),
[logd handover protocol](../../logd/docs/handover-protocol.md),
[logd IPC interface](../../logd/docs/ipc-interface.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md), [services/svcmgr/README.md](../README.md),
[svcmgr IPC Interface](ipc-interface.md), [Restart Protocol](restart-protocol.md),
[services/svctest/README.md](../../svctest/README.md)
