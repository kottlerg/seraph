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

Line-oriented `key = value`, split by the line grammar of
[`shared/svc-grammar`](../../../shared/svc-grammar/README.md), which svcmgr's definition and class
parsers and devmgr's platform description table parser share. Lines starting with `#` are
comments. Blank lines are tolerated. Whitespace around `=` is tolerated.
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
seed      = rootfs.root pwrmgr.shutdown devmgr.registry devmgr.bind vfsd.mount vfsd.deny
```

## Keys

| Key | Required | Value |
|---|---|---|
| `binary` | yes | Absolute path under svcmgr's root, in the canonical form of [docs/signing.md](../../../docs/signing.md) § Signed Attributes (no empty, `.` or `..` component, no trailing `/`) and at most `procmgr_labels::CREATE_NAME_MAX` (256) bytes, since svcmgr names the binary to procmgr by it and procmgr verifies the image was signed under it; any other path is a parser error. The entry svcmgr restarts from holds it at its own length (see [Restart Protocol](restart-protocol.md#recipe-storage)). Walked from `system_root_cap` at launch / restart. |
| `argv` | no | Space-separated tokens. Becomes NUL-separated, NUL-terminated bytes on the wire. Bounded; see [`argv` / `env`](#argv--env). |
| `env` | no | Space-separated `KEY=VAL` tokens. Same NUL packing and bounds as `argv`. |
| `restart` | yes | One of `never`, `on_failure`, `always`. |
| `critical` | yes | `yes` or `no`. Whether the system is viable without this service once it is permanently down. Orthogonal to `restart`. |
| `namespace` | yes | One of `none`, `universal`, `subtree:<path>:<rights>`. |
| `cwd` | no | Path interpreted relative to svcmgr's universal root; must lie inside the namespace (see [`cwd`](#cwd)). Forbidden when `namespace = none`. |
| `seed` | no | Space-separated discovery-registry names, resolved positionally (cap[i] = i-th name; cap[i+1] for a `provides` service). Any number of names; slots past one bootstrap round's `MSG_CAP_SLOTS_MAX` (4) caps ride in further rounds; see [`seed`](#seed). |
| `provides` | no | Space-separated `name[:auth\|:grant\|:deny]` entries. svcmgr creates this service's endpoint, serves its RECV as bootstrap `cap[0]`, and publishes one badged SEND per entry into the discovery registry. See [`provides`](#provides). |
| `log_sink` | no | `yes` or `no` (default `no`). Marks the service as the system log sink (real-logd); svcmgr mints its bootstrap round from the reserved log-sink sources init endows. Mutually exclusive with `seed` and `provides`. See [`log_sink`](#log_sink). |
| `shutdown_actuator` | no | One name of this recipe's `provides` list, carrying `:auth` (not `:grant`). Declares the service the system's shutdown actuator: svcmgr calls the shutdown request through that name when a `critical = yes` service is permanently down, and serves it a receive-only derivation of svcmgr's own death queue in the bootstrap slot after its `seed` caps and its authority slots. Needs `restart` other than `never`. See [`shutdown_actuator`](#shutdown_actuator). |
| `debug_authority` | no | `yes` or `no` (default `no`). Endows the service with procmgr's debug authority, a `DEBUG_AUTHORITY` `SEND\|GRANT` on procmgr, in the bootstrap slot after its `seed` caps. Mutually exclusive with `log_sink`. See [`debug_authority`](#debug_authority). |
| `stop_authority` | no | `yes` or `no` (default `no`). Endows the service with svcmgr's stop authority, a `STOP_AUTHORITY` SEND on svcmgr's service endpoint, in the bootstrap slot after its `seed` caps and its debug-authority slot. Mutually exclusive with `log_sink`. See [`stop_authority`](#stop_authority). |
| `entropy_authority` | no | `yes` or `no` (default `no`). Endows the service with the kernel's entropy-contribution authority, an `EntropyControl` capability carrying `Contribute`, in the bootstrap slot after its `seed` caps and its debug- and stop-authority slots. One service holds it: the first recipe in launch order that sets it. Mutually exclusive with `log_sink`. A core role. See [`entropy_authority`](#entropy_authority). |
| `stop_source` | no | `program`. Makes the service a stop source of that class: svcmgr creates it contained and lists it, with a stop-badged SEND on its endpoint, to a stop-authority holder. A core role. Needs `provides` with every entry badged, and `restart` other than `never`. See [`stop_source`](#stop_source). |
| `oom_stop` | no | `yes` or `no` (default `no`). Opts the service in to being stopped by a stop-authority holder. Refused, as a parser error, on a recipe the eligibility rule refuses. See [`oom_stop`](#oom_stop). |
| `reserve` | no | `yes` or `no` (default `no`). Creates the service inside memmgr's system reserve. A core role: the eligibility rule never stops it. See [`reserve`](#reserve). |
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
`seraph::log!` sends ([logd IPC interface](../../logd/docs/ipc-interface.md) § Levels). It
reaches only a service svcmgr launches: svcmgr only binds the services init spawns (procmgr,
devmgr, vfsd; § Reconciliation), so an `env` key in their recipes reaches nothing.

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
| `yes` | svcmgr logs `critical service unrecoverable: <name>; initiating graceful shutdown` and issues [`pwrmgr_labels::SHUTDOWN`](../../../shared/ipc/src/pwrmgr_labels.rs) through the [`shutdown_actuator`](#shutdown_actuator). See [restart-protocol.md](restart-protocol.md). |

Because the two fields are independent, any combination is valid — e.g.
`restart = always` + `critical = no` (the `crasher` fixture: respawned on
every fault, but its eventual permanent death is non-fatal).

**The shutdown actuator's own death** is the edge case. pwrmgr, the
actuator, is `restart = on_failure` + `critical = no`: a crashed pwrmgr is
recoverable (svcmgr re-creates it and it re-acquires its actuator authority from
devmgr or acpid — see [services/pwrmgr/README.md](../../pwrmgr/README.md)), and its
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
| `universal` | `cap_copy` of svcmgr's own root (the system universal root). Reserved for services that need genuine root authority. The recipes that declare it are `svctest` (the namespace tester), `usertest`, `sessiond`, and the `stopsrc` test fixture, which resolve and spawn programs; the recipes of the init-bootstrapped substrate services declare `none`, since init, not svcmgr, spawned them. |
| `subtree:<path>:<rights>` | Walk `<path>` from svcmgr's root requesting `<rights>` per hop, hand the resulting directory cap to the child. `<path>` is absolute, names a directory below the root, and is at most `ipc::MAX_PATH_LEN` (4096) bytes; longer is a parser error, and so is a path with no components (`subtree:/`, which no namespace server would attenuate; use `universal`). `<rights>` is a `+`-joined list of rights names (`LOOKUP`, `READDIR`, `STAT`, `READ`, `WRITE`, `EXEC`, `MUTATE_DIR`, `ADMIN` — see [`shared/namespace-protocol/src/rights.rs`](../../../shared/namespace-protocol/src/rights.rs)). Unknown rights names are parser errors. Empty rights list is a parser error. |

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

Space-separated discovery-registry names. svcmgr resolves each name to a freshly-derived
`RIGHTS_EP_SEND` cap on the published endpoint (`RIGHTS_EP_SEND_GRANT` for `devmgr.bind`, whose
`BIND_DRIVERS` moves a directory cap and so needs `GRANT`, and for each [`:grant`](#provides) name)
and injects them positionally into the child's bootstrap rounds:

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
[`ipc::published_names`](../../../shared/ipc/src/published_names.rs). Every name
resolves as a seed; only those marked in the Query column also resolve
through `QUERY_ENDPOINT`, which refuses a seed-only name and never yields `GRANT`
([ipc-interface.md § Label 4](ipc-interface.md#label-4-query_endpoint)):

| Name | Publisher | Cap shape | Query |
|---|---|---|---|
| `rootfs.root` | svcmgr (endowed `rootfs.root` SEND) | badged SEND on vfsd's namespace endpoint at its synthetic root, with full namespace rights: the namespace root, which crosses mounts (derived from init's system-root cap) | no |
| `pwrmgr.shutdown` | svcmgr (`pwrmgr.svc` provider) | `SHUTDOWN_AUTHORITY`-badged SEND on pwrmgr's service endpoint | no |
| `pwrmgr.deny` | svcmgr (`pwrmgr.svc` provider) | no-authority SEND on pwrmgr's service endpoint (negative-test twin) | yes |
| `acpid.power` | svcmgr (`acpid.svc` provider) | `POWER_AUTHORITY`-badged SEND on acpid's service endpoint, gating `SLEEP`, `RESET` and `WAIT_EVENT` (seeded by pwrmgr only) | no |
| `acpid.deny` | svcmgr (`acpid.svc` provider) | no-authority SEND on acpid's service endpoint (negative-test twin) | yes |
| `timed` | svcmgr (`timed.svc` provider) | un-badged SEND on timed's service endpoint (wall-clock) | yes |
| `svcmgr` | svcmgr (its own service endpoint) | `PUBLISHED_SEND_BADGE`-badged SEND on svcmgr's own service endpoint (no verb-bit) | yes |
| `devmgr.registry` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's registry endpoint | no |
| `devmgr.shutdown` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY \| SHUTDOWN_DEVICE_AUTHORITY`-badged SEND on devmgr's registry endpoint (seeded by pwrmgr only) | no |
| `devmgr.bind` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY \| BIND_AUTHORITY`-badged `SEND\|GRANT` on devmgr's registry endpoint, gating `BIND_DRIVERS`, which moves a directory cap (seeded by svctest only) | no |
| `devmgr.acpi` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY \| ACPI_AUTHORITY`-badged SEND on devmgr's registry endpoint, gating the labels acpid calls (seeded by acpid only) | no |
| `devmgr.class.<stem>` | svcmgr (a `MINT_CLASS_SEND` reply, one per class file; `<stem>` is the class file's name without `.class`) | class SEND on devmgr's registry endpoint: the badge names the class's slot and the class file's verbs ([Device class files](service-definitions.md#device-class-files)) | no |
| `vfsd.mount` | svcmgr (endowed `MOUNT_AUTHORITY` SEND) | `MOUNT_AUTHORITY`-badged SEND on vfsd's service endpoint (seeded by svctest and the hotplug-check disk mode) | no |
| `vfsd.deny` | svcmgr (endowed `DENY_BADGE` SEND) | no-authority (`DENY_BADGE`) SEND on vfsd's service endpoint, the negative-test twin (seeded by svctest only) | no |
| `vfsd.swap` | svcmgr (endowed `SWAP_AUTHORITY` SEND) | `SWAP_AUTHORITY`-badged SEND on vfsd's service endpoint, the `GET_SWAP_PARTITION` surface (seeded by the swap service's recipe; by svctest while no swap service exists) | no |
| `sessiond.operator` | svcmgr (`sessiond.svc` provider) | `:grant`-badged `SEND\|GRANT` on sessiond's service endpoint, the operator authority, which carries no stop bit (seeded by terminal and svctest) | no |
| `logd.query` | svcmgr (minted from the reserved master-log source) | `LOG_QUERY_AUTHORITY`-badged SEND on the master log endpoint: logd's `QUERY_SLOTS` and `QUERY_HISTORY` ([logd IPC interface](../../logd/docs/ipc-interface.md) § Queries; seeded by svctest only) | no |

## `provides`

Declares the registry names a service's own endpoint is published under.
svcmgr creates a service endpoint, serves its RECV as bootstrap `cap[0]`
(ahead of the `seed` caps), and publishes one SEND per entry. If the RECV
derive fails, on first launch or on a restart, svcmgr destroys the new
child instead of shifting the seeds down into cap[0]. Providers
launch ahead of pure consumers during reconciliation, and a provider after
each provider whose name it seeds (§ Reconciliation), so a provided name
is resolvable before any service launched in the scan queries it. The endpoint persists across
restarts (svcmgr holds the source), so a cached client cap survives a
crash-restart and no re-publish is needed.

Each space-separated entry is `name[:auth|:grant|:deny]`; the suffix selects the
badge svcmgr stamps on that name's SEND (the badge rides through to a
consumer unchanged), and a badge carrying a verb bit makes the name
seed-only ([ipc-interface.md § Label 4](ipc-interface.md#label-4-query_endpoint)):

| Suffix | Badge | Use |
|---|---|---|
| *(none)* | `0` (unbadged) | Plain SEND, for an endpoint whose server gates no label on a verb-bit: a consumer can badge an unbadged SEND itself ([Capability Model](../../../docs/capability-model.md#verb-bit-authority-pattern)). e.g. `timed`. |
| `:auth` | `1 << 63` | The first verb bit, the one a server's primary `*_AUTHORITY` gate tests — the server's `badge & (1 << 63)` gate passes. Seed-only: `QUERY_ENDPOINT` refuses the name. e.g. `pwrmgr.shutdown:auth`. |
| `:grant` | `1 << 63` | As `:auth`, and svcmgr publishes the SEND with `GRANT`, so each recipe seeding the name receives `SEND\|GRANT` and can move caps to the provider in its calls. Seed-only, as `:auth`, so `QUERY_ENDPOINT` never yields `GRANT`. e.g. `sessiond.operator:grant`. |
| `:deny` | `1` | Present so the cap resolves, but the authority gate fails. The negative-test twin. e.g. `pwrmgr.deny:deny`. |

```
provides = pwrmgr.shutdown:auth pwrmgr.deny:deny
```

A `:grant` name is for a server whose clients hand it capabilities: sessiond's interfaces hand it
each session's end queue, death relay and stdio rings. A seeder of the name can send the provider
any cap it holds, of any type and with any rights, so the provider treats each received cap as
untrusted input: it checks the cap's type and rights (`cap_info`) before it keeps the cap or
forwards it, and deletes a cap it does not keep. The parser refuses a `:grant` entry as the
[`shutdown_actuator`](#shutdown_actuator) name, since the shutdown request moves no cap; a
[`stop_source`](#stop_source) may provide one, since the entry is badged.

## `log_sink`

`yes` marks the service as the system's master log sink — real-logd, the
receive-side owner of the master log endpoint. Exactly one recipe carries
`log_sink = yes`.

A log-sink service's bootstrap round is **not** assembled from `seed` or
`provides`. svcmgr mints it from the reserved log-sink sources init endows
at handover (the master-log endpoint source and the procmgr `SEND|GRANT`
death-auth source — see
[`process-lifecycle.md`](../../../docs/process-lifecycle.md)) and from
its `devmgr.class.serial` and `devmgr.class.framebuffer` publications. The round has five
positional slots, carried with a presence word as
[`seed`](#seed) describes, so an absent slot rides as no cap:

| Index | Cap |
|---|---|
| 0 | `RECV` on the master log endpoint |
| 1 | `SEND` on the master log endpoint (single-use; the `HANDOVER_PULL` drain then the terminal `HANDOVER_RELEASE`, then deleted; see the [logd handover protocol](../../logd/docs/handover-protocol.md#call-shape)). Absent on a restart once an instance has taken all its bootstrap rounds — no init-logd remains to pull from; present on a restart before that ([Restart Protocol § Death detection](restart-protocol.md#death-detection)) |
| 2 | badged `SEND\|GRANT` on procmgr carrying `DEATH_EQ_AUTHORITY` (logd registers per-sender death-notifications for slot reclaim; see [logd README](../../logd/README.md#bootstrap-caps)) |
| 3 | the `serial` class SEND, derived from the `devmgr.class.serial` publication (logd resolves the serial driver via `QUERY_DEVICE`; see [logd README](../../logd/README.md#bootstrap-caps)) |
| 4 | the `framebuffer` class SEND, derived from the `devmgr.class.framebuffer` publication (logd resolves the framebuffer driver via `QUERY_DEVICE`) |

Because these slots are svcmgr-minted, `seed` and `provides` have no
position in the round; declaring either alongside `log_sink = yes` is a
parser error. The same svcmgr-minted round drives the first launch (`cap[1]`
present, history pulled from init-logd per the
[logd handover protocol](../../logd/docs/handover-protocol.md)). A slot whose source is absent
from the endowment or not published (slots 3 and 4 when no class file configured the class), or
whose derive fails, is absent from the round; logd requires only `cap[0]`.
svcmgr holds the master-log source for the system's life, so the round also
drives every restart (`cap[1]` absent and the history pull skipped once an
instance has taken all its bootstrap rounds; present, with the pull, on a
restart before that), each relaunched logd
re-attaching a fresh RECV to the same endpoint object every sender already
targets, with `restart` and `critical` behaving as for any other service. On a
`log_sink` service's death svcmgr writes no line before the respawn, since no
logd receives until then, and writes the death's lines once the new instance
runs ([restart-protocol.md](restart-protocol.md#supervision-hierarchy)). The
one exception is a first launch that dies before its bootstrap request, whose
`died during its bootstrap` line svcmgr writes at once, since init-logd still
receives on the endpoint then ([restart-protocol.md](restart-protocol.md#death-detection)).

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
[`pwrmgr_labels::SHUTDOWN`](../../../shared/ipc/src/pwrmgr_labels.rs), the request label the
actuator serves, through it. It does not resolve `<name>` from the discovery registry, which keeps a
name's first publisher: the registry's entry for `<name>` may be another service's endpoint, or,
when the recipe also lists `<name>:deny` first, the no-authority SEND. svcmgr knows the actuator
only by this key; its code names no service.

The actuator is supervised: the parser rejects the key on a `restart = never` recipe, a name that
is not one of the recipe's `provides` entries, an entry without `:auth` (a `:grant` entry among
them), a value of more than one name, and a repeated key. Only the first recipe that declares the
key, in reconciliation's launch order, is the actuator; svcmgr logs each later one (`<service> also
declares shutdown_actuator; not recognised`) and launches it as an ordinary service. An actuator
whose entry holds no service endpoint (one init spawned, which svcmgr only binds) is not recorded,
and svcmgr logs that graceful shutdown is unavailable.

svcmgr calls the actuator only while it runs: its entry is active and the kernel reports its
thread not exited. The actuator's service endpoint outlives it, so a call to a dead actuator would
block svcmgr with no receiver to answer. An actuator whose entry is active but whose thread has
exited has a death svcmgr has not yet routed; svcmgr routes it first, so the actuator restarts
under its own `restart` policy or ends down, and then checks again. When no actuator is recorded,
or the recorded one is down (its own permanent death included), svcmgr logs `graceful shutdown
impossible` and the system continues degraded. An actuator that dies during the call still leaves
svcmgr blocked.

svcmgr also serves the recognised actuator the means to observe svcmgr's own death
([Supervision § Observing svcmgr](../../../docs/supervision.md#observing-svcmgr)): on its first
launch and on every restart, a derivation carrying only the receive right of the event queue
svcmgr's own main thread and address space post their death to, in the bootstrap slot after the
`seed` caps and after any debug-authority and stop-authority slots (`cap[3]` for pwrmgr). A derive
that fails, or a queue svcmgr could not make, leaves the slot absent. A recipe that declares the
key but is not recognised gets no such slot.

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

## `stop_authority`

`yes` endows the service with svcmgr's stop authority: on its first launch and on every restart,
svcmgr mints a SEND on its own service endpoint badged `stop_labels::STOP_AUTHORITY` and delivers
it in the bootstrap slot after the `seed` caps and, for a `debug_authority = yes` service, after
the debug-authority slot. A derive that fails leaves the slot absent. The authority serves
svcmgr's `STOP_CANDIDATE`, `LIST_CANDIDATES` and `LIST_STOP_SOURCES`
([ipc-interface.md § Stop authority](ipc-interface.md#stop-authority)): the holder learns which
services it may stop, with each one's memory usage, and has svcmgr stop one, and it learns the
[stop sources](#stop_source), each reached through a SEND svcmgr derives for it. svcmgr does the
stopping, through the process handle it holds as the service's creator, so the holder never holds
a kill authority, and stops only what the [`oom_stop`](#oom_stop) rule allows. This key is the only
path that mints the cap.

`stop_authority = yes` alongside `log_sink = yes` is a parser error, as for `debug_authority`. A
holder has a core role, so no holder stops another or itself. A one-shot holder
(`restart = never`) is allowed: svctest's recipe sets the key.

## `entropy_authority`

`yes` endows the service with the kernel's entropy-contribution authority: on its first launch
and on every restart, svcmgr derives a copy of the `EntropyControl` source init endows it
([ipc-interface.md § Handover endowment](ipc-interface.md#handover-endowment-bootstrap-rounds)),
carrying `Contribute`, the type's one right, and delivers it in the bootstrap slot after the `seed`
caps and, for a service that sets them, after the debug-authority and stop-authority slots. A
source init could not endow, or a derive that fails, leaves the slot absent. The capability
serves `SYS_ENTROPY_CONTRIBUTE`, which mixes bytes into the kernel pool with no entropy credit
([docs/capability-model.md § `EntropyControl`](../../../docs/capability-model.md#entropycontrol));
this key is the only path that delivers it, and svcmgr never publishes the source.

One service holds the authority. svcmgr keeps the key on the first recipe that sets it in launch
order (`svcmgr_defs::keep_one_entropy_holder`) and clears it on every later one, which it launches
without the capability and logs (`<name> also declares entropy_authority; not given`). The
default image's holder is entropyd ([services/entropyd/README.md](../../entropyd/README.md)).

`entropy_authority = yes` alongside `log_sink = yes` is a parser error, as for `debug_authority`.
The key is a core role, so the [`oom_stop`](#oom_stop) rule never stops the holder.

```
binary            = /services/entropyd
restart           = on_failure
critical          = no
namespace         = none
seed              = devmgr.class.hwrng
entropy_authority = yes
```

## `stop_source`

`program` makes the service a stop source of the program class
([Session Supervision § Stop Sources](../../../docs/session-supervision.md#stop-sources)): a
service that holds kill authority over a set of processes and offers a stop-authority holder the
stop of them. It serves the shared stop labels (`ipc::stop_labels`) on its service endpoint, on a
badge carrying `stop_labels::STOP_AUTHORITY`. While an instance runs, svcmgr lists it in
`LIST_STOP_SOURCES` ([ipc-interface.md § Label 7](ipc-interface.md#label-7-list_stop_sources))
with the class this key names and a SEND on that endpoint badged with the stop bit. The class is
read from the recipe, never from the source, so a source cannot claim the service class to delay
its own stop. `program` is the one value; any other is a parser error. sessiond's recipe sets it,
the default image's program-class source
([services/sessiond/README.md](../../sessiond/README.md)); the `stopsrc` test fixture's does
too ([services/stopsrc/README.md](../../stopsrc/README.md)).

The key is a core role, so the [`oom_stop`](#oom_stop) rule never stops a source and
`LIST_CANDIDATES` never lists one. The parser rejects it on a recipe without `provides`, since a
source is reached on its service endpoint; on one with a bare `provides` entry, since a bare entry
publishes an unbadged SEND, from which any holder could derive a SEND badged with the stop bit, so
every entry carries `:auth`, `:grant` or `:deny`; and with `restart = never`, since svcmgr lists
only a source it supervises.

svcmgr creates each instance of a source contained, on its launch and on every restart
(`procmgr_labels::CREATE_CONTAIN`,
[procmgr IPC Interface § Process Tree](../../procmgr/docs/ipc-interface.md#process-tree)): when the
instance ends, procmgr destroys what is left of its subtree, so no process the source started
outlives it, a candidate it listed is gone with it, and its next instance starts with none.

```
binary      = /tests/stopsrc
restart     = always
critical    = no
namespace   = universal
provides    = stopsrc.ctl:deny
stop_source = program
```

## `oom_stop`

`yes` opts the service in to being stopped by a [`stop_authority`](#stop_authority) holder, and
makes svcmgr ask procmgr for a node handle to the service's memory budget node at each create
(`CREATE_NODE_HANDLE`), through which `LIST_CANDIDATES` reads its usage. Opting in is not enough:
svcmgr stops a service only when this rule, `svcmgr_defs::stop::stop_refusal`, allows it,
refusing for the first row that applies:

| Row | The service | Refused because |
|---|---|---|
| 1 | was started by init (memmgr, procmgr, devmgr, vfsd), so svcmgr only binds it | not launched by svcmgr |
| 2 | has `restart = never`, so svcmgr does not supervise it | one-shot |
| 3 | has `critical = yes` | the system is not viable without it |
| 4 | holds a core role: `log_sink`, `debug_authority`, `stop_authority`, `entropy_authority`, `reserve`, `shutdown_actuator` or `stop_source` | the system's log, crash reporting, stopping, shutdown and entropy contribution rest on it |
| 5 | does not set `oom_stop = yes` | not opted in |

Eligibility is read from the recipe's keys alone, never from the service's name. The parser
applies the same rule to a recipe that sets `oom_stop = yes`, as a service svcmgr launches, and
rejects one the rule refuses (`oom_stop = yes` with `restart = never`, `critical = yes`, or a
core role), naming the reason, so an opt-in that could never take effect is an error where it is
written. A recipe of a service init starts that sets the key parses, and svcmgr refuses its stop.

A stop is routed as the death `EXIT_KILLED` through the service's restart policy and budget, so
an `on_failure` or `always` service restarts while its budget lasts
([Restart Protocol](restart-protocol.md)).

```
binary    = /tests/crasher
argv      = crasher worker-fault
restart   = on_failure
critical  = no
namespace = none
provides  = crasher.worker
oom_stop  = yes
```

## `reserve`

`yes` creates the service inside memmgr's system reserve: svcmgr sets procmgr's
`CREATE_RESERVE` on each create, so the service's budget node is a reserve node, which may take
the free pages memmgr keeps in reserve
([memmgr Memory Pool § Distribution policy](../../memmgr/docs/memory-pool.md#distribution-policy);
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md) § Messages, **Memory max and
reserve**). procmgr honours the flag because svcmgr's own node is a reserve node. Without the key
a service svcmgr launches is outside the reserve. The key acts on svcmgr's creates only: a service
init starts is placed by init, and init's children (devmgr, vfsd and svcmgr) are reserve nodes
without it. A reserve service has a core role, so no stop-authority holder stops it.

A service is a reserve service when it acts to end a memory-pressure episode, or when a reserve
service calls it on that path: outside the reserve, a first touch of its heap or stack while the
free pool is at the reserve is declined and kills it, and svcmgr's create of its next instance is
refused while the pool stays there. svcmgr makes that create once, so the service stays down, and a
`critical = yes` one shuts the system down
([Restart Protocol § Decision tree](restart-protocol.md#decision-tree)).
Four recipes of the default image set the key. oomd's lists and stops
services ([services/oomd/docs/operation.md](../../oomd/docs/operation.md)), sessiond's lists and
stops sessions and jobs ([docs/session-supervision.md](../../../docs/session-supervision.md)),
crashd's reports, holds and dumps a fault memmgr declined for want of memory
([services/crashd/docs/operation.md](../../crashd/docs/operation.md) § Hold), and logd's
receives the lines each of the three writes with a synchronous call
([services/logd/README.md](../../logd/README.md)). With logd in the reserve, every
`critical = yes` service is a reserve node.

## Device class files

devmgr's device classes are configured from class files, not from source. svcmgr reads every
`/config/devmgr/classes/<class>.class` file, shipped from `rootfs/config/devmgr/classes/`, before
it sends `SET_DRIVERS_DIR`. For each file it sends devmgr `devmgr_labels::MINT_CLASS_SEND`, on a
`CLASS_AUTHORITY`-badged derivation of its endowed badge-0 devmgr-registry source, and publishes
the class SEND devmgr replies with seed-only as `devmgr.class.<stem>`, `<stem>` being the file
name without `.class` (`ipc::published_names::DEVMGR_CLASS_PREFIX`). A service reaches a class
only when its `seed` line names that publication. A file that cannot be read or parsed, or whose
class devmgr refuses, is logged and skipped. The files are read through vfsd and the classes
minted by devmgr, and either found dead ends the pass
([restart-protocol.md § Death detection](restart-protocol.md#death-detection)).

The grammar is the `.svc` grammar: line-oriented `key = value`, `#` comments, an unknown or
repeated key an error. The class name is the `class` key, or the file stem (the file name without
`.class`) when the key is absent: 1 to `ipc::devmgr_labels::MAX_CLASS_NAME_BYTES` (32) bytes of
`[a-z0-9_-]`. A second file may name an existing class with its own `verbs`, and publishes a
differently attenuated SEND on that class under its own stem: `serial-deny.class`
(`class = serial`, `verbs = 58`) publishes `devmgr.class.serial-deny`. The keys:

| Key | Required | Value |
|---|---|---|
| `class` | no | The class name (default the file stem) |
| `verbs` | yes | Space-separated bit positions, each in `ipc::VERB_BIT_MASK` (58 to 63), none repeated: the verb bits a `QUERY_DEVICE` reply through the class SEND carries |

The shipped classes:

| Class | `verbs` |
|---|---|
| `block` | 63 (`blk_labels::MOUNT_AUTHORITY`) |
| `serial` | 63 62 (serial `WRITE`, `READ`) |
| `framebuffer` | 63 (framebuffer `WRITE`) |
| `rtc` | 63 (rtc `READ`) |
| `input` | 63 (input `READ`) |
| `debug-port` | 63 62 (serial `WRITE`, `READ`) |

init requests the `block` class SEND itself, for vfsd's root mount.

## Reconciliation

At `HANDOVER_COMPLETE` svcmgr scans `/config/svcmgr/services/`, parses each
`<name>.svc`, and reconciles against the pending-registration table
(substrate triples parked from the handover endowment):

| Definition | Pending registration | Outcome |
|---|---|---|
| present | present | **bind only** — bind both death observers through the endowed thread cap and observer cap; record the recipe's fixed fields on a `ServiceEntry` and its argv/env/cwd/seed, log-sink, debug-authority, stop-authority, entropy-authority, `oom_stop` and `reserve` flags, `stop_source` class, and scheduling fields in the parallel `RestartRecipe` table for restart use. |
| present | absent | **launching** — svcmgr launches the service via [`definitions::launch`](../src/definitions/launch.rs): walk `binary`, `CREATE_FROM_FILE` with argv/env, the scheduling fields and the create flags `reserve`, `oom_stop` and `stop_source` ask for (`CREATE_RESERVE`, `CREATE_NODE_HANDLE`, `CREATE_CONTAIN`), `CONFIGURE_NAMESPACE` with the namespace+cwd, bind both death observers (when `restart != never`, so they are in place before the thread runs), `START_PROCESS`, serve the seed bootstrap rounds, and (when `restart != never`) record a `ServiceEntry`. |
| absent | present | **error** — `registered without definition: <name>; refusing to bind`. svcmgr has no recipe; an endowed name without a matching `.svc` is a configuration error. |

svcmgr launches the **launching** entries in launch order, which
`svcmgr_defs::launch_order` computes over every parsed recipe: providers (a non-empty
`provides`) ahead of pure consumers, each group in service-name order, and among the providers
each one after every provider whose name it seeds. svcmgr publishes a provided name only once
its provider has launched, so this order is what lets one provider seed another's name: pwrmgr
seeds `acpid.power`, so acpid launches first. A seed naming a name no recipe provides orders
nothing. When providers seed each other in a cycle, the first of them in name order is placed
first, which svcmgr logs (`<name> is in a seed cycle; launched before a provider it seeds from`),
and its seeds of the others' names resolve to nothing at its launch.

The order promises only which launch is attempted first, within the one scan:

- A provider launches whether or not the launch of a provider it seeds from succeeded; the seed
  of a provider whose launch failed is unresolved at its launch, as any unresolved seed is.
- A **bind only** service, which init already launched, is not launched again, so its place in
  the order does nothing.
- A restarted service's seeds are resolved again at its restart, from what the registry then
  holds; a provider's endpoint, and so its published names, outlive its restarts.

Out of memory changes two outcomes. When the scan has no room for the list of parsed recipes, it
launches nothing and releases every pending registration's thread cap: each endowed service runs
on unsupervised, and none is reported as a configuration error. When a **bind only** entry's
`ServiceEntry` or restart recipe cannot be built, svcmgr logs `no memory for <name>'s entry;
running unsupervised` and releases that thread cap; a **launching** entry in the same state is
not launched. A recipe the heap cannot copy at parse time is dropped like a malformed one.

A vfsd found dead before or during the scan, which reads through vfsd, ends reconciliation as a
scan with no room for the parsed list does: nothing is recorded or launched, every pending
registration is released, and svcmgr routes vfsd's death as system death
([restart-protocol.md § Death detection](restart-protocol.md#death-detection)).

## Relevant Design Documents

| Document | Content |
|---|---|
| [README.md](../README.md) | Component scope, responsibilities, restart policy |
| [ipc-interface.md](ipc-interface.md) | handover endowment, `HANDOVER_COMPLETE`, `PUBLISH_ENDPOINT` / `QUERY_ENDPOINT`, `STOP_CANDIDATE` / `LIST_CANDIDATES` / `LIST_STOP_SOURCES` |
| [restart-protocol.md](restart-protocol.md) | Restart sequencing, shared spawn primitives, criticality semantics |
| [shared/ipc/src/published_names.rs](../../../shared/ipc/src/published_names.rs) | `published_names` constants |
| [shared/ipc/src/svcmgr_labels.rs](../../../shared/ipc/src/svcmgr_labels.rs) | `svcmgr_labels::*` |
| [shared/ipc/src/svcmgr_errors.rs](../../../shared/ipc/src/svcmgr_errors.rs) | `svcmgr_errors::*` |
| [shared/ipc/src/stop_labels.rs](../../../shared/ipc/src/stop_labels.rs) | `stop_labels::*` |

---

## Summarized By

[Fault Handling](../../../docs/fault-handling.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[Session Supervision](../../../docs/session-supervision.md),
[services/crashd/README.md](../../crashd/README.md),
[crashd Operation](../../crashd/docs/operation.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[services/logd/README.md](../../logd/README.md),
[logd handover protocol](../../logd/docs/handover-protocol.md),
[logd IPC interface](../../logd/docs/ipc-interface.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md), [services/svcmgr/README.md](../README.md),
[svcmgr IPC Interface](ipc-interface.md), [Restart Protocol](restart-protocol.md),
[services/svctest/README.md](../../svctest/README.md)
