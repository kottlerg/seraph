# Restart Protocol

Crash detection via thread death notifications, restart sequencing,
shared spawn primitives, and criticality handling.

---

## Death detection

svcmgr binds every supervised service's main thread to one shared
EventQueue (`deaths_eq`) via `SYS_THREAD_BIND_NOTIFICATION`, using the
service's table index as the correlator. When a thread exits — either
cleanly via `SYS_THREAD_EXIT` or due to an unhandled fault — the
kernel posts `(correlator << 32) | exit_reason` to `deaths_eq` (per
[syscalls.md](../../../core/kernel/docs/syscalls.md)).

The WaitSet has two members: the service endpoint (badge 0) and the
deaths queue (badge 1). On wakeup svcmgr drains the queue and routes
each payload to its `ServiceEntry` via the correlator, then dispatches
through [`restart::handle_death`](../src/restart.rs).

Exit reason encoding (owned by
[process-lifecycle.md](../../../docs/process-lifecycle.md#exit-reason)), and
how the `on_failure` policy classes each range:

| Value | Meaning | `on_failure` |
|---|---|---|
| `0` (`EXIT_VOLUNTARY`) | Voluntary, clean | not a failure |
| `1 ..= 0x0FFF` | Voluntary, exit code | not a failure |
| `0x1000 ..= 0x1FFF` (`EXIT_FAULT_BASE + vector`) | Fault | failure |
| `0x2000` (`EXIT_KILLED`) | Killed | failure |

---

## Decision tree

[`restart::handle_death`](../src/restart.rs) returns a
[`DeathOutcome`](../src/restart.rs) the dispatch loop routes. Restart is
decided **solely** by the restart policy + budget; `system_critical`
(`critical = yes|no`) is consulted only once a service ends up
permanently down. The two concerns are orthogonal — `restart` owns
*whether/when to respawn*, `critical` owns *can the system survive its
permanent loss* (per [service-definitions.md](service-definitions.md#critical)).

1. **`should_restart(svc, exit_reason)`** evaluates the restart policy:
   * `POLICY_NEVER` → no restart.
   * `POLICY_ON_FAILURE` → restart iff `exit_reason >= EXIT_FAULT_BASE`
     (a fault or `EXIT_KILLED`; voluntary codes do not restart; per
     [service-definitions.md](service-definitions.md#restart)).
   * `POLICY_ALWAYS` → restart unconditionally.
   * The restart-count budget (`MAX_RESTARTS`, currently `1`) is
     enforced here; an exhausted budget reports "max restarts reached,
     marking degraded" and returns false.
   * A missing restart source (`vfs_path_len == 0`) reports
     "no restart source" and returns false.
2. **Restart not permitted** → mark service inactive; route to
   `permanent_death_outcome`:
   * `system_critical` (`critical = yes`, per
     [service-definitions.md](service-definitions.md#critical)) → log
     `critical service unrecoverable: <name>; initiating graceful shutdown`,
     return `Unrecoverable`.
   * Otherwise (`critical = no`) → log `service down: <name>; system
     continues degraded`, return `Degraded`.
3. **Restart permitted** → call `restart_process`:
   * If `process_handle != 0` (svcmgr-launched services), send
     `procmgr_labels::DESTROY_PROCESS` to reclaim the previous
     instance's kernel objects. Init-spawned services start with
     `process_handle == 0`, so the first death cannot destroy;
     subsequent deaths can.
   * Spawn a fresh instance via the shared primitive
     [`walk_and_create_from_file`](#shared-spawn-primitives) (VFS
     path) or `CREATE_PROCESS` with a fresh module-cap derivation,
     replaying the recipe's `argv` / `env` from the stored
     [`RestartRecipe`](../src/service.rs).
   * Re-apply the per-service namespace policy **and `cwd`** via
     [`apply_namespace_policy`](#shared-spawn-primitives).
   * Serve the restart bootstrap round, re-resolving the recipe's
     `seed` names from the discovery registry in declaration order (or,
     for init-endowed services with no seeds, re-deriving the stored
     bundle caps).
   * Rebind death-notification on the new thread cap using the same
     correlator so subsequent crashes route back to the same entry.
   * On success: increment `restart_count`, return `Restarted`.
   * On failure: route through `permanent_death_outcome`.

`dispatch_deaths` reacts to `Unrecoverable` by calling
`initiate_graceful_shutdown`, which resolves
`ipc::published_names::PWRMGR_SHUTDOWN` from svcmgr's discovery
registry and issues `pwrmgr_labels::SHUTDOWN`. Edge case: a
`system_critical` pwrmgr death cannot trigger graceful shutdown
(the shutdown source is itself gone); svcmgr logs the degraded
state and returns (see
[service-definitions.md](service-definitions.md#critical)).

---

## Shared spawn primitives

First-launch ([`definitions::launch`](../src/definitions/launch.rs))
and restart ([`restart::create_process`](../src/restart.rs)) share
the same procmgr-side primitives so a service's spawn shape is
identical across both code paths:

* [`mint_child_creator`](../src/restart.rs) — allocate a fresh
  bootstrap badge + badged SEND on svcmgr's `bootstrap_ep`.
* [`walk_and_create_from_file`](../src/restart.rs) — walk svcmgr's
  universal `root_dir_cap` for the binary path, then call
  `procmgr_labels::CREATE_FROM_FILE` with argv / env blobs. Both paths
  build the blobs from the recipe: launch from the parsed `Definition`,
  restart from the stored [`RestartRecipe`](../src/service.rs).
* [`apply_namespace_policy`](../src/restart.rs) — resolve the namespace
  cap for `NS_POLICY_NONE` / `_UNIVERSAL` / `_SUBTREE`, then hand it (and
  the optional `cwd` cap) to the shared `configure_namespace_caps`. Both
  paths install `cwd` identically; restart pulls it from the
  `RestartRecipe`.
* [`start_process`](../src/restart.rs) — `procmgr_labels::START_PROCESS`.

The launch path is documented in
[service-definitions.md](service-definitions.md#reconciliation). The
`.svc` recipe is the single source of truth for both paths: the fixed
fields are recorded on `ServiceEntry` and the heap-backed surfaces
(argv / env / cwd / seed) on the parallel `RestartRecipe`, so a restart
reproduces the first-launch spawn shape byte-for-byte. The binary path
is re-walked on every spawn, so a binary update on disk is picked up by
the next restart without code changes.

---

## Recipe storage

svcmgr records the parsed `.svc` recipe across two index-aligned tables
at reconciliation time. The fixed-size fields live on `ServiceEntry`:

| Field | Source |
|---|---|
| `name` / `name_len` | `<name>.svc` filename |
| `vfs_path` / `vfs_path_len` | `binary = ...` |
| `restart_policy` | `restart = never \| on_failure \| always` |
| `system_critical` | `critical = yes \| no` |
| `ns_policy_kind` / `ns_subtree_path` / `ns_subtree_rights` | `namespace = ...` |
| `thread_cap` | endowment thread cap (bind-only) or `Launched.thread_cap` (svcmgr-launched) |
| `process_handle` | `Launched.process_handle` for svcmgr-launched; `0` for init-spawned (see DESTROY_PROCESS comment above) |
| `module_cap` | `0` (services restart from their `vfs_path`; no module caps are held) |

The heap-backed launch surfaces that don't fit the fixed record are held
in a parallel [`RestartRecipe`](../src/service.rs) table
(`SvcmgrState.recipes`), index-aligned with `services[]` via the death
correlator:

| Field | Source |
|---|---|
| `argv` | `argv = ...` |
| `env` | `env = ...` |
| `cwd` | `cwd = ...` |
| `seed` | `seed = ...` |

`restart_process` replays all four on every respawn — argv/env into
`CREATE_FROM_FILE`, cwd through `apply_namespace_policy`, and seeds
re-resolved from the discovery registry — so a restarted child comes
back with the same surfaces first launch gave it.

---

## Supervision hierarchy

svcmgr only supervises top-level services. devmgr spawns drivers (serial /
framebuffer / virtio-blk / virtio-input / cmos / goldfish-rtc / future net; per
[devmgr responsibilities](../../devmgr/docs/responsibilities.md#relationship-to-drivers)),
and vfsd spawns filesystem drivers (fatfs / future ext / btrfs); neither observes
a child's death or restarts it (per
[storage.md](../../../docs/storage.md#failure-and-revocation-invariants)).
Supervision of those children by devmgr and vfsd is design intent; not yet
implemented (#17, #262). None of those flow through the handover
endowment.

The set of services svcmgr currently supervises (per the shipped
`.svc` files):

`svctest` and `crasher` are test-tier fixtures: their recipes live in
`/config/svcmgr/tests/` (svcmgr does not scan it) and are staged into
`/config/svcmgr/services/` only for test boots — `crasher` is co-staged
with `svctest` (per [testing.md](../../../docs/testing.md#gating)).
The rest ship in `/config/svcmgr/services/` and load on every boot.

| Service | Source | Restart | Critical |
|---|---|---|---|
| `svctest` | svcmgr-launched (test-tier, staged) | `never` | `no` |
| `crasher` | svcmgr-launched (test-tier, staged) | `always` | `no` |
| `memmgr` | init-endowed (bind only) | `never` | `yes` |
| `procmgr` | init-endowed (bind only) | `never` | `yes` |
| `devmgr` | init-endowed (bind only) | `never` | `yes` |
| `vfsd` | init-endowed (bind only) | `never` | `yes` |
| `logd` | svcmgr-launched (log sink) | `on_failure` | `yes` |
| `timed` | svcmgr-launched (provider) | `on_failure` | `no` |
| `pwrmgr` | svcmgr-launched (provider) | `on_failure` | `no` |

Restart paths for the init-endowed (bind-only) substrate set are
aspirational today: each was spawned with arch-/firmware-authority caps
that init holds and svcmgr cannot re-mint (memmgr/procmgr via raw
`cap_create_*` syscalls; devmgr/vfsd with one-shot authority handover;
per [init bootstrap](../../init/docs/bootstrap.md)). When their `.svc`
`restart` value moves off `never` in the future, the spawn path needs to
gain access to those caps — either via a new init→svcmgr handover round,
or by relocating the spawn entirely into svcmgr.

`timed`, `pwrmgr`, and `logd` are *not* in that set: they are
svcmgr-launched. `timed` and `pwrmgr` are genuinely restartable: they hold no
unique source cap — each re-acquires its authority on (re)start by
querying devmgr (`QUERY_RTC_DEVICE` for timed, per
[timed/README.md](../../timed/README.md); `QUERY_ACPI_TABLE` +
`QUERY_SHUTDOWN_DEVICE` for pwrmgr, per
[pwrmgr/README.md](../../pwrmgr/README.md)), and svcmgr re-serves a fresh
RECV on the persistent service endpoint so cached client caps survive the
restart. `logd` is the log sink: svcmgr holds the master-log endpoint
source for the system's life and mints each (re)launched logd a fresh RECV
on that persistent endpoint, so log senders' caps survive the restart (per
[service-definitions.md](service-definitions.md#log_sink)). A working logd
restart is design intent; not yet implemented (#262). procmgr's
`REGISTER_DEATH_EQ` is first-wins, so a restarted logd's registration is
rejected and it receives no death events for slot eviction; and svcmgr's
death handler emits blocking `log!` calls on the master-log endpoint before
it respawns logd, so with no logd receiving, svcmgr blocks and the restart
never happens.

---

## procmgr Fallback

If procmgr itself crashes, svcmgr cannot use procmgr IPC to restart it.
A raw-syscall fallback that recreates procmgr is design intent; not yet
implemented (#26); svcmgr holds no process-creation capabilities today.
procmgr is `critical = yes`, so its death falls into the graceful-shutdown
path (per
[process-lifecycle.md](../../../docs/process-lifecycle.md#procmgr-restart-fallback)).

---

## Summarized By

[Process Lifecycle](../../../docs/process-lifecycle.md),
[services/crasher/README.md](../../crasher/README.md),
[services/procmgr/README.md](../../procmgr/README.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md), [services/svcmgr/README.md](../README.md),
[svcmgr IPC Interface](ipc-interface.md), [`.svc` Service Definitions](service-definitions.md)
