# Restart Protocol

Crash detection via thread death notifications, restart sequencing,
shared spawn primitives, and criticality handling.

---

## Death detection

svcmgr binds two death observers for every supervised service instance, both
on its death EventQueues and both with the instance's `DeathTag` as the
correlator, `(instance << 32) | slot` ([`svc-defs`](../svc-defs/src/death_tag.rs)):
the slot is the service's table index, and the instance is `0` for the first
and one more for each restart. One observer is on the main thread
(`SYS_THREAD_BIND_NOTIFICATION`): when that thread exits, cleanly via
`SYS_THREAD_EXIT` or on an unhandled fault, the kernel posts the death entry
`(exit_reason, correlator)` to its queue (per
[syscalls.md](../../../core/kernel/docs/syscalls.md)). The other is on the
address space, and the first terminal fault of any of its threads posts it.
procmgr's teardown of the process stops the main thread without a post and
revokes svcmgr's thread cap, so the address-space observer is the one that
reports a fault of another thread. svcmgr binds the address-space observer
as follows:

- For a service svcmgr launches or restarts, procmgr binds it:
  `BIND_DEATH_OBSERVER` (procmgr label 25) on the process handle, with a `POST`
  copy of a svcmgr death queue. Both binds happen before `START_PROCESS`.
- For memmgr and procmgr, which init creates by raw syscalls, svcmgr binds it
  itself with `SYS_ASPACE_BIND_NOTIFICATION` (`DeathSet::bind_aspace`), through a
  Control-only address-space cap the handover endowment delivers, which the
  entry keeps (`ServiceEntry.aspace_cap`).
- For devmgr and vfsd, which init creates through procmgr, svcmgr sends
  `BIND_DEATH_OBSERVER` on the process handle the handover endowment delivers,
  which the entry keeps (`ServiceEntry.process_handle`).

A bind takes one death-observer node from its queue's pool, fixed when the
queue is created, so svcmgr keeps a growable set of queues: a bind tries the
newest queue first, then the older ones, and only when every queue is out of
nodes creates a further queue, funded from svcmgr's own memory, with twice
the last pool (4 nodes first, below the two each of a boot's seven supervised
and adopted services takes, so every boot grows the set; up to
`EVENT_QUEUE_MAX_CAPACITY`). A
further queue is one contiguous grant from memmgr; when memmgr refuses it,
svcmgr retries at half the pool, down to the first pool's size. A bind that
still fails fails the launch or restart. An adoption records the service all
the same, so a death no observer reports is found by a resync (§ Death
detection).

The WaitSet holds the service endpoint (badge 0) and every death queue
(badge 1), and svcmgr's death-queue set (`DeathSet`, the
[`shared/death-set`](../../../shared/death-set/README.md) crate, sized by
[`src/death_queues.rs`](../src/death_queues.rs)) owns it: it starts with
room for two members, and when the queues fill it, svcmgr creates one with
twice the members, up to `WAIT_SET_MAX_MEMBERS` (1024), moves every member
across, and deletes the old one; the event loop waits on whichever is
current, and every boot widens it once its queues pass the first. The kernel
queues a member that is already ready when it is added, so the move loses no
pending request or death post. A deleted sub-page wait set's bytes return to
the runtime's pooled object-slab page; a page-sized set's (32 members or
more) dedicated grant returns to memmgr through
`std::os::seraph::object_slab_release`. Up to 1023 queues hold more nodes
than svcmgr's `CSpace` has slots. On wakeup svcmgr drains every queue and
routes each payload to its `ServiceEntry` via the correlator, then
dispatches through [`restart::handle_death`](../src/restart.rs). The service
table grows on the heap and never reuses a slot, so a slot names one
service for svcmgr's lifetime. `route_death` routes a post only when the
slot is active and the tag's instance is the slot's current one, and the exit
reason is the post's. Any other post is dropped: a late post of an instance
already routed, and the second of the two posts a main-thread fault makes when
it is the address space's first terminal fault.

Each death queue has a fixed tuning capacity (`DEATHS_EQ_CAPACITY`, 64),
not one sized from the service count. The kernel drops a post to a full
queue, so a drain that takes a full queue's worth of events or more from one
queue resyncs: it routes a death for every active service whose main thread the kernel reports
exited (the kernel's reason), whose thread cap no longer resolves (`EXIT_KILLED`: procmgr's teardown
revokes it), or whose endowed address space has a retained terminal fault
(`CAP_INFO_ASPACE_TERMINAL_FAULT`). A dropped post leaves a full queue of events behind it for that
drain or the next, so the resync runs after the drop.

A worker-thread fault of a service procmgr created shows in svcmgr's caps only once procmgr's
teardown revokes the thread cap, which can follow the resync. So the resync then asks procmgr
about each such service its caps show alive, through its process handle
(`procmgr_labels::QUERY_PROCESS`): procmgr reads the space's retained terminal fault and answers
`EXITED` with it before it reaps the process. The query runs only while memmgr and procmgr are
active and alive, since it blocks until procmgr answers.

Reconciliation records a devmgr that died before its bind, or a vfsd that died after the recipe
scan, with the thread cap init endowed, and a resync right after reconciliation routes its death
(`EXIT_KILLED` for a revoked cap).

svcmgr calls vfsd and devmgr before reconciliation records them. vfsd serves svcmgr's namespace
root: before the handover svcmgr reads the device class files and walks the drivers directory
through it, and at the handover it reads the recipe directory. devmgr mints each device class and
takes `SET_DRIVERS_DIR` before the handover, through the endowed devmgr-registry source. A call to
a dead server waits for good, since svcmgr's own capability keeps the endpoint alive with none of
its receivers left. So svcmgr reads a server's liveness from its substrate registration before
each step that calls it and after every call to it that fails
([`src/endowed_servers.rs`](../src/endowed_servers.rs)): the state of the endowed thread cap
(`EXIT_KILLED` for a revoked one), then, while memmgr and procmgr show alive, `QUERY_PROCESS` on
the endowed process handle, which reports a worker-thread fault procmgr has not yet torn down. A
dead server ends the step. A dead devmgr is then recorded by reconciliation, and the resync after
it routes its death, as above. A dead vfsd found at the handover, before or during the recipe
scan, is system death with no recipe to supervise by: svcmgr records and launches nothing,
releases every substrate registration (each such service runs on unsupervised, logged), and takes
the graceful shutdown path, which, with no shutdown actuator recorded, logs the degraded state
(§ Decision tree). A server that dies after a check, while svcmgr's next call to it waits
unreceived, still leaves svcmgr blocked (#1185).

Exit reason encoding (owned by
[process-lifecycle.md](../../../docs/process-lifecycle.md#exit-reason)), and
how the `on_failure` policy classes each range:

| Value | Meaning | `on_failure` |
|---|---|---|
| `0` (`EXIT_VOLUNTARY`) | Voluntary, clean | not a failure |
| `1 ..= 0x0FFF` | Voluntary, exit code | not a failure |
| `0x1000 ..= 0x1FFF` (`EXIT_FAULT_BASE + vector`) | Fault | failure |
| `0x2000` (`EXIT_KILLED`) | Killed | failure |

A stop svcmgr makes for a stop-authority holder
([ipc-interface.md § Label 5](ipc-interface.md#label-5-stop_candidate)) is not posted by the kernel:
svcmgr destroys the instance through procmgr, then routes the death itself as `EXIT_KILLED`
under the instance's tag, so it takes this decision tree as a crash does. A post of the destroyed
instance that arrives after it names the old instance and is dropped.

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
   * A missing restart source (an empty `vfs_path`) reports
     "no restart source" and returns false.
   * The windowed restart budget (`svcmgr_defs::RestartBudget`) is
     charged here: at most `RESTART_BURST` (3) restarts within one
     `RESTART_WINDOW_NS` (60 s) window, the window opening at the first
     restart after the previous one has passed. A spent window reports
     "restart budget spent for this window" and returns false
     (`permanent_death_outcome` then logs the outcome); a service that
     crashes less often than the budget allows restarts every time.
2. **Restart not permitted** → mark service inactive; route to
   `permanent_death_outcome`:
   * `system_critical` (`critical = yes`, per
     [service-definitions.md](service-definitions.md#critical)) → log
     `critical service unrecoverable: <name>; initiating graceful shutdown`,
     return `Unrecoverable`.
   * Otherwise (`critical = no`) → log `service down: <name>; system
     continues degraded`, return `Degraded`.
3. **Restart permitted** → call `restart_process`:
   * If `process_handle != 0`, send `procmgr_labels::DESTROY_PROCESS` to
     reclaim the previous instance's kernel objects. Every service
     procmgr created has a handle, including devmgr and vfsd, whose handles
     init endows; memmgr and procmgr, which init creates by raw syscalls,
     have `process_handle == 0`.
   * Delete the dead instance's `thread_cap` and `aspace_cap`, svcmgr's
     references to the exited thread and its address space.
   * Spawn a fresh instance via the shared primitive
     [`walk_and_create_from_file`](#shared-spawn-primitives) (VFS
     path), replaying the recipe's `argv` / `env` from the stored
     [`RestartRecipe`](../src/service.rs).
   * Re-apply the per-service namespace policy **and `cwd`** via
     [`apply_namespace_policy`](#shared-spawn-primitives).
   * Bind both death observers of the new instance (`bind_instance_observers`)
     under the same slot and the next instance, so subsequent crashes route
     back to the same entry and a late post of the dead instance is dropped.
   * Start the child via [`start_process`](#shared-spawn-primitives)
     (`START_PROCESS`).
   * Serve the restart bootstrap rounds, re-resolving the recipe's
     `seed` names from the discovery registry in declaration order.
   * On success: increment `restart_count` (a lifetime count for the
     restart log line), return `Restarted`.
   * On failure: any failure after `CREATE_FROM_FILE` destroys the new
     child via `DESTROY_PROCESS`, as first launch does; then route
     through `permanent_death_outcome`. A create whose reply caps never
     reach svcmgr needs no destroy: when the reply's cap transfer into
     svcmgr's CSpace fails, svcmgr receives `IPC_REPLY_TRANSFER_FAILED`
     with no process handle, and procmgr destroys the child it created
     (see the [procmgr IPC interface](../../procmgr/docs/ipc-interface.md)
     § Label 1), on first launch and on restart alike.

`route_death` reacts to `Unrecoverable` by calling
`initiate_graceful_shutdown`, which derives a SEND from the service
endpoint of the shutdown actuator, the service whose recipe declares
[`shutdown_actuator`](service-definitions.md#shutdown_actuator), stamped
with the badge of the `:auth` name it declares, and issues
`pwrmgr_labels::SHUTDOWN` through it. An actuator whose entry is active but
whose current instance the kernel shows dead has its own death routed first, so it restarts or
ends down before svcmgr calls it. Edge case: with no actuator recorded, or
the actuator not running (its entry inactive, its own permanent death
included), graceful shutdown is impossible; svcmgr logs the degraded state
and returns without calling (see
[service-definitions.md](service-definitions.md#critical)).

---

## Shared spawn primitives

First-launch ([`definitions::launch`](../src/definitions/launch.rs))
and restart ([`restart::create_process`](../src/restart.rs)) share
the procmgr-side primitives below so a service's spawn shape is
identical across both code paths:

* [`mint_child_creator`](../src/restart.rs) — allocate a fresh
  bootstrap badge + badged SEND on svcmgr's `bootstrap_ep`.
* [`walk_and_create_from_file`](../src/restart.rs) — walk svcmgr's
  universal `root_dir_cap` for the binary path, then call
  `procmgr_labels::CREATE_FROM_FILE`, naming the binary by that path for
  procmgr's verification, with argv / env blobs in an argv/env Memory
  cap (`std::os::seraph::process::ArgvEnvCap`). Both paths build the
  blobs from the recipe: launch from the parsed `Definition`, restart
  from the stored [`RestartRecipe`](../src/service.rs). Before minting
  any cap the primitive returns `None` (logged) when it cannot build
  that cap: blobs past the argv/env region, a backstop behind the
  parser's `TooLarge` rejection, or a run memmgr will not fund; on
  restart that `None` fails the attempt and is routed through
  `permanent_death_outcome`.
* [`configure_namespace_caps`](../src/restart.rs) — walk the optional
  `cwd` from svcmgr's universal root, then install the namespace cap and
  the `cwd` cap on the child via `procmgr_labels::CONFIGURE_NAMESPACE`.
  Each path resolves the namespace cap itself and feeds it in: launch
  from the parsed `Definition` (`definitions::launch`'s
  `configure_namespace`), restart through
  [`apply_namespace_policy`](../src/restart.rs), which resolves it for
  `NS_POLICY_UNIVERSAL` / `_SUBTREE` from the `ServiceEntry` and takes
  `cwd` from the `RestartRecipe`. Both paths install `cwd` identically,
  and neither sends `CONFIGURE_NAMESPACE` for a `namespace = none`
  service.
* [`start_process`](../src/restart.rs) — `procmgr_labels::START_PROCESS`.

The launch path is documented in
[service-definitions.md](service-definitions.md#reconciliation). The
`.svc` recipe is the single source of truth for both paths: the fixed
fields are recorded on `ServiceEntry` and the argv / env / cwd / seed,
the log-sink, debug-authority, stop-authority, `oom_stop` and `reserve`
flags, and the scheduling fields on the parallel `RestartRecipe`, so
a restart reproduces the first-launch spawn shape byte-for-byte, except the
log-sink round, whose history-pull SEND is absent on a restart (per
[service-definitions.md](service-definitions.md#log_sink)). The binary path
is re-walked on every spawn, so a binary update on disk is picked up by
the next restart without code changes.

---

## Recipe storage

svcmgr records the parsed `.svc` recipe across two index-aligned heap
tables at reconciliation time. The recipe-derived fields live on
`ServiceEntry` (which also carries the runtime state `restart_count`,
`restart_budget`, `active`, `bootstrap_badge`, and `provided_endpoint`), each
string at its own length:

| Field | Source |
|---|---|
| `name` | `<name>.svc` filename |
| `vfs_path` | `binary = ...` |
| `restart_policy` | `restart = never \| on_failure \| always` |
| `system_critical` | `critical = yes \| no` |
| `ns_policy_kind` / `ns_subtree_path` / `ns_subtree_rights` | `namespace = ...` |
| `thread_cap` | endowment thread cap (bind-only) or `Launched.thread_cap` (svcmgr-launched) |
| `process_handle` | `Launched.process_handle` for svcmgr-launched; the endowed process handle for devmgr and vfsd; `0` for memmgr and procmgr (see DESTROY_PROCESS above) |
| `aspace_cap` | the endowed Control-only address-space cap for memmgr and procmgr; `0` otherwise |
| `instance` | the death-tag instance: `0` for the first, one more per restart |
| `launched` | `true` when svcmgr launched the service from its recipe, `false` for a service init started; read by the stop eligibility rule ([service-definitions.md § `oom_stop`](service-definitions.md#oom_stop)) |
| `node_handle` | for an `oom_stop = yes` service, the node handle to the running instance's budget node, the create reply's last cap (`CREATE_NODE_HANDLE`); `0` otherwise. Released with the instance's other caps when it dies, and replaced at each restart |

The launch surfaces svcmgr replays beyond that record (the
argv / env / cwd / seed, plus the log-sink, debug-authority,
stop-authority, `oom_stop` and `reserve` flags, the `stop_source`
class and the scheduling fields) are held in a parallel
[`RestartRecipe`](../src/service.rs) table
(`ServiceTable.recipes`), index-aligned with `services` by slot:

| Field | Source |
|---|---|
| `argv` | `argv = ...` |
| `env` | `env = ...` |
| `cwd` | `cwd = ...` |
| `seed` | `seed = ...` |
| `log_sink` | `log_sink = ...` |
| `debug_authority` | `debug_authority = ...` |
| `stop_authority` | `stop_authority = ...` |
| `oom_stop` | `oom_stop = ...` |
| `reserve` | `reserve = ...` |
| `stop_source` | `stop_source = ...` (`None` = unset); svcmgr lists a running source by it (`LIST_STOP_SOURCES`) |
| `priority` | `priority = ...` (`0` = unset) |
| `sched_max` | `sched_max = ...` (`0` = unset) |

`restart_process` replays every field on every respawn — argv/env, the
scheduling fields and the create flags `reserve`, `oom_stop` and `stop_source`
ask for (`CREATE_RESERVE`, `CREATE_NODE_HANDLE`, `CREATE_CONTAIN`) into
`CREATE_FROM_FILE`, cwd
through `apply_namespace_policy`, seeds re-resolved from the discovery
registry, a fresh `DEBUG_AUTHORITY` and `STOP_AUTHORITY` cap after them,
and `log_sink` selecting the log-sink round — so a restarted child comes
back with the same surfaces first launch gave it, the log-sink round's
history-pull SEND aside.

---

## Supervision hierarchy

The supervision hierarchy, the core set, and the restart shapes are specified in
[Supervision](../../../docs/supervision.md); this section states svcmgr's part of them. svcmgr
supervises top-level services only. The drivers devmgr spawns and the filesystem drivers vfsd
spawns are not in its table, and none of them flows through the handover endowment
([Supervision § Supervision Hierarchy](../../../docs/supervision.md#supervision-hierarchy)).

The table below lists the services svcmgr currently binds or launches
(per the shipped and staged `.svc` files). A `restart = never` service
svcmgr launches (`svctest`, `usertest`, `terminal`) is launched one-shot:
svcmgr binds no death notification for it and records no `ServiceEntry`
([service-definitions.md](service-definitions.md#reconciliation)).

`svctest`, `usertest`, and `crasher` are test-tier fixtures: their recipes
live in `/config/svcmgr/tests/` (svcmgr does not scan it) and are staged
into `/config/svcmgr/services/` only for test boots — `crasher` is
co-staged with `svctest` (per [testing.md](../../../docs/testing.md#gating)).
Every other recipe in `/config/svcmgr/tests/` is `restart = never`,
`critical = no`, staged only by the test command that uses it. The rest
ship in `/config/svcmgr/services/` and load on every boot, except
that the functional harness boots drop `terminal` (per
[testing.md](../../../docs/testing.md#one-shutdown-invoking-harness-per-boot)
§ One shutdown-invoking harness per boot, Test isolation).

| Service | Source | Restart | Critical |
|---|---|---|---|
| `svctest` | svcmgr-launched (test-tier, staged) | `never` | `no` |
| `usertest` | svcmgr-launched (test-tier, staged) | `never` | `no` |
| `crasher` | svcmgr-launched (test-tier, staged) | `always` | `no` |
| `memmgr` | init-endowed (bind only) | `never` | `yes` |
| `procmgr` | init-endowed (bind only) | `never` | `yes` |
| `devmgr` | init-endowed (bind only) | `never` | `yes` |
| `vfsd` | init-endowed (bind only) | `never` | `yes` |
| `logd` | svcmgr-launched (log sink) | `on_failure` | `yes` |
| `timed` | svcmgr-launched (provider) | `on_failure` | `no` |
| `pwrmgr` | svcmgr-launched (provider) | `on_failure` | `no` |
| `crashd` | svcmgr-launched | `on_failure` | `no` |
| `terminal` | svcmgr-launched | `never` | `no` |

memmgr and procmgr are in the core set and never restart; devmgr and vfsd
are not, but no restart of either is designed. svcmgr holds none of the
authority init created them with, so it could not respawn any of the four
([Supervision § Restart Authority](../../../docs/supervision.md#restart-authority)).

`timed`, `pwrmgr`, and `logd` restart on a persistent endpoint
([Supervision § Restart Shapes](../../../docs/supervision.md#restart-shapes)).
`timed` and `pwrmgr` hold no
unique source cap — each re-acquires its authority on (re)start by
querying devmgr (`QUERY_DEVICE` on the rtc class SEND for timed, per
[timed/README.md](../../timed/README.md); `QUERY_SHUTDOWN_DEVICE` on RISC-V for
pwrmgr, per
[pwrmgr/README.md](../../pwrmgr/README.md)), and svcmgr re-serves a fresh
RECV on the persistent service endpoint so cached client caps survive the
restart. `logd` is the log sink: svcmgr holds the master-log endpoint
source for the system's life and mints each (re)launched logd a fresh RECV
on that persistent endpoint, so log senders' caps survive the restart (per
[service-definitions.md](service-definitions.md#log_sink)). The restarted
logd skips the history pull, serves a fresh table (which holds no sender's
display name: logd refuses a sender's next message with `NAME_UNKNOWN`, and
the sender registers its name again and resends, so its lines render under
its name), and registers its death queue with procmgr, whose
`REGISTER_DEATH_EQ` takes it in place of the dead instance's
([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md)
§ `REGISTER_DEATH_EQ`), so slot eviction resumes. svcmgr's death handler
writes none of a logd death's lines before the respawn: with no logd
receiving, each would wait out its bound (the first `LOG_CALL_TIMEOUT_MS`,
the rest `LOG_CALL_UNANSWERED_TIMEOUT_MS`, per
[shared/log](../../../shared/log/README.md)) and be dropped. It writes them
once the new instance has started and been served its bootstrap round, and
none when no instance follows (the policy or the budget refuses the restart,
or the restart fails), since no receiver is left to take them. A failure
line of the create path itself (`restart_process` and the helpers it
calls) is written as it occurs and waits out its bound. procmgr writes a
create's success lines after its reply, so the create of the new instance
waits on none of them. svctest's
`logd_restart` phase kills logd and checks both
([services/svctest/README.md](../../svctest/README.md)).

svcmgr's own death is not routed here: svcmgr is in the core set, and
pwrmgr observing it is design intent; not yet implemented (#262)
([Supervision § Observing svcmgr](../../../docs/supervision.md#observing-svcmgr)).

---

## Summarized By

[Console Model](../../../docs/console-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[Supervision](../../../docs/supervision.md),
[services/crasher/README.md](../../crasher/README.md),
[services/logd/README.md](../../logd/README.md),
[logd handover protocol](../../logd/docs/handover-protocol.md),
[logd IPC interface](../../logd/docs/ipc-interface.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md), [services/svcmgr/README.md](../README.md),
[svcmgr IPC Interface](ipc-interface.md), [`.svc` Service Definitions](service-definitions.md)
