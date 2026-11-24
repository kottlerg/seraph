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
address space, and the first terminal end of any of its threads, a fault or an exit, posts it.
procmgr's teardown of the process stops the main thread without a post and
revokes svcmgr's thread cap, so the address-space observer is the one that
reports a fault of another thread. svcmgr binds the address-space observer
as follows:

- For a service svcmgr launches or restarts, procmgr binds it:
  `BIND_DEATH_OBSERVER` (procmgr label 25) on the process handle, with a `POST`
  copy of a svcmgr death queue. Both binds happen before `START_PROCESS`.
- For memmgr and procmgr, which init creates by raw syscalls, svcmgr binds
  neither observer on its death queues. At its start it binds both, with
  `SYS_THREAD_BIND_NOTIFICATION` and `SYS_ASPACE_BIND_NOTIFICATION`, on the
  core-death queue the shutdown actuator receives on ([Supervision § Observing
  the Core Set](../../../docs/supervision.md#observing-the-core-set)), through
  the thread cap and the Control-only address-space cap the handover endowment
  delivers. The entry keeps both (`ServiceEntry.thread_cap`,
  `ServiceEntry.aspace_cap`) for the liveness reads of a resync and of the
  check made before each call into procmgr, the stop paths' included, and a
  non-zero `aspace_cap`, which no other entry holds, marks the entry as a core
  member's, whose death `route_death` leaves to pwrmgr (§ Decision tree).
- For devmgr and vfsd, which init creates through procmgr, svcmgr sends
  `BIND_DEATH_OBSERVER` on the process handle the handover endowment delivers,
  which the entry keeps (`ServiceEntry.process_handle`).

A bind takes one death-observer node from its queue's pool, fixed when the
queue is created, so svcmgr keeps a growable set of queues: a bind tries the
newest queue first, then the older ones, and only when every queue is out of
nodes creates a further queue, funded from svcmgr's own memory, with twice
the last pool (4 nodes first, below the two each of a boot's supervised and
adopted services take, a dozen services or more, so every boot grows the set; up to
`EVENT_QUEUE_MAX_CAPACITY`). A
further queue is one contiguous grant from memmgr; when memmgr refuses it,
svcmgr retries at half the pool, down to the first pool's size. A bind that
still fails fails the launch or restart. An adoption records the service all
the same, so a death no observer reports is found by a resync (§ Death
detection).

The WaitSet holds the service endpoint (badge 0), every death queue
(badge 1), and the Notification memmgr signals on a change of its pressure
level (badge 2; § Decision tree, the memory wait), and svcmgr's death-queue
set (`DeathSet`, the
[`shared/death-set`](../../../shared/death-set/README.md) crate, sized by
[`src/death_queues.rs`](../src/death_queues.rs)) owns it: it starts with
room for four members (two queues beside the endpoint and the Notification), and when the
queues fill it, svcmgr creates one with
twice the members, up to `WAIT_SET_MAX_MEMBERS` (1024), moves every member
across, and deletes the old one; the event loop waits on whichever is
current, and every boot widens it once its queues pass the second. The kernel
queues a member that is already ready when it is added, so the move loses no
pending request or death post. A deleted sub-page wait set's bytes return to
the runtime's pooled object-slab page; a page-sized set's (32 members or
more) dedicated grant returns to memmgr through
`std::os::seraph::object_slab_release`. Up to 1022 queues hold more nodes
than svcmgr's `CSpace` has slots. On wakeup svcmgr drains every queue and
routes each payload to its `ServiceEntry` via the correlator, then
dispatches through [`restart::handle_death`](../src/restart.rs). The service
table grows on the heap and never reuses a slot, so a slot names one
service for svcmgr's lifetime. `route_death` routes a post only when the
slot is active and the tag's instance is the slot's current one. The exit reason
it routes, for a post and for a death svcmgr's own caps show alike (the resync below, the
shutdown actuator's death found before the shutdown call, and a stop's target found already
dead), is the one procmgr gives the process, asked through the service's process handle
(`procmgr_labels::QUERY_PROCESS`, while memmgr and procmgr are active and alive), since a post
of the main thread's own `sys_thread_exit` carries the process's reason only when it is the
process's first end ([process-lifecycle.md](../../../docs/process-lifecycle.md#exit-reason)); the
post's or the caps' own reason stands when procmgr does not answer `EXITED`, while memmgr or
procmgr is down, and for a service svcmgr holds no process handle of. Any other post is dropped: a
late post of an instance already routed, and the second of the two posts a main-thread fault or exit
makes when it is the address space's first terminal end.

Each death queue has a fixed tuning capacity (`DEATHS_EQ_CAPACITY`, 64),
not one sized from the service count. The kernel drops a post to a full
queue, so a drain that takes a full queue's worth of events or more from one
queue resyncs: it routes a death for every active service whose main thread the kernel reports
exited (the kernel's reason), whose thread cap no longer resolves (`EXIT_KILLED`: procmgr's teardown
revokes it), or whose endowed address space has a retained terminal end
(`CAP_INFO_ASPACE_END`), each with the reason procmgr gives the process, as above, when svcmgr
holds its process handle. A dropped post leaves a full queue of events behind it for that
drain or the next, so the resync runs after the drop.

A worker-thread fault of a service procmgr created shows in svcmgr's caps only once procmgr's
teardown revokes the thread cap, which can follow the resync. So the resync then asks procmgr
about each such service its caps show alive, through its process handle
(`procmgr_labels::QUERY_PROCESS`): procmgr reads the space's retained terminal end and answers
`EXITED` with it before it reaps the process. The query runs only while memmgr and procmgr are
active and alive, since it blocks until procmgr answers.

Reconciliation records a devmgr that died before its bind, or a vfsd that died after the recipe
scan, with the thread cap init endowed, and a resync right after reconciliation routes its death
(`EXIT_KILLED` for a revoked cap).

A child that dies after `START_PROCESS` and before its bootstrap request sends none, so svcmgr does
not wait for a request without bound. Its wait for each of a child's requests
([`serve_boot_slots`](../src/definitions/launch.rs), through
`ipc::bootstrap::serve_round_watched`) is a receive bounded at `ipc::bootstrap::WATCH_POLL_MS`
(50 ms), and after each one that expires svcmgr reads the child's main thread through its own
thread cap, as a resync does (the kernel's reason for an exited thread, `EXIT_KILLED` for a
revoked cap); a round that fails is read the same way. A dead child ends the serve: svcmgr releases
the caps of the rounds it did not serve and routes the death at once through
`restart::handle_death`, under the instance's tag, as any other death:

- On the first launch the service is recorded as launched, and its provided names published, as
  for a child that took its rounds, since the endpoint outlives the instance; its death is routed
  before reconciliation launches the next recipe, so a dead log sink is restarted before svcmgr's
  next lines. Until procmgr reports init reaped, each restart of it is served the first launch's
  round, with the `HANDOVER_PULL` SEND, since init-logd may still wait for the handover
  (§ Supervision hierarchy). An unrecoverable outcome starts the graceful
  shutdown once reconciliation ends, when the shutdown actuator is recorded. svcmgr logs a death
  on the first launch at once (`svcmgr: <name> died during its bootstrap`), a one-shot service's
  (`restart = never`) and the log sink's included: no instance of the log sink has taken the
  handover then, so init-logd still receives the line.
- On a restart the dead new instance is a death of its own, decided by the same steps
  (§ Decision tree), its restart charged to the same budget, which bounds the repeats.

The posts the dead instance's observers make arrive later and are dropped, its instance already
routed. A child that is alive and sends no request, one a debugger holds stopped among them, is
still waited for, `WATCH_POLL_MS` at a time.

svcmgr calls vfsd and devmgr before reconciliation records them. vfsd serves svcmgr's namespace
root: before the handover svcmgr reads the device class files and walks the drivers and platform
tables directories through it, and at the handover it reads the recipe directory. devmgr mints each
device class and takes `SET_DRIVERS_DIR` before the handover, through the endowed devmgr-registry
source. A call to a dead server fails: svcmgr's capabilities to its endpoints carry no Receive
right, and init keeps none, so once the server's process is torn down no capability with the Receive
right is left and the kernel fails the call, queued or new, with `NoReceiver`. So svcmgr reads a
server's liveness from its substrate registration before each step that calls it and after every
call to it that fails ([`src/endowed_servers.rs`](../src/endowed_servers.rs)): the state of the
endowed thread cap (`EXIT_KILLED` for a revoked one), then, while memmgr and procmgr show alive,
`QUERY_PROCESS` on the endowed process handle, which reports a worker-thread fault procmgr has not
yet torn down. A dead server ends the step. A dead devmgr is then recorded by reconciliation, and
the resync after it routes its death, as above. A dead vfsd found at the handover, before or during
the recipe read, is system death with no recipe to supervise by: svcmgr records and launches
nothing, releases every substrate registration (each such service runs on unsupervised, logged), and
takes the graceful shutdown path, which, with no shutdown actuator recorded, logs the degraded state
(§ Decision tree). A server that dies after a check, while svcmgr's next call to it waits
unreceived, fails that call the same way, and the check after the failed call finds the death.

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

A core member's death is not decided here. The observers of memmgr and procmgr are on the
core-death queue, whose entries the shutdown actuator acts on, so svcmgr's death queues carry none
of their posts, and only a resync finds such a death (§ Death detection): `route_death` then marks
the entry inactive and returns, with no line, no restart decision and no graceful shutdown, each of
which could wait on the dead member; pwrmgr powers the system off ([Supervision § Core Set and
System Death](../../../docs/supervision.md#core-set-and-system-death)).

1. **`should_restart(svc, exit_reason)`** evaluates the restart policy:
   * `POLICY_NEVER` → no restart.
   * `POLICY_ON_FAILURE` → restart iff `exit_reason >= EXIT_FAULT_BASE`
     (a fault or `EXIT_KILLED`; voluntary codes do not restart; per
     [service-definitions.md](service-definitions.md#restart)).
   * `POLICY_ALWAYS` → restart unconditionally.
   * A missing restart source (an empty `vfs_path`) reports
     "no restart source" and returns false.
   * The windowed restart budget (`restart_budget::RestartBudget`) is
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
     `seed` names from the discovery registry in declaration order,
     each wait for a request watched for the new instance's death
     (§ Death detection).
   * On success: increment `restart_count` (a lifetime count for the
     restart log line), return `Restarted`.
   * When the new instance dies during its rounds: increment
     `restart_count`, and decide its death from step 1 with its exit
     reason. The entry names the dead instance, which the next restart
     releases as above.
   * On failure: any failure after `CREATE_FROM_FILE` destroys the new
     child via `DESTROY_PROCESS`, as first launch does; then route
     through `permanent_death_outcome`. A create procmgr refuses with
     `OUT_OF_MEMORY` is decided first, as below (the memory wait). A create
     whose reply caps never reach svcmgr needs no destroy: when the reply's cap transfer into
     svcmgr's CSpace fails, svcmgr receives `IPC_REPLY_TRANSFER_FAILED`
     with no process handle, and procmgr destroys the child it created
     (see the [procmgr IPC interface](../../procmgr/docs/ipc-interface.md)
     § Label 1), on first launch and on restart alike.

**The memory wait.** memmgr refuses a request from a budget node outside the system reserve that
would leave fewer free pages than the growth floor ([memmgr Memory Pool §
Allocation](../../memmgr/docs/memory-pool.md#allocation)). Its pressure level reads `CRITICAL` at
or below that floor and leaves it only once the free pool clears it by a hysteresis band
([§ Memory pressure](../../memmgr/docs/memory-pool.md#memory-pressure)), so a restart whose create
needs more than the margin of free pages above the floor has its create refused with
`OUT_OF_MEMORY`, at `CRITICAL` (as when oomd stops a service that is not the one holding the
memory) or below it. The level reads `CRITICAL` through the band above the floor too, where a
create smaller than the margin is admitted, so `CRITICAL` is no proof that a retry is refused.
Only memory coming free ends such a refusal, and memmgr signals a change of level but not memory
coming free otherwise. The
wait is one state machine, `svcmgr_defs::memory_wait` (host-tested over every transition), which
`restart.rs` and the main loop drive:

| State | Event | Next state |
|---|---|---|
| decided (step 1 charged the death's restart to the budget) | create refused `OUT_OF_MEMORY`, the service outside the reserve and not the log sink, svcmgr holding the pressure Notification | waiting |
| decided | any other create failure, or one of a reserve service, of the log sink, or with no Notification | down |
| waiting | a signal (a change of level) read below `CRITICAL` | retry (on a signal) |
| waiting | a signal read at `CRITICAL` | waiting |
| waiting, level read | the retry deadline, armed `MEMORY_RETRY_MS` (1 s) ahead and moved by no other event, passes, whatever woke the main loop | retry (timed, counted only when the level reads below `CRITICAL`); the next deadline armed |
| waiting | the level reads unread (memmgr did not answer) | waiting; deadline cleared, no timer |
| retry | the new instance runs | restarted |
| retry | the new instance dies during its bootstrap | a new death: step 1, charged |
| retry | create refused `OUT_OF_MEMORY` | waiting, a counted retry counted; down once the counted retries reach `MEMORY_RETRY_LIMIT` (60) |
| retry | any other failure | down |

- **Waiting.** The entry is inactive, holds no instance, and records the death's exit reason and
  its timed retries (`ServiceEntry::memory_wait`); `handle_death` returns `WaitingForMemory`, on
  which the caller does nothing more, `critical = yes` or not. svcmgr logs `restart of <name>
  waits for memory`. svcmgr records memmgr's level after each refusal for want of memory and on
  each wake. While a restart waits and a level has been read, `CRITICAL` included, a retry deadline
  `MEMORY_RETRY_MS` ahead is armed once and kept (`MemoryWaits::poll_timer`): the main loop waits at
  most the time left to it and retries once it has passed, whatever woke it, so no stream of
  requests on svcmgr's endpoint holds a timed retry off. The timer runs at `CRITICAL` too, since
  the free pool moves inside the band with no signal. Otherwise (no restart waits, or memmgr did
  not answer) the deadline is cleared and the wait has no timeout, so svcmgr makes no idle
  wake-up.
- **Retry.** Every waiting service is retried on the wake that makes a retry due: its create is made
  again (`restart::retry_memory_wait`), charging the budget nothing, since the budget bounds deaths
  and step 1 charged this one; a retry on a signal is logged `memory level fell; retrying the
  restart of <name>`. Retries on signals are bounded by the changes of level, and timed retries
  made below `CRITICAL` by `MEMORY_RETRY_LIMIT`, about a minute there with memory still short,
  after which svcmgr logs `restart of <name> given up`. A timed retry at `CRITICAL` is not
  counted: an episode oomd has yet to end spends none of the limit. A retry's refusal for want of
  memory logs nothing, so a wait that holds at `CRITICAL` adds no line per timed retry; the wait's
  own lines (`waits for memory`, `given up`, `service restarted`) report it.
- **Down.** `permanent_death_outcome`: `critical` decides the rest, an `Unrecoverable` outcome
  starting the graceful shutdown.

svcmgr waits on its own Notification (`std::os::seraph::memory_pressure_notification`, which the
std runtime registers for every process) in its main wait set (badge 2), and takes its bits before
it reads the level, so a change after the read signals again. A wake is a signal only when its bits
hold `MEMORY_PRESSURE_BIT` (`Wake::signal`): one carrying only `COMMIT_DRAW_ROOM_BIT`, an
opening of memmgr's draw room, is left to the timer, since no hysteresis band spaces the openings,
and a draw room that a waiting create's partial grants close and its teardown reopens would
otherwise retry it at once, uncounted, at each opening.

A waiting service is not running wherever svcmgr reports a service's state: a stop of it is refused
`NO_CANDIDATE`, `LIST_CANDIDATES` and `LIST_STOP_SOURCES` leave it out, no death post routes to its
inactive entry, and the shutdown path finds a waiting actuator down. Its provided endpoint outlives
the wait, as it outlives any instance: a client's call on it waits, unreceived, until the next
instance receives it, and waits for good if the service ends permanently down, as a call on any
service that is down does.

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
the log-sink, debug-authority, stop-authority, entropy-authority, `oom_stop`,
`reserve` and `private_image` flags, the `stop_source` class, and the scheduling fields on the
parallel `RestartRecipe`, so
a restart reproduces the first-launch spawn shape byte-for-byte, except the
log-sink round, whose history-pull SEND is absent on a restart once procmgr
reports init reaped (per
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
stop-authority, entropy-authority, `oom_stop`, `reserve` and `private_image` flags, the
`stop_source` class and the scheduling fields) are held in a parallel
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
| `entropy_authority` | `entropy_authority = ...`; cleared on every declaration after the first in launch order |
| `oom_stop` | `oom_stop = ...` |
| `reserve` | `reserve = ...` |
| `private_image` | `private_image = ...` |
| `stop_source` | `stop_source = ...` (`None` = unset); svcmgr lists a running source by it (`LIST_STOP_SOURCES`) |
| `priority` | `priority = ...` (`0` = unset) |
| `sched_max` | `sched_max = ...` (`0` = unset) |

`restart_process` replays every field on every respawn — argv/env, the
scheduling fields and the create flags `reserve`, `oom_stop`, `stop_source` and
`private_image` ask for (`CREATE_RESERVE`, `CREATE_NODE_HANDLE`, `CREATE_CONTAIN`,
`CREATE_PRIVATE_IMAGE`) into
`CREATE_FROM_FILE`, cwd
through `apply_namespace_policy`, seeds re-resolved from the discovery
registry, a fresh `DEBUG_AUTHORITY` and `STOP_AUTHORITY` cap and `EntropyControl` copy after them,
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
svcmgr launches (`svctest`, `usertest`) is launched one-shot:
svcmgr binds no death notification for it and records no `ServiceEntry`
([service-definitions.md](service-definitions.md#reconciliation)).

`svctest`, `usertest`, and `crasher` are test-tier fixtures: their recipes
live in `/config/svcmgr/tests/` (svcmgr does not read it) and are staged
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
| `sessiond` | svcmgr-launched (stop source) | `on_failure` | `no` |
| `terminal` | svcmgr-launched | `on_failure` | `no` |
| `acpid` | svcmgr-launched (provider) | `on_failure` | `no` |
| `oomd` | svcmgr-launched (stop-authority holder) | `on_failure` | `no` |
| `entropyd` | svcmgr-launched (entropy-authority holder) | `on_failure` | `no` |

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
[service-definitions.md](service-definitions.md#log_sink)). A logd
restarted while procmgr does not report init reaped (`QUERY_INIT_REAP`, or the query fails) is
minted the first launch's round, `HANDOVER_PULL` SEND included, since init-logd may still serve
the endpoint. Any later restarted logd skips the history pull, serves a fresh table
(which holds no sender's display name: logd refuses a sender's next message with `NAME_UNKNOWN`, and
the sender registers its name again and resends, so its lines render under
its name), and registers its death queue with procmgr, whose
`REGISTER_DEATH_EQ` takes it in place of the dead instance's
([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md)
§ `REGISTER_DEATH_EQ`), so slot eviction resumes. svcmgr's death handler
writes none of a logd death's lines before the respawn: with no logd
receiving, each would wait out its bound (the first `LOG_CALL_TIMEOUT_MS`,
the rest `LOG_CALL_UNANSWERED_TIMEOUT_MS`, per
[shared/log](../../../shared/log/README.md)) and be dropped. It writes them
once the new instance has started and been served its bootstrap round,
with one line counting the instances that died during their bootstrap
before it, and none when no instance follows (the policy or the budget refuses the restart,
or the restart fails), since no receiver is left to take them. Before it writes
them it tells its log client that the receiver restarted
(`std::os::seraph::log::receiver_restarted`): a line svcmgr wrote while the dead
instance received nothing, as when it died in its handover from init-logd before its
receive workers started, timed out and left svcmgr's later calls at the short bound,
which the new instance's start outlasts, so the held lines would be dropped. The one line
written before the respawn is a first launch's death before its bootstrap
request (§ Death detection), which init-logd, still serving the endpoint,
receives. A failure
line of the create path itself (`restart_process` and the helpers it
calls) is written as it occurs and waits out its bound. procmgr writes a
create's success lines after its reply, so the create of the new instance
waits on none of them. svctest's
`logd_restart` phase kills logd and checks both
([services/svctest/README.md](../../svctest/README.md)).

svcmgr's own death is not routed here, nor memmgr's or procmgr's: they
are the core set, and pwrmgr observes their deaths on the core-death queue
and powers the system off
([Supervision § Observing the Core Set](../../../docs/supervision.md#observing-the-core-set)).

---

## Summarized By

[Console Model](../../../docs/console-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[Supervision](../../../docs/supervision.md),
[services/fixtures/crasher/README.md](../../fixtures/crasher/README.md),
[services/logd/README.md](../../logd/README.md),
[logd handover protocol](../../logd/docs/handover-protocol.md),
[logd IPC interface](../../logd/docs/ipc-interface.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md), [services/svcmgr/README.md](../README.md),
[svcmgr IPC Interface](ipc-interface.md), [`.svc` Service Definitions](service-definitions.md)
