# service-modes

svctest's shared service-role fixture: the services svctest's recipes have svcmgr start in the
service role whose checks need no image of their own. One binary serves every mode, chosen by the
first argument the recipe's `argv` gives after the program name, with the mode's own arguments after
it. It installs at `/tests/fixtures/service-modes`, whose path gives it the service signing role
([docs/signing.md](../../../docs/signing.md)); see
[docs/testing.md](../../../docs/testing.md#sysroot-layout) for where test fixtures install. Each
recipe is under `/config/svcmgr/tests/` and is staged only by the harness that runs it.

Each mode is a module under `src/` named for it (`src/<mode>.rs`); `src/main.rs` dispatches on the
first argument.

| Mode | Recipe | Argv |
|---|---|---|
| [`crasher`](#crasher) | `crasher.svc` | `service-modes crasher selftest` |
| [`crasher`](#crasher) | `crasher-boot.svc` | `service-modes crasher boot-fault` |
| [`crasher`](#crasher) | `crasher-worker.svc` | `service-modes crasher worker-fault` |
| [`crasher`](#crasher) | `crasher-once.svc` | `service-modes crasher worker-fault` |
| [`memhog`](#memhog) | `memhog.svc` | `service-modes memhog` |
| [`stopsrc`](#stopsrc) | `stopsrc.svc` | `service-modes stopsrc`; its job `/tests/fixtures/service-modes stopsrc job <pages>` |

Unknown or missing mode: it registers the log name `service-modes`, logs an error
`no mode <argument>`, the argument in Rust's debug form (`Some("x")`, or `None` when there is
none), and returns (`src/main.rs`).

---

## crasher

Test-tier fixture that validates svcmgr's restart path by crashing on purpose. It is gated and
opt-in: its recipes live in `/config/svcmgr/tests/`, are co-staged with `svctest` in CI, and are
never launched on a normal boot. Source: `src/crasher.rs`.

On every spawn of the `selftest` role (`crasher.svc`, `argv = service-modes crasher selftest`) it
checks that the recipe surfaces (argv, env, cwd, and bootstrap seeds) survived
and logs `<surface> ok` for each; the argv check wants `[service-modes, crasher, selftest]`, and the
cwd check resolves the relative path `service-modes` through the recipe's cwd `/tests/fixtures`.
It then logs `alive` and probes the svcmgr seed with a
`QUERY_ENDPOINT` for the unknown name `__probe__`, logging the reply label; any reply shows the
cap is live, and a call that gets no reply is a failed round-trip. Finally it faults on purpose
(a NULL write) so svcmgr respawns it under `restart = always`. A surface that fails to
round-trip, such as one dropped on restart, is logged with a `FATAL:` prefix, which the
`run --runs` fail regex catches to fail the run. The deliberate `USERSPACE FAULT` does not
count as a failure.

A second role, selected by argv `service-modes crasher worker-fault`, checks that svcmgr routes the
fault of a thread other than the main thread. Its recipe,
`rootfs/config/svcmgr/tests/crasher-worker.svc`
(`restart = on_failure`, `critical = no`, `namespace = none`, `provides = crasher.worker`,
`oom_stop = yes`), is
co-staged with `svctest` wherever `crasher.svc` is. The role takes the provided name's service
endpoint from bootstrap slot 0, logs `worker-fault: serving`, and serves
`ipc::restart_probe_labels`: `PROBE_INSTANCE` replies a per-instance random nonce in word 0, and
`PROBE_FAULT_WORKER` replies, then receives nothing more while a worker thread takes a terminal
fault after `FAULT_DELAY_MS` (200 ms), logging `worker-fault: worker thread faulting`. The role
starts that thread before it serves and lets it go on the request, so the fault takes no memory
when it is asked for, and one asked for while memory is critical still happens. An instance that
cannot start the thread (memmgr refuses its IPC buffer's grant while memory is critical) logs
`worker-fault: worker thread not started; retrying` at warn level and tries again every 50 ms,
serving once it runs. procmgr
tears the process down, and svcmgr restarts it through its address-space observer; svctest's
`svcmgr_worker_fault_restart` phase, which skips when the staged fixture set does not declare
`crasher-worker`, reads a new nonce from
the restarted instance. `oom_stop = yes` makes it a service of that boot a stop-authority holder may
stop, as the `memhog` fixture does ([memhog](#memhog)): svctest's `svcmgr_stop_service`
phase lists it, has svcmgr stop it, and reads the restarted instance's nonce the same way. A role
that lacks its endpoint or nonce logs `FATAL: worker-fault: ...`.

A third role, selected by argv `service-modes crasher boot-fault`, checks that svcmgr routes the
death of a service that dies before its bootstrap request. Its recipe,
`rootfs/config/svcmgr/tests/crasher-boot.svc` (`restart = on_failure`, `critical = no`,
`namespace = subtree:/data/crasher-boot:LOOKUP+STAT+MUTATE_DIR`, `provides = crasher.boot`), is
co-staged with `svctest` wherever `crasher.svc` is. Before it asks for its bootstrap round, an
instance removes the token `/die-early` of its namespace (`/data/crasher-boot/die-early`): when the
removal succeeds it logs `boot-fault: token taken; faulting before the bootstrap request` and
faults its main thread; when the token is not there it serves as the `worker-fault` role does, on
`crasher.boot`. Any other failure of the removal logs `FATAL: boot-fault: ...`. The data partition
ships the token (`rootfs/data/crasher-boot/die-early`), so the first launch dies so, and svctest's
`svcmgr_boot_death` phase writes it again before it faults a serving instance's worker, so a
restart dies so too.

The `worker-fault` role also runs under a second recipe,
`rootfs/config/svcmgr/tests/crasher-once.svc` (`restart = never`, `critical = no`,
`namespace = none`, `provides = crasher.once`), co-staged with `svctest` wherever `crasher.svc` is.
svctest's `svcmgr_one_shot_death` phase faults its instance's worker and checks that svcmgr logs the
death and the decision not to restart it.

---

### Capabilities

The bootstrap round delivers the recipe's two seeds again on every spawn and respawn (the
`worker-fault` and `boot-fault` roles instead receive their provided service endpoint in
`caps[0]`):

| Slot      | Cap                       |
|-----------|---------------------------|
| `caps[0]` | svcmgr service endpoint   |
| `caps[1]` | pwrmgr deny twin          |

The log and procmgr endpoints come in through `ProcessInfo`, so they are not part of the
bootstrap round.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | How harnesses and fixtures are staged and co-staged |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Process startup and `ProcessInfo` handover |
| [Restart Protocol](../../svcmgr/docs/restart-protocol.md) | svcmgr restart policy |

---

## memhog

Test-tier fixture for the out-of-memory policy service: a supervised service that, on request,
takes what memmgr can still promise a process outside the system reserve, until the pressure level
reads `CRITICAL`, and holds it until it is stopped. It is gated and opt-in: its recipe,
`rootfs/config/svcmgr/tests/memhog.svc`, lives in `/config/svcmgr/tests/`, is co-staged with
`svctest` in CI, and is never launched on a normal boot.

The recipe sets `binary = /tests/fixtures/service-modes`, `argv = service-modes memhog`,
`restart = on_failure`, `critical = no`, `namespace = none`,
`provides = memhog.ctl` and `oom_stop = yes`, with no `reserve`, so it is a service
oomd may stop ([services/oomd/README.md](../../oomd/README.md)), and a stop's `EXIT_KILLED` death
restarts it. The fixture takes the provided name's service endpoint from bootstrap slot 0, allocates
its fill's ballast, touches its stack, logs `serving`, and serves `ipc::memhog_labels`:

| Label | Reply |
|---|---|
| `PROBE` (1) | `SUCCESS`, word 0 a per-instance random nonce, word 1 the pages it holds |
| `HOG` (2) | `SUCCESS` with word 0 the pages it holds, once nothing is left to take and the level has read `CRITICAL` for 500 ms; `NOT_CRITICAL` when that does not happen within 30 s, or memmgr does not answer |
| any other | `UNKNOWN_OPCODE` |

The fill is [`mem-fill`](../../../shared/mem-fill/README.md)'s, shared with crashme's `oom-fill`
mode: it commits what memmgr can still promise a process outside the reserve through the heap and
takes the rest by one-page grants, as many as its `CSpace`'s free general slots hold, so its
receives keep the IPC receive reserve. Once hogging, the fixture tops up every 10 ms between
requests, so it takes back what another process frees and the level stays `CRITICAL` until it is
stopped.

svctest's `oom_policy` phase, which skips when the staged fixture set does not declare `memhog`, has
it hog and reads that oomd stopped it, or with `OOMD_STOP=no` that nothing did, and that its next
instance answers `PROBE` with a new nonce and no pages; its `logd_reserve` phase has it hog while
logd is killed and restarted ([services/svctest/README.md](../../svctest/README.md)). Its
`oom_stop = yes` also makes it a service svctest's `svcmgr_stop_service` phase may list. A fixture
that lacks its endpoint or nonce, or cannot allocate its ballast, logs an error and exits.

Source: `src/memhog.rs`.

---

### Capabilities

| Slot      | Cap                                              |
|-----------|--------------------------------------------------|
| `caps[0]` | The service endpoint of `memhog.ctl`, which svcmgr delivers to the provider |

memmgr's endpoint and the log endpoint come in through `ProcessInfo`, so they are not part of the
bootstrap round.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | How harnesses and fixtures are staged and co-staged |
| [services/oomd/docs/operation.md](../../oomd/docs/operation.md) | The ladder and the stop sources the fixture drives |
| [shared/mem-fill/README.md](../../../shared/mem-fill/README.md) | The fill |
| [services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md) | § Memory pressure, § Distribution policy |
| [services/svcmgr/docs/service-definitions.md](../../svcmgr/docs/service-definitions.md) | `provides`, `oom_stop` |

---

## stopsrc

Test-tier fixture for stop sources: a supervised stop source of the program class that, on
request, starts one job, a child process holding memory, lists it to a stop-authority holder, and
destroys it on a stop. It is a second source of the program class beside sessiond, the default
image's. It is gated and opt-in: its recipe, `rootfs/config/svcmgr/tests/stopsrc.svc`,
lives in `/config/svcmgr/tests/`, is co-staged with `svctest` in CI, and is never launched on a
normal boot.

The recipe sets `binary = /tests/fixtures/service-modes`, `argv = service-modes stopsrc`,
`restart = always`, `critical = no`, `namespace = universal`,
`provides = stopsrc.ctl:deny` and `stop_source = program`, so svcmgr lists it to oomd, with the
program class and a SEND on its endpoint badged with the stop bit ([`.svc` Service
Definitions](../../svcmgr/docs/service-definitions.md) § `stop_source`). Its namespace is the
universal root because it starts its job from `/tests/fixtures/service-modes`, the path its image is
signed under, which procmgr verifies. The fixture takes the provided name's service endpoint from
bootstrap slot 0, touches its stack, logs `serving`, and serves, on any badge,
`ipc::stopsrc_labels`:

| Label | Reply |
|---|---|
| `PROBE` (1) | `SUCCESS`, word 0 a per-instance random nonce, word 1 the job's state (`JOB_NONE` 0, `JOB_RUNNING` 1, `JOB_STOPPED` 2), word 2 the running job's key or 0 |
| `START_JOB` (2) | Start a job of `data[0]` pages: `SUCCESS` with word 0 the job's key once the fixture's budget subtree holds that many pages beyond its own node; `JOB_FAILED` when the child is not created or does not hold them within 10 s, and is destroyed; `BUSY` while a job runs |
| `EXIT` (3) | `SUCCESS`, then the fixture exits with status 0, leaving a running job to procmgr, which destroys it with the fixture since svcmgr creates the fixture contained; `restart = always` restarts it |
| any other | `UNKNOWN_OPCODE` |

and, on a badge carrying `stop_labels::STOP_AUTHORITY`, the shared stop labels as well
([svcmgr IPC Interface](../../svcmgr/docs/ipc-interface.md) § Label 5, § Label 6):

| Label | Reply |
|---|---|
| `STOP_CANDIDATE` (5) | `SUCCESS` once the job the key names is destroyed through the process handle the fixture holds as its creator; `NO_CANDIDATE` for any other key, or with no job running; `UNAVAILABLE` when procmgr does not destroy it |
| `LIST_CANDIDATES` (6) | `SUCCESS` with one entry while a job runs, at cursor 0: its key, `RANK_JOB`, the pages the fixture's subtree holds beyond its own node (memmgr's `QUERY_MEMORY_USAGE`), and the name `stopsrc-job`; no entry otherwise |

`STOP_CANDIDATE` and `LIST_CANDIDATES` on any other badge, the `:deny` SEND any process can
query among them, reply `UNAUTHORIZED`. A job's key is new for each job of an instance, counted up
from the instance's nonce, so a key an earlier instance handed out names a later one's job only by
chance. The job is the fixture's own binary run as
`/tests/fixtures/service-modes stopsrc job <pages>`, so
procmgr lists it under `/tests/fixtures/service-modes`: it touches that many pages
of heap and sleeps until it is destroyed.

svctest's `svcmgr_stop_service` phase reads that svcmgr lists the fixture as a source of the
program class, that the stop labels and `PROBE` answer on the SEND svcmgr hands out, that the
stop labels refuse on the `:deny` one, and that a job the fixture started is gone once the fixture
has exited. Its `oom_policy` phase has the fixture exit, so the instance svcmgr restarts starts
after oomd, and start a job before memhog fills memory: oomd stops the job before memhog, and the
fixture reports it stopped ([services/svctest/README.md](../../svctest/README.md)). A fixture that
lacks its endpoint or nonce logs an error and exits.

Source: `src/stopsrc.rs`.

---

### Capabilities

| Slot      | Cap                                              |
|-----------|--------------------------------------------------|
| `caps[0]` | The service endpoint of `stopsrc.ctl`, which svcmgr delivers to the provider |

memmgr's endpoint, procmgr's and the log endpoint come in through `ProcessInfo`, so they are not
part of the bootstrap round.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | How harnesses and fixtures are staged and co-staged |
| [docs/session-supervision.md](../../../docs/session-supervision.md) | § Stop Sources |
| [services/oomd/docs/operation.md](../../oomd/docs/operation.md) | The stop sources and the order the fixture drives |
| [services/svcmgr/docs/service-definitions.md](../../svcmgr/docs/service-definitions.md) | `provides`, `stop_source` |
| [services/svcmgr/docs/ipc-interface.md](../../svcmgr/docs/ipc-interface.md) | § Label 5, § Label 6, § Label 7 |

---

## Summarized By

None
