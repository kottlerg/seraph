# stopsrc

Test-tier fixture for stop sources: a supervised stop source of the program class that, on
request, starts one job, a child process holding memory, lists it to a stop-authority holder, and
destroys it on a stop. It is gated and opt-in: its recipe, `rootfs/config/svcmgr/tests/stopsrc.svc`,
lives in `/config/svcmgr/tests/`, is co-staged with `svctest` in CI, and is never launched on a
normal boot.

The recipe sets `restart = always`, `critical = no`, `namespace = universal`,
`provides = stopsrc.ctl:deny` and `stop_source = program`, so svcmgr lists it to oomd, with the
program class and a SEND on its endpoint badged with the stop bit
([`.svc` Service Definitions](../svcmgr/docs/service-definitions.md) § `stop_source`). Its
namespace is the universal root because it starts its job from `/tests/stopsrc`, the path its image
is signed under, which procmgr verifies. The fixture takes the provided name's service endpoint
from bootstrap slot 0, touches its stack, logs `serving`, and serves, on any badge,
`ipc::stopsrc_labels`:

| Label | Reply |
|---|---|
| `PROBE` (1) | `SUCCESS`, word 0 a per-instance random nonce, word 1 the job's state (`JOB_NONE` 0, `JOB_RUNNING` 1, `JOB_STOPPED` 2), word 2 the running job's key or 0 |
| `START_JOB` (2) | Start a job of `data[0]` pages: `SUCCESS` with word 0 the job's key once the fixture's budget subtree holds that many pages beyond its own node; `JOB_FAILED` when the child is not created or does not hold them within 10 s, and is destroyed; `BUSY` while a job runs |
| `EXIT` (3) | `SUCCESS`, then the fixture destroys its job and exits with status 0, which `restart = always` restarts |
| any other | `UNKNOWN_OPCODE` |

and, on a badge carrying `stop_labels::STOP_AUTHORITY`, the shared stop labels in place of its
own ([svcmgr IPC Interface](../svcmgr/docs/ipc-interface.md) § Label 5, § Label 6):

| Label | Reply |
|---|---|
| `STOP_CANDIDATE` (5) | `SUCCESS` once the job the key names is destroyed through the process handle the fixture holds as its creator; `NO_CANDIDATE` for any other key, or with no job running; `UNAVAILABLE` when procmgr does not destroy it |
| `LIST_CANDIDATES` (6) | `SUCCESS` with one entry while a job runs, at cursor 0: its key, `RANK_JOB`, the pages the fixture's subtree holds beyond its own node (memmgr's `QUERY_MEMORY_USAGE`), and the name `stopsrc-job`; no entry otherwise |

`STOP_CANDIDATE` and `LIST_CANDIDATES` on any other badge, the `:deny` SEND any process can
query among them, reply `UNAUTHORIZED`. A job's key is new for each job of an instance. The job is
the fixture's own binary run as `stopsrc job <pages>`: it touches that many pages of heap and
sleeps until it is destroyed.

svctest's `svcmgr_stop_service` phase reads that svcmgr lists the fixture as a source of the
program class, and that the stop labels answer on the SEND svcmgr hands out and refuse on the
`:deny` one. Its `oom_policy` phase has the fixture exit, so the instance svcmgr restarts starts
after oomd, and start a job before memhog fills memory: oomd stops the job before memhog, and the
fixture reports it stopped ([services/svctest/README.md](../svctest/README.md)). A fixture that
lacks its endpoint or nonce logs an error and exits.

---

## Source Layout

```
stopsrc/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # The label loop, the job and its child role
```

---

## Capabilities

| Slot      | Cap                                              |
|-----------|--------------------------------------------------|
| `caps[0]` | The service endpoint of `stopsrc.ctl`, which svcmgr delivers to the provider |

memmgr's endpoint, procmgr's and the log endpoint come in through `ProcessInfo`, so they are not
part of the bootstrap round.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | How harnesses and fixtures are staged and co-staged |
| [docs/session-supervision.md](../../docs/session-supervision.md) | § Stop Sources |
| [services/oomd/docs/operation.md](../oomd/docs/operation.md) | The stop sources and the order the fixture drives |
| [services/svcmgr/docs/service-definitions.md](../svcmgr/docs/service-definitions.md) | `provides`, `stop_source` |
| [services/svcmgr/docs/ipc-interface.md](../svcmgr/docs/ipc-interface.md) | § Label 5, § Label 6, § Label 7 |

---

## Summarized By

None
