# sessiond

The supervisor of operator sessions: it creates each session's leader for the interface that opens
it, holds the leader's handle, ends the session when the leader or the interface ends, and offers
oomd the stop of a session's programs before any service.

---

## Role

A session is the set of processes started for one use of the system through one interface, its
leader and every process the leader starts
([docs/session-supervision.md](../../docs/session-supervision.md) § Sessions). sessiond holds the
kill authority over them, so no interface holds a process handle: the terminal, the one interface
of the default image, opens its session through sessiond and keeps only the leader's standard
streams and the relay its end is posted to.

svcmgr starts sessiond from `rootfs/config/svcmgr/services/sessiond.svc`:

| Key | Value | Why |
|---|---|---|
| `argv` | `sessiond /programs/shell` | `argv[1]` names every leader's binary; no interface chooses it |
| `restart` | `on_failure` | A restart ends every session; each interface opens a new one |
| `critical` | `no` | Without sessiond the system runs with no operator session |
| `namespace` | `universal` | sessiond resolves the leader's binary and hands each leader a copy of its root |
| `provides` | `sessiond.operator:grant` | The operator authority, a `SEND\|GRANT` seeded only to the interfaces whose recipes name it |
| `stop_source` | `program` | svcmgr lists sessiond to oomd as the source of the program class, and creates it contained |
| `reserve` | `yes` | sessiond lists and stops while the pool outside the system reserve is spent |

For each session sessiond makes a budget node under its own with memmgr's `CREATE_SUB_NODE`,
outside the system reserve, and creates the leader through procmgr from the file `argv[1]` names:
suspended, contained, charged to that node, at priority 5 with a band ceiling of 5, with the
interface's queue as its death relay. The interface then hands over the leader's three pipes, which
sessiond installs with procmgr's `CONFIGURE_PIPE`, and asks sessiond to start the session:
sessiond hands the leader a copy of its own namespace root with no working directory, and starts
it. The wire exchange is [docs/ipc-interface.md](docs/ipc-interface.md)'s.

A session ends when its leader ends, when its interface ends, or when a stop-authority holder
stops it. sessiond observes the leader's end through one death queue, bound to the leader's main
thread and, through procmgr's `BIND_DEATH_OBSERVER`, to its process, each with the session's key
as the correlator. It observes the interface's end through the end queue the interface registered
on itself with procmgr and handed sessiond the receive right of. At the end it destroys the leader,
which procmgr does with every process below it and then posts the leader's end to the relay, and
releases the session's node. sessiond's own death ends every session, since svcmgr creates it
contained.

sessiond is the stop source of the program class
([docs/session-supervision.md](../../docs/session-supervision.md) § Stop Sources). Through the
stop-badged SEND svcmgr hands a stop-authority holder, it lists each started session, ranked
`RANK_SESSION`, with its node's subtree pages, and each child of a session's leader, a job, ranked
`RANK_JOB`, with the subtree pages procmgr's `LIST_CHILDREN` reports. It stops a session by
destroying its leader, and a job with `DESTROY_CHILD` on its leader's handle. It opens no session
while memmgr's pressure level reads `CRITICAL`: a session opened then would be a fresh candidate
oomd stops before any service, so an interface that reopened its stopped session would undo the
stop.

One thread serves sessiond's endpoint and waits on one wait set over the endpoint, the death queue
and each interface's end queue. Every table is a fixed array (docs/limits.md), the list and stop
paths allocate nothing, and the stack they use is touched at start, so sessiond answers oomd while
memory is critical.

---

## Source Layout

```
sessiond/
├── Cargo.toml
├── README.md
├── docs/
│   └── ipc-interface.md   # The operator and stop labels, the open sequence, the replies
├── src/
│   └── main.rs            # Startup, the wait loop, the interface, session and stop paths
└── table/                 # Slot tables, candidate keys, the paging of the list (host-tested)
    ├── Cargo.toml
    └── src/lib.rs
```

---

## Capabilities

| Slot | Cap |
|---|---|
| `caps[0]` | The service endpoint of `sessiond.operator`, which svcmgr delivers to the provider |

memmgr's endpoint, procmgr's, the log endpoint and the namespace root come in through
`ProcessInfo`, so they are not part of the bootstrap round.

---

## Testing

`table/`'s host tests cover the slot tables and their generations, the keys of sessions and jobs,
the paging of the candidate list, and the session names. svctest's `sessiond_operator` phase
drives sessiond as an interface, through its `sessiond.operator` seed, and as a stop-authority
holder: the badge gates, an open under an unregistered nonce, a session that runs the shell, lists
its job and has it stopped, then exits, and a session stopped whole. Its `oom_policy` phase opens a
session whose shell runs a job larger than the `stopsrc` fixture's, and checks that oomd stops that
job first, then `stopsrc`'s, then the session, then `memhog`
([services/svctest/README.md](../svctest/README.md)). `cargo xtask test-terminal` drives the
terminal's session end to end.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-interface.md](docs/ipc-interface.md) | The labels, the open sequence, the replies |
| [docs/session-supervision.md](../../docs/session-supervision.md) | Sessions, sessiond, attribution, stop sources |
| [services/procmgr/docs/ipc-interface.md](../procmgr/docs/ipc-interface.md) | `CREATE_PROCESS`, `CONFIGURE_PIPE`, `CONFIGURE_NAMESPACE`, `LIST_CHILDREN`, `DESTROY_CHILD`, `REGISTER_END_QUEUE` |
| [services/memmgr/docs/ipc-interface.md](../memmgr/docs/ipc-interface.md) | § Node Handles |
| [services/svcmgr/docs/service-definitions.md](../svcmgr/docs/service-definitions.md) | `provides`, `stop_source`, `reserve` |
| [services/oomd/docs/operation.md](../oomd/docs/operation.md) | The stop sources and the order oomd stops in |

---

## Summarized By

[Session Supervision](../../docs/session-supervision.md)
