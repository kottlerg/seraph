# oomd

The out-of-memory policy service: when memory stays critical, stops one candidate of its stop
sources, a session's program before any service that opted in to being stopped, and within that
the one using the most memory, so its memory is given back.

---

## Role

Neither the kernel nor memmgr kills a process when memory runs out
([docs/memory-model.md](../../docs/memory-model.md) § Frame Allocation is Fallible). memmgr
keeps a system reserve that only reserve nodes may take, signals its pressure level (`NORMAL`,
`LOW`, `CRITICAL`) to every process, and declines a page fault it cannot back; crashd holds such
a fault until memory is freed or its stall passes
([services/crashd/docs/operation.md](../crashd/docs/operation.md) § Hold). oomd is the rung above
them: when the level has read `CRITICAL` for a grace period, it stops one candidate of its stop
sources, at most one per cooldown. svcmgr is the source of the service class: it destroys a
service through the handle it holds as its creator and routes the death through the service's
restart policy, which starts it again with its memory released. Every other source is a service
whose recipe sets `stop_source = program`, which svcmgr lists to oomd; such a source lists the
programs it holds kill authority over, and oomd stops them before any service.

A service is stoppable only when its recipe sets `oom_stop = yes` and svcmgr's eligibility rule
admits it ([`.svc` Service Definitions](../svcmgr/docs/service-definitions.md) § `oom_stop`). No
recipe of the default image sets `oom_stop` or `stop_source`, so by default oomd finds nothing to
stop and only logs the episode. With `OOMD_STOP=no` it names the service it would stop and stops
none.

oomd acts only through the capabilities its recipe endows: the stop authority svcmgr mints for
`stop_authority = yes`, a SEND on svcmgr's endpoint that serves the stop labels (`LIST_CANDIDATES`,
`STOP_CANDIDATE`) and the list of stop sources (`LIST_STOP_SOURCES`) and nothing else, the
stop-badged SENDs that list hands it for one act, and its own memmgr endpoint, on which, after its
start, it makes only the `QUERY_POOL_STATUS` query. It holds no process handle and no debug
authority, and holds no fault. Its recipe also sets `reserve = yes`, so it runs while the pool
outside the reserve is spent; it touches its stack and heap and funds its CSpace headroom at start,
and allocates nothing after.

svcmgr starts oomd from `rootfs/config/svcmgr/services/oomd.svc`. Whether a system has the
policy is a staging decision: an image without the recipe has none, and memory runs out for
whichever process asks next while the reserve keeps the core alive.

The ladder, the configuration, the stop sources and the order oomd stops in are in
[docs/operation.md](docs/operation.md).

---

## Source Layout

```
oomd/
├── Cargo.toml
├── README.md
├── docs/
│   └── operation.md       # Configuration, the ladder, the stop sources and order, bounds
├── policy/                # Configuration, the ladder, the stop order (host-tested)
│   ├── Cargo.toml
│   └── src/lib.rs
└── src/
    ├── main.rs            # Startup, the wait on the level, the act
    └── source.rs          # The stop sources: their discovery, lists and stop, bounded
```

Every decision oomd makes is `policy/`'s, host-tested there: how a setting parses, when the ladder
asks for an act, and which candidate a walk keeps. `src/` waits on memmgr's Notification, reads
the level, calls the sources and logs.

---

## Testing

`policy/`'s host tests cover each setting's parse, each step of the ladder (the grace, the cooldown,
a fall below `CRITICAL`, an unreadable level, `OOMD_STOP=no`), the class codes and the stop order.
The svctest `oom_policy` phase drives oomd end to end with the `memhog` fixture
([services/memhog/README.md](../memhog/README.md)) and the `stopsrc` fixture
([services/stopsrc/README.md](../stopsrc/README.md)), which the svctest boot stages: stopsrc
restarts, so the source oomd finds started after oomd, and starts a job; memhog fills the pool up to
the reserve; oomd stops the job after the grace and memhog a cooldown later, the level falls to
`NORMAL`, memhog's next instance is idle, and oomd has logged one stop of each. In a boot that
stages crashd with a stall, a child of svctest writes a page while the pool is full, and crashd
resumes it once the stop frees memory. With `OOMD_STOP=no`, or without oomd's recipe, the phase
checks that nothing stops memhog ([services/svctest/README.md](../svctest/README.md)).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/operation.md](docs/operation.md) | Configuration, the ladder, the stop sources and order, bounds |
| [docs/memory-model.md](../../docs/memory-model.md) | § Frame Allocation is Fallible |
| [services/memmgr/docs/memory-pool.md](../memmgr/docs/memory-pool.md) | § Memory pressure, the system reserve |
| [services/svcmgr/docs/ipc-interface.md](../svcmgr/docs/ipc-interface.md) | § Label 5: `STOP_CANDIDATE`, § Label 6: `LIST_CANDIDATES`, § Label 7: `LIST_STOP_SOURCES` |
| [services/svcmgr/docs/service-definitions.md](../svcmgr/docs/service-definitions.md) | `stop_authority`, `stop_source`, `oom_stop`, `reserve`, `env` |
| [services/crashd/docs/operation.md](../crashd/docs/operation.md) | § Hold |
| [docs/session-supervision.md](../../docs/session-supervision.md) | § Stop Sources |

---

## Summarized By

[Memory Model](../../docs/memory-model.md)
