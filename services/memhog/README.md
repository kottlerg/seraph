# memhog

Test-tier fixture for the out-of-memory policy service: a supervised service that, on request,
takes what memmgr can still promise a process outside the system reserve, until the pressure level
reads `CRITICAL`, and holds it until it is stopped. It is gated and opt-in: its recipe,
`rootfs/config/svcmgr/tests/memhog.svc`, lives in `/config/svcmgr/tests/`, is co-staged with
`svctest` in CI, and is never launched on a normal boot.

The recipe sets `restart = on_failure`, `critical = no`, `namespace = none`,
`provides = memhog.ctl` and `oom_stop = yes`, with no `reserve`, so it is a service
oomd may stop ([services/oomd/README.md](../oomd/README.md)), and a stop's `EXIT_KILLED` death
restarts it. The fixture takes the provided name's service endpoint from bootstrap slot 0, allocates
its fill's ballast, touches its stack, logs `serving`, and serves `ipc::memhog_labels`:

| Label | Reply |
|---|---|
| `PROBE` (1) | `SUCCESS`, word 0 a per-instance random nonce, word 1 the pages it holds |
| `HOG` (2) | `SUCCESS` with word 0 the pages it holds, once nothing is left to take and the level has read `CRITICAL` for 500 ms; `NOT_CRITICAL` when that does not happen within 30 s, or memmgr does not answer |
| any other | `UNKNOWN_OPCODE` |

The fill is [`mem-fill`](../../shared/mem-fill/README.md)'s, shared with crashme's `oom-fill`
mode: it commits what memmgr can still promise a process outside the reserve through the heap and
takes the rest by one-page grants. Once hogging, the fixture tops up every 10 ms between requests,
so it takes back what another process frees and the level stays `CRITICAL` until it is stopped.

svctest's `oom_policy` phase, which runs when this recipe is staged, has it hog and reads that oomd
stopped it, or with `OOMD_STOP=no` or no oomd that nothing did, and that its next instance answers
`PROBE` with a new nonce and no pages; its `logd_reserve` phase has it hog while logd is killed and
restarted ([services/svctest/README.md](../svctest/README.md)). Its `oom_stop = yes` also makes it
a service svctest's `svcmgr_stop_service` phase may list. A fixture that lacks its endpoint or
nonce, or cannot allocate its ballast, logs an error and exits.

---

## Source Layout

```
memhog/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # The label loop, the fill and its top-ups
```

---

## Capabilities

| Slot      | Cap                                              |
|-----------|--------------------------------------------------|
| `caps[0]` | The service endpoint of `memhog.ctl`, which svcmgr delivers to the provider |

memmgr's endpoint and the log endpoint come in through `ProcessInfo`, so they are not part of the
bootstrap round.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | How harnesses and fixtures are staged and co-staged |
| [services/oomd/docs/operation.md](../oomd/docs/operation.md) | The ladder and the stop sources the fixture drives |
| [shared/mem-fill/README.md](../../shared/mem-fill/README.md) | The fill |
| [services/memmgr/docs/memory-pool.md](../memmgr/docs/memory-pool.md) | § Memory pressure, § Distribution policy |
| [services/svcmgr/docs/service-definitions.md](../svcmgr/docs/service-definitions.md) | `provides`, `oom_stop` |

---

## Summarized By

None
