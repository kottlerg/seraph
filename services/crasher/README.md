# crasher

Test-tier fixture that validates svcmgr's restart path by crashing on purpose. It is gated and
opt-in: its recipe lives in `/config/svcmgr/tests/`, is co-staged with `svctest` in CI, and is
never launched on a normal boot.

On every spawn it checks that the recipe surfaces (argv, env, cwd, and bootstrap seeds)
survived, logs `<surface> ok` for each, and then faults on purpose (a NULL write) so svcmgr
respawns it under `restart = always`. A surface that fails to round-trip, such as one dropped on
restart, is logged with a `FATAL:` prefix, which the `run-parallel` fail regex catches to fail
the run. The deliberate `USERSPACE FAULT` does not count as a failure.

---

## Source Layout

```
crasher/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Surface checks, then the deliberate fault
```

---

## Capabilities

The bootstrap round delivers the recipe's two seeds again on every spawn and respawn:

| Slot      | Cap                       |
|-----------|---------------------------|
| `caps[0]` | svcmgr service endpoint   |
| `caps[1]` | pwrmgr deny twin          |

The log and procmgr endpoints come in through `ProcessInfo`, so they are not part of the
bootstrap round.

---

## Relevant Design Documents

- [docs/testing.md](../../docs/testing.md): how harnesses and fixtures are staged and
  co-staged
- [docs/process-lifecycle.md](../../docs/process-lifecycle.md): process startup and
  `ProcessInfo` handover
- [Restart Protocol](../svcmgr/docs/restart-protocol.md): svcmgr restart policy

---

## Summarized By

None
