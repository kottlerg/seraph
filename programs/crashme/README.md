# crashme

Test fixture that dies on a fault on purpose, for the crash report its death leaves in the system
log.

---

## Role

The fixture's per-program tester, `crashme-tester`, runs it once in each of the `vm`, `exception`,
`worker`, and `registry-declare` modes, and the `usertest` orchestrator discovers and runs that
tester. svctest's `crash_endpoint` phase also spawns it, in the `vm`, `exception`,
`registry-main`, `registry-worker`, and `debugger-tag` modes
([services/svctest/README.md § Fixtures](../../services/svctest/README.md#fixtures)). The fixture
installs at `/programs/crashme` and the tester at `/tests/programs/crashme`, per [docs/testing.md §
Per-program tester protocol](../../docs/testing.md#per-program-tester-protocol).

| Mode | Fault |
|---|---|
| `vm` | A write to the null page: a page fault memmgr cannot back, which it forwards to the crash endpoint |
| `exception` | An illegal instruction (`ud2` on x86-64, `unimp` on riscv64) |
| `worker` | The illegal instruction on a spawned thread, listed past the first page of an attach (after four parked threads), while a sibling is held blocked on a fault at the same instruction: the main thread binds the sibling's exception class to its own endpoint, and a holder thread receives that fault and never answers it |
| `registry-main` | The illegal instruction on the main thread, with two parked threads registered and a detached one exited |
| `registry-worker` | The illegal instruction on a spawned thread, after its registered sibling was joined |
| `debugger-tag` | None: in steps svctest sets up as its debugger, each let go by a line on stdin, it checks that a thread it spawns while its main thread carries a debugger's binding, with no debugger watched, is bound back to the crash endpoint under a crash badge and its upcall class unbound at its registration, then that its `DECLARE_NO_DEBUG`, with a debugger attached and watched, unbinds the debugger's exception and upcall bindings of its main thread; it prints one line per step and exits 0 when both hold |
| `registry-declare` | None: with a registered thread parked, it sends `DECLARE_NO_DEBUG` and checks that the thread's crash binding, under a badge other than the main thread's, is unbound with the main thread's; it prints `registry-declare: PASS` and exits 0 when so |

In each faulting mode the fixture registers the log name `crashme` and logs a line first, so logd's
`reclaim:` line at its death names it, and prints `faulting (<mode>)` to stdout. It reaches the
fault two calls deep, so the report's stack walk has frames to find. The threads it spawns
register with procmgr ([runtime/ruststd/README.md](../../runtime/ruststd/README.md) § Thread
registration), so the crash service reads a spawned thread's fault as it reads the main thread's.

The tester passes when, for each faulting mode it runs, the fixture printed its line and died of a
fault: a non-clean exit whose reason is in the fault range, and when `registry-declare` passed.
That the crash service declined the fault, and the thread still died with a fault reason, is what
it shows; the report blocks themselves are checked host-side, in the boot's serial log, by
`cargo xtask test-crash-report` ([docs/testing.md](../../docs/testing.md) § Crash reports), which
ties each block to `crashme` through the badge logd's `reclaim:` line names.

---

## Source Layout

```
crashme/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs            # The modes
│   └── arch/
│       ├── mod.rs         # Architecture-dispatch surface
│       ├── x86_64/
│       │   └── mod.rs     # `ud2`
│       └── riscv64/
│           └── mod.rs     # `unimp`
└── tester/
    ├── Cargo.toml
    └── src/
        └── main.rs        # Runs four modes; checks each death and the declaration
```

---

## Relevant Design Documents

| Document | Covers |
|---|---|
| [services/crashd/README.md](../../services/crashd/README.md) | The crash service the fixture's deaths are reported by |
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Crash Reports, § Reply |
| [docs/testing.md](../../docs/testing.md) | § Per-program tester protocol, § Crash reports |

---

## Summarized By

None
