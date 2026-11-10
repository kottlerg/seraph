# crashme

Test fixture that dies on a fault on purpose, for the crash report its death leaves in the system
log.

---

## Role

The fixture's per-program tester, `crashme-tester`, runs it once in each mode, and the `usertest`
orchestrator discovers and runs that tester. The fixture installs at `/programs/crashme` and the
tester at `/tests/programs/crashme`, per
[docs/testing.md § Per-program tester protocol](../../docs/testing.md#per-program-tester-protocol).

| Mode | Fault |
|---|---|
| `vm` | A write to the null page: a page fault memmgr cannot back, which it forwards to the crash endpoint |
| `exception` | An illegal instruction (`ud2` on x86-64, `unimp` on riscv64) |

In each mode the fixture registers the log name `crashme` and logs a line first, so logd's
`reclaim:` line at its death names it, and prints `faulting (<mode>)` to stdout. It reaches the
fault two calls deep, so the report's stack walk has frames to find.

The tester passes when, for each mode, the fixture printed its line and died of a fault: a
non-clean exit whose reason is in the fault range. That the crash service declined the fault, and
the thread still died with a fault reason, is what it shows; the report blocks themselves are
checked host-side, in the boot's serial log, by `cargo xtask test-crash-report`
([docs/testing.md](../../docs/testing.md) § Crash reports), which ties each block to `crashme`
through the badge logd's `reclaim:` line names.

---

## Source Layout

```
crashme/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs            # The two modes
│   └── arch/
│       ├── mod.rs         # Architecture-dispatch surface
│       ├── x86_64/
│       │   └── mod.rs     # `ud2`
│       └── riscv64/
│           └── mod.rs     # `unimp`
└── tester/
    ├── Cargo.toml
    └── src/
        └── main.rs        # Runs both modes and checks each death
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
