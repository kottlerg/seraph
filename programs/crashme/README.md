# crashme

Test fixture that dies on a fault on purpose, for the crash report its death leaves in the system
log.

---

## Role

The fixture's per-program tester, `crashme-tester`, runs it once in each of the `vm`, `exception`,
`worker`, and `registry-declare` modes, then twice in the `oom-touch` mode, with one page, beside
the `oom-fill` mode, and the `usertest` orchestrator discovers and runs that tester. svctest's
`crash_endpoint` phase also spawns it, in the `vm`, `exception`, `registry-main`,
`registry-worker`, and `debugger-tag` modes, and its `oom_policy` phase in the `oom-touch` mode,
with 1024 pages, and, through the shell of an operator session it opens, in the `oom-hold` mode
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
| `oom-touch <pages>` | A write to each page of a demand region of `<pages>` pages it registered before, in turn, made on its second line of stdin while the `oom-fill` mode or the `memhog` fixture keeps memory critical: the writes spend whatever free pages lie above the growth floor (the system reserve and, while pages are swapped, the restore headroom), and memmgr declines the first past them for want of memory, which the crash service holds. It prints `ready` after the first line, and `touched held_ms=<ms>`, its longest write, and exits 0 when the writes complete; it dies of the fault when the hold times out |
| `oom-fill <ms>` | None: through [`mem-fill`](../../shared/mem-fill/README.md), shared with the `memhog` fixture, it commits what memmgr can still promise a process outside the system reserve, through its heap and then by one-page grants, until nothing is left and the pressure level has read `CRITICAL` for 500 ms, prints `full`, keeps taking what other processes free for `<ms>` milliseconds, and exits 0, which gives it all back |
| `oom-hold <pages>` | None: it touches `<pages>` pages of heap, prints `holding <pages>`, and waits to be destroyed: a job of an operator session, which oomd stops before any service ([docs/session-supervision.md](../../docs/session-supervision.md)) |
| `registry-declare` | None: with a registered thread parked, it sends `DECLARE_NO_DEBUG` and checks that the thread's crash binding, under a badge other than the main thread's, is unbound with the main thread's; it prints `registry-declare: PASS` and exits 0 when so |

In each faulting mode the fixture registers the log name `crashme` and logs a line first, so logd's
`reclaim:` line at its death names it, and prints `faulting (<mode>)` to stdout. It reaches the
fault two calls deep, so the report's stack walk has frames to find. The threads it spawns
register with procmgr ([runtime/ruststd/README.md](../../runtime/ruststd/README.md) § Thread
registration), so the crash service reads a spawned thread's fault as it reads the main thread's.
The `oom-` modes register the log name `crashme-oom` instead, so the crash-report check, which
reads the `crashme` blocks, does not take the timed-out fault's block for one of them. Neither
`oom-fill` nor `oom-touch` allocates nor touches a new stack page between the filler's `full` and
its exit, since a fault of its own would be held too.

The tester passes when, for each faulting mode it runs, the fixture printed its line and died of a
fault: a non-clean exit whose reason is in the fault range, and left one new core in `/crash`, when
`registry-declare` passed, and when the crash service's hold of a fault declined for want of memory
([services/crashd/docs/operation.md](../../services/crashd/docs/operation.md) § Hold) behaved in its
two cases. In the first, the filler keeps memory critical for 1000 ms after `full` while `oom-touch`
writes its page: the write completes, held at least 500 ms. In the second, the filler keeps it
critical for the usertest crash service's stall, 3000 ms, and 1500 ms more: the fixture dies of the
fault, with a fault reason, at least 1000 ms after its write, and leaves no core, since memory was
still critical. The usertest boot stages a crash service whose `CORE_DUMP` names `crashme`
([docs/testing.md](../../docs/testing.md) § Gating), so each faulting death leaves an ELF core
([services/crashd/docs/core-format.md](../../services/crashd/docs/core-format.md)). The tester reads
it with a reader of its own, not crashd's code, and checks that it is an `ET_CORE` of the machine,
that its first `NT_PRSTATUS` carries the fault's signal (`SIGSEGV` for `vm`, `SIGILL` for the
others) and an instruction pointer and a stack pointer inside `PT_LOAD`s whose bytes the core holds,
that the bytes at the instruction pointer are the illegal instruction in the `exception` and
`worker` modes, and that the `worker` core records more than one thread. That the crash service
declined the fault, and the thread still died with a fault reason, is what it shows; the report
blocks themselves are checked host-side, in the boot's serial log, by `cargo xtask
test-crash-report` ([docs/testing.md](../../docs/testing.md) § Crash reports), which ties each block
to `crashme` through the badge logd's `reclaim:` line names.

---

## Source Layout

```
crashme/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs            # The modes
│   ├── oom.rs             # The `oom-fill`, `oom-touch` and `oom-hold` modes
│   └── arch/
│       ├── mod.rs         # Architecture-dispatch surface
│       ├── x86_64/
│       │   └── mod.rs     # `ud2`
│       └── riscv64/
│           └── mod.rs     # `unimp`
└── tester/
    ├── Cargo.toml
    └── src/
        └── main.rs        # Runs the modes; checks each death, its core, the declaration, the hold
```

---

## Relevant Design Documents

| Document | Covers |
|---|---|
| [services/crashd/README.md](../../services/crashd/README.md) | The crash service the fixture's deaths are reported by |
| [services/crashd/docs/core-format.md](../../services/crashd/docs/core-format.md) | The core the tester checks |
| [services/crashd/docs/operation.md](../../services/crashd/docs/operation.md) | § Hold: the hold the `oom-` modes drive |
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Crash Reports, § Reply |
| [docs/testing.md](../../docs/testing.md) | § Per-program tester protocol, § Crash reports |

---

## Summarized By

None
