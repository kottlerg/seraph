# threadstack

Test fixture for the guarded demand-paged stack that a spawned thread gets.

---

## Role

Its per-program tester, `threadstack-tester`, drives it in two modes, and the `usertest`
orchestrator discovers and runs that tester. The fixture installs at `/programs/threadstack`
and the tester at `/tests/programs/threadstack`, per
[docs/testing.md § Per-program tester protocol](../../docs/testing.md#per-program-tester-protocol).
Both use idiomatic `std` only and handle no Seraph capabilities directly.

---

## Source Layout

```
threadstack/
├── Cargo.toml
├── README.md
├── src/
│   └── main.rs            # grow and guard modes; the stack-growing recursion
└── tester/
    ├── Cargo.toml
    └── src/
        └── main.rs        # Spawns both modes and checks stdout and exit status
```

---

## Stack Under Test

Every process procmgr creates is demand-paged by default
([Fault Handling § Default System Pager](../../docs/fault-handling.md#default-system-pager)),
so the fixture needs no opt-in: each thread it spawns gets the stack that
[ruststd § Spawned-thread stacks](../../runtime/ruststd/README.md#spawned-thread-stacks)
specifies, a demand-paged region above an unregistered guard page that `join` frees through
memmgr's
[`UNREGISTER_REGION`](../../services/memmgr/docs/ipc-interface.md#label-9-unregister_region).

The worker thread recurses through `recurse`, and each level fills and sums a 4096-byte
stack buffer, so the stack grows by about one page per level. The recursive call goes
through a `black_box`'d function pointer so the optimiser cannot fold the recursion into a
loop.

---

## Modes

The mode is `guard` if any argv entry equals `guard`; otherwise it is `grow`.

| Mode | Behavior | Stdout and exit |
|---|---|---|
| `grow` | A worker recurses `GROW_DEPTH` (200) levels, inside the default 2 MiB usable stack, and is joined | `grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS`. A panicked worker prints `grow worker panicked` and exits with code 3 |
| `guard` | The main thread prints and flushes `about to overflow`, then a worker recurses without bound into the guard page | No clean exit: the guard fault is terminal and procmgr tears down the whole process. If `join` returns, prints `SURVIVED (BUG)` and exits `ExitCode::SUCCESS` so the tester fails |

A terminal fault on a worker thread brings down the whole process because procmgr observes the
address space's death, as
[Capability Model § "Kill process" pattern](../../docs/capability-model.md#kill-process-pattern)
describes.

---

## Tester Checks

`threadstack-tester` runs `/programs/threadstack grow` and then `/programs/threadstack guard`
through `std::process::Command`. For each run it pipes stdout, reads it to the end, and waits
for the exit status. It fails, printing `[threadstack-tester] FAIL <reason>` and exiting with
code 1, when any of these holds:

- `grow`: a stdout line is `SURVIVED (BUG)`, no line is `PASS`, or the exit is not a success.
- `guard`: a stdout line is `SURVIVED (BUG)`, no line contains `about to overflow`, the exit
  is a success, or the exit code is below `EXIT_FAULT_BASE` (`0x1000`), the base of the Fault
  range in [Process Lifecycle § Exit reason](../../docs/process-lifecycle.md#exit-reason) (so a
  Fault or Killed reason passes).

If both runs pass, it prints `[threadstack-tester] PASS` and exits with code 0.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Per-program tester layout, install path, and exit-code contract |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Demand paging as the system default; memmgr as the pager |
| [docs/capability-model.md](../../docs/capability-model.md) | Address-space death observers and process teardown on a terminal fault |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Exit-reason ranges, including `EXIT_FAULT_BASE` |
| [runtime/ruststd/README.md](../../runtime/ruststd/README.md) | Spawned-thread stack geometry, heap fallback, and release at `join` |
| [memmgr IPC Interface](../../services/memmgr/docs/ipc-interface.md) | `UNREGISTER_REGION`, which frees a joined thread's guarded stack |

---

## Summarized By

None
